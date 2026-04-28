# Architecture

`walletrs` is a single-tenant Rust service that creates and operates Bitcoin wallets backed by [BDK](https://github.com/bitcoindevkit/bdk), [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript), and a vendored fork of [Liana](https://github.com/wizardsardine/liana) for primary/recovery descriptor compilation. It exposes the same handler set over gRPC (tonic) and HTTP/JSON (axum), generated from a single proto. This doc describes how the pieces fit together; for ops/integrator concerns see [`OPERATING.md`](OPERATING.md) and [`INTEGRATING.md`](INTEGRATING.md).

## Component map

```
                                    ┌───────────────────────┐
                              ┌────►│   crates.io BDK 1.x   │  block + utxo state, signing context, persistence
                              │     └───────────────────────┘
                              │
                              │     ┌───────────────────────┐
                              ├────►│  rust-miniscript 12   │  descriptor parsing + compilation
                              │     └───────────────────────┘
                              │
                              │     ┌───────────────────────┐
        ┌──────────────┐      │     │   contrib/liana 12    │  primary + time-locked recovery policies → taproot
        │   gRPC API   │──────┤     └───────────────────────┘
        │ (tonic 0.9)  │      │
        └──────┬───────┘      │     ┌───────────────────────┐
               │              ├────►│   storage backend     │  local FS or S3/R2 with envelope crypto
        ┌──────┴───────┐      │     └───────────────────────┘
        │  HTTP/JSON   │──────┤
        │  (axum 0.6)  │      │     ┌───────────────────────┐
        └──────┬───────┘      └────►│      electrs URL      │  Electrum-Rust server for chain sync
               │                    └───────────────────────┘
               │
        ┌──────▼───────┐
        │   Auth       │  bearer-token gate on both surfaces, Ping bypasses
        └──────────────┘
```

External callers reach the service over either gRPC (default `:50051`) or HTTP/JSON (default `:8080`). Both surfaces share one `WalletService` impl: gRPC frames are decoded by tonic; HTTP requests are decoded by an axum router whose routes are codegen'd at build time from `(google.api.http)` annotations on the proto. The bearer-token gate sits in front of every RPC except `Ping`.

## Module layout

```
crates/server/src/
├── auth.rs                      (planned top-level — currently lives in wallet/service/)
├── config.rs                    env-driven Config + global Lazy<Config>
├── db.rs                        thin `(StorageManager, models)` re-export layer
├── lib.rs                       crate root + public re-exports
├── main.rs                      tonic + axum bootstrap (gRPC + HTTP gateway)
├── http.rs                      HTTP/JSON gateway: status mapping, auth middleware, includes build-time-generated routes
├── proto/
│   └── mod.rs                   `tonic::include_proto!("walletrpc")` + pbjson serde
├── storage/                     pluggable storage abstraction
│   ├── traits.rs                Storage / StorageBackend / IndexableStorage
│   ├── filesystem.rs            local FS backend
│   ├── s3.rs                    S3 / R2 backend (path-style, force-checksum-suppression)
│   ├── encrypting.rs            wraps any backend with envelope-encrypted writes
│   ├── crypto.rs                ChaCha20-Poly1305 + KEK envelope
│   ├── path.rs                  scope-based path generation
│   ├── schema.rs                indexable field declarations per model
│   ├── index.rs                 secondary-index manager (in-memory + on-disk persisted)
│   ├── manager.rs               StorageManager — top-level entry per scope
│   └── models/                  StoredWallet, StoredManagedKey, StoredPSBT, StoredSignedPSBT
└── wallet/
    ├── advanced/                wallet-creation pipeline
    │   ├── spec.rs              SpendingCondition / WalletSpec / validation
    │   ├── shape.rs             WalletShape + classify()
    │   ├── descriptor.rs        typed descriptor builders per shape
    │   ├── taproot.rs           leaf-hash + internal-key extraction
    │   ├── build.rs             build_wallet pipeline
    │   ├── error.rs             WalletCreationError
    │   └── tests.rs             cross-module integration tests
    ├── bdk/                     BdkWalletManager + KeyUtils + R2BackedStore
    ├── service/                 gRPC handlers
    │   ├── mod.rs               WalletRPC dispatch
    │   ├── auth.rs              bearer-token interceptor
    │   ├── middleware.rs        request-logging tower layer
    │   ├── system.rs            Ping
    │   ├── key_management.rs    CreateSystemManagedKey / CreateCustomerManagedKey / Get / List
    │   ├── wallet_creation.rs   CreateGenericWallet — proto → WalletSpec → build_wallet
    │   ├── wallet_operations.rs GetWallet / Update / RevealNextAddress / ListAddresses / GetSpendingPaths
    │   └── transaction_handling.rs  GetTx / GetUtxos / Fund / SignWallet / AddVerifySig / Finalize / Broadcast
    └── signer/
        └── mod.rs               PSBT signing + leaf-hash → policy-path resolution
```

## Wallet creation pipeline

`CreateGenericWallet` and the `WalletSpec` it builds are the cleanest entrypoint into the system:

```
                  CreateGenericWalletRequest (proto)
                              │
                              ▼
               wallet_creation::create_generic_wallet
                              │
                              ▼
                     ┌──────────────────┐
                     │  WalletSpec      │   conditions + managed_keys + network +
                     │  (validated)     │   preferred_script_type
                     └────────┬─────────┘
                              │
                              ▼
                     ┌──────────────────┐
                     │  classify()      │   resolve key references, decide shape
                     └────────┬─────────┘
                              │
            ┌─────────────────┼──────────────────┐
            │                 │                  │
            ▼                 ▼                  ▼
       SingleSig         Multisig         TimelockedPolicy
       (wpkh / tr)    (wsh sortedmulti    (LianaDescriptor —
                       or tr+multi_a)     primary keypath +
                                          time-locked recoveries)
            │                 │                  │
            └────────┬────────┴──────────────────┘
                     ▼
              descriptor::build
                     │
                     ▼
            DescriptorPair { external, internal, liana: Option<LianaDescriptor> }
                     │
                     ▼
        BdkWalletManager::create_wallet_with_descriptors
                     │
                     ▼
         taproot::extract  (only when shape = TimelockedPolicy
                            and the descriptor is taproot)
                     │
                     ▼
            WalletBuildResult
                     │
                     ▼
        StoredWallet persisted (with `liana_descriptor` field set
        only when a real Liana descriptor was generated)
```

### `WalletShape` variants

| Variant | Descriptor template | When |
|---|---|---|
| `SingleSig { kind: SegwitV0 }` | `wpkh(K)` | one key, no timelock, `Auto` or `SegwitV0` preference |
| `SingleSig { kind: Taproot }` | `tr(K)` (BIP-86) | one key, no timelock, `Taproot` preference |
| `Multisig { kind: SegwitV0 }` | `wsh(sortedmulti(t, K1, K2, …))` | many keys + threshold, `Auto` or `SegwitV0` |
| `Multisig { kind: Taproot }` | `tr(NUMS, multi_a(t, K1, K2, …))` | many keys + threshold, `Taproot` (or `Auto` when classifier folds zero-timelock conditions) |
| `TimelockedPolicy` | Liana — primary path + `BTreeMap<u16, PathInfo>` recoveries → taproot multipath | any condition has a non-zero timelock, or multiple primaries with disjoint signers |

The `Auto` script-type combined with multiple zero-timelock conditions triggers the "smart taproot multisig combine" branch — the classifier folds every condition's keys into one taproot multisig with the primary's threshold. This matches clients that model multisigs as several conditions instead of one `Multi` condition; raw Liana would reject `timelock=0` recovery paths anyway.

## PSBT lifecycle

```
   FundWalletTransaction
          │
          ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ resolve_policy_path_from_leaf(selected_leaf_hash, …)         │
   │   "keypath" → vec![0]                                         │
   │   real hex  → fingerprint match against primary or recoveries │
   └──────────────────────────────────────────────────────────────┘
          │
          ▼
   tx_builder.policy_path(…) + finish() → PSBT
          │
          ▼
   StoredPSBT (persisted) + Liana descriptor pruning when applicable
          │
          ▼
   SignWalletTransaction (system key flow)         AddVerifyTransactionSignature (HWW flow)
          │                                                  │
          ▼                                                  ▼
   add_signers_for_psbt + sign_psbt_with_taproot_support   Combine partial sigs into stored PSBT
          │                                                  │
          └──────────────────────────┬───────────────────────┘
                                     ▼
                            FinalizeWalletTransaction
                                     │
                                     ▼
                            BroadcastWalletTransaction → electrs
```

System-managed keys decrypt the envelope-encrypted private material on demand and add only the specific BIP32 derivations the PSBT inputs need — no broad signer registration.

## Storage model

Three persistence concerns:

1. **BDK file_store.** Per-wallet binary blob (`wallets/<wallet_id>/bdk.store`) holding chain state, transactions, address index. Read on `load_wallet`, written on every `wallet.persist()`. The `R2BackedStore` wrapper proxies a local `bdk_file_store::Store` to the configured `AnyBackend` (local FS or S3) on every persist.
2. **walletrs models.** Indexable JSON documents under their own scopes:
   - `StoredWallet` (one per wallet, indexed by `wallet_id` and `user_id`)
   - `StoredManagedKey` (per device / per user / per type)
   - `StoredPSBT` (active spend in flight)
   - `StoredSignedPSBT` (collected signatures + finalized output)

   The `EncryptingBackend` wrapper transparently envelope-encrypts payloads with `WALLETRS_KEK` before writes and decrypts on reads, so even an attacker who exfiltrates the storage tier can't read system-managed private keys without the KEK.
3. **Per-wallet locks.** `WALLET_LOCKS` is a `HashMap<wallet_id, Arc<Mutex<()>>>`; every load / create acquires the lock for the duration of the call. Prevents concurrent BDK reads/writes against the same store from racing. Locks are surface-agnostic — gRPC and HTTP requests contend on the same map.

## HTTP/JSON gateway

The HTTP surface reuses the gRPC `WalletService` impl with no per-RPC glue:

1. `proto/walletrpc.proto` annotates each RPC with `option (google.api.http) = { post: "/wallet/<snake>" body: "*" };` (single source of truth for the path mapping).
2. `crates/server/build.rs` compiles the proto with `tonic-build`, emits a `FileDescriptorSet`, then runs two extra steps:
   - `pbjson-build` adds `serde::Serialize`/`Deserialize` impls to the prost types so JSON encoding follows proto3 JSON semantics (numeric stays numeric, `bytes` is base64, enums use the canonical name).
   - A custom step reads the descriptor with `prost-reflect`, walks every RPC's `(google.api.http)` extension, and writes `http_routes.rs` — an axum `Router` that decodes the request body into the prost message, wraps it in a `tonic::Request`, dispatches through `WalletService::<rpc>`, and serializes the response.
3. `crates/server/src/http.rs` `include!`s the generated routes, maps `tonic::Status` codes to HTTP status codes, and provides a thin axum middleware mirroring `AuthLayer` semantics for the bearer token.
4. `main.rs` runs the axum server alongside the tonic server under one `tokio::select!` — both bind on `WALLETRS_HOST`, separated only by `WALLETRS_PORT` (gRPC) and `WALLETRS_HTTP_PORT` (HTTP).

Adding a new RPC is a one-line proto change (annotation) followed by the usual handler addition. The HTTP route generates itself.

## Why these specific dependencies

- **BDK 1.x** for the wallet primitive (descriptor parsing, address derivation, coin selection, signing context). 1.x is the modern API where the bitcoin crate is exposed instead of vendored.
- **rust-miniscript 12** for descriptor types. We use multipath descriptors directly so external/internal keychains can be derived from the same descriptor template.
- **Liana 12** (vendored at `contrib/liana/`) for the primary + time-locked recovery policy compiler. It produces taproot descriptors with the primary as the keypath and each recovery as a timelocked script leaf. We don't try to re-implement that compiler — it's a non-trivial piece of code that already has prod usage at Wizardsardine.
- **AWS SDK** for the S3 backend. Path-style addressing + a pinned `BehaviorVersion` works around a checksum-header regression that broke MinIO compatibility in 1.x SDKs.

## What's intentionally not here

- **Multi-tenancy.** The wire contract carries `user_id` on every request because the same proto serves single-tenant OSS deployments and multi-tenant operators that run a walletrs instance per logical tenant. The OSS distribution does not enforce tenant isolation — operators that need it run multiple instances or wrap walletrs behind a tenant-aware proxy.
- **Hardware wallet integration.** Signing with HWWs is the client's job. Walletrs accepts pre-signed PSBTs via `AddVerifyTransactionSignature` and combines them in-place; it does not talk USB / HID.
- **Built-in TLS.** Run a reverse proxy (Caddy / Traefik / nginx) for TLS termination on either surface. Native TLS is a future opt-in, not a v0.1.0 feature.
- **Audit log.** No append-only history of mutations today. On the roadmap.
