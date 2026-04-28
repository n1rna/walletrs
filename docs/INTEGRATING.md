# Integrating with walletrs

This guide is for client engineers connecting their service to a walletrs instance. For ops concerns see [`OPERATING.md`](OPERATING.md).

## Connection model

walletrs exposes two surfaces against the same handlers:

- **gRPC** on `WALLETRS_HOST:WALLETRS_PORT` (default `127.0.0.1:50051`).
- **HTTP/JSON** on `WALLETRS_HOST:WALLETRS_HTTP_PORT` (default `127.0.0.1:8080`). Routes are derived from `(google.api.http)` annotations on the proto and exposed at `POST /wallet/<snake_case_method>` with an `application/json` body.

Both serve plaintext. For non-localhost deployments, terminate TLS at a reverse proxy and have your client trust that proxy's certificate.

Bearer-token auth is required by default on both surfaces — every RPC except `Ping` checks `Authorization: Bearer <token>` (gRPC metadata or HTTP header).

### When to pick which

- **gRPC**: server-to-server, when you already have tonic / grpc-go / grpcio in the stack and want native streaming, codegen'd types, low overhead.
- **HTTP/JSON**: browser, curl, scripts, polyglot clients without protoc tooling, gateways that prefer HTTP. Same handlers, same auth, same errors — just a different wire format.

## Vendoring the proto contract

The canonical `walletrpc.proto` lives in this repo at [`proto/walletrpc.proto`](../proto/walletrpc.proto). Two recommended ways to consume it:

### Git submodule (recommended)

```bash
git submodule add https://github.com/n1rna/walletrs vendor/walletrs
git -C vendor/walletrs checkout v0.1.0
```

Point your build at `vendor/walletrs/proto/walletrpc.proto`. Bumping walletrs is a single submodule update.

### Tarball pin

If submodules don't fit your repo conventions, download the proto from a release tag:

```bash
curl -o vendor/walletrpc.proto \
  https://raw.githubusercontent.com/n1rna/walletrs/v0.1.0/proto/walletrpc.proto
```

Track the version in your dependency manifest so renovating is explicit.

## Generating client stubs

### Rust (tonic)

`build.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("vendor/walletrs/proto/walletrpc.proto")?;
    Ok(())
}
```

`Cargo.toml`:

```toml
[dependencies]
tonic = "0.9"
prost = "0.11"

[build-dependencies]
tonic-build = "0.9"
```

Calling code:

```rust
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

pub mod walletrpc {
    tonic::include_proto!("walletrpc");
}

use walletrpc::wallet_service_client::WalletServiceClient;
use walletrpc::PingRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://127.0.0.1:50051").connect().await?;
    let token: MetadataValue<_> = "Bearer <YOUR_TOKEN>".parse()?;
    let mut client =
        WalletServiceClient::with_interceptor(channel, move |mut req: Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    let resp = client.ping(PingRequest {}).await?;
    println!("ping: {:?}", resp);
    Ok(())
}
```

### Python (grpcio + grpcio-tools)

```bash
pip install grpcio grpcio-tools
python -m grpc_tools.protoc \
  --proto_path=vendor/walletrs/proto \
  --python_out=. --grpc_python_out=. \
  vendor/walletrs/proto/walletrpc.proto
```

```python
import grpc
import walletrpc_pb2
import walletrpc_pb2_grpc

token = "YOUR_TOKEN"

with grpc.insecure_channel("127.0.0.1:50051") as channel:
    stub = walletrpc_pb2_grpc.WalletServiceStub(channel)
    metadata = (("authorization", f"Bearer {token}"),)
    response = stub.Ping(walletrpc_pb2.PingRequest(), metadata=metadata)
    print("ping:", response)
```

### TypeScript (@grpc/grpc-js + protoc-gen-ts)

```bash
npm install @grpc/grpc-js @grpc/proto-loader
```

```ts
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

const def = protoLoader.loadSync("vendor/walletrs/proto/walletrpc.proto", {
  keepCase: false,
  longs: String,
  enums: String,
});
const proto = (grpc.loadPackageDefinition(def) as any).walletrpc;

const client = new proto.WalletService(
  "127.0.0.1:50051",
  grpc.credentials.createInsecure(),
);

const meta = new grpc.Metadata();
meta.set("authorization", `Bearer ${process.env.WALLETRS_AUTH_TOKEN}`);

client.Ping({}, meta, (err: any, resp: any) => {
  if (err) throw err;
  console.log("ping:", resp);
});
```

For TLS, swap `createInsecure()` for `createSsl(...)` and point at your reverse-proxy hostname.

### HTTP/JSON (curl / any HTTP client)

Every RPC is also reachable as `POST /wallet/<snake_case_method>` on the HTTP port. Request and response bodies are the JSON encoding of the same proto messages (numeric fields stay numeric, `bytes` fields are base64, enums use the canonical name). Errors map gRPC status codes to HTTP status codes and return a `{ "code": <int>, "message": <string> }` body.

```bash
TOKEN=...

# Liveness — no auth required
curl -sS -X POST http://127.0.0.1:8080/wallet/ping \
  -H 'content-type: application/json' -d '{}'

# Authenticated call
curl -sS -X POST http://127.0.0.1:8080/wallet/create_system_managed_key \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"user_id":"alice","device_id":"alice-device-1","key_name":"primary"}'
```

| HTTP path | gRPC method |
|---|---|
| `POST /wallet/ping` | `Ping` |
| `POST /wallet/create_generic_wallet` | `CreateGenericWallet` |
| `POST /wallet/create_system_managed_key` | `CreateSystemManagedKey` |
| `POST /wallet/create_customer_managed_key` | `CreateCustomerManagedKey` |
| `POST /wallet/get_managed_key` | `GetManagedKey` |
| `POST /wallet/list_managed_keys` | `ListManagedKeys` |
| `POST /wallet/get` | `GetWallet` |
| `POST /wallet/update` | `UpdateWallet` |
| `POST /wallet/reveal_next_address` | `RevealNextAddress` |
| `POST /wallet/list_addresses` | `ListAddresses` |
| `POST /wallet/get_transactions` | `GetWalletTransactions` |
| `POST /wallet/get_utxos` | `GetWalletUtxos` |
| `POST /wallet/fund_transaction` | `FundWalletTransaction` |
| `POST /wallet/sign_transaction` | `SignWalletTransaction` |
| `POST /wallet/add_verify_transaction_signature` | `AddVerifyTransactionSignature` |
| `POST /wallet/finalize_transaction` | `FinalizeWalletTransaction` |
| `POST /wallet/broadcast_transaction` | `BroadcastWalletTransaction` |
| `POST /wallet/get_spending_paths` | `GetWalletSpendingPaths` |

The mapping is generated from `(google.api.http)` annotations in `proto/walletrpc.proto` — the proto stays the single source of truth.

## Worked end-to-end example

Goal: spin up a wallet from a single system-managed key, fund it on regtest, sign and broadcast a transaction.

### 1. Create a system-managed key

```rust
let key = client
    .create_system_managed_key(walletrpc::CreateSystemManagedKeysRequest {
        user_id: "alice".into(),
        device_id: "alice-device-1".into(),
        key_name: "primary".into(),
    })
    .await?
    .into_inner();
println!("xpub: {}, fingerprint: {}", key.xpub, key.fingerprint);
```

The response carries the public xpub + derivation path. The corresponding xpriv is stored encrypted under `WALLETRS_KEK` and never leaves the server.

### 2. Create the wallet

```rust
use walletrpc::{
    CreateGenericWalletRequest, PolicyType, PreferredScriptType, SpendingCondition,
};

let wallet = client
    .create_generic_wallet(CreateGenericWalletRequest {
        user_id: "alice".into(),
        wallet_id: "alice-wallet-1".into(),
        spending_conditions: vec![SpendingCondition {
            id: "primary".into(),
            is_primary: true,
            timelock: 0,
            threshold: 1,
            policy: PolicyType::Single as i32,
            managed_key_ids: vec!["alice-device-1".into()],
        }],
        network: "regtest".into(),
        preferred_script_type: PreferredScriptType::ScriptTypeAuto as i32,
    })
    .await?
    .into_inner();
```

That gives you a single-sig SegWit-v0 (`wpkh`) wallet. Switch to taproot by setting `preferred_script_type = ScriptTypeTaproot`. For inheritance / recovery flows, add a second `SpendingCondition` with non-zero `timelock`.

### 3. Reveal an address and fund it

```rust
let addr = client
    .reveal_next_address(walletrpc::RevealNextAddressRequest {
        wallet_id: "alice-wallet-1".into(),
        num: 1,
        change: false,
    })
    .await?
    .into_inner()
    .addresses[0]
    .address
    .clone();

// Send some regtest BTC to `addr` via bitcoin-cli, then sync the wallet:
client
    .update_wallet(walletrpc::UpdateWalletRequest {
        wallet_id: "alice-wallet-1".into(),
    })
    .await?;
```

### 4. Build, sign, and broadcast

```rust
let funded = client
    .fund_wallet_transaction(walletrpc::FundWalletTransactionRequest {
        wallet_id: "alice-wallet-1".into(),
        destination_address: "bcrt1q...".into(),
        destination_value: 50_000,
        change_address: "".into(),
        fee_per_kb: 1_000,
        selected_leaf_hash: "".into(),  // empty for non-taproot or default path
        spend_change: false,
    })
    .await?
    .into_inner();

client
    .sign_wallet_transaction(walletrpc::SignWalletTransactionRequest {
        wallet_id: "alice-wallet-1".into(),
        txid: funded.txid.clone(),
        device_id: "alice-device-1".into(),
    })
    .await?;

client
    .finalize_wallet_transaction(walletrpc::FinalizeWalletTransactionRequest {
        wallet_id: "alice-wallet-1".into(),
        txid: funded.txid.clone(),
    })
    .await?;

client
    .broadcast_wallet_transaction(walletrpc::BroadcastWalletTransactionRequest {
        wallet_id: "alice-wallet-1".into(),
        txid: funded.txid,
    })
    .await?;
```

### 5. Hardware wallet flow

For PSBTs signed externally (HWW, air-gapped signer), skip step 4's `sign_wallet_transaction` and feed each partial signature back via `add_verify_transaction_signature`:

```rust
client
    .add_verify_transaction_signature(walletrpc::AddVerifyTransactionSignatureRequest {
        wallet_id: "alice-wallet-1".into(),
        txid: funded.txid.clone(),
        signedpsbt: signed_psbt_b64,
        devicefingerprint: hww_fingerprint,
        devicederivationpath: "m/86h/1h/0h".into(),
    })
    .await?;
```

After the threshold of signatures is collected, call `finalize_wallet_transaction` and `broadcast_wallet_transaction` as above.

## Taproot leaf-hash spends

Wallets created with multiple time-locked recovery paths return a `TaprootLeafInfo[]` in the `CreateGenericWallet` response. Each entry has a `leaf_hash` (or the sentinel `"keypath"`) and a `spending_condition_id` matching one of your input conditions. To spend via a specific path:

```rust
fund_wallet_transaction(FundWalletTransactionRequest {
    selected_leaf_hash: "abcdef...".into(),  // the leaf_hash for the recovery you want
    ...
});
```

The signer maps that leaf hash back to a BDK policy-path index (`vec![0]` for primary / keypath, `vec![idx + 1]` for the Nth recovery). For the primary keypath spend, pass `selected_leaf_hash: "keypath"`.

## Common errors

| Error | Cause |
|---|---|
| `UNAUTHENTICATED: missing or invalid bearer token` | Forgot the `Authorization: Bearer …` header (HTTP) or metadata (gRPC). `Ping` is the only RPC that bypasses. HTTP returns `401` with `{"code": 16, "message": ...}`. |
| `INVALID_ARGUMENT: Leaf hash 'X' does not match any spending path in the descriptor` | The leaf hash you sent isn't part of this wallet's taproot tree. Check the `TaprootLeafInfo[]` from `CreateGenericWallet`. |
| `NOT_FOUND: Wallet not found` | Either the wallet was never created or the storage tier doesn't have it (S3 misconfig, wrong `WALLETRS_S3_PREFIX`, missing local data dir). |
| `INTERNAL: Failed to extract taproot leaf hash for recovery condition X` | The descriptor's signer fingerprints didn't surface in `tap_key_origins` — usually a malformed input key. Re-check `xpub` + `fingerprint` + `derivation_path` on the `CreateCustomerManagedKey` call. |

## Versioning

The proto contract follows additive semver inside a minor series — fields and RPCs land without breaking older clients. Pin the walletrs version your stubs were generated against, and bump deliberately. The [CHANGELOG](../CHANGELOG.md) calls out anything backwards-incompatible.
