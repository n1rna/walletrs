# Operating walletrs

This guide is for operators running a walletrs instance. For the gRPC integration story see [`INTEGRATING.md`](INTEGRATING.md); for the threat model see [`/SECURITY.md`](../SECURITY.md).

## Deploy paths

### Docker Compose (recommended for trying it out)

The shipped `docker-compose.yml` brings up a regtest stack — bitcoind + electrs + walletrs — in one command.

```bash
docker compose up --build
```

walletrs listens on `127.0.0.1:50051`. The first start logs a `STORE THIS — generated auth token: <token>` line; copy it into your client.

To pin a known token across restarts, drop a `.env` next to the compose file:

```bash
WALLETRS_AUTH_TOKEN=$(openssl rand -hex 32)
WALLETRS_KEK=$(openssl rand -base64 32)   # required if you create system-managed keys
```

Switch networks by editing the bitcoind / electrs flags and the `BITCOIN_NETWORK` env in `walletrs`.

### Standalone Docker

```bash
docker run --rm -p 50051:50051 \
  -v walletrs-data:/data \
  -e BITCOIN_NETWORK=signet \
  -e ELECTRS_URL=tcp://your-electrs:50001 \
  -e WALLETRS_AUTH_TOKEN=$(openssl rand -hex 32) \
  -e WALLETRS_KEK=$(openssl rand -base64 32) \
  ghcr.io/n1rna/walletrs:latest
```

Released images are tagged on every `v*` git tag — `:0.1.0`, `:0.1`, `:latest`. Multi-arch (`linux/amd64` + `linux/arm64`).

### From source

```bash
cargo build --release --bin walletrs
./target/release/walletrs
```

Binaries are also attached to GitHub releases for `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`.

### Behind a reverse proxy (recommended for non-localhost)

walletrs serves plaintext gRPC. Terminate TLS at a reverse proxy:

```caddyfile
walletrs.example.com {
    reverse_proxy h2c://127.0.0.1:50051
}
```

(Caddy serves HTTP/2 cleartext upstreams via `h2c://`. Traefik / nginx need analogous gRPC configuration.) Native TLS on the gRPC layer is not in v0.1.0.

## Configuration

Every knob is an environment variable; there is no config file.

| Variable | Default | Required when | Notes |
|---|---|---|---|
| `WALLETRS_HOST` | `127.0.0.1` | always | gRPC bind host. Use `0.0.0.0` inside containers. |
| `WALLETRS_PORT` | `50051` | always | |
| `BITCOIN_NETWORK` | `regtest` | always | `mainnet` / `testnet` / `signet` / `regtest` |
| `ELECTRS_URL` | `tcp://127.0.0.1:60401` | always | Electrum-Rust server URL |
| `WALLETRS_STORAGE_KIND` | `local` | always | `local` or `s3` |
| `WALLETRS_STORAGE_PATH` | `./data` | local-only | filesystem root |
| `WALLETRS_S3_ENDPOINT` | — | s3 | leave unset for AWS S3, set for R2 / MinIO |
| `WALLETRS_S3_BUCKET` | — | s3 | |
| `WALLETRS_S3_REGION` | `auto` | s3 | R2 takes `auto`; AWS takes the actual region name |
| `WALLETRS_S3_ACCESS_KEY_ID` | — | s3 | |
| `WALLETRS_S3_SECRET_ACCESS_KEY` | — | s3 | |
| `WALLETRS_S3_PREFIX` | — | s3 | object-key namespace inside the bucket |
| `WALLETRS_S3_FORCE_PATH_STYLE` | `true` | s3 | required for MinIO; safe for R2 |
| `WALLETRS_KEK` | — | system-keys | base64 32-byte envelope KEK |
| `WALLETRS_AUTH_TOKEN` | — | optional | bearer token for gRPC; auto-generated when unset |
| `WALLETRS_AUTH_DISABLED` | `0` | optional | disables auth entirely |
| `RUST_LOG` | `info,walletrs=debug` | optional | |

## Storage backends

### Local filesystem

`WALLETRS_STORAGE_KIND=local` plus `WALLETRS_STORAGE_PATH=/some/dir`. Wallet state, managed keys, and PSBTs all live under that directory. Back this up.

### S3 / R2 / MinIO

`WALLETRS_STORAGE_KIND=s3` plus the `WALLETRS_S3_*` family. Two reasons to prefer this in production:

- The `R2BackedStore` uploads the BDK file_store on every `wallet.persist()`, so a container can be ephemeral — restart, pull state from object storage, keep going.
- Encrypted blobs at rest: even if an attacker exfiltrates the bucket, they need `WALLETRS_KEK` to read system-managed key material.

Cloudflare R2 example:

```bash
WALLETRS_STORAGE_KIND=s3
WALLETRS_S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
WALLETRS_S3_BUCKET=walletrs-prod
WALLETRS_S3_REGION=auto
WALLETRS_S3_ACCESS_KEY_ID=...
WALLETRS_S3_SECRET_ACCESS_KEY=...
WALLETRS_S3_PREFIX=mainnet
WALLETRS_S3_FORCE_PATH_STYLE=true
```

The pinned `BehaviorVersion` in `crates/server/src/storage/s3.rs` works around an AWS SDK regression where `x-amz-checksum-*` headers got added to mutating requests, breaking R2 / MinIO compatibility. Don't downgrade the AWS SDK without re-validating.

## Authentication

Three modes for the gRPC bearer token:

1. **Operator-supplied** — set `WALLETRS_AUTH_TOKEN`. Recommended for production so you can rotate independently from the binary lifecycle.
2. **Auto-generated** — leave `WALLETRS_AUTH_TOKEN` unset. walletrs generates a hex-encoded 32-byte token at startup, prints it once with the prefix `STORE THIS — generated auth token: <token>`, and enforces it from there.
3. **Disabled** — `WALLETRS_AUTH_DISABLED=1`. Bypasses the interceptor entirely. Acceptable for trusted local environments (loopback only) but never for anything internet-reachable.

`Ping` always bypasses auth so liveness probes don't need the token.

To rotate a token:

1. Generate a new one and stash it.
2. Update clients to send the new one.
3. Restart walletrs with the new `WALLETRS_AUTH_TOKEN`.

The token is checked in constant time (`subtle::ConstantTimeEq`).

## Envelope KEK rotation

`WALLETRS_KEK` is a base64-encoded 32-byte key that wraps system-managed private key material. Customer keys (xpub-only) don't use the KEK.

There is no built-in rotation flow today. The pragmatic procedure:

1. Stop walletrs.
2. Decrypt every `StoredManagedKey` blob in the store with the old KEK (e.g. via a one-off script using `crates/server/src/storage/crypto.rs`).
3. Re-encrypt under the new KEK.
4. Set the new `WALLETRS_KEK` and start.

Rotation as a first-class flow is on the roadmap. Until then, treat the KEK as a long-lived secret and store it in your secrets manager (AWS KMS, GCP KMS, HashiCorp Vault, 1Password Connect).

If you lose the KEK, system-managed private material is unrecoverable — wallets remain valid for receive-only use, but signing requires re-creating new system keys and migrating funds.

## Backups

What to back up:

- **`WALLETRS_KEK`** — without it, system-managed keys are dead weight. Highest-criticality secret; offsite, encrypted, multiple copies.
- **The storage tier** — local filesystem under `WALLETRS_STORAGE_PATH`, or the S3/R2 bucket. Snapshot daily for the first week, weekly after that.
- **Customer xpubs** — these are also stored in the wallet bucket but you should keep an out-of-band record so you can re-create wallets if storage is destroyed.
- **`proto/walletrpc.proto` at the version your clients depend on** — pinned via tag in the walletrs git history.

What you don't need to back up:

- The walletrs binary itself (rebuild from source / pull image).
- The auth token (regenerate; just push a new value to clients).

## Logs and observability

- `RUST_LOG=info,walletrs=debug` is the default. Crank to `walletrs=trace` for verbose PSBT and BDK logs while debugging signing flows.
- Structured logging is not yet in place — output is human-readable env_logger format. JSON logs are on the roadmap.
- No built-in metrics. Use a sidecar gRPC reflection scraper or front the service with an Envoy / Linkerd proxy if you need per-RPC latency histograms.

## Network upgrades

Walletrs follows BDK + miniscript + bitcoin crate versions. When Bitcoin Core ships a soft fork that changes descriptor semantics (rare), check the release notes of those upstream crates and update.

For walletrs version pinning:

- Pin a specific tag (`ghcr.io/n1rna/walletrs:0.1.0`) in production, not `:latest`.
- Subscribe to GitHub releases to get notifications on new tags.
- The `proto/walletrpc.proto` contract is additive in the spirit of semver: new RPCs / fields land without removing old ones inside a minor series.
