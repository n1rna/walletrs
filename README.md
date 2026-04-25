# walletrs

A standalone gRPC service for advanced Bitcoin wallets — multisig, miniscript policies, taproot leaf-hash spends, PSBT lifecycle.

Built on top of [BDK](https://github.com/bitcoindevkit/bdk) and [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript).

> **Status:** pre-1.0. The gRPC contract (`proto/walletrpc.proto`) is stable in spirit but may still gain fields. Track the [CHANGELOG](CHANGELOG.md) before integrating.

## What it does

- Creates Bitcoin wallets from declarative spending conditions (single sig, sortedmulti, taproot multisig with NUMS internal key, primary + time-locked recovery policies).
- Manages keys: imports customer xpubs, generates system keys with envelope-encrypted private material, signs PSBTs from stored keys.
- Funds, signs, finalizes, and broadcasts transactions over gRPC.
- Resolves taproot leaf hashes back to BDK policy paths so clients can pick which spending path to use.
- Stores wallet state on local disk or S3-compatible object storage (Cloudflare R2, MinIO, AWS S3).

## What it does not do

- Multi-tenancy. One walletrs instance serves one logical owner; deploy multiple instances if you need tenant isolation.
- TLS termination. Run it behind a reverse proxy (Caddy, Traefik, nginx) when exposing it across a network boundary.
- Hardware wallet integration. The signer flow assumes managed keys live in walletrs' encrypted store. HWW signing is the client's job.

## Quickstart

> Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Operating: [`docs/OPERATING.md`](docs/OPERATING.md). Client integration: [`docs/INTEGRATING.md`](docs/INTEGRATING.md). Security: [`SECURITY.md`](SECURITY.md).

### With Docker (recommended)

The included `docker-compose.yml` brings up bitcoind + electrs + walletrs in regtest:

```bash
docker compose up --build
```

walletrs listens on `127.0.0.1:50051`. The first boot logs a `STORE THIS — generated auth token: <token>` line; copy that into your client's bearer-auth config. Pin a fixed token by setting `WALLETRS_AUTH_TOKEN` in a `.env` next to the compose file.

For mainnet, signet, or testnet: edit the `bitcoind` service flags + `electrs --network` arg + `BITCOIN_NETWORK` env to match.

### From source

```bash
cargo build --release --bin walletrs

WALLETRS_HOST=127.0.0.1 \
WALLETRS_PORT=50051 \
BITCOIN_NETWORK=regtest \
ELECTRS_URL=tcp://127.0.0.1:60401 \
WALLETRS_STORAGE_KIND=local \
WALLETRS_STORAGE_PATH=./data \
RUST_LOG=info,walletrs=debug \
./target/release/walletrs
```

The service generates a bearer auth token at first startup and prints it once with a `STORE THIS` prefix unless you provide `WALLETRS_AUTH_TOKEN` or set `WALLETRS_AUTH_DISABLED=1`.

## Configuration

| Variable | Default | Required | Notes |
|---|---|---|---|
| `WALLETRS_HOST` | `127.0.0.1` | yes | gRPC bind host |
| `WALLETRS_PORT` | `50051` | yes | |
| `BITCOIN_NETWORK` | `regtest` | yes | `mainnet` / `testnet` / `signet` / `regtest` |
| `ELECTRS_URL` | `tcp://127.0.0.1:60401` | yes | Electrum / Electrs server URL |
| `WALLETRS_STORAGE_KIND` | `local` | yes | `local` or `s3` |
| `WALLETRS_STORAGE_PATH` | `./data` | local-only | filesystem root for wallet data |
| `WALLETRS_S3_*` | — | s3-only | endpoint, bucket, region, creds, prefix, force_path_style |
| `WALLETRS_KEK` | — | system-keys | base64 32-byte envelope KEK |
| `WALLETRS_AUTH_TOKEN` | — | optional | bearer token for gRPC; auto-generated when unset |
| `WALLETRS_AUTH_DISABLED` | `0` | optional | disables auth entirely |
| `RUST_LOG` | `info,walletrs=debug` | optional | |

## Repository layout

```
walletrs/
├── crates/
│   └── server/        # main gRPC binary + library
├── contrib/
│   └── liana/
├── proto/
│   └── walletrpc.proto
├── docs/              # ARCHITECTURE, OPERATING, INTEGRATING
├── SECURITY.md
├── LICENSE
└── README.md
```

## License

[BSD 3-Clause](LICENSE).
