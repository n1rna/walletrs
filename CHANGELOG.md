# Changelog

All notable changes to this project will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-05-25

### Added

- **Defense-in-depth test sprint across `wallet/service`, `wallet/advanced`, `wallet/signer`.** Eliminated panics on user-controlled input and storage-read paths (address parse, PSBT parse, fingerprint parse, descriptor parse). Built an in-process `WalletService` integration harness (tempdir storage + regtest fixtures) covering all gRPC handlers end-to-end. Added a `CONFIG` test seam so the global config no longer pins test orderings. Net +46 service-layer tests.
- **`proptest` invariants + UTXO-injection lifecycle harness.** Property tests assert structural invariants over descriptor compilation, policy-path enumeration, and PSBT round-trips; a deterministic UTXO-injection harness exercises the full create→fund→sign→broadcast cycle without an external regtest node.
- **`cargo-fuzz` parser targets + seeded corpora + nightly fuzz workflow.** Fuzz targets cover PSBT, descriptor, address, and policy parsers; corpora are checked in under `crates/server/fuzz/corpus/`. `.github/workflows/fuzz.yml` runs the suite nightly on a schedule with budget caps.
- **Supply-chain gates: `cargo-deny`.** License + advisory + ban policy enforced in CI.

### Fixed

- **Storage index race.** Concurrent wallet writes could interleave index updates and leave the index pointing at a half-written wallet payload. Switched to a write-then-rename + lock-scoped index update.

## [0.4.0] - 2026-05-23

### Added

- **HTTP/JSON gateway alongside gRPC.** A new axum server runs on `WALLETRS_HTTP_PORT` (default `8080`) and exposes every RPC at `POST /wallet/<snake_case_method>`. Routes are generated at build time from `(google.api.http)` annotations on `proto/walletrpc.proto` — adding a new RPC requires only the annotation, no Rust glue. JSON encoding uses proto3 semantics via `pbjson` (numeric fields stay numeric, `bytes` is base64). Bearer-token auth is shared with gRPC; the `Ping` RPC bypasses on both surfaces. `tonic::Status` is mapped to standard HTTP status codes with a `{ "code", "message" }` body. Vendored minimal `google/api/{annotations,http}.proto` under `proto/google/api/` to keep the proto compile self-contained.
- **Workspace split into reusable crates.** Pure wallet primitives extracted from `crates/server` into two new crates: `policy-core` (descriptor / policy types, no I/O) and `wallet-runtime` (BDK 1.x runtime + signer + electrum wrapper). `crates/server` now consumes both. Lets downstream Rust integrators depend on the policy + runtime layers without pulling in the gRPC service.
- **Unspendable-primary spending condition.** Primary path can be configured with an unspendable internal xpub (BIP-341-style NUMS construction via `policy-core::unspendable_primary_xpub`), forcing all spends through the recovery path while preserving descriptor shape.
- **Spending-path enumeration helper** in `wallet-runtime` for inspecting which policy paths a given PSBT could satisfy.

### Changed

- **Renamed Liana-flavored internals to `TimelockedPolicy`.** Public-facing types now reflect the generic shape rather than the upstream vendor name; the proto contract is unchanged.

### Fixed

- Release workflow installs `libprotobuf-dev` so `tonic_build` can locate well-known proto types on the GitHub-hosted runner.

## [0.3.0] - 2026-04-27

### Changed

- **Sigvault agent transport switched from gRPC bidi streaming to HTTP + WebSocket.** `Pair` is `POST /api/v2/walletrs/agent/pair`; the operation stream is `WS /api/v2/walletrs/agent/connect`. The JSON envelope wraps prost-encoded operation payloads (no double-encoding of walletrpc messages). Drops the `WalletrsAgent` gRPC service from `proto/walletrpc.proto`; agent message types now live as serde structs in `crates/server/src/agent/wire.rs`. Reasoning: lets sigvault's broker live as a regular FastAPI route inside the existing api process — no second port, no `grpc.aio` runtime, no separate broker container. Walletrs gains `reqwest` + `tokio-tungstenite` + `futures-util` + `url` deps and drops `tokio-stream`. Default sigvault endpoint flipped from `https://api.sigvault.example` to `https://api.sigvault.org`.

## [0.2.0] - 2026-04-25

### Added

- **Sigvault agent (BYO walletrs).** Outbound reverse-tunnel client that lets a user-hosted walletrs instance pair with a cloud sigvault deployment. Pairing via one-shot token (`--sigvault-token` / `WALLETRS_SIGVAULT_TOKEN`) generates a local Ed25519 keypair (private key envelope-encrypted under `WALLETRS_KEK`) and exchanges it for a stable `agent_id`. Persistent stream re-authenticates on every reconnect via signed challenge nonce. Operations from sigvault are dispatched through the same internal handlers as the local gRPC server — no parallel codegen path. Ships disabled by default; existing standalone deployments are unaffected.
- Bearer-token gRPC auth interceptor (`Authorization: Bearer <token>`); auto-generates a token at first boot when `WALLETRS_AUTH_TOKEN` is unset and logs it once with a `STORE THIS` prefix. `WALLETRS_AUTH_DISABLED=1` opts out.
- Multi-stage `Dockerfile` (cargo-chef) producing a `debian:bookworm-slim` runtime image.
- `docker-compose.yml` regtest stack (`lncm/bitcoind:v25.0` + `mempool/electrs:latest` + walletrs).
- GitHub Actions: CI (`fmt`, `clippy`, `test`, docker build) on every push/PR; release workflow (Linux x86_64 + macOS x86_64/arm64 binaries + multi-arch Docker push to GHCR) on `v*` tags.
- Documentation: `docs/ARCHITECTURE.md`, `docs/OPERATING.md`, `docs/INTEGRATING.md`, top-level `SECURITY.md`.

### Changed

- Repository extracted from the `sigvault` monorepo. Cargo workspace at the root with `crates/server` (the gRPC binary + library) and `contrib/liana`. The proto contract lives at `proto/walletrpc.proto` as the single source of truth.
- License: BSD-3-Clause (single `LICENSE` file).

[0.5.0]: https://github.com/n1rna/walletrs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/n1rna/walletrs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/n1rna/walletrs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/n1rna/walletrs/compare/v0.1.0...v0.2.0
