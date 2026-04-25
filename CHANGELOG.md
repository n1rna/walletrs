# Changelog

All notable changes to this project will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Bearer-token gRPC auth interceptor (`Authorization: Bearer <token>`); auto-generates a token at first boot when `WALLETRS_AUTH_TOKEN` is unset and logs it once with a `STORE THIS` prefix. `WALLETRS_AUTH_DISABLED=1` opts out.
- Multi-stage `Dockerfile` (cargo-chef) producing a `debian:bookworm-slim` runtime image.
- `docker-compose.yml` regtest stack (`lncm/bitcoind:v25.0` + `mempool/electrs:latest` + walletrs).
- GitHub Actions: CI (`fmt`, `clippy`, `test`, docker build) on every push/PR; release workflow (Linux x86_64 + macOS x86_64/arm64 binaries + multi-arch Docker push to GHCR) on `v*` tags.
- Documentation: `docs/ARCHITECTURE.md`, `docs/OPERATING.md`, `docs/INTEGRATING.md`, top-level `SECURITY.md`.

### Changed

- Repository extracted from the `sigvault` monorepo. Cargo workspace at the root with `crates/server` (the gRPC binary + library) and `contrib/liana`. The proto contract lives at `proto/walletrpc.proto` as the single source of truth.
- License: BSD-3-Clause (single `LICENSE` file).

[Unreleased]: https://github.com/n1rna/walletrs/compare/v0.1.0...HEAD
