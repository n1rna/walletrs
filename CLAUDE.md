# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repo.

## Project

`walletrs` is a standalone gRPC service for advanced Bitcoin wallets — multisig, miniscript / Liana policies, taproot leaf-hash spends, PSBT lifecycle. Built on BDK + rust-miniscript with a vendored fork of Liana for primary/recovery descriptor compilation.

It was extracted from a larger application (sigvault) and is intended as an open-source service that any operator can deploy.

## Repo layout

```
walletrs/
├── crates/server/    # main binary + library — package name `walletrs`
├── contrib/liana/    # vendored upstream wizardsardine/liana — see UPSTREAM.md
├── proto/            # walletrpc.proto — single source of truth for the gRPC contract
├── docs/             # operator + integrator docs
└── README.md
```

The two cargo workspace members are `crates/server` and `contrib/liana`. Everything else is documentation, license, or build configuration.

## Common commands

```bash
cargo build                           # compile everything
cargo test --workspace                # run all tests
cargo build --release --bin walletrs  # release binary
cargo clippy --lib                    # lint the server lib
cargo fmt                             # format
```

When the proto changes, rerun `cargo build` — `crates/server/build.rs` invokes `tonic_build::compile_protos` and emits Rust stubs into `OUT_DIR`.

## Architecture pointers

- `crates/server/src/wallet/advanced/` — wallet-creation pipeline (`spec → classify → shape → descriptor → bdk → taproot metadata`). The clean entrypoint is `advanced::build_wallet`.
- `crates/server/src/wallet/signer/` — PSBT signing + leaf-hash → policy-path resolution.
- `crates/server/src/wallet/service/` — gRPC handlers for `WalletService` RPCs.
- `crates/server/src/storage/` — pluggable backend (local FS or S3-compatible) with envelope-encrypted managed keys.
- `crates/server/src/config.rs` — env-var loader; one struct, one `Lazy` static.

## Conventions

- No code comments unless the *why* is non-obvious.
- Errors at module boundaries; `unwrap` only in tests or genuinely-unreachable paths.
- gRPC contract changes go through `proto/walletrpc.proto` first, then the Rust handlers.
- Vendored Liana stays unmodified — see `contrib/liana/UPSTREAM.md` for the rebase procedure.

## Status

Pre-1.0. The roadmap toward `v0.1.0` (auth interceptor, Dockerfile, CI, full docs) is tracked as issues / PRs in this repo.
