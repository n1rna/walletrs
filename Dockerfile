# syntax=docker/dockerfile:1.7
#
# walletrs production image — cargo-chef baked into a persistent layer so
# CI cache stores stay warm across runs.
#
#   cold  (no cache):   ~10 min  (all deps + walletrs compile)
#   warm  (deps reused): ~1-2 min (only walletrs compiles)

ARG RUST_VERSION=1.91

FROM rust:${RUST_VERSION}-bookworm AS chef
RUN cargo install cargo-chef --locked --version ^0.1
WORKDIR /usr/src/app

RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

# ── Planner: compute the dep graph into recipe.json ──────────────────────
# Invalidates only when a Cargo.toml / Cargo.lock / member manifest changes.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY contrib ./contrib
COPY proto ./proto
RUN cargo chef prepare --recipe-path /tmp/recipe.json

# ── Cacher: compile every external dep listed in the recipe ──────────────
# Workspace member sources are stubbed out by chef; build.rs still runs and
# needs `proto/` plus a real Liana manifest, so both are copied here.
FROM chef AS cacher
COPY --from=planner /tmp/recipe.json /tmp/recipe.json
COPY Cargo.toml Cargo.lock ./
COPY crates/server/Cargo.toml ./crates/server/Cargo.toml
COPY crates/server/build.rs ./crates/server/build.rs
COPY contrib ./contrib
COPY proto ./proto
RUN cargo chef cook --release --recipe-path /tmp/recipe.json

# ── Builder: compile walletrs on top of the cached deps ──────────────────
# `cargo clean -p walletrs` invalidates the stub-source artifacts cargo-chef
# left behind in the cacher stage so build.rs is forced to re-run with the
# real source — without this, OUT_DIR points at a hash that never wrote
# walletrpc.rs and `tonic::include_proto!` fails.
FROM cacher AS builder
COPY crates/server/src ./crates/server/src
RUN cargo clean -p walletrs \
 && cargo build --release --bin walletrs \
 && cp target/release/walletrs /usr/local/bin/walletrs

# ── Runtime ──────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS production
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/local/bin/walletrs ./walletrs

EXPOSE 50051
ENV WALLETRS_HOST=0.0.0.0 \
    WALLETRS_PORT=50051 \
    WALLETRS_STORAGE_PATH=/data \
    RUST_LOG=info,walletrs=debug

VOLUME ["/data"]
CMD ["./walletrs"]
