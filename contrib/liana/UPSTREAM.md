# contrib/liana — Vendored upstream

This directory is a snapshot of the [Liana](https://github.com/wizardsardine/liana) wallet library by Wizardsardine. We vendor it instead of depending on `crates.io` because the upstream stopped publishing releases there after `v5.0.0`, and walletrs needs `v12.x` features (taproot policy compilation, `update_psbt_in` leaf-hash extraction).

## Pin

- **Upstream:** https://github.com/wizardsardine/liana
- **Pinned version:** `v12.0` (matches `Cargo.toml`'s `version = "12.0.0"` field)
- **Last sync:** 2026-04-25
- **License:** BSD-3-Clause — see `LICENCE` in this directory

## Local modifications

None. The Rust source is upstream `v12.0` verbatim.

## Rebase procedure

When pulling in a newer upstream release:

```bash
# From the walletrs repo root
UPSTREAM_TAG=v13.0
TMP=$(mktemp -d)
git clone --depth 1 --branch ${UPSTREAM_TAG} https://github.com/wizardsardine/liana.git ${TMP}

# Replace src + LICENCE
rm -rf contrib/liana/src
cp -r ${TMP}/src contrib/liana/src
cp ${TMP}/LICENCE contrib/liana/LICENCE
cp ${TMP}/Cargo.toml contrib/liana/Cargo.toml

# Bump version pin in this file, then run the test suite
cargo test --workspace
```

If we ever need a local patch, fork to a separate `n1rna/liana-fork` repo and depend via git tag — do not modify the vendored copy in place.

## Why this lives in `contrib/`

Cargo workspaces let third-party-but-modified crates live anywhere in the tree; `contrib/` is a long-standing convention for vendored deps that aren't first-party but ship with the binary. Keeps the BSD-3-Clause attribution scope visually separate from the dual MIT-Apache-2.0 license that covers the rest of the repo.
