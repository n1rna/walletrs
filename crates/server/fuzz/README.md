# walletrs fuzz targets

Coverage-guided fuzzing for the parsers that take untrusted input in walletrs:
PSBT, Bitcoin address, Liana descriptor, miniscript Concrete policy.

This crate is a deliberately-separate workspace member (excluded from the
root `[workspace]`) because it depends on `libfuzzer-sys`, which requires
the nightly toolchain.

## One-time setup

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Running a target

From `crates/server/fuzz`:

```bash
cargo +nightly fuzz run psbt
cargo +nightly fuzz run address
cargo +nightly fuzz run descriptor
cargo +nightly fuzz run miniscript_policy
```

Pass `-- -max_total_time=60` to time-box a run (useful in CI smoke
tests):

```bash
cargo +nightly fuzz run psbt -- -max_total_time=60
```

When a crash is found, libFuzzer writes a reproducer file to
`fuzz/artifacts/<target>/crash-…`. Replay it with:

```bash
cargo +nightly fuzz run psbt fuzz/artifacts/psbt/crash-<hash>
```

## CI

The root workflow runs `cargo check` on this crate (compilation only) so
the targets don't bit-rot. Actual fuzz runs are not part of CI by default
— they are intended for periodic local / nightly runs.

## Adding a target

1. Add a `fuzz_targets/<name>.rs` containing a `fuzz_target!` macro
   invocation.
2. Add a corresponding `[[bin]]` entry to `Cargo.toml`.
3. Document the target's purpose in a header doc comment.
