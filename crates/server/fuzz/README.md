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

## Seed corpora

Each target ships with a small hand-curated seed corpus under
`fuzz/corpus/<target>/`. Inputs range from "just the magic prefix"
to "small valid example" — enough to give libFuzzer's coverage-guided
mutator a head start on each parser's interesting code paths.

Adding new seeds is just a matter of dropping a file in the right
directory. Use one-input-per-file; no extension is needed. Keep
seeds short — libFuzzer mutates from them, so larger isn't better.

When the nightly workflow grows the corpus (via libFuzzer's
coverage-guided synthesis), the expanded set is uploaded as an
artifact (`fuzz-corpus-<target>-<run_id>`) and retained for 7 days
so it can be downloaded and committed if particularly interesting
inputs surface.

## CI

Two workflows:

- **`ci.yml`** (`fuzz-check` job) runs `cargo check --bins` against
  this crate on every PR using the nightly toolchain. This catches
  bit-rot in the target definitions without paying for an actual
  fuzz run on every PR.
- **`fuzz.yml`** runs every fuzz target for ~10 minutes nightly
  (04:00 UTC) on a `cron` schedule, and also via the Actions UI
  "Run workflow" button (`workflow_dispatch`). Crashes are
  surfaced as red workflow status plus an uploaded reproducer
  artifact. To trigger a longer ad-hoc fuzz run:

  ```text
  Actions → Nightly fuzz → Run workflow → max_total_time: 3600
  ```

## Adding a target

1. Add a `fuzz_targets/<name>.rs` containing a `fuzz_target!` macro
   invocation.
2. Add a corresponding `[[bin]]` entry to `Cargo.toml`.
3. Document the target's purpose in a header doc comment.
