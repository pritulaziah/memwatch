# AGENTS.md

## Scope

- Treat `memwatch` as a standalone Cargo repository, not part of the enclosing
  `sciter-adguard-ui` workspace; parent UI/Deskview commands do not apply.
- Use Windows for builds/tests: Win32 and `std::os::windows` are unconditional.
  Use Rust 1.96 from `rust-toolchain.toml` (edition 2024).

## Commands

Run from this directory; `Cargo.lock` is committed.

```powershell
cargo build --locked
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked

# Focused checks: library, CLI parsing, one integration target, one test
cargo test --locked --lib
cargo test --locked --bin memwatch
cargo test --locked --test report
cargo test --locked --test report report_omits_command_lines
```

- Integration tests build `memwatch-fixture` and spawn real Windows process
  trees; allow tens of seconds. CDP tests use loopback mock servers,
  not a running browser. GPU counters may be `unavailable`.
- To capture a short run or rebuild a report:

```powershell
cargo run --locked -- run --name sample --duration 30s --warmup 1s -- app.exe
cargo run --locked -- report 'runs\sample-YYYYMMDD-HHMMSS' --lang ru --warmup 1s
```

Reports default to a **10-minute warmup**; override it for short measurements.
All CLI durations must be positive, including warmup: `--warmup 0s` is rejected.
Rebuilds overwrite `<run-dir>/report/report.md`; use `--out <dir>` to redirect.

## Code Flow

- Capture: `src/main.rs` / `src/options.rs` validate CLI input, `src/sampler.rs`
  orchestrates `src/launch.rs` and `src/collect/`, and `src/store.rs` /
  `src/meta.rs` persist six CSVs and `meta.json`.
- Reporting: `src/analyze.rs` loads saved runs and computes statistics;
  `src/report.rs` renders English/Russian Markdown. `run` invokes reporting
  best-effort after capture; report failure must not change the run exit code.
- `src/bin/memwatch-fixture.rs` is the test load generator, not the product CLI.
  `runs/` is ignored measurement output; regenerate reports rather than editing
  generated Markdown.

## Behavioral Contracts

- Preserve suspended launch into a `KILL_ON_JOB_CLOSE` Job Object: dropping or
  killing memwatch must clean up the launched tree. CLI exit codes describe the
  run outcome, not the child's exit code (`tests/cli.rs`, `tests/launch.rs`).
- Keep collector source failures distinct from write failures
  (`src/collect/mod.rs`): ten successive source failures disable the collector;
  a run-directory write failure stops the run.
- Keep CSV headers/order (`src/store.rs`) and metadata (`src/meta.rs`) in sync
  with readers and tests. The reader accepts schema version 1 only; preserve
  legacy-run coverage in `tests/report.rs` when extending the format.
- Identify processes by `proc_key` (`<pid>-<creation filetime>`), not PID alone;
  PID reuse must not merge lifetimes or allow termination of a replacement.
- Keep missing counters as empty CSV cells / `None` / report `no data`, not
  zero. Real zero is valid. Never fill absent legacy kernel counters with
  sampled estimates.
- Keep kernel lifetime peaks separate from sampled role/tree maxima; do not sum
  lifetime peaks. Report CDP targets separately, never as a summed total.
- Update both report languages when changing output. Keep command lines, image
  paths, and raw CDP protocol failure details out of generated reports.
- GPU/CDP intervals must be whole multiples of the base interval (defaults:
  2s/10s versus 500ms). `--cdp-port` replaces the child's
  `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` with the remote-debugging flag;
  collector connections must stay loopback-only.
