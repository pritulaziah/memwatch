# memwatch

A Windows command-line tool for developers measuring an application's entire
process tree.

memwatch launches an application, records its resource usage, and generates a
Markdown report. Counters include memory, CPU, I/O, handles, threads, and GPU
usage where available. For WebView2, it can also collect JavaScript heap and
DOM counters through the Chrome DevTools Protocol (CDP). Reports are available
in English and Russian.

## Get started

Use Windows with [Rust installed through rustup](https://rustup.rs/). The
repository pins Rust 1.96; rustup selects that toolchain automatically.

Build the CLI from source in PowerShell:

```powershell
git clone https://github.com/pritulaziah/memwatch.git
cd memwatch
cargo build --release --locked --bin memwatch
```

## Quick start

From the checkout, record a short process tree using Windows' built-in `cmd.exe`
and `ping.exe`. This example contacts only the local machine and takes about
five seconds:

```powershell
.\target\release\memwatch.exe run --name ping --warmup 1s -- cmd.exe /c ping -n 6 127.0.0.1
```

memwatch prints the run directory under `runs`. Open `report\report.md` inside
that directory to inspect the result. The directory also contains CSV counters,
`meta.json`, application stdout/stderr logs, and `memwatch.log`.

To measure an application, replace the command after `--` with its executable
and arguments. Put memwatch's options before `--`. Use Ctrl+C or add
`--duration 30s` to stop a capture before the application exits.

Reports separate whole-run statistics from statistics after warmup. The default
warmup is **10 minutes**, so the short example uses `--warmup 1s`. CLI durations
must be positive integers with `ms`, `s`, `m`, or `h`; `--warmup 0s` is invalid.

## Usage

Rebuild the latest example's report in Russian without rerunning the app:

```powershell
$run = Get-ChildItem .\runs -Directory -Filter 'ping-*' |
    Sort-Object Name -Descending | Select-Object -First 1
.\target\release\memwatch.exe report $run.FullName --lang ru --warmup 1s
```

Rebuilding overwrites the existing report, not the recorded measurements. Add
`--out .\report-ru` to write `report-ru\report.md` instead. Use `--lang en` for
English output.

For all options and defaults:

```powershell
.\target\release\memwatch.exe run --help
.\target\release\memwatch.exe report --help
```

## Before measuring

- **Stopping memwatch terminates the launched process tree.** This includes
  duration limits and Ctrl+C; do not launch work you need to keep running.
- The application inherits memwatch's working directory. Its stdout/stderr go
  to files in the run directory, and stdin is disconnected from the terminal.
- memwatch keeps the system and display awake by default. Use `--allow-sleep`
  if that is not wanted.
- Unavailable counters stay missing rather than becoming zero. GPU collection
  depends on the machine's available Windows performance counters.
- For WebView2, `--cdp-port` sets a remote-debugging flag in the child's
  `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, replacing any existing value. CDP
  collection connects only to loopback endpoints.
- **Review recordings before sharing them.** Raw metadata, process records,
  and application logs may contain command-line arguments, paths, URLs, or
  other sensitive data. Reports omit command lines and full executable paths,
  but are not a general-purpose redaction mechanism.

## Documentation

- [Repository guidance](AGENTS.md) — build and test commands, code flow, and
  compatibility constraints for contributors and coding agents.
