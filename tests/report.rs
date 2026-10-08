//! End-to-end tests of the report written at the end of `memwatch run` and
//! rebuilt by `memwatch report`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use memwatch::meta::EndReason;
use memwatch::options::RunOptions;
use memwatch::sampler::StopHandle;
use tempfile::TempDir;

/// Path of the memwatch binary built by Cargo for these tests.
const MEMWATCH: &str = env!("CARGO_BIN_EXE_memwatch");

/// Path of the fixture binary built by Cargo for these tests.
const FIXTURE: &str = env!("CARGO_BIN_EXE_memwatch-fixture");

/// Builds the command line that starts the fixture with `args`.
fn fixture_command(args: &[&str]) -> Vec<OsString> {
    let mut command = vec![OsString::from(FIXTURE)];
    command.extend(args.iter().map(OsString::from));
    command
}

/// Builds options for a run of the fixture into `out_dir`.
fn fixture_options(out_dir: &Path, command: Vec<OsString>) -> RunOptions {
    RunOptions {
        name: "fixture".to_string(),
        out_dir: out_dir.to_path_buf(),
        labels: BTreeMap::new(),
        interval: Duration::from_secs(1),
        duration: None,
        gpu_interval: Duration::from_secs(2),
        cdp_interval: Duration::from_secs(10),
        cdp_port: None,
        allow_sleep: true,
        command,
    }
}

/// Returns the only run directory under `out`.
fn single_run_dir(out: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = fs::read_dir(out)
        .expect("the output directory must be readable")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    assert_eq!(
        dirs.len(),
        1,
        "exactly one run directory must exist: {dirs:?}"
    );
    dirs.pop().expect("the run directory must be found")
}

/// Waits until the first run directory appears under `out`.
fn wait_for_run_dir(out: &Path, timeout: Duration) -> PathBuf {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(entries) = fs::read_dir(out) {
            let mut dirs: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect();
            dirs.sort();
            if let Some(dir) = dirs.into_iter().next() {
                return dir;
            }
        }
        assert!(
            Instant::now() < deadline,
            "a run directory must appear within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Reads `report.md` of a run directory.
fn read_report(run_dir: &Path) -> String {
    fs::read_to_string(run_dir.join("report").join("report.md"))
        .expect("report.md must be readable")
}

/// Reads `meta.json` into a JSON value.
fn read_meta(run_dir: &Path) -> serde_json::Value {
    let content =
        fs::read_to_string(run_dir.join("meta.json")).expect("meta.json must be readable");
    serde_json::from_str(&content).expect("meta.json must be valid JSON")
}

#[test]
fn run_writes_report_after_finishing() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&[
        "--duration",
        "5s",
        "--alloc-mb-per-sec",
        "20",
        "--gdi",
        "50",
        "--busy-ms-per-sec",
        "200",
    ]);

    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg("auto")
        .arg("--out")
        .arg(&out)
        .arg("--")
        .args(&fixture);
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("memwatch must run");
    assert_eq!(status.code(), Some(0), "the fixture run must exit with 0");

    let run_dir = single_run_dir(&out);
    let meta = read_meta(&run_dir);
    assert_eq!(
        meta["end_reason"], "app_exited",
        "the fixture must end by itself"
    );

    let report = read_report(&run_dir);
    for expected in [
        "# Run auto",
        "## Warnings",
        "## Tree summary",
        "| Private bytes |",
        "## Roles",
        "## Processes",
        "- **End reason**: app_exited",
    ] {
        assert!(
            report.contains(expected),
            "the report must contain `{expected}`:\n{report}"
        );
    }
}

#[test]
fn run_honours_language() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "60s"]);

    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg("auto-ru")
        .arg("--out")
        .arg(&out)
        .args(["--lang", "ru", "--duration", "3s", "--"])
        .args(&fixture);
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("memwatch must run");
    assert_eq!(status.code(), Some(0), "the timed run must exit with 0");

    let run_dir = single_run_dir(&out);
    let report = read_report(&run_dir);
    for expected in [
        "# Прогон auto-ru",
        "## Предупреждения",
        "## Итоги по дереву",
        "| Метрика | Старт |",
    ] {
        assert!(
            report.contains(expected),
            "the report must contain `{expected}`:\n{report}"
        );
    }
}

#[test]
fn report_command_rebuilds_a_run() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "3s"]);

    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg("rebuild")
        .arg("--out")
        .arg(&out)
        .arg("--")
        .args(&fixture);
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("memwatch must run");
    assert_eq!(status.code(), Some(0), "the fixture run must exit with 0");

    let run_dir = single_run_dir(&out);
    let report_dir = run_dir.join("report");
    assert!(
        report_dir.join("report.md").is_file(),
        "the run must build the report by itself"
    );
    fs::remove_dir_all(&report_dir).expect("the report directory must be removable");

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report command must exit with 0"
    );

    let path = report_dir.join("report.md");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&path.display().to_string()),
        "stdout must name the report path: {stdout}"
    );
    assert!(path.is_file(), "the report must be rebuilt");
}

#[test]
fn report_command_builds_report_of_stopped_run() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(&out, fixture_command(&["--duration", "60s"]));
    let stop = StopHandle::new();
    let stopper = stop.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        stopper.stop();
    });

    let outcome = memwatch::run(&options, stop).expect("the run must finish");
    assert_eq!(
        outcome.end_reason,
        EndReason::CtrlC,
        "the stop handle must end the run as Ctrl+C"
    );

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report command must exit with 0"
    );

    let report = read_report(&outcome.run_dir);
    assert!(
        report.contains("- **End reason**: ctrl_c"),
        "the report must record the stop:\n{report}"
    );
}

#[test]
fn report_notes_missing_optional_files() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(&out, fixture_command(&["--duration", "3s"]));
    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");

    for file in ["gpu.csv", "cdp.csv"] {
        fs::remove_file(outcome.run_dir.join(file)).expect("the optional file must be removable");
    }

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a run without optional files must still report"
    );

    let report = read_report(&outcome.run_dir);
    assert!(
        report.contains("no data"),
        "missing metrics must be marked:\n{report}"
    );
    for warning in [
        "- no data: missing file gpu.csv",
        "- no data: missing file cdp.csv",
    ] {
        assert!(
            report.contains(warning),
            "the report must contain `{warning}`:\n{report}"
        );
    }
}

#[test]
fn report_rejects_incompatible_schema() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(&out, fixture_command(&["--duration", "3s"]));
    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");

    let meta_path = outcome.run_dir.join("meta.json");
    let mut meta = read_meta(&outcome.run_dir);
    meta["schema_version"] = serde_json::json!(2);
    fs::write(
        &meta_path,
        serde_json::to_vec_pretty(&meta).expect("meta.json must serialize"),
    )
    .expect("meta.json must be writable");

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(1),
        "an incompatible schema must exit with 1"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("schema_version"),
        "the error must name the field: {stderr}"
    );
    assert!(
        stderr.contains('2'),
        "the error must name the found version: {stderr}"
    );
}

#[test]
fn report_bad_arguments_exit_with_two() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let run_dir = dir.path().join("run");

    for args in [["--warmup", "0s"], ["--lang", "de"]] {
        let output = Command::new(MEMWATCH)
            .arg("report")
            .arg(&run_dir)
            .args(args)
            .output()
            .expect("memwatch must run");
        assert_eq!(output.status.code(), Some(2), "`{args:?}` must exit with 2");
    }
}

#[test]
fn report_command_honours_language() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(&out, fixture_command(&["--duration", "3s"]));
    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .args(["--lang", "ru"])
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report command must exit with 0"
    );

    let report = read_report(&outcome.run_dir);
    for expected in [
        "# Прогон",
        "## Предупреждения",
        "## Итоги по дереву",
        "| Метрика | Старт |",
        "## Роли",
        "## Процессы",
    ] {
        assert!(
            report.contains(expected),
            "the report must contain `{expected}`:\n{report}"
        );
    }
    assert!(
        !report.contains("## Warnings"),
        "the English headings must be gone:\n{report}"
    );
}

#[test]
fn report_omits_command_lines() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(
        &out,
        fixture_command(&["--duration", "3s", "--echo-env", "cmdline-secret-marker"]),
    );
    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");

    let meta = read_meta(&outcome.run_dir);
    assert!(
        meta["command"]
            .to_string()
            .contains("cmdline-secret-marker"),
        "the marker must be recorded in meta.command: {}",
        meta["command"]
    );

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report command must exit with 0"
    );

    let report = read_report(&outcome.run_dir);
    assert!(
        !report.contains("cmdline-secret-marker"),
        "command lines must not leak into the report:\n{report}"
    );
    assert!(
        report.contains("memwatch-fixture.exe"),
        "the executable basename must be listed:\n{report}"
    );
    assert!(
        !report.contains(FIXTURE),
        "only the basename may appear, not the full path:\n{report}"
    );
}

#[test]
fn run_keeps_exit_code_when_report_fails() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "60s"]);

    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg("auto-fail")
        .arg("--out")
        .arg(&out)
        .arg("--duration")
        .arg("6s")
        .arg("--")
        .args(&fixture);
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("memwatch must start");

    let run_dir = wait_for_run_dir(&out, Duration::from_secs(30));
    fs::write(run_dir.join("report"), "not a directory")
        .expect("the report path must be turned into a file");

    let output = child.wait_with_output().expect("memwatch must be reaped");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a failed report must not change the run outcome"
    );

    assert!(
        !run_dir.join("report").join("report.md").exists(),
        "the report must not be written"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot build the report"),
        "the failure must be reported on stderr: {stderr}"
    );
    let log =
        fs::read_to_string(run_dir.join("memwatch.log")).expect("memwatch.log must be readable");
    assert!(
        log.contains("cannot build the report"),
        "the failure must reach the journal:\n{log}"
    );
}
