//! Integration tests for the run lifecycle: ticks, stop conditions and the
//! finished run directory.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use memwatch::meta::EndReason;
use memwatch::options::{RunOptions, run_dir_name};
use memwatch::sampler::StopHandle;
use memwatch::win::ProcHandle;
use tempfile::TempDir;
use time::OffsetDateTime;

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
        allow_sleep: true,
        command,
    }
}

/// One row of `process.csv` as read by the tests.
#[derive(Debug, serde::Deserialize)]
struct ProcessRow {
    /// Process role.
    role: String,
    /// Private commit in bytes; empty when unavailable.
    private_bytes: Option<u64>,
    /// CPU usage of the whole machine; empty for the first sample.
    cpu_pct: Option<String>,
    /// GDI objects.
    gdi: Option<u64>,
}

/// One row of `processes.csv` as read by the tests.
#[derive(Debug, serde::Deserialize)]
struct EventRow {
    /// `start` or `exit`.
    event: String,
    /// Process ID.
    pid: u32,
    /// Process role.
    role: String,
}

#[test]
fn run_records_fixture_until_exit() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let mut options = fixture_options(
        &dir.path().join("runs"),
        fixture_command(&[
            "--duration",
            "5s",
            "--alloc-mb-per-sec",
            "20",
            "--gdi",
            "50",
            "--busy-ms-per-sec",
            "200",
            "--exit-code",
            "7",
        ]),
    );
    options
        .labels
        .insert("branch".to_string(), "test".to_string());

    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");
    assert_eq!(
        outcome.end_reason,
        EndReason::AppExited,
        "the fixture must end by itself"
    );
    assert_eq!(
        outcome.exit_code,
        Some(7),
        "the fixture exit code must be recorded"
    );

    let run_dir = &outcome.run_dir;
    for file in [
        "meta.json",
        "processes.csv",
        "process.csv",
        "job.csv",
        "system.csv",
        "app.stdout.log",
        "app.stderr.log",
        "memwatch.log",
    ] {
        assert!(
            run_dir.join(file).is_file(),
            "{file} must exist in the run directory"
        );
    }

    let rows = read_process_rows(&run_dir.join("process.csv"));
    assert!(
        rows.iter().any(|row| row.role == "main"),
        "the root must be sampled: {rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.role == "memwatch-fixture"),
        "the fixture child must be sampled"
    );

    let root: Vec<&ProcessRow> = rows.iter().filter(|row| row.role == "main").collect();
    let first = root.first().expect("the root must have a first sample");
    let last = root.last().expect("the root must have a last sample");
    assert!(
        last.private_bytes
            .expect("the root private bytes must be readable")
            > first
                .private_bytes
                .expect("the root private bytes must be readable"),
        "the allocating fixture must grow: first={:?} last={:?}",
        first.private_bytes,
        last.private_bytes
    );
    assert!(
        rows.iter().any(|row| row.gdi.unwrap_or(0) > 0),
        "the fixture must create GDI objects"
    );
    assert!(
        rows.iter().any(|row| row
            .cpu_pct
            .as_deref()
            .and_then(|pct| pct.parse::<f64>().ok())
            .is_some_and(|pct| pct > 0.0)),
        "the busy fixture must consume CPU"
    );

    let events = read_events(&run_dir.join("processes.csv"));
    for role in ["main", "memwatch-fixture"] {
        let role_events: Vec<&EventRow> = events.iter().filter(|row| row.role == role).collect();
        assert_eq!(
            role_events
                .iter()
                .filter(|row| row.event == "start")
                .count(),
            1,
            "{role} must start exactly once: {role_events:?}"
        );
        assert_eq!(
            role_events.iter().filter(|row| row.event == "exit").count(),
            1,
            "{role} must exit exactly once: {role_events:?}"
        );
    }
    for row in &events {
        assert!(
            matches!(row.role.as_str(), "main" | "memwatch-fixture" | "conhost"),
            "unexpected role `{}` in the fixture tree",
            row.role
        );
    }

    let meta = read_meta(run_dir);
    assert_eq!(meta["end_reason"], "app_exited");
    assert_eq!(meta["exit_code"], 7);
    assert_eq!(meta["labels"]["branch"], "test");
    assert!(!meta["ended_at"].is_null(), "ended_at must be set");
    let collectors = meta["collectors"]
        .as_object()
        .expect("collectors must be an object");
    let mut names: Vec<&str> = collectors.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["job", "process", "system"]);
    for name in names {
        assert_eq!(
            collectors.get(name),
            Some(&serde_json::Value::from("ok")),
            "{name} must finish ok"
        );
    }
}

#[test]
fn stop_handle_ends_run_as_ctrl_c() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let options = fixture_options(
        &dir.path().join("runs"),
        fixture_command(&["--duration", "60s"]),
    );
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
    assert_eq!(
        outcome.exit_code, None,
        "no application exit code must be recorded"
    );

    let events = read_events(&outcome.run_dir.join("processes.csv"));
    for pid in events
        .iter()
        .filter(|row| row.event == "start")
        .map(|row| row.pid)
    {
        wait_until_dead(pid, Duration::from_secs(5));
    }

    let meta = read_meta(&outcome.run_dir);
    assert_eq!(meta["end_reason"], "ctrl_c");
}

#[test]
fn run_dir_collision_is_an_error() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    fs::create_dir_all(&out).expect("the output directory must be created");
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    let mut created = Vec::new();
    for offset in -1..=2 {
        let path = out.join(run_dir_name(
            "fixture",
            now + time::Duration::seconds(offset),
        ));
        fs::create_dir(&path).expect("the colliding run directory must be created");
        created.push(path);
    }

    let options = fixture_options(&out, fixture_command(&["--duration", "1s"]));
    let result = memwatch::run(&options, StopHandle::new());

    assert!(
        result.is_err(),
        "an existing run directory must fail the run"
    );
    for path in created {
        assert!(
            !path.join("app.stdout.log").exists(),
            "the application must not start in a colliding run directory"
        );
    }
}

/// Reads `process.csv` into row structs.
fn read_process_rows(path: &Path) -> Vec<ProcessRow> {
    let mut reader = csv::Reader::from_path(path).expect("process.csv must be readable");
    reader
        .deserialize()
        .map(|row| row.expect("every row must parse"))
        .collect()
}

/// Reads `processes.csv` into event rows.
fn read_events(path: &Path) -> Vec<EventRow> {
    let mut reader = csv::Reader::from_path(path).expect("processes.csv must be readable");
    reader
        .deserialize()
        .map(|row| row.expect("every row must parse"))
        .collect()
}

/// Reads `meta.json` into a JSON value.
fn read_meta(run_dir: &Path) -> serde_json::Value {
    let content =
        fs::read_to_string(run_dir.join("meta.json")).expect("meta.json must be readable");
    serde_json::from_str(&content).expect("meta.json must be valid JSON")
}

/// Waits until the process with `pid` is gone or `timeout` runs out.
fn wait_until_dead(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match ProcHandle::open(pid).expect("opening the process must not fail") {
            None => return,
            Some(process) => {
                if process
                    .exit_code()
                    .expect("the exit code must be readable")
                    .is_some()
                {
                    return;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "PID {pid} must exit within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
