//! End-to-end tests of the `memwatch` command-line interface.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use memwatch::store::PROCESS_COLUMNS;
use memwatch::win::ProcHandle;
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

/// Builds a `memwatch run` command line for `command` in `out`.
fn memwatch_run(out: &Path, name: &str, command: &[OsString]) -> Command {
    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg(name)
        .arg("--out")
        .arg(out)
        .arg("--")
        .args(command);
    cmd
}

#[test]
fn missing_exe_gives_launch_failed() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let missing = dir.path().join("does-not-exist.exe");

    let status = memwatch_run(&out, "missing", &[missing.into_os_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("memwatch must run");

    assert_eq!(status.code(), Some(1), "a failed launch must exit with 1");
    let run_dir = single_run_dir(&out);
    assert!(
        run_dir.join("memwatch.log").is_file(),
        "memwatch.log must exist in the run directory"
    );
    let meta = read_meta(&run_dir);
    assert_eq!(meta["end_reason"], "launch_failed");
}

#[test]
fn bad_arguments_exit_with_two() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "1s"]);

    let mut zero_interval = Command::new(MEMWATCH);
    zero_interval
        .args(["run", "--name", "bad", "--out"])
        .arg(&out)
        .args(["--interval", "0s", "--"])
        .args(&fixture);

    let mut bad_name = Command::new(MEMWATCH);
    bad_name
        .args(["run", "--name", "a b", "--out"])
        .arg(&out)
        .arg("--")
        .args(&fixture);

    let mut no_command = Command::new(MEMWATCH);
    no_command
        .args(["run", "--name", "bad", "--out"])
        .arg(&out)
        .arg("--");

    for (case, cmd) in [
        ("zero interval", &mut zero_interval),
        ("name with a space", &mut bad_name),
        ("no command", &mut no_command),
    ] {
        let status = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("memwatch must run");
        assert_eq!(
            status.code(),
            Some(2),
            "{case}: bad arguments must exit with 2"
        );
    }
}

#[test]
fn fixture_exit_code_is_not_propagated() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "2s", "--exit-code", "7"]);

    let status = memwatch_run(&out, "exit-code", &fixture)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("memwatch must run");

    assert_eq!(
        status.code(),
        Some(0),
        "the application exit code must not be propagated"
    );
}

#[test]
fn killed_memwatch_takes_tree_and_keeps_rows() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "60s"]);

    let mut child = memwatch_run(&out, "killed", &fixture)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("memwatch must start");

    std::thread::sleep(Duration::from_secs(4));
    child.kill().expect("memwatch must be killable");
    child.wait().expect("memwatch must be reaped");

    let run_dir = single_run_dir(&out);

    // Closing the job with the killed memwatch must take the whole tree down.
    let events = read_events(&run_dir.join("processes.csv"));
    for pid in events
        .iter()
        .filter(|row| row.event == "start")
        .map(|row| row.pid)
    {
        wait_until_dead(pid, Duration::from_secs(5));
    }

    // The rows written before the kill must stay readable; only the row cut
    // off by the kill may be incomplete.
    let (records, torn) = read_process_records(&run_dir.join("process.csv"));
    assert!(!records.is_empty(), "process.csv must keep rows");
    let complete = if torn {
        records.len()
    } else {
        records.len().saturating_sub(1)
    };
    for record in &records[..complete] {
        assert_eq!(
            record.len(),
            PROCESS_COLUMNS.len(),
            "only the last row may be incomplete: {record:?}"
        );
    }

    let mut ticks: Vec<u64> = records
        .iter()
        .filter_map(|record| record.get(0))
        .filter_map(|t_ms| t_ms.parse().ok())
        .collect();
    ticks.sort_unstable();
    ticks.dedup();
    assert!(
        ticks.len() >= 3,
        "at least three ticks must be on disk, got {ticks:?}"
    );

    let meta = read_meta(&run_dir);
    assert!(
        meta["ended_at"].is_null(),
        "a killed memwatch must not finalize meta.json"
    );
}

/// One row of `processes.csv` as read by the tests.
#[derive(Debug, serde::Deserialize)]
struct EventRow {
    /// `start` or `exit`.
    event: String,
    /// Process ID.
    pid: u32,
}

/// Reads `processes.csv` into event rows.
fn read_events(path: &Path) -> Vec<EventRow> {
    let mut reader = csv::Reader::from_path(path).expect("processes.csv must be readable");
    reader
        .deserialize()
        .map(|row| row.expect("every row must parse"))
        .collect()
}

/// Reads `process.csv` tolerating a torn last row.
///
/// Returns the parsed records and whether the tail could not be parsed at all.
fn read_process_records(path: &Path) -> (Vec<csv::StringRecord>, bool) {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .expect("process.csv must be readable");
    let mut records = Vec::new();
    let mut torn = false;
    for record in reader.records() {
        match record {
            Ok(record) => records.push(record),
            Err(_) => {
                torn = true;
                break;
            }
        }
    }
    (records, torn)
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
