//! Integration tests for launching a process tree inside a job object.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use memwatch::launch::{Launched, launch};
use memwatch::win::ProcHandle;
use tempfile::TempDir;

/// Path of the fixture binary built by Cargo for these tests.
const FIXTURE: &str = env!("CARGO_BIN_EXE_memwatch-fixture");

/// Builds the command line that starts the fixture for `duration`.
fn fixture_command(duration: &str) -> Vec<OsString> {
    vec![
        OsString::from(FIXTURE),
        OsString::from("--duration"),
        OsString::from(duration),
    ]
}

/// Starts the fixture in a fresh job inside `dir`.
fn start_fixture(dir: &TempDir, duration: &str) -> Launched {
    launch(&fixture_command(duration), &BTreeMap::new(), dir.path())
        .expect("the fixture must launch")
}

/// Waits until the fixture prints the child PID and returns it.
fn wait_for_child_pid(stdout_log: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(content) = fs::read_to_string(stdout_log)
            && let Some(pid) = child_pid(&content)
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "the fixture must print `child=` within 3 s"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Extracts the `child=<pid>` value from the fixture output.
fn child_pid(stdout: &str) -> Option<u32> {
    stdout
        .lines()
        .find_map(|line| line.split("child=").nth(1))
        .and_then(|pid| pid.trim().parse().ok())
}

/// Waits until `process` exits or `timeout` runs out.
fn wait_until_exited(process: &ProcHandle, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while process
        .exit_code()
        .expect("the exit code must be readable")
        .is_none()
    {
        assert!(
            Instant::now() < deadline,
            "the process must exit within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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

#[test]
fn fixture_child_is_inside_job() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let app = start_fixture(&dir, "5s");
    let child = wait_for_child_pid(&dir.path().join("app.stdout.log"));

    let ids = app
        .job
        .process_ids()
        .expect("the job process list must be readable");
    assert!(
        ids.contains(&app.root_pid),
        "the job must contain the root PID {}",
        app.root_pid
    );
    assert!(
        ids.contains(&child),
        "the job must contain the child PID {child}"
    );
}

#[test]
fn stdout_is_redirected_to_log() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let app = start_fixture(&dir, "1s");

    wait_until_exited(&app.root, Duration::from_secs(10));

    let content = fs::read_to_string(dir.path().join("app.stdout.log"))
        .expect("the stdout log must be readable");
    assert!(
        content.contains("memwatch-fixture started pid="),
        "`{content}` must contain the fixture start line"
    );
}

#[test]
fn terminate_kills_whole_tree() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let app = start_fixture(&dir, "60s");
    let child_pid = wait_for_child_pid(&dir.path().join("app.stdout.log"));
    let child = ProcHandle::open(child_pid)
        .expect("opening the child must not fail")
        .expect("the child must be running");

    app.job
        .terminate(1)
        .expect("terminating the job must succeed");

    wait_until_exited(&app.root, Duration::from_secs(5));
    wait_until_exited(&child, Duration::from_secs(5));
}

#[test]
fn dropping_launched_kills_tree() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let app = start_fixture(&dir, "60s");
    let child_pid = wait_for_child_pid(&dir.path().join("app.stdout.log"));
    let child = ProcHandle::open(child_pid)
        .expect("opening the child must not fail")
        .expect("the child must be running");
    let root_pid = app.root_pid;

    drop(app);

    wait_until_dead(root_pid, Duration::from_secs(5));
    wait_until_exited(&child, Duration::from_secs(5));
}

#[test]
fn missing_exe_is_an_error() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let command = vec![OsString::from(dir.path().join("does-not-exist.exe"))];

    let result = launch(&command, &BTreeMap::new(), dir.path());

    assert!(result.is_err(), "a missing executable must be an error");
}
