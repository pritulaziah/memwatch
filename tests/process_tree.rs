//! Integration test for tracking the process tree of a launched fixture.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use memwatch::collect::job::JobCollector;
use memwatch::collect::process::ProcessTree;
use memwatch::collect::{Collector, TickCtx};
use memwatch::launch::{Launched, launch};
use memwatch::log::RunLog;
use memwatch::store::{CsvTable, JOB_COLUMNS, PROCESSES_COLUMNS};
use tempfile::TempDir;

/// Path of the fixture binary built by Cargo for these tests.
const FIXTURE: &str = env!("CARGO_BIN_EXE_memwatch-fixture");

/// One row of `processes.csv` as read by the test.
#[derive(Debug, serde::Deserialize)]
struct EventRow {
    /// `start` or `exit`.
    event: String,
    /// Process role.
    role: String,
    /// Exit code; empty for a process that vanished without a code.
    exit_code: Option<String>,
}

#[test]
fn tree_tracks_fixture_parent_and_child() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let command = vec![
        OsString::from(FIXTURE),
        OsString::from("--duration"),
        OsString::from("4s"),
        OsString::from("--gdi"),
        OsString::from("20"),
    ];
    let Launched {
        job,
        root,
        root_pid,
    } = launch(&command, &BTreeMap::new(), dir.path()).expect("the fixture must launch");

    let events = CsvTable::create(&dir.path().join("processes.csv"), PROCESSES_COLUMNS)
        .expect("processes.csv must be created");
    let log =
        RunLog::create(&dir.path().join("memwatch.log")).expect("memwatch.log must be created");
    let mut tree = ProcessTree::new(job, root, root_pid, events, log);

    let start = Instant::now();
    while tree.root_exit().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the fixture must exit within 30 s"
        );
        let t_ms = start.elapsed().as_millis() as u64;
        tree.refresh(t_ms, unix_ms_now())
            .expect("a refresh must succeed");
        std::thread::sleep(Duration::from_millis(500));
    }

    let t_ms = start.elapsed().as_millis() as u64;
    tree.finish(t_ms, unix_ms_now(), Duration::from_secs(5))
        .expect("finish must succeed");
    assert_eq!(
        tree.root_exit(),
        Some(Some(0)),
        "the fixture must exit with code 0"
    );
    assert!(
        !tree.tree_walk_fallback(),
        "the fixture tree must stay inside the job"
    );
    tree.flush(false).expect("the events must be flushed");

    let rows = read_events(&dir.path().join("processes.csv"));
    let main: Vec<&EventRow> = rows.iter().filter(|row| row.role == "main").collect();
    assert_eq!(
        main.len(),
        2,
        "the root must have exactly one start and one exit: {main:?}"
    );
    assert_eq!(
        main.iter().filter(|row| row.event == "start").count(),
        1,
        "the root must start once"
    );
    let main_exit = main
        .iter()
        .find(|row| row.event == "exit")
        .expect("the root exit must be recorded");
    assert_eq!(
        main_exit.exit_code.as_deref(),
        Some("0"),
        "the root must exit with the fixture code"
    );

    let child: Vec<&EventRow> = rows
        .iter()
        .filter(|row| row.role == "memwatch-fixture")
        .collect();
    assert_eq!(
        child.len(),
        2,
        "the child must have exactly one start and one exit: {child:?}"
    );
    assert_eq!(
        child.iter().filter(|row| row.event == "start").count(),
        1,
        "the child must start once"
    );
    let child_exit = child
        .iter()
        .find(|row| row.event == "exit")
        .expect("the child exit must be recorded");
    assert_eq!(
        child_exit.exit_code.as_deref(),
        Some("0"),
        "the child must exit with its own code"
    );

    for row in &rows {
        assert!(
            matches!(row.role.as_str(), "main" | "memwatch-fixture" | "conhost"),
            "unexpected role `{}` in the fixture tree",
            row.role
        );
    }
}

#[test]
fn job_collector_writes_rows_for_running_fixture() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let command = vec![
        OsString::from(FIXTURE),
        OsString::from("--duration"),
        OsString::from("5s"),
        OsString::from("--busy-ms-per-sec"),
        OsString::from("300"),
    ];
    let Launched { job, .. } =
        launch(&command, &BTreeMap::new(), dir.path()).expect("the fixture must launch");

    let table = CsvTable::create(&dir.path().join("job.csv"), JOB_COLUMNS)
        .expect("job.csv must be created");
    let mut collector = JobCollector::new(job, table, memwatch::win::logical_cpus());

    let start = Instant::now();
    let first = TickCtx {
        t_ms: 0,
        unix_ms: unix_ms_now(),
        tick: 0,
        processes: &[],
    };
    collector
        .sample(&first)
        .expect("the first sample must succeed");

    std::thread::sleep(Duration::from_secs(1));

    let second = TickCtx {
        t_ms: start.elapsed().as_millis() as u64,
        unix_ms: unix_ms_now(),
        tick: 1,
        processes: &[],
    };
    collector
        .sample(&second)
        .expect("the second sample must succeed");
    collector.flush(false).expect("job.csv must be flushed");

    let rows = read_job_rows(&dir.path().join("job.csv"));
    assert_eq!(rows.len(), 2, "both samples must be written");
    let row = &rows[1];
    let cpu_pct: f64 = row
        .cpu_pct
        .as_deref()
        .expect("the second row must have cpu_pct")
        .parse()
        .expect("cpu_pct must be a number");
    assert!(
        cpu_pct > 0.0,
        "the busy fixture must consume CPU: cpu_pct = {cpu_pct}"
    );
    assert!(
        row.active_processes >= 2,
        "the fixture root and child must both be active: {}",
        row.active_processes
    );
}

/// One row of `job.csv` as read by the test.
#[derive(Debug, serde::Deserialize)]
struct JobCsvRow {
    /// Processes currently active in the job.
    active_processes: u32,
    /// CPU usage of the whole machine; empty for the first sample.
    cpu_pct: Option<String>,
}

/// Reads `job.csv` into row structs.
fn read_job_rows(path: &Path) -> Vec<JobCsvRow> {
    let mut reader = csv::Reader::from_path(path).expect("job.csv must be readable");
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

/// Returns the current wall-clock time in milliseconds since the epoch.
fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock must be after the epoch")
        .as_millis() as u64
}
