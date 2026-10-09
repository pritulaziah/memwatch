//! Integration test for tracking the process tree of a launched fixture.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use memwatch::collect::job::JobCollector;
use memwatch::collect::process::ProcessTree;
use memwatch::collect::{Collector, TickCtx};
use memwatch::launch::{Job, Launched, launch};
use memwatch::log::RunLog;
use memwatch::store::{CsvTable, JOB_COLUMNS, PROCESSES_COLUMNS};
use memwatch::win::{self, OwnedHandle, ProcHandle, ProcessState};
use tempfile::TempDir;
use windows::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
};

/// Path of the fixture binary built by Cargo for these tests.
const FIXTURE: &str = env!("CARGO_BIN_EXE_memwatch-fixture");

/// One row of `processes.csv` as read by the test.
#[derive(Debug, serde::Deserialize)]
struct EventRow {
    t_ms: u64,
    pid: u32,
    /// `start` or `exit`.
    event: String,
    /// Process role.
    role: String,
    /// Exit code; empty for a process that vanished without a code.
    exit_code: Option<String>,
}

struct OwnedChild(Child);

impl OwnedChild {
    fn spawn_leaf() -> Self {
        Self(
            Command::new(FIXTURE)
                .args(["--child", "--duration", "60s"])
                .creation_flags(0x0800_0000)
                .spawn()
                .expect("owned leaf must spawn"),
        )
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = reap_until(&mut self.0, Instant::now() + Duration::from_secs(3));
    }
}

fn reap_until(child: &mut Child, deadline: Instant) -> anyhow::Result<()> {
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "owned child did not exit before cleanup deadline"
        );
        std::thread::sleep(
            Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn clone_child_handle(child: &Child) -> anyhow::Result<ProcHandle> {
    let mut duplicate = HANDLE::default();
    // SAFETY: Child owns the source handle; the duplicate becomes independently owned.
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            HANDLE(child.as_raw_handle()),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )?;
        Ok(ProcHandle::from_owned(OwnedHandle::new(duplicate)))
    }
}

fn stop_owned_process(original: &ProcHandle, pid: u32, creation_time: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        creation_time > 0 && original.creation_time()? == creation_time,
        "owned identity must be known"
    );
    // SAFETY: the original handle is owned and its PID is checked before reopening.
    anyhow::ensure!(
        unsafe { GetProcessId(original.raw()) } == pid,
        "original PID changed"
    );
    if original.exit_code()?.is_some() {
        return Ok(());
    }
    // SAFETY: this handle is used only after matching the registered owned identity.
    let fresh = unsafe {
        ProcHandle::from_owned(OwnedHandle::new(OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )?))
    };
    anyhow::ensure!(
        unsafe { GetProcessId(fresh.raw()) } == pid && fresh.creation_time()? == creation_time,
        "fresh owned identity changed"
    );
    unsafe {
        TerminateProcess(fresh.raw(), 1)?;
    }
    Ok(())
}

fn discover_fixture_children(
    root: &ProcHandle,
    pid: u32,
    creation_time: u64,
) -> anyhow::Result<Vec<(u32, u64, ProcHandle)>> {
    anyhow::ensure!(
        root.exit_code()?.is_some(),
        "root must stop before final discovery"
    );
    anyhow::ensure!(
        creation_time > 0
            && root.creation_time()? == creation_time
            && unsafe { GetProcessId(root.raw()) } == pid,
        "root identity must remain held"
    );
    let mut children = Vec::new();
    for entry in win::snapshot()?
        .into_iter()
        .filter(|entry| entry.ppid == pid)
    {
        let Some(handle) = ProcHandle::open(entry.pid)? else {
            continue;
        };
        let created = handle.creation_time()?;
        if handle.parent_pid()? == pid && created > 0 && created >= creation_time {
            children.push((entry.pid, created, handle));
        }
    }
    Ok(children)
}

struct FixtureTreeGuard {
    root: Child,
    root_handle: Option<ProcHandle>,
    creation_time: u64,
    children: Vec<(u32, u64, ProcHandle)>,
    reader: Option<JoinHandle<()>>,
    reader_finished: Receiver<()>,
}

impl FixtureTreeGuard {
    fn spawn() -> Self {
        Self::spawn_with_registration(|_, _| Ok(())).expect("owned tree must spawn")
    }

    fn spawn_with_registration(
        before_registration: impl FnOnce(&Self, u32) -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        let root = Command::new(FIXTURE)
            .args(["--duration", "60s"])
            .creation_flags(0x0800_0000)
            .stdout(Stdio::piped())
            .spawn()?;
        let (finished_tx, reader_finished) = mpsc::channel();
        // Own the root before any fallible setup so unwind cannot leave it spawning children.
        let mut guard = Self {
            root,
            root_handle: None,
            creation_time: 0,
            children: Vec::new(),
            reader: None,
            reader_finished,
        };
        let setup = (|| {
            guard.root_handle = Some(clone_child_handle(&guard.root)?);
            guard.creation_time = guard.root_handle.as_ref().unwrap().creation_time()?;
            let stdout = guard
                .root
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("stdout missing"))?;
            let (line_tx, line_rx) = mpsc::channel();
            guard.reader = Some(std::thread::spawn(move || {
                let mut line = String::new();
                let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
                let _ = line_tx.send(result);
                let _ = finished_tx.send(());
            }));
            let line = line_rx.recv_timeout(Duration::from_secs(5))??;
            let child_pid: u32 = line
                .split_whitespace()
                .find_map(|word| word.strip_prefix("child="))
                .ok_or_else(|| anyhow::anyhow!("child PID missing"))?
                .parse()?;
            before_registration(&guard, child_pid)?;
            let child =
                ProcHandle::open(child_pid)?.ok_or_else(|| anyhow::anyhow!("child vanished"))?;
            let created = child.creation_time()?;
            anyhow::ensure!(
                child.parent_pid()? == guard.root.id()
                    && created > 0
                    && created >= guard.creation_time,
                "child ownership must be confirmed"
            );
            guard.children.push((child_pid, created, child));
            Ok(())
        })();
        if let Err(err) = setup {
            return match guard.cleanup() {
                Ok(()) => Err(err),
                Err(cleanup) => Err(err.context(format!("cleanup also failed: {cleanup:#}"))),
            };
        }
        Ok(guard)
    }

    fn cleanup(&mut self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut errors = Vec::new();
        let _ = self.root.kill();
        let root_stopped = reap_until(&mut self.root, deadline);
        if let Err(err) = &root_stopped {
            errors.push(err.to_string());
        }
        // Hold the root identity until every discovered child has been cleaned up.
        if self.root_handle.is_none() {
            match clone_child_handle(&self.root) {
                Ok(handle) => self.root_handle = Some(handle),
                Err(err) => errors.push(err.to_string()),
            }
        }
        if let Some(root) = &self.root_handle {
            if self.creation_time == 0 {
                self.creation_time = root.creation_time().unwrap_or(0);
            }
            if root_stopped.is_ok() {
                match discover_fixture_children(root, self.root.id(), self.creation_time) {
                    Ok(found) => {
                        for child in found {
                            if !self
                                .children
                                .iter()
                                .any(|(pid, time, _)| *pid == child.0 && *time == child.1)
                            {
                                self.children.push(child);
                            }
                        }
                    }
                    Err(err) => errors.push(err.to_string()),
                }
            }
        }
        for (pid, time, handle) in &self.children {
            if let Err(err) = stop_owned_process(handle, *pid, *time) {
                errors.push(err.to_string());
            }
        }
        for (_, _, handle) in &self.children {
            loop {
                match handle.exit_code() {
                    Ok(Some(_)) => break,
                    Err(err) => {
                        errors.push(err.to_string());
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(
                        Duration::from_millis(20)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    ),
                    Ok(None) => {
                        errors.push("child cleanup timed out".into());
                        break;
                    }
                }
            }
        }
        if self.reader.is_some() {
            match self
                .reader_finished
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(()) => {
                    if self.reader.take().unwrap().join().is_err() {
                        errors.push("reader panicked".into());
                    }
                }
                Err(err) => errors.push(format!("reader did not finish: {err}")),
            }
        }
        anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
        Ok(())
    }
}

impl Drop for FixtureTreeGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn outside_tree(dir: &TempDir, root: &ProcHandle, pid: u32) -> (Rc<Job>, ProcessTree) {
    let job = Rc::new(Job::create().expect("independent empty job must be created"));
    assert!(!job.contains(root).unwrap());
    let events = CsvTable::create(&dir.path().join("processes.csv"), PROCESSES_COLUMNS).unwrap();
    let log = RunLog::create(&dir.path().join("memwatch.log")).unwrap();
    let tree = ProcessTree::new(job.clone(), root.try_clone().unwrap(), pid, events, log);
    (job, tree)
}

#[test]
fn finish_terminates_confirmed_outsider_in_empty_job() {
    let mut fixture = FixtureTreeGuard::spawn();
    let dir = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
    let (job, mut tree) = outside_tree(
        &dir,
        fixture.root_handle.as_ref().unwrap(),
        fixture.root.id(),
    );
    let child = &fixture.children[0];
    assert!(!job.contains(&child.2).unwrap());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !tree
        .processes()
        .iter()
        .any(|process| process.pid == child.0)
    {
        tree.refresh(0, unix_ms_now()).unwrap();
        assert!(Instant::now() < deadline, "owned child must be discovered");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(tree.tree_walk_fallback());
    let outcome = tree
        .finish(1, unix_ms_now(), Duration::from_secs(3))
        .unwrap();
    assert!(
        child.2.exit_code().unwrap().is_some(),
        "confirmed outsider must exit"
    );
    assert!(
        fixture
            .root_handle
            .as_ref()
            .unwrap()
            .exit_code()
            .unwrap()
            .is_none(),
        "unconfirmed root must stay alive"
    );
    assert!(outcome.issues.iter().all(|issue| issue.pid != child.0));
    assert!(
        outcome
            .issues
            .iter()
            .any(|issue| issue.pid == fixture.root.id()
                && issue.state == memwatch::meta::ShutdownState::Alive
                && issue.reason == memwatch::meta::ShutdownReason::WaitTimeout)
    );
    tree.flush(false).unwrap();
    assert_eq!(
        read_events(&dir.path().join("processes.csv"))
            .iter()
            .filter(|row| row.pid == child.0 && row.event == "exit")
            .count(),
        1
    );
    fixture.cleanup().unwrap();
}

#[test]
fn finish_does_not_record_exit_for_live_unconfirmed_root() {
    let leaf = OwnedChild::spawn_leaf();
    let root = clone_child_handle(&leaf.0).unwrap();
    let dir = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
    let (_, mut tree) = outside_tree(&dir, &root, leaf.0.id());
    tree.refresh(0, unix_ms_now()).unwrap();
    let outcome = tree.finish(1, unix_ms_now(), Duration::ZERO).unwrap();
    assert_eq!(root.exit_code().unwrap(), None);
    tree.flush(false).unwrap();
    let rows = read_events(&dir.path().join("processes.csv"));
    let root_rows: Vec<_> = rows.iter().filter(|row| row.pid == leaf.0.id()).collect();
    assert_eq!(
        root_rows.iter().filter(|row| row.event == "exit").count(),
        0,
        "live root must not receive exit"
    );
    assert_eq!(root_rows.len(), 1);
    assert_eq!(
        outcome
            .issues
            .iter()
            .find(|issue| issue.pid == leaf.0.id())
            .unwrap()
            .state,
        memwatch::meta::ShutdownState::Alive
    );
    assert_eq!(
        outcome
            .issues
            .iter()
            .find(|issue| issue.pid == leaf.0.id())
            .unwrap()
            .reason,
        memwatch::meta::ShutdownReason::WaitTimeout
    );
}

#[test]
fn finish_records_confirmed_exit_once() {
    let mut fixture = FixtureTreeGuard::spawn();
    let dir = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
    let (_, mut tree) = outside_tree(
        &dir,
        fixture.root_handle.as_ref().unwrap(),
        fixture.root.id(),
    );
    tree.refresh(0, unix_ms_now()).unwrap();
    let root_pid = fixture.root.id();
    let child_pid = fixture.children[0].0;
    fixture.cleanup().unwrap();
    tree.refresh(2, unix_ms_now()).unwrap();
    tree.refresh(3, unix_ms_now()).unwrap();
    assert!(
        tree.finish(4, unix_ms_now(), Duration::ZERO)
            .unwrap()
            .issues
            .is_empty()
    );
    assert!(
        tree.finish(5, unix_ms_now(), Duration::ZERO)
            .unwrap()
            .issues
            .is_empty()
    );
    tree.flush(false).unwrap();
    let rows = read_events(&dir.path().join("processes.csv"));
    for pid in [root_pid, child_pid] {
        let exits: Vec<_> = rows
            .iter()
            .filter(|row| row.pid == pid && row.event == "exit")
            .collect();
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].t_ms, 2);
        assert!(exits[0].exit_code.is_some());
    }
}

fn wait_for_exit(handle: &ProcHandle, timeout: Duration) -> ProcessState {
    let deadline = Instant::now().checked_add(timeout).unwrap();
    loop {
        let state = handle.state().unwrap();
        if matches!(state, ProcessState::Exited(_)) || Instant::now() >= deadline {
            return state;
        }
        std::thread::sleep(
            Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[test]
fn verified_termination_stops_owned_fixture() {
    let leaf = OwnedChild::spawn_leaf();
    let handle = ProcHandle::open(leaf.0.id()).unwrap().unwrap();
    handle
        .terminate_verified(leaf.0.id(), handle.creation_time().unwrap(), 1)
        .unwrap();
    assert_eq!(
        wait_for_exit(&handle, Duration::from_secs(3)),
        ProcessState::Exited(Some(1))
    );
    handle
        .terminate_verified(leaf.0.id(), handle.creation_time().unwrap(), 1)
        .unwrap();
}

#[test]
fn fixture_cleanup_covers_setup_failure_before_child_registration() {
    let mut observations = None;
    let started = Instant::now();
    let result = FixtureTreeGuard::spawn_with_registration(|guard, child_pid| {
        observations = Some((
            guard.root_handle.as_ref().unwrap().try_clone()?,
            ProcHandle::open(child_pid)?.ok_or_else(|| anyhow::anyhow!("child missing"))?,
        ));
        Err(anyhow::anyhow!("injected registration failure"))
    });
    assert!(result.is_err());
    let error = format!("{:#}", result.err().unwrap());
    assert!(error.contains("injected registration failure"));
    assert!(!error.contains("cleanup also failed"), "{error}");
    let (root, child) = observations.unwrap();
    assert!(root.exit_code().unwrap().is_some());
    assert!(child.exit_code().unwrap().is_some());
    assert!(started.elapsed() < Duration::from_secs(5));
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
    let outcome = tree
        .finish(t_ms, unix_ms_now(), Duration::from_secs(5))
        .expect("finish must succeed");
    assert!(outcome.issues.is_empty());
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
