//! The process tree: discovery, lifecycle events and per-process metrics.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::collect::{CollectError, Collector, TickCtx};
use crate::launch::Job;
use crate::log::RunLog;
use crate::meta::{ImageInfo, ShutdownIssue, ShutdownReason, ShutdownState};
use crate::store::{CsvTable, ProcessEvent, ProcessEventRow, ProcessRow, fmt_pct};
use crate::win::{self, ProcHandle, ProcessMetrics, ProcessState, SnapshotEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitObservation {
    Exited(Option<u32>),
    Alive,
    Unknown,
}

fn observe_exit(
    handle_state: Option<Result<ProcessState, ()>>,
    snapshot_contains_pid: Option<bool>,
) -> ExitObservation {
    match handle_state {
        Some(Ok(ProcessState::Exited(code))) => ExitObservation::Exited(code),
        Some(Ok(ProcessState::Running)) => ExitObservation::Alive,
        _ if snapshot_contains_pid == Some(false) => ExitObservation::Exited(None),
        _ => ExitObservation::Unknown,
    }
}

fn observe_process(
    process: &TrackedProcess,
    snapshot: Option<&[SnapshotEntry]>,
    log: &RunLog,
) -> ExitObservation {
    let state = process.handle.as_ref().map(|handle| {
        handle.state().map_err(|err| {
            log.error(
                "process",
                format!("cannot observe PID {}: {err:#}", process.pid),
            );
        })
    });
    observe_exit(
        state,
        snapshot.map(|s| s.iter().any(|entry| entry.pid == process.pid)),
    )
}

/// Final diagnostics for processes whose exit could not be confirmed.
#[derive(Debug, Default)]
pub struct ShutdownOutcome {
    /// Unresolved processes after the bounded shutdown wait.
    pub issues: Vec<ShutdownIssue>,
}

/// A collection failure together with the complete shutdown diagnostics.
#[derive(Debug)]
pub struct ShutdownFailure {
    /// Diagnostics retained even when lifecycle event writes fail.
    pub outcome: ShutdownOutcome,
    /// Original collection error, with write errors taking priority.
    pub error: CollectError,
}

impl std::fmt::Display for ShutdownFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for ShutdownFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Builds the role of a process.
///
/// The root is `main`. Another process uses the value of the `--type=` flag
/// from its command line; without the flag, or without a command line, the
/// executable name without its extension, in lower case.
pub fn role_for(is_root: bool, cmdline: Option<&str>, exe_name: &str) -> String {
    if is_root {
        return "main".to_string();
    }
    if let Some(role) = cmdline.and_then(type_flag) {
        return role.to_string();
    }
    exe_stem(exe_name)
}

/// Extracts the value of the `--type=` flag from a command line.
///
/// The flag may be a bare token or wrapped in quotes.
fn type_flag(cmdline: &str) -> Option<&str> {
    for token in cmdline.split_whitespace() {
        let token = token.trim_matches('"');
        if let Some(value) = token.strip_prefix("--type=") {
            let value = value.trim_matches('"');
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Returns the executable name without its extension, in lower case.
fn exe_stem(exe_name: &str) -> String {
    match exe_name.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem.to_lowercase(),
        _ => exe_name.to_lowercase(),
    }
}

/// Builds the stable identity of a process: `<pid>-<creation time>`.
pub fn proc_key(pid: u32, creation_time: u64) -> String {
    format!("{pid}-{creation_time}")
}

/// Finds the descendants of `parents` in `snapshot`, level by level.
///
/// The parents of the first level are the given processes; the children
/// accepted on a level become the parents of the next one. A candidate is
/// accepted when its `ppid` equals a parent PID, `creation_time(pid,
/// parent_pid)` returns a time, and that time is not earlier than the
/// parent's creation time. `None` from `creation_time` rejects the candidate
/// together with its whole subtree. PIDs that are parents or already accepted
/// are not considered again. The result holds the accepted `(pid, creation
/// time)` pairs in level order.
pub fn descendants(
    parents: &[(u32, u64)],
    snapshot: &[SnapshotEntry],
    mut creation_time: impl FnMut(u32, u32) -> Option<u64>,
) -> Vec<(u32, u64)> {
    let mut known: HashSet<u32> = parents.iter().map(|(pid, _)| *pid).collect();
    let mut accepted = Vec::new();
    let mut level = parents.to_vec();

    while !level.is_empty() {
        let mut next = Vec::new();
        for entry in snapshot {
            if known.contains(&entry.pid) {
                continue;
            }
            let Some((_, parent_created)) = level.iter().find(|(pid, _)| *pid == entry.ppid) else {
                continue;
            };
            let Some(created) = creation_time(entry.pid, entry.ppid) else {
                continue;
            };
            if created < *parent_created {
                continue;
            }
            known.insert(entry.pid);
            accepted.push((entry.pid, created));
            next.push((entry.pid, created));
        }
        level = next;
    }
    accepted
}

/// Chooses the PIDs to track this tick.
///
/// Without a fallback and without a confirmed outsider the job list is
/// authoritative. A confirmed outsider or an active fallback keeps the union
/// of the job list and the descendants; the returned flag tells whether the
/// tree is walked by parent PID from now on.
pub fn select_pids(
    job_pids: &[u32],
    descendants: &[u32],
    confirmed_outsiders: &[u32],
    fallback: bool,
) -> (Vec<u32>, bool) {
    if !fallback && confirmed_outsiders.is_empty() {
        return (job_pids.to_vec(), false);
    }
    let mut pids = job_pids.to_vec();
    for pid in descendants {
        if !pids.contains(pid) {
            pids.push(*pid);
        }
    }
    (pids, true)
}

/// Chooses the PIDs to start this tick.
///
/// A PID is kept when it is not in `tracked` yet and the snapshot already
/// lists it, in the order of `pids`. A PID that appeared in the job list
/// after the snapshot was taken is left out and retried on the next call.
pub fn unstarted_pids(tracked: &[u32], pids: &[u32], snapshot: &[SnapshotEntry]) -> Vec<u32> {
    pids.iter()
        .copied()
        .filter(|pid| !tracked.contains(pid) && snapshot.iter().any(|entry| entry.pid == *pid))
        .collect()
}

/// One process tracked by a [`ProcessTree`].
pub struct TrackedProcess {
    /// Whether original identity and ancestry confirmed a live descendant outside the job.
    pub confirmed_outsider: bool,
    /// Stable identity `<pid>-<creation time>`.
    pub proc_key: String,
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Creation time as a FILETIME `u64`; zero when the process could not be
    /// opened.
    pub creation_time: u64,
    /// Process role.
    pub role: String,
    /// Open handle; `None` when the process could not be opened.
    pub handle: Option<ProcHandle>,
    /// Full path of the executable.
    pub image_path: Option<String>,
    /// Threads at the last snapshot.
    pub threads: Option<u32>,
}

/// Watches the process tree of a run.
///
/// It discovers the processes of the tree, writes their `start` and `exit`
/// rows to `processes.csv` and remembers every executable it has seen. The
/// root handle is kept separately, so its exit can be checked independently
/// of [`refresh`](ProcessTree::refresh).
pub struct ProcessTree {
    job: Rc<Job>,
    root: ProcHandle,
    root_pid: u32,
    events: CsvTable,
    log: RunLog,
    processes: Vec<TrackedProcess>,
    images: Vec<ImageInfo>,
    tree_walk_fallback: bool,
    root_started: bool,
}

impl ProcessTree {
    /// Creates a tree around the launched root process.
    pub fn new(
        job: Rc<Job>,
        root: ProcHandle,
        root_pid: u32,
        events: CsvTable,
        log: RunLog,
    ) -> ProcessTree {
        ProcessTree {
            job,
            root,
            root_pid,
            events,
            log,
            processes: Vec::new(),
            images: Vec::new(),
            tree_walk_fallback: false,
            root_started: false,
        }
    }

    /// Reads one snapshot of the machine and updates the tracked processes.
    ///
    /// Exited processes get an `exit` row; the root is added on the first
    /// call; descendants of the tracked live processes are found through the
    /// snapshot; a descendant outside the job switches the tree to walking by
    /// parent PID. New processes get a `start` row.
    pub fn refresh(&mut self, t_ms: u64, unix_ms: u64) -> Result<(), CollectError> {
        self.refresh_with(
            t_ms,
            unix_ms,
            |tree, t, u, process, code| {
                tree.write_event(t, u, ProcessEvent::Exit, process, code.map(i64::from), None)
            },
            |tree, t, u, process, cmdline| {
                tree.write_event(t, u, ProcessEvent::Start, process, None, cmdline)
            },
        )
    }

    fn refresh_with(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        write_exit: impl FnMut(
            &mut ProcessTree,
            u64,
            u64,
            &TrackedProcess,
            Option<u32>,
        ) -> Result<(), CollectError>,
        write_start: impl FnMut(
            &mut ProcessTree,
            u64,
            u64,
            &TrackedProcess,
            Option<String>,
        ) -> Result<(), CollectError>,
    ) -> Result<(), CollectError> {
        let snapshot = win::snapshot().map_err(CollectError::Source)?;
        let job_pids = self.job.process_ids().map_err(CollectError::Source)?;

        self.record_exits(t_ms, unix_ms, &snapshot, write_exit)?;
        self.update_threads(&snapshot);

        if !self.root_started {
            self.start_root(t_ms, unix_ms, &snapshot)?;
            self.root_started = true;
        }

        let parents: Vec<(u32, u64)> =
            self.processes
                .iter()
                .filter(|process| {
                    process.creation_time > 0
                        && process.handle.as_ref().is_some_and(|handle| {
                            matches!(handle.state(), Ok(ProcessState::Running))
                        })
                })
                .map(|process| (process.pid, process.creation_time))
                .collect();

        let mut opened: HashMap<u32, ProcHandle> = HashMap::new();
        let found = descendants(&parents, &snapshot, |pid, ppid| {
            let handle = match ProcHandle::open(pid) {
                Ok(Some(handle)) => handle,
                _ => return None,
            };
            match handle.parent_pid() {
                Ok(parent) if parent == ppid => {}
                _ => return None,
            }
            let created = handle.creation_time().ok()?;
            if created == 0
                || handle.pid().ok()? != pid
                || !matches!(handle.state(), Ok(ProcessState::Running))
            {
                return None;
            }
            opened.insert(pid, handle);
            Some(created)
        });

        let mut confirmed_outsiders = Vec::new();
        for (pid, created) in &found {
            let Some(handle) = opened.get(pid) else {
                continue;
            };
            if *created == 0 || !matches!(handle.state(), Ok(ProcessState::Running)) {
                continue;
            }
            if let Ok(false) = self.job.contains(handle) {
                confirmed_outsiders.push(*pid);
            }
        }

        // Recheck previously tracked descendants on their held original handles.
        for process in &mut self.processes {
            if process.pid == self.root_pid || process.creation_time == 0 {
                continue;
            }
            let Some(handle) = &process.handle else {
                continue;
            };
            let valid_parent = parents
                .iter()
                .any(|(pid, created)| *pid == process.ppid && *created <= process.creation_time);
            if valid_parent
                && handle.parent_pid().ok() == Some(process.ppid)
                && handle.pid().ok() == Some(process.pid)
                && handle.creation_time().ok() == Some(process.creation_time)
                && matches!(handle.state(), Ok(ProcessState::Running))
                && matches!(self.job.contains(handle), Ok(false))
            {
                process.confirmed_outsider = true;
                confirmed_outsiders.push(process.pid);
            }
        }

        let found_pids: Vec<u32> = found.iter().map(|(pid, _)| *pid).collect();
        let (pids, fallback) = select_pids(
            &job_pids,
            &found_pids,
            &confirmed_outsiders,
            self.tree_walk_fallback,
        );
        if fallback && !self.tree_walk_fallback {
            self.log.warn(
                "process",
                "a descendant is outside the job object; switching to walking the process tree by parent PID",
            );
        }
        self.tree_walk_fallback = fallback;

        let tracked_pids: Vec<u32> = self.processes.iter().map(|process| process.pid).collect();
        let mut discovered = Vec::new();
        for pid in unstarted_pids(&tracked_pids, &pids, &snapshot) {
            let handle = match opened.remove(&pid) {
                Some(handle) => Some(handle),
                None => match ProcHandle::open(pid) {
                    Ok(Some(handle)) => Some(handle),
                    // The process disappeared between the listing and opening.
                    Ok(None) => continue,
                    // No access; the process is tracked with empty metrics.
                    Err(_) => None,
                },
            };
            discovered.push(Self::prepare_process(
                pid,
                handle,
                &snapshot,
                confirmed_outsiders.contains(&pid),
            ));
        }
        self.start_processes_with(t_ms, unix_ms, discovered, write_start)
    }

    /// Checks the root process independently of the tracked list.
    ///
    /// Returns `None` while the root is running, `Some(Some(code))` after it
    /// has exited, and `Some(None)` when its exit code cannot be read.
    pub fn root_exit(&self) -> Option<Option<u32>> {
        match self.root.exit_code() {
            Ok(None) => None,
            Ok(Some(code)) => Some(Some(code)),
            Err(err) => {
                self.log.error(
                    "process",
                    format!("cannot read the exit code of the root process: {err}"),
                );
                Some(None)
            }
        }
    }

    /// Returns the processes tracked at the last refresh.
    pub fn processes(&self) -> &[TrackedProcess] {
        &self.processes
    }

    /// Returns whether the tree is walked by parent PID instead of the job
    /// list.
    pub fn tree_walk_fallback(&self) -> bool {
        self.tree_walk_fallback
    }

    /// Returns every executable seen in the tree, without repeats.
    pub fn images(&self) -> Vec<ImageInfo> {
        self.images.clone()
    }

    /// Flushes `processes.csv` to the operating system.
    pub fn flush(&mut self, durable: bool) -> io::Result<()> {
        self.events.flush(durable)
    }

    /// Attempts to stop confirmed outsiders and waits for positive exit evidence.
    ///
    /// Unresolved processes remain tracked and become shutdown diagnostics. Event
    /// write failures retain these diagnostics and do not interrupt cleanup.
    pub fn finish(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        wait: Duration,
    ) -> Result<ShutdownOutcome, ShutdownFailure> {
        let log = self.log.clone();
        self.finish_with(
            t_ms,
            unix_ms,
            wait,
            |process| {
                process.handle.as_ref().unwrap().terminate_verified(
                    process.pid,
                    process.creation_time,
                    1,
                )
            },
            win::snapshot,
            |process, snapshot| observe_process(process, snapshot, &log),
            |tree, t, u, process, code| {
                tree.write_event(t, u, ProcessEvent::Exit, process, code.map(i64::from), None)
            },
        )
    }

    // Keep each shutdown operation independently injectable without a test-only framework.
    #[allow(clippy::too_many_arguments)]
    fn finish_with(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        wait: Duration,
        mut terminate: impl FnMut(&TrackedProcess) -> Result<(), win::TerminationError>,
        mut snapshot: impl FnMut() -> anyhow::Result<Vec<SnapshotEntry>>,
        mut observe: impl FnMut(&TrackedProcess, Option<&[SnapshotEntry]>) -> ExitObservation,
        mut write_exit: impl FnMut(
            &mut ProcessTree,
            u64,
            u64,
            &TrackedProcess,
            Option<u32>,
        ) -> Result<(), CollectError>,
    ) -> Result<ShutdownOutcome, ShutdownFailure> {
        let deadline = Instant::now() + wait;
        let initial_snapshot = snapshot()
            .map_err(|err| {
                self.log.error(
                    "process",
                    format!("cannot snapshot during shutdown: {err:#}"),
                );
            })
            .ok();
        let mut observations: Vec<_> = self
            .processes
            .iter()
            .map(|p| observe(p, initial_snapshot.as_deref()))
            .collect();
        let mut reasons = vec![None; self.processes.len()];

        for (index, process) in self.processes.iter().enumerate() {
            if !process.confirmed_outsider
                || process.pid == self.root_pid
                || matches!(observations[index], ExitObservation::Exited(_))
            {
                continue;
            }
            if process.creation_time == 0 || process.handle.is_none() {
                reasons[index] = Some(ShutdownReason::IdentityUnknown);
                continue;
            }
            let handle = process.handle.as_ref().unwrap();
            // Only the held original handle can establish that this process is alive.
            match handle.state() {
                Ok(ProcessState::Exited(_)) => continue,
                Ok(ProcessState::Running) if observations[index] == ExitObservation::Alive => {}
                Ok(ProcessState::Running) => {
                    reasons[index] = Some(ShutdownReason::QueryFailed);
                    continue;
                }
                Err(err) => {
                    self.log.error(
                        "process",
                        format!(
                            "cannot check PID {} before termination: {err:#}",
                            process.pid
                        ),
                    );
                    reasons[index] = Some(ShutdownReason::QueryFailed);
                    continue;
                }
            }
            match self.job.contains(handle) {
                Ok(false) => {}
                Ok(true) => continue,
                Err(err) => {
                    self.log.error(
                        "process",
                        format!(
                            "cannot check job membership of PID {}: {err:#}",
                            process.pid
                        ),
                    );
                    reasons[index] = Some(ShutdownReason::QueryFailed);
                    continue;
                }
            }
            if let Err(err) = terminate(process) {
                self.log.error(
                    "process",
                    format!("cannot stop outsider PID {}: {}", process.pid, err.detail),
                );
                reasons[index] = Some(err.reason);
            }
        }

        // Always observe once after the attempts, including a zero-duration wait.
        loop {
            let current_snapshot = snapshot()
                .map_err(|err| {
                    self.log.error(
                        "process",
                        format!("cannot snapshot during shutdown: {err:#}"),
                    );
                })
                .ok();
            for (index, process) in self.processes.iter().enumerate() {
                if !matches!(observations[index], ExitObservation::Exited(_)) {
                    observations[index] = observe(process, current_snapshot.as_deref());
                }
            }
            if observations
                .iter()
                .all(|state| matches!(state, ExitObservation::Exited(_)))
                || Instant::now() >= deadline
            {
                break;
            }
            std::thread::sleep(
                Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
            );
        }

        let mut outcome = ShutdownOutcome::default();
        for (index, process) in self.processes.iter().enumerate() {
            if matches!(observations[index], ExitObservation::Exited(_)) {
                continue;
            }
            let reason = reasons[index].unwrap_or_else(|| {
                if process.creation_time == 0 {
                    ShutdownReason::IdentityUnknown
                } else if observations[index] == ExitObservation::Unknown {
                    ShutdownReason::QueryFailed
                } else {
                    ShutdownReason::WaitTimeout
                }
            });
            let state = if reason == ShutdownReason::IdentityChanged
                || observations[index] == ExitObservation::Unknown
            {
                ShutdownState::Unknown
            } else {
                ShutdownState::Alive
            };
            outcome.issues.push(ShutdownIssue {
                pid: process.pid,
                proc_key: (process.creation_time > 0).then(|| process.proc_key.clone()),
                role: process.role.clone(),
                state,
                reason,
            });
        }

        // Cleanup and final observations precede writes, which may fail independently.
        let mut first_error = None;
        let mut retained = Vec::new();
        for (process, observation) in std::mem::take(&mut self.processes)
            .into_iter()
            .zip(observations)
        {
            if let ExitObservation::Exited(code) = observation {
                if let Err(error) = write_exit(self, t_ms, unix_ms, &process, code) {
                    if first_error.is_none()
                        || (matches!(error, CollectError::Write(_))
                            && !matches!(first_error, Some(CollectError::Write(_))))
                    {
                        first_error = Some(error);
                    }
                    retained.push(process);
                }
            } else {
                retained.push(process);
            }
        }
        self.processes = retained;
        match first_error {
            Some(error) => Err(ShutdownFailure { outcome, error }),
            None => Ok(outcome),
        }
    }

    /// Removes the exited processes and writes their `exit` rows.
    ///
    /// Only a signal or snapshot absence without a readable handle confirms exit.
    /// A failed write restores all unresolved entries and the untouched tail.
    fn record_exits(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        snapshot: &[SnapshotEntry],
        mut write_exit: impl FnMut(
            &mut ProcessTree,
            u64,
            u64,
            &TrackedProcess,
            Option<u32>,
        ) -> Result<(), CollectError>,
    ) -> Result<(), CollectError> {
        let mut alive = Vec::with_capacity(self.processes.len());
        let mut pending = std::mem::take(&mut self.processes).into_iter();
        while let Some(process) = pending.next() {
            if let ExitObservation::Exited(code) =
                observe_process(&process, Some(snapshot), &self.log)
            {
                if let Err(error) = write_exit(self, t_ms, unix_ms, &process, code) {
                    alive.push(process);
                    alive.extend(pending);
                    self.processes = alive;
                    return Err(error);
                }
            } else {
                alive.push(process);
            }
        }
        self.processes = alive;
        Ok(())
    }

    /// Refreshes the thread counts from the snapshot.
    fn update_threads(&mut self, snapshot: &[SnapshotEntry]) {
        for process in &mut self.processes {
            process.threads = snapshot
                .iter()
                .find(|entry| entry.pid == process.pid)
                .map(|entry| entry.threads);
        }
    }

    /// Adds the root process and writes its `start` row.
    ///
    /// The root is added even when it is already gone from the job; its
    /// parent PID comes from the snapshot, or from memwatch itself when the
    /// root is missing there.
    fn start_root(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        snapshot: &[SnapshotEntry],
    ) -> Result<(), CollectError> {
        let entry = snapshot.iter().find(|entry| entry.pid == self.root_pid);
        let handle = self.root.try_clone().ok();
        let image_path = handle.as_ref().and_then(|handle| handle.image_path().ok());
        let cmdline = handle
            .as_ref()
            .and_then(|handle| handle.command_line().ok());
        let creation_time = handle
            .as_ref()
            .and_then(|handle| handle.creation_time().ok())
            .unwrap_or(0);
        let process = TrackedProcess {
            confirmed_outsider: false,
            proc_key: proc_key(self.root_pid, creation_time),
            pid: self.root_pid,
            ppid: entry
                .map(|entry| entry.ppid)
                .unwrap_or_else(std::process::id),
            creation_time,
            role: "main".to_string(),
            handle,
            image_path,
            threads: entry.map(|entry| entry.threads),
        };
        self.record_image(&process.image_path);
        self.write_event(t_ms, unix_ms, ProcessEvent::Start, &process, None, cmdline)?;
        self.processes.push(process);
        Ok(())
    }

    /// Builds a found process while retaining its original discovery handle.
    fn prepare_process(
        pid: u32,
        handle: Option<ProcHandle>,
        snapshot: &[SnapshotEntry],
        confirmed_outsider: bool,
    ) -> (TrackedProcess, Option<String>) {
        let entry = snapshot.iter().find(|entry| entry.pid == pid);
        let image_path = handle.as_ref().and_then(|handle| handle.image_path().ok());
        let cmdline = handle
            .as_ref()
            .and_then(|handle| handle.command_line().ok());
        let creation_time = handle
            .as_ref()
            .and_then(|handle| handle.creation_time().ok())
            .unwrap_or(0);
        let exe_name = entry
            .map(|entry| entry.exe_name.as_str())
            .unwrap_or_default();
        let process = TrackedProcess {
            confirmed_outsider,
            proc_key: proc_key(pid, creation_time),
            pid,
            ppid: entry.map(|entry| entry.ppid).unwrap_or(0),
            creation_time,
            role: role_for(false, cmdline.as_deref(), exe_name),
            handle,
            image_path,
            threads: entry.map(|entry| entry.threads),
        };
        (process, cmdline)
    }

    /// Writes starts in discovery order, retaining all discoveries on a write error.
    fn start_processes_with(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        processes: Vec<(TrackedProcess, Option<String>)>,
        mut write_start: impl FnMut(
            &mut ProcessTree,
            u64,
            u64,
            &TrackedProcess,
            Option<String>,
        ) -> Result<(), CollectError>,
    ) -> Result<(), CollectError> {
        let mut pending = processes.into_iter();
        while let Some((process, cmdline)) = pending.next() {
            self.record_image(&process.image_path);
            let result = write_start(self, t_ms, unix_ms, &process, cmdline);
            self.processes.push(process);
            if let Err(error) = result {
                // Discovery already confirmed these original identities. Keep the
                // failed entry and untouched tail reachable by shutdown cleanup.
                self.processes.extend(pending.map(|(process, _)| process));
                return Err(error);
            }
        }
        Ok(())
    }

    /// Remembers an executable and its version once.
    fn record_image(&mut self, image_path: &Option<String>) {
        let Some(path) = image_path else {
            return;
        };
        if self.images.iter().any(|image| image.path == *path) {
            return;
        }
        let version = win::file_version(Path::new(path));
        self.images.push(ImageInfo {
            path: path.clone(),
            version,
        });
    }

    /// Writes one `start` or `exit` row of `processes.csv`.
    fn write_event(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        event: ProcessEvent,
        process: &TrackedProcess,
        exit_code: Option<i64>,
        cmdline: Option<String>,
    ) -> Result<(), CollectError> {
        let image_version = process
            .image_path
            .as_deref()
            .and_then(|path| win::file_version(Path::new(path)));
        let row = ProcessEventRow {
            t_ms,
            unix_ms,
            event,
            proc_key: process.proc_key.clone(),
            pid: process.pid,
            ppid: process.ppid,
            role: process.role.clone(),
            image_path: process.image_path.clone(),
            image_version,
            exit_code,
            cmdline,
        };
        self.events.write(&row).map_err(CollectError::Write)
    }
}

/// Samples `process.csv` from the processes of the tree.
pub struct ProcessCollector {
    table: CsvTable,
    log: RunLog,
    logical_cpus: u32,
    previous: HashMap<String, (u64, Instant)>,
}

impl ProcessCollector {
    /// Creates the collector around an open `process.csv` table.
    pub fn new(table: CsvTable, log: RunLog, logical_cpus: u32) -> ProcessCollector {
        ProcessCollector {
            table,
            log,
            logical_cpus,
            previous: HashMap::new(),
        }
    }

    /// Computes `cpu_pct` from the previous sample of the process and stores
    /// the current CPU counter.
    ///
    /// The first sample of a process returns `None`.
    fn cpu_pct(
        &mut self,
        process: &TrackedProcess,
        metrics: Option<&ProcessMetrics>,
    ) -> Option<String> {
        let cpu_100ns = metrics.and_then(|metrics| metrics.cpu_100ns)?;
        let now = Instant::now();
        let pct = self.previous.get(&process.proc_key).map(|(previous, at)| {
            fmt_pct(win::cpu_pct(
                *previous,
                cpu_100ns,
                now.duration_since(*at),
                self.logical_cpus,
            ))
        });
        self.previous
            .insert(process.proc_key.clone(), (cpu_100ns, now));
        pct
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &str {
        "process"
    }

    fn every_ticks(&self) -> u32 {
        1
    }

    fn sample(&mut self, ctx: &TickCtx) -> Result<(), CollectError> {
        for process in ctx.processes {
            let metrics = process.handle.as_ref().map(ProcHandle::metrics);
            let cpu_pct = self.cpu_pct(process, metrics.as_ref());
            let row = ProcessRow {
                t_ms: ctx.t_ms,
                unix_ms: ctx.unix_ms,
                proc_key: process.proc_key.clone(),
                pid: process.pid,
                role: process.role.clone(),
                private_bytes: metrics.as_ref().and_then(|metrics| metrics.private_bytes),
                working_set: metrics.as_ref().and_then(|metrics| metrics.working_set),
                private_working_set: metrics
                    .as_ref()
                    .and_then(|metrics| metrics.private_working_set),
                peak_working_set: metrics
                    .as_ref()
                    .and_then(|metrics| metrics.peak_working_set),
                peak_private_bytes: metrics
                    .as_ref()
                    .and_then(|metrics| metrics.peak_private_bytes),
                page_faults: metrics.as_ref().and_then(|metrics| metrics.page_faults),
                cpu_user_ms: metrics.as_ref().and_then(|metrics| metrics.cpu_user_ms),
                cpu_kernel_ms: metrics.as_ref().and_then(|metrics| metrics.cpu_kernel_ms),
                cpu_cycles: metrics.as_ref().and_then(|metrics| metrics.cpu_cycles),
                cpu_pct,
                io_read_bytes: metrics.as_ref().and_then(|metrics| metrics.io_read_bytes),
                io_write_bytes: metrics.as_ref().and_then(|metrics| metrics.io_write_bytes),
                io_other_bytes: metrics.as_ref().and_then(|metrics| metrics.io_other_bytes),
                io_read_ops: metrics.as_ref().and_then(|metrics| metrics.io_read_ops),
                io_write_ops: metrics.as_ref().and_then(|metrics| metrics.io_write_ops),
                io_other_ops: metrics.as_ref().and_then(|metrics| metrics.io_other_ops),
                handles: metrics.as_ref().and_then(|metrics| metrics.handles),
                gdi: metrics.as_ref().and_then(|metrics| metrics.gdi),
                gdi_peak: metrics.as_ref().and_then(|metrics| metrics.gdi_peak),
                user: metrics.as_ref().and_then(|metrics| metrics.user),
                user_peak: metrics.as_ref().and_then(|metrics| metrics.user_peak),
                threads: if process.handle.is_some() {
                    process.threads
                } else {
                    None
                },
            };
            if process.handle.is_none() {
                self.log.warn_once(
                    &process.proc_key,
                    "process",
                    format!(
                        "PID {} cannot be opened; metrics are unavailable",
                        process.pid
                    ),
                );
            }
            self.table.write(&row).map_err(CollectError::Write)?;
        }
        Ok(())
    }

    fn flush(&mut self, durable: bool) -> io::Result<()> {
        self.table.flush(durable)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::win::SnapshotEntry;

    fn test_tree() -> (tempfile::TempDir, ProcessTree) {
        let dir = tempfile::TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        let events = CsvTable::create(
            &dir.path().join("processes.csv"),
            crate::store::PROCESSES_COLUMNS,
        )
        .unwrap();
        let log = RunLog::create(&dir.path().join("memwatch.log")).unwrap();
        // The mocked tracked outsiders must not share the tree's root PID.
        let tree = ProcessTree::new(
            Rc::new(Job::create().unwrap()),
            ProcHandle::current(),
            u32::MAX - 2,
            events,
            log,
        );
        (dir, tree)
    }

    fn live_process(role: &str) -> TrackedProcess {
        let handle = ProcHandle::current();
        let pid = std::process::id();
        let creation_time = handle.creation_time().unwrap();
        TrackedProcess {
            confirmed_outsider: true,
            proc_key: proc_key(pid, creation_time),
            pid,
            ppid: handle.parent_pid().unwrap(),
            creation_time,
            role: role.into(),
            handle: Some(handle),
            image_path: None,
            threads: Some(1),
        }
    }

    fn unhandled_process(pid: u32, role: &str) -> TrackedProcess {
        TrackedProcess {
            confirmed_outsider: false,
            proc_key: proc_key(pid, 0),
            pid,
            ppid: 0,
            creation_time: 0,
            role: role.into(),
            handle: None,
            image_path: None,
            threads: None,
        }
    }

    fn denied() -> win::TerminationError {
        win::TerminationError {
            reason: ShutdownReason::AccessDenied,
            detail: "injected denial".into(),
        }
    }

    fn assert_saved_issues(
        dir: &Path,
        result: Result<ShutdownOutcome, ShutdownFailure>,
        expected_reason: crate::meta::EndReason,
    ) {
        let mut meta = crate::analyze::fixtures::sample_meta();
        meta.end_reason = Some(expected_reason);
        meta.exit_code = Some(7);
        let result = crate::sampler::save_shutdown(&mut meta, result);
        if let Err(CollectError::Write(_)) = result {
            meta.end_reason = Some(crate::meta::EndReason::MemwatchError);
        }
        assert_eq!(meta.exit_code, Some(7));
        meta.write_atomic(dir).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("meta.json")).unwrap()).unwrap();
        assert_eq!(saved["end_reason"], "memwatch_error");
        assert_eq!(saved["exit_code"], 7);
        assert!(
            saved["shutdown_issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["role"] == "outsider"
                    && issue["state"] == "alive"
                    && issue["reason"] == "access_denied")
        );
        let run = crate::analyze::load(dir).unwrap();
        let summary = crate::analyze::summarize(
            &run,
            crate::analyze::Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );
        let issue = run
            .meta
            .shutdown_issues
            .iter()
            .find(|issue| issue.role == "outsider")
            .unwrap();
        assert!(
            run.events
                .iter()
                .all(|event| event.role.as_deref() != Some("outsider")
                    || event.event != Some(ProcessEvent::Exit))
        );
        for lang in [crate::report::Lang::En, crate::report::Lang::Ru] {
            let view = crate::report::build(&run, &summary, lang);
            assert_eq!(view.header[5].1, "memwatch_error");
            let key = issue.proc_key.as_deref().unwrap_or("—");
            let expected = match lang {
                crate::report::Lang::En => format!(
                    "Incomplete shutdown: PID {}, identity {key}, role outsider, state alive, reason access denied",
                    issue.pid
                ),
                crate::report::Lang::Ru => format!(
                    "Неполная остановка: PID {}, идентичность {key}, роль outsider, состояние жив, причина отказ в доступе",
                    issue.pid
                ),
            };
            assert!(view.warnings.contains(&expected));
            assert!(crate::report::render(&view).contains(&format!("- {expected}")));
            let row = view
                .process_rows
                .iter()
                .find(|row| row[0] == "outsider")
                .unwrap();
            assert_eq!(&row[4..6], ["—", "—"]);
        }
    }

    #[test]
    fn observe_exit_requires_positive_evidence() {
        assert_eq!(observe_exit(None, Some(true)), ExitObservation::Unknown);
        assert_eq!(
            observe_exit(None, Some(false)),
            ExitObservation::Exited(None)
        );
        assert_eq!(
            observe_exit(Some(Err(())), Some(false)),
            ExitObservation::Exited(None)
        );
        assert_eq!(
            observe_exit(Some(Err(())), Some(true)),
            ExitObservation::Unknown
        );
        assert_eq!(observe_exit(None, None), ExitObservation::Unknown);
        assert_eq!(
            observe_exit(Some(Ok(ProcessState::Running)), Some(false)),
            ExitObservation::Alive
        );
        assert_eq!(
            observe_exit(Some(Ok(ProcessState::Exited(None))), Some(true)),
            ExitObservation::Exited(None)
        );
    }

    #[test]
    fn record_exits_does_not_trust_job_list_absence() {
        let (_dir, mut tree) = test_tree();
        tree.processes
            .push(unhandled_process(std::process::id(), "unknown"));
        let mut writes = 0;
        tree.record_exits(0, 0, &win::snapshot().unwrap(), |_, _, _, _, _| {
            writes += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            writes, 0,
            "snapshot presence without handle is not exit evidence"
        );
        assert_eq!(tree.processes().len(), 1);
    }

    #[test]
    fn finish_reports_denied_termination_without_false_exit() {
        let (_dir, mut tree) = test_tree();
        tree.processes = vec![live_process("outsider"), live_process("other")];
        let key = tree.processes[0].proc_key.clone();
        let mut attempts = Vec::new();
        let mut exits = Vec::new();
        let outcome = tree
            .finish_with(
                1,
                1,
                Duration::ZERO,
                |process| {
                    attempts.push(process.role.clone());
                    if process.role == "outsider" {
                        Err(denied())
                    } else {
                        Ok(())
                    }
                },
                || Ok(Vec::new()),
                |_, _| ExitObservation::Alive,
                |_, _, _, process, _| {
                    exits.push(process.role.clone());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(attempts, ["outsider", "other"]);
        assert!(exits.is_empty());
        assert_eq!(outcome.issues.len(), 2);
        let issue = &outcome.issues[0];
        assert_eq!(issue.proc_key.as_deref(), Some(key.as_str()));
        assert_eq!(issue.role, "outsider");
        assert_eq!(issue.state, ShutdownState::Alive);
        assert_eq!(issue.reason, ShutdownReason::AccessDenied);
        assert_eq!(tree.processes.len(), 2);
    }

    #[test]
    fn finish_identity_mismatch_never_terminates_replacement() {
        let (_dir, mut tree) = test_tree();
        tree.processes.push(live_process("outsider"));
        let mut writes = 0;
        let outcome = tree
            .finish_with(
                1,
                1,
                Duration::ZERO,
                |_| {
                    Err(win::TerminationError {
                        reason: ShutdownReason::IdentityChanged,
                        detail: "replacement PID".into(),
                    })
                },
                || Ok(Vec::new()),
                |_, _| ExitObservation::Alive,
                |_, _, _, _, _| {
                    writes += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(writes, 0);
        assert_eq!(outcome.issues[0].state, ShutdownState::Unknown);
        assert_eq!(outcome.issues[0].reason, ShutdownReason::IdentityChanged);
    }

    #[test]
    fn finish_removes_issue_after_confirmed_exit() {
        let (_dir, mut tree) = test_tree();
        tree.processes.push(live_process("outsider"));
        let mut attempts = 0;
        let mut observations = 0;
        let mut codes = Vec::new();
        let outcome = tree
            .finish_with(
                1,
                1,
                Duration::ZERO,
                |_| {
                    attempts += 1;
                    Err(denied())
                },
                || Ok(Vec::new()),
                |_, _| {
                    observations += 1;
                    if observations == 1 {
                        ExitObservation::Alive
                    } else {
                        ExitObservation::Exited(Some(9))
                    }
                },
                |_, _, _, _, code| {
                    codes.push(code);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(attempts, 1);
        assert_eq!(codes, [Some(9)]);
        assert!(outcome.issues.is_empty());
        assert!(tree.processes.is_empty());
    }

    #[test]
    fn refresh_write_failure_retains_outsiders_for_shutdown() {
        for outsider_before in [true, false] {
            let (dir, mut tree) = test_tree();
            tree.root_started = true;
            let outsider = live_process("outsider");
            tree.write_event(0, 0, ProcessEvent::Start, &outsider, None, None)
                .unwrap();
            let raw = outsider.handle.as_ref().unwrap().raw();
            let key = outsider.proc_key.clone();
            let successful = unhandled_process(u32::MAX - 1, "saved_exit");
            let failed = unhandled_process(u32::MAX, "failed_exit");
            let unknown = unhandled_process(std::process::id(), "unknown_tail");
            tree.processes = if outsider_before {
                vec![successful, outsider, failed, unknown]
            } else {
                vec![successful, failed, outsider, unknown]
            };
            let mut rows = Vec::new();
            let result = tree.refresh_with(
                0,
                0,
                |_, _, _, process, _| {
                    rows.push(process.role.clone());
                    if process.role == "failed_exit" {
                        Err(CollectError::Write(io::Error::other(
                            "injected refresh write",
                        )))
                    } else {
                        Ok(())
                    }
                },
                |_, _, _, _, _| panic!("discovery must not follow a failed exit write"),
            );
            assert!(matches!(result, Err(CollectError::Write(_))));
            let expected = if outsider_before {
                vec!["outsider", "failed_exit", "unknown_tail"]
            } else {
                vec!["failed_exit", "outsider", "unknown_tail"]
            };
            assert_eq!(
                tree.processes
                    .iter()
                    .map(|p| p.role.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "refresh must restore alive, failed exit and untouched tail in order"
            );
            let restored = tree
                .processes
                .iter()
                .find(|p| p.role == "outsider")
                .unwrap();
            assert_eq!(restored.proc_key, key);
            assert_eq!(restored.handle.as_ref().unwrap().raw(), raw);
            assert!(restored.confirmed_outsider);
            assert_eq!(rows, ["saved_exit", "failed_exit"]);
            let mut attempts = Vec::new();
            let result = tree.finish_with(
                1,
                1,
                Duration::ZERO,
                |p| {
                    attempts.push(p.role.clone());
                    Err(denied())
                },
                || Ok(Vec::new()),
                |p, _| match p.role.as_str() {
                    "outsider" => ExitObservation::Alive,
                    "failed_exit" => ExitObservation::Exited(None),
                    _ => ExitObservation::Unknown,
                },
                |tree, t, u, p, code| {
                    tree.write_event(t, u, ProcessEvent::Exit, p, code.map(i64::from), None)
                },
            );
            assert_eq!(attempts, ["outsider"]);
            tree.flush(false).unwrap();
            let csv = std::fs::read_to_string(dir.path().join("processes.csv")).unwrap();
            assert!(
                csv.contains("outsider"),
                "the actual start event must survive"
            );
            assert_saved_issues(dir.path(), result, crate::meta::EndReason::MemwatchError);
        }
    }

    #[test]
    fn start_write_failure_retains_failed_discovery_and_unprocessed_tail() {
        assert_start_write_failure_retains_discoveries(0);
    }

    #[test]
    fn start_write_failure_retains_previous_successes_and_unprocessed_tail() {
        assert_start_write_failure_retains_discoveries(1);
    }

    fn assert_start_write_failure_retains_discoveries(failing_index: usize) {
        let (dir, mut tree) = test_tree();
        tree.processes.push(unhandled_process(1, "existing"));
        let roles = ["saved_start", "failed_start", "tail_start", "unknown_tail"];
        // Held duplicates of this test's process exercise identity retention; the
        // termination callback below is always a mock and never kills a process.
        let mut discovered: Vec<_> = roles[..3]
            .iter()
            .map(|role| {
                let mut process = live_process(role);
                process.handle = Some(process.handle.take().unwrap().try_clone().unwrap());
                assert!(!tree.job.contains(process.handle.as_ref().unwrap()).unwrap());
                (process, Some(format!("command for {role}")))
            })
            .collect();
        discovered.push((unhandled_process(std::process::id(), roles[3]), None));
        let identities: Vec<_> = discovered
            .iter()
            .map(|(process, _)| {
                (
                    process.pid,
                    process.ppid,
                    process.creation_time,
                    process.proc_key.clone(),
                    process.role.clone(),
                    process.handle.as_ref().map(ProcHandle::raw),
                    process.confirmed_outsider,
                    process.threads,
                    process.image_path.clone(),
                )
            })
            .collect();
        let mut writes = Vec::new();
        let result =
            tree.start_processes_with(10, 20, discovered, |tree, t, u, process, cmdline| {
                writes.push(process.role.clone());
                if process.role == roles[failing_index] {
                    Err(CollectError::Write(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "injected start write",
                    )))
                } else {
                    tree.write_event(t, u, ProcessEvent::Start, process, None, cmdline)
                }
            });
        assert!(matches!(
            result,
            Err(CollectError::Write(ref error))
                if error.kind() == io::ErrorKind::WriteZero
                    && error.to_string() == "injected start write"
        ));
        assert_eq!(writes, roles[..=failing_index]);
        let retained: Vec<_> = tree.processes()[1..]
            .iter()
            .map(|process| {
                (
                    process.pid,
                    process.ppid,
                    process.creation_time,
                    process.proc_key.clone(),
                    process.role.clone(),
                    process.handle.as_ref().map(ProcHandle::raw),
                    process.confirmed_outsider,
                    process.threads,
                    process.image_path.clone(),
                )
            })
            .collect();
        assert_eq!(
            retained, identities,
            "failed Start and every untouched discovery must retain original identity and order"
        );
        assert_eq!(tree.processes()[0].role, "existing");

        let mut attempts = Vec::new();
        let outcome = tree.finish_with(
            30,
            40,
            Duration::ZERO,
            |process| {
                attempts.push(process.role.clone());
                Err(denied())
            },
            || Ok(Vec::new()),
            |process, _| {
                if process.confirmed_outsider {
                    ExitObservation::Alive
                } else {
                    ExitObservation::Unknown
                }
            },
            |_, _, _, _, _| panic!("unresolved discoveries must not receive Exit events"),
        );
        assert_eq!(attempts, roles[..3]);
        let mut meta = crate::analyze::fixtures::sample_meta();
        meta.end_reason = Some(crate::meta::EndReason::MemwatchError);
        meta.exit_code = Some(7);
        crate::sampler::save_shutdown(&mut meta, outcome).unwrap();
        assert_eq!(meta.end_reason, Some(crate::meta::EndReason::MemwatchError));
        assert_eq!(meta.exit_code, Some(7));
        tree.flush(false).unwrap();
        meta.write_atomic(dir.path()).unwrap();
        let run = crate::analyze::load(dir.path()).unwrap();
        assert_eq!(run.meta.end_reason, meta.end_reason);
        assert_eq!(run.meta.exit_code, Some(7));
        assert_eq!(run.meta.shutdown_issues, meta.shutdown_issues);
        assert_eq!(run.meta.shutdown_issues.len(), roles.len() + 1);
        let unknown = run.meta.shutdown_issues.last().unwrap();
        assert_eq!(unknown.role, "unknown_tail");
        assert_eq!(unknown.proc_key, None);
        assert_eq!(unknown.state, ShutdownState::Unknown);
        assert_eq!(unknown.reason, ShutdownReason::IdentityUnknown);
        assert_eq!(run.events.len(), failing_index);
        for (event, role) in run.events.iter().zip(&roles) {
            assert_eq!(event.event, Some(ProcessEvent::Start));
            assert_eq!(event.role.as_deref(), Some(*role));
        }
        let summary = crate::analyze::summarize(
            &run,
            crate::analyze::Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );
        for lang in [crate::report::Lang::En, crate::report::Lang::Ru] {
            let view = crate::report::build(&run, &summary, lang);
            assert_eq!(view.header[5].1, "memwatch_error");
            assert_eq!(view.process_rows.len(), failing_index);
            assert!(view.process_rows.iter().all(|row| row[4..6] == ["—", "—"]));
            for (index, role) in roles[..3].iter().enumerate() {
                let issue = &run.meta.shutdown_issues[index + 1];
                assert_eq!(issue.role, *role);
                assert_eq!(issue.proc_key.as_ref(), Some(&identities[index].3));
                assert_eq!(issue.pid, identities[index].0);
                assert_eq!(issue.state, ShutdownState::Alive);
                assert_eq!(issue.reason, ShutdownReason::AccessDenied);
                let key = issue.proc_key.as_deref().unwrap();
                let rendered_role = role.replace('_', "\\_");
                let expected = match lang {
                    crate::report::Lang::En => format!(
                        "Incomplete shutdown: PID {}, identity {key}, role {rendered_role}, state alive, reason access denied",
                        issue.pid
                    ),
                    crate::report::Lang::Ru => format!(
                        "Неполная остановка: PID {}, идентичность {key}, роль {rendered_role}, состояние жив, причина отказ в доступе",
                        issue.pid
                    ),
                };
                assert!(
                    view.warnings.contains(&expected),
                    "expected {expected:?}, warnings: {:?}",
                    view.warnings
                );
                assert!(crate::report::render(&view).contains(&format!("- {expected}")));
            }
        }
    }

    #[test]
    fn finish_write_failure_preserves_unresolved_outsider_diagnostics() {
        let (dir, mut tree) = test_tree();
        let outsider = live_process("outsider");
        tree.write_event(0, 0, ProcessEvent::Start, &outsider, None, None)
            .unwrap();
        tree.processes = vec![
            outsider,
            live_process("failed_exit"),
            live_process("later_exit"),
        ];
        let attempts = std::cell::RefCell::new(Vec::new());
        let mut rows = Vec::new();
        let mut phase = 0;
        let result = tree.finish_with(
            1,
            1,
            Duration::ZERO,
            |p| {
                attempts.borrow_mut().push(p.role.clone());
                if p.role == "outsider" {
                    Err(denied())
                } else {
                    Ok(())
                }
            },
            || Ok(Vec::new()),
            |p, _| {
                phase += 1;
                if phase <= 3 || p.role == "outsider" {
                    ExitObservation::Alive
                } else {
                    ExitObservation::Exited(Some(1))
                }
            },
            |_, _, _, p, _| {
                assert_eq!(
                    attempts.borrow().len(),
                    3,
                    "cleanup must precede every write"
                );
                rows.push(p.role.clone());
                if p.role == "failed_exit" {
                    Err(CollectError::Write(io::Error::other(
                        "injected finish write",
                    )))
                } else {
                    Ok(())
                }
            },
        );
        let failure = result.as_ref().unwrap_err();
        assert_eq!(failure.outcome.issues.len(), 1);
        assert_eq!(
            failure.outcome.issues[0].reason,
            ShutdownReason::AccessDenied
        );
        assert!(
            matches!(&failure.error, CollectError::Write(err) if err.to_string() == "injected finish write")
        );
        assert_eq!(rows, ["failed_exit", "later_exit"]);
        tree.flush(false).unwrap();
        assert_saved_issues(dir.path(), result, crate::meta::EndReason::AppExited);
    }

    fn entry(pid: u32, ppid: u32, threads: u32, exe_name: &str) -> SnapshotEntry {
        SnapshotEntry {
            pid,
            ppid,
            threads,
            exe_name: exe_name.to_string(),
        }
    }

    #[test]
    fn role_for_root_is_main() {
        assert_eq!(
            role_for(true, Some("x --type=renderer"), "msedgewebview2.exe"),
            "main"
        );
    }

    #[test]
    fn role_for_uses_type_flag() {
        assert_eq!(
            role_for(
                false,
                Some("msedgewebview2.exe --type=gpu-process --no-sandbox"),
                "msedgewebview2.exe"
            ),
            "gpu-process"
        );
        assert_eq!(
            role_for(
                false,
                Some(r#"msedgewebview2.exe "--type=utility" --no-sandbox"#),
                "msedgewebview2.exe"
            ),
            "utility"
        );
    }

    #[test]
    fn role_for_falls_back_to_exe_stem() {
        assert_eq!(
            role_for(
                false,
                Some("MsEdgeWebView2.exe --no-sandbox"),
                "MsEdgeWebView2.exe"
            ),
            "msedgewebview2"
        );
        assert_eq!(role_for(false, None, "conhost.exe"), "conhost");
    }

    #[test]
    fn proc_key_formats_pid_and_creation() {
        assert_eq!(
            proc_key(1234, 133_000_000_000_000_000),
            "1234-133000000000000000"
        );
    }

    #[test]
    fn descendants_follow_parents_level_by_level() {
        let snapshot = [
            entry(30, 20, 1, "grandchild.exe"),
            entry(20, 10, 1, "child.exe"),
            entry(40, 99, 1, "stranger.exe"),
        ];
        let times: HashMap<u32, u64> = [(20, 2_000), (30, 3_000), (40, 4_000)].into();
        let mut calls = Vec::new();
        let found = descendants(&[(10, 1_000)], &snapshot, |pid, ppid| {
            calls.push((pid, ppid));
            times.get(&pid).copied()
        });

        assert_eq!(
            found,
            [(20, 2_000), (30, 3_000)],
            "the child and, through it, the grandchild must be accepted in level order"
        );
        assert_eq!(
            calls,
            [(20, 10), (30, 20)],
            "only children of tracked parents must be opened"
        );
    }

    #[test]
    fn descendants_reject_older_child_and_its_subtree() {
        let snapshot = [
            entry(20, 10, 1, "old-child.exe"),
            entry(30, 20, 1, "grandchild.exe"),
        ];
        let times: HashMap<u32, u64> = [(20, 500), (30, 2_000)].into();
        let found = descendants(&[(10, 1_000)], &snapshot, |pid, _| times.get(&pid).copied());
        assert!(
            found.is_empty(),
            "a child created before its parent and its subtree must be rejected"
        );
    }

    #[test]
    fn descendants_skip_unopenable() {
        let snapshot = [
            entry(20, 10, 1, "child.exe"),
            entry(30, 20, 1, "grandchild.exe"),
        ];
        let mut calls = Vec::new();
        let found = descendants(&[(10, 1_000)], &snapshot, |pid, _| {
            calls.push(pid);
            if pid == 20 { None } else { Some(2_000) }
        });
        assert!(
            found.is_empty(),
            "a process that cannot be opened and its subtree must be rejected"
        );
        assert_eq!(
            calls,
            [20],
            "the children of a rejected process must not be opened"
        );
    }

    #[test]
    fn select_pids_keeps_job_list_when_all_inside() {
        let (pids, fallback) = select_pids(&[1, 2, 3], &[2, 3], &[], false);
        assert_eq!(pids, [1, 2, 3], "the job list must stay authoritative");
        assert!(!fallback, "no outsider means no fallback");
    }

    #[test]
    fn select_pids_switches_on_confirmed_outsider() {
        let (pids, fallback) = select_pids(&[1, 2], &[2, 5, 6], &[5], false);
        assert_eq!(
            pids,
            [1, 2, 5, 6],
            "a confirmed outsider must add the descendants to the job list"
        );
        assert!(fallback, "a confirmed outsider must switch to tree walking");
    }

    #[test]
    fn select_pids_stays_in_fallback() {
        let (pids, fallback) = select_pids(&[1, 2], &[3], &[], true);
        assert_eq!(
            pids,
            [1, 2, 3],
            "an active fallback must keep the descendants even without outsiders"
        );
        assert!(fallback, "the fallback must stay active");
    }

    #[test]
    fn unstarted_pids_skips_pids_missing_from_snapshot() {
        let tracked = [1];
        let pids = [1, 2, 3];
        let snapshot = [entry(1, 0, 1, "root.exe"), entry(2, 1, 1, "child.exe")];
        assert_eq!(
            unstarted_pids(&tracked, &pids, &snapshot),
            [2],
            "a PID that is missing from the snapshot must not be started"
        );

        let snapshot = [
            entry(1, 0, 1, "root.exe"),
            entry(2, 1, 1, "child.exe"),
            entry(3, 2, 1, "grandchild.exe"),
        ];
        assert_eq!(
            unstarted_pids(&tracked, &pids, &snapshot),
            [2, 3],
            "a PID must be started once it appears in the snapshot"
        );
    }
}
