//! The process tree: discovery, lifecycle events and per-process metrics.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::collect::{CollectError, Collector, TickCtx};
use crate::launch::Job;
use crate::log::RunLog;
use crate::meta::ImageInfo;
use crate::store::{CsvTable, ProcessEvent, ProcessEventRow, ProcessRow, fmt_pct};
use crate::win::{self, ProcHandle, ProcessMetrics, SnapshotEntry};

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
        let snapshot = win::snapshot().map_err(CollectError::Source)?;
        let job_pids = self.job.process_ids().map_err(CollectError::Source)?;

        self.record_exits(t_ms, unix_ms, &snapshot, &job_pids)?;
        self.update_threads(&snapshot);

        if !self.root_started {
            self.start_root(t_ms, unix_ms, &snapshot)?;
            self.root_started = true;
        }

        let parents: Vec<(u32, u64)> = self
            .processes
            .iter()
            .filter(|process| process.handle.is_some())
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
            opened.insert(pid, handle);
            Some(created)
        });

        let mut confirmed_outsiders = Vec::new();
        for (pid, _) in &found {
            if job_pids.contains(pid) {
                continue;
            }
            let Some(handle) = opened.get(pid) else {
                continue;
            };
            if !matches!(handle.exit_code(), Ok(None)) {
                continue;
            }
            if let Ok(false) = self.job.contains(handle) {
                confirmed_outsiders.push(*pid);
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
            self.start_process(t_ms, unix_ms, pid, handle, &snapshot)?;
        }
        Ok(())
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

    /// Waits for the remaining processes to exit and writes their `exit` rows.
    ///
    /// Processes that are still running after `wait` get an empty exit code.
    pub fn finish(&mut self, t_ms: u64, unix_ms: u64, wait: Duration) -> Result<(), CollectError> {
        let deadline = Instant::now() + wait;
        while !self.all_exited() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }

        for process in std::mem::take(&mut self.processes) {
            let exit_code = process
                .handle
                .as_ref()
                .and_then(|handle| handle.exit_code().ok().flatten())
                .map(|code| code as i64);
            self.write_event(t_ms, unix_ms, ProcessEvent::Exit, &process, exit_code, None)?;
        }
        Ok(())
    }

    /// Returns whether every tracked handle has signaled.
    fn all_exited(&self) -> bool {
        self.processes.iter().all(|process| match &process.handle {
            Some(handle) => !matches!(handle.exit_code(), Ok(None)),
            None => true,
        })
    }

    /// Removes the exited processes and writes their `exit` rows.
    ///
    /// A tracked process with a handle has exited when the handle has
    /// signaled. A tracked process without a handle has exited when it is
    /// missing from the snapshot, or, in job mode, from the job list; its
    /// exit code stays empty.
    fn record_exits(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        snapshot: &[SnapshotEntry],
        job_pids: &[u32],
    ) -> Result<(), CollectError> {
        let mut alive = Vec::with_capacity(self.processes.len());
        for process in std::mem::take(&mut self.processes) {
            match &process.handle {
                Some(handle) => match handle.exit_code() {
                    Ok(Some(code)) => {
                        let code = code as i64;
                        self.write_event(
                            t_ms,
                            unix_ms,
                            ProcessEvent::Exit,
                            &process,
                            Some(code),
                            None,
                        )?;
                    }
                    Ok(None) => alive.push(process),
                    Err(err) => {
                        self.log.error(
                            "process",
                            format!("cannot read the exit code of PID {}: {err}", process.pid),
                        );
                        alive.push(process);
                    }
                },
                None => {
                    let missing = !snapshot.iter().any(|entry| entry.pid == process.pid)
                        || (!self.tree_walk_fallback && !job_pids.contains(&process.pid));
                    if missing {
                        self.write_event(t_ms, unix_ms, ProcessEvent::Exit, &process, None, None)?;
                    } else {
                        alive.push(process);
                    }
                }
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

    /// Adds one found process and writes its `start` row.
    fn start_process(
        &mut self,
        t_ms: u64,
        unix_ms: u64,
        pid: u32,
        handle: Option<ProcHandle>,
        snapshot: &[SnapshotEntry],
    ) -> Result<(), CollectError> {
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
            proc_key: proc_key(pid, creation_time),
            pid,
            ppid: entry.map(|entry| entry.ppid).unwrap_or(0),
            creation_time,
            role: role_for(false, cmdline.as_deref(), exe_name),
            handle,
            image_path,
            threads: entry.map(|entry| entry.threads),
        };
        self.record_image(&process.image_path);
        self.write_event(t_ms, unix_ms, ProcessEvent::Start, &process, None, cmdline)?;
        self.processes.push(process);
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
