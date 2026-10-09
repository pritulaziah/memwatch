//! The run lifecycle: ticks, collector scheduling, stop conditions and the
//! final `meta.json`.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use windows::Win32::System::Power::{
    ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED, SetThreadExecutionState,
};

use crate::collect::cdp::CdpCollector;
use crate::collect::gpu::GpuCollector;
use crate::collect::job::JobCollector;
use crate::collect::process::{ProcessCollector, ProcessTree, ShutdownFailure, ShutdownOutcome};
use crate::collect::system::SystemCollector;
use crate::collect::{CollectError, Collector, FailureCounter, TickCtx};
use crate::launch::{Launched, launch};
use crate::log::RunLog;
use crate::meta::{CollectorStatus, EndReason, Meta, host_info};
use crate::options::RunOptions;
use crate::store::{
    CDP_COLUMNS, CsvTable, GPU_COLUMNS, JOB_COLUMNS, PROCESS_COLUMNS, PROCESSES_COLUMNS,
    SYSTEM_COLUMNS, create_run_dir,
};

/// How often the CSV files are synced to the storage device.
const FSYNC_INTERVAL: Duration = Duration::from_secs(60);

/// How long the tree is given to exit after the job is terminated.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// How long the DevTools polling thread is given to stop after the run.
const CDP_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Saves shutdown diagnostics before propagating any original collection error.
pub(crate) fn save_shutdown(
    meta: &mut Meta,
    result: Result<ShutdownOutcome, ShutdownFailure>,
) -> Result<(), CollectError> {
    match result {
        Ok(outcome) => {
            meta.shutdown_issues = outcome.issues;
            Ok(())
        }
        Err(failure) => {
            meta.shutdown_issues = failure.outcome.issues;
            Err(failure.error)
        }
    }
}

/// A handle that asks a run to stop.
#[derive(Clone)]
pub struct StopHandle {
    state: Arc<(Mutex<bool>, Condvar)>,
}

impl StopHandle {
    /// Creates a handle in the not-stopped state.
    pub fn new() -> StopHandle {
        StopHandle {
            state: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// Asks the run to stop.
    pub fn stop(&self) {
        let (lock, condvar) = &*self.state;
        let mut stopped = lock.lock().expect("the stop mutex is not poisoned");
        *stopped = true;
        condvar.notify_all();
    }

    /// Returns whether a stop was requested.
    pub fn is_stopped(&self) -> bool {
        let (lock, _) = &*self.state;
        *lock.lock().expect("the stop mutex is not poisoned")
    }

    /// Waits until a stop is requested or `timeout` runs out.
    ///
    /// Returns `true` when the run must stop.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let (lock, condvar) = &*self.state;
        let stopped = lock.lock().expect("the stop mutex is not poisoned");
        let (stopped, _) = condvar
            .wait_timeout_while(stopped, timeout, |stopped| !*stopped)
            .expect("the stop mutex is not poisoned");
        *stopped
    }
}

impl Default for StopHandle {
    fn default() -> StopHandle {
        StopHandle::new()
    }
}

/// What a finished run leaves behind.
pub struct RunOutcome {
    /// Directory of the run.
    pub run_dir: PathBuf,
    /// Why the run stopped.
    pub end_reason: EndReason,
    /// Exit code of the main process; `None` when it did not exit on its own.
    pub exit_code: Option<i64>,
}

/// Keeps the machine awake for as long as it is alive.
///
/// When enabled, the constructor sets `ES_CONTINUOUS | ES_SYSTEM_REQUIRED |
/// ES_DISPLAY_REQUIRED`; dropping the value resets the state to
/// `ES_CONTINUOUS`.
pub struct KeepAwake {
    enabled: bool,
}

impl KeepAwake {
    /// Prevents system sleep and display off while the value is alive.
    pub fn new(enabled: bool) -> KeepAwake {
        if enabled {
            // SAFETY: the flags are plain constants; the call takes no
            // pointers and cannot fail.
            unsafe {
                let _ = SetThreadExecutionState(
                    ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED,
                );
            }
        }
        KeepAwake { enabled }
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        if self.enabled {
            // SAFETY: the flag is a plain constant; the call takes no
            // pointers and cannot fail.
            unsafe {
                let _ = SetThreadExecutionState(ES_CONTINUOUS);
            }
        }
    }
}

/// Runs `opts.command` and records the resource usage of its process tree.
///
/// The run directory is created before the application starts. A failure to
/// create the directory, the log or the initial `meta.json` is returned as an
/// error; a failed launch or a failure to create the CSV files leaves a
/// finished run directory with the matching [`EndReason`].
pub fn run(opts: &RunOptions, stop: StopHandle) -> anyhow::Result<RunOutcome> {
    let started = Instant::now();
    let started_at = now_local();
    let run_dir = create_run_dir(&opts.out_dir, &opts.name, started_at)?;
    let log = RunLog::create(&run_dir.join("memwatch.log"))?;
    let mut meta = Meta::new(opts, started_at, host_info());

    if let Err(err) = meta.write_atomic(&run_dir) {
        log.error("sampler", format!("cannot write meta.json: {err}"));
        return Err(err.into());
    }

    let (events, process_table, job_table, system_table, gpu_table, cdp_table) =
        match create_tables(&run_dir) {
            Ok(tables) => tables,
            Err(err) => {
                log.error("sampler", format!("cannot create the CSV files: {err}"));
                return Ok(finish_start_failure(
                    &log,
                    &mut meta,
                    &run_dir,
                    EndReason::MemwatchError,
                ));
            }
        };

    let Launched {
        job,
        root,
        root_pid,
    } = match launch(&opts.command, &meta.env_overrides, &run_dir) {
        Ok(launched) => launched,
        Err(err) => {
            log.error("launch", format!("cannot launch the application: {err}"));
            return Ok(finish_start_failure(
                &log,
                &mut meta,
                &run_dir,
                EndReason::LaunchFailed,
            ));
        }
    };

    if let Some(duration) = opts.duration {
        let timer_stop = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(duration);
            timer_stop.stop();
        });
    }

    let gpu_every_ticks = (opts.gpu_interval.as_millis() / opts.interval.as_millis()) as u32;
    let cdp = match opts.cdp_port {
        Some(port) => CdpCollector::start(port, opts.cdp_interval, started, cdp_table, log.clone()),
        None => CdpCollector::disabled(cdp_table),
    };

    let logical_cpus = meta.host.logical_cpus;
    let mut sampler = Sampler {
        tree: ProcessTree::new(job.clone(), root, root_pid, events, log.clone()),
        process: ProcessCollector::new(process_table, log.clone(), logical_cpus),
        job: JobCollector::new(job.clone(), job_table, logical_cpus),
        system: SystemCollector::new(system_table, logical_cpus),
        gpu: GpuCollector::new(gpu_table, log.clone(), gpu_every_ticks),
        process_counter: FailureCounter::new(),
        job_counter: FailureCounter::new(),
        system_counter: FailureCounter::new(),
        gpu_counter: FailureCounter::new(),
        cdp,
        log: log.clone(),
    };
    let _keep_awake = KeepAwake::new(!opts.allow_sleep);

    let mut exit_code = None;
    let mut tick = 0u64;
    let mut last_fsync: Option<Instant> = None;
    let mut final_sample = true;

    let mut end_reason = loop {
        let t_ms = started.elapsed().as_millis() as u64;
        let unix_ms = unix_ms_now();
        let sampled_process = !sampler.process_counter.is_failed();

        if sampler.sample_tick(tick, t_ms, unix_ms).is_err() {
            break EndReason::MemwatchError;
        }

        let durable = last_fsync.is_none_or(|at| at.elapsed() >= FSYNC_INTERVAL);
        if durable {
            last_fsync = Some(Instant::now());
        }
        if let Err(err) = sampler.flush(durable) {
            log.error("sampler", format!("cannot flush the CSV files: {err}"));
            break EndReason::MemwatchError;
        }

        if let Some(code) = sampler.tree.root_exit() {
            exit_code = code.map(i64::from);
            final_sample = !sampled_process;
            break EndReason::AppExited;
        }

        tick += 1;
        let mut target = started + opts.interval * tick as u32;
        while target <= Instant::now() {
            tick += 1;
            target += opts.interval;
        }
        if stop.wait_timeout(target.saturating_duration_since(Instant::now())) {
            break EndReason::CtrlC;
        }
    };

    // The final sample is skipped after a memwatch error and when the exit of
    // the root was already seen after this tick's sample.
    if end_reason != EndReason::MemwatchError && final_sample {
        let t_ms = started.elapsed().as_millis() as u64;
        let unix_ms = unix_ms_now();
        if sampler.sample_final(tick, t_ms, unix_ms).is_err() {
            end_reason = EndReason::MemwatchError;
        }
        if let Err(err) = sampler.flush(true) {
            log.error("sampler", format!("cannot flush the CSV files: {err}"));
            end_reason = EndReason::MemwatchError;
        }
    }

    if let Err(err) = job.terminate(1) {
        log.error("sampler", format!("cannot terminate the job: {err}"));
    }

    let t_ms = started.elapsed().as_millis() as u64;
    let unix_ms = unix_ms_now();
    match save_shutdown(&mut meta, sampler.tree.finish(t_ms, unix_ms, SHUTDOWN_WAIT)) {
        Ok(()) => {}
        Err(CollectError::Source(err)) => {
            log.error("process", format!("cannot finish the process tree: {err}"));
        }
        Err(CollectError::Write(err)) => {
            log.error("process", format!("cannot write processes.csv: {err}"));
            if end_reason != EndReason::MemwatchError {
                end_reason = EndReason::MemwatchError;
            }
        }
    }

    if let Err(err) = sampler.flush(true) {
        log.error("sampler", format!("cannot flush the CSV files: {err}"));
        end_reason = EndReason::MemwatchError;
    }

    sampler.cdp.stop();
    if !sampler.cdp.join(CDP_JOIN_TIMEOUT) {
        log.error(
            "cdp",
            format!("the DevTools polling thread did not stop within {CDP_JOIN_TIMEOUT:?}"),
        );
    }

    let gpu_status = if sampler.gpu.unavailable() {
        CollectorStatus::Unavailable
    } else {
        sampler.gpu_counter.status()
    };

    meta.ended_at = Some(now_rfc3339());
    meta.end_reason = Some(end_reason);
    meta.exit_code = exit_code;
    meta.images = sampler.tree.images();
    meta.collectors = BTreeMap::from([
        ("process".to_string(), sampler.process_counter.status()),
        ("job".to_string(), sampler.job_counter.status()),
        ("system".to_string(), sampler.system_counter.status()),
        ("gpu".to_string(), gpu_status),
        ("cdp".to_string(), sampler.cdp.status()),
    ]);
    meta.tree_walk_fallback = sampler.tree.tree_walk_fallback();

    if let Err(err) = meta.write_atomic(&run_dir) {
        log.error("sampler", format!("cannot write meta.json: {err}"));
        if end_reason != EndReason::MemwatchError {
            end_reason = EndReason::MemwatchError;
            meta.end_reason = Some(end_reason);
            if let Err(err) = meta.write_atomic(&run_dir) {
                log.error("sampler", format!("cannot write meta.json: {err}"));
            }
        }
    }

    Ok(RunOutcome {
        run_dir,
        end_reason,
        exit_code,
    })
}

/// Creates the six CSV files of the run with their headers.
fn create_tables(
    run_dir: &Path,
) -> io::Result<(CsvTable, CsvTable, CsvTable, CsvTable, CsvTable, CsvTable)> {
    Ok((
        CsvTable::create(&run_dir.join("processes.csv"), PROCESSES_COLUMNS)?,
        CsvTable::create(&run_dir.join("process.csv"), PROCESS_COLUMNS)?,
        CsvTable::create(&run_dir.join("job.csv"), JOB_COLUMNS)?,
        CsvTable::create(&run_dir.join("system.csv"), SYSTEM_COLUMNS)?,
        CsvTable::create(&run_dir.join("gpu.csv"), GPU_COLUMNS)?,
        CsvTable::create(&run_dir.join("cdp.csv"), CDP_COLUMNS)?,
    ))
}

/// Writes the final `meta.json` of a run that never started.
fn finish_start_failure(
    log: &RunLog,
    meta: &mut Meta,
    run_dir: &Path,
    end_reason: EndReason,
) -> RunOutcome {
    meta.ended_at = Some(now_rfc3339());
    meta.end_reason = Some(end_reason);
    if let Err(err) = meta.write_atomic(run_dir) {
        log.error("sampler", format!("cannot write meta.json: {err}"));
    }
    RunOutcome {
        run_dir: run_dir.to_path_buf(),
        end_reason,
        exit_code: None,
    }
}

/// The collectors of a running run together with their failure counters.
struct Sampler {
    tree: ProcessTree,
    process: ProcessCollector,
    job: JobCollector,
    system: SystemCollector,
    gpu: GpuCollector,
    process_counter: FailureCounter,
    job_counter: FailureCounter,
    system_counter: FailureCounter,
    gpu_counter: FailureCounter,
    cdp: CdpCollector,
    log: RunLog,
}

impl Sampler {
    /// Runs one scheduled tick of every live collector.
    fn sample_tick(&mut self, tick: u64, t_ms: u64, unix_ms: u64) -> Result<(), EndReason> {
        self.sample_process(tick, t_ms, unix_ms)?;
        self.sample_others(tick, t_ms, unix_ms, true)
    }

    /// Runs the final sample of every live collector, ignoring their schedule.
    fn sample_final(&mut self, tick: u64, t_ms: u64, unix_ms: u64) -> Result<(), EndReason> {
        self.sample_process(tick, t_ms, unix_ms)?;
        self.sample_others(tick, t_ms, unix_ms, false)
    }

    /// Samples the process tree and `process.csv` for one tick.
    ///
    /// The refresh and the sample count as one result per tick: when the
    /// refresh fails, the sample is skipped and the refresh error is the
    /// reason. A failed collector is not called at all; the root is still
    /// checked through [`ProcessTree::root_exit`].
    fn sample_process(&mut self, tick: u64, t_ms: u64, unix_ms: u64) -> Result<(), EndReason> {
        if self.process_counter.is_failed() {
            return Ok(());
        }
        match self.tree.refresh(t_ms, unix_ms) {
            Ok(()) => {
                let ctx = TickCtx {
                    t_ms,
                    unix_ms,
                    tick,
                    processes: self.tree.processes(),
                };
                match self.process.sample(&ctx) {
                    Ok(()) => {
                        self.process_counter.record_ok();
                        Ok(())
                    }
                    Err(CollectError::Source(err)) => {
                        self.log
                            .error("process", format!("cannot sample the process tree: {err}"));
                        self.process_counter.record_err(err.to_string());
                        Ok(())
                    }
                    Err(CollectError::Write(err)) => {
                        self.log
                            .error("process", format!("cannot write process.csv: {err}"));
                        Err(EndReason::MemwatchError)
                    }
                }
            }
            Err(CollectError::Source(err)) => {
                self.log
                    .error("process", format!("cannot refresh the process tree: {err}"));
                self.process_counter.record_err(err.to_string());
                Ok(())
            }
            Err(CollectError::Write(err)) => {
                self.log
                    .error("process", format!("cannot write processes.csv: {err}"));
                Err(EndReason::MemwatchError)
            }
        }
    }

    /// Samples the job, system and gpu collectors.
    ///
    /// With `scheduled_only` each collector runs only on the ticks of its
    /// schedule; otherwise every live collector runs.
    fn sample_others(
        &mut self,
        tick: u64,
        t_ms: u64,
        unix_ms: u64,
        scheduled_only: bool,
    ) -> Result<(), EndReason> {
        let ctx = TickCtx {
            t_ms,
            unix_ms,
            tick,
            processes: self.tree.processes(),
        };
        if !self.job_counter.is_failed()
            && (!scheduled_only || tick.is_multiple_of(u64::from(self.job.every_ticks())))
        {
            sample_collector(&mut self.job, &mut self.job_counter, &self.log, &ctx)?;
        }
        if !self.system_counter.is_failed()
            && (!scheduled_only || tick.is_multiple_of(u64::from(self.system.every_ticks())))
        {
            sample_collector(&mut self.system, &mut self.system_counter, &self.log, &ctx)?;
        }
        if !self.gpu_counter.is_failed()
            && (!scheduled_only || tick.is_multiple_of(u64::from(self.gpu.every_ticks())))
        {
            sample_collector(&mut self.gpu, &mut self.gpu_counter, &self.log, &ctx)?;
        }
        Ok(())
    }

    /// Flushes every CSV file to the operating system.
    fn flush(&mut self, durable: bool) -> io::Result<()> {
        self.tree.flush(durable)?;
        self.process.flush(durable)?;
        self.job.flush(durable)?;
        self.system.flush(durable)?;
        self.gpu.flush(durable)?;
        self.cdp.flush(durable)?;
        Ok(())
    }
}

/// Samples one collector and records its result in `counter`.
///
/// A source error is logged and counted; a write error stops the run.
fn sample_collector(
    collector: &mut dyn Collector,
    counter: &mut FailureCounter,
    log: &RunLog,
    ctx: &TickCtx,
) -> Result<(), EndReason> {
    match collector.sample(ctx) {
        Ok(()) => {
            counter.record_ok();
            Ok(())
        }
        Err(CollectError::Source(err)) => {
            log.error(collector.name(), format!("cannot sample: {err}"));
            counter.record_err(err.to_string());
            Ok(())
        }
        Err(CollectError::Write(err)) => {
            log.error(
                collector.name(),
                format!("cannot write the CSV file: {err}"),
            );
            Err(EndReason::MemwatchError)
        }
    }
}

/// Returns the current local time, falling back to UTC when the local offset
/// cannot be determined.
fn now_local() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

/// Returns the current time as an RFC 3339 string in the local offset.
fn now_rfc3339() -> String {
    now_local()
        .format(&Rfc3339)
        .expect("the fixed RFC 3339 format is valid for any date-time")
}

/// Returns the current wall-clock time in milliseconds since the epoch.
fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{ShutdownIssue, ShutdownReason, ShutdownState};

    #[test]
    fn shutdown_diagnostics_preserve_run_outcome() {
        let mut meta = crate::analyze::fixtures::sample_meta();
        meta.end_reason = Some(EndReason::CtrlC);
        meta.exit_code = Some(7);
        let outcome = RunOutcome {
            run_dir: PathBuf::from("owned-run"),
            end_reason: EndReason::CtrlC,
            exit_code: Some(7),
        };
        let issue = ShutdownIssue {
            pid: 12,
            proc_key: None,
            role: "main".into(),
            state: ShutdownState::Alive,
            reason: ShutdownReason::WaitTimeout,
        };
        save_shutdown(
            &mut meta,
            Ok(ShutdownOutcome {
                issues: vec![issue.clone()],
            }),
        )
        .unwrap();
        assert_eq!(
            meta.shutdown_issues.as_slice(),
            std::slice::from_ref(&issue)
        );
        let result = save_shutdown(
            &mut meta,
            Err(ShutdownFailure {
                outcome: ShutdownOutcome {
                    issues: vec![issue.clone()],
                },
                error: CollectError::Write(io::Error::other("original write failure")),
            }),
        );
        assert!(
            matches!(result, Err(CollectError::Write(err)) if err.to_string() == "original write failure")
        );
        assert_eq!(meta.shutdown_issues, [issue]);
        assert_eq!(meta.end_reason, Some(outcome.end_reason));
        assert_eq!(meta.exit_code, outcome.exit_code);
        assert_eq!(outcome.run_dir, PathBuf::from("owned-run"));
    }
}
