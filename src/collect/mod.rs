//! The collector contract shared by every data source.
//!
//! A collector reads one kind of data on the run's tick. Its errors are
//! counted per collector, so a broken data source never stops the run, while
//! a failed write to the run directory stops it.

pub mod job;
pub mod process;
pub mod system;

use std::fmt;
use std::io;

use crate::collect::process::TrackedProcess;
use crate::meta::CollectorStatus;

/// Number of consecutive failed ticks after which a collector is stopped.
const FAILURE_THRESHOLD: u32 = 10;

/// Failure of one collector tick.
#[derive(Debug)]
pub enum CollectError {
    /// The data source could not be read; the run continues and the failure
    /// is counted by [`FailureCounter`].
    Source(anyhow::Error),
    /// Writing to the run directory failed; the run stops.
    Write(io::Error),
}

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectError::Source(err) => write!(f, "{err}"),
            CollectError::Write(err) => write!(f, "cannot write to the run directory: {err}"),
        }
    }
}

impl std::error::Error for CollectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CollectError::Source(err) => Some(err.as_ref()),
            CollectError::Write(err) => Some(err),
        }
    }
}

/// Everything a collector sees at one tick.
pub struct TickCtx<'a> {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// Number of the tick, starting at zero.
    pub tick: u64,
    /// Processes tracked at this tick.
    pub processes: &'a [TrackedProcess],
}

/// A data source sampled on the run's tick.
pub trait Collector {
    /// Name of the collector; also its file and status name.
    fn name(&self) -> &str;

    /// Number of ticks between two samples.
    fn every_ticks(&self) -> u32;

    /// Reads one sample into the collector's file.
    fn sample(&mut self, ctx: &TickCtx) -> Result<(), CollectError>;

    /// Flushes the collector's file to the operating system.
    ///
    /// When `durable` is set, the file is also synced to the storage device.
    fn flush(&mut self, durable: bool) -> io::Result<()>;
}

/// Counts consecutive collector failures and reports the collector status.
pub struct FailureCounter {
    failures: u32,
    status: CollectorStatus,
}

impl FailureCounter {
    /// Creates a counter in the `ok` state.
    pub fn new() -> FailureCounter {
        FailureCounter {
            failures: 0,
            status: CollectorStatus::Ok,
        }
    }

    /// Records a successful tick and resets the failure count.
    pub fn record_ok(&mut self) {
        self.failures = 0;
        self.status = CollectorStatus::Ok;
    }

    /// Records a failed tick.
    ///
    /// The tenth failure in a row stops the collector with `reason` as its
    /// status.
    pub fn record_err(&mut self, reason: String) {
        self.failures += 1;
        if self.failures >= FAILURE_THRESHOLD {
            self.status = CollectorStatus::Failed(reason);
        }
    }

    /// Returns the current collector status.
    pub fn status(&self) -> CollectorStatus {
        self.status.clone()
    }

    /// Returns whether the collector was stopped after repeated failures.
    pub fn is_failed(&self) -> bool {
        matches!(self.status, CollectorStatus::Failed(_))
    }
}

impl Default for FailureCounter {
    fn default() -> FailureCounter {
        FailureCounter::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::CollectorStatus;

    #[test]
    fn failure_counter_fails_after_ten_in_a_row() {
        let mut counter = FailureCounter::new();
        for attempt in 0..9 {
            counter.record_err(format!("error {attempt}"));
        }
        assert_eq!(
            counter.status(),
            CollectorStatus::Ok,
            "nine errors in a row must keep the collector running"
        );
        assert!(!counter.is_failed());

        counter.record_err("tenth error".to_string());
        assert_eq!(
            counter.status(),
            CollectorStatus::Failed("tenth error".to_string()),
            "the tenth error in a row must fail the collector with its reason"
        );
        assert!(counter.is_failed());

        let mut counter = FailureCounter::new();
        for attempt in 0..9 {
            counter.record_err(format!("error {attempt}"));
        }
        counter.record_ok();
        for attempt in 0..9 {
            counter.record_err(format!("error {attempt}"));
        }
        assert_eq!(
            counter.status(),
            CollectorStatus::Ok,
            "a success between errors must reset the count"
        );
        assert!(!counter.is_failed());

        counter.record_err("after reset".to_string());
        assert_eq!(
            counter.status(),
            CollectorStatus::Failed("after reset".to_string())
        );
    }
}
