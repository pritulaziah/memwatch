//! Machine-wide counters written to `system.csv`.

use std::io;
use std::mem::size_of;
use std::time::Instant;

use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::GetSystemTimes;

use crate::collect::{CollectError, Collector, TickCtx};
use crate::store::{CsvTable, SystemRow, fmt_pct};
use crate::win::{self, ProcHandle, ProcessMetrics};

/// Machine-wide CPU times in 100 ns units, as read by `GetSystemTimes`.
///
/// `kernel` includes `idle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemTimes {
    /// Idle time.
    pub idle: u64,
    /// Kernel time; includes the idle time.
    pub kernel: u64,
    /// User time.
    pub user: u64,
}

/// Computes whole-machine CPU usage from two `GetSystemTimes` samples:
/// `(Δkernel + Δuser − Δidle) / (Δkernel + Δuser) × 100`.
///
/// Returns `0.0` when neither kernel nor user time has advanced.
pub fn system_cpu_pct(prev: SystemTimes, cur: SystemTimes) -> f64 {
    let kernel = cur.kernel.saturating_sub(prev.kernel) as f64;
    let user = cur.user.saturating_sub(prev.user) as f64;
    let idle = cur.idle.saturating_sub(prev.idle) as f64;
    let total = kernel + user;
    if total == 0.0 {
        return 0.0;
    }
    (total - idle) / total * 100.0
}

/// Samples `system.csv` from machine-wide counters and from memwatch itself.
pub struct SystemCollector {
    table: CsvTable,
    logical_cpus: u32,
    handle: ProcHandle,
    previous_times: Option<SystemTimes>,
    previous_self: Option<(u64, Instant)>,
}

impl SystemCollector {
    /// Creates the collector around an open `system.csv` table.
    pub fn new(table: CsvTable, logical_cpus: u32) -> SystemCollector {
        SystemCollector {
            table,
            logical_cpus,
            handle: ProcHandle::current(),
            previous_times: None,
            previous_self: None,
        }
    }

    /// Computes `self_cpu_pct` from the previous sample of memwatch and stores
    /// the current CPU counter.
    ///
    /// The first sample returns `None`.
    fn self_cpu_pct(&mut self, metrics: &ProcessMetrics) -> Option<String> {
        let cpu_100ns = metrics.cpu_100ns?;
        let now = Instant::now();
        let pct = self.previous_self.map(|(previous, at)| {
            fmt_pct(win::cpu_pct(
                previous,
                cpu_100ns,
                now.duration_since(at),
                self.logical_cpus,
            ))
        });
        self.previous_self = Some((cpu_100ns, now));
        pct
    }
}

impl Collector for SystemCollector {
    fn name(&self) -> &str {
        "system"
    }

    fn every_ticks(&self) -> u32 {
        1
    }

    fn sample(&mut self, ctx: &TickCtx) -> Result<(), CollectError> {
        let times = system_times().map_err(CollectError::Source)?;
        let (mem_total_bytes, mem_avail_bytes) = memory_status().map_err(CollectError::Source)?;
        let (commit_bytes, commit_limit_bytes) = commit_info().map_err(CollectError::Source)?;
        let self_metrics = self.handle.metrics();

        let cpu_pct = self
            .previous_times
            .map(|previous| fmt_pct(system_cpu_pct(previous, times)));
        self.previous_times = Some(times);

        let row = SystemRow {
            t_ms: ctx.t_ms,
            unix_ms: ctx.unix_ms,
            cpu_pct,
            mem_total_bytes,
            mem_avail_bytes,
            commit_bytes,
            commit_limit_bytes,
            self_cpu_pct: self.self_cpu_pct(&self_metrics),
            self_private_bytes: self_metrics.private_bytes,
        };
        self.table.write(&row).map_err(CollectError::Write)
    }

    fn flush(&mut self, durable: bool) -> io::Result<()> {
        self.table.flush(durable)
    }
}

/// Reads the machine-wide CPU times.
fn system_times() -> anyhow::Result<SystemTimes> {
    let mut idle = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all three pointers point to writable `FILETIME` storage.
    unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user))? };
    Ok(SystemTimes {
        idle: filetime_to_u64(idle),
        kernel: filetime_to_u64(kernel),
        user: filetime_to_u64(user),
    })
}

/// Reads total and available physical memory via `GlobalMemoryStatusEx`.
fn memory_status() -> anyhow::Result<(u64, u64)> {
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..MEMORYSTATUSEX::default()
    };
    // SAFETY: `status` declares its own size and is writable.
    unsafe { GlobalMemoryStatusEx(&mut status)? };
    Ok((status.ullTotalPhys, status.ullAvailPhys))
}

/// Reads the commit charge and limit via `GetPerformanceInfo`.
///
/// The counters are page counts, so they are multiplied by the page size.
fn commit_info() -> anyhow::Result<(u64, u64)> {
    let mut info = PERFORMANCE_INFORMATION {
        cb: size_of::<PERFORMANCE_INFORMATION>() as u32,
        ..PERFORMANCE_INFORMATION::default()
    };
    // SAFETY: `info` declares its own size and is writable.
    unsafe { GetPerformanceInfo(&mut info, info.cb)? };
    let page = info.PageSize as u64;
    Ok((
        info.CommitTotal as u64 * page,
        info.CommitLimit as u64 * page,
    ))
}

/// Converts a `FILETIME` into a `u64`.
fn filetime_to_u64(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::store::{CsvTable, SYSTEM_COLUMNS};

    /// One row of `system.csv` as read by the test.
    #[derive(Debug, serde::Deserialize)]
    struct Row {
        /// CPU usage of the whole machine; empty for the first sample.
        cpu_pct: Option<String>,
        /// Physical memory in bytes.
        mem_total_bytes: u64,
        /// Available physical memory in bytes.
        mem_avail_bytes: u64,
        /// Committed memory in bytes.
        commit_bytes: u64,
        /// Commit limit in bytes.
        commit_limit_bytes: u64,
        /// CPU usage of memwatch itself; empty for the first sample.
        self_cpu_pct: Option<String>,
        /// Private commit of memwatch itself in bytes.
        self_private_bytes: Option<u64>,
    }

    #[test]
    fn system_cpu_pct_from_deltas() {
        let prev = SystemTimes {
            idle: 0,
            kernel: 0,
            user: 0,
        };
        let busy = SystemTimes {
            idle: 50,
            kernel: 80,
            user: 20,
        };
        assert_eq!(
            system_cpu_pct(prev, busy),
            50.0,
            "half of the kernel and user delta spent outside idle must be 50%"
        );
        assert_eq!(system_cpu_pct(busy, busy), 0.0, "a zero delta must be 0%");
    }

    #[test]
    fn system_collector_reports_memory() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let path = dir.path().join("system.csv");
        let table = CsvTable::create(&path, SYSTEM_COLUMNS).expect("system.csv must be created");
        let mut collector = SystemCollector::new(table, crate::win::logical_cpus());
        let ctx = TickCtx {
            t_ms: 0,
            unix_ms: 0,
            tick: 0,
            processes: &[],
        };

        collector.sample(&ctx).expect("the sample must succeed");
        collector.flush(false).expect("system.csv must be flushed");

        let rows = read_rows(&path);
        assert_eq!(rows.len(), 1, "one sample must write one row");
        let row = &rows[0];
        assert!(
            row.mem_total_bytes > row.mem_avail_bytes && row.mem_avail_bytes > 0,
            "total memory must exceed the available memory, and both must be positive"
        );
        assert!(
            row.commit_limit_bytes >= row.commit_bytes && row.commit_bytes > 0,
            "the commit limit must cover the commit charge, and the charge must be positive"
        );
        assert!(
            row.self_private_bytes
                .expect("memwatch private bytes must be readable")
                > 0,
            "memwatch itself must report private bytes"
        );
        assert!(row.cpu_pct.is_none(), "the first row must have no cpu_pct");
        assert!(
            row.self_cpu_pct.is_none(),
            "the first row must have no self_cpu_pct"
        );
    }

    /// Reads `system.csv` into row structs.
    fn read_rows(path: &Path) -> Vec<Row> {
        let mut reader = csv::Reader::from_path(path).expect("system.csv must be readable");
        reader
            .deserialize()
            .map(|row| row.expect("every row must parse"))
            .collect()
    }
}
