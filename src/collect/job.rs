//! Job object aggregates written to `job.csv`.

use std::io;
use std::rc::Rc;
use std::time::Instant;

use crate::collect::{CollectError, Collector, TickCtx};
use crate::launch::Job;
use crate::store::{CsvTable, JobRow, fmt_pct};
use crate::win;

/// Samples `job.csv` from the accounting of the run's job object.
pub struct JobCollector {
    job: Rc<Job>,
    table: CsvTable,
    logical_cpus: u32,
    previous: Option<(u64, Instant)>,
}

impl JobCollector {
    /// Creates the collector around the job and an open `job.csv` table.
    pub fn new(job: Rc<Job>, table: CsvTable, logical_cpus: u32) -> JobCollector {
        JobCollector {
            job,
            table,
            logical_cpus,
            previous: None,
        }
    }

    /// Computes `cpu_pct` from the previous sample and stores the current CPU
    /// counter.
    ///
    /// The first sample returns `None`.
    fn cpu_pct(&mut self, total_100ns: u64) -> Option<String> {
        let now = Instant::now();
        let pct = self.previous.map(|(previous, at)| {
            fmt_pct(win::cpu_pct(
                previous,
                total_100ns,
                now.duration_since(at),
                self.logical_cpus,
            ))
        });
        self.previous = Some((total_100ns, now));
        pct
    }
}

impl Collector for JobCollector {
    fn name(&self) -> &str {
        "job"
    }

    fn every_ticks(&self) -> u32 {
        1
    }

    fn sample(&mut self, ctx: &TickCtx) -> Result<(), CollectError> {
        let accounting = self.job.accounting().map_err(CollectError::Source)?;
        let peaks = self.job.peaks().map_err(CollectError::Source)?;

        let total_100ns = accounting.total_user_100ns + accounting.total_kernel_100ns;
        let cpu_pct = self.cpu_pct(total_100ns);

        let row = JobRow {
            t_ms: ctx.t_ms,
            unix_ms: ctx.unix_ms,
            active_processes: accounting.active_processes as u32,
            total_processes: accounting.total_processes as u32,
            total_terminated_processes: accounting.total_terminated_processes as u32,
            cpu_user_ms: accounting.total_user_100ns / 10_000,
            cpu_kernel_ms: accounting.total_kernel_100ns / 10_000,
            cpu_pct,
            page_faults: accounting.total_page_faults,
            peak_job_memory: peaks.peak_job_memory,
            peak_process_memory: peaks.peak_process_memory,
            io_read_bytes: accounting.io_read_bytes,
            io_write_bytes: accounting.io_write_bytes,
            io_other_bytes: accounting.io_other_bytes,
            io_read_ops: accounting.io_read_ops,
            io_write_ops: accounting.io_write_ops,
            io_other_ops: accounting.io_other_ops,
        };
        self.table.write(&row).map_err(CollectError::Write)
    }

    fn flush(&mut self, durable: bool) -> io::Result<()> {
        self.table.flush(durable)
    }
}
