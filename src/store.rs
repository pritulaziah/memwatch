//! CSV tables and the run directory layout.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use time::OffsetDateTime;

use crate::options::run_dir_name;

/// Column headers of `processes.csv`.
pub const PROCESSES_COLUMNS: &[&str] = &[
    "t_ms",
    "unix_ms",
    "event",
    "proc_key",
    "pid",
    "ppid",
    "role",
    "image_path",
    "image_version",
    "exit_code",
    "cmdline",
];

/// Column headers of `process.csv`.
pub const PROCESS_COLUMNS: &[&str] = &[
    "t_ms",
    "unix_ms",
    "proc_key",
    "pid",
    "role",
    "private_bytes",
    "working_set",
    "private_working_set",
    "peak_working_set",
    "peak_private_bytes",
    "page_faults",
    "cpu_user_ms",
    "cpu_kernel_ms",
    "cpu_cycles",
    "cpu_pct",
    "io_read_bytes",
    "io_write_bytes",
    "io_other_bytes",
    "io_read_ops",
    "io_write_ops",
    "io_other_ops",
    "handles",
    "gdi",
    "gdi_peak",
    "user",
    "user_peak",
    "threads",
];

/// Column headers of `job.csv`.
pub const JOB_COLUMNS: &[&str] = &[
    "t_ms",
    "unix_ms",
    "active_processes",
    "total_processes",
    "total_terminated_processes",
    "cpu_user_ms",
    "cpu_kernel_ms",
    "cpu_pct",
    "page_faults",
    "peak_job_memory",
    "peak_process_memory",
    "io_read_bytes",
    "io_write_bytes",
    "io_other_bytes",
    "io_read_ops",
    "io_write_ops",
    "io_other_ops",
];

/// Column headers of `system.csv`.
pub const SYSTEM_COLUMNS: &[&str] = &[
    "t_ms",
    "unix_ms",
    "cpu_pct",
    "mem_total_bytes",
    "mem_avail_bytes",
    "commit_bytes",
    "commit_limit_bytes",
    "self_cpu_pct",
    "self_private_bytes",
];

/// Creates the run directory `<out>/<name>-<YYYYMMDD-HHMMSS>`.
///
/// Missing parents of `out` are created. Fails with
/// [`io::ErrorKind::AlreadyExists`] when the run directory already exists, so
/// two runs started in the same second do not share a directory.
pub fn create_run_dir(out: &Path, name: &str, started: OffsetDateTime) -> io::Result<PathBuf> {
    fs::create_dir_all(out)?;
    let run_dir = out.join(run_dir_name(name, started));
    fs::create_dir(&run_dir)?;
    Ok(run_dir)
}

/// Formats a percentage with two decimal places.
pub fn fmt_pct(v: f64) -> String {
    format!("{v:.2}")
}

/// Kind of a process lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessEvent {
    /// The process appeared in the tree.
    Start,
    /// The process left the tree.
    Exit,
}

/// One row of `processes.csv`: a process lifecycle event.
#[derive(Debug, Serialize)]
pub struct ProcessEventRow {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// Event kind.
    pub event: ProcessEvent,
    /// Stable process identity `<pid>-<creation filetime>`.
    pub proc_key: String,
    /// Process ID.
    pub pid: u32,
    /// Parent process ID at the moment of discovery.
    pub ppid: u32,
    /// Process role.
    pub role: String,
    /// Full path of the executable.
    pub image_path: Option<String>,
    /// `FileVersion` of the executable; empty when the resource has none.
    pub image_version: Option<String>,
    /// Exit code; present only for [`ProcessEvent::Exit`].
    pub exit_code: Option<i64>,
    /// Command line; present only for [`ProcessEvent::Start`].
    pub cmdline: Option<String>,
}

/// One row of `process.csv`: per-process counters at one tick.
///
/// Counter fields are cumulative and written as read; a `None` field means
/// the value is unavailable and becomes an empty cell.
#[derive(Debug, Serialize)]
pub struct ProcessRow {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// Stable process identity.
    pub proc_key: String,
    /// Process ID.
    pub pid: u32,
    /// Process role.
    pub role: String,
    /// Private commit in bytes.
    pub private_bytes: Option<u64>,
    /// Working set in bytes.
    pub working_set: Option<u64>,
    /// Private working set in bytes; empty when the counter is unavailable.
    pub private_working_set: Option<u64>,
    /// Peak working set in bytes.
    pub peak_working_set: Option<u64>,
    /// Peak private commit in bytes.
    pub peak_private_bytes: Option<u64>,
    /// Page faults (cumulative).
    pub page_faults: Option<u64>,
    /// User CPU time in milliseconds (cumulative).
    pub cpu_user_ms: Option<u64>,
    /// Kernel CPU time in milliseconds (cumulative).
    pub cpu_kernel_ms: Option<u64>,
    /// CPU cycles (cumulative).
    pub cpu_cycles: Option<u64>,
    /// CPU usage of the whole machine, formatted with two decimal places;
    /// empty for the first sample of the process.
    pub cpu_pct: Option<String>,
    /// Bytes read (cumulative).
    pub io_read_bytes: Option<u64>,
    /// Bytes written (cumulative).
    pub io_write_bytes: Option<u64>,
    /// Bytes transferred in other operations (cumulative).
    pub io_other_bytes: Option<u64>,
    /// Read operations (cumulative).
    pub io_read_ops: Option<u64>,
    /// Write operations (cumulative).
    pub io_write_ops: Option<u64>,
    /// Other operations (cumulative).
    pub io_other_ops: Option<u64>,
    /// Open handles.
    pub handles: Option<u64>,
    /// GDI objects.
    pub gdi: Option<u64>,
    /// Peak GDI objects.
    pub gdi_peak: Option<u64>,
    /// USER objects.
    pub user: Option<u64>,
    /// Peak USER objects.
    pub user_peak: Option<u64>,
    /// Threads at the moment of the snapshot.
    pub threads: Option<u32>,
}

/// One row of `job.csv`: job object accounting at one tick.
///
/// Counters are cumulative and include terminated processes.
#[derive(Debug, Serialize)]
pub struct JobRow {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// Processes currently active in the job.
    pub active_processes: u32,
    /// Processes ever assigned to the job.
    pub total_processes: u32,
    /// Processes terminated since assignment.
    pub total_terminated_processes: u32,
    /// User CPU time of the job in milliseconds (cumulative).
    pub cpu_user_ms: u64,
    /// Kernel CPU time of the job in milliseconds (cumulative).
    pub cpu_kernel_ms: u64,
    /// CPU usage of the whole machine, formatted with two decimal places;
    /// empty for the first sample.
    pub cpu_pct: Option<String>,
    /// Page faults (cumulative).
    pub page_faults: u64,
    /// Peak memory committed by the job in bytes.
    pub peak_job_memory: u64,
    /// Peak memory committed by any single process of the job in bytes.
    pub peak_process_memory: u64,
    /// Bytes read (cumulative).
    pub io_read_bytes: u64,
    /// Bytes written (cumulative).
    pub io_write_bytes: u64,
    /// Bytes transferred in other operations (cumulative).
    pub io_other_bytes: u64,
    /// Read operations (cumulative).
    pub io_read_ops: u64,
    /// Write operations (cumulative).
    pub io_write_ops: u64,
    /// Other operations (cumulative).
    pub io_other_ops: u64,
}

/// One row of `system.csv`: machine-wide counters at one tick.
#[derive(Debug, Serialize)]
pub struct SystemRow {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// CPU usage of the whole machine, formatted with two decimal places;
    /// empty for the first sample.
    pub cpu_pct: Option<String>,
    /// Physical memory in bytes.
    pub mem_total_bytes: u64,
    /// Available physical memory in bytes.
    pub mem_avail_bytes: u64,
    /// Committed memory in bytes.
    pub commit_bytes: u64,
    /// Commit limit in bytes.
    pub commit_limit_bytes: u64,
    /// CPU usage of memwatch itself; empty for the first sample.
    pub self_cpu_pct: Option<String>,
    /// Private commit of memwatch itself in bytes.
    pub self_private_bytes: Option<u64>,
}

/// An append-only CSV file with a fixed header row.
pub struct CsvTable {
    writer: csv::Writer<fs::File>,
}

impl CsvTable {
    /// Creates the file and writes the header row immediately.
    pub fn create(path: &Path, columns: &[&str]) -> io::Result<CsvTable> {
        let file = fs::File::create(path)?;
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(file);
        writer.write_record(columns)?;
        writer.flush()?;
        Ok(CsvTable { writer })
    }

    /// Appends one row; `None` fields become empty cells.
    pub fn write<R: Serialize>(&mut self, row: &R) -> io::Result<()> {
        self.writer.serialize(row)?;
        Ok(())
    }

    /// Flushes buffered rows to the operating system.
    ///
    /// When `durable` is set, the file is also synced to the storage device.
    pub fn flush(&mut self, durable: bool) -> io::Result<()> {
        self.writer.flush()?;
        if durable {
            self.writer.get_ref().sync_all()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use time::macros::datetime;

    fn sample_event_row() -> ProcessEventRow {
        ProcessEventRow {
            t_ms: 1_000,
            unix_ms: 1_700_000_000_000,
            event: ProcessEvent::Start,
            proc_key: "1234-133000000000000000".to_string(),
            pid: 1234,
            ppid: 4321,
            role: "main".to_string(),
            image_path: Some("C:\\app\\main.exe".to_string()),
            image_version: Some("1.2.3.4".to_string()),
            exit_code: None,
            cmdline: Some("main.exe --flag".to_string()),
        }
    }

    fn sample_process_row() -> ProcessRow {
        ProcessRow {
            t_ms: 1_000,
            unix_ms: 1_700_000_000_000,
            proc_key: "1234-133000000000000000".to_string(),
            pid: 1234,
            role: "main".to_string(),
            private_bytes: Some(1_000),
            working_set: Some(2_000),
            private_working_set: Some(1_500),
            peak_working_set: Some(2_500),
            peak_private_bytes: Some(1_800),
            page_faults: Some(10),
            cpu_user_ms: Some(100),
            cpu_kernel_ms: Some(50),
            cpu_cycles: Some(1_000_000),
            cpu_pct: Some("12.35".to_string()),
            io_read_bytes: Some(100),
            io_write_bytes: Some(200),
            io_other_bytes: Some(300),
            io_read_ops: Some(4),
            io_write_ops: Some(5),
            io_other_ops: Some(6),
            handles: Some(7),
            gdi: Some(8),
            gdi_peak: Some(9),
            user: Some(10),
            user_peak: Some(11),
            threads: Some(12),
        }
    }

    fn sample_job_row() -> JobRow {
        JobRow {
            t_ms: 1_000,
            unix_ms: 1_700_000_000_000,
            active_processes: 2,
            total_processes: 3,
            total_terminated_processes: 1,
            cpu_user_ms: 100,
            cpu_kernel_ms: 50,
            cpu_pct: Some("12.35".to_string()),
            page_faults: 10,
            peak_job_memory: 1_000,
            peak_process_memory: 800,
            io_read_bytes: 100,
            io_write_bytes: 200,
            io_other_bytes: 300,
            io_read_ops: 4,
            io_write_ops: 5,
            io_other_ops: 6,
        }
    }

    fn sample_system_row() -> SystemRow {
        SystemRow {
            t_ms: 1_000,
            unix_ms: 1_700_000_000_000,
            cpu_pct: Some("12.35".to_string()),
            mem_total_bytes: 32_000_000_000,
            mem_avail_bytes: 16_000_000_000,
            commit_bytes: 8_000_000_000,
            commit_limit_bytes: 40_000_000_000,
            self_cpu_pct: Some("0.10".to_string()),
            self_private_bytes: Some(50_000_000),
        }
    }

    fn round_trip<R: Serialize>(
        dir: &Path,
        file: &str,
        columns: &[&str],
        row: &R,
    ) -> (csv::StringRecord, csv::StringRecord) {
        let path = dir.join(file);
        let mut table = CsvTable::create(&path, columns).expect("the table must be created");
        table.write(row).expect("the row must be written");
        table.flush(false).expect("the table must be flushed");

        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(&path)
            .expect("the table must be readable");
        let mut records = reader.records();
        (
            records.next().expect("the header must be present").unwrap(),
            records.next().expect("the row must be present").unwrap(),
        )
    }

    fn check_row_matches_columns<R: Serialize>(dir: &Path, file: &str, columns: &[&str], row: &R) {
        let (header, record) = round_trip(dir, file, columns, row);
        assert_eq!(
            header.iter().collect::<Vec<_>>(),
            columns,
            "{file}: the header must match the column constants"
        );
        assert_eq!(
            record.len(),
            columns.len(),
            "{file}: the row must have one field per column"
        );
    }

    #[test]
    fn table_writes_header_without_rows() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("process.csv");
        let mut table = CsvTable::create(&path, PROCESS_COLUMNS).unwrap();
        table.flush(false).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.trim_end(), PROCESS_COLUMNS.join(","));
    }

    #[test]
    fn none_fields_become_empty_cells() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("process.csv");
        let mut table = CsvTable::create(&path, PROCESS_COLUMNS).unwrap();

        let mut row = sample_process_row();
        row.private_working_set = None;
        row.cpu_pct = None;
        table.write(&row).unwrap();
        table.flush(false).unwrap();

        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_path(&path)
            .unwrap();
        let record = reader.records().next().unwrap().unwrap();
        assert_eq!(record.get(7), Some(""), "private_working_set must be empty");
        assert_eq!(record.get(14), Some(""), "cpu_pct must be empty");
        assert_eq!(record.get(5), Some("1000"), "private_bytes must be kept");
    }

    #[test]
    fn row_field_order_matches_columns() {
        let dir = TempDir::new().unwrap();
        check_row_matches_columns(
            dir.path(),
            "processes.csv",
            PROCESSES_COLUMNS,
            &sample_event_row(),
        );
        check_row_matches_columns(
            dir.path(),
            "process.csv",
            PROCESS_COLUMNS,
            &sample_process_row(),
        );
        check_row_matches_columns(dir.path(), "job.csv", JOB_COLUMNS, &sample_job_row());
        check_row_matches_columns(
            dir.path(),
            "system.csv",
            SYSTEM_COLUMNS,
            &sample_system_row(),
        );
    }

    #[test]
    fn fmt_pct_rounds_to_two_decimals() {
        assert_eq!(fmt_pct(12.345), "12.35");
        assert_eq!(fmt_pct(0.0), "0.00");
    }

    #[test]
    fn flush_makes_rows_visible_to_reader() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("job.csv");
        let mut table = CsvTable::create(&path, JOB_COLUMNS).unwrap();

        table.write(&sample_job_row()).unwrap();
        table.flush(false).unwrap();
        assert_eq!(visible_rows(&path), 1);

        table.write(&sample_job_row()).unwrap();
        table.flush(true).unwrap();
        assert_eq!(visible_rows(&path), 2);
    }

    fn visible_rows(path: &Path) -> usize {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_path(path)
            .unwrap();
        reader.records().count()
    }

    #[test]
    fn create_run_dir_rejects_existing() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("nested").join("runs");
        let started = datetime!(2026-10-07 16:05:09 UTC);

        let run_dir = create_run_dir(&out, "wry", started).unwrap();
        assert_eq!(run_dir, out.join("wry-20261007-160509"));
        assert!(run_dir.is_dir());

        let err = create_run_dir(&out, "wry", started).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }
}
