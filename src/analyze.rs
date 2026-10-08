//! Reading and validating a recorded run directory.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::meta::{CollectorStatus, EndReason, ImageInfo, Meta};
use crate::store::ProcessEvent;

/// Why a run directory could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunReadError {
    /// `meta.json` is missing from the run directory.
    MissingMeta,
    /// `meta.json` exists but could not be read or parsed.
    UnreadableMeta {
        /// Description of the read or parse error.
        detail: String,
    },
    /// `meta.json` is valid JSON but not an object.
    MetaNotObject,
    /// `meta.json` declares a schema version other than 1.
    IncompatibleSchema {
        /// The declared version as JSON text.
        version: String,
    },
    /// `processes.csv` is missing from the run directory.
    MissingProcesses,
    /// `processes.csv` has no header row.
    ProcessesWithoutHeader,
}

/// One process lifecycle event from `processes.csv`.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// Event kind; `None` when the cell is empty or holds an unknown value.
    pub event: Option<ProcessEvent>,
    /// Stable process identity `<pid>-<creation filetime>`.
    pub proc_key: Option<String>,
    /// Process role.
    pub role: Option<String>,
    /// Full path of the executable.
    pub image_path: Option<String>,
    /// `FileVersion` of the executable.
    pub image_version: Option<String>,
}

/// One process sample from `process.csv`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessSample {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// Stable process identity.
    pub proc_key: Option<String>,
    /// Process role.
    pub role: Option<String>,
    /// Private commit in bytes.
    pub private_bytes: Option<f64>,
    /// Working set in bytes.
    pub working_set: Option<f64>,
    /// User CPU time in milliseconds (cumulative).
    pub cpu_user_ms: Option<f64>,
    /// Kernel CPU time in milliseconds (cumulative).
    pub cpu_kernel_ms: Option<f64>,
    /// CPU usage of the whole machine as a percentage.
    pub cpu_pct: Option<f64>,
    /// Open handles.
    pub handles: Option<f64>,
    /// GDI objects.
    pub gdi: Option<f64>,
    /// USER objects.
    pub user: Option<f64>,
    /// Threads at the moment of the snapshot.
    pub threads: Option<f64>,
}

/// One job sample from `job.csv`.
#[derive(Debug, Clone, PartialEq)]
pub struct JobSample {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// User CPU time of the job in milliseconds (cumulative).
    pub cpu_user_ms: Option<f64>,
    /// Kernel CPU time of the job in milliseconds (cumulative).
    pub cpu_kernel_ms: Option<f64>,
}

/// One GPU sample from `gpu.csv`.
#[derive(Debug, Clone, PartialEq)]
pub struct GpuSample {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// Dedicated GPU memory in bytes.
    pub dedicated_bytes: Option<f64>,
    /// Shared GPU memory in bytes.
    pub shared_bytes: Option<f64>,
}

/// One DevTools sample from `cdp.csv`.
#[derive(Debug, Clone, PartialEq)]
pub struct CdpSample {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// Used JavaScript heap in bytes.
    pub js_heap_used_bytes: Option<f64>,
    /// DOM nodes in the page.
    pub nodes: Option<f64>,
}

/// One machine-wide sample from `system.csv`.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemSample {
    /// Milliseconds since the start of the run.
    pub t_ms: u64,
    /// Unix time in milliseconds.
    pub unix_ms: u64,
    /// CPU usage of the whole machine as a percentage.
    pub cpu_pct: Option<f64>,
    /// CPU usage of memwatch itself as a percentage.
    pub self_cpu_pct: Option<f64>,
}

/// The kind of a [`Warning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningKind {
    /// A table has no data.
    NoData,
    /// Rows of a table were dropped.
    DroppedRow,
    /// Non-numeric cells of a table were read as empty.
    NonNumeric,
    /// Wall-clock time jumped between neighbouring ticks.
    TimeGap,
    /// Outside load on the machine was high on average.
    NoisyMachine,
    /// A collector ended with a status other than ok or waiting.
    CollectorStatus,
    /// The process collector switched to walking the tree.
    TreeWalkFallback,
    /// The run ended for an unexpected reason.
    UnexpectedEndReason,
}

/// Parameters of a [`Warning`], sufficient to render it in any language.
#[derive(Debug, Clone, PartialEq)]
pub enum WarningMessage {
    /// A file of the run is missing or has no header.
    MissingFile {
        /// Name of the file.
        file: String,
    },
    /// Rows of a file were dropped while reading.
    DroppedRows {
        /// Name of the file.
        file: String,
    },
    /// Non-numeric cells of a file were read as empty.
    NonNumericCells {
        /// Name of the file.
        file: String,
    },
    /// Wall-clock time jumped between neighbouring ticks.
    TimeGap {
        /// Size of the gap in milliseconds.
        gap_ms: u64,
    },
    /// Outside load on the machine was high on average.
    NoisyMachine {
        /// Average outside load as a percentage.
        average_pct: f64,
    },
    /// A collector ended with a status other than ok or waiting.
    CollectorStatus {
        /// Name of the collector.
        name: String,
        /// Final status of the collector.
        status: CollectorStatus,
    },
    /// The process collector switched to walking the tree.
    TreeWalkFallback,
    /// The run did not finish.
    DidNotFinish,
    /// The run ended for an unexpected reason.
    UnexpectedEndReason {
        /// The recorded end reason.
        reason: EndReason,
    },
}

/// A problem found while reading or analyzing a run.
#[derive(Debug, Clone, PartialEq)]
pub struct Warning {
    /// The kind of the problem.
    pub kind: WarningKind,
    /// The parameters needed to render the warning in any language.
    pub message: WarningMessage,
}

/// A run directory read into metadata, samples and reading warnings.
#[derive(Debug)]
pub struct Run {
    /// Metadata from `meta.json`.
    pub meta: Meta,
    /// End time as an RFC 3339 string; recovered from the last tick when the
    /// metadata has none.
    pub ended_at: Option<String>,
    /// Whether the end time was recovered from the last tick.
    pub ended_at_recovered: bool,
    /// Executables that appeared in the process tree.
    pub images: Vec<ImageInfo>,
    /// Rows of `processes.csv`.
    pub events: Vec<Event>,
    /// Rows of `process.csv`.
    pub processes: Vec<ProcessSample>,
    /// Rows of `job.csv`.
    pub job: Vec<JobSample>,
    /// Rows of `gpu.csv`.
    pub gpu: Vec<GpuSample>,
    /// Rows of `cdp.csv`.
    pub cdp: Vec<CdpSample>,
    /// Rows of `system.csv`.
    pub system: Vec<SystemSample>,
    /// Warnings collected while reading.
    pub warnings: Vec<Warning>,
}

impl Run {
    /// Returns the greatest `t_ms` across all samples and events, or zero when
    /// there are none.
    pub fn duration_ms(&self) -> u64 {
        let mut last = 0;
        for t_ms in self
            .events
            .iter()
            .map(|event| event.t_ms)
            .chain(self.processes.iter().map(|sample| sample.t_ms))
            .chain(self.job.iter().map(|sample| sample.t_ms))
            .chain(self.gpu.iter().map(|sample| sample.t_ms))
            .chain(self.cdp.iter().map(|sample| sample.t_ms))
            .chain(self.system.iter().map(|sample| sample.t_ms))
        {
            last = last.max(t_ms);
        }
        last
    }
}

/// Reads a run directory into a [`Run`], validating its files and recovering
/// missing metadata.
pub fn load(run_dir: &Path) -> Result<Run, RunReadError> {
    let meta = read_meta(run_dir)?;
    let mut warnings = Vec::new();

    let processes_path = run_dir.join("processes.csv");
    if !processes_path.is_file() {
        return Err(RunReadError::MissingProcesses);
    }
    let events = match read_table(&processes_path, PROCESSES_NUMERIC) {
        TableRead::Read(table) => {
            warnings.extend(table.read_warnings("processes.csv"));
            events_from(&table)
        }
        TableRead::Missing | TableRead::WithoutHeader => {
            return Err(RunReadError::ProcessesWithoutHeader);
        }
    };

    let processes = read_group(
        run_dir,
        "process.csv",
        PROCESS_NUMERIC,
        &mut warnings,
        process_samples,
    );
    let job = read_group(run_dir, "job.csv", JOB_NUMERIC, &mut warnings, job_samples);
    let gpu = read_group(run_dir, "gpu.csv", GPU_NUMERIC, &mut warnings, gpu_samples);
    let cdp = read_group(run_dir, "cdp.csv", CDP_NUMERIC, &mut warnings, cdp_samples);
    let system = read_group(
        run_dir,
        "system.csv",
        SYSTEM_NUMERIC,
        &mut warnings,
        system_samples,
    );

    let images = if meta.images.is_empty() {
        recover_images(&events)
    } else {
        meta.images.clone()
    };

    let mut run = Run {
        meta,
        ended_at: None,
        ended_at_recovered: false,
        images,
        events,
        processes,
        job,
        gpu,
        cdp,
        system,
        warnings,
    };
    let (ended_at, ended_at_recovered) = recover_ended_at(&run.meta, run.duration_ms());
    run.ended_at = ended_at;
    run.ended_at_recovered = ended_at_recovered;
    Ok(run)
}

/// Numeric columns of `processes.csv`.
const PROCESSES_NUMERIC: &[&str] = &["pid", "ppid", "exit_code"];

/// Numeric columns of `process.csv`.
const PROCESS_NUMERIC: &[&str] = &[
    "pid",
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

/// Numeric columns of `job.csv`.
const JOB_NUMERIC: &[&str] = &[
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

/// Numeric columns of `gpu.csv`.
const GPU_NUMERIC: &[&str] = &[
    "pid",
    "dedicated_bytes",
    "shared_bytes",
    "committed_bytes",
    "util_3d",
    "util_copy",
    "util_video_decode",
    "util_video_encode",
    "util_compute",
    "util_other",
];

/// Numeric columns of `cdp.csv`.
const CDP_NUMERIC: &[&str] = &[
    "js_heap_used_bytes",
    "js_heap_total_bytes",
    "nodes",
    "documents",
    "frames",
    "js_event_listeners",
    "layout_count",
    "recalc_style_count",
    "layout_duration_ms",
    "recalc_style_duration_ms",
    "script_duration_ms",
    "task_duration_ms",
];

/// Numeric columns of `system.csv`.
const SYSTEM_NUMERIC: &[&str] = &[
    "cpu_pct",
    "mem_total_bytes",
    "mem_avail_bytes",
    "commit_bytes",
    "commit_limit_bytes",
    "self_cpu_pct",
    "self_private_bytes",
];

/// Result of reading one CSV table.
enum TableRead {
    /// The file is missing or cannot be opened.
    Missing,
    /// The file exists but has no header row.
    WithoutHeader,
    /// The file was read; rows that passed validation are kept.
    Read(Table),
}

/// One CSV table with its validated rows and reading counters.
struct Table {
    /// Column names of the header row.
    header: Vec<String>,
    /// Rows that passed validation.
    rows: Vec<TableRow>,
    /// Rows dropped because of a wrong field count, `t_ms` or `unix_ms`.
    dropped: usize,
    /// Non-numeric cells of numeric columns read as empty.
    non_numeric: usize,
}

/// One validated CSV row.
struct TableRow {
    /// Milliseconds since the start of the run.
    t_ms: u64,
    /// Unix time in milliseconds.
    unix_ms: u64,
    /// Cells in header order.
    cells: Vec<String>,
}

impl Table {
    /// Returns the reading warnings of this table.
    fn read_warnings(&self, file: &str) -> Vec<Warning> {
        let mut warnings = Vec::new();
        if self.dropped > 0 {
            warnings.push(Warning {
                kind: WarningKind::DroppedRow,
                message: WarningMessage::DroppedRows {
                    file: file.to_string(),
                },
            });
        }
        if self.non_numeric > 0 {
            warnings.push(Warning {
                kind: WarningKind::NonNumeric,
                message: WarningMessage::NonNumericCells {
                    file: file.to_string(),
                },
            });
        }
        warnings
    }

    /// Returns the non-empty cell of `column`, or `None` when the column is
    /// absent or the cell is empty.
    fn cell<'a>(&self, row: &'a TableRow, column: &str) -> Option<&'a str> {
        let index = self.header.iter().position(|name| name == column)?;
        let cell = row.cells.get(index)?;
        (!cell.is_empty()).then_some(cell.as_str())
    }

    /// Returns the non-empty text cell of `column`.
    fn text(&self, row: &TableRow, column: &str) -> Option<String> {
        self.cell(row, column).map(str::to_string)
    }

    /// Returns the numeric cell of `column`; empty and non-numeric cells are
    /// `None`.
    fn number(&self, row: &TableRow, column: &str) -> Option<f64> {
        self.cell(row, column).and_then(|cell| cell.parse().ok())
    }
}

/// Reads `meta.json`, validating its schema version.
fn read_meta(run_dir: &Path) -> Result<Meta, RunReadError> {
    let meta_path = run_dir.join("meta.json");
    if !meta_path.is_file() {
        return Err(RunReadError::MissingMeta);
    }
    let text = fs::read_to_string(&meta_path).map_err(|err| RunReadError::UnreadableMeta {
        detail: err.to_string(),
    })?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|err| RunReadError::UnreadableMeta {
            detail: err.to_string(),
        })?;
    if !value.is_object() {
        return Err(RunReadError::MetaNotObject);
    }
    let version = value.get("schema_version");
    if version.and_then(serde_json::Value::as_u64) != Some(1) {
        let version = version.map_or_else(|| "null".to_string(), serde_json::Value::to_string);
        return Err(RunReadError::IncompatibleSchema { version });
    }
    serde_json::from_value(value).map_err(|err| RunReadError::UnreadableMeta {
        detail: err.to_string(),
    })
}

/// Reads one optional CSV table into typed samples.
///
/// A missing or headerless file leaves the group empty and adds one no-data
/// warning.
fn read_group<T>(
    run_dir: &Path,
    file: &str,
    numeric_columns: &[&str],
    warnings: &mut Vec<Warning>,
    samples: impl Fn(&Table) -> Vec<T>,
) -> Vec<T> {
    match read_table(&run_dir.join(file), numeric_columns) {
        TableRead::Read(table) => {
            warnings.extend(table.read_warnings(file));
            samples(&table)
        }
        TableRead::Missing | TableRead::WithoutHeader => {
            warnings.push(Warning {
                kind: WarningKind::NoData,
                message: WarningMessage::MissingFile {
                    file: file.to_string(),
                },
            });
            Vec::new()
        }
    }
}

/// Reads one CSV table, validating its rows.
///
/// A row whose field count differs from the header is dropped silently when it
/// is the last row of the file and counted as dropped otherwise. A row whose
/// `t_ms` or `unix_ms` is missing, is not a non-negative integer or has a
/// decreasing `t_ms` is dropped. A non-numeric cell of a numeric column counts
/// once per file; an empty cell reads as `None` in any column. Reading stops at
/// the first parse error, so a torn tail is ignored.
fn read_table(path: &Path, numeric_columns: &[&str]) -> TableRead {
    let Ok(file) = fs::File::open(path) else {
        return TableRead::Missing;
    };
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(file);
    let mut records = reader.records();

    let header = match records.next() {
        Some(Ok(header)) if !header.is_empty() => header,
        _ => return TableRead::WithoutHeader,
    };
    let header: Vec<String> = header.iter().map(str::to_string).collect();

    let mut raw = Vec::new();
    for record in records {
        match record {
            Ok(record) => raw.push(record),
            Err(_) => break,
        }
    }

    let t_ms_index = header.iter().position(|column| column == "t_ms");
    let unix_ms_index = header.iter().position(|column| column == "unix_ms");
    let numeric: Vec<bool> = header
        .iter()
        .map(|column| numeric_columns.contains(&column.as_str()))
        .collect();

    let last = raw.len().saturating_sub(1);
    let mut rows = Vec::new();
    let mut dropped = 0;
    let mut non_numeric = 0;
    let mut previous_t_ms: Option<u64> = None;

    for (position, record) in raw.iter().enumerate() {
        if record.len() != header.len() {
            if position != last {
                dropped += 1;
            }
            continue;
        }

        let t_ms = t_ms_index.and_then(|index| parse_int(&record[index]));
        let unix_ms = unix_ms_index.and_then(|index| parse_int(&record[index]));
        let (Some(t_ms), Some(unix_ms)) = (t_ms, unix_ms) else {
            dropped += 1;
            continue;
        };
        if previous_t_ms.is_some_and(|previous| t_ms < previous) {
            dropped += 1;
            continue;
        }
        previous_t_ms = Some(t_ms);

        for (index, is_numeric) in numeric.iter().enumerate() {
            if !is_numeric {
                continue;
            }
            let cell = &record[index];
            if !cell.is_empty() && cell.parse::<f64>().is_err() {
                non_numeric += 1;
            }
        }

        rows.push(TableRow {
            t_ms,
            unix_ms,
            cells: record.iter().map(str::to_string).collect(),
        });
    }

    TableRead::Read(Table {
        header,
        rows,
        dropped,
        non_numeric,
    })
}

/// Parses a non-negative integer cell, returning `None` for anything else.
fn parse_int(value: &str) -> Option<u64> {
    value.parse::<u64>().ok()
}

/// Builds the typed events of `processes.csv`.
fn events_from(table: &Table) -> Vec<Event> {
    table
        .rows
        .iter()
        .map(|row| Event {
            t_ms: row.t_ms,
            unix_ms: row.unix_ms,
            event: match table.cell(row, "event") {
                Some("start") => Some(ProcessEvent::Start),
                Some("exit") => Some(ProcessEvent::Exit),
                _ => None,
            },
            proc_key: table.text(row, "proc_key"),
            role: table.text(row, "role"),
            image_path: table.text(row, "image_path"),
            image_version: table.text(row, "image_version"),
        })
        .collect()
}

/// Builds the typed samples of `process.csv`.
fn process_samples(table: &Table) -> Vec<ProcessSample> {
    table
        .rows
        .iter()
        .map(|row| ProcessSample {
            t_ms: row.t_ms,
            unix_ms: row.unix_ms,
            proc_key: table.text(row, "proc_key"),
            role: table.text(row, "role"),
            private_bytes: table.number(row, "private_bytes"),
            working_set: table.number(row, "working_set"),
            cpu_user_ms: table.number(row, "cpu_user_ms"),
            cpu_kernel_ms: table.number(row, "cpu_kernel_ms"),
            cpu_pct: table.number(row, "cpu_pct"),
            handles: table.number(row, "handles"),
            gdi: table.number(row, "gdi"),
            user: table.number(row, "user"),
            threads: table.number(row, "threads"),
        })
        .collect()
}

/// Builds the typed samples of `job.csv`.
fn job_samples(table: &Table) -> Vec<JobSample> {
    table
        .rows
        .iter()
        .map(|row| JobSample {
            t_ms: row.t_ms,
            unix_ms: row.unix_ms,
            cpu_user_ms: table.number(row, "cpu_user_ms"),
            cpu_kernel_ms: table.number(row, "cpu_kernel_ms"),
        })
        .collect()
}

/// Builds the typed samples of `gpu.csv`.
fn gpu_samples(table: &Table) -> Vec<GpuSample> {
    table
        .rows
        .iter()
        .map(|row| GpuSample {
            t_ms: row.t_ms,
            unix_ms: row.unix_ms,
            dedicated_bytes: table.number(row, "dedicated_bytes"),
            shared_bytes: table.number(row, "shared_bytes"),
        })
        .collect()
}

/// Builds the typed samples of `cdp.csv`.
fn cdp_samples(table: &Table) -> Vec<CdpSample> {
    table
        .rows
        .iter()
        .map(|row| CdpSample {
            t_ms: row.t_ms,
            unix_ms: row.unix_ms,
            js_heap_used_bytes: table.number(row, "js_heap_used_bytes"),
            nodes: table.number(row, "nodes"),
        })
        .collect()
}

/// Builds the typed samples of `system.csv`.
fn system_samples(table: &Table) -> Vec<SystemSample> {
    table
        .rows
        .iter()
        .map(|row| SystemSample {
            t_ms: row.t_ms,
            unix_ms: row.unix_ms,
            cpu_pct: table.number(row, "cpu_pct"),
            self_cpu_pct: table.number(row, "self_cpu_pct"),
        })
        .collect()
}

/// Collects the executables of `start` events, keeping the first occurrence of
/// each path.
fn recover_images(events: &[Event]) -> Vec<ImageInfo> {
    let mut images = Vec::new();
    let mut seen = HashSet::new();
    for event in events {
        if event.event != Some(ProcessEvent::Start) {
            continue;
        }
        let Some(path) = event.image_path.as_ref() else {
            continue;
        };
        if !seen.insert(path.clone()) {
            continue;
        }
        images.push(ImageInfo {
            path: path.clone(),
            version: event.image_version.clone(),
        });
    }
    images
}

/// Returns the run end time, recovering a missing one from the last tick.
fn recover_ended_at(meta: &Meta, last_t_ms: u64) -> (Option<String>, bool) {
    if let Some(ended_at) = &meta.ended_at {
        return (Some(ended_at.clone()), false);
    }
    let Ok(started) = OffsetDateTime::parse(&meta.started_at, &Rfc3339) else {
        return (None, true);
    };
    let offset = i64::try_from(last_t_ms).unwrap_or(i64::MAX);
    let ended = started.checked_add(time::Duration::milliseconds(offset));
    (ended.and_then(|value| value.format(&Rfc3339).ok()), true)
}

/// A named metric sampled at strictly increasing run ticks.
#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    /// Role, `proc_key` or `tree`.
    pub name: String,
    /// Ticks in milliseconds, strictly increasing.
    pub xs: Vec<u64>,
    /// Values aligned with `xs`; `None` where a tick has no values.
    pub values: Vec<Option<f64>>,
}

/// Sums the present values of all processes on every `process.csv` tick.
///
/// Returns `None` when the table has no rows.
pub fn tree_series(run: &Run, value: impl Fn(&ProcessSample) -> Option<f64>) -> Option<Series> {
    group_series(&run.processes, |sample| sample.t_ms, value)
}

/// Sums the present values of every role on every `process.csv` tick.
///
/// Returns one series per non-empty role in alphabetical order; a role with no
/// values on a tick gets `None` there.
pub fn role_series(run: &Run, value: impl Fn(&ProcessSample) -> Option<f64>) -> Vec<Series> {
    let ticks = sample_ticks(&run.processes, |sample| sample.t_ms);
    if ticks.is_empty() {
        return Vec::new();
    }
    let mut roles: Vec<&str> = run
        .processes
        .iter()
        .filter_map(|sample| sample.role.as_deref())
        .collect();
    roles.sort_unstable();
    roles.dedup();
    roles
        .into_iter()
        .map(|role| Series {
            name: role.to_string(),
            values: sums_by_tick(
                &run.processes,
                &ticks,
                |sample| sample.t_ms,
                &value,
                |sample| sample.role.as_deref() == Some(role),
            ),
            xs: ticks.clone(),
        })
        .collect()
}

/// Sums the present values of every process on its own `process.csv` ticks.
///
/// Returns one series per non-empty `proc_key` in order of first appearance.
pub fn process_series(run: &Run, value: impl Fn(&ProcessSample) -> Option<f64>) -> Vec<Series> {
    let mut keys: Vec<&str> = Vec::new();
    let mut seen = HashSet::new();
    for sample in &run.processes {
        let Some(key) = sample.proc_key.as_deref() else {
            continue;
        };
        if seen.insert(key) {
            keys.push(key);
        }
    }
    keys.into_iter()
        .map(|key| {
            let own: Vec<&ProcessSample> = run
                .processes
                .iter()
                .filter(|sample| sample.proc_key.as_deref() == Some(key))
                .collect();
            let ticks = sample_ticks(&own, |sample| sample.t_ms);
            Series {
                name: key.to_string(),
                values: sums_by_tick(
                    &own,
                    &ticks,
                    |sample| sample.t_ms,
                    |sample| value(sample),
                    |_| true,
                ),
                xs: ticks,
            }
        })
        .collect()
}

/// Counts the `process.csv` rows of every tick.
///
/// Returns `None` when the table has no rows.
pub fn count_series(run: &Run) -> Option<Series> {
    let ticks = sample_ticks(&run.processes, |sample| sample.t_ms);
    if ticks.is_empty() {
        return None;
    }
    let mut counts = vec![0.0; ticks.len()];
    for sample in &run.processes {
        if let Ok(index) = ticks.binary_search(&sample.t_ms) {
            counts[index] += 1.0;
        }
    }
    Some(Series {
        name: "processes".to_string(),
        xs: ticks,
        values: counts.into_iter().map(Some).collect(),
    })
}

/// Sums the present values of every `gpu.csv` row of a tick.
///
/// Returns `None` when the table has no rows.
pub fn gpu_series(run: &Run, value: impl Fn(&GpuSample) -> Option<f64>) -> Option<Series> {
    group_series(&run.gpu, |sample| sample.t_ms, value)
}

/// Sums the present values of every `cdp.csv` row of a tick.
///
/// Returns `None` when the table has no rows.
pub fn cdp_series(run: &Run, value: impl Fn(&CdpSample) -> Option<f64>) -> Option<Series> {
    group_series(&run.cdp, |sample| sample.t_ms, value)
}

/// Sums the present values of every `system.csv` row of a tick.
///
/// Returns `None` when the table has no rows.
pub fn system_series(run: &Run, value: impl Fn(&SystemSample) -> Option<f64>) -> Option<Series> {
    group_series(&run.system, |sample| sample.t_ms, value)
}

/// Builds the `tree` series of a table: sums of present values by tick.
fn group_series<T>(
    samples: &[T],
    t_ms: impl Fn(&T) -> u64,
    value: impl Fn(&T) -> Option<f64>,
) -> Option<Series> {
    let ticks = sample_ticks(samples, &t_ms);
    if ticks.is_empty() {
        return None;
    }
    let values = sums_by_tick(samples, &ticks, &t_ms, &value, |_| true);
    Some(Series {
        name: "tree".to_string(),
        xs: ticks,
        values,
    })
}

/// Returns the sorted unique ticks of `samples`.
fn sample_ticks<T>(samples: &[T], t_ms: impl Fn(&T) -> u64) -> Vec<u64> {
    let mut ticks: Vec<u64> = samples.iter().map(t_ms).collect();
    ticks.sort_unstable();
    ticks.dedup();
    ticks
}

/// Sums the present values of the matching samples of every tick, aligned to
/// `ticks`; a tick without values stays `None`.
fn sums_by_tick<T>(
    samples: &[T],
    ticks: &[u64],
    t_ms: impl Fn(&T) -> u64,
    value: impl Fn(&T) -> Option<f64>,
    keep: impl Fn(&T) -> bool,
) -> Vec<Option<f64>> {
    let mut sums = vec![None; ticks.len()];
    for sample in samples {
        if !keep(sample) {
            continue;
        }
        let Ok(index) = ticks.binary_search(&t_ms(sample)) else {
            continue;
        };
        if let Some(value) = value(sample) {
            *sums[index].get_or_insert(0.0) += value;
        }
    }
    sums
}

/// A closed interval of run ticks in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// First tick of the window, inclusive.
    pub start_ms: u64,
    /// Last tick of the window, inclusive.
    pub end_ms: u64,
}

/// One metric of the summary table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetricId {
    /// Private commit of the process tree.
    PrivateBytes,
    /// Working set of the process tree.
    WorkingSet,
    /// Dedicated GPU memory.
    GpuDedicatedBytes,
    /// Shared GPU memory.
    GpuSharedBytes,
    /// Used JavaScript heap.
    JsHeapUsedBytes,
    /// DOM nodes in the page.
    DomNodes,
    /// Open handles of the process tree.
    Handles,
    /// GDI objects of the process tree.
    Gdi,
    /// USER objects of the process tree.
    User,
    /// Threads of the process tree.
    Threads,
}

impl MetricId {
    /// All metrics in the order of the summary table.
    pub const ALL: [MetricId; 10] = [
        MetricId::PrivateBytes,
        MetricId::WorkingSet,
        MetricId::GpuDedicatedBytes,
        MetricId::GpuSharedBytes,
        MetricId::JsHeapUsedBytes,
        MetricId::DomNodes,
        MetricId::Handles,
        MetricId::Gdi,
        MetricId::User,
        MetricId::Threads,
    ];
}

/// Summary of one metric over a run window.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricStats {
    /// First present value of the window.
    pub start: Option<f64>,
    /// Greatest present value of the window.
    pub peak: Option<f64>,
    /// Arithmetic mean of the present values.
    pub mean: Option<f64>,
    /// Median of the present values.
    pub p50: Option<f64>,
    /// 95th percentile of the present values.
    pub p95: Option<f64>,
    /// Last present value of the window.
    pub end: Option<f64>,
    /// Difference between the last and the first value.
    pub delta: Option<f64>,
    /// Least-squares slope per hour after the warmup threshold.
    pub growth_per_hour: Option<f64>,
    /// Coefficient of determination of the growth line.
    pub r2: Option<f64>,
    /// Last-hour median minus first-hour median after the warmup threshold.
    pub median_hour_delta: Option<f64>,
    /// Number of present values in the window.
    pub samples: usize,
}

/// CPU time and usage of a run.
#[derive(Debug, Clone, PartialEq)]
pub struct CpuStats {
    /// Total CPU seconds of the run.
    pub total_seconds: Option<f64>,
    /// Whether the CPU seconds came from the last process rows instead of the
    /// last job row.
    pub from_process_rows: bool,
    /// Mean tree CPU percentage over the window.
    pub mean_pct: Option<f64>,
    /// Median tree CPU percentage over the window.
    pub p50_pct: Option<f64>,
    /// 95th percentile of the tree CPU percentage over the window.
    pub p95_pct: Option<f64>,
}

/// Process lifecycle counters of a run.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessStats {
    /// Number of `start` events.
    pub started: usize,
    /// Number of `exit` events.
    pub exited: usize,
    /// Greatest number of process rows on a tick.
    pub max_concurrent: usize,
}

/// Computed totals of a run over a window.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    /// Window the totals were computed over.
    pub window: Window,
    /// Warmup that growth and hour deltas exclude.
    pub warmup_ms: u64,
    /// Whether the run is too short for an hour delta.
    pub too_short_for_hour_delta: bool,
    /// One entry per metric, all of [`MetricId::ALL`].
    pub metrics: BTreeMap<MetricId, MetricStats>,
    /// CPU totals of the run.
    pub cpu: CpuStats,
    /// Process lifecycle counters.
    pub processes: ProcessStats,
}

/// Returns the linearly interpolated quantile of `values`, or `None` when the
/// list is empty.
pub fn percentile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let position = q * (ordered.len() - 1) as f64;
    let index = position.floor() as usize;
    if index >= ordered.len() - 1 {
        return ordered.last().copied();
    }
    let fraction = position - index as f64;
    Some(ordered[index] + fraction * (ordered[index + 1] - ordered[index]))
}

/// Summarizes a series inside a window, excluding the warmup from growth and
/// hour deltas.
pub fn metric_stats(series: Option<&Series>, window: Window, warmup_ms: u64) -> MetricStats {
    let points = window_points(series, window);
    let values: Vec<f64> = points.iter().map(|(_, value)| *value).collect();
    if values.is_empty() {
        return MetricStats {
            start: None,
            peak: None,
            mean: None,
            p50: None,
            p95: None,
            end: None,
            delta: None,
            growth_per_hour: None,
            r2: None,
            median_hour_delta: None,
            samples: 0,
        };
    }
    let start = values[0];
    let end = values[values.len() - 1];
    let (growth_per_hour, r2) = least_squares(&after_warmup(&points, window, warmup_ms));
    MetricStats {
        start: Some(start),
        peak: values.iter().copied().reduce(f64::max),
        mean: Some(values.iter().sum::<f64>() / values.len() as f64),
        p50: percentile(&values, 0.5),
        p95: percentile(&values, 0.95),
        end: Some(end),
        delta: Some(end - start),
        growth_per_hour,
        r2,
        median_hour_delta: median_hour_delta(&points, window, warmup_ms),
        samples: values.len(),
    }
}

/// Computes the metric, CPU and process summaries of a run over a window.
pub fn summarize(run: &Run, window: Window, warmup_ms: u64) -> Summary {
    let threshold = window.start_ms.max(warmup_ms);
    let mut metrics = BTreeMap::new();
    for metric in MetricId::ALL {
        metrics.insert(
            metric,
            metric_stats(source_series(run, metric).as_ref(), window, warmup_ms),
        );
    }
    let cpu_values: Vec<f64> =
        window_points(tree_series(run, |sample| sample.cpu_pct).as_ref(), window)
            .into_iter()
            .map(|(_, value)| value)
            .collect();
    let (total_seconds, from_process_rows) = cpu_seconds(run);
    Summary {
        window,
        warmup_ms,
        too_short_for_hour_delta: window.end_ms.saturating_sub(threshold) < 7_200_000,
        metrics,
        cpu: CpuStats {
            total_seconds,
            from_process_rows,
            mean_pct: if cpu_values.is_empty() {
                None
            } else {
                Some(cpu_values.iter().sum::<f64>() / cpu_values.len() as f64)
            },
            p50_pct: percentile(&cpu_values, 0.5),
            p95_pct: percentile(&cpu_values, 0.95),
        },
        processes: process_stats(run),
    }
}

/// Returns the tree series of a metric from its source table.
fn source_series(run: &Run, metric: MetricId) -> Option<Series> {
    match metric {
        MetricId::PrivateBytes => tree_series(run, |sample| sample.private_bytes),
        MetricId::WorkingSet => tree_series(run, |sample| sample.working_set),
        MetricId::GpuDedicatedBytes => gpu_series(run, |sample| sample.dedicated_bytes),
        MetricId::GpuSharedBytes => gpu_series(run, |sample| sample.shared_bytes),
        MetricId::JsHeapUsedBytes => cdp_series(run, |sample| sample.js_heap_used_bytes),
        MetricId::DomNodes => cdp_series(run, |sample| sample.nodes),
        MetricId::Handles => tree_series(run, |sample| sample.handles),
        MetricId::Gdi => tree_series(run, |sample| sample.gdi),
        MetricId::User => tree_series(run, |sample| sample.user),
        MetricId::Threads => tree_series(run, |sample| sample.threads),
    }
}

/// Returns the present points of a series inside the window, in series order.
fn window_points(series: Option<&Series>, window: Window) -> Vec<(u64, f64)> {
    let Some(series) = series else {
        return Vec::new();
    };
    series
        .xs
        .iter()
        .copied()
        .zip(series.values.iter().copied())
        .filter_map(|(t_ms, value)| {
            let value = value?;
            (window.start_ms <= t_ms && t_ms <= window.end_ms).then_some((t_ms, value))
        })
        .collect()
}

/// Returns the points that lie at or after the warmup threshold.
fn after_warmup(points: &[(u64, f64)], window: Window, warmup_ms: u64) -> Vec<(u64, f64)> {
    let threshold = window.start_ms.max(warmup_ms);
    points
        .iter()
        .copied()
        .filter(|(t_ms, _)| *t_ms >= threshold)
        .collect()
}

/// Returns the least-squares slope per hour and the R² of the points.
fn least_squares(points: &[(u64, f64)]) -> (Option<f64>, Option<f64>) {
    if points.len() < 2 {
        return (None, None);
    }
    let xs: Vec<f64> = points
        .iter()
        .map(|(t_ms, _)| *t_ms as f64 / 3_600_000.0)
        .collect();
    let ys: Vec<f64> = points.iter().map(|(_, value)| *value).collect();
    let mean_x = xs.iter().sum::<f64>() / xs.len() as f64;
    let mean_y = ys.iter().sum::<f64>() / ys.len() as f64;
    let sxx: f64 = xs.iter().map(|x| (x - mean_x).powi(2)).sum();
    if sxx == 0.0 {
        return (None, None);
    }
    let sxy: f64 = xs
        .iter()
        .zip(&ys)
        .map(|(x, y)| (x - mean_x) * (y - mean_y))
        .sum();
    let slope = sxy / sxx;
    let intercept = mean_y - slope * mean_x;
    let ss_res: f64 = xs
        .iter()
        .zip(&ys)
        .map(|(x, y)| (y - (intercept + slope * x)).powi(2))
        .sum();
    let ss_tot: f64 = ys.iter().map(|y| (y - mean_y).powi(2)).sum();
    let r2 = if ss_tot == 0.0 {
        1.0
    } else {
        1.0 - ss_res / ss_tot
    };
    (Some(slope), Some(r2))
}

/// Returns the last-hour minus first-hour median, or `None` for a short run.
fn median_hour_delta(points: &[(u64, f64)], window: Window, warmup_ms: u64) -> Option<f64> {
    let threshold = window.start_ms.max(warmup_ms);
    if window.end_ms.saturating_sub(threshold) < 7_200_000 {
        return None;
    }
    let first: Vec<f64> = points
        .iter()
        .filter(|(t_ms, _)| threshold <= *t_ms && *t_ms < threshold + 3_600_000)
        .map(|(_, value)| *value)
        .collect();
    let last: Vec<f64> = points
        .iter()
        .filter(|(t_ms, _)| {
            window.end_ms.saturating_sub(3_600_000) <= *t_ms && *t_ms <= window.end_ms
        })
        .map(|(_, value)| *value)
        .collect();
    let first_median = percentile(&first, 0.5)?;
    let last_median = percentile(&last, 0.5)?;
    Some(last_median - first_median)
}

/// Returns the total CPU seconds and whether they came from process rows.
fn cpu_seconds(run: &Run) -> (Option<f64>, bool) {
    if run.meta.tree_walk_fallback {
        (process_row_cpu_seconds(&run.processes), true)
    } else {
        (job_cpu_seconds(&run.job), false)
    }
}

/// Returns the CPU seconds of the last job row, or `None` without data.
fn job_cpu_seconds(job: &[JobSample]) -> Option<f64> {
    let row = last_row(job, |sample| sample.t_ms)?;
    Some((row.cpu_user_ms? + row.cpu_kernel_ms?) / 1000.0)
}

/// Sums the last CPU seconds of every process, skipping rows with a missing
/// addend.
fn process_row_cpu_seconds(processes: &[ProcessSample]) -> Option<f64> {
    let mut keys: Vec<&str> = Vec::new();
    let mut seen = HashSet::new();
    for sample in processes {
        let Some(key) = sample.proc_key.as_deref() else {
            continue;
        };
        if seen.insert(key) {
            keys.push(key);
        }
    }
    let mut total = 0.0;
    let mut counted = false;
    for key in keys {
        let own: Vec<&ProcessSample> = processes
            .iter()
            .filter(|sample| sample.proc_key.as_deref() == Some(key))
            .collect();
        let Some(row) = last_row(&own, |sample| sample.t_ms) else {
            continue;
        };
        let (Some(user), Some(kernel)) = (row.cpu_user_ms, row.cpu_kernel_ms) else {
            continue;
        };
        total += (user + kernel) / 1000.0;
        counted = true;
    }
    counted.then_some(total)
}

/// Returns the row with the greatest `t_ms`, keeping the first on ties.
fn last_row<T>(rows: &[T], t_ms: impl Fn(&T) -> u64) -> Option<&T> {
    let mut best: Option<&T> = None;
    for row in rows {
        if best.is_none_or(|current| t_ms(row) > t_ms(current)) {
            best = Some(row);
        }
    }
    best
}

/// Counts process start and exit events and the greatest number of rows per
/// tick.
fn process_stats(run: &Run) -> ProcessStats {
    let mut ticks: BTreeMap<u64, usize> = BTreeMap::new();
    for sample in &run.processes {
        *ticks.entry(sample.t_ms).or_default() += 1;
    }
    ProcessStats {
        started: run
            .events
            .iter()
            .filter(|event| event.event == Some(ProcessEvent::Start))
            .count(),
        exited: run
            .events
            .iter()
            .filter(|event| event.event == Some(ProcessEvent::Exit))
            .count(),
        max_concurrent: ticks.values().copied().max().unwrap_or(0),
    }
}

/// A wall-clock gap between neighbouring ticks above this threshold is a gap.
const GAP_THRESHOLD_MS: u64 = 5_000;

/// Average outside CPU load above this threshold means a noisy machine.
const NOISE_THRESHOLD_PCT: f64 = 20.0;

/// Collects the reading warnings of a run first, then the computed ones.
///
/// The computed warnings follow in this order: wall-clock gaps, machine noise,
/// collector statuses, the tree-walk fallback and the end reason.
pub fn compute_warnings(run: &Run, summary: &Summary) -> Vec<Warning> {
    let mut warnings = run.warnings.clone();
    warnings.extend(time_gap_warnings(run, summary));
    if let Some(noisy) = noisy_machine_warning(run, summary) {
        warnings.push(noisy);
    }
    warnings.extend(collector_status_warnings(run));
    if run.meta.tree_walk_fallback {
        warnings.push(Warning {
            kind: WarningKind::TreeWalkFallback,
            message: WarningMessage::TreeWalkFallback,
        });
    }
    if let Some(unexpected) = unexpected_end_reason_warning(run) {
        warnings.push(unexpected);
    }
    warnings
}

/// Returns the unique ticks of `process.csv` with their wall-clock time, or the
/// ticks of `system.csv` when the process table is empty.
///
/// Pairs are keyed by the first occurrence of `t_ms` and sorted by `t_ms`.
fn tick_unix_times(run: &Run) -> Vec<(u64, u64)> {
    let mut pairs: Vec<(u64, u64)> = if run.processes.is_empty() {
        run.system
            .iter()
            .map(|sample| (sample.t_ms, sample.unix_ms))
            .collect()
    } else {
        run.processes
            .iter()
            .map(|sample| (sample.t_ms, sample.unix_ms))
            .collect()
    };
    let mut seen = HashSet::new();
    pairs.retain(|(t_ms, _)| seen.insert(*t_ms));
    pairs.sort_unstable_by_key(|(t_ms, _)| *t_ms);
    pairs
}

/// Builds one warning per wall-clock gap above five seconds between the ticks
/// of the window.
fn time_gap_warnings(run: &Run, summary: &Summary) -> Vec<Warning> {
    let ticks: Vec<(u64, u64)> = tick_unix_times(run)
        .into_iter()
        .filter(|(t_ms, _)| summary.window.start_ms <= *t_ms && *t_ms <= summary.window.end_ms)
        .collect();
    ticks
        .windows(2)
        .filter_map(|pair| {
            let gap_ms = pair[1].1.saturating_sub(pair[0].1);
            (gap_ms > GAP_THRESHOLD_MS).then_some(Warning {
                kind: WarningKind::TimeGap,
                message: WarningMessage::TimeGap { gap_ms },
            })
        })
        .collect()
}

/// Warns when the average outside CPU load of the window ticks is above twenty
/// percent.
///
/// The outside load of a tick is `system.cpu_pct` minus the tree `cpu_pct` and
/// `system.self_cpu_pct`; only ticks where all three values are present count.
fn noisy_machine_warning(run: &Run, summary: &Summary) -> Option<Warning> {
    let tree = tree_series(run, |sample| sample.cpu_pct)?;
    let system_cpu = system_series(run, |sample| sample.cpu_pct)?;
    let self_cpu = system_series(run, |sample| sample.self_cpu_pct)?;
    let tree_values = present_by_tick(&tree);
    let system_values = present_by_tick(&system_cpu);
    let self_values = present_by_tick(&self_cpu);

    let mut outside = Vec::new();
    for (t_ms, system_value) in &system_values {
        if !(summary.window.start_ms <= *t_ms && *t_ms <= summary.window.end_ms) {
            continue;
        }
        let (Some(tree_value), Some(self_value)) = (tree_values.get(t_ms), self_values.get(t_ms))
        else {
            continue;
        };
        outside.push(system_value - tree_value - self_value);
    }
    if outside.is_empty() {
        return None;
    }
    let average_pct = outside.iter().sum::<f64>() / outside.len() as f64;
    (average_pct > NOISE_THRESHOLD_PCT).then_some(Warning {
        kind: WarningKind::NoisyMachine,
        message: WarningMessage::NoisyMachine { average_pct },
    })
}

/// Maps the present values of a series to their ticks.
fn present_by_tick(series: &Series) -> BTreeMap<u64, f64> {
    series
        .xs
        .iter()
        .copied()
        .zip(series.values.iter().copied())
        .filter_map(|(t_ms, value)| value.map(|value| (t_ms, value)))
        .collect()
}

/// Builds one warning per collector that is not working or still starting, by
/// name.
fn collector_status_warnings(run: &Run) -> Vec<Warning> {
    run.meta
        .collectors
        .iter()
        .filter(|(_, status)| !matches!(status, CollectorStatus::Ok | CollectorStatus::Waiting))
        .map(|(name, status)| Warning {
            kind: WarningKind::CollectorStatus,
            message: WarningMessage::CollectorStatus {
                name: name.clone(),
                status: status.clone(),
            },
        })
        .collect()
}

/// Warns when the run stopped for a reason other than an app exit or Ctrl+C.
fn unexpected_end_reason_warning(run: &Run) -> Option<Warning> {
    let message = match run.meta.end_reason {
        Some(EndReason::AppExited | EndReason::CtrlC) => return None,
        Some(reason) => WarningMessage::UnexpectedEndReason { reason },
        None => WarningMessage::DidNotFinish,
    };
    Some(Warning {
        kind: WarningKind::UnexpectedEndReason,
        message,
    })
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Synthetic run directories for the tests.

    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use crate::meta::{CollectorStatus, EndReason, Host, ImageInfo, Meta};
    use crate::store::{
        CDP_COLUMNS, GPU_COLUMNS, JOB_COLUMNS, PROCESS_COLUMNS, PROCESSES_COLUMNS, SYSTEM_COLUMNS,
    };

    use super::Run;

    /// Marker written into the command lines of the synthetic run.
    pub(crate) const CMDLINE_MARKER: &str = "cmdline-secret-marker";

    /// Start time of the synthetic run.
    const STARTED_AT: &str = "2026-10-07T16:05:09+03:00";

    /// End time of the synthetic run.
    const ENDED_AT: &str = "2026-10-07T16:06:09+03:00";

    /// Returns the metadata of the synthetic run written by [`write_run`].
    pub(crate) fn sample_meta() -> Meta {
        let mut labels = BTreeMap::new();
        labels.insert("branch".to_string(), "test".to_string());

        let mut intervals_ms = BTreeMap::new();
        intervals_ms.insert("process".to_string(), 1000);
        intervals_ms.insert("job".to_string(), 1000);
        intervals_ms.insert("system".to_string(), 1000);
        intervals_ms.insert("gpu".to_string(), 2000);
        intervals_ms.insert("cdp".to_string(), 10_000);

        let mut collectors = BTreeMap::new();
        for name in ["process", "job", "system", "gpu", "cdp"] {
            collectors.insert(name.to_string(), CollectorStatus::Ok);
        }

        Meta {
            schema_version: 1,
            memwatch_version: "0.1.0".to_string(),
            name: "synthetic".to_string(),
            labels,
            started_at: STARTED_AT.to_string(),
            ended_at: Some(ENDED_AT.to_string()),
            end_reason: Some(EndReason::AppExited),
            exit_code: Some(0),
            command: vec![r"C:\app\main.exe".to_string()],
            cwd: r"C:\app".to_string(),
            env_overrides: BTreeMap::new(),
            intervals_ms,
            host: Host {
                os: "Windows 11 Pro 23H2 (build 22631.4317)".to_string(),
                cpu: "Test CPU".to_string(),
                logical_cpus: 8,
                ram_bytes: 17_179_869_184,
                gpus: vec!["Test GPU".to_string()],
            },
            images: vec![
                ImageInfo {
                    path: r"C:\app\main.exe".to_string(),
                    version: Some("1.0.0.0".to_string()),
                },
                ImageInfo {
                    path: r"C:\app\renderer.exe".to_string(),
                    version: Some("2.0.0.0".to_string()),
                },
            ],
            collectors,
            tree_walk_fallback: false,
        }
    }

    /// Returns a run with the synthetic metadata and no samples.
    pub(crate) fn empty_run() -> Run {
        let meta = sample_meta();
        let images = meta.images.clone();
        Run {
            meta,
            ended_at: Some(ENDED_AT.to_string()),
            ended_at_recovered: false,
            images,
            events: Vec::new(),
            processes: Vec::new(),
            job: Vec::new(),
            gpu: Vec::new(),
            cdp: Vec::new(),
            system: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Writes a complete synthetic run into `dir` and returns the run
    /// directory.
    pub(crate) fn write_run(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).expect("the run directory must be created");
        let started =
            OffsetDateTime::parse(STARTED_AT, &Rfc3339).expect("the start time must parse");
        let base_unix_ms = started.unix_timestamp() * 1000;

        write_json(&dir.join("meta.json"), &sample_meta());

        let mut events = Vec::new();
        events.push(row(
            PROCESSES_COLUMNS,
            &[
                ("t_ms", "0".to_string()),
                ("unix_ms", base_unix_ms.to_string()),
                ("event", "start".to_string()),
                ("proc_key", "100-1000".to_string()),
                ("pid", "100".to_string()),
                ("ppid", "50".to_string()),
                ("role", "main".to_string()),
                ("image_path", r"C:\app\main.exe".to_string()),
                ("image_version", "1.0.0.0".to_string()),
                ("cmdline", format!("main.exe {CMDLINE_MARKER}")),
            ],
        ));
        events.push(row(
            PROCESSES_COLUMNS,
            &[
                ("t_ms", "0".to_string()),
                ("unix_ms", base_unix_ms.to_string()),
                ("event", "start".to_string()),
                ("proc_key", "200-2000".to_string()),
                ("pid", "200".to_string()),
                ("ppid", "100".to_string()),
                ("role", "renderer".to_string()),
                ("image_path", r"C:\app\renderer.exe".to_string()),
                ("image_version", "2.0.0.0".to_string()),
                ("cmdline", format!("renderer.exe {CMDLINE_MARKER}")),
            ],
        ));
        events.push(row(
            PROCESSES_COLUMNS,
            &[
                ("t_ms", "60000".to_string()),
                ("unix_ms", (base_unix_ms + 60_000).to_string()),
                ("event", "exit".to_string()),
                ("proc_key", "100-1000".to_string()),
                ("pid", "100".to_string()),
                ("ppid", "50".to_string()),
                ("role", "main".to_string()),
                ("exit_code", "0".to_string()),
            ],
        ));
        events.push(row(
            PROCESSES_COLUMNS,
            &[
                ("t_ms", "60000".to_string()),
                ("unix_ms", (base_unix_ms + 60_000).to_string()),
                ("event", "exit".to_string()),
                ("proc_key", "200-2000".to_string()),
                ("pid", "200".to_string()),
                ("ppid", "100".to_string()),
                ("role", "renderer".to_string()),
                ("exit_code", "0".to_string()),
            ],
        ));
        write_csv(&dir.join("processes.csv"), PROCESSES_COLUMNS, &events);

        let mut process_rows = Vec::new();
        for t_ms in (0_i64..=60_000).step_by(1_000) {
            let unix_ms = (base_unix_ms + t_ms).to_string();
            process_rows.push(row(
                PROCESS_COLUMNS,
                &[
                    ("t_ms", t_ms.to_string()),
                    ("unix_ms", unix_ms.clone()),
                    ("proc_key", "100-1000".to_string()),
                    ("pid", "100".to_string()),
                    ("role", "main".to_string()),
                    ("private_bytes", (100_000_000 + t_ms * 1000).to_string()),
                    ("working_set", (120_000_000 + t_ms * 1000).to_string()),
                    ("cpu_user_ms", (t_ms * 2).to_string()),
                    ("cpu_kernel_ms", t_ms.to_string()),
                    ("cpu_pct", "2.00".to_string()),
                    ("handles", (100 + t_ms / 1000).to_string()),
                    ("gdi", (50 + t_ms / 1000).to_string()),
                    ("user", (40 + t_ms / 1000).to_string()),
                    ("threads", "10".to_string()),
                ],
            ));
            process_rows.push(row(
                PROCESS_COLUMNS,
                &[
                    ("t_ms", t_ms.to_string()),
                    ("unix_ms", unix_ms),
                    ("proc_key", "200-2000".to_string()),
                    ("pid", "200".to_string()),
                    ("role", "renderer".to_string()),
                    ("private_bytes", (50_000_000 + t_ms * 500).to_string()),
                    ("working_set", (70_000_000 + t_ms * 500).to_string()),
                    ("cpu_user_ms", t_ms.to_string()),
                    ("cpu_kernel_ms", (t_ms / 2).to_string()),
                    ("cpu_pct", "1.00".to_string()),
                    ("handles", "80".to_string()),
                    ("gdi", "30".to_string()),
                    ("user", "20".to_string()),
                    ("threads", "8".to_string()),
                ],
            ));
        }
        write_csv(&dir.join("process.csv"), PROCESS_COLUMNS, &process_rows);

        let job_rows: Vec<Vec<String>> = (0_i64..=60_000)
            .step_by(1_000)
            .map(|t_ms| {
                row(
                    JOB_COLUMNS,
                    &[
                        ("t_ms", t_ms.to_string()),
                        ("unix_ms", (base_unix_ms + t_ms).to_string()),
                        ("active_processes", "2".to_string()),
                        ("total_processes", "2".to_string()),
                        ("total_terminated_processes", "0".to_string()),
                        ("cpu_user_ms", (t_ms * 3).to_string()),
                        ("cpu_kernel_ms", (t_ms * 2).to_string()),
                        ("cpu_pct", "3.00".to_string()),
                    ],
                )
            })
            .collect();
        write_csv(&dir.join("job.csv"), JOB_COLUMNS, &job_rows);

        let gpu_rows: Vec<Vec<String>> = (0_i64..=60_000)
            .step_by(2_000)
            .map(|t_ms| {
                row(
                    GPU_COLUMNS,
                    &[
                        ("t_ms", t_ms.to_string()),
                        ("unix_ms", (base_unix_ms + t_ms).to_string()),
                        ("proc_key", "200-2000".to_string()),
                        ("pid", "200".to_string()),
                        ("dedicated_bytes", (64_000_000 + t_ms * 100).to_string()),
                        ("shared_bytes", "16000000".to_string()),
                        ("util_3d", "5.00".to_string()),
                    ],
                )
            })
            .collect();
        write_csv(&dir.join("gpu.csv"), GPU_COLUMNS, &gpu_rows);

        let cdp_rows: Vec<Vec<String>> = (0_i64..=60_000)
            .step_by(10_000)
            .map(|t_ms| {
                row(
                    CDP_COLUMNS,
                    &[
                        ("t_ms", t_ms.to_string()),
                        ("unix_ms", (base_unix_ms + t_ms).to_string()),
                        ("target_id", "page-1".to_string()),
                        ("url", "about:blank".to_string()),
                        ("js_heap_used_bytes", (20_000_000 + t_ms * 1000).to_string()),
                        ("nodes", (1000 + t_ms / 100).to_string()),
                    ],
                )
            })
            .collect();
        write_csv(&dir.join("cdp.csv"), CDP_COLUMNS, &cdp_rows);

        let system_rows: Vec<Vec<String>> = (0_i64..=60_000)
            .step_by(1_000)
            .map(|t_ms| {
                row(
                    SYSTEM_COLUMNS,
                    &[
                        ("t_ms", t_ms.to_string()),
                        ("unix_ms", (base_unix_ms + t_ms).to_string()),
                        ("cpu_pct", "10.00".to_string()),
                        ("self_cpu_pct", "1.00".to_string()),
                    ],
                )
            })
            .collect();
        write_csv(&dir.join("system.csv"), SYSTEM_COLUMNS, &system_rows);

        dir.to_path_buf()
    }

    /// Writes `meta` as pretty JSON.
    fn write_json(path: &Path, meta: &Meta) {
        let json = serde_json::to_vec_pretty(meta).expect("the metadata must serialize");
        fs::write(path, json).expect("meta.json must be written");
    }

    /// Writes a CSV file with the given header and rows.
    fn write_csv(path: &Path, columns: &[&str], rows: &[Vec<String>]) {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_path(path)
            .expect("the fixture CSV must be created");
        writer
            .write_record(columns)
            .expect("the header must be written");
        for row in rows {
            writer.write_record(row).expect("the row must be written");
        }
        writer.flush().expect("the fixture CSV must be flushed");
    }

    /// Builds one CSV row from `(column, value)` pairs; absent cells become
    /// empty strings.
    fn row(columns: &[&str], values: &[(&str, String)]) -> Vec<String> {
        columns
            .iter()
            .map(|column| {
                values
                    .iter()
                    .find(|(name, _)| name == column)
                    .map_or_else(String::new, |(_, value)| value.clone())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn load_reads_complete_run() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());

        let run = load(&run_dir).expect("the complete run must load");

        assert_eq!(run.meta.name, "synthetic");
        assert_eq!(run.ended_at.as_deref(), Some("2026-10-07T16:06:09+03:00"));
        assert!(
            !run.ended_at_recovered,
            "the end time must not be recovered"
        );
        let images: Vec<(&str, Option<&str>)> = run
            .images
            .iter()
            .map(|image| (image.path.as_str(), image.version.as_deref()))
            .collect();
        assert_eq!(
            images,
            [
                (r"C:\app\main.exe", Some("1.0.0.0")),
                (r"C:\app\renderer.exe", Some("2.0.0.0")),
            ]
        );
        assert!(!run.events.is_empty(), "events must be read");
        assert!(!run.processes.is_empty(), "processes must be read");
        assert!(!run.job.is_empty(), "job must be read");
        assert!(!run.gpu.is_empty(), "gpu must be read");
        assert!(!run.cdp.is_empty(), "cdp must be read");
        assert!(!run.system.is_empty(), "system must be read");
        assert!(
            run.warnings.is_empty(),
            "a complete run must have no warnings"
        );
        assert_eq!(run.duration_ms(), 60_000);
    }

    #[test]
    fn load_requires_meta_json() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        fs::remove_file(run_dir.join("meta.json")).expect("meta.json must be removed");

        assert_eq!(load(&run_dir).unwrap_err(), RunReadError::MissingMeta);
    }

    #[test]
    fn load_requires_processes_csv() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        fs::remove_file(run_dir.join("processes.csv")).expect("processes.csv must be removed");

        assert_eq!(load(&run_dir).unwrap_err(), RunReadError::MissingProcesses);
    }

    #[test]
    fn load_rejects_incompatible_schema_version() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        edit_meta(&run_dir, "schema_version", serde_json::json!(2));

        assert_eq!(
            load(&run_dir).unwrap_err(),
            RunReadError::IncompatibleSchema {
                version: "2".to_string()
            }
        );
    }

    #[test]
    fn load_rejects_unreadable_meta_json() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        fs::write(run_dir.join("meta.json"), "{not json").expect("meta.json must be written");

        assert!(matches!(
            load(&run_dir).unwrap_err(),
            RunReadError::UnreadableMeta { .. }
        ));
    }

    #[test]
    fn load_rejects_processes_csv_without_header() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        fs::write(run_dir.join("processes.csv"), "").expect("processes.csv must be written");

        assert_eq!(
            load(&run_dir).unwrap_err(),
            RunReadError::ProcessesWithoutHeader
        );
    }

    #[test]
    fn load_missing_optional_file_warns_and_leaves_group_empty() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        fs::remove_file(run_dir.join("gpu.csv")).expect("gpu.csv must be removed");

        let run = load(&run_dir).expect("a run without gpu.csv must load");

        assert!(run.gpu.is_empty(), "the gpu group must stay empty");
        assert_eq!(
            run.warnings,
            vec![Warning {
                kind: WarningKind::NoData,
                message: WarningMessage::MissingFile {
                    file: "gpu.csv".to_string()
                },
            }]
        );
        assert!(!run.events.is_empty(), "events must be read");
        assert!(!run.processes.is_empty(), "processes must be read");
    }

    #[test]
    fn load_optional_file_without_header_warns() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        fs::write(run_dir.join("gpu.csv"), "").expect("gpu.csv must be written");

        let run = load(&run_dir).expect("a run with an empty gpu.csv must load");

        assert!(run.gpu.is_empty(), "the gpu group must stay empty");
        assert_eq!(
            run.warnings,
            vec![Warning {
                kind: WarningKind::NoData,
                message: WarningMessage::MissingFile {
                    file: "gpu.csv".to_string()
                },
            }]
        );
    }

    #[test]
    fn load_drops_torn_last_row() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        let path = run_dir.join("process.csv");
        let mut content = fs::read_to_string(&path).expect("process.csv must be readable");
        content.push_str("60000,1791378369000\n");
        fs::write(&path, content).expect("process.csv must be written");

        let run = load(&run_dir).expect("a run with a torn last row must load");

        assert_eq!(run.processes.len(), 122);
        assert!(run.warnings.is_empty(), "a torn last row must be silent");
    }

    #[test]
    fn load_drops_rows_with_decreasing_t_ms() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        let path = run_dir.join("process.csv");
        let mut rows = read_rows(&path);
        let mut duplicate = rows.last().expect("there must be rows").clone();
        duplicate[0] = "59000".to_string();
        rows.push(duplicate);
        write_rows(&path, &rows);

        let run = load(&run_dir).expect("a run with a decreasing t_ms must load");

        assert_eq!(run.processes.len(), 122);
        assert_eq!(
            run.warnings,
            vec![Warning {
                kind: WarningKind::DroppedRow,
                message: WarningMessage::DroppedRows {
                    file: "process.csv".to_string()
                },
            }]
        );
    }

    #[test]
    fn load_drops_rows_with_non_numeric_t_ms() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        let path = run_dir.join("process.csv");
        let mut rows = read_rows(&path);
        let mut duplicate = rows.last().expect("there must be rows").clone();
        duplicate[0] = "x".to_string();
        rows.push(duplicate);
        write_rows(&path, &rows);

        let run = load(&run_dir).expect("a run with a non-numeric t_ms must load");

        assert_eq!(run.processes.len(), 122);
        assert_eq!(
            run.warnings,
            vec![Warning {
                kind: WarningKind::DroppedRow,
                message: WarningMessage::DroppedRows {
                    file: "process.csv".to_string()
                },
            }]
        );
    }

    #[test]
    fn load_treats_non_numeric_cell_as_missing() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        rewrite_cell(&run_dir.join("process.csv"), 0, "private_bytes", "x");

        let run = load(&run_dir).expect("a run with a non-numeric cell must load");

        assert_eq!(run.processes[0].private_bytes, None);
        assert_eq!(
            run.warnings,
            vec![Warning {
                kind: WarningKind::NonNumeric,
                message: WarningMessage::NonNumericCells {
                    file: "process.csv".to_string()
                },
            }]
        );
    }

    #[test]
    fn load_keeps_empty_cells_as_missing() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        rewrite_cell(&run_dir.join("process.csv"), 0, "cpu_pct", "");

        let run = load(&run_dir).expect("a run with an empty cell must load");

        assert_eq!(run.processes[0].cpu_pct, None);
        assert!(run.warnings.is_empty(), "an empty cell must be silent");
    }

    #[test]
    fn load_keeps_empty_text_cells_as_none() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());

        let run = load(&run_dir).expect("the complete run must load");

        let exits: Vec<&Event> = run
            .events
            .iter()
            .filter(|event| event.event == Some(ProcessEvent::Exit))
            .collect();
        assert_eq!(exits.len(), 2, "the synthetic run must have two exits");
        for event in exits {
            assert_eq!(event.image_path, None);
            assert_eq!(event.image_version, None);
        }
    }

    #[test]
    fn load_recovers_ended_at_from_last_tick() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        edit_meta(&run_dir, "ended_at", serde_json::Value::Null);

        let run = load(&run_dir).expect("a run without ended_at must load");

        assert_eq!(run.ended_at.as_deref(), Some("2026-10-07T16:06:09+03:00"));
        assert!(run.ended_at_recovered, "the end time must be recovered");
    }

    #[test]
    fn load_recovers_images_from_events() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        edit_meta(&run_dir, "images", serde_json::json!([]));
        let path = run_dir.join("processes.csv");
        let mut rows = read_rows(&path);
        let mut duplicate = rows[1].clone();
        duplicate[0] = "60000".to_string();
        duplicate[1] = (duplicate[1]
            .parse::<i64>()
            .expect("unix_ms must be an integer")
            + 60_000)
            .to_string();
        duplicate[3] = "300-3000".to_string();
        duplicate[4] = "300".to_string();
        rows.push(duplicate);
        write_rows(&path, &rows);

        let run = load(&run_dir).expect("a run without images must load");

        let images: Vec<(&str, Option<&str>)> = run
            .images
            .iter()
            .map(|image| (image.path.as_str(), image.version.as_deref()))
            .collect();
        assert_eq!(
            images,
            [
                (r"C:\app\main.exe", Some("1.0.0.0")),
                (r"C:\app\renderer.exe", Some("2.0.0.0")),
            ]
        );
        assert!(
            run.warnings.is_empty(),
            "the recovered run must have no warnings"
        );
    }

    #[test]
    fn load_reads_header_only_tables() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        for name in [
            "processes.csv",
            "process.csv",
            "job.csv",
            "gpu.csv",
            "cdp.csv",
            "system.csv",
        ] {
            let path = run_dir.join(name);
            let header = read_rows(&path)[..1].to_vec();
            write_rows(&path, &header);
        }

        let run = load(&run_dir).expect("a run with header-only tables must load");

        assert!(run.events.is_empty());
        assert!(run.processes.is_empty());
        assert!(run.job.is_empty());
        assert!(run.gpu.is_empty());
        assert!(run.cdp.is_empty());
        assert!(run.system.is_empty());
        assert_eq!(run.duration_ms(), 0);
        assert!(run.warnings.is_empty());
    }

    #[test]
    fn tree_series_sums_present_values_per_tick() {
        let run = run_with_processes(vec![
            process_sample(0, "100-1000", "main", Some(100.0)),
            process_sample(0, "200-2000", "renderer", Some(200.0)),
            process_sample(1000, "100-1000", "main", Some(150.0)),
            process_sample(1000, "200-2000", "renderer", None),
            process_sample(2000, "100-1000", "main", None),
            process_sample(2000, "200-2000", "renderer", None),
        ]);

        let series = tree_series(&run, |sample| sample.private_bytes);

        assert_eq!(
            series,
            Some(series_of(
                "tree",
                vec![0, 1000, 2000],
                vec![Some(300.0), Some(150.0), None]
            ))
        );
    }

    #[test]
    fn role_series_groups_by_role_on_every_tick() {
        let run = run_with_processes(vec![
            process_sample(0, "200-2000", "renderer", Some(10.0)),
            process_sample(0, "100-1000", "main", Some(20.0)),
            process_sample(1000, "100-1000", "main", Some(30.0)),
        ]);

        let series = role_series(&run, |sample| sample.private_bytes);

        assert_eq!(
            series,
            vec![
                series_of("main", vec![0, 1000], vec![Some(20.0), Some(30.0)]),
                series_of("renderer", vec![0, 1000], vec![Some(10.0), None]),
            ]
        );
    }

    #[test]
    fn process_series_follows_each_process() {
        let run = run_with_processes(vec![
            process_sample(0, "200-2000", "renderer", Some(5.0)),
            process_sample(0, "100-1000", "main", Some(7.0)),
            process_sample(1000, "100-1000", "main", Some(8.0)),
        ]);

        let series = process_series(&run, |sample| sample.private_bytes);

        assert_eq!(
            series,
            vec![
                series_of("200-2000", vec![0], vec![Some(5.0)]),
                series_of("100-1000", vec![0, 1000], vec![Some(7.0), Some(8.0)]),
            ]
        );
    }

    #[test]
    fn count_series_counts_rows_per_tick() {
        let run = run_with_processes(vec![
            process_sample(0, "100-1000", "main", None),
            process_sample(0, "200-2000", "renderer", None),
            process_sample(1000, "100-1000", "main", None),
        ]);

        let series = count_series(&run);

        assert_eq!(
            series,
            Some(series_of(
                "processes",
                vec![0, 1000],
                vec![Some(2.0), Some(1.0)]
            ))
        );
    }

    #[test]
    fn gpu_series_sums_rows_per_tick() {
        let mut run = fixtures::empty_run();
        run.gpu = vec![
            gpu_sample(0, Some(100.0)),
            gpu_sample(0, Some(200.0)),
            gpu_sample(2000, Some(50.0)),
        ];

        let series = gpu_series(&run, |sample| sample.dedicated_bytes);

        assert_eq!(
            series,
            Some(series_of(
                "tree",
                vec![0, 2000],
                vec![Some(300.0), Some(50.0)]
            ))
        );
    }

    #[test]
    fn cdp_series_sums_pages_per_tick() {
        let mut run = fixtures::empty_run();
        run.cdp = vec![
            cdp_sample(0, Some(10.0)),
            cdp_sample(0, Some(20.0)),
            cdp_sample(10_000, Some(30.0)),
        ];

        let series = cdp_series(&run, |sample| sample.js_heap_used_bytes);

        assert_eq!(
            series,
            Some(series_of(
                "tree",
                vec![0, 10_000],
                vec![Some(30.0), Some(30.0)]
            ))
        );
    }

    #[test]
    fn system_series_reads_ticks() {
        let mut run = fixtures::empty_run();
        run.system = vec![
            system_sample(0, Some(10.0)),
            system_sample(1000, Some(20.0)),
        ];

        let series = system_series(&run, |sample| sample.cpu_pct);

        assert_eq!(
            series,
            Some(series_of(
                "tree",
                vec![0, 1000],
                vec![Some(10.0), Some(20.0)]
            ))
        );
    }

    #[test]
    fn series_return_none_for_missing_group() {
        let run = fixtures::empty_run();

        assert_eq!(tree_series(&run, |sample| sample.private_bytes), None);
        assert_eq!(role_series(&run, |sample| sample.private_bytes), Vec::new());
        assert_eq!(
            process_series(&run, |sample| sample.private_bytes),
            Vec::new()
        );
        assert_eq!(count_series(&run), None);
        assert_eq!(gpu_series(&run, |sample| sample.dedicated_bytes), None);
        assert_eq!(cdp_series(&run, |sample| sample.js_heap_used_bytes), None);
        assert_eq!(system_series(&run, |sample| sample.cpu_pct), None);
    }

    /// Reads all CSV rows of a file, including its header.
    fn read_rows(path: &Path) -> Vec<Vec<String>> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_path(path)
            .expect("the CSV must be readable");
        reader
            .records()
            .map(|record| {
                record
                    .expect("the row must parse")
                    .iter()
                    .map(str::to_string)
                    .collect()
            })
            .collect()
    }

    /// Replaces a CSV file with the given rows.
    fn write_rows(path: &Path, rows: &[Vec<String>]) {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_path(path)
            .expect("the CSV must be writable");
        for row in rows {
            writer.write_record(row).expect("the row must be written");
        }
        writer.flush().expect("the CSV must be flushed");
    }

    /// Replaces one data cell of a CSV file; `row_index` counts data rows.
    fn rewrite_cell(path: &Path, row_index: usize, column: &str, value: &str) {
        let mut rows = read_rows(path);
        let index = rows[0]
            .iter()
            .position(|name| name == column)
            .expect("the column must exist");
        rows[row_index + 1][index] = value.to_string();
        write_rows(path, &rows);
    }

    /// Applies one change to the metadata of a synthetic run.
    fn edit_meta(run_dir: &Path, key: &str, value: serde_json::Value) {
        let path = run_dir.join("meta.json");
        let text = fs::read_to_string(&path).expect("meta.json must be readable");
        let mut root: serde_json::Value =
            serde_json::from_str(&text).expect("meta.json must parse");
        root.as_object_mut()
            .expect("meta.json must be an object")
            .insert(key.to_string(), value);
        fs::write(
            &path,
            serde_json::to_string(&root).expect("meta.json must serialize"),
        )
        .expect("meta.json must be written");
    }

    /// Builds an expected series value.
    fn series_of(name: &str, xs: Vec<u64>, values: Vec<Option<f64>>) -> Series {
        Series {
            name: name.to_string(),
            xs,
            values,
        }
    }

    /// Builds a process sample with only the fields the series tests need.
    fn process_sample(
        t_ms: u64,
        proc_key: &str,
        role: &str,
        private_bytes: Option<f64>,
    ) -> ProcessSample {
        ProcessSample {
            t_ms,
            unix_ms: t_ms,
            proc_key: Some(proc_key.to_string()),
            role: Some(role.to_string()),
            private_bytes,
            working_set: None,
            cpu_user_ms: None,
            cpu_kernel_ms: None,
            cpu_pct: None,
            handles: None,
            gdi: None,
            user: None,
            threads: None,
        }
    }

    /// Builds a GPU sample with only the fields the series tests need.
    fn gpu_sample(t_ms: u64, dedicated_bytes: Option<f64>) -> GpuSample {
        GpuSample {
            t_ms,
            unix_ms: t_ms,
            dedicated_bytes,
            shared_bytes: None,
        }
    }

    /// Builds a DevTools sample with only the fields the series tests need.
    fn cdp_sample(t_ms: u64, js_heap_used_bytes: Option<f64>) -> CdpSample {
        CdpSample {
            t_ms,
            unix_ms: t_ms,
            js_heap_used_bytes,
            nodes: None,
        }
    }

    /// Builds a machine-wide sample with only the fields the series tests need.
    fn system_sample(t_ms: u64, cpu_pct: Option<f64>) -> SystemSample {
        SystemSample {
            t_ms,
            unix_ms: t_ms,
            cpu_pct,
            self_cpu_pct: None,
        }
    }

    /// Returns an empty run with the given process samples.
    fn run_with_processes(processes: Vec<ProcessSample>) -> Run {
        let mut run = fixtures::empty_run();
        run.processes = processes;
        run
    }

    /// One hour in milliseconds.
    const HOUR_MS: u64 = 3_600_000;

    /// Half an hour in milliseconds.
    const HALF_HOUR_MS: u64 = HOUR_MS / 2;

    #[test]
    fn metric_stats_computes_start_peak_mean_and_percentiles() {
        let series = series_of(
            "tree",
            vec![0, HOUR_MS, 2 * HOUR_MS, 3 * HOUR_MS],
            vec![Some(10.0), Some(20.0), Some(30.0), Some(40.0)],
        );

        let stats = metric_stats(
            Some(&series),
            Window {
                start_ms: 0,
                end_ms: 3 * HOUR_MS,
            },
            0,
        );

        assert_eq!(stats.start, Some(10.0));
        assert_eq!(stats.peak, Some(40.0));
        assert_eq!(stats.mean, Some(25.0));
        assert_eq!(stats.p50, Some(25.0));
        assert_eq!(stats.p95, Some(38.5));
        assert_eq!(stats.end, Some(40.0));
        assert_eq!(stats.delta, Some(30.0));
        assert_eq!(stats.samples, 4);
    }

    #[test]
    fn metric_stats_growth_uses_least_squares() {
        let xs: Vec<u64> = (0..5_u64).map(|index| index * HALF_HOUR_MS).collect();
        let values: Vec<Option<f64>> = (0..5_u64).map(|index| Some(index as f64)).collect();
        let series = series_of("tree", xs, values);

        let stats = metric_stats(
            Some(&series),
            Window {
                start_ms: 0,
                end_ms: 2 * HOUR_MS,
            },
            0,
        );

        assert!(
            (stats.growth_per_hour.expect("growth must be present") - 2.0).abs() < 1e-9,
            "the slope must be two units per hour"
        );
        assert!(
            (stats.r2.expect("R² must be present") - 1.0).abs() < 1e-9,
            "a linear series must fit perfectly"
        );
    }

    #[test]
    fn metric_stats_r2_reports_fit_quality() {
        let series = series_of(
            "tree",
            vec![0, HOUR_MS, 2 * HOUR_MS],
            vec![Some(0.0), Some(1.0), Some(0.0)],
        );

        let stats = metric_stats(
            Some(&series),
            Window {
                start_ms: 0,
                end_ms: 2 * HOUR_MS,
            },
            0,
        );

        assert!(
            (stats.growth_per_hour.expect("growth must be present") - 0.0).abs() < 1e-9,
            "a symmetric series must have no slope"
        );
        assert!(
            (stats.r2.expect("R² must be present") - 0.0).abs() < 1e-9,
            "a series that no line fits must score zero"
        );
    }

    #[test]
    fn metric_stats_excludes_warmup_from_growth() {
        let series = series_of(
            "tree",
            vec![0, 600_000, 1_200_000, 1_800_000, 2_400_000, 3_000_000],
            vec![
                Some(0.0),
                Some(0.0),
                Some(100.0),
                Some(100.0),
                Some(100.0),
                Some(100.0),
            ],
        );

        let after_warmup = metric_stats(
            Some(&series),
            Window {
                start_ms: 0,
                end_ms: 3_000_000,
            },
            1_200_000,
        );
        let without_warmup = metric_stats(
            Some(&series),
            Window {
                start_ms: 0,
                end_ms: 3_000_000,
            },
            0,
        );

        assert!(
            after_warmup
                .growth_per_hour
                .expect("growth must be present")
                .abs()
                < 1e-9,
            "the flat section after the warmup must have no slope"
        );
        assert!(
            after_warmup.growth_per_hour < without_warmup.growth_per_hour,
            "excluding the warmup must reduce the slope"
        );
    }

    #[test]
    fn metric_stats_without_values_are_empty() {
        let series = series_of("tree", vec![0, HOUR_MS], vec![None, None]);

        let stats = metric_stats(
            Some(&series),
            Window {
                start_ms: 0,
                end_ms: 2 * HOUR_MS,
            },
            0,
        );

        assert_eq!(stats.start, None);
        assert_eq!(stats.peak, None);
        assert_eq!(stats.mean, None);
        assert_eq!(stats.p50, None);
        assert_eq!(stats.p95, None);
        assert_eq!(stats.end, None);
        assert_eq!(stats.delta, None);
        assert_eq!(stats.growth_per_hour, None);
        assert_eq!(stats.r2, None);
        assert_eq!(stats.median_hour_delta, None);
        assert_eq!(stats.samples, 0);
    }

    #[test]
    fn metric_stats_hour_delta_compares_first_and_last_hour() {
        let series = series_of(
            "tree",
            (0..7_u64).map(|index| index * HALF_HOUR_MS).collect(),
            vec![
                Some(100.0),
                Some(100.0),
                Some(100.0),
                Some(150.0),
                Some(200.0),
                Some(200.0),
                Some(200.0),
            ],
        );

        let stats = metric_stats(
            Some(&series),
            Window {
                start_ms: 0,
                end_ms: 3 * HOUR_MS,
            },
            0,
        );

        assert_eq!(stats.median_hour_delta, Some(100.0));
    }

    #[test]
    fn summarize_flags_short_runs() {
        let run = run_with_processes(vec![
            process_sample(0, "100-1000", "main", Some(100.0)),
            process_sample(HOUR_MS, "100-1000", "main", Some(200.0)),
        ]);

        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: HOUR_MS,
            },
            0,
        );

        assert!(summary.too_short_for_hour_delta);
        assert!(
            summary
                .metrics
                .values()
                .all(|stats| stats.median_hour_delta.is_none()),
            "a short run must not report hour deltas"
        );
    }

    #[test]
    fn summarize_collects_tree_metrics() {
        let mut first = blank_process_sample(0, "100-1000", "main");
        first.private_bytes = Some(100.0);
        first.working_set = Some(110.0);
        first.handles = Some(10.0);
        first.threads = Some(4.0);
        let mut second = blank_process_sample(0, "200-2000", "renderer");
        second.private_bytes = Some(200.0);
        second.working_set = Some(210.0);
        second.handles = Some(20.0);
        second.threads = Some(5.0);
        let mut third = blank_process_sample(1000, "100-1000", "main");
        third.private_bytes = Some(150.0);
        third.working_set = Some(160.0);
        third.handles = Some(11.0);
        third.threads = Some(4.0);
        let mut fourth = blank_process_sample(1000, "200-2000", "renderer");
        fourth.private_bytes = Some(250.0);
        fourth.working_set = Some(260.0);
        fourth.handles = Some(21.0);
        fourth.threads = Some(6.0);
        let run = run_with_processes(vec![first, second, third, fourth]);

        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: 1000,
            },
            0,
        );

        assert!(summary.metrics[&MetricId::PrivateBytes].samples > 0);
        assert!(summary.metrics[&MetricId::Handles].samples > 0);
        assert!(summary.metrics[&MetricId::Threads].samples > 0);
        assert_eq!(summary.metrics[&MetricId::DomNodes].samples, 0);
    }

    #[test]
    fn summarize_takes_cpu_seconds_from_job() {
        let mut run = fixtures::empty_run();
        run.job = vec![
            job_sample(0, Some(500.0), Some(100.0)),
            job_sample(1000, Some(1500.0), Some(500.0)),
        ];

        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: 1000,
            },
            0,
        );

        assert_eq!(summary.cpu.total_seconds, Some(2.0));
        assert!(!summary.cpu.from_process_rows);
    }

    #[test]
    fn summarize_takes_cpu_seconds_from_process_rows_on_tree_walk() {
        let mut first = blank_process_sample(0, "100-1000", "main");
        first.cpu_user_ms = Some(100.0);
        first.cpu_kernel_ms = Some(50.0);
        let mut second = blank_process_sample(1000, "100-1000", "main");
        second.cpu_user_ms = Some(2000.0);
        second.cpu_kernel_ms = Some(1000.0);
        let mut third = blank_process_sample(0, "200-2000", "renderer");
        third.cpu_user_ms = Some(10.0);
        third.cpu_kernel_ms = Some(5.0);
        let mut fourth = blank_process_sample(1000, "200-2000", "renderer");
        fourth.cpu_user_ms = Some(500.0);
        fourth.cpu_kernel_ms = Some(500.0);
        let mut run = run_with_processes(vec![first, second, third, fourth]);
        run.meta.tree_walk_fallback = true;

        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: 1000,
            },
            0,
        );

        assert_eq!(summary.cpu.total_seconds, Some(4.0));
        assert!(summary.cpu.from_process_rows);
    }

    #[test]
    fn summarize_counts_processes() {
        let mut run = run_with_processes(vec![
            blank_process_sample(0, "100-1000", "main"),
            blank_process_sample(0, "200-2000", "renderer"),
            blank_process_sample(1000, "100-1000", "main"),
        ]);
        run.events = vec![
            event_sample(0, ProcessEvent::Start),
            event_sample(0, ProcessEvent::Start),
            event_sample(500, ProcessEvent::Start),
            event_sample(900, ProcessEvent::Exit),
            event_sample(1000, ProcessEvent::Exit),
        ];

        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: 1000,
            },
            0,
        );

        assert_eq!(summary.processes.started, 3);
        assert_eq!(summary.processes.exited, 2);
        assert_eq!(summary.processes.max_concurrent, 2);
    }

    /// Wall-clock base of the computed-warning tests.
    const BASE_UNIX_MS: u64 = 1_700_000_000_000;

    #[test]
    fn warnings_report_time_gaps() {
        let run = run_with_processes(vec![
            warning_process_sample(0, BASE_UNIX_MS, None),
            warning_process_sample(1000, BASE_UNIX_MS + 6000, None),
        ]);
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );

        let gaps: Vec<Warning> = compute_warnings(&run, &summary)
            .into_iter()
            .filter(|warning| warning.kind == WarningKind::TimeGap)
            .collect();

        assert_eq!(
            gaps,
            vec![Warning {
                kind: WarningKind::TimeGap,
                message: WarningMessage::TimeGap { gap_ms: 6000 },
            }]
        );

        let run = run_with_processes(vec![
            warning_process_sample(0, BASE_UNIX_MS, None),
            warning_process_sample(1000, BASE_UNIX_MS + 3000, None),
        ]);
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );

        assert!(
            compute_warnings(&run, &summary)
                .iter()
                .all(|warning| warning.kind != WarningKind::TimeGap),
            "a three-second gap must not warn"
        );
    }

    #[test]
    fn warnings_report_noisy_machine() {
        let mut run = run_with_processes(vec![warning_process_sample(0, BASE_UNIX_MS, Some(10.0))]);
        run.system = vec![warning_system_sample(
            0,
            BASE_UNIX_MS,
            Some(50.0),
            Some(5.0),
        )];
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );

        let noisy: Vec<Warning> = compute_warnings(&run, &summary)
            .into_iter()
            .filter(|warning| warning.kind == WarningKind::NoisyMachine)
            .collect();

        assert_eq!(
            noisy,
            vec![Warning {
                kind: WarningKind::NoisyMachine,
                message: WarningMessage::NoisyMachine { average_pct: 35.0 },
            }]
        );

        let mut run = run_with_processes(vec![warning_process_sample(0, BASE_UNIX_MS, Some(10.0))]);
        run.system = vec![warning_system_sample(
            0,
            BASE_UNIX_MS,
            Some(30.0),
            Some(5.0),
        )];
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );

        assert!(
            compute_warnings(&run, &summary)
                .iter()
                .all(|warning| warning.kind != WarningKind::NoisyMachine),
            "an average outside load of fifteen percent must not warn"
        );
    }

    #[test]
    fn warnings_report_collector_statuses() {
        let mut run = fixtures::empty_run();
        run.meta.collectors = BTreeMap::from([
            ("process".to_string(), CollectorStatus::Ok),
            ("job".to_string(), CollectorStatus::Failed("x".to_string())),
            ("gpu".to_string(), CollectorStatus::Unavailable),
            ("cdp".to_string(), CollectorStatus::Disabled),
            ("system".to_string(), CollectorStatus::Waiting),
        ]);
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );

        let statuses: Vec<Warning> = compute_warnings(&run, &summary)
            .into_iter()
            .filter(|warning| warning.kind == WarningKind::CollectorStatus)
            .collect();

        assert_eq!(
            statuses,
            vec![
                Warning {
                    kind: WarningKind::CollectorStatus,
                    message: WarningMessage::CollectorStatus {
                        name: "cdp".to_string(),
                        status: CollectorStatus::Disabled,
                    },
                },
                Warning {
                    kind: WarningKind::CollectorStatus,
                    message: WarningMessage::CollectorStatus {
                        name: "gpu".to_string(),
                        status: CollectorStatus::Unavailable,
                    },
                },
                Warning {
                    kind: WarningKind::CollectorStatus,
                    message: WarningMessage::CollectorStatus {
                        name: "job".to_string(),
                        status: CollectorStatus::Failed("x".to_string()),
                    },
                },
            ]
        );
    }

    #[test]
    fn warnings_report_tree_walk_fallback() {
        let mut run = fixtures::empty_run();
        run.meta.tree_walk_fallback = true;
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );

        let fallbacks: Vec<Warning> = compute_warnings(&run, &summary)
            .into_iter()
            .filter(|warning| warning.kind == WarningKind::TreeWalkFallback)
            .collect();

        assert_eq!(
            fallbacks,
            vec![Warning {
                kind: WarningKind::TreeWalkFallback,
                message: WarningMessage::TreeWalkFallback,
            }]
        );

        let run = fixtures::empty_run();
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );

        assert!(
            compute_warnings(&run, &summary)
                .iter()
                .all(|warning| warning.kind != WarningKind::TreeWalkFallback),
            "a run without the fallback must not warn"
        );
    }

    #[test]
    fn warnings_report_unexpected_end_reason() {
        for reason in [Some(EndReason::LaunchFailed), None] {
            let mut run = fixtures::empty_run();
            run.meta.end_reason = reason;
            let summary = summarize(
                &run,
                Window {
                    start_ms: 0,
                    end_ms: run.duration_ms(),
                },
                0,
            );

            let unexpected: Vec<Warning> = compute_warnings(&run, &summary)
                .into_iter()
                .filter(|warning| warning.kind == WarningKind::UnexpectedEndReason)
                .collect();

            assert_eq!(unexpected.len(), 1, "{reason:?} must warn");
            let expected = match reason {
                Some(reason) => WarningMessage::UnexpectedEndReason { reason },
                None => WarningMessage::DidNotFinish,
            };
            assert_eq!(unexpected[0].message, expected);
        }

        for reason in [EndReason::AppExited, EndReason::CtrlC] {
            let mut run = fixtures::empty_run();
            run.meta.end_reason = Some(reason);
            let summary = summarize(
                &run,
                Window {
                    start_ms: 0,
                    end_ms: run.duration_ms(),
                },
                0,
            );

            assert!(
                compute_warnings(&run, &summary)
                    .iter()
                    .all(|warning| warning.kind != WarningKind::UnexpectedEndReason),
                "{reason:?} must not warn"
            );
        }
    }

    #[test]
    fn warnings_include_read_warnings_first() {
        let read_warnings = vec![
            Warning {
                kind: WarningKind::NoData,
                message: WarningMessage::MissingFile {
                    file: "gpu.csv".to_string(),
                },
            },
            Warning {
                kind: WarningKind::DroppedRow,
                message: WarningMessage::DroppedRows {
                    file: "process.csv".to_string(),
                },
            },
        ];
        let mut run = fixtures::empty_run();
        run.meta.end_reason = Some(EndReason::LaunchFailed);
        run.warnings = read_warnings.clone();
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        );

        let warnings = compute_warnings(&run, &summary);

        assert_eq!(&warnings[..2], &read_warnings[..]);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.kind == WarningKind::UnexpectedEndReason),
            "the computed warnings must follow the reading ones"
        );
    }

    /// Builds a process sample with the given tick, wall-clock time and CPU
    /// percentage.
    fn warning_process_sample(t_ms: u64, unix_ms: u64, cpu_pct: Option<f64>) -> ProcessSample {
        let mut sample = blank_process_sample(t_ms, "100-1000", "main");
        sample.unix_ms = unix_ms;
        sample.cpu_pct = cpu_pct;
        sample
    }

    /// Builds a machine-wide sample with both CPU percentages set.
    fn warning_system_sample(
        t_ms: u64,
        unix_ms: u64,
        cpu_pct: Option<f64>,
        self_cpu_pct: Option<f64>,
    ) -> SystemSample {
        SystemSample {
            t_ms,
            unix_ms,
            cpu_pct,
            self_cpu_pct,
        }
    }

    /// Builds a process sample with only the tick, identity and role set.
    fn blank_process_sample(t_ms: u64, proc_key: &str, role: &str) -> ProcessSample {
        ProcessSample {
            t_ms,
            unix_ms: t_ms,
            proc_key: Some(proc_key.to_string()),
            role: Some(role.to_string()),
            private_bytes: None,
            working_set: None,
            cpu_user_ms: None,
            cpu_kernel_ms: None,
            cpu_pct: None,
            handles: None,
            gdi: None,
            user: None,
            threads: None,
        }
    }

    /// Builds a job sample with the given cumulative CPU times.
    fn job_sample(t_ms: u64, cpu_user_ms: Option<f64>, cpu_kernel_ms: Option<f64>) -> JobSample {
        JobSample {
            t_ms,
            unix_ms: t_ms,
            cpu_user_ms,
            cpu_kernel_ms,
        }
    }

    /// Builds a process lifecycle event with the given kind.
    fn event_sample(t_ms: u64, event: ProcessEvent) -> Event {
        Event {
            t_ms,
            unix_ms: t_ms,
            event: Some(event),
            proc_key: None,
            role: None,
            image_path: None,
            image_version: None,
        }
    }
}
