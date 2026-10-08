//! GPU memory and engine utilization read from PDH performance counters.

use std::collections::BTreeMap;
use std::io;
use std::mem::size_of;

use anyhow::anyhow;
use windows::Win32::System::Performance::{
    PDH_CSTATUS_INVALID_DATA, PDH_CSTATUS_NO_INSTANCE, PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE,
    PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA, PDH_NO_DATA, PdhAddEnglishCounterW, PdhCloseQuery,
    PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
};
use windows::core::PCWSTR;

use crate::collect::{CollectError, Collector, TickCtx};
use crate::log::RunLog;
use crate::store::{CsvTable, GpuRow, fmt_pct};

/// One PDH GPU instance: a process and, for engine counters, the engine type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuInstance {
    /// Process ID from the instance name.
    pub pid: u32,
    /// Engine type after the last `engtype_`; `None` when the name has none.
    pub engine_type: Option<String>,
}

/// Parses a PDH GPU instance name.
///
/// The name must start with `pid_` followed by digits. The engine type is the
/// text after the last `engtype_`; a name without it is a memory instance.
/// Everything else in the name is ignored. Returns `None` when the name does
/// not start with `pid_<digits>`.
pub fn parse_instance(name: &str) -> Option<GpuInstance> {
    let rest = name.strip_prefix("pid_")?;
    let digits = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 {
        return None;
    }
    let pid: u32 = rest[..digits].parse().ok()?;
    let engine_type = name
        .rsplit_once("engtype_")
        .map(|(_, engine_type)| engine_type.to_string());
    Some(GpuInstance { pid, engine_type })
}

/// GPU memory and utilization of one process, aggregated over its counter
/// instances.
///
/// Every field is `None` when no instance of that metric was read for the
/// process; `Some(0)` is a real zero.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct GpuTotals {
    /// Dedicated GPU memory in bytes, summed over the adapters.
    pub dedicated_bytes: Option<u64>,
    /// Shared GPU memory in bytes, summed over the adapters.
    pub shared_bytes: Option<u64>,
    /// Total committed GPU memory in bytes, summed over the adapters.
    pub committed_bytes: Option<u64>,
    /// 3D engine utilization percentage; the maximum over the engines.
    pub util_3d: Option<f64>,
    /// Copy engine utilization percentage; the maximum over the engines.
    pub util_copy: Option<f64>,
    /// Video decode engine utilization percentage; the maximum over the
    /// engines.
    pub util_video_decode: Option<f64>,
    /// Video encode engine utilization percentage; the maximum over the
    /// engines.
    pub util_video_encode: Option<f64>,
    /// Compute engine utilization percentage; the maximum over the engines.
    pub util_compute: Option<f64>,
    /// Utilization percentage of every other engine type; the maximum over
    /// the engines.
    pub util_other: Option<f64>,
}

/// Aggregates counter readings by process.
///
/// Memory readings are summed over all instances of a process and rounded to
/// whole bytes. Utilization is the maximum over the engines of one type:
/// `3D`, `Copy`, `VideoDecode` and `VideoEncode` map to their own fields,
/// `Compute_*` maps to compute, and every other type (including an empty one)
/// maps to other. A process without a reading of a metric gets `None` in that
/// field.
pub fn aggregate(
    dedicated: &[(u32, f64)],
    shared: &[(u32, f64)],
    committed: &[(u32, f64)],
    engines: &[(u32, String, f64)],
) -> BTreeMap<u32, GpuTotals> {
    let mut totals: BTreeMap<u32, GpuTotals> = BTreeMap::new();

    for (pid, bytes) in sum_bytes(dedicated) {
        totals.entry(pid).or_default().dedicated_bytes = Some(bytes);
    }
    for (pid, bytes) in sum_bytes(shared) {
        totals.entry(pid).or_default().shared_bytes = Some(bytes);
    }
    for (pid, bytes) in sum_bytes(committed) {
        totals.entry(pid).or_default().committed_bytes = Some(bytes);
    }
    for (pid, engine_type, value) in engines {
        let totals = totals.entry(*pid).or_default();
        keep_max(utilization(totals, engine_type), *value);
    }
    totals
}

/// Sums one kind of memory readings per process and rounds every sum to whole
/// bytes.
fn sum_bytes(readings: &[(u32, f64)]) -> BTreeMap<u32, u64> {
    let mut sums: BTreeMap<u32, f64> = BTreeMap::new();
    for (pid, value) in readings {
        *sums.entry(*pid).or_default() += value;
    }
    sums.into_iter()
        .map(|(pid, sum)| (pid, sum.round() as u64))
        .collect()
}

/// Returns the utilization field of `totals` that belongs to `engine_type`.
fn utilization<'a>(totals: &'a mut GpuTotals, engine_type: &str) -> &'a mut Option<f64> {
    match engine_type {
        "3D" => &mut totals.util_3d,
        "Copy" => &mut totals.util_copy,
        "VideoDecode" => &mut totals.util_video_decode,
        "VideoEncode" => &mut totals.util_video_encode,
        _ if engine_type.starts_with("Compute_") => &mut totals.util_compute,
        _ => &mut totals.util_other,
    }
}

/// Keeps the larger of `slot` and `value` in `slot`.
fn keep_max(slot: &mut Option<f64>, value: f64) {
    if slot.is_none_or(|current| current < value) {
        *slot = Some(value);
    }
}

/// Handles of the counters added to a PDH query.
#[derive(Default)]
struct PdhCounters {
    /// `\GPU Process Memory(*)\Dedicated Usage`.
    dedicated: Option<PDH_HCOUNTER>,
    /// `\GPU Process Memory(*)\Shared Usage`.
    shared: Option<PDH_HCOUNTER>,
    /// `\GPU Process Memory(*)\Total Committed`.
    committed: Option<PDH_HCOUNTER>,
    /// `\GPU Engine(*)\Utilization Percentage`.
    engines: Option<PDH_HCOUNTER>,
}

impl PdhCounters {
    /// Returns whether no counter was added.
    fn is_empty(&self) -> bool {
        self.dedicated.is_none()
            && self.shared.is_none()
            && self.committed.is_none()
            && self.engines.is_none()
    }
}

/// An open PDH query with the GPU counters that could be added to it.
///
/// The query counts its successful collects: rate counters such as engine
/// utilization only produce values after two of them, so the first read after
/// the very first collect is expected to be empty.
struct PdhQuery {
    handle: PDH_HQUERY,
    counters: PdhCounters,
    collects: u32,
}

impl PdhQuery {
    /// Opens a query and adds the GPU counters by their English names.
    ///
    /// Returns `None` when the query cannot be opened or when none of the
    /// counters can be added; the query is closed in both cases.
    fn open() -> Option<PdhQuery> {
        let mut handle = PDH_HQUERY::default();
        // SAFETY: `PCWSTR::null()` selects the local machine, and `handle`
        // points to writable storage for the new query.
        let status = unsafe { PdhOpenQueryW(PCWSTR::null(), 0, &mut handle) };
        if status != 0 {
            return None;
        }

        let counters = PdhCounters {
            dedicated: add_counter(handle, r"\GPU Process Memory(*)\Dedicated Usage"),
            shared: add_counter(handle, r"\GPU Process Memory(*)\Shared Usage"),
            committed: add_counter(handle, r"\GPU Process Memory(*)\Total Committed"),
            engines: add_counter(handle, r"\GPU Engine(*)\Utilization Percentage"),
        };
        let query = PdhQuery {
            handle,
            counters,
            collects: 0,
        };
        if query.counters.is_empty() {
            return None;
        }
        Some(query)
    }

    /// Takes one sample of every counter of the query.
    ///
    /// The first successful collect only primes the rate counters; their
    /// values become readable after the next one.
    fn collect(&mut self) -> anyhow::Result<()> {
        // SAFETY: the handle was returned by `PdhOpenQueryW` and stays valid
        // until this value is dropped.
        let status = unsafe { PdhCollectQueryData(self.handle) };
        if status != 0 {
            return Err(anyhow!(
                "PdhCollectQueryData failed with status 0x{status:08X}"
            ));
        }
        self.collects = self.collects.saturating_add(1);
        Ok(())
    }

    /// Reads the formatted values of one counter with their instance names.
    ///
    /// A counter without instances yields an empty vector. The first read
    /// after the first collect is empty too: a rate counter has no value
    /// until it is primed by a second collect, and its status reports the
    /// data as invalid.
    fn read(&self, counter: PDH_HCOUNTER) -> anyhow::Result<Vec<(String, f64)>> {
        let first_collect = self.collects == 1;
        let mut size = 0u32;
        let mut count = 0u32;
        // SAFETY: a null item buffer asks only for the required byte size and
        // item count; both pointers are writable.
        let status = unsafe {
            PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &mut size, &mut count, None)
        };
        if status == 0 || status_is_empty_read(status, first_collect) {
            return Ok(Vec::new());
        }
        if status != PDH_MORE_DATA {
            return Err(anyhow!(
                "PdhGetFormattedCounterArrayW failed with status 0x{status:08X}"
            ));
        }

        // The item type contains pointers and a double, so an array of `u64`
        // gives it both the required alignment and at least the reported byte
        // size.
        let mut buffer = vec![0u64; (size as usize).div_ceil(size_of::<u64>())];
        let items = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
        // SAFETY: `items` points to `buffer`, which is aligned for
        // `PDH_FMT_COUNTERVALUE_ITEM_W` and has at least the byte size
        // reported by the first call.
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_DOUBLE,
                &mut size,
                &mut count,
                Some(items),
            )
        };
        if status != 0 {
            if status_is_empty_read(status, first_collect) {
                return Ok(Vec::new());
            }
            return Err(anyhow!(
                "PdhGetFormattedCounterArrayW failed with status 0x{status:08X}"
            ));
        }

        // SAFETY: the second call filled `count` items at `items`; every
        // `szName` of those items points into `buffer`, which is still alive.
        let items = unsafe { std::slice::from_raw_parts(items, count as usize) };
        let mut values = Vec::with_capacity(items.len());
        for item in items {
            // SAFETY: `szName` is a NUL-terminated string inside `buffer`.
            let name = unsafe { item.szName.to_string() }
                .map_err(|err| anyhow!("a counter instance name is not valid UTF-16: {err}"))?;
            // SAFETY: `PDH_FMT_DOUBLE` makes the union hold `doubleValue`.
            let value = unsafe { item.FmtValue.Anonymous.doubleValue };
            values.push((name, value));
        }
        Ok(values)
    }
}

impl Drop for PdhQuery {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `PdhOpenQueryW` and is not used
        // after this call.
        unsafe {
            let _ = PdhCloseQuery(self.handle);
        }
    }
}

/// Adds one English-named counter to an open query.
fn add_counter(handle: PDH_HQUERY, path: &str) -> Option<PDH_HCOUNTER> {
    let path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut counter = PDH_HCOUNTER::default();
    // SAFETY: `path` is a valid NUL-terminated UTF-16 counter path, and
    // `counter` points to writable storage for the new counter handle.
    let status =
        unsafe { PdhAddEnglishCounterW(handle, PCWSTR::from_raw(path.as_ptr()), 0, &mut counter) };
    (status == 0).then_some(counter)
}

/// Returns whether a counter status means that no values are available for
/// this read.
///
/// `PDH_CSTATUS_INVALID_DATA` is expected on the first collect: a rate
/// counter needs a second sample before it produces values. After that the
/// same status is a real fault, so only the first collect treats it as empty.
fn status_is_empty_read(status: u32, first_collect: bool) -> bool {
    status == PDH_CSTATUS_NO_INSTANCE
        || status == PDH_NO_DATA
        || (first_collect && status == PDH_CSTATUS_INVALID_DATA)
}

/// Reads a memory counter as `(pid, value)` pairs.
///
/// Instances without a recognizable name are skipped.
fn read_memory(
    query: &PdhQuery,
    counter: Option<PDH_HCOUNTER>,
) -> Result<Vec<(u32, f64)>, CollectError> {
    let Some(counter) = counter else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for (name, value) in query.read(counter).map_err(CollectError::Source)? {
        if let Some(instance) = parse_instance(&name) {
            values.push((instance.pid, value));
        }
    }
    Ok(values)
}

/// Reads the engine counter as `(pid, engine type, value)` triples.
///
/// Instances without a recognizable name or without an engine type are
/// skipped.
fn read_engines(
    query: &PdhQuery,
    counter: Option<PDH_HCOUNTER>,
) -> Result<Vec<(u32, String, f64)>, CollectError> {
    let Some(counter) = counter else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for (name, value) in query.read(counter).map_err(CollectError::Source)? {
        let Some(instance) = parse_instance(&name) else {
            continue;
        };
        let Some(engine_type) = instance.engine_type else {
            continue;
        };
        values.push((instance.pid, engine_type, value));
    }
    Ok(values)
}

/// Samples `gpu.csv` from the GPU performance counters.
///
/// The counters are opened on the first sample. When none of them can be
/// added, the collector reports itself unavailable and writes nothing; a
/// missing counter leaves only its cells empty.
pub struct GpuCollector {
    table: CsvTable,
    log: RunLog,
    every_ticks: u32,
    query: Option<PdhQuery>,
    unavailable: bool,
}

impl GpuCollector {
    /// Creates the collector around an open `gpu.csv` table.
    ///
    /// `every_ticks` is the number of run ticks between two samples.
    pub fn new(table: CsvTable, log: RunLog, every_ticks: u32) -> GpuCollector {
        GpuCollector {
            table,
            log,
            every_ticks,
            query: None,
            unavailable: false,
        }
    }

    /// Returns whether the GPU performance counters are missing on this
    /// machine.
    pub fn unavailable(&self) -> bool {
        self.unavailable
    }
}

impl Collector for GpuCollector {
    fn name(&self) -> &str {
        "gpu"
    }

    fn every_ticks(&self) -> u32 {
        self.every_ticks
    }

    fn sample(&mut self, ctx: &TickCtx) -> Result<(), CollectError> {
        if self.unavailable {
            return Ok(());
        }
        if self.query.is_none() {
            match PdhQuery::open() {
                Some(query) => self.query = Some(query),
                None => {
                    self.unavailable = true;
                    self.log.warn(
                        "gpu",
                        "the GPU performance counters are not available; the GPU collector writes nothing",
                    );
                    return Ok(());
                }
            }
        }
        self.query
            .as_mut()
            .expect("the query is open after the first sample")
            .collect()
            .map_err(CollectError::Source)?;
        let query = self
            .query
            .as_ref()
            .expect("the query is open after the first sample");

        let totals = aggregate(
            &read_memory(query, query.counters.dedicated)?,
            &read_memory(query, query.counters.shared)?,
            &read_memory(query, query.counters.committed)?,
            &read_engines(query, query.counters.engines)?,
        );

        for process in ctx.processes {
            let Some(total) = totals.get(&process.pid) else {
                continue;
            };
            let row = GpuRow {
                t_ms: ctx.t_ms,
                unix_ms: ctx.unix_ms,
                proc_key: process.proc_key.clone(),
                pid: process.pid,
                dedicated_bytes: total.dedicated_bytes,
                shared_bytes: total.shared_bytes,
                committed_bytes: total.committed_bytes,
                util_3d: total.util_3d.map(fmt_pct),
                util_copy: total.util_copy.map(fmt_pct),
                util_video_decode: total.util_video_decode.map(fmt_pct),
                util_video_encode: total.util_video_encode.map(fmt_pct),
                util_compute: total.util_compute.map(fmt_pct),
                util_other: total.util_other.map(fmt_pct),
            };
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
    use super::*;

    #[test]
    fn parse_instance_reads_pid_and_engine_type() {
        assert_eq!(
            parse_instance("pid_1234_luid_0x00000000_0x00000000_phys_0_eng_0_engtype_3D"),
            Some(GpuInstance {
                pid: 1234,
                engine_type: Some("3D".to_string()),
            }),
            "an engine instance must yield its PID and engine type"
        );
        assert_eq!(
            parse_instance("pid_1234_luid_0x00000000_0x00000000_phys_0_eng_0_engtype_Compute_0"),
            Some(GpuInstance {
                pid: 1234,
                engine_type: Some("Compute_0".to_string()),
            }),
            "the whole engine type must be kept after `engtype_`"
        );
        assert_eq!(
            parse_instance("pid_1234_luid_0x00000000_0x00000000_phys_0_eng_0_engtype_VideoDecode"),
            Some(GpuInstance {
                pid: 1234,
                engine_type: Some("VideoDecode".to_string()),
            }),
            "a video engine type must be kept as is"
        );
        assert_eq!(
            parse_instance("pid_1234_luid_0x00000000_0x00000000_phys_0"),
            Some(GpuInstance {
                pid: 1234,
                engine_type: None,
            }),
            "a memory instance must yield its PID and no engine type"
        );
    }

    #[test]
    fn parse_instance_rejects_malformed_names() {
        for name in [
            "luid_0x00000000_0x00000000_phys_0",
            "pid__luid_0x0",
            "pid_x_luid_0x0",
            "",
        ] {
            assert_eq!(parse_instance(name), None, "`{name}` must be rejected");
        }
    }

    #[test]
    fn status_is_empty_read_maps_unavailable_statuses() {
        assert!(
            status_is_empty_read(PDH_CSTATUS_NO_INSTANCE, false),
            "a counter without instances must read as empty"
        );
        assert!(
            status_is_empty_read(PDH_NO_DATA, false),
            "a counter without data must read as empty"
        );
        assert!(
            status_is_empty_read(PDH_CSTATUS_INVALID_DATA, true),
            "an invalid value on the first collect must read as empty"
        );
        assert!(
            !status_is_empty_read(PDH_CSTATUS_INVALID_DATA, false),
            "an invalid value after the first collect must stay an error"
        );
        assert!(
            !status_is_empty_read(PDH_MORE_DATA, true),
            "a larger buffer request must not read as empty"
        );
        assert!(
            !status_is_empty_read(0, true),
            "success must not read as empty"
        );
    }

    #[test]
    fn aggregate_sums_memory_across_adapters() {
        let totals = aggregate(&[(7, 100.4), (7, 200.0), (8, 50.0)], &[(7, 10.0)], &[], &[]);

        let seven = totals.get(&7).expect("PID 7 must be aggregated");
        assert_eq!(
            seven.dedicated_bytes,
            Some(300),
            "dedicated memory must be summed over the adapters of the process"
        );
        assert_eq!(seven.shared_bytes, Some(10));
        assert_eq!(
            seven.committed_bytes, None,
            "a process without a committed reading must stay empty"
        );
        assert_eq!(seven.util_3d, None);
        assert_eq!(seven.util_copy, None);
        assert_eq!(seven.util_video_decode, None);
        assert_eq!(seven.util_video_encode, None);
        assert_eq!(seven.util_compute, None);
        assert_eq!(seven.util_other, None);

        let eight = totals.get(&8).expect("PID 8 must be aggregated");
        assert_eq!(eight.dedicated_bytes, Some(50));
        assert_eq!(eight.shared_bytes, None);
    }

    #[test]
    fn aggregate_takes_max_utilization_per_engine_type() {
        let engines = [
            (7, "3D".to_string(), 10.0),
            (7, "3D".to_string(), 40.0),
            (7, "Copy".to_string(), 5.0),
            (7, "VideoDecode".to_string(), 7.0),
            (7, "VideoEncode".to_string(), 3.0),
            (7, "Compute_0".to_string(), 1.0),
            (7, "Compute_1".to_string(), 2.5),
            (7, "Weird".to_string(), 9.0),
            (7, "Compute".to_string(), 8.0),
        ];
        let totals = aggregate(&[], &[], &[], &engines);
        let seven = totals.get(&7).expect("PID 7 must be aggregated");

        assert_eq!(
            seven.util_3d,
            Some(40.0),
            "3D must take the maximum over its engines"
        );
        assert_eq!(
            seven.util_copy,
            Some(5.0),
            "Copy must take the maximum over its engines"
        );
        assert_eq!(seven.util_video_decode, Some(7.0));
        assert_eq!(seven.util_video_encode, Some(3.0));
        assert_eq!(
            seven.util_compute,
            Some(2.5),
            "Compute_0 and Compute_1 must share util_compute"
        );
        assert_eq!(
            seven.util_other,
            Some(9.0),
            "unknown engine types must share util_other"
        );
    }
}
