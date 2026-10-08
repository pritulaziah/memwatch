//! Run metadata written to `meta.json`.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::mem::size_of;
use std::path::Path;

use serde::{Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ADAPTER_FLAG_SOFTWARE, DXGI_ERROR_NOT_FOUND, IDXGIFactory1,
};
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::core::PCWSTR;

use crate::options::{RunOptions, cdp_env_overrides};
use crate::win;

/// Version of the run directory format.
pub const SCHEMA_VERSION: u32 = 1;

/// Registry key that holds the Windows version.
const WINDOWS_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// Registry key that holds the processor name.
const CPU_KEY: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";

/// Description of one run, written to `meta.json`.
#[derive(Debug, Serialize)]
pub struct Meta {
    /// Version of the run directory format.
    pub schema_version: u32,
    /// Version of the memwatch crate.
    pub memwatch_version: String,
    /// Run name from `--name`.
    pub name: String,
    /// Labels from `--label key=value`.
    pub labels: BTreeMap<String, String>,
    /// Start time as an RFC 3339 string.
    pub started_at: String,
    /// End time as an RFC 3339 string; `None` while the run is going or if
    /// memwatch crashed.
    pub ended_at: Option<String>,
    /// Why the run stopped; `None` while the run is going.
    pub end_reason: Option<EndReason>,
    /// Exit code of the main process; `None` while the run is going.
    pub exit_code: Option<i64>,
    /// The launched command with its arguments.
    pub command: Vec<String>,
    /// Working directory of the run.
    pub cwd: String,
    /// Environment variables set by memwatch itself.
    pub env_overrides: BTreeMap<String, String>,
    /// Sampling interval in milliseconds per collector.
    pub intervals_ms: BTreeMap<String, u64>,
    /// The machine the run was made on.
    pub host: Host,
    /// Executables that appeared in the process tree.
    pub images: Vec<ImageInfo>,
    /// Final status of every collector.
    pub collectors: BTreeMap<String, CollectorStatus>,
    /// Whether the process collector switched to walking the tree by parent
    /// PID.
    pub tree_walk_fallback: bool,
}

impl Meta {
    /// Builds the metadata of a run that is about to start.
    ///
    /// The end fields stay `None`; the process, job, system and gpu collectors
    /// start as `ok`, while the DevTools collector starts as `waiting` with a
    /// port and as `disabled` without one. `env_overrides` holds only the
    /// browser arguments that open the DevTools port and is empty when no port
    /// is given.
    pub fn new(opts: &RunOptions, started: OffsetDateTime, host: Host) -> Meta {
        let interval_ms = opts.interval.as_millis() as u64;

        let mut intervals_ms = BTreeMap::new();
        intervals_ms.insert("process".to_string(), interval_ms);
        intervals_ms.insert("job".to_string(), interval_ms);
        intervals_ms.insert("system".to_string(), interval_ms);
        intervals_ms.insert("gpu".to_string(), opts.gpu_interval.as_millis() as u64);
        intervals_ms.insert("cdp".to_string(), opts.cdp_interval.as_millis() as u64);

        let mut collectors = BTreeMap::new();
        collectors.insert("process".to_string(), CollectorStatus::Ok);
        collectors.insert("job".to_string(), CollectorStatus::Ok);
        collectors.insert("system".to_string(), CollectorStatus::Ok);
        collectors.insert("gpu".to_string(), CollectorStatus::Ok);
        collectors.insert(
            "cdp".to_string(),
            if opts.cdp_port.is_some() {
                CollectorStatus::Waiting
            } else {
                CollectorStatus::Disabled
            },
        );

        Meta {
            schema_version: SCHEMA_VERSION,
            memwatch_version: env!("CARGO_PKG_VERSION").to_string(),
            name: opts.name.clone(),
            labels: opts.labels.clone(),
            started_at: started
                .format(&Rfc3339)
                .expect("the fixed RFC 3339 format is valid for any date-time"),
            ended_at: None,
            end_reason: None,
            exit_code: None,
            command: opts
                .command
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect(),
            cwd: std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            env_overrides: cdp_env_overrides(opts.cdp_port),
            intervals_ms,
            host,
            images: Vec::new(),
            collectors,
            tree_walk_fallback: false,
        }
    }

    /// Writes `meta.json` atomically: a temporary file is synced and renamed
    /// over the destination.
    pub fn write_atomic(&self, run_dir: &Path) -> io::Result<()> {
        let tmp_path = run_dir.join("meta.json.tmp");
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;

        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(&json)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp_path, run_dir.join("meta.json"))
    }
}

/// Why the run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The main process exited on its own.
    AppExited,
    /// The user pressed Ctrl+C.
    CtrlC,
    /// The command could not be launched.
    LaunchFailed,
    /// memwatch stopped because of its own error.
    MemwatchError,
}

/// State of one collector, written to `meta.json` as a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorStatus {
    /// The collector works.
    Ok,
    /// The collector is switched off by a flag.
    Disabled,
    /// The data source is missing on this machine.
    Unavailable,
    /// The source is not ready yet.
    Waiting,
    /// The collector stopped after repeated errors.
    Failed(String),
}

impl Serialize for CollectorStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = match self {
            CollectorStatus::Ok => "ok".to_string(),
            CollectorStatus::Disabled => "disabled".to_string(),
            CollectorStatus::Unavailable => "unavailable".to_string(),
            CollectorStatus::Waiting => "waiting".to_string(),
            CollectorStatus::Failed(reason) => format!("failed: {reason}"),
        };
        serializer.serialize_str(&value)
    }
}

/// An executable that appeared in the process tree.
#[derive(Debug, Clone, Serialize)]
pub struct ImageInfo {
    /// Full path of the executable.
    pub path: String,
    /// `FileVersion` of the executable; `None` when the resource has none.
    pub version: Option<String>,
}

/// The machine the run was made on.
#[derive(Debug, Clone, Serialize)]
pub struct Host {
    /// Operating system name, version and build.
    pub os: String,
    /// Processor name.
    pub cpu: String,
    /// Number of logical processors.
    pub logical_cpus: u32,
    /// Physical memory in bytes.
    pub ram_bytes: u64,
    /// Names of the graphics adapters.
    pub gpus: Vec<String>,
}

/// Formats the operating system description from the registry values.
///
/// Windows 10 and 11 share the major build number, so the registry keeps
/// reporting `Windows 10`; a build of 22000 or later is corrected to
/// `Windows 11`. The version is `display_version`, then `release_id`, then
/// omitted.
pub fn os_name(
    product: &str,
    display_version: Option<&str>,
    release_id: Option<&str>,
    build: u32,
    ubr: u32,
) -> String {
    let product = if build >= 22_000 {
        product.replace("Windows 10", "Windows 11")
    } else {
        product.to_string()
    };
    match display_version.or(release_id) {
        Some(version) => format!("{product} {version} (build {build}.{ubr})"),
        None => format!("{product} (build {build}.{ubr})"),
    }
}

/// Reads the machine description from the registry, Win32 and DXGI.
///
/// Every piece is best-effort: an unreadable value becomes an empty string,
/// a zero counter or an empty list, so a run can still start.
pub fn host_info() -> Host {
    let product = reg_string(WINDOWS_VERSION_KEY, "ProductName");
    let build = reg_string(WINDOWS_VERSION_KEY, "CurrentBuildNumber")
        .and_then(|value| value.parse::<u32>().ok());
    let os = match (product.as_deref(), build) {
        (Some(product), Some(build)) => {
            let display_version = reg_string(WINDOWS_VERSION_KEY, "DisplayVersion");
            let release_id = reg_string(WINDOWS_VERSION_KEY, "ReleaseId");
            os_name(
                product,
                display_version.as_deref(),
                release_id.as_deref(),
                build,
                reg_dword(WINDOWS_VERSION_KEY, "UBR").unwrap_or(0),
            )
        }
        _ => String::new(),
    };

    Host {
        os,
        cpu: reg_string(CPU_KEY, "ProcessorNameString").unwrap_or_default(),
        logical_cpus: win::logical_cpus(),
        ram_bytes: total_ram_bytes(),
        gpus: gpu_names(),
    }
}

/// Encodes a string as NUL-terminated UTF-16 for the registry APIs.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads a `REG_SZ` value from `HKLM\<subkey>`.
///
/// Returns `None` when the value is missing, has another type or cannot be
/// read.
fn reg_string(subkey: &str, value: &str) -> Option<String> {
    let subkey = wide(subkey);
    let value = wide(value);
    let subkey = PCWSTR::from_raw(subkey.as_ptr());
    let value = PCWSTR::from_raw(value.as_ptr());

    let mut size = 0u32;
    // SAFETY: both names are valid NUL-terminated UTF-16 strings; a null data
    // buffer asks only for the required size.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey,
            value,
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    if status.is_err() || size < 2 {
        return None;
    }

    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    // SAFETY: `buffer` is writable for `size` bytes as requested by the
    // previous call, and `size` points to writable storage.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey,
            value,
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status.is_err() {
        return None;
    }

    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..end]))
}

/// Reads a `REG_DWORD` value from `HKLM\<subkey>`.
///
/// Returns `None` when the value is missing, has another type or cannot be
/// read.
fn reg_dword(subkey: &str, value: &str) -> Option<u32> {
    let subkey = wide(subkey);
    let value = wide(value);

    let mut data = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: `data` is writable for the declared size, and both names are
    // valid NUL-terminated UTF-16 strings.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey.as_ptr()),
            PCWSTR::from_raw(value.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut data as *mut u32).cast()),
            Some(&mut size),
        )
    };
    status.is_ok().then_some(data)
}

/// Reads the total physical memory via `GlobalMemoryStatusEx`.
///
/// Returns `0` when the call fails.
fn total_ram_bytes() -> u64 {
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..MEMORYSTATUSEX::default()
    };
    // SAFETY: `status` declares its own size and is writable.
    if unsafe { GlobalMemoryStatusEx(&mut status) }.is_err() {
        return 0;
    }
    status.ullTotalPhys
}

/// Lists the names of the hardware graphics adapters via DXGI.
///
/// Software adapters (for example the Basic Render Driver) are skipped; an
/// error while creating the factory or enumerating adapters yields an empty
/// list.
fn gpu_names() -> Vec<String> {
    // SAFETY: factory creation has no preconditions, and the returned
    // interface is released when dropped.
    let Ok(factory) = (unsafe { CreateDXGIFactory1::<IDXGIFactory1>() }) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    let mut index = 0;
    loop {
        // SAFETY: `factory` is a valid `IDXGIFactory1`; the index starts at 0
        // and grows until the enumeration reports `DXGI_ERROR_NOT_FOUND`.
        match unsafe { factory.EnumAdapters1(index) } {
            Ok(adapter) => {
                // SAFETY: `adapter` is a valid `IDXGIAdapter1`.
                if let Ok(desc) = unsafe { adapter.GetDesc1() }
                    && desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32 == 0
                {
                    let end = desc
                        .Description
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(desc.Description.len());
                    names.push(String::from_utf16_lossy(&desc.Description[..end]));
                }
                index += 1;
            }
            Err(err) if err.code() == DXGI_ERROR_NOT_FOUND => break,
            Err(_) => return Vec::new(),
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use tempfile::TempDir;
    use time::macros::datetime;

    fn sample_options() -> RunOptions {
        let mut labels = BTreeMap::new();
        labels.insert("branch".to_string(), "wry".to_string());
        RunOptions {
            name: "wry".to_string(),
            out_dir: PathBuf::from("runs"),
            labels,
            interval: Duration::from_secs(1),
            gpu_interval: Duration::from_secs(2),
            cdp_interval: Duration::from_secs(10),
            cdp_port: None,
            allow_sleep: false,
            command: vec![OsString::from("app.exe"), OsString::from("--no-devtools")],
        }
    }

    fn sample_started() -> OffsetDateTime {
        datetime!(2026-10-07 16:05:09 UTC)
    }

    fn sample_host() -> Host {
        Host {
            os: "Windows 11 Pro 23H2 (build 22631.4317)".to_string(),
            cpu: "Test CPU".to_string(),
            logical_cpus: 8,
            ram_bytes: 16_000_000_000,
            gpus: vec!["Test GPU".to_string()],
        }
    }

    #[test]
    fn meta_serializes_pinned_field_names() {
        let mut meta = Meta::new(&sample_options(), sample_started(), sample_host());
        meta.images.push(ImageInfo {
            path: r"C:\app\main.exe".to_string(),
            version: Some("1.2.3.4".to_string()),
        });

        let value = serde_json::to_value(&meta).expect("the metadata must serialize");
        let object = value.as_object().expect("the metadata must be an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "collectors",
                "command",
                "cwd",
                "end_reason",
                "ended_at",
                "env_overrides",
                "exit_code",
                "host",
                "images",
                "intervals_ms",
                "labels",
                "memwatch_version",
                "name",
                "schema_version",
                "started_at",
                "tree_walk_fallback",
            ]
        );

        assert_eq!(object["schema_version"], SCHEMA_VERSION);
        assert_eq!(object["memwatch_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(object["name"], "wry");
        assert_eq!(object["labels"]["branch"], "wry");
        assert_eq!(object["started_at"], "2026-10-07T16:05:09Z");
        assert!(object["ended_at"].is_null(), "ended_at must start as null");
        assert!(
            object["end_reason"].is_null(),
            "end_reason must start as null"
        );
        assert!(
            object["exit_code"].is_null(),
            "exit_code must start as null"
        );
        assert_eq!(
            object["command"],
            serde_json::json!(["app.exe", "--no-devtools"])
        );
        assert!(object["cwd"].is_string(), "cwd must be a string");
        assert_eq!(
            object["env_overrides"],
            serde_json::json!({}),
            "env_overrides must start empty"
        );

        let intervals = object["intervals_ms"]
            .as_object()
            .expect("intervals_ms must be an object");
        for name in ["process", "job", "system"] {
            let interval = intervals
                .get(name)
                .expect("every collector must have an interval");
            assert_eq!(
                interval.as_u64(),
                Some(1000),
                "{name} must tick every second"
            );
        }
        assert_eq!(
            intervals.get("gpu").and_then(serde_json::Value::as_u64),
            Some(2000),
            "gpu must tick every two seconds"
        );
        assert_eq!(
            intervals.get("cdp").and_then(serde_json::Value::as_u64),
            Some(10000),
            "cdp must tick every ten seconds"
        );

        let host = object["host"].as_object().expect("host must be an object");
        let mut host_keys: Vec<&str> = host.keys().map(String::as_str).collect();
        host_keys.sort_unstable();
        assert_eq!(
            host_keys,
            ["cpu", "gpus", "logical_cpus", "os", "ram_bytes"]
        );

        assert_eq!(object["images"][0]["path"], r"C:\app\main.exe");
        assert_eq!(object["images"][0]["version"], "1.2.3.4");

        let collectors = object["collectors"]
            .as_object()
            .expect("collectors must be an object");
        for name in ["process", "job", "system"] {
            let status = collectors
                .get(name)
                .expect("every collector must have a status");
            assert_eq!(status, "ok", "{name} must start as ok");
        }
        assert_eq!(
            collectors.get("gpu"),
            Some(&serde_json::json!("ok")),
            "gpu must start as ok"
        );
        assert_eq!(
            collectors.get("cdp"),
            Some(&serde_json::json!("disabled")),
            "cdp must start as disabled without a port"
        );
        assert_eq!(object["tree_walk_fallback"], false);
    }

    #[test]
    fn meta_marks_cdp_waiting_with_a_port() {
        let mut opts = sample_options();
        opts.cdp_port = Some(9222);
        let meta = Meta::new(&opts, sample_started(), sample_host());

        let value = serde_json::to_value(&meta).expect("the metadata must serialize");
        let object = value.as_object().expect("the metadata must be an object");

        assert_eq!(
            object["collectors"]["cdp"], "waiting",
            "cdp must wait for the DevTools port to come up"
        );
        assert_eq!(
            object["env_overrides"],
            serde_json::json!({
                "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": "--remote-debugging-port=9222"
            }),
            "the browser arguments must open the given port"
        );
        assert_eq!(
            object["intervals_ms"]["cdp"].as_u64(),
            Some(10000),
            "cdp must tick every ten seconds"
        );
    }

    #[test]
    fn end_reason_serializes_snake_case() {
        let cases = [
            (EndReason::AppExited, "\"app_exited\""),
            (EndReason::CtrlC, "\"ctrl_c\""),
            (EndReason::LaunchFailed, "\"launch_failed\""),
            (EndReason::MemwatchError, "\"memwatch_error\""),
        ];
        for (reason, expected) in cases {
            assert_eq!(
                serde_json::to_string(&reason).expect("the reason must serialize"),
                expected
            );
        }
    }

    #[test]
    fn collector_status_serializes_as_string() {
        let cases = [
            (CollectorStatus::Ok, "\"ok\""),
            (CollectorStatus::Disabled, "\"disabled\""),
            (CollectorStatus::Unavailable, "\"unavailable\""),
            (CollectorStatus::Waiting, "\"waiting\""),
            (CollectorStatus::Failed("x".to_string()), "\"failed: x\""),
        ];
        for (status, expected) in cases {
            assert_eq!(
                serde_json::to_string(&status).expect("the status must serialize"),
                expected
            );
        }
    }

    #[test]
    fn write_atomic_replaces_and_leaves_no_tmp() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let mut first = Meta::new(&sample_options(), sample_started(), sample_host());
        first.exit_code = Some(1);
        first
            .write_atomic(dir.path())
            .expect("the first write must succeed");

        let mut second = Meta::new(&sample_options(), sample_started(), sample_host());
        second.exit_code = Some(42);
        second
            .write_atomic(dir.path())
            .expect("the second write must succeed");

        let mut names: Vec<String> = fs::read_dir(dir.path())
            .expect("the run directory must be readable")
            .map(|entry| {
                entry
                    .expect("the entry must be readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(names, ["meta.json"], "only meta.json must remain");

        let content =
            fs::read_to_string(dir.path().join("meta.json")).expect("meta.json must be readable");
        let value: serde_json::Value =
            serde_json::from_str(&content).expect("meta.json must be valid JSON");
        assert_eq!(value["exit_code"], 42, "the second write must win");
    }

    #[test]
    fn os_name_corrects_windows_11() {
        assert_eq!(
            os_name("Windows 10 Pro", Some("23H2"), None, 22631, 4317),
            "Windows 11 Pro 23H2 (build 22631.4317)"
        );
        assert_eq!(
            os_name("Windows 10 Pro", None, Some("2004"), 19041, 1),
            "Windows 10 Pro 2004 (build 19041.1)"
        );
    }

    #[test]
    fn host_info_reports_machine() {
        let host = host_info();
        assert!(host.logical_cpus > 0, "logical CPUs must be positive");
        assert!(host.ram_bytes > 0, "RAM must be positive");
        assert!(!host.os.is_empty(), "the OS name must not be empty");
        assert!(!host.cpu.is_empty(), "the CPU name must not be empty");
    }
}
