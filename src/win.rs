//! Thin wrappers over the Win32 process APIs used by the collectors.
//!
//! This module is the only place in the crate that calls raw Win32 process
//! functions. Every wrapper is safe: failures become `anyhow::Error` or a
//! `None` in a single [`ProcessMetrics`] field, so an unavailable counter or
//! a missing permission never fails a whole sample.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use anyhow::anyhow;
use windows::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation,
};
use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED,
    ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_NOT_FOUND, FILETIME, GetLastError, HANDLE,
    SetLastError, UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FFI_SIGNATURE, VS_FIXEDFILEINFO,
    VerQueryValueW,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
    PROCESS_MEMORY_COUNTERS_EX2,
};
use windows::Win32::System::Threading::{
    ALL_PROCESSOR_GROUPS, GET_GUI_RESOURCES_FLAGS, GR_GDIOBJECTS, GR_GDIOBJECTS_PEAK,
    GR_USEROBJECTS, GR_USEROBJECTS_PEAK, GetActiveProcessorCount, GetCurrentProcess,
    GetExitCodeProcess, GetGuiResources, GetProcessHandleCount, GetProcessIoCounters,
    GetProcessTimes, IO_COUNTERS, OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    WaitForSingleObject,
};
use windows::Win32::System::WindowsProgramming::QueryProcessCycleTime;
use windows::core::{HRESULT, PCWSTR, PWSTR};

/// An owned Win32 handle that is closed with `CloseHandle` when dropped.
///
/// The pinned `windows` crate version no longer ships an owned-handle type,
/// so this wrapper provides one with the usual behavior: [`try_clone`]
/// duplicates the handle, and `Drop` skips closing the invalid
/// `GetCurrentProcess` pseudo-handle.
///
/// [`try_clone`]: OwnedHandle::try_clone
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Takes ownership of a raw handle.
    ///
    /// # Safety
    ///
    /// `handle` must be owned by the caller and may be closed with
    /// `CloseHandle`, or it must be the `GetCurrentProcess` pseudo-handle.
    pub unsafe fn new(handle: HANDLE) -> OwnedHandle {
        OwnedHandle(handle)
    }

    /// Duplicates the handle with the same access rights.
    pub fn try_clone(&self) -> anyhow::Result<OwnedHandle> {
        let mut duplicate = HANDLE::default();
        // SAFETY: both pseudo-handles of the current process are valid, and
        // `duplicate` points to writable storage for the new handle.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.0,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )?;
        }
        Ok(OwnedHandle(duplicate))
    }

    /// Returns the raw handle.
    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle is owned by this value and not yet closed.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// An open process handle with the access rights used by the collectors.
pub struct ProcHandle(OwnedHandle);

impl ProcHandle {
    /// Opens `pid` with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE`.
    ///
    /// Returns `Ok(None)` when the process is gone (the PID no longer maps to
    /// a process) and an error when the process exists but cannot be opened.
    pub fn open(pid: u32) -> anyhow::Result<Option<ProcHandle>> {
        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
        // SAFETY: `access` only requests query and synchronization rights, and
        // the returned handle is owned by this process.
        match unsafe { OpenProcess(access, false, pid) } {
            Ok(handle) => Ok(Some(ProcHandle(unsafe { OwnedHandle::new(handle) }))),
            Err(err) => {
                let code = err.code();
                if code == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0)
                    || code == HRESULT::from_win32(ERROR_NOT_FOUND.0)
                {
                    Ok(None)
                } else {
                    Err(err.into())
                }
            }
        }
    }

    /// Returns a handle of the current process.
    ///
    /// The `GetCurrentProcess` pseudo-handle is always valid and is never
    /// closed, so this call cannot fail.
    pub fn current() -> ProcHandle {
        // SAFETY: the current-process pseudo-handle is always valid and is
        // skipped by `OwnedHandle::drop`.
        ProcHandle(unsafe { OwnedHandle::new(GetCurrentProcess()) })
    }

    /// Wraps an already opened handle.
    pub fn from_owned(handle: OwnedHandle) -> ProcHandle {
        ProcHandle(handle)
    }

    /// Returns the raw handle for calls that need it.
    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }

    /// Duplicates the handle so it can be stored independently.
    pub fn try_clone(&self) -> anyhow::Result<ProcHandle> {
        Ok(ProcHandle(self.0.try_clone()?))
    }

    /// Returns the process creation time as a `FILETIME` value in `u64`.
    pub fn creation_time(&self) -> anyhow::Result<u64> {
        let (creation, _, _, _) = process_times(self.raw())?;
        Ok(creation)
    }

    /// Returns the parent PID from `NtQueryInformationProcess`.
    pub fn parent_pid(&self) -> anyhow::Result<u32> {
        let mut info = PROCESS_BASIC_INFORMATION::default();
        // SAFETY: `info` is a valid `PROCESS_BASIC_INFORMATION` buffer of the
        // declared size, and the handle grants query access.
        let status = unsafe {
            NtQueryInformationProcess(
                self.raw(),
                ProcessBasicInformation,
                (&mut info as *mut PROCESS_BASIC_INFORMATION).cast(),
                size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        status.ok()?;
        Ok(info.InheritedFromUniqueProcessId as u32)
    }

    /// Returns the exit code once the process has exited.
    ///
    /// Returns `None` while the process is still running.
    pub fn exit_code(&self) -> anyhow::Result<Option<u32>> {
        // SAFETY: the handle grants synchronization access and is valid.
        match unsafe { WaitForSingleObject(self.raw(), 0) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: `code` points to writable storage for the exit code.
                unsafe { GetExitCodeProcess(self.raw(), &mut code)? };
                Ok(Some(code))
            }
            WAIT_TIMEOUT => Ok(None),
            other => Err(anyhow!("WaitForSingleObject failed: {other:?}")),
        }
    }

    /// Returns the full path of the executable.
    pub fn image_path(&self) -> anyhow::Result<String> {
        let mut buffer = vec![0u16; 32_768];
        let mut size = buffer.len() as u32;
        // SAFETY: `buffer` is writable for `size` UTF-16 code units, and
        // `size` points to writable storage for the resulting length.
        unsafe {
            QueryFullProcessImageNameW(
                self.raw(),
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )?;
        }
        Ok(String::from_utf16_lossy(&buffer[..size as usize]))
    }

    /// Returns the command line of the process.
    pub fn command_line(&self) -> anyhow::Result<String> {
        let mut size = 0u32;
        // SAFETY: the first call only asks for the required buffer size.
        let probe = unsafe {
            NtQueryInformationProcess(
                self.raw(),
                ProcessCommandLineInformation,
                std::ptr::null_mut(),
                0,
                &mut size,
            )
        };
        if size == 0 {
            return Err(anyhow!("the command line size is unknown ({probe:?})"));
        }

        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` is writable for `size` bytes, and `size` points to
        // writable storage for the resulting length.
        let status = unsafe {
            NtQueryInformationProcess(
                self.raw(),
                ProcessCommandLineInformation,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        };
        status.ok()?;

        // SAFETY: the kernel filled `buffer` with a `UNICODE_STRING` followed
        // by the string data it points into; the buffer may be unaligned.
        let unicode = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<UNICODE_STRING>()) };
        if unicode.Buffer.0.is_null() {
            return Ok(String::new());
        }
        // SAFETY: `Buffer` points to `Length / 2` UTF-16 code units inside
        // `buffer`, which is still alive.
        let chars =
            unsafe { std::slice::from_raw_parts(unicode.Buffer.0, unicode.Length as usize / 2) };
        Ok(String::from_utf16_lossy(chars))
    }

    /// Reads every metric independently.
    ///
    /// A metric that cannot be read is `None` while the other metrics are
    /// still filled.
    pub fn metrics(&self) -> ProcessMetrics {
        let mut metrics = ProcessMetrics::default();
        self.fill_memory(&mut metrics);
        self.fill_times(&mut metrics);
        metrics.cpu_cycles = self.cpu_cycles();
        self.fill_io(&mut metrics);
        metrics.handles = self.handle_count();
        self.fill_gui(&mut metrics);
        metrics
    }

    fn fill_memory(&self, metrics: &mut ProcessMetrics) {
        let mut ex2 = PROCESS_MEMORY_COUNTERS_EX2 {
            cb: size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32,
            ..PROCESS_MEMORY_COUNTERS_EX2::default()
        };
        // SAFETY: the buffer has the size declared in `cb`, and the wider
        // structure is accepted by `GetProcessMemoryInfo` when supported.
        let ex2_ok = unsafe {
            GetProcessMemoryInfo(
                self.raw(),
                (&mut ex2 as *mut PROCESS_MEMORY_COUNTERS_EX2).cast::<PROCESS_MEMORY_COUNTERS>(),
                ex2.cb,
            )
            .is_ok()
        };
        if ex2_ok {
            metrics.private_bytes = Some(ex2.PrivateUsage as u64);
            metrics.working_set = Some(ex2.WorkingSetSize as u64);
            metrics.private_working_set = Some(ex2.PrivateWorkingSetSize as u64);
            metrics.peak_working_set = Some(ex2.PeakWorkingSetSize as u64);
            metrics.peak_private_bytes = Some(ex2.PeakPagefileUsage as u64);
            metrics.page_faults = Some(ex2.PageFaultCount as u64);
            return;
        }

        let mut ex = PROCESS_MEMORY_COUNTERS_EX {
            cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..PROCESS_MEMORY_COUNTERS_EX::default()
        };
        // SAFETY: same as above; `private_working_set` stays empty because the
        // narrower structure does not carry it.
        let ex_ok = unsafe {
            GetProcessMemoryInfo(
                self.raw(),
                (&mut ex as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
                ex.cb,
            )
            .is_ok()
        };
        if ex_ok {
            metrics.private_bytes = Some(ex.PrivateUsage as u64);
            metrics.working_set = Some(ex.WorkingSetSize as u64);
            metrics.peak_working_set = Some(ex.PeakWorkingSetSize as u64);
            metrics.peak_private_bytes = Some(ex.PeakPagefileUsage as u64);
            metrics.page_faults = Some(ex.PageFaultCount as u64);
        }
    }

    fn fill_times(&self, metrics: &mut ProcessMetrics) {
        let Ok((_creation, _exit, kernel, user)) = process_times(self.raw()) else {
            return;
        };
        metrics.cpu_user_ms = Some(user / 10_000);
        metrics.cpu_kernel_ms = Some(kernel / 10_000);
        metrics.cpu_100ns = Some(user + kernel);
    }

    fn cpu_cycles(&self) -> Option<u64> {
        let mut cycles = 0u64;
        // SAFETY: `cycles` points to writable storage for the counter.
        unsafe { QueryProcessCycleTime(self.raw(), &mut cycles) }.ok()?;
        Some(cycles)
    }

    fn fill_io(&self, metrics: &mut ProcessMetrics) {
        let mut counters = IO_COUNTERS::default();
        // SAFETY: `counters` points to writable storage for the counters.
        if unsafe { GetProcessIoCounters(self.raw(), &mut counters) }.is_err() {
            return;
        }
        metrics.io_read_bytes = Some(counters.ReadTransferCount);
        metrics.io_write_bytes = Some(counters.WriteTransferCount);
        metrics.io_other_bytes = Some(counters.OtherTransferCount);
        metrics.io_read_ops = Some(counters.ReadOperationCount);
        metrics.io_write_ops = Some(counters.WriteOperationCount);
        metrics.io_other_ops = Some(counters.OtherOperationCount);
    }

    fn handle_count(&self) -> Option<u64> {
        let mut count = 0u32;
        // SAFETY: `count` points to writable storage for the counter.
        unsafe { GetProcessHandleCount(self.raw(), &mut count) }.ok()?;
        Some(count as u64)
    }

    fn fill_gui(&self, metrics: &mut ProcessMetrics) {
        metrics.gdi = gui_resource(self.raw(), GR_GDIOBJECTS);
        metrics.gdi_peak = gui_resource(self.raw(), GR_GDIOBJECTS_PEAK);
        metrics.user = gui_resource(self.raw(), GR_USEROBJECTS);
        metrics.user_peak = gui_resource(self.raw(), GR_USEROBJECTS_PEAK);
    }
}

/// Process counters read at one moment.
///
/// Every field is independent: `None` means the counter is unavailable, while
/// `Some(0)` is a real zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessMetrics {
    /// Private commit in bytes.
    pub private_bytes: Option<u64>,
    /// Working set in bytes.
    pub working_set: Option<u64>,
    /// Private working set in bytes.
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
    /// User plus kernel CPU time in 100 ns units (cumulative); not written to
    /// the CSV and used only for [`cpu_pct`].
    pub cpu_100ns: Option<u64>,
    /// CPU cycles (cumulative).
    pub cpu_cycles: Option<u64>,
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
}

/// One process as listed by a Toolhelp32 snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Number of running threads.
    pub threads: u32,
    /// Executable file name without the path.
    pub exe_name: String,
}

/// Takes a Toolhelp32 snapshot of all processes on the machine.
pub fn snapshot() -> anyhow::Result<Vec<SnapshotEntry>> {
    // SAFETY: the snapshot handle is owned by this process and closed by
    // `OwnedHandle`.
    let snapshot = unsafe { OwnedHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?) };

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    // SAFETY: `entry` has the size declared in `dwSize` and is writable.
    match unsafe { Process32FirstW(snapshot.raw(), &mut entry) } {
        Ok(()) => {}
        Err(err) if err.code() == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) => {
            return Ok(Vec::new());
        }
        Err(err) => return Err(err.into()),
    }

    let mut entries = Vec::new();
    loop {
        entries.push(SnapshotEntry {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            threads: entry.cntThreads,
            exe_name: exe_name(&entry.szExeFile),
        });
        // SAFETY: same as `Process32FirstW`; `entry` is reused for each call.
        match unsafe { Process32NextW(snapshot.raw(), &mut entry) } {
            Ok(()) => {}
            Err(err) if err.code() == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(entries)
}

/// Returns `true` when the error is `ERROR_ACCESS_DENIED`.
pub fn is_access_denied(err: &anyhow::Error) -> bool {
    err.downcast_ref::<windows::core::Error>()
        .is_some_and(|err| err.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0))
}

/// Reads the numeric `FileVersion` from the version resource of `path`.
///
/// Returns `None` when the file has no version resource. The result has the
/// form `a.b.c.d` from `dwFileVersionMS` and `dwFileVersionLS`.
pub fn file_version(path: &Path) -> Option<String> {
    let mut file_name: Vec<u16> = path.as_os_str().encode_wide().collect();
    file_name.push(0);
    let file_name = PCWSTR::from_raw(file_name.as_ptr());

    // SAFETY: `file_name` is a valid NUL-terminated path, and all buffers are
    // sized according to the values returned by the version APIs.
    unsafe {
        let size = GetFileVersionInfoSizeW(file_name, None);
        if size == 0 {
            return None;
        }
        let mut block = vec![0u8; size as usize];
        GetFileVersionInfoW(file_name, None, size, block.as_mut_ptr().cast()).ok()?;

        let mut value: *mut c_void = std::ptr::null_mut();
        let mut value_len = 0u32;
        let subblock: Vec<u16> = "\\".encode_utf16().chain(std::iter::once(0)).collect();
        let found = VerQueryValueW(
            block.as_ptr().cast(),
            PCWSTR::from_raw(subblock.as_ptr()),
            &mut value,
            &mut value_len,
        );
        if !found.as_bool()
            || value.is_null()
            || (value_len as usize) < size_of::<VS_FIXEDFILEINFO>()
        {
            return None;
        }

        let info = &*value.cast::<VS_FIXEDFILEINFO>();
        if info.dwSignature != VS_FFI_SIGNATURE as u32 {
            return None;
        }
        let ms = info.dwFileVersionMS;
        let ls = info.dwFileVersionLS;
        Some(format!(
            "{}.{}.{}.{}",
            ms >> 16,
            ms & 0xFFFF,
            ls >> 16,
            ls & 0xFFFF
        ))
    }
}

/// Returns the number of logical processors across all processor groups.
pub fn logical_cpus() -> u32 {
    // SAFETY: the call has no arguments that could be invalid.
    unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) }
}

/// Computes whole-machine CPU usage from cumulative 100 ns counters:
/// `Δ(user + kernel) / (Δwall × logical_cpus) × 100`.
///
/// Returns `0.0` when no wall time has passed.
pub fn cpu_pct(prev_100ns: u64, cur_100ns: u64, wall: Duration, logical_cpus: u32) -> f64 {
    if wall.is_zero() || logical_cpus == 0 {
        return 0.0;
    }
    let delta = cur_100ns.saturating_sub(prev_100ns) as f64;
    let wall_100ns = wall.as_nanos() as f64 / 100.0;
    delta / (wall_100ns * logical_cpus as f64) * 100.0
}

fn process_times(handle: HANDLE) -> anyhow::Result<(u64, u64, u64, u64)> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all four pointers point to writable `FILETIME` storage.
    unsafe {
        GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)?;
    }
    Ok((
        filetime_to_u64(creation),
        filetime_to_u64(exit),
        filetime_to_u64(kernel),
        filetime_to_u64(user),
    ))
}

fn filetime_to_u64(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

fn gui_resource(handle: HANDLE, flag: GET_GUI_RESOURCES_FLAGS) -> Option<u64> {
    // SAFETY: the handle grants query access; `SetLastError`/`GetLastError`
    // distinguish a real zero from a failed call.
    unsafe {
        SetLastError(WIN32_ERROR(0));
        let count = GetGuiResources(handle, flag);
        if count == 0 && GetLastError() != WIN32_ERROR(0) {
            None
        } else {
            Some(count as u64)
        }
    }
}

fn exe_name(name: &[u16; 260]) -> String {
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    String::from_utf16_lossy(&name[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::Path;
    use std::time::Duration;

    use windows::Win32::Foundation::COLORREF;
    use windows::Win32::Graphics::Gdi::{CreateSolidBrush, DeleteObject, HGDIOBJ};

    #[test]
    fn read_metrics_of_self() {
        let handle = ProcHandle::current();
        let first = handle.metrics();
        assert!(
            first.private_bytes.expect("private bytes must be readable") > 0,
            "private bytes must be positive"
        );
        assert!(
            first.working_set.expect("working set must be readable") > 0,
            "working set must be positive"
        );
        assert!(
            first.handles.expect("handles must be readable") > 0,
            "handle count must be positive"
        );

        let first_cpu = first.cpu_user_ms.expect("user time must be readable")
            + first.cpu_kernel_ms.expect("kernel time must be readable");
        let second = handle.metrics();
        let second_cpu = second.cpu_user_ms.expect("user time must be readable")
            + second.cpu_kernel_ms.expect("kernel time must be readable");
        assert!(second_cpu >= first_cpu, "CPU time must not decrease");
    }

    #[test]
    fn gdi_count_grows_after_brush() {
        let handle = ProcHandle::current();
        let before = handle.metrics().gdi.expect("GDI objects must be readable");
        let brush = unsafe { CreateSolidBrush(COLORREF(0)) };
        assert!(!brush.is_invalid(), "the brush must be created");
        let after = handle.metrics().gdi.expect("GDI objects must be readable");
        unsafe {
            let _ = DeleteObject(HGDIOBJ(brush.0));
        }
        assert!(
            after > before,
            "GDI objects must grow after `CreateSolidBrush`"
        );
    }

    #[test]
    fn image_path_and_cmdline_of_self() {
        let exe_name = std::env::current_exe()
            .expect("the test executable path must be known")
            .file_name()
            .expect("the test executable must have a file name")
            .to_string_lossy()
            .into_owned();
        let handle = ProcHandle::current();

        let path = handle
            .image_path()
            .expect("the image path must be readable");
        let actual = Path::new(&path)
            .file_name()
            .expect("the image path must have a file name")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            actual, exe_name,
            "the image path must point at the test executable"
        );

        let cmdline = handle
            .command_line()
            .expect("the command line must be readable");
        assert!(
            cmdline.contains(exe_name.as_str()),
            "the command line must contain the executable name"
        );
    }

    #[test]
    fn snapshot_contains_self_with_parent() {
        let entries = snapshot().expect("the snapshot must be taken");
        let me = entries
            .iter()
            .find(|entry| entry.pid == std::process::id())
            .expect("the snapshot must contain the test process");
        assert_ne!(me.ppid, 0, "the parent PID must be non-zero");
        assert!(me.threads > 0, "the thread count must be positive");
    }

    #[test]
    fn open_missing_process_is_none() {
        let alive: HashSet<u32> = snapshot()
            .expect("the snapshot must be taken")
            .into_iter()
            .map(|entry| entry.pid)
            .collect();
        let mut pid = u32::MAX;
        while alive.contains(&pid) {
            pid -= 1;
        }
        assert!(
            ProcHandle::open(pid)
                .expect("opening a missing process must not fail")
                .is_none(),
            "PID {pid} must map to no process"
        );
    }

    #[test]
    fn file_version_of_system_exe() {
        let version = file_version(Path::new(r"C:\Windows\System32\kernel32.dll"))
            .expect("kernel32.dll must have a file version");
        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(parts.len(), 4, "`{version}` must be a.b.c.d");
        for part in parts {
            assert!(part.parse::<u32>().is_ok(), "`{version}` must be numeric");
        }

        let file = tempfile::NamedTempFile::new().expect("the temporary file must be created");
        assert_eq!(
            file_version(file.path()),
            None,
            "a file without a version resource must be None"
        );
    }

    #[test]
    fn cpu_pct_normalizes_by_cpus() {
        assert_eq!(cpu_pct(0, 10_000_000, Duration::from_secs(1), 4), 25.0);
        assert_eq!(cpu_pct(0, 10_000_000, Duration::ZERO, 4), 0.0);
    }

    #[test]
    fn cloned_handle_reads_same_creation_time() {
        let handle = ProcHandle::current();
        let clone = handle.try_clone().expect("the handle must be clonable");
        assert_eq!(
            handle
                .creation_time()
                .expect("the creation time must be readable"),
            clone
                .creation_time()
                .expect("the creation time must be readable")
        );
    }

    #[test]
    fn parent_pid_of_self_matches_snapshot() {
        let parent = ProcHandle::current()
            .parent_pid()
            .expect("the parent PID must be readable");
        let entries = snapshot().expect("the snapshot must be taken");
        let me = entries
            .iter()
            .find(|entry| entry.pid == std::process::id())
            .expect("the snapshot must contain the test process");
        assert_eq!(parent, me.ppid);
    }
}
