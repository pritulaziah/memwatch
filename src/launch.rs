//! Job objects and process launching.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString, c_void};
use std::fs;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::rc::Rc;

use anyhow::anyhow;
use windows::Win32::Foundation::{
    ERROR_MORE_DATA, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAndIoAccountingInformation,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute,
};
use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR, w};

use crate::win::{OwnedHandle, ProcHandle};

/// A job object that kills every process assigned to it when the job closes.
pub struct Job {
    handle: OwnedHandle,
}

impl Job {
    /// Creates a job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    pub fn create() -> anyhow::Result<Job> {
        // SAFETY: both arguments are optional; the returned handle is owned
        // by this process.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null())? };
        let job = Job {
            handle: unsafe { OwnedHandle::new(handle) },
        };

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `info` is a valid structure of the declared size.
        unsafe {
            SetInformationJobObject(
                job.handle.raw(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )?;
        }
        Ok(job)
    }

    /// Assigns `process` to the job.
    pub fn assign(&self, process: &ProcHandle) -> anyhow::Result<()> {
        // SAFETY: both handles are valid and owned by this process.
        unsafe { AssignProcessToJobObject(self.handle.raw(), process.raw())? };
        Ok(())
    }

    /// Returns whether `process` is assigned to the job.
    pub fn contains(&self, process: &ProcHandle) -> anyhow::Result<bool> {
        let mut result = BOOL::default();
        // SAFETY: `result` points to writable storage, and both handles are
        // valid.
        unsafe { IsProcessInJob(process.raw(), Some(self.handle.raw()), &mut result)? };
        Ok(result.as_bool())
    }

    /// Terminates every process in the job with `exit_code`.
    pub fn terminate(&self, exit_code: u32) -> anyhow::Result<()> {
        // SAFETY: the job handle is valid and owned by this process.
        unsafe { TerminateJobObject(self.handle.raw(), exit_code)? };
        Ok(())
    }

    /// Lists the PIDs currently assigned to the job.
    pub fn process_ids(&self) -> anyhow::Result<Vec<u32>> {
        // The list is a header followed by an array of PIDs. The first probe
        // asks for 64 PIDs; the buffer doubles until the whole list fits.
        let header = size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() - size_of::<usize>();
        let mut capacity = 64usize;
        loop {
            let length = header + capacity * size_of::<usize>();
            // A `Vec<usize>` keeps the buffer aligned for the structure.
            let mut buffer = vec![0usize; length.div_ceil(size_of::<usize>())];
            // SAFETY: the buffer is large enough for the header and `capacity`
            // PIDs, and the job handle is valid.
            let query = unsafe {
                QueryInformationJobObject(
                    Some(self.handle.raw()),
                    JobObjectBasicProcessIdList,
                    buffer.as_mut_ptr().cast(),
                    length as u32,
                    None,
                )
            };
            match query {
                Ok(()) => {
                    // SAFETY: the kernel filled the header and the PID array.
                    let list =
                        unsafe { &*buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
                    let count = list.NumberOfProcessIdsInList as usize;
                    // SAFETY: `count` PIDs were written into the buffer.
                    let pids =
                        unsafe { std::slice::from_raw_parts(list.ProcessIdList.as_ptr(), count) };
                    return Ok(pids.iter().map(|pid| *pid as u32).collect());
                }
                Err(err) if err.code() == HRESULT::from_win32(ERROR_MORE_DATA.0) => {
                    capacity *= 2;
                    if capacity > 1 << 20 {
                        return Err(anyhow!("the job process list does not fit in memory"));
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// Reads the cumulative job accounting counters.
    pub fn accounting(&self) -> anyhow::Result<JobAccounting> {
        let mut info = JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION::default();
        // SAFETY: `info` is writable and has the declared size.
        unsafe {
            QueryInformationJobObject(
                Some(self.handle.raw()),
                JobObjectBasicAndIoAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>() as u32,
                None,
            )?;
        }
        Ok(JobAccounting {
            total_user_100ns: info.BasicInfo.TotalUserTime as u64,
            total_kernel_100ns: info.BasicInfo.TotalKernelTime as u64,
            total_page_faults: info.BasicInfo.TotalPageFaultCount as u64,
            total_processes: info.BasicInfo.TotalProcesses as u64,
            active_processes: info.BasicInfo.ActiveProcesses as u64,
            total_terminated_processes: info.BasicInfo.TotalTerminatedProcesses as u64,
            io_read_bytes: info.IoInfo.ReadTransferCount,
            io_write_bytes: info.IoInfo.WriteTransferCount,
            io_other_bytes: info.IoInfo.OtherTransferCount,
            io_read_ops: info.IoInfo.ReadOperationCount,
            io_write_ops: info.IoInfo.WriteOperationCount,
            io_other_ops: info.IoInfo.OtherOperationCount,
        })
    }

    /// Reads the peak memory counters of the job.
    pub fn peaks(&self) -> anyhow::Result<JobPeaks> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: `info` is writable and has the declared size.
        unsafe {
            QueryInformationJobObject(
                Some(self.handle.raw()),
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                None,
            )?;
        }
        Ok(JobPeaks {
            peak_job_memory: info.PeakJobMemoryUsed as u64,
            peak_process_memory: info.PeakProcessMemoryUsed as u64,
        })
    }
}

/// Cumulative job accounting counters.
///
/// Times are 100 ns units; the counters include terminated processes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobAccounting {
    /// Total user CPU time in 100 ns units.
    pub total_user_100ns: u64,
    /// Total kernel CPU time in 100 ns units.
    pub total_kernel_100ns: u64,
    /// Total page faults.
    pub total_page_faults: u64,
    /// Processes ever assigned to the job.
    pub total_processes: u64,
    /// Processes currently active in the job.
    pub active_processes: u64,
    /// Processes terminated since assignment.
    pub total_terminated_processes: u64,
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

/// Peak memory counters of a job.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobPeaks {
    /// Peak memory committed by the job in bytes.
    pub peak_job_memory: u64,
    /// Peak memory committed by any single process of the job in bytes.
    pub peak_process_memory: u64,
}

/// A launched process tree: its job, the root process and the root PID.
pub struct Launched {
    /// The job that holds the tree; closing it terminates the tree.
    pub job: Rc<Job>,
    /// The root process.
    pub root: ProcHandle,
    /// PID of the root process.
    pub root_pid: u32,
}

/// Builds a Windows command line from `args` using the MSVC quoting rules.
///
/// The result does not include a terminating NUL. An argument without spaces,
/// tabs or quotes is appended as is; every other argument is wrapped in
/// quotes, backslashes before a quote or at the end of the argument are
/// doubled, and quotes are escaped with a backslash.
pub fn quote_command_line(args: &[OsString]) -> Vec<u16> {
    let mut line = Vec::new();
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            line.push(u16::from(b' '));
        }
        append_argument(&mut line, arg);
    }
    line
}

/// Appends one argument quoted by the MSVC rules to `line`.
fn append_argument(line: &mut Vec<u16>, arg: &OsStr) {
    let units: Vec<u16> = arg.encode_wide().collect();
    let special = |unit: &u16| *unit == u16::from(b' ') || *unit == u16::from(b'\t');
    let needs_quotes = units.is_empty()
        || units
            .iter()
            .any(|unit| special(unit) || *unit == u16::from(b'"'));
    if !needs_quotes {
        line.extend_from_slice(&units);
        return;
    }

    line.push(u16::from(b'"'));
    let mut backslashes = 0usize;
    for &unit in &units {
        if unit == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }
        let escaped = if unit == u16::from(b'"') {
            backslashes * 2 + 1
        } else {
            backslashes
        };
        line.extend(std::iter::repeat_n(u16::from(b'\\'), escaped));
        backslashes = 0;
        line.push(unit);
    }
    line.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    line.push(u16::from(b'"'));
}

/// Launches `command` in a new job with redirected stdio.
///
/// The process is created suspended, assigned to the job and resumed. stdout
/// and stderr are appended to `app.stdout.log` and `app.stderr.log` in
/// `run_dir`, stdin is `NUL`. The working directory is the current directory
/// of memwatch. An empty `env_overrides` inherits the environment; otherwise
/// the current environment is extended with the overrides.
pub fn launch(
    command: &[OsString],
    env_overrides: &BTreeMap<String, String>,
    run_dir: &Path,
) -> anyhow::Result<Launched> {
    let stdout = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(run_dir.join("app.stdout.log"))?;
    let stderr = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(run_dir.join("app.stderr.log"))?;

    // SAFETY: `NUL` is a valid device name; the returned handle is owned here.
    let stdin = unsafe {
        OwnedHandle::new(CreateFileW(
            w!("NUL"),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?)
    };

    make_inheritable(stdin.raw())?;
    make_inheritable(HANDLE(stdout.as_raw_handle()))?;
    make_inheritable(HANDLE(stderr.as_raw_handle()))?;

    let job = Job::create()?;
    let environment = if env_overrides.is_empty() {
        None
    } else {
        Some(environment_block(std::env::vars_os(), env_overrides))
    };

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.raw();
    startup.StartupInfo.hStdOutput = HANDLE(stdout.as_raw_handle());
    startup.StartupInfo.hStdError = HANDLE(stderr.as_raw_handle());

    let handles = [
        stdin.raw(),
        HANDLE(stdout.as_raw_handle()),
        HANDLE(stderr.as_raw_handle()),
    ];
    let attributes = AttributeList::new(&handles)?;
    startup.lpAttributeList = attributes.raw();

    let mut command_line = quote_command_line(command);
    command_line.push(0);

    let flags = CREATE_SUSPENDED
        | CREATE_NO_WINDOW
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT;
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: the command line is NUL-terminated and stays alive for the
    // call, `startup` points to an initialized attribute list, and the
    // security attributes are optional.
    let created = unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            flags,
            environment.as_ref().map(|block| block.as_ptr().cast()),
            PCWSTR::null(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    drop(attributes);
    created?;

    // SAFETY: `CreateProcessW` succeeded, so both handles are owned by this
    // call and stay valid until they are closed.
    let root = ProcHandle::from_owned(unsafe { OwnedHandle::new(info.hProcess) });
    let thread = unsafe { OwnedHandle::new(info.hThread) };

    let started = job.assign(&root).and_then(|()| resume_thread(thread.raw()));
    if let Err(err) = started {
        // SAFETY: the process was created by this call and has not run yet.
        unsafe {
            let _ = TerminateProcess(root.raw(), 1);
        }
        return Err(err);
    }
    drop(thread);

    Ok(Launched {
        job: Rc::new(job),
        root,
        root_pid: info.dwProcessId,
    })
}

/// Marks `handle` as inheritable by child processes.
fn make_inheritable(handle: HANDLE) -> anyhow::Result<()> {
    // SAFETY: `handle` is valid; only the inherit flag is changed.
    unsafe {
        SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)?;
    }
    Ok(())
}

/// Resumes the primary thread of a suspended process.
fn resume_thread(thread: HANDLE) -> anyhow::Result<()> {
    // SAFETY: `thread` is a valid handle of a suspended process thread.
    let previous = unsafe { ResumeThread(thread) };
    if previous == u32::MAX {
        return Err(anyhow!(
            "ResumeThread failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Builds a `CREATE_UNICODE_ENVIRONMENT` block from `base` plus `overrides`.
///
/// An override replaces the value of the variable whose name matches it
/// case-insensitively; new names are appended. Names and values are encoded
/// with `OsStr::encode_wide`, so unpaired surrogates survive. The block ends
/// with an empty string (a double NUL).
fn environment_block(
    base: impl Iterator<Item = (OsString, OsString)>,
    overrides: &BTreeMap<String, String>,
) -> Vec<u16> {
    let mut vars: Vec<(Vec<u16>, Vec<u16>)> = base
        .map(|(name, value)| (name.encode_wide().collect(), value.encode_wide().collect()))
        .collect();

    for (name, value) in overrides {
        let name: Vec<u16> = name.encode_utf16().collect();
        let value: Vec<u16> = value.encode_utf16().collect();
        match vars
            .iter_mut()
            .find(|(key, _)| wide_eq_ignore_ascii_case(key, &name))
        {
            Some((_, existing)) => *existing = value,
            None => vars.push((name, value)),
        }
    }

    let mut block = Vec::new();
    for (name, value) in vars {
        block.extend(name);
        block.push(u16::from(b'='));
        block.extend(value);
        block.push(0);
    }
    block.push(0);
    block
}

/// Compares two UTF-16 environment variable names case-insensitively.
///
/// Only ASCII letters are folded, matching how Windows compares environment
/// variable names.
fn wide_eq_ignore_ascii_case(left: &[u16], right: &[u16]) -> bool {
    let lower = |unit: u16| {
        if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
            unit + u16::from(b'a' - b'A')
        } else {
            unit
        }
    };
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| lower(*left) == lower(*right))
}

/// An initialized process attribute list that deletes itself when dropped.
struct AttributeList {
    buffer: Vec<usize>,
}

impl AttributeList {
    /// Creates a list that allows exactly `handles` to be inherited.
    fn new(handles: &[HANDLE]) -> anyhow::Result<AttributeList> {
        let mut size = 0usize;
        // SAFETY: the first call only asks for the required buffer size; a
        // null list fails with `ERROR_INSUFFICIENT_BUFFER`.
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, 1, None, &mut size);
        }
        if size == 0 {
            return Err(anyhow!("cannot determine the process attribute list size"));
        }

        // A `Vec<usize>` keeps the buffer aligned for the attribute list.
        let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr().cast());
        // SAFETY: `buffer` is aligned and large enough for one attribute, and
        // the handle array stays alive for the call.
        unsafe {
            InitializeProcThreadAttributeList(Some(list), 1, None, &mut size)?;
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                size_of_val(handles),
                None,
                None,
            )?;
        }
        Ok(AttributeList { buffer })
    }

    /// Returns the pointer for `STARTUPINFOEXW::lpAttributeList`.
    fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.buffer.as_ptr() as *mut c_void)
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialized in `new` and is not used afterwards.
        unsafe { DeleteProcThreadAttributeList(self.raw()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    #[test]
    fn quote_command_line_follows_msvc_rules() {
        let cases: [(&[&str], &str); 9] = [
            (&["abc"], "abc"),
            (&["a b"], r#""a b""#),
            (&["a\"b"], r#""a\"b""#),
            (&["a\\"], r"a\"),
            (&["a\\\"b"], r#""a\\\"b""#),
            (&["a\\\\"], r"a\\"),
            (&[""], r#""""#),
            (&["a b\\\\"], r#""a b\\\\""#),
            (&["abc", "a b"], r#"abc "a b""#),
        ];
        for (args, expected) in cases {
            let args: Vec<OsString> = args.iter().map(|arg| OsString::from(*arg)).collect();
            let line = quote_command_line(&args);
            let line = String::from_utf16(&line).expect("the command line must be valid UTF-16");
            assert_eq!(line, expected, "`{args:?}` must be quoted per MSVC rules");
        }
    }

    #[test]
    fn environment_block_keeps_unpaired_surrogates() {
        let base = [(
            OsString::from("EXOTIC"),
            OsString::from_wide(&[0x41, 0xD800, 0x42]),
        )];

        let block = environment_block(base.into_iter(), &BTreeMap::new());

        assert!(
            block.contains(&0xD800),
            "an unpaired surrogate must be encoded as is: {block:?}"
        );
        assert!(
            !block.contains(&0xFFFD),
            "the replacement character must not appear: {block:?}"
        );
        let tail = &block[block.len() - 2..];
        assert_eq!(tail, &[0, 0][..], "the block must end with a double NUL");
    }

    #[test]
    fn environment_block_replaces_overrides_case_insensitively() {
        let base = [(OsString::from("Path"), OsString::from("old"))];
        let overrides = BTreeMap::from([
            ("path".to_string(), "new".to_string()),
            ("NEW_VAR".to_string(), "added".to_string()),
        ]);

        let block = environment_block(base.into_iter(), &overrides);

        let text = String::from_utf16(&block).expect("ASCII names must stay valid UTF-16");
        assert!(
            text.contains("Path=new\0"),
            "the existing spelling must be kept and only the value replaced: {text:?}"
        );
        assert!(
            !text.contains("Path=old"),
            "the replaced value must be gone: {text:?}"
        );
        assert!(
            text.contains("NEW_VAR=added\0"),
            "a new override must be appended: {text:?}"
        );
        assert_eq!(
            text.matches("Path=").count(),
            1,
            "the variable must not be duplicated: {text:?}"
        );
    }
}
