//! The run journal written to `memwatch.log`.

use std::collections::HashSet;
use std::fmt::Display;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use time::OffsetDateTime;

/// A shared, append-only journal of the run.
#[derive(Clone)]
pub struct RunLog {
    file: Arc<Mutex<File>>,
    warned: Arc<Mutex<HashSet<String>>>,
}

impl RunLog {
    /// Creates the journal file, truncating it if it exists.
    pub fn create(path: &Path) -> io::Result<RunLog> {
        Ok(RunLog {
            file: Arc::new(Mutex::new(File::create(path)?)),
            warned: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Writes an `INFO` line and flushes it.
    pub fn info(&self, component: &str, msg: impl Display) {
        self.write("INFO", component, msg);
    }

    /// Writes a `WARN` line and flushes it.
    pub fn warn(&self, component: &str, msg: impl Display) {
        self.write("WARN", component, msg);
    }

    /// Writes an `ERROR` line and flushes it.
    pub fn error(&self, component: &str, msg: impl Display) {
        self.write("ERROR", component, msg);
    }

    /// Writes a `WARN` line only the first time `key` is seen.
    pub fn warn_once(&self, key: &str, component: &str, msg: impl Display) {
        let first = self
            .warned
            .lock()
            .expect("the warned-keys mutex is not poisoned")
            .insert(key.to_string());
        if first {
            self.write("WARN", component, msg);
        }
    }

    fn write(&self, level: &str, component: &str, msg: impl Display) {
        let unix_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let mut file = self.file.lock().expect("the log mutex is not poisoned");
        let result =
            writeln!(file, "{unix_ms} {level} {component}: {msg}").and_then(|()| file.flush());
        if let Err(err) = result {
            eprintln!("memwatch: cannot write to the run log: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::TempDir;

    #[test]
    fn log_line_format() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("memwatch.log");
        let log = RunLog::create(&path).unwrap();

        log.info("job", "started");
        log.warn("process", "text");
        log.error("system", "boom");

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let (stamp, _) = line
                .split_once(' ')
                .expect("the line must start with a timestamp");
            assert!(
                stamp.parse::<i64>().is_ok(),
                "`{stamp}` must be unix milliseconds"
            );
        }
        assert_eq!(lines[0].split_once(' ').unwrap().1, "INFO job: started");
        assert_eq!(lines[1].split_once(' ').unwrap().1, "WARN process: text");
        assert_eq!(lines[2].split_once(' ').unwrap().1, "ERROR system: boom");
    }

    #[test]
    fn warn_once_writes_only_first_per_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("memwatch.log");
        let log = RunLog::create(&path).unwrap();

        log.warn_once("1234-0", "process", "no access");
        log.warn_once("1234-0", "process", "no access");
        log.warn_once("5678-0", "process", "no access");

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
    }
}
