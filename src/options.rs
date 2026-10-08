//! Command-line option parsing for the `run` command.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use time::OffsetDateTime;
use time::macros::format_description;

/// Resolved options of the `run` command.
#[derive(Debug)]
pub struct RunOptions {
    /// Run name; also the prefix of the run directory.
    pub name: String,
    /// Directory that holds run directories.
    pub out_dir: PathBuf,
    /// Labels stored in the run metadata.
    pub labels: BTreeMap<String, String>,
    /// Sampling interval.
    pub interval: Duration,
    /// Interval of the GPU collector; a whole multiple of `interval`.
    pub gpu_interval: Duration,
    /// Interval of the DevTools collector; a whole multiple of `interval`.
    pub cdp_interval: Duration,
    /// Port that the launched application opens for DevTools; `None` keeps it
    /// closed.
    pub cdp_port: Option<u16>,
    /// Whether the machine may sleep during the run.
    pub allow_sleep: bool,
    /// Command to run followed by its arguments.
    pub command: Vec<OsString>,
}

/// Parses a duration such as `500ms`, `1s`, `10m` or `2h`.
///
/// The value must be a non-zero integer followed by one of `ms`, `s`, `m`
/// or `h`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let (number, millis_per_unit) = if let Some(number) = s.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = s.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = s.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = s.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        return Err(format!(
            "invalid duration `{s}`: expected a non-zero integer followed by `ms`, `s`, `m` or `h`"
        ));
    };

    let value = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration `{s}`: `{number}` is not a non-negative integer"))?;
    if value == 0 {
        return Err(format!("invalid duration `{s}`: zero is not allowed"));
    }

    let millis = value
        .checked_mul(millis_per_unit)
        .ok_or_else(|| format!("invalid duration `{s}`: value is too large"))?;
    Ok(Duration::from_millis(millis))
}

/// Splits a `key=value` label on the first `=`.
///
/// The key must not be empty; the value may be.
pub fn parse_label(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_string(), value.to_string())),
        _ => Err(format!(
            "invalid label `{s}`: expected `key=value` with a non-empty key"
        )),
    }
}

/// Validates a run name and returns it unchanged when it is safe.
///
/// Only ASCII letters, digits, `.`, `_` and `-` are allowed.
pub fn validate_name(s: &str) -> Result<String, String> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if s.is_empty() || !s.chars().all(allowed) {
        return Err(format!(
            "invalid name `{s}`: only ASCII letters, digits, `.`, `_` and `-` are allowed"
        ));
    }
    Ok(s.to_string())
}

/// Builds the run directory name `<name>-<YYYYMMDD-HHMMSS>`.
///
/// The date-time is formatted in its own offset, so callers pass the local
/// start time.
pub fn run_dir_name(name: &str, started: OffsetDateTime) -> String {
    let format = format_description!("[year][month][day]-[hour][minute][second]");
    let stamp = started
        .format(&format)
        .expect("the fixed format description is valid for any date-time");
    format!("{name}-{stamp}")
}

/// Checks that the GPU and DevTools intervals are whole multiples of the
/// sampling interval.
///
/// The GPU interval is checked first, so when both are invalid the error
/// names the GPU flag.
pub fn validate_intervals(
    interval: Duration,
    gpu_interval: Duration,
    cdp_interval: Duration,
) -> Result<(), String> {
    let interval_ms = interval.as_millis();
    for (flag, value) in [
        ("--gpu-interval", gpu_interval),
        ("--cdp-interval", cdp_interval),
    ] {
        if value.as_millis() % interval_ms != 0 {
            return Err(format!(
                "{flag} must be a multiple of --interval: {}ms is not a whole multiple of {interval_ms}ms",
                value.as_millis()
            ));
        }
    }
    Ok(())
}

/// Builds the environment overrides for the launched application.
///
/// With a port the application receives `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`
/// set to `--remote-debugging-port=<port>`; without one the map is empty.
pub fn cdp_env_overrides(port: Option<u16>) -> BTreeMap<String, String> {
    let mut overrides = BTreeMap::new();
    if let Some(port) = port {
        overrides.insert(
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS".to_string(),
            format!("--remote-debugging-port={port}"),
        );
    }
    overrides
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn parse_duration_accepts_units() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("1s"), Ok(Duration::from_secs(1)));
        assert_eq!(parse_duration("10m"), Ok(Duration::from_secs(600)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
    }

    #[test]
    fn parse_duration_rejects_invalid() {
        for input in ["", "0s", "1", "1d", "-1s", "1.5s"] {
            assert!(parse_duration(input).is_err(), "`{input}` must be rejected");
        }
    }

    #[test]
    fn parse_label_splits_on_first_equals() {
        assert_eq!(
            parse_label("a=b=c"),
            Ok(("a".to_string(), "b=c".to_string()))
        );
        assert!(parse_label("a").is_err());
        assert!(parse_label("=b").is_err());
    }

    #[test]
    fn validate_name_allows_safe_chars() {
        assert_eq!(validate_name("wry"), Ok("wry".to_string()));
        assert_eq!(
            validate_name("release-10.0_x"),
            Ok("release-10.0_x".to_string())
        );
        assert!(validate_name("a b").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("").is_err());
    }

    #[test]
    fn run_dir_name_formats_local_time() {
        let started = datetime!(2026-10-07 16:05:09 UTC);
        assert_eq!(run_dir_name("wry", started), "wry-20261007-160509");
    }

    #[test]
    fn validate_intervals_accepts_multiples() {
        assert_eq!(
            validate_intervals(
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(10)
            ),
            Ok(())
        );
        assert_eq!(
            validate_intervals(
                Duration::from_millis(500),
                Duration::from_millis(500),
                Duration::from_secs(1)
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_intervals_rejects_non_multiples() {
        let gpu_error = validate_intervals(
            Duration::from_secs(1),
            Duration::from_millis(1500),
            Duration::from_secs(10),
        )
        .expect_err("a GPU interval that is not a whole multiple must be rejected");
        assert!(
            gpu_error.contains("--gpu-interval"),
            "the error must name the GPU flag: {gpu_error}"
        );

        let cdp_error = validate_intervals(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_millis(1500),
        )
        .expect_err("a DevTools interval that is not a whole multiple must be rejected");
        assert!(
            cdp_error.contains("--cdp-interval"),
            "the error must name the DevTools flag: {cdp_error}"
        );
    }

    #[test]
    fn cdp_env_overrides_sets_browser_arguments() {
        let overrides = cdp_env_overrides(Some(9222));
        assert_eq!(
            overrides.len(),
            1,
            "exactly one variable must be set: {overrides:?}"
        );
        assert_eq!(
            overrides.get("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"),
            Some(&"--remote-debugging-port=9222".to_string()),
            "the browser arguments must open the given port"
        );
    }

    #[test]
    fn cdp_env_overrides_is_empty_without_port() {
        assert!(
            cdp_env_overrides(None).is_empty(),
            "no port must mean no overrides"
        );
    }
}
