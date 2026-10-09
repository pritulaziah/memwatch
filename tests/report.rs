//! End-to-end tests of the report written at the end of `memwatch run` and
//! rebuilt by `memwatch report`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use memwatch::analyze::{MetricId, WarningMessage, Window, compute_warnings, load, summarize};
use memwatch::meta::{EndReason, Host, Meta};
use memwatch::options::RunOptions;
use memwatch::sampler::StopHandle;
use memwatch::store::{
    CDP_COLUMNS, GPU_COLUMNS, JOB_COLUMNS, PROCESS_COLUMNS, PROCESSES_COLUMNS, SYSTEM_COLUMNS,
};
use tempfile::TempDir;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Path of the memwatch binary built by Cargo for these tests.
const MEMWATCH: &str = env!("CARGO_BIN_EXE_memwatch");

/// Path of the fixture binary built by Cargo for these tests.
const FIXTURE: &str = env!("CARGO_BIN_EXE_memwatch-fixture");

/// Builds the command line that starts the fixture with `args`.
fn fixture_command(args: &[&str]) -> Vec<OsString> {
    let mut command = vec![OsString::from(FIXTURE)];
    command.extend(args.iter().map(OsString::from));
    command
}

/// Builds options for a run of the fixture into `out_dir`.
fn fixture_options(out_dir: &Path, command: Vec<OsString>) -> RunOptions {
    RunOptions {
        name: "fixture".to_string(),
        out_dir: out_dir.to_path_buf(),
        labels: BTreeMap::new(),
        interval: Duration::from_secs(1),
        duration: None,
        gpu_interval: Duration::from_secs(2),
        cdp_interval: Duration::from_secs(10),
        cdp_port: None,
        allow_sleep: true,
        command,
    }
}

/// Returns the only run directory under `out`.
fn single_run_dir(out: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = fs::read_dir(out)
        .expect("the output directory must be readable")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    assert_eq!(
        dirs.len(),
        1,
        "exactly one run directory must exist: {dirs:?}"
    );
    dirs.pop().expect("the run directory must be found")
}

/// Waits until the first run directory appears under `out`.
fn wait_for_run_dir(out: &Path, timeout: Duration) -> PathBuf {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(entries) = fs::read_dir(out) {
            let mut dirs: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect();
            dirs.sort();
            if let Some(dir) = dirs.into_iter().next() {
                return dir;
            }
        }
        assert!(
            Instant::now() < deadline,
            "a run directory must appear within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Reads `report.md` of a run directory.
fn read_report(run_dir: &Path) -> String {
    fs::read_to_string(run_dir.join("report").join("report.md"))
        .expect("report.md must be readable")
}

/// Reads `meta.json` into a JSON value.
fn read_meta(run_dir: &Path) -> serde_json::Value {
    let content =
        fs::read_to_string(run_dir.join("meta.json")).expect("meta.json must be readable");
    serde_json::from_str(&content).expect("meta.json must be valid JSON")
}

/// Reaps the owned CLI process even when an assertion unwinds.
struct ReportChildGuard(Option<Child>);

impl Drop for ReportChildGuard {
    fn drop(&mut self) {
        let Some(child) = self.0.as_mut() else {
            return;
        };
        let _ = child.kill();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if matches!(child.try_wait(), Ok(Some(_))) || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Captures the small CLI response with a bounded wait and owned-child cleanup.
fn command_output(command: &mut Command, timeout: Duration) -> Output {
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the report command must start");
    let mut guard = ReportChildGuard(Some(child));
    let deadline = Instant::now() + timeout;
    loop {
        if guard
            .0
            .as_mut()
            .expect("the command must remain owned")
            .try_wait()
            .expect("the command state must be readable")
            .is_some()
        {
            return guard
                .0
                .take()
                .expect("the exited command must remain owned")
                .wait_with_output()
                .expect("the exited command output must be readable");
        }
        assert!(
            Instant::now() < deadline,
            "the command exceeded {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Writes rows by column name, leaving unspecified metric cells empty.
fn write_named_csv(path: &Path, columns: &[&str], rows: &[BTreeMap<&str, String>]) {
    let mut writer = csv::Writer::from_path(path).expect("the CSV must be writable");
    writer
        .write_record(columns)
        .expect("the header must be writable");
    for row in rows {
        writer
            .write_record(
                columns
                    .iter()
                    .map(|column| row.get(column).map(String::as_str).unwrap_or_default()),
            )
            .expect("the row must be writable");
    }
    writer.flush().expect("the CSV must be flushed");
}

/// Creates a fixed synthetic recording in the original schema-one format.
fn write_legacy_run(dir: &Path) -> PathBuf {
    let run_dir = dir.join("synthetic-legacy");
    fs::create_dir(&run_dir).expect("the input directory must be created");
    let started = OffsetDateTime::parse("2026-10-07T16:05:09+03:00", &Rfc3339)
        .expect("the fixed start time must parse");
    let unix_ms = (started.unix_timestamp_nanos() / 1_000_000) as u64;
    let image = r"C:\private\path-secret\legacy.exe";
    let command = vec![
        OsString::from(image),
        OsString::from("--token=command-secret"),
    ];
    let mut options = fixture_options(dir, command);
    options.name = "synthetic-legacy".to_string();
    let mut meta = Meta::new(
        &options,
        started,
        Host {
            os: "Windows 11 synthetic".to_string(),
            cpu: "Synthetic CPU".to_string(),
            logical_cpus: 4,
            ram_bytes: 8 * 1_073_741_824,
            gpus: vec!["Synthetic GPU".to_string()],
        },
    );
    meta.memwatch_version = "0.1.0".to_string();
    meta.cwd = r"C:\private\cwd-secret".to_string();
    meta.ended_at = Some(
        (started + time::Duration::minutes(20))
            .format(&Rfc3339)
            .expect("the fixed end time must format"),
    );
    meta.end_reason = Some(EndReason::AppExited);
    meta.exit_code = Some(0);
    for status in meta.collectors.values_mut() {
        *status = memwatch::meta::CollectorStatus::Ok;
    }
    let mut json = serde_json::to_value(meta).expect("metadata must serialize");
    json.as_object_mut()
        .expect("metadata must be an object")
        .remove("shutdown_issues");
    fs::write(
        run_dir.join("meta.json"),
        serde_json::to_vec_pretty(&json).expect("legacy metadata must serialize"),
    )
    .expect("legacy metadata must be writable");

    let events: Vec<_> = [(0, "start"), (1_200_000, "exit")]
        .into_iter()
        .map(|(t_ms, event)| {
            BTreeMap::from([
                ("t_ms", t_ms.to_string()),
                ("unix_ms", (unix_ms + t_ms).to_string()),
                ("event", event.to_string()),
                ("proc_key", "100-1000".to_string()),
                ("pid", "100".to_string()),
                ("ppid", "0".to_string()),
                ("role", "main".to_string()),
                ("image_path", image.to_string()),
                (
                    "exit_code",
                    if event == "exit" { "0" } else { "" }.to_string(),
                ),
                (
                    "cmdline",
                    if event == "start" {
                        "--token=command-secret"
                    } else {
                        ""
                    }
                    .to_string(),
                ),
            ])
        })
        .collect();
    write_named_csv(&run_dir.join("processes.csv"), PROCESSES_COLUMNS, &events);
    let process: Vec<_> = [(0, 1000), (599_999, 1000), (600_000, 100), (1_200_000, 100)]
        .into_iter()
        .map(|(t_ms, mib)| {
            BTreeMap::from([
                ("t_ms", t_ms.to_string()),
                ("unix_ms", (unix_ms + t_ms).to_string()),
                ("proc_key", "100-1000".to_string()),
                ("pid", "100".to_string()),
                ("role", "main".to_string()),
                ("private_bytes", (mib * 1_048_576_u64).to_string()),
            ])
        })
        .collect();
    write_named_csv(&run_dir.join("process.csv"), PROCESS_COLUMNS, &process);
    let mut cdp = Vec::new();
    for (target, ticks, mib, nodes) in [
        ("A", [0, 599_999, 600_000, 1_200_000], 10, 100),
        ("B", [1, 599_998, 600_001, 1_199_999], 20, 200),
    ] {
        for t_ms in ticks {
            cdp.push(BTreeMap::from([
                ("t_ms", t_ms.to_string()),
                ("unix_ms", (unix_ms + t_ms).to_string()),
                ("target_id", target.to_string()),
                ("url", "https://private.invalid/url-secret".to_string()),
                ("js_heap_used_bytes", (mib * 1_048_576_u64).to_string()),
                ("nodes", nodes.to_string()),
            ]));
        }
    }
    cdp.sort_by_key(|row| {
        row["t_ms"]
            .parse::<u64>()
            .expect("the fixed time must parse")
    });
    let legacy_columns: Vec<_> = CDP_COLUMNS
        .iter()
        .copied()
        .filter(|column| *column != "session_id")
        .collect();
    write_named_csv(&run_dir.join("cdp.csv"), &legacy_columns, &cdp);
    for (file, columns) in [
        ("job.csv", JOB_COLUMNS),
        ("system.csv", SYSTEM_COLUMNS),
        ("gpu.csv", GPU_COLUMNS),
    ] {
        write_named_csv(&run_dir.join(file), columns, &[]);
    }
    run_dir
}

/// Snapshots the seven source files, excluding all generated report artifacts.
fn input_bytes(run_dir: &Path) -> BTreeMap<String, Vec<u8>> {
    [
        "meta.json",
        "processes.csv",
        "process.csv",
        "job.csv",
        "gpu.csv",
        "cdp.csv",
        "system.csv",
    ]
    .into_iter()
    .map(|file| {
        (
            file.to_string(),
            fs::read(run_dir.join(file)).expect("the input file must be readable"),
        )
    })
    .collect()
}

/// Builds a CLI report in a separate temporary output directory.
fn legacy_report(run_dir: &Path, out: &Path, lang: &str, warmup: Option<&str>) -> String {
    let mut command = Command::new(MEMWATCH);
    command
        .arg("report")
        .arg(run_dir)
        .args(["--lang", lang])
        .arg("--out")
        .arg(out);
    if let Some(warmup) = warmup {
        command.args(["--warmup", warmup]);
    }
    let output = command_output(&mut command, Duration::from_secs(10));
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&out.join("report.md").display().to_string())
    );
    assert!(
        !run_dir.join("report").exists(),
        "custom output must not modify the run"
    );
    fs::read_to_string(out.join("report.md")).expect("the generated report must be readable")
}

/// Returns one Markdown section up to the next heading at the same level or above.
fn report_section<'a>(document: &'a str, heading: &str) -> &'a str {
    let start = document
        .find(&format!("{heading}\n"))
        .expect("the report section must exist");
    let rest = &document[start + heading.len() + 1..];
    let level = heading
        .chars()
        .take_while(|character| *character == '#')
        .count();
    let mut end = 0;
    for line in rest.split_inclusive('\n') {
        let next_level = line
            .chars()
            .take_while(|character| *character == '#')
            .count();
        if next_level > 0 && next_level <= level {
            break;
        }
        end += line.len();
    }
    &rest[..end]
}

/// Reads a single table row by its exact label rather than matching unrelated numbers.
fn report_cells<'a>(section: &'a str, label: &str) -> Vec<&'a str> {
    let rows: Vec<_> = section
        .lines()
        .filter(|line| line.starts_with('|'))
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect::<Vec<_>>()
        })
        .filter(|cells| cells.first() == Some(&label))
        .collect();
    assert_eq!(rows.len(), 1, "one row for {label} must exist:\n{section}");
    rows.into_iter().next().expect("the unique row must exist")
}

/// Checks the two independent target tables and their metric-specific counts.
fn assert_legacy_targets(document: &str, lang: &str, steady_counts: [usize; 2]) {
    let (target_label, whole, steady, unit, growth_unit, short) = if lang == "en" {
        (
            "CDP target",
            "Whole run",
            "After warmup",
            "MB",
            "count/h",
            "run too short",
        )
    } else {
        (
            "источник CDP",
            "Весь прогон",
            "После прогрева",
            "МБ",
            "шт./ч",
            "прогон слишком короткий",
        )
    };
    for (index, target) in ["A", "B"].into_iter().enumerate() {
        let section = report_section(document, &format!("### {target_label} {target}"));
        for (heading, count, width) in [(whole, 4, 9), (steady, steady_counts[index], 12)] {
            let window = report_section(section, &format!("#### {heading}"));
            for (metric, start, delta, slope) in [
                (
                    "JS heap",
                    format!("{:.1} {unit}", ((index + 1) * 10) as f64),
                    format!("0.0 {unit}"),
                    format!("0.0 {unit}/{}", if lang == "en" { "h" } else { "ч" }),
                ),
                (
                    "DOM nodes",
                    ((index + 1) * 100).to_string(),
                    "0".to_string(),
                    format!("0 {growth_unit}"),
                ),
            ] {
                let cells = report_cells(window, metric);
                assert_eq!(cells.len(), width);
                assert_eq!(cells[1], start);
                assert_eq!(cells[2], start);
                assert_eq!(cells[3], start);
                assert_eq!(cells[5], start);
                assert_eq!(cells[6], start);
                assert_eq!(cells[7], delta);
                assert_eq!(cells.last(), Some(&count.to_string().as_str()));
                if width == 12 {
                    assert_eq!(cells[8], slope);
                    assert_eq!(cells[10], short);
                }
            }
        }
    }
    let tree = report_section(
        document,
        if lang == "en" {
            "## Tree summary"
        } else {
            "## Итоги по дереву"
        },
    );
    assert!(
        !tree.contains("JS heap"),
        "multiple targets must not create a primary JS row"
    );
    assert!(!tree.contains("DOM nodes"));
    for marker in ["url-secret", "command-secret", "path-secret", "cwd-secret"] {
        assert!(!document.contains(marker), "the report must omit {marker}");
    }
}

#[test]
fn report_rebuilds_legacy_cdp_with_two_windows_and_targets() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let run_dir = write_legacy_run(dir.path());
    let before = input_bytes(&run_dir);
    assert!(read_meta(&run_dir).get("shutdown_issues").is_none());
    let run = load(&run_dir).expect("the original schema must load");
    assert_eq!(run.meta.schema_version, 1);
    assert!(run.meta.shutdown_issues.is_empty());
    assert_eq!(run.cdp.len(), 8);
    assert!(run.cdp.iter().all(|sample| sample.session_id.is_none()));
    let summary = summarize(
        &run,
        Window {
            start_ms: 0,
            end_ms: run.duration_ms(),
        },
        1,
    );
    assert_eq!(summary.primary_cdp_target, None);
    for (index, target) in summary.cdp_targets.iter().enumerate() {
        assert_eq!(target.target_id, ["A", "B"][index]);
        for metric in [MetricId::JsHeapUsedBytes, MetricId::DomNodes] {
            assert_eq!(target.whole_run[&metric].samples, 4);
            assert_eq!(target.steady_state[&metric].samples, [3, 4][index]);
            assert_eq!(target.steady_state[&metric].delta, Some(0.0));
        }
    }
    for lang in ["en", "ru"] {
        let document = legacy_report(&run_dir, &dir.path().join(lang), lang, Some("1ms"));
        assert_legacy_targets(&document, lang, [3, 4]);
        assert_eq!(
            before,
            input_bytes(&run_dir),
            "reading must not migrate input files"
        );
    }
}

#[test]
fn report_validates_legacy_startup_and_steady_windows() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let run_dir = write_legacy_run(dir.path());
    let before = input_bytes(&run_dir);
    for lang in ["en", "ru"] {
        let document = legacy_report(&run_dir, &dir.path().join(lang), lang, None);
        let (whole, steady, metric_header, unit, short) = if lang == "en" {
            ("Whole run", "After warmup", "Metric", "MB", "run too short")
        } else {
            (
                "Весь прогон",
                "После прогрева",
                "Метрика",
                "МБ",
                "прогон слишком короткий",
            )
        };
        let whole = report_section(&document, &format!("### {whole}"));
        let steady = report_section(&document, &format!("### {steady}"));
        assert_eq!(report_cells(whole, metric_header).len(), 8);
        assert_eq!(report_cells(steady, metric_header).len(), 11);
        for label in ["Growth", "R²", "Median delta", "Рост", "Разница медиан"] {
            assert!(
                !whole.contains(label),
                "whole-run statistics must omit trends"
            );
        }
        assert_eq!(
            report_cells(whole, "Private bytes")[2],
            format!("1000.0 {unit}")
        );
        let cells = report_cells(steady, "Private bytes");
        assert_eq!(cells[3], format!("100.0 {unit}"));
        assert_eq!(cells[5], format!("100.0 {unit}"));
        assert_eq!(
            cells[8],
            format!("0.0 {unit}/{}", if lang == "en" { "h" } else { "ч" })
        );
        assert_eq!(cells[10], short);
        assert!(whole.contains("[0:00, 20:00]"));
        assert!(steady.contains("[10:00, 20:00]"));
        assert_legacy_targets(&document, lang, [2, 2]);
        assert_eq!(
            before,
            input_bytes(&run_dir),
            "reading must not migrate input files"
        );
    }
}

#[test]
fn report_renders_shutdown_issues_without_invented_exits() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let run_dir = write_legacy_run(dir.path());
    for file in ["processes.csv", "process.csv"] {
        let mut reader =
            csv::Reader::from_path(run_dir.join(file)).expect("the process input must be readable");
        let headers = reader.headers().expect("the headers must exist").clone();
        let columns: Vec<_> = headers.iter().collect();
        let mut rows: Vec<BTreeMap<&str, String>> = reader
            .records()
            .map(|record| {
                let record = record.expect("the process row must parse");
                columns
                    .iter()
                    .copied()
                    .zip(record.iter().map(str::to_string))
                    .collect()
            })
            .collect();
        drop(reader);
        let mut child = if file == "processes.csv" {
            rows[0].clone()
        } else {
            rows.last().expect("the last sample must exist").clone()
        };
        child.insert("proc_key", "101-1001".to_string());
        child.insert("pid", "101".to_string());
        child.insert("role", "renderer".to_string());
        if file == "processes.csv" {
            child.insert("ppid", "100".to_string());
            rows.insert(1, child);
        } else {
            rows.push(child);
        }
        write_named_csv(&run_dir.join(file), &columns, &rows);
    }
    for reason in ["app_exited", "ctrl_c"] {
        let mut meta = read_meta(&run_dir);
        meta["end_reason"] = serde_json::json!(reason);
        meta["shutdown_issues"] = serde_json::json!([{
            "pid": 101, "proc_key": "101-1001", "role": "renderer",
            "state": "alive", "reason": "wait_timeout"
        }]);
        fs::write(
            run_dir.join("meta.json"),
            serde_json::to_vec_pretty(&meta).expect("metadata must serialize"),
        )
        .expect("metadata must be writable");
        let before = input_bytes(&run_dir);
        for lang in ["en", "ru"] {
            let document = legacy_report(
                &run_dir,
                &dir.path().join(format!("{reason}-{lang}")),
                lang,
                None,
            );
            let (warning, end_label, totals, started, exited, processes) = if lang == "en" {
                (
                    "Incomplete shutdown: PID 101, identity 101-1001, role renderer, state alive, reason wait timed out",
                    "End reason",
                    "Run totals",
                    "Processes started",
                    "Processes exited",
                    "Processes",
                )
            } else {
                (
                    "Неполная остановка: PID 101, идентичность 101-1001, роль renderer, состояние жив, причина истекло время ожидания",
                    "Причина завершения",
                    "Общие итоги прогона",
                    "Процессов стартовало",
                    "Процессов завершилось",
                    "Процессы",
                )
            };
            assert!(document.contains(warning));
            assert!(document.contains(&format!("- **{end_label}**: {reason}")));
            let totals = report_section(&document, &format!("### {totals}"));
            assert_eq!(report_cells(totals, started)[1], "2");
            assert_eq!(report_cells(totals, exited)[1], "1");
            let cells = report_cells(
                report_section(&document, &format!("## {processes}")),
                "renderer",
            );
            assert_eq!(cells[1], "legacy.exe");
            assert_eq!(cells[3], "0:00");
            assert_eq!(&cells[4..6], &["—", "—"]);
            assert_eq!(
                before,
                input_bytes(&run_dir),
                "reports must not invent saved exits"
            );
        }
    }
}

#[test]
fn report_warns_for_requested_empty_cdp_with_legacy_metadata() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let run_dir = write_legacy_run(dir.path());
    let columns: Vec<_> = CDP_COLUMNS
        .iter()
        .copied()
        .filter(|column| *column != "session_id")
        .collect();
    write_named_csv(&run_dir.join("cdp.csv"), &columns, &[]);
    for (case, status, remote) in [
        ("waiting", Some("waiting"), false),
        ("ok", Some("ok"), false),
        ("override", None, true),
        ("not-requested", None, false),
    ] {
        let requested = status.is_some() || remote;
        let mut meta = read_meta(&run_dir);
        let collectors = meta["collectors"]
            .as_object_mut()
            .expect("the status map must exist");
        if let Some(status) = status {
            collectors.insert("cdp".to_string(), serde_json::json!(status));
        } else {
            collectors.remove("cdp");
        }
        meta["env_overrides"] = if remote {
            serde_json::json!({"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": "--remote-debugging-port=9222"})
        } else {
            serde_json::json!({})
        };
        fs::write(
            run_dir.join("meta.json"),
            serde_json::to_vec_pretty(&meta).expect("metadata must serialize"),
        )
        .expect("metadata must be writable");
        let before = input_bytes(&run_dir);
        let run = load(&run_dir).expect("legacy metadata must load");
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            600_000,
        );
        let warnings = compute_warnings(&run, &summary);
        assert_eq!(
            warnings
                .iter()
                .filter(|warning| matches!(warning.message, WarningMessage::TimeGap { .. }))
                .count(),
            2,
            "the sparse recording retains its unrelated whole-run gap warnings"
        );
        assert_eq!(
            warnings
                .iter()
                .filter(|warning| matches!(
                    warning.message,
                    WarningMessage::CdpMetricsMissing { .. }
                ))
                .count(),
            usize::from(requested)
        );
        assert_eq!(
            warnings
                .iter()
                .filter(|warning| matches!(warning.message, WarningMessage::CdpWaiting))
                .count(),
            usize::from(status == Some("waiting"))
        );
        for lang in ["en", "ru"] {
            let document = legacy_report(
                &run_dir,
                &dir.path().join(format!("{case}-{lang}")),
                lang,
                None,
            );
            let (heading, missing, waiting, clean) = if lang == "en" {
                (
                    "Warnings",
                    "CDP requested, but no usable JS heap and DOM nodes samples for the whole run",
                    "CDP source was unavailable at the end of the run",
                    "No warnings",
                )
            } else {
                (
                    "Предупреждения",
                    "CDP запрошен, но нет пригодных замеров JS heap и DOM nodes: весь прогон",
                    "Источник CDP был недоступен к концу прогона",
                    "Предупреждений нет",
                )
            };
            let section = report_section(&document, &format!("## {heading}"));
            assert_eq!(section.matches(missing).count(), usize::from(requested));
            assert_eq!(
                section.matches(waiting).count(),
                usize::from(status == Some("waiting"))
            );
            if requested {
                assert!(!section.contains(clean), "requested empty CDP must warn");
            }
            assert_eq!(
                before,
                input_bytes(&run_dir),
                "reading must not migrate metadata"
            );
        }
    }
}

#[test]
fn run_writes_report_after_finishing() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&[
        "--duration",
        "5s",
        "--alloc-mb-per-sec",
        "20",
        "--gdi",
        "50",
        "--busy-ms-per-sec",
        "200",
    ]);

    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg("auto")
        .arg("--out")
        .arg(&out)
        .arg("--")
        .args(&fixture);
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("memwatch must run");
    assert_eq!(status.code(), Some(0), "the fixture run must exit with 0");

    let run_dir = single_run_dir(&out);
    let meta = read_meta(&run_dir);
    assert_eq!(
        meta["end_reason"], "app_exited",
        "the fixture must end by itself"
    );

    let report = read_report(&run_dir);
    for expected in [
        "# Run auto",
        "## Warnings",
        "## Tree summary",
        "### Whole run",
        "### After warmup",
        "### Run totals",
        "## CDP targets",
        "| Private bytes |",
        "## Roles",
        "## Processes",
        "- **End reason**: app_exited",
    ] {
        assert!(
            report.contains(expected),
            "the report must contain `{expected}`:\n{report}"
        );
    }
}

#[test]
fn run_honours_language() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "60s"]);

    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg("auto-ru")
        .arg("--out")
        .arg(&out)
        .args(["--lang", "ru", "--duration", "3s", "--"])
        .args(&fixture);
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("memwatch must run");
    assert_eq!(status.code(), Some(0), "the timed run must exit with 0");

    let run_dir = single_run_dir(&out);
    let report = read_report(&run_dir);
    for expected in [
        "# Прогон auto-ru",
        "## Предупреждения",
        "## Итоги по дереву",
        "### Весь прогон",
        "### После прогрева",
        "### Общие итоги прогона",
        "## Источники CDP",
        "| Метрика | Старт |",
    ] {
        assert!(
            report.contains(expected),
            "the report must contain `{expected}`:\n{report}"
        );
    }
}

#[test]
fn report_command_rebuilds_a_run() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "3s"]);

    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg("rebuild")
        .arg("--out")
        .arg(&out)
        .arg("--")
        .args(&fixture);
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("memwatch must run");
    assert_eq!(status.code(), Some(0), "the fixture run must exit with 0");

    let run_dir = single_run_dir(&out);
    let report_dir = run_dir.join("report");
    assert!(
        report_dir.join("report.md").is_file(),
        "the run must build the report by itself"
    );
    fs::remove_dir_all(&report_dir).expect("the report directory must be removable");

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report command must exit with 0"
    );

    let path = report_dir.join("report.md");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&path.display().to_string()),
        "stdout must name the report path: {stdout}"
    );
    assert!(path.is_file(), "the report must be rebuilt");
}

#[test]
fn report_command_builds_report_of_stopped_run() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(&out, fixture_command(&["--duration", "60s"]));
    let stop = StopHandle::new();
    let stopper = stop.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        stopper.stop();
    });

    let outcome = memwatch::run(&options, stop).expect("the run must finish");
    assert_eq!(
        outcome.end_reason,
        EndReason::CtrlC,
        "the stop handle must end the run as Ctrl+C"
    );

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report command must exit with 0"
    );

    let report = read_report(&outcome.run_dir);
    assert!(
        report.contains("- **End reason**: ctrl_c"),
        "the report must record the stop:\n{report}"
    );
}

#[test]
fn report_notes_missing_optional_files() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(&out, fixture_command(&["--duration", "3s"]));
    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");

    for file in ["gpu.csv", "cdp.csv"] {
        fs::remove_file(outcome.run_dir.join(file)).expect("the optional file must be removable");
    }

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a run without optional files must still report"
    );

    let report = read_report(&outcome.run_dir);
    assert!(
        report.contains("no data"),
        "missing metrics must be marked:\n{report}"
    );
    for warning in [
        "- no data: missing file gpu.csv",
        "- no data: missing file cdp.csv",
    ] {
        assert!(
            report.contains(warning),
            "the report must contain `{warning}`:\n{report}"
        );
    }
}

#[test]
fn report_rejects_incompatible_schema() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(&out, fixture_command(&["--duration", "3s"]));
    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");

    let meta_path = outcome.run_dir.join("meta.json");
    let mut meta = read_meta(&outcome.run_dir);
    meta["schema_version"] = serde_json::json!(2);
    fs::write(
        &meta_path,
        serde_json::to_vec_pretty(&meta).expect("meta.json must serialize"),
    )
    .expect("meta.json must be writable");

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(1),
        "an incompatible schema must exit with 1"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("schema_version"),
        "the error must name the field: {stderr}"
    );
    assert!(
        stderr.contains('2'),
        "the error must name the found version: {stderr}"
    );
}

#[test]
fn report_bad_arguments_exit_with_two() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let run_dir = dir.path().join("run");

    for args in [["--warmup", "0s"], ["--lang", "de"]] {
        let output = Command::new(MEMWATCH)
            .arg("report")
            .arg(&run_dir)
            .args(args)
            .output()
            .expect("memwatch must run");
        assert_eq!(output.status.code(), Some(2), "`{args:?}` must exit with 2");
    }
}

#[test]
fn report_command_honours_language() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(&out, fixture_command(&["--duration", "3s"]));
    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .args(["--lang", "ru"])
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report command must exit with 0"
    );

    let report = read_report(&outcome.run_dir);
    for expected in [
        "# Прогон",
        "## Предупреждения",
        "## Итоги по дереву",
        "### Весь прогон",
        "### После прогрева",
        "### Общие итоги прогона",
        "## Источники CDP",
        "| Метрика | Старт |",
        "## Роли",
        "## Процессы",
    ] {
        assert!(
            report.contains(expected),
            "the report must contain `{expected}`:\n{report}"
        );
    }
    assert!(
        !report.contains("## Warnings"),
        "the English headings must be gone:\n{report}"
    );
}

#[test]
fn report_omits_command_lines() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let options = fixture_options(
        &out,
        fixture_command(&["--duration", "3s", "--echo-env", "cmdline-secret-marker"]),
    );
    let outcome = memwatch::run(&options, StopHandle::new()).expect("the run must finish");

    let meta = read_meta(&outcome.run_dir);
    assert!(
        meta["command"]
            .to_string()
            .contains("cmdline-secret-marker"),
        "the marker must be recorded in meta.command: {}",
        meta["command"]
    );

    let output = Command::new(MEMWATCH)
        .arg("report")
        .arg(&outcome.run_dir)
        .output()
        .expect("memwatch must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report command must exit with 0"
    );

    let report = read_report(&outcome.run_dir);
    assert!(
        !report.contains("cmdline-secret-marker"),
        "command lines must not leak into the report:\n{report}"
    );
    assert!(
        report.contains("memwatch-fixture.exe"),
        "the executable basename must be listed:\n{report}"
    );
    assert!(
        !report.contains(FIXTURE),
        "only the basename may appear, not the full path:\n{report}"
    );
}

#[test]
fn run_keeps_exit_code_when_report_fails() {
    let dir = TempDir::new().expect("the temporary directory must be created");
    let out = dir.path().join("runs");
    let fixture = fixture_command(&["--duration", "60s"]);

    let mut cmd = Command::new(MEMWATCH);
    cmd.arg("run")
        .arg("--name")
        .arg("auto-fail")
        .arg("--out")
        .arg(&out)
        .arg("--duration")
        .arg("6s")
        .arg("--")
        .args(&fixture);
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("memwatch must start");

    let run_dir = wait_for_run_dir(&out, Duration::from_secs(30));
    fs::write(run_dir.join("report"), "not a directory")
        .expect("the report path must be turned into a file");

    let output = child.wait_with_output().expect("memwatch must be reaped");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a failed report must not change the run outcome"
    );

    assert!(
        !run_dir.join("report").join("report.md").exists(),
        "the report must not be written"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot build the report"),
        "the failure must be reported on stderr: {stderr}"
    );
    let log =
        fs::read_to_string(run_dir.join("memwatch.log")).expect("memwatch.log must be readable");
    assert!(
        log.contains("cannot build the report"),
        "the failure must reach the journal:\n{log}"
    );
}
