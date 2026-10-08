//! Report model, value formats, texts and the Markdown document.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::analyze::{
    CpuStats, MetricId, MetricStats, Run, RunReadError, Series, Summary, Warning, WarningMessage,
    Window, compute_warnings, load, process_series, role_series, summarize,
};
use crate::store::ProcessEvent;

/// One mebibyte in bytes; memory values are shown in these units.
const MIB: f64 = 1_048_576.0;

/// One gibibyte in bytes; the host memory line is shown in these units.
const GIB: f64 = 1_073_741_824.0;

/// Language of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// English.
    En,
    /// Russian.
    Ru,
}

/// Options of one report build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportOptions {
    /// Language of the report.
    pub lang: Lang,
    /// Warmup excluded from growth and hour deltas.
    pub warmup: Duration,
}

/// The report model of a run: header, warnings and table rows.
#[derive(Debug)]
pub struct ReportView {
    /// Run name, or the no-data placeholder without one.
    pub name: String,
    /// Language of the report.
    pub lang: Lang,
    /// Label/value pairs of the header, in report order.
    pub header: Vec<(String, String)>,
    /// Warnings rendered in the report language.
    pub warnings: Vec<String>,
    /// Rows of the summary table.
    pub summary_rows: Vec<Vec<String>>,
    /// Rows of the CPU table.
    pub cpu_rows: Vec<Vec<String>>,
    /// Rows of the role table.
    pub role_rows: Vec<Vec<String>>,
    /// Rows of the process table.
    pub process_rows: Vec<Vec<String>>,
    /// Warmup of the summary in milliseconds.
    pub warmup_ms: u64,
}

/// All report texts of one language.
struct Texts {
    /// Title with the run name.
    title: &'static str,
    /// Heading of the warnings section.
    heading_warnings: &'static str,
    /// Heading of the tree summary section.
    heading_summary: &'static str,
    /// Heading of the roles section.
    heading_roles: &'static str,
    /// Heading of the processes section.
    heading_processes: &'static str,
    /// Text shown when a run has no warnings.
    no_warnings: &'static str,
    /// Cell text of a value without data.
    no_data: &'static str,
    /// Cell text of a median delta of a short run.
    run_too_short: &'static str,
    /// Suffix marking a recovered end time.
    recovered: &'static str,
    /// End reason of a run that did not finish.
    did_not_finish: &'static str,
    /// Text of run labels without any.
    empty_labels: &'static str,
    /// Cell text of a missing identifier or instant.
    dash: &'static str,
    /// Labels of the header fields, in report order.
    header_fields: [&'static str; 11],
    /// Headers of the summary table.
    summary_headers: [&'static str; 11],
    /// Headers of the CPU table.
    cpu_headers: [&'static str; 2],
    /// Headers of the role table.
    role_headers: [&'static str; 4],
    /// Headers of the process table.
    process_headers: [&'static str; 8],
    /// Labels of the CPU table rows.
    cpu_rows: [&'static str; 7],
    /// Suffix marking CPU seconds summed over process rows.
    cpu_seconds_suffix: &'static str,
    /// Unit of memory values.
    memory_unit: &'static str,
    /// Suffix of per-hour growth values.
    per_hour_suffix: &'static str,
    /// Unit of per-hour counter growth.
    count_growth_unit: &'static str,
    /// Unit of CPU seconds.
    seconds_unit: &'static str,
    /// Unit of the host memory value.
    ram_unit: &'static str,
    /// Template of a missing-file warning.
    warning_missing_file: &'static str,
    /// Template of a dropped-rows warning.
    warning_dropped_rows: &'static str,
    /// Template of a non-numeric-cells warning.
    warning_non_numeric_cells: &'static str,
    /// Template of a wall-clock gap warning.
    warning_time_gap: &'static str,
    /// Template of a noisy-machine warning.
    warning_noisy_machine: &'static str,
    /// Template of a collector-status warning.
    warning_collector_status: &'static str,
    /// Text of a tree-walk fallback warning.
    warning_tree_walk_fallback: &'static str,
    /// Template of an unexpected-end-reason warning.
    warning_unexpected_end_reason: &'static str,
    /// Template of a missing meta.json error.
    error_missing_meta: &'static str,
    /// Template of an unreadable meta.json error.
    error_unreadable_meta: &'static str,
    /// Text of a meta.json that is not an object.
    error_meta_not_object: &'static str,
    /// Template of an incompatible schema version error.
    error_incompatible_schema: &'static str,
    /// Template of a missing processes.csv error.
    error_missing_processes: &'static str,
    /// Template of a processes.csv without header error.
    error_processes_without_header: &'static str,
}

/// English report texts.
const EN: Texts = Texts {
    title: "Run {name}",
    heading_warnings: "Warnings",
    heading_summary: "Tree summary",
    heading_roles: "Roles",
    heading_processes: "Processes",
    no_warnings: "No warnings",
    no_data: "no data",
    run_too_short: "run too short",
    recovered: "(recovered)",
    did_not_finish: "did not finish",
    empty_labels: "none",
    dash: "—",
    header_fields: [
        "Name",
        "Labels",
        "Duration",
        "Start",
        "End",
        "End reason",
        "Exit code",
        "Host",
        "Executables",
        "Warmup",
        "Collectors",
    ],
    summary_headers: [
        "Metric",
        "Start",
        "Peak",
        "Mean",
        "p50",
        "p95",
        "End",
        "Δ",
        "Growth",
        "R²",
        "Median delta",
    ],
    cpu_headers: ["Indicator", "Value"],
    role_headers: [
        "Role",
        "Processes",
        "Peak private bytes",
        "Peak working set",
    ],
    process_headers: [
        "Role",
        "Exe",
        "Version",
        "Start",
        "End",
        "Duration",
        "Peak private bytes",
        "Peak working set",
    ],
    cpu_rows: [
        "CPU seconds",
        "CPU % mean",
        "CPU % p50",
        "CPU % p95",
        "Processes started",
        "Processes exited",
        "Processes max concurrent",
    ],
    cpu_seconds_suffix: "(from processes)",
    memory_unit: "MB",
    per_hour_suffix: "/h",
    count_growth_unit: "count/h",
    seconds_unit: "s",
    ram_unit: "GB",
    warning_missing_file: "no data: missing file {file}",
    warning_dropped_rows: "{file}: dropped rows",
    warning_non_numeric_cells: "{file}: non-numeric cells read as empty",
    warning_time_gap: "data gap: {seconds} s",
    warning_noisy_machine: "noisy machine: on average {average} % of outside load",
    warning_collector_status: "collector {name}: {status}",
    warning_tree_walk_fallback: "processes left the job: tree walk enabled",
    warning_unexpected_end_reason: "unexpected end reason: {reason}",
    error_missing_meta: "no meta.json in the run directory {dir}",
    error_unreadable_meta: "cannot read meta.json: {detail}",
    error_meta_not_object: "cannot read meta.json: expected a JSON object",
    error_incompatible_schema: "incompatible schema_version: {version}, expected 1",
    error_missing_processes: "no processes.csv in the run directory {dir}",
    error_processes_without_header: "no header in processes.csv in the run directory {dir}",
};

/// Russian report texts.
const RU: Texts = Texts {
    title: "Прогон {name}",
    heading_warnings: "Предупреждения",
    heading_summary: "Итоги по дереву",
    heading_roles: "Роли",
    heading_processes: "Процессы",
    no_warnings: "Предупреждений нет",
    no_data: "нет данных",
    run_too_short: "прогон слишком короткий",
    recovered: "(восстановлено)",
    did_not_finish: "не завершился",
    empty_labels: "нет",
    dash: "—",
    header_fields: [
        "Имя",
        "Метки",
        "Длительность",
        "Начало",
        "Окончание",
        "Причина завершения",
        "Код выхода",
        "Хост",
        "Версии exe",
        "Прогрев",
        "Сборщики",
    ],
    summary_headers: [
        "Метрика",
        "Старт",
        "Пик",
        "Среднее",
        "p50",
        "p95",
        "Конец",
        "Δ",
        "Рост",
        "R²",
        "Разница медиан",
    ],
    cpu_headers: ["Показатель", "Значение"],
    role_headers: ["Роль", "Процессов", "Пик private bytes", "Пик working set"],
    process_headers: [
        "Роль",
        "Exe",
        "Версия",
        "Начало",
        "Конец",
        "Длительность",
        "Пик private bytes",
        "Пик working set",
    ],
    cpu_rows: [
        "CPU-секунды",
        "CPU % среднее",
        "CPU % p50",
        "CPU % p95",
        "Процессов стартовало",
        "Процессов завершилось",
        "Процессов максимум одновременно",
    ],
    cpu_seconds_suffix: "(по процессам)",
    memory_unit: "МБ",
    per_hour_suffix: "/ч",
    count_growth_unit: "шт./ч",
    seconds_unit: "с",
    ram_unit: "ГБ",
    warning_missing_file: "нет данных: отсутствует файл {file}",
    warning_dropped_rows: "{file}: отброшены строки",
    warning_non_numeric_cells: "{file}: нечисловые ячейки прочитаны как пустые",
    warning_time_gap: "разрыв в данных: {seconds} с",
    warning_noisy_machine: "шумная машина: в среднем {average} % посторонней нагрузки",
    warning_collector_status: "сборщик {name}: {status}",
    warning_tree_walk_fallback: "процессы вышли из job: включён обход дерева",
    warning_unexpected_end_reason: "неожиданная причина завершения: {reason}",
    error_missing_meta: "нет файла meta.json в папке прогона {dir}",
    error_unreadable_meta: "не удалось прочитать meta.json: {detail}",
    error_meta_not_object: "не удалось прочитать meta.json: ожидался объект JSON",
    error_incompatible_schema: "несовместимая schema_version: {version}, ожидается 1",
    error_missing_processes: "нет файла processes.csv в папке прогона {dir}",
    error_processes_without_header: "нет заголовка в processes.csv в папке прогона {dir}",
};

/// Returns the texts of a language.
fn texts(lang: Lang) -> &'static Texts {
    match lang {
        Lang::En => &EN,
        Lang::Ru => &RU,
    }
}

/// Kind of a metric value, selecting its number format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricKind {
    /// A byte count shown in mebibytes.
    Memory,
    /// A plain counter.
    Count,
}

/// Metric id, table label and value kind, in summary table order.
const METRIC_ROWS: [(MetricId, &str, MetricKind); 10] = [
    (MetricId::PrivateBytes, "Private bytes", MetricKind::Memory),
    (MetricId::WorkingSet, "Working set", MetricKind::Memory),
    (
        MetricId::GpuDedicatedBytes,
        "GPU dedicated",
        MetricKind::Memory,
    ),
    (MetricId::GpuSharedBytes, "GPU shared", MetricKind::Memory),
    (MetricId::JsHeapUsedBytes, "JS heap", MetricKind::Memory),
    (MetricId::DomNodes, "DOM nodes", MetricKind::Count),
    (MetricId::Handles, "Handles", MetricKind::Count),
    (MetricId::Gdi, "GDI", MetricKind::Count),
    (MetricId::User, "USER", MetricKind::Count),
    (MetricId::Threads, "Threads", MetricKind::Count),
];

/// Builds the report model of a run from its summary.
pub fn build(run: &Run, summary: &Summary, lang: Lang) -> ReportView {
    let texts = texts(lang);
    let name = if run.meta.name.is_empty() {
        texts.no_data.to_string()
    } else {
        run.meta.name.clone()
    };
    ReportView {
        name: name.clone(),
        lang,
        header: header(run, summary, &name, texts),
        warnings: compute_warnings(run, summary)
            .iter()
            .map(|warning| warning_text(warning, lang))
            .collect(),
        summary_rows: summary_rows(summary, texts),
        cpu_rows: cpu_rows(summary, texts),
        role_rows: role_rows(run, texts),
        process_rows: process_rows(run, texts),
        warmup_ms: summary.warmup_ms,
    }
}

/// Formats a duration as `M:SS` below an hour and `H:MM:SS` from an hour.
pub fn format_duration_ms(ms: u64) -> String {
    let seconds = ms / 1000;
    let minutes = seconds / 60;
    let seconds = seconds % 60;
    let hours = minutes / 60;
    let minutes = minutes % 60;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// Renders the report model as a Markdown document.
pub fn render(view: &ReportView) -> String {
    let texts = texts(view.lang);
    let mut lines = vec![
        format!("# {}", fill(texts.title, &[("name", &view.name)])),
        String::new(),
    ];
    lines.extend(
        view.header
            .iter()
            .map(|(label, value)| format!("- **{label}**: {value}")),
    );
    lines.push(String::new());
    lines.push(format!("## {}", texts.heading_warnings));
    lines.push(String::new());
    if view.warnings.is_empty() {
        lines.push(texts.no_warnings.to_string());
    } else {
        lines.extend(view.warnings.iter().map(|message| format!("- {message}")));
    }
    lines.push(String::new());
    lines.push(format!("## {}", texts.heading_summary));
    lines.push(String::new());
    lines.extend(table(&texts.summary_headers, &view.summary_rows));
    lines.push(String::new());
    lines.extend(table(&texts.cpu_headers, &view.cpu_rows));
    lines.push(String::new());
    lines.push(format!("## {}", texts.heading_roles));
    lines.push(String::new());
    lines.extend(table(&texts.role_headers, &view.role_rows));
    lines.push(String::new());
    lines.push(format!("## {}", texts.heading_processes));
    lines.push(String::new());
    lines.extend(table(&texts.process_headers, &view.process_rows));
    lines.push(String::new());
    lines.join("\n")
}

/// Renders a Markdown table with a header row and a separator row.
fn table(headers: &[&str], rows: &[Vec<String>]) -> Vec<String> {
    let mut lines = vec![
        format!("| {} |", headers.join(" | ")),
        format!("| {} |", vec!["---"; headers.len()].join(" | ")),
    ];
    lines.extend(rows.iter().map(|row| format!("| {} |", row.join(" | "))));
    lines
}

/// Builds the report of a recorded run and writes it as a Markdown file.
pub fn write(run_dir: &Path, options: &ReportOptions, out: Option<&Path>) -> io::Result<PathBuf> {
    let run = load(run_dir)
        .map_err(|err| io::Error::other(read_error_text(&err, run_dir, options.lang)))?;
    let summary = summarize(
        &run,
        Window {
            start_ms: 0,
            end_ms: run.duration_ms(),
        },
        options.warmup.as_millis() as u64,
    );
    let view = build(&run, &summary, options.lang);
    let out_dir = out.map_or_else(|| run_dir.join("report"), |path| path.to_path_buf());
    fs::create_dir_all(&out_dir)?;
    let path = out_dir.join("report.md");
    fs::write(&path, render(&view))?;
    Ok(path)
}

/// Renders one warning in the given language.
fn warning_text(warning: &Warning, lang: Lang) -> String {
    let texts = texts(lang);
    match &warning.message {
        WarningMessage::MissingFile { file } => fill(texts.warning_missing_file, &[("file", file)]),
        WarningMessage::DroppedRows { file } => fill(texts.warning_dropped_rows, &[("file", file)]),
        WarningMessage::NonNumericCells { file } => {
            fill(texts.warning_non_numeric_cells, &[("file", file)])
        }
        WarningMessage::TimeGap { gap_ms } => {
            let seconds = format!("{:.1}", *gap_ms as f64 / 1000.0);
            fill(texts.warning_time_gap, &[("seconds", &seconds)])
        }
        WarningMessage::NoisyMachine { average_pct } => {
            let average = format!("{average_pct:.1}");
            fill(texts.warning_noisy_machine, &[("average", &average)])
        }
        WarningMessage::CollectorStatus { name, status } => {
            let status = status.to_string();
            fill(
                texts.warning_collector_status,
                &[("name", name), ("status", &status)],
            )
        }
        WarningMessage::TreeWalkFallback => texts.warning_tree_walk_fallback.to_string(),
        WarningMessage::DidNotFinish => texts.did_not_finish.to_string(),
        WarningMessage::UnexpectedEndReason { reason } => {
            let reason = reason.to_string();
            fill(texts.warning_unexpected_end_reason, &[("reason", &reason)])
        }
    }
}

/// Renders one run read error in the given language.
fn read_error_text(err: &RunReadError, run_dir: &Path, lang: Lang) -> String {
    let texts = texts(lang);
    let dir = run_dir.display().to_string();
    match err {
        RunReadError::MissingMeta => fill(texts.error_missing_meta, &[("dir", &dir)]),
        RunReadError::UnreadableMeta { detail } => {
            fill(texts.error_unreadable_meta, &[("detail", detail)])
        }
        RunReadError::MetaNotObject => texts.error_meta_not_object.to_string(),
        RunReadError::IncompatibleSchema { version } => {
            fill(texts.error_incompatible_schema, &[("version", version)])
        }
        RunReadError::MissingProcesses => fill(texts.error_missing_processes, &[("dir", &dir)]),
        RunReadError::ProcessesWithoutHeader => {
            fill(texts.error_processes_without_header, &[("dir", &dir)])
        }
    }
}

/// Replaces every `{key}` placeholder of the template with its value.
fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut text = template.to_string();
    for (key, value) in values {
        text = text.replace(&format!("{{{key}}}"), value);
    }
    text
}

/// Builds the label/value header fields in report order.
fn header(run: &Run, summary: &Summary, name: &str, texts: &Texts) -> Vec<(String, String)> {
    vec![
        (texts.header_fields[0].to_string(), name.to_string()),
        (texts.header_fields[1].to_string(), labels_value(run, texts)),
        (
            texts.header_fields[2].to_string(),
            format_duration_ms(run.duration_ms()),
        ),
        (
            texts.header_fields[3].to_string(),
            text_or(&run.meta.started_at, texts),
        ),
        (
            texts.header_fields[4].to_string(),
            ended_at_value(run, texts),
        ),
        (
            texts.header_fields[5].to_string(),
            end_reason_value(run, texts),
        ),
        (
            texts.header_fields[6].to_string(),
            exit_code_value(run, texts),
        ),
        (texts.header_fields[7].to_string(), host_value(run, texts)),
        (texts.header_fields[8].to_string(), images_value(run, texts)),
        (
            texts.header_fields[9].to_string(),
            format_duration_ms(summary.warmup_ms),
        ),
        (
            texts.header_fields[10].to_string(),
            collectors_value(run, texts),
        ),
    ]
}

/// Returns a non-empty text, or the no-data placeholder.
fn text_or(value: &str, texts: &Texts) -> String {
    if value.is_empty() {
        texts.no_data.to_string()
    } else {
        value.to_string()
    }
}

/// Formats the run end time, marking a recovered one.
fn ended_at_value(run: &Run, texts: &Texts) -> String {
    match &run.ended_at {
        None => texts.no_data.to_string(),
        Some(ended_at) if run.ended_at_recovered => format!("{ended_at} {}", texts.recovered),
        Some(ended_at) => ended_at.clone(),
    }
}

/// Formats the end reason, naming a missing one.
fn end_reason_value(run: &Run, texts: &Texts) -> String {
    match run.meta.end_reason {
        Some(reason) => reason.to_string(),
        None => texts.did_not_finish.to_string(),
    }
}

/// Formats the exit code of the main process, or a dash without one.
fn exit_code_value(run: &Run, texts: &Texts) -> String {
    match run.meta.exit_code {
        Some(code) => code.to_string(),
        None => texts.dash.to_string(),
    }
}

/// Formats run labels as `key=value` pairs, or the empty-labels placeholder.
fn labels_value(run: &Run, texts: &Texts) -> String {
    if run.meta.labels.is_empty() {
        return texts.empty_labels.to_string();
    }
    run.meta
        .labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<String>>()
        .join(", ")
}

/// Formats collector statuses as `name: status` pairs, or no data.
fn collectors_value(run: &Run, texts: &Texts) -> String {
    if run.meta.collectors.is_empty() {
        return texts.no_data.to_string();
    }
    run.meta
        .collectors
        .iter()
        .map(|(name, status)| format!("{name}: {status}"))
        .collect::<Vec<String>>()
        .join(", ")
}

/// Formats the host line as OS, CPU, logical CPU count, RAM and GPUs.
fn host_value(run: &Run, texts: &Texts) -> String {
    let host = &run.meta.host;
    let cpus = format!("{} CPU", host.logical_cpus);
    let ram = format!("{:.1} {}", host.ram_bytes as f64 / GIB, texts.ram_unit);
    let gpus = if host.gpus.is_empty() {
        texts.no_data.to_string()
    } else {
        host.gpus.join(", ")
    };
    format!(
        "{}; {}; {}; {}; {}",
        text_or(&host.os, texts),
        text_or(&host.cpu, texts),
        cpus,
        ram,
        gpus
    )
}

/// Formats the executables of the run as `name version` pairs.
fn images_value(run: &Run, texts: &Texts) -> String {
    if run.images.is_empty() {
        return texts.no_data.to_string();
    }
    run.images
        .iter()
        .map(|image| {
            let version = image.version.as_deref().unwrap_or(texts.dash);
            format!("{} {}", exe_name(Some(&image.path), texts), version)
        })
        .collect::<Vec<String>>()
        .join("; ")
}

/// Builds the metric table rows in the fixed metric order.
fn summary_rows(summary: &Summary, texts: &Texts) -> Vec<Vec<String>> {
    METRIC_ROWS
        .iter()
        .map(|(metric, label, kind)| {
            let stats = &summary.metrics[metric];
            vec![
                (*label).to_string(),
                metric_value(stats.start, *kind, texts),
                metric_value(stats.peak, *kind, texts),
                metric_value(stats.mean, *kind, texts),
                metric_value(stats.p50, *kind, texts),
                metric_value(stats.p95, *kind, texts),
                metric_value(stats.end, *kind, texts),
                metric_value(stats.delta, *kind, texts),
                stats.growth_per_hour.map_or_else(
                    || texts.no_data.to_string(),
                    |value| fmt_growth(value, *kind, texts),
                ),
                fit_value(stats.r2, texts),
                median_value(stats, *kind, summary.too_short_for_hour_delta, texts),
            ]
        })
        .collect()
}

/// Formats one metric cell of its kind, or the no-data placeholder.
fn metric_value(value: Option<f64>, kind: MetricKind, texts: &Texts) -> String {
    match value {
        Some(value) => match kind {
            MetricKind::Memory => fmt_memory(value, texts),
            MetricKind::Count => fmt_count(value),
        },
        None => texts.no_data.to_string(),
    }
}

/// Formats an R² value, or the no-data placeholder.
fn fit_value(value: Option<f64>, texts: &Texts) -> String {
    value.map_or_else(|| texts.no_data.to_string(), fmt_r2)
}

/// Formats the median hour delta, naming a short run and missing data.
fn median_value(stats: &MetricStats, kind: MetricKind, too_short: bool, texts: &Texts) -> String {
    if let Some(delta) = stats.median_hour_delta {
        return metric_value(Some(delta), kind, texts);
    }
    if too_short && stats.samples > 0 {
        texts.run_too_short.to_string()
    } else {
        texts.no_data.to_string()
    }
}

/// Builds the CPU and process counter table rows.
fn cpu_rows(summary: &Summary, texts: &Texts) -> Vec<Vec<String>> {
    let cpu = &summary.cpu;
    let processes = &summary.processes;
    vec![
        vec![texts.cpu_rows[0].to_string(), cpu_seconds_value(cpu, texts)],
        vec![
            texts.cpu_rows[1].to_string(),
            percent_value(cpu.mean_pct, texts),
        ],
        vec![
            texts.cpu_rows[2].to_string(),
            percent_value(cpu.p50_pct, texts),
        ],
        vec![
            texts.cpu_rows[3].to_string(),
            percent_value(cpu.p95_pct, texts),
        ],
        vec![texts.cpu_rows[4].to_string(), processes.started.to_string()],
        vec![texts.cpu_rows[5].to_string(), processes.exited.to_string()],
        vec![
            texts.cpu_rows[6].to_string(),
            processes.max_concurrent.to_string(),
        ],
    ]
}

/// Formats total CPU seconds, marking a value summed over process rows.
fn cpu_seconds_value(cpu: &CpuStats, texts: &Texts) -> String {
    let Some(seconds) = cpu.total_seconds else {
        return texts.no_data.to_string();
    };
    let text = fmt_seconds(seconds, texts);
    if cpu.from_process_rows {
        format!("{text} {}", texts.cpu_seconds_suffix)
    } else {
        text
    }
}

/// Formats a percentage, or the no-data placeholder.
fn percent_value(value: Option<f64>, texts: &Texts) -> String {
    value.map_or_else(|| texts.no_data.to_string(), fmt_percent)
}

/// Builds the role table rows in alphabetical order.
fn role_rows(run: &Run, texts: &Texts) -> Vec<Vec<String>> {
    let private = role_series(run, |sample| sample.private_bytes);
    let working = role_series(run, |sample| sample.working_set);
    let counts = role_start_counts(run);
    let mut roles: BTreeSet<String> = BTreeSet::new();
    for series in private.iter().chain(working.iter()) {
        roles.insert(series.name.clone());
    }
    roles.extend(counts.keys().cloned());
    roles
        .into_iter()
        .map(|role| {
            vec![
                role.clone(),
                counts.get(&role).copied().unwrap_or(0).to_string(),
                peak_value(find_series(&private, &role), texts),
                peak_value(find_series(&working, &role), texts),
            ]
        })
        .collect()
}

/// Counts the `start` events of every role.
fn role_start_counts(run: &Run) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for event in &run.events {
        if event.event != Some(ProcessEvent::Start) {
            continue;
        }
        if let Some(role) = &event.role
            && !role.is_empty()
        {
            *counts.entry(role.clone()).or_default() += 1;
        }
    }
    counts
}

/// Finds a series by name.
fn find_series<'a>(series: &'a [Series], name: &str) -> Option<&'a Series> {
    series.iter().find(|series| series.name == name)
}

/// Formats the greatest present value of a series in memory units, or no data.
fn peak_value(series: Option<&Series>, texts: &Texts) -> String {
    let Some(series) = series else {
        return texts.no_data.to_string();
    };
    let peak = series.values.iter().flatten().copied().reduce(f64::max);
    match peak {
        Some(value) => fmt_memory(value, texts),
        None => texts.no_data.to_string(),
    }
}

/// Builds one process table row per `proc_key` in start event order.
fn process_rows(run: &Run, texts: &Texts) -> Vec<Vec<String>> {
    let private = process_series(run, |sample| sample.private_bytes);
    let working = process_series(run, |sample| sample.working_set);
    let exits = exit_ticks(run);
    let last_ticks = last_ticks(run);
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    for event in &run.events {
        if event.event != Some(ProcessEvent::Start) {
            continue;
        }
        let Some(key) = event.proc_key.as_deref() else {
            continue;
        };
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        let start_ms = Some(event.t_ms);
        let end_ms = exits
            .get(key)
            .copied()
            .or_else(|| last_ticks.get(key).copied());
        rows.push(vec![
            event
                .role
                .as_deref()
                .map_or_else(|| texts.dash.to_string(), str::to_string),
            exe_name(event.image_path.as_deref(), texts),
            event
                .image_version
                .as_deref()
                .map_or_else(|| texts.dash.to_string(), str::to_string),
            duration_value(start_ms, texts),
            duration_value(end_ms, texts),
            elapsed_value(start_ms, end_ms, texts),
            peak_value(find_series(&private, key), texts),
            peak_value(find_series(&working, key), texts),
        ]);
    }
    rows
}

/// Maps every `proc_key` to its latest `exit` tick.
fn exit_ticks(run: &Run) -> BTreeMap<String, u64> {
    let mut exits: BTreeMap<String, u64> = BTreeMap::new();
    for event in &run.events {
        if event.event != Some(ProcessEvent::Exit) {
            continue;
        }
        let Some(key) = &event.proc_key else {
            continue;
        };
        exits
            .entry(key.clone())
            .and_modify(|tick| *tick = (*tick).max(event.t_ms))
            .or_insert(event.t_ms);
    }
    exits
}

/// Maps every `proc_key` to its latest `process.csv` tick.
fn last_ticks(run: &Run) -> BTreeMap<String, u64> {
    let mut ticks: BTreeMap<String, u64> = BTreeMap::new();
    for sample in &run.processes {
        let Some(key) = &sample.proc_key else {
            continue;
        };
        ticks
            .entry(key.clone())
            .and_modify(|tick| *tick = (*tick).max(sample.t_ms))
            .or_insert(sample.t_ms);
    }
    ticks
}

/// Formats an instant as a duration from the run start, or a dash.
fn duration_value(ms: Option<u64>, texts: &Texts) -> String {
    ms.map_or_else(|| texts.dash.to_string(), format_duration_ms)
}

/// Formats the time between two instants, or a dash without both.
fn elapsed_value(start_ms: Option<u64>, end_ms: Option<u64>, texts: &Texts) -> String {
    match (start_ms, end_ms) {
        (Some(start_ms), Some(end_ms)) => format_duration_ms(end_ms.saturating_sub(start_ms)),
        _ => texts.dash.to_string(),
    }
}

/// Returns the file name of an executable path, or a dash without one.
fn exe_name(path: Option<&str>, texts: &Texts) -> String {
    match path {
        Some(path) if !path.is_empty() => {
            path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
        }
        _ => texts.dash.to_string(),
    }
}

/// Formats a byte count in memory units with one decimal.
fn fmt_memory(value: f64, texts: &Texts) -> String {
    format!("{:.1} {}", value / MIB, texts.memory_unit)
}

/// Formats a per-hour growth value of its kind.
fn fmt_growth(value: f64, kind: MetricKind, texts: &Texts) -> String {
    match kind {
        MetricKind::Memory => format!("{}{}", fmt_memory(value, texts), texts.per_hour_suffix),
        MetricKind::Count => format!("{} {}", fmt_count(value), texts.count_growth_unit),
    }
}

/// Formats a counter without decimals.
fn fmt_count(value: f64) -> String {
    format!("{value:.0}")
}

/// Formats a percentage with two decimals.
fn fmt_percent(value: f64) -> String {
    format!("{value:.2}")
}

/// Formats an R² value with two decimals.
fn fmt_r2(value: f64) -> String {
    format!("{value:.2}")
}

/// Formats CPU seconds with one decimal.
fn fmt_seconds(value: f64, texts: &Texts) -> String {
    format!("{:.1} {}", value, texts.seconds_unit)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;
    use crate::analyze::fixtures;
    use crate::analyze::{
        Event, ProcessSample, Run, RunReadError, Summary, Warning, WarningKind, WarningMessage,
        Window, load, summarize,
    };
    use crate::meta::{CollectorStatus, EndReason};
    use crate::store::ProcessEvent;

    /// Summarizes a run over its full window without warmup.
    fn summary_of(run: &Run) -> Summary {
        summarize(
            run,
            Window {
                start_ms: 0,
                end_ms: run.duration_ms(),
            },
            0,
        )
    }

    /// Builds and renders the document of a run without warmup.
    fn document_of(run: &Run, lang: Lang) -> String {
        render(&build(run, &summary_of(run), lang))
    }

    /// Returns report options of a language without warmup.
    fn options(lang: Lang) -> ReportOptions {
        ReportOptions {
            lang,
            warmup: Duration::ZERO,
        }
    }

    /// Returns the value of the `End` header field.
    fn end_field(view: &ReportView) -> &str {
        &view.header[4].1
    }

    /// Maps the summary rows by their metric label.
    fn rows_by_label(view: &ReportView) -> BTreeMap<&str, &Vec<String>> {
        view.summary_rows
            .iter()
            .map(|row| (row[0].as_str(), row))
            .collect()
    }

    /// Builds a process sample with only the memory values set.
    fn memory_row(
        t_ms: u64,
        proc_key: &str,
        role: &str,
        private_bytes: f64,
        working_set: f64,
    ) -> ProcessSample {
        ProcessSample {
            t_ms,
            unix_ms: t_ms,
            proc_key: Some(proc_key.to_string()),
            role: Some(role.to_string()),
            private_bytes: Some(private_bytes),
            working_set: Some(working_set),
            cpu_user_ms: None,
            cpu_kernel_ms: None,
            cpu_pct: None,
            handles: None,
            gdi: None,
            user: None,
            threads: None,
        }
    }

    /// Builds a `start` event.
    fn start_event(
        t_ms: u64,
        proc_key: &str,
        role: &str,
        image_path: &str,
        image_version: Option<&str>,
    ) -> Event {
        Event {
            t_ms,
            unix_ms: t_ms,
            event: Some(ProcessEvent::Start),
            proc_key: Some(proc_key.to_string()),
            role: Some(role.to_string()),
            image_path: Some(image_path.to_string()),
            image_version: image_version.map(str::to_string),
        }
    }

    /// Builds an `exit` event.
    fn exit_event(t_ms: u64, proc_key: &str, role: &str) -> Event {
        Event {
            t_ms,
            unix_ms: t_ms,
            event: Some(ProcessEvent::Exit),
            proc_key: Some(proc_key.to_string()),
            role: Some(role.to_string()),
            image_path: None,
            image_version: None,
        }
    }

    /// Returns a run with the events and process rows of the role tests.
    fn role_process_run() -> Run {
        let mut run = fixtures::empty_run();
        run.events = vec![
            start_event(0, "100-1000", "main", r"C:\app\main.exe", Some("1.0.0.0")),
            start_event(0, "200-2000", "renderer", r"C:\app\renderer.exe", None),
            exit_event(60_000, "100-1000", "main"),
        ];
        run.processes = vec![
            memory_row(0, "100-1000", "main", 1_048_576.0, 2_097_152.0),
            memory_row(30_000, "100-1000", "main", 2_097_152.0, 3_145_728.0),
            memory_row(60_000, "100-1000", "main", 1_048_576.0, 2_097_152.0),
            memory_row(0, "200-2000", "renderer", 524_288.0, 1_048_576.0),
        ];
        run
    }

    #[test]
    fn view_marks_missing_metrics_with_no_data() {
        let mut run = fixtures::empty_run();
        run.processes = vec![
            memory_row(0, "100-1000", "main", 1_048_576.0, 2_097_152.0),
            memory_row(60_000, "100-1000", "main", 3_145_728.0, 4_194_304.0),
        ];

        let view = build(&run, &summary_of(&run), Lang::En);

        let rows = rows_by_label(&view);
        for label in ["GPU dedicated", "GPU shared", "JS heap", "DOM nodes"] {
            assert_eq!(rows[label][1..], ["no data"; 10], "{label}");
        }
        assert_eq!(rows["Private bytes"][1], "1.0 MB");
        assert_eq!(rows["Private bytes"][10], "run too short");
    }

    #[test]
    fn view_formats_russian_values() {
        let run = role_process_run();

        let view = build(&run, &summary_of(&run), Lang::Ru);

        let rows = rows_by_label(&view);
        for label in ["GPU dedicated", "GPU shared", "JS heap", "DOM nodes"] {
            assert_eq!(rows[label][1..], ["нет данных"; 10], "{label}");
        }
        assert_eq!(rows["Private bytes"][10], "прогон слишком короткий");
        assert_eq!(rows["Working set"][10], "прогон слишком короткий");
        assert_eq!(
            view.role_rows,
            vec![
                vec!["main", "1", "2.0 МБ", "3.0 МБ"],
                vec!["renderer", "1", "0.5 МБ", "1.0 МБ"],
            ]
        );
        assert_eq!(
            view.process_rows,
            vec![
                vec![
                    "main", "main.exe", "1.0.0.0", "0:00", "1:00", "1:00", "2.0 МБ", "3.0 МБ"
                ],
                vec![
                    "renderer",
                    "renderer.exe",
                    "—",
                    "0:00",
                    "0:00",
                    "0:00",
                    "0.5 МБ",
                    "1.0 МБ"
                ],
            ]
        );
    }

    #[test]
    fn view_lists_warnings() {
        let run = fixtures::empty_run();
        assert_eq!(
            build(&run, &summary_of(&run), Lang::En).warnings,
            Vec::<String>::new()
        );

        let mut run = fixtures::empty_run();
        run.warnings = vec![Warning {
            kind: WarningKind::NoData,
            message: WarningMessage::MissingFile {
                file: "gpu.csv".to_string(),
            },
        }];

        assert_eq!(
            build(&run, &summary_of(&run), Lang::En).warnings,
            ["no data: missing file gpu.csv"]
        );
    }

    #[test]
    fn view_does_not_show_image_paths() {
        let mut run = fixtures::empty_run();
        run.events = vec![start_event(
            0,
            "100-1000",
            "main",
            r"C:\app\main.exe",
            Some("1.0.0.0"),
        )];

        let view = build(&run, &summary_of(&run), Lang::En);

        let header: BTreeMap<&str, &str> = view
            .header
            .iter()
            .map(|(label, value)| (label.as_str(), value.as_str()))
            .collect();
        assert!(header["Executables"].contains("main.exe"));
        assert!(!header["Executables"].contains(r"C:\app"));
        assert_eq!(view.process_rows[0][1], "main.exe");
        assert!(
            view.process_rows.iter().all(|row| !row[1].contains('\\')),
            "no process row must show a full path"
        );
    }

    #[test]
    fn view_formats_durations() {
        assert_eq!(format_duration_ms(65_000), "1:05");
        assert_eq!(format_duration_ms(3_661_000), "1:01:01");
    }

    #[test]
    fn view_reports_recovered_end_time() {
        let mut run = fixtures::empty_run();
        run.ended_at_recovered = true;

        let en = build(&run, &summary_of(&run), Lang::En);
        let ru = build(&run, &summary_of(&run), Lang::Ru);

        assert_eq!(end_field(&en), "2026-10-07T16:06:09+03:00 (recovered)");
        assert_eq!(end_field(&ru), "2026-10-07T16:06:09+03:00 (восстановлено)");
    }

    #[test]
    fn view_summary_rows_follow_metric_order() {
        let run = fixtures::empty_run();

        let view = build(&run, &summary_of(&run), Lang::En);

        let labels: Vec<&str> = view
            .summary_rows
            .iter()
            .map(|row| row[0].as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "Private bytes",
                "Working set",
                "GPU dedicated",
                "GPU shared",
                "JS heap",
                "DOM nodes",
                "Handles",
                "GDI",
                "USER",
                "Threads",
            ]
        );
        assert_eq!(view.summary_rows[0][0], "Private bytes");
        assert_eq!(view.summary_rows[9][0], "Threads");
        assert!(
            view.summary_rows.iter().all(|row| row.len() == 11),
            "every summary row must have eleven cells"
        );
    }

    #[test]
    fn view_builds_role_and_process_rows() {
        let run = role_process_run();

        let view = build(&run, &summary_of(&run), Lang::En);

        assert_eq!(
            view.role_rows,
            vec![
                vec!["main", "1", "2.0 MB", "3.0 MB"],
                vec!["renderer", "1", "0.5 MB", "1.0 MB"],
            ]
        );
        assert_eq!(
            view.process_rows,
            vec![
                vec![
                    "main", "main.exe", "1.0.0.0", "0:00", "1:00", "1:00", "2.0 MB", "3.0 MB"
                ],
                vec![
                    "renderer",
                    "renderer.exe",
                    "—",
                    "0:00",
                    "0:00",
                    "0:00",
                    "0.5 MB",
                    "1.0 MB"
                ],
            ]
        );
    }

    #[test]
    fn view_header_lists_fields_in_order() {
        let run = fixtures::empty_run();

        let view = build(&run, &summary_of(&run), Lang::En);

        let labels: Vec<&str> = view
            .header
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "Name",
                "Labels",
                "Duration",
                "Start",
                "End",
                "End reason",
                "Exit code",
                "Host",
                "Executables",
                "Warmup",
                "Collectors",
            ]
        );
        let header: BTreeMap<&str, &str> = view
            .header
            .iter()
            .map(|(label, value)| (label.as_str(), value.as_str()))
            .collect();
        assert_eq!(header["Name"], "synthetic");
        assert_eq!(header["Labels"], "branch=test");
        assert_eq!(
            header["Host"],
            "Windows 11 Pro 23H2 (build 22631.4317); Test CPU; 8 CPU; 16.0 GB; Test GPU"
        );
    }

    #[test]
    fn warning_messages_are_bilingual() {
        let cases = [
            (
                WarningKind::NoData,
                WarningMessage::MissingFile {
                    file: "gpu.csv".to_string(),
                },
                "no data: missing file gpu.csv",
                "нет данных: отсутствует файл gpu.csv",
            ),
            (
                WarningKind::DroppedRow,
                WarningMessage::DroppedRows {
                    file: "process.csv".to_string(),
                },
                "process.csv: dropped rows",
                "process.csv: отброшены строки",
            ),
            (
                WarningKind::NonNumeric,
                WarningMessage::NonNumericCells {
                    file: "process.csv".to_string(),
                },
                "process.csv: non-numeric cells read as empty",
                "process.csv: нечисловые ячейки прочитаны как пустые",
            ),
            (
                WarningKind::TimeGap,
                WarningMessage::TimeGap { gap_ms: 6000 },
                "data gap: 6.0 s",
                "разрыв в данных: 6.0 с",
            ),
            (
                WarningKind::NoisyMachine,
                WarningMessage::NoisyMachine { average_pct: 35.0 },
                "noisy machine: on average 35.0 % of outside load",
                "шумная машина: в среднем 35.0 % посторонней нагрузки",
            ),
            (
                WarningKind::CollectorStatus,
                WarningMessage::CollectorStatus {
                    name: "gpu".to_string(),
                    status: CollectorStatus::Unavailable,
                },
                "collector gpu: unavailable",
                "сборщик gpu: unavailable",
            ),
            (
                WarningKind::TreeWalkFallback,
                WarningMessage::TreeWalkFallback,
                "processes left the job: tree walk enabled",
                "процессы вышли из job: включён обход дерева",
            ),
            (
                WarningKind::UnexpectedEndReason,
                WarningMessage::DidNotFinish,
                "did not finish",
                "не завершился",
            ),
            (
                WarningKind::UnexpectedEndReason,
                WarningMessage::UnexpectedEndReason {
                    reason: EndReason::LaunchFailed,
                },
                "unexpected end reason: launch_failed",
                "неожиданная причина завершения: launch_failed",
            ),
        ];
        for (kind, message, en, ru) in cases {
            let warning = Warning { kind, message };
            assert_eq!(warning_text(&warning, Lang::En), en);
            assert_eq!(warning_text(&warning, Lang::Ru), ru);
        }
    }

    #[test]
    fn read_error_messages_are_bilingual() {
        let run_dir = Path::new("run-dir");
        let cases = [
            (
                RunReadError::MissingMeta,
                "no meta.json in the run directory run-dir",
                "нет файла meta.json в папке прогона run-dir",
            ),
            (
                RunReadError::UnreadableMeta {
                    detail: "x".to_string(),
                },
                "cannot read meta.json: x",
                "не удалось прочитать meta.json: x",
            ),
            (
                RunReadError::MetaNotObject,
                "cannot read meta.json: expected a JSON object",
                "не удалось прочитать meta.json: ожидался объект JSON",
            ),
            (
                RunReadError::IncompatibleSchema {
                    version: "2".to_string(),
                },
                "incompatible schema_version: 2, expected 1",
                "несовместимая schema_version: 2, ожидается 1",
            ),
            (
                RunReadError::MissingProcesses,
                "no processes.csv in the run directory run-dir",
                "нет файла processes.csv в папке прогона run-dir",
            ),
            (
                RunReadError::ProcessesWithoutHeader,
                "no header in processes.csv in the run directory run-dir",
                "нет заголовка в processes.csv в папке прогона run-dir",
            ),
        ];
        for (err, en, ru) in cases {
            assert_eq!(read_error_text(&err, run_dir, Lang::En), en);
            assert_eq!(read_error_text(&err, run_dir, Lang::Ru), ru);
        }
    }

    #[test]
    fn render_contains_header_warnings_and_tables() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run = load(&fixtures::write_run(dir.path())).expect("the synthetic run must load");

        let document = document_of(&run, Lang::En);

        for expected in [
            "# Run synthetic",
            "- **Name**: synthetic",
            "## Warnings",
            "No warnings",
            "## Tree summary",
            "| Metric | Start |",
            "| Private bytes |",
            "## Roles",
            "| main |",
            "## Processes",
            "| Role | Exe | Version |",
        ] {
            assert!(document.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn render_uses_russian_texts() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run = load(&fixtures::write_run(dir.path())).expect("the synthetic run must load");

        let document = document_of(&run, Lang::Ru);

        for expected in [
            "# Прогон synthetic",
            "## Предупреждения",
            "Предупреждений нет",
            "## Итоги по дереву",
            "| Метрика | Старт |",
            "| Показатель | Значение |",
            "## Роли",
            "## Процессы",
        ] {
            assert!(document.contains(expected), "missing {expected}");
        }
        for absent in [
            "## Warnings",
            "## Tree summary",
            "## Roles",
            "## Processes",
            "No warnings",
        ] {
            assert!(!document.contains(absent), "unexpected {absent}");
        }
    }

    #[test]
    fn render_marks_missing_metrics_with_no_data() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        fs::remove_file(run_dir.join("gpu.csv")).expect("gpu.csv must be removed");
        fs::remove_file(run_dir.join("cdp.csv")).expect("cdp.csv must be removed");
        let run = load(&run_dir).expect("the run without optional files must load");

        let document = document_of(&run, Lang::En);

        assert!(document.contains("| GPU dedicated | no data |"));
        assert!(document.contains("| JS heap | no data |"));
    }

    #[test]
    fn render_lists_warnings() {
        let mut run = fixtures::empty_run();
        run.warnings = vec![Warning {
            kind: WarningKind::NoData,
            message: WarningMessage::MissingFile {
                file: "gpu.csv".to_string(),
            },
        }];

        assert!(document_of(&run, Lang::En).contains("- no data: missing file gpu.csv"));

        let run = fixtures::empty_run();
        assert!(document_of(&run, Lang::En).contains("No warnings"));
    }

    #[test]
    fn render_omits_command_lines() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run = load(&fixtures::write_run(dir.path())).expect("the synthetic run must load");

        let document = document_of(&run, Lang::En);

        assert!(!document.contains(fixtures::CMDLINE_MARKER));
    }

    #[test]
    fn write_defaults_to_run_report_directory() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());

        let path = write(&run_dir, &options(Lang::En), None).expect("the report must be written");

        assert_eq!(path, run_dir.join("report").join("report.md"));
        let document = fs::read_to_string(&path).expect("the report must be readable");
        assert!(document.starts_with("# Run"));
    }

    #[test]
    fn write_honours_out_directory() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        let out = dir.path().join("out");

        let path =
            write(&run_dir, &options(Lang::En), Some(&out)).expect("the report must be written");

        assert_eq!(path, out.join("report.md"));
        assert!(path.is_file());
        assert!(!run_dir.join("report").exists());
    }

    #[test]
    fn write_overwrites_existing_report() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        let report_dir = run_dir.join("report");
        fs::create_dir_all(&report_dir).expect("the report directory must be created");
        let path = report_dir.join("report.md");
        fs::write(&path, "stale").expect("the stale report must be written");

        write(&run_dir, &options(Lang::En), None).expect("the report must be written");

        let run = load(&run_dir).expect("the synthetic run must load");
        assert_eq!(
            fs::read_to_string(&path).expect("the report must be readable"),
            document_of(&run, Lang::En)
        );
    }

    #[test]
    fn write_fails_when_out_is_a_file() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        let out = dir.path().join("out");
        fs::write(&out, "not a directory").expect("the out file must be written");

        assert!(write(&run_dir, &options(Lang::En), Some(&out)).is_err());
    }

    #[test]
    fn write_localises_read_errors() {
        let dir = TempDir::new().expect("a temporary directory must be created");

        let en = write(dir.path(), &options(Lang::En), None).expect_err("meta.json is missing");
        assert!(en.to_string().contains("no meta.json"));

        let ru = write(dir.path(), &options(Lang::Ru), None).expect_err("meta.json is missing");
        assert!(ru.to_string().contains("нет файла meta.json"));
    }
}
