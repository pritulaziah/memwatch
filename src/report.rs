//! Report model, value formats, texts and the Markdown document.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::analyze::{
    CdpTargetSummary, CpuPercentStats, CpuStats, MetricId, MetricStats, Run, RunReadError, Series,
    Summary, Warning, WarningMessage, Window, WindowSummary, compute_warnings, load,
    process_series, role_series, summarize,
};
use crate::meta::{CollectorStatus, ShutdownReason, ShutdownState};
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
    /// Warmup excluded from all after-warmup window statistics.
    pub warmup: Duration,
}

/// Formatted primary metrics and CPU percentages of one analysis window.
#[derive(Debug)]
pub struct WindowView {
    /// Inclusive run-relative boundaries, or an explanation of an absent window.
    pub caption: String,
    /// Fixed-order primary metric rows for the window.
    pub metric_rows: Vec<Vec<String>>,
    /// Mean, median and 95th-percentile tree CPU percentage rows.
    pub cpu_rows: Vec<Vec<String>>,
    /// Explanation when the after-warmup window has no usable data.
    pub no_data: Option<String>,
}

/// Formatted independent gauge statistics of one recorded CDP target.
#[derive(Debug)]
pub struct CdpTargetView {
    /// Recorded source identity, not its URL.
    pub target_id: String,
    /// Whole-run gauge rows with usable sample counts as their final cell.
    pub whole_run_rows: Vec<Vec<String>>,
    /// After-warmup gauge rows with usable sample counts as their final cell.
    pub steady_state_rows: Vec<Vec<String>>,
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
    /// Whole-run primary metric and CPU percentage tables.
    pub whole_run: WindowView,
    /// After-warmup primary metric and CPU percentage tables.
    pub steady_state: WindowView,
    /// Cumulative CPU seconds and process lifecycle counters, shown once.
    pub totals_rows: Vec<Vec<String>>,
    /// Independent CDP source tables in alphabetical target order.
    pub cdp_targets: Vec<CdpTargetView>,
    /// Rows of the role table, with peaks over the entire run.
    pub role_rows: Vec<Vec<String>>,
    /// Rows of the process table, with peaks over the entire run.
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
    /// Heading of each whole-run window table.
    heading_whole_run: &'static str,
    /// Heading of each after-warmup window table.
    heading_steady_state: &'static str,
    /// Heading of the independent CDP source section.
    heading_cdp_targets: &'static str,
    /// Heading of the cumulative totals table.
    heading_totals: &'static str,
    /// Template for inclusive run-relative window boundaries.
    window_caption: &'static str,
    /// Caption for an absent after-warmup window.
    empty_window: &'static str,
    /// Explanation for an after-warmup window without usable data.
    empty_steady_data: &'static str,
    /// Explanation of the CPU percentage scale.
    cpu_scope: &'static str,
    /// Explanation of the scope of role and process peaks.
    whole_run_scope: &'static str,
    /// Explanation of CDP measurement attribution and the absence of totals.
    cdp_scope: &'static str,
    /// Template naming a recorded CDP measurement source.
    target_label: &'static str,
    /// Final column label for usable target gauge sample counts.
    samples_header: &'static str,
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
    /// Headers of the whole-run summary table, without trends.
    whole_run_headers: [&'static str; 8],
    /// Headers of the after-warmup summary table, including trends.
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
    /// Safe localized CDP failure status; raw protocol details remain in the log.
    cdp_failed: &'static str,
    /// Template for missing usable CDP gauge samples.
    warning_cdp_metrics_missing: &'static str,
    /// Warning about a source unavailable at the end of a completed run.
    warning_cdp_waiting: &'static str,
    /// Template for excluded CDP rows without source identity.
    warning_cdp_identity: &'static str,
    /// Template for a recorded process with unconfirmed shutdown.
    warning_shutdown: &'static str,
    /// Names both requested CDP gauges.
    cdp_both_metrics: &'static str,
    /// Global scope of missing CDP gauge warnings.
    whole_run_warning_scope: &'static str,
    /// Localized states in Alive, Unknown order.
    shutdown_states: [&'static str; 2],
    /// Localized reasons in the order of ShutdownReason variants.
    shutdown_reasons: [&'static str; 6],
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
    heading_whole_run: "Whole run",
    heading_steady_state: "After warmup",
    heading_cdp_targets: "CDP targets",
    heading_totals: "Run totals",
    window_caption: "Window: [{start}, {end}], inclusive",
    empty_window: "No window after warmup",
    empty_steady_data: "No usable data after warmup",
    cpu_scope: "CPU %: 100% is the whole machine",
    whole_run_scope: "Roles and process peaks cover the whole run",
    cdp_scope: "CDP targets are measurement sources; renderer/isolate scope may be shared. Values are not summed.",
    target_label: "CDP target {id}",
    samples_header: "Samples",
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
    whole_run_headers: ["Metric", "Start", "Peak", "Mean", "p50", "p95", "End", "Δ"],
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
    cdp_failed: "failed (details in memwatch.log)",
    warning_cdp_metrics_missing: "CDP requested, but no usable {metrics} samples for {scope}",
    warning_cdp_waiting: "CDP source was unavailable at the end of the run",
    warning_cdp_identity: "CDP: {rows} rows without target identity were excluded",
    warning_shutdown: "Incomplete shutdown: PID {pid}, identity {key}, role {role}, state {state}, reason {reason}",
    cdp_both_metrics: "JS heap and DOM nodes",
    whole_run_warning_scope: "the whole run",
    shutdown_states: ["alive", "unknown"],
    shutdown_reasons: [
        "access denied",
        "identity unknown",
        "identity changed",
        "state query failed",
        "termination failed",
        "wait timed out",
    ],
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
    heading_whole_run: "Весь прогон",
    heading_steady_state: "После прогрева",
    heading_cdp_targets: "Источники CDP",
    heading_totals: "Общие итоги прогона",
    window_caption: "Окно: [{start}, {end}], границы включены",
    empty_window: "Нет окна после прогрева",
    empty_steady_data: "Нет пригодных данных после прогрева",
    cpu_scope: "CPU %: 100% соответствует всей машине",
    whole_run_scope: "Роли и пики процессов относятся ко всему прогону",
    cdp_scope: "CDP targets — источники измерений; область renderer/isolate может быть общей. Значения не суммируются.",
    target_label: "источник CDP {id}",
    samples_header: "Замеров",
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
    whole_run_headers: [
        "Метрика",
        "Старт",
        "Пик",
        "Среднее",
        "p50",
        "p95",
        "Конец",
        "Δ",
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
    cdp_failed: "сбой (подробности в memwatch.log)",
    warning_cdp_metrics_missing: "CDP запрошен, но нет пригодных замеров {metrics}: {scope}",
    warning_cdp_waiting: "Источник CDP был недоступен к концу прогона",
    warning_cdp_identity: "CDP: исключено строк без идентичности target: {rows}",
    warning_shutdown: "Неполная остановка: PID {pid}, идентичность {key}, роль {role}, состояние {state}, причина {reason}",
    cdp_both_metrics: "JS heap и DOM nodes",
    whole_run_warning_scope: "весь прогон",
    shutdown_states: ["жив", "неизвестно"],
    shutdown_reasons: [
        "отказ в доступе",
        "идентичность неизвестна",
        "идентичность изменилась",
        "не удалось запросить состояние",
        "не удалось завершить процесс",
        "истекло время ожидания",
    ],
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
        whole_run: window_view(
            &summary.whole_run,
            summary.primary_cdp_target.as_deref(),
            false,
            texts,
        ),
        steady_state: window_view(
            &summary.steady_state,
            summary.primary_cdp_target.as_deref(),
            true,
            texts,
        ),
        totals_rows: totals_rows(summary, texts),
        cdp_targets: summary
            .cdp_targets
            .iter()
            .map(|target| target_view(target, summary, texts))
            .collect(),
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
    lines.push(texts.cpu_scope.to_string());
    lines.push(String::new());
    for (heading, window, headers) in [
        (
            texts.heading_whole_run,
            &view.whole_run,
            texts.whole_run_headers.as_slice(),
        ),
        (
            texts.heading_steady_state,
            &view.steady_state,
            texts.summary_headers.as_slice(),
        ),
    ] {
        lines.push(format!("### {heading}"));
        lines.push(String::new());
        lines.push(window.caption.clone());
        lines.push(String::new());
        if let Some(no_data) = &window.no_data {
            lines.push(no_data.clone());
            lines.push(String::new());
        }
        lines.extend(table(headers, &window.metric_rows));
        lines.push(String::new());
        lines.extend(table(&texts.cpu_headers, &window.cpu_rows));
        lines.push(String::new());
    }
    lines.push(format!("### {}", texts.heading_totals));
    lines.push(String::new());
    lines.extend(table(&texts.cpu_headers, &view.totals_rows));
    lines.push(String::new());
    lines.push(format!("## {}", texts.heading_cdp_targets));
    lines.push(String::new());
    lines.push(texts.cdp_scope.to_string());
    lines.push(String::new());
    if view.cdp_targets.is_empty() {
        lines.push(texts.no_data.to_string());
        lines.push(String::new());
    }
    for target in &view.cdp_targets {
        lines.push(format!(
            "### {}",
            fill(
                texts.target_label,
                &[("id", &markdown_literal(&target.target_id))]
            )
        ));
        lines.push(String::new());
        for (heading, window, rows, headers) in [
            (
                texts.heading_whole_run,
                &view.whole_run,
                &target.whole_run_rows,
                texts.whole_run_headers.as_slice(),
            ),
            (
                texts.heading_steady_state,
                &view.steady_state,
                &target.steady_state_rows,
                texts.summary_headers.as_slice(),
            ),
        ] {
            lines.push(format!("#### {heading}"));
            lines.push(String::new());
            lines.push(window.caption.clone());
            lines.push(String::new());
            let mut headers = headers.to_vec();
            headers.push(texts.samples_header);
            lines.extend(table(&headers, rows));
            lines.push(String::new());
        }
    }
    lines.push(format!("## {}", texts.heading_roles));
    lines.push(String::new());
    lines.push(texts.whole_run_scope.to_string());
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
            let status = collector_status_text(name, status, texts);
            fill(
                texts.warning_collector_status,
                &[("name", name), ("status", &status)],
            )
        }
        WarningMessage::CdpMetricsMissing { target_id, metric } => {
            let metrics = match metric {
                Some(MetricId::JsHeapUsedBytes) => "JS heap",
                Some(MetricId::DomNodes) => "DOM nodes",
                _ => texts.cdp_both_metrics,
            };
            let scope = target_id.as_ref().map_or_else(
                || texts.whole_run_warning_scope.to_string(),
                |id| fill(texts.target_label, &[("id", &markdown_literal(id))]),
            );
            fill(
                texts.warning_cdp_metrics_missing,
                &[("metrics", metrics), ("scope", &scope)],
            )
        }
        WarningMessage::CdpWaiting => texts.warning_cdp_waiting.to_string(),
        WarningMessage::CdpTargetIdentityMissing { rows } => {
            fill(texts.warning_cdp_identity, &[("rows", &rows.to_string())])
        }
        WarningMessage::ShutdownIssue { issue } => fill(
            texts.warning_shutdown,
            &[
                ("pid", &issue.pid.to_string()),
                (
                    "key",
                    &markdown_literal(issue.proc_key.as_deref().unwrap_or(texts.dash)),
                ),
                ("role", &markdown_literal(&issue.role)),
                ("state", shutdown_state_text(issue.state, texts)),
                ("reason", shutdown_reason_text(issue.reason, texts)),
            ],
        ),
        WarningMessage::TreeWalkFallback => texts.warning_tree_walk_fallback.to_string(),
        WarningMessage::DidNotFinish => texts.did_not_finish.to_string(),
        WarningMessage::UnexpectedEndReason { reason } => {
            let reason = reason.to_string();
            fill(texts.warning_unexpected_end_reason, &[("reason", &reason)])
        }
    }
}

/// Formats CDP failures without publishing arbitrary saved protocol details.
fn collector_status_text(name: &str, status: &CollectorStatus, texts: &Texts) -> String {
    if name == "cdp" && matches!(status, CollectorStatus::Failed(_)) {
        texts.cdp_failed.to_string()
    } else {
        status.to_string()
    }
}

/// Localizes a coded final process state without arbitrary diagnostic text.
fn shutdown_state_text(state: ShutdownState, texts: &Texts) -> &str {
    texts.shutdown_states[match state {
        ShutdownState::Alive => 0,
        ShutdownState::Unknown => 1,
    }]
}

/// Localizes a coded shutdown reason without arbitrary diagnostic text.
fn shutdown_reason_text(reason: ShutdownReason, texts: &Texts) -> &str {
    texts.shutdown_reasons[match reason {
        ShutdownReason::AccessDenied => 0,
        ShutdownReason::IdentityUnknown => 1,
        ShutdownReason::IdentityChanged => 2,
        ShutdownReason::QueryFailed => 3,
        ShutdownReason::TerminateFailed => 4,
        ShutdownReason::WaitTimeout => 5,
    }]
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

/// Escapes an inline literal for Markdown headings and GFM table cells.
///
/// Line endings are spelled visibly to keep labels on one physical line. Escaped
/// backticks prevent code spans from bypassing escapes, and pipes remain escaped
/// even when the original identity placed them between backticks.
fn markdown_literal(value: &str) -> String {
    let mut literal = String::new();
    for ch in value.chars() {
        match ch {
            '\r' => literal.push_str("\\\\r"),
            '\n' => literal.push_str("\\\\n"),
            '\\' | '`' | '*' | '_' | '~' | '[' | ']' | '(' | ')' | '<' | '>' | '#' | '&' | '!'
            | '|' => {
                literal.push('\\');
                literal.push(ch);
            }
            _ => literal.push(ch),
        }
    }
    literal
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
        .map(|(name, status)| format!("{name}: {}", collector_status_text(name, status, texts)))
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

/// Builds available primary metric rows in the fixed order, naming any CDP source.
fn summary_rows(
    window: &WindowSummary,
    primary_target: Option<&str>,
    steady: bool,
    texts: &Texts,
) -> Vec<Vec<String>> {
    METRIC_ROWS
        .iter()
        .filter_map(|(metric, label, kind)| {
            let stats = window.metrics.get(metric)?;
            let scoped_label = if matches!(metric, MetricId::JsHeapUsedBytes | MetricId::DomNodes) {
                primary_target.map(|id| {
                    format!(
                        "{label} ({})",
                        fill(texts.target_label, &[("id", &markdown_literal(id))])
                    )
                })
            } else {
                None
            };
            Some(metric_row(
                scoped_label.as_deref().unwrap_or(label),
                stats,
                *kind,
                steady,
                window.too_short_for_hour_delta,
                texts,
            ))
        })
        .collect()
}

/// Formats one metric row with trends only in the after-warmup table.
fn metric_row(
    label: &str,
    stats: &MetricStats,
    kind: MetricKind,
    steady: bool,
    too_short: bool,
    texts: &Texts,
) -> Vec<String> {
    let mut row = vec![
        label.to_string(),
        metric_value(stats.start, kind, texts),
        metric_value(stats.peak, kind, texts),
        metric_value(stats.mean, kind, texts),
        metric_value(stats.p50, kind, texts),
        metric_value(stats.p95, kind, texts),
        metric_value(stats.end, kind, texts),
        metric_value(stats.delta, kind, texts),
    ];
    if steady {
        row.extend([
            stats.growth_per_hour.map_or_else(
                || texts.no_data.to_string(),
                |value| fmt_growth(value, kind, texts),
            ),
            fit_value(stats.r2, texts),
            median_value(stats, kind, too_short, texts),
        ]);
    }
    row
}

/// Formats primary rows, CPU rows and the availability explanation for a window.
fn window_view(
    window: &WindowSummary,
    primary_target: Option<&str>,
    steady: bool,
    texts: &Texts,
) -> WindowView {
    WindowView {
        caption: window_caption(window.window, texts),
        metric_rows: summary_rows(window, primary_target, steady, texts),
        cpu_rows: cpu_rows(&window.cpu, texts),
        no_data: (steady && !window.has_data).then(|| texts.empty_steady_data.to_string()),
    }
}

/// Formats both windows of a target, appending each gauge's usable sample count.
fn target_view(target: &CdpTargetSummary, summary: &Summary, texts: &Texts) -> CdpTargetView {
    let rows = |metrics: &BTreeMap<MetricId, MetricStats>, steady| {
        METRIC_ROWS
            .iter()
            .filter_map(|(metric, label, kind)| {
                let stats = metrics.get(metric)?;
                let mut row = metric_row(
                    label,
                    stats,
                    *kind,
                    steady,
                    summary.steady_state.too_short_for_hour_delta,
                    texts,
                );
                row.push(stats.samples.to_string());
                Some(row)
            })
            .collect()
    };
    CdpTargetView {
        target_id: target.target_id.clone(),
        whole_run_rows: rows(&target.whole_run, false),
        steady_state_rows: rows(&target.steady_state, true),
    }
}

/// Formats inclusive run-relative boundaries without displaying a reversed interval.
fn window_caption(window: Option<Window>, texts: &Texts) -> String {
    let instant = |ms| {
        let value = format_duration_ms(ms);
        if ms % 1000 == 0 {
            value
        } else {
            format!("{value}.{:03}", ms % 1000)
        }
    };
    match window {
        Some(window) => fill(
            texts.window_caption,
            &[
                ("start", &instant(window.start_ms)),
                ("end", &instant(window.end_ms)),
            ],
        ),
        None => texts.empty_window.to_string(),
    }
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

/// Builds the three tree CPU percentage rows of a window.
fn cpu_rows(cpu: &CpuPercentStats, texts: &Texts) -> Vec<Vec<String>> {
    vec![
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
    ]
}

/// Builds cumulative CPU seconds and lifecycle totals once for the entire run.
fn totals_rows(summary: &Summary, texts: &Texts) -> Vec<Vec<String>> {
    let processes = &summary.processes;
    vec![
        vec![
            texts.cpu_rows[0].to_string(),
            cpu_seconds_value(&summary.cpu, texts),
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
        let end_ms = exits.get(key).copied();
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

    /// Maps the after-warmup rows by their metric label.
    fn rows_by_label(view: &ReportView) -> BTreeMap<&str, &Vec<String>> {
        view.steady_state
            .metric_rows
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
    fn cdp_and_shutdown_warnings_are_bilingual() {
        use crate::meta::{ShutdownIssue, ShutdownReason, ShutdownState};
        for lang in [Lang::En, Lang::Ru] {
            let mut run = fixtures::empty_run();
            let expected = match lang {
                Lang::En => {
                    "CDP requested, but no usable JS heap and DOM nodes samples for the whole run"
                }
                Lang::Ru => {
                    "CDP запрошен, но нет пригодных замеров JS heap и DOM nodes: весь прогон"
                }
            };
            assert_eq!(build(&run, &summary_of(&run), lang).warnings, [expected]);
            run.meta
                .collectors
                .insert("cdp".into(), CollectorStatus::Waiting);
            run.cdp = vec![target_sample(0, "A", Some(0.0), Some(0.0))];
            let waiting = match lang {
                Lang::En => "CDP source was unavailable at the end of the run",
                Lang::Ru => "Источник CDP был недоступен к концу прогона",
            };
            assert_eq!(build(&run, &summary_of(&run), lang).warnings, [waiting]);
            run.meta
                .collectors
                .insert("cdp".into(), CollectorStatus::Ok);
            run.cdp.push(target_sample(1, "", Some(1.0), Some(1.0)));
            let identity = match lang {
                Lang::En => "CDP: 1 rows without target identity were excluded",
                Lang::Ru => "CDP: исключено строк без идентичности target: 1",
            };
            assert_eq!(build(&run, &summary_of(&run), lang).warnings, [identity]);
            run.cdp.pop();
            for (heap, nodes, en, ru) in [
                (None, Some(1.0), "JS heap", "JS heap"),
                (Some(1.0), None, "DOM nodes", "DOM nodes"),
                (None, None, "JS heap and DOM nodes", "JS heap и DOM nodes"),
            ] {
                run.cdp = vec![
                    target_sample(0, "A", Some(0.0), Some(0.0)),
                    target_sample(1, "B", heap, nodes),
                ];
                let expected = match lang {
                    Lang::En => {
                        format!("CDP requested, but no usable {en} samples for CDP target B")
                    }
                    Lang::Ru => {
                        format!("CDP запрошен, но нет пригодных замеров {ru}: источник CDP B")
                    }
                };
                assert_eq!(build(&run, &summary_of(&run), lang).warnings, [expected]);
                run.cdp.remove(0);
                let expected = match lang {
                    Lang::En => {
                        format!("CDP requested, but no usable {en} samples for the whole run")
                    }
                    Lang::Ru => format!("CDP запрошен, но нет пригодных замеров {ru}: весь прогон"),
                };
                assert_eq!(build(&run, &summary_of(&run), lang).warnings, [expected]);
            }
            run.cdp = vec![target_sample(0, "A", Some(0.0), Some(0.0))];
            for (reason, en, ru) in [
                (
                    ShutdownReason::AccessDenied,
                    "access denied",
                    "отказ в доступе",
                ),
                (
                    ShutdownReason::IdentityUnknown,
                    "identity unknown",
                    "идентичность неизвестна",
                ),
                (
                    ShutdownReason::IdentityChanged,
                    "identity changed",
                    "идентичность изменилась",
                ),
                (
                    ShutdownReason::QueryFailed,
                    "state query failed",
                    "не удалось запросить состояние",
                ),
                (
                    ShutdownReason::TerminateFailed,
                    "termination failed",
                    "не удалось завершить процесс",
                ),
                (
                    ShutdownReason::WaitTimeout,
                    "wait timed out",
                    "истекло время ожидания",
                ),
            ] {
                for (state, en_state, ru_state) in [
                    (ShutdownState::Alive, "alive", "жив"),
                    (ShutdownState::Unknown, "unknown", "неизвестно"),
                ] {
                    for key in [Some("10-100".to_string()), None] {
                        run.meta.shutdown_issues = vec![ShutdownIssue {
                            pid: 10,
                            proc_key: key.clone(),
                            role: "renderer".into(),
                            state,
                            reason,
                        }];
                        let key = key.as_deref().unwrap_or("—");
                        let expected = match lang {
                            Lang::En => format!(
                                "Incomplete shutdown: PID 10, identity {key}, role renderer, state {en_state}, reason {en}"
                            ),
                            Lang::Ru => format!(
                                "Неполная остановка: PID 10, идентичность {key}, роль renderer, состояние {ru_state}, причина {ru}"
                            ),
                        };
                        let view = build(&run, &summary_of(&run), lang);
                        assert_eq!(view.warnings, std::slice::from_ref(&expected));
                        assert!(render(&view).contains(&format!("- {expected}")));
                    }
                }
            }
            run.meta.shutdown_issues.clear();
            let raw = "B|`*_\r\n# [label]";
            run.cdp.push(target_sample(1, raw, None, None));
            let view = build(&run, &summary_of(&run), lang);
            assert_eq!(view.cdp_targets[1].target_id, raw);
            assert!(view.warnings[0].contains(&markdown_literal(raw)));
            assert!(!view.warnings[0].contains('\n'));
        }
    }

    #[test]
    fn process_without_confirmed_exit_has_no_end_in_report() {
        use crate::meta::{ShutdownIssue, ShutdownReason, ShutdownState};
        let mut run = role_process_run();
        run.processes
            .push(memory_row(60_000, "200-2000", "renderer", MIB, MIB));
        run.meta.shutdown_issues = vec![ShutdownIssue {
            pid: 200,
            proc_key: Some("200-2000".into()),
            role: "renderer".into(),
            state: ShutdownState::Alive,
            reason: ShutdownReason::WaitTimeout,
        }];
        for lang in [Lang::En, Lang::Ru] {
            let view = build(&run, &summary_of(&run), lang);
            assert_eq!(&view.process_rows[1][4..6], ["—", "—"]);
            assert_eq!(&view.process_rows[0][4..6], ["1:00", "1:00"]);
            let state = match lang {
                Lang::En => "state alive, reason wait timed out",
                Lang::Ru => "состояние жив, причина истекло время ожидания",
            };
            assert!(view.warnings.iter().any(|warning| warning.contains(state)));
            assert!(render(&view).contains("renderer.exe | — | 0:00 | — | — |"));
        }
    }

    #[test]
    fn requested_empty_cdp_never_renders_no_warnings() {
        for lang in [Lang::En, Lang::Ru] {
            for status in [CollectorStatus::Waiting, CollectorStatus::Ok] {
                let mut run = fixtures::empty_run();
                run.meta.collectors.insert("cdp".into(), status.clone());
                let document = document_of(&run, lang);
                assert!(!document.contains(texts(lang).no_warnings));
                assert!(document.contains(match lang {
                    Lang::En => "CDP requested",
                    Lang::Ru => "CDP запрошен",
                }));
            }
            let mut run = fixtures::empty_run();
            run.meta
                .collectors
                .insert("cdp".into(), CollectorStatus::Waiting);
            run.cdp = vec![target_sample(0, "A", Some(0.0), Some(0.0))];
            assert!(!document_of(&run, lang).contains(texts(lang).no_warnings));
        }
    }

    #[test]
    fn failed_cdp_status_hides_legacy_details_in_header_and_warnings() {
        let dir = TempDir::new().unwrap();
        let run_dir = fixtures::write_run(dir.path());
        let markers = [
            "https://private.invalid/url-secret",
            r"C:\private\path-secret\app.exe",
            "--token=command-secret",
            "arbitrary-unrecognized-suffix",
        ];
        let mut meta = fixtures::sample_meta();
        meta.collectors
            .insert("cdp".into(), CollectorStatus::Failed(markers.join(" ")));
        // Other collectors retain their existing diagnostic detail.
        meta.collectors.insert(
            "gpu".into(),
            CollectorStatus::Failed("gpu diagnostic".into()),
        );
        let mut legacy = serde_json::to_value(meta).unwrap();
        legacy.as_object_mut().unwrap().remove("shutdown_issues");
        fs::write(
            run_dir.join("meta.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let run = load(&run_dir).unwrap();
        assert!(run.meta.shutdown_issues.is_empty());
        for lang in [Lang::En, Lang::Ru] {
            let view = build(&run, &summary_of(&run), lang);
            let copy = match lang {
                Lang::En => "failed (details in memwatch.log)",
                Lang::Ru => "сбой (подробности в memwatch.log)",
            };
            let header = &view.header[10].1;
            let warnings = view.warnings.join("\n");
            assert!(header.contains("gpu: failed: gpu diagnostic"));
            for surface in [header.as_str(), warnings.as_str(), render(&view).as_str()] {
                for marker in markers {
                    assert!(!surface.contains(marker), "private marker leaked: {marker}");
                }
                assert!(surface.contains(copy));
            }
        }
    }

    #[test]
    fn render_separates_startup_peak_from_steady_statistics() {
        let mut run = fixtures::empty_run();
        run.processes = vec![
            memory_row(0, "100-1000", "main", 1000.0 * MIB, 1000.0 * MIB),
            memory_row(599_999, "100-1000", "main", 1000.0 * MIB, 1000.0 * MIB),
            memory_row(600_000, "100-1000", "main", 100.0 * MIB, 100.0 * MIB),
            memory_row(1_200_000, "100-1000", "main", 100.0 * MIB, 100.0 * MIB),
        ];
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: 1_200_000,
            },
            600_000,
        );
        for lang in [Lang::En, Lang::Ru] {
            let document = render(&build(&run, &summary, lang));
            let (whole, steady, unit, growth) = match lang {
                Lang::En => ("### Whole run", "### After warmup", "MB", "Growth"),
                Lang::Ru => ("### Весь прогон", "### После прогрева", "МБ", "Рост"),
            };
            let whole = document_section(&document, whole);
            let steady = document_section(&document, steady);
            assert!(whole.contains(&format!(
                "| Private bytes | 1000.0 {unit} | 1000.0 {unit} | 550.0 {unit} |"
            )));
            assert!(!whole.contains(growth));
            assert!(steady.contains(&format!("| Private bytes | 100.0 {unit} | 100.0 {unit} | 100.0 {unit} | 100.0 {unit} | 100.0 {unit} |")));
            assert!(steady.contains(growth));
            assert!(whole.contains("[0:00, 20:00]"));
            assert!(steady.contains("[10:00, 20:00]"));
        }
    }

    #[test]
    fn render_reports_each_cdp_target_without_a_total() {
        let mut run = fixtures::empty_run();
        run.cdp = vec![
            target_sample(0, "B", Some(20.0 * MIB), Some(200.0)),
            target_sample(1, "A", Some(10.0 * MIB), Some(100.0)),
            target_sample(100, "B", Some(20.0 * MIB), None),
            target_sample(101, "A", Some(10.0 * MIB), Some(100.0)),
            target_sample(102, "C", None, None),
        ];
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: 102,
            },
            100,
        );
        for lang in [Lang::En, Lang::Ru] {
            let document = render(&build(&run, &summary, lang));
            let (cdp, target, samples, unit) = match lang {
                Lang::En => ("## CDP targets", "CDP target", "Samples", "MB"),
                Lang::Ru => ("## Источники CDP", "источник CDP", "Замеров", "МБ"),
            };
            let tree = document.split(cdp).next().expect("the tree section exists");
            assert!(
                !tree.contains("| JS heap"),
                "multiple targets cannot supply primary JS rows"
            );
            let a = document_section(&document, &format!("### {target} A"));
            let b = document_section(&document, &format!("### {target} B"));
            let c = document_section(&document, &format!("### {target} C"));
            assert!(a.contains(samples));
            assert!(a.contains(&format!("| JS heap | 10.0 {unit} |")));
            assert!(b.contains(&format!("| JS heap | 20.0 {unit} |")));
            assert!(!document.contains(&format!("30.0 {unit}")));
            let a_rows = metric_lines(a, "JS heap");
            assert_eq!(a_rows.len(), 2);
            assert!(a_rows[0].ends_with("| 2 |"));
            assert!(a_rows[1].ends_with("| 1 |"));
            let b_nodes = metric_lines(b, "DOM nodes");
            assert!(b_nodes[0].ends_with("| 1 |"));
            assert!(b_nodes[1].ends_with("| 0 |"));
            assert!(
                metric_lines(c, "JS heap")
                    .iter()
                    .all(|row| row.ends_with("| 0 |"))
            );
            assert!(
                document.find(&format!("### {target} A")).unwrap()
                    < document.find(&format!("### {target} B")).unwrap()
            );
        }
    }

    #[test]
    fn render_single_cdp_target_names_primary_scope() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        fs::write(run_dir.join("cdp.csv"), "t_ms,unix_ms,target_id,url,js_heap_used_bytes,nodes\n0,1000,page-1,https://private-url-marker.invalid/path,10485760,100\n100,1100,page-1,https://private-url-marker.invalid/path,10485760,100\n").expect("cdp.csv must be written");
        let run = load(&run_dir).expect("the legacy CSV must load");
        for lang in [Lang::En, Lang::Ru] {
            let document = document_of(&run, lang);
            let target = match lang {
                Lang::En => "CDP target page-1",
                Lang::Ru => "источник CDP page-1",
            };
            let primary = metric_lines(&document, &format!("JS heap ({target})"));
            assert_eq!(
                primary.len(),
                2,
                "each primary window must explicitly name its source"
            );
            let target_rows = metric_lines(
                document_section(&document, &format!("### {target}")),
                "JS heap",
            );
            assert_eq!(target_rows.len(), 2);
            for (primary, target) in primary.iter().zip(target_rows) {
                let primary: Vec<_> = primary.split('|').map(str::trim).collect();
                let target: Vec<_> = target.split('|').map(str::trim).collect();
                assert_eq!(&primary[2..primary.len() - 1], &target[2..target.len() - 2]);
            }
            assert!(!document.contains("private-url-marker"));
            assert!(!document.contains(fixtures::CMDLINE_MARKER));
            assert!(!document.contains(r"C:\app"));
        }
    }

    #[test]
    fn render_preserves_cdp_table_columns_for_hostile_ids() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        for (raw_id, literal_id) in HOSTILE_TARGET_IDS {
            write_target_csv(&run_dir, &[raw_id]);
            let run = load(&run_dir).expect("quoted CSV target identities must load");
            let summary = summarize(
                &run,
                Window {
                    start_ms: 0,
                    end_ms: 100,
                },
                0,
            );
            assert_eq!(run.cdp[0].target_id.as_deref(), Some(raw_id));
            assert_eq!(summary.primary_cdp_target.as_deref(), Some(raw_id));
            assert_eq!(summary.cdp_targets[0].target_id, raw_id);

            for lang in [Lang::En, Lang::Ru] {
                let view = build(&run, &summary, lang);
                assert_eq!(view.cdp_targets[0].target_id, raw_id);
                let document = render(&view);
                let (whole, steady, target_label, unit) = match lang {
                    Lang::En => ("### Whole run", "### After warmup", "CDP target", "MB"),
                    Lang::Ru => (
                        "### Весь прогон",
                        "### После прогрева",
                        "источник CDP",
                        "МБ",
                    ),
                };
                for (heading, width) in [(whole, 8), (steady, 11)] {
                    let section = document_section(&document, heading);
                    for (metric, first) in [
                        ("JS heap", format!("10.0 {unit}")),
                        ("DOM nodes", "100".to_string()),
                    ] {
                        let rows: Vec<_> = section
                            .lines()
                            .filter(|line| line.starts_with(&format!("| {metric} (")))
                            .collect();
                        assert_eq!(
                            rows.len(),
                            1,
                            "one complete {metric} row is required for {raw_id:?}"
                        );
                        let cells = gfm_cells(rows[0]);
                        assert_eq!(
                            cells.len(),
                            width,
                            "escaped pipes, including those between backticks, must not create columns: {raw_id:?}"
                        );
                        assert_eq!(cells[0], format!("{metric} ({target_label} {literal_id})"));
                        assert_eq!(cells[1], first);
                        assert_eq!(cells[2], first);
                        assert_eq!(cells[3], first);
                        assert_eq!(cells[6], first);
                    }
                }
                assert!(!document.contains("private-url-marker"));
                assert!(!document.contains(fixtures::CMDLINE_MARKER));
                assert!(!document.contains(r"C:\app"));
            }
        }
    }

    #[test]
    fn render_keeps_hostile_cdp_target_ids_in_literal_headings() {
        let dir = TempDir::new().expect("a temporary directory must be created");
        let run_dir = fixtures::write_run(dir.path());
        let raw_ids: Vec<_> = HOSTILE_TARGET_IDS.iter().map(|(raw, _)| *raw).collect();
        write_target_csv(&run_dir, &raw_ids);
        let run = load(&run_dir).expect("quoted multiline identities must load");
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: 100,
            },
            0,
        );
        assert_eq!(summary.primary_cdp_target, None);
        let mut sorted = HOSTILE_TARGET_IDS.to_vec();
        sorted.sort_by_key(|(raw, _)| *raw);
        assert_eq!(
            summary
                .cdp_targets
                .iter()
                .map(|target| target.target_id.as_str())
                .collect::<Vec<_>>(),
            sorted.iter().map(|(raw, _)| *raw).collect::<Vec<_>>()
        );

        for lang in [Lang::En, Lang::Ru] {
            let view = build(&run, &summary, lang);
            assert_eq!(
                view.cdp_targets
                    .iter()
                    .map(|target| target.target_id.as_str())
                    .collect::<Vec<_>>(),
                sorted.iter().map(|(raw, _)| *raw).collect::<Vec<_>>()
            );
            let document = render(&view);
            let texts = texts(lang);
            let mut expected_headings = vec![
                "# ".to_string() + &fill(texts.title, &[("name", "synthetic")]),
                format!("## {}", texts.heading_warnings),
                format!("## {}", texts.heading_summary),
                format!("### {}", texts.heading_whole_run),
                format!("### {}", texts.heading_steady_state),
                format!("### {}", texts.heading_totals),
                format!("## {}", texts.heading_cdp_targets),
            ];
            for (_, literal_id) in &sorted {
                expected_headings.extend([
                    format!("### {}", fill(texts.target_label, &[("id", literal_id)])),
                    format!("#### {}", texts.heading_whole_run),
                    format!("#### {}", texts.heading_steady_state),
                ]);
            }
            expected_headings.extend([
                format!("## {}", texts.heading_roles),
                format!("## {}", texts.heading_processes),
            ]);
            let actual_headings: Vec<_> = document
                .lines()
                .filter(|line| line.starts_with('#'))
                .collect();
            assert_eq!(
                actual_headings, expected_headings,
                "target identities must be literal single-line headings, not Markdown or injected sections"
            );
            let tree = document_section(&document, &format!("## {}", texts.heading_summary));
            assert!(!tree.contains("| JS heap"));
            assert!(!tree.contains("| DOM nodes"));
            for (_, literal_id) in &sorted {
                let target = document_section(
                    &document,
                    &format!("### {}", fill(texts.target_label, &[("id", literal_id)])),
                );
                for (heading, width) in [
                    (texts.heading_whole_run, 9),
                    (texts.heading_steady_state, 12),
                ] {
                    let window = document_section(target, &format!("#### {heading}"));
                    for metric in ["JS heap", "DOM nodes"] {
                        let rows = metric_lines(window, metric);
                        assert_eq!(rows.len(), 1);
                        let cells = gfm_cells(rows[0]);
                        assert_eq!(cells.len(), width);
                        assert_eq!(cells[width - 1], "2");
                    }
                }
            }
            assert!(!document.contains("private-url-marker"));
            assert!(!document.contains(fixtures::CMDLINE_MARKER));
            assert!(!document.contains(r"C:\app"));
        }
    }

    /// Raw identities paired with literal Markdown source, not rendered markup.
    const HOSTILE_TARGET_IDS: [(&str, &str); 5] = [
        ("page|A", r"page\|A"),
        (r"page\|A", r"page\\\|A"),
        ("`page|A`", r"\`page\|A\`"),
        (
            "page\r\n## injected\n`title`",
            r"page\\r\\n\#\# injected\\n\`title\`",
        ),
        (
            "**bold**_[link](dest)_ <b> &copy; ###",
            r"\*\*bold\*\*\_\[link\]\(dest\)\_ \<b\> \&copy; \#\#\#",
        ),
    ];

    /// Writes quoted legacy CSV identities with two constant gauge samples each.
    fn write_target_csv(run_dir: &Path, target_ids: &[&str]) {
        let mut writer =
            csv::Writer::from_path(run_dir.join("cdp.csv")).expect("cdp.csv must be created");
        writer
            .write_record([
                "t_ms",
                "unix_ms",
                "target_id",
                "url",
                "js_heap_used_bytes",
                "nodes",
            ])
            .expect("the header must be written");
        for tick in [0, 100] {
            for target_id in target_ids {
                writer
                    .write_record([
                        tick.to_string(),
                        (1000 + tick).to_string(),
                        target_id.to_string(),
                        "https://private-url-marker.invalid/path".to_string(),
                        "10485760".to_string(),
                        "100".to_string(),
                    ])
                    .expect("the quoted target row must be written");
            }
        }
        writer.flush().expect("cdp.csv must be flushed");
    }

    /// Splits GFM cells at pipes not escaped by an odd number of backslashes.
    fn gfm_cells(row: &str) -> Vec<&str> {
        let mut cells = Vec::new();
        let mut start = 0;
        let mut backslashes = 0;
        for (index, ch) in row.char_indices() {
            if ch == '|' && backslashes % 2 == 0 {
                cells.push(row[start..index].trim());
                start = index + 1;
            }
            backslashes = if ch == '\\' { backslashes + 1 } else { 0 };
        }
        cells.push(row[start..].trim());
        assert_eq!(
            cells.first(),
            Some(&""),
            "a table row must start with a pipe"
        );
        assert_eq!(cells.pop(), Some(""), "a table row must end with a pipe");
        cells.remove(0);
        cells
    }

    #[test]
    fn render_distinguishes_empty_steady_window_from_short_window() {
        let mut run = fixtures::empty_run();
        run.processes = vec![memory_row(0, "100-1000", "main", MIB, MIB)];
        for lang in [Lang::En, Lang::Ru] {
            let (heading, empty_window, empty_data, no_data, short) = match lang {
                Lang::En => (
                    "### After warmup",
                    "No window after warmup",
                    "No usable data after warmup",
                    "no data",
                    "run too short",
                ),
                Lang::Ru => (
                    "### После прогрева",
                    "Нет окна после прогрева",
                    "Нет пригодных данных после прогрева",
                    "нет данных",
                    "прогон слишком короткий",
                ),
            };
            for end_ms in [99, 200] {
                let summary = summarize(
                    &run,
                    Window {
                        start_ms: 0,
                        end_ms,
                    },
                    100,
                );
                let document = render(&build(&run, &summary, lang));
                let steady = document_section(&document, heading);
                assert!(steady.contains(empty_data));
                assert_eq!(steady.contains(empty_window), end_ms == 99);
                if end_ms == 200 {
                    assert!(
                        steady.contains("[0:00.100, 0:00.200]"),
                        "window captions must preserve subsecond inclusive boundaries"
                    );
                }
                assert!(steady.contains(&format!(
                    "| Private bytes | {} |",
                    [no_data; 10].join(" | ")
                )));
                assert!(!steady.contains(short));
            }
            run.processes
                .push(memory_row(100, "100-1000", "main", 2.0 * MIB, 2.0 * MIB));
            let summary = summarize(
                &run,
                Window {
                    start_ms: 0,
                    end_ms: 200,
                },
                100,
            );
            let document = render(&build(&run, &summary, lang));
            let steady = document_section(&document, heading);
            assert!(!steady.contains(empty_data));
            let row = metric_lines(steady, "Private bytes")[0];
            assert!(row.ends_with(&format!("| {no_data} | {no_data} | {short} |")));
            run.processes.pop();
        }
    }

    #[test]
    fn render_has_windowed_cpu_and_single_lifecycle_totals() {
        let mut run = role_process_run();
        for sample in &mut run.processes {
            sample.cpu_pct = Some(if sample.t_ms == 0 { 45.0 } else { 10.0 });
        }
        let summary = summarize(
            &run,
            Window {
                start_ms: 0,
                end_ms: 60_000,
            },
            30_000,
        );
        for lang in [Lang::En, Lang::Ru] {
            let document = render(&build(&run, &summary, lang));
            let (whole, steady, labels, cpu_scope, peaks_scope) = match lang {
                Lang::En => (
                    "### Whole run",
                    "### After warmup",
                    EN.cpu_rows,
                    "CPU %: 100% is the whole machine",
                    "Roles and process peaks cover the whole run",
                ),
                Lang::Ru => (
                    "### Весь прогон",
                    "### После прогрева",
                    RU.cpu_rows,
                    "CPU %: 100% соответствует всей машине",
                    "Роли и пики процессов относятся ко всему прогону",
                ),
            };
            let whole = document_section(&document, whole);
            let steady = document_section(&document, steady);
            assert!(whole.contains(&format!("| {} | 36.67 |", labels[1])));
            assert!(steady.contains(&format!("| {} | 10.00 |", labels[1])));
            for label in &labels[1..4] {
                assert_eq!(document.matches(&format!("| {label} |")).count(), 2);
            }
            for label in [labels[0], labels[4], labels[5], labels[6]] {
                assert_eq!(document.matches(&format!("| {label} |")).count(), 1);
            }
            assert!(document.contains(cpu_scope));
            assert!(document.contains(peaks_scope));
        }
    }

    /// Returns a heading's body up to the next heading of the same or higher level.
    fn document_section<'a>(document: &'a str, heading: &str) -> &'a str {
        let level = heading.bytes().take_while(|byte| *byte == b'#').count();
        let start = document
            .find(&format!("{heading}\n"))
            .unwrap_or_else(|| panic!("missing {heading}"))
            + heading.len()
            + 1;
        let body = &document[start..];
        let end = body
            .match_indices("\n#")
            .find_map(|(index, _)| {
                let next_level = body[index + 1..]
                    .bytes()
                    .take_while(|byte| *byte == b'#')
                    .count();
                (next_level <= level).then_some(index)
            })
            .unwrap_or(body.len());
        &body[..end]
    }

    /// Returns the Markdown rows whose first cell is exactly the metric label.
    fn metric_lines<'a>(document: &'a str, label: &str) -> Vec<&'a str> {
        document
            .lines()
            .filter(|line| line.starts_with(&format!("| {label} |")))
            .collect()
    }

    /// Builds a target gauge row, preserving missing values as failed attempts.
    fn target_sample(
        t_ms: u64,
        target_id: &str,
        heap: Option<f64>,
        nodes: Option<f64>,
    ) -> crate::analyze::CdpSample {
        crate::analyze::CdpSample {
            t_ms,
            unix_ms: t_ms,
            target_id: Some(target_id.to_string()),
            session_id: None,
            js_heap_used_bytes: heap,
            nodes,
        }
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
        for label in ["GPU dedicated", "GPU shared"] {
            assert_eq!(rows[label][1..], ["no data"; 10], "{label}");
        }
        assert!(!rows.contains_key("JS heap"));
        assert!(!rows.contains_key("DOM nodes"));
        assert_eq!(rows["Private bytes"][1], "1.0 MB");
        assert_eq!(rows["Private bytes"][10], "run too short");
    }

    #[test]
    fn view_formats_russian_values() {
        let run = role_process_run();

        let view = build(&run, &summary_of(&run), Lang::Ru);

        let rows = rows_by_label(&view);
        for label in ["GPU dedicated", "GPU shared"] {
            assert_eq!(rows[label][1..], ["нет данных"; 10], "{label}");
        }
        assert!(!rows.contains_key("JS heap"));
        assert!(!rows.contains_key("DOM nodes"));
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
                    "—",
                    "—",
                    "0.5 МБ",
                    "1.0 МБ"
                ],
            ]
        );
    }

    #[test]
    fn view_lists_warnings() {
        let mut run = fixtures::empty_run();
        run.meta.collectors.remove("cdp");
        run.meta
            .env_overrides
            .remove("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
        assert_eq!(
            build(&run, &summary_of(&run), Lang::En).warnings,
            Vec::<String>::new()
        );

        let mut run = fixtures::empty_run();
        run.meta.collectors.remove("cdp");
        run.meta
            .env_overrides
            .remove("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
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
            .whole_run
            .metric_rows
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
                "Handles",
                "GDI",
                "USER",
                "Threads",
            ]
        );
        assert_eq!(view.whole_run.metric_rows[0][0], "Private bytes");
        assert_eq!(view.whole_run.metric_rows[7][0], "Threads");
        assert!(
            view.whole_run.metric_rows.iter().all(|row| row.len() == 8),
            "every whole-run row must have eight cells"
        );
        assert!(
            view.steady_state
                .metric_rows
                .iter()
                .all(|row| row.len() == 11)
        );
        assert_eq!(view.whole_run.cpu_rows.len(), 3);
        assert_eq!(view.steady_state.cpu_rows.len(), 3);
        assert_eq!(view.totals_rows.len(), 4);
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
                    "—",
                    "—",
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
        assert!(!document.contains("| JS heap"));
        assert!(document_section(&document, "## CDP targets").contains("no data"));
    }

    #[test]
    fn render_lists_warnings() {
        let mut run = fixtures::empty_run();
        run.meta.collectors.remove("cdp");
        run.meta
            .env_overrides
            .remove("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
        run.warnings = vec![Warning {
            kind: WarningKind::NoData,
            message: WarningMessage::MissingFile {
                file: "gpu.csv".to_string(),
            },
        }];

        assert!(document_of(&run, Lang::En).contains("- no data: missing file gpu.csv"));

        let mut run = fixtures::empty_run();
        run.meta.collectors.remove("cdp");
        run.meta
            .env_overrides
            .remove("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
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
