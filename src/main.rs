//! `memwatch` command-line entry point.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::error::ErrorKind;
use clap::{Args, CommandFactory, Parser, Subcommand};

use memwatch::log::RunLog;
use memwatch::meta::EndReason;
use memwatch::options::{
    RunOptions, parse_duration, parse_label, parse_lang, validate_intervals, validate_name,
};
use memwatch::report::{Lang, ReportOptions};
use memwatch::sampler::StopHandle;

/// Records resource usage of a tree of Windows processes while it runs.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Runs a command and records resource usage of its process tree.
    Run(RunArgs),
    /// Builds the report of a recorded run directory.
    Report(ReportArgs),
}

/// Arguments of the `report` command.
#[derive(Debug, Args)]
struct ReportArgs {
    /// Directory of a recorded run.
    run_dir: PathBuf,

    /// Language of the report.
    #[arg(long, default_value = "en", value_parser = parse_lang)]
    lang: Lang,

    /// Warmup excluded from growth and hour deltas.
    #[arg(long, default_value = "10m", value_parser = parse_duration)]
    warmup: Duration,

    /// Directory of the report; defaults to `<run-dir>/report`.
    #[arg(long)]
    out: Option<PathBuf>,
}

/// Arguments of the `run` command.
#[derive(Debug, Args)]
struct RunArgs {
    /// Run name; also the prefix of the run directory.
    #[arg(long, value_parser = validate_name)]
    name: String,

    /// Directory that holds run directories.
    #[arg(long, default_value = "runs")]
    out: PathBuf,

    /// Label stored in the run metadata as `key=value`; may be repeated.
    #[arg(long, value_parser = parse_label)]
    label: Vec<(String, String)>,

    /// Sampling interval.
    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    interval: Duration,

    /// Stop the run after this time (like Ctrl+C).
    #[arg(long, value_parser = parse_duration)]
    duration: Option<Duration>,

    /// Interval of the GPU collector; must be a multiple of `--interval`.
    #[arg(long, default_value = "2s", value_parser = parse_duration)]
    gpu_interval: Duration,

    /// Interval of the DevTools collector; must be a multiple of `--interval`.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    cdp_interval: Duration,

    /// Port for DevTools opened by the launched application.
    #[arg(long)]
    cdp_port: Option<u16>,

    /// Allow the machine to sleep during the run.
    #[arg(long)]
    allow_sleep: bool,

    /// Language of the report written after the run.
    #[arg(long, default_value = "en", value_parser = parse_lang)]
    lang: Lang,

    /// Warmup excluded from growth and hour deltas in the report.
    #[arg(long, default_value = "10m", value_parser = parse_duration)]
    warmup: Duration,

    /// Command to run followed by its arguments.
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<OsString>,
}

impl From<RunArgs> for RunOptions {
    fn from(args: RunArgs) -> Self {
        RunOptions {
            name: args.name,
            out_dir: args.out,
            labels: args.label.into_iter().collect(),
            interval: args.interval,
            duration: args.duration,
            gpu_interval: args.gpu_interval,
            cdp_interval: args.cdp_interval,
            cdp_port: args.cdp_port,
            allow_sleep: args.allow_sleep,
            command: args.command,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => {
            if let Err(message) =
                validate_intervals(args.interval, args.gpu_interval, args.cdp_interval)
            {
                Cli::command()
                    .error(ErrorKind::ValueValidation, message)
                    .exit();
            }
            run_command(args);
        }
        Command::Report(args) => report_command(args),
    }
}

/// Runs the `run` command and exits with the code of the run.
fn run_command(args: RunArgs) {
    let report_options = ReportOptions {
        lang: args.lang,
        warmup: args.warmup,
    };
    let options = RunOptions::from(args);
    let stop = StopHandle::new();
    let handler_stop = stop.clone();
    let signals = AtomicUsize::new(0);
    if let Err(err) = ctrlc::set_handler(move || {
        // The first Ctrl+C asks the run to stop; the second exits at once.
        if signals.fetch_add(1, Ordering::SeqCst) == 0 {
            handler_stop.stop();
        } else {
            std::process::exit(1);
        }
    }) {
        eprintln!("memwatch: cannot install the Ctrl+C handler: {err}");
        std::process::exit(1);
    }

    match memwatch::run(&options, stop) {
        Ok(outcome) => {
            println!("run directory: {}", outcome.run_dir.display());
            println!("end reason: {}", end_reason_name(outcome.end_reason));
            build_report(&outcome.run_dir, &report_options);
            match outcome.end_reason {
                EndReason::AppExited | EndReason::CtrlC => std::process::exit(0),
                EndReason::LaunchFailed | EndReason::MemwatchError => std::process::exit(1),
            }
        }
        Err(err) => {
            eprintln!("memwatch: {err}");
            std::process::exit(1);
        }
    }
}

/// Builds the report of a recorded run and exits with the report status.
fn report_command(args: ReportArgs) {
    let options = ReportOptions {
        lang: args.lang,
        warmup: args.warmup,
    };
    match memwatch::report::write(&args.run_dir, &options, args.out.as_deref()) {
        Ok(path) => {
            println!("report: {}", path.display());
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("memwatch: {err}");
            std::process::exit(1);
        }
    }
}

/// Builds the report of a finished run without changing the run outcome.
///
/// A failure is written to the run journal and to stderr; the run itself
/// has already finished, so its exit code stays untouched.
fn build_report(run_dir: &Path, options: &ReportOptions) {
    let Err(err) = memwatch::report::write(run_dir, options, None) else {
        return;
    };
    let message = format!("cannot build the report: {err}");
    match RunLog::append(&run_dir.join("memwatch.log")) {
        Ok(log) => log.error("report", &message),
        Err(log_err) => eprintln!("memwatch: cannot write to the run log: {log_err}"),
    }
    eprintln!("memwatch: {message}");
}

/// Returns the `meta.json` spelling of the end reason.
fn end_reason_name(reason: EndReason) -> &'static str {
    match reason {
        EndReason::AppExited => "app_exited",
        EndReason::CtrlC => "ctrl_c",
        EndReason::LaunchFailed => "launch_failed",
        EndReason::MemwatchError => "memwatch_error",
    }
}
