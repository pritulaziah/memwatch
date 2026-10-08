//! `memwatch` command-line entry point.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use memwatch::meta::EndReason;
use memwatch::options::{RunOptions, parse_duration, parse_label, validate_name};
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

    /// Allow the machine to sleep during the run.
    #[arg(long)]
    allow_sleep: bool,

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
            allow_sleep: args.allow_sleep,
            command: args.command,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => run_command(args),
    }
}

/// Runs the `run` command and exits with the code of the run.
fn run_command(args: RunArgs) {
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

/// Returns the `meta.json` spelling of the end reason.
fn end_reason_name(reason: EndReason) -> &'static str {
    match reason {
        EndReason::AppExited => "app_exited",
        EndReason::CtrlC => "ctrl_c",
        EndReason::LaunchFailed => "launch_failed",
        EndReason::MemwatchError => "memwatch_error",
    }
}
