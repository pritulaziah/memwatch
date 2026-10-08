//! Synthetic load process for the memwatch tests.
//!
//! Without `--child` the fixture starts a second copy of itself with the same
//! load options and a zero exit code, prints the root and child PIDs, runs
//! the load for `--duration`, waits for the child and exits with
//! `--exit-code`. With `--child` it only runs the load. Every second the
//! fixture allocates and fills `--alloc-mb-per-sec` megabytes and spins the
//! CPU for `--busy-ms-per-sec` milliseconds; on the first second it creates
//! `--gdi` GDI brushes. Everything allocated is held until the process exits.

use std::io::Write;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use clap::Parser;
use memwatch::options::parse_duration;
use windows::Win32::Foundation::COLORREF;
use windows::Win32::Graphics::Gdi::{CreateSolidBrush, HBRUSH};

/// `CREATE_NO_WINDOW`: starts the child without a console window.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Command-line options of the fixture.
#[derive(Debug, Parser)]
struct FixtureArgs {
    /// How long the process runs.
    #[arg(long, value_parser = parse_duration)]
    duration: Duration,

    /// Megabytes allocated, filled and held every second.
    #[arg(long, default_value_t = 0)]
    alloc_mb_per_sec: u64,

    /// GDI brushes created and held on the first second.
    #[arg(long, default_value_t = 0)]
    gdi: u32,

    /// Milliseconds of busy CPU work every second.
    #[arg(long, default_value_t = 0)]
    busy_ms_per_sec: u64,

    /// Exit code of the parent process.
    #[arg(long, default_value_t = 0)]
    exit_code: i32,

    /// Run as the child process instead of spawning one.
    #[arg(long)]
    child: bool,
}

fn main() {
    let args = FixtureArgs::parse();
    if args.child {
        let load = run_load(&args);
        std::hint::black_box(&load);
        std::process::exit(args.exit_code);
    }

    let mut child = spawn_child(&args);
    let load = run_load(&args);
    let _ = child.wait();
    std::hint::black_box(&load);
    std::process::exit(args.exit_code);
}

/// Starts a child copy with the same load options and a zero exit code.
fn spawn_child(args: &FixtureArgs) -> Child {
    let exe = std::env::current_exe().expect("the fixture path must be known");
    let mut command = Command::new(exe);
    command
        .arg("--child")
        .arg("--duration")
        .arg(format!("{}ms", args.duration.as_millis()))
        .arg("--alloc-mb-per-sec")
        .arg(args.alloc_mb_per_sec.to_string())
        .arg("--gdi")
        .arg(args.gdi.to_string())
        .arg("--busy-ms-per-sec")
        .arg(args.busy_ms_per_sec.to_string())
        .arg("--exit-code")
        .arg("0");
    command.creation_flags(CREATE_NO_WINDOW);

    let child = command.spawn().expect("the child fixture must start");
    println!(
        "memwatch-fixture started pid={} child={}",
        std::process::id(),
        child.id()
    );
    std::io::stdout().flush().expect("stdout must be flushed");
    child
}

/// Runs the load loop and returns the allocations so the caller can keep them
/// alive until the process exits.
fn run_load(args: &FixtureArgs) -> (Vec<Vec<u8>>, Vec<HBRUSH>) {
    let start = Instant::now();
    let end = start + args.duration;
    let mut allocations: Vec<Vec<u8>> = Vec::new();
    let mut brushes: Vec<HBRUSH> = Vec::new();

    let mut tick = 0u64;
    while start.elapsed() < args.duration {
        if args.alloc_mb_per_sec > 0 {
            let bytes = args.alloc_mb_per_sec * 1024 * 1024;
            allocations.push(vec![0xAB; bytes as usize]);
        }
        if tick == 0 {
            for _ in 0..args.gdi {
                // SAFETY: the brush is a plain GDI object held until exit.
                let brush = unsafe { CreateSolidBrush(COLORREF(0x00AB_CDEF)) };
                if !brush.is_invalid() {
                    brushes.push(brush);
                }
            }
        }
        tick += 1;

        busy_wait(args.busy_ms_per_sec);

        let next_tick = start + Duration::from_secs(tick);
        std::thread::sleep(next_tick.min(end).saturating_duration_since(Instant::now()));
    }

    (allocations, brushes)
}

/// Spins the CPU for `millis` milliseconds.
fn busy_wait(millis: u64) {
    if millis == 0 {
        return;
    }
    let deadline = Instant::now() + Duration::from_millis(millis);
    let mut state = 1u64;
    while Instant::now() < deadline {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
    }
    std::hint::black_box(state);
}
