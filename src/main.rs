//! Mobile-friendly benchmark runner — phases (iv) Holder Update, (v) Presentation, (vi) Verification.
//!
//! Server-side phases (i)–(iii) are in `benches/server.rs` (criterion).
//!
//! Usage:
//!   cargo run --release -- [--quick] [--json <path>] [--csv] [--thermal <°C>] [--reps N] [--only mechanism]
//!
//! --quick          200 reps, short sleeps, no thermal gate (fast, no cooling waits)
//! --json PATH      Write machine-readable results to PATH
//! --csv            Print results as CSV to stdout; progress goes to stderr
//! --thermal FLOAT  Override thermal throttle threshold in °C (full mode only; --quick always disables it)
//! --reps N         Override bench_reps from --quick/full defaults
//! --only NAME      Only register one mechanism: kb21 | clrsab | bbsbpp | ecdsa
//! --case SUBSTR    Only run cases whose label contains SUBSTR, e.g. "witness_update_k4096"

// wasmer (transitive via proof_system → legogroth16) was compiled against an
// older Rust that exported __rust_probestack for stack-overflow detection.
// Rust ≥1.77 switched to inline-asm probes; this stub satisfies the linker.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __rust_probestack() {}

mod bench_bbs_bpp;
mod bench_cl_rsa_b;
mod bench_ecdsa;
mod bench_kb21;
mod runner;
mod types;

use runner::{BenchConfig, BenchSuite};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let quick    = args.iter().any(|a| a == "--quick");
    let csv_mode = args.iter().any(|a| a == "--csv");
    let json_path: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--json")
        .map(|w| w[1].clone());
    let thermal_override: Option<f64> = args
        .windows(2)
        .find(|w| w[0] == "--thermal")
        .and_then(|w| w[1].parse().ok());
    let reps_override: Option<u32> = args
        .windows(2)
        .find(|w| w[0] == "--reps")
        .and_then(|w| w[1].parse().ok());
    let only_filter: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--only")
        .map(|w| w[1].to_lowercase());
    let case_filter: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--case")
        .map(|w| w[1].clone());

    // Warmup = one full batch: lets DVFS ramp-up, allocator growth, and
    // one-time costs (e.g. rayon's thread-pool spin-up) settle before any
    // timed rep runs, instead of leaving that to chance across 1 rep.
    let mut cfg = if quick {
        BenchConfig {
            warmup_reps:          50,
            bench_reps:           200,
            batch_size:           50,
            inter_rep_sleep_ms:   10,
            inter_batch_sleep_ms: 100,
            inter_case_sleep_ms:  200,
            // --quick always disables the thermal gate, even if --thermal is
            // also passed — a hot, single-core-pinned run can otherwise stall
            // waiting for a threshold this laptop won't reach.
            thermal_limit_celsius: None,
        }
    } else {
        BenchConfig {
            warmup_reps:          5,
            bench_reps:           50,
            batch_size:           5,
            inter_rep_sleep_ms:   100,
            inter_batch_sleep_ms: 5_000,
            inter_case_sleep_ms:  2_000,
            thermal_limit_celsius: thermal_override.or(Some(45.0)),
        }
    };
    if let Some(r) = reps_override { cfg.bench_reps = r; }

    let want = |name: &str| only_filter.as_deref().map(|f| f == name).unwrap_or(true);
    let active_mechs: Vec<&str> = [("kb21", "KB21"), ("clrsab", "CL-RSA-B"), ("bbsbpp", "BBS-BP"), ("ecdsa", "ECDSA-LF")]
        .iter().filter(|(k, _)| want(k)).map(|(_, label)| *label).collect();

    // In CSV mode all progress/banner output goes to stderr so stdout stays clean CSV.
    let banner = |s: &str| if csv_mode { eprintln!("{s}") } else { println!("{s}") };
    banner("=================================================================");
    banner(" Revocation Comparison Benchmark Suite — mobile runner");
    banner(&format!(" Mechanisms: {}", active_mechs.join(" | ")));
    banner("=================================================================");
    banner(&format!(" Mode      : {}", if quick { "QUICK" } else { "FULL" }));
    banner(&format!(" Reps      : {} warmup + {} bench ({} per batch, {} batches)",
        cfg.warmup_reps, cfg.bench_reps, cfg.batch_size,
        cfg.bench_reps.div_ceil(cfg.batch_size)));
    banner(&format!(" Cool-down : {}ms/rep  {}ms/batch  {}ms/case",
        cfg.inter_rep_sleep_ms, cfg.inter_batch_sleep_ms, cfg.inter_case_sleep_ms));
    match cfg.thermal_limit_celsius {
        Some(t) => banner(&format!(" Thermal   : wait between batches if temp > {t}°C")),
        None    => banner(" Thermal   : disabled (fixed inter-batch pause)"),
    }
    if let Some(c) = &case_filter { banner(&format!(" Case      : {c}")); }
    banner("=================================================================\n");

    let mut suite = BenchSuite::new(cfg);
    suite.quiet_stdout = csv_mode;
    suite.case_filter  = case_filter;

    if want("kb21")   { bench_kb21::register(&mut suite); }
    if want("clrsab") { bench_cl_rsa_b::register(&mut suite); }
    if want("bbsbpp") { bench_bbs_bpp::register(&mut suite); }
    if want("ecdsa")  { bench_ecdsa::register(&mut suite); }

    if suite.case_filter.is_some() && suite.case_count() == 0 {
        eprintln!("[error] --case matched no registered cases — check spelling/mechanism (--only).");
        std::process::exit(1);
    }

    let results = suite.run();

    if csv_mode {
        results.print_csv();
    } else {
        results.print_table();
        let json = results.to_json();
        if let Some(path) = json_path {
            std::fs::write(&path, &json).expect("failed to write JSON");
            println!("\nJSON results written to: {path}");
        }
    }
}
