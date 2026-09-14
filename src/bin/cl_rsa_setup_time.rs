/// Wall-clock timer for CL-RSA-B Setup (prime generation).
/// Criterion is impractical here (10–60 s/iter).
/// Prints human-readable stats to stderr and one CSV key=value row to stdout.
use cl_rsa_b::accumulator::CLRSABAccumulator;
use common::accumulator::Accumulator;
use std::time::Instant;

const N: usize = 5;

fn main() {
    eprintln!("CL-RSA-B Setup: {} iterations (1536-bit safe-prime generation)", N);

    let mut times_ms = Vec::with_capacity(N);
    for i in 0..N {
        let t = Instant::now();
        let _ = CLRSABAccumulator::new();
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        eprintln!("  iter {}/{}: {:.0} ms", i + 1, N, ms);
        times_ms.push(ms);
    }

    times_ms.sort_by(f64::total_cmp);
    let mean   = times_ms.iter().sum::<f64>() / N as f64;
    let var    = times_ms.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / N as f64;
    let stddev = var.sqrt();
    let median = times_ms[N / 2];
    let min    = times_ms[0];
    let max    = times_ms[N - 1];

    println!("mean_ms={:.4},stddev_ms={:.4},median_ms={:.4},min_ms={:.4},max_ms={:.4},n={}",
             mean, stddev, median, min, max, N);

    eprintln!("mean={:.0} ms  std={:.0} ms  median={:.0} ms  [{:.0}–{:.0} ms]",
              mean, stddev, median, min, max);
}
