use crate::types::{BenchCaseResult, BenchResults, Phase, SampleStats};
use std::time::{Duration, Instant};

// ─── /proc helpers ────────────────────────────────────────────────────────────

fn read_vm_hwm_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status").ok().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("VmHWM:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
    })
}

/// Max temperature across all /sys/class/thermal/thermal_zone* sensors (°C).
/// Android reports millidegrees; values > 1000 are divided by 1000.
/// Returns None if no readable sensor is found.
fn read_max_thermal_celsius() -> Option<f64> {
    let mut max: Option<f64> = None;
    for zone in 0..30u32 {
        let path = format!("/sys/class/thermal/thermal_zone{zone}/temp");
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(raw) = s.trim().parse::<i64>() {
                let t = if raw > 1000 { raw as f64 / 1000.0 } else { raw as f64 };
                if (10.0..150.0).contains(&t) {
                    max = Some(max.unwrap_or(f64::NEG_INFINITY).max(t));
                }
            }
        }
    }
    max
}

// ─── Config ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct BenchConfig {
    pub warmup_reps:          u32,
    /// Total measured repetitions (= batch_size × ⌈total/batch_size⌉).
    pub bench_reps:           u32,
    /// Reps per batch; an inter-batch pause follows each completed batch.
    pub batch_size:           u32,
    /// Sleep between individual reps within a batch.
    pub inter_rep_sleep_ms:   u64,
    /// Fixed pause between batches (used as poll interval when thermal_limit is set).
    pub inter_batch_sleep_ms: u64,
    /// Sleep between consecutive benchmark cases.
    pub inter_case_sleep_ms:  u64,
    /// If Some(t), wait between batches until all sensors read ≤ t °C.
    /// Falls back to a fixed inter_batch_sleep_ms pause when thermals are unavailable.
    pub thermal_limit_celsius: Option<f64>,
}

// ─── Internal case representation ─────────────────────────────────────────────

struct BenchCase {
    category: String,
    name:     String,
    phase:    Phase,
    batch_k:  Option<u64>,
    func:     Box<dyn Fn() -> (usize, bool) + Send + Sync>,
}

// ─── Suite ────────────────────────────────────────────────────────────────────

pub struct BenchSuite {
    cfg:          BenchConfig,
    cases:        Vec<BenchCase>,
    /// Redirect progress lines to stderr so stdout is clean CSV when true.
    pub quiet_stdout: bool,
    /// Set via `--case` in main.rs: substring filter (case-insensitive) on
    /// the formatted case label, checked before `setup` runs.
    pub case_filter: Option<String>,
}

impl BenchSuite {
    pub fn new(cfg: BenchConfig) -> Self {
        Self { cfg, cases: Vec::new(), quiet_stdout: false, case_filter: None }
    }

    pub fn case_count(&self) -> usize { self.cases.len() }

    /// Register a benchmark where setup is run once before all repetitions.
    ///
    /// `setup` is called immediately (not timed); its output is shared across
    /// every repetition.  `work` is called `bench_reps` times and timed.
    /// Returns `(proof_bytes, verify_ok)`.
    pub fn register<S>(
        &mut self,
        category: impl Into<String>,
        name:     impl Into<String>,
        phase:    Phase,
        batch_k:  Option<u64>,
        setup:    impl FnOnce() -> S + 'static,
        work:     impl Fn(&S) -> (usize, bool) + Send + Sync + 'static,
    ) where S: Send + Sync + 'static {
        use std::sync::Arc;
        let name = name.into();
        let label = match batch_k {
            Some(k) => format!("{name}_k{k}"),
            None    => name.clone(),
        };
        if let Some(filter) = &self.case_filter {
            if !label.to_lowercase().contains(&filter.to_lowercase()) { return; }
        }
        let state = Arc::new(setup());
        self.cases.push(BenchCase {
            category: category.into(),
            name,
            phase,
            batch_k,
            func: Box::new(move || work(&state)),
        });
    }

    pub fn run(self) -> BenchResults {
        let mut results: Vec<BenchCaseResult> = Vec::new();
        let log = |s: String| if self.quiet_stdout { eprintln!("{s}") } else { println!("{s}") };

        for (idx, case) in self.cases.iter().enumerate() {
            let label = match case.batch_k {
                Some(k) => format!("{}_k{k}", case.name),
                None    => case.name.clone(),
            };
            log(format!("[{}/{}] {} / {}", idx + 1, self.cases.len(), case.category, label));

            // Warm-up (not timed, no sleep between reps).
            for _ in 0..self.cfg.warmup_reps {
                let _ = (case.func)();
            }

            let hwm_before = read_vm_hwm_kb();

            let total      = self.cfg.bench_reps;
            let batch_size = self.cfg.batch_size.max(1);
            let num_batches = total.div_ceil(batch_size);

            let mut durations:   Vec<Duration> = Vec::with_capacity(total as usize);
            let mut proof_sizes: Vec<usize>    = Vec::with_capacity(total as usize);
            let mut all_ok = true;
            let mut rep   = 0u32;

            for batch in 0..num_batches {
                if batch > 0 {
                    if let Some(limit) = self.cfg.thermal_limit_celsius {
                        loop {
                            let t = read_max_thermal_celsius();
                            if t.map(|c| c <= limit).unwrap_or(true) { break; }
                            log(format!("   [batch {batch}/{num_batches}] temp={:.1}°C > {limit}°C, waiting {}ms",
                                t.unwrap(), self.cfg.inter_batch_sleep_ms));
                            Self::sleep(self.cfg.inter_batch_sleep_ms);
                        }
                    } else {
                        Self::sleep(self.cfg.inter_batch_sleep_ms);
                    }
                }

                let batch_end = ((batch + 1) * batch_size).min(total);
                while rep < batch_end {
                    let t0 = Instant::now();
                    let (proof_sz, ok) = (case.func)();
                    durations.push(t0.elapsed());
                    proof_sizes.push(proof_sz);
                    if !ok { all_ok = false; }
                    rep += 1;
                    if rep < total { Self::sleep(self.cfg.inter_rep_sleep_ms); }
                }
            }

            let hwm_delta_kb = read_vm_hwm_kb()
                .zip(hwm_before)
                .map(|(after, before)| after.saturating_sub(before));

            let stats = SampleStats::from_durations(&durations);
            let proof_bytes = proof_sizes.iter().copied().max().unwrap_or(0);
            let mut samples_ms: Vec<f64> = durations
                .iter()
                .map(|d| (d.as_secs_f64() * 1_000.0 * 100.0).round() / 100.0)
                .collect();
            samples_ms.sort_by(f64::total_cmp);

            let temp_str = read_max_thermal_celsius()
                .map(|t| format!("  temp={t:.1}°C"))
                .unwrap_or_default();
            log(format!(
                "   mean={:.2}ms  median={:.2}ms  proof={}B  ok={}{}",
                stats.mean_ms, stats.median_ms, proof_bytes, all_ok, temp_str,
            ));

            results.push(BenchCaseResult {
                category: case.category.clone(),
                name:     case.name.clone(),
                phase:    case.phase,
                batch_k:  case.batch_k,
                stats,
                samples_ms,
                proof_bytes,
                all_verified: all_ok,
                hwm_delta_kb,
            });

            if idx + 1 < self.cases.len() {
                Self::sleep(self.cfg.inter_case_sleep_ms);
            }
        }

        BenchResults(results)
    }

    fn sleep(ms: u64) {
        if ms > 0 { std::thread::sleep(Duration::from_millis(ms)); }
    }
}
