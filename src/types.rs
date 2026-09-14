use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration};

// ─── Phase ────────────────────────────────────────────────────────────────────

/// Mobile-runner lifecycle phase (iv = Holder Update, v = Presentation, vi = Verification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    HolderUpdate,
    Presentation,
    Verification,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::HolderUpdate => "iv",
            Phase::Presentation  => "v",
            Phase::Verification  => "vi",
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Statistics ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleStats {
    pub mean_ms:   f64,
    pub stddev_ms: f64,
    pub min_ms:    f64,
    pub p25_ms:    f64,
    pub median_ms: f64,
    pub p75_ms:    f64,
    pub p90_ms:    f64,
    pub p95_ms:    f64,
    pub p99_ms:    f64,
    pub max_ms:    f64,
}

impl SampleStats {
    pub fn from_durations(samples: &[Duration]) -> Self {
        assert!(!samples.is_empty(), "no samples");
        let mut ms: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1_000.0).collect();
        ms.sort_by(f64::total_cmp);
        let n = ms.len() as f64;
        let mean   = ms.iter().sum::<f64>() / n;
        let stddev = (ms.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n).sqrt();
        Self {
            mean_ms:   r2(mean),
            stddev_ms: r2(stddev),
            min_ms:    r2(ms[0]),
            p25_ms:    r2(percentile(&ms, 25.0)),
            median_ms: r2(percentile(&ms, 50.0)),
            p75_ms:    r2(percentile(&ms, 75.0)),
            p90_ms:    r2(percentile(&ms, 90.0)),
            p95_ms:    r2(percentile(&ms, 95.0)),
            p99_ms:    r2(percentile(&ms, 99.0)),
            max_ms:    r2(*ms.last().unwrap()),
        }
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn r2(v: f64) -> f64 { (v * 100.0).round() / 100.0 }

// ─── Per-case result ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchCaseResult {
    pub category:     String,
    pub name:         String,
    pub phase:        Phase,
    /// Batch size for parametric benchmarks (e.g. revocations per epoch).
    pub batch_k:      Option<u64>,
    pub stats:        SampleStats,
    /// Raw per-rep timings in milliseconds (sorted ascending).
    pub samples_ms:   Vec<f64>,
    /// Serialised proof size in bytes. Zero for operations that produce no proof.
    pub proof_bytes:  usize,
    /// True iff every repetition passed its internal verification check.
    pub all_verified: bool,
    /// Increase in process VmHWM (peak RSS) across all reps, in kibibytes.
    /// None on non-Linux or when /proc/self/status is unavailable.
    pub hwm_delta_kb: Option<u64>,
}

// ─── Aggregated results ───────────────────────────────────────────────────────

pub struct BenchResults(pub Vec<BenchCaseResult>);

impl BenchResults {
    /// Markdown table, one section per mechanism, columns padded to align.
    /// Full stats (stddev, percentiles, RAM delta) are in --json/--csv output;
    /// this view is just mean/median/proof/ok.
    pub fn print_table(&self) {
        const HEADERS: [&str; 6] = ["Case", "ph", "mean (ms)", "median (ms)", "proof (B)", "ok"];

        fn row_str(cells: &[String; 6], widths: &[usize; 6]) -> String {
            let padded: Vec<String> = cells.iter().enumerate()
                .map(|(i, c)| format!("{c:<w$}", w = widths[i]))
                .collect();
            format!("| {} |", padded.join(" | "))
        }

        fn flush(cat: &str, rows: &mut Vec<[String; 6]>) {
            if rows.is_empty() { return; }
            let mut widths: [usize; 6] = std::array::from_fn(|i| HEADERS[i].chars().count());
            for row in rows.iter() {
                for (i, w) in widths.iter_mut().enumerate() {
                    *w = (*w).max(row[i].chars().count());
                }
            }
            println!("\n### {cat}\n");
            println!("{}", row_str(&HEADERS.map(String::from), &widths));
            let sep: Vec<String> = widths.iter().map(|w| "-".repeat(w + 2)).collect();
            println!("|{}|", sep.join("|"));
            for row in rows.iter() { println!("{}", row_str(row, &widths)); }
            rows.clear();
        }

        let mut current_cat = String::new();
        let mut rows: Vec<[String; 6]> = Vec::new();
        for r in &self.0 {
            if r.category != current_cat {
                flush(&current_cat, &mut rows);
                current_cat = r.category.clone();
            }
            let label = match r.batch_k {
                Some(k) => format!("{}_k{k}", r.name),
                None    => r.name.clone(),
            };
            let ok = if r.all_verified { "✓" } else { "⚠ FAIL" };
            rows.push([
                label, r.phase.to_string(),
                format!("{:.2}", r.stats.mean_ms), format!("{:.2}", r.stats.median_ms),
                r.proof_bytes.to_string(), ok.to_string(),
            ]);
        }
        flush(&current_cat, &mut rows);
        println!();
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.0).expect("serialization failed")
    }

    /// CSV output, one row per benchmark case.
    /// Redirect stdout to collect: ./mobile_bench --csv > phone.csv
    pub fn print_csv(&self) {
        println!(
            "mechanism,phase,label,batch_k,source,\
             mean_ms,stddev_ms,\
             median_ms,p25_ms,p75_ms,p90_ms,p95_ms,p99_ms,\
             min_ms,max_ms,\
             proof_bytes,ok,hwm_delta_kb"
        );
        for r in &self.0 {
            let s = &r.stats;
            println!(
                "{mech},{phase},{label},{bk},mobile_runner,\
                 {mean:.4},{std:.4},\
                 {med:.4},{p25:.4},{p75:.4},{p90:.4},{p95:.4},{p99:.4},\
                 {min:.4},{max:.4},\
                 {proof},{ok},{hwm}",
                mech  = r.category,
                phase = r.phase,
                label = r.name,
                bk    = r.batch_k.map(|k| k.to_string()).unwrap_or_default(),
                mean  = s.mean_ms,  std  = s.stddev_ms,
                med   = s.median_ms, p25  = s.p25_ms,
                p75   = s.p75_ms,   p90  = s.p90_ms,
                p95   = s.p95_ms,   p99  = s.p99_ms,
                min   = s.min_ms,   max  = s.max_ms,
                proof = r.proof_bytes,
                ok    = r.all_verified,
                hwm   = r.hwm_delta_kb.map(|k| k.to_string()).unwrap_or_default(),
            );
        }
    }
}
