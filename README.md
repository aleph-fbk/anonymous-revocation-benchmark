# anonymous-revocation-bench

Benchmarking of the anonymous revocation mechanisms under comparison for EUDI Wallet (TS-14), for a compelete discussion about the mechanisms refer to [Comparing Privacy-Preserving Revocation for the EUDI Wallet](https://eprint.iacr.org/2026/1824) by Flamini et al.

Two families are compared across a common six-phase lifecycle framework:

| Family | Mechanism | Library |
|:---|:---|:---|
| Accumulator | [CL-RSA-B] \([BCD+17]\) | local (`accumulators/cl-rsa-b`) |
| Accumulator | [KB21] (KBPositive) | [docknetwork/crypto] (`vb_accumulator`) |
| Signed Pairs | BBS-2023 + Bulletproofs++ | [docknetwork/crypto] (`bbs_plus`, `bulletproofs_plus_plus`, `proof_system`) |
| Signed Pairs | ECDSA + longfellow-zk | [google/longfellow-zk] (`scripts/bench_longfellow.sh`) |

---

## Lifecycle phases

| # | Name | Actor | Runner |
|:--|:---|:---|:---|
| i | **Setup** | Status Manager | Criterion (server) |
| ii | **Add** | Status Manager → Holder | Criterion (server) |
| iii | **Revocation** | Status Manager | Criterion (server) |
| iv | **Holder Update** | Holder | mobile runner |
| v | **Presentation** | Holder | mobile runner / longfellow |
| vi | **Verification** | Verifier | mobile runner / longfellow |

Phases i–iii run on server hardware via [Criterion.rs].
Phases iv–vi run on mobile hardware via the custom runner (`mobile_bench`).
ECDSA phases v–vi use the longfellow-zk C++ benchmarks (see below).

## Coverage map

What each mechanism actually measures per phase:

|#| Phase | KB21 | CL-RSA-B | BBS+BPP | ECDSA |
|:--|:--|:--|:--|:--|:--|
|i | **Setup** | params + keygen + acc init | safe-prime gen (see note) | BBS params + keygen + BPP gen setup | P-256 keygen |
|ii | **Add** | `add_batch(k)` + `issue_witness(1)` | `add_batch(k)` + `issue_witness(1)` | `sign_gap(1)` — 4 attrs | `sign_gap(1)` |
|iii | **Revocation** | upmessage publish (k G1 elements) | batch remove, publishes raw P_D | re-sign full list (`LIST_BASE_SIZE + k + 1` sigs) | re-sign full list |
|iv | **Holder Update** | upmessage eval (k G1 scalar mults) | ext-GCD + 2 modexp, O(k) | scan + BBS sig verify | scan + ECDSA verify |
|v | **Presentation** | NI-ZKP prove | NI-ZKP prove | BBS+BPP composite proof | longfellow-zk |
|vi | **Verification** | NI-ZKP verify | NI-ZKP verify | BBS+BPP composite verify | longfellow-zk |

---

## Install

### Rust

```bash
curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### System dependencies (host benchmarks)

```bash
# Debian / Ubuntu
sudo apt install -y libssl-dev pkg-config
```

### Android cross-compilation (mobile benchmarks)

```bash
rustup target add aarch64-linux-android
# Install NDK via Android Studio or:
#   https://developer.android.com/ndk/downloads
# Set ANDROID_NDK_HOME to the NDK root.
```

### longfellow-zk (ECDSA phases v–vi)

```bash
# Ubuntu / Debian
sudo apt install -y clang cmake libssl-dev libzstd-dev \
                    libgtest-dev libbenchmark-dev zlib1g-dev
```

---

## Taking the measurements

### 1 — Build

```bash
cargo build --release
```

### 2 — Server benchmarks (phases i–iii, Criterion)

```bash
cargo bench --bench server                   # all mechanisms
cargo bench --bench server -- "KB21"         # only KB21
cargo bench --bench server -- "CL-RSA-B"     # only CL-RSA-B  ⚠ slow (RSA prime gen)
cargo bench --bench server -- "BBS\+BPP"     # only BBS+BPP
cargo bench --bench server -- "ECDSA"        # only ECDSA
```

Criterion writes HTML reports and JSON estimates to `target/criterion/`.

#### CL-RSA-B Setup (prime generation — too slow for Criterion)

CL-RSA-B Setup generates two 1536-bit safe primes (10–60 s/iteration).
Run the dedicated timing binary once:

```bash
cargo run --release --bin cl_rsa_setup_time
```

The binary prints mean, stddev, median, min, max over 5 iterations to stdout
and progress to stderr. Redirect stdout to save it:

```bash
cargo run --release --bin cl_rsa_setup_time > cl_rsa_setup.txt
```

### 3 — Mobile runner (phases iv–vi, host or on-device)

```bash
# Full run: 50 reps in batches of 5, waits for ≤ 45 °C between batches
cargo run --release --bin mobile_bench

# Quick run: 200 reps in batches of 50, no thermal gate, short sleeps
cargo run --release --bin mobile_bench -- --quick

# Save results as JSON
cargo run --release --bin mobile_bench -- --json /tmp/mobile.json

# Write CSV to stdout (progress to stderr)
cargo run --release --bin mobile_bench -- --csv > results/mobile/$(hostname -s).csv

# Override thermal threshold
cargo run --release --bin mobile_bench -- --thermal 40
```

### 4 — Android (on-device, phases iv–vi)

```bash
# 1. Install cargo-ndk (once)
cargo install cargo-ndk
rustup target add aarch64-linux-android

# 2. Cross-compile.  ANDROID_TARGET_CPU=cortex-x4 targets e.g. a Tensor G5 prime core.
ANDROID_NDK_HOME=/path/to/ndk \
ANDROID_TARGET_CPU=cortex-x4 \
    ./scripts/android.sh build

# 3. Connect the phone (USB debugging on), then push and run.
#    --pin-core pins to a specific big core for consistent results.
./scripts/android.sh run --csv --pin-core 7
# → results/mobile/<model>.csv
```

> The binary is cross-compiled with ARMv8.2 ISA flags (`+neon,+sha2,+sha3,+aes,…`)
> and the sha2 hardware SHA-256 accelerator.  Without `--pin-core`, Android may run
> the benchmark on slow efficiency cores.

```bash
./scripts/android.sh run --quick      # 200 reps
./scripts/android.sh run --csv --mobile-cpu Pixel9Pro   # explicit device label
```

The device must be connected via adb with USB debugging enabled.

### 5 — longfellow-zk benchmarks (ECDSA phases v–vi, C++)

longfellow-zk is a C++ library cloned into `vendor/` and built with CMake + clang.
On x86_64 the build script enables `-march=native` (AVX2 + AES-NI).

```bash
./scripts/build_longfellow.sh
./scripts/bench_longfellow.sh --no-build
# → results/longfellow/presentation.json
# → results/longfellow/verification.json
# → results/longfellow/circuit_compile.json
```

Optional flags for `bench_longfellow.sh`:

| Flag | Default | Description |
|:---|:---|:---|
| `--quick` | off | 3 reps instead of 10 |
| `--out-dir DIR` | `results/longfellow/` | Where to write JSON output |
| `--no-build` | off | Skip build step |

#### Longfellow benchmark targets

| Target | Phase | Description |
|:---|:---|:---|
| `BM_MdocCircuitCompile` | (i) Setup | One-time circuit compilation (~900 ms on i5). Can be cached via `proto/circuit_writer.h`. |
| `BM_MdocRevocationProver` | (v) Presentation | Non-revocation ZK proof: Ligero over Fp256 proves a P-256 ECDSA signature on `(epoch, left, right)` is valid and `left < holder_id < right`. |
| `BM_MdocRevocationVerifier` | (vi) Verification | ZK proof verification: `recv_commitment()` + `verify()` on a pre-generated proof. |

#### Android (longfellow-zk on-device)

```bash
./scripts/android.sh build-lf    # cross-compile C++ binary for AArch64
./scripts/android.sh run-lf      # push and run on device
```

Output is raw Google Benchmark JSON.

---

## Output

Raw measurement output lands in three places, none of them committed to the repo:

| Source | Location | Format |
|:---|:---|:---|
| Server benchmarks (phases i–iii) | `target/criterion/` | Criterion HTML + JSON |
| Mobile runner (phases iv–vi) | `results/mobile/<cpu>.csv` | CSV (one row per case) |
| longfellow-zk (ECDSA phases v–vi) | `results/longfellow/*.json` | Google Benchmark JSON |

---

[CL-RSA-B]: https://doi.org/10.1109/EuroSP.2017.13
[BCD+17]: https://eprint.iacr.org/2017/043
[KB21]: https://eprint.iacr.org/2021/638.pdf
[docknetwork/crypto]: https://github.com/docknetwork/crypto
[google/longfellow-zk]: https://github.com/google/longfellow-zk
[Criterion.rs]: https://bheisler.github.io/criterion.rs/book/
