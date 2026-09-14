#!/usr/bin/env bash
# scripts/android.sh — Android cross-compile and run helpers.
#
# Usage: android.sh <subcommand> [options]
#
# Subcommands:
#   build       Cross-compile mobile_bench (Rust) for Android/aarch64
#   build-lf    Cross-compile longfellow-zk (C++) for Android
#   run         Push mobile_bench via adb and run it on device
#   run-lf      Run longfellow benchmarks on device via adb and collect JSON
#
# Env vars (apply across subcommands where relevant):
#   ANDROID_NDK_HOME / ANDROID_NDK_ROOT  Path to the Android NDK
#   ADB_SERIAL                           Target a specific adb device
#   LONGFELLOW_DIR                       Path to the longfellow-zk checkout
#   REPS, COOLDOWN, OUTPUT               run-lf tuning

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if   [[ -f "$SCRIPT_DIR/Cargo.toml"    ]]; then PROJECT_ROOT="$SCRIPT_DIR"
elif [[ -f "$SCRIPT_DIR/../Cargo.toml" ]]; then PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else PROJECT_ROOT="$(pwd)"; fi

# ─── shared helpers ───────────────────────────────────────────────────────────

ADB=(adb)
[[ -n "${ADB_SERIAL:-}" ]] && ADB=(adb -s "$ADB_SERIAL")

adb_check() {
  command -v adb >/dev/null 2>&1 || { echo "[error] adb not found on PATH" >&2; exit 1; }
  if ! "${ADB[@]}" get-state >/dev/null 2>&1; then
    echo "[error] no device via adb. Check USB debugging + 'adb devices'." >&2; exit 1
  fi
}

ndk_root() {
  local ndk="${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-${NDK_HOME:-}}}"
  [[ -n "$ndk" && -d "$ndk" ]] || {
    echo "[error] set ANDROID_NDK_ROOT (or ANDROID_NDK_HOME) to your NDK path." >&2; exit 1; }
  echo "$ndk"
}

# First matching NDK llvm toolchain bin dir (host-agnostic: linux/darwin).
ndk_toolchain_bin() {
  local ndk="$1"
  set -- "$ndk"/toolchains/llvm/prebuilt/*/bin
  echo "$1"
}

# ─── build (Rust mobile_bench) ────────────────────────────────────────────────

cmd_build() {
  local abi="${ANDROID_ABI:-arm64-v8a}"
  local triple="${ANDROID_TRIPLE:-aarch64-linux-android}"
  local bin="${BIN_NAME:-mobile_bench}"
  # Pixel 10 Pro ships Android 15 (API 35).  Keep ≥28 for POSIX compat.
  export CARGO_NDK_PLATFORM="${ANDROID_PLATFORM:-35}"

  cd "$PROJECT_ROOT"
  echo "[build] project root: $PROJECT_ROOT"

  command -v cargo-ndk >/dev/null 2>&1 || {
    echo "[error] cargo-ndk not found.  Install: cargo install cargo-ndk" >&2; exit 1; }
  [[ -n "${ANDROID_NDK_HOME:-}${NDK_HOME:-}" ]] || {
    echo "[error] ANDROID_NDK_HOME is not set." >&2; exit 1; }
  rustup target list --installed 2>/dev/null | grep -qx "$triple" || {
    echo "[build] adding rust target $triple"; rustup target add "$triple"; }

  # Allow vendored OpenSSL for Android: the NDK has no system libssl headers,
  # so openssl-sys must build from source.  OPENSSL_NO_VENDOR=1 in config.toml
  # is right for host builds but wrong here; shell env beats config.toml (no
  # force=true), so exporting 0 suppresses the config value.
  export OPENSSL_NO_VENDOR=0

  # Optional device-specific CPU target.
  # Pixel 10 Pro (Tensor G5, Cortex-X4 prime core):
  #   ANDROID_TARGET_CPU=cortex-x4 ./scripts/android.sh build
  # This appends -C target-cpu=X on top of the features in config.toml,
  # giving LLVM the full prime-core ISA (SVE2, i8mm, bf16 …).
  # Only use when you pin --pin-core to the matching big core at runtime.
  #
  # IMPORTANT: RUSTFLAGS, if set at all (even ""), completely overrides
  # .cargo/config.toml's per-target `rustflags` rather than merging with it.
  # So we only export RUSTFLAGS when the user actually opted into a CPU
  # override — otherwise we let cargo pick up config.toml's baseline
  # features (+neon,+aes,+sha2,+sha3,+crc,+lse,+rdm,+dotprod) untouched.
  echo "[build] ABI=$abi  API=$CARGO_NDK_PLATFORM  NDK=${ANDROID_NDK_HOME:-${NDK_HOME:-?}}"
  echo "[build] OPENSSL_NO_VENDOR=0 (vendored build, NDK clang)"
  echo "[build] cargo ndk build --release --bin $bin ..."
  if [[ -n "${ANDROID_TARGET_CPU:-}" ]]; then
    echo "[build] target-cpu override: ${ANDROID_TARGET_CPU}"
    RUSTFLAGS="-C target-cpu=${ANDROID_TARGET_CPU}" cargo ndk -t "$abi" build --release --bin "$bin"
  else
    cargo ndk -t "$abi" build --release --bin "$bin"
  fi

  local out="$PROJECT_ROOT/dist"
  rm -rf "$out"; mkdir -p "$out"
  local src="target/$triple/release/$bin"
  [[ -f "$src" ]] || { echo "[error] $src not found — build failed" >&2; exit 1; }
  cp "$src" "$out/$bin"; chmod +x "$out/$bin"

  echo ""
  echo "=================================================================="
  echo " Binary: $out/$bin"
  command -v file >/dev/null 2>&1 && file "$out/$bin" | sed 's/^/   /'
  echo ""
  echo " Push and run:"
  echo "   ./scripts/android.sh run [--quick] [--csv] [--pin-core 7]"
  echo "=================================================================="
}

# ─── build-lf (C++ longfellow-zk) ─────────────────────────────────────────────

cmd_build_lf() {
  local api="${ANDROID_API:-34}"
  local abi="arm64-v8a"
  local jobs; jobs="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)"

  local ndk_path; ndk_path="$(ndk_root)"
  export ANDROID_NDK_ROOT="$ndk_path"
  local toolchain="$ndk_path/build/cmake/android.toolchain.cmake"
  local tc_bin; tc_bin="$(ndk_toolchain_bin "$ndk_path")"
  [[ -d "$tc_bin" ]] || { echo "[error] NDK llvm toolchain bin not found." >&2; exit 1; }

  # locate longfellow checkout
  local lf_root=""
  for d in "${LONGFELLOW_DIR:-}" "$PROJECT_ROOT/vendor/longfellow-zk" \
            "$PROJECT_ROOT/longfellow-zk" "$PROJECT_ROOT/../longfellow-zk"; do
    [[ -n "$d" && -f "$d/lib/CMakeLists.txt" ]] && { lf_root="$d"; break; }
  done
  [[ -n "$lf_root" ]] || {
    echo "[error] Could not find longfellow checkout. Set LONGFELLOW_DIR=/path/to/longfellow-zk" >&2
    exit 1; }
  lf_root="$(cd "$lf_root" && pwd)"
  cd "$lf_root"
  echo "[lf] longfellow root: $lf_root"
  echo "[lf] NDK=$ndk_path  ABI=$abi  API=$api  jobs=$jobs"

  local deps="$lf_root/deps-android"
  local src="$lf_root/deps-src"
  mkdir -p "$deps" "$src"

  local common=( -DCMAKE_TOOLCHAIN_FILE="$toolchain"
                 -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$api"
                 -DANDROID_STL=c++_static
                 -DCMAKE_INSTALL_PREFIX="$deps"
                 -DCMAKE_BUILD_TYPE=Release )

  # 1. googletest
  [[ -d "$src/googletest" ]] || git clone --depth 1 https://github.com/google/googletest.git "$src/googletest"
  echo "[lf] building googletest"
  cmake -S "$src/googletest" -B "$src/googletest/build-android" "${common[@]}" \
        -DBUILD_GTEST=ON -DBUILD_GMOCK=ON
  cmake --build "$src/googletest/build-android" --target install --parallel "$jobs"

  # 2. google-benchmark
  [[ -d "$src/benchmark" ]] || git clone --depth 1 https://github.com/google/benchmark.git "$src/benchmark"
  echo "[lf] building google-benchmark"
  cmake -S "$src/benchmark" -B "$src/benchmark/build-android" "${common[@]}" \
        -DBENCHMARK_ENABLE_TESTING=OFF -DBENCHMARK_ENABLE_GTEST_TESTS=OFF \
        -DBENCHMARK_ENABLE_LIBPFM=OFF
  cmake --build "$src/benchmark/build-android" --target install --parallel "$jobs"

  # 3. zstd (CMake lives under build/cmake)
  [[ -d "$src/zstd" ]] || git clone --depth 1 https://github.com/facebook/zstd.git "$src/zstd"
  echo "[lf] building zstd"
  cmake -S "$src/zstd/build/cmake" -B "$src/zstd/build-android" "${common[@]}" \
        -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_STATIC=ON -DZSTD_BUILD_PROGRAMS=OFF
  cmake --build "$src/zstd/build-android" --target install --parallel "$jobs"

  # 4. OpenSSL (slow; slimmed to what longfellow uses)
  [[ -d "$src/openssl" ]] || git clone --depth 1 https://github.com/openssl/openssl.git "$src/openssl"
  echo "[lf] building openssl (slow)"
  (
    cd "$src/openssl"
    export PATH="$tc_bin:$PATH"
    CFLAGS="-Wno-macro-redefined" ./Configure android-arm64 -D__ANDROID_API__="$api" \
        --prefix="$deps" \
        no-autoalginit no-autoerrinit no-tls no-dtls no-legacy no-apps no-docs \
        no-autoload-config no-quic no-zlib no-http no-threads no-mdc2 no-ui-console \
        no-winstore no-idea no-cast no-poly1305 no-siphash no-cmac no-chacha no-cmp \
        no-cms no-comp no-blake2 no-gost no-whirlpool no-camellia no-rc2 no-rc4 no-md4 \
        no-ml-dsa no-ml-kem no-argon2 no-aria no-dsa no-scrypt no-slh-dsa no-sm2 no-sm3 \
        no-sm4 no-sock no-srp no-srtp no-ssl-trace no-unstable-qlog no-uplink no-dso \
        no-multiblock no-tls1_1 no-tls1_2
    make -j"$jobs"
    make install_sw
  )
  echo "[lf] removing shared libs to force static linking"
  rm -f "$deps"/lib/*.so "$deps"/lib/*.so.* 2>/dev/null || true

  # 5. longfellow itself
  echo "[lf] building longfellow (lib/)"
  rm -rf build-android-arm64
  cmake -S lib -B build-android-arm64 \
        -DCMAKE_TOOLCHAIN_FILE="$toolchain" \
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$api" \
        -DANDROID_STL=c++_static \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_FIND_ROOT_PATH="$deps"
  cmake --build build-android-arm64 --config Release --parallel "$jobs"

  # 6. stage executables
  local out="$lf_root/dist-longfellow"
  rm -rf "$out"; mkdir -p "$out"
  echo "[lf] collecting benchmark executables"
  mapfile -t BINS < <(find build-android-arm64 -type f -perm -u+x \
                        \( -name '*_test' -o -iname '*benchmark*' \) \
                        ! -iname '*.so' ! -iname '*.a' ! -iname '*.o' \
                        ! -iname '*.cmake' ! -iname '*.txt' 2>/dev/null | sort -u)
  if [[ ${#BINS[@]} -eq 0 ]]; then
    echo "[warn] no *_test executables found under build-android-arm64/" >&2
  else
    for b in "${BINS[@]}"; do cp "$b" "$out/" && echo "   $(basename "$b")"; done
  fi

  echo ""
  echo "=================================================================="
  echo " Benchmark binaries in: $out"
  echo ""
  echo " The mdoc benchmarks live in: mdoc_revocation_test"
  echo " Run them with:  ./scripts/android.sh run-lf"
  echo "=================================================================="
}

# ─── run (Rust mobile_bench on device) ────────────────────────────────────────

# Detect the CPU number with the highest max-frequency (= prime/big core).
# Falls back to $1 (the caller-supplied default) if sysfs is unavailable.
_detect_big_core() {
  local default_core="$1"
  local best_core="" best_freq=0
  local info
  # Read max_freq for each online CPU via adb; pick the highest.
  info="$("${ADB[@]}" shell "
    for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
      f=\$cpu/cpufreq/scaling_max_freq
      n=\${cpu##*cpu}
      [ -f \"\$f\" ] && printf '%s %s\n' \"\$n\" \"\$(cat \$f)\"
    done
  " 2>/dev/null | tr -d '\r')"
  while read -r num freq; do
    [[ "$freq" =~ ^[0-9]+$ ]] || continue
    if (( freq > best_freq )); then best_freq=$freq; best_core=$num; fi
  done <<< "$info"
  echo "${best_core:-$default_core}"
}

# Build a taskset prefix compatible with this device's toybox/util-linux
# `taskset`. Toybox's taskset does NOT support `-c <cpu-list>`; it takes a
# positional hex affinity MASK instead (e.g. `taskset 80 cmd` == CPU7).
# Probes availability + syntax and degrades to unpinned if either fails,
# since some Android builds don't even ship taskset.
_taskset_prefix_for_core() {
  local core="$1"
  if ! "${ADB[@]}" shell "command -v taskset" >/dev/null 2>&1; then
    echo "[run] taskset not available on device — running unpinned" >&2
    return 0
  fi
  local mask_hex; mask_hex="$(printf '%x' $(( 1 << core )))"
  if "${ADB[@]}" shell "taskset $mask_hex true" >/dev/null 2>&1; then
    echo "[run] taskset mask: 0x${mask_hex} (CPU${core})" >&2
    echo "taskset $mask_hex"
  else
    echo "[run] taskset present but mask syntax failed — running unpinned" >&2
  fi
}

cmd_run() {
  local csv_mode=0 quick_mode=0 mobile_cpu="" output="" thermal="" pin_core=""
  local remote_dir="/data/local/tmp"
  local bin="mobile_bench"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --csv)        csv_mode=1 ;;
      --quick)      quick_mode=1 ;;
      --mobile-cpu) mobile_cpu="$2"; shift ;;
      --output)     output="$2"; shift ;;
      --thermal)    thermal="$2"; shift ;;
      --pin-core)   pin_core="$2"; shift ;;
      *) echo "[warn] unknown flag: $1" >&2 ;;
    esac
    shift
  done

  local src="$PROJECT_ROOT/dist/$bin"
  [[ -f "$src" ]] || {
    echo "[error] $src not found. Build first: ./scripts/android.sh build" >&2; exit 1; }

  adb_check

  echo "[run] removing any existing $bin on device"
  "${ADB[@]}" shell "rm -f $remote_dir/$bin"

  echo "[run] pushing $bin to $remote_dir/"
  "${ADB[@]}" push "$src" "$remote_dir/$bin" >/dev/null
  "${ADB[@]}" shell "chmod +x $remote_dir/$bin"

  # ── CPU pinning ─────────────────────────────────────────────────────────────
  # Tensor G5 (Pixel 10 Pro): CPU0-3=A520, CPU4-6=A725, CPU7=X4.
  # ANDROID_BIG_CORE env var or --pin-core flag override auto-detect.
  local big_core="${pin_core:-${ANDROID_BIG_CORE:-}}"
  if [[ -z "$big_core" ]]; then
    printf '[run] detecting big core ... '
    big_core="$(_detect_big_core 7)"
    echo "CPU${big_core}"
  fi

  # Try to set the performance cpufreq governor for the big core.
  # Requires root; fails silently on most user-build phones.
  local gov_path="/sys/devices/system/cpu/cpufreq/policy${big_core}/scaling_governor"
  if "${ADB[@]}" shell "[ -w '$gov_path' ] && echo performance > '$gov_path'" >/dev/null 2>&1; then
    echo "[run] cpufreq governor → performance (CPU${big_core})"
  else
    echo "[run] cpufreq governor: read-only (no root) — pinning to core is still effective"
  fi

  local taskset_prefix
  taskset_prefix="$(_taskset_prefix_for_core "$big_core")"

  # ── flags for mobile_bench ─────────────────────────────────────────────────
  local flags=""
  [[ "$quick_mode" -eq 1 ]] && flags="$flags --quick"
  [[ -n "$thermal" ]]       && flags="$flags --thermal $thermal"

  echo "[run] pinned to CPU${big_core}  flags:${flags:- (none)}"

  # ── run ────────────────────────────────────────────────────────────────────
  if [[ "$csv_mode" -eq 1 ]]; then
    if [[ -z "$mobile_cpu" ]]; then
      local model; model="$("${ADB[@]}" shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
      mobile_cpu="$(printf '%s' "$model" | sed 's/[^a-zA-Z0-9_-]/_/g')"
      [[ -z "$mobile_cpu" ]] && mobile_cpu="android_device"
    fi
    [[ -z "$output" ]] && output="$PROJECT_ROOT/results/mobile/${mobile_cpu}.csv"
    mkdir -p "$(dirname "$output")"

    echo "[run] mode=CSV  device=$mobile_cpu  output=$output"
    "${ADB[@]}" shell "cd $remote_dir && $taskset_prefix ./$bin $flags --csv 2>/dev/null > mobile.csv"
    "${ADB[@]}" pull "$remote_dir/mobile.csv" "$output" >/dev/null
    echo "[run] done — CSV saved to: $output"
  else
    echo "[run] mode=interactive"
    "${ADB[@]}" shell "cd $remote_dir && $taskset_prefix ./$bin $flags"
  fi
}

# ─── run-lf (longfellow benchmarks on device) ─────────────────────────────────

cmd_run_lf() {
  local reps="${REPS:-5}"
  local cooldown="${COOLDOWN:-20}"
  local output="${OUTPUT:-/tmp/longfellow.json}"
  local remote_dir="${REMOTE_DIR:-/data/local/tmp/lf}"

  adb_check

  local lf_root=""
  for d in "${LONGFELLOW_DIR:-}" "$PROJECT_ROOT/vendor/longfellow-zk" \
            "$PROJECT_ROOT/longfellow-zk" "$PROJECT_ROOT/../longfellow-zk"; do
    [[ -n "$d" && -f "$d/lib/CMakeLists.txt" ]] && { lf_root="$d"; break; }
  done

  local binpath=""
  if [[ -n "${BIN:-}" && -f "${BIN:-}" ]]; then
    binpath="$BIN"
  elif [[ -n "$lf_root" ]]; then
    binpath="$(find "$lf_root" -type f -perm -u+x -name 'mdoc_revocation_test' 2>/dev/null | head -n1 || true)"
  fi
  [[ -n "$binpath" && -f "$binpath" ]] || {
    echo "[error] mdoc_revocation_test not found. Set BIN= or LONGFELLOW_DIR=" >&2
    exit 1; }
  local binname; binname="$(basename "$binpath")"
  echo "[run-lf] binary : $binpath"
  echo "[run-lf] reps=$reps  cooldown=${cooldown}s  output=$output"

  "${ADB[@]}" shell "mkdir -p $remote_dir" >/dev/null
  "${ADB[@]}" shell "rm -f $remote_dir/$binname"
  "${ADB[@]}" push "$binpath" "$remote_dir/$binname" >/dev/null
  "${ADB[@]}" shell "chmod +x $remote_dir/$binname" >/dev/null
  echo "[run-lf] pushed to $remote_dir/$binname"

  local benches=( BM_MdocCircuitCompile BM_MdocRevocationProver BM_MdocRevocationVerifier )
  local WORK; WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT

  for bench in "${benches[@]}"; do
    echo ""
    echo "[run-lf] === $bench ==="
    for i in $(seq 1 "$reps"); do
      printf '   rep %d/%d ... ' "$i" "$reps"
      local remote_json="$remote_dir/${bench}_${i}.json"
      local ldp=""; [[ "${REMOTE_LDPATH:-0}" == "1" ]] && ldp="LD_LIBRARY_PATH=$remote_dir "
      local dev_out
      dev_out="$("${ADB[@]}" shell "cd $remote_dir && ${ldp}./$binname \
            --benchmark_filter='^${bench}\$' \
            --benchmark_min_time=1x \
            --benchmark_format=json --benchmark_out='$remote_json' 2>&1; echo __RC=\$?")"
      local rc
      rc="$(printf '%s' "$dev_out" | sed -n 's/.*__RC=\([0-9]*\).*/\1/p' | tail -1)"
      if "${ADB[@]}" pull "$remote_json" "$WORK/${bench}_${i}.json" >/dev/null 2>&1 \
         && python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if any(b.get('name')=='$bench' and 'real_time' in b
                  for b in d.get('benchmarks',[])) else 1)
" "$WORK/${bench}_${i}.json" 2>/dev/null; then
        echo "ok"
      else
        rm -f "$WORK/${bench}_${i}.json"
        echo "RUN FAILED (rc=${rc:-?}, no valid JSON)"
        printf '%s\n' "$dev_out" | grep -v '__RC=' | sed 's/^/      /' >&2
      fi
      [[ "$i" -lt "$reps" ]] && sleep "$cooldown"
    done
  done

  echo ""
  echo "[run-lf] merging into $output"
  python3 - "$WORK" "$output" <<'PY'
import json, glob, os, sys, statistics as st
work, out = sys.argv[1], sys.argv[2]
files = sorted(glob.glob(os.path.join(work, "*.json")))
if not files:
    sys.exit("no per-rep JSON collected -- all runs failed?")
context = None
runs = {}
for f in files:
    try: d = json.load(open(f))
    except Exception: continue
    if context is None and "context" in d: context = d["context"]
    for b in d.get("benchmarks", []):
        if b.get("run_type", "iteration") != "aggregate":
            runs.setdefault(b["name"], []).append(b)
merged = []
for name, entries in runs.items():
    unit = entries[0].get("time_unit", "ns")
    for idx, e in enumerate(entries):
        e = dict(e); e["run_type"] = "iteration"
        e["repetition_index"] = idx; e["repetitions"] = len(entries)
        merged.append(e)
    def agg(field, fn):
        vals = [e[field] for e in entries if field in e]
        return fn(vals) if vals else 0.0
    for aname, fn in (("mean", st.mean), ("median", st.median),
                      ("stddev", (lambda v: st.stdev(v) if len(v) > 1 else 0.0))):
        merged.append({"name": f"{name}_{aname}", "run_name": name,
                        "run_type": "aggregate", "aggregate_name": aname,
                        "repetitions": len(entries), "time_unit": unit,
                        "real_time": agg("real_time", fn),
                        "cpu_time":  agg("cpu_time",  fn),
                        "iterations": entries[0].get("iterations", 1)})
json.dump({"context": context or {}, "benchmarks": merged}, open(out, "w"), indent=2)
print(f"   {len(runs)} benchmarks, {sum(len(v) for v in runs.values())} measured reps -> {out}")
PY

  echo ""
  echo "=================================================================="
  echo " Done. Raw Google Benchmark JSON saved to: $output"
  echo "=================================================================="
}

# ─── dispatch ────────────────────────────────────────────────────────────────

CMD="${1:-}"
[[ $# -gt 0 ]] && shift

case "$CMD" in
  build)    cmd_build    "$@" ;;
  build-lf) cmd_build_lf "$@" ;;
  run)      cmd_run      "$@" ;;
  run-lf)   cmd_run_lf   "$@" ;;
  *)
    echo "Usage: $(basename "$0") {build|build-lf|run|run-lf} [opts]" >&2
    echo "" >&2
    echo "  build                     Cross-compile mobile_bench (Rust) for Android/aarch64" >&2
    echo "  build-lf                  Cross-compile longfellow-zk (C++) for Android" >&2
    echo "  run [--quick] [--csv]     Push mobile_bench via adb and run on device" >&2
    echo "      [--mobile-cpu SLUG]   Device CPU slug (auto-detected from ro.product.model)" >&2
    echo "      [--output FILE]       CSV destination (default: results/mobile/<slug>.csv)" >&2
    echo "      [--thermal N]         Cool-down threshold °C (passed to mobile_bench)" >&2
    echo "      [--pin-core N]        Pin to CPU N (auto-detects big core if omitted)" >&2
    echo "  run-lf                    Run longfellow benchmarks on device and collect JSON" >&2
    echo "" >&2
    echo "Env (build): ANDROID_NDK_HOME, ANDROID_PLATFORM (default 35), ANDROID_TARGET_CPU" >&2
    echo "     e.g.  ANDROID_TARGET_CPU=cortex-x4 ./scripts/android.sh build" >&2
    echo "Env (run):   ADB_SERIAL, ANDROID_BIG_CORE (default: auto-detect by max_freq)" >&2
    echo "Env (run-lf): LONGFELLOW_DIR, REPS, COOLDOWN, OUTPUT" >&2
    exit 1 ;;
esac