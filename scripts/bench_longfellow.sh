#!/usr/bin/env bash
# Run longfellow-zk benchmarks and write raw Google Benchmark JSON output.
#
# TS-14 phases covered
# --------------------
#   (v)  Presentation -- BM_MdocRevocationProver   (Signed Pairs non-revocation ZK proof)
#   (vi) Verification -- BM_MdocRevocationVerifier (injected by build_longfellow.sh)
#
# Also runs BM_MdocCircuitCompile (also injected by build_longfellow.sh): a
# one-time, input-independent circuit-compile cost (~900ms) that is cached to
# disk after first run and never repeated per presentation. It is NOT one of
# phases i-vi -- it's recorded only so the one-time cost and its circuit_bytes
# (serialized cache size) are documented in the output.
#
# BM_MdocRevocationProver is the Signed Pairs benchmark:
#   Circuit: MdocRevocationSpan<LogicCircuit, Fp256Base, P256>
#   Proves:  ECDSA-P256 signature on span (epoch, left_id, right_id) is valid
#            AND left < holder_id < right
#   Backend: Ligero over Fp256Base, RS rate=7, queries=132, domain 2^31
#
# Server-side phases (i-iii) are standard ECDSA-P256 keygen/sign operations
# and are negligible compared to ZK proof generation -- not benchmarked here.
#
# Usage:
#   ./scripts/bench_longfellow.sh [--quick] [--out-dir <dir>] [--no-build]
#
#   --quick        3 repetitions, minimal warm-up (suitable for CI)
#   --out-dir DIR  write JSON files to DIR/ (default: results/longfellow/)
#   --no-build     skip build step (assumes build-release already exists)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
BUILD="$ROOT/vendor/longfellow-zk/build-release"

QUICK=0
OUT_DIR="$ROOT/results/longfellow"
NO_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)    QUICK=1 ;;
    --out-dir)  OUT_DIR="$2"; shift ;;
    --no-build) NO_BUILD=1 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
  shift
done

# -- Build if not suppressed --------------------------------------------------
if [[ "$NO_BUILD" -eq 0 ]]; then
  "$SCRIPT_DIR/build_longfellow.sh"
fi

# -- Locate mdoc_revocation_test binary ---------------------------------------
REVOC_BIN=$(find "$BUILD" -name "mdoc_revocation_test" -type f -perm /111 2>/dev/null | head -1)

if [[ -z "${REVOC_BIN:-}" ]]; then
  echo "Error: 'mdoc_revocation_test' binary not found under $BUILD" >&2
  echo "       Run ./scripts/build_longfellow.sh and try again." >&2
  exit 1
fi

# -- Benchmark parameters -----------------------------------------------------
# ZK proof generation takes several seconds per iteration; use a fixed number
# of repetitions rather than a wall-clock min_time target.
if [[ "$QUICK" -eq 1 ]]; then
  REPS=3
  MIN_TIME="0.001"   # effectively one run per rep for slow ZK provers
else
  REPS=10
  MIN_TIME="1.0"
fi

mkdir -p "$OUT_DIR"

# -- Run BM_MdocRevocationProver (Phase v) ------------------------------------
echo "[longfellow] Running BM_MdocRevocationProver"
echo "             (Phase v -- Signed Pairs non-revocation ZK proof)"
"$REVOC_BIN" \
  --benchmark_filter="BM_MdocRevocationProver" \
  --benchmark_format=json \
  --benchmark_out="$OUT_DIR/presentation.json" \
  --benchmark_repetitions="$REPS" \
  --benchmark_min_time="$MIN_TIME" \
  2>&1 | grep -vE "^$" || true

# -- Run BM_MdocRevocationVerifier (Phase vi) ---------------------------------
echo ""
echo "[longfellow] Running BM_MdocRevocationVerifier"
echo "             (Phase vi -- ZK proof verification)"
"$REVOC_BIN" \
  --benchmark_filter="BM_MdocRevocationVerifier" \
  --benchmark_format=json \
  --benchmark_out="$OUT_DIR/verification.json" \
  --benchmark_repetitions="$REPS" \
  --benchmark_min_time="$MIN_TIME" \
  2>&1 | grep -vE "^$" || true

# -- Run BM_MdocCircuitCompile (one-time cost, NOT one of phases i-vi) --------
# This is a one-off, input-independent cost (compiling the fixed ZK statement)
# that's cached to disk after the first run (proto/circuit_writer.h) and never
# repeated per presentation. We still record its time and its circuit_bytes
# size (serialized cache size) for documentation purposes.
echo ""
echo "[longfellow] Running BM_MdocCircuitCompile"
echo "             (one-time circuit compile/cache cost)"
"$REVOC_BIN" \
  --benchmark_filter="BM_MdocCircuitCompile" \
  --benchmark_format=json \
  --benchmark_out="$OUT_DIR/circuit_compile.json" \
  --benchmark_repetitions="$REPS" \
  --benchmark_min_time="$MIN_TIME" \
  2>&1 | grep -vE "^$" || true

echo ""
echo "=================================================================="
echo " Done. Raw Google Benchmark JSON written to:"
echo "   $OUT_DIR/presentation.json"
echo "   $OUT_DIR/verification.json"
echo "   $OUT_DIR/circuit_compile.json"
echo "=================================================================="
