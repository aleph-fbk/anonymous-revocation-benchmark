#!/usr/bin/env bash
# Build Google's longfellow-zk from source using CMake + clang.
#
# Clones into vendor/longfellow-zk/ and builds a Release configuration in
# vendor/longfellow-zk/build-release/.
#
# Desktop system dependencies
# ---------------------------
# Fedora / RHEL:
#   sudo dnf install -y clang cmake openssl-devel zstd-devel \
#                       gtest-devel google-benchmark-devel libpfm-devel
#
# Ubuntu / Debian:
#   sudo apt install -y clang cmake libssl-dev libzstd-dev \
#                       libgtest-dev libbenchmark-dev zlib1g-dev
#
# macOS (Homebrew):
#   brew install llvm cmake googletest google-benchmark zstd openssl
#
# Termux (Android):
#   Run scripts/setup_termux.sh first -- it installs pkg dependencies and
#   builds gtest + google-benchmark from source into $PREFIX.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
VENDOR="$ROOT/vendor/longfellow-zk"
BUILD="$VENDOR/build-release"
REPO="https://github.com/google/longfellow-zk.git"
MDOC_DIR="$VENDOR/lib/circuits/tests/mdoc"
PROVER_CC="$MDOC_DIR/mdoc_revocation_test.cc"
VERIFY_APPEND="$ROOT/benchmarks/lf_verify_append.cc"

# -- Clone or update ----------------------------------------------------------
if [[ ! -d "$VENDOR/.git" ]]; then
  echo "[longfellow] Cloning $REPO"
  git clone --depth 1 "$REPO" "$VENDOR"
else
  echo "[longfellow] Updating existing clone"
  git -C "$VENDOR" pull --ff-only
fi

# -- Inject Phase (vi) verifier benchmark -------------------------------------
# Append lf_verify_append.cc to mdoc_revocation_test.cc so the verifier
# benchmark compiles in the same TU and inherits all helpers (fill_input,
# CIRCUIT, kRootX/Y, kLigeroRate/Nreq, p256_base, etc.).
#
# Reset the pristine clone's copy first, then always re-append: this file is
# tracked in our repo (benchmarks/lf_verify_append.cc) and may change, so a
# stale "already present" check would silently keep compiling an old version
# after the file's contents were edited.
echo "[longfellow] Injecting Phase (vi)/(i) benchmarks"
git -C "$VENDOR" checkout -- "${PROVER_CC#"$VENDOR"/}"
printf '\n' >> "$PROVER_CC"
cat "$VERIFY_APPEND" >> "$PROVER_CC"

# -- Check compiler -----------------------------------------------------------
if ! command -v clang++ &>/dev/null; then
  echo "Error: clang++ not found." >&2
  echo "  Termux:  pkg install clang" >&2
  echo "  Fedora:  sudo dnf install clang" >&2
  echo "  Ubuntu:  sudo apt install clang" >&2
  exit 1
fi

# -- Detect environment and set cmake flags -----------------------------------
# Termux: gtest and benchmark are installed under $PREFIX after setup_termux.sh
# Desktop: they are in standard system paths; no prefix override needed.
#
# -march=native on x86_64 desktop enables AVX2 + AES-NI (not set by the
# longfellow CMakeLists which only adds -mpclmul for x86_64).  Measured
# speedup: ~1.6× on both prover and verifier vs the default build.
# Deliberately skipped on Termux because cross-compiled aarch64 builds must
# not use host-specific ISA flags.
CMAKE_EXTRA_ARGS=()

if [[ -n "${TERMUX_VERSION:-}" ]] || [[ -d "/data/data/com.termux" ]]; then
  echo "[longfellow] Termux detected -- adding CMAKE_PREFIX_PATH=$PREFIX"
  CMAKE_EXTRA_ARGS+=("-DCMAKE_PREFIX_PATH=${PREFIX:?'$PREFIX not set in Termux'}")
else
  ARCH=$(uname -m)
  if [[ "$ARCH" == "x86_64" ]]; then
    echo "[longfellow] x86_64 desktop -- enabling -march=native (AVX2 + AES-NI)"
    CMAKE_EXTRA_ARGS+=("-DCMAKE_CXX_FLAGS=-march=native")
  fi
fi

# -- Configure ----------------------------------------------------------------
echo "[longfellow] Configuring (Release)"
cmake -S "$VENDOR/lib" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_COMPILER=clang \
  "${CMAKE_EXTRA_ARGS[@]}"

# -- Build --------------------------------------------------------------------
JOBS=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)
echo "[longfellow] Building ($JOBS jobs)"
cmake --build "$BUILD" --parallel "$JOBS"

echo "[longfellow] Build complete -> $BUILD"
