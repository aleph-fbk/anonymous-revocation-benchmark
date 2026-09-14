// Phase (vi) Verification benchmark — appended to mdoc_revocation_test.cc
// by scripts/build_longfellow.sh.
//
// Re-opens namespace proofs::{ so that make_circuit(), fill_input(),
// p256_base, kLigeroRate, and kLigeroNreq are all in scope.
// Type aliases are redefined locally (they live inside BM_MdocRevocationProver,
// not at file scope).

#include "proto/circuit_writer.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace {

// Phase (i) circuit compilation — one-time cost at wallet setup / first run.
// The circuit only encodes the fixed statement being proved ("valid P-256 sig
// on (epoch,left,right) AND left<id<right"), not any per-holder or per-epoch
// data, so it never needs to be recompiled: compile once, serialize via
// CircuitWriter (proto/circuit_writer.h), and reload the cached bytes on every
// later presentation instead. This timing is deliberately NOT one of the six
// benchmarked phases -- it's paid at most once over a wallet's lifetime, so
// comparing it against per-presentation phases would misrepresent
// per-presentation cost. We still report its one-time serialized size
// (circuit_bytes) -- the disk/memory footprint of the cache.
void BM_MdocCircuitCompile(benchmark::State& state) {
  double circuit_bytes = 0;
  for (auto s : state) {
    auto CIRCUIT = make_circuit(p256_base);
    benchmark::DoNotOptimize(CIRCUIT);

    if (circuit_bytes == 0) {
      CircuitWriter<Fp256Base> writer(p256_base, P256_ID);
      std::vector<uint8_t> circuit_buf;
      writer.to_bytes(*CIRCUIT, circuit_buf);
      circuit_bytes = static_cast<double>(circuit_buf.size());
    }
  }
  state.counters["circuit_bytes"] = circuit_bytes;
}
BENCHMARK(BM_MdocCircuitCompile);

void BM_MdocRevocationVerifier(benchmark::State& state) {
  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT = make_circuit(p256_base);

  // Full prover witness
  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  fill_input(W, p256_base, /*prover=*/true);

  // Public inputs only: constant 1 + pkX + pkY  (npub_in == 3)
  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);
  fill_input(pub, p256_base, /*prover=*/false);

  // Type aliases (mirror BM_MdocRevocationProver)
  using f2_p256 = Fp2<Fp256Base>;
  using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
  using RSFactory = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;

  const f2_p256 p256_2(p256_base);

  static constexpr char kRootX[] =
      "112649224146410281873500457609690258373018840430489408729223714171582664"
      "680802";
  static constexpr char kRootY[] =
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908";
  const typename f2_p256::Elt omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory rsf(fft_b, p256_base);

  // Generate proof once outside the timing loop
  ZkProof<Fp256Base> zkpr(*CIRCUIT, kLigeroRate, kLigeroNreq);
  {
    ZkProver<Fp256Base, RSFactory> prover(*CIRCUIT, p256_base, rsf);
    Transcript tp(reinterpret_cast<const uint8_t*>("test"), 4);
    SecureRandomEngine rng;
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
  }

  ZkVerifier<Fp256Base, RSFactory> verifier(
      *CIRCUIT, rsf, kLigeroRate, kLigeroNreq, p256_base);

  // Measure serialized proof size (constant across iterations).
  std::vector<uint8_t> proof_buf;
  zkpr.write(proof_buf, p256_base);
  const double kProofBytes = static_cast<double>(proof_buf.size());

  // Benchmark: verification only (fresh transcript each iteration)
  for (auto s : state) {
    Transcript tv(reinterpret_cast<const uint8_t*>("test"), 4);
    verifier.recv_commitment(zkpr, tv);
    bool ok = verifier.verify(zkpr, pub, tv);
    benchmark::DoNotOptimize(ok);
  }

  // Report proof size as an iteration-invariant counter.
  state.counters["proof_bytes"] = kProofBytes;
}
BENCHMARK(BM_MdocRevocationVerifier);

}  // namespace
}  // namespace proofs
