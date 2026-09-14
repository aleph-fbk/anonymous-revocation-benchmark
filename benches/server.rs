//! Criterion benchmarks — server-side phases (i) Setup, (ii) Add, (iii) Revocation.
//!
//! Run with:
//!   cargo bench --bench server
//!   cargo bench --bench server -- "KB21"             # both KB21 constructions
//!   cargo bench --bench server -- "KB21-Adaptive"     # BB-sig + non-adaptive accumulator
//!   cargo bench --bench server -- "KB21-NonAdaptive"  # bare construction, no signature
//!   cargo bench --bench server -- "CL-RSA-B"
//!   cargo bench --bench server -- "BBS+BPP"
//!   cargo bench --bench server -- "ECDSA"
//!
//! Batch dimensions (from TS-14 spec):
//!   Add        : 1, 2^10, 2^12, 2^14, 2^16  new members per epoch
//!   Revocation : 1, 2^3,  2^6,  2^9,  2^12  revocations per epoch
//!
//! ⚠  CL-RSA-B Setup generates two 1536-bit safe primes — expect ≈10–60 s/iteration.

// See src/main.rs for the __rust_probestack workaround (not needed in bench binary).

use revocation_comparison_bench::params::{
    ADD_BATCH, BBS_CRED_ATTR_COUNT, DEL_BATCH, EXPIRY_TS, LIST_BASE_SIZE,
};

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};
use std::time::Duration;

// ── ECDSA imports ─────────────────────────────────────────────────────────────
use p256::ecdsa::{
    signature::Signer as _,
    Signature as EcdsaSig,
    SigningKey as EcdsaSigningKey,
};

// ─── KB21 imports ─────────────────────────────────────────────────────────────
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use blake2::Blake2b512;
use short_group_sig::common::ProvingKey;
use std::collections::HashSet;
use vb_accumulator::{
    batch_utils::Omega,
    kb_positive_accumulator::{
        adaptive_accumulator::KBPositiveAccumulator,
        non_adaptive_accumulator::NonAdaptivePositiveAccumulator,
        setup::{PublicKey, SecretKey, SetupParams},
    },
    persistence::State,
    positive::Accumulator as _,
    setup::{
        Keypair as RootKeypair, PublicKey as RootPublicKey, SecretKey as RootSecretKey,
        SetupParams as RootSetupParams,
    },
};

// ─── BBS+BPP imports ──────────────────────────────────────────────────────────
use bbs_plus::{
    setup::{KeypairG2 as BBSKeypair, SignatureParams23G1 as BBSParams},
    signature_23::Signature23G1 as BBSSig,
};
use bulletproofs_plus_plus::setup::SetupParams as BppSetupParams;

// ─── CL-RSA-B imports ─────────────────────────────────────────────────────────
use cl_rsa_b::{
    accumulator::CLRSABAccumulator,
    hash::hash_to_prime,
    H2P_SIZE,
};
use common::accumulator::{Accumulator, Subtractive};
use unknown_order::BigNumber;

type Fr = <Bls12_381 as Pairing>::ScalarField;

// All batch-size constants live in src/params.rs — imported above.

// ─────────────────────────────────────────────────────────────────────────────
// Shared KB21 helpers
//
// The `vb_accumulator` crate ships two KB21 constructions (see
// `src/bench_kb21.rs` for the full rationale):
//   - `KB21-Adaptive`    — `kb_positive_accumulator::adaptive_accumulator`,
//                          BB signature + non-adaptive accumulator.
//   - `KB21-NonAdaptive` — `kb_positive_accumulator::non_adaptive_accumulator`,
//                          the bare construction, no per-member signature.
// Both are benchmarked below, clearly labelled.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct SimpleState(HashSet<Fr>);

impl SimpleState {
    fn new() -> Self { Self(HashSet::new()) }
}

impl State<Fr> for SimpleState {
    fn add(&mut self, e: Fr) { self.0.insert(e); }
    fn remove(&mut self, e: &Fr) { self.0.remove(e); }
    fn has(&self, e: &Fr) -> bool { self.0.contains(e) }
    fn size(&self) -> u64 { self.0.len() as u64 }
}

struct KB21Setup {
    params: SetupParams<Bls12_381>,
    sk: SecretKey<Fr>,
    #[allow(dead_code)]
    pk: PublicKey<Bls12_381>,
    #[allow(dead_code)]
    proving_key: ProvingKey<G1Affine>,
}

fn build_kb21_setup() -> KB21Setup {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_0042_u64);
    let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"rcb-kb21-v1");
    let sk = SecretKey::<Fr>::new(&mut rng);
    let pk = PublicKey::<Bls12_381>::new(&sk, &params);
    let proving_key =
        ProvingKey::<G1Affine>::generate_using_hash::<Blake2b512>(b"rcb-kb21-pk-v1");
    KB21Setup { params, sk, pk, proving_key }
}

struct KB21NonAdaptiveSetup {
    params: RootSetupParams<Bls12_381>,
    sk: RootSecretKey<Fr>,
    #[allow(dead_code)]
    pk: RootPublicKey<Bls12_381>,
}

fn build_kb21_non_adaptive_setup() -> KB21NonAdaptiveSetup {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_0044_u64);
    let params = RootSetupParams::<Bls12_381>::new::<Blake2b512>(b"rcb-kb21-na-v1");
    let keypair = RootKeypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
    KB21NonAdaptiveSetup { params, sk: keypair.secret_key.clone(), pk: keypair.public_key.clone() }
}

// ─────────────────────────────────────────────────────────────────────────────
// KB21-Adaptive Accumulator — Phase (i) Setup
// ─────────────────────────────────────────────────────────────────────────────

fn bench_kb21_setup(c: &mut Criterion) {
    c.benchmark_group("KB21-Adaptive / Setup")
        .sample_size(10)
        .bench_function("initialize", |b| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(black_box(42_u64));
                let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"rcb-kb21-v1");
                let sk = SecretKey::<Fr>::new(&mut rng);
                let pk = PublicKey::<Bls12_381>::new(&sk, &params);
                let acc = KBPositiveAccumulator::<Bls12_381>::initialize(&mut rng, &params.accum);
                black_box((params, sk, pk, acc))
            })
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// KB21-NonAdaptive Accumulator — Phase (i) Setup
// ─────────────────────────────────────────────────────────────────────────────

fn bench_kb21_non_adaptive_setup(c: &mut Criterion) {
    c.benchmark_group("KB21-NonAdaptive / Setup")
        .sample_size(10)
        .bench_function("initialize", |b| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(black_box(42_u64));
                let params = RootSetupParams::<Bls12_381>::new::<Blake2b512>(b"rcb-kb21-na-v1");
                let keypair = RootKeypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
                let acc = NonAdaptivePositiveAccumulator::<Bls12_381>::initialize(&mut rng, &params);
                black_box((params, keypair, acc))
            })
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// KB21-Adaptive — Phase (ii) Add
//
// Measures `add_batch(k)`: the issuer adds k new members in one epoch, then
// issues k witnesses (one per new holder) — both timed together.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_kb21_issue_witness(c: &mut Criterion) {
    // Time to issue ONE membership witness (the credential the holder gets).
    let s = build_kb21_setup();
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_u64);
    let mut seed_state = SimpleState::new();
    let acc = KBPositiveAccumulator::<Bls12_381>::initialize(&mut rng, &s.params.accum);
    // Add 100 members so the accumulator is non-trivially populated.
    for _ in 0..100 {
        let m = Fr::rand(&mut rng);
        acc.add::<Blake2b512>(&m, &s.sk, &s.params, &mut seed_state)
            .expect("seed add failed");
    }

    c.benchmark_group("KB21-Adaptive / Add")
        .sample_size(10)
        .bench_function("issue_witness", |b| {
            b.iter_batched(
                || {
                    let m = Fr::rand(&mut rng);
                    let mut st = seed_state.clone();
                    acc.add::<Blake2b512>(&m, &s.sk, &s.params, &mut st)
                        .expect("add failed");
                    (m, st)
                },
                |(m, st)| {
                    black_box(acc.get_witness::<Blake2b512>(&m, &s.sk, &s.params, &st))
                },
                BatchSize::SmallInput,
            )
        });
}

fn bench_kb21_add_batch(c: &mut Criterion) {
    // Full phase (ii) cost: SM adds k new handles to the accumulator, then
    // issues k witnesses (one per new holder) — both timed together.
    let s = build_kb21_setup();
    let mut rng = StdRng::seed_from_u64(0xBEEF_CAFE_u64);

    let max_k = *ADD_BATCH.last().unwrap();
    let all_elements: Vec<Fr> = (0..max_k).map(|_| Fr::rand(&mut rng)).collect();

    let mut group = c.benchmark_group("KB21-Adaptive / Add / add_batch");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for &k in ADD_BATCH {
        let elements = all_elements[..k].to_vec();
        group.bench_with_input(BenchmarkId::new("k", k), &k, |b, _| {
            b.iter_batched(
                || {
                    let acc = KBPositiveAccumulator::<Bls12_381>::initialize(
                        &mut rng, &s.params.accum,
                    );
                    let state = SimpleState::new();
                    (acc, state, elements.clone())
                },
                |(acc, mut state, elems)| {
                    acc.add_batch::<Blake2b512>(elems.clone(), &s.sk, &s.params, &mut state)
                        .expect("add failed");
                    for m in &elems {
                        black_box(acc.get_witness::<Blake2b512>(m, &s.sk, &s.params, &state));
                    }
                },
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// KB21-NonAdaptive — Phase (ii) Add
//
// `NonAdaptivePositiveAccumulator::add`/`add_batch` never touch the
// accumulated value — no BB signature, no group op at all, just a state
// insert (see the module doc in `src/bench_kb21.rs`).  `issue_witness` is
// the only real per-holder cost: one scalar inversion + one G1 scalar mult.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_kb21_non_adaptive_issue_witness(c: &mut Criterion) {
    let s = build_kb21_non_adaptive_setup();
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABF_u64);
    let mut seed_state = SimpleState::new();
    let acc = NonAdaptivePositiveAccumulator::<Bls12_381>::initialize(&mut rng, &s.params);
    // Add 100 members so the accumulator is non-trivially populated.
    for _ in 0..100 {
        let m = Fr::rand(&mut rng);
        acc.add(m, &mut seed_state).expect("seed add failed");
    }

    c.benchmark_group("KB21-NonAdaptive / Add")
        .sample_size(10)
        .bench_function("issue_witness", |b| {
            b.iter_batched(
                || {
                    let m = Fr::rand(&mut rng);
                    let mut st = seed_state.clone();
                    acc.add(m, &mut st).expect("add failed");
                    (m, st)
                },
                |(m, st)| black_box(acc.get_membership_witness(&m, &s.sk, &st)),
                BatchSize::SmallInput,
            )
        });
}

fn bench_kb21_non_adaptive_add_batch(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xBEEF_CAFF_u64);

    let max_k = *ADD_BATCH.last().unwrap();
    let all_elements: Vec<Fr> = (0..max_k).map(|_| Fr::rand(&mut rng)).collect();

    let s = build_kb21_non_adaptive_setup();
    let mut group = c.benchmark_group("KB21-NonAdaptive / Add / add_batch");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for &k in ADD_BATCH {
        let elements = all_elements[..k].to_vec();
        group.bench_with_input(BenchmarkId::new("k", k), &k, |b, _| {
            b.iter_batched(
                || {
                    let acc = NonAdaptivePositiveAccumulator::<Bls12_381>::initialize(
                        &mut rng, &s.params,
                    );
                    let state = SimpleState::new();
                    (acc, state, elements.clone())
                },
                |(acc, mut state, elems)| {
                    acc.add_batch(elems.clone(), &mut state).expect("add failed");
                    for m in &elems {
                        black_box(acc.get_membership_witness(m, &s.sk, &state));
                    }
                },
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// KB21-Adaptive — Phase (iii) Revocation
//
// Measures `Omega::new_for_kb_positive_accumulator(k)`: publishing the batch
// witness-update message for k revoked members.  This is the main issuer cost
// at epoch boundary.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_kb21_revoke_batch(c: &mut Criterion) {
    let s = build_kb21_setup();
    let mut rng = StdRng::seed_from_u64(0xDEAD_C0DE_u64);

    let max_k = *DEL_BATCH.last().unwrap();
    let existing: Vec<Fr> = (0..max_k + 50).map(|_| Fr::rand(&mut rng)).collect();

    // Build accumulator once (setup not timed).
    let acc = KBPositiveAccumulator::<Bls12_381>::initialize(&mut rng, &s.params.accum);
    let mut state = SimpleState::new();
    acc.add_batch::<Blake2b512>(existing.clone(), &s.sk, &s.params, &mut state)
        .expect("bulk add failed");
    let old_acc_value = *acc.value();

    let mut group = c.benchmark_group("KB21-Adaptive / Revocation / revoke_batch");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for &k in DEL_BATCH {
        let revoked = existing[..k].to_vec();
        group.bench_with_input(BenchmarkId::new("k", k), &k, |b, _| {
            b.iter(|| {
                let omega = Omega::<G1Affine>::new_for_kb_positive_accumulator::<Blake2b512>(
                    &black_box(revoked.clone()),
                    &black_box(old_acc_value),
                    &s.sk,
                );
                let mut buf = Vec::new();
                omega.serialize_compressed(&mut buf).ok();
                black_box(buf.len())
            })
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// KB21-NonAdaptive — Phase (iii) Revocation
//
// Measures `Omega::new(k)`: publishing the batch witness-update message for
// k revoked members.  Same math as KB21-Adaptive's Ω (the KB-positive variant
// is `Omega::new` specialised to an empty addition set), just without the
// BB-signature PRF applied to each removed element first.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_kb21_non_adaptive_revoke_batch(c: &mut Criterion) {
    let s = build_kb21_non_adaptive_setup();
    let mut rng = StdRng::seed_from_u64(0xDEAD_C0DF_u64);

    let max_k = *DEL_BATCH.last().unwrap();
    let existing: Vec<Fr> = (0..max_k + 50).map(|_| Fr::rand(&mut rng)).collect();

    // Build accumulator once (setup not timed).
    let acc = NonAdaptivePositiveAccumulator::<Bls12_381>::initialize(&mut rng, &s.params);
    let mut state = SimpleState::new();
    acc.add_batch(existing.clone(), &mut state).expect("bulk add failed");
    let old_acc_value = *acc.value();

    let mut group = c.benchmark_group("KB21-NonAdaptive / Revocation / revoke_batch");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for &k in DEL_BATCH {
        let revoked = existing[..k].to_vec();
        group.bench_with_input(BenchmarkId::new("k", k), &k, |b, _| {
            b.iter(|| {
                let omega = Omega::<G1Affine>::new(
                    &[],
                    &black_box(revoked.clone()),
                    &black_box(old_acc_value),
                    &s.sk,
                );
                let mut buf = Vec::new();
                omega.serialize_compressed(&mut buf).ok();
                black_box(buf.len())
            })
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// CL-RSA-B — Phase (i) Setup
//
// ⚠ Generates two 1536-bit safe primes — expect 10–60 s/iteration.
//   Criterion is configured with a small sample_size to limit total runtime.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_clrsab_setup(c: &mut Criterion) {
    c.benchmark_group("CL-RSA-B / Setup")
        .sample_size(10)
        .measurement_time(Duration::from_secs(120))
        .bench_function("initialize", |b| {
            b.iter(|| black_box(CLRSABAccumulator::new()))
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// CL-RSA-B — Phase (ii) Add
//
// `witness_mem` is the issuer's per-holder operation: given the current
// accumulator value, compute a membership witness for one new element.
// The accumulator value does NOT change on insertion (CL-RSA-B property) —
// same as KB21's positive accumulator, whose `add`/`add_batch` is a bare
// HashSet insert with no group operations at all (see
// `NonAdaptivePositiveAccumulator::add` in vb_accumulator).  Unlike KB21,
// RSA membership witnesses have no batch-computation speedup (each is an
// independent `value.modpow(1/item mod phi, N)`), so `add_batch(k)` here is
// k independent repetitions of `witness_mem`, not `insert_batch`'s discarded
// aggregate-product witness (which models nothing in the real protocol).
// ─────────────────────────────────────────────────────────────────────────────

fn bench_clrsab_issue_witness(c: &mut Criterion) {
    let (acc, aux) = CLRSABAccumulator::new();
    let item = BigNumber::prime(H2P_SIZE);
    let elems = vec![item.clone()];

    c.benchmark_group("CL-RSA-B / Add")
        .sample_size(10)
        .bench_function("issue_witness", |b| {
            b.iter(|| black_box(acc.witness_mem(&item, aux.as_ref(), &elems)))
        });
}

fn bench_clrsab_add_batch(c: &mut Criterion) {
    // Generate RSA primes ONCE — cloning the 3072-bit BigNumbers per iteration
    // is microseconds vs. 10–60 s for safe-prime generation.
    let (acc_template, aux) = CLRSABAccumulator::new();

    let max_k = *ADD_BATCH.last().unwrap();
    let all_primes: Vec<BigNumber> = (0..max_k)
        .map(|i| {
            let mut data = [0u8; 8];
            data.copy_from_slice(&(i as u64).to_be_bytes());
            hash_to_prime(data)
        })
        .collect();

    let mut group = c.benchmark_group("CL-RSA-B / Add / add_batch");
    group.sample_size(10).measurement_time(Duration::from_secs(120));

    for &k in ADD_BATCH {
        let primes = all_primes[..k].to_vec();
        group.bench_with_input(BenchmarkId::new("k", k), &k, |b, _| {
            b.iter_batched(
                || {
                    // Cheap: clone two BigNumbers, not the prime-generation.
                    (acc_template.clone(), primes.clone())
                },
                |(acc, items)| {
                    for item in &items {
                        black_box(acc.witness_mem(item, aux.as_ref(), &items));
                    }
                },
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// CL-RSA-B — Phase (iii) Revocation
//
// `remove_batch(k)` multiplies k revoked primes into a raw batch product P_D
// (~256k bits) and updates the accumulator value A ← A^{P_D^{-1} mod phi}.
// P_D is published without reduction mod phi — reducing would leak phi.
// Holders apply one extended-GCD(my_elem, P_D): O(k) work.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_clrsab_revoke_batch(c: &mut Criterion) {
    // Generate RSA primes ONCE — revocation modifies acc.value but the modulus
    // and phi stay fixed, so we clone the accumulator per iteration instead of
    // re-generating primes (which costs 10–60 s each).
    let max_k = *DEL_BATCH.last().unwrap();
    let all_primes: Vec<BigNumber> = (0..(max_k + 1))
        .map(|i| {
            let mut data = [0u8; 8];
            data.copy_from_slice(&(i as u64).to_be_bytes());
            hash_to_prime(data)
        })
        .collect();

    // new_with_elements ignores its argument and just generates fresh primes;
    // call new() directly for clarity.
    let (acc_template, aux) = CLRSABAccumulator::new();
    let all_elems_template: Vec<BigNumber> = all_primes.clone();

    let mut group = c.benchmark_group("CL-RSA-B / Revocation / revoke_batch");
    group.sample_size(10).measurement_time(Duration::from_secs(120));

    for &k in DEL_BATCH {
        let to_revoke = all_primes[..k].to_vec();
        let all_elems = all_elems_template.clone();
        group.bench_with_input(BenchmarkId::new("k", k), &k, |b, _| {
            b.iter_batched(
                || {
                    // Cheap: clone two 3072-bit BigNumbers + element list.
                    (acc_template.clone(), to_revoke.clone(), all_elems.clone())
                },
                |(mut acc, to_revoke, mut elems)| {
                    let refs: Vec<&BigNumber> = to_revoke.iter().collect();
                    black_box(acc.update_after_remove_batch(refs, aux.as_ref(), &mut elems))
                },
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// BBS+BPP (Signed Pairs) — Phase (i) Setup
// ─────────────────────────────────────────────────────────────────────────────

fn bench_sp_setup(c: &mut Criterion) {
    // Full wallet onboarding cost: BBS params + keygen + BPP generator setup.
    // BPP setup hashes to group points and is a one-time cost paid at registration.
    c.benchmark_group("BBS+BPP / Setup")
        .sample_size(10)
        .bench_function("initialize", |b| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(black_box(0xFEED_FACE_u64));
                let params = BBSParams::<Bls12_381>::new::<sha2::Sha256>(
                    b"rcb-sp-params-v1",
                    BBS_CRED_ATTR_COUNT,
                );
                let kp = BBSKeypair::<Bls12_381>::generate_using_rng_and_bbs23_params(
                    &mut rng, &params,
                );
                let bp_gens = BppSetupParams::<G1Affine>::new_for_perfect_range_proof::<Blake2b512>(
                    b"rcb-bpp-gens-v1", 2, 64, 2,
                );
                black_box((params, kp, bp_gens))
            })
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// BBS+BPP — Phase (ii) Add
//
// The issuer signs one gap attestation (lower_id, upper_id, expiry_ts) per
// new holder.  Cost is one BBS-2023 signature.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_sp_sign_gap(c: &mut Criterion) {
    // Signs the 4-attribute credential the holder will use in the ZK proof:
    // (lower_id, upper_id, expiry_ts, rev_handle).
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_u64);
    let params = BBSParams::<Bls12_381>::new::<sha2::Sha256>(b"rcb-sp-params-v1", BBS_CRED_ATTR_COUNT);
    let kp = BBSKeypair::<Bls12_381>::generate_using_rng_and_bbs23_params(&mut rng, &params);

    c.benchmark_group("BBS+BPP / Add")
        .sample_size(10)
        .bench_function("sign_gap", |b| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(black_box(0x9999_8888_u64));
                let msgs = vec![
                    Fr::from(black_box(1_000_u64)),   // lower_id
                    Fr::from(black_box(2_000_u64)),   // upper_id
                    Fr::from(black_box(EXPIRY_TS)),   // expiry_ts
                    Fr::from(black_box(1_500_u64)),   // rev_handle (holder's UID, kept secret in proof)
                ];
                let _ = black_box(BBSSig::<Bls12_381>::new(&mut rng, &msgs, &kp.secret_key, &params));
            })
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// BBS+BPP — Phase (iii) Revocation
//
// At epoch boundary the issuer re-signs the ENTIRE gap list (LIST_BASE_SIZE
// pre-existing gaps) PLUS k+1 new gaps produced by the k new revocations.
// Each revocation splits one gap into two (+1 net gap per revocation).
// Contrast with KB21/CL-RSA-B which only publish a k-element batch message.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_sp_epoch_renewal(c: &mut Criterion) {
    // Re-signs the entire gap list: LIST_BASE_SIZE + k+1 gaps × 4 attributes each.
    // Each gap also carries a rev_handle slot; in practice each holder credential
    // has a unique rev_handle but the signing cost per slot is identical.
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_u64);
    let params = BBSParams::<Bls12_381>::new::<sha2::Sha256>(b"rcb-sp-params-v1", BBS_CRED_ATTR_COUNT);
    let kp = BBSKeypair::<Bls12_381>::generate_using_rng_and_bbs23_params(&mut rng, &params);

    // At LIST_BASE_SIZE = 100_000, one iteration re-signs ~100k tuples
    // (~46s at ~0.46ms/sig), so the default sample_size=100 would take
    // hours; cut it down like CL-RSA-B's slow benchmarks do.
    let mut group = c.benchmark_group("BBS+BPP / Revocation / epoch_renewal");
    group.sample_size(10).measurement_time(Duration::from_secs(120));

    for &k in DEL_BATCH {
        let total_gaps = LIST_BASE_SIZE + k + 1;
        group.bench_with_input(BenchmarkId::new("k", k), &k, |b, _| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(black_box(0xDEAD_C0DE_u64));
                for i in 0u64..(total_gaps as u64) {
                    let msgs = vec![
                        Fr::from(i * 10),         // lower_id
                        Fr::from(i * 10 + 9),     // upper_id
                        Fr::from(EXPIRY_TS + i),  // expiry_ts
                        Fr::from(i * 10 + 5),     // rev_handle (midpoint of gap)
                    ];
                    let _ = black_box(BBSSig::<Bls12_381>::new(&mut rng, &msgs, &kp.secret_key, &params));
                }
            })
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// ECDSA Signed Pairs — Phase (i) Setup
//
// Measures P-256 key generation: the issuer generates a new signing key
// at system initialisation.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_ecdsa_setup(c: &mut Criterion) {
    c.benchmark_group("ECDSA / Setup")
        .sample_size(10)
        .bench_function("keygen", |b| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(black_box(42_u64));
                let sk = EcdsaSigningKey::random(&mut rng);
                black_box(sk)
            })
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// ECDSA — Phase (ii) Add
//
// Measures signing one gap attestation: epoch (8 B) ‖ lower_id (8 B) ‖
// upper_id (8 B).  This is the per-holder cost at issuance — one P-256
// signature per credential.  Matches the span format used by longfellow-zk.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_ecdsa_sign_gap(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_u64);
    let sk = EcdsaSigningKey::random(&mut rng);

    c.benchmark_group("ECDSA / Add")
        .sample_size(10)
        .bench_function("sign_gap", |b| {
            b.iter(|| {
                let mut msg = [0u8; 24];
                msg[0..8].copy_from_slice(&black_box(1025_u64).to_be_bytes());      // epoch
                msg[8..16].copy_from_slice(&black_box(0x7fff_u64).to_be_bytes());   // lower_id
                msg[16..24].copy_from_slice(&black_box(0x2f60_3a_u64).to_be_bytes()); // upper_id
                let sig: EcdsaSig = sk.sign(&msg);
                black_box(sig)
            })
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// ECDSA — Phase (iii) Revocation
//
// At epoch boundary the issuer re-signs the ENTIRE gap list: LIST_BASE_SIZE
// pre-existing gaps + k+1 new gaps from k new revocations.
// Same model as BBS+BPP epoch_renewal; contrast with accumulator schemes.
// ─────────────────────────────────────────────────────────────────────────────

fn bench_ecdsa_epoch_renewal(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_u64);
    let sk = EcdsaSigningKey::random(&mut rng);

    // Same reasoning as BBS+BPP's epoch_renewal group above: at
    // LIST_BASE_SIZE = 100_000 the default sample_size=100 would take well
    // over an hour, so cut it down the same way.
    let mut group = c.benchmark_group("ECDSA / Revocation / epoch_renewal");
    group.sample_size(10).measurement_time(Duration::from_secs(120));

    for &k in DEL_BATCH {
        let total_gaps = LIST_BASE_SIZE + k + 1;
        group.bench_with_input(BenchmarkId::new("k", k), &k, |b, _| {
            b.iter(|| {
                for i in 0u64..(total_gaps as u64) {
                    let mut msg = [0u8; 24];
                    msg[0..8].copy_from_slice(&1025_u64.to_be_bytes());
                    msg[8..16].copy_from_slice(&(i * 10).to_be_bytes());
                    msg[16..24].copy_from_slice(&(i * 10 + 100).to_be_bytes());
                    let sig: EcdsaSig = sk.sign(&msg);
                    black_box(sig);
                }
            })
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Criterion groups
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(
    kb21,
    bench_kb21_setup,
    bench_kb21_issue_witness,
    bench_kb21_add_batch,
    bench_kb21_revoke_batch,
);

criterion_group!(
    kb21_non_adaptive,
    bench_kb21_non_adaptive_setup,
    bench_kb21_non_adaptive_issue_witness,
    bench_kb21_non_adaptive_add_batch,
    bench_kb21_non_adaptive_revoke_batch,
);

criterion_group!(
    clrsab,
    bench_clrsab_setup,
    bench_clrsab_issue_witness,
    bench_clrsab_add_batch,
    bench_clrsab_revoke_batch,
);

criterion_group!(sp, bench_sp_setup, bench_sp_sign_gap, bench_sp_epoch_renewal);

criterion_group!(
    ecdsa,
    bench_ecdsa_setup,
    bench_ecdsa_sign_gap,
    bench_ecdsa_epoch_renewal,
);

criterion_main!(kb21_non_adaptive, clrsab, sp, ecdsa);