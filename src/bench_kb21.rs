//! KB21 Accumulator — phases (iv) Holder Update, (v) Presentation, (vi) Verification.
//!
//! The `vb_accumulator` crate ships two constructions from the KB21 paper
//! ([Efficient Constructions of Pairing Based Accumulators](https://eprint.iacr.org/2021/638)):
//!
//! - `kb_positive_accumulator::non_adaptive_accumulator::NonAdaptivePositiveAccumulator`
//!   — the bare construction. Proven secure only in
//!   the non-adaptive model, but cheaper: no per-member BB signature.
//! - `kb_positive_accumulator::adaptive_accumulator::KBPositiveAccumulator`
//!   — the same construction wrapped with a BB signature per member to lift
//!   security to the adaptive model, at the cost of an extra signature +
//!   signature proof-of-knowledge on every Add/Presentation/Verification.
//!
//! Both are benchmarked below, clearly separated (`KB21-Adaptive` /
//! `KB21-NonAdaptive`), each paired with the "cdh" proof protocol variant
//! (`proofs_cdh`: prover does no pairings, deferred entirely to the
//! verifier's single check — more efficient than `proofs::`).
//!
//! Holder Update is O(k): after k revocations the issuer publishes a public Ω
//! message (one G1 element per revoked member).  The holder evaluates the Ω
//! polynomial at its own element — k scalar multiplications in G1.

use crate::{runner::BenchSuite, types::Phase};
use revocation_comparison_bench::params::DEL_BATCH;

use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use blake2::{Blake2b512, Digest as _};
use short_group_sig::common::ProvingKey;
use std::collections::HashSet;
use vb_accumulator::{
    batch_utils::Omega,
    kb_positive_accumulator::{
        adaptive_accumulator::KBPositiveAccumulator,
        non_adaptive_accumulator::NonAdaptivePositiveAccumulator,
        // proofs_cdh: prover does no pairings (deferred entirely to the
        // verifier's single check) — more efficient than proofs::.
        proofs_cdh::KBPositiveAccumulatorMembershipProofProtocol,
        setup::{PublicKey, SecretKey, SetupParams},
        witness::KBPositiveAccumulatorWitness,
    },
    persistence::State,
    positive::Accumulator as _,
    proofs_cdh::{MembershipProof, MembershipProofProtocol},
    setup::{
        Keypair as RootKeypair, PublicKey as RootPublicKey, SecretKey as RootSecretKey,
        SetupParams as RootSetupParams,
    },
    witness::MembershipWitness,
};

type Fr = <Bls12_381 as Pairing>::ScalarField;

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct SimpleState(HashSet<Fr>);
impl SimpleState { fn new() -> Self { Self(HashSet::new()) } }
impl State<Fr> for SimpleState {
    fn add(&mut self, e: Fr)     { self.0.insert(e); }
    fn remove(&mut self, e: &Fr) { self.0.remove(e); }
    fn has(&self, e: &Fr) -> bool { self.0.contains(e) }
    fn size(&self) -> u64 { self.0.len() as u64 }
}

fn derive_challenge(transcript: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(&Blake2b512::digest(transcript))
}

// ═════════════════════════════════════════════════════════════════════════════
// KB21-Adaptive (BB signature + non-adaptive accumulator)
// ═════════════════════════════════════════════════════════════════════════════

struct KB21AdaptiveSetup {
    params:           SetupParams<Bls12_381>,
    sk:               SecretKey<Fr>,
    pk:               PublicKey<Bls12_381>,
    member:           Fr,
    /// All pre-existing members (populated before our target member).
    /// The holder-update benchmark treats `existing_members[..k]` as revoked.
    existing_members: Vec<Fr>,
    acc:              KBPositiveAccumulator<Bls12_381>,
    witness:          KBPositiveAccumulatorWitness<Bls12_381>,
    proving_key:      ProvingKey<G1Affine>,
    #[allow(dead_code)]
    state:            SimpleState,
}

fn build_adaptive_setup(n_existing: usize) -> KB21AdaptiveSetup {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_0042_u64);
    let params      = SetupParams::<Bls12_381>::new::<Blake2b512>(b"rcb-kb21-v1");
    let sk          = SecretKey::<Fr>::new(&mut rng);
    let pk          = PublicKey::<Bls12_381>::new(&sk, &params);
    let proving_key = ProvingKey::<G1Affine>::generate_using_hash::<Blake2b512>(b"rcb-kb21-pk-v1");
    let acc         = KBPositiveAccumulator::<Bls12_381>::initialize(&mut rng, &params.accum);
    let mut state   = SimpleState::new();

    let existing_members: Vec<Fr> = (0..n_existing).map(|_| Fr::rand(&mut rng)).collect();
    if !existing_members.is_empty() {
        acc.add_batch::<Blake2b512>(existing_members.clone(), &sk, &params, &mut state)
            .expect("bulk add failed");
    }

    let member  = Fr::rand(&mut rng);
    let witness = acc.add::<Blake2b512>(&member, &sk, &params, &mut state)
        .expect("add member failed");

    KB21AdaptiveSetup { params, sk, pk, member, existing_members, acc, witness, proving_key, state }
}

fn register_adaptive(suite: &mut BenchSuite) {
    for &k in DEL_BATCH {
        suite.register(
            "KB21-Adaptive",
            "adaptive_witness_update",
            Phase::HolderUpdate,
            Some(k as u64),
            move || {
                // Build with k + 50 pre-existing members; the first k are treated
                // as revoked.  The extra 50 keep the accumulator non-trivially
                // populated independent of k.
                let s    = build_adaptive_setup(k + 50);
                let revoked: Vec<Fr> = s.existing_members[..k].to_vec();
                let old_acc_value = *s.acc.value();
                let omega = Omega::<G1Affine>::new_for_kb_positive_accumulator::<Blake2b512>(
                    &revoked, &old_acc_value, &s.sk,
                );
                let revoked_acc_members: Vec<Fr> = revoked
                    .iter()
                    .map(|e| KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(e, &s.sk))
                    .collect();
                (s, omega, revoked_acc_members)
            },
            |(s, omega, revoked_acc_members)| {
                let w  = s.witness.clone();
                let ok = w.update_using_public_info_after_batch_updates(revoked_acc_members, omega).is_ok();
                (0, ok)
            },
        );
    }

    suite.register(
        "KB21-Adaptive",
        "adaptive_prove_membership",
        Phase::Presentation,
        None,
        || build_adaptive_setup(100),
        |s| {
            let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
            let protocol = KBPositiveAccumulatorMembershipProofProtocol::init(
                &mut rng, s.member, None, &s.witness, s.acc.value(), &s.pk, &s.params, &s.proving_key,
            );
            let mut transcript = Vec::new();
            protocol.challenge_contribution(
                s.acc.value(), &s.pk, &s.params, &s.proving_key, &mut transcript,
            ).expect("challenge_contribution failed");
            let proof = protocol.gen_proof(&derive_challenge(&transcript))
                .expect("gen_proof failed");
            let mut buf = Vec::new();
            proof.serialize_compressed(&mut buf).ok();
            (buf.len(), true)
        },
    );

    suite.register(
        "KB21-Adaptive",
        "adaptive_verify_membership",
        Phase::Verification,
        None,
        || {
            let s = build_adaptive_setup(100);
            let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
            let protocol = KBPositiveAccumulatorMembershipProofProtocol::init(
                &mut rng, s.member, None, &s.witness, s.acc.value(), &s.pk, &s.params, &s.proving_key,
            );
            let mut transcript = Vec::new();
            protocol.challenge_contribution(
                s.acc.value(), &s.pk, &s.params, &s.proving_key, &mut transcript,
            ).expect("challenge_contribution failed");
            let challenge = derive_challenge(&transcript);
            let proof = protocol.gen_proof(&challenge).expect("gen_proof failed");
            let mut buf = Vec::new();
            proof.serialize_compressed(&mut buf).ok();
            (s, proof, challenge, buf.len())
        },
        |(s, proof, challenge, proof_size)| {
            let ok = proof.verify(
                s.acc.value(), challenge, s.pk.clone(), s.params.clone(), &s.proving_key,
            ).is_ok();
            (*proof_size, ok)
        },
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// KB21-NonAdaptive (bare construction, no BB signature)
// ═════════════════════════════════════════════════════════════════════════════

struct KB21NonAdaptiveSetup {
    params:           RootSetupParams<Bls12_381>,
    sk:               RootSecretKey<Fr>,
    pk:               RootPublicKey<Bls12_381>,
    member:           Fr,
    /// All pre-existing members (populated before our target member).
    /// The holder-update benchmark treats `existing_members[..k]` as revoked.
    existing_members: Vec<Fr>,
    acc:              NonAdaptivePositiveAccumulator<Bls12_381>,
    witness:          MembershipWitness<G1Affine>,
    #[allow(dead_code)]
    state:            SimpleState,
}

fn build_non_adaptive_setup(n_existing: usize) -> KB21NonAdaptiveSetup {
    let mut rng     = StdRng::seed_from_u64(0xDEAD_BEEF_0044_u64);
    let params      = RootSetupParams::<Bls12_381>::new::<Blake2b512>(b"rcb-kb21-na-v1");
    let keypair     = RootKeypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
    let acc         = NonAdaptivePositiveAccumulator::<Bls12_381>::initialize(&mut rng, &params);
    let mut state   = SimpleState::new();

    let existing_members: Vec<Fr> = (0..n_existing).map(|_| Fr::rand(&mut rng)).collect();
    if !existing_members.is_empty() {
        acc.add_batch(existing_members.clone(), &mut state).expect("bulk add failed");
    }

    let member = Fr::rand(&mut rng);
    acc.add(member, &mut state).expect("add member failed");
    let witness = acc.get_membership_witness(&member, &keypair.secret_key, &state)
        .expect("witness failed");

    KB21NonAdaptiveSetup {
        params, sk: keypair.secret_key.clone(), pk: keypair.public_key.clone(), member,
        existing_members, acc, witness, state,
    }
}

fn register_non_adaptive(suite: &mut BenchSuite) {
    for &k in DEL_BATCH {
        suite.register(
            "KB21-NonAdaptive",
            "non_adaptive_witness_update",
            Phase::HolderUpdate,
            Some(k as u64),
            move || {
                // Build with k + 50 pre-existing members; the first k are treated
                // as revoked.  The extra 50 keep the accumulator non-trivially
                // populated independent of k.
                let s    = build_non_adaptive_setup(k + 50);
                let revoked: Vec<Fr> = s.existing_members[..k].to_vec();
                let old_acc_value = *s.acc.value();
                let omega = Omega::<G1Affine>::new(&[], &revoked, &old_acc_value, &s.sk);
                (s, omega, revoked)
            },
            |(s, omega, revoked)| {
                let ok = s.witness
                    .update_using_public_info_after_batch_updates(&[], revoked, omega, &s.member)
                    .is_ok();
                (0, ok)
            },
        );
    }

    suite.register(
        "KB21-NonAdaptive",
        "non_adaptive_prove_membership",
        Phase::Presentation,
        None,
        || build_non_adaptive_setup(100),
        |s| {
            let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
            let protocol: MembershipProofProtocol<Bls12_381> = MembershipProofProtocol::init(
                &mut rng, s.member, None, s.acc.value(), &s.witness,
            );
            let mut transcript = Vec::new();
            protocol.challenge_contribution(s.acc.value(), &mut transcript)
                .expect("challenge_contribution failed");
            let proof = protocol.gen_proof(&derive_challenge(&transcript))
                .expect("gen_proof failed");
            let mut buf = Vec::new();
            proof.serialize_compressed(&mut buf).ok();
            (buf.len(), true)
        },
    );

    suite.register(
        "KB21-NonAdaptive",
        "non_adaptive_verify_membership",
        Phase::Verification,
        None,
        || {
            let s = build_non_adaptive_setup(100);
            let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
            let protocol: MembershipProofProtocol<Bls12_381> = MembershipProofProtocol::init(
                &mut rng, s.member, None, s.acc.value(), &s.witness,
            );
            let mut transcript = Vec::new();
            protocol.challenge_contribution(s.acc.value(), &mut transcript)
                .expect("challenge_contribution failed");
            let challenge = derive_challenge(&transcript);
            let proof: MembershipProof<Bls12_381> = protocol.gen_proof(&challenge)
                .expect("gen_proof failed");
            let mut buf = Vec::new();
            proof.serialize_compressed(&mut buf).ok();
            (s, proof, challenge, buf.len())
        },
        |(s, proof, challenge, proof_size)| {
            let ok = proof.verify(s.acc.value(), challenge, s.pk.clone(), s.params.clone()).is_ok();
            (*proof_size, ok)
        },
    );
}

// ─────────────────────────────────────────────────────────────────────────────

pub fn register(suite: &mut BenchSuite) {
    register_adaptive(suite);
    register_non_adaptive(suite);
}
