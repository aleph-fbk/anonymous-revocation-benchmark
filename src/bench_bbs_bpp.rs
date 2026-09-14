//! BBS+ + Bulletproofs++ (Signed Pairs) — phases (iv) Holder Update, (v) Presentation, (vi) Verification.
//!
//! Non-revocation proof structure:
//!
//!   (a) Composite proof (proof_system):
//!       - BBS-2023 PoK over (lower_id, upper_id, expiry_ts, rev_handle);
//!         expiry_ts revealed to the verifier.
//!       - Three PedersenCommitment PoKs binding C_L, C_H, C_U to the BBS+ attributes.
//!       - EqualWitnesses links each Pedersen value to its BBS+ attribute.
//!
//!   (b) Single AGGREGATE Bulletproof++ on [D1, D2]:
//!       D1 = C_H − C_L − G  proves lower_id  < rev_handle
//!       D2 = C_U − C_H − G  proves rev_handle < upper_id
//!
//!       One aggregate BPP call (num_proofs=2) instead of two separate proofs
//!       reduces proof size and prover/verifier time (log-factor saving).
//!
//! Decomposition benches (below the (iv)/(v)/(vi) registrations):
//!   - `*_bbs_only`               : BBS+ PoK alone, no Pedersen commitments.
//!   - `*_bbs_pedcomm`            : (a) above — BBS+ PoK + 3 PedComm PoKs + equalities, no BPP.
//!   - `*_bpp_single_unaggregated`: one plain (non-aggregated) 32-bit BPP range proof —
//!                                  the "single bulletproof" baseline unit.
//!   - `*_bpp_aggregate`          : (b) above — the actual aggregate-of-2 BPP this
//!                                  construction uses, isolated from (a).
//!   - `*_non_revocation`         : (a) + (b) combined — the real end-to-end cost.
//!   - `bpp_aggregate_bitwidth_*` : sweeps the aggregate BPP's bit-width
//!                                  (16/32/64/128/256) holding num_proofs=2 fixed,
//!                                  to see how the bulletproof itself scales with
//!                                  the identifier space size.

use crate::{runner::BenchSuite, types::Phase};
use revocation_comparison_bench::params::{BBS_CRED_ATTR_COUNT, DEL_BATCH, EXPIRY_TS, LIST_BASE_SIZE};

use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
use blake2::Blake2b512;
use dock_crypto_utils::transcript::new_merlin_transcript;
use std::collections::{BTreeMap, BTreeSet};

use bbs_plus::{
    setup::{KeypairG2 as BBSKeypair, PublicKeyG2 as BBSPublicKey, SignatureParams23G1 as BBSParams},
    signature_23::Signature23G1 as BBSSig,
};
use bulletproofs_plus_plus::{
    prelude::{Proof as BppProof, Prover as BppProver},
    setup::SetupParams as BppSetupParams,
};
use proof_system::{
    meta_statement::{EqualWitnesses, MetaStatements},
    proof::Proof,
    proof_spec::ProofSpec,
    statement::{
        bbs_23::{
            PoKBBSSignature23G1Prover  as BBSSigStmtProver,
            PoKBBSSignature23G1Verifier as BBSSigStmtVerifier,
        },
        ped_comm::PedersenCommitment as PedCommStmt,
        Statements,
    },
    witness::{PoKBBSSignature23G1 as BBSSigWit, Witness, Witnesses},
};

type Fr = <Bls12_381 as Pairing>::ScalarField;
type BppParams = BppSetupParams<G1Affine>;

// ─────────────────────────────────────────────────────────────────────────────
// Domain constants
// ─────────────────────────────────────────────────────────────────────────────

// REV_ATTR_COUNT is BBS_CRED_ATTR_COUNT from params: lower_id, upper_id, expiry_ts, rev_handle.
const REV_HANDLE_VAL: u64 = 1_500_u64;
const LOWER_ID:       u64 = 1_000_u64;
const UPPER_ID:       u64 = 2_000_u64;

/// Bit-widths swept for the isolated aggregate-BPP benchmark. All must be
/// powers of two (bulletproofs_plus_plus requirement). 256 matches the wider
/// id domain used by longfellow-zk's mdoc revocation circuit (see README).
const BPP_BIT_WIDTHS: &[u16] = &[16, 32, 64, 128, 256];

// ─────────────────────────────────────────────────────────────────────────────
// Presentation / Verification shared state
// ─────────────────────────────────────────────────────────────────────────────

pub struct SPSetup {
    pub rev_params: BBSParams<Bls12_381>,
    pub rev_kp:     BBSKeypair<Bls12_381>,
    pub rev_msgs:   Vec<Fr>,
    pub rev_sig:    BBSSig<Bls12_381>,
    // BPP generators configured for 2 aggregated 32-bit range proofs.
    // (longfellow-zk's mdoc revocation circuit uses a wider 256-bit id
    // domain — see the README's "Cross-mechanism ZK statement" note for
    // that asymmetry between the two constructions.)
    pub bp_gens:    BppParams,
    // Pedersen commitment key shared with BPP: [G_bpp, H_bpp_0].
    pub ped_key:    Vec<G1Affine>,
    pub nonce:      Vec<u8>,
}

fn build_setup() -> SPSetup {
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_C0DE_u64);

    let rev_params = BBSParams::<Bls12_381>::new::<sha2::Sha256>(b"rcb-sp-params-v1", BBS_CRED_ATTR_COUNT);
    let rev_kp = BBSKeypair::<Bls12_381>::generate_using_rng_and_bbs23_params(&mut rng, &rev_params);

    let rev_msgs = vec![
        Fr::from(LOWER_ID),
        Fr::from(UPPER_ID),
        Fr::from(EXPIRY_TS),
        Fr::from(REV_HANDLE_VAL),
    ];
    let rev_sig = BBSSig::<Bls12_381>::new(&mut rng, &rev_msgs, &rev_kp.secret_key, &rev_params)
        .expect("signing failed");

    // num_value_bits = 32: comfortably covers any realistic list size
    // (~999,000 needs ~20 bits); see README's "Cross-mechanism ZK statement"
    // note for why not 64/256.
    let bp_gens = BppParams::new_for_perfect_range_proof::<Blake2b512>(
        b"rcb-bpp-gens-v1",
        2,   // base = 2 (binary)
        32, // num_value_bits
        2,   // aggregate two commitments in one proof
    );
    let ped_key = vec![bp_gens.G, bp_gens.H_vec[0]];

    SPSetup { rev_params, rev_kp, rev_msgs, rev_sig, bp_gens, ped_key, nonce: b"rcb-nonce-12345".to_vec() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof bundle
// ─────────────────────────────────────────────────────────────────────────────

struct FullProof {
    composite: Proof<Bls12_381>,
    c_l: G1Affine,
    c_h: G1Affine,
    c_u: G1Affine,
    bpp: BppProof<G1Affine>,
}

fn serialized_size(fp: &FullProof) -> usize {
    let mut buf = Vec::new();
    fp.composite.serialize_compressed(&mut buf).ok();
    fp.c_l.serialize_compressed(&mut buf).ok();
    fp.c_h.serialize_compressed(&mut buf).ok();
    fp.c_u.serialize_compressed(&mut buf).ok();
    fp.bpp.serialize_compressed(&mut buf).ok();
    buf.len()
}

/// Output of the (a) composite-proof step alone (BBS+ PoK + 3 PedComm PoKs +
/// equalities), before the BPP layer is added. Carries the commitment
/// randomness forward so the BPP step can be built/timed separately.
struct CompositeProof {
    proof: Proof<Bls12_381>,
    c_l: G1Affine,
    c_h: G1Affine,
    c_u: G1Affine,
    r_l: Fr,
    r_h: Fr,
    r_u: Fr,
    size: usize,
}

fn build_composite_proof(s: &SPSetup) -> CompositeProof {
    let mut rng = StdRng::seed_from_u64(0xABCD_EF01_u64);

    // Pedersen commitments to lower_id, rev_handle, upper_id.
    let r_l = Fr::rand(&mut rng);
    let r_h = Fr::rand(&mut rng);
    let r_u = Fr::rand(&mut rng);
    let c_l = s.bp_gens.compute_pedersen_commitment(LOWER_ID, &r_l);
    let c_h = s.bp_gens.compute_pedersen_commitment(REV_HANDLE_VAL, &r_h);
    let c_u = s.bp_gens.compute_pedersen_commitment(UPPER_ID, &r_u);

    // Composite proof: BBS+ PoK + three PedComm PoKs + equality witnesses.
    let mut revealed_rev: BTreeMap<usize, Fr> = BTreeMap::new();
    revealed_rev.insert(2, s.rev_msgs[2]); // expiry_ts revealed to verifier

    let stmt0    = BBSSigStmtProver::<Bls12_381>::new_statement_from_params(s.rev_params.clone(), revealed_rev);
    let stmt_cl  = PedCommStmt::new_statement_from_params::<Bls12_381>(s.ped_key.clone(), c_l);
    let stmt_ch  = PedCommStmt::new_statement_from_params::<Bls12_381>(s.ped_key.clone(), c_h);
    let stmt_cu  = PedCommStmt::new_statement_from_params::<Bls12_381>(s.ped_key.clone(), c_u);

    let mut statements = Statements::new();
    let s0   = statements.add(stmt0);
    let s_cl = statements.add(stmt_cl);
    let s_ch = statements.add(stmt_ch);
    let s_cu = statements.add(stmt_cu);

    let mut eq_lo  = BTreeSet::new(); eq_lo.insert((s0, 0)); eq_lo.insert((s_cl, 0));
    let mut eq_hi  = BTreeSet::new(); eq_hi.insert((s0, 1)); eq_hi.insert((s_cu, 0));
    let mut eq_rev = BTreeSet::new(); eq_rev.insert((s0, 3)); eq_rev.insert((s_ch, 0));

    let mut meta = MetaStatements::new();
    meta.add_witness_equality(EqualWitnesses(eq_lo));
    meta.add_witness_equality(EqualWitnesses(eq_hi));
    meta.add_witness_equality(EqualWitnesses(eq_rev));

    let proof_spec = ProofSpec::new(statements, meta, vec![], None);
    proof_spec.validate().expect("invalid proof spec");

    let mut unrevealed: BTreeMap<usize, Fr> = BTreeMap::new();
    unrevealed.insert(0, s.rev_msgs[0]);
    unrevealed.insert(1, s.rev_msgs[1]);
    unrevealed.insert(3, s.rev_msgs[3]);
    let w0   = BBSSigWit::<Bls12_381>::new_as_witness(s.rev_sig.clone(), unrevealed);
    let w_cl = Witness::PedersenCommitment(vec![Fr::from(LOWER_ID),       r_l]);
    let w_ch = Witness::PedersenCommitment(vec![Fr::from(REV_HANDLE_VAL), r_h]);
    let w_cu = Witness::PedersenCommitment(vec![Fr::from(UPPER_ID),       r_u]);

    let mut witnesses = Witnesses::new();
    witnesses.add(w0);
    witnesses.add(w_cl);
    witnesses.add(w_ch);
    witnesses.add(w_cu);

    let (proof, _) = Proof::<Bls12_381>::new::<StdRng, Blake2b512>(
        &mut rng, proof_spec, witnesses, Some(s.nonce.clone()), Default::default(),
    ).expect("composite proof failed");

    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).ok();
    let size = buf.len();

    CompositeProof { proof, c_l, c_h, c_u, r_l, r_h, r_u, size }
}

fn verify_composite_proof_ok(
    s: &SPSetup, composite: &Proof<Bls12_381>, c_l: G1Affine, c_h: G1Affine, c_u: G1Affine,
) -> bool {
    let mut rng = StdRng::seed_from_u64(0xAAAA_BBBB_u64);

    let mut revealed: BTreeMap<usize, Fr> = BTreeMap::new();
    revealed.insert(2, s.rev_msgs[2]);
    let stmt0   = BBSSigStmtVerifier::<Bls12_381>::new_statement_from_params(
        s.rev_params.clone(), s.rev_kp.public_key.clone(), revealed,
    );
    let stmt_cl = PedCommStmt::new_statement_from_params::<Bls12_381>(s.ped_key.clone(), c_l);
    let stmt_ch = PedCommStmt::new_statement_from_params::<Bls12_381>(s.ped_key.clone(), c_h);
    let stmt_cu = PedCommStmt::new_statement_from_params::<Bls12_381>(s.ped_key.clone(), c_u);

    let mut statements = Statements::new();
    let s0   = statements.add(stmt0);
    let s_cl = statements.add(stmt_cl);
    let s_ch = statements.add(stmt_ch);
    let s_cu = statements.add(stmt_cu);

    let mut eq_lo  = BTreeSet::new(); eq_lo.insert((s0, 0)); eq_lo.insert((s_cl, 0));
    let mut eq_hi  = BTreeSet::new(); eq_hi.insert((s0, 1)); eq_hi.insert((s_cu, 0));
    let mut eq_rev = BTreeSet::new(); eq_rev.insert((s0, 3)); eq_rev.insert((s_ch, 0));

    let mut meta = MetaStatements::new();
    meta.add_witness_equality(EqualWitnesses(eq_lo));
    meta.add_witness_equality(EqualWitnesses(eq_hi));
    meta.add_witness_equality(EqualWitnesses(eq_rev));

    let proof_spec = ProofSpec::new(statements, meta, vec![], None);
    composite.clone()
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, Some(s.nonce.clone()), Default::default())
        .is_ok()
}

/// The aggregate BPP step (b): builds D1/D2 from the composite proof's
/// commitments and proves both ranges in one aggregated call.
fn build_bpp_proof(gens: &BppParams, c_l: G1Affine, c_h: G1Affine, c_u: G1Affine, r_l: Fr, r_h: Fr, r_u: Fr) -> BppProof<G1Affine> {
    let mut rng = StdRng::seed_from_u64(0xABCD_EF01_u64);

    let g_proj = gens.G.into_group();
    let d1 = (c_h.into_group() - c_l.into_group() - g_proj).into_affine();
    let d2 = (c_u.into_group() - c_h.into_group() - g_proj).into_affine();

    let diff1 = REV_HANDLE_VAL - LOWER_ID - 1; // 499
    let diff2 = UPPER_ID - REV_HANDLE_VAL - 1; // 499

    let mut t = new_merlin_transcript(b"rcb-bpp-aggregate");
    BppProver::new(32, vec![d1, d2], vec![diff1, diff2], vec![r_h - r_l, r_u - r_h])
        .expect("BPP prover init failed")
        .prove(&mut rng, gens.clone(), &mut t)
        .expect("BPP proof generation failed")
}

fn build_proof(s: &SPSetup) -> (FullProof, usize) {
    let cp = build_composite_proof(s);
    let bpp = build_bpp_proof(&s.bp_gens, cp.c_l, cp.c_h, cp.c_u, cp.r_l, cp.r_h, cp.r_u);
    let fp = FullProof { composite: cp.proof, c_l: cp.c_l, c_h: cp.c_h, c_u: cp.c_u, bpp };
    let size = serialized_size(&fp);
    (fp, size)
}

// ─────────────────────────────────────────────────────────────────────────────
// BBS+-only baseline (no Pedersen commitments, no BPP at all)
// ─────────────────────────────────────────────────────────────────────────────

fn build_bbs_only_proof(s: &SPSetup) -> (Proof<Bls12_381>, usize) {
    let mut rng = StdRng::seed_from_u64(0xABCD_EF01_u64);

    let mut revealed_rev: BTreeMap<usize, Fr> = BTreeMap::new();
    revealed_rev.insert(2, s.rev_msgs[2]);
    let stmt0 = BBSSigStmtProver::<Bls12_381>::new_statement_from_params(s.rev_params.clone(), revealed_rev);

    let mut statements = Statements::new();
    statements.add(stmt0);
    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), vec![], None);
    proof_spec.validate().expect("invalid proof spec");

    let mut unrevealed: BTreeMap<usize, Fr> = BTreeMap::new();
    unrevealed.insert(0, s.rev_msgs[0]);
    unrevealed.insert(1, s.rev_msgs[1]);
    unrevealed.insert(3, s.rev_msgs[3]);
    let w0 = BBSSigWit::<Bls12_381>::new_as_witness(s.rev_sig.clone(), unrevealed);
    let mut witnesses = Witnesses::new();
    witnesses.add(w0);

    let (proof, _) = Proof::<Bls12_381>::new::<StdRng, Blake2b512>(
        &mut rng, proof_spec, witnesses, Some(s.nonce.clone()), Default::default(),
    ).expect("bbs-only proof failed");

    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).ok();
    let size = buf.len();
    (proof, size)
}

fn verify_bbs_only_proof(s: &SPSetup, proof: &Proof<Bls12_381>) -> bool {
    let mut rng = StdRng::seed_from_u64(0xAAAA_BBBB_u64);
    let mut revealed: BTreeMap<usize, Fr> = BTreeMap::new();
    revealed.insert(2, s.rev_msgs[2]);
    let stmt0 = BBSSigStmtVerifier::<Bls12_381>::new_statement_from_params(
        s.rev_params.clone(), s.rev_kp.public_key.clone(), revealed,
    );
    let mut statements = Statements::new();
    statements.add(stmt0);
    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), vec![], None);
    proof.clone()
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, Some(s.nonce.clone()), Default::default())
        .is_ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Single (non-aggregated) 32-bit bulletproof — the "one bulletproof" baseline
// ─────────────────────────────────────────────────────────────────────────────

struct SingleBppSetup {
    gens:  BppParams,
    d1:    G1Affine,
    diff1: u64,
    dr1:   Fr,
}

fn build_single_bpp_setup() -> SingleBppSetup {
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_C0DE_u64);
    // Sized for num_proofs=1: a real, standalone single range proof, not a
    // slice of the aggregate-of-2 generators used elsewhere in this file.
    let gens = BppParams::new_for_perfect_range_proof::<Blake2b512>(b"rcb-bpp-gens-single-v1", 2, 32, 1);

    let r_l = Fr::rand(&mut rng);
    let r_h = Fr::rand(&mut rng);
    let c_l = gens.compute_pedersen_commitment(LOWER_ID, &r_l);
    let c_h = gens.compute_pedersen_commitment(REV_HANDLE_VAL, &r_h);
    let g_proj = gens.G.into_group();
    let d1 = (c_h.into_group() - c_l.into_group() - g_proj).into_affine();

    SingleBppSetup { gens, d1, diff1: REV_HANDLE_VAL - LOWER_ID - 1, dr1: r_h - r_l }
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregate-of-2 bulletproof in isolation (the (b) step actually used above)
// ─────────────────────────────────────────────────────────────────────────────

struct BppOnlySetup {
    gens:  BppParams,
    d1:    G1Affine,
    d2:    G1Affine,
    diff1: u64,
    diff2: u64,
    dr1:   Fr,
    dr2:   Fr,
}

fn build_bpp_only_setup() -> BppOnlySetup {
    let s = build_setup();
    let mut rng = StdRng::seed_from_u64(0xABCD_EF01_u64);
    let r_l = Fr::rand(&mut rng);
    let r_h = Fr::rand(&mut rng);
    let r_u = Fr::rand(&mut rng);
    let c_l = s.bp_gens.compute_pedersen_commitment(LOWER_ID, &r_l);
    let c_h = s.bp_gens.compute_pedersen_commitment(REV_HANDLE_VAL, &r_h);
    let c_u = s.bp_gens.compute_pedersen_commitment(UPPER_ID, &r_u);
    let g_proj = s.bp_gens.G.into_group();
    let d1 = (c_h.into_group() - c_l.into_group() - g_proj).into_affine();
    let d2 = (c_u.into_group() - c_h.into_group() - g_proj).into_affine();
    BppOnlySetup {
        gens: s.bp_gens, d1, d2,
        diff1: REV_HANDLE_VAL - LOWER_ID - 1,
        diff2: UPPER_ID - REV_HANDLE_VAL - 1,
        dr1: r_h - r_l,
        dr2: r_u - r_h,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bulletproof bit-width sweep (aggregate-of-2, num_bits varies)
// ─────────────────────────────────────────────────────────────────────────────

struct BitWidthSetup {
    gens:     BppParams,
    d1:       G1Affine,
    d2:       G1Affine,
    diff1:    u64,
    diff2:    u64,
    dr1:      Fr,
    dr2:      Fr,
    num_bits: u16,
}

fn build_bitwidth_setup(num_bits: u16) -> BitWidthSetup {
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_C0DE_u64);
    let gens = BppParams::new_for_perfect_range_proof::<Blake2b512>(
        b"rcb-bpp-gens-bitwidth-v1", 2, num_bits, 2,
    );
    let r_l = Fr::rand(&mut rng);
    let r_h = Fr::rand(&mut rng);
    let r_u = Fr::rand(&mut rng);
    let c_l = gens.compute_pedersen_commitment(LOWER_ID, &r_l);
    let c_h = gens.compute_pedersen_commitment(REV_HANDLE_VAL, &r_h);
    let c_u = gens.compute_pedersen_commitment(UPPER_ID, &r_u);
    let g_proj = gens.G.into_group();
    let d1 = (c_h.into_group() - c_l.into_group() - g_proj).into_affine();
    let d2 = (c_u.into_group() - c_h.into_group() - g_proj).into_affine();
    BitWidthSetup {
        gens, d1, d2,
        diff1: REV_HANDLE_VAL - LOWER_ID - 1,
        diff2: UPPER_ID - REV_HANDLE_VAL - 1,
        dr1: r_h - r_l,
        dr2: r_u - r_h,
        num_bits,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Holder Update (iv): scan RL_t + verify BBS+ signature on holder's gap
// ─────────────────────────────────────────────────────────────────────────────

struct HolderUpdateSetup {
    gaps:       Vec<(u64, u64)>,
    uid:        u64,
    rev_sig:    BBSSig<Bls12_381>,
    rev_msgs:   Vec<Fr>,
    rev_pk:     BBSPublicKey<Bls12_381>,
    rev_params: BBSParams<Bls12_381>,
}

fn build_holder_update_setup(n: usize) -> HolderUpdateSetup {
    let half = n / 2;
    let mut gaps = Vec::with_capacity(n);
    for i in 0u64..(half as u64) {
        gaps.push((i * 2, i * 2 + 1));
    }
    let target_lo = (half as u64) * 2;
    let target_hi = target_lo + 2;
    let uid = target_lo + 1;
    gaps.push((target_lo, target_hi));
    for i in 0u64..((n - half - 1) as u64) {
        gaps.push((target_hi + 1 + i * 2, target_hi + 2 + i * 2));
    }

    // Reuse build_setup() so the BBS+ credential and key material are
    // identical to the presentation benchmark (same nonce, same params).
    let s = build_setup();
    HolderUpdateSetup {
        gaps,
        uid,
        rev_sig:    s.rev_sig,
        rev_msgs:   s.rev_msgs,
        rev_pk:     s.rev_kp.public_key.clone(),
        rev_params: s.rev_params,
    }
}

// ─────────────────────────────────────────────────────────────────────────────

pub fn register(suite: &mut BenchSuite) {
    for &k in DEL_BATCH {
        let total = LIST_BASE_SIZE + k + 1;
        suite.register(
            "BBS-BP",
            "witness_update",
            Phase::HolderUpdate,
            Some(k as u64),
            move || build_holder_update_setup(total),
            |s| {
                let found = s.gaps.iter().find(|(lo, hi)| lo <= &s.uid && &s.uid <= hi);
                if found.is_none() { return (0, false); }
                // Verify the BBS+ signature on the holder's gap credential.
                // This matches ECDSA holder update which also does scan + sig verify.
                let ok = s.rev_sig.verify(&s.rev_msgs, s.rev_pk.clone(), s.rev_params.clone()).is_ok();
                (0, ok)
            },
        );
    }

    suite.register(
        "BBS-BP",
        "prove_membership",
        Phase::Presentation,
        None,
        build_setup,
        |s| {
            let (_fp, size) = build_proof(s);
            (size, true)
        },
    );

    suite.register(
        "BBS-BP",
        "verify_membership",
        Phase::Verification,
        None,
        || {
            let s = build_setup();
            let (fp, size) = build_proof(&s);
            (s, fp, size)
        },
        |(s, fp, proof_size)| {
            let ok_composite = verify_composite_proof_ok(s, &fp.composite, fp.c_l, fp.c_h, fp.c_u);

            let g_proj = s.bp_gens.G.into_group();
            let d1 = (fp.c_h.into_group() - fp.c_l.into_group() - g_proj).into_affine();
            let d2 = (fp.c_u.into_group() - fp.c_h.into_group() - g_proj).into_affine();

            let mut t = new_merlin_transcript(b"rcb-bpp-aggregate");
            let ok_bpp = fp.bpp.verify(32, &[d1, d2], &s.bp_gens, &mut t).is_ok();

            (*proof_size, ok_composite && ok_bpp)
        },
    );

    // ─── Decomposition: BBS-only baseline ──────────────────────────────────
    suite.register(
        "BBS-BP", "prove_bbs_only", Phase::Presentation, None,
        build_setup,
        |s| { let (_p, size) = build_bbs_only_proof(s); (size, true) },
    );
    suite.register(
        "BBS-BP", "verify_bbs_only", Phase::Verification, None,
        || { let s = build_setup(); let (p, size) = build_bbs_only_proof(&s); (s, p, size) },
        |(s, p, size)| { (*size, verify_bbs_only_proof(s, p)) },
    );

    // ─── Decomposition: BBS + 3 Pedersen-commitment PoKs, no BPP ───────────
    suite.register(
        "BBS-BP", "prove_bbs_pedcomm", Phase::Presentation, None,
        build_setup,
        |s| { let cp = build_composite_proof(s); (cp.size, true) },
    );
    suite.register(
        "BBS-BP", "verify_bbs_pedcomm", Phase::Verification, None,
        || { let s = build_setup(); let cp = build_composite_proof(&s); (s, cp) },
        |(s, cp)| { (cp.size, verify_composite_proof_ok(s, &cp.proof, cp.c_l, cp.c_h, cp.c_u)) },
    );

    // ─── Decomposition: one plain (non-aggregated) 32-bit bulletproof ──────
    suite.register(
        "BBS-BP", "prove_bpp_single_unaggregated", Phase::Presentation, None,
        build_single_bpp_setup,
        |s: &SingleBppSetup| {
            let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
            let mut t = new_merlin_transcript(b"rcb-bpp-single");
            let bpp = BppProver::new(32, vec![s.d1], vec![s.diff1], vec![s.dr1])
                .expect("BPP prover init failed")
                .prove(&mut rng, s.gens.clone(), &mut t)
                .expect("BPP proof generation failed");
            let mut buf = Vec::new();
            bpp.serialize_compressed(&mut buf).ok();
            (buf.len(), true)
        },
    );
    suite.register(
        "BBS-BP", "verify_bpp_single_unaggregated", Phase::Verification, None,
        || {
            let s = build_single_bpp_setup();
            let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
            let mut t = new_merlin_transcript(b"rcb-bpp-single");
            let bpp = BppProver::new(32, vec![s.d1], vec![s.diff1], vec![s.dr1])
                .expect("BPP prover init failed")
                .prove(&mut rng, s.gens.clone(), &mut t)
                .expect("BPP proof generation failed");
            (s, bpp)
        },
        |(s, bpp): &(SingleBppSetup, BppProof<G1Affine>)| {
            let mut t = new_merlin_transcript(b"rcb-bpp-single");
            let ok = bpp.verify(32, &[s.d1], &s.gens, &mut t).is_ok();
            let mut buf = Vec::new();
            bpp.serialize_compressed(&mut buf).ok();
            (buf.len(), ok)
        },
    );

    // ─── Decomposition: the actual aggregate-of-2 bulletproof, isolated ────
    suite.register(
        "BBS-BP", "prove_bpp_aggregate", Phase::Presentation, None,
        build_bpp_only_setup,
        |s: &BppOnlySetup| {
            let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
            let mut t = new_merlin_transcript(b"rcb-bpp-aggregate");
            let bpp = BppProver::new(32, vec![s.d1, s.d2], vec![s.diff1, s.diff2], vec![s.dr1, s.dr2])
                .expect("BPP prover init failed")
                .prove(&mut rng, s.gens.clone(), &mut t)
                .expect("BPP proof generation failed");
            let mut buf = Vec::new();
            bpp.serialize_compressed(&mut buf).ok();
            (buf.len(), true)
        },
    );
    suite.register(
        "BBS-BP", "verify_bpp_aggregate", Phase::Verification, None,
        || {
            let s = build_bpp_only_setup();
            let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
            let mut t = new_merlin_transcript(b"rcb-bpp-aggregate");
            let bpp = BppProver::new(32, vec![s.d1, s.d2], vec![s.diff1, s.diff2], vec![s.dr1, s.dr2])
                .expect("BPP prover init failed")
                .prove(&mut rng, s.gens.clone(), &mut t)
                .expect("BPP proof generation failed");
            (s, bpp)
        },
        |(s, bpp): &(BppOnlySetup, BppProof<G1Affine>)| {
            let mut t = new_merlin_transcript(b"rcb-bpp-aggregate");
            let ok = bpp.verify(32, &[s.d1, s.d2], &s.gens, &mut t).is_ok();
            let mut buf = Vec::new();
            bpp.serialize_compressed(&mut buf).ok();
            (buf.len(), ok)
        },
    );

    // ─── Sweep: aggregate-of-2 bulletproof cost vs. identifier bit-width ───
    for &bits in BPP_BIT_WIDTHS {
        suite.register(
            "BBS-BP", "bpp_aggregate_bitwidth_prove", Phase::Presentation, Some(bits as u64),
            move || build_bitwidth_setup(bits),
            |s: &BitWidthSetup| {
                let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
                let mut t = new_merlin_transcript(b"rcb-bpp-aggregate");
                let bpp = BppProver::new(s.num_bits, vec![s.d1, s.d2], vec![s.diff1, s.diff2], vec![s.dr1, s.dr2])
                    .expect("BPP prover init failed")
                    .prove(&mut rng, s.gens.clone(), &mut t)
                    .expect("BPP proof generation failed");
                let mut buf = Vec::new();
                bpp.serialize_compressed(&mut buf).ok();
                (buf.len(), true)
            },
        );
        suite.register(
            "BBS-BP", "bpp_aggregate_bitwidth_verify", Phase::Verification, Some(bits as u64),
            move || {
                let s = build_bitwidth_setup(bits);
                let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
                let mut t = new_merlin_transcript(b"rcb-bpp-aggregate");
                let bpp = BppProver::new(s.num_bits, vec![s.d1, s.d2], vec![s.diff1, s.diff2], vec![s.dr1, s.dr2])
                    .expect("BPP prover init failed")
                    .prove(&mut rng, s.gens.clone(), &mut t)
                    .expect("BPP proof generation failed");
                (s, bpp)
            },
            |(s, bpp): &(BitWidthSetup, BppProof<G1Affine>)| {
                let mut t = new_merlin_transcript(b"rcb-bpp-aggregate");
                let ok = bpp.verify(s.num_bits, &[s.d1, s.d2], &s.gens, &mut t).is_ok();
                let mut buf = Vec::new();
                bpp.serialize_compressed(&mut buf).ok();
                (buf.len(), ok)
            },
        );
    }
}
