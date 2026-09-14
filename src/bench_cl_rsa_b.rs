//! CL-RSA-B Accumulator — phases (iv) Holder Update, (v) Presentation, (vi) Verification.
//!
//! Holder Update is O(k): the server publishes the raw batch product
//! P_D = x₁ × … × xₖ (~256k bits).  The holder computes
//! extended-GCD(my_elem ≈ 256 bits, P_D ≈ 256k bits) to get Bezout
//! coefficients, then updates the witness with two modular exponentiations.
//! Reducing P_D mod φ(n) before publishing would leak a multiple of φ.

use crate::{runner::BenchSuite, types::Phase};
use revocation_comparison_bench::params::DEL_BATCH;

use cl_rsa_b::{accumulator::CLRSABAccumulator, hash::hash_to_prime, H2P_SIZE};
use common::accumulator::{Accumulator, Positive, Subtractive, ZKPositive};
use unknown_order::BigNumber;

// ─── Setup helpers ────────────────────────────────────────────────────────────

struct UpdateSetup {
    acc:        CLRSABAccumulator,
    my_elem:    BigNumber,
    my_witness: cl_rsa_b::witness::CLRSABWitness,
}

/// Build an accumulator with `k` elements already present plus one holder element,
/// then perform the batch revocation so the timed work is only the witness update.
fn build_update_setup(k: usize) -> (UpdateSetup, cl_rsa_b::update::CLRSABUpdate) {
    let to_revoke: Vec<BigNumber> = (0..k)
        .map(|i| {
            let mut data = [0u8; 8];
            data.copy_from_slice(&(i as u64).to_be_bytes());
            hash_to_prime(data)
        })
        .collect();

    let my_elem = BigNumber::prime(H2P_SIZE);
    let mut all: Vec<BigNumber> = to_revoke.iter().cloned().collect();
    all.push(my_elem.clone());

    let (mut acc, aux) = CLRSABAccumulator::new_with_elements(&all);
    let my_witness = acc.witness_mem(&my_elem, aux.as_ref(), &all);

    let refs: Vec<&BigNumber> = to_revoke.iter().collect();
    let update = acc
        .update_after_remove_batch(refs, aux.as_ref(), &mut all)
        .expect("batch remove failed");

    (UpdateSetup { acc, my_elem, my_witness }, update)
}

struct ProofSetup {
    acc:     CLRSABAccumulator,
    elem:    BigNumber,
    witness: cl_rsa_b::witness::CLRSABWitness,
    params:  cl_rsa_b::proof::CLRSABMemParams,
}

fn build_proof_setup() -> ProofSetup {
    let my_elem = BigNumber::prime(H2P_SIZE);
    let elems = vec![my_elem.clone()];
    let (acc, aux) = CLRSABAccumulator::new_with_elements(&elems);
    let witness = acc.witness_mem(&my_elem, aux.as_ref(), &elems);
    let params  = acc.gen_param();
    ProofSetup { acc, elem: my_elem, witness, params }
}

// Byte size of a CLRSABMemProof (13 BigNumber fields).
fn proof_size(proof: &cl_rsa_b::proof::CLRSABMemProof) -> usize {
    [&proof.c_u, &proof.c_e, &proof.c_r,
     &proof.t_1, &proof.t_2, &proof.t_3, &proof.t_4,
     &proof.s_alpha, &proof.s_beta, &proof.s_delta,
     &proof.s_epsilon, &proof.s_zeta, &proof.s_eta]
        .iter().map(|n| n.to_bytes().len()).sum()
}

// ─────────────────────────────────────────────────────────────────────────────

pub fn register(suite: &mut BenchSuite) {
    for &k in DEL_BATCH {
        suite.register(
            "CL-RSA-B",
            "witness_update",
            Phase::HolderUpdate,
            Some(k as u64),
            move || build_update_setup(k),
            |(setup, update)| {
                let new_witness = setup.acc.update(&setup.my_witness, Some(&setup.my_elem), update);
                (0, setup.acc.verify_mem(&setup.my_elem, Some(&new_witness)))
            },
        );
    }

    suite.register(
        "CL-RSA-B",
        "prove_membership",
        Phase::Presentation,
        None,
        build_proof_setup,
        |s| {
            let proof = s.acc.prove_mem(&s.params, &s.elem, &s.witness, b"eudi-rcb-nonce");
            (proof_size(&proof), true)
        },
    );

    suite.register(
        "CL-RSA-B",
        "verify_membership",
        Phase::Verification,
        None,
        || {
            let s = build_proof_setup();
            let proof = s.acc.prove_mem(&s.params, &s.elem, &s.witness, b"eudi-rcb-nonce");
            let size  = proof_size(&proof);
            (s, proof, size)
        },
        |(s, proof, size)| {
            (*size, s.acc.verify_mem_proof(&s.params, proof, b"eudi-rcb-nonce"))
        },
    );
}
