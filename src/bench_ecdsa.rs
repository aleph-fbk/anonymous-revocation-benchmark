//! ECDSA-based Signed Pairs — phase (iv) Holder Update.
//!
//! After each epoch the issuer publishes a new RL_t: each gap is individually
//! signed with ECDSA-P256 over epoch ‖ lower_id ‖ upper_id (24 bytes).
//! The holder scans the list, finds the gap containing its UID, and verifies
//! the ECDSA signature to confirm authenticity.
//!
//! Phases (v) and (vi) are benchmarked via scripts/android.sh run-lf
//! (longfellow-zk C++ binary).

use crate::{runner::{BenchSuite}, types::Phase};
use revocation_comparison_bench::params::{DEL_BATCH, LIST_BASE_SIZE};

use ark_std::rand::{rngs::StdRng, SeedableRng};
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature as EcdsaSig,
    SigningKey as EcdsaSigningKey,
    VerifyingKey as EcdsaVerifyingKey,
};

struct SignedGap {
    lower: u64,
    upper: u64,
    epoch: u64,
    sig:   EcdsaSig,
}

/// Encode a gap as the 24-byte message that was signed: epoch ‖ lower ‖ upper.
/// Must match the format used in benches/server.rs bench_ecdsa_sign_gap.
fn encode_gap(epoch: u64, lower: u64, upper: u64) -> [u8; 24] {
    let mut msg = [0u8; 24];
    msg[0..8].copy_from_slice(&epoch.to_be_bytes());
    msg[8..16].copy_from_slice(&lower.to_be_bytes());
    msg[16..24].copy_from_slice(&upper.to_be_bytes());
    msg
}

struct EcdsaSetup {
    vk:   EcdsaVerifyingKey,
    gaps: Vec<SignedGap>,
    uid:  u64,
}

fn build_setup(n: usize) -> EcdsaSetup {
    let mut rng = StdRng::seed_from_u64(0xEC_DA_5E_ED_u64);
    let sk = EcdsaSigningKey::random(&mut rng);
    let vk = EcdsaVerifyingKey::from(&sk);
    let epoch = 1025_u64;

    let half = n / 2;
    let mut gaps = Vec::with_capacity(n);
    for i in 0..n {
        let lower = (i as u64) * 10;
        let upper = lower + 9;
        let sig: EcdsaSig = sk.sign(&encode_gap(epoch, lower, upper));
        gaps.push(SignedGap { lower, upper, epoch, sig });
    }
    let uid = (half as u64) * 10 + 4;

    EcdsaSetup { vk, gaps, uid }
}

pub fn register(suite: &mut BenchSuite) {
    for &k in DEL_BATCH {
        let total = LIST_BASE_SIZE + k + 1;
        suite.register(
            "ECDSA-LF",
            "witness_update",
            Phase::HolderUpdate,
            Some(k as u64),
            move || build_setup(total),
            |s| {
                let found = s.gaps.iter().find(|g| g.lower <= s.uid && s.uid <= g.upper);
                match found {
                    None    => (0, false),
                    Some(g) => {
                        let msg = encode_gap(g.epoch, g.lower, g.upper);
                        (0, s.vk.verify(&msg, &g.sig).is_ok())
                    }
                }
            },
        );
    }
    // Phases (v) and (vi): run scripts/android.sh run-lf
}
