use crate::{
    accumulator::CLRSABAccumulator,
    helpers::generate_quadratic_residue,
    proof::{CLRSABMemParams, CLRSABMemProof},
    witness::CLRSABWitness,
    CHALLENGE_SIZE, H2P_SIZE, NONCE_SIZE, P_SIZE,
};
use common::accumulator::ZKPositive;

use blake3::Hasher;
use unknown_order::BigNumber;

fn hash_to_k_bits(params: &CLRSABMemParams, nums: &[&BigNumber], extra: &[u8]) -> BigNumber {
    let mut hasher = Hasher::new();

    // hasher.update(&params.p.to_bytes());
    // hasher.update(&params.q.to_bytes());
    // hasher.update(&params.gg.to_bytes());
    // hasher.update(&params.hh.to_bytes());
    hasher.update(&params.g.to_bytes());
    hasher.update(&params.h.to_bytes());

    for n in nums {
        hasher.update(&n.to_bytes());
    }

    hasher.update(extra);

    let mut hash = [0u8; CHALLENGE_SIZE / 8];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut hash);

    BigNumber::from_slice(hash)
}

impl ZKPositive for CLRSABAccumulator {
    type MemProof = CLRSABMemProof;
    type MemParams = CLRSABMemParams;

    fn gen_param(&self) -> Self::MemParams {
        // From `Dynamic Accumulators and Application to Efficient Revocation of Anonymous
        // Credentials` (Camenisch and Lysyanskaya, 2002), sec. 3.3
        //
        // https://doi.org/10.1007/3-540-45708-9_5

        // For the group (G_q, ·) we use a Schnorr group where:
        // - q has 256 bits to resist Pollard ρ
        // - p has 2048 bits to resist index calculus
        // let q = BigNumber::prime(256);
        // let mut r: BigNumber = BigNumber::one() << 1792;
        // let p = loop {
        //     let t: BigNumber = r.clone() * q.clone() + 1;
        //     if t.is_prime() {
        //         break t;
        //     }
        //     r += 2;
        // };

        // // Find generators
        // let mut gg = BigNumber::random_range(&BigNumber::one(), &p);
        // while gg.modpow(&r, &p).is_one() {
        //     gg += 1;
        // }
        // gg = gg.modpow(&r, &p);
        // let mut hh = BigNumber::random_range(&BigNumber::one(), &p);
        // while hh.modpow(&r, &p).is_one() {
        //     hh += 1;
        // }
        // hh = hh.modpow(&r, &p);

        // Two quadratic residues with unknown discrete logarithm
        let g = generate_quadratic_residue(&self.modulus);
        let exp = BigNumber::random_bits(P_SIZE as u32 / 2);
        let h = g.modpow(&exp, &self.modulus);

        CLRSABMemParams { 
            // p, q, gg, hh, 
            g, h }
    }

    fn prove_mem(
        &self,
        params: &Self::MemParams,
        item: &Self::Element,
        witness: &Self::Witness,
        extra: &[u8],
    ) -> Self::MemProof {
        // From `Efficient Revocation of Anonymous Group Membership Certificates and Anonymous
        // Credentials` (Camenisch and Lysyanskaya, 2001), appendix A
        //
        // https://eprint.iacr.org/2001/113
        let CLRSABMemParams { 
            //p, q, gg, hh, 
            g, h } = params;
        //let kprime = 64; // TODO: choose an appropriate value
        let n_fourths = &self.modulus >> 2;

        // // Form a commitment to the element
        // let r = BigNumber::random_range(&BigNumber::zero(), q);
        // let cc_e = gg.modpow(item, p).modmul(&hh.modpow(&r, p), p);

        // Form auxiliary commitments for the element, its witness, and the randomness used
        let r_1 = BigNumber::random_range(&BigNumber::zero(), &n_fourths);
        let r_2 = BigNumber::random_range(&BigNumber::zero(), &n_fourths);
        let r_3 = BigNumber::random_range(&BigNumber::zero(), &n_fourths);

        let c_e = g
            .modpow(item, &self.modulus)
            .modmul(&h.modpow(&r_1, &self.modulus), &self.modulus);
        let CLRSABWitness::Membership { u } = witness else {
            panic!("You must provide a membership witness.")
        };
        let c_u = u.modmul(&h.modpow(&r_2, &self.modulus), &self.modulus);
        let c_r = h
            .modpow(&r_2, &self.modulus)
            .modmul(&g.modpow(&r_3, &self.modulus), &self.modulus);

        // Generate the alpha, beta, ..., eta randomness
        let range: BigNumber = BigNumber::one() << (H2P_SIZE + CHALLENGE_SIZE + NONCE_SIZE);
        let r_alpha = BigNumber::random_range(&-range.clone(), &range.clone());

        // let r_gamma = BigNumber::random_range(&BigNumber::zero(), q);
        // let r_phi = BigNumber::random_range(&BigNumber::zero(), q);
        // let r_psi = BigNumber::random_range(&BigNumber::zero(), q);

        // let r_sigma = BigNumber::random_range(&BigNumber::zero(), q);
        // let r_xi = BigNumber::random_range(&BigNumber::zero(), q);

        let range: BigNumber = &n_fourths << (CHALLENGE_SIZE + NONCE_SIZE);
        let r_epsilon = BigNumber::random_range(&-range.clone(), &range.clone());
        let r_eta = BigNumber::random_range(&-range.clone(), &range.clone());
        let r_zeta = BigNumber::random_range(&-range.clone(), &range.clone());

        // let range: BigNumber = q * (&n_fourths << (CHALLENGE_SIZE + NONCE_SIZE));
        let range: BigNumber = &n_fourths << (H2P_SIZE + CHALLENGE_SIZE + NONCE_SIZE);
        let r_beta = BigNumber::random_range(&-range.clone(), &range.clone());
        let r_delta = BigNumber::random_range(&-range.clone(), &range.clone());

        // // The values to be sent to the verifier
        // let tt_1 = gg.modpow(&r_alpha, p).modmul(&hh.modpow(&r_phi, p), p);
        // let tt_2 = cc_e
        //     .moddiv(gg, p)
        //     .modpow(&r_gamma, p)
        //     .modmul(&hh.modpow(&(-&r_psi), p), p);
        // // tt3 = (gC_e)^r_sigma * h^(-r_xi)
        // // https://doi.org/10.1007/3-540-45708-9_5
        // let tt_3 = cc_e
        //     .modmul(gg, p)
        //     .modpow(&r_sigma, p)
        //     .modmul(&hh.modpow(&(-&r_xi), p), p);
        let t_1 = h
            .modpow(&r_epsilon, &self.modulus)
            .modmul(&g.modpow(&r_zeta, &self.modulus), &self.modulus);
        let t_2 = g
            .modpow(&r_alpha, &self.modulus)
            .modmul(&h.modpow(&r_eta, &self.modulus), &self.modulus);
        let t_3 = c_u
            .modpow(&r_alpha, &self.modulus)
            .modmul(&h.modpow(&-r_beta.clone(), &self.modulus), &self.modulus);
        let t_4 = c_r
            .modpow(&r_alpha, &self.modulus)
            .modmul(&g.modpow(&-&r_delta, &self.modulus), &self.modulus)
            .modmul(&h.modpow(&-r_beta.clone(), &self.modulus), &self.modulus);

        // Randomness, obtained with Fiat-Shamir from commitments and ts to make the proof non-interactive
        let c = hash_to_k_bits(
            params,
            &[
                // &cc_e, 
                &c_e, &c_u, &c_r, 
                // &tt_1, &tt_2, &tt_3, 
                &t_1, &t_2, &t_3, &t_4,
            ],
            extra,
        );

        let s_alpha = r_alpha - c.clone() * item;
        let s_eta = r_eta - c.clone() * r_1;
        // let s_phi = (r_phi - c.clone() * r.clone()).nmod(q);
        let s_beta = r_beta - c.clone() * r_2.clone() * item;
        let s_epsilon = r_epsilon - c.clone() * r_2.clone();
        // let s_gamma = (r_gamma - c.clone() * (item - BigNumber::one()).invert(q).unwrap()).nmod(q);
        // let s_sigma = (r_sigma - c.clone() * (item + BigNumber::one()).invert(q).unwrap()).nmod(q);
        let s_zeta = r_zeta - c.clone() * r_3.clone();
        let s_delta = r_delta - c.clone() * r_3.clone() * item;
        // let s_psi =
        //     (r_psi - c.clone() * r.clone() * (item - BigNumber::one()).invert(q).unwrap()).nmod(q);
        // let s_xi =
        //     (r_xi - c.clone() * r.clone() * (item + BigNumber::one()).invert(q).unwrap()).nmod(q);

        CLRSABMemProof {
            // cc_e,
            c_u,
            c_e,
            c_r,
            // tt_1,
            // tt_2,
            // tt_3,
            t_1,
            t_2,
            t_3,
            t_4,
            s_alpha,
            s_beta,
            // s_gamma,
            s_delta,
            s_epsilon,
            s_zeta,
            // s_phi,
            // s_sigma,
            // s_psi,
            // s_xi,
            s_eta,
        }
    }

    /// Check that an element has been accumulated
    fn verify_mem_proof(
        &self,
        params: &Self::MemParams,
        proof: &Self::MemProof,
        extra: &[u8],
    ) -> bool {
        // From `Efficient Revocation of Anonymous Group Membership Certificates and Anonymous
        // Credentials` (Camenisch and Lysyanskaya, 2001), appendix A
        //
        // https://eprint.iacr.org/2001/113
        let CLRSABMemParams {
            // p,
            // q: _,
            // gg,
            // hh,
            g,
            h,
        } = params;
        let CLRSABMemProof {
            // cc_e,
            c_u,
            c_e,
            c_r,
            // tt_1,
            // tt_2,
            // tt_3,
            t_1,
            t_2,
            t_3,
            t_4,
            s_alpha,
            s_beta,
            // s_gamma,
            s_delta,
            s_epsilon,
            s_zeta,
            // s_phi,
            // s_sigma,
            // s_psi,
            // s_xi,
            s_eta,
        } = proof;
        //let kprime = 64; // TODO: choose an appropriate value

        // Recover the randomness
        let c = &hash_to_k_bits(
            params,
            &[
                // cc_e,
                c_e, c_u, c_r, 
                // tt_1, tt_2, tt_3, 
                t_1, t_2, t_3, t_4],
            extra,
        );

        let mut check = true;

        // check &= *tt_1
        //     == cc_e
        //         .modpow(c, p)
        //         .modmul(&gg.modpow(s_alpha, p), p)
        //         .modmul(&hh.modpow(s_phi, p), p);
        // check &= *tt_2
        //     == gg
        //         .modpow(c, p)
        //         .modmul(&cc_e.moddiv(gg, p).modpow(s_gamma, p), p)
        //         .modmul(&hh.modpow(&-s_psi, p), p);
        // check &= *tt_3
        //     == gg
        //         .modpow(c, p)
        //         .modmul(&cc_e.modmul(gg, p).modpow(s_sigma, p), p)
        //         .modmul(&hh.modpow(&-s_xi, p), p);

        check &= *t_1
            == c_r
                .modpow(c, &self.modulus)
                .modmul(&h.modpow(s_epsilon, &self.modulus), &self.modulus)
                .modmul(&g.modpow(s_zeta, &self.modulus), &self.modulus);
        check &= *t_2
            == c_e
                .modpow(c, &self.modulus)
                .modmul(&g.modpow(s_alpha, &self.modulus), &self.modulus)
                .modmul(&h.modpow(s_eta, &self.modulus), &self.modulus);
        check &= *t_3
            == self
                .value
                .modpow(c, &self.modulus)
                .modmul(&c_u.modpow(s_alpha, &self.modulus), &self.modulus)
                .modmul(&h.modpow(&-s_beta, &self.modulus), &self.modulus);
        check &= *t_4
            == c_r
                .modpow(s_alpha, &self.modulus)
                .modmul(&g.modpow(&-s_delta, &self.modulus), &self.modulus)
                .modmul(&h.modpow(&-s_beta, &self.modulus), &self.modulus);

        // TODO: find a better way to get the absolute value
        // An idea could be:
        // let t = s_alpha >> (H2P_SIZE + CHALLENGE_SIZE + NONCE_SIZE + 1);
        // check &= t.is_zero() | (-t).is_one() 
        let s_alpha = if s_alpha < &BigNumber::zero() {
            s_alpha.clone()
        } else {
            -s_alpha.clone()
        };
        let bound: BigNumber = &BigNumber::one() << (H2P_SIZE + CHALLENGE_SIZE + NONCE_SIZE + 1);
        check &= s_alpha < bound;

        check
    }
}
