use crate::{
    helpers::{generate_quadratic_residue, generate_rsa_primes},
    update::CLRSABUpdate,
    witness::CLRSABWitness,
};
use common::accumulator::Accumulator;
use unknown_order::{BigNumber, GcdResult};

/// An RSA based cryptographic accumulator
///
/// Defined in [[BCD+17]], modifies the RSA [`rsa`] accumulator to support static updates. With this
/// modification, the membership witnesses of accumulated elements don't have to be updated when
/// new elements are inserted. They have to be updated only when elements are removed.
///
/// Elements are represented by arrays of bytes and hashed into a prime when they are inserted.
///
/// [BCD+17]: https://doi.org/10.1109/EuroSP.2017.13
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CLRSABAccumulator {
    pub(super) modulus: BigNumber,
    pub(super) value: BigNumber,
}

impl Accumulator for CLRSABAccumulator {
    type Element = BigNumber;
    type Trapdoor = BigNumber;
    type Witness = CLRSABWitness;
    type Update = CLRSABUpdate;

    fn new_with_elements(_items: &[Self::Element]) -> (Self, Option<Self::Trapdoor>) {
        // RSA modulus
        let (p, q) = generate_rsa_primes();
        let modulus = p.clone() * q.clone();
        let phi = (p.clone() - 1) * (q.clone() - 1);

        // Initial value of the accumulator (quadratic residue)
        let value = generate_quadratic_residue(&modulus);

        (Self { modulus, value }, Some(phi))
    }

    fn update(
        &self,
        witness: &Self::Witness,
        item: Option<&Self::Element>,
        update: &Self::Update,
    ) -> Self::Witness {
        match witness {
            // Variable names use the notation of `Dynamic Accumulators and Application to
            // Efficient Revocation of Anonymous Credentials` (Camenisch and Lysyanskaya, 2002),
            // sec. 3.2
            //
            // https://doi.org/10.1007/3-540-45708-9_5
            CLRSABWitness::Membership { u } => match update {
                CLRSABUpdate::Insertion => CLRSABWitness::Membership { u: u.clone() },

                CLRSABUpdate::Removal { x: xtilde } => {
                    let x = item.expect(
                        "This update requires the value of the item this witness refers to",
                    );
                    let GcdResult { gcd, x: a, y: b } = BigNumber::extended_gcd(x, xtilde);
                    debug_assert!(gcd.is_one()); // `x` and `xtilde` should be coprime

                    CLRSABWitness::Membership {
                        u: u.clone()
                            .modpow(&b, &self.modulus)
                            .modmul(&self.value.modpow(&a, &self.modulus), &self.modulus),
                    }
                }
            },
        }
    }

    fn witness_mem(
        &self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &[Self::Element],
    ) -> Self::Witness {
        debug_assert!(all_elements.contains(item));

        // From `Universal Accumulators with Efficient Nonmembership Proofs (Li et al., 2007)`, sec. 3.2
        // https://doi.org/10.1007/978-3-540-72738-5_17
        if let Some(phi) = aux {
            // Paragraph `How to compute witness with the auxiliary information`, pp. 258-259
            let a = item.invert(phi).unwrap();

            CLRSABWitness::Membership {
                u: self.value.modpow(&a, &self.modulus),
            }
        } else {
            unimplemented!(
                "The CL-RSA-B can't generate witnesses without the auxiliary information."
            );
        }
    }

    fn witness_nonmem(
        &self,
        _item: &Self::Element,
        _aux: Option<&Self::Trapdoor>,
        _all_elements: &[Self::Element],
    ) -> Self::Witness {
        unimplemented!("The CL-RSA-B does not support non-membership witnesses");
    }
}
