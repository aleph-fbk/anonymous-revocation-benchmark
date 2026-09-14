use crate::{accumulator::CLRSABAccumulator, witness::CLRSABWitness};
use common::accumulator::Positive;

impl Positive for CLRSABAccumulator {
    fn verify_mem(&self, item: &Self::Element, witness: Option<&Self::Witness>) -> bool {
        let CLRSABWitness::Membership { u } = witness.unwrap();
        u.modpow(item, &self.modulus) == self.value
    }
}
