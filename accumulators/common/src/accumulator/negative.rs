use crate::accumulator::Accumulator;

pub trait Negative: Accumulator {
    fn verify_nonmem(&self, item: &Self::Element, witness: Option<&Self::Witness>) -> bool;
}
