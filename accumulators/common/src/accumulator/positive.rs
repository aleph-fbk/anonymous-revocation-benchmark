use crate::accumulator::Accumulator;

pub trait Positive: Accumulator {
    fn verify_mem(&self, item: &Self::Element, witness: Option<&Self::Witness>) -> bool;
}
