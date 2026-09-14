use crate::accumulator::Positive;

pub trait ZKPositive: Positive {
    type MemProof;
    type MemParams;

    fn gen_param(&self) -> Self::MemParams;

    fn prove_mem(
        &self,
        params: &Self::MemParams,
        item: &Self::Element,
        witness: &Self::Witness,
        extra: &[u8],
    ) -> Self::MemProof;

    fn verify_mem_proof(
        &self,
        params: &Self::MemParams,
        proof: &Self::MemProof,
        extra: &[u8],
    ) -> bool;
}
