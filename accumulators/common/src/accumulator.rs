pub mod additive;
pub mod negative;
pub mod positive;
pub mod subtractive;
pub mod zk_positive;

pub use crate::accumulator::additive::Additive;
pub use crate::accumulator::negative::Negative;
pub use crate::accumulator::positive::Positive;
pub use crate::accumulator::subtractive::Subtractive;
pub use crate::accumulator::zk_positive::ZKPositive;

pub trait Accumulator: Sized {
    type Element;
    type Trapdoor;
    type Witness;
    type Update;

    fn new() -> (Self, Option<Self::Trapdoor>) {
        Self::new_with_elements(&[])
    }

    fn new_with_elements(items: &[Self::Element]) -> (Self, Option<Self::Trapdoor>);

    fn update(
        &self,
        witness: &Self::Witness,
        item: Option<&Self::Element>,
        update: &Self::Update,
    ) -> Self::Witness;

    fn witness_mem(
        &self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &[Self::Element],
    ) -> Self::Witness;

    fn witness_nonmem(
        &self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &[Self::Element],
    ) -> Self::Witness;
}
