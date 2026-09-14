use crate::accumulator::Accumulator;

pub trait Additive: Accumulator {
    fn insert(
        &mut self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> (Option<Self::Witness>, Option<Self::Update>);

    fn insert_batch(
        &mut self,
        items: Vec<&Self::Element>,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> Option<Self::Update> {
        for item in items {
            self.insert(item, aux, all_elements);
        }
        None
    }
}
