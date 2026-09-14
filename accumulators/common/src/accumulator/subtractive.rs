use crate::accumulator::Accumulator;

pub trait Subtractive: Accumulator {
    fn remove(
        &mut self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> (Option<Self::Witness>, Option<Self::Update>);

    fn update_after_remove(
        &mut self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> Option<Self::Update>;

    fn remove_batch(
        &mut self,
        items: Vec<&Self::Element>,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> Option<Self::Update> {
        for item in items {
            self.remove(item, aux, all_elements);
        }
        None
    }

    fn update_after_remove_batch(
        &mut self,
        items: Vec<&Self::Element>,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> Option<Self::Update> {
        for item in items {
            self.update_after_remove(item, aux, all_elements);
        }
        None
    }
}
