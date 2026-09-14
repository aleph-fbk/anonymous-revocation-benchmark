use crate::{accumulator::CLRSABAccumulator, update::CLRSABUpdate};
use common::accumulator::{Accumulator, Additive};

use unknown_order::BigNumber;

impl Additive for CLRSABAccumulator {
    fn insert(
        &mut self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> (Option<Self::Witness>, Option<Self::Update>) {
        // This elements has not been accumulated yet
        debug_assert!(!all_elements.contains(item));

        all_elements.push(item.clone());
        let witness = self.witness_mem(item, aux, all_elements);

        (Some(witness), Some(CLRSABUpdate::Insertion))
    }

    fn insert_batch(
        &mut self,
        items: Vec<&Self::Element>,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> Option<Self::Update> {
        let phi = aux.unwrap();

        let batch = items.iter().fold(BigNumber::one(), |a, i| a.modmul(i, phi));
        let mut elems = all_elements.clone();
        all_elements.extend(items.iter().map(|&x| x.clone()));

        self.insert(&batch, aux, &mut elems).1
    }
}
