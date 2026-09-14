use crate::{accumulator::CLRSABAccumulator, update::CLRSABUpdate};
use common::accumulator::Subtractive;

use unknown_order::BigNumber;

impl Subtractive for CLRSABAccumulator {
    fn remove(
        &mut self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> (Option<Self::Witness>, Option<Self::Update>) {
        // This elements has been accumulated
        debug_assert!(all_elements.contains(item));

        let phi =
            aux.expect("The RSA accumulator needs auxiliary information for element removal.");
        let item_inv = item.invert(phi).unwrap();

        self.value = self.value.modpow(&item_inv, &self.modulus);
        all_elements.retain(|x| x != item);

        (None, Some(CLRSABUpdate::Removal { x: item.clone() }))
    }

    fn update_after_remove(
        &mut self,
        item: &Self::Element,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> Option<Self::Update> {
        // This elements has been accumulated
        debug_assert!(all_elements.contains(item));

        let phi =
            aux.expect("The RSA accumulator needs auxiliary information for element removal.");
        let item_inv = item.invert(phi).unwrap();

        self.value = self.value.modpow(&item_inv, &self.modulus);
        all_elements.retain(|x| x != item);

        Some(CLRSABUpdate::Removal { x: item.clone() })
        
    }

    fn remove_batch(
        &mut self,
        items: Vec<&Self::Element>,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> Option<Self::Update> {
        // Raw product — do NOT reduce mod phi here.
        // Reducing mod phi would publish a value that reveals phi to anyone who
        // knows the elements: M = P_D - (P_D mod phi) ≡ 0 (mod phi).
        // Two such multiples suffice for gcd recovery.
        // update_after_remove inverts mod phi internally (trapdoor stays private).
        let batch = items.iter().fold(BigNumber::one(), |acc, i| acc * *i);
        let mut elems = all_elements.clone();
        elems.push(batch.clone());
        all_elements.retain(|x| !items.contains(&x));

        self.remove(&batch, aux, &mut elems).1
    }

    fn update_after_remove_batch(
        &mut self,
        items: Vec<&Self::Element>,
        aux: Option<&Self::Trapdoor>,
        all_elements: &mut Vec<Self::Element>,
    ) -> Option<Self::Update> {
        // Same reasoning: publish raw product, not product mod phi.
        let batch = items.iter().fold(BigNumber::one(), |acc, i| acc * *i);
        let mut elems = all_elements.clone();
        elems.push(batch.clone());
        all_elements.retain(|x| !items.contains(&x));

        self.update_after_remove(&batch, aux, &mut elems)
    }
}
