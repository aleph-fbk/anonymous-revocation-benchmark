use unknown_order::BigNumber;

/// The witness of a CL-RSA-B accumulator
#[derive(Debug)]
pub enum CLRSABWitness {
    /// The witness for an element that has been accumulated
    Membership { u: BigNumber },
}
