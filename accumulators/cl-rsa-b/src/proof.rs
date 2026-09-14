use unknown_order::BigNumber;

/// The zero knowledge membership proof of a CL-RSA-B accumulator
#[derive(Debug)]
pub struct CLRSABMemProof {
    // Main commitment
    // pub cc_e: BigNumber,

    // Auxiliary commitments
    pub c_u: BigNumber,
    pub c_e: BigNumber,
    pub c_r: BigNumber,

    // t
    // pub tt_1: BigNumber,
    // pub tt_2: BigNumber,
    // pub tt_3: BigNumber,
    pub t_1: BigNumber,
    pub t_2: BigNumber,
    pub t_3: BigNumber,
    pub t_4: BigNumber,

    // s
    pub s_alpha: BigNumber,
    pub s_beta: BigNumber,
    // pub s_gamma: BigNumber,
    pub s_delta: BigNumber,
    pub s_epsilon: BigNumber,
    pub s_zeta: BigNumber,
    // pub s_phi: BigNumber,
    // pub s_sigma: BigNumber,
    // pub s_psi: BigNumber,
    // pub s_xi: BigNumber,
    pub s_eta: BigNumber,
}

/// The public parameters used in the proof
#[derive(Hash)]
pub struct CLRSABMemParams {
    // // Order of the group where G_q lives
    // pub p: BigNumber,

    // // Order of the subgroup G_q we use
    // pub q: BigNumber,

    // // Generators of G_q
    // pub gg: BigNumber,
    // pub hh: BigNumber,

    // Two elements of QR_n
    pub g: BigNumber,
    pub h: BigNumber,
}