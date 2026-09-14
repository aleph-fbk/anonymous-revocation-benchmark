use crate::P_SIZE;
use unknown_order::BigNumber;

pub fn generate_rsa_primes() -> (BigNumber, BigNumber) {
    let p = BigNumber::safe_prime(P_SIZE);
    let q = BigNumber::safe_prime(P_SIZE);

    (p, q)
}

pub fn generate_quadratic_residue(modulus: &BigNumber) -> BigNumber {
    BigNumber::random(modulus).modpow(&BigNumber::from(2), modulus)
}
