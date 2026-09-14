use blake3::hash;
use unknown_order::BigNumber;

pub fn hash_to_prime<B: AsRef<[u8]>>(input: B) -> BigNumber {
    let mut input = input.as_ref().to_vec();
    let mut counter = 1usize;
    input.extend_from_slice(&counter.to_be_bytes()[..]);

    let mut prime;
    loop {
        let mut hash: [u8; 32] = hash(input.as_slice()).into();
        hash[31] |= 1; // odd
        hash[7] |= 1; // > 2^192
        prime = BigNumber::from_slice(hash);
        if prime.is_prime() {
            return prime;
        }
        counter += 1;
        input = [&hash, &counter.to_be_bytes()[..]].concat();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hash() {
        assert!(hash_to_prime(b"test").is_prime());
    }
}
