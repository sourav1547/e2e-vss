use std::ops::Mul;
use blstrs::{Scalar, G1Projective};
use ff::Field;

// I borrowed these 

/// Return `cnt` consecutive powers of `x`
pub fn get_xpowers(x: &Scalar, cnt: usize) -> Vec<Scalar> {
    let mut r = Vec::with_capacity(cnt);

    let mut xpow = Scalar::one();
    for _ in 0..cnt {
        xpow *= x;
        r.push(xpow.clone());
    }

    r
}

/// Return `cnt` consecutive powers of `x`
pub fn get_xpowers_at_0(x: &Scalar, cnt: usize) -> Vec<Scalar> {
    let mut r = Vec::with_capacity(cnt);

    let mut xpow = Scalar::one();
    for _ in 0..cnt {
        r.push(xpow.clone());
        xpow *= x;
    }

    r
}


pub fn batch_mul(g: &G1Projective, exps: &Vec<Scalar>) -> Vec<G1Projective> {
    exps.iter().map(|x| g.mul(x)).collect::<Vec<_>>()
}


pub fn scalar_mult_exp(lhs: &[Scalar], rhs: &[Scalar]) -> Scalar {
    let terms = std::cmp::min(lhs.len(), rhs.len());
    let mut accum = Scalar::zero();
    for i in 0..terms {
        accum += &lhs[i] * &rhs[i];
    }
    accum
}

pub fn scalar_usize_mult_exp(lhs: &[Scalar], rhs: &[usize]) -> Scalar {
    let terms = std::cmp::min(lhs.len(), rhs.len());
    let mut accum: Scalar = Scalar::zero();
    for i in 0..terms {
        accum += &lhs[i] * Scalar::from(rhs[i] as u64);
    }
    accum
}

/// Return a hash value of this element suitable for linear search
///
/// # Warning
///
/// This function is a perfect hash function (ie, has no collisions) for the
/// set of elements gt*{0..2**16-1}, which is what is used to represent
/// ciphertext elements in the NIDKG. It is not useful in other contexts.
///
/// This function is not stable over time; it may change in the future.
/// Do not serialize this value, or use it as an index in storage.
pub fn short_hash_for_linear_search(g: &G1Projective) -> u32 {
    fn extract4(tag: &[u8], idx: usize) -> u32 {
        let mut fbytes = [0u8; 4];
        fbytes.copy_from_slice(&tag[idx..idx + 4]);
        u32::from_le_bytes(fbytes)
    }

    let tag = g.to_compressed();
    extract4(&tag, 0) ^ extract4(&tag, 32)
}