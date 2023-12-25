use std::ops::Mul;
use aptos_crypto::CryptoMaterialError;
use blstrs::{G1Projective, G2Projective, Gt, Scalar};
use ff::Field;
use group::Group;
use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use num_integer::Integer;
use once_cell::sync::Lazy;
use sha3::Digest;

pub mod fft;
pub mod vss;
pub mod lagrange;
pub mod polynomials;
pub mod evaluation_domain;
pub mod tests;
pub mod pvss;
pub mod util;
pub mod rbc;

/// TODO(rand_core_hell): Domain-separator for our `rand_core_hell` randomness generation.
const DST_RAND_CORE_HELL : &[u8; 21] = b"AptosRandCoreHellHack";

/// Random seed for picking group elements in our PVSS public parameters by hashing to the curve.
pub const SEED_PVSS_PUBLIC_PARAMS_GENERATION: &[u8; 33] = b"APTOS_DISTRIBUTED_RANDOMNESS_SEED";

/// Domain-separator for picking group elements in our PVSS public parameters by hashing to the curve.
pub const DST_PVSS_PUBLIC_PARAMS_GENERATION : &[u8; 35] = b"AptosPvssPublicParametersGeneration";

/// The size in bytes of a compressed G1 point (efficiently deserializable into projective coordinates)
pub const G1_PROJ_NUM_BYTES : usize = 48;

/// The size in bytes of a compressed G2 point (efficiently deserializable into projective coordinates)
pub const G2_PROJ_NUM_BYTES : usize = 96;

/// The size in bytes of a scalar.
pub const SCALAR_NUM_BYTES : usize = 32;

// TODO(rand_core_hell): Remove this once rand_core_hell is fixed.
pub(crate) const SCALAR_FIELD_ORDER : Lazy<BigUint> = Lazy::new(get_scalar_field_order_as_biguint);

#[inline]
pub fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1) == 0)
}

/// Helper method to *securely* parse a sequence of bytes into a `G1Projective` point.
/// NOTE: This function will check for prime-order subgroup membership in $\mathbb{G}_1$.
pub fn g1_proj_from_bytes(bytes: &[u8]) -> Result<G1Projective, CryptoMaterialError> {
    let slice = match <&[u8; G1_PROJ_NUM_BYTES]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => return Err(CryptoMaterialError::WrongLengthError),
    };

    let a = G1Projective::from_compressed(slice);

    if a.is_some().unwrap_u8() == 1u8 {
        Ok(a.unwrap())
    } else {
        Err(CryptoMaterialError::DeserializationError)
    }
}

// TODO(rand_core_hell): Remove this once rand_core_hell is fixed.
/// Returns the order of the scalar field in our implementation's choice of an elliptic curve group.
pub(crate) fn get_scalar_field_order_as_biguint() -> BigUint {
    let r = BigUint::from_bytes_be(hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001").unwrap().as_slice());

    // Here, we paranoically assert that r is correct, by checking 0 - 1 mod r (computed via Scalar) equals r-1 (computed from the constant above)
    let minus_one = Scalar::zero() - Scalar::one();
    let max = &r - 1u8;
    assert_eq!(minus_one.to_bytes_le().as_slice(), max.to_bytes_le().as_slice());

    r
}

/// Returns a random `blstrs::Scalar` given an older RNG as input.
/// Hacks around the incompatibility of `blstrs`'s `rand_core` dependency (newer) and `aptos_crypto`'s `rand_core` dependency (older).
///
/// Works pretty fast: 1 microsecond / call.
///
/// TODO(Security): The following code pertains to the `rand_core_hell` hack and should be audited.
pub fn random_scalar<R>(rng: &mut R) -> Scalar
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng
{
    let mut bytes = [0u8; 2 * SCALAR_NUM_BYTES];
    rng.fill(&mut bytes);

    let bignum = BigUint::from_bytes_le(&bytes);
    let remainder = bignum.mod_floor(&SCALAR_FIELD_ORDER);

    biguint_to_scalar(&remainder)
}

/// Like `random_scalar`. Thought it was slower due to the rejection sampling, but it's not.
pub fn random_scalar_alternative<R>(rng: &mut R) -> Scalar
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng
{
    //
    // TODO(Security): The following code pertains to the `rand_core_hell` hack and should be audited.
    //
    // Ideally, we would write the following sane code. But we can't due to
    // `aptos-crypto`'s dependency on an older version of rand and rand-core than blstrs's version.
    //
    // ```
    // let mut dk = Scalar::random(rng);
    // while dk.is_zero() {
    //     dk = Scalar::random(rng);
    // }
    // ```
    //
    let mut big_uint;

    // The decryption key cannot be zero since it needs to have an inverse in the scalar field.
    loop {
        // TODO(Security): Make sure this correctly uses the RNG to pick the number uniformly in [0, SCALAR_FIELD_ORDER)
        // NOTE(Alin): This uses rejection-sampling, which should be correct (e.g., https://cs.stackexchange.com/a/2578/54866)
        big_uint = rng.gen_biguint_below(&SCALAR_FIELD_ORDER);
        if !big_uint.is_zero() {
            break
        }
    }

    biguint_to_scalar(&big_uint)
}

fn biguint_to_scalar(big_uint: &BigUint) -> Scalar {
    // `blstrs`'s `Scalar::from_bytes_le` needs `SCALAR_NUM_BYTES` bytes. The current
    // implementation of `BigUint::to_bytes_le()` does not always return `SCALAR_NUM_BYTES` bytes
    // when the integer is smaller than 32 bytes. So we have to pad it.
    let mut bytes = big_uint.to_bytes_le();

    while bytes.len() < SCALAR_NUM_BYTES {
        bytes.push(0u8);
    }

    debug_assert_eq!(BigUint::from_bytes_le(&bytes.as_slice()), *big_uint);

    let slice = match <&[u8; SCALAR_NUM_BYTES]>::try_from(bytes.as_slice()) {
        Ok(slice) => slice,
        Err(_) => {
            panic!("WARNING: Got {} bytes instead of {SCALAR_NUM_BYTES} (i.e., got {})", bytes.as_slice().len(), big_uint.to_string());
        }
    };

    let opt = Scalar::from_bytes_le(slice);

    if opt.is_some().unwrap_u8() == 1u8 {
        opt.unwrap()
    } else {
        panic!("Deserialization of randomly-generated num_bigint::BigUint failed.");
    }
}

/// Hashes the specified `msg` and domain separation tag `dst` into a `Scalar` by computing a 512-bit
/// number as SHA3-512(SHA3-512(dst) || msg) and reducing it modulo the order of the field.
/// (Same design as in `curve25519-dalek` explained here https://crypto.stackexchange.com/questions/88002/how-to-map-output-of-hash-algorithm-to-a-finite-field)
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    // TODO(Security): Should probably rely on our own domain separation from Rust here.
    // TODO(Security): This SHA3-512 call will not be domain separated from other SHA3-512 calls in our system.
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst);
    let binding = hasher.finalize();
    let dst_hash = binding.as_slice();

    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst_hash);
    hasher.update(msg);
    let binding = hasher.finalize();
    let bytes = binding.as_slice();

    assert_eq!(bytes.len(), 64);

    let bignum = BigUint::from_bytes_le(&bytes);
    let remainder = bignum.mod_floor(&SCALAR_FIELD_ORDER);

    biguint_to_scalar(&remainder)
}

/// Returns a random `blstrs::G1Projective` given an older RNG as input.
/// Hacks around the incompatibility of `blstrs`'s `rand_core` dependency (newer) and `aptos_crypto`'s `rand_core` dependency (older).
///
/// Takes 50 microseconds.
pub fn random_g1_point<R>(rng: &mut R) -> G1Projective
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng
{
    // TODO(Security): The following code pertains to the `rand_core_hell` hack and should be audited.
    let mut rand_seed = [0u8; G1_PROJ_NUM_BYTES];

    rng.fill(rand_seed.as_mut_slice());

    G1Projective::hash_to_curve(rand_seed.as_slice(), DST_RAND_CORE_HELL, b"G1")
}

/// Returns a random `blstrs::G2Projective` given an older RNG as input.
/// Hacks around the incompatibility of `blstrs`'s `rand_core` dependency (newer) and `aptos_crypto`'s `rand_core` dependency (older).
///
/// Takes 150 microseconds.
pub fn random_g2_point<R>(rng: &mut R) -> G2Projective
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng
{
    // TODO(Security): The following code pertains to the `rand_core_hell` hack and should be audited.
    let mut rand_seed = [0u8; G2_PROJ_NUM_BYTES];

    rng.fill(rand_seed.as_mut_slice());

    G2Projective::hash_to_curve(rand_seed.as_slice(), DST_RAND_CORE_HELL, b"G2")
}

/// Returns a random `blstrs::GTProjective` given an older RNG as input.
/// Hacks around the incompatibility of `blstrs`'s `rand_core` dependency (newer) and `aptos_crypto`'s `rand_core` dependency (older).
///
/// Takes 507 microseconds.
pub fn random_gt_point<R>(rng: &mut R) -> Gt
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng
{
    let s = random_scalar(rng);

    // TODO(TestPerformance): Cannot sample more efficiently than this because `fp12::Fp12` is not exposed.
    Gt::generator().mul(s)
}


/// Returns a vector of random `blstrs::Scalar`'s, given an RNG as input.
pub fn random_scalars<R>(n: usize, rng: &mut R) -> Vec<Scalar>
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng {
    let mut v = Vec::with_capacity(n);

    for _ in 0..n {
        v.push(random_scalar(rng));
    }

    debug_assert_eq!(v.len(), n);

    v
}

/// Returns a vector of random `blstrs::G1Projective`'s, given an RNG as input.
pub fn random_g1_points<R>(n: usize, rng: &mut R) -> Vec<G1Projective>
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng {
    let mut v = Vec::with_capacity(n);

    for _ in 0..n {
        v.push(random_g1_point(rng));
    }

    debug_assert_eq!(v.len(), n);

    v
}

/// Returns a vector of random `blstrs::G2Projective`'s, given an RNG as input.
pub fn random_g2_points<R>(n: usize, rng: &mut R) -> Vec<G2Projective>
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng {
    let mut v = Vec::with_capacity(n);

    for _ in 0..n {
        v.push(random_g2_point(rng));
    }

    debug_assert_eq!(v.len(), n);

    v
}

/// Returns a vector of random `blstrs::GTT`'s, given an RNG as input.
pub fn random_gt_points<R>(n: usize, rng: &mut R) -> Vec<Gt>
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng
{
    let mut v = Vec::with_capacity(n);

    for _ in 0..n {
        v.push(random_gt_point(rng));
    }

    debug_assert_eq!(v.len(), n);

    v
}