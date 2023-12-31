use std::ops::Mul;

use acss::{random_scalars,  pvss::SharingConfiguration};
use acss::vss::common::{generate_ed_sig_keys, generate_bls_sig_keys};
use aptos_crypto::bls12381::{PublicKey, PrivateKey};
use aptos_crypto::ed25519::{Ed25519PublicKey, Ed25519PrivateKey};
use aptos_crypto::multi_ed25519::MultiEd25519PublicKey;
use aptos_crypto::test_utils::TEST_SEED;
use blstrs::{G1Projective, Scalar};
use rand::rngs::StdRng;
use rand::thread_rng;
use rand_core::SeedableRng;

pub fn yurek_params(n: usize, bases: [G1Projective; 2]) -> Vec<G1Projective> {
    let dkeys = {
        let mut rng = thread_rng();
        random_scalars(n, &mut rng)
    };

    dkeys.iter().map(|x| bases[0].mul(x)).collect::<Vec<G1Projective>>()
}

pub fn low_ed_params(sc: &SharingConfiguration, idx: usize) -> (Ed25519PrivateKey, Vec<Ed25519PublicKey>) {
    let n = sc.get_total_num_players();

    let keys = generate_ed_sig_keys(n);
    let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<Ed25519PublicKey>>();

    (keys[idx].private_key.clone(), vkeys)
}

pub fn low_bls_params(sc: &SharingConfiguration, idx: usize) -> (PrivateKey, Vec<PublicKey>) {
    let n = sc.get_total_num_players();
    let keys = generate_bls_sig_keys(n);
    let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<PublicKey>>();

    (keys[idx].private_key.clone(), vkeys)
}

pub fn mixed_ed_params(sc: &SharingConfiguration, bases: &[G1Projective], idx:usize) -> (
    Ed25519PrivateKey, 
    Vec<Ed25519PublicKey>,
    Vec<G1Projective>,
) {
    let n = sc.get_total_num_players();
    let deg = sc.get_threshold()-1;

    let keys = generate_ed_sig_keys(n);
    let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<Ed25519PublicKey>>();

    let dkeys = {
        let mut rng = StdRng::from_seed(TEST_SEED);
        random_scalars(n, &mut rng)
    };
    let ekeys = dkeys.iter().map(|x| bases[0].mul(x)).collect::<Vec<_>>();

    (keys[idx].private_key.clone(), vkeys, ekeys)
}

pub fn mixed_bls_params(sc: &SharingConfiguration, bases: &[G1Projective], idx: usize) -> (
    PrivateKey, 
    Vec<PublicKey>,
    Vec<G1Projective>,
) {
    let n = sc.get_total_num_players();
    let keys = generate_bls_sig_keys(n);
    let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<PublicKey>>();

    let dec_keys = {
        let mut rng = StdRng::from_seed(TEST_SEED);
        random_scalars(n, &mut rng)
    };
    let enc_keys = dec_keys.iter().map(|x| bases[0].mul(x)).collect::<Vec<_>>();

    (keys[idx].private_key.clone(), vkeys, enc_keys)
}


pub fn groth_params(sc: &SharingConfiguration, bases: &[G1Projective], idx: usize) -> (
    Scalar, 
    Vec<G1Projective>,
) {
    let n = sc.get_total_num_players();
    let dkeys = {
        let mut rng = StdRng::from_seed(TEST_SEED);
        random_scalars(n, &mut rng)
    };
    let ekeys = dkeys.iter().map(|x| bases[0].mul(x)).collect::<Vec<_>>();

    (dkeys[idx], ekeys)
}