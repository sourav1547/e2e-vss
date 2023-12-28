use std::ops::Mul;

use aptos_crypto::{ed25519::{Ed25519PrivateKey, Ed25519Signature, Ed25519PublicKey}, test_utils::{KeyPair, TEST_SEED}, Uniform};
use blstrs::{Scalar, G1Projective};
use group::Group;
use rand::{distributions, prelude::Distribution, thread_rng, rngs::StdRng};
use rand_core::SeedableRng;
use serde::{Serialize, Deserialize};

use crate::{evaluation_domain::BatchEvaluationDomain, lagrange::all_lagrange_denominators, random_scalars, fft::{fft_assign, fft}, pvss::SharingConfiguration};

use super::keys::InputSecret;


/// Return a random scalar within a small range [0,n) 
pub fn random_scalar_range<R>(mut rng: &mut R, u: u64) -> Scalar 
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng {
    let die = distributions::Uniform::from(0..u);
    let val = die.sample(&mut rng);
    Scalar::from(val)
}

pub fn random_scalars_range<R>(mut rng: &mut R, u: u64, n: usize) -> Vec<Scalar> 
    where R: rand_core::RngCore + rand::Rng + rand_core::CryptoRng + rand::CryptoRng {
    
    let mut v = Vec::with_capacity(n);

    for _ in 0..n {
        v.push(random_scalar_range(&mut rng, u));
    }
    v
}


#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct Share {
    pub(crate) share: [Scalar; 2],
}

impl Share {
    pub fn get(&self) -> &[Scalar] {
        self.share.as_slice()
    }

    pub fn identity() -> Share {
        let share = [Scalar::from(1), Scalar::from(1)];
        Share { share }
    }
}

/// Checks that the committed degred is low
pub fn low_deg_test(coms: &Vec<G1Projective>, sc: &SharingConfiguration) -> bool {
    // If the degree is n-1, then the check is trivially true
    if sc.t == sc.n {
        return true; 
    }

    let mut rng = thread_rng();
    let batch_dom = BatchEvaluationDomain::new(sc.n);   
    let vf = get_dual_code_word(sc.t - 1, &batch_dom, sc.n, &mut rng);   
    let ip = G1Projective::multi_exp(&coms, vf.as_ref());
    
    ip.eq(&G1Projective::identity())
}

#[allow(unused)]
pub fn get_dual_code_word<R: rand_core::RngCore + rand_core::CryptoRng>(
    deg: usize,
    batch_dom: &BatchEvaluationDomain,
    n: usize,
    mut rng: &mut R,
) -> Vec<Scalar> {
    // The degree-(t-1) polynomial p(X) that shares our secret
    // So, deg = t-1 => t = deg + 1
    // The "dual" polynomial f(X) of degree n - t - 1 = n - (deg + 1) - 1 = n - deg - 2
    let mut f = random_scalars(n - deg - 2, &mut rng);

    // Compute f(\omega^i) for all i's
    let dom = batch_dom.get_subdomain(n);
    fft_assign(&mut f, &dom);
    f.truncate(n);

    // Compute v_i = 1 / \prod_{j \ne i, j \in [0, n-1]} (\omega^i - \omega^j), for all i's
    let v = all_lagrange_denominators(&batch_dom, n);

    // Compute v_i * f(\omega^i), for all i's
    let vf = f
        .iter()
        .zip(v.iter())
        .map(|(v, f)| v.mul(f))
        .collect::<Vec<Scalar>>();

    vf
}

pub fn gen_coms_shares(sc: &SharingConfiguration, s: &InputSecret, bases: &[G1Projective; 2]) -> (Vec<G1Projective>, Vec<Share>) {
    let f = s.get_secret_f();
    let r = s.get_secret_r();

    let mut f_evals = fft(f, sc.get_evaluation_domain());
    f_evals.truncate(sc.n);

    let mut r_evals = fft(r, sc.get_evaluation_domain());
    r_evals.truncate(sc.n);

    let mut shares: Vec<Share> = Vec::with_capacity(sc.n);
    for i in 0..sc.n {
        shares.push(Share{share: [f_evals[i], r_evals[i]]});
    }

    let mut coms:Vec<G1Projective> = Vec::with_capacity(sc.n);
    for i in 0..sc.n {
        let scalars = [f_evals[i], r_evals[i]];
        coms.push(G1Projective::multi_exp(bases, scalars.as_slice())); 
    }
    (coms , shares)
}

pub fn sign_verified_deal(sig_key: Ed25519PrivateKey, msg: Vec<u8>) -> Option<Ed25519Signature> {
    return Some(sig_key.sign_arbitrary_message(msg.as_slice()));
}

pub fn share_verify(idx: usize, coms: &Vec<G1Projective>, share: &Share, bases: &[G1Projective; 2], sc: &SharingConfiguration) -> bool {
    let com: G1Projective = coms[idx];
    let e_com = G1Projective::multi_exp(bases, &share.share);
    com.eq(&e_com)  && low_deg_test(coms, sc)
}

pub fn generate_ed_sig_keys(n: usize) -> Vec<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>> {
    let mut rng = StdRng::from_seed(TEST_SEED);
    (0..n)
        .map(|_| KeyPair::<Ed25519PrivateKey, Ed25519PublicKey>::generate(&mut rng))
        .collect()
}

use aptos_crypto::bls12381::{PrivateKey, PublicKey};
// Helper function to generate N bls12381 private keys.
pub fn generate_bls_sig_keys(n: usize) -> Vec<KeyPair<PrivateKey, PublicKey>> {
    let mut rng = StdRng::from_seed(TEST_SEED);
    (0..n)
        .map(|_| KeyPair::<PrivateKey, PublicKey>::generate(&mut rng))
        .collect()
}