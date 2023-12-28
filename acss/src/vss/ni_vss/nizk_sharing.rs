//! Proofs of correct sharing
#![allow(clippy::needless_range_loop)]

use crate::{util, hash_to_scalar, random_scalar};
use group::Group;
use rand::thread_rng;
use serde::{Serialize, Deserialize};
use std::{vec::Vec, ops::{Mul, Add}};
use blstrs::{G1Projective, Scalar};
use crate::vss::ni_vss::chunking::NUM_CHUNKS;
use super::{encryption::CiphertextChunks, utils::{get_xpowers_at_0, get_xpowers, scalar_mult_exp}, chunking:: CHUNK_SIZE, fiat_shamir::NIVSS_DOM_SEP};

// pub fn check_instance(&self) -> Result<(), ZkProofSharingError> {
//     if self.randomizers.is_empty() || self.public_evals.is_empty() {
//         return Err(ZkProofSharingError::InvalidInstance);
//     };

//     if self.randomizers.len() != NUM_CHUNKS {
//         return Err(ZkProofSharingError::InvalidInstance);
//     };
//     if self.ciphertext_chunks.len() != self.public_evals.len() {
//         return Err(ZkProofSharingError::InvalidInstance);
//     };
//     Ok(())
// }


#[derive(Clone, Debug)]
pub struct SharingWitness {
    enc_s: Scalar,
    enc_r: Scalar,
    shares: Vec<Scalar>, 
    randomness: Vec<Scalar>,
}


impl SharingWitness {
    pub fn new(enc_s: Scalar, enc_r: Scalar, shares: Vec<Scalar>, randomness: Vec<Scalar>) -> Self {
        Self {
            enc_s, 
            enc_r, 
            shares, 
            randomness,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProofSharing {
    ff: G1Projective,
    aa: G1Projective,
    yy: G1Projective,
    z_s: Scalar,
    z_r: Scalar,
    z_ab: Scalar,
}

impl ProofSharing {
    pub fn new(ff: G1Projective, aa: G1Projective, yy: G1Projective, z_s: Scalar, z_r: Scalar, z_ab: Scalar) -> Self {
        Self {
            ff,
            aa,
            yy,
            z_s,
            z_r,
            z_ab,
        }
    }
}

pub fn prove_sharing(
    h: &G1Projective,
    commits: &[G1Projective],
    public_keys: &[G1Projective],
    r_aa: &G1Projective, 
    enc_ss: &[G1Projective],
    r_bb: &G1Projective,
    enc_rr: &[G1Projective], 
    witness: &SharingWitness,
) -> ProofSharing {
    //   instance = ([y_1..y_n], [V_1..V_n], A, [C_1..C_n], B, [R_1..R_n])
    //   witness = (enc_s, [s_1..s_n], enc_r, [r_1..r_n])
    
    let n = public_keys.len();

    let x = ShareOracle::new(commits, public_keys, r_aa, enc_ss, r_bb, enc_rr).get_chal();
    let xpowers = get_xpowers(&x, n);

    let s = scalar_mult_exp(&witness.shares, &xpowers);
    let r = scalar_mult_exp(&witness.randomness, &xpowers);

    let pk_mul_xi = G1Projective::multi_exp(public_keys, &xpowers);
    let g1 = G1Projective::generator(); 

    // Now the tuple is (g, h, aa_bb, com_mul_xi, pk_mul_xi, c_aa_bb)
    let mut rng = thread_rng();

    // First move (prover)
    // alpha, beta, rho <- random Z_p
    let alpha = random_scalar(&mut rng);
    let beta = random_scalar(&mut rng);
    let rho = random_scalar(&mut rng);
    
    // F = g_1^rho
    // A = g_2^alpha
    // Y = product [y_i^x^i | i <- [1..n]]^rho * g_1^alpha
    let ff = g1.mul(&rho);
    let aa = G1Projective::multi_exp([g1, *h].as_slice(), [alpha, beta].as_slice()) ;
    let pk_rho = pk_mul_xi.mul(&rho);
    let yy = pk_rho.add(&aa); 

    // Second move (verifier's challenge)
    // x' = oracle(x, F, A, Y)
    let x_chal = first_challenge(&x, &ff, &aa,  &yy);

    // Third move (prover)
    let z_s = s * x_chal + alpha;
    let z_r = r * x_chal + beta;
    let z_ab = (witness.enc_s + witness.enc_r)* x_chal + rho;

    ProofSharing {
        ff,
        aa,
        yy,
        z_s,
        z_r,
        z_ab,
    }
}

pub fn first_challenge(x: &Scalar, ff:&G1Projective, aa: &G1Projective, yy: &G1Projective) -> Scalar {
    let mut t = merlin::Transcript::new(NIVSS_DOM_SEP);

    util::append_scalar(&mut t, b"", x);
    util::append_g1_point(&mut t, b"", ff);
    util::append_g1_point(&mut t, b"", aa);
    util::append_g1_point(&mut t, b"", yy);

    let mut buf = [0u8; 64];
    t.challenge_bytes(b"challenge_c", &mut buf);
    hash_to_scalar(buf.as_slice(), b"")
}

struct ShareOracle {
    t: merlin::Transcript,
}

impl ShareOracle {
    pub fn new(
        commits: &[G1Projective],
        public_keys: &[G1Projective],
        aa: &G1Projective, 
        enc_ss: &[G1Projective],
        bb: &G1Projective,
        enc_rr: &[G1Projective], 
    ) 
    -> Self {
        let mut t = merlin::Transcript::new(NIVSS_DOM_SEP);

        util::append_g1_vector(&mut t, b"", &commits.to_vec());
        util::append_g1_vector(&mut t, b"", &public_keys.to_vec());
        util::append_g1_point(&mut t, b"", aa);
        util::append_g1_vector(&mut t, b"", &enc_ss.to_vec());
        util::append_g1_point(&mut t, b"", bb);
        util::append_g1_vector(&mut t, b"", &enc_rr.to_vec());

        let mut buf = [0u8; 32];
        t.challenge_bytes(b"label", &mut buf);
        
        Self {t}
    }

    fn get_chal(&mut self) -> Scalar {

        let mut buf = [0u8; 64];
        self.t.challenge_bytes(b"challenge_c", &mut buf);
        hash_to_scalar(buf.as_slice(), b"")
    }
}


/// Verify a proof of correct sharing
pub fn verify_sharing(
    h: &G1Projective,
    commits: &[G1Projective],
    ciphertext: &CiphertextChunks,
    public_keys: &[G1Projective],
    r_bb: &G1Projective, 
    enc_rr: &[G1Projective], 
    sh_proof: &ProofSharing,
) -> bool {
    let n = commits.len();
    let g = G1Projective::generator();

    // 1. Compute the main ciphertexts from Chunks
    let b = Scalar::from(CHUNK_SIZE as u64);
    let bpowers = get_xpowers_at_0(&b, NUM_CHUNKS); 
    let r_aa = G1Projective::multi_exp(&ciphertext.rr, &bpowers);
    
    let enc_ss = ciphertext.cc.iter()
        .map(|cc| G1Projective::multi_exp(cc, &bpowers))
        .collect::<Vec<G1Projective>>();

    let x = ShareOracle::new(commits, public_keys, &r_aa, &enc_ss, r_bb, enc_rr).get_chal();
    let xpowers = get_xpowers(&x, n);


    let pk_mul_xi = G1Projective::multi_exp(public_keys, &xpowers);
    let com_mul_xi = G1Projective::multi_exp(commits, &xpowers);
    let ss_mul_xi = G1Projective::multi_exp(&enc_ss, &xpowers);
    let rr_mul_xi = G1Projective::multi_exp(enc_rr, &xpowers);

    let r_aa_bb = r_aa.add(r_bb);
    let c_aa_bb = ss_mul_xi.add(&rr_mul_xi);

    let x_chal = first_challenge(&x, &sh_proof.ff, &sh_proof.aa,  &sh_proof.yy);

    let lhs1 = r_aa_bb.mul(&x_chal).add(&sh_proof.ff);
    let rhs1 = g.mul(sh_proof.z_ab);
    assert!(lhs1.eq(&rhs1));

    let lhs2 = com_mul_xi.mul(&x_chal).add(&sh_proof.aa);
    let points = [g, *h];
    let scalars = [sh_proof.z_s, sh_proof.z_r];
    let rhs2 = G1Projective::multi_exp(points.as_slice(), scalars.as_slice());
    assert!(lhs2.eq(&rhs2));

    let lhs3 = c_aa_bb.mul(&x_chal).add(&sh_proof.yy);
    let points = [pk_mul_xi, g, *h];
    let scalars = [sh_proof.z_ab, sh_proof.z_s, sh_proof.z_r];
    let rhs3 = G1Projective::multi_exp(points.as_slice(), scalars.as_slice());
    assert!(lhs3.eq(&rhs3));

    true
}

// Verify a proof of correct sharing
// pub fn verify_sharing(
//     public_evals: &[G1Projective],
//     ciphertext: &CiphertextChunks,
// ) -> bool {

//     let n = public_evals.len();
    
//     // TODO: For better efficiency, we can pre-compute xs and xs_b
//     let mut rng = thread_rng();
//     let xs = random_scalars(n,  &mut rng);

//     let b = Scalar::from(CHUNK_SIZE as u64);
//     let bs = get_xpowers_at_0(&b, NUM_CHUNKS); 

//     let mut xs_b: Vec<Scalar> = Vec::with_capacity(n*NUM_CHUNKS);
//     xs.iter().for_each(|&x| {
//         bs.iter().for_each(|&b| xs_b.push(x*b))
//     });

//     let mut flat_ciphertexts = Vec::with_capacity(n*NUM_CHUNKS);
//     for &ctxt in ciphertext.cc.iter() {
//         flat_ciphertexts.append(&mut ctxt.to_vec())
//     }

//     let mut lhs = G1Projective::multi_exp(&public_evals, &xs);
//     // FIXME: Adding this additional case to accomodate for the bug in the blstrs library where multi-exponentiation does not work when the length of the vector is 1. 
//     if xs.len()==1 {
//         lhs = public_evals[0].mul(xs[0]);
//     }

//     let rhs = G1Projective::multi_exp(&flat_ciphertexts, &xs_b);

//     assert!(lhs.eq(&rhs));
//     true
// }
