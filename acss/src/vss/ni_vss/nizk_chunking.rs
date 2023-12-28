//! Proofs of correct chunking
#![allow(clippy::needless_range_loop)]

use std::ops::{Neg, Mul};
use crate::vss::ni_vss::chunking::{CHUNK_SIZE, NUM_CHUNKS};
use crate::vss::ni_vss::fiat_shamir::FiatShamirProtocol;
use crate::{random_scalars, util, hash_to_scalar};
use blstrs::{G1Projective, Scalar};
use group::Group;
use rand::distributions::Uniform;
use rand::prelude::Distribution;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{SeedableRng, RngCore as CRngCore};
use rand::{Rng, thread_rng};
use serde::{Serialize, Deserialize};
 
use super::encryption::CiphertextChunks;
use super::fiat_shamir::NIVSS_DOM_SEP;
use super::utils::{get_xpowers, batch_mul, scalar_mult_exp, scalar_usize_mult_exp};

pub const SECURITY_LEVEL: usize = 256;

/// The number of parallel proofs handled by one challenge
///
/// In Section 6.5 of <https://eprint.iacr.org/2021/339.pdf> this
/// value is referred to as `l`
pub const NUM_ZK_REPETITIONS: usize = 32;

/// Defined as ceil(SECURITY_LEVEL/NUM_ZK_REPETITIONS)
pub const CHALLENGE_BITS: usize = (SECURITY_LEVEL + NUM_ZK_REPETITIONS - 1) / NUM_ZK_REPETITIONS;

// The number of bytes needed to represent a challenge (which must fit in a usize)
pub const CHALLENGE_BYTES: usize = (CHALLENGE_BITS + 7) / 8;
const _: () = assert!(CHALLENGE_BYTES < std::mem::size_of::<usize>());

// A bitmask specifyng the size of a challenge
pub const CHALLENGE_MASK: usize = (1 << CHALLENGE_BITS) - 1;

/// Witness for the validity of a chunking instance.
///
/// From Section 6.5 of the NIDKG paper:
///   Witness = (scalar_r =[r_1..r_m], scalar_s=[s_{1,1}..s_{n,m}])
#[derive(Clone, Debug)]
pub struct ChunkingWitness {
    scalars_r: [Scalar; NUM_CHUNKS],
    scalars_s: Vec<[Scalar; NUM_CHUNKS]>,
}

impl ChunkingWitness {
    pub fn new(scalars_r: [Scalar; NUM_CHUNKS], scalars_s: Vec<[Scalar; NUM_CHUNKS]>) -> Self {
        ChunkingWitness {
            scalars_r,
            scalars_s,
        }
    }
}

/// Creating or verifying a proof of correct chunking failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofChunkingError {
    InvalidProof
}


/// Zero-knowledge proof of chunking.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProofChunking {
    y0: G1Projective,
    bb: Vec<G1Projective>,
    cc: Vec<G1Projective>,
    dd: Vec<G1Projective>,
    yy: G1Projective,
    z_r: Vec<Scalar>,
    z_s: [Scalar; NUM_ZK_REPETITIONS],
    z_beta: Scalar,
}

/// First move of the prover in the zero-knowledge proof of chunking.
struct FirstMoveChunking {
    y0: G1Projective,
    bb: Vec<G1Projective>,
    cc: Vec<G1Projective>,
}

impl FirstMoveChunking {
    pub fn new(y0: G1Projective, bb: Vec<G1Projective>,
        cc: Vec<G1Projective>) -> Self {
            FirstMoveChunking { y0: y0, bb: bb, cc: cc }
        }
}

/// Prover's response to the first challenge of the verifier.
// TODO: The paper also includes the challenges from the previous query,
// Maybe that is not needed in this context.
pub struct SecondMoveChunking {
    z_s: Vec<Scalar>,
    dd: Vec<G1Projective>,
    yy: G1Projective,
}

impl SecondMoveChunking {
    fn from(z_s: &[Scalar], dd: &[G1Projective], yy: &G1Projective) -> Self {
        Self {
            z_s: z_s.to_owned(),
            dd: dd.to_owned(),
            yy: yy.to_owned(),
        }
    }
}


/// Create a proof of correct chunking
pub fn prove_chunking(
    public_keys: &[G1Projective],
    ciphertexts: &CiphertextChunks,
    witness: &ChunkingWitness,
) -> ProofChunking {
    let mut rng = thread_rng();
    
    // instance .check_instance().expect("The chunking proof instance is invalid");

    let m = ciphertexts.rr.len();
    let n = public_keys.len();

    let ss = n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK;
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let range = zz - 1 + ss + 1;
    let zz_big = Scalar::from(zz as u64);
    let p_sub_s = Scalar::from(ss as u64).neg();

    // y0 <- getRandomG1
    // let y0 = G1Affine::hash(b"ic-crypto-nizk-chunking-proof-y0", &rng.gen::<[u8; 32]>());
    // TODO: The dealer can also sample this value by sampling the scalar and then raising it to the exponent.
    let y0 = G1Projective::hash_to_curve(&rng.gen::<[u8; 32]>(), b"nizk-chunking-proof-y0", b"G1");

    let g1 = G1Projective::generator();
    let y0_g1_tbl = [y0, g1];
    
    let beta = random_scalars(NUM_ZK_REPETITIONS, &mut rng);
    let bb = beta.iter().map(|x| g1.mul(x)).collect::<Vec<G1Projective>>();


    let (first_move, first_challenge, z_s) = loop {
        let sigma = [(); NUM_ZK_REPETITIONS]
            .map(|_| random_within_range(range as u64) + &p_sub_s); 

        let cc = {
            let mut cc = Vec::with_capacity(NUM_ZK_REPETITIONS);
            for i in 0..NUM_ZK_REPETITIONS {
                let b = beta[i];
                let s = sigma[i];
                cc.push(G1Projective::multi_exp(y0_g1_tbl.as_slice(), [b,s].as_slice()));
            }
            cc 
        };

        let first_move = FirstMoveChunking::new(y0.clone(), bb.clone(), cc);
        // Verifier's challenge.
        let first_challenge = ChunksOracle::new(public_keys, ciphertexts, &first_move).get_all_chunks(n, m);

        // z_s = [sum [e_ijk * s_ij | i <- [1..n], j <- [1..m]] + sigma_k | k <- [1..l]]

        let iota: [usize; NUM_ZK_REPETITIONS] = std::array::from_fn(|i| i);

        let z_s = iota.map(|k| {
            let mut acc = Scalar::from(0);
            first_challenge
                .iter()
                .zip(witness.scalars_s.iter())
                .for_each(|(e_i, s_i)| {
                    e_i.iter().zip(s_i.iter()).for_each(|(e_ij, s_ij)| {
                        acc += Scalar::from(e_ij[k] as u64) * s_ij;
                    });
                });
            acc += &sigma[k];

            acc
        });

        // Now check if our z_s is valid. Our control flow reveals if we retry
        // but in the event of a retry it should ideally not reveal *which* z_s
        // caused us to retry, since that may reveal information about the witness.
        //
        // Perform the check by using ct_compare with zz_big. This function
        // returns 1 if the zz_big is greater than its argument. If for any
        // input it returns 0 or -1 (indicating z was == or > zz_big) then the
        // sum will not match the overall length of z_s. // TODO: The last statment is not clear.

        let zs_in_range = z_s
            .iter()
            .map(|z| zz_big.gt(z) as isize)
            .sum::<isize>() as usize
            == NUM_ZK_REPETITIONS;

        if zs_in_range {
            break (first_move, first_challenge, z_s);
        }
    };

    // delta <- replicate (n + 1) getRandom
    // dd = map (g1^) delta
    // Y = product [y_i^delta_i | i <- [0..n]]
    let delta = random_scalars(n+1, &mut rng); 
    let dd = delta.iter().map(|d| g1.mul(d)).collect::<Vec<G1Projective>>();

    let yy = {
        let y0_and_pk = [y0.clone()]
            .iter()
            .chain(public_keys)
            .cloned()
            .collect::<Vec<_>>();
        G1Projective::multi_exp(&y0_and_pk, &delta)
    };

    let second_move = SecondMoveChunking::from(&z_s, &dd, &yy);

    // Second verifier's challege. Forth move in the protocol.
    // x = oracle(e, z_s, dd, yy)
    let second_challenge = second_challenge(&first_challenge, &second_move);

    // TODO: xpowers is not implemented in blstrs so we have to implement it ourselves.
    let xpowers = get_xpowers(&second_challenge, NUM_ZK_REPETITIONS);

    let mut z_r = Vec::with_capacity(first_challenge.len());
    let mut delta_idx = 1;

    for e_i in first_challenge.iter() {
        let mut xpow_e_ij = Vec::with_capacity(e_i.len());
        for j in 0..e_i.len() {
            xpow_e_ij.push(scalar_usize_mult_exp(&xpowers, &e_i[j]));
        }
        // TODO: Implement the inner product argument
        let z_rk = scalar_mult_exp(&witness.scalars_r, &xpow_e_ij) + &delta[delta_idx];

        z_r.push(z_rk);

        delta_idx += 1;
    }

    let z_beta = scalar_mult_exp(&beta, &xpowers) + &delta[0];

    ProofChunking {
        y0,
        bb,
        cc: first_move.cc,
        dd,
        yy,
        z_r,
        z_s,
        z_beta,
    }
}

/// Verify a proof of correct chunking
pub fn verify_chunking(
    public_keys: &[G1Projective], 
    ciphertexts: &CiphertextChunks,
    nizk: &ProofChunking,
) -> Result<(), ZkProofChunkingError> {
    // instance.check_instance()?;

    let num_receivers = public_keys.len();
    require_eq("bb", nizk.bb.len(), NUM_ZK_REPETITIONS)?;
    require_eq("cc", nizk.cc.len(), NUM_ZK_REPETITIONS)?;
    require_eq("dd", nizk.dd.len(), num_receivers + 1)?;
    require_eq("z_r", nizk.z_r.len(), num_receivers)?;
    require_eq("z_s", nizk.z_s.len(), NUM_ZK_REPETITIONS)?;

    let m = ciphertexts.rr.len();
    let n = public_keys.len();
    let ss = n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK;
    let zz = 2 * NUM_ZK_REPETITIONS * ss;
    let zz_big = Scalar::from(zz as u64);

    for z_sk in nizk.z_s.iter() {
        if z_sk >= &zz_big {
            return Err(ZkProofChunkingError::InvalidProof);
        }
    }

    let first_move = FirstMoveChunking::new(nizk.y0.clone(), nizk.bb.clone(), nizk.cc.clone());
    let second_move = SecondMoveChunking::from(&nizk.z_s, &nizk.dd, &nizk.yy);
    // e_{m,n,l} = oracle(instance, y_0, bb, cc)
    let e = ChunksOracle::new(public_keys, ciphertexts, &first_move).get_all_chunks(n, m);

    // x = oracle(e, z_s, dd, yy)
    let x = second_challenge(&e, &second_move);

    let xpowers = get_xpowers(&x, NUM_ZK_REPETITIONS);
    let g1 = G1Projective::generator();

    /*
    Verify lhs == rhs where
      lhs = product [R_j ^ sum [e_ijk * x^k | k <- [1..l]] | j <- [1..m]] * dd_i
      rhs = g1 ^ z_r_i | i <- [1..n]]
    */

    let rhs = batch_mul(&g1, &nizk.z_r);

    let lhs = {
        let mut lhs = Vec::with_capacity(e.len());
        for (i, e_i) in e.iter().enumerate() {
            let e_ijk_polynomials: Vec<_> = e_i
                .iter()
                .map(|e_ij| scalar_usize_mult_exp(&xpowers, e_ij))
                .collect();

            let rj_e_ijk =
                G1Projective::multi_exp(&ciphertexts.rr, &e_ijk_polynomials);

            lhs.push(rj_e_ijk + &nizk.dd[i + 1]);
        }
        lhs
    };

    if lhs != rhs {
        return Err(ZkProofChunkingError::InvalidProof);
    }

    // Verify: product [bb_k ^ x^k | k <- [1..l]] * dd_0 == g1 ^ z_beta
    let lhs = G1Projective::multi_exp(&nizk.bb, &xpowers) + &nizk.dd[0];


    let rhs = g1 * &nizk.z_beta;
    if lhs != rhs {
        return Err(ZkProofChunkingError::InvalidProof);
    }

    // Verify: product [product [chunk_ij ^ e_ijk | i <- [1..n], j <- [1..m]] ^ x^k
    // | k <- [1..l]] * product [cc_k ^ x^k | k <- [1..l]] * Y   = product
    // [y_i^z_ri | i <- [1..n]] * y0^z_beta * g_1 ^ sum [z_sk * x^k | k <- [1..l]]

    let cij_to_eijks: Vec<G1Projective> = (0..NUM_ZK_REPETITIONS)
        .map(|k| {
            let c_ij_s: Vec<_> = ciphertexts.cc
                .iter()
                .flatten()
                .cloned()
                .collect();
            let e_ijk_s: Vec<_> = e
                .iter()
                .flatten()
                .map(|e_ij| Scalar::from(e_ij[k] as u64))
                .collect();
            if c_ij_s.len() != m * n || e_ijk_s.len() != m * n {
                return Err(ZkProofChunkingError::InvalidProof);
            }

            Ok(G1Projective::multi_exp(&c_ij_s, &e_ijk_s) + &nizk.cc[k])
        })
        .collect::<Result<Vec<_>, _>>()?;

    let lhs = G1Projective::multi_exp(&cij_to_eijks[..], &xpowers[..]) + &nizk.yy;

    let acc = scalar_mult_exp(&nizk.z_s, &xpowers);

    let rhs = G1Projective::multi_exp(public_keys, &nizk.z_r) + G1Projective::multi_exp([nizk.y0, g1].as_slice(), [nizk.z_beta, acc].as_slice());

    if lhs != rhs {
        return Err(ZkProofChunkingError::InvalidProof);
    }
    Ok(())
}


// TODO: Not sure why this is needed.
#[inline]
fn require_eq(
    name: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), ZkProofChunkingError> {
    if expected != actual {
        dbg!(name);
        dbg!(actual);
        dbg!(expected);
        Err(ZkProofChunkingError::InvalidProof)
    } else {
        Ok(())
    }
}

// TODO: To fix this. Right now this is not implemented correctly
pub fn second_challenge(first_challenge: &Vec<Vec<Vec<usize>>>, second_move: &SecondMoveChunking) -> Scalar {
    let mut t = merlin::Transcript::new(NIVSS_DOM_SEP);

    util::append_scalars(&mut t, b"", &second_move.z_s);
    util::append_g1_vector(&mut t, b"", &second_move.dd);
    util::append_g1_point(&mut t, b"", &second_move.yy);


    for x in first_challenge.iter() {
        for y in x.iter() {
            for &z in y.iter() {
                t.append_u64(b"", z as u64);
            }
        }
    }

    let mut buf = [0u8; 64];
    t.challenge_bytes(b"challenge_c", &mut buf);
    hash_to_scalar(buf.as_slice(), b"")
}

struct ChunksOracle {
    rng: ChaCha20Rng, // The choice of RNG matters so this is explicit, not a trait.
}

impl ChunksOracle {
    pub fn new(public_keys: &[G1Projective], cxts: &CiphertextChunks, first_move: &FirstMoveChunking) -> Self {
        let mut t = merlin::Transcript::new(NIVSS_DOM_SEP);

        t.append_encryption_keys(&public_keys.to_vec()); 
        t.append_chunks_ciphertext(cxts); 

        util::append_g1_point(&mut t, b"", &first_move.y0);
        util::append_g1_vector(&mut t, b"", &first_move.bb);
        util::append_g1_vector(&mut t, b"", &first_move.cc);

        let mut buf = [0u8; 32];
        t.challenge_bytes(b"label", &mut buf);
        let rng = ChaCha20Rng::from_seed(buf);
        
        Self {rng }
    }

    fn getbyte(&mut self) -> u8 {
        let mut random_byte: [u8; 1] = [0; 1];
        // `fill_bytes()` with 1-byte buffer consumes 4 bytes of the random stream.
        self.rng.fill_bytes(&mut random_byte);
        random_byte[0]
    }

    /// Get a chunk-sized unit of data.
    fn get_chunk(&mut self) -> usize {
        // The order of the getbyte(..) calls matters so this is intentionally serial.
        CHALLENGE_MASK
            & (0..CHALLENGE_BYTES).fold(0, |state, _| (state << 8) | (self.getbyte() as usize))
    }

    fn get_all_chunks(&mut self, n: usize, m: usize) -> Vec<Vec<Vec<usize>>> {
        (0..n)
            .map(|_| {
                (0..m)
                    .map(|_| (0..NUM_ZK_REPETITIONS).map(|_| self.get_chunk()).collect())
                    .collect()
            })
            .collect()
    }
}

/// Return a random scalar within a small range [0,n) 
pub fn random_within_range(n: u64) -> Scalar {
    let mut rng = thread_rng();
    let die = Uniform::from(0..n);
    let val = die.sample(&mut rng);
    Scalar::from(val)
}