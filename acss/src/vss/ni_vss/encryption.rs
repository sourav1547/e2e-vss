#![allow(clippy::needless_range_loop)]
use blstrs::{G1Projective, Scalar};
use group::Group;
use rand::thread_rng;
use serde::{Serialize, Deserialize};
use std::ops::Mul;
use crate::{random_scalars, vss::ni_vss::chunking::CHUNK_SIZE};
use self::crypto::PlaintextChunks;

use super::{chunking::NUM_CHUNKS, dlog_recovery::{HonestDealerDlogLookupTable, CheatingDealerDlogSolver}, utils::{get_xpowers_at_0, scalar_mult_exp}};

mod crypto {
    pub use crate::vss::ni_vss::nizk_chunking::{
        prove_chunking, verify_chunking, ChunkingWitness, ProofChunking,
    };
    pub use crate::vss::ni_vss::nizk_sharing::verify_sharing;
    pub use crate::vss::ni_vss::chunking::PlaintextChunks;
}

#[derive(Serialize, Deserialize, Default)]
pub struct CiphertextChunks {
    pub(crate) rr: Vec<G1Projective>,
    pub(crate) cc: Vec<[G1Projective; NUM_CHUNKS]>,
}

impl CiphertextChunks {
    pub fn new(rr: Vec<G1Projective>, cc: Vec<[G1Projective; NUM_CHUNKS]>) -> Self {
        CiphertextChunks{
            rr: rr,
            cc: cc,
        }
    }

    pub fn default() -> Self {
        CiphertextChunks { 
            rr: Vec::with_capacity(0), 
            cc: Vec::with_capacity(0)
        }
    }
}

impl Clone for CiphertextChunks{
    fn clone(&self) -> Self {
        Self { rr: self.rr.clone(), cc: self.cc.clone() }
    }
}

pub struct EncryptionWitness {
    pub(crate) r_0: Scalar,
    pub(crate) scalars_r: [Scalar; NUM_CHUNKS]
}

/// Encrypt chunks. Returns ciphertext as well as the witness for later use
/// in the NIZK proofs.
pub fn enc_chunks(
    public_keys: &[G1Projective],
    plaintext_chunks: &Vec<crypto::PlaintextChunks>,
) -> (CiphertextChunks, EncryptionWitness) {
    let mut rng = thread_rng();
    let receivers = public_keys.len();

    let g1 = G1Projective::generator();
    let r: Result<[Scalar; NUM_CHUNKS], _> = random_scalars(NUM_CHUNKS, &mut rng).try_into();
    let r = r.unwrap();

    // let b = Scalar::from(CHUNK_SIZE as u64);
    // let mut b_powers = get_xpowers(&b, NUM_CHUNKS-1);
    // let r0 = {
    //     let mut r0 = Scalar::zero();
    //     for i in 1..NUM_CHUNKS {
    //         r0 += b_powers[i-1]*r[i]
    //     }
    //     r0.neg()
    // };
    // r[0] = r0;

    let b = Scalar::from(CHUNK_SIZE as u64);
    let bpowers = get_xpowers_at_0(&b, NUM_CHUNKS);
    let r_0 = scalar_mult_exp(&r, &bpowers);

    let rr = r.iter().map(|x| g1.mul(x)).collect();

    let cc = {
        let mut cc: Vec<[G1Projective; NUM_CHUNKS]> = Vec::with_capacity(receivers);

        for i in 0..receivers {
            let pk = public_keys[i].clone();
            let ptext = &plaintext_chunks[i];

            let g1 = G1Projective::generator();
            let pk_g1_tbl = [pk, g1];
            let chunks = ptext.chunks_as_scalars();

            let encrypted_chunks = {
                let mut v = Vec::with_capacity(NUM_CHUNKS);
                for i in 0..NUM_CHUNKS {
                    let scalars = [r[i], chunks[i]];
                    v.push(G1Projective::multi_exp(pk_g1_tbl.as_slice(), scalars.as_slice()));
                }

                let array: Result<[G1Projective; NUM_CHUNKS], _> = v.try_into();
                array.unwrap() // FIXME: Add a check here that the conversion is correct.
            };

            cc.push(encrypted_chunks);
        }

        cc
    };

    let witness = EncryptionWitness {r_0: r_0, scalars_r: r};
    let ciphertext = CiphertextChunks::new(rr, cc);

    (ciphertext, witness)
}

pub fn dec_chunks(
    ctxt: &CiphertextChunks,
    secret: Scalar,
    index: usize,
) -> Scalar {
    let n = ctxt.cc.len();
    let m = ctxt.cc[index].len();


    let cj = &ctxt.cc[index];

    let powers = cj.iter().zip(ctxt.rr.iter()).map(|(cc, rr)| cc-(rr.mul(secret))).collect::<Vec<_>>(); 

    // Find discrete log of the powers
    let linear_search = HonestDealerDlogLookupTable::new();

    let mut dlogs = {
        let mut dlogs = linear_search.solve_several(&powers);

        if dlogs.iter().any(|x| x.is_none()) {
            // Cheating dealer case
            let cheating_solver = CheatingDealerDlogSolver::new(n, m);

            for i in 0..dlogs.len() {
                if dlogs[i].is_none() {
                    // It may take hours to brute force a cheater's discrete log.
                    dlogs[i] = cheating_solver.solve(&powers[i]);
                }
            }
        }

        let mut solutions = Vec::with_capacity(dlogs.len());

        let mut i = 0;
        for dlog in dlogs {
                solutions.push(dlog.unwrap());
                let g = G1Projective::generator();
                assert!(powers[i] == g.mul(dlog.unwrap()));
                i+=1;
        }

        solutions
    };

    dlogs.reverse();
    PlaintextChunks::from_dlogs(&dlogs).recombine_to_scalar()
}

/// Encrypts several messages to several recipients
///
/// # Errors
/// This should never return an error if the protocol is followed.  Every error
/// should be prevented by the caller validating the arguments beforehand.
pub fn encrypt_and_prove(
    public_keys: &[G1Projective],
    shares: &[Scalar],
) -> (CiphertextChunks, crypto::ProofChunking, Scalar) {
    
    let plaintext_chunks = shares
        .iter()
        .map(|s| crypto::PlaintextChunks::from_scalar(s))
        .collect::<Vec<_>>();

    let (ciphertext, encryption_witness) = enc_chunks(
        public_keys, 
        &plaintext_chunks
    );

    // let b = Scalar::from(CHUNK_SIZE as u64);
    // let b_powers = get_xpowers_at_0(&b, NUM_CHUNKS);    
    // let r_recon = {
    //     let mut r_recon = Scalar::zero();
    //     for i in 0..NUM_CHUNKS {
    //         r_recon += b_powers[i]*encryption_witness.scalars_r[i]
    //     }
    //     r_recon
    // };
    // assert!(r_recon.is_zero_vartime());

    // let s_recon = {
    //     let mut s_recon = Scalar::zero();
    //     for i in 0..NUM_CHUNKS {
    //         s_recon += b_powers[i]*Scalar::from(plaintext_chunks[0].chunks[i] as u64)
    //     }
    //     s_recon
    // };
    // assert!(s_recon.eq(&shares[0]));
    // assert!(plaintext_chunks[0].recombine_to_scalar().eq(&shares[0]));

    let chunking_proof = prove_chunking(
        &public_keys,
        &ciphertext,
        &plaintext_chunks,
        &encryption_witness,
    );

    (ciphertext, chunking_proof, encryption_witness.r_0)
}

/// Zero knowledge proof of correct chunking
///
/// Note: The crypto::nizk API data types are inconsistent with those used in
/// crypto::forward_secure so we need a thin wrapper to convert.
fn prove_chunking(
    public_keys: &[G1Projective],
    ciphertext: &CiphertextChunks,
    plaintext_chunks: &Vec<crypto::PlaintextChunks>,
    encryption_witness: &EncryptionWitness,
) -> crypto::ProofChunking {
    let big_plaintext_chunks: Vec<_> = plaintext_chunks
        .iter()
        .map(|chunks| chunks.chunks_as_scalars())
        .collect();

    let chunking_witness =
        crypto::ChunkingWitness::new(encryption_witness.scalars_r, big_plaintext_chunks);

    crypto::prove_chunking(public_keys, ciphertext, &chunking_witness)
}

/// Verify zk proof of Groths NiVSS
pub fn verify_chunk_proofs(
    receiver_keys: &[G1Projective],
    ciphertext: &CiphertextChunks,
    chunking_proof: &crypto::ProofChunking,
) -> bool {

    crypto::verify_chunking(
        receiver_keys,
        ciphertext,
        chunking_proof,
    ).is_ok()
}