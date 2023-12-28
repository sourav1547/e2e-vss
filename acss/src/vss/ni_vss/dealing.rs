//! Dealing phase of Groth20-BLS12-381 non-interactive verifier secret sharing
use std::ops::{Mul, Add};

use blstrs::{G1Projective, Scalar};
use group::Group;
use rand::thread_rng;
use crate::random_scalar;

use super::encryption::{encrypt_and_prove, CiphertextChunks, verify_chunk_proofs};
use super::nizk_chunking::ProofChunking;
use super::nizk_sharing::{verify_sharing, ProofSharing, prove_sharing, SharingWitness};


/// Generate the NiVSS transcript
pub fn create_dealing(
    h: &G1Projective, 
    commits: &[G1Projective],
    receiver_keys: &[G1Projective],
    shares : &[Scalar],
    randomness : &[Scalar],
) -> (CiphertextChunks, G1Projective, Vec<G1Projective>, ProofChunking, ProofSharing) {
    let (ctxt, enc_pf, r_a) = encrypt_and_prove(receiver_keys, shares);

    let g1 = G1Projective::generator();

    // Computing ElGamal ciphertexts of h^r
    let mut rng = thread_rng();
    let r_b = random_scalar(&mut rng);
    let r_bb = g1.mul(r_b);
    let enc_rr = randomness.iter()
        .zip(receiver_keys.iter())
        .map(|(r, pk)| h.mul(r).add(pk.mul(&r_b))).collect::<Vec<G1Projective>>();

    let enc_ss = shares.iter()
        .zip(receiver_keys.iter())
        .map(|(s, pk)| g1.mul(s).add(pk.mul(&r_a))).collect::<Vec<G1Projective>>();
    
    let r_aa = g1.mul(&r_a);
    let witness = SharingWitness::new(r_a, r_b, shares.to_vec(), randomness.to_vec());

    let sh_pf = prove_sharing(h, commits, receiver_keys, &r_aa, &enc_ss, &r_bb, &enc_rr, &witness);
    
    
    (ctxt, r_bb, enc_rr, enc_pf, sh_pf)
}

/// Verify the NiVSS transcript
pub fn verify_dealing(
    h: &G1Projective,
    commits: &[G1Projective],
    public_keys: &[G1Projective],
    ciphertext: &CiphertextChunks,
    enc_proof: &ProofChunking,
    r_bb: &G1Projective, 
    enc_rr: &[G1Projective], 
    sh_proof: &ProofSharing
) -> bool {
    // TODO: To verify the formatting of the dealing instance
    let valid_share = verify_sharing(h, commits, ciphertext, public_keys,  r_bb, enc_rr, sh_proof);
    valid_share && verify_chunk_proofs(public_keys, ciphertext ,enc_proof)
}

#[allow(unused)]
mod test {
    use super::*; 
    use crate::{random_scalars, vss::ni_vss::encryption::dec_chunks};

    
    #[test]
    fn test_deal(){
        let n = 7;
        let mut rng = thread_rng();

        let g = G1Projective::generator();
        let x = Scalar::from(42);
        let h = g.mul(x);


        let shares = random_scalars(n, &mut rng);
        let randomness = random_scalars(n, &mut rng);
        let skeys = random_scalars(n, &mut rng);
        let pkeys = skeys.iter().map(|x| g.mul(x)).collect::<Vec<_>>();

        
        let commits = shares.iter()
            .zip(randomness.iter())
            .map(|(s,r)| g.mul(s).add(h.mul(r)))
            .collect::<Vec<G1Projective>>();

        let (ctxt, r_bb, enc_rr, enc_pf, sh_pf) = create_dealing(&h, &commits, &pkeys, &shares, &randomness);

        assert!(verify_dealing(&h, &commits, &pkeys, &ctxt, &enc_pf, &r_bb, &enc_rr, &sh_pf));
        for i in 0..n {
            let share = dec_chunks(&ctxt, skeys[i], i);
            assert!(share.eq(&shares[i]));
        }
    }

}