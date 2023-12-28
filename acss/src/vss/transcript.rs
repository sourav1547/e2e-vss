use blstrs::{G1Projective, Scalar};
use serde::Deserialize;
use serde::Serialize;

use crate::vss::sigs::AggregateSignature;
use crate::vss::sigs::EdSignature;

use super::ni_vss::encryption::CiphertextChunks;
use super::ni_vss::nizk_chunking::ProofChunking;
use super::ni_vss::nizk_sharing::ProofSharing;


#[derive(Clone, Serialize, Deserialize, Default)]
#[allow(non_snake_case)]
pub struct TranscriptBLS {
    /// Pedersen commitment to the polynomial
    coms: Vec<G1Projective>,
    /// Shares of those who did not sign
    shares: Vec<Scalar>,
    /// Pedersen commitment randomness of those who did not sign
    randomness: Vec<Scalar>,
    /// Multisignature from the set of nodes who received valid shares
    agg_sig : AggregateSignature,
}


impl TranscriptBLS {
    pub fn new(coms:Vec<G1Projective>, shares:Vec<Scalar>, randomness:Vec<Scalar>, agg_sig: AggregateSignature) -> Self {
        Self {
            coms: coms,
            shares: shares,
            randomness: randomness,
            agg_sig: agg_sig,
        }
    }

    pub fn coms(&self) -> &Vec<G1Projective> {
        &self.coms
    }

    pub fn shares(&self) -> &Vec<Scalar> {
        &self.shares
    }

    pub fn randomness(&self) -> &Vec<Scalar> {
        &self.randomness
    }

    pub fn agg_sig(&self) -> &AggregateSignature {
        &self.agg_sig
    }
}





#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct TranscriptEd {
    /// Pedersen commitment to the polynomial
    coms: Vec<G1Projective>,
    /// Shares of those who did not sign
    shares: Vec<Scalar>,
    /// Pedersen commitment randomness of those who did not sign
    randomness: Vec<Scalar>,
    /// Multisignature from the set of nodes who received valid shares
    agg_sig : EdSignature,
}

impl TranscriptEd {
    pub fn new(coms:Vec<G1Projective>, shares:Vec<Scalar>, randomness:Vec<Scalar>, agg_sig: EdSignature) -> Self {
        Self {
            coms: coms,
            shares: shares,
            randomness: randomness,
            agg_sig: agg_sig,
        }
    }

    pub fn coms(&self) -> &Vec<G1Projective> {
        &self.coms
    }

    pub fn shares(&self) -> &Vec<Scalar> {
        &self.shares
    }

    pub fn randomness(&self) -> &Vec<Scalar> {
        &self.randomness
    }

    pub fn agg_sig(&self) -> &EdSignature {
        &self.agg_sig
    }
}

#[allow(non_snake_case)]
pub struct TranscriptMixed {
    /// Pedersen commitment to the polynomial
    coms: Vec<G1Projective>,
    /// Shares of those who did not sign
    shares: Vec<Scalar>,
    /// Pedersen commitment randomness of those who did not sign
    randomness: Vec<Scalar>,
    /// Multisignature from the set of nodes who received valid shares
    agg_sig : AggregateSignature,
    /// Chunkciphertext of the remaining parties
    pub(crate) ciphertext: CiphertextChunks,
    /// NIZK proof of correct encryption
    pub(crate) chunk_pf: ProofChunking,
    /// ElGamal Encryption of h^r
    pub(crate) r_bb : G1Projective, 
    pub(crate) enc_rr: Vec<G1Projective>, 
    /// NIZK proof of correct sharing
    pub(crate) share_pf: ProofSharing,
}

impl TranscriptMixed {
    pub fn new(
        coms:Vec<G1Projective>, 
        shares:Vec<Scalar>, 
        randomness:Vec<Scalar>, 
        agg_sig: AggregateSignature, 
        ciphertext: CiphertextChunks, 
        chunk_pf: ProofChunking, 
        r_bb: G1Projective,
        enc_rr: Vec<G1Projective>,
        share_pf: ProofSharing,
    ) -> Self {
        Self{coms, shares, randomness, agg_sig,
            ciphertext,
            chunk_pf,
            r_bb,
            enc_rr,
            share_pf,
        }
    }

    pub fn coms(&self) -> &Vec<G1Projective> {
        &self.coms
    }

    pub fn reveal_count(&self) -> usize {
        self.shares.len()
    }

    pub fn shares(&self) -> &Vec<Scalar> {
        &self.shares
    }

    pub fn randomness(&self) -> &Vec<Scalar> {
        &self.randomness
    }

    pub fn agg_sig(&self) -> &AggregateSignature {
        &self.agg_sig
    }

    pub fn ciphertext(&self) -> &CiphertextChunks {
        &self.ciphertext
    }

    pub fn chunk_pf(&self) -> &ProofChunking {
        &self.chunk_pf
    }

    pub fn share_pf(&self) -> &ProofSharing {
        &self.share_pf
    }

    pub fn enc_rr(&self) -> &[G1Projective] {
        &self.enc_rr
    }
    
}

pub struct TranscriptMixedEd {
    /// Pedersen commitment to the polynomial
    coms: Vec<G1Projective>,
    /// Shares of those who did not sign
    shares: Vec<Scalar>,
    /// Pedersen commitment randomness of those who did not sign
    randomness: Vec<Scalar>,
    /// Multisignature from the set of nodes who received valid shares
    agg_sig : EdSignature,
    /// Chunkciphertext of the remaining parties
    pub(crate) ciphertext: CiphertextChunks,
    /// NIZK proof of correct encryption
    pub(crate) chunk_pf: ProofChunking,
    /// ElGamal Encryption of h^r
    pub(crate) r_bb : G1Projective, 
    pub(crate) enc_rr: Vec<G1Projective>, 
    /// NIZK proof of correct sharing
    pub(crate) share_pf: ProofSharing,
}

impl TranscriptMixedEd {
    pub fn new(
        coms:Vec<G1Projective>, 
        shares:Vec<Scalar>, 
        randomness:Vec<Scalar>, 
        agg_sig : EdSignature,
        ciphertext: CiphertextChunks, 
        chunk_pf: ProofChunking, 
        r_bb: G1Projective,
        enc_rr: Vec<G1Projective>,
        share_pf: ProofSharing,
    ) -> Self {
        Self{coms, shares, randomness, agg_sig,
            ciphertext,
            chunk_pf,
            r_bb,
            enc_rr,
            share_pf,
        }
    }

    pub fn coms(&self) -> &Vec<G1Projective> {
        &self.coms
    }

    pub fn reveal_count(&self) -> usize {
        self.shares.len()
    }

    pub fn shares(&self) -> &Vec<Scalar> {
        &self.shares
    }

    pub fn randomness(&self) -> &Vec<Scalar> {
        &self.randomness
    }

    pub fn agg_sig(&self) -> &EdSignature {
        &self.agg_sig
    }

    pub fn ciphertext(&self) -> &CiphertextChunks {
        &self.ciphertext
    }

    pub fn chunk_pf(&self) -> &ProofChunking {
        &self.chunk_pf
    }

    pub fn share_pf(&self) -> &ProofSharing {
        &self.share_pf
    }

    pub fn enc_rr(&self) -> &[G1Projective] {
        &self.enc_rr
    }
    
}
