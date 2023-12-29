use blstrs::{G1Projective, Scalar};
use serde::Deserialize;
use serde::Serialize;

use crate::vss::sigs::AggregateSignature;
use crate::vss::sigs::EdSignature;

use super::ni_vss::encryption::CiphertextChunks;
use super::ni_vss::nizk_chunking::ProofChunking;
use super::ni_vss::nizk_sharing::ProofSharing;


#[derive(Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct TranscriptYurek {
    pub coms: Vec<G1Projective>, 
    pub ek: G1Projective,
    pub ctxt: Vec<[[u8; 32];2]>,
}

impl TranscriptYurek {
    pub fn new(coms: Vec<G1Projective>, ek: G1Projective, ctxt: Vec<[[u8; 32];2]>) -> Self {
        Self { coms, ek, ctxt }
    }
}




#[derive(Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
// NOTE: We are omitting sending the coms a part of the transcript again as the 
// the dealer already sent it as part of ShareMsg
pub struct TranscriptBLS {
    shares: Vec<Scalar>, // Shares of those who did not sign
    randomness: Vec<Scalar>, // Pedersen commitment randomness of those who did not sign
    agg_sig : AggregateSignature, // Multisignature from the set of nodes who received valid shares
}


impl TranscriptBLS {
    pub fn new(shares:Vec<Scalar>, randomness:Vec<Scalar>, agg_sig: AggregateSignature) -> Self {
        Self { shares, randomness, agg_sig }
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
// NOTE: We are omitting sending the coms a part of the transcript again as the 
// the dealer already sent it as part of ShareMsg
pub struct TranscriptEd {
    shares: Vec<Scalar>, // Shares of those who did not sign
    randomness: Vec<Scalar>, // commitment randomness of those who did not sign
    agg_sig : EdSignature, // Multisignature from the set of nodes who received valid shares
}

impl TranscriptEd {
    pub fn new(shares:Vec<Scalar>, randomness:Vec<Scalar>, agg_sig: EdSignature) -> Self {
        Self { shares, randomness, agg_sig }
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
#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptGroth {
    coms: Vec<G1Projective>,
    pub(crate) ciphertext: CiphertextChunks, // Chunkciphertext of the remaining parties
    pub(crate) chunk_pf: ProofChunking, // NIZK proof of correct encryption
    pub(crate) r_bb : G1Projective,  // ElGamal Encryption of h^r
    pub(crate) enc_rr: Vec<G1Projective>,
    pub(crate) share_pf: ProofSharing, // NIZK proof of correct sharing
}

impl TranscriptGroth {
    pub fn new(
        coms:Vec<G1Projective>, 
        ciphertext: CiphertextChunks, 
        chunk_pf: ProofChunking, 
        r_bb: G1Projective,
        enc_rr: Vec<G1Projective>,
        share_pf: ProofSharing,
    ) -> Self {
        Self{coms, ciphertext, chunk_pf, r_bb, enc_rr, share_pf}
    }

    pub fn coms(&self) -> &Vec<G1Projective> {
        &self.coms
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


#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptMixedBLS {
    coms: Vec<G1Projective>,
    shares: Vec<Scalar>,
    randomness: Vec<Scalar>,
    agg_sig : AggregateSignature,
    pub(crate) ciphertext: CiphertextChunks, // Chunkciphertext of the remaining parties
    pub(crate) chunk_pf: ProofChunking, // NIZK proof of correct encryption
    pub(crate) r_bb : G1Projective,  // ElGamal Encryption of h^r
    pub(crate) enc_rr: Vec<G1Projective>,
    pub(crate) share_pf: ProofSharing, // NIZK proof of correct sharing
}

impl TranscriptMixedBLS {
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

#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptMixedEd {
    coms: Vec<G1Projective>,
    shares: Vec<Scalar>,
    randomness: Vec<Scalar>,
    agg_sig : EdSignature,
    pub(crate) ciphertext: CiphertextChunks, // Chunkciphertext of the remaining parties
    pub(crate) chunk_pf: ProofChunking, // NIZK proof of correct encryption
    pub(crate) r_bb : G1Projective, // ElGamal Encryption of h^r
    pub(crate) enc_rr: Vec<G1Projective>, 
    pub(crate) share_pf: ProofSharing, // NIZK proof of correct sharing
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
