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
    pub shares: Option<Vec<Scalar>>, // Shares of those who did not sign
    pub randomness: Option<Vec<Scalar>>, // Pedersen commitment randomness of those who did not sign
    pub agg_sig : AggregateSignature, // Multisignature from the set of nodes who received valid shares
}


impl TranscriptBLS {
    pub fn new(shares:Option<Vec<Scalar>>, randomness:Option<Vec<Scalar>>, agg_sig: AggregateSignature) -> Self {
        Self { shares, randomness, agg_sig }
    }

    pub fn shares(&self) -> &Option<Vec<Scalar>> {
        &self.shares
    }

    pub fn randomness(&self) -> &Option<Vec<Scalar>> {
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
    pub shares: Option<Vec<Scalar>>, // Shares of those who did not sign
    pub randomness: Option<Vec<Scalar>>, // commitment randomness of those who did not sign
    pub agg_sig : EdSignature, // Multisignature from the set of nodes who received valid shares
}

impl TranscriptEd {
    pub fn new(shares:Option<Vec<Scalar>>, randomness:Option<Vec<Scalar>>, agg_sig: EdSignature) -> Self {
        Self { shares, randomness, agg_sig }
    }

    pub fn shares(&self) -> &Option<Vec<Scalar>> {
        &self.shares
    }

    pub fn randomness(&self) -> &Option<Vec<Scalar>> {
        &self.randomness
    }

    pub fn agg_sig(&self) -> &EdSignature {
        &self.agg_sig
    }
}


#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptGroth {
    pub coms: Vec<G1Projective>,
    pub t_ve: TranscriptVE,
}

impl TranscriptGroth {
    pub fn new(coms:Vec<G1Projective>, t_ve: TranscriptVE) 
    -> Self {
        Self{coms, t_ve}
    }

    pub fn coms(&self) -> &Vec<G1Projective> {
        &self.coms
    }

    pub fn t_ve(&self) -> &TranscriptVE {
        &self.t_ve
    }
}


#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptMixedBLS {
    pub t_bls : TranscriptBLS, 
    pub t_ve: Option<TranscriptVE>,
}

impl TranscriptMixedBLS {
    pub fn new(t_bls: TranscriptBLS, t_ve: Option<TranscriptVE>) -> Self {
        Self{t_bls, t_ve}
    }

    pub fn t_bls(&self) -> &TranscriptBLS {
        &self.t_bls
    }

    pub fn t_ve(&self) -> &Option<TranscriptVE> {
        &self.t_ve
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptVE {
    pub ciphertext: CiphertextChunks, // Chunkciphertext of the remaining parties
    pub chunk_pf: ProofChunking, // NIZK proof of correct encryption
    pub r_bb : G1Projective, // ElGamal Encryption of h^r
    pub enc_rr: Vec<G1Projective>, 
    pub share_pf: ProofSharing, // NIZK proof of correct sharing
}

impl TranscriptVE {
    pub fn new(
        ciphertext: CiphertextChunks, 
        chunk_pf: ProofChunking, 
        r_bb: G1Projective,
        enc_rr: Vec<G1Projective>,
        share_pf: ProofSharing,
    ) -> Self {
        Self{ciphertext, chunk_pf, r_bb, enc_rr, share_pf}
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
    pub t_ed : TranscriptEd,
    pub t_ve: Option<TranscriptVE>,
}

impl TranscriptMixedEd {
    pub fn new(t_ed: TranscriptEd, t_ve: Option<TranscriptVE>) -> Self {
        Self{t_ed, t_ve}
    }
}
