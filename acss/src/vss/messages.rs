use serde::{Deserialize, Serialize};
use network::tokio::sync::oneshot;

use crate::{G1Projective, Scalar, pvss::SharingConfiguration};

use super::common::{Share, low_deg_test};

pub struct Shutdown(pub oneshot::Sender<()>);

#[derive(Debug)]
pub struct ACSSDeliver {
    pub y: Share,
    pub coms: Vec<G1Projective>,
    pub sender: usize,
}

impl ACSSDeliver {
    pub fn new(y: Share, coms: Vec<G1Projective>, sender: usize) -> Self {
        Self { y, coms, sender }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SendMsg {
    pub coms: Vec<G1Projective>,
    pub share: Share,
}

/// Checks whether the commitment is to a low-degree polynomial
pub fn verify_com(coms: &Vec<G1Projective>, sc: &SharingConfiguration) -> bool {
    low_deg_test(coms, sc)
}

// pub fn verify_eval(coms:&Vec<G1Projective>, pp: &PublicParameters, i:usize, share: &Share) -> bool {
//     let com = G1Projective::multi_exp(pp.get_bases(), share.get());
//     coms[i].eq(&com)
// }

impl SendMsg {
    pub fn new(coms: Vec<G1Projective>, share: Share) -> Self {
        Self { coms, share}
    }

    pub fn is_correct(&self, own_idx: usize, sc: &SharingConfiguration,  num_peers: usize) -> bool {
        if num_peers != self.coms.len() { return false; }
        if !verify_com(&self.coms, sc) { return false; }

        // TODO: To add  the share validation check
        true
    }
}

#[derive(Serialize, Deserialize)]
pub struct EchoMsg {
    // TODO: To check whether to use a byte string instead
    pub digest: Scalar, // Hash of the commitment
}

impl EchoMsg {
    pub fn new(digest: Scalar) -> Self {
        Self { digest }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReadyMsg {
    pub digest: Scalar
}

impl ReadyMsg {
    pub fn new(digest: Scalar) -> Self {
        Self { digest }
    }
}

#[derive(Debug)]
pub struct ACSSDone;
