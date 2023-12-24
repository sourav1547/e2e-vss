use serde::{Deserialize, Serialize};
use network::tokio::sync::oneshot;

use crate::{G1Projective, Scalar};

pub struct Shutdown(pub oneshot::Sender<()>);

#[derive(Debug)]
pub struct ACSSDeliver {
    pub y: Scalar,
    pub commitment: Vec<G1Projective>,
    pub sender: usize,
}

impl ACSSDeliver {
    pub fn new(y: Scalar, commitment: Vec<G1Projective>, sender: usize) -> Self {
        Self { y, commitment, sender }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SendMsg {
    pub commitment: Vec<G1Projective>,
    pub s: Scalar,
    pub r: Scalar,
}

impl SendMsg {
    pub fn new(commitment: Vec<G1Projective>, s:Scalar, r:Scalar) -> Self {
        Self { commitment, s, r}
    }

    pub fn is_correct(&self, commitment: Vec<G1Projective>, own_idx: usize, num_peers: usize) -> bool {
        if num_peers != self.commitment.len()
        {
            return false;
        }

        // TODO: To verify the polynomial commitment here.
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
