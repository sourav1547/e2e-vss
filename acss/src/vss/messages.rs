use serde::{Deserialize, Serialize};
use network::tokio::sync::oneshot;
use crate::G1Projective;
use super::common::Share;

pub struct Shutdown(pub oneshot::Sender<()>);
use aptos_crypto::ed25519::Ed25519Signature;

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
pub struct ShareMsg {
    pub coms: Vec<G1Projective>,
    pub share: Share,
}

impl ShareMsg {
    pub fn new(coms: Vec<G1Projective>, share: Share) -> Self {
        Self {coms, share}
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AckMsg {
    pub sig: Ed25519Signature,
}

impl AckMsg {
    pub fn new(sig: Ed25519Signature) -> Self {
        Self {sig}
    }
}

#[derive(Debug)]
pub struct ACSSDone;
