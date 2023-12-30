use serde::{Deserialize, Serialize};
use network::tokio::sync::oneshot;

pub struct Shutdown(pub oneshot::Sender<()>);

#[derive(Serialize, Deserialize, Clone)]
pub struct SendMsg<B, P = ()> where
    B: Serialize + Clone, 
    P: Serialize,
 {
    pub bmsg: B,
    pub pmsg: Option<P>,
}

impl<B,P> SendMsg<B,P> where 
    B: Serialize + Clone, 
    P: Serialize,
{
    pub fn new(bmsg: B, pmsg: Option<P>) -> Self {
        Self { bmsg, pmsg }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EchoMsg {
    pub digest: [u8; 32], // Hash of the commitment
}

impl EchoMsg {
    pub fn new(digest: [u8; 32]) -> Self {
        Self { digest }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReadyMsg {
    pub digest: [u8; 32]
}

impl ReadyMsg {
    pub fn new(digest: [u8; 32]) -> Self {
        Self { digest }
    }
}

#[derive(Debug)]
pub struct ACSSDone;
