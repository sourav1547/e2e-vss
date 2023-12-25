extern crate core;

use blstrs::G1Projective;
use protocol::{Protocol, ProtocolParams, PublicParameters, run_protocol};
use rand::thread_rng;
use serde::{Serialize, Deserialize};
use network::tokio::sync::mpsc;
use utils::tokio::{self, task};

use crate::pvss::SharingConfiguration;

use super::keys::InputSecret;
use super::simple_acss::{ACSSSenderParams, ACSSReceiver, ACSSReceiverParams, ACSSSender};
use super::messages::{Shutdown, ACSSDeliver};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACSSParams {
    bases: [G1Projective; 2]
}

impl ACSSParams {
    pub fn new(g: G1Projective, h:G1Projective) -> Self {
        Self { bases: [g, h] }
    }
}

impl PublicParameters<[G1Projective; 2]> for ACSSParams {
    fn get_pp(&self) -> &[G1Projective; 2]  {
        &self.bases
    }
}

pub struct ACSS {
    params: ProtocolParams<ACSSParams, Shutdown, ()>,
    additional_params: Option<ACSSSenderParams>,
}

impl Protocol<ACSSParams, ACSSSenderParams, Shutdown, ()> for ACSS {
    fn new(params: ProtocolParams<ACSSParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: ACSSSenderParams) {
        self.additional_params = Some(params);
    }
}

impl ACSS {
    pub async fn run(&mut self) {
        // ACSS Sender
        let sender = 0;
        let mut id_acss_sender = self.params.id.clone();
        id_acss_sender.push(sender);

        if sender == self.params.node.get_own_idx() {
            let ACSSSenderParams{sc, s} = self.additional_params.take().expect("No additional params!");
            
            let (tx, rx) = mpsc::channel(network::network::CHANNEL_LIMIT);
            // Start ACSS Sender
            let sender_params = ACSSSenderParams::new(sc, s);
            let _ = run_protocol!(ACSSSender, self.params.handle.clone(),
                    self.params.node.clone(), id_acss_sender.clone(), self.params.dst.clone(), sender_params);
        }

        // TODOs: 
        // [x] Wait for ACSS receiver to finish here.
        // [x] Send a signal saying ACSSDone
        // [] Close the ACSS receiver channel which are open
        // [] Close all the ACSS sender related channels

        // let (tx_acss_recv, mut rx_acss_recv) = mpsc::channel(network::network::CHANNEL_LIMIT);
        // Starting the ACSS receiver
        // let (tx, rx) = mpsc::channel(network::network::CHANNEL_LIMIT);
        let ACSSReceiverParams{sender, sc} = self.additional_params.take().expect("No additional params!");
        let add_params = ACSSReceiverParams::new(sender, sc);
        let (_, mut rx) = run_protocol!(ACSSReceiver, self.params.handle.clone(),
                    self.params.node.clone(), id_acss_sender.clone(), self.params.dst.clone(), add_params);
        
        match rx.recv().await {
            Some(ACSSDeliver {..}) => {
                self.params.tx.send(()).await.expect("Parent unreachable");
            },
            None => assert!(false),
        }
        return 
    }
}

