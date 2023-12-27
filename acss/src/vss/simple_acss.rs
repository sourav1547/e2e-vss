extern crate core;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;

use blstrs::{G1Projective, Scalar};
use network::subscribe_msg;
use protocol::{Protocol, ProtocolParams, PublicParameters, run_protocol};
use utils::tokio::sync::mpsc;
use utils::{close_and_drain, shutdown_done, spawn_blocking};
use utils::{rayon, tokio};

use tokio::select;
use tokio::sync::oneshot;

use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver};
use crate::vss::keys::InputSecret;

use crate::fft::fft;
use crate::pvss::SharingConfiguration;

use crate::vss::messages::SendMsg;
use super::common::Share;
use super::messages::*;
use serde::{Serialize, Deserialize};


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

// This would be nicer if it were generic. However, to sensibly do this, one would have to define
// traits for groups/fields (because e.g., Ark does not use the RustCrypto group, field, etc. traits)
// which is out of scope.
#[derive(Clone)]
pub struct ACSSSenderParams {
    pub sc: SharingConfiguration, 
    pub s: InputSecret,
}

impl ACSSSenderParams {
    pub fn new(sc: SharingConfiguration, s: InputSecret) -> Self {
        Self { sc, s }
    }
}
pub struct ACSSSender {
    params: ProtocolParams<ACSSParams, Shutdown, ()>,
    additional_params: Option<ACSSSenderParams>,
}


impl Protocol<ACSSParams, ACSSSenderParams, Shutdown, ()> for ACSSSender {
    fn new(params: ProtocolParams<ACSSParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: ACSSSenderParams) {
        self.additional_params = Some(params);
    }
}

impl ACSSSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");

        type B = Vec<G1Projective>;
        type P = Share;
        // type F = dyn Fn(&B, &P) -> bool;

        let ACSSSenderParams{sc, s} = self.additional_params.take().expect("No additional params given!");

        let num_peers = self.params.node.get_num_nodes();
        let node = self.params.node.clone();
        // let pp = node.get_pp();
        
        let (coms, shares) = {
            // TODO: Use a different thread for faster verification
            // let _ = thread::spawn(move || {
            let f = s.get_secret_f();
            let r = s.get_secret_r();

            let mut f_evals = fft(f, sc.get_evaluation_domain());
            f_evals.truncate(num_peers);

            let mut r_evals = fft(r, sc.get_evaluation_domain());
            r_evals.truncate(num_peers);

            let mut shares: Vec<Share> = Vec::with_capacity(num_peers);
            for i in 0..num_peers {
                shares.push(Share{share: [f_evals[i], r_evals[i]]});
            }

            let mut coms:Vec<G1Projective> = Vec::with_capacity(num_peers);
            for i in 0..num_peers {
                let scalars = [f_evals[i], r_evals[i]];
                coms.push(G1Projective::multi_exp(node.get_pp(), scalars.as_slice())); 
            }

            // TODO: To double check how this tx_oneshot works
            (coms , shares)
        };


        let params = RBCSenderParams::new(coms, shares);
        let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), params);

    }
}

#[derive(Clone)]
pub struct ACSSReceiverParams {
    pub sender: usize,
    pub sc: SharingConfiguration,
}

impl ACSSReceiverParams {
    pub fn new(sender: usize, sc: SharingConfiguration) -> Self {
        Self { sender, sc }
    }
}

pub struct ACSSReceiver {
    params: ProtocolParams<ACSSParams, Shutdown, ACSSDeliver>,
    additional_params: Option<ACSSReceiverParams>
}

impl Protocol<ACSSParams, ACSSReceiverParams, Shutdown, ACSSDeliver> for ACSSReceiver {
    fn new(params: ProtocolParams<ACSSParams, Shutdown, ACSSDeliver>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: ACSSReceiverParams) {
        self.additional_params = Some(params)
    }
}

impl ACSSReceiver {
    pub async fn run(&mut self) {
        let ACSSReceiverParams{sender, ..} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        type B = Vec<G1Projective>;
        type P = Share;
        // type F = dyn Fn(&B, &P) -> bool;
        type F = Box<dyn Fn(&Vec<G1Projective>, &Share) -> bool + Send + Sync>;

        // let num_peers = self.params.node.get_num_nodes();
        let node = self.params.node.clone();

        let node_clone = self.params.node.clone();
        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a Vec<G1Projective>, &'b Share) -> bool + Send + Sync>> = Arc::new(Box::new(move |coms, share| {
            let com: G1Projective = coms[node_clone.get_own_idx()];
            let pp = node_clone.get_pp();
            let e_com = G1Projective::multi_exp(pp, &share.share);
            com.eq(&e_com)
        }));

        let add_params = RBCReceiverParams::new(node.get_own_idx(), verify);
        let (_, mut rx) = run_protocol!(RBCReceiver<B, P, F>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), add_params);

        match rx.recv().await {
            Some(RBCDeliver { bmsg, pmsg, .. }) => {
                let deliver = ACSSDeliver::new(pmsg, bmsg, sender);
                self.params.tx.send(deliver).await.expect("Send to parent failed!");
                return
            },
            None => assert!(false),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::time::Duration;

    use blstrs::Scalar;
    use ff::Field;
    use group::Group;
    use rand::thread_rng;
    use crypto::interpolate_at;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::{shutdown, tokio};
    use crate::DST_PVSS_PUBLIC_PARAMS_GENERATION;
    use crate::pvss::SharingConfiguration;
    use crate::vss::keys::InputSecret;
    use crate::vss::messages::ACSSDeliver;
    use crate::vss::simple_acss::{ACSSSender, ACSSReceiverParams, ACSSReceiver};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_acss() {
        let mut rng = thread_rng();
        let seed = b"hello";
        let g = G1Projective::generator(); 
        let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        let pp = ACSSParams::new(g, h);
        
        let (nodes, handles) = generate_nodes::<ACSSParams>(10098, 10114, 6, pp.clone());

        let n = nodes.len();
        let th= n/2;
        let sc = SharingConfiguration::new(th, n);
        let s = InputSecret::new_random(&sc, true, &mut rng);

        let id = Id::default();
        let dst = "DST".to_string();

        let mut rxs = Vec::new();
        for i in 0..n {
            let add_params = ACSSReceiverParams::new(nodes[0].get_own_idx(), sc.clone());
            let (_, rx) =
                run_protocol!(ACSSReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            // txs.push(tx);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

        let params = ACSSSenderParams::new(sc.clone(), s);
        let _ = run_protocol!(ACSSSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        // let mut points = Vec::new();
        for (i, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(ACSSDeliver { y, coms, .. }) => {
                    assert!(coms.len() == n);
                    let com: G1Projective = coms[nodes[i].get_own_idx()];
                    let e_com = G1Projective::multi_exp(pp.get_pp(), &y.share);
                    assert!(com.eq(&e_com));

                    // TODO: To do the low-degree test.
                    // points.push((Scalar::from(nodes[i].get_own_idx() as u64 + 1), y));
                },
                None => assert!(false),
            }
        }
        assert!(true)
    }
    
}
