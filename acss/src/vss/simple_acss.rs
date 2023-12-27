extern crate core;

use std::sync::Arc;
use blstrs::G1Projective ;
use protocol::{Protocol, ProtocolParams, run_protocol};
use utils::tokio;

use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver, RBCParams};
use crate::vss::common::gen_coms_shares;
use crate::vss::keys::InputSecret;
use crate::pvss::SharingConfiguration;

use super::common::Share;
use super::messages::*;

type B = Vec<G1Projective>;
type P = Share;
type F = Box<dyn Fn(&Vec<G1Projective>, &Share) -> bool + Send + Sync>;

#[derive(Clone)]
pub struct ACSSSenderParams {
    pub bases: [G1Projective; 2],
    pub sc: SharingConfiguration, 
    pub s: InputSecret,
}

impl ACSSSenderParams {
    pub fn new(sc: SharingConfiguration, s: InputSecret, bases: [G1Projective; 2]) -> Self {
        Self { sc, s, bases }
    }
}
pub struct ACSSSender {
    params: ProtocolParams<RBCParams, Shutdown, ()>,
    additional_params: Option<ACSSSenderParams>,
}

impl Protocol<RBCParams, ACSSSenderParams, Shutdown, ()> for ACSSSender {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: ACSSSenderParams) {
        self.additional_params = Some(params);
    }
}

impl ACSSSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");

        let ACSSSenderParams{sc, s, bases} = self.additional_params.take().expect("No additional params given!");

        let node = self.params.node.clone();
        let (coms, shares) = gen_coms_shares(&sc, &s, &bases);

        let params = RBCSenderParams::new(coms, shares);
        let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), params);
    }
}

#[derive(Clone)]
pub struct ACSSReceiverParams {
    pub bases : [G1Projective; 2],
    pub sender: usize,
    pub sc: SharingConfiguration,
}

impl ACSSReceiverParams {
    pub fn new(sender: usize, sc: SharingConfiguration, bases : [G1Projective; 2]) -> Self {
        Self { sender, sc, bases }
    }
}

pub struct ACSSReceiver {
    params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>,
    additional_params: Option<ACSSReceiverParams>
}

impl Protocol<RBCParams, ACSSReceiverParams, Shutdown, ACSSDeliver> for ACSSReceiver {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: ACSSReceiverParams) {
        self.additional_params = Some(params)
    }
}

impl ACSSReceiver {
    pub async fn run(&mut self) {
        let ACSSReceiverParams{bases, sender, ..} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        let node = self.params.node.clone();
        let node_clone = self.params.node.clone();

        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a Vec<G1Projective>, &'b Share) -> bool + Send + Sync>> = Arc::new(Box::new(move |coms, share| {
            let com: G1Projective = coms[node_clone.get_own_idx()];
            let e_com = G1Projective::multi_exp(&bases, &share.share);
            com.eq(&e_com)
        }));

        let add_params = RBCReceiverParams::new(sender, verify);
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
    use std::thread;
    use std::time::Duration;

    use group::Group;
    use rand::thread_rng;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::tokio;
    use crate::DST_PVSS_PUBLIC_PARAMS_GENERATION;
    use crate::pvss::SharingConfiguration;
    use crate::vss::common::low_deg_test;
    use crate::vss::keys::InputSecret;
    use crate::vss::messages::ACSSDeliver;
    use crate::vss::simple_acss::{ACSSSender, ACSSReceiverParams, ACSSReceiver};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_acss() {
        let mut rng = thread_rng();
        let seed = b"hello";
        // let pp = ACSSParams::new(n, t);
        
        let g = G1Projective::generator(); 
        let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        let bases = [g, h];
        let pp = RBCParams::new(16, 6);
        
        let (nodes, handles) = generate_nodes::<RBCParams>(10098, 10114, 6, pp);

        let n = nodes.len();
        let th= n/2;
        let sc = SharingConfiguration::new(th, n);
        let s = InputSecret::new_random(&sc, true, &mut rng);

        let id = Id::default();
        let dst = "DST".to_string();

        let mut rxs = Vec::new();
        for i in 0..n {
            let add_params = ACSSReceiverParams::new(nodes[0].get_own_idx(), sc.clone(), bases);
            let (_, rx) =
                run_protocol!(ACSSReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

        let params = ACSSSenderParams::new(sc.clone(), s, bases);
        let _ = run_protocol!(ACSSSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        for (i, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(ACSSDeliver { y, coms, .. }) => {
                    assert!(coms.len() == n);
                    let com: G1Projective = coms[nodes[i].get_own_idx()];
                    let e_com = G1Projective::multi_exp(&bases, &y.share);
                    assert!(com.eq(&e_com));
                    assert!(low_deg_test(&coms, &sc));
                },
                None => assert!(false),
            }
        }
        assert!(true)
    }
    
}
