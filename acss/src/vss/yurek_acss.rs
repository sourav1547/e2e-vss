extern crate core;

use std::sync::Arc;
use blstrs::G1Projective;
use protocol::{Protocol, ProtocolParams, run_protocol};
use utils::tokio;

use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver, RBCParams};
use crate::vss::common::gen_coms_shares;
use crate::vss::keys::InputSecret;
use crate::pvss::SharingConfiguration;

use super::common::Share;
use super::messages::*;


// This would be nicer if it were generic. However, to sensibly do this, one would have to define
// traits for groups/fields (because e.g., Ark does not use the RustCrypto group, field, etc. traits)
// which is out of scope.
#[derive(Clone)]
pub struct YurekSenderParams {
    pub bases: [G1Projective; 2],
    pub eks: Vec<G1Projective>,
    pub sc: SharingConfiguration, 
    pub s: InputSecret,
}

impl YurekSenderParams {
    pub fn new(sc: SharingConfiguration, s: InputSecret, bases: [G1Projective; 2], eks: Vec<G1Projective>) -> Self {
        Self { sc, s, bases, eks }
    }
}
pub struct YurekSender {
    params: ProtocolParams<RBCParams, Shutdown, ()>,
    additional_params: Option<YurekSenderParams>,
}


impl Protocol<RBCParams, YurekSenderParams, Shutdown, ()> for YurekSender {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: YurekSenderParams) {
        self.additional_params = Some(params);
    }
}

type B = Vec<G1Projective>;
type P = Share;

impl YurekSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");

        let YurekSenderParams{sc, s, bases, eks} = self.additional_params.take().expect("No additional params given!");

        let node = self.params.node.clone();
        let (coms, shares) = gen_coms_shares(&sc, &s, &bases);

        // TODO:
        // [] Compute all n encryption keys
        // [] Create a vector of encryptions
        // [] Send the encrypted vector

        let params = RBCSenderParams::new(coms, Some(shares));
        let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), params);

    }
}

#[derive(Clone)]
pub struct YurekReceiverParams {
    pub bases : [G1Projective; 2],
    pub sender: usize,
    pub sc: SharingConfiguration,
}

impl YurekReceiverParams {
    pub fn new(sender: usize, sc: SharingConfiguration, bases : [G1Projective; 2]) -> Self {
        Self { sender, sc, bases }
    }
}

pub struct YurekReceiver {
    params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>,
    additional_params: Option<YurekReceiverParams>
}

impl Protocol<RBCParams, YurekReceiverParams, Shutdown, ACSSDeliver> for YurekReceiver {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: YurekReceiverParams) {
        self.additional_params = Some(params)
    }
}

impl YurekReceiver {
    pub async fn run(&mut self) {
        let YurekReceiverParams{bases, sender, ..} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        type B = Vec<G1Projective>;
        type P = Share;
        // type F = dyn Fn(&B, &P) -> bool;
        type F = Box<dyn Fn(&Vec<G1Projective>, Option<&Share>) -> bool + Send + Sync>;

        // let num_peers = self.params.node.get_num_nodes();
        let node = self.params.node.clone();

        let node_clone = self.params.node.clone();
        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a Vec<G1Projective>, Option<&'b Share>) -> bool + Send + Sync>> = Arc::new(Box::new(move |coms, share| {
            if share.is_none() {
                return false
            }
            let com: G1Projective = coms[node_clone.get_own_idx()];
            let e_com = G1Projective::multi_exp(&bases, &share.unwrap().share);
            com.eq(&e_com)

            // TODO:
            // [] Use the decryption key to decrypt the share
            // [] Check if shares are valid.
            // [] For this scheme, we can even send commitments to the coefficients instead of evaluations
        }));

        let add_params = RBCReceiverParams::new(sender, verify);
        let (_, mut rx) = run_protocol!(RBCReceiver<B, P, F>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), add_params);

        match rx.recv().await {
            Some(RBCDeliver { bmsg, pmsg, .. }) => {
                if let Some(pmsg) = pmsg {
                    let deliver = ACSSDeliver::new(pmsg, bmsg, sender);
                    self.params.tx.send(deliver).await.expect("Send to parent failed!");
                    return
                }
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
    use crate::vss::keys::InputSecret;
    use crate::vss::messages::ACSSDeliver;

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
            let add_params = YurekReceiverParams::new(nodes[0].get_own_idx(), sc.clone(), bases);
            let (_, rx) =
                run_protocol!(YurekReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            // txs.push(tx);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);
        let eks = Vec::with_capacity(n);

        let params = YurekSenderParams::new(sc.clone(), s, bases, eks);
        let _ = run_protocol!(YurekSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        // let mut points = Vec::new();
        for (i, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(ACSSDeliver { y, coms, .. }) => {
                    assert!(coms.len() == n);
                    let com: G1Projective = coms[nodes[i].get_own_idx()];
                    let e_com = G1Projective::multi_exp(&bases, &y.share);
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
