extern crate core;

use blstrs::G1Projective;
use protocol::{Protocol, ProtocolParams, PublicParameters};
use serde::{Serialize, Deserialize};

use super::simple_acss::ACSSSenderParams;
use super::messages::Shutdown;


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

        // let ACSSSenderParams{sc, s} = self.additional_params.take().expect("No additional params!");
        // let num_peers = self.params.node.get_num_nodes();
        // let mut rng = thread_rng();
        
        // // Start ACSS receivers
        // let (tx_acss_recv, mut rx_acss_recv) = mpsc::channel(network::network::CHANNEL_LIMIT);
        // let mut acss_recv_txs = Vec::with_capacity(num_peers);
        // let mut id_acss = self.params.id.clone();
        // id_acss.push(0);
        // let acss_sender = 0;
        // let sc = SharingConfiguration::new(th, n);

        // for sender in 0..num_peers {
        //     let mut id = id_acss.clone();
        //     id.push(*sender);

        //     let (tx, rx) = mpsc::channel(network::network::CHANNEL_LIMIT);
        //     let params = ProtocolParams::new_raw(self.params.handle.clone(),
        //                                         self.params.node.clone(), id, self.params.dst.clone(), tx_acss_recv.clone(), rx);
        //     let mut acss_recv = ACSSReceiver::new(params);
        //     let add_params = ACSSReceiverParams::new(*sender);
        //     acss_recv.additional_params(add_params);
        //     acss_recv_txs.push(tx);

        //     tokio::spawn(async move { acss_recv.run().await });
        //     task::yield_now().await;
        // }
        // let mut acss_y_received = HashMap::new();
        // let mut acss_feldman_received = HashMap::new();


        // // ACSS Sender
        // // TODO: 
        // let mut id_acss_sender = id_acss.clone();
        // id_acss_sender.push(self.params.node.get_own_idx());

        // let mut tx_acss_sender = None;
        // if acss_sender == self.params.node.get_own_idx() {
        //     let s = InputSecret::new_random(&sc, true, &mut rng);
        //     // Start ACSS Sender
        //     let sender_params = ACSSSenderParams::new(sc, s);
        //     let (tx, _) = run_protocol!(ACSSSender, self.params.handle.clone(),
        //             self.params.node.clone(), id_acss_sender.clone(), self.params.dst.clone(), sender_params);
        //     tx_acss_sender = Some(tx);
        // }
    }
}


#[cfg(test)]
mod tests {
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
        
        let (nodes, handles) = generate_nodes::<ACSSParams>(10098, 10103, 2, pp.clone());

        let n = nodes.len();
        let th= n/2;
        let sc = SharingConfiguration::new(th, n);
        let s = InputSecret::new_random(&sc, true, &mut rng);

        let id = Id::default();
        let dst = "DST".to_string();

        let mut txs = Vec::new();
        let mut rxs = Vec::new();

        let params = ACSSSenderParams::new(sc.clone(), s);
        let _ = run_protocol!(ACSSSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        let add_params = ACSSReceiverParams::new(nodes[0].get_own_idx(), sc);
        for i in 0..nodes.len() {
            let (tx, rx) =
                run_protocol!(ACSSReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params.clone());
            txs.push(tx);
            rxs.push(rx);
        }

        let mut points = Vec::new();
        for (i, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(ACSSDeliver { y, coms, .. }) => {
                    let com = coms[nodes[i].get_own_idx()];
                    let e_com = G1Projective::multi_exp(pp.get_pp(), &y.share);
                    assert!(com.eq(&e_com));

                    // TODO: To do the low-degree test.
                    points.push((Scalar::from(nodes[i].get_own_idx() as u64 + 1), y));
                },
                None => assert!(false),
            }
        }
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        let mut rs = Vec::new();
        for (x, y) in points {
            xs.push(x);
            ys.push(y.share[0]);
            rs.push(y.share[1]);
        }
        // assert_eq!(value, interpolate_at(&xs, ys, &Scalar::zero(), |s| s.invert().unwrap(), Scalar::zero()));
        // for tx in txs.iter() {
        //     shutdown!(tx, Shutdown);
        // }
        // // TODO: To shutdown the receipients
        // for handle in handles {
        //     handle.shutdown().await;
        // }
        assert!(true)
    }
    
}
