extern crate core;

use std::collections::HashSet;
use std::thread;

use blstrs::{G1Projective, Scalar};
use network::subscribe_msg;
use protocol::{Protocol, ProtocolParams, PublicParameters};
use utils::{close_and_drain, shutdown_done, spawn_blocking};
use utils::{rayon, tokio};

use tokio::select;
use tokio::sync::oneshot;

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

        let ACSSSenderParams{sc, s} = self.additional_params.take().expect("No additional params given!");

        let num_peers = self.params.node.get_num_nodes();
        let node = self.params.node.clone();
        let (tx_oneshot, rx_oneshot) = oneshot::channel();

        let _ = thread::spawn(move || {
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
            let _ = tx_oneshot.send((coms , shares));
        });

        select! {
            Ok((coms, mut shares)) = rx_oneshot => {
                for (i, y_s) in shares.drain(0..).enumerate() {
                    let send_msg = SendMsg::new(coms.clone(), y_s);
                    self.params.handle.send(i, &self.params.id, &send_msg).await;
                }
                self.params.handle.handle_stats_end().await;
            },
            Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                self.params.handle.handle_stats_end().await;
                shutdown_done!(tx_shutdown);
            }
        }
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
        let ACSSReceiverParams{sender: acss_sender, sc} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", acss_sender));

        let mut rx_send = subscribe_msg!(self.params.handle, &self.params.id, SendMsg);
        let mut rx_echo = subscribe_msg!(self.params.handle, &self.params.id, EchoMsg);
        let mut rx_ready = subscribe_msg!(self.params.handle, &self.params.id, ReadyMsg);

        // TODO: 
        // [] Figure out how to use the networking channels
        // [] Run the code in AWS setting.

        // let c_to_key = |c: &Scalar| c.to_bytes_be();
        // let mut c_data: HashMap<[u8; 48], (Vec<G1Projective>, HashMap<usize, Scalar>)> = HashMap::new();
        let mut echo_set = HashSet::new();  // Tracks parties we have received echos from
        let mut ready_sent = false;
        let mut ready_set = HashSet::new();  // Tracks parties we have received readys from
        // let mut c_count: HashMap<[u8; 48], usize> = HashMap::new();
        let num_peers = self.params.node.get_num_nodes();
        let mut coms: Vec<G1Projective> = Vec::with_capacity(num_peers);
        let mut share = Share::identity();

        loop {
            select! {
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                    close_and_drain!(rx_echo);
                    self.params.handle.unsubscribe::<SendMsg>(&self.params.id).await;
                    close_and_drain!(rx_send);
                    self.params.handle.unsubscribe::<ReadyMsg>(&self.params.id).await;
                    close_and_drain!(rx_ready);
                    close_and_drain!(self.params.rx);

                    self.params.handle.handle_stats_end().await;

                    shutdown_done!(tx_shutdown);
                },

                Some(msg) = rx_send.recv() => {
                    if msg.get_sender() == &acss_sender {
                        if let Ok(send_msg) = msg.get_content::<SendMsg>() {

                            coms = send_msg.coms.clone();
                            share = send_msg.share;

                            self.params.handle.handle_stats_event("Before send_msg.is_correct");
                            if spawn_blocking!(send_msg.is_correct(
                                self.params.node.get_own_idx(),
                                &sc,
                                self.params.node.get_num_nodes())
                            ) {
                                self.params.handle.handle_stats_event("After send_msg.is_correct");
                                // Echo message
                                for i in 0..self.params.node.get_num_nodes() {
                                    // TODO: Compute the actual hash
                                    let digest = Scalar::from(4);
                                    let echo = EchoMsg::new(digest);
                                    self.params.handle.send(i, &self.params.id, &echo).await;
                                }
                                self.params.handle.unsubscribe::<SendMsg>(&self.params.id).await;
                                close_and_drain!(rx_send);
                                self.params.handle.handle_stats_event("After sending echo");
                            }
                        }
                    }
                },

                Some(msg) = rx_echo.recv() => {
                    // Get sender
                    let sender_idx = msg.get_sender();
                    if let Ok(echo_msg) = msg.get_content::<EchoMsg>() {
                        if !echo_set.contains(sender_idx) {
                            echo_set.insert(*sender_idx);
                        }
                        // let c_key = c_to_key(&digest);
                        // let count = match c_count.remove(&c_key) {
                        //     None => 1,
                        //     Some(x) => x + 1,
                        // };
                        // c_count.insert(c_key.clone(), count);
                        let EchoMsg {digest} = echo_msg;

                        // // Send ready
                        if echo_set.len() >= 2 * self.params.node.get_threshold() - 1 {
                            self.params.handle.handle_stats_event("Send ready from echo");
                            self.send_ready(&mut ready_sent, digest).await;
                        }
                    }
                },


                Some(msg) = rx_ready.recv() => {
                    // Get sender
                    let sender_idx = msg.get_sender();
                    if let Ok(ready_msg) = msg.get_content::<ReadyMsg>() {

                        if !ready_set.contains(sender_idx) {
                            ready_set.insert(*sender_idx);
                            let ReadyMsg {digest} = ready_msg;

                            // Ready amplification
                            if ready_set.len() >= self.params.node.get_threshold() {
                                self.params.handle.handle_stats_event("Send ready from ready");
                                self.send_ready(&mut ready_sent, digest).await;
                            }
                                                    // // Send ready
                            if ready_set.len() >= 2 * self.params.node.get_threshold() - 1 {
                                
                                // TODO: Check if the node already received coms from the sender or not before returning ACSSDeliver
                                if coms.len() > 0 {
                                    self.params.handle.unsubscribe::<ReadyMsg>(&self.params.id).await;

                                    // Close everything
                                    self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                                    close_and_drain!(rx_echo);
                                    self.params.handle.unsubscribe::<SendMsg>(&self.params.id).await;
                                    close_and_drain!(rx_send);
                                    close_and_drain!(self.params.rx);


                                    self.params.handle.handle_stats_event("Output");
                                    self.params.handle.handle_stats_end().await;

                                    let deliver = ACSSDeliver::new(share, coms, acss_sender);
                                    self.params.tx.send(deliver).await.expect("Send to parent failed!");

                                    // Close everything
                                    self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                                    close_and_drain!(rx_echo);
                                    self.params.handle.unsubscribe::<SendMsg>(&self.params.id).await;
                                    close_and_drain!(rx_send);
                                    close_and_drain!(self.params.rx);

                                    self.params.handle.handle_stats_event("Output");
                                    self.params.handle.handle_stats_end().await;

                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn send_ready(&mut self, ready_sent: &mut bool, digest: Scalar) {
        if !*ready_sent {
            *ready_sent = true;
            let ready = ReadyMsg::new(digest.clone());
            self.params.handle.broadcast(&self.params.id, &ready).await;
        }
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
        // let mut xs = Vec::new();
        // let mut ys = Vec::new();
        // let mut rs = Vec::new();
        // for (x, y) in points {
        //     xs.push(x);
        //     ys.push(y.share[0]);
        //     rs.push(y.share[1]);
        // }
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
