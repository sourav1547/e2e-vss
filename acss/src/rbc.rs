extern crate core;
use std::collections::{HashSet, HashMap};
use std::marker::PhantomData;
use std::sync::Arc;
use std::thread;
use network::subscribe_msg;
use protocol::{Protocol, ProtocolParams};
use serde::de::DeserializeOwned;

use sha2::{Digest, Sha256};

use utils::{close_and_drain, shutdown_done};
use utils::tokio;

use tokio::select;
use tokio::sync::oneshot;

use serde::{Serialize, Deserialize};
use crate::vss::messages::Shutdown;
use crate::messages::*;

pub const NIVSS_HASH_TO_SCALAR_DST: &[u8; 24] = b"NIVSS_HASH_TO_SCALAR_DST";

pub struct RBCDeliver<B,P = ()> {
    pub bmsg: B,
    pub pmsg: Option<P>,
    pub sender: usize,
}

impl<B,P> RBCDeliver<B,P> {
    pub fn new(bmsg: B, pmsg: Option<P>, sender: usize) -> Self {
        Self { bmsg, pmsg, sender }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBCParams {
    pub n: usize, 
    pub t: usize,
}

impl RBCParams {
    pub fn new(n:usize, t:usize) -> Self {
        Self { n, t}
    }
}

// This would be nicer if it were generic. However, to sensibly do this, one would have to define
// traits for groups/fields (because e.g., Ark does not use the RustCrypto group, field, etc. traits)
// which is out of scope.
#[derive(Clone)]
pub struct RBCSenderParams<B, P> {
    pub bmsg: B,
    pub pmsg: Option<Vec<P>>,
}

impl<B,P> RBCSenderParams<B, P> {
    pub fn new(bmsg: B, pmsg: Option<Vec<P>>) -> Self {
        Self { bmsg, pmsg }
    }
}
pub struct RBCSender<B,P> {
    params: ProtocolParams<RBCParams, Shutdown, ()>,
    additional_params: Option<RBCSenderParams<B,P>>,
}


impl<B,P> Protocol<RBCParams, RBCSenderParams<B,P>, Shutdown, ()> for RBCSender<B,P> 
{
    fn new(params: ProtocolParams<RBCParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: RBCSenderParams<B,P>) {
        self.additional_params = Some(params);
    }
}

impl<B,P> RBCSender<B,P> 
    where
        B : 'static + Serialize + Clone + Send, 
        P : 'static + Serialize + Clone + Send,
 {
    pub fn new(params: ProtocolParams<RBCParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("RBC Sender");

        let RBCSenderParams{bmsg, pmsg} = self.additional_params.take().expect("No additional params given!");

        let (tx_one, rx_one) = oneshot::channel();

        let _ = thread::spawn(move || {
            let _ = tx_one.send((bmsg, pmsg));
        });

        select! {
            Ok((bmsg, pmsg)) = rx_one => {
                let pmsg_vec = pmsg.map_or_else(|| vec![None; self.params.node.get_num_nodes()], |vec| vec.into_iter().map(Some).collect());

                assert_eq!(self.params.node.get_num_nodes(), pmsg_vec.len());
                for i in 0..self.params.node.get_num_nodes() {
                    let send_msg = SendMsg::new(bmsg.clone(), pmsg_vec[i].clone());
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
pub struct RBCReceiverParams<B, P, F> 
    where
        F: Fn(&B, Option<&P>) -> bool + Send + Sync + 'static + ?Sized,
{
    pub sender: usize,
    pub verify: Arc<F>,
    phantom_b: PhantomData<B>,
    phantom_p: PhantomData<P>,
}

impl<B, P, F> RBCReceiverParams<B, P, F> 
    where
        F: Fn(&B, Option<&P>) -> bool + Send + Sync + 'static,
{
    pub fn new(sender: usize, verify: Arc<F>) -> Self {
        Self { sender, verify, phantom_b: PhantomData, phantom_p: PhantomData }
    }
}

pub struct RBCReceiver<B,P,F> 
    where
        F: Fn(&B, Option<&P>) -> bool + Send + Sync + 'static + ?Sized,
{
    params: ProtocolParams<RBCParams, Shutdown, RBCDeliver<B,P>>,
    additional_params: Option<RBCReceiverParams<B,P,F>>,
}

impl<B,P,F: ?Sized> Protocol<RBCParams, RBCReceiverParams<B,P,F>, Shutdown, RBCDeliver<B,P>> for RBCReceiver<B,P,F> 
    where
        F: Fn(&B, Option<&P>) -> bool + Send + Sync + 'static,
{
    fn new(params: ProtocolParams<RBCParams, Shutdown, RBCDeliver<B,P>>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: RBCReceiverParams<B,P,F>) {
        self.additional_params = Some(params)
    }
}

impl<B,P,F> RBCReceiver<B,P,F> 
    where
        B: 'static + Serialize + Clone + DeserializeOwned, 
        P: 'static + Serialize + Clone + DeserializeOwned,
        F: Fn(&B, Option<&P>) -> bool + Send + Sync + 'static,
 {
    pub async fn run(&mut self) {
        let RBCReceiverParams{sender, verify, ..} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("RBC Receiver {}", sender));

        let mut rx_send = subscribe_msg!(self.params.handle, &self.params.id, SendMsg<B,P>);
        let mut rx_echo = subscribe_msg!(self.params.handle, &self.params.id, EchoMsg);
        let mut rx_ready = subscribe_msg!(self.params.handle, &self.params.id, ReadyMsg);

        let mut echo_set = HashSet::new();  // Tracks parties we have received echos from
        let mut ready_sent = false;
        let mut ready_set = HashSet::new();  // Tracks parties we have received readys from
        let mut echo_count = HashMap::new();
        let mut ready_count = HashMap::new();

        let mut bmsg= None;
        let mut pmsg= None;

        loop {
            select! {
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<SendMsg<B,P>>(&self.params.id).await;
                    close_and_drain!(rx_send);
                    self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                    close_and_drain!(rx_echo);
                    self.params.handle.unsubscribe::<ReadyMsg>(&self.params.id).await;
                    close_and_drain!(rx_ready);
                    close_and_drain!(self.params.rx);

                    self.params.handle.handle_stats_end().await;
                    shutdown_done!(tx_shutdown);
                },

                Some(msg) = rx_send.recv() => {
                    if msg.get_sender() == &sender {
                        if let Ok(send_msg) = msg.get_content::<SendMsg<B,P>>() {
                            self.params.handle.handle_stats_event("Before send_msg.is_correct");
                            if verify(&send_msg.bmsg, send_msg.pmsg.as_ref()) {
                                self.params.handle.handle_stats_event("After send_msg.is_correct");

                                let mut hasher = Sha256::new();
                                hasher.update(bcs::to_bytes(&send_msg.bmsg).unwrap());
                                let digest = hasher.finalize().into();

                                bmsg = Some(send_msg.bmsg);
                                pmsg = Some(send_msg.pmsg);

                                // Echo message
                                for i in 0..self.params.node.get_num_nodes() {
                                    let echo = EchoMsg::new(digest);
                                    self.params.handle.send(i, &self.params.id, &echo).await;
                                }
                                self.params.handle.unsubscribe::<SendMsg<B,P>>(&self.params.id).await;
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

                            let EchoMsg {digest} = echo_msg;

                            let count = echo_count.entry(digest).or_insert(0);
                            *count += 1;

                            // Send ready
                            if *count >= 2 * self.params.node.get_threshold() + 1 {
                                self.send_ready(&mut ready_sent, digest, true).await;
                            }
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

                            let count = ready_count.entry(digest).or_insert(0);
                            *count += 1;

                            // Ready amplication
                            if *count > self.params.node.get_threshold() {
                                self.send_ready(&mut ready_sent, digest, false).await;
                            }

                            // Deliver and Terminate
                            // TODO: Check if the node already received coms from the sender or not before returning RBCDeliver
                            if *count >= 2 * self.params.node.get_threshold() + 1 {
                                if bmsg.is_some() && pmsg.is_some() {
                                    self.params.handle.handle_stats_event("RBC Delivered!");
                                    let deliver = RBCDeliver::new(bmsg.unwrap(), pmsg.unwrap(), sender);
                                    self.params.tx.send(deliver).await.expect("Send to parent failed!");
                                } else { 
                                    panic! ("Bmsg None!"); 
                                }

                                // Close everything
                                self.params.handle.unsubscribe::<SendMsg<B,P>>(&self.params.id).await;
                                close_and_drain!(rx_send);
                                self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                                close_and_drain!(rx_echo);
                                self.params.handle.unsubscribe::<ReadyMsg>(&self.params.id).await;
                                close_and_drain!(rx_ready);
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

    async fn send_ready(&mut self, ready_sent: &mut bool, digest: [u8; 32], echo: bool) {
        if !*ready_sent {
            *ready_sent = true;
            let ready = ReadyMsg::new(digest.clone());
            self.params.handle.broadcast(&self.params.id, &ready).await;
            
            // FIXME: Not so beautiful code
            if echo{
                self.params.handle.handle_stats_event("Send ready from echo");
            } else {
                self.params.handle.handle_stats_event("Send ready from ready");
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use blstrs::{Scalar, G1Projective};
    use group::Group;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::{tokio, shutdown};
    use crate::DST_PVSS_PUBLIC_PARAMS_GENERATION;
    
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_rbc() {
        
        type B = Vec<G1Projective>;
        type P = Scalar;
        type F = Box<dyn Fn(&B, Option<&P>) -> bool + Send + Sync>;
       
        let seed = b"hello";
        let g = G1Projective::generator(); 
        let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");

        let th: usize = 12;
        let n = 3*th + 1;
        let start: u16 = 10098;
        let end = start + n as u16; 
        
        let pp = RBCParams::new(n, th);

        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a Vec<blstrs::G1Projective>, Option<&'b Scalar>) -> bool + Send + Sync>> = Arc::new(Box::new(|_, _| true));

        let (nodes, handles) = generate_nodes::<RBCParams>(start, end, th, pp);
        let n = nodes.len();

        // Creating dummy messaages
        let _bmsg = [g, h].to_vec();
        let mut pmsgs = Vec::with_capacity(n);
        for i in 0..n {
            pmsgs.push(Scalar::from(i as u64));
        }
            
        let id = Id::default();
        let dst = "DST".to_string();

        let mut txs = Vec::new();
        let mut rxs = Vec::new();
        for i in 0..n {
            let add_params = RBCReceiverParams::new(nodes[0].get_own_idx(), verify.clone());
            let (tx, rx) =
                run_protocol!(RBCReceiver<B,P,F>, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            rxs.push(rx);
            txs.push(tx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

        let params = RBCSenderParams::new(_bmsg.clone(), Some(pmsgs));
        let (stx, _) = run_protocol!(RBCSender<B,P>, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        for (_, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(RBCDeliver { bmsg, .. }) => {
                    assert_eq!(bmsg, _bmsg);
                },
                None => assert!(false),
            }
        }

        shutdown!(stx, Shutdown);
        for tx in txs.iter() {
            shutdown!(tx, Shutdown);
        }
        for handle in handles {
            handle.shutdown().await;
        }
    }
    
}
