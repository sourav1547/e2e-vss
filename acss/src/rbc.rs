extern crate core;
use std::collections::HashSet;
use std::marker::PhantomData;
use blstrs::Scalar;
use network::subscribe_msg;
use protocol::{Protocol, ProtocolParams, PublicParameters};
use serde::de::DeserializeOwned;
use utils::{close_and_drain, shutdown_done};
use utils::tokio;

use tokio::select;
use tokio::sync::oneshot;

use serde::{Serialize, Deserialize};
use crate::vss::messages::Shutdown;
use crate::vss::simple_acss::ACSSParams;

pub struct RBCDeliver<B,P> {
    pub bmsg: B,
    pub pmsg: P,
    pub sender: usize,
}

impl<B,P> RBCDeliver<B,P> {
    pub fn new(bmsg: B, pmsg: P, sender: usize) -> Self {
        Self { bmsg, pmsg, sender }
    }
}


#[derive(Serialize, Deserialize, Clone)]
pub struct SendMsg<B, P> where
    B: Serialize + Clone, 
    P: Serialize,
 {
    pub bmsg: B,
    pub pmsg: P,
}

impl<B,P> SendMsg<B,P> where 
    B: Serialize + Clone, 
    P: Serialize,
{
    pub fn new(bmsg: B, pmsg: P) -> Self {
        Self { bmsg, pmsg }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EchoMsg {
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

// This would be nicer if it were generic. However, to sensibly do this, one would have to define
// traits for groups/fields (because e.g., Ark does not use the RustCrypto group, field, etc. traits)
// which is out of scope.
#[derive(Clone)]
pub struct RBCSenderParams<B, P> {
    pub bmsg: B,
    pub pmsg: Vec<P>,
}

impl<B,P> RBCSenderParams<B, P> {
    pub fn new(bmsg: B, pmsg: Vec<P>) -> Self {
        Self { bmsg, pmsg }
    }
}
pub struct RBCSender<B,P> {
    params: ProtocolParams<ACSSParams, Shutdown, ()>,
    additional_params: Option<RBCSenderParams<B,P>>,
}


impl<B,P> Protocol<ACSSParams, RBCSenderParams<B,P>, Shutdown, ()> for RBCSender<B,P> 
{
    fn new(params: ProtocolParams<ACSSParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: RBCSenderParams<B,P>) {
        self.additional_params = Some(params);
    }
}

impl<B,P> RBCSender<B,P> 
    where
        B : 'static + Serialize + Clone, 
        P : 'static + Serialize + Clone,
 {
    pub fn new(params: ProtocolParams<ACSSParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");

        let RBCSenderParams{bmsg, pmsg} = self.additional_params.take().expect("No additional params given!");

        // let num_peers = self.params.node.get_num_nodes();
        // let node = self.params.node.clone();
        let (tx_oneshot, rx_oneshot) = oneshot::channel();

        // let _ = thread::spawn(move || {
        let _ = tx_oneshot.send((bmsg, pmsg));
        // });

        select! {
            Ok((bmsg, pmsg)) = rx_oneshot => {
                for (i, y_s) in pmsg.iter().enumerate() {
                    let send_msg = SendMsg::new(bmsg.clone(), y_s.clone());
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
pub struct RBCReceiverParams<B, P> 
{
    pub sender: usize,
    phantom_b: PhantomData<B>,
    phantom_p: PhantomData<P>,
}

impl<B, P> RBCReceiverParams<B, P> 
{
    pub fn new(sender: usize) -> Self {
        Self { sender, phantom_b: PhantomData, phantom_p: PhantomData }
    }
}

pub struct RBCReceiver<B,P> 
{
    params: ProtocolParams<ACSSParams, Shutdown, RBCDeliver<B,P>>,
    additional_params: Option<RBCReceiverParams<B,P>>,
}

impl<B,P> Protocol<ACSSParams, RBCReceiverParams<B,P>, Shutdown, RBCDeliver<B,P>> for RBCReceiver<B,P> 
{
    fn new(params: ProtocolParams<ACSSParams, Shutdown, RBCDeliver<B,P>>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: RBCReceiverParams<B,P>) {
        self.additional_params = Some(params)
    }
}

impl<B,P> RBCReceiver<B,P> 
    where
        B: 'static + Serialize + Clone + DeserializeOwned + Default, 
        P: 'static + Serialize + Clone + DeserializeOwned + Default,
 {
    pub async fn run(&mut self) {
        let RBCReceiverParams{sender, phantom_b, phantom_p } = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        let mut rx_send = subscribe_msg!(self.params.handle, &self.params.id, SendMsg<B,P>);
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
        let mut bmsg= B::default();
        let mut pmsg= P::default();

        loop {
            select! {
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                    close_and_drain!(rx_echo);
                    self.params.handle.unsubscribe::<SendMsg<B,P>>(&self.params.id).await;
                    close_and_drain!(rx_send);
                    self.params.handle.unsubscribe::<ReadyMsg>(&self.params.id).await;
                    close_and_drain!(rx_ready);
                    close_and_drain!(self.params.rx);

                    self.params.handle.handle_stats_end().await;

                    shutdown_done!(tx_shutdown);
                },

                Some(msg) = rx_send.recv() => {
                    if msg.get_sender() == &sender {
                        if let Ok(send_msg) = msg.get_content::<SendMsg<B,P>>() {

                            bmsg = send_msg.bmsg;
                            pmsg = send_msg.pmsg;

                            self.params.handle.handle_stats_event("Before send_msg.is_correct");
                            if true {
                                self.params.handle.handle_stats_event("After send_msg.is_correct");
                                // Echo message
                                for i in 0..self.params.node.get_num_nodes() {
                                    // TODO: Compute the actual hash
                                    let digest = Scalar::from(4);
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
                                self.params.handle.unsubscribe::<ReadyMsg>(&self.params.id).await;

                                // Close everything
                                self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                                close_and_drain!(rx_echo);
                                self.params.handle.unsubscribe::<SendMsg<B,P>>(&self.params.id).await;
                                close_and_drain!(rx_send);
                                close_and_drain!(self.params.rx);


                                self.params.handle.handle_stats_event("Output");
                                self.params.handle.handle_stats_end().await;

                                let deliver = RBCDeliver::new(bmsg, pmsg, sender);
                                self.params.tx.send(deliver).await.expect("Send to parent failed!");

                                // Close everything
                                self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                                close_and_drain!(rx_echo);
                                self.params.handle.unsubscribe::<SendMsg<B,P>>(&self.params.id).await;
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
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use blstrs::{Scalar, G1Projective};
    use group::Group;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::tokio;
    use crate::DST_PVSS_PUBLIC_PARAMS_GENERATION;
    
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_rbc() {
        
        type B = Vec<G1Projective>;
        type P = Scalar;
        type F = dyn Fn(&B, &P) -> bool;

        
        let seed = b"hello";
        let g = G1Projective::generator(); 
        let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        let pp = ACSSParams::new(g, h);
        

        // let verify : &'static F = &|b, p| -> bool {
        //     true
        // };

        let (nodes, handles) = generate_nodes::<ACSSParams>(10098, 10114, 2, pp);
        let n = nodes.len();

        // Creating dummy messaages
        let _bmsg = [g, h].to_vec();
        let mut pmsgs = Vec::with_capacity(n);
        for i in 0..n {
            pmsgs.push(Scalar::from(i as u64));
        }
            
        let id = Id::default();
        let dst = "DST".to_string();

        let mut rxs = Vec::new();
        for i in 0..n {
            let add_params = RBCReceiverParams::new(nodes[0].get_own_idx());
            let (_, rx) =
                run_protocol!(RBCReceiver<B,P>, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

        let params = RBCSenderParams::new(_bmsg, pmsgs);
        let _ = run_protocol!(RBCSender<B,P>, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        for (_, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(RBCDeliver { bmsg, .. }) => {
                    assert!(bmsg.len() >0);
                },
                None => assert!(false),
            }
        }
        assert!(true)
    }
    
}
