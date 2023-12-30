extern crate core;

use std::ops::Mul;
use std::sync::Arc;
use blstrs::{G1Projective, Scalar};
use protocol::{Protocol, ProtocolParams, run_protocol};
use rand::thread_rng;
use utils::{tokio::{self, select}, shutdown_done, close_and_drain};
use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};

use crate::random_scalar;
use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver, RBCParams};
use crate::vss::common::gen_coms_shares;
use crate::vss::keys::InputSecret;
use crate::pvss::SharingConfiguration;

use super::common::{Share, low_deg_test};
use super::messages::*;
use super::transcript::TranscriptYurek;


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

type B = TranscriptYurek;
type P = Share;
type F = Box<dyn Fn(&B, Option<&P>) -> bool + Send + Sync>;


pub fn get_transcript(coms: Vec<G1Projective>, shares: &Vec<Share>, dk: Scalar, params: YurekSenderParams) -> TranscriptYurek {
    // TODO: To optimize this part
    let mut ctxts = Vec::with_capacity(params.sc.n);
    for idx in 0..params.sc.n {
        let share = shares[idx].get();

        let mut hasher = Shake128::default();
        let dh_key = params.eks[idx].mul(&dk);
        let symm_key = dh_key.to_compressed();
        hasher.update(&symm_key);
        let mut reader = hasher.finalize_xof();
        let mut res_key = [0u8; 64];
        reader.read(&mut res_key);

        let mut s_ctxt = share[0].to_bytes_be(); 
        let mut r_ctxt = share[1].to_bytes_be();

        // Perform XOR operation with the key
        for i in 0..32 {
            s_ctxt[i] = s_ctxt[i] ^ res_key[i];
            r_ctxt[i] = r_ctxt[i] ^ res_key[32+i];
        }
        ctxts.push([s_ctxt, r_ctxt]);
    }

    let ek = params.bases[0].mul(&dk);
    TranscriptYurek::new(coms, ek, ctxts)
}

impl YurekSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");
        let YurekSenderParams{sc, s, bases, eks} = self.additional_params.take().expect("No additional params given!");

        let dk = {  
            let mut rng = thread_rng();
            random_scalar(&mut rng)
        };
        let (coms, shares) = gen_coms_shares(&sc, &s, &bases);
        let t = {
            let params = YurekSenderParams{sc, s, bases, eks};
            get_transcript(coms, &shares, dk, params)
        };
        
        let rbc_params = RBCSenderParams::new(t, Some(shares));
        let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), self.params.node.clone(), self.params.id.clone(), self.params.dst.clone(), rbc_params);

        select! {
            Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                close_and_drain!(self.params.rx);
                self.params.handle.handle_stats_end().await;
                shutdown_done!(tx_shutdown);
            }
        }
    }
}

#[derive(Clone)]
pub struct YurekReceiverParams {
    pub bases : [G1Projective; 2],
    pub eks: Vec<G1Projective>,
    pub sender: usize,
    pub sc: SharingConfiguration,
}

impl YurekReceiverParams {
    pub fn new(sender: usize, eks: Vec<G1Projective>, sc: SharingConfiguration, bases : [G1Projective; 2]) -> Self {
        Self { sender, eks, sc, bases }
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
        let YurekReceiverParams{bases, sender, sc, ..} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        let node = self.params.node.clone();
        let self_idx = node.get_own_idx();

        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a B, Option<&'b P>) -> bool + Send + Sync>> = Arc::new(Box::new(move |t, share| {
            if share.is_none() {
                return false
            }
            let com: G1Projective = t.coms[self_idx];
            let e_com = G1Projective::multi_exp(&bases, &share.unwrap().share);
            com.eq(&e_com) && low_deg_test(&t.coms, &sc)
        }));

        let (_, mut rx) = {
            let rbc_params = RBCReceiverParams::new(sender, verify);
            run_protocol!(RBCReceiver<B, P, F>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), rbc_params)
        };


        loop {
            select! {
                Some(RBCDeliver { bmsg, pmsg, .. }) = rx.recv() => {
                    if let Some(pmsg) = pmsg {
                        let deliver = ACSSDeliver::new(pmsg, bmsg.coms, sender);
                        self.params.tx.send(deliver).await.expect("Send to parent failed!");

                        close_and_drain!(self.params.rx);
                        self.params.handle.handle_stats_end().await;
                        return
                    }
                },
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    close_and_drain!(self.params.rx);
                    self.params.handle.handle_stats_end().await;
                    shutdown_done!(tx_shutdown);
                }
            }
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
    use utils::{tokio, shutdown};
    use crate::{DST_PVSS_PUBLIC_PARAMS_GENERATION, random_scalars};
    use crate::pvss::SharingConfiguration;
    use crate::vss::keys::InputSecret;
    use crate::vss::messages::ACSSDeliver;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 50)]
    async fn test_acss() {
        let mut rng = thread_rng();
        let seed = b"hello";

        let th: usize = 12;
        let deg = th;
        let n = 3*th + 1;

        let start: u16 = 10098;
        let end = start + n as u16; 
        let pp = RBCParams::new(n, th);
        
        let g = G1Projective::generator(); 
        let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        let bases = [g, h];
        
        let (nodes, handles) = generate_nodes::<RBCParams>(start, end, th, pp);

        let sc = SharingConfiguration::new(deg+1, n);
        let s = InputSecret::new_random(&sc, true, &mut rng);

        let id = Id::default();
        let dst = "DST".to_string();

        let dkeys = random_scalars(n, &mut rng);
        let ekeys = dkeys.iter().map(|x| g.mul(x)).collect::<Vec<G1Projective>>();

        let mut txs = Vec::new();
        let mut rxs = Vec::new();
        for i in 0..n {
            let add_params = YurekReceiverParams::new(nodes[0].get_own_idx(), ekeys.clone(), sc.clone(), bases);
            let (tx, rx) =
                run_protocol!(YurekReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            txs.push(tx);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(2000);
        thread::sleep(duration);

        let params = YurekSenderParams::new(sc.clone(), s, bases, ekeys);
        let (stx, _) = run_protocol!(YurekSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

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

        shutdown!(stx, Shutdown);
        for tx in txs.iter() {
            shutdown!(tx, Shutdown);
        }
        for handle in handles {
            handle.shutdown().await;
        }
    }
    
}
