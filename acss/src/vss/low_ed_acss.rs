extern crate core;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use aptos_bitvec::BitVec;
use blstrs::{G1Projective, Scalar};
use ff::Field;
use network::subscribe_msg;
use protocol::{Protocol, ProtocolParams,run_protocol};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use utils::{close_and_drain, shutdown_done};
use utils::tokio;

use tokio::select;
use tokio::sync::oneshot;

use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver, RBCParams};
use crate::vss::common::{share_verify, random_scalars_range};
use crate::vss::keys::InputSecret;
use crate::pvss::SharingConfiguration;
use super::common::{Share, gen_coms_shares};
use super::messages::*;
use super::sigs::EdSignature;
use super::transcript::TranscriptEd;
use aptos_crypto::Signature;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519Signature};
use aptos_crypto::multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature};

#[derive(Clone)]
pub struct LowEdSenderParams {
    pub bases: [G1Projective; 2],
    pub vks : MultiEd25519PublicKey,
    pub sc: SharingConfiguration, 
    pub s: InputSecret,
}

impl LowEdSenderParams {
    pub fn new(bases: [G1Projective; 2], vks: MultiEd25519PublicKey, sc: SharingConfiguration, s: InputSecret) -> Self {
        Self { bases, vks, sc, s }
    }
}
pub struct LowEdSender {
    params: ProtocolParams<RBCParams, Shutdown, ()>,
    additional_params: Option<LowEdSenderParams>,
}


impl Protocol<RBCParams, LowEdSenderParams, Shutdown, ()> for LowEdSender {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: LowEdSenderParams) {
        self.additional_params = Some(params);
    }
}

// type B = Vec<(usize, Ed25519Signature)>;
type B = TranscriptEd;
type P = Share;
type F = Box<dyn Fn(&TranscriptEd, Option<&Share>) -> bool + Send + Sync>;

// This function assumes that all signatures are valid
pub fn get_transcript(shares: &Vec<Share>, signers: &Vec<bool>, sigs: Vec<Ed25519Signature>) -> TranscriptEd {
    let agg_sig = aggregate_sig(signers.clone(), sigs);
    let n = shares.len();
    let missing_count = n-agg_sig.get_num_voters();

    let mut m_shares = Vec::with_capacity(missing_count);
    let mut m_randomness = Vec::with_capacity(missing_count);

    for (i, &is_set) in signers.iter().enumerate() {
        if !is_set {
            m_shares.push(shares[i].share[0]);
            m_randomness.push(shares[i].share[1]);
        }
    }

    TranscriptEd::new(m_shares, m_randomness, agg_sig)
}

// Takes as input a vector of boolean indicating which signers are set
pub fn aggregate_sig(signers: Vec<bool>, sigs: Vec<Ed25519Signature>) -> EdSignature {
    let mut indices: Vec<usize> = Vec::with_capacity(sigs.len());
    for i in 0..signers.len() {
        if signers[i] {
            indices.push(i);
        }
    }

    let new_sigs = sigs.iter().zip(indices.iter()).map(|(s, &i)| (s.clone(),i)).collect::<Vec<(Ed25519Signature,usize)>>();
    let mt_sig = MultiEd25519Signature::new(new_sigs);
    EdSignature::new(BitVec::from(signers), Some(mt_sig.unwrap()))
}

pub fn verify_transcript(coms: &Vec<G1Projective>, t: &TranscriptEd, sc: &SharingConfiguration, bases: &[G1Projective; 2], pk: &MultiEd25519PublicKey) -> bool {
    let num_signed = t.agg_sig().get_num_voters();
    let n = sc.n;
    let missing_ct = n-num_signed;
    
    // Checking low-degree of the committed polynomial
    assert!(t.shares().len() == t.randomness().len());
    assert!(t.shares().len() == missing_ct);

    // Checking correctness of aggregate signature
    let mut hasher = Sha256::new();
    hasher.update(bcs::to_bytes(coms).unwrap());
    let root: [u8; 32] = hasher.finalize().into();
    assert!(t.agg_sig().verify(root.as_slice(), &pk));

    let mut missing_coms = Vec::with_capacity(t.shares().len());

    let mut rng = thread_rng();
    let lambdas = random_scalars_range(&mut rng, u64::MAX, missing_ct);

    // Checking the correctness of the revealed shares and randomness 
    let mut idx = 0;
    let mut s = Scalar::zero();
    let mut r = Scalar::zero();
    for pos in 0..n {
        if !t.agg_sig().get_signers_bitvec().is_set(pos as u16) {
            s += lambdas[idx]*t.shares()[idx];
            r += lambdas[idx]*t.randomness()[idx];
            
            idx +=1;
            missing_coms.push(coms[pos]);
        }
    }

    let com_pos = G1Projective::multi_exp(bases, [s, r].as_slice());
    let com = G1Projective::multi_exp(&missing_coms, &lambdas);
    
    com_pos == com
}

impl LowEdSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");
        let mut rx_ack = subscribe_msg!(self.params.handle, &self.params.id, AckMsg);

        let LowEdSenderParams{sc, s, bases, vks} = self.additional_params.take().expect("No additional params given!");

        let node = self.params.node.clone();
        let (coms, shares) = gen_coms_shares(&sc, &s, &bases);
        let (tx_oneshot, rx_oneshot) = oneshot::channel();

        let coms_clone = coms.clone();
        let shares_clone = shares.clone();
        let _ = thread::spawn(move || {
            let _ = tx_oneshot.send((coms_clone, shares_clone));
        });

        select! {
            Ok((bmsg, pmsg)) = rx_oneshot => {
                for (i, y_s) in pmsg.iter().enumerate() {
                    let send_msg = ShareMsg::new(bmsg.clone(), y_s.clone());
                    self.params.handle.send(i, &self.params.id, &send_msg).await;
                }
                self.params.handle.handle_stats_end().await;
            }
        }

        // Handling ack messages
        let public_keys = vks.public_keys();
        let mut signers = vec![false; sc.n];
        let mut sig_map: HashMap<usize, Ed25519Signature> = HashMap::new();
        
        // Computing the commitment digest
        let mut hasher = Sha256::new();
        hasher.update(bcs::to_bytes(&coms).unwrap());
        let root: [u8; 32] = hasher.finalize().into();
        
        loop {
            select! {
                Some(msg) = rx_ack.recv() => {
                    let sender = *msg.get_sender(); 
                    if signers[sender] {continue}

                    if let Ok(ack_msg) = msg.get_content::<AckMsg>() {
                        if ack_msg.sig.verify_arbitrary_msg(root.as_slice(), &public_keys[sender]).is_ok() {       
                            signers[sender] = true;
                            sig_map.insert(sender, ack_msg.sig);
                            
                            if sig_map.len() >= sc.t {
                                self.params.handle.unsubscribe::<AckMsg>(&self.params.id).await;
                                close_and_drain!(rx_ack);
                                self.params.handle.handle_stats_event("Enough sigs collected");
                                break
                            }
                        }
                    }
                },
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<AckMsg>(&self.params.id).await;
                    close_and_drain!(rx_ack);
                    close_and_drain!(self.params.rx);
                    self.params.handle.handle_stats_end().await;
                    shutdown_done!(tx_shutdown);
                }
            }
        }

        let (tx_oneshot, rx_oneshot) = oneshot::channel();
        let _ = thread::spawn(move || {
            let mut sigs = Vec::new();
            for idx in 0..sc.n {
                if sig_map.contains_key(&idx) {
                    sigs.push(sig_map.get(&idx).unwrap().clone())
                }
            }
            let _ = tx_oneshot.send(get_transcript(&shares, &signers, sigs));
        });

        select! {
            Ok(t) = rx_oneshot => {
                let rbc_params = RBCSenderParams::new(t, None);
                let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), rbc_params);
            }
        }
    }
}

#[derive(Clone)]
pub struct LowEdReceiverParams {
    pub bases : [G1Projective; 2],
    pub mpk : MultiEd25519PublicKey,
    pub sk : Ed25519PrivateKey,
    pub sender: usize,
    pub sc: SharingConfiguration,
}

impl LowEdReceiverParams {
    pub fn new(bases: [G1Projective;2], mpk: MultiEd25519PublicKey, sk: Ed25519PrivateKey, sender: usize, sc: SharingConfiguration) -> Self {
        Self { bases, mpk, sk, sender, sc }
    }
}

pub struct LowEdReceiver {
    params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>,
    additional_params: Option<LowEdReceiverParams>
}

impl Protocol<RBCParams, LowEdReceiverParams, Shutdown, ACSSDeliver> for LowEdReceiver {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: LowEdReceiverParams) {
        self.additional_params = Some(params)
    }
}

impl LowEdReceiver {
    pub async fn run(&mut self) {
        let LowEdReceiverParams{bases, mpk, sk, sender, sc} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        // TODO: We can even make this verify function optional
        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a TranscriptEd, Option<&'b Share>) -> bool + Send + Sync>> = Arc::new(Box::new(move |_, _| {
            true
        }));

        let rbc_params = RBCReceiverParams::new(sender, verify);
        let (_, mut rx) = run_protocol!(RBCReceiver<B, P, F>, self.params.handle.clone(), self.params.node.clone(), self.params.id.clone(), self.params.dst.clone(), rbc_params);
        
        let mut rx_share = subscribe_msg!(self.params.handle, &self.params.id, ShareMsg);

        let mut maybe_coms = None;
        let mut maybe_share = None;
        let mut maybe_bmsg = None;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(10));

        loop {
            select! {
                Some(msg) = rx_share.recv() => {
                    if msg.get_sender() == &sender {
                        if let Ok(share_msg) = msg.get_content::<ShareMsg>() {

                            self.params.handle.handle_stats_event("Before share_msg.is_correct");
                            if share_verify(self.params.node.get_own_idx(), &share_msg.coms, &share_msg.share, &bases, &sc) {
                                self.params.handle.handle_stats_event("After share_msg.is_correct");

                                let mut hasher = Sha256::new();
                                hasher.update(bcs::to_bytes(&share_msg.coms).unwrap());
                                let root: [u8; 32] = hasher.finalize().into();

                                let sig = Some(sk.sign_arbitrary_message(root.as_slice())).unwrap();

                                // Respond with ACK message
                                let ack = AckMsg::new(sig);
                                self.params.handle.send(sender, &self.params.id, &ack).await;

                                maybe_coms = Some(share_msg.coms);
                                maybe_share = Some(share_msg.share);
                                
                                self.params.handle.unsubscribe::<ShareMsg>(&self.params.id).await;
                                close_and_drain!(rx_share);
                                self.params.handle.handle_stats_event("After sending ack");
                            }
                        }
                    }
                }
                Some(RBCDeliver { bmsg, .. }) = rx.recv() => {
                    maybe_bmsg = Some(bmsg);
                }
                _ = interval.tick() => {
                    if let (Some(coms), Some(share), Some(bmsg)) = (&maybe_coms, &maybe_share, &maybe_bmsg) {
                        if verify_transcript(coms, bmsg, &sc, &bases, &mpk) {
                            let deliver = ACSSDeliver::new(share.clone(), coms.clone(), sender);
                            self.params.tx.send(deliver).await.expect("Send to parent failed!");

                            self.params.handle.unsubscribe::<ShareMsg>(&self.params.id).await;
                            close_and_drain!(rx_share);
                            close_and_drain!(self.params.rx);
                            self.params.handle.handle_stats_end().await;

                            return;
                        }
                    }
                },
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<ShareMsg>(&self.params.id).await;
                    close_and_drain!(rx_share);
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

    use aptos_crypto::ed25519::Ed25519PublicKey;
    use group::Group;
    use rand::thread_rng;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::{tokio, shutdown};
    use crate::DST_PVSS_PUBLIC_PARAMS_GENERATION;
    use crate::pvss::SharingConfiguration;
    use crate::vss::common::{generate_ed_sig_keys, low_deg_test};
    use crate::vss::keys::InputSecret;
    use crate::vss::messages::ACSSDeliver;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_low_ed_acss() {
        let mut rng = thread_rng();
        let seed = b"hello";
        
        let th: usize = 12;
        let deg = 2*th;
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

        let keys = generate_ed_sig_keys(n);
        let ver_keys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<Ed25519PublicKey>>();
        let mpk = MultiEd25519PublicKey::new(ver_keys, deg+1).unwrap();

        let id = Id::default();
        let dst = "DST".to_string();

        let mut txs = Vec::new();
        let mut rxs = Vec::new();
        for i in 0..n {
            let sk = &keys[i].private_key;
            let add_params = LowEdReceiverParams::new(bases, mpk.clone(), sk.clone(), nodes[0].get_own_idx(), sc.clone());
            let (tx, rx) =
                run_protocol!(LowEdReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            txs.push(tx);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

        let params = LowEdSenderParams::new(bases, mpk, sc.clone(), s);
        let (stx, _) = run_protocol!(LowEdSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

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
