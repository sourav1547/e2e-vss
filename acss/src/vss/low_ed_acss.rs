extern crate core;

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use aptos_crypto::test_utils::{KeyPair, TEST_SEED};
use blstrs::G1Projective;
use network::subscribe_msg;
use protocol::{Protocol, ProtocolParams,run_protocol};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use utils::{close_and_drain, shutdown_done};
use utils::tokio;

use tokio::select;
use tokio::sync::oneshot;

use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver, RBCParams};
use crate::vss::keys::InputSecret;
use crate::fft::fft;
use crate::pvss::SharingConfiguration;
use super::common::{Share, low_deg_test};
use super::messages::*;
use aptos_crypto::{Signature, Uniform};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519Signature, Ed25519PublicKey};
use aptos_crypto::multi_ed25519::MultiEd25519PublicKey;

// This would be nicer if it were generic. However, to sensibly do this, one would have to define
// traits for groups/fields (because e.g., Ark does not use the RustCrypto group, field, etc. traits)
// which is out of scope.
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

impl LowEdSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");

        
        let LowEdSenderParams{sc, s, bases, vks} = self.additional_params.take().expect("No additional params given!");

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
                coms.push(G1Projective::multi_exp(&bases, scalars.as_slice())); 
            }
            (coms , shares)
        };

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
            },
            Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                self.params.handle.handle_stats_end().await;
                shutdown_done!(tx_shutdown);
            }
        }

        // To receieve the ack message 
        let mut rx_ack = subscribe_msg!(self.params.handle, &self.params.id, AckMsg);
        let mut sigs = Vec::new();
        
        // TODO: Maintain a hash_map per digest.
        let mut ack_set = HashSet::new();

        // Computing the commitment digest
        let _bmsg = bcs::to_bytes(&coms).unwrap(); 
        let mut hasher = Sha256::new();
        hasher.update(_bmsg);
        let digest: [u8; 32] = hasher.finalize().into();

        let public_keys = vks.public_keys();

        loop {
            select! {
                Some(msg) = rx_ack.recv() => {
                    let sender = *msg.get_sender(); 
                    if ack_set.contains(&sender) {continue}

                    if let Ok(ack_msg) = msg.get_content::<AckMsg>() {
                        let sig = ack_msg.sig;
                        let pk = &public_keys[sender];
                        if sig.verify_arbitrary_msg(digest.as_slice(), pk).is_ok() {       
                            ack_set.insert(sender);
                            sigs.push((sender, sig));
                            if ack_set.len() >= 2 * self.params.node.get_threshold() - 1 {
                                self.params.handle.unsubscribe::<AckMsg>(&self.params.id).await;
                                close_and_drain!(rx_ack);
                                self.params.handle.handle_stats_event("Enough sigs collected");
                                break
                            }
                        }
                    }
                }
            }
        }

        type B = Vec<(usize, Ed25519Signature)>;
        type P = Share;

        // To update the verify function here.
        let params = RBCSenderParams::new(sigs, shares);
        let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), params);

    }
}

#[derive(Clone)]
pub struct LowEdReceiverParams {
    pub bases : [G1Projective; 2],
    pub vks : MultiEd25519PublicKey,
    pub sk : Ed25519PrivateKey,
    pub sender: usize,
    pub sc: SharingConfiguration,
}

impl LowEdReceiverParams {
    pub fn new(bases: [G1Projective;2], vks: MultiEd25519PublicKey, sk: Ed25519PrivateKey, sender: usize, sc: SharingConfiguration) -> Self {
        Self { bases, vks, sk, sender, sc }
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

    pub fn sign_verified_deal(sig_key: Ed25519PrivateKey, msg: Vec<u8>) -> Option<Ed25519Signature> {
        return Some(sig_key.sign_arbitrary_message(msg.as_slice()));
    }

    pub fn share_verify(&self, coms: &Vec<G1Projective>, share: &Share, bases: &[G1Projective; 2], sc: &SharingConfiguration) -> bool {
        let own_idx = self.params.node.get_own_idx();
        let com: G1Projective = coms[own_idx];
        let e_com = G1Projective::multi_exp(bases, &share.share);
        com.eq(&e_com)  && low_deg_test(coms, sc)
    }

    pub async fn run(&mut self) {
        let LowEdReceiverParams{bases, vks, sk, sender, sc} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));
        
        let mut rx_share = subscribe_msg!(self.params.handle, &self.params.id, ShareMsg);
        let mut coms = Vec::new();
        let mut share: Share;
        let root: [u8; 32];

        loop {
            select! {
                Some(msg) = rx_share.recv() => {
                    if msg.get_sender() == &sender {
                        if let Ok(share_msg) = msg.get_content::<ShareMsg>() {

                            coms = share_msg.coms;
                            share = share_msg.share;

                            self.params.handle.handle_stats_event("Before send_msg.is_correct");
                            if self.share_verify(&coms, &share, &bases, &sc) {
                                self.params.handle.handle_stats_event("After send_msg.is_correct");

                                let mut hasher = Sha256::new();
                                let _bmsg = bcs::to_bytes(&coms).unwrap();
                                hasher.update(_bmsg);
                                root = hasher.finalize().into();

                                let sig =  Some(sk.sign_arbitrary_message(root.as_slice())).unwrap();

                                // Respond with ACK message
                                let ack = AckMsg::new(sig);
                                self.params.handle.send(sender, &self.params.id, &ack).await;
                                
                                self.params.handle.unsubscribe::<ShareMsg>(&self.params.id).await;
                                close_and_drain!(rx_share);
                                self.params.handle.handle_stats_event("After sending echo");
                                
                                break
                            }
                        }
                    }
                }
            }
        }

        type B = Vec<(usize, Ed25519Signature)>;
        type P = Share;
        type F = Box<dyn Fn(&Vec<(usize, Ed25519Signature)>, &Share) -> bool + Send + Sync>;

        // let num_peers = self.params.node.get_num_nodes();
        let node = self.params.node.clone();
        let public_keys = vks.public_keys().clone();

        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a Vec<(usize, Ed25519Signature)>, &'b Share) -> bool + Send + Sync>> = Arc::new(Box::new(move |sigs, share| {

            for (idx, sig) in sigs.iter() {
                let pk = &public_keys[*idx];
                if !sig.verify_arbitrary_msg(root.as_slice(), pk).is_ok() {
                    return false;
                }
            }
            true
        }));

        let add_params = RBCReceiverParams::new(sender, verify);
        let (_, mut rx) = run_protocol!(RBCReceiver<B, P, F>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), add_params);

        match rx.recv().await {
            Some(RBCDeliver { .. }) => {
                let deliver = ACSSDeliver::new(share, coms, sender);
                self.params.tx.send(deliver).await.expect("Send to parent failed!");
                return
            },
            None => assert!(false),
        }
    }
}

pub fn generate_ed_sig_keys(n: usize) -> Vec<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>> {
    let mut rng = StdRng::from_seed(TEST_SEED);
    (0..n)
        .map(|_| KeyPair::<Ed25519PrivateKey, Ed25519PublicKey>::generate(&mut rng))
        .collect()
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
    async fn test_low_ed_acss() {
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

        let keys = generate_ed_sig_keys(n);
        let ver_keys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<Ed25519PublicKey>>();
        let mpk = MultiEd25519PublicKey::new(ver_keys, th).unwrap();

        let id = Id::default();
        let dst = "DST".to_string();

        let mut rxs = Vec::new();
        for i in 0..n {
            let sk = &keys[i].private_key;
            let add_params = LowEdReceiverParams::new(bases, mpk.clone(), sk.clone(), nodes[0].get_own_idx(), sc.clone());
            let (_, rx) =
                run_protocol!(LowEdReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            // txs.push(tx);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

            

        let params = LowEdSenderParams::new(bases, mpk, sc.clone(), s);
        let _ = run_protocol!(LowEdSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

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
