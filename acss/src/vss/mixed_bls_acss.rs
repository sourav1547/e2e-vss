extern crate core;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{thread, cmp};
use aptos_bitvec::BitVec;
use blstrs::G1Projective;
use network::subscribe_msg;
use protocol::{Protocol, ProtocolParams,run_protocol};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use utils::tokio::time::sleep;
use utils::{close_and_drain, shutdown_done};
use utils::tokio;
use tokio::select;
use tokio::sync::oneshot;
use aptos_crypto::Signature;
use aptos_crypto::{
    bls12381,
    bls12381::{PrivateKey, PublicKey}, 
    SigningKey
};


use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver, RBCParams};
use crate::vss::common::share_verify;
use crate::vss::keys::InputSecret;
use crate::pvss::SharingConfiguration;
use crate::vss::ni_vss::dealing::{create_dealing, verify_dealing};
use crate::vss::transcript::{TranscriptBLS, TranscriptVE};
use super::common::{Share, gen_coms_shares};
use super::messages::*;
use super::sigs::AggregateSignature;
use super::transcript::TranscriptMixedBLS;

// This would be nicer if it were generic. However, to sensibly do this, one would have to define
// traits for groups/fields (because e.g., Ark does not use the RustCrypto group, field, etc. traits)
// which is out of scope.
#[derive(Clone)]
pub struct MixedBLSSenderParams {
    pub bases: [G1Projective; 2],
    pub vks : Vec<PublicKey>,
    pub eks: Vec<G1Projective>,
    pub sc: SharingConfiguration, 
    pub s: InputSecret,
    pub wait: usize,
}

impl MixedBLSSenderParams {
    pub fn new(
        bases: [G1Projective; 2],
        vks: Vec<PublicKey>, 
        eks: Vec<G1Projective>, 
        sc: SharingConfiguration, 
        s: InputSecret,
        wait: usize
    ) -> Self {
        Self { bases, vks, eks, sc, s, wait }
    }
}
pub struct MixedBLSSender {
    params: ProtocolParams<RBCParams, Shutdown, ()>,
    additional_params: Option<MixedBLSSenderParams>,
}

impl Protocol<RBCParams, MixedBLSSenderParams, Shutdown, ()> for MixedBLSSender {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: MixedBLSSenderParams) {
        self.additional_params = Some(params);
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AckMsg {
    pub sig: bls12381::Signature,
}

impl AckMsg {
    pub fn new(sig: bls12381::Signature) -> Self {
        Self {sig}
    }
}

type B = TranscriptMixedBLS;
type P = Share;
type F = Box<dyn Fn(&TranscriptMixedBLS, Option<&Share>) -> bool + Send + Sync>;

// This function assumes that all signatures are valid
pub fn get_transcript(coms: &Vec<G1Projective>, shares: &Vec<Share>, signers: &Vec<bool>, sigs: &Vec<bls12381::Signature>, params: &MixedBLSSenderParams, th: usize) -> TranscriptMixedBLS {
    assert!(sigs.len() >= 2*th+1);
    let agg_sig = aggregate_sig(signers.clone(), sigs.to_vec());
    if sigs.len() == params.sc.get_total_num_players() {
        return TranscriptMixedBLS::new(TranscriptBLS::new(None, None, agg_sig), None);
    }

    let deg = params.sc.get_threshold() -1;
    let max_reveal = 2*th - deg;
    let n = signers.len();
    
    let missing_count = n - sigs.len();
    let reveal_count = cmp::min(missing_count, max_reveal);
    let enc_count = cmp::max(0, missing_count - reveal_count);

    let mut reveal_shares = Vec::with_capacity(reveal_count);
    let mut reveal_randomness = Vec::with_capacity(reveal_count);
    
    let mut enc_shares = Vec::with_capacity(enc_count);
    let mut enc_randomness = Vec::with_capacity(enc_count);
    let mut enc_commits = Vec::with_capacity(enc_count);
    let mut enc_pks = Vec::with_capacity(enc_count);


    let mut count = 0;
    for (i, &is_set) in signers.iter().enumerate() {
        if !is_set {
            if count < reveal_count {
                reveal_shares.push(shares[i].share[0]);
                reveal_randomness.push(shares[i].share[1]);
            } else {
                enc_shares.push(shares[i].share[0]);
                enc_randomness.push(shares[i].share[1]);
                enc_commits.push(coms[i]);
                enc_pks.push(params.eks[i]);
            }
            count +=1;
        }
    }
    
    let h = params.bases[1];
    let (ciphertext, r_bb, enc_rr, chunk_pf, share_pf) = create_dealing(&h, &enc_commits, &enc_pks, &enc_shares, &enc_randomness);
    
    let t_bls = TranscriptBLS::new(Some(reveal_shares), Some(reveal_randomness), agg_sig);
    let t_ve = TranscriptVE::new(ciphertext, chunk_pf, r_bb, enc_rr, share_pf);

    TranscriptMixedBLS::new(t_bls, Some(t_ve))
}

// Takes as input a vector of boolean indicating which signers are set
pub fn aggregate_sig(signers: Vec<bool>, sigs: Vec<bls12381::Signature>) -> AggregateSignature {
    AggregateSignature::new(BitVec::from(signers), Some(bls12381::Signature::aggregate(sigs).unwrap()))
}

pub fn verify_transcript(coms: &Vec<G1Projective>, t: &TranscriptMixedBLS, params: &MixedBLSReceiverParams) -> bool {
    let n = coms.len();
    let TranscriptMixedBLS{t_bls, t_ve} = t.clone();
    let TranscriptBLS{shares, randomness, agg_sig} = t_bls;
    
    // Checking correctness of aggregate signature
    let mut hasher = Sha256::new();
    hasher.update(bcs::to_bytes(coms).unwrap());
    let root: [u8; 32] = hasher.finalize().into();

    let missing_count = n-agg_sig.get_num_voters();
    let mpk = params.mpk.iter().map(|x| x).collect::<Vec<&PublicKey>>();
    if missing_count == 0 {
        return agg_sig.verify(root.as_slice(), &mpk)
    }
    
    let TranscriptVE{ciphertext, chunk_pf, r_bb, enc_rr, share_pf} = t_ve.unwrap();
    let shares = shares.unwrap();
    let randomness = randomness.unwrap();
    let reveal_count = shares.len();
    let enc_count = missing_count-reveal_count;
    
    // Checking lengths of the openning vectors
    assert!(randomness.len() == reveal_count);
    assert!(enc_rr.len() == enc_count);

    // Encryption keys of nodes whose shares are not opened
    let mut enc_coms = Vec::with_capacity(enc_count);
    let mut enc_keys = Vec::with_capacity(enc_count);
    
    // Checking the correctness of the revealed shares and randomness 
    let mut idx = 0;
    for pos in 0..n {
        if !agg_sig.get_signers_bitvec().is_set(pos as u16) {
            
            if idx < reveal_count {
                let s = shares[idx];
                let r = randomness[idx];

                let com_pos = G1Projective::multi_exp(&params.bases, [s, r].as_slice());
                assert!(com_pos == coms[pos]);
            } else {
                enc_coms.push(coms[pos].clone());
                enc_keys.push(params.eks[pos].clone());
            }
            idx +=1;
        }
    }

    // FIXME: As of now this assert will fail if the randomness vector is non-zero
    let h = params.bases[1];
    agg_sig.verify(root.as_slice(), &mpk) && (verify_dealing(&h, &enc_coms, &enc_keys, &ciphertext, &chunk_pf, &r_bb, &enc_rr, &share_pf))

}

impl MixedBLSSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");
        let th = self.params.node.get_threshold();
        let mut rx_ack = subscribe_msg!(self.params.handle, &self.params.id, AckMsg);

        let MixedBLSSenderParams{bases, vks, eks, sc, s, wait} = self.additional_params.take().expect("No additional params given!");
        let node = self.params.node.clone();
        let (coms, shares) = gen_coms_shares(&sc, &s, &bases);
        let (tx_one, rx_one) = oneshot::channel();

        let coms_clone = coms.clone();
        let shares_clone = shares.clone();
        let _ = thread::spawn(move || {
            let _ = tx_one.send((coms_clone, shares_clone));
        });

        let start;
        let wait_time = Duration::from_millis(wait.try_into().unwrap());
        select! {
            Ok((bmsg, pmsg)) = rx_one => {
                for (i, y_s) in pmsg.iter().enumerate() {
                    let send_msg = ShareMsg::new(bmsg.clone(), y_s.clone());
                    self.params.handle.send(i, &self.params.id, &send_msg).await;
                }
                start = Instant::now();                
                self.params.handle.handle_stats_end().await;
            },
        }

        // Handling ack messages
        let mut signers = vec![false; sc.n];
        let mut sig_map: HashMap<usize, bls12381::Signature> = HashMap::new();
        
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
                        if ack_msg.sig.verify_arbitrary_msg(root.as_slice(), &vks[sender]).is_ok() {        
                            signers[sender] = true;
                            sig_map.insert(sender, ack_msg.sig);
                            
                            let duration = start.elapsed();
                            if (sig_map.len()==sc.n) || (sig_map.len() >= sc.n-th && duration > wait_time) {
                                self.params.handle.unsubscribe::<AckMsg>(&self.params.id).await;
                                close_and_drain!(rx_ack);
                                self.params.handle.handle_stats_event("Enough sigs collected");
                                break
                            }
                        }
                    }
                },
                _ = sleep(Duration::from_millis(wait.try_into().unwrap())) => {
                    if sig_map.len() >= sc.n-th {
                        self.params.handle.unsubscribe::<AckMsg>(&self.params.id).await;
                        close_and_drain!(rx_ack);
                        self.params.handle.handle_stats_event("Enough sigs collected");
                        break
                    }
                },
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<AckMsg>(&self.params.id).await;
                    close_and_drain!(rx_ack);
                    self.params.handle.handle_stats_end().await;
                    shutdown_done!(tx_shutdown);
                }
            }
        }

        let (tx_one, rx_one) = oneshot::channel();
        let _ = thread::spawn(move || {
            let mut sigs = Vec::new();
            for idx in 0..sc.n {
                if sig_map.contains_key(&idx) {
                    sigs.push(sig_map.get(&idx).unwrap().clone())
                }
            }
            let params = MixedBLSSenderParams { bases, vks, eks, sc, s , wait};
            let _ = tx_one.send(get_transcript(&coms,&shares, &signers, &sigs, &params, th));
        });

        select! {
            Ok(t) = rx_one => {
                let rbc_params = RBCSenderParams::new(t, None);
                let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), rbc_params);
            }
        }

    }
}

#[derive(Clone)]
pub struct MixedBLSReceiverParams {
    pub bases : [G1Projective; 2],
    pub mpk : Vec<PublicKey>,
    pub eks: Vec<G1Projective>,
    pub sk : PrivateKey,
    pub sender: usize,
    pub sc: SharingConfiguration,
}

impl MixedBLSReceiverParams {
    pub fn new(bases: [G1Projective;2], mpk: Vec<PublicKey>, eks: Vec<G1Projective>, sk: PrivateKey, sender: usize, sc: SharingConfiguration) -> Self {
        Self { bases, mpk, eks, sk, sender, sc }
    }
}

pub struct MixedBLSReceiver {
    params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>,
    additional_params: Option<MixedBLSReceiverParams>
}

impl Protocol<RBCParams, MixedBLSReceiverParams, Shutdown, ACSSDeliver> for MixedBLSReceiver {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: MixedBLSReceiverParams) {
        self.additional_params = Some(params)
    }
}

impl MixedBLSReceiver {
    pub async fn run(&mut self) {
        let MixedBLSReceiverParams{bases, mpk, eks, sk, sender, sc} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a TranscriptMixedBLS, Option<&'b Share>) -> bool + Send + Sync>> = Arc::new(Box::new(move |_, _| {
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
                        let params = MixedBLSReceiverParams{bases, mpk, eks, sk, sender, sc};
                        if verify_transcript(coms, bmsg, &params) {
                            let deliver = ACSSDeliver::new(share.clone(), coms.clone(), sender);
                            self.params.tx.send(deliver).await.expect("Send to parent failed!");
                            self.params.handle.unsubscribe::<ShareMsg>(&self.params.id).await;
                            close_and_drain!(rx_share);
                            close_and_drain!(self.params.rx);
                            self.params.handle.handle_stats_end().await;
                            
                            return;
                        } else {
                            panic!("Transcript verification failed!");
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
    use std::ops::Mul;
    use std::thread;
    use std::time::Duration;

    use group::Group;
    use rand::seq::IteratorRandom;
    use rand::thread_rng;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::{tokio, shutdown};
    use crate::vss::recon::reconstruct;
    use crate::{DST_PVSS_PUBLIC_PARAMS_GENERATION, random_scalars};
    use crate::pvss::SharingConfiguration;
    use crate::vss::common::{low_deg_test, generate_bls_sig_keys};
    use crate::vss::keys::InputSecret;
    use crate::vss::messages::ACSSDeliver;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 20)]
    async fn test_low_ed_acss() {
        let mut rng = thread_rng();
        let seed = b"hello";
        
        let th: usize = 5;
        let deg = 2*th;
        let n = 3*th + 1;
        let start: u16 = 10098;
        let end = start + n as u16; 
        
        let pp = RBCParams::new(n, th);
        
        let g = G1Projective::generator(); 
        let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        let bases = [g, h];

        let (nodes, handles) = generate_nodes::<RBCParams>(start, end, th, pp);
        let n = nodes.len();

        let sc = SharingConfiguration::new(deg+1, n);
        let s = InputSecret::new_random(&sc, true, &mut rng);

        let keys = generate_bls_sig_keys(n);
        let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<PublicKey>>();

        let dec_keys = random_scalars(n, &mut rng);
        let enc_keys = dec_keys.iter().map(|x| g.mul(x)).collect::<Vec<_>>();

        let id = Id::default();
        let dst = "DST".to_string();

        let mut txs = Vec::new();
        let mut rxs = Vec::new();
        for i in 0..n {
            let sk = &keys[i].private_key;
            let add_params = MixedBLSReceiverParams::new(bases, vkeys.clone(), enc_keys.clone(), sk.clone(), nodes[0].get_own_idx(), sc.clone());
            let (tx, rx) =
                run_protocol!(MixedBLSReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            txs.push(tx);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

        let wait = 0;
        let secret_s = s.get_secret_a();
        let secret_r = s.get_secret_r0();

        let params = MixedBLSSenderParams::new(bases, vkeys, enc_keys, sc.clone(), s, wait);
        let (stx,_) = run_protocol!(MixedBLSSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        let mut all_shares = Vec::with_capacity(n);
        for (i, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(ACSSDeliver { y, coms, .. }) => {
                    assert!(coms.len() == n);
                    let com: G1Projective = coms[nodes[i].get_own_idx()];
                    let e_com = G1Projective::multi_exp(&bases, &y.share);
                    assert!(com.eq(&e_com));
                    assert!(low_deg_test(&coms, &sc));
                    all_shares.push(y);
                },
                None => assert!(false),
            }
        }

        let mut shares = Vec::with_capacity(th);
        let mut players : Vec<usize> = (0..n)
        .choose_multiple(&mut rng, deg+1)
        .into_iter().collect::<Vec<usize>>();
        players.sort();

        for i in 0..=deg {
            shares.push(all_shares[players[i]]);
        }
        let (recon_s, recon_r) = reconstruct(&shares, &players, n);
        assert!(secret_s == recon_s);
        assert!(secret_r == recon_r);

        shutdown!(stx, Shutdown);
        for tx in txs.iter() {
            shutdown!(tx, Shutdown);
        }
        for handle in handles {
            handle.shutdown().await;
        }
    }
    
}
