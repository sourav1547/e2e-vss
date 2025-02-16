extern crate core;

use std::sync::Arc;
use std::thread;
use blstrs::{G1Projective, Scalar};
use ff::Field;
use protocol::{Protocol, ProtocolParams, run_protocol};
use utils::tokio::sync::oneshot;
use utils::{close_and_drain, shutdown_done};

use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver, RBCParams};
use crate::vss::keys::InputSecret;
use crate::pvss::SharingConfiguration;
use crate::vss::ni_vss::dealing::verify_dealing;
use crate::vss::ni_vss::encryption::dec_chunks;
use super::common::{Share, groth_deal};
use super::messages::*;
use super::transcript::TranscriptGroth;
use super::transcript::TranscriptVE;
use utils::tokio::{self, select};

#[derive(Clone)]
pub struct GrothSenderParams {
    pub bases: [G1Projective; 2],
    pub eks: Vec<G1Projective>,
    pub sc: SharingConfiguration, 
    pub s: InputSecret,
}

impl GrothSenderParams {
    pub fn new(sc: SharingConfiguration, s: InputSecret, bases: [G1Projective; 2], eks: Vec<G1Projective>) -> Self {
        Self { sc, s, bases, eks }
    }
}

pub struct GrothSender {
    params: ProtocolParams<RBCParams, Shutdown, ()>,
    additional_params: Option<GrothSenderParams>,
}

impl Protocol<RBCParams, GrothSenderParams, Shutdown, ()> for GrothSender {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: GrothSenderParams) {
        self.additional_params = Some(params);
    }
}

type B = TranscriptGroth;
type P = Share;
type F = Box<dyn Fn(&TranscriptGroth, Option<&Share>) -> bool + Send + Sync>;

pub fn get_transcript(params: &GrothSenderParams) -> TranscriptGroth {
    let (coms, ciphertext, r_bb, enc_rr, chunk_pf, sh_pf) = groth_deal(&params.sc, &params.bases, &params.eks, &params.s);

    TranscriptGroth::new(coms, TranscriptVE::new(ciphertext, chunk_pf, r_bb, enc_rr,  sh_pf))
}

impl GrothSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");
        let GrothSenderParams{sc, s, bases, eks} = self.additional_params.take().expect("No additional params given!");
        let (tx_one, rx_one) = oneshot::channel();

        let _ = thread::spawn(move || {
            let params = GrothSenderParams{sc, s, bases, eks};    
            let _ = tx_one.send(get_transcript(&params));
        });

        select! {
            Ok(t) = rx_one => {
                let rbc_params = RBCSenderParams::new(t, None);
                let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), self.params.node.clone(), self.params.id.clone(), self.params.dst.clone(), rbc_params);
            },
            Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                close_and_drain!(self.params.rx);
                self.params.handle.handle_stats_end().await;
                shutdown_done!(tx_shutdown);
            }
        }
    }
}

#[derive(Clone)]
pub struct GrothReceiverParams {
    pub bases : [G1Projective; 2],
    pub eks : Vec<G1Projective>,
    pub sender: usize,
    pub dk: Scalar,
    pub sc: SharingConfiguration,
}

impl GrothReceiverParams {
    pub fn new(bases : [G1Projective; 2], eks: Vec<G1Projective>, sender: usize, dk: Scalar, sc: SharingConfiguration) -> Self {
        Self { bases, eks, sender, dk, sc }
    }
}

pub struct GrothReceiver {
    params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>,
    additional_params: Option<GrothReceiverParams>
}

impl Protocol<RBCParams, GrothReceiverParams, Shutdown, ACSSDeliver> for GrothReceiver {
    fn new(params: ProtocolParams<RBCParams, Shutdown, ACSSDeliver>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: GrothReceiverParams) {
        self.additional_params = Some(params)
    }
}

pub fn verify_transcript(t: &TranscriptGroth, params: &GrothReceiverParams) -> bool {
    let h = params.bases[1];
    verify_dealing(&h, t.coms(), &params.eks, &t.t_ve.ciphertext, &t.t_ve.chunk_pf, &t.t_ve.r_bb, &t.t_ve.enc_rr, &t.t_ve.share_pf)
}


impl GrothReceiver {
    pub async fn run(&mut self) {
        let GrothReceiverParams{bases, eks, sender, dk, sc} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        let node = self.params.node.clone();
        let dk_clone = dk.clone();
        
        let params = GrothReceiverParams{bases, eks, sender, dk, sc};
        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a TranscriptGroth, Option<&'b Share>) -> bool + Send + Sync>> = Arc::new(Box::new(move |t, _| {
            verify_transcript(t, &params)
        }));

        let rbc_params = RBCReceiverParams::new(sender, verify);
        let (_, mut rx) = run_protocol!(RBCReceiver<B, P, F>, self.params.handle.clone(), node.clone(), self.params.id.clone(), self.params.dst.clone(), rbc_params);

        loop {
            select! {
                Some(RBCDeliver {bmsg, .. })  = rx.recv() => {
                    let secret = dec_chunks(&bmsg.t_ve.ciphertext, dk_clone, node.get_own_idx().clone());
                    let share = Share{share: [secret, Scalar::zero()]};
    
                    let deliver = ACSSDeliver::new(share, bmsg.coms().clone(), sender);
                    self.params.tx.send(deliver).await.expect("Send to parent failed!");
                    
                    close_and_drain!(self.params.rx);
                    self.params.handle.handle_stats_end().await;
                    return
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
    use crate::vss::common::low_deg_test;
    use crate::vss::recon::reconstruct;
    use crate::{DST_PVSS_PUBLIC_PARAMS_GENERATION, random_scalars};
    use crate::pvss::SharingConfiguration;
    use crate::vss::keys::InputSecret;
    use crate::vss::messages::ACSSDeliver;
    
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_acss() {
        let mut rng = thread_rng();
        let seed = b"hello";

        let th: usize = 4;
        let deg = 2*th;
        let n = 3*th + 1;
        let start: u16 = 10098;
        let end = start + n as u16; 

        let pp = RBCParams::new(16, 6);
        
        let g = G1Projective::generator(); 
        let h = G1Projective::hash_to_curve(seed, DST_PVSS_PUBLIC_PARAMS_GENERATION.as_slice(), b"h");
        let bases = [g, h];

        let (nodes, handles) = generate_nodes::<RBCParams>(start, end, th, pp);
        let n = nodes.len();

        let sc = SharingConfiguration::new(deg+1, n);
        let s = InputSecret::new_random(&sc, false, &mut rng);

        let dec_keys = random_scalars(n, &mut rng);
        let enc_keys = dec_keys.iter().map(|x| g.mul(x)).collect::<Vec<_>>();

        let id = Id::default();
        let dst = "DST".to_string();

        let mut txs = Vec::new();
        let mut rxs = Vec::new();
        for i in 0..n {
            let add_params = GrothReceiverParams::new(bases, enc_keys.clone(), nodes[0].get_own_idx(), dec_keys[i], sc.clone());
            let (tx, rx) =
                run_protocol!(GrothReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            txs.push(tx);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

        let secret_s = s.get_secret_a();
        let secret_r = s.get_secret_r0();

        let params = GrothSenderParams::new(sc.clone(), s, bases, enc_keys);
        let (stx, _) = run_protocol!(GrothSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

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
