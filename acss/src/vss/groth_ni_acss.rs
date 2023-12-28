extern crate core;

use std::sync::Arc;
use blstrs::{G1Projective, Scalar};
use ff::Field;
use protocol::{Protocol, ProtocolParams, run_protocol};

use crate::rbc::{RBCSenderParams, RBCSender, RBCReceiverParams, RBCReceiver, RBCDeliver, RBCParams};
use crate::vss::keys::InputSecret;
use crate::pvss::SharingConfiguration;
use crate::vss::ni_vss::dealing::verify_dealing;
use crate::vss::ni_vss::encryption::dec_chunks;
use super::common::{Share, groth_deal};
use super::messages::*;
use super::transcript::TranscriptGroth;
use utils::tokio;

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
type F = Box<dyn Fn(&TranscriptGroth, &Share) -> bool + Send + Sync>;

pub fn get_transcript(params: &GrothSenderParams) -> TranscriptGroth {
    let (coms, ciphertext, r_bb, enc_rr, chunk_pf, sh_pf) = groth_deal(&params.sc, &params.bases, &params.eks, &params.s);

    TranscriptGroth::new(coms, ciphertext, chunk_pf, r_bb, enc_rr,  sh_pf)
}

impl GrothSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");

        let GrothSenderParams{sc, s, bases, eks} = self.additional_params.take().expect("No additional params given!");
        
        // TODO: To remove this after making the RBC private message optional
        let mut shares: Vec<Share> = Vec::new();
        for _ in 0..sc.n {
            shares.push(Share{share: [Scalar::zero(), Scalar::zero()]});
        }

        let node = self.params.node.clone();
        let params = GrothSenderParams{sc, s, bases, eks};
        let t = get_transcript(&params);

        let rbc_params = RBCSenderParams::new(t, shares);
        let _ = run_protocol!(RBCSender<B, P>, self.params.handle.clone(), node, self.params.id.clone(), self.params.dst.clone(), rbc_params);
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
    let valid = verify_dealing(&h, t.coms(), &params.eks, &t.ciphertext, &t.chunk_pf, &t.r_bb, &t.enc_rr, &t.share_pf);
    valid
}


impl GrothReceiver {
    pub async fn run(&mut self) {
        let GrothReceiverParams{bases, eks, sender, dk, sc} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", sender));

        let node = self.params.node.clone();
        let dk_clone = dk.clone();
        
        let params = GrothReceiverParams{bases, eks, sender, dk, sc};
        let verify: Arc<Box<dyn for<'a, 'b> Fn(&'a TranscriptGroth, &'b Share) -> bool + Send + Sync>> = Arc::new(Box::new(move |t, share| {
            verify_transcript(t, &params)
        }));

        let rbc_params = RBCReceiverParams::new(sender, verify);
        let (_, mut rx) = run_protocol!(RBCReceiver<B, P, F>, self.params.handle.clone(), node.clone(), self.params.id.clone(), self.params.dst.clone(), rbc_params);

        
        match rx.recv().await {
            Some(RBCDeliver {bmsg, .. }) => {

                let secret = dec_chunks(&bmsg.ciphertext, dk_clone, node.get_own_idx().clone());
                let share = Share{share: [secret, Scalar::zero()]};
                let coms = bmsg.coms();

                let deliver = ACSSDeliver::new(share, coms.clone(), sender);
                self.params.tx.send(deliver).await.expect("Send to parent failed!");
                return
            },
            None => assert!(false),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::ops::Mul;
    use std::thread;
    use std::time::Duration;
    use group::Group;
    use rand::thread_rng;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::tokio;
    use crate::vss::common::low_deg_test;
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
        let s = InputSecret::new_random(&sc, true, &mut rng);

        let dec_keys = random_scalars(n, &mut rng);
        let enc_keys = dec_keys.iter().map(|x| g.mul(x)).collect::<Vec<_>>();

        let id = Id::default();
        let dst = "DST".to_string();

        let mut rxs = Vec::new();
        for i in 0..n {
            let add_params = GrothReceiverParams::new(bases, enc_keys.clone(), nodes[0].get_own_idx(), dec_keys[i], sc.clone());
            let (_, rx) =
                run_protocol!(GrothReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params);
            rxs.push(rx);
        }

        // Adding half second to start all the receivers, and starting the sender only after it.
        let duration = Duration::from_millis(500);
        thread::sleep(duration);

        let params = GrothSenderParams::new(sc.clone(), s, bases, enc_keys);
        let _ = run_protocol!(GrothSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        // let mut points = Vec::new();
        for (i, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(ACSSDeliver { y, coms, .. }) => {
                    assert!(coms.len() == n);
                    // let com: G1Projective = coms[nodes[i].get_own_idx()];
                    // let e_com = G1Projective::multi_exp(&bases, &y.share);
                    // assert!(com.eq(&e_com));
                    assert!(low_deg_test(&coms, &sc));
                },
                None => assert!(false),
            }
        }
        assert!(true)
    }
    
}
