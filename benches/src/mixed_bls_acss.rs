use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::Measurement, Throughput};



pub fn vss_mixed_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("mix-bls");
    
    let ts = [21, 42, 85, 170, 341];
    let ns = [64, 128, 256, 512, 1024];

    for (&t, &n) in ts.iter().zip(ns.iter()) {
        mixed_bls_acss::vss_deal(t, n, &mut group);
        mixed_bls_acss::vss_verify(t, n, &mut group);
    }
    group.finish();
}

mod mixed_bls_acss {
    use super::*;
    use rand::thread_rng;
    use std::ops::Mul;
    use acss::random_scalars;
    use acss::vss::common::{generate_bls_sig_keys, gen_coms_shares, share_verify};
    use acss::vss::mixed_bls_acss::{self, MixedBLSSenderParams, MixedBLSReceiverParams};
    use acss::vss::{public_parameters::PublicParameters, keys::InputSecret}; 
    use acss::pvss::SharingConfiguration;
    use aptos_crypto::Signature;
    use blstrs::G1Projective;
    use sha2::{Digest, Sha256};

    use aptos_crypto::{
        bls12381::{PrivateKey, PublicKey}, 
        SigningKey
    };
    
    #[allow(warnings)]
    pub(crate) fn vss_deal<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        g.throughput(Throughput::Elements(n as u64));

        let mut rng = thread_rng();
        let mut _rng = thread_rng();

        let deg = 2*t;
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);
        let s = InputSecret::new_random(&sc, true, &mut rng);
        let bases : [G1Projective; 2] = pp.get_bases().try_into().unwrap();

        let keys = generate_bls_sig_keys(n);
        let skeys = keys.iter().map(|x| &x.private_key).collect::<Vec<&PrivateKey>>();
        let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<PublicKey>>();

        let wait = 0;
        let gen_g = bases[0];
        let dkeys = random_scalars(n, &mut rng);
        let ekeys = dkeys.iter().map(|x| gen_g.mul(x)).collect::<Vec<_>>();

        g.bench_function(BenchmarkId::new(format!("deal-{}", t), n), move |b| {
            b.iter_with_setup(|| {
                let s = InputSecret::new_random(&sc, true, &mut rng);
                let (coms, shares) = gen_coms_shares(&sc, &s, &bases);

                // Computing the commitment digest
                let mut hasher = Sha256::new();
                hasher.update(bcs::to_bytes(&coms).unwrap());
                let root: [u8; 32] = hasher.finalize().into();

                let mut sigs = Vec::with_capacity(n);
                for i in 0..(deg+1) {
                    let sig = Some(skeys[i].sign_arbitrary_message(root.as_slice())).unwrap();
                    sigs.push(sig)
                }
                let params = MixedBLSSenderParams::new(bases, vkeys.clone(), ekeys.clone(), sc.clone(), s.clone() , wait);
                (s, sigs, params)  
        
            }, |(s, sigs, params)| {
                // 1. Cost of sampling the polynomial. 
                InputSecret::new_random(&sc, true, &mut _rng);
                
                // 2. Cost of computing the commitments and shares
                let (coms, shares) = gen_coms_shares(&sc, &s, &bases);

                // 3. Computing the digest of the commitment
                let mut hasher = Sha256::new();
                hasher.update(bcs::to_bytes(&coms).unwrap());
                let root: [u8; 32] = hasher.finalize().into();

                // 4. Verifying the individual ACK signatures
                assert!(sigs.iter().zip(vkeys.iter()).all(|(sig, pk)| sig.verify_arbitrary_msg(&root, pk).is_ok()));

                // 5. Computing the rest of the transcript
                let mut signers = vec![false; n];
                signers.iter_mut().take(deg + 1).for_each(|s| *s = true);
                mixed_bls_acss::get_transcript(&coms, &shares, &signers, &sigs, &params, t);
            })
        });
    }


    #[allow(warnings)]
    pub(crate) fn vss_verify<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        
        let mut rng = thread_rng();
        let deg = 2*t;
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);
        let s = InputSecret::new_random(&sc, true, &mut rng);
        let bases : [G1Projective; 2] = pp.get_bases().try_into().unwrap();

        let keys = generate_bls_sig_keys(n);
        let skeys = keys.iter().map(|x| &x.private_key).collect::<Vec<&PrivateKey>>();
        let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<PublicKey>>();

        let gen_g = bases[0];
        let dkeys = random_scalars(n, &mut rng);
        let ekeys = dkeys.iter().map(|x| gen_g.mul(x)).collect::<Vec<_>>();

        let wait = 0;
        let rcv_params = MixedBLSReceiverParams::new(bases, vkeys.clone(), ekeys.clone(), skeys[0].clone(), 1, sc.clone());
        
        g.bench_function(BenchmarkId::new(format!("verify-{}", t), n), move |b| {
            b.iter_with_setup(|| {
                let s = InputSecret::new_random(&sc, true, &mut rng);
                let (coms, shares) = gen_coms_shares(&sc, &s, &bases);

                // Computing the commitment digest
                let mut hasher = Sha256::new();
                hasher.update(bcs::to_bytes(&coms).unwrap());
                let root: [u8; 32] = hasher.finalize().into();

                let mut signers = vec![false; n];
                let mut sigs = Vec::with_capacity(n);
                for i in 0..(deg+1) {
                    signers[i] = true;
                    let sig = Some(skeys[i].sign_arbitrary_message(root.as_slice())).unwrap();
                    sigs.push(sig)
                }
                let params = MixedBLSSenderParams::new(bases, vkeys.clone(), ekeys.clone(), sc.clone(), s.clone() , wait);

                let trx = mixed_bls_acss::get_transcript(&coms, &shares, &signers, &sigs, &params, t);

                (coms, trx, shares[0], root)
            }, |(coms, trx, share, root)| {
                // 1. Checking the low-degree test and checking correctness of the shares
                assert!(share_verify(0, &coms, &share, &bases, &sc));

                // 2. Computing the signature
                Some(skeys[0].sign_arbitrary_message(root.as_slice())).unwrap();

                // 3. Verify the rest of the transcript
                assert!(mixed_bls_acss::verify_transcript(&coms, &trx, &rcv_params));
            })
        });
    }

}


criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = vss_mixed_group);
criterion_main!(benches);