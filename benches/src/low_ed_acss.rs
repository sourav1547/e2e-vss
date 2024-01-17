use criterion::{criterion_main, criterion_group};
use criterion::{BenchmarkGroup, BenchmarkId, Criterion, measurement::Measurement, Throughput};

pub fn vss_low_ed_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("low-ed");

    let ts = [85, 170, 341];
    let ns= [256, 512, 1024];

    for (&t, &n) in ts.iter().zip(ns.iter()) {
        low_ed_acss::vss_deal(t, n, &mut group);
        low_ed_acss::vss_verify(t, n, &mut group);
    }

    group.finish();
}


mod low_ed_acss {
    use super::*;
    use rand::thread_rng;
    use acss::pvss::SharingConfiguration;
    use acss::vss::common::{generate_ed_sig_keys, gen_coms_shares, share_verify};
    use acss::vss::keys::InputSecret;
    use acss::vss::low_ed_acss;
    use aptos_crypto::Signature;
    use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use acss::vss::public_parameters::PublicParameters;
    use blstrs::G1Projective;
    use sha2::{Digest, Sha256};
    

    #[allow(warnings)]
    pub(crate) fn vss_deal<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        let mut rng = thread_rng();
        let mut _rng = thread_rng();

        g.throughput(Throughput::Elements(n as u64));

        let deg = 2*t;
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);
        let bases: [G1Projective; 2] = pp.get_bases().try_into().unwrap();
        
        let keys = generate_ed_sig_keys(n);
        let skeys = keys.iter().map(|x| &x.private_key).collect::<Vec<&Ed25519PrivateKey>>();
        let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<Ed25519PublicKey>>();
        

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
                (s, sigs)
        
            }, |(s, sigs)| {
                // 1. Cost of sampling the polynomial.
                InputSecret::new_random(&sc, true, &mut _rng);
                
                // 2. Cost of computing the commitments and shares
                let (coms, shares) = gen_coms_shares(&sc, &s, &bases);

                // 3. Computing the digest of the commitment
                let mut hasher = Sha256::new();
                hasher.update(bcs::to_bytes(&coms).unwrap());
                let root: [u8; 32] = hasher.finalize().into();

                // 4. Verifying the individual ACK signatures
                for (sig, pk) in sigs.iter().zip(vkeys.iter()) {
                    assert!(sig.verify_arbitrary_msg(&root, pk).is_ok());
                }

                // 4. Computing the rest of the transcript
                let mut signers = vec![false; n];
                for i in 0..(deg+1) {
                    signers[i] = true;
                }
                low_ed_acss::get_transcript(&shares, &signers, sigs);
            })
        });
    }


    pub(crate) fn vss_verify<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        let mut rng = thread_rng();

        g.throughput(Throughput::Elements(n as u64));

        let deg = 2*t;
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);
        let bases: &[G1Projective; 2] = pp.get_bases().try_into().unwrap();

        let keys = generate_ed_sig_keys(n);
        let skeys = keys.iter().map(|x| &x.private_key).collect::<Vec<&Ed25519PrivateKey>>();
        let vkeys = keys.iter().map(|x| x.public_key.clone()).collect::<Vec<Ed25519PublicKey>>();

            
        
        g.bench_function(BenchmarkId::new(format!("verify-{}", t), n), move |b| {
            b.iter_with_setup(|| {
                let s = InputSecret::new_random(&sc, true, &mut rng);
                let (coms, shares) = gen_coms_shares(&sc, &s, bases);

                // Computing the commitment digest
                let mut hasher = Sha256::new();
                hasher.update(bcs::to_bytes(&coms).unwrap());
                let root: [u8; 32] = hasher.finalize().into();

                // Computing the rest of the transcript
                let mut signers = vec![false; n];
                let mut sigs = Vec::with_capacity(n);
                for i in 0..(deg+1) {
                    signers[i] = true;
                    let sig = Some(skeys[i].sign_arbitrary_message(root.as_slice())).unwrap();
                    sigs.push(sig);
                }
                let trx = low_ed_acss::get_transcript(&shares, &signers, sigs);

                (coms, shares[0], trx)
            }, |(coms, share, trx)| {
                // 1. Checking the low-degree test and checking correctness of the shares
                assert!(share_verify(0, &coms, &share, &bases, &sc));

                // 2. Computing the digest of the coms vector
                let mut hasher = Sha256::new();
                hasher.update(bcs::to_bytes(&coms).unwrap());
                let root: [u8; 32] = hasher.finalize().into();

                // 3. Computing the signature
                Some(skeys[0].sign_arbitrary_message(root.as_slice())).unwrap();

                // 4. Verifying the broadcast transcript
                assert!(low_ed_acss::verify_transcript(&coms, &trx, &sc, &bases, &vkeys)); 
            })
        });
    }
}


criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    //config = Criterion::default();
    targets = vss_low_ed_group);
criterion_main!(benches);