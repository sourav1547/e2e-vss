use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::Measurement, Throughput};

pub fn vss_yurek_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("yurek");
    
    let ts = [21, 42, 85, 170, 341];
    let ns = [64, 128, 256, 512, 1024];

    for (&t, &n) in ts.iter().zip(ns.iter()) {
        yurek_acss::vss_deal(t, n, &mut group);
        yurek_acss::vss_verify(t, n, &mut group);
    }

    group.finish();
}

mod yurek_acss {
    use super::*;
    use rand::thread_rng;
    use std::ops::Mul;
    use acss::random_scalar;
    use acss::vss::common::{gen_coms_shares, low_deg_test};
    use acss::vss::yurek_acss::{YurekSenderParams, self};
    use acss::{pvss::SharingConfiguration, random_scalars};
    use acss::vss::keys::InputSecret;
    use acss::vss::public_parameters::PublicParameters;
    use blstrs::G1Projective;
    use sha2::{Digest, Sha256};

    #[allow(warnings)]
    pub(crate) fn vss_deal<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        g.throughput(Throughput::Elements(n as u64));

        let deg = t;
        let mut rng = thread_rng();
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);
        let bases:[G1Projective; 2] = pp.get_bases().try_into().unwrap();

        let gen_g = bases[0];
        let dkeys = random_scalars(n, &mut rng);
        let eks = dkeys.iter().map(|x| gen_g.mul(x)).collect::<Vec<G1Projective>>();
        
        g.bench_function(BenchmarkId::new(format!("deal-{}", t), n), move |b| {
            b.iter_with_setup(|| {
                let sc_clone = sc.clone(); 
                let eks_clone = eks.clone();

                (sc_clone, eks_clone)
            }, |(sc, eks)| {
                // 1. Samplign the secret
                let s = InputSecret::new_random(&sc, true, &mut rng);
                
                // 2. Computing the commitments and shares
                let (coms, shares) = gen_coms_shares(&sc, &s, &bases);

                // 3. Computing the public key encryptions
                let trx = {
                    let dk = random_scalar(&mut rng);
                    let params = YurekSenderParams{sc, s, bases, eks};
                    yurek_acss::get_transcript(coms, &shares, dk, params)
                };
            })
        });
    }

    #[allow(warnings)]
    pub(crate) fn vss_verify<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        g.throughput(Throughput::Elements(n as u64));

        let mut rng = thread_rng();
        let deg = t;
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);

        let bases:[G1Projective; 2] = pp.get_bases().try_into().unwrap();
        let gen_g = bases[0];
        let dkeys = random_scalars(n, &mut rng);
        let eks = dkeys.iter().map(|x| gen_g.mul(x)).collect::<Vec<G1Projective>>();
        
        g.bench_function(BenchmarkId::new(format!("verify-{}", t), n), move |b| {
            b.iter_with_setup(|| {
                let s = InputSecret::new_random(&sc, true, &mut rng);
                let (coms, shares) = gen_coms_shares(&sc, &s, &bases);
                let trx = {
                    let dk = random_scalar(&mut rng);
                    let params = YurekSenderParams{sc: sc.clone(), s, bases, eks: eks.clone()};
                    yurek_acss::get_transcript(coms, &shares, dk, params)
                };

                (trx, shares[0])
            }, |(trx, share)| {
                //1. Checking received share is correct
                let e_com = G1Projective::multi_exp(&bases, &share.get());
                assert!(e_com.eq(&trx.coms[0]));
                
                // 2. Low-degree test of the commitment
                assert!(low_deg_test(&trx.coms, &sc));

                // 3. Computing the digest of the coms vector, needed for RBC
                let mut hasher = Sha256::new();
                hasher.update(bcs::to_bytes(&trx.coms).unwrap());
                let root: [u8; 32] = hasher.finalize().into();
            })
        });
    }
}


criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    //config = Criterion::default();
    targets = vss_yurek_group);
criterion_main!(benches);