use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::Measurement, Throughput};



pub fn vss_groth_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("groth");
    
    let ts = [21, 42, 85, 170, 341];
    let ns = [64, 128, 256, 512, 1024];

    for (&t, &n) in ts.iter().zip(ns.iter()) {
        groth_ni_acss::vss_deal(t, n, &mut group);
        groth_ni_acss::vss_verify(t, n, &mut group);
    }

    group.finish();
}

mod groth_ni_acss {
    use super::*;
    use rand::thread_rng;
    use std::ops::Mul;
    use acss::{vss::{public_parameters::PublicParameters, keys::InputSecret, groth_ni_acss::{GrothSenderParams, self, GrothReceiverParams}}, pvss::SharingConfiguration, random_scalars};
    use blstrs::G1Projective;
    use acss::vss::ni_vss::encryption::dec_chunks;

    #[allow(warnings)]
    pub(crate) fn vss_deal<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        g.throughput(Throughput::Elements(n as u64));

        let mut rng = thread_rng();
        let mut _rng = thread_rng();
        let deg = t;
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);
        let bases: [G1Projective; 2] = pp.get_bases().try_into().unwrap();
        
        let gen_g = bases[0];
        let dkeys = random_scalars(n, &mut rng);
        let eks = dkeys.iter().map(|x| gen_g.mul(x)).collect::<Vec<_>>();

        g.bench_function(BenchmarkId::new(format!("deal-{}", deg), n), move |b| {
            b.iter_with_setup(|| {
                let s = InputSecret::new_random(&sc, true, &mut rng);
                GrothSenderParams::new(sc.clone(), s, bases, eks.clone())
            }, |params| {
                // 1. Place holder to measure the cost of sampling a polynomial
                InputSecret::new_random(&sc, true, &mut _rng);

                // 2. Generatign the Groth-VSS transcript
                groth_ni_acss::get_transcript(&params);
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
        let bases: [G1Projective; 2] = pp.get_bases().try_into().unwrap();
        
        let gen_g = bases[0];
        let dkeys = random_scalars(n, &mut rng);
        let eks = dkeys.iter().map(|x| gen_g.mul(x)).collect::<Vec<_>>();
        
        let rcv_params = GrothReceiverParams::new(bases, eks.clone(), 0, dkeys[0], sc.clone());
        
        g.bench_function(BenchmarkId::new(format!("verify-{}", t), n), move |b| {
            b.iter_with_setup(|| {
                let s = InputSecret::new_random(&sc, true, &mut rng);
                let params = GrothSenderParams::new(sc.clone(), s, bases, eks.clone());    
                groth_ni_acss::get_transcript(&params)

            }, |trx| {
                // 1. To verify the transcript
                assert!(groth_ni_acss::verify_transcript(&trx, &rcv_params));

                // 2. To decrypt its share
                // FIXME: Right now, we are only decrypting the share and not the randomness. 
                // decrypting the randomness will infact increase the verifier's time. But, since
                // this is a baseline, it is okay, as we are favoring the baseline.
                dec_chunks(&trx.t_ve.ciphertext, dkeys[0], 0);
            })
        });
    }
}


criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = vss_groth_group);
criterion_main!(benches);