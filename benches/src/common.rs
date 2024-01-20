use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::Measurement, Throughput};


pub fn common_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("common");
    
    let ts = [21, 42, 85, 170, 341];
    // let ts = [42, 84, 170, 340, 682];
    let ns = [64, 128, 256, 512, 1024];

    for (&t, &n) in ts.iter().zip(ns.iter()) {
        common::vss_recon(t, n, &mut group);
        common::vss_low_deg_test(t, n, &mut group);
    }

    group.finish();
}

mod common {
    use super::*;
    use rand::thread_rng;
    use std::ops::Mul;
    use acss::vss::common::{gen_coms_shares, low_deg_test};
    use acss::{pvss::SharingConfiguration, random_scalars};
    use acss::vss::keys::InputSecret;
    use acss::vss::public_parameters::PublicParameters;
    use acss::vss::recon::reconstruct;
    use blstrs::G1Projective;
    use rand::seq::IteratorRandom;

    #[allow(warnings)]
    pub(crate) fn vss_recon<M: Measurement>(t: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        g.throughput(Throughput::Elements(n as u64));

        let mut rng = thread_rng();
        let deg = t;
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);

        let bases:[G1Projective; 2] = pp.get_bases().try_into().unwrap();
        let gen_g = bases[0];
        let dkeys = random_scalars(n, &mut rng);
        let eks = dkeys.iter().map(|x| gen_g.mul(x)).collect::<Vec<G1Projective>>();


        g.bench_function(BenchmarkId::new(format!("recon-{}", t), n), move |b| {
            b.iter_with_setup(|| {
                
                let s = InputSecret::new_random(&sc, true, &mut rng);
                let secret = s.get_secret_a();
                let (coms, shares) = gen_coms_shares(&sc, &s, &bases);
                
                let mut players : Vec<usize> = (0..n)
                .choose_multiple(&mut rng, deg+1)
                .into_iter().collect::<Vec<usize>>();
                players.sort();

                (secret, coms, shares, players)

            }, |(secret, coms, shares, players)| {
                // 1. Validating the shares
                let mut valid_shares = Vec::with_capacity(deg+1);
                for i in 0..(deg+1) {
                    let share = shares[players[i]];
                    let com: G1Projective = coms[players[i]];
                    let e_com = G1Projective::multi_exp(&bases, share.get());
                    assert!(com.eq(&e_com));
                    valid_shares.push(share);
                }

                // 2. Lagrange interpolation
                let (recon_secret, _) = reconstruct(&valid_shares, &players, n);
                assert!(secret == recon_secret);
            })
        });
    }

    #[allow(warnings)]
    pub(crate) fn vss_low_deg_test<M: Measurement>(deg: usize, n: usize, g: &mut BenchmarkGroup<M>) {
        g.throughput(Throughput::Elements(n as u64));

        let mut rng = thread_rng();
        let pp = PublicParameters::default();
        let sc = SharingConfiguration::new(deg+1, n);
        let bases:[G1Projective; 2] = pp.get_bases().try_into().unwrap();

        g.bench_function(BenchmarkId::new(format!("low-deg-test-{}", deg), n), move |b| {
            b.iter_with_setup(|| {
                let s = InputSecret::new_random(&sc, true, &mut rng);
                let (coms, _) = gen_coms_shares(&sc, &s, &bases);
                coms
            }, |coms| {
                assert!(low_deg_test(&coms, &sc));
            })
        });
    }

}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = common_group);
criterion_main!(benches);