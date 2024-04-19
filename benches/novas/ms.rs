use criterion::*;
use ff::Field;
use ms_nova::{
    provider::{PallasEngine, VestaEngine},
    traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
    PublicParams, RecursiveSNARK,
};
use nexus_nova_ex::novas::ms::TestCircuit;
use std::time::Instant;

type G1 = PallasEngine;
type G2 = VestaEngine;
type F1 = <G1 as Engine>::Scalar;
type F2 = <G2 as Engine>::Scalar;
type C1 = TestCircuit<F1>;
type C2 = TrivialCircuit<F2>;

const BENCHMARK_SAMPLE_SIZE: usize = 20;
const INIT_VALUE: F1 = F1::ZERO;

/// The number of recursive steps before the last
const WARMUP_STEP_NUM: usize = 10;

fn benchmark(c: &mut Criterion) {
    let c1 = TestCircuit::new();
    let c2 = TrivialCircuit::default();

    let pp = PublicParams::<G1, G2, C1, C2>::setup(
        &c1,
        &c2,
        &*default_ck_hint(),
        &*default_ck_hint(),
    )
    .unwrap();

    let mut recursive_snark: RecursiveSNARK<G1, G2, C1, C2> =
        RecursiveSNARK::new(&pp, &c1, &c2, &[INIT_VALUE], &[F2::ZERO]).unwrap();

    // We only bench for the last step, the first steps are cheaper.
    let now = Instant::now();
    for i in 0..WARMUP_STEP_NUM {
        recursive_snark.prove_step(&pp, &c1, &c2).unwrap();
        recursive_snark
            .verify(&pp, i + 1, &[INIT_VALUE], &[F2::ZERO])
            .unwrap();
    }
    println!("Finish warmup steps, elapsed: {:?}", now.elapsed());

    let mut group =
        c.benchmark_group(format!("ms-nova-{}", WARMUP_STEP_NUM + 1));
    group.sample_size(BENCHMARK_SAMPLE_SIZE);

    group.bench_function("Prove", |b| {
        b.iter(|| {
            black_box(&mut recursive_snark.clone())
                .prove_step(black_box(&pp), black_box(&c1), black_box(&c2))
                .unwrap();
        })
    });

    group.bench_function("Verify", |b| {
        b.iter(|| {
            black_box(&recursive_snark)
                .verify(
                    black_box(&pp),
                    black_box(WARMUP_STEP_NUM),
                    black_box(&[INIT_VALUE]),
                    black_box(&[F2::ZERO]),
                )
                .unwrap();
        });
    });

    group.finish();
}

criterion_group! {
    name = ms_nova;
    config = Criterion::default();
    targets = benchmark,
}

criterion_main!(ms_nova);
