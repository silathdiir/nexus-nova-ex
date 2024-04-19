use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ec::CurveConfig;
use ark_ff::AdditiveGroup;
use criterion::*;
use nexus_nova::{
    circuits::nova::sequential::{IVCProof, PublicParams},
    pedersen::PedersenCommitment,
    poseidon_config,
};
use nexus_nova_ex::novas::nexus::TestCircuit;
use std::time::Instant;

type G1 = ark_pallas::PallasConfig;
type G2 = ark_vesta::VestaConfig;
type C1 = PedersenCommitment<ark_pallas::Projective>;
type C2 = PedersenCommitment<ark_vesta::Projective>;
type F = <G1 as CurveConfig>::ScalarField;

const BENCHMARK_SAMPLE_SIZE: usize = 20;
const INIT_VALUE: F = F::ZERO;

/// The number of recursive steps before the last
const WARMUP_STEP_NUM: usize = 10;

fn benchmark(c: &mut Criterion) {
    let poseidon_conf = poseidon_config();
    let circuit = TestCircuit::<F>(poseidon_conf.clone());

    let params = PublicParams::<
        G1,
        G2,
        C1,
        C2,
        PoseidonSponge<F>,
        TestCircuit<F>,
    >::setup(poseidon_conf, &circuit, &(), &())
    .unwrap();

    let z_0 = vec![INIT_VALUE];
    let mut recursive_snark = IVCProof::new(&z_0);

    // We only bench for the last step, the first steps are cheaper.
    let now = Instant::now();
    for i in 0..WARMUP_STEP_NUM {
        recursive_snark =
            IVCProof::prove_step(recursive_snark, &params, &circuit).unwrap();
        recursive_snark.verify(&params, i + 1).unwrap();
    }
    println!("Finish warmup steps, elapsed: {:?}", now.elapsed());

    let mut group =
        c.benchmark_group(format!("nexus-nova-{}", WARMUP_STEP_NUM + 1));
    group.sample_size(BENCHMARK_SAMPLE_SIZE);

    group.bench_function("Prove", |b| {
        b.iter(|| {
            IVCProof::prove_step(
                black_box(recursive_snark.clone()),
                black_box(&params),
                black_box(&circuit),
            )
            .unwrap();
        })
    });

    group.bench_function("Verify", |b| {
        b.iter(|| {
            black_box(&recursive_snark)
                .verify(black_box(&params), black_box(WARMUP_STEP_NUM))
                .unwrap();
        });
    });

    group.finish();
}

criterion_group! {
    name = nexus_nova;
    config = Criterion::default();
    targets = benchmark,
}

criterion_main!(nexus_nova);
