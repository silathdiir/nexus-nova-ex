use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_ec::CurveConfig;
use ark_ff::AdditiveGroup;
use criterion::*;
use nexus_nova::{
    circuits::supernova::{NIVCProof, PublicParams},
    pedersen::PedersenCommitment,
    poseidon_config,
};
use nexus_nova_ex::novas::nexus_super::arity_tree::SuperCircuit;
use std::time::{Duration, Instant};

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
    let circuit = SuperCircuit::<F>(poseidon_conf.clone());

    let params = PublicParams::<
        G1,
        G2,
        C1,
        C2,
        PoseidonSponge<F>,
        SuperCircuit<F>,
    >::setup(poseidon_conf, &circuit, &(), &())
    .unwrap();

    let z_0 = vec![INIT_VALUE; 2];
    let mut recursive_snark = NIVCProof::new(&z_0);

    // We only bench for the last step, the first steps are cheaper.
    let now = Instant::now();
    for _ in 0..WARMUP_STEP_NUM {
        recursive_snark =
            NIVCProof::prove_step(recursive_snark, &params, &circuit).unwrap();
    }
    println!("Finish warmup steps, elapsed: {:?}", now.elapsed());

    let mut group = c.benchmark_group(format!(
        "nexus-supernova-arity-tree-{}",
        WARMUP_STEP_NUM + 1
    ));
    group.sample_size(BENCHMARK_SAMPLE_SIZE);

    group.bench_function("Prove", |b| {
        b.iter(|| {
            NIVCProof::prove_step(
                black_box(recursive_snark.clone()),
                black_box(&params),
                black_box(&circuit),
            )
            .unwrap();
        })
    });

    group.finish();
}

criterion_group! {
    name = nexus_super_nova_arity_tree;
    config = Criterion::default().measurement_time(Duration::from_secs(15)).warm_up_time(Duration::from_secs(15));
    targets = benchmark,
}

criterion_main!(nexus_super_nova_arity_tree);
