use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, Absorb};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use criterion::*;
use nexus_nova::{
    circuits::supernova::{NIVCProof, NonUniformCircuit, PublicParams},
    commitment::CommitmentScheme,
    pedersen::{PedersenCommitment, SVDWMap},
    poseidon_config,
};
use pprof::criterion::{Output, PProfProfiler};
use std::{marker::PhantomData, time::Duration};

#[derive(Debug, Default)]
pub struct TestCircuit<F: Field>(PhantomData<F>);

/// The test circuit has two sub-circuits: + 2 and * 2, the selector (0 or 1)
/// decides to apply which circuit in each proving step.
impl<F: PrimeField> NonUniformCircuit<F> for TestCircuit<F> {
    const ARITY: usize = 2;

    const NUM_CIRCUITS: usize = 2;

    fn compute_selector(
        &self,
        _: ConstraintSystemRef<F>,
        _: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        // store selector in the first input var.
        Ok(z[0].clone())
    }

    fn generate_constraints(
        &self,
        _: ConstraintSystemRef<F>,
        pc: u64,
        _: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // alternate between + 2 and * 2
        assert_eq!(z.len(), 2);

        let x = &z[1];

        let y = match pc {
            0 => x + FpVar::constant(2u64.into()),
            1 => x.double()?,
            _ => unreachable!(),
        };

        // update z[0]
        let pc = &z[0];
        let pc_is_zero = pc.is_zero()?;
        let pc_next = pc_is_zero.select(&FpVar::one(), &FpVar::zero())?;

        Ok(vec![pc_next, y])
    }
}

fn nivc_multiple_steps_with_cycle<G1, G2, C1, C2>(c: &mut Criterion)
where
    G1: SWCurveConfig + SVDWMap,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField> + SVDWMap,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: CommitmentScheme<Projective<G1>, SetupAux = [u8]>,
    C2: CommitmentScheme<Projective<G2>, SetupAux = [u8]>,
{
    let ro_config = poseidon_config();

    let circuit = TestCircuit::<G1::ScalarField>(PhantomData);
    let z_0 = vec![G1::ScalarField::ZERO, G1::ScalarField::from(2u64)];
    let num_steps = 5;

    let params = PublicParams::<
        G1,
        G2,
        C1,
        C2,
        PoseidonSponge<G1::ScalarField>,
        TestCircuit<G1::ScalarField>,
    >::setup(ro_config, &circuit)
    .unwrap();

    let mut recursive_snark = NIVCProof::new(&z_0);

    let mut group = c.benchmark_group(format!("nexus-supernova-{num_steps}"));
    group.sample_size(10);

    group.bench_function("Prove", |b| {
        b.iter(|| {
            for _ in 0..num_steps {
                recursive_snark =
                    NIVCProof::prove_step(recursive_snark.clone(), &params, &circuit).unwrap();
            }
        })
    });

    group.bench_function("Verify", |b| {
        b.iter(|| {
            recursive_snark.verify(&params, num_steps).unwrap();
        });
    });
    group.finish();

    assert_eq!(&recursive_snark.z_i()[1], &G1::ScalarField::from(22));
}

fn bench_recursive_snark(c: &mut Criterion) {
    nivc_multiple_steps_with_cycle::<
        ark_pallas::PallasConfig,
        ark_vesta::VestaConfig,
        PedersenCommitment<ark_pallas::PallasConfig>,
        PedersenCommitment<ark_vesta::VestaConfig>,
    >(c);
}

criterion_group! {
    name = recursive_snark;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark,
}

criterion_main!(recursive_snark);
