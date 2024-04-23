use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use nexus_nova::circuits::supernova::NonUniformCircuit;
use rand::{thread_rng, Rng};

#[derive(Debug)]
pub struct SuperCircuit<F: PrimeField>(pub PoseidonConfig<F>);

impl<F: PrimeField> NonUniformCircuit<F> for SuperCircuit<F> {
    const ARITY: usize = 2;
    const NUM_CIRCUITS: usize = 3;

    fn compute_selector(
        &self,
        _: ConstraintSystemRef<F>,
        _: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        // store selector in the first input var.
        // 0 for leaf, 1 for branch, 2 for extension.
        Ok(z[0].clone())
    }

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        pc: u64,
        _: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert_eq!(z.len(), 2);

        let result = match pc {
            0 => Leaf::generate_constraints(cs.clone(), &self.0),
            1 => Branch::generate_constraints(cs.clone(), &self.0),
            2 => Extension::generate_constraints(cs, &self.0),
            _ => unreachable!(),
        };

        // random to decide if next node is branch or extension.
        let selector: u8 = thread_rng().gen_range(1..=2);
        let selector = FpVar::Constant(F::from(selector));

        Ok(vec![selector, result])
    }
}
#[derive(Debug)]
struct Leaf;
impl Leaf {
    fn generate_constraints<F: PrimeField>(
        cs: ConstraintSystemRef<F>,
        params: &PoseidonConfig<F>,
    ) -> FpVar<F> {
        let vars = thread_rng().gen::<[u8; 30]>().map(F::from);
        rand_poseidon(cs, params, vars.to_vec())
    }
}

#[derive(Debug)]
struct Branch;
impl Branch {
    fn generate_constraints<F: PrimeField>(
        cs: ConstraintSystemRef<F>,
        params: &PoseidonConfig<F>,
    ) -> FpVar<F> {
        let vars = thread_rng().gen::<[u64; 20]>().map(F::from);
        rand_poseidon(cs, params, vars.to_vec())
    }
}

#[derive(Debug)]
struct Extension;
impl Extension {
    fn generate_constraints<F: PrimeField>(
        cs: ConstraintSystemRef<F>,
        params: &PoseidonConfig<F>,
    ) -> FpVar<F> {
        let vars = thread_rng().gen::<[u64; 10]>().map(F::from);
        rand_poseidon(cs, params, vars.to_vec())
    }
}

fn rand_poseidon<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    params: &PoseidonConfig<F>,
    vars: Vec<F>,
) -> FpVar<F> {
    let mut poseidon = PoseidonSpongeVar::<F>::new(cs, params);
    for v in vars {
        poseidon.absorb(&FpVar::Constant(v)).unwrap();
    }

    let mut result = poseidon.squeeze_field_elements(1).unwrap();
    assert_eq!(result.len(), 1);

    result.pop().unwrap()
}
