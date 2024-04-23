use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use nexus_nova::circuits::supernova::NonUniformCircuit;

#[derive(Debug)]
pub struct TestCircuit<F: PrimeField>(pub PoseidonConfig<F>);

impl<F: PrimeField> NonUniformCircuit<F> for TestCircuit<F> {
    const ARITY: usize = 1;
    const NUM_CIRCUITS: usize = 1;

    fn compute_selector(
        &self,
        _: ConstraintSystemRef<F>,
        _: &FpVar<F>,
        _: &[FpVar<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        Ok(FpVar::constant(F::ZERO))
    }

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _: u64,
        _: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert_eq!(z.len(), 1);

        let mut poseidon = PoseidonSpongeVar::<F>::new(cs, &self.0);
        poseidon.absorb(&z[0]).unwrap();
        let new_z = poseidon.squeeze_field_elements(1).unwrap();
        assert_eq!(new_z.len(), 1);

        Ok(new_z)
    }
}
