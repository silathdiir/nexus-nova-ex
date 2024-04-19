use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use generic_array::typenum::U1;
use ms_nova::traits::circuit::StepCircuit;
use neptune::{
    circuit::{poseidon_hash_circuit, CircuitType},
    poseidon::PoseidonConstants,
};

#[derive(Clone, Debug, Default)]
pub struct TestCircuit<F: PrimeField>(PoseidonConstants<F, U1>);

impl<F: PrimeField> TestCircuit<F> {
    pub fn new() -> Self {
        let constants = PoseidonConstants::new();

        Self(constants)
    }
}
impl<F: PrimeField> StepCircuit<F> for TestCircuit<F> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(z.len(), 1);

        let hash_output = poseidon_hash_circuit(
            cs,
            CircuitType::Legacy,
            z.to_vec(),
            &self.0,
        )?;

        Ok(vec![hash_output])
    }
}
