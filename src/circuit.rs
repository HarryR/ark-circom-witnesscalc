// We avoid the circom-compat crate, and copy necessary parts directly
// This avoids building the full arkworks-rs/circom-compat package
// Because it depends on wasix & this borks with WASM builds...
// From https://github.com/arkworks-rs/circom-compat/blame/3c95ed98e23a408b4d99a53e483a9bba39685a4e/src/circom/circuit.rs

use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

use ark_ff::PrimeField;

use super::r1cs_reader::R1CS;

use anyhow::Result;

#[derive(Clone, Debug)]
pub struct CircomCircuit<F: PrimeField> {
    pub r1cs: R1CS<F>,
    pub witness: Option<Vec<F>>,
}

impl<F: PrimeField> CircomCircuit<F> {
    pub fn get_public_inputs(&self) -> Option<Vec<F>> {
        match &self.witness {
            None => None,
            Some(w) => match &self.r1cs.wire_mapping {
                None => Some(w[1..self.r1cs.num_inputs].to_vec()),
                Some(m) => Some(m[1..self.r1cs.num_inputs].iter().map(|i| w[*i]).collect()),
            },
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CircomCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let witness = &self.witness;
        let wire_mapping = &self.r1cs.wire_mapping;

        // Start from 1 because Arkworks implicitly allocates One for the first input
        for i in 1..self.r1cs.num_inputs {
            cs.new_input_variable(|| {
                Ok(match witness {
                    None => F::from(1u32),
                    Some(w) => match wire_mapping {
                        Some(m) => w[m[i]],
                        None => w[i],
                    },
                })
            })?;
        }

        for i in 0..self.r1cs.num_aux {
            cs.new_witness_variable(|| {
                Ok(match witness {
                    None => F::from(1u32),
                    Some(w) => match wire_mapping {
                        Some(m) => w[m[i + self.r1cs.num_inputs]],
                        None => w[i + self.r1cs.num_inputs],
                    },
                })
            })?;
        }

        let make_index = |index| {
            if index < self.r1cs.num_inputs {
                Variable::Instance(index)
            } else {
                Variable::Witness(index - self.r1cs.num_inputs)
            }
        };
        let make_lc = |lc_data: &[(usize, F)]| {
            lc_data.iter().fold(
                LinearCombination::<F>::zero(),
                |lc: LinearCombination<F>, (index, coeff)| lc + (*coeff, make_index(*index)),
            )
        };

        for constraint in &self.r1cs.constraints {
            cs.enforce_constraint(
                make_lc(&constraint.0),
                make_lc(&constraint.1),
                make_lc(&constraint.2),
            )?;
        }

        Ok(())
    }
}
