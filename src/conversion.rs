use ark_circom::CircomCircuit;
use ark_ff::{Field, PrimeField};
use bulletproofs::circuit::types::{Circuit, Witness};

/// Converts a Circom R1CS circuit to Bulletproofs format with power-of-2 padding
/// 
/// Transforms R1CS constraints A·w ⊙ B·w = C·w into bulletproof weight matrices.
/// The circuit and witness are automatically padded to the next power of 2.
pub fn circom_to_bulletproofs<Fr: Field + PrimeField>(
    circom_circuit: &CircomCircuit<Fr>,
) -> Result<(Circuit<Fr>, Witness<Fr>), ConversionError> {
    let r1cs = &circom_circuit.r1cs;
    let witness_values = circom_circuit.witness.as_ref()
        .ok_or(ConversionError::MissingWitness)?;
    
    let constraints_count = r1cs.constraints.len();
    let variables_count = r1cs.num_variables;
    
    if variables_count == 0 || constraints_count == 0 {
        return Err(ConversionError::EmptyCircuit);
    }
    
    // Bulletproofs requires power-of-2 dimensions
    let padded_variables_count = variables_count.next_power_of_two();
    
    // Initialize bulletproof constraint matrices with power-of-2 padding
    let zero_row = vec![Fr::zero(); padded_variables_count];
    let mut w_l = vec![zero_row.clone(); constraints_count];
    let mut w_r = vec![zero_row.clone(); constraints_count];
    let mut w_o = vec![zero_row.clone(); constraints_count];
    let w_v = vec![zero_row; constraints_count];
    let c = vec![Fr::zero(); constraints_count];
    
    // Map R1CS constraints to bulletproof weight matrices
    for (i, (a_coeffs, b_coeffs, c_coeffs)) in r1cs.constraints.iter().enumerate() {
        // A -> w_l, B -> w_r, -C -> w_o (negated to move to LHS)
        for &(var_idx, coeff) in a_coeffs {
            if var_idx < padded_variables_count {
                w_l[i][var_idx] = coeff;
            }
        }
        for &(var_idx, coeff) in b_coeffs {
            if var_idx < padded_variables_count {
                w_r[i][var_idx] = coeff;
            }
        }
        for &(var_idx, coeff) in c_coeffs {
            if var_idx < padded_variables_count {
                w_o[i][var_idx] = -coeff;
            }
        }
    }
    
    // Extract and pad witness values
    let mut witness = if let Some(wire_mapping) = &r1cs.wire_mapping {
        wire_mapping.iter()
            .take(variables_count)
            .map(|&idx| witness_values.get(idx).copied().unwrap_or(Fr::zero()))
            .collect::<Vec<_>>()
    } else {
        witness_values[..variables_count].to_vec()
    };
    witness.resize(padded_variables_count, Fr::zero());
    
    let circuit = Circuit::new(w_l, w_r, w_o, w_v, c);
    let bp_witness = Witness {
        a_l: vec![Fr::zero(); padded_variables_count],
        a_r: vec![Fr::zero(); padded_variables_count],
        a_o: vec![Fr::zero(); padded_variables_count],
        v: witness,
        gamma: vec![Fr::zero(); padded_variables_count],
    };
    
    Ok((circuit, bp_witness))
}

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Circuit witness is missing")]
    MissingWitness,
    #[error("Circuit is empty")]
    EmptyCircuit,
}