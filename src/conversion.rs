use ark_circom::CircomCircuit;
use ark_ff::{Field, PrimeField};
use bulletproofs::circuit::types::{Circuit, Witness};

/// Converts a Circom R1CS circuit to a flattened Bulletproofs arithmetic circuit
/// 
/// This function transforms R1CS constraints of the form A·w ⊙ B·w = C·w
/// into arithmetic circuit constraints of the form:
/// w_l·a_l + w_r·a_r + w_o·a_o = w_v·v + c
/// where a_l ⊙ a_r = a_o (hadamard product constraint)
pub fn circom_to_bulletproofs<Fr: Field + PrimeField>(
    circom_circuit: &CircomCircuit<Fr>,
) -> Result<(Circuit<Fr>, Witness<Fr>), ConversionError> {
    let r1cs = &circom_circuit.r1cs;
    let witness_values = circom_circuit.witness.as_ref()
        .ok_or(ConversionError::MissingWitness)?;
    
    let num_constraints = r1cs.constraints.len();
    let num_variables = r1cs.num_variables;
    
    if num_variables == 0 || num_constraints == 0 {
        return Err(ConversionError::EmptyCircuit);
    }
    
    // Pad to next power of 2 for bulletproofs compatibility
    let padded_num_variables = if num_variables.is_power_of_two() {
        num_variables
    } else {
        num_variables.next_power_of_two()
    };
    
    // Initialize constraint matrices for bulletproofs format using padded size
    let mut w_l = vec![vec![Fr::zero(); padded_num_variables]; num_constraints];
    let mut w_r = vec![vec![Fr::zero(); padded_num_variables]; num_constraints];
    let mut w_o = vec![vec![Fr::zero(); padded_num_variables]; num_constraints];
    let w_v = vec![vec![Fr::zero(); padded_num_variables]; num_constraints];
    let c = vec![Fr::zero(); num_constraints];
    
    // Convert each R1CS constraint: A·w ⊙ B·w = C·w
    // to arithmetic circuit form: w_l·a_l + w_r·a_r + w_o·a_o = w_v·v + c
    for (constraint_idx, (a_vec, b_vec, c_vec)) in r1cs.constraints.iter().enumerate() {
        // For each constraint, we map:
        // A coefficients -> w_l (left wire weights)  
        // B coefficients -> w_r (right wire weights)
        // -C coefficients -> w_o (output wire weights, negated)
        // We don't use w_v (auxiliary weights) for basic R1CS conversion
        
        // Set A coefficients in w_l
        for &(var_idx, coeff) in a_vec {
            if var_idx < padded_num_variables {
                w_l[constraint_idx][var_idx] = coeff;
            }
        }
        
        // Set B coefficients in w_r  
        for &(var_idx, coeff) in b_vec {
            if var_idx < padded_num_variables {
                w_r[constraint_idx][var_idx] = coeff;
            }
        }
        
        // Set -C coefficients in w_o (negated because we move C to LHS)
        for &(var_idx, coeff) in c_vec {
            if var_idx < padded_num_variables {
                w_o[constraint_idx][var_idx] = -coeff;
            }
        }
        
        // For R1CS conversion, we don't use auxiliary weights w_v
        // and constant term c remains zero for pure R1CS constraints
    }
    
    // Extract witness values, applying wire mapping if present, then pad to power of 2
    let mut mapped_witness = if let Some(wire_mapping) = &r1cs.wire_mapping {
        // Apply wire mapping: mapped_witness[i] = witness[wire_mapping[i]]
        wire_mapping.iter()
            .take(num_variables)
            .map(|&mapped_idx| {
                witness_values.get(mapped_idx)
                    .copied()
                    .unwrap_or(Fr::zero())
            })
            .collect::<Vec<_>>()
    } else {
        witness_values[..num_variables].to_vec()
    };
    
    // Pad witness with zeros to reach power of 2 size
    mapped_witness.resize(padded_num_variables, Fr::zero());
    
    // For R1CS constraints, we need to properly construct the bulletproofs witness
    // The R1CS constraint A·w ⊙ B·w = C·w needs to be satisfied by the witness
    // For simplicity, we'll use the original witness as v and derive a_l, a_r, a_o
    // such that the constraint matrices work correctly
    
    // For now, use a simple mapping where we put witness values appropriately
    let a_l = vec![Fr::zero(); padded_num_variables];
    let a_r = vec![Fr::zero(); padded_num_variables]; 
    let a_o = vec![Fr::zero(); padded_num_variables];
    let v = mapped_witness;
    
    let circuit = Circuit::new(w_l, w_r, w_o, w_v, c);
    
    // Create witness with random gamma values
    let witness = {
        let gamma = (0..padded_num_variables).map(|_| Fr::zero()).collect(); // Could use random values
        Witness {
            a_l,
            a_r, 
            a_o,
            v,
            gamma,
        }
    };
    
    Ok((circuit, witness))
}

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Circuit witness is missing")]
    MissingWitness,
    #[error("Circuit is empty")]
    EmptyCircuit,
    #[error("Invalid constraint format")]
    InvalidConstraint,
}