use ark_circom::{CircomBuilder, CircomConfig};
use ark_bn254::{Fr, G1Projective};
use bulletproofs::circuit::{
    CircuitProofDomainSeparator, prove as circuit_prove, verify as circuit_verify,
    types::{CRS as CircuitCRS, Statement as CircuitStatement}
};
use rand::rngs::OsRng;
use serde_json::{Map, Value};
use spongefish::{DomainSeparator, codecs::arkworks_algebra::CommonGroupToUnit};
mod conversion;
use conversion::circom_to_bulletproofs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get circuit name from command line arguments
    let args: Vec<String> = std::env::args().collect();
    let circuit_name = if args.len() > 1 {
        &args[1]
    } else {
        return Err("Usage: cargo run <circuit_name>".into());
    };
    
    // Load circuit files
    let wasm_path = format!("./circuits/{}_js/{}.wasm", circuit_name, circuit_name);
    let r1cs_path = format!("./circuits/{}.r1cs", circuit_name);
    let inputs_path = format!("./circuits/{}_inputs.json", circuit_name);
    
    let config = CircomConfig::<Fr>::new(&wasm_path, &r1cs_path)?;
    let mut builder = CircomBuilder::new(config);
    
    // Load inputs from JSON file
    let inputs_json = std::fs::read_to_string(&inputs_path)?;
    let inputs: Map<String, Value> = serde_json::from_str(&inputs_json)?;
    
    // Add all inputs to the circuit builder
    for (key, value) in inputs {
        let input_value = match value {
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    i
                } else if let Some(u) = n.as_u64() {
                    u as i64
                } else {
                    return Err(format!("Invalid number format for input '{}'", key).into());
                }
            }
            _ => return Err(format!("Input '{}' must be a number", key).into()),
        };
        builder.push_input(&key, input_value);
    }
    
    let circom = builder.build()?;
    if circom.witness.is_none() {
        return Err("Witness generation failed".into());
    }
    
    println!("Generated witness with {} values", circom.witness.as_ref().unwrap().len());
    
    // Convert to bulletproofs format with power-of-2 padding
    let (circuit, witness) = circom_to_bulletproofs(&circom)?;
    println!("Bulletproof circuit: {} constraints, {} variables", circuit.size(), circuit.dim());
    
    if !circuit.is_satisfied_by(&witness) {
        return Err("Circuit not satisfied by witness".into());
    }
    
    // Generate CRS (circuit dimension is already power-of-2)
    let mut rng = OsRng;
    let crs_size = circuit.dim();
    println!("Generating CRS with size: {}", crs_size);
    let crs: CircuitCRS<G1Projective> = CircuitCRS::rand(crs_size, &mut rng);
    
    // Create public statement
    let statement = CircuitStatement::new(&crs, &witness);
    
    // Set up Fiat-Shamir domain separator
    let domain_separator = {
        let ds = DomainSeparator::new("circom-to-bulletproofs");
        let ds = CircuitProofDomainSeparator::<G1Projective>::circuit_proof_statement(ds, statement.v.len()).ratchet();
        CircuitProofDomainSeparator::<G1Projective>::add_circuit_proof(ds, crs_size)
    };
    
    // Generate bulletproof
    println!("Generating proof...");
    let mut prover_state = domain_separator.to_prover_state();
    prover_state.public_points(&statement.v)?;
    prover_state.ratchet()?;
    let proof = circuit_prove(&mut prover_state, &crs, &circuit, &witness, &mut rng)?;
    
    // Verify bulletproof
    println!("Verifying proof...");
    let mut verifier_state = domain_separator.to_verifier_state(&proof);
    verifier_state.public_points(&statement.v)?;
    verifier_state.ratchet()?;
    circuit_verify(&mut verifier_state, &crs, &circuit, &statement, &mut rng)?;
    
    println!("✅ Proof verified successfully!");

    Ok(())
}