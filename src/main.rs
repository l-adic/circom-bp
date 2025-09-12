use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_bn254::{Fr, G1Projective};
use bulletproofs::circuit::{
    CircuitProofDomainSeparator, prove as circuit_prove, verify as circuit_verify,
    types::{CRS as CircuitCRS, Statement as CircuitStatement}
};
use spongefish::DomainSeparator;
use spongefish::codecs::arkworks_algebra::CommonGroupToUnit;
use rand::rngs::OsRng;

mod conversion;
use conversion::circom_to_bulletproofs;

fn default_main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = CircomConfig::<Fr>::new(
        "circuits/multiplier2_js/multiplier2.wasm",
        "circuits/multiplier2.r1cs",
    )?;

    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    let circom: CircomCircuit<Fr> = builder.build().unwrap();

    // Check if witness was generated
    if circom.witness.is_none() {
        return Err("Witness generation failed - no witness found".into());
    }
    
    let _inputs = circom.get_public_inputs().unwrap();
    println!("Generated witness with {} values", circom.witness.as_ref().unwrap().len());
    
    // Convert to bulletproofs format
    let (bp_circuit, bp_witness) = circom_to_bulletproofs(&circom)?;
    
    println!("Converted circuit size: {}", bp_circuit.size());
    println!("Circuit dimension: {}", bp_circuit.dim());
    println!("Witness satisfied: {}", bp_circuit.is_satisfied_by(&bp_witness));
    
    // Generate CRS with power-of-2 size
    let mut rng = OsRng;
    let circuit_dim = bp_circuit.dim();
    
    // Ensure CRS size is power of 2 and >= circuit dimension
    let crs_size = if circuit_dim.is_power_of_two() {
        circuit_dim
    } else {
        circuit_dim.next_power_of_two()
    };
    
    println!("Generating CRS with size: {}", crs_size);
    let crs: CircuitCRS<G1Projective> = CircuitCRS::rand(crs_size, &mut rng);
    
    // Create statement (public commitments)
    println!("Creating statement...");
    let statement: CircuitStatement<G1Projective> = CircuitStatement::new(&crs, &bp_witness);
    
    // Set up domain separator
    let domain_separator = {
        let ds = DomainSeparator::new("circom-to-bulletproofs");
        let ds = CircuitProofDomainSeparator::<G1Projective>::circuit_proof_statement(ds, statement.v.len()).ratchet();
        CircuitProofDomainSeparator::<G1Projective>::add_circuit_proof(ds, crs_size)
    };
    
    // Generate proof
    println!("Generating bulletproof...");
    let mut prover_state = domain_separator.to_prover_state();
    prover_state.public_points(&statement.v)?;
    prover_state.ratchet()?;
    let proof = circuit_prove(&mut prover_state, &crs, &bp_circuit, &bp_witness, &mut rng)?;
    
    // Verify proof
    println!("Verifying bulletproof...");
    let mut verifier_state = domain_separator.to_verifier_state(&proof);
    verifier_state.public_points(&statement.v)?;
    verifier_state.ratchet()?;
    circuit_verify(&mut verifier_state, &crs, &bp_circuit, &statement, &mut rng)?;
    
    println!("Proof verified successfully!");

    Ok(())
}

fn main() {
    if let Err(e) = default_main() {
        eprintln!("Error: {}", e);
    }
}
