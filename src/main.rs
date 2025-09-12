use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_bn254::{Bn254, Fr};


fn default_main() -> Result<(), Box<dyn std::error::Error>> {

    let cfg = CircomConfig::<Fr>::new(
        "./circuits/multiplier2_js/multiplier2.wasm",
        "./circuits/multiplier2_js/multiplier2.r1cs",
    )?;

    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    let circom: CircomCircuit<Fr> = builder.build().unwrap();

    let inputs = circom.get_public_inputs().unwrap();

    Ok(())
}

fn main() {

}
