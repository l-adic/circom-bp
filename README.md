# circom-bp

A Rust library that bridges Circom circuits with Bulletproofs zero-knowledge proof system. This tool converts Circom R1CS circuits into Bulletproof-compatible formats and generates verifiable zero-knowledge proofs.

## What it does

This project converts compiled Circom circuits (`.r1cs` and `.wasm` files) into Bulletproof circuits. It transforms R1CS constraint systems into Bulletproof weight matrices with automatic power-of-2 padding. The tool loads circuit inputs from JSON files, generates witnesses, creates zero-knowledge proofs using Bulletproofs, and verifies them.

This enables privacy-preserving computation verification for any computation expressible in Circom, leveraging Bulletproofs' efficient proof system for arithmetic circuits.

## Running the circuits

Two example circuits are included. Run either with:

```bash
cargo run multiplier2
cargo run simpleCheck
```

Both circuits will generate a bulletproof, verify it, and display "✅ Proof verified successfully!" upon completion.