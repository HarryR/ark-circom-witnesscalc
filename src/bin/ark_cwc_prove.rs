use std::env;
use std::fs::{OpenOptions, read, read_to_string, write};

use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use ark_circom_witnesscalc::{proof_oneshot, jsonstructs::proof_to_json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 {
        eprintln!("Usage: {} <input.json> <input.graph> <input.r1cs> <input.pkey> <output.proof-json> <output.proof-bin>", args[0]);
        std::process::exit(1);
    }

    let path_input_json = &args[1];
    let path_input_graph = &args[2];
    let path_input_r1cs = &args[3];
    let path_input_pkey = &args[4];
    let path_out_proof_json = &args[5];
    let path_out_proof_bin = &args[6];

    let inputs_data = read_to_string(path_input_json)
        .expect("Failed to read input file");
    let graph_data = read(path_input_graph)
        .expect("Failed to read graph file");

    let r1cs_data = read(path_input_r1cs)
        .expect("Failed to read r1cs file");

    let pkey_data = read(path_input_pkey)
        .expect("Failed to read graph file");

    let (proof,public_inputs) = proof_oneshot(&inputs_data, &pkey_data, &graph_data, &r1cs_data);    

    let proof_json = proof_to_json(&proof, &public_inputs)?;

    write(path_out_proof_json, proof_json)?;

    let binproof_out_file = OpenOptions::new()
        .truncate(true)
        .create(true)
        .write(true)
        .open(path_out_proof_bin)?;
    proof.serialize_uncompressed(binproof_out_file)?;

    Ok(())
}