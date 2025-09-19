use ark_bn254::Bn254;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;

use std::env;
use std::fs::{write, File};
use std::io::BufReader;

use ark_circom_witnesscalc::{verifying_key_to_json, CircomCircuit, R1CSFile};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "Usage: {} <input.r1cs> <out.ark-pkey> <out.ark-vk> <out.vk-json>",
            args[0]
        );
        std::process::exit(1);
    }
    let reader = BufReader::new(File::open(&args[1])?);
    let r1cs = R1CSFile::new(reader)?.into();
    let mut circom = CircomCircuit {
        r1cs,
        witness: None,
    };
    circom.r1cs.wire_mapping = None; // Disable the wire mapping
    let params = Groth16::<Bn254, LibsnarkReduction>::generate_random_parameters_with_reduction(
        circom,
        &mut thread_rng(),
    )?;

    let mut pk_bytes = Vec::new();
    params.serialize_uncompressed(&mut pk_bytes)?;
    write(&args[2], pk_bytes)?;

    let mut vk_bytes = Vec::new();
    params.vk.serialize_uncompressed(&mut vk_bytes)?;
    write(&args[3], vk_bytes)?;

    write(&args[4], verifying_key_to_json(&params.vk)?.as_bytes())?;

    Ok(())
}
