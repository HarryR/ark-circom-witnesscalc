use ark_bn254::Fr as Bn254Fr;
use std::env;
use std::fs::read;
use std::process::ExitCode;
use std::str::FromStr;

use ark_circom_witnesscalc::verify_proof;
use ark_ff::BigInt;

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <proof.bin> <input.vk-bin> [inputs ...]", args[0]);
        std::process::exit(1);
    }

    let mut public_inputs = Vec::<Bn254Fr>::new();
    for value in args.iter().skip(3) {
        let bi = BigInt::<4>::from_str(value).unwrap();
        let el = Bn254Fr::new(bi);
        public_inputs.push(el);
    }

    let proof_data = read(&args[1]).expect("Failed to read proof bin file");

    let vk_data = read(&args[2]).expect("Failed to read vk bin file");

    let result = verify_proof(&vk_data, &proof_data, &public_inputs)?;

    if result {
        println!("true");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("false");
        Ok(ExitCode::FAILURE)
    }
}
