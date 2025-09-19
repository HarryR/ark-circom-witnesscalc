use std::env;
use std::fs::read_to_string;
use std::process::ExitCode;

use ark_circom_witnesscalc::verify_proof_json;

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <proof.json> <vk.json>", args[0]);
        std::process::exit(1);
    }

    let proof_json = read_to_string(&args[1])
        .expect("Failed to read proof json");

    let vk_json = read_to_string(&args[2])
        .expect("Failed to read vk json");

    let result = verify_proof_json(&vk_json, &proof_json)?;

    if result {
        println!("true");
        Ok(ExitCode::SUCCESS)
    }
    else {
        eprintln!("false");
        Ok(ExitCode::FAILURE)
    }
}
