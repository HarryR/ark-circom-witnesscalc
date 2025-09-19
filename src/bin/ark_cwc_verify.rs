use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        eprintln!("Usage: {} <proof.json> <input.graph> <input.r1cs> <input.pkey> <output.proof-json>", args[0]);
        std::process::exit(1);
    }

    Ok(())
}
