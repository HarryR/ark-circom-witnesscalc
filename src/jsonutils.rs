use ark_groth16::{VerifyingKey, Proof};
use ark_bn254::{Bn254, Fr as Bn254Fr};

use std::error::Error;
use std::fmt::Write;

pub fn verifying_key_to_json(vk: &VerifyingKey<Bn254>) -> Result<String,Box<dyn Error>>
{
    let mut buf = String::new();

    writeln!(buf, "{{")?;
    writeln!(buf, "\t\"protocol\":\"groth16\",")?;
    writeln!(buf, "\t\"curve\":\"bn128\",")?;
    writeln!(buf, "\t\"nPublic\": {},", vk.gamma_abc_g1.len() - 1)?;
    writeln!(buf, "\t\"vk_alpha_1\": [\"{}\", \"{}\", \"1\"],", vk.alpha_g1.x, vk.alpha_g1.y)?;
    writeln!(buf, "\t\"vk_beta_2\": [[\"{}\", \"{}\"], [\"{}\", \"{}\"], [\"1\",\"0\"]],",
                    vk.beta_g2.x.c0, vk.beta_g2.x.c1, vk.beta_g2.y.c0, vk.beta_g2.y.c1)?;
    writeln!(buf, "\t\"vk_gamma_2\": [[\"{}\", \"{}\"], [\"{}\", \"{}\"], [\"1\",\"0\"]],",
                    vk.gamma_g2.x.c0, vk.gamma_g2.x.c1, vk.gamma_g2.y.c0, vk.gamma_g2.y.c1)?;
    writeln!(buf, "\t\"vk_delta_2\": [[\"{}\", \"{}\"], [\"{}\", \"{}\"], [\"1\",\"0\"]],",
                    vk.delta_g2.x.c0, vk.delta_g2.x.c1, vk.delta_g2.y.c0, vk.delta_g2.y.c1)?;
    writeln!(buf, "\t\"IC\":[")?;
    for (i, item) in vk.gamma_abc_g1.iter().enumerate() {
        if i != 0 {
            writeln!(buf, ",")?;
        }
        write!(buf, "\t\t[\"{}\", \"{}\", \"1\"]", item.x, item.y)?;
    }
    writeln!(buf, "\n\t]")?;
    writeln!(buf, "}}")?;

    Ok(buf)
}

pub fn proof_to_json(proof: &Proof<Bn254>, public_inputs: &Vec<Bn254Fr>) -> Result<String,Box<dyn Error>>
{
    let mut buf = String::new();

    writeln!(buf, "{{")?;
    writeln!(buf, "\t\"protocol\":\"groth16\",")?;
    writeln!(buf, "\t\"type\":\"proof\",")?;
    writeln!(buf, "\t\"curve\":\"bn128\",")?;
    writeln!(buf, "\t\"a\": [\"{}\", \"{}\", \"1\"],", proof.a.x, proof.a.y)?;
    writeln!(buf, "\t\"b\": [[\"{}\", \"{}\"], [\"{}\", \"{}\"], [\"1\",\"0\"]],",
                    proof.b.x.c0, proof.b.x.c1, proof.b.y.c0, proof.b.y.c1)?;
    writeln!(buf, "\t\"c\": [\"{}\", \"{}\", \"1\"]", proof.c.x, proof.c.y)?;
    writeln!(buf, "\t\"inputs\": [")?;
    for (i, value) in public_inputs.iter().enumerate() {
        if i != 0 {
            writeln!(buf, ",")?;
        }
        write!(buf, "\t\t\"{}\"", value.to_string())?;
    }
    writeln!(buf, "\n\t]")?;
    writeln!(buf, "}}")?;

    Ok(buf)
}
