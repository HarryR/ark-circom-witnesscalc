use anyhow::{anyhow, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr};
use ark_ec::pairing::Pairing;
use ark_ff::BigInt;
use ark_groth16::{Proof, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// JSON representation structs
#[derive(Serialize, Deserialize)]
pub struct VerifyingKeyJson {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    n_public: usize,
    vk_alpha_1: [String; 3],
    vk_beta_2: [[String; 2]; 3],
    vk_gamma_2: [[String; 2]; 3],
    vk_delta_2: [[String; 2]; 3],
    #[serde(rename = "IC")]
    ic: Vec<[String; 3]>,
}

#[derive(Serialize, Deserialize)]
pub struct ProofJson {
    protocol: String,
    #[serde(rename = "type")]
    proof_type: String,
    curve: String,
    a: [String; 3],
    b: [[String; 2]; 3],
    c: [String; 3],
    inputs: Vec<String>,
}

// Helper functions to reduce duplication
fn g1_point_to_strings(point: &<Bn254 as Pairing>::G1Affine) -> [String; 3] {
    [point.x.to_string(), point.y.to_string(), "1".to_string()]
}

fn g2_point_to_strings(point: &<Bn254 as Pairing>::G2Affine) -> [[String; 2]; 3] {
    [
        [point.x.c0.to_string(), point.x.c1.to_string()],
        [point.y.c0.to_string(), point.y.c1.to_string()],
        ["1".to_string(), "0".to_string()],
    ]
}

fn parse_g1_point_from_strings(
    x_str: &str,
    y_str: &str,
    z_str: &str,
) -> Result<<Bn254 as Pairing>::G1Affine> {
    // Verify it's in affine representation
    if z_str != "1" {
        return Err(anyhow!(
            "G1 point not in affine representation: z = {}, expected 1",
            z_str
        ));
    }

    let x_bi = BigInt::<4>::from_str(x_str)
        .map_err(|_| anyhow!("Failed to parse x coordinate: {}", x_str))?;
    let y_bi = BigInt::<4>::from_str(y_str)
        .map_err(|_| anyhow!("Failed to parse y coordinate: {}", y_str))?;
    let x = Fq::new(x_bi);
    let y = Fq::new(y_bi);
    Ok(<Bn254 as Pairing>::G1Affine::new(x, y))
}

fn parse_g2_point_from_coords(coords: &[[String; 2]; 3]) -> Result<<Bn254 as Pairing>::G2Affine> {
    // Verify it's in affine representation
    if coords[2][0] != "1" || coords[2][1] != "0" {
        return Err(anyhow!(
            "G2 point not in affine representation: z = [{}, {}], expected [1, 0]",
            coords[2][0],
            coords[2][1]
        ));
    }

    let x_c0_bi = BigInt::<4>::from_str(&coords[0][0])
        .map_err(|_| anyhow!("Failed to parse x.c0: {}", &coords[0][0]))?;
    let x_c1_bi = BigInt::<4>::from_str(&coords[0][1])
        .map_err(|_| anyhow!("Failed to parse x.c1: {}", &coords[0][1]))?;
    let y_c0_bi = BigInt::<4>::from_str(&coords[1][0])
        .map_err(|_| anyhow!("Failed to parse y.c0: {}", &coords[1][0]))?;
    let y_c1_bi = BigInt::<4>::from_str(&coords[1][1])
        .map_err(|_| anyhow!("Failed to parse y.c1: {}", &coords[1][1]))?;

    let x = Fq2::new(Fq::new(x_c0_bi), Fq::new(x_c1_bi));
    let y = Fq2::new(Fq::new(y_c0_bi), Fq::new(y_c1_bi));
    Ok(<Bn254 as Pairing>::G2Affine::new(x, y))
}

fn parse_field_element(s: &str) -> Result<Fr> {
    let bi =
        BigInt::<4>::from_str(s).map_err(|_| anyhow!("Failed to parse field element: {}", s))?;
    Ok(Fr::new(bi))
}

// Conversion functions
impl From<&VerifyingKey<Bn254>> for VerifyingKeyJson {
    fn from(vk: &VerifyingKey<Bn254>) -> Self {
        VerifyingKeyJson {
            protocol: "groth16".to_string(),
            curve: "bn128".to_string(),
            n_public: vk.gamma_abc_g1.len() - 1,
            vk_alpha_1: g1_point_to_strings(&vk.alpha_g1),
            vk_beta_2: g2_point_to_strings(&vk.beta_g2),
            vk_gamma_2: g2_point_to_strings(&vk.gamma_g2),
            vk_delta_2: g2_point_to_strings(&vk.delta_g2),
            ic: vk.gamma_abc_g1.iter().map(g1_point_to_strings).collect(),
        }
    }
}

impl TryFrom<VerifyingKeyJson> for VerifyingKey<Bn254> {
    type Error = anyhow::Error;

    fn try_from(json: VerifyingKeyJson) -> Result<Self> {
        if json.protocol != "groth16" {
            return Err(anyhow!(
                "Invalid protocol: expected 'groth16', got '{}'",
                json.protocol
            ));
        }
        if json.curve != "bn128" {
            return Err(anyhow!(
                "Invalid curve: expected 'bn128', got '{}'",
                json.curve
            ));
        }

        // Parse alpha_g1 using helper function
        let alpha_g1 = parse_g1_point_from_strings(
            &json.vk_alpha_1[0],
            &json.vk_alpha_1[1],
            &json.vk_alpha_1[2],
        )?;

        // Parse G2 points using helper function
        let beta_g2 = parse_g2_point_from_coords(&json.vk_beta_2)?;
        let gamma_g2 = parse_g2_point_from_coords(&json.vk_gamma_2)?;
        let delta_g2 = parse_g2_point_from_coords(&json.vk_delta_2)?;

        // Parse gamma_abc_g1 using helper function
        let mut gamma_abc_g1 = Vec::new();
        for (i, coords) in json.ic.iter().enumerate() {
            let point = parse_g1_point_from_strings(&coords[0], &coords[1], &coords[2])
                .map_err(|e| anyhow!("Failed to parse IC[{}]: {}", i, e))?;
            gamma_abc_g1.push(point);
        }

        Ok(VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }
}

impl From<(&Proof<Bn254>, &Vec<Fr>)> for ProofJson {
    fn from((proof, public_inputs): (&Proof<Bn254>, &Vec<Fr>)) -> Self {
        ProofJson {
            protocol: "groth16".to_string(),
            proof_type: "proof".to_string(),
            curve: "bn128".to_string(),
            a: g1_point_to_strings(&proof.a),
            b: g2_point_to_strings(&proof.b),
            c: g1_point_to_strings(&proof.c),
            inputs: public_inputs
                .iter()
                .map(|input| input.to_string())
                .collect(),
        }
    }
}

impl TryFrom<ProofJson> for (Proof<Bn254>, Vec<Fr>) {
    type Error = anyhow::Error;

    fn try_from(json: ProofJson) -> Result<Self> {
        if json.protocol != "groth16" {
            return Err(anyhow!(
                "Invalid protocol: expected 'groth16', got '{}'",
                json.protocol
            ));
        }
        if json.curve != "bn128" {
            return Err(anyhow!(
                "Invalid curve: expected 'bn128', got '{}'",
                json.curve
            ));
        }
        if json.proof_type != "proof" {
            return Err(anyhow!(
                "Invalid type: expected 'proof', got '{}'",
                json.proof_type
            ));
        }

        // Parse G1 points using helper function
        let a = parse_g1_point_from_strings(&json.a[0], &json.a[1], &json.a[2])?;
        let c = parse_g1_point_from_strings(&json.c[0], &json.c[1], &json.c[2])?;

        // Parse point B (G2) using helper function
        let b = parse_g2_point_from_coords(&json.b)?;

        // Parse public inputs using helper function
        let mut public_inputs = Vec::new();
        for (i, input_str) in json.inputs.iter().enumerate() {
            let el = parse_field_element(input_str)
                .map_err(|e| anyhow!("Failed to parse input[{}]: {}", i, e))?;
            public_inputs.push(el);
        }

        let proof = Proof { a, b, c };
        Ok((proof, public_inputs))
    }
}

// Main serialization/deserialization functions
pub fn verifying_key_to_json(vk: &VerifyingKey<Bn254>) -> Result<String> {
    let json_vk = VerifyingKeyJson::from(vk);
    Ok(serde_json::to_string_pretty(&json_vk)?)
}

pub fn verifying_key_from_json(json_str: &str) -> Result<VerifyingKey<Bn254>> {
    let json_vk: VerifyingKeyJson = serde_json::from_str(json_str)?;
    VerifyingKey::try_from(json_vk)
}

pub fn proof_to_json(proof: &Proof<Bn254>, public_inputs: &Vec<Fr>) -> Result<String> {
    let json_proof = ProofJson::from((proof, public_inputs));
    Ok(serde_json::to_string_pretty(&json_proof)?)
}

pub fn proof_from_json(json_str: &str) -> Result<(Proof<Bn254>, Vec<Fr>)> {
    let json_proof: ProofJson = serde_json::from_str(json_str)?;
    <(Proof<Bn254>, Vec<Fr>)>::try_from(json_proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifying_key_deserialization() {
        let vk_json = r#"{
	"protocol":"groth16",
	"curve":"bn128",
	"nPublic": 2,
	"vk_alpha_1": ["14294736614990674966396623028803009115049001595062557165449477993453732800914", "16403779603127981111404952147536838932574573959885092213466973207730988248744", "1"],
	"vk_beta_2": [["3690250390531159792182810706199558530011152443236236316148429759851202632185", "7181447983574240535096108951419011671122610106706318811519767758412121191671"], ["18903949123289243237360231390412925963082099721924281123079749233292975283708", "11752118997903370298075117314340230052476465863449911602944876945651913830724"], ["1","0"]],
	"vk_gamma_2": [["2772204544545143745036642647329016796016477347816712789345741859457088126286", "5820988467473537566833519916519597543631455780504447427080278108971502609568"], ["6920072944147306036917161943266759424466930268609042427928446187786171160694", "338394630223224278219244011824126808724142848749307879698459195126736965603"], ["1","0"]],
	"vk_delta_2": [["18747970342366397216484970789592543900248114418300490001193977733049641644946", "1409455623867796783765628324117898066639067722535957637572506835201777023154"], ["10044353901010805573702826446649533157093287966227536611798472884805014233421", "1100455837014046159940971754605909292700516718490931598674110957434711818264"], ["1","0"]],
	"IC":[
		["20662526494079920157061002738647583446881021430596087771228299228351005766192", "5748308059588685207234398742531008825939341408141823519188647173863100181444", "1"],
		["3268982782370409438690550254080177231796009753224998922477477781476537484434", "7283492216111651860872429609223050515931611851121597633410734094315586405131", "1"],
		["4400968086040099372960574301818625400334606309655325517678832007445237168329", "17295528924224860754510996071213162727241147380616405972755183483481875721340", "1"]
	]
}"#;

        let result = verifying_key_from_json(vk_json);
        assert!(
            result.is_ok(),
            "Failed to deserialize verifying key: {:?}",
            result.err()
        );

        let vk = result.unwrap();

        // Verify basic properties
        assert_eq!(
            vk.gamma_abc_g1.len(),
            3,
            "Expected 3 IC elements (nPublic=2 + 1)"
        );

        // Test roundtrip serialization
        let serialized = verifying_key_to_json(&vk);
        assert!(
            serialized.is_ok(),
            "Failed to serialize verifying key: {:?}",
            serialized.err()
        );

        // Deserialize again and compare
        let vk2_result = verifying_key_from_json(&serialized.unwrap());
        assert!(
            vk2_result.is_ok(),
            "Failed to deserialize roundtrip verifying key: {:?}",
            vk2_result.err()
        );

        let vk2 = vk2_result.unwrap();

        // Compare key fields (basic structural equality)
        assert_eq!(
            vk.gamma_abc_g1.len(),
            vk2.gamma_abc_g1.len(),
            "IC length mismatch after roundtrip"
        );
        assert_eq!(
            vk.alpha_g1, vk2.alpha_g1,
            "alpha_g1 mismatch after roundtrip"
        );
        assert_eq!(vk.beta_g2, vk2.beta_g2, "beta_g2 mismatch after roundtrip");
        assert_eq!(
            vk.gamma_g2, vk2.gamma_g2,
            "gamma_g2 mismatch after roundtrip"
        );
        assert_eq!(
            vk.delta_g2, vk2.delta_g2,
            "delta_g2 mismatch after roundtrip"
        );
        assert_eq!(
            vk.gamma_abc_g1, vk2.gamma_abc_g1,
            "gamma_abc_g1 mismatch after roundtrip"
        );
    }

    #[test]
    fn test_proof_deserialization() {
        let proof_json = r#"{
	"protocol":"groth16",
	"type":"proof",
	"curve":"bn128",
	"a": ["19801287090726837578044200885001440254402844668381646296109323380504107979463", "16223645295886758837836946460684489930824831996298592009362843244530537565095", "1"],
	"b": [["14419158160229828478156294188598564679024729352043826435394413630574520415635", "13227541383047502364817281770506826380994950495371717515327355831245222863808"], ["10170314160637616072929693052506642860784907058519406560969697126545938282647", "7701434206311278289343724947323209665008169752900822212424490783498470765028"], ["1","0"]],
	"c": ["15931542535481606335382873551011159013606998048559820372751278530993816517682", "9936785827820229135526754961312073112426012772106930225610536358663776965", "1"],
	"inputs": [
		"110",
		"11"
	]
}"#;

        let result = proof_from_json(proof_json);
        assert!(
            result.is_ok(),
            "Failed to deserialize proof: {:?}",
            result.err()
        );

        let (proof, public_inputs) = result.unwrap();

        // Verify basic properties
        assert_eq!(public_inputs.len(), 2, "Expected 2 public inputs");

        // Verify input values
        assert_eq!(public_inputs[0].to_string(), "110", "First input mismatch");
        assert_eq!(public_inputs[1].to_string(), "11", "Second input mismatch");

        // Test roundtrip serialization
        let serialized = proof_to_json(&proof, &public_inputs);
        assert!(
            serialized.is_ok(),
            "Failed to serialize proof: {:?}",
            serialized.err()
        );

        // Deserialize again and compare
        let (proof2, public_inputs2) = proof_from_json(&serialized.unwrap()).unwrap();

        // Compare proof fields
        assert_eq!(proof.a, proof2.a, "Point A mismatch after roundtrip");
        assert_eq!(proof.b, proof2.b, "Point B mismatch after roundtrip");
        assert_eq!(proof.c, proof2.c, "Point C mismatch after roundtrip");

        // Compare public inputs
        assert_eq!(
            public_inputs.len(),
            public_inputs2.len(),
            "Public inputs length mismatch after roundtrip"
        );
        for (i, (input1, input2)) in public_inputs.iter().zip(public_inputs2.iter()).enumerate() {
            assert_eq!(
                input1, input2,
                "Public input {} mismatch after roundtrip",
                i
            );
        }
    }
}
