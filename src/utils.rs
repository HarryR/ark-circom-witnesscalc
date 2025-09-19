use std::vec;
use std::io::Cursor;
use std::collections::HashMap;

use anyhow::Result;
use anyhow::anyhow;
use ark_groth16::prepare_verifying_key;
use ark_groth16::VerifyingKey;

use crate::circuit::CircomCircuit;
use crate::proof_from_json;
use crate::r1cs_reader::R1CSFile;
use crate::verifying_key_from_json;

use circom_witnesscalc::{
    field::{Field, FieldOperations, FieldOps, U254},
    graph::{evaluate, Nodes, NodesInterface, NodesStorage, VecNodes},
    storage::proto_deserializer::deserialize_witnesscalc_graph_from_bytes,
    InputSignalsInfo
};

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16, ProvingKey, Proof};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::thread_rng;

pub fn calc_len(vs: &Vec<serde_json::Value>) -> usize {
    let mut len = vs.len();

    for v in vs {
        if let serde_json::Value::Array(arr) = v {
            len += calc_len(arr)-1;
        }
    }

    len
}

pub fn flatten_array2<T: FieldOps>(
    key: &str,
    vs: &Vec<serde_json::Value>,
    ff: &Field<T>) -> Result<Vec<T>, Box<dyn std::error::Error>> {

    let mut vals: Vec<T> = Vec::with_capacity(calc_len(vs));

    for v in vs {
        match v {
            serde_json::Value::String(s) => {
                let i = ff.parse_str(s)?;
                vals.push(i);
            }
            serde_json::Value::Number(n) => {
                if !n.is_u64() {
                    return Err(anyhow!("signal value is not a positive integer").into());
                }
                let n = n.as_u64().unwrap().to_string();
                let i = ff.parse_str(&n)?;
                vals.push(i);
            }
            serde_json::Value::Array(arr) => {
                vals.extend_from_slice(flatten_array2(key, arr, ff)?.as_slice());
            }
            _ => {
                return Err(anyhow!("inputs must be a string: {}", key).into());
            }
        };

    }
    Ok(vals)
}

pub fn deserialize_inputs2<T: FieldOps>(
    inputs_data: &[u8],
    ff: &Field<T>) -> Result<HashMap<String, Vec<T>>, Box<dyn std::error::Error>> {

    let v: serde_json::Value = serde_json::from_slice(inputs_data)?;

    let map = if let serde_json::Value::Object(map) = v {
        map
    } else {
        return Err(anyhow!("inputs must be an object").into());
    };

    let mut inputs: HashMap<String, Vec<T>> = HashMap::new();
    for (k, v) in map {
        match v {
            serde_json::Value::String(s) => {
                let i = ff.parse_str(s.as_str())?;
                inputs.insert(k.clone(), vec![i]);
            }
            serde_json::Value::Number(n) => {
                if !n.is_u64() {
                    return Err(anyhow!("signal value is not a positive integer").into());
                }
                let s = format!("{}", n.as_u64().unwrap());
                let i = ff.parse_str(&s)?;
                inputs.insert(k.clone(), vec![i]);
            }
            serde_json::Value::Array(ss) => {
                let vals: Vec<T> = flatten_array2(k.as_str(), &ss, ff)?;
                inputs.insert(k.clone(), vals);
            }
            _ => {
                return Err(anyhow!(
                    "value for key {} must be an a number as a string, as a number of an array of strings of numbers",
                    k.clone()).into());
            }
        }
    }
    Ok(inputs)
}

pub fn calc_witness_typed<T: FieldOps, NS: NodesStorage>(
    nodes: &Nodes<T, NS>, inputs: &str, input_mapping: &InputSignalsInfo,
    signals: &[usize]) -> Result<Vec<T>, Box<dyn std::error::Error>> {

    let inputs = deserialize_inputs2(
        inputs.as_bytes(), &nodes.ff)?;
    let inputs = create_inputs(&inputs, input_mapping)?;
    let result = evaluate(
        &nodes.ff, &nodes.nodes, &inputs, signals,
        &nodes.constants);
    Ok(result)
}

pub fn create_inputs<T: FieldOps>(
    input_list: &HashMap<String, Vec<T>>,
    inputs_info: &InputSignalsInfo) -> Result<Vec<T>, Box<dyn std::error::Error>> {

    let mut max_idx: usize = 0;
    for (offset, len) in inputs_info.values() {
        let idx = offset + len;
        if idx > max_idx {
            max_idx = idx;
        }
    }
    let mut inputs = vec![T::zero(); max_idx + 1];
    inputs[0] = T::one();
    for (key, value) in input_list {
        if ! inputs_info.contains_key(key) {
            return Err(anyhow!("Unknown key in input: '{}'", key).into());
        }
        let (offset, len) = inputs_info[key];
        if len != value.len() {
            return Err(anyhow!("Invalid input length for key: '{}'", key).into());
        }

        for (i, v) in value.iter().enumerate() {
            inputs[offset + i] = *v;
        }
    };
    Ok(inputs)
}

pub fn calc_witness2<F:PrimeField>(
    inputs: &str,
    graph_data: &[u8]) -> Result<Vec<F>, Box<dyn std::error::Error>> {

    //let start = std::time::Instant::now();
    // let inputs = deserialize_inputs(inputs.as_bytes())?;
    //println!("Inputs loaded in {:?}", start.elapsed());

    //let start = std::time::Instant::now();
    let (nodes, signals, input_mapping): (Box<dyn NodesInterface>, Vec<usize>, InputSignalsInfo) =
        deserialize_witnesscalc_graph_from_bytes(graph_data).unwrap();
    //println!("Graph loaded in {:?}", start.elapsed());

    //let start = std::time::Instant::now();
    // let mut inputs_buffer = get_inputs_buffer(nodes.get_inputs_size());
    // populate_inputs(&inputs, &input_mapping, &mut inputs_buffer);
    //println!("Inputs populated in {:?}", start.elapsed());

    let nodes = nodes.as_any().downcast_ref::<Nodes<U254, VecNodes>>().unwrap();
    let result = calc_witness_typed(nodes, inputs, &input_mapping, &signals)?;
    let vec_witness: Vec<F> = result
        .iter()
        .map(|a| F::from_le_bytes_mod_order(a.as_le_slice()))
        .collect();
    Ok(vec_witness)
}

pub fn proof_oneshot(inputs_data: &str, pkey_data:&[u8], graph_data:&[u8], r1cs_data:&[u8]) -> (Proof<Bn254>,Vec<Bn254Fr>)
{
    let witness = calc_witness2(&inputs_data, &graph_data).unwrap();

    let r1cs_reader = Cursor::new(r1cs_data);
    let r1cs = R1CSFile::new(r1cs_reader).unwrap();

    let pkey_reader = Cursor::new(pkey_data);
    let pkey = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(pkey_reader).unwrap();

    let circom = CircomCircuit::<Bn254Fr> {
        r1cs: r1cs.into(),
        witness: Some(witness),
    };

    let public_inputs = circom.get_public_inputs().unwrap();
    let mut rng = thread_rng();
    
    let proof = Groth16::<Bn254,LibsnarkReduction>::prove(&pkey, circom, &mut rng).unwrap();

    // Verify the proof can be rverified!
    let pvk = prepare_verifying_key(&pkey.vk);
    let result = Groth16::<Bn254,LibsnarkReduction>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
    assert!(result);

    (proof, public_inputs)
}

pub fn verify_proof(vkey_data:&[u8], proof_data: &[u8], public_inputs: &[Bn254Fr]) -> Result<bool>
{
    let vkey_reader = Cursor::new(vkey_data);
    let vkey = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(vkey_reader).unwrap();

    let proof_reader = Cursor::new(proof_data);
    let proof = Proof::<Bn254>::deserialize_uncompressed_unchecked(proof_reader).unwrap();

    let pvk = prepare_verifying_key(&vkey);
    let result = Groth16::<Bn254,LibsnarkReduction>::verify_proof(&pvk, &proof, public_inputs)?;
    Ok(result)
}

pub fn verify_proof_json(vkey_json:&str, proof_json: &str) -> Result<bool>
{
    let (proof, public_inputs) = proof_from_json(&proof_json)?;
    let vkey = verifying_key_from_json(vkey_json)?;

    let pvk = prepare_verifying_key(&vkey);
    let result = Groth16::<Bn254,LibsnarkReduction>::verify_proof(&pvk, &proof, &public_inputs)?;

    Ok(result)
}
