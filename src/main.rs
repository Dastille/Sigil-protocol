use clap::{Arg, Command};
use rand::Rng;
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc, FixedOffset};
use reed_solomon::{Encoder, Buffer};
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_dilithium::dilithium5::*;
use rayon::prelude::*;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::Type as ParquetType;
use parquet::basic::{Compression, Encoding};
use arrow::array::{ArrayBuilder, BinaryBuilder};
use merkle_tree::{MerkleTree, Sha256Hash};
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use bincode::{serialize, deserialize};

fn logistic_chaos(seed: f64, length: usize, r: f64) -> Vec<u8> {
    (0..length).into_par_iter().map(|i| {
        let mut x = seed + i as f64 * 0.000001;  // Slight perturbation for parallelism
        x = r * x * (1.0 - x);
        (x * 256.0) as u8 ^ rand::thread_rng().gen::<u8>()
    }).collect()
}

fn ratchet_key(old_key: &str, data_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(old_key);
    hasher.update(data_hash);
    format!("{:x}", hasher.finalize())
}

fn check_access(time_restriction: Option<DateTime<FixedOffset>>, place: Option<&str>, manner: Option<&str>) -> Result<(), Box<dyn Error>> {
    if let Some(tr) = time_restriction {
        if Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap()) > tr {
            return Err("Access expired".into());
        }
    }
    if let Some(p) = place {
        if p != "allowed_location" {
            return Err("Place denied".into());
        }
    }
    if let Some(m) = manner {
        if m != "read_only" {
            return Err("Manner denied".into());
        }
    }
    Ok(())
}

fn fib_sequence(up_to: u64) -> Vec<u64> {
    let mut fibs = vec![0, 1];
    while fibs.last().cloned().unwrap_or(0) <= up_to {
        let next = fibs[fibs.len() - 1] + fibs[fibs.len() - 2];
        fibs.push(next);
    }
    fibs.pop();
    fibs
}

fn zeckendorf(num: u64) -> String {
    if num == 0 {
        return "0".to_string();
    }
    let fibs = fib_sequence(num);
    let mut code = String::new();
    let mut remaining = num;
    for &f in fibs.iter().rev() {
        if f <= remaining {
            code.push('1');
            remaining -= f;
        } else {
            code.push('0');
        }
    }
    code.trim_start_matches('0').to_string()
}

fn decode_zeckendorf(code: &str) -> u64 {
    let fibs = fib_sequence(u64::MAX);
    code.chars().rev().enumerate().fold(0u64, |num, (i, bit)| if bit == '1' { num + fibs[i + 2] } else { num })
}

fn add_rs_parity(data_chunks: &[Vec<u8>], parity_count: usize) -> Vec<Vec<u8>> {
    let symbol_size = data_chunks[0].len();
    let enc = Encoder::new(symbol_size);
    let buffers = data_chunks.iter().map(|c| Buffer::from_slice(c.as_slice(), symbol_size)).collect::<Vec<_>>();
    let parity_buffers = enc.encode(&buffers, parity_count).unwrap();
    let mut chunks_with_parity = data_chunks.to_vec();
    chunks_with_parity.extend(parity_buffers.iter().map(|p| p.data().to_vec()));
    chunks_with_parity
}

fn regenerate_with_rs(chunks_with_parity: &mut [Vec<u8>], missing_indices: &[usize]) -> Result<(), Box<dyn Error>> {
    let symbol_size = chunks_with_parity[0].len();
    let enc = Encoder::new(symbol_size);
    let mut buffers = chunks_with_parity.iter_mut().map(|c| Buffer::from_slice_mut(c.as_mut_slice(), symbol_size)).collect::<Vec<_>>();
    enc.reconstruct(&mut buffers, missing_indices)?;
    Ok(())
}

fn sigil_transform(data: &[u8], seed_key: &str, time_restriction: Option<DateTime<FixedOffset>>, place: Option<&str>, manner: Option<&str>) -> Result<(Vec<Vec<u8>>, String, usize, String), Box<dyn Error>> {
    check_access(time_restriction, place, manner)?;
    let seed = 0.314159;
    let chaos_seq = logistic_chaos(seed, data.len(), 3.99);
    let encrypted = data.iter().zip(chaos_seq.iter()).map(|(&b, &c)| b ^ c).collect::<Vec<u8>>();
    let data_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&encrypted);
        format!("{:x}", hasher.finalize())
    };
    let new_key = ratchet_key(seed_key, &data_hash);
    let chunk_size = 4;
    let mut chunks = (0..encrypted.len()).step_by(chunk_size).map(|i| {
        let mut chunk = encrypted[i..std::cmp::min(i + chunk_size, encrypted.len())].to_vec();
        chunk.resize(chunk_size, 0);
        chunk
    }).collect::<Vec<_>>();
    let chunks_with_parity = add_rs_parity(&chunks, 2);
    let fib_residual = zeckendorf(encrypted.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64));
    Ok((chunks_with_parity, new_key, data.len(), fib_residual))
}

fn sigil_regenerate(chunks_with_parity: &mut [Vec<u8>], seed_key: &str, missing_indices: &[usize], original_length: usize, fib_residual: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    regenerate_with_rs(chunks_with_parity, missing_indices)?;
    let mut encrypted = Vec::new();
    for chunk in &chunks_with_parity[..chunks_with_parity.len() - 2] {
        encrypted.extend_from_slice(chunk);
    }
    let fib_check = decode_zeckendorf(fib_residual);
    let encrypted_check = encrypted.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
    if fib_check != encrypted_check {
        return Err("Fibonacci mismatch".into());
    }
    let seed = 0.314159;
    let chaos_seq = logistic_chaos(seed, encrypted.len(), 3.99);
    let data = encrypted.iter().zip(chaos_seq.iter()).map(|(&b, &c)| b ^ c).collect::<Vec<u8>>();
    Ok(data[..original_length].to_vec())
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = Command::new("Sigil")
        .subcommand(Command::new("create").arg(Arg::new("input").required(true)).arg(Arg::new("output").required(true)))
        .subcommand(Command::new("regen").arg(Arg::new("input").required(true)).arg(Arg::new("output").required(true)))
        .get_matches();

    match matches.subcommand() {
        Some(("create", sub_matches)) => {
            let input_path = sub_matches.get_one::<String>("input").unwrap();
            let output_path = sub_matches.get_one::<String>("output").unwrap();
            let mut file = File::open(input_path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            let time_restriction = Some(DateTime::parse_from_rfc3339("2025-12-31T23:59:59+00:00").expect("Invalid time"));
            let (transformed, new_key, orig_len, fib_residual) = sigil_transform(&data, "initial_seed", time_restriction, Some("allowed_location"), Some("read_only"))?;
            let blueprint = serialize(& (transformed, new_key, orig_len, fib_residual))?;
            let mut out_file = File::create(output_path)?;
            out_file.write_all(&blueprint)?;
            let parquet_path = "output.parquet";
            let schema = ParquetType::group_type_builder("schema")
                .with_fields(vec![
                    ParquetType::primitive_type_builder("data", ParquetType::BYTE_ARRAY).build()?,
                ])
                .build()?;
            let file = File::create(parquet_path)?;
            let props = WriterProperties::builder().set_compression(Compression::SNAPPY).set_encoding(Encoding::PLAIN).build();
            let mut writer = SerializedFileWriter::new(file, schema, props)?;
            let mut builder = BinaryBuilder::new();
            builder.append_value(&data);
            let col = builder.finish();
            let row_group = arrow::record_batch::RecordBatch::try_new(std::sync::Arc::new(schema.clone()), vec![std::sync::Arc::new(col)])?;
            writer.write_row_group(row_group)?;
            writer.close()?;
            println!("Blueprint created at {}", output_path);
        }
        Some(("regen", sub_matches)) => {
            let input_path = sub_matches.get_one::<String>("input").unwrap();
            let output_path = sub_matches.get_one::<String>("output").unwrap();
            let mut file = File::open(input_path)?;
            let mut blueprint_data = Vec::new();
            file.read_to_end(&mut blueprint_data)?;
            let (mut transformed, new_key, orig_len, fib_residual) = deserialize(&blueprint_data)?;
            let regenerated = sigil_regenerate(&mut transformed, "initial_seed", &[0, 1], orig_len, &fib_residual)?;
            let mut out_file = File::create(output_path)?;
            out_file.write_all(&regenerated)?;
            println!("Regenerated file at {}", output_path);
        }
        _ => println!("Invalid command"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeckendorf() {
        assert_eq!(zeckendorf(13), "1001");
    }

    #[test]
    fn test_regen() {
        let data = b"test";
        let (mut transformed, _, orig_len, fib_residual) = sigil_transform(data, "test_key", None, None, None).unwrap();
        let regenerated = sigil_regenerate(&mut transformed, "test_key", &[0], orig_len, &fib_residual).unwrap();
        assert_eq!(regenerated, data.to_vec());
    }
}
