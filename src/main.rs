use rand::Rng;
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc, FixedOffset};
use reed_solomon::{Encoder, Buffer};
use pqcrypto_kyber::kyber1024::*;
use rayon::prelude::*;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::Type as ParquetType;
use parquet::basic::{Compression, Encoding};
use arrow::array::ArrayBuilder;
use std::error::Error;
use std::env;
use std::fs::File;
use std::path::Path;

fn logistic_chaos(seed: f64, length: usize, r: f64) -> Vec<u8> {
    let mut x = seed;
    let mut sequence = Vec::with_capacity(length);
    let mut rng = rand::thread_rng();
    for _ in 0..length {
        x = r * x * (1.0 - x);
        sequence.push((x * 256.0) as u8 ^ rng.gen::<u8>());
    }
    sequence
}

fn ratchet_key(old_key: &str, data_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(old_key.as_bytes());
    hasher.update(data_hash.as_bytes());
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
    let mut num = 0;
    for (i, bit) in code.chars().rev().enumerate() {
        if bit == '1' {
            num += fibs[i + 2];
        }
    }
    num
}

fn add_rs_parity(data_chunks: &[Vec<u8>], parity_count: usize) -> Vec<Vec<u8>> {
    let symbol_size = data_chunks[0].len();
    let enc = Encoder::new(symbol_size);
    let mut chunks_with_parity = data_chunks.to_vec();
    let mut buffers = data_chunks.iter().map(|c| Buffer::from_slice(c.as_slice(), symbol_size)).collect::<Vec<_>>();
    let parity_buffers = enc.encode(&mut buffers, parity_count)?;
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

fn sigil_transform(data: &[u8], seed_key: &str, time_restriction: Option<DateTime<FixedOffset>>, place: Option<&str>, manner: Option<&str>) -> (Vec<Vec<u8>>, String, usize, String) {
    let seed = 0.314159;
    let chaos_seq = logistic_chaos(seed, data.len(), 3.99);
    let encrypted = data.par_iter().zip(chaos_seq.par_iter()).map(|(&b, &c)| b ^ c).collect::<Vec<u8>>();
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
    check_access(time_restriction, place, manner)?;
    (chunks_with_parity, new_key, data.len(), fib_residual)
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <data>", args[0]);
        return;
    }
    let test_data = args[1].as_bytes();
    let time_restriction = Some(DateTime::parse_from_rfc3339("2025-12-31T23:59:59+00:00").expect("Invalid time"));
    let (mut transformed, new_key, orig_len, fib_residual) = sigil_transform(test_data, "initial_seed", time_restriction, Some("allowed_location"), Some("read_only"));
    println!("Transformed: {:?}", transformed);
    println!("Key: {}", new_key);
    println!("Fib Residual: {}", fib_residual);

    transformed[0] = vec![0; transformed[0].len()];
    transformed[1] = vec![0; transformed[1].len()];
    match sigil_regenerate(&mut transformed, "initial_seed", &[0, 1], orig_len, &fib_residual) {
        Ok(regenerated) => println!("Regenerated Success: {}", regenerated == test_data),
        Err(e) => println!("Failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeckendorf() {
        assert_eq!(zeckendorf(13), "1001");  // 13 = 13 (Fib8=8, but correct is 13 = 13, Fib seq adjustment
    }

    #[test]
    fn test_regen() {
        let data = b"test";
        let (mut transformed, _, orig_len, fib_residual) = sigil_transform(data, "test_key", None, None, None);
        transformed[0] = vec![0; transformed[0].len()];
        let regenerated = sigil_regenerate(&mut transformed, "test_key", &[0], orig_len, &fib_residual).unwrap();
        assert_eq!(regenerated, data);
    }
}
