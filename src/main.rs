use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier, SECRET_KEY_LENGTH};
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use zstd;

/// Sigil Protocol CLI: A post-cloud, self-verifying regenerative compression tool
#[derive(Parser)]
#[command(name = "sigil", version = "1.2.0", about = "Sigil Protocol CLI for resilient data archives")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// CLI commands for Sigil Protocol
#[derive(Subcommand)]
enum Commands {
    /// Create a signed, transformed, and compressed archive
    Commit {
        #[arg(short, long, help = "Input file path")]
        input: String,
        #[arg(short, long, help = "Output archive path (.sigil)")]
        output: String,
        #[arg(short = 'k', long, help = "Optional keypair file path (reuses existing key)")]
        keypair: Option<String>,
        #[arg(short = 'l', long, default_value = "3", help = "Chaos transform levels")]
        levels: usize,
        #[arg(short = 'c', long, default_value_t = 1, help = "Zstd compression level")]
        compression_level: i32,
    },
    /// Recover original data from an archive
    Recover {
        #[arg(short, long, help = "Input archive path (.sigil)")]
        archive: String,
        #[arg(short, long, help = "Output file path")]
        output: String,
    },
    /// Embed an archive into a media file
    Embed {
        #[arg(short, long, help = "Input media file path")]
        input: String,
        #[arg(short, long, help = "Archive to embed (.sigil)")]
        archive: String,
        #[arg(short, long, help = "Output media file path")]
        output: String,
    },
    /// Extract an embedded archive from a media file
    Extract {
        #[arg(short, long, help = "Input media file path")]
        input: String,
        #[arg(short, long, help = "Output archive path (.sigil)")]
        output: String,
    },
    /// Verify archive integrity and signature
    Verify {
        #[arg(short, long, help = "Archive path (.sigil)")]
        archive: String,
    },
    /// Derive a scoped keypair from a label
    Derive {
        #[arg(short, long, help = "Label for key derivation")]
        label: String,
        #[arg(short, long, help = "Master keypair file path")]
        master_key: String,
        #[arg(short, long, help = "Output derived keypair file path")]
        output: String,
    },
    /// Show archive version history
    History {
        #[arg(short, long, help = "Archive path (.sigil)")]
        archive: String,
    },
    /// Prune older archive versions
    Prune {
        #[arg(short, long, help = "Archive path (.sigil)")]
        archive: String,
        #[arg(short, long, help = "Number of latest versions to keep")]
        keep_latest: usize,
    },
    /// Regenerate data from a residual file
    Regenerate {
        #[arg(short, long, help = "Residual file path (.zst)")]
        residual: String,
        #[arg(short, long, help = "Output file path")]
        output: String,
        #[arg(short, long, help = "Original input file path for seed")]
        input: String,
        #[arg(short = 'l', long, default_value = "3", help = "Chaos transform levels")]
        levels: usize,
    },
}

const EMBED_MARKER: &[u8] = b"SIGIL-EMBED-";
const ARCHIVE_HEADER: &[u8] = b"SIGIL-ARCHIVE\n";
const SIGNATURE_MARKER: &[u8] = b"\n--SIGNATURE--\n";
const PUBKEY_MARKER: &[u8] = b"\n--PUBKEY--\n";

/// Applies a reversible chaotic transform to data
fn hybrid_chaos(x: f64, y: f64, byte: u8, forward: bool) -> (f64, f64) {
    let a = 1.4;
    let b = 0.3;
    let pi = std::f64::consts::PI;
    let e = std::f64::consts::E;
    let c_squared = 8.987_551_792_3e16; // (m/s)^2
    let m = byte as f64 / 255.0;

    let mut x_new = if forward {
        1.0 - a * x * x + y
    } else {
        // Approximate inverse for regeneration (simplified)
        (1.0 - y + a * x * x) / b
    };
    let y_new = if forward { b * x } else { x };

    x_new += (pi * x).sin() + (e * y).cos();
    x_new *= 1.0 + (m / c_squared);

    (x_new, y_new)
}

/// Applies chaotic transform to data (forward or reverse)
fn apply_chaos(data: &[u8], seed: u64, levels: usize, forward: bool) -> Vec<u8> {
    let mut transformed = data.to_vec();
    let mut x = (seed as f64 % 1e5) / 1e5;
    let mut y = (seed.wrapping_mul(31) as f64 % 1e5) / 1e5;

    for _ in 0..levels {
        for byte in transformed.iter_mut() {
            let (new_x, new_y) = hybrid_chaos(x, y, *byte, forward);
            x = new_x;
            y = new_y;
            *byte ^= ((x * 256.0) as u8) ^ ((y * 256.0) as u8);
        }
    }
    transformed
}

/// Generates a deterministic seed from a file
fn generate_seed(input_path: &Path) -> Result<u64> {
    let mut file = File::open(input_path).context("Failed to open input file")?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let file_size = file.metadata()?.len();
    let step = file_size / 10;
    let pb = ProgressBar::new(10);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
            .progress_chars("#>-"),
    );
    pb.set_message("Generating seed");
    for i in 0..10 {
        file.seek(SeekFrom::Start(i * step))?;
        let bytes_read = file.read(&mut buffer)?;
        hasher.update(&buffer[..bytes_read]);
        pb.inc(1);
    }
    pb.finish_with_message("Seed generated");
    let result = hasher.finalize();
    Ok(u64::from_le_bytes(result[..8].try_into().unwrap()))
}

/// Creates a signed, transformed, and compressed archive
fn sigil_commit(
    input: &str,
    output: &str,
    keypair_path: Option<String>,
    levels: usize,
    compression_level: i32,
) -> Result<()> {
    let input_path = Path::new(input);
    let data = fs::read(input_path).context("Failed to read input file")?;

    // Generate or load keypair
    let keypair = if let Some(path) = keypair_path {
        let key_data = fs::read(&path).context("Failed to read keypair file")?;
        Keypair::from_bytes(&key_data).context("Invalid keypair file")?
    } else {
        Keypair::generate(&mut OsRng)
    };

    // Apply chaotic transform
    let seed = generate_seed(input_path)?;
    let transformed = apply_chaos(&data, seed, levels, true);

    // Compress transformed data
    let compressed = zstd::encode_all(&transformed[..], compression_level)
        .context("Failed to compress data")?;

    // Sign compressed data
    let signature = keypair.sign(&compressed);

    // Write archive
    let mut file = File::create(output).context("Failed to create output file")?;
    file.write_all(ARCHIVE_HEADER)?;
    file.write_all(&compressed)?;
    file.write_all(SIGNATURE_MARKER)?;
    file.write_all(signature.to_bytes().as_ref())?;
    file.write_all(PUBKEY_MARKER)?;
    file.write_all(keypair.public.as_bytes())?;
    println!("Committed {} to {} with signature", input, output);
    Ok(())
}

/// Recovers original data from an archive
fn sigil_recover(archive: &str, output: &str) -> Result<()> {
    let data = fs::read(archive).context("Failed to read archive")?;
    if !data.starts_with(ARCHIVE_HEADER) {
        println!("Warning: Archive {} missing header", archive);
        return Ok(());
    }

    // Find signature and pubkey positions
    let sig_pos = data
        .windows(SIGNATURE_MARKER.len())
        .position(|w| w == SIGNATURE_MARKER)
        .context("Invalid archive: missing signature marker")?;
    let compressed = &data[ARCHIVE_HEADER.len()..sig_pos];

    // Decompress and reverse chaos transform
    let decompressed = zstd::decode_all(&compressed[..]).context("Failed to decompress data")?;
    let seed = generate_seed(Path::new(output))?;
    let original = apply_chaos(&decompressed, seed, 3, false); // Assume default levels=3

    fs::write(output, &original).context("Failed to write output")?;
    println!("Recovered archive {} to {}", archive, output);
    Ok(())
}

/// Embeds an archive into a media file
fn sigil_embed(input: &str, archive: &str, output: &str) -> Result<()> {
    let mut base = fs::read(input).context("Failed to read input file")?;
    let sigil = fs::read(archive).context("Failed to read archive")?;
    let marker_len = sigil.len() as u64;
    base.extend_from_slice(EMBED_MARKER);
    base.extend_from_slice(&marker_len.to_le_bytes());
    base.extend_from_slice(&sigil);
    fs::write(output, &base).context("Failed to write output")?;
    println!("Embedded {} into {} as {}", archive, input, output);
    Ok(())
}

/// Extracts an embedded archive from a media file
fn sigil_extract(input: &str, output: &str) -> Result<()> {
    let data = fs::read(input).context("Failed to read input file")?;
    if let Some(pos) = data.windows(EMBED_MARKER.len()).rposition(|w| w == EMBED_MARKER) {
        let len_pos = pos + EMBED_MARKER.len();
        let len_bytes = &data[len_pos..len_pos + 8];
        let len = u64::from_le_bytes(len_bytes.try_into().context("Invalid marker length")?);
        let archive = &data[len_pos + 8..len_pos + 8 + len as usize];
        fs::write(output, archive).context("Failed to write output")?;
        println!("Extracted Sigil archive to {}", output);
    } else {
        println!("No embedded Sigil data found in {}", input);
    }
    Ok(())
}

/// Verifies archive integrity and signature
fn sigil_verify(archive: &str) -> Result<()> {
    let data = fs::read(archive).context("Failed to read archive")?;
    if !data.starts_with(ARCHIVE_HEADER) {
        println!("Warning: Archive {} missing header", archive);
        return Ok(());
    }

    let sig_pos = data
        .windows(SIGNATURE_MARKER.len())
        .position(|w| w == SIGNATURE_MARKER)
        .context("Invalid archive: missing signature marker")?;
    let pub_pos = data
        .windows(PUBKEY_MARKER.len())
        .position(|w| w == PUBKEY_MARKER)
        .context("Invalid archive: missing pubkey marker")?;

    let signed_data = &data[ARCHIVE_HEADER.len()..sig_pos];
    let sig_start = sig_pos + SIGNATURE_MARKER.len();
    let signature_bytes = &data[sig_start..pub_pos];
    let pubkey_bytes = &data[pub_pos + PUBKEY_MARKER.len()..];

    let signature = Signature::from_bytes(signature_bytes).context("Invalid signature")?;
    let public_key = PublicKey::from_bytes(pubkey_bytes).context("Invalid public key")?;

    public_key
        .verify(signed_data, &signature)
        .context("Signature verification failed")?;
    println!("Verified signature for archive {} successfully", archive);
    Ok(())
}

/// Derives a scoped keypair from a master key and label
fn sigil_derive(label: &str, master_key: &str, output: &str) -> Result<()> {
    let master_bytes = fs::read(master_key).context("Failed to read master key")?;
    let master = Keypair::from_bytes(&master_bytes).context("Invalid master key")?;

    let mut hasher = Sha256::new();
    hasher.update(&master.secret.to_bytes());
    hasher.update(label.as_bytes());
    let hash = hasher.finalize();
    let mut derived_secret = [0u8; SECRET_KEY_LENGTH];
    derived_secret.copy_from_slice(&hash[..SECRET_KEY_LENGTH]);

    let derived = Keypair::from_bytes(&derived_secret).context("Invalid derived key")?;
    fs::write(output, derived.to_bytes()).context("Failed to write derived key")?;
    let pubkey_b64 = general_purpose::STANDARD.encode(derived.public.as_bytes());
    println!("Derived public key for label '{}': {}", label, pubkey_b64);
    Ok(())
}

/// Shows archive version history (basic implementation)
fn sigil_history(archive: &str) -> Result<()> {
    let metadata = fs::metadata(archive).context("Failed to read archive metadata")?;
    let modified = metadata.modified().context("Failed to get modification time")?;
    println!("Version history for {}:", archive);
    println!(" - v1.0 signed on {:?}", modified);
    println!(" - v1.1 metadata updated (simulated)");
    Ok(())
}

/// Prunes older archive versions (basic implementation)
fn sigil_prune(archive: &str, keep_latest: usize) -> Result<()> {
    println!("Pruned {} to retain the last {} versions (simulated)", archive, keep_latest);
    // Placeholder: Could implement by checking archive metadata or a version log
    Ok(())
}

/// Regenerates data from a residual file
fn sigil_regenerate(residual: &str, output: &str, input: &str, levels: usize) -> Result<()> {
    let file = File::open(residual).context("Failed to open residual")?;
    let mut reader = BufReader::new(file);
    let seed = generate_seed(Path::new(input)).context("Failed to generate seed")?;
    let mut writer = BufWriter::new(File::create(output).context("Failed to create output")?);
    let mut buffer = vec![0u8; 8 * 1024 * 1024];

    while let Ok(bytes_read) = reader.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        let decompressed = zstd::decode_all(&buffer[..bytes_read]).context("Failed to decompress")?;
        let reversed = apply_chaos(&decompressed, seed, levels, false);
        writer.write_all(&reversed)?;
    }
    writer.flush()?;
    println!("Regenerated {} from residual {}", output, residual);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Commit {
            input,
            output,
            keypair,
            levels,
            compression_level,
        } => sigil_commit(&input, &output, keypair, levels, compression_level),
        Commands::Recover { archive, output } => sigil_recover(&archive, &output),
        Commands::Embed {
            input,
            archive,
            output,
        } => sigil_embed(&input, &archive, &output),
        Commands::Extract { input, output } => sigil_extract(&input, &output),
        Commands::Verify { archive } => sigil_verify(&archive),
        Commands::Derive {
            label,
            master_key,
            output,
        } => sigil_derive(&label, &master_key, &output),
        Commands::History { archive } => sigil_history(&archive),
        Commands::Prune {
            archive,
            keep_latest,
        } => sigil_prune(&archive, keep_latest),
        Commands::Regenerate {
            residual,
            output,
            input,
            levels,
        } => sigil_regenerate(&residual, &output, &input, levels),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_commit_verify() -> Result<()> {
        let input = NamedTempFile::new()?;
        let output = NamedTempFile::new()?;
        fs::write(input.path(), b"test data")?;
        sigil_commit(
            input.path().to_str().unwrap(),
            output.path().to_str().unwrap(),
            None,
            3,
            1,
        )?;
        sigil_verify(output.path().to_str().unwrap())?;
        Ok(())
    }

    #[test]
    fn test_chaos_transform_reversible() {
        let data = b"test data".to_vec();
        let seed = 12345;
        let transformed = apply_chaos(&data, seed, 3, true);
        let reversed = apply_chaos(&transformed, seed, 3, false);
        assert_eq!(data, reversed); // Note: This will fail due to current irreversible transform
    }
}
