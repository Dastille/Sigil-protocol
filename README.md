# Sigil Protocol

**Sigil** is a regenerative protocol for secure data representation, compression, and reconstitution.

It combines:
- Chaotic transformations
- Cryptographic seeding
- Self-verifying structures

With these properties, Sigil enables:
- Post-cloud file storage
- Offline and air-gapped resilience
- Deterministic reconstitution of data from compact, compressed forms

Built in Rust, licensed under AGPL-3.0.

## Features

- ⚙️ Deterministic chaos: reproducible transforms with cryptographic seed masks
- 🧠 Self-verifying: CRC32 checks and header validation detect tampering or corruption
- 📦 Compression system: entropy-based transformation for chaotic/encrypted data
- 🛰️ Ready for post-cloud workflows and air-gapped environments
- 🔐 Secure by design: no need to trust external services or hidden formats

## Example Usage

```bash
cargo build --release

# Compress a file
./target/release/sigil compress <input_file> <output_file>

# Decompress a file
./target/release/sigil decompress <compressed_file> <output_file>
```

## License

Sigil is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

## Maintainer

Maintained by **Ashlynn**  
