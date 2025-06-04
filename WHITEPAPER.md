Title: Sigil Protocol and Regent Framework
A Distributed Entropy-Aware Memory System for Portable, Verifiable, and Self-Healing Digital Objects


---

Abstract
The Sigil Protocol defines a cryptographically verifiable file format (.sg1) that captures entropy, structure, and identity across files, folders, and entire drives. Paired with the Regent framework, it enables chunk-level verification, redundancy-aware recovery, drift detection, and granular access control. Recent enhancements extend Sigil into a distributed, recursive object graph where files, folders, and systems become cryptographically linked and mutually regenerable. This redefines how data is stored, backed up, verified, and restored—without relying on OS-level access control, central servers, or fragile trust anchors.


---

1. Introduction

Traditional data validation methods rely on simple hashes, opaque ACLs, and monolithic backups. Sigil replaces this with a system where:

Every file has a unique entropy identity

Every folder and drive forms a verifiable graph of those identities

Missing files can be reconstructed probabilistically from the structure and data of related objects

Access is cryptographically enforced, without relying on the OS


This architecture is designed for durability, auditability, zero-trust, and forensic-grade restoration.


---

2. Core Concepts

2.1 Sigil File (.sg1)
A .sg1 file includes:

Magic header and version

Entropy fingerprint and compression residual

ChaosRegen compression only (exclusive)

Regent chunk map for rapid verification and patching

Access control manifest

ECC signature blocks for identity and verification

Optional encryption per file, folder, or segment


2.2 Regent
Regent divides any object into verifiable, independent chunks. Each chunk:

Has its own entropy score and hash

Can be validated independently

Can be encrypted or unlocked individually

Participates in a Merkle tree for fast verification


2.3 Recursive Object Graphing
Files are treated as chunks of folders, folders as chunks of drives, and drives as forests of object memory. Each layer:

Inherits from or references its child .sg1 files

Can be used to validate, reconstruct, or compare any other known .sg1

Enables structure-based deduplication and cross-entropy recovery


2.4 Regeneration & Deduplication
Given overlapping .sg1 files:

Sigil can detect shared entropy blocks

Rebuild missing or corrupted segments

Reconstruct files from partial graphs or sibling containers


2.5 Resilience Modes

Glyph Mode: Lightweight—Entropy + ChaosRegen + Signature (default)

Reflection Mode: Adds parity and deterministic recovery codes for partial regen

Seal Mode: Full redundancy—designed for high-risk/high-integrity storage (e.g., cold storage, forensics)



---

3. Access Control & Identity

Owner-only or multi-signature unlock

Per-file or per-folder access lists

Expiry flags (TTL)

Role-based or time-gated reads

ECC-based identity enforcement (e.g. curve25519)

Optional audit trail of access or edit changes



---

4. Use Cases

Sector	Use Case

Forensics	Self-healing forensic disk graphs
Gaming	Secure P2P patching with regen validation
Cybersecurity	File drift detection with entropy deltas
Legal	Time-locked, multi-signed document graphs
Storage	Composable, verifiable, encrypted folders
Disaster Recovery	Redundant entropy-aware backup maps



---

5. Why It’s Different

Traditional	Sigil + Regent

SHA256	Residual + entropy signature
Full-file encryption	Chunk + role + time gated unlocks
Rsync-style diff	Entropy-aware chunk deduplication
Filesystem ACLs	Portable cryptographic access manifests
Backups	Cross-file self-healing graph structure
Zip/rar archive	ZK-enabled access + audit trace



---

6. Roadmap

v0.1: Core .sg1 generator with entropy fingerprint

v0.2: Regent chunk verification + Merkle structure

v0.3: Access control manifest + ECC locking

v0.4: Regen system: chunk-level recovery from .sg1 siblings

v0.5: Meta-manifest for folder and drive-level graphs

v1.0: Full distributed .sg1 recovery engine + UI tools

v1.x: Delta versioning and rollback + audit chain + ZK proof integration (Halo2/Zexe)



---

7. Conclusion

Sigil isn’t just a file format—it’s a substrate for decentralized object memory.
It captures not just what a file is, but how it relates to other files, how it can be recovered, and how it can be trusted—across time, systems, and failures.

With ChaosRegen as its engine, Regent as its structure, and cryptographic control as its foundation, Sigil enables data systems that aren’t just secure—they’re alive.


---

Appendix A: Algorithms & Math

Entropy Score: Calculated using Shannon entropy per chunk:
H = -Σ (p_i * log2(p_i)) over all byte values in the chunk

Residual Signature: Difference between original and ChaosRegen-compressed version:
R = H_raw - H_compressed

Chunk Matching:
Compare chunk hashes or calculate similarity score:
similarity = shared_bytes / total_bytes

Regeneration Confidence:
confidence = matching_chunks / total_chunks

Merkle Tree Hashing:
Binary tree built over chunk hashes:
parent_hash = H(left_child + right_child)

ECC Signature Scope:
Entire .sg1 body excluding the signature block is signed with curve25519

Seeding: Initial signature hash → seed for ChaCha-based PRNG → deterministic regen



---

Appendix B: Workflows

sigil create <file>: Generate entropy profile, compress with ChaosRegen, output .sg1

sigil verify <file> <file.sg1>: Compare current file's entropy + hash to .sg1

sigil regen <partial.sg1> <other.sg1>: Attempt to reconstruct partial file from related .sg1

sigil compare <a.sg1> <b.sg1>: Show entropy + chunk structure diff

sigil sign <file.sg1>: Sign file with owner’s ECC key

sigil audit <file.sg1>: View signature, edit, and role history if enabled



---

Appendix C: .sg1 Format Specification

Header: 4-byte magic SIG1, 1-byte version

Metadata Block: JSON (optional TTL, tags, timestamps)

Entropy Block: Per-chunk entropy profile, residual

Chunk Map: Fixed-size chunk offsets + hashes + Merkle root

Compression Block: ChaosRegen output

Access Control: ECC pubkeys, roles, expiration

Signature Block: ECC signature, signer pubkey

Optional Delta/Version Log: For enabled version control



---

License & Ethics
Sigil Protocol is licensed under AGPL. All enhancements and integrations must preserve the user’s rights to view, verify, and modify the protocol code. Its goal is to ensure user autonomy, prevent vendor lock-in, and promote data integrity beyond corporate boundaries.


---

Contact
To contribute, integrate, or build tooling: contact the protocol designer.

