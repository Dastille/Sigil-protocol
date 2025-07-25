Abstract
The Sigil Protocol defines a cryptographically verifiable file format (.sg1) that captures entropy, structure, and identity across files, folders, and entire drives. Paired with the Regent framework, it enables chunk-level verification, redundancy-aware recovery, drift detection, and granular access control. Recent enhancements extend Sigil into a distributed, recursive object graph where files, folders, and systems become cryptographically linked and mutually regenerable, using mathematical innovations like π-anchored chaos maps, Fibonacci residual encoding, and vector-like parametric creation. This redefines data storage, backup, verification, and restoration—without relying on OS-level access control, central servers, or fragile trust anchors. As an open-source Rust project under AGPL-3.0, Sigil empowers users to build resilient systems for ransomware recovery, secure transfers, and decentralized distribution.
1. Introduction
Data integrity in modern systems is increasingly threatened by ransomware, supply-chain attacks, and corruption. Traditional methods—simple hashes, ACLs, and monolithic backups—fail to address partial loss or tampering in data lakes. The Sigil Protocol solves this by treating data as self-healing blueprints: entropy fingerprints ensure drift detection, chaotic transformations (anchored by constants like π and φ) enable deterministic regeneration, and recursive graphing links objects for cross-recovery.
Developed in Rust for safety and performance, Sigil is modular and open-source, with no proprietary dependencies. It draws on under-utilized math: logistic chaos for reversible "folding," Fibonacci self-similarity for compact residuals, and vector equations for generative unfold. Regent complements this with sharding and parity, making Sigil ideal for data lakes where ransomware demands rapid, offline reconstruction.
2. Core Concepts
2.1 Sigil File (.sg1) A .sg1 blueprint includes:
Magic header (SIG1) and version.
Entropy fingerprint (Shannon entropy per chunk) and chaos residuals.
ChaosRegen compression (seeded by π/φ for determinism).
Regent chunk map with Merkle tree for verification.
Access control manifest (time/place/manner policies).
Post-quantum signatures (Kyber/Dilithium for quantum safety).
Optional encryption per segment.
2.2 Regent Framework Regent shards data into verifiable chunks:
Each chunk has entropy scores, hashes, and Reed-Solomon parity.
Supports parallel validation (rayon integration).
Enables recursive graphing: Files shard folders, folders shard drives.
2.3 Recursive Object Graphing Data forms a distributed graph:
Chunks reference siblings via Merkle roots.
Regeneration uses cross-entropy from related .sg1 objects.
Fibonacci encoding for residuals ensures efficient, self-similar recovery.
2.4 Regeneration & Deduplication
Probabilistic reconstruction from partial graphs.
Deduplicate via shared entropy blocks.
Vector-like creation: Fit data to parametric equations (e.g., Bezier with φ ratios) for generative unfold.
2.5 Resilience Modes
Glyph: Lightweight entropy + signature.
Reflection: Adds Reed-Solomon parity for 30% loss tolerance.
Seal: Full redundancy with quantum-safe ratcheting for high-integrity storage.
3. Access Control & Identity
Multi-signature unlock (Dilithium for quantum safety).
Granular policies: Time (expiration), place (geofencing/IP), manner (read-only/audit-required).
Role-based workflows.
Expiry and TTL flags.
Audit trails: Merkle-logged access/edit history, tamper-evident.
Ratchet encryption evolves keys per chunk, ensuring forward security.
4. Use Cases
Sector
Use Case
Forensics
Self-healing disk graphs for evidence preservation.
Gaming
Secure P2P patching with regen validation.
Cybersecurity
File drift detection with entropy deltas.
Legal
Time-locked, multi-signed document graphs.
Storage
Composable, verifiable, encrypted folders.
Disaster Recovery
Redundant entropy-aware backup maps for data lakes.
5. Why It’s Different
Traditional
Sigil + Regent
SHA256 hashes
Entropy + chaos residuals + Merkle trees.
Full-file encryption
Post-quantum ratcheted shards.
Rsync diffs
Cross-graph deduplication with Fibonacci residuals.
Filesystem ACLs
Portable, contextual manifests (time/place/manner).
Backups
Self-healing, regenerative blueprints with vector creation.
ZIP archives
ZK proofs + quantum-safe signatures + partial regen.
6. Roadmap
v0.1: Core .sg1 generator with entropy/chaos.
v0.2: Regent sharding + Merkle verification.
v0.3: Post-quantum access + ratcheting.
v0.4: Reed-Solomon regen + Fibonacci residuals.
v0.5: Data lake integration (Parquet/S3).
v1.0: Full distributed recovery engine + CLI/UI.
v1.x: ZK proofs (Halo2) + delta versioning.
7. Conclusion
Sigil Protocol transforms data from vulnerable files into dynamic, self-healing graphs. By fusing open-source Rust with mathematical innovation, it offers unparalleled resilience against ransomware in data lakes—regenerating from blueprints, enforcing secure access, and verifying integrity offline. Under AGPL-3.0, Sigil invites collaboration to redefine data sovereignty.
For code: https://github.com/Dastille/Sigil-protocol.
Appendix A: Algorithms & Math
Entropy Score: \( H = -\sum p_i \log_2 p_i \) per chunk.
Residual Signature: Difference post-chaos compression.
Fibonacci Encoding: Zeckendorf sums for residuals, anchored by φ.
Chaos Map: Logistic \( x_{n+1} = r x_n (1 - x_n) \), seeded by π.
Reed-Solomon: Parity for n-k recovery.
Merkle Tree: Binary hashing for verification.
Post-Quantum: Kyber encapsulation, Dilithium signing.
Appendix B: Workflows
sigil create <file>: Generate .sg1 blueprint.
sigil verify <file.sg1>: Check integrity/Merkle.
sigil regen <partial.sg1> <sibling.sg1>: Reconstruct from graph.
sigil sign <file.sg1>: Apply quantum-safe signature.
sigil audit <file.sg1>: View logs/policies.
Appendix C: .sg1 Format
Header: SIG1 magic, version.
Metadata: JSON (TTL, tags).
Entropy Block: Scores/residuals.
Chunk Map: Offsets, hashes, Merkle root.
Compression: Chaos output.
Access: Policies, keys.
Signature: Dilithium block.
Optional Log: Audit trail.
