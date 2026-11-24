# Sigil: self-repairing file objects with verified-or-refused recovery

**White paper · Version 1.0 · 23 November 2026 · Final**

Sigil project (github.com/Dastille/Sigil-protocol). Describes the reference implementation
`crate/sigil` as built on 23 November 2026 plus the documentation update of 23 November 2026, and
the release public key published 24 November 2026.
Format specification: `docs/sigil-v1.txt` (Apache-2.0). Program: AGPL-3.0-or-later.

---

## Abstract

Stored files decay. Disks develop bad sectors, downloads are cut short, and over years
individual bits flip ("bit rot"). Common file formats carry no means of repair, and a
damaged copy is often discovered only when it is needed. Sigil is a file format and
command-line tool that wraps a file or folder into one self-contained object, a *Sigil*
(`.sg1`). The object carries Reed–Solomon repair data, several copies of its own header,
and fingerprints of its content. A Sigil in the default mode is about 1.33 times the size
of the original and can be rebuilt after losing any 4 of its 16 pieces; the stronger mode
is about 2 times the size and tolerates losing any 8. Beyond whole lost pieces, a byte-column
repair fixes scattered bit errors inside every piece: on a 1 MB test file, 1 024 random bit
flips spread over all pieces were repaired exactly in 10 of 10 trials. Every repair either
returns bytes that match the stored fingerprints or writes nothing; no measured trial
returned wrong bytes. Optional encryption (AES-256-GCM, passphrases stretched with Argon2id)
hides content and file metadata, and repair works without the key. This paper states the
problem precisely, describes the design, gives the threat model, reports only measured
results with their sources, and lists the limitations.

## 1. Problem statement

### 1.1 Setting

A user stores a file *M* (a byte string of length |*M*|) for years on media that may be
damaged, and may copy it across links that lose or corrupt data. The user wants, at any
later time and from whatever copy survives, either *M* exactly or a clear statement that *M*
cannot be recovered from that copy. Optionally *M* must remain confidential from people who
hold a copy but not the key.

### 1.2 Definitions

**Definition 1 (Sigil).** A Sigil *S* = Encode(*M*, mode, *n*, key?) is a byte string made
of a 160-byte header, three further header copies (Keystone), an optional key-wrap block,
and *n* shards. Each shard is preceded by a header copy (Ember) and followed by its CRC-32.
For mode Reflection *k* = 3*n*/4, for Seal *k* = *n*/2, for Glyph *k* = *n*; by default
*n* = 16.

**Definition 2 (true name and binding).** The *true name* is SHA-256(*M*). The *binding* is
the root of a SHA-256 Merkle tree over the *n* shard payloads as written. Both are stored in
the header. For encrypted Sigils the true-name slot holds a keyed fingerprint instead
(HMAC-SHA256 under a key derived from the content key), and the real true name is stored
inside the encrypted payload.

**Definition 3 (damage).** A damaged copy *S'* differs from *S* in an arbitrary set of byte
positions, may be truncated, and may lack whole shards. A shard is *good* if its CRC-32
matches, *soft* if present but its CRC-32 fails, and *missing* otherwise.

**Definition 4 (acceptance gate).** A candidate output *M''* rebuilt from *S'* is accepted
only if (a) re-encoding *M''* gives shards whose Merkle root equals the stored binding, and
(b) for an unencrypted Sigil, SHA-256(*M''*) equals the stored true name and |*M''*| equals
the stored length. For an encrypted Sigil the AES-GCM tags of the key wrap and the body
must also verify.

### 1.3 Required properties

- **P1 Exactness.** Decode and repair output either *M* exactly, or nothing.
- **P2 Erasure tolerance.** If at least *k* shards are good, *M* is recovered.
- **P3 Error tolerance.** Scattered errors inside soft shards are corrected where the code
  allows (Section 2.9), without a format change.
- **P4 No key for maintenance.** Checking and repairing need no secret.
- **P5 Confidentiality (opt-in).** With a key, content and the file's name and length are
  hidden from holders of a copy who lack the key.

P1 is the central property. P2 follows from the code; P3 is best-effort and measured.

## 2. System overview

### 2.1 The Sigil object

`sigil seal` reads the input, optionally compresses it (DEFLATE), permutes it with a
keyed-by-salt logistic map (the *fold*; this is obfuscation, not encryption), optionally
encrypts it, and splits it into *k* data shards. Large inputs become a *work pack*: a
sequence of Sigils of 4 MiB each in one file, with a list of their fingerprints.
`sigil scry` and `sigil verify` check a Sigil without unpacking it. `sigil unseal` returns
the original. `sigil mend` writes a repaired copy.

### 2.2 Reed–Solomon coding: Reflection and Seal

Byte position by byte position, the *k* data shards are the values of a polynomial of
degree less than *k* over the finite field GF(2^8), and shard *i* holds that polynomial's
value at *x* = *i* + 1 (Reed and Solomon, 1960). The code is systematic (the first *k* shards are the data) and maximum distance
separable: any *k* shards determine the data. Reflection (12 of 16) costs about 1.33 times
the original; Seal (8 of 16) about 2 times. Up to 254 distinct shards are possible, which
`sigil deluge` uses to send extra pieces.

### 2.3 Header redundancy

The 160-byte header (geometry, lengths, true name, salt, nonce, tag, binding) is the map to
everything else. It is stored at the front, three more times as the Keystone, once at the
end as a trailer on new Sigils, and before every shard as an Ember. A Sigil whose front is
destroyed can still be located from any surviving copy.

### 2.4 Ward: encryption

With a passphrase or a recipient key, the payload is encrypted with AES-256-GCM (NIST SP
800-38D) under a random 256-bit content key. The content key is *wrapped*: for a passphrase,
under a key derived with Argon2id (RFC 9106; defaults *m* = 19 456 KiB, *t* = 2, *p* = 1,
stored in the file and capped by readers); for a recipient, with an X25519 key agreement
(RFC 7748) and HKDF-SHA256 (RFC 5869). Identity files (`.sgk`) hold X25519 and Ed25519 (RFC
8032) keys and can themselves be passphrase-protected with Argon2id and AES-256-GCM.
Encrypted Sigils written since October 2026 use header version 3 ("private label"): the
file name, original length and true name move inside the ciphertext, and the outer header
is bound to the ciphertext as AES-GCM associated data.

### 2.5 Key wrap stored twice

The key-wrap block (SGTO, about 100 bytes) is the only part of an encrypted Sigil that is
not covered by Reed–Solomon coding. Until 17 November 2026 one damaged byte in it made the
file unopenable although every shard was intact. Encrypted Sigils written since then (SGTO
version 3) keep a second, identical copy (SGTS) after the shards. A reader uses the front
copy if its CRC-32 checks, else the spare, else a byte-by-byte merge of the two (at most 12
differing bytes); any result must still pass the AES-GCM tags. The extra cost is the wrap
length plus 8 bytes: 109 bytes for a passphrase, 121 bytes for one recipient. Older builds
refuse version-3 files rather than mis-read them.

### 2.6 Frost Rune: cold storage

`sigil frost place` deals the *n* shards of one Seal Sigil round-robin into *D* folders (by
default 4, so 4 shards each), one per unplugged drive, plus a plain manifest. Any *D*/2
drives hold *k* = 8 shards. `sigil frost mend` rebuilds the Sigil from the folders that
remain, through the same acceptance gate. No new code is involved: this is placement of
existing shards.

### 2.7 Channel: rateless transfer (mana)

For one-way or lossy links, `sigil deluge --channel` encodes the whole `.sg1` with RaptorQ
(RFC 6330) into packets called *mana* (`.mana` files). Any sufficiently large set rebuilds
the Sigil; the receiver writes output only if the rebuilt bytes match the object's SHA-256.
The per-packet checksum is an integrity check, not a message authentication code, so an
attacker who can inject packets can prevent recovery but cannot cause wrong output.

### 2.8 Signed segment log

A *segment log* is an append-only archive. `sigil log add` seals each new or changed file as
its own Sigil (a segment) and appends a line to an INDEX whose entries are hash-chained and
summarized by a Merkle root, following the design of Certificate Transparency (RFC 6962).
Sigil's tree splits differently from RFC 6962, so its proofs are not wire-compatible with
RFC 6962 tools. An optional Ed25519 key signs the head. `sigil log verify` checks the chain,
the signature and every segment; inclusion and consistency proofs let a user show that an
entry is in the log and that a later log extends an earlier one. With a key, the INDEX
itself (names, sizes, fingerprints) can be sealed.

### 2.9 Repair: quick, deeper, and scan-estimate-decide

Repair never edits the input. Without `-o`, the output is `<name>.mended.<ext>` next to
the input, with a numeric suffix if that name exists.

**Quick (hard) repair.** Shards are graded good, soft or missing. If at least *k* are good,
Reed–Solomon erasure decoding rebuilds the rest.

**Deeper (soft) repair.** When fewer than *k* shards are good, byte *j* of every shard is
treated as one Reed–Solomon codeword. A single flipped bit is then one wrong symbol in one
column rather than a lost shard. Each column is corrected independently when
2·*e* + *f* ≤ *n* − *k*, with *e* wrong symbols and *f* erasures (Berlekamp–Welch decoding;
Welch and Berlekamp, 1986). The implementation (`crate/sigil/src/soft_ratchet.rs`) works
easiest-first: it locks clean columns in one matrix pass; treats shards that are wrong
almost everywhere as erasures; decodes the remaining columns; promotes a soft shard to
trusted once its stored CRC-32 matches; tries bounded erasure guesses for stuck columns,
locking a guess only when two spare symbols confirm it; settles runs of neighbouring stuck
columns together, because a bad sector damages one shard over many neighbouring columns
(one shared erasure guess must fit every column of the window: collaborative decoding of
interleaved Reed–Solomon codes, Bleichenbacher, Kiayias and Yung, 2003), and decides again,
from its neighbours, any settled column that looks miscorrected (after anchor decoding,
Häger and Pfister, 2018); and uses the linearity of CRC-32 to settle up to 64 last columns. The whole result then passes the acceptance gate once. Only if
that fails are at most 2(*n* − *k*) + 1 older shard-order candidates tried, each through the
gate. Column work and candidates run on up to 8 threads; the output is the same bytes for
any thread count. This is "soft" in the sense of using CRC-failed shards and reliability
ordering (after Forney's generalized minimum distance decoding, 1966); it is not
Koetter–Vardy algebraic soft-decision decoding (2003).

**Default order.** Since 17 November 2026 plain `sigil mend` runs the quick repair and, if
that fails, the deeper repair, and says which was used. `--hard-only` skips the deeper repair.

**Scan, estimate, decide.** Since 18–19 November 2026 `mend` first grades the shards,
names the damage kind (clean, truncated, one region, scattered, mixed) and the likely path,
and computes a padded time estimate from measured throughput (`docs/MEND-SCAN.md`). It
prints the estimate from 10 seconds, asks on a terminal above about 2 minutes, skips
unattended repairs above 15 minutes (exit 4), shows a progress line after 5 seconds, and
stops safely on Ctrl-C (exit 130, nothing written). The scan is advisory: it never accepts
or rejects a result, and the damage kind does not choose the method, because routing by kind
was measured and gave no gain (Section 5.6).

**Several copies.** Damaged copies of one Sigil can be pooled shard by shard; copies of
different Sigils, or copies that disagree on a good shard, are refused.

## 3. Guarantees

**Claim 1 (P1, exactness).** If SHA-256 is collision resistant, any output accepted by the
gate of Definition 4 equals *M*, except with negligible probability. *Reason:* the
accepted shards hash to the stored binding; a different shard set with the same Merkle root
is a SHA-256 collision; the shards determine *M*. For unencrypted Sigils the true name is a
second, independent check. This holds for faults (adversary F, Section 4), not for an
adversary who rewrites header and payload consistently (see Section 4, NOT claimed).

**Claim 2 (P2).** If at least *k* shards are good and the header is locatable from any one
copy, quick repair recovers *M*. *Reason:* the code is maximum distance separable.

**Claim 3 (P3, per column).** A column with *e* wrong symbols and *f* erasures among *n* is
corrected when 2·*e* + *f* ≤ *n* − *k* (Reflection at *n* = 16: *e* ≤ 2 with no erasures;
Seal: *e* ≤ 4). Columns past that bound may still be settled by the CRC-guided steps; if
any column remains wrong, the gate refuses the result. Damage past these bounds is refused,
not guessed.

**Claim 4 (P4).** Grading, scanning and both repairs operate on the stored (possibly
encrypted) shards and the binding, and never need the key.

## 4. Threat model

This section restates, and defers to, the THREAT MODEL of `docs/sigil-v1.txt`, written in
the style of RFC 3552. Assets: the payload (confidentiality only when encrypted;
recoverability always), its identity (true name, binding), metadata (name, sizes, geometry)
and secrets (passphrase, `.sgk` keys, kept outside the Sigil).

| Adversary | Capability | Claimed | NOT claimed |
|---|---|---|---|
| F — faults | bit rot, torn or truncated writes, lost pieces, destroyed front | exact recovery while ≥ *k* shards good; deeper repair within the per-column bound; header found from any copy; key wrap survives damage to either copy (new files) | recovery past the budget; repair of encrypted files written before 17 Nov 2026 whose single key wrap is damaged |
| P — passive holder without key | reads every byte | with encryption: content (AES-256-GCM), and for v3 files the name, length and true name | confidentiality of unencrypted Sigils or their pieces: one unencrypted Seal piece on one Frost Rune drive yields its slice of the payload (tested) |
| A — active tamperer without key | edits bytes, swaps Sigils, crafts hostile headers and pieces | encrypted: GCM rejects any payload change; all: output checked against true name and length; parsers treat input as hostile | authenticity of unencrypted Sigils (header protected only by CRC-32; a consistent rewrite is a valid new Sigil); origin needs a separate signature (`sigil sign`) or a true name known out of band |
| G — offline guesser | runs the passphrase function on guesses | cost per guess is Argon2id at the stored parameters | protection of guessable passphrases; legacy files using PBKDF2 at 80 000 iterations are as weak as before |
| K — key holder | has passphrase or `.sgk` | out of scope by definition | — |

Further items not claimed (spec, "Out of scope"): hiding that a file is a Sigil, whether it
is encrypted, its mode, shard counts and ciphertext length (unless padding is opted into);
rollback to an older valid Sigil without an external record; destruction beyond the budget
or of all copies; compromised endpoints, key theft, malware, side channels and coercion.
Additionally, `scry` and `verify` do not predict repairability: they count good shards only,
so heavy scattered bit rot is reported "NOT recoverable" even when the deeper repair
succeeds (`mend --scan` reports the deeper path).

## 5. Evaluation

Every number below is measured. The source column names the receipt or test; receipts named
`sigil-*` are in the maintainers' receipt folder (not in this repository)
and are summarized in the cited repository document. Numbers not found in such a source
were left out.

### 5.1 Storage overhead

Table 1. Size of one 2 270 725-byte JPEG photograph after sealing (23 Nov 2026).

| Mode | Shards (any of) | Sigil size (bytes) | Ratio |
|---|---:|---:|---:|
| Reflection (default) | 12 of 16 | 3 019 109 | 1.33 |
| Seal | 8 of 16 | 4 526 933 | 1.99 |

Source: `sigil-1123-docs-captures/cap-01-start.txt` and `docs/wiki/Getting-started.md`
(main build of 23 November 2026). The key-wrap spare adds 109 bytes (passphrase) or 121 bytes (one
recipient) per encrypted file (`docs/KEYWRAP-SPARE.md`).

<div style="page-break-before: always"></div>

### 5.2 Scattered bit flips (1 MB file, 10 trials per row)

Table 2. Exact recoveries out of 10, before and after byte-column repair; 1 000 000-byte
random file; Reflection Sigil 1 336 608 bytes, Seal 2 003 264 bytes.

| Mode | Flipped bits | Before | After | WRONG output |
|---|---:|---:|---:|---:|
| Reflection | 1–4 | 10 | 10 | 0 |
| Reflection | 16 / 64 / 256 / 1 024 | 0 | 10 | 0 |
| Reflection | 4 096 | 0 | 3 | 0 |
| Reflection | 16 384 | 0 | 0 | 0 |
| Seal | 16 / 64 / 256 / 1 024 / 4 096 / 16 384 | 0 | 10 | 0 |

Source: `docs/research/DEEP-SPACE.md` §5.2, script `docs/research/deep-space-bench.py`
(fixed seeds). Measured in October 2026, before the easy-first rewrite of Section 2.9;
later changes were tested to return the same bytes where the old search succeeded (test
`mend_soft_matches_old_path_on_damage_corpus`). Ten trials cannot show rare failures; the
argument against wrong output is Claim 1, not these trials.

### 5.3 Contiguous damage (1 MB file, 10 trials per row)

Reflection recovered 10 of 10 with a zeroed run of 1% or 10% of the Sigil, 8 of 10 at 20%,
0 of 10 at 30%; truncation recovered 10 of 10 up to 20%. Seal recovered 10 of 10 with zeroed
runs up to 30% and 7 of 10 at 45%, and 10 of 10 with truncation up to 45%. No trial returned
wrong bytes. Source: `docs/research/DEEP-SPACE.md` §5.2.

### 5.4 Repair time and capability (easy-first, threads)

Table 3. Deeper repair, release build, 8-core build box. "Before" in rows 2–3 is the main build of 20 November 2026 (column work already split into 8 fixed chunks); "after" adds the shared-counter thread race of 22 November 2026.

| Case (10 MB file) | Before | After | Source |
|---|---:|---:|---|
| Reflection, 2 wiped shards + bit-error rate 10⁻³ (refused) | 963.4 s | 0.6–0.8 s | `sigil-1116-mend-soft-timing-and-cli-compare.md`; `docs/SOFT-RS.md` |
| Reflection, 2 lost + 10⁻⁵ (repaired); before vs after the thread race (8 threads) | 1.012 s | 0.599 s | the 22 November race-baseline receipt, `sigil-1122-race-after.txt` |
| Seal, 4 lost + 10⁻⁵ (repaired); before vs after the thread race (8 threads) | 0.955 s | 0.629 s | same |
| Same two repairs, after, limited to 1 thread | — | 2.71 s / 2.52 s | `sigil-1122-race-after.txt` |

On a fixed 60-case damage corpus, the old candidate search repaired 18 cases and the
easy-first repair 36; adding threads did not change the count (36 of 60), only the time
(`sigil-1122-race-after.txt`; test harness `mend_soft_timing` in
`crate/sigil/src/mend_soft_tests.rs`). Output bytes are identical on 1, 2 and 8 threads (test
`mend_soft_same_bytes_any_thread_count`).

### 5.5 Key wrap stored twice

Over 7 200 whole-file damage trials (4 KiB, 1 MiB and 10 MiB files; Reflection and Seal;
random bit errors at three rates and bursts of 512 B, 4 KiB and 10% of the file), files lost
*only* because the key wrap was damaged fell from 908 to 9. A single burst no longer lost any
file to the key wrap (156 before). No trial returned wrong bytes. Source:
`sigil-1117-keywrap-measure/table.md` (totals recomputed 23 Nov 2026: 908 and 9);
`docs/KEYWRAP-SPARE.md`; tests in `crate/sigil/src/keywrap_spare_tests.rs`.

### 5.6 Routing by damage kind (negative result)

Choosing the repair method by the scanned damage kind and racing two methods on mixed damage
was measured on the 60-case corpus (median of 20 runs). Mixed cases took 425.5 ms in total
with the fixed order and 528.0 ms routed (24.1% slower), with the same 36 of 60 repaired.
The fixed order was kept and the code was not merged. Source:
`sigil-1122-route-measure.txt`, `sigil-1123-route-variantA.txt`; `docs/SOFT-RS.md` step 3f.

### 5.7 Scan estimate against an actual repair

A 150 000 000-byte Sigil with 150 000 flipped bits: the scan estimated "about 80 seconds"
(padded high on purpose); the repair took 6.27 s on a 20-thread desktop CPU and
passed the gate. The estimate model uses rates measured on the 8-core build box and is
unverified on slower machines. Source: `sigil-1123-docs-captures/cap-04-progress.txt` and
`README.txt` there; `docs/MEND-SCAN.md`.

## 6. Related work

**Reed–Solomon codes** (Reed and Solomon, 1960) are the basis of the shard code. Sigil uses
them as a systematic maximum-distance-separable code over GF(2^8), both for erasures (whole
shards) and, column by column, for errors.

**PAR2** (Parity Volume Set Specification 2.0) also uses Reed–Solomon recovery data over
files, stored in separate recovery volumes beside the protected files. Sigil instead stores
the recovery data, header copies and fingerprints inside one object, adds optional
encryption whose repair needs no key, and corrects errors inside damaged blocks by byte
column. No head-to-head measurement against PAR2 was made, so no comparison of efficiency is
claimed.

**Generalized minimum distance decoding** (Forney, 1966) erases the least reliable symbols
and retries; Sigil's fallback candidates follow this idea at shard level. **Algebraic
soft-decision decoding** (Koetter and Vardy, 2003) uses per-symbol reliabilities; Sigil does
not implement it. **Berlekamp–Welch** decoding (Welch and Berlekamp, 1986) is used per column.

**RaptorQ** (RFC 6330) is used unchanged for the Channel transfer mode. **Certificate
Transparency** (RFC 6962) provides the model for the segment log's Merkle tree with inclusion
and consistency proofs. **AES-GCM** (NIST SP 800-38D), **Argon2** (RFC 9106), **X25519**
(RFC 7748), **Ed25519** (RFC 8032), **HKDF** (RFC 5869) and **HMAC** (RFC 2104) are used as
specified, through vetted library implementations.

## 7. Limitations

- **Budget.** Damage past *n* − *k* whole shards, or past the per-column bound in any
  column, is refused. Sigil is not a backup schedule; a second copy elsewhere is still needed.
- **Unencrypted Sigils are not authenticated.** The header is protected by CRC-32 only.
- **Health reports are conservative.** `scry`/`verify` can report "NOT recoverable" for a
  file the deeper repair can fix (Section 4).
- **Uncoded regions.** A large-file pack's own head, length framing and fingerprint list are
  not Reed–Solomon coded; heavy damage there is refused. The folder index of a folder pack
  has no spare copy. Encrypted files written before 17 November 2026 have one key-wrap copy.
- **Measurement scope.** Bit-flip results use independent uniform flips, 10 trials per row,
  on one x86-64 machine; burst, stuck-bit and multi-bit-upset patterns were measured only as
  zeroed runs. Time estimates come from one 8-core machine.
- **Wait screen.** The question is asked before the repair, not after the quick part; there
  is no live re-estimate and no "finish later" option. Large-file packs, folder packs and
  pooled copies are not scanned by plain `mend`. On Windows, Ctrl-C ends the process at once.
- **Memory.** A segment-log segment is sealed in memory, so a single file larger than memory
  cannot be added to a log.
- **Release signing.** The official minisign public key (id `6AA9D817CBAC87FA`) is in
  `keys/sigil-release.pub` and is also printed in the README and START.md:

      untrusted comment: minisign public key 6AA9D817CBAC87FA
      RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi

  No release has been signed with it yet; existing checksum files (`SHA256SUMS`) catch
  accidental damage, not a swapped file. Once a release includes `SHA256SUMS.minisig`,
  verify with
  `minisign -Vm SHA256SUMS -P RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi`, then
  `sha256sum -c SHA256SUMS`. Compare the key against more than one place (the repo file, the
  README, and a paper copy).
- **Platforms.** Built and tested on Linux only.

## 8. Reproducing the results

```
git clone https://github.com/Dastille/Sigil-protocol.git && cd Sigil-protocol
cargo build --locked --release --bin sigil
cargo test --locked                      # includes the equivalence and thread tests named above
python3 docs/research/deep-space-bench.py target/release/sigil 10 1000000
```

The timing harness is `cargo test --release mend_soft_timing -- --ignored --nocapture`
(see `docs/SOFT-RS.md`); the key-wrap measurement is `crate/sigil/src/keywrap_measure.rs`.

## References

1. I. S. Reed and G. Solomon, "Polynomial Codes Over Certain Finite Fields," *Journal of the
   Society for Industrial and Applied Mathematics*, vol. 8, no. 2, pp. 300–304, 1960.
   doi:10.1137/0108018.
2. G. D. Forney, Jr., "Generalized minimum distance decoding," *IEEE Transactions on
   Information Theory*, vol. 12, no. 2, pp. 125–131, 1966. doi:10.1109/TIT.1966.1053873.
3. R. Koetter and A. Vardy, "Algebraic soft-decision decoding of Reed–Solomon codes," *IEEE
   Transactions on Information Theory*, vol. 49, no. 11, pp. 2809–2825, 2003.
   doi:10.1109/TIT.2003.819332.
4. L. R. Welch and E. R. Berlekamp, "Error correction for algebraic block codes," U.S. Patent
   4,633,470, 30 December 1986.
5. M. Luby, A. Shokrollahi, M. Watson, T. Stockhammer and L. Minder, "RaptorQ Forward Error
   Correction Scheme for Object Delivery," RFC 6330, IETF, August 2011.
6. B. Laurie, A. Langley and E. Kasper, "Certificate Transparency," RFC 6962, IETF, June 2013.
7. A. Biryukov, D. Dinu, D. Khovratovich and S. Josefsson, "Argon2 Memory-Hard Function for
   Password Hashing and Proof-of-Work Applications," RFC 9106, IRTF, September 2021.
8. M. Dworkin, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
   and GMAC," NIST Special Publication 800-38D, November 2007.
9. A. Langley, M. Hamburg and S. Turner, "Elliptic Curves for Security," RFC 7748, IETF,
   January 2016.
10. S. Josefsson and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA),"
    RFC 8032, IETF, January 2017.
11. H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function
    (HKDF)," RFC 5869, IETF, May 2010.
12. H. Krawczyk, M. Bellare and R. Canetti, "HMAC: Keyed-Hashing for Message
    Authentication," RFC 2104, IETF, February 1997.
13. E. Rescorla and B. Korver, "Guidelines for Writing RFC Text on Security
    Considerations," RFC 3552, IETF, July 2003.
14. Parchive project, "Parity Volume Set Specification 2.0," 2003.
    https://parchive.github.io/doc/Parity%20Volume%20Set%20Specification%20v2.0.html

---
*Changelog: 1.0 (23 November 2026) — first version.*
