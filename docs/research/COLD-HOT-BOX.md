# Cold and hot Sigil boxes: one-way signed health reports

Status: design note only. No `.sg1` format change and no new command. The one code
change shipped with this note is a key-file permission fix found while testing it
(section 9). The product name for the box is not picked; "cold Sigil box" and "hot
Sigil server" are working labels.

## Abstract

Frost Rune drives sit in a drawer and nobody checks them until the day they are
needed. A small computer with Sigil installed could hold those drives, check and
mend them on a schedule, and send out signed health reports over a link that
cannot carry anything back in. This note states the problem, separates the two
things "one-way" can mean, tests what today's commands already give, sketches a
report format, threat-models it, and lists what would have to be built. Its main
findings, all from runs on 2026-11-11: today a box could sign a scrub report but
nothing on the receiving side can verify that signature from the command line;
`doctor --scrub` cannot write JSON; `doctor --scrub` on a Frost Rune drive checks
nothing and still exits 0; and `sigil keygen --legacy` wrote its signing seed
world-readable (fixed here).

## 1. Direction (Ashlynn's words)

- 2026-11-09, 9:39 AM ET: "Yes, so thinking of it from a sigil perspective, either
  cold or hot storage, or a cold storage computer with sigil on it that can do a one
  way talk (like a yubico key hardware key has a one way hardware on it)."
- 2026-10-26: "I want you to think hard about how people would use this in a
  different environment such as Linux server, databases, Windows servers, AWS,
  mainframe even, etc."
- 2026-11-10, 12:10 AM ET: approved this note as item 2 of the design-note queue
  (after damage marking, before the long-term decoder and quantum-safe notes).

## 2. Problem

1. **Nobody looks at cold copies.** Frost Rune deals a Seal's shards round-robin
   onto D drives (default 4 drives, 4 of 16 shards each) and tolerates losing
   whole drives while k shards survive (`docs/sigil-v1.txt:136–154`). Bit rot that
   is not noticed piles up until it passes n − k and the file is gone
   (`docs/sigil-v1.txt:183–197`). The README already says to run
   `sigil doctor --scrub` "on a schedule so small damage is fixed before it piles
   up" (`README.md:147–150`), but a drawer has no schedule.
2. **A checking computer is an attack surface.** If a computer stays plugged into
   the cold drives so it can check them, anything that can talk *to* it can try to
   change or delete them. The point of cold storage is that nothing reaches it.
3. **A report is only useful if you can trust it and notice when it stops.** A
   report that can be forged, replayed from last year, or silently not sent gives
   false comfort.

## 3. What "one-way" can mean (two separate properties)

- **One-way link (data diode).** NIST SP 800-82r3 defines a data diode as "a
  network appliance or device that allows data to travel only in one direction",
  and notes that, unlike a firewall, "data diodes cannot be programmed to allow
  data to flow in both directions because the hardware is incapable" [1]. For the
  box: reports go out, nothing comes in over that link.
- **Key that never leaves (hardware security key).** Yubico's documentation states
  that a private key in a YubiKey PIV slot "resides in the YubiKey's secure
  element, from which it cannot be extracted or exported" [2], and `ykman piv keys
  generate` lists ED25519 among the on-device algorithms [3]. For the box: the
  signing key that proves "this report came from the box" cannot be copied off it,
  even by someone who takes the box.

Ashlynn's YubiKey example is closest to the second; her "one way talk" wording is
the first. A good box wants both: a non-exportable signing key, and an outbound-only
report path. They protect different things (sections 6 and 7).

## 4. What today's Sigil already gives (tested 2026-11-11)

Receipt: `/workspace/receipts/sigil-1111-box-experiments.txt` (release build of
main `f44970b`, umask 0022).

| Need | Today | Evidence |
|---|---|---|
| Check and mend without the key | Yes for `.sg1` files: `mend`, `scry`, `verify`, `doctor` work without the key on encrypted Sigils | `README.md:324`; scrub repaired a flipped bit: "REPAIRED (Merkle + true name checked)" |
| Check Frost Rune pieces on a drive | **No.** `doctor --scrub frost/usb-0` printed "scrub: 0 Sigil(s) … 0 clean" and **exited 0**; `doctor frost` exited 3 ("nothing found") | receipt lines 17–24. Update 2026-11-13: scrub now fails closed here (lists the pieces as NOT CHECKED, exit 3); it still cannot check them |
| Machine-readable scrub report | **No.** "the argument '--scrub' cannot be used with '--json'" (exit 2) | receipt lines 4–11 |
| Sign a report | Yes: `sigil sign report --key box.sgk` writes `report.sig` (Ed25519 over SHA-256 of the file) | `crate/sigil/src/attest.rs`; receipt line 26 |
| Verify a signed report (CLI) | **No.** `sigil verify report.json` tries to parse it as a Sigil: "failed to fill whole buffer", exit 1. The library function works on any file (new test `attest::tests::signed_report_roundtrip_and_tamper_fails`) | receipt lines 29–32 |
| Pin the box's key | **No.** The `.sig` carries its own public key and verify prints `pubkey=…`; a verifier that does not compare it to a pinned key accepts a report re-signed by anyone | `attest.rs` `verify_attestation` |

So a "level 0" box (cron job: scrub, sign, copy out) is possible today only for
plain `.sg1` folders, with text output, and the receiving side would have to verify
with its own code. It would also report "0 clean, exit 0" for a Frost Rune drive,
which is the dangerous case: **a health check that checked nothing must not look
healthy.** That is a fail-open default and is the first code fix this note
recommends (section 10).

## 5. Report design (proposal, sidecar only)

A health report is a small text file plus a detached signature, not a `.sg1`.

Contents (each line plain text, readable without Sigil):
- box public key (Ed25519 today) and a box label;
- **sequence number**, strictly increasing, kept on the box;
- **hash of the previous report** (a hash chain, so a deleted or reordered report
  shows as a gap);
- box clock time, labelled as untrusted (the box has no inbound time source);
- per archive: true name, mode, k/n, status (`healthy`, `repaired`,
  `needs-repair`, `not-recoverable`, `not-checked`), shards present/bad, and what
  was repaired;
- per holder (drive): shards checked, bad, missing; with stripe checks from
  `docs/research/DAMAGE-MARKING.md` §5, bad stripes too;
- a count of items **not checked**, with reasons. "Not checked" is never folded
  into "healthy".

Receiver rules:
- verify the signature against a **pinned** box key, never the key inside the
  `.sig`;
- accept only a sequence number one above the last accepted, with the matching
  previous-report hash;
- **alarm when no report arrives by the deadline** (for example a weekly report
  with a 9-day deadline). Silence is a finding.

## 6. Threat model

Adversaries use the letters of `docs/sigil-v1.txt:159–222` (F faults, P passive
holder, A active tamperer, G guesser, K key holder). New cases for the box are
marked **B** (box compromise) and **H** (lying hot holder). None of this is claimed
by the shipped code; it is what the design must meet.

| Threat | Covered by | Not covered |
|---|---|---|
| F: bit rot, dead drive | scheduled scrub + mend (fail closed: rewrite only when Merkle and true name match, `README.md:147–150`); report names the failing drive | damage past n − k |
| P: box or one drive stolen | archives on the box must be **encrypted** (encrypt-to or passphrase); the box needs no decryption key to check or mend (`README.md:324`). Plain Seal pieces are readable from one drive (`docs/sigil-v1.txt:149–154`, tested) | plain archives; file names and true names in plain headers and KIT (`docs/sigil-v1.txt:152–153`) |
| A: report changed or forged in transit | Ed25519 signature checked against a pinned key | a verifier that trusts the key inside the `.sig` |
| A: old "healthy" report replayed, or reports suppressed | sequence number + previous-hash chain + receiver deadline alarm | an attacker who blocks every report gets an alarm, not data |
| B: attacker reaches the box over the network | outbound-only link (data diode): no network path in [1] | physical access, USB sticks used to load new archives, supply chain; a diode "does nothing about threats arriving by other routes" (see [1] scope) |
| B: box key copied | key generated in a hardware key (non-exportable [2]) or, at minimum, an owner-only key file (section 9) | a fully compromised box can still sign false reports while compromised; a signature proves *who* said it, not that it is *true* |
| H: a hot server (Sigil installed) says "healthy" but threw the data away | **not covered by one-way reports.** Detecting this needs the owner to challenge the holder and check the answer: spot-fetch random shards and check them against the true name or a signed stripe table (`DAMAGE-MARKING.md` §5), or proofs of data possession [5][6]. Challenges need an inbound path, so they do not fit a one-way box | everything until a challenge protocol exists |
| Quantum adversary | not covered: Ed25519 is not post-quantum. A forged report matters only while it is current, so signatures are a lower priority than harvest-now risk to encrypt-to; queued for the quantum-safe note | all of it, today |
| Side channels on the box | out of scope (`docs/sigil-v1.txt:296`) | |

## 7. Carriers for the one-way link

Ranked by how hard it is to send something back in. All are proposals; none is
built or measured here.

1. **Screen to camera**: the box shows the report and signature as QR codes; a
   phone or PC camera reads them. Nothing can flow back. Report size matters
   (one Ed25519 signature is 64 bytes plus 32 for the key). A watch item from the
   2026-11-09 packet (AirFerry, animated QR with RaptorQ) is the same idea for
   bigger payloads.
2. **Transmit-only serial or optical diode** (the NIST data diode [1]). Commercial
   hardware exists; a hobby build (receive pin cut) is possible but unverified here.
3. **Paper**: the box prints a weekly report; the human is the carrier. Fits the
   PaperBack tier and "Sigil not installed" readers.
4. **Not one-way**: a USB stick carried back and forth, a network share, email.
   Any of these is an inbound path; use only with the box's own write-protection
   and accept that this is a normal networked computer, not a cold box.

## 8. Perspectives (Ashlynn 2026-11-09 list and 2026-10-26 targets)

- **Cold storage (Frost Rune).** The main case. Box holds D drives, scrubs, mends
  inside the budget, reports outward. Needs `doctor --scrub` to read `.sgp` pieces
  per drive (today it does not; section 4).
- **Hot storage (Fire Rune, reserved name, no behaviour claimed,
  `docs/sigil-v1.txt:156–157`).** The same report format works for a hot server,
  but a hot server is exactly the holder that can lie (H). One-way reports are
  "self-reporting"; hot storage needs owner-driven challenges as well.
- **Servers (Linux, Windows).** A server with Sigil installed can run the same
  scrub-and-sign job from cron or Task Scheduler and push reports to a log host.
  A server is networked, so the one-way property is lost; the signed, chained,
  deadline-checked report still helps.
- **Personal PCs.** A family member's PC can run the scheduled scrub; the report
  goes to Ashlynn. The PC is not a cold box; the value is "someone checks the
  drawer". Plain archives on a family PC are readable by anyone at that PC (P).
- **Cloud vs non-cloud (AWS).** A cloud bucket cannot be a one-way box: the
  provider is a passive holder (P) and possibly an active one (A/H). The owner
  side must fetch-and-verify (true name, signed stripe table). Archive-tier
  storage that charges per retrieval makes spot checks a cost question; not
  measured here.
- **Databases.** Database dumps sealed as `.sg1` go on the box like any file. The
  box never needs the database or its credentials.
- **Mainframe / tape.** A tape library with a controller is close to a box
  already: it mounts media on a schedule. The report format is plain text so a
  mainframe job could produce or consume it; untested.
- **Sigil installed vs not installed.** The box must have Sigil. The *reader of
  the report* should not need it: the report is plain text, and the signature is
  plain Ed25519 [4] over SHA-256 of the file, so any Ed25519 tool can verify it
  given the pinned key (not tested with a non-Sigil tool yet). The drives
  themselves stay recoverable without the box (recovery kit,
  `docs/SFX-DESIGN.md`).
- **Paper.** Printed reports are a one-way carrier with a human reader; a paper
  copy of the pinned box key is the trust anchor.

## 9. Fix shipped with this note: legacy signing seed was world-readable

Reproduced on main `f44970b` with umask 0022: `sigil keygen --legacy -o leg2.key`
created `leg2.key` with mode **644** while `sigil keygen -o box.sgk` created mode
600 (receipt lines 33–40). The legacy seed is a raw Ed25519 signing key (also usable
as a Talisman), so any local user could copy it and sign as its owner.

Fix: `attest::keygen` now writes through `keys::write_secret_file` (created 0600),
and `write_secret_file` now also tightens an **existing** file to 0600 before
writing the secret (previously `mode(0o600)` applied only to new files). The seed
buffer is zeroized on drop. Tests:
`attest::tests::legacy_seed_file_is_owner_only_even_over_old_world_readable_file`
(failed before the fix: mode 420 = 0o644; passes after) and
`attest::tests::signed_report_roundtrip_and_tamper_fails`.

## 10. Recommended next steps (each needs Ashlynn's OK before code)

1. **Fail-closed scrub** (small, safe-by-default fix): `doctor --scrub` on a folder
   with no `.sg1` files, or with Frost Rune pieces it does not read, must not exit
   0. Exit 3 ("could not check"), matching `doctor`.
2. **`doctor --scrub --json`** with the per-archive and not-checked fields above.
3. **Scrub Frost Rune drives**: read `.sgp` pieces per `usb-*` folder, check each
   piece's CRC, and report per drive; mend only when enough pieces are present.
4. **`sigil verify-sig FILE --key BOX.pub`**: verify a detached signature on any
   file against a pinned key (refuse when the key inside the `.sig` differs).
5. **`sigil box report`**: sequence number, previous-report hash, signed output.
6. Later: hardware-key signing (PIV/PKCS#11), a QR display mode, and a challenge
   protocol for hot holders. The hardware-key path adds a dependency and is
   untested here.

## 11. Limitations

- Nothing in sections 5–8 is built or measured. Carrier ranking is reasoning, not
  a test. No hardware was used.
- A signature proves which key signed a report, not that the report is true. A
  compromised box can lie until it is found out.
- One-way reports cannot detect a lying hot holder (H); that needs challenges.
- Ed25519 is not quantum-safe.
- Claims about YubiKey and data diodes come from vendor and NIST documentation
  [1][2][3], not from our own tests.
- The Ed25519-tool interoperability claim in §8 is untested.

## Citations

1. K. Stouffer et al., *Guide to Operational Technology (OT) Security*, NIST
   SP 800-82r3, Sept 2023, glossary ("data diode", "unidirectional gateway") and
   appendix E.1.2. https://doi.org/10.6028/NIST.SP.800-82r3 (opened 2026-11-11).
2. Yubico, *Provision Your Certificate onto Your iOS Keychain*, Yubico
   Authenticator User Guide.
   https://docs.yubico.com/software/yubikey/tools/authenticator/auth-guide/smartc-provisioning.html
   (opened 2026-11-11).
3. Yubico, *PIV Commands*, YubiKey Manager (ykman) CLI Guide.
   https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html
   (opened 2026-11-11).
4. S. Josefsson, I. Liusvaara, *Edwards-Curve Digital Signature Algorithm
   (EdDSA)*, RFC 8032, 2017. (Not re-opened this run.)
5. G. Ateniese et al., "Provable data possession at untrusted stores", ACM CCS
   2007. (Not re-opened this run.)
6. A. Juels, B. Kaliski, "PORs: proofs of retrievability for large files", ACM
   CCS 2007. (Not re-opened this run.)
7. Sigil: `docs/sigil-v1.txt`, `README.md`, `docs/research/DAMAGE-MARKING.md`,
   `docs/SFX-DESIGN.md`, `crate/sigil/src/attest.rs`, `crate/sigil/src/keys.rs`.
