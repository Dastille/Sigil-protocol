# Self-extracting archives (SFX) with repair: design options (decision pending)

**Status: design note only. Nothing here is implemented; no stub binary exists. The recommended
default below is a proposal pending Ashlynn's decision. Sizes are from the current build
(`target/release/sigil`, Linux x86_64, ~6.6 MB, all features of the default build), not from a
trimmed extractor.**

## Abstract

A Sigil mark (`.sg1`) survives damage because it carries Reed–Solomon parity, spare header copies
(Keystone) and a Merkle binding; but healing and opening it needs a program that understands the
format: today the `sigil` CLI (`mend`, `unseal` / `de-scribe`, `gather`, `kit mend`) or the web
lab's TypeScript codec. An archive found years later on a drive, by someone without the tool, is
only as recoverable as their ability to get that program. A self-extracting archive (SFX) bundles
an extractor with the payload so "run this file" is enough. This note states when that is worth
it, lists five options with their costs, and asks the questions that must be answered first.

## 1. Problem

* **Who asks for it.** Cold storage and hand-offs: a USB kit in a drawer (see
  [LRC-COLD-USB.md](LRC-COLD-USB.md)), an archive sent to a relative or a lawyer, a backup opened
  on a fresh machine with no Rust toolchain and no network.
* **What they need, in order:** (1) open the data; (2) repair it first if it is damaged; (3) trust
  that the thing they are running is not malware.
* **What already exists:** the format is specified ([sigil-v1.txt](sigil-v1.txt), Apache-2.0
  layout) so independent decoders are possible; release builds exist for Linux (musl, static),
  Windows (MSVC) and macOS (aarch64) (`.github/workflows/release.yml`, manual dispatch); the web
  lab codec opens the same bytes in a browser. Any SFX must not fork the `.sg1` layout (format
  policy: additive only; plain seals readable forever).

## 2. Options

### Option 0: No SFX; ship a recovery kit convention

Put next to every archive: the release binaries for the three platforms, their SHA-256 list (and
a signature once releases are signed), `sigil-v1.txt`, and a one-page `RECOVER.txt` ("`sigil
mend X.sg1 -o fixed.sg1`, then `sigil unseal fixed.sg1 -o out`"). Could be written by a
`sigil kit` subcommand later (copy the running binary + docs), but works by hand today.

* **Gains:** no new code path that runs untrusted bytes; the `.sg1` stays a plain data file
  (no antivirus trouble, no executable bit on archives); every platform covered; repair is the
  full `mend` / `kit mend` / `gather`.
* **Costs:** two files instead of one; the user must pick the right binary; binaries can be lost
  or separated from the archive (the drawer problem again, smaller).

### Option A: Stub + payload, Linux x86_64 only (static musl)

`sigil sfx make X.sg1 -o X.run` writes `[extractor ELF][X.sg1 bytes][trailer: magic, payload
offset, length, SHA-256 of payload]`. Running `./X.run` offers: verify, mend in place to a new
file, unseal (prompting for the passphrase on the terminal, as `--pass -`), or "write the plain
`.sg1` out" so the normal tool can take over. `sigil` itself would also open `X.run` (find the
trailer, read the payload) so nothing is locked inside the stub.

* **Gains:** one file; works on any Linux x86_64 with no install; full repair because the stub
  *is* the Sigil code (a trimmed build: no FUSE, no GUI, no passkey).
* **Costs:** a few MB per archive (≈ the extractor size; the current full binary is ~6.6 MB, a
  trimmed one would be smaller, unmeasured); Linux x86_64 only; the stub becomes a release
  artefact that must be versioned and trusted (see threat model); the stub region itself is not
  RS-protected, so damage there needs Option 0's spare binary anyway. AGPL: the bundled
  extractor is a distributed copy of the program, so the source offer applies to every SFX sent.

### Option B: Polyglot script stub that runs an installed `sigil`

`X.sh.sg1` starts with a short POSIX shell header that checks for `sigil` on `PATH` and calls it
on the rest of the file (or prints how to get it).

* **Gains:** tiny overhead; trivial to build.
* **Costs:** needs `sigil` installed, which is exactly what SFX was meant to avoid; Unix only;
  scripts in archives are a classic phishing shape. Little value over Option 0.

### Option C: Platform matrix (Linux, Windows, macOS stubs)

Option A for all three release targets, chosen at `sfx make --target …`.

* **Gains:** "double-click it" for most users.
* **Costs:** Windows SmartScreen and macOS Gatekeeper treat unsigned executables as hostile; to
  be usable they need code signing (Authenticode, Apple Developer ID + notarization), i.e.
  certificates, accounts and a signing pipeline the project does not have. Without that this
  option ships something users are told not to run. Largest maintenance cost.

### Option D: Self-contained HTML page (web lab codec + payload)

One `.html` file: the TypeScript codec, a small UI, and the `.sg1` bytes (base64 or a binary
`<script type="application/octet-stream">` block). Opens offline in any modern browser on any OS.

* **Gains:** no executable, no platform matrix, no code signing; the browser sandbox limits what
  a malicious page could do; the codec is already cross-checked against the CLI in CI.
* **Costs:** base64 adds ~33% to the payload; browsers handle files up to a few hundred MB
  comfortably, not tens of GB; whether the TS codec implements **repair** (RS decode from a
  damaged file, Keystone header recovery) to the same extent as `mend` must be checked before
  this is promised (not verified for this note); the page's own bytes are not RS-protected;
  needs a page build that lives with the lab UI, which already exists in the
  dove-bloom-star-island repository (the codec itself is in this repo, `src/lib/sigil/`); the
  SFX page would be built and tested there, or from a small template here; nothing has to move.

### Comparison

| | 0 kit | A Linux stub | B script | C matrix | D HTML |
|---|---|---|---|---|---|
| One file | no | yes | yes | yes | yes |
| Needs install | no (binary beside it) | no | yes | no | no (browser) |
| Platforms | all release targets | Linux x86_64 | Unix | all three | any browser |
| Full repair | yes | yes | yes (installed tool) | yes | unverified |
| Executable archive | no | yes | yes | yes | no |
| Code signing needed | for trust, optional | for trust, optional | n/a | effectively yes | no |
| Build size | small | medium | small | large | medium |

## 3. Recommended default (proposal, pending Ashlynn's OK)

**Option 0 now, as the documented answer; Option D next if the TS codec's repair is confirmed;
Option A only for a concrete Linux cold-storage need.** Reasons: Option 0 adds no new attack
surface and covers every platform with the full repair path; the archive stays plain data. Option
D is the only single-file form that avoids executable archives and code signing. Option A is
sound but makes every archive carry and vouch for a binary. Options B and C are not recommended
(B adds little; C cannot be done honestly without code-signing infrastructure).

This recommendation is **unverified**: no stub was built, no trimmed extractor size measured, and
the web codec's repair coverage was not checked for this note.

## 4. Threat model

* **Supply chain of the extractor.** Whoever runs an SFX runs code that came with the data. A
  tampered archive can carry a tampered stub (it can steal the passphrase it prompts for). The
  `.sg1` payload's Merkle binding and AEAD protect the *data*, not the stub. Mitigation: stubs are
  byte-identical release artefacts with published SHA-256 (and signatures once releases are
  signed), and `sigil sfx check X.run` (from a trusted install) can compare the stub region to a
  known release before anyone runs it. Option 0 and D avoid running archive-supplied native code.
* **Passphrase entry.** A stub must read the passphrase from the terminal only (as `--pass -`),
  never from arguments or environment; HTML (D) must never send it anywhere (no network code in
  the page; a strict CSP); either way the user is trusting the extractor with the key.
* **Antivirus / OS reputation.** Unknown executables with appended data match common malware
  packer heuristics; expect false positives and quarantine (A, B, C). HTML (D) and plain files (0)
  do not trigger this class.
* **Repair without the full tool.** The parity protects the payload, not the extractor. Damage to
  the stub (A/C) or the page (D) leaves the payload intact but the "just run it" path broken; the
  fallback is always "extract the `.sg1` bytes and use a trusted `sigil`" (keep Option 0's kit).
* **Downgrade.** An old stub may lack fixes. The payload must stay openable by current `sigil`, so
  users can always step outside the stub.

## 5. Interaction with existing commands

* `inscribe` / `seal`: unchanged; an SFX wraps a finished `.sg1` (or a folder pack, a work pack).
* `mend` / `mend --soft` / `unseal --repair`: the stub (A) would expose exactly these; HTML (D)
  only as far as the TS codec does.
* `scatter` / `deluge` / `gather` and `kit place` / `kit mend`: multi-file forms; an SFX of one
  piece does not help reassembly. Option 0's kit is the natural home (the binary beside the
  pieces). A stub could gather from sibling files, but that grows it into the full CLI.
* Encrypted folder packs, private labels, wards: unchanged; the extractor needs the same keys.
* Segment logs: out of scope (a log is a directory, not one file).

## 6. Limitations and non-goals

* Not a new container format; the `.sg1` layout does not change.
* Not an installer, updater or auto-runner. Nothing executes on open; the user runs it.
* Not protection of the extractor by RS parity.
* Not code signing (no infrastructure today).
* Not streaming / INDEX pruning (separate deferred items).

## 7. Open questions for Ashlynn

1. Is SFX wanted at all, or is Option 0 (kit convention, possibly `sigil kit recover-pack`) enough?
2. If single-file: HTML (D) or native Linux stub (A) first?
3. Must the one-file form repair, or is "open if healthy, otherwise use the CLI" acceptable?
4. Size budget per archive for an embedded extractor?
5. Release trust: will releases be signed (and with what key) before any stub ships?
6. For D: should the SFX page be built in dove-bloom-star-island (where the lab UI already
   lives), or as a small standalone template in this repository next to the codec?
7. AGPL: is a bundled source offer (URL + version in `RECOVER.txt` / the stub banner) the intended
   compliance route?

## Prior work in this repo

* [sigil-v1.txt](sigil-v1.txt): the format specification (independent decoders).
* [LRC-COLD-USB.md](LRC-COLD-USB.md): cold USB kits, `kit place` / `kit mend`.
* [PACK-HEAD-REPAIR.md](PACK-HEAD-REPAIR.md), [SOFT-RS.md](SOFT-RS.md): what `mend` repairs.
* README "Web lab": the TypeScript codec and its cross-checks against the CLI.
* Common SFX practice (7-Zip / RAR SFX modules, `makeself` shell archives) is the model for
  Options A and B; their known antivirus and trust issues are the reason for section 4.
