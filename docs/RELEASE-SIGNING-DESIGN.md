# Release and recovery-kit signatures: design options (decision pending)

Status: **design note only.** Releases are unsigned today, and nothing here is implemented. The
recommendation is **pending Ashlynn's OK** (it needs a key she controls). Related:
SFX-DESIGN.md (kit, "Not yet: signatures"), `scripts/make-recovery-kit.sh`,
`.github/workflows/release.yml`.

## 1. Problem

* `release.yml` (manual dispatch) uploads binaries to a GitHub release. It publishes no checksum
  list and no signature.
* The recovery kit writes `SHA256SUMS` and `ARCHIVES.sha256` next to the binaries. A checksum
  file catches **accidental** damage only: whoever can swap a binary can rewrite the checksums
  in the same folder, the same release page or the same mirror.
* So nothing today lets someone years later tell "this is the sigil Ashlynn built" from "a
  binary someone replaced", and a recovery kit is exactly the thing people run in a hurry.

## 2. Options

### A. minisign (Ed25519) detached signatures — recommended
One long-term key, offline. Sign `SHA256SUMS` (one signature covers every artefact). Verify with
`minisign -Vm SHA256SUMS -P <pubkey>`; tiny, audited, static binaries exist for all platforms;
the public key is a one-line string that can be printed in README, START.md and `RECOVER.txt`.
* Cost: key custody (offline copy + backup), a manual signing step at release time.
* Risk: key loss means rotating (publish new key signed by old if possible); key theft means
  revocation by announcement only (no transparency log).

### B. Sigstore / cosign keyless (GitHub OIDC + Rekor transparency log)
CI signs with a short-lived certificate tied to the workflow identity; signatures are logged.
* No long-lived key; public, auditable log.
* Verification needs `cosign` plus network access to Rekor/Fulcio roots (or a saved bundle),
  and trust in GitHub + Sigstore. Weak fit for an offline recovery kit opened in 2040.

### C. Signed git tags (SSH or OpenPGP)
Proves the source tag, not the binaries; needs reproducible builds to connect the two. Good
complement, not a replacement.

### D. Sigil-native signatures
Sigil already has Ed25519 identities (`log` signers). Signing releases with `sigil` itself is
circular for a recovery kit (you must trust the binary to check the binary) and would be new
tooling; no new crypto, but no gain over A. Not recommended.

### E. Platform code signing (Authenticode, Apple Developer ID + notarisation)
Removes OS warnings; needs paid certificates/accounts and a pipeline. Orthogonal to A; only
needed if SFX Option A/C stubs ship (see SFX-DESIGN.md).

## 3. Threat model

In scope: a swapped binary or kit file on a mirror, release page, shared drive or USB stick; a
tampered `SHA256SUMS`; downgrade to an older, signed but vulnerable release (mitigated by the
version being inside the signed list and the trusted comment).
Out of scope: a compromised signing key or build machine (needs reproducible builds and
multiple builders), a compromised verifier binary already on the user's machine.

## 4. Recovery kit (embedding)

With A, `make-recovery-kit.sh` would copy in `SHA256SUMS.minisig` from the release and the
public key as `SIGNING-KEY.pub`, and `RECOVER.txt` would say: check with minisign **using the key
printed in the project README / on paper, not only the copy in this folder** (a swapped kit can
swap its own key). `ARCHIVES.sha256` stays unsigned unless the kit maker signs it with their own
key (optional `--sign-key`, later). The kit would refuse `--bin` files whose hash is not in the
signed list only when asked (`--require-signed`), so local builds still work.

## 5. Licence / distribution notes

* The CLI is AGPL-3.0 (LICENSE, LICENSE.app); the byte layout spec is Apache-2.0 (LICENSE.SPEC).
  Signing does not change obligations: a kit that ships binaries should keep a source offer
  (URL + exact tag/commit) in `RECOVER.txt`; signing the tag (C) makes that offer checkable.
* minisign is ISC-licensed and is used as an external tool, not bundled into sigil.
* Signatures add no restriction on redistribution: third parties may re-host unchanged signed
  files; modified builds are simply not signed by the project key.

## 6. Recommended default (pending Ashlynn's OK)

1. Add a `SHA256SUMS` step to `release.yml` (no key needed; catches accidents).
2. Ashlynn creates one minisign key offline; sign `SHA256SUMS` locally after each manual
   release; upload `SHA256SUMS.minisig`; print the public key in README, START.md, RECOVER.txt.
3. Sign release tags (SSH signing) as a complement.
4. Kit: copy signature + key, add the "check against the key printed elsewhere" step.
Keyless Sigstore (B) can be added later in CI without replacing A.

## 7. Open questions for Ashlynn

1. Who holds the signing key, where is the offline backup, and is one key enough?
2. minisign (A) acceptable, or a preference for OpenPGP / SSH signatures?
3. Should CI ever sign (B), or only local manual signing?
4. Where is the public key published so it outlives the GitHub repo (paper, website, keyserver)?
5. Should kits made by others be signable with their own key (`--sign-key`)?
6. Reproducible builds: worth pursuing so tag signatures cover binaries?
