# Release and recovery-folder signatures (minisign + signed tags)

> **Decision (2026-11-02): Option A (minisign) + C (signed tags).** Shipped:
> `scripts/make-sha256sums.sh` and a `checksums` job in `release.yml` that uploads
> `SHA256SUMS` (no key, no secret); the minisign public key in `keys/sigil-release.pub`
> (created 24 November 2026, id `6AA9D817CBAC87FA`); recovery folders always copy that key
> as `SIGNING-KEY.pub`, and copy `SHA256SUMS.minisig` when one is supplied (`--minisig` or a
> file next to the archive). CI never signs. **Not done:** signing the first release tag
> (`SHA256SUMS.minisig` does not exist yet); SSH-signed tags; a paper copy of the public key
> held offline.
>
> Public key (also in the README, START.md, the white paper, and `RECOVER.txt`):
> ```
> untrusted comment: minisign public key 6AA9D817CBAC87FA
> RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi
> ```
>
> Manual signing after each release (key holder, offline machine):
> ```
> minisign -G -p sigil-release.pub -s sigil-release.key     # already done; back the .key up offline
> gh release download vX.Y.Z -p SHA256SUMS
> minisign -Sm SHA256SUMS -s sigil-release.key -t "sigil vX.Y.Z"
> gh release upload vX.Y.Z SHA256SUMS.minisig
> ```
> Verify: `minisign -Vm SHA256SUMS -P RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi`
> then `sha256sum -c SHA256SUMS`. Compare the key against more than one place (the repo file,
> the README, and a paper copy).
>
> Tag signing (SSH): `git config gpg.format ssh; git config user.signingkey ~/.ssh/id_ed25519.pub;
> git tag -s vX.Y.Z -m "sigil vX.Y.Z"; git push origin vX.Y.Z`. Verify with an allowed-signers
> file: `git config gpg.ssh.allowedSignersFile allowed_signers; git tag -v vX.Y.Z`.
>
> Recovery folder layout: `sigil-recovery/SIGNING-KEY.pub` (always) and, when supplied,
> `sigil-recovery/SHA256SUMS.minisig` (the official *release* signature). RECOVER.txt tells
> the reader to compare the key against the one printed in the README / on paper, never only
> the recovery folder copy, and to verify `SHA256SUMS.minisig` next to the release
> `SHA256SUMS`, not as a signature of the folder's own checksums.

Status: public key published; no release signed yet. Related: SFX-DESIGN.md,
`scripts/make-recovery-kit.sh`, `.github/workflows/release.yml`.

## 1. Problem

* `release.yml` (manual dispatch) uploads binaries to a GitHub release. It publishes no checksum
  list and no signature.
* The recovery folder writes `SHA256SUMS` and `ARCHIVES.sha256` next to the binaries. A checksum
  file catches **accidental** damage only: whoever can swap a binary can rewrite the checksums
  in the same folder, the same release page or the same mirror.
* So nothing today lets someone years later tell "this is the sigil the maintainer built" from "a
  binary someone replaced", and a recovery folder is exactly the thing people run in a hurry.

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
  and trust in GitHub + Sigstore. Weak fit for an offline recovery folder opened in 2040.

### C. Signed git tags (SSH or OpenPGP)
Proves the source tag, not the binaries; needs reproducible builds to connect the two. Good
complement, not a replacement.

### D. Sigil-native signatures
Sigil already has Ed25519 identities (`log` signers). Signing releases with `sigil` itself is
circular for a recovery folder (you must trust the binary to check the binary) and would be new
tooling; no new crypto, but no gain over A. Not recommended.

### E. Platform code signing (Authenticode, Apple Developer ID + notarisation)
Removes OS warnings; needs paid certificates/accounts and a pipeline. Orthogonal to A; only
needed if SFX Option A/C stubs ship (see SFX-DESIGN.md).

## 3. Threat model

In scope: a swapped binary or recovery folder file on a mirror, release page, shared drive or USB stick; a
tampered `SHA256SUMS`; downgrade to an older, signed but vulnerable release (mitigated by the
version being inside the signed list and the trusted comment).
Out of scope: a compromised signing key or build machine (needs reproducible builds and
multiple builders), a compromised verifier binary already on the user's machine.

## 4. Recovery folder (embedding)

`make-recovery-kit.sh` always copies the public key as `SIGNING-KEY.pub`, and copies
`SHA256SUMS.minisig` from the release when `--minisig FILE` is given or when that file sits
next to the archive. `RECOVER.txt` says: check with minisign **using the key printed in the
project README / on paper, not only the copy in this folder** (a swapped recovery folder can
swap its own key). `ARCHIVES.sha256` stays unsigned unless the recovery folder maker signs it with their own
key (optional `--sign-key`, later). The recovery folder would refuse `--bin` files whose hash is not in the
signed list only when asked (`--require-signed`), so local builds still work.

## 5. Licence / distribution notes

* The CLI is AGPL-3.0 (LICENSE, LICENSE.app); the byte layout spec is Apache-2.0 (LICENSE.SPEC).
  Signing does not change obligations: a recovery folder that ships binaries should keep a source offer
  (URL + exact tag/commit) in `RECOVER.txt`; signing the tag (C) makes that offer checkable.
* minisign is ISC-licensed and is used as an external tool, not bundled into sigil.
* Signatures add no restriction on redistribution: third parties may re-host unchanged signed
  files; modified builds are simply not signed by the project key.

## 6. Recommended default (locked 2026-11-02; key created 2026-11-24)

1. Add a `SHA256SUMS` step to `release.yml` (no key needed; catches accidents). **Done.**
2. The maintainer creates one minisign key offline; print the public key in README, START.md,
   RECOVER.txt and `keys/sigil-release.pub`. **Done** (id `6AA9D817CBAC87FA`). Still to do:
   sign `SHA256SUMS` locally after each manual release and upload `SHA256SUMS.minisig`.
3. Sign release tags (SSH signing) as a complement. **Not done.**
4. Recovery folder: copy the public key always, copy the release signature when supplied, and
   tell the reader to check the key against the one printed elsewhere. **Done** (key copy);
   signature copy waits on the first signed release.
Keyless Sigstore (B) can be added later in CI without replacing A.

## 7. Open questions

1. Who holds the signing key, where is the offline backup, and is one key enough?
2. minisign (A) acceptable, or a preference for OpenPGP / SSH signatures?
3. Should CI ever sign (B), or only local manual signing?
4. Where is the public key published so it outlives the GitHub repo (paper, website, keyserver)?
5. Should recovery folders made by others be signable with their own key (`--sign-key`)?
6. Reproducible builds: worth pursuing so tag signatures cover binaries?
