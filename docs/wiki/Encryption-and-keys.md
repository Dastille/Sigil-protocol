# Encryption and keys

*Version 1.0, 23 November 2026. Output captured from Sigil built from the main branch on 23 November 2026.*

A plain Sigil protects a file from **damage**, not from **reading**: anyone with the file
can open it. To keep a file private, lock it. Sigil has two ways.

| Way | You keep | Good for |
|---|---|---|
| Passphrase | a long phrase you remember | your own files |
| Key file ("encrypt-to") | a key file (`.sgk`) and its public half (`.pub`) | files for yourself on other machines, or for someone else |

Both use AES-256-GCM, a standard, widely reviewed method of encryption. A passphrase is
stretched with Argon2id, a method designed to make guessing slow.

## Lock with a passphrase

Sigil does not accept the passphrase typed straight into the command, because other
programs on the computer could see it. Either type it when asked (`--pass -`), or put it on
the first line of a file that only you can read (`chmod 600 my-pass.txt`):

```
$ sigil seal --pass-file my-pass.txt -o secret.sg1 photo.jpg
inscribed 2270725 bytes → secret.sg1

$ sigil scry secret.sg1
ok  v3  live=16/16 need=12 merkle=closed keystone=intact label=private (name, size and fingerprint inside the lock)
attestation: none (no .sig beside this file)
```

Without the key, even the file name and size stay hidden (`label=private`). Opening it:

```
$ sigil unseal -o secret-out.jpg secret.sg1
passphrase or --identity required — this Sigil Archive is Warded

What you can try:
  - Provide the passphrase interactively with --pass - or from a file with --pass-file <path>
  - Or pass your authorized secret key with --identity <me.sgk> (or --talisman <keyfile> for a Talisman Ward)

$ sigil unseal --pass-file wrong-pass.txt -o secret-out.jpg secret.sg1
Wrong passphrase or key — this Sigil Archive is Warded (matching --identity or passphrase did not unlock it)

What you can try:
  - Check your passphrase and try again with --pass - (interactive) or --pass-file <path>
  - If Warded to a recipient key, pass the matching secret key with --identity <me.sgk>
  - If shared with multiple recipients, ask another listed recipient to unlock it with their .sgk key
  - If a Tome member has its own Ward, pass --ward-file <member>=<pwfile> (or --ward <member>:-)
  - Sigil Wards have no password reset — if the key is lost, check for an unencrypted backup or an earlier Vault version (sigil vault versions)

$ sigil unseal --pass-file my-pass.txt -o secret-out.jpg secret.sg1
de-scribed 2270725 bytes → secret-out.jpg
```

(The first command was run with no keyboard attached; at a terminal it asks for the
passphrase. Both errors exit with code 1.)

Typing the passphrase into the command is refused:

```
$ sigil seal --pass 'correct horse battery staple' -o x.sg1 photo.jpg
error: --pass <PASS>: a passphrase given as --pass VALUE is refused: it is visible to other programs on this computer (process list) and may be saved in your shell history. Use --pass-file PATH (a file only you can read, e.g. --pass-file <(pass show sigil)) or --pass - (type it, hidden)
```

## Lock to a key file (encrypt-to)

Make a key pair once. The secret half (`me.sgk`) is itself locked with a passphrase:

```
$ sigil keygen -o me.sgk --pass-file my-pass.txt
identity → me.sgk  (passphrase-protected)  x25519 db51baecdcdc25391bdeb327d2139822dc754c3df6e9853dd799c4d888d2fe5d
public → me.sgk.pub  (encrypt-to: --to me.sgk.pub)
attest seed is inside .sgk; sign with --key me.sgk
keep the passphrase safe: without it this identity cannot be opened (there is no reset)
```

The long string of letters and digits is the public key written in hexadecimal (a way of
writing numbers with the digits 0–9 and the letters a–f). You never need to type it.

Anyone with `me.sgk.pub` can lock a file that only `me.sgk` opens:

```
$ sigil seal --to me.sgk.pub -o for-me.sg1 photo.jpg
inscribed 2270725 bytes → for-me.sg1 (encrypt-to 1 recipient)

$ sigil unseal --identity me.sgk --identity-pass-file my-pass.txt -o for-me-out.jpg for-me.sg1
de-scribed 2270725 bytes → for-me-out.jpg

$ sigil unseal --identity me.sgk --identity-pass-file wrong-pass.txt -o for-me-out2.jpg for-me.sg1
me.sgk: wrong passphrase, or the identity file was changed or damaged (SGKP check failed); nothing was unlocked
```

## Repair works without the key

A locked Sigil can be checked and repaired without the passphrase, so a helper can fix it
without being able to read it:

```
$ sigil mend secret-torn.sg1
mended secret-torn.sg1 → secret-torn.mended.sg1 (live 16/16, need 12, merkle ok)
Your repaired copy is secret-torn.mended.sg1 (no -o given, so Sigil picked a new name next to the original). The damaged file was left as it is.
To double-check the repaired copy: sigil verify secret-torn.mended.sg1

$ sigil unseal --pass-file my-pass.txt -o secret-back.jpg secret-torn.mended.sg1
de-scribed 2270725 bytes → secret-back.jpg
```

Since 17 November 2026, locked Sigils keep two copies of the small block that unlocks
them (the "key wrap"), one at the front and one at the end, so damage in one place no
longer makes the file unopenable. Locked Sigils made before that date keep one copy;
seal them again to get the second.

## A lost key cannot be reset

There is no "forgot my password" for Sigil. Nobody, including the people who wrote Sigil,
can open a locked Sigil without its passphrase or key file. Before you lock anything
important:

- write the passphrase down and keep it somewhere safe and separate;
- keep a copy of `me.sgk` (it is useless without its passphrase) on another drive;
- test that you can open the file before you delete the original.

## What a lock does not hide

Without the key, someone can still see that a file is a Sigil, that it is locked, roughly
how big it is, and its name on disk. Give locked files plain names (`2026-a.sg1`, not
`medical-records.sg1`). Details: [PRIVATE-LABEL.md](../PRIVATE-LABEL.md).
