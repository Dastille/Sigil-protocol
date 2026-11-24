# Archives and the signed log

*Version 1.0, 23 November 2026. Output captured from Sigil built from the main branch on 23 November 2026.*

A **segment log** is an archive that only grows. Each time you back up a folder, Sigil
wraps every new or changed file as its own Sigil (a **segment**) and adds a line to the
log's list (the **INDEX**). Old entries are never rewritten. If the log is **signed**, a key
you hold vouches for every addition, so you can later prove the archive was not altered.

## Make a signing key and a log

```
$ sigil keygen -o signer.sgk --pass-file my-pass.txt
identity → signer.sgk  (passphrase-protected)  x25519 6dc10dfd0a7572854460d9b97dcfa8cf28487edbe87fc080777e8ddd47609d22
public → signer.sgk.pub  (encrypt-to: --to signer.sgk.pub)
attest seed is inside .sgk; sign with --key signer.sgk
keep the passphrase safe: without it this identity cannot be opened (there is no reset)

$ sigil log init backup --identity signer.sgk --identity-pass-file my-pass.txt
log backup.sigil  created (signed; signer 090111f02ceceb0c6655a8471531eb387854c8182235ffd3fa6cd9a6eed7ac28)
public INDEX: no --pass / --to given, so file names, sizes and SHA-256s are stored in the clear (create the log with --pass or --to to seal them)
```

The long strings are key fingerprints in hexadecimal (digits 0–9 and letters a–f). The
second line warns that this log keeps its list of file names readable. To keep names
private, create the log with `--pass-file` or `--to` (see the README, "Private INDEX").

## Back up a folder

```
$ sigil log add backup Photos --identity signer.sgk --identity-pass-file my-pass.txt
  + 2026/macaw.jpg  2270725 bytes  new → segment 1
  + notes.txt  19 bytes  new → segment 2
  + sunset.png  10569 bytes  new → segment 3
log add backup.sigil from Photos: added 3, changed 0, unchanged 0, missing 0, skipped-special 0  root 8c14815b235b99e1… (signed)
```

Run the same command again later; only new or changed files are added:

```
$ sigil log add backup Photos --identity signer.sgk --identity-pass-file my-pass.txt
log add backup.sigil from Photos: added 0, changed 0, unchanged 3, missing 0, skipped-special 0  (nothing to do: log unchanged)
```

A file deleted from `Photos` stays in the log; Sigil reports it as "missing" and never
removes it from the archive on its own.

## See what is in it

The archivist view (the first line, the full folder path, is trimmed here):

```
$ sigil log ls backup --pretty
  ──────────────────────────────────────────────────────────────────────────
  LOG       backup.sigil
  FORMAT    segment log, format 1
  SIGNED    yes, by key 090111f02ceceb0c
  STATUS    healthy
            fast check: chain, HEAD, 3 segments present
            deep check NOT run (add --deep, or sigil log verify)
  FILES     3 live files · 0 tombstoned
  SIZE      2.2 MiB
  SEGMENTS  3 entries
  ──────────────────────────────────────────────────────────────────────────
  2026/                                                      1 file  2.2 MiB
    macaw.jpg                                                        2.2 MiB
  notes.txt                                                             19 B
  sunset.png                                                        10.3 KiB
  ──────────────────────────────────────────────────────────────────────────
  ROOT      8c14815b235b99e1321f7af505f58099c2a631df7f2180498cd01386b2beda6d
```

`ROOT` is one fingerprint of the whole archive at this moment. Write it down somewhere else
(an email to yourself, a notebook): if anyone later rewrites history, the root changes.
`sigil log ls backup` (without `--pretty`) prints it as an "anchor" you can check later
with `sigil log verify backup --anchor 3:<root>`.

## Check it fully

```
$ sigil log verify backup --signer signer.sgk.pub
log verify backup.sigil (log, container, 3 segment(s), signed format 1)
verified 3 member(s)
result: healthy
```

This checks every segment bit by bit, the chain of entries, and the signature, and needs
no passphrase. If a segment is damaged, `sigil log mend backup` repairs it.

## Get one file back

```
$ sigil log read backup --name 2026/macaw.jpg -o macaw-restored.jpg
reading 2026/macaw.jpg (segment 1)

$ cmp photo.jpg macaw-restored.jpg && echo same bytes
same bytes
```

## Limits

- Each file is read into memory when it is added, so a single file larger than the
  computer's memory cannot go into a log yet. Seal such files on their own with `sigil seal`.
- Deleting history is deliberate and separate (`tombstone`, `compact`, and `shred` for logs
  made with per-segment keys); see [SEGMENT-LOG.md](../SEGMENT-LOG.md).
