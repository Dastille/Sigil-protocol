# Segment log (`sigil log …`)

Status: **slice 1 shipped** (append, ls, read, verify, mend, gc / doctor support) and
**slice 2 shipped** (tombstones + compaction, `log=2`). Approved 2026-10-06 as a general-purpose
mode (not tied to any one application); built after the tidy-container track. Per-segment keys /
crypto-shredding, nested hierarchical cards and a log mount view are **deferred** (see the end).

A segment log is an **append-only, tamper-evident sequence of sealed batches**. Each
`sigil log append` seals one blob of bytes — a day of events, a chunk of a journal, a
database change-set, a batch of sensor readings — as an **immutable segment star** (an ordinary
`.sg1`), and extends a hash-chained, Merkle-rooted index. Nothing is ever rewritten in place.

Strictly additive: the `.sg1` byte layout is unchanged, plain `.sg1` files keep opening forever,
and the container format stays `sigil-container=1` (a log is just `kind=log` plus a few extra
manifest keys). A sigil without log support does not recognise the kind (its `gc` / `doctor` refuse it as "not a vault or constellation"); upgrade rather than point older tools at a log.

**Log format versions.** `log=1` (slice 1) = segment entries only. `log=2` (slice 2) = the INDEX
may also hold tombstone and compaction entries. A log **stays `log=1`, byte-for-byte compatible
with slice 1, until it first gains a tombstone or compaction entry**; only then does the manifest
become `log=2`. A sigil that only knows `log=1` refuses a `log=2` log with
"segment log format 2 is newer than this sigil understands; upgrade sigil" (it never gets as far as
misreading entries as "missing segments").

## Layout

```text
events.sigil/                       one container per log
  CONTAINER                         sigil-container=1  kind=log  name=events
                                    log=1 (or 2, see below)  log-id=<32 hex>  [signer=<64 hex Ed25519 key>]
  INDEX                             sigil-log-index=1, then one chained line per segment
  HEAD                              sigil-log-head=1: latest seq, chain, Merkle root [, signature]
  segments/0000/0000000001.sg1      segment 1 … 1000 per shard folder (seq / 1000)
  segments/0000/0000000002.sg1
  segments/0001/0000001000.sg1
```

* A **segment** is a normal star made by the normal seal path: ECC (Glyph / Reflection / Seal
  modes), `--pass`, `--to` (encrypt-to), compression — all unchanged. `sigil unseal`,
  `sigil mend`, `sigil verify` work on a segment by itself.
* **Sequence numbers** (entry numbers) start at 1 and have no gaps. Every INDEX line, whatever
  its type, takes the next number. With only appends, entry *n* is segment *n* (slice 1).
* The **plain bytes of a segment are opaque** to sigil: the log does not parse, split or merge
  them. One append = one segment = whatever bytes you pipe in. `log read` returns them
  unchanged and concatenated in order, so framing inside a segment (lines, records, length
  prefixes) is the application's business.

### INDEX line

```text
seq=7 t=1760000000 size=4096 sha=<64 hex> chain=<64 hex>                       segment entry (no op=)
seq=8 t=1760000050 op=tomb del=2,4-5 reason=user%20request chain=<64 hex>      tombstone (log=2)
seq=9 t=1760000090 size=…  sha=<64 hex> op=compact of=1,3,6-7 chain=<64 hex>   compaction (log=2)
```

| Field   | Meaning |
|---------|---------|
| `seq`   | 1-based, must equal the line's position |
| `t`     | unix seconds at append (informational; not trusted for ordering) |
| `size`  | plain length in bytes (segment / compaction entries) |
| `sha`   | SHA-256 of the **plain** bytes — the star's true-name, readable from its header without any key |
| `op`    | absent = segment; `tomb` = tombstone; `compact` = compaction. Any other value is an error ("upgrade sigil") |
| `del`   | tombstone: the deleted segment seqs as ascending ranges (`2,4-5`) |
| `reason`| tombstone, optional: free text, `%XX`-escaped so the value stays one token. The INDEX is not secret: no secrets in reasons |
| `of`    | compaction: the original segment seqs whose plain bytes were concatenated (ascending) into this entry's segment |
| `chain` | `SHA-256("sigil-log-entry-v1\0" ‖ previous chain ‖ line text before " chain=")` |

The first "previous chain" is `SHA-256("sigil-log-genesis-v1\0" ‖ log-id)`, so an INDEX cannot be
pasted into another log. `chain` covers the **whole line before it**, including keys this sigil
does not know — future additive fields (tombstone flags, key ids …) are protected from day one.
Readers ignore unknown keys.

The chain deliberately does **not** include the sealed file's hash: mending a segment (ECC
repair) rewrites its bytes but not its plain bytes, so the index stays valid across repairs.

### HEAD

```text
sigil-log-head=1
seq=7
chain=<chain of entry 7>
root=<Merkle root over the chain hashes of entries 1..7>
t=1760000100
signer=<Ed25519 public key>       # only when signed
sig=<Ed25519 signature>           # over "sigil-log-head-v1\nid=<log-id>\nseq=…\nchain=…\nroot=…\nt=…\n"
```

The Merkle root is the existing sigil Merkle (`merkle.rs`) over the entries' chain hashes. It lets
you pin a short `SEQ:ROOT` **anchor** ("at entry 7 the log was exactly this"); any later state of
the same log reproduces that root from its first 7 entries. `SEQ` counts INDEX entries of every
type, and **the INDEX is never rewritten** (not by tombstones, not by compaction), so an anchor
pinned at any time keeps verifying for the life of the log (see "Anchors" below).

### Signing (optional, via `--identity`)

```sh
sigil log init events                       # unsigned: HEAD is a checksum (accidents), not proof
sigil log init events --identity me.sgk     # signed: the identity's Ed25519 key is pinned in CONTAINER
sigil log append events batch.json --identity me.sgk
```

* Reuses the existing `.sgk` identity (Ed25519 half; same key `sigil sign` uses). Passkey-protected
  identities unlock as usual.
* Signing is chosen at `init` and pinned. A signed log refuses an append without the key (or with
  another key); an unsigned log refuses a signing key. (Adding a signer later = deferred.)
* The signature binds the log-id, so it cannot be replayed on another log.

## Operations

```sh
sigil log init events [--identity me.sgk]
sigil log append events FILE|-  [--mode glyph|reflection|seal] [--pass …|--talisman F] [--to RECIPIENT]… [--identity me.sgk]
sigil log ls events                           # also: sigil ls events
sigil log read events [--seq N | --from A --to B] [-o out] [--pass … | --identity key.sgk]…
sigil log verify events [--quick] [--pass … | --identity …] [--signer KEY] [--anchor SEQ:ROOT]… [--json]
sigil log mend events
sigil log tombstone events --seq N | --from A --to B [--reason TEXT] [--identity me.sgk]
sigil log compact events [--keep-last N] [--older-than 30d] [--range A-B] [--apply] [--target-size BYTES]
                         [--pass …|--identity …] [--seal-pass …|--to RECIPIENT]… [--mode …] [--allow-decrypt]
sigil gc events [--apply]        # orphans of crashed appends, and files the INDEX declares dead
sigil doctor events              # same checks as verify, plus the shared exit codes
```

`PATH` may be `events` or `events.sigil`. `append` accepts `-` for stdin. `log read` skips
tombstoned segments in a range or whole-log read (stderr note; `--strict` makes it an error), and
errors clearly for a tombstoned `--seq`.
Default mode is Reflection (like constellations); `--mode glyph` stores the bytes with almost no
redundancy (detect-only) and is the right choice when another copy of the log exists.

### Append protocol (crash-safe order)

1. take `LOG.lock` (`create_new`; one writer at a time),
2. read INDEX + HEAD, refuse on any inconsistency (damaged chain, HEAD ahead of INDEX, signer mismatch),
3. seal the batch → `segments/…/<seq>.sg1.part` → fsync → atomic rename,
4. append the chained line to INDEX, fsync,
5. rewrite HEAD (+ signature) atomically,
6. release the lock.

| Crash after… | State | Recovery |
|--------------|-------|----------|
| 3 | segment exists, INDEX not extended → *orphan segment* | next append reuses that seq and replaces the file; or `sigil gc --apply` once older than `--temp-age` |
| 4 (mid-line) | INDEX ends without newline → *torn tail* | ignored by readers (`index-torn`), trimmed by the next append |
| 4 (complete) | HEAD one behind INDEX → `head-lag` (warning) | next append re-covers it (signed logs: re-signed by the key holder) |
| 1 | stale `LOG.lock` | remove it, or `gc --apply` once older than `--temp-age` |

### `verify` (needs no keys)

Checks, in order: manifest + log format (newer → "upgrade sigil") → INDEX chain, sequence and
genesis → HEAD vs INDEX (`head-truncated`, `head-mismatch`, `head-root`, `head-lag`) → signature
(`head-signature`, `head-signer`, `head-unsigned`, `--signer`) → `--anchor` pins → every segment:
file present (`segment-missing`), header true-name equals the INDEX `sha` (`segment-digest`
catches a swapped or altered star), ECC health (`bit-rot` repairable / `bit-rot-unrecoverable`, skipped
by `--quick`) → strays (`orphan-segment`, `recent-segment`, `temp-file`, `unknown-file`).
With `--pass` / `--identity` it also **unseals** each segment and compares plain hash and size with
the INDEX (`segment-content`, `segment-unseal`). Exit codes match `sigil doctor`: 0 healthy, 1 warnings,
2 problems, 3 not a log. `read` runs the INDEX/HEAD checks first and refuses on any error.

### `mend`

`sigil log mend` heals every repairable segment **in place** (atomic replace) using the ordinary
star repair; it checks the mended star still carries the indexed true-name. INDEX and HEAD never
change. Segments beyond repair or missing are listed (exit 2): restore them from another copy — any
copy of the sealed `.sg1` is valid, since the index only knows the plain true-name.

### `gc` and `doctor`

`gc` can only ever remove: a segment file **beyond** the INDEX (seq > number of entries) that is
older than `--temp-age` (default 3600 s), abandoned `*.part` / `LOG.lock`, emptied shard folders,
and — log=2 — segment files **the INDEX itself declares dead**: the file of a segment whose every
batch is tombstoned (`deleted segment`), or whose batches were all merged into a later compaction
segment (`superseded seg.`). A segment that is still needed is never a candidate, whatever its state.
gc **refuses to run** if the INDEX is damaged or HEAD claims more entries than INDEX holds (the
"extra" segments may then be live).

Dead files are judged **only from entries the HEAD vouches for**: HEAD must be consistent with the
INDEX and, for a signed log, carry the pinned signer's valid signature. A tombstone or compaction
line somebody appended to the INDEX without being able to re-sign HEAD (`head-lag`) never gets a
file deleted on its say-so, and the files it mentions are treated as live until the key holder's next
operation re-covers it.

`doctor` reports the same things plus bit rot / missing segments, tombstone / compaction state
(`tombstones`, `compactions` notes), pending erasure (`deleted-segment`, `deleted-data`,
`superseded-segment` warnings); `doctor --fix` runs `gc --apply` and nothing else. Report-only by
default, exactly like for vaults and constellations.

## Tombstones and compaction (slice 2, `log=2`)

Strictly additive: no `.sg1` byte changes, plain stars open forever, a log that never uses either
feature is untouched, still `log=1`, and readable by slice-1 sigils.

### Tombstone

`sigil log tombstone PATH --seq N | --from A --to B [--reason TEXT]` appends one `op=tomb` entry
(no segment file) naming segments as deleted. It is **chain-covered** like every entry and, in a
signed log, covered by the re-signed HEAD, so deleting is itself tamper-evident: removing the
tombstone line later is a `head-truncated` / anchor failure, editing it is an `index-chain` failure.

* A tombstone is **permanent and logical**: there is no undelete. `read` and `ls` honour it at once.
* Targets must be earlier *segment* entries that are not yet deleted. A `--from/--to` range is
  clipped to live segments (compaction / tombstone records inside it are skipped; already-deleted
  ones are counted and skipped). `--seq` on a non-segment or already-deleted entry is an error.
* `log read --seq N` of a deleted segment fails with the tombstone number and reason. Ranges and the
  default whole-log read **skip** deleted segments and say so on stderr; `--strict` fails instead.
* It does **not** erase bytes. They go when `compact --apply` (or `gc --apply`) removes the file
  (see "Erasure").
* Before the first line is written the manifest is raised to `log=2` (manifest first, so an older
  sigil refuses the log instead of reading a line it does not know).

### Compaction

`sigil log compact PATH [--keep-last N] [--older-than DUR] [--range A-B] [--apply]` merges live
segments into fewer, larger ones and erases dead files. **Dry run by default** (prints the plan,
touches nothing, takes no lock), like `gc`.

* **Eligibility (retention rule).** Rules combine with AND: `--keep-last N` leaves the newest N
  batches out, `--older-than DUR` (`90`, `30m`, `12h`, `7d`, `2w`) only merges batches appended at
  least that long ago, `--range A-B` only merges batches with original seq in A..B. No rule = every
  live segment. A file is merged only if **all** of its live batches qualify. Independently of the
  rule, a file that still contains tombstoned batches is always rewritten without them, and files
  whose every batch is deleted are simply erased: the tombstone *is* the retention decision.
* **One merged segment** = one new ordinary star holding the plain bytes of the member batches
  concatenated in ascending original seq (so `unseal` shows exactly that). `--target-size`
  (default 64 MiB) starts a new merged segment before it would be exceeded. Runs of eligible
  neighbours are merged; a kept (ineligible) live segment ends a run.
* **The compaction entry** `seq=K … size=<total> sha=<merged plain sha> op=compact of=1,3,6-7` is a new INDEX
  line at the end of the log. It carries no history rewrite: the original entries 1, 3, 6, 7 stay in
  the INDEX untouched.
* **Seq identity is kept.** Every original seq still addresses its batch: `log read --seq 3` finds
  seq 3 inside compaction segment K, cuts it out by the sizes recorded in the INDEX, and checks it
  against seq 3's own `sha`. Deleted seqs stay deleted. New appends keep numbering from the end.
* **Sealing the merged segments.** Sources are opened with `--pass` / `--identity` (as for `read`);
  the merged segment is sealed with `--mode` (default Reflection) and `--seal-pass` / `--to`. If any
  source needed a key and no `--seal-pass` / `--to` is given, compaction **refuses** rather than
  quietly storing decrypted batches (`--allow-decrypt` overrides). A signed log needs
  `--identity` of its signer because HEAD is rewritten; a key-less dry run is fine.
* Memory: a merged segment is built and sealed in memory (up to `--target-size`, or one oversized
  batch).

### Anchors after compaction (decision)

Because compaction **only appends** (INDEX lines are immutable and compaction's entry is chained
after everything), every `SEQ:ROOT` anchor ever pinned **still verifies after any number of
tombstones and compactions** (`verify --anchor`), and a rolled-back log is still detected. There is
no "old root" bookkeeping and no verification gap. What does change: an anchor commits to the
*entries* (including each batch's `size` / `sha`), not to the presence of bytes; after erasure the
anchor still proves what the log said, but the data is gone (that is the point). The cost: INDEX
size never shrinks (~170 bytes per entry, plus ~one line per compaction). Truncating / rolling up
old INDEX history would be a deliberate chain-breaking operation and belongs to the deferred
hierarchical-cards work, not here.

### Erasure (what is and is not promised)

`compact --apply` is the **retention path to actual erasure**: it unlinks the old files (a
tombstoned batch inside a merged segment goes when that segment is rewritten without it). That is
file-system deletion: no overwrite, no secure wipe, and snapshots / backups / copies of the old
files (rsync, cold kits) are untouched. Real, key-based **crypto-shredding** (each segment under its
own key, destroy the key) is the later slice and is **not** started here. Until then, treat
tombstone + compact as "deleted from the log and from this disk", not as forensic erasure.

### Crash safety of `compact --apply`

Order: **(1)** merged segments written as unindexed files (`*.part` → atomic rename) → **(2)**
manifest raised to `log=2` → **(3)** INDEX lines appended + fsync (the commit point) → **(4)** HEAD
rewritten atomically → **(5)** old files deleted last. A failure while building (key missing,
encrypted-into-clear refusal…) removes the files from (1) again.

| Crash after… | State | Result |
|---|---|---|
| 1 | merged files beyond the INDEX = orphans | verifies; `gc --apply` reclaims them once older than `--temp-age`; rerun compacts |
| 2 | manifest `log=2`, INDEX unchanged | verifies (an upgrade with no new lines is harmless) |
| 3 | INDEX has the compaction line, HEAD lags | `head-lag` warning; reads work; old files are still treated as live (HEAD does not vouch yet); the next append / tombstone / compact re-covers HEAD |
| 4 | everything committed, old files remain | `superseded-segment` warnings; `gc --apply` erases them |
| 5 (partway) | some old files gone | no error (superseded files are not required); `gc --apply` finishes |

In no case is a live segment missing or a log unverifiable; the leftovers are orphans / dead files
that `gc` (or a rerun of `compact`) reclaims. `LOG.lock` serialises `append`, `tombstone` and
`compact --apply`.

### `verify` / `doctor` / `mend` with log=2

* `verify` checks the new lines like any other: chain, then structure (a tombstone may only name
  earlier, live segment entries; a compaction may only name earlier, live segment entries and its
  `size` must equal the sum of its members: `index-tombstone` / `index-compact` errors), then HEAD /
  signature. `segment-missing` is only raised for files still *needed*; with keys it also cuts each
  merged segment back into its members and compares every one with the original entry
  (`segment-content`).
* New findings: `deleted-segment` (tombstoned, file still there), `deleted-data` (a merged segment
  still contains tombstoned batches), `superseded-segment` (merged away, file still there), all
  warnings pointing at `compact --apply` / `gc --apply`; `log-format` (error) if a `log=1` manifest
  sits over an INDEX with tombstone / compaction lines; notes `tombstones` / `compactions` with the
  counts. `log ls` shows `DELETED (tombstone #N)`, `in #K`, `tombstone: deletes …`,
  `compaction of …` rows and the bytes still pending erasure.
* `mend` heals the segments that are still needed (merged segments included) and ignores dead files.

## Invariants

1. A segment, once appended, is never modified except by ECC repair that preserves its plain bytes.
2. `INDEX` is append-only; entry *n*'s chain hash commits to entries 1..*n* and to the log-id.
3. A segment file is needed iff some non-deleted batch lives in it (per the INDEX entries the HEAD
   vouches for). Tools delete only files that are not needed: unindexed leftovers once old enough,
   and files the INDEX declares dead; only after the INDEX is proven readable.
3a. The INDEX is only ever appended to. Tombstones and compactions are new lines; no entry is edited,
   dropped or renumbered, so every anchor stays valid.
3b. A log is `log=1` until its first tombstone / compaction line; the manifest is raised **before**
   that line is written.
4. Absence of `kind=log` / `log=` means "not a segment log"; a log is invisible to older readers.
5. Plain `.sg1` stars, constellations and vaults are untouched by this feature.

## Threat model

| Adversary / event | Outcome |
|-------------------|---------|
| Random bit rot, torn writes in a segment | detected by `verify`, healed by `mend` (within the seal's ECC budget) |
| Edit / reorder / delete an entry in the middle of INDEX | chain break → `verify` and `read` refuse |
| Swap a segment for another valid star, or for an altered copy | header true-name ≠ INDEX `sha` → `segment-digest` (no key needed) |
| Cut entries off the end of INDEX only | HEAD ahead of INDEX → `head-truncated`; append and gc refuse |
| Remove / edit a tombstone to "undelete" or redirect it | chain break (`index-chain`), or HEAD ahead of INDEX (`head-truncated`); unsigned log rewritten consistently = only `--anchor` / a signature catches it, same as any rewrite |
| Append a forged tombstone / compaction line (valid chain, no key) to a signed log | HEAD does not cover it (`head-lag`); gc / compact never delete a file on its say-so; the key holder's next operation would re-cover it (inspect `log ls` after a `head-lag`) |
| A compaction entry that lies about its content (merged bytes ≠ members) | keyed `verify` / `read` compare each member's `sha` with its original entry (`segment-content`); keyless verify only proves the merged star matches the entry. In a signed log the compaction is the signer's attestation |
| Compaction silently decrypting encrypted batches | refused unless `--seal-pass` / `--to` (or explicit `--allow-decrypt`) |
| Expecting erasure to defeat backups / forensics | not promised: file unlink only, copies untouched; crypto-shredding (per-segment keys) is the later slice |
| Rewrite INDEX **and** HEAD consistently, **unsigned** log | **not detectable** from the log alone — an unsigned HEAD is a checksum. Use `--anchor SEQ:ROOT` pins kept elsewhere, or sign |
| Same, **signed** log, attacker lacks the key | HEAD signature fails (`head-signature`) |
| Roll back to an older, validly signed INDEX+HEAD pair | **not detectable** without an external pin; `--anchor` (or any copy of a newer HEAD) catches it |
| Signer key stolen | attacker can extend or re-sign; out of scope (rotate by starting a new log; key rotation deferred) |
| Attacker with segment write access and the plain data | can replace a segment only by a star with the same true-name = same plain bytes |
| Confidentiality | per segment via `--pass` / `--to`; INDEX leaks sequence, time, sizes and plain true-names (hashes of the batches). Do not use it for low-entropy secrets you cannot afford to have confirmed by guessing. Hiding that metadata = deferred |
| Availability | ECC inside each segment; across segments sigil adds none — keep a second copy (`rsync`, atlas, cold kit) of the container |

Unauthorised concurrent writers are not a security feature: `LOG.lock` is advisory and local. One
writer at a time; do not put the container on a filesystem without atomic `rename` / `create_new`.

## Size notes (measured, slice 1; compaction removes the per-segment overhead for merged batches)

Each segment carries a fixed overhead of about **3.2 KB** (header, keystone, Merkle) plus the
mode's redundancy: Reflection ≈ 1.34×, Seal ≈ 2×, Glyph ≈ 1.003× on incompressible data (text
compresses first). **Batch small events into larger appends** (KBs–MBs, not single lines).
A batch is sealed in memory in one piece in this slice; very large single batches should be split
(work-pack chunking for segments is deferred). INDEX is ~170 bytes per entry; `append` re-reads it
in full (O(n) hashing, fine into the hundreds of thousands of segments).

## Deferred (later slices)

Done in slice 2: tombstones + compaction (above). Still deferred:

* **Per-segment keys / crypto-shredding**: each segment under its own key, wrapped for the log's
  recipients, so destroying a key makes that segment unreadable while the chain still verifies.
* **Nested hierarchical cards**: a card of cards (daily → monthly roll-ups) with their own Merkle roots.
* Adding or rotating a signer after `init`; signed *inclusion proofs* for a single entry.
* Streaming appends / segments above memory size (work-pack chunking); metadata-hiding INDEX.
* `sigil mount` view of a log (one file per segment, honouring tombstones) and `tidy` migration from ad-hoc segment folders.
* INDEX roll-up / pruning of very old history (needs the hierarchical cards: it is chain-breaking by nature).
* Automatic, scheduled retention (`compact` is explicit today; a monthly `doctor` + `compact --dry-run` routine is the intended shape).
