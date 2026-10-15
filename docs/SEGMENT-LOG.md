# Segment log (`sigil log …`)

Status: **slice 1 shipped** (append, ls, read, verify, mend, gc / doctor support),
**slice 2 shipped** (tombstones + compaction, `log=2`), **slice 3 shipped** (opt-in per-segment
keys and crypto-shredding, `log=3`), and **log mount shipped** (`sigil mount` / `--export-dir` of a
`kind=log` container), **`log adopt` shipped** (tidy a loose pile of `.sg1` stars into a log), and **inclusion proofs
shipped** (`log prove` / `log check-proof`: an offline receipt that one entry is in the log), and **signer
rotation shipped** (`log rotate-signer`, `log=4`: hand a signed log over to a new key). Approved 2026-10-06 as a general-purpose mode (not tied to any one
application); built after the tidy-container track. Nested hierarchical cards remain **deferred**
(see the end).

A segment log is an **append-only, tamper-evident sequence of sealed batches**. Each
`sigil log append` seals one blob of bytes — a day of events, a chunk of a journal, a
database change-set, a batch of sensor readings — as an **immutable segment star** (an ordinary
`.sg1`), and extends a hash-chained, Merkle-rooted index. Nothing is ever rewritten in place.

Strictly additive: the `.sg1` byte layout is unchanged, plain `.sg1` files keep opening forever,
and the container format stays `sigil-container=1` (a log is just `kind=log` plus a few extra
manifest keys). A sigil without log support does not recognise the kind (its `gc` / `doctor` refuse it as "not a vault or constellation"); upgrade rather than point older tools at a log.

**Log format versions.** `log=1` (slice 1) = segment entries only. `log=2` (slice 2) = the INDEX
may also hold tombstone and compaction entries. `log=3` (slice 3) = the log has per-segment keys
(`segkeys=1`, a `keys/` key ring, and the INDEX may hold shred entries). A log **stays `log=1`,
byte-for-byte compatible with slice 1, until it first gains a tombstone or compaction entry** (then
`log=2`); only `sigil log init --segment-keys` ever creates `log=3`, from its first byte: a log
that does not opt in never becomes `log=3`, never grows a `keys/` folder and never gets a `segkeys`
manifest key. `log=4` = the INDEX may also hold **signer handover** entries (`op=signer`); a log is
raised to `log=4` only by its first `sigil log rotate-signer` (manifest first), whatever it was
before (a `--segment-keys` log keeps `segkeys=1`). A log that is never rotated never becomes `log=4`.
A sigil that only knows an older format refuses a newer log with
"segment log format 3 is newer than this sigil understands; upgrade sigil" (it never gets as far as
misreading entries as "missing segments").

## Layout

```text
events.sigil/                       one container per log
  CONTAINER                         sigil-container=1  kind=log  name=events
                                    log=1 (2, 3 or 4, see below)  log-id=<32 hex>  [signer=<64 hex Ed25519 key>]
  INDEX                             sigil-log-index=1, then one chained line per segment
  HEAD                              sigil-log-head=1: latest seq, chain, Merkle root [, signature]
  segments/0000/0000000001.sg1      segment 1 … 1000 per shard folder (seq / 1000)
  segments/0000/0000000002.sg1
  segments/0001/0000001000.sg1
  keys/0000.sg1                     only with `init --segment-keys` (log=3): the key ring, 1000 keys per shard
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
seq=10 t=1760000120 op=tomb del=3 shred=1 reason=gdpr chain=<64 hex>               crypto-shred (log=3)
seq=11 t=1760000200 op=signer from=<64 hex> to=<64 hex> sig=<128 hex> chain=<64 hex>   signer handover (log=4)
```

| Field   | Meaning |
|---------|---------|
| `seq`   | 1-based, must equal the line's position |
| `t`     | unix seconds at append (informational; not trusted for ordering) |
| `size`  | plain length in bytes (segment / compaction entries) |
| `sha`   | SHA-256 of the **plain** bytes — the star's true-name, readable from its header without any key |
| `op`    | absent = segment; `tomb` = tombstone; `compact` = compaction; `signer` = signer handover. Any other value is an error ("upgrade sigil") |
| `del`   | tombstone: the deleted segment seqs as ascending ranges (`2,4-5`) |
| `shred` | tombstone, optional, only `1`: this is a crypto-shred — the key of the named segments' file was destroyed (needs `segkeys=1`; in any other log it is a `log-format` error) |
| `reason`| tombstone, optional: free text, `%XX`-escaped so the value stays one token. The INDEX is not secret: no secrets in reasons |
| `of`    | compaction: the original segment seqs whose plain bytes were concatenated (ascending) into this entry's segment |
| `from`, `to`, `sig` | signer handover: the outgoing and the new Ed25519 key, and `from`'s signature over `"sigil-log-signer-v1\nid=<log-id>\nseq=<this seq>\nfrom=<hex>\nto=<hex>\n"` |
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
  another key); an unsigned log refuses a signing key. The key can later be **handed over** to a
  new one with `sigil log rotate-signer` (see "Signer rotation"); adding a signer to an unsigned log
  is still deferred.
* The signature binds the log-id, so it cannot be replayed on another log.

## Operations

```sh
sigil log init events [--identity me.sgk] [--segment-keys]
sigil log append events FILE|-  [--mode glyph|reflection|seal] [--pass …|--talisman F] [--to RECIPIENT]… [--identity me.sgk]
sigil log ls events                           # also: sigil ls events
sigil log read events [--seq N | --from A --to B] [-o out] [--pass … | --identity key.sgk]…
sigil log verify events [--quick] [--pass … | --identity …] [--signer KEY] [--anchor SEQ:ROOT]… [--json]
sigil log mend events
sigil log adopt events PILE/ [STAR.sg1 …] [--keep] [--dry-run] [--identity me.sgk]   # tidy loose stars in
sigil log tombstone events --seq N | --from A --to B [--reason TEXT] [--identity me.sgk]
sigil log shred events --seq N | --from A --to B [--reason TEXT] [--identity me.sgk]    # --segment-keys logs only
sigil log rotate-signer events --identity old.sgk --new new.pub   # hand a signed log over to a new key (log=4)
sigil log prove events --seq N [--at M] [-o receipt.proof]   # receipt: this entry is in the log
sigil log check-proof receipt.proof [--file BATCH] [--signer KEY] [--anchor SEQ:ROOT]   # offline, no log, no keys
sigil log compact events [--keep-last N] [--older-than 30d] [--range A-B] [--apply] [--target-size BYTES]
                         [--pass …|--identity …] [--seal-pass …|--to RECIPIENT]… [--mode …] [--allow-decrypt]
sigil gc events [--apply]        # orphans of crashed appends, and files the INDEX declares dead
sigil doctor events              # same checks as verify, plus the shared exit codes
sigil mount events ./view [--export-dir DIR] [--pass … | --identity key.sgk]…
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
own key, destroy the key) is slice 3 (see "Per-segment keys and crypto-shredding" below). In a log **without** segment keys, treat tombstone
+ compact as "deleted from the log and from this disk", not as forensic erasure.

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

## Per-segment keys and crypto-shredding (slice 3, `log=3`)

Opt-in at `init`, never retrofitted:

```sh
sigil log init events --segment-keys [--identity me.sgk]
sigil log append events batch.json --to alice.pub          # or --pass …, or both
sigil log read events --identity alice.sgk
sigil log shred events --seq 2 --reason "erasure request 42"
```

**How it works.** Every append seals the batch under its own **fresh random key** (the existing
encrypt-to path, to an identity derived from that key — no new cipher, no new seal layout; a
segment is still an ordinary `.sg1`). The key is then **wrapped with the existing SGTO machinery**
(X25519 `--to` recipients and/or a `--pass` passphrase, exactly what `sigil seal --to` / `--pass`
do) and stored in a small **key ring**, a separate member of the container:

```text
events.sigil/
  keys/0000.sg1        a star (Reflection ECC, not encrypted) whose plain bytes are one text record
                       per segment: seq=7 salt=<hex> wrap=<hex SGTO block>; 1000 records per shard
```

* In a `--segment-keys` log, `--pass` / `--to` on `append` and `compact` (`--seal-pass` / `--to`)
  protect the **key**, not the segment directly. At least one of them is required (otherwise there
  would be nowhere safe to keep the key and the append is refused before anything is written).
  Different appends may be wrapped to different recipients; reading needs the right `--pass` /
  `--identity` for each segment.
* Appending needs only **public** recipients; **destroying** keys needs **no secret at all**.
  `shred` therefore works from a machine that cannot read the data.
* The key ring is a plain ECC star: it heals with the same Reed–Solomon budget as everything else
  (`sigil log mend` heals shards, `verify` reports `bit-rot` in them). It holds only wrapped keys, so
  it is safe at rest and needs no extra secrecy beyond what the wraps give.
* The INDEX does not contain keys or key ids. `segkeys=1` in `CONTAINER` is the only marker.
  Unknown to an older sigil → it refuses the log (`log=3` is newer), never misreads it.

### `shred`

`sigil log shred events --seq N | --from A --to B [--reason TEXT] [--identity me.sgk]`

1. under `LOG.lock`, check the target (not a tombstone / compaction record, not already shredded);
2. append one chained INDEX line `op=tomb del=… shred=1 [reason=…]` and rewrite HEAD (signed logs
   need `--identity`, exactly like a tombstone). **This is the commit point.**
3. destroy the segment's record in the key ring: the shard is rewritten without it (new file in
   place first, then the old bytes are overwritten with zeros through a second hard link, then
   removed; a crash can never leave a half-written ring);
4. unlink the now-unreadable ciphertext file.

A shred is a tombstone that is also key destruction: reads, `ls` and compaction treat it as
deleted, and `read` says `segment N was crypto-shredded by entry #K … its key is destroyed and its
data cannot be recovered`. An earlier plain tombstone may later be **hardened** into a shred.
Shredding is final (there is no unshred).

**Compaction segments share one key.** `compact` merges batches into one file sealed under one new
key, so the key of one batch cannot be destroyed without the others. `shred` therefore refuses a
batch whose file holds other live batches ("they share one key") unless all of them are named; for
one batch use `tombstone` + `compact --apply`, which rewrites the file without it under a fresh
key and destroys the old one. (This is checked by `verify` too: an INDEX that shreds part of a
shared file is `index-shred`.) Merged segments of a `--segment-keys` log need `--seal-pass` or
`--to` on `compact --apply`, for the same reason appends do.

### What stays valid after a shred

* **The INDEX is only appended to.** The shred is one more chained line; `verify`, the Merkle
  root, the signed HEAD and **every anchor ever pinned still verify** (`verify --anchor`). An
  anchor commits to what the log *said* (each batch's size and plain true-name), not to the bytes
  being present.
* **`verify` / `doctor`** do not call a shredded segment damaged or missing: no `segment-missing`,
  no `segment-digest`, no `bit-rot` for it. A ciphertext file of a shredded segment that is still
  on disk (a restored backup, an interrupted shred) is an `info` (`shredded-segment`); a key record
  that is still in the ring although the INDEX says it was destroyed is a **warning**
  (`shred-key-present`). Other new findings: `key-missing` (error: a live segment has no record —
  restore the ring from a copy), `keyring-damaged` (error: shard unreadable), `dead-key`
  (warning: key of a tombstoned / merged-away segment still there) and `orphan-key` (warning: a
  record no INDEX entry uses, left by a crashed append or compaction).
* **`mend`** only heals segments that are still needed (a shredded one is not touched) and the key
  ring shards.
* **`gc`** reclaims the ciphertext of shredded segments and **destroys dead key records** (shredded,
  tombstoned, merged away, or beyond the INDEX after a crash). Key destruction happens under
  `LOG.lock` with a fresh read of the INDEX, so an append in flight can never lose its brand-new
  key, and only for entries the HEAD vouches for (a forged, unsigned INDEX line cannot make `gc`
  destroy a key).
* **`compact --apply`** drops shredded and tombstoned batches from the merged files, deletes the old
  files and **destroys the old files' key records** together with them (a new file gets a new key).
* Crash order of `shred`: INDEX line → HEAD → key destroyed → file unlinked. A crash after the INDEX
  line leaves a record the entry says is dead (`shred-key-present`); `sigil gc --apply` finishes
  the shred. Nothing is ever *less* shredded than the INDEX claims without `verify` saying so.

### What crypto-shredding does and does not guarantee

Be precise about what you are buying:

* **It guarantees** that, from this log's files alone and after `shred`, no key for the segment
  exists any more, so the remaining ciphertext (if any is left by a copy) cannot be decrypted by
  anyone who does not hold a key copy — including you. The INDEX keeps its hash and size, so you
  can still prove a batch of that size and true-name existed and was shredded.
* **It does not reach copies.** Anything that copied the key ring **or** the ciphertext **before**
  the shred (backups, snapshots, rsync mirrors, cold kits, cloud sync, an exported `keys/`) still
  has them; a copy of the *old key ring shard plus* a copy of the old segment file decrypts the
  batch for whoever holds the recipient key or passphrase. sigil cannot erase what it cannot see.
  Shred only works end to end if no copy of the key survives, so decide up front which copies of
  the ring exist: keep `keys/` out of backups of data you may need to shred (or back it up only to
  places you can also shred).
* **The scrub of the ring is best effort.** sigil overwrites the old shard with zeros after
  replacing it, but journaling and copy-on-write file systems, SSD wear levelling, RAID, snapshots
  and swap can keep old bytes. Real assurance needs an encrypted disk whose key you can destroy, or
  recipient keys you control (destroying the *recipient's* private key or passphrase is the
  strongest shred of all and works on copies too).
* **It does not hide metadata.** The INDEX still shows that a segment existed, when, its size and
  the true-name (hash) of the plain bytes; do not shred low-entropy secrets and expect the hash to
  protect them (anyone can still confirm a guess).
* **Wrapped recipients matter.** A key wrapped to a passphrase is only as strong as the
  passphrase, and a key wrapped to alice.pub opens for anyone who ever held alice.sgk — shredding
  does not revoke that for copies made earlier.
* **A shred is an authority.** In an unsigned log anyone with file access can append a forged
  shred line (it hides data from reads but, being unvouched by HEAD, `gc` will not destroy a key on
  its say-so). Sign the log (`--identity`) if shred authority matters.
* Nothing about `.sg1` changed: a segment taken out of the log is a normal encrypt-to star; if you
  hold the key ring record and the recipient key you can open it with ordinary tools, and a
  `log=1` / `log=2` log or plain `.sg1` has none of this and is untouched.

## Adopting a pile of stars (`sigil log adopt`)

Before there was a log mode, the natural way to keep batches was a folder of loose stars
(`daily/2026-10-01.sg1`, `daily/2026-10-02.sg1`, …). `adopt` tidies such a pile into a log:

```sh
sigil log init daily                       # or an existing log; --identity to sign it
sigil log adopt daily daily-old/ --dry-run # plan: order, sizes, what would be skipped
sigil log adopt daily daily-old/           # adopt, then remove the originals
sigil log adopt daily a.sg1 b.sg1 --keep   # explicit files, in the order given; keep originals
```

* **Byte-for-byte.** A star is copied as it is: never unsealed, re-sealed or decrypted. The INDEX
  needs only the plain size and the true-name, and both are in every star's header, so adoption
  needs **no keys** and each segment keeps its own ECC mode and protection (`--pass`, `--to`).
  Read or verify it later with the key that opened the original. The segment's header still
  carries the original file name (only visible to `unseal`; mounts name segments by seq).
* **Order.** A folder gives its `*.sg1` children (not recursive) in natural name order, so
  `day-2` comes before `day-10` and ISO dates sort by date. Other files are counted and left alone.
  Files named on the command line keep the given order. `t=` is the adoption time (informational,
  as for every entry).
* **Checks.** A file that is not a star, or whose ECC check finds damage, is **left in place** and
  listed (exit code 1); a repairable one says to run `sigil mend FILE` first. Folders that are
  already sigil containers, and stars inside one, are refused (adopt is for loose stars).
* **Crash-safe order:** segments written as unindexed files (each read back) → INDEX lines
  appended in one write (the commit point) → HEAD → originals removed last. Before the commit a
  crash leaves only unindexed leftovers (`gc` reclaims them, the next append overwrites them).
* **Idempotent.** Each adopted line carries an additive `src=<SHA-256 of the star file>` key. It
  is ordinary chain-covered data, older sigils ignore it, and the line stays a `log=1` segment line
  (adopting never raises the log format). A re-run recognises sources whose exact bytes were
  already adopted ("already segment N") and only removes them, so a run that stopped between the
  commit and the cleanup is finished by running it again. The same path named twice counts once.
  If those exact bytes were adopted and later **tombstoned**, the file is left in place: deleted
  data is never re-added behind your back, and your copy is not removed.
* **Not for `--segment-keys` logs.** There every segment must be sealed under its own key (that is
  what makes shredding work), so a ready-made star cannot be adopted as is; unseal it and
  `sigil log append` the bytes. A signed log needs `--identity` as for `append`.
* `compact` later re-seals adopted batches like any other, so it needs keys that open every
  adopted star it merges (locked stars from different passphrases: give a key for each, or leave
  them out of the compaction range).

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
6. Per-segment keys are opt-in at `init` (`log=3`, `segkeys=1`); a log without them is byte-identical
   to what slice 1 / 2 write and never grows a `keys/` folder. A key record is destroyed only after
   the INDEX line that says so is committed and covered by HEAD, and never while a needed segment
   (or an entry HEAD does not cover yet) depends on it.
7. Signer handovers are opt-in by use (`log=4` from the first one); a log that is never rotated is
   byte-identical to what earlier slices write. The manifest pin never changes; a HEAD covering
   entries `1..n` must be signed by the key the handovers with seq < `n` lead to from the pin.

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
| Expecting erasure to defeat backups / forensics | not promised: file unlink only, copies untouched; `--segment-keys` + `shred` destroys the key here, but copies of the key ring or of the recipient's key still decrypt copies of the ciphertext (see above) |
| `shred` interrupted after its INDEX line | `shred-key-present` warning; reads already refuse the segment; `gc --apply` destroys the key |
| Forged `shred=1` line in an unsigned / unvouched INDEX | hides data from reads like any forged tombstone; HEAD does not cover it, so `gc` / `compact` destroy no key on its say-so |
| Key ring record lost or altered | that segment cannot be opened (`key-missing` / `segment-unseal`); a wrong key can never make wrong plaintext verify — the true-name is in the chain |
| Key ring shard bit rot | ECC star: healed by `mend`; beyond the budget → `bit-rot-unrecoverable` (restore from a copy of the ring) |
| Rewrite INDEX **and** HEAD consistently, **unsigned** log | **not detectable** from the log alone — an unsigned HEAD is a checksum. Use `--anchor SEQ:ROOT` pins kept elsewhere, or sign |
| Same, **signed** log, attacker lacks the key | HEAD signature fails (`head-signature`) |
| Roll back to an older, validly signed INDEX+HEAD pair | **not detectable** without an external pin; `--anchor` (or any copy of a newer HEAD) catches it |
| Signer key stolen | attacker can extend or re-sign (or hand the log over to their own key); out of scope. Rotate with `log rotate-signer` while the key is still yours, and keep anchors elsewhere |
| Forged signer handover (valid chain, not signed by the signer in effect; or no signature; or replayed from another seq / log) | `index-signer` / `index-line` error; writers, `gc`, `read` refuse; `check-proof` rejects a forged `handover-N` |
| HEAD signed by a retired key after its handover | `head-signer` error (HEAD must be signed by the signer for its position) |
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

## Inclusion proofs (`sigil log prove` / `sigil log check-proof`)

A **receipt** that one INDEX entry is part of a log, which anyone can check offline: without the
log, without its segments and without any key. Typical use: you appended a batch to someone's log
(or they to yours) and want proof it is in there, at that position, under that root, that does not
depend on trusting whoever hands you the log later.

```sh
sigil log prove events --seq 7 -o day7.proof              # against the current HEAD (signed if the log is)
sigil log check-proof day7.proof --file day7.json --signer owner.pub
sigil log prove events --seq 3 --at 7 -o old.proof        # against an anchor 7:ROOT pinned earlier
sigil log check-proof old.proof --anchor 7:<ROOT>
```

A proof is a small text file (`sigil-log-proof=1`; about 0.4 KB unsigned or 0.7 KB signed, plus 65 bytes per
tree level, so about 1.8 KB for a signed proof in a log of 100,000 entries):

| Field | Meaning |
|-------|---------|
| `log` | the log-id (the genesis hash and the HEAD signature both bind it) |
| `name` | informational only |
| `entry` | the entry's full INDEX line, `chain=` included |
| `prev` | chain hash of the entry before it (for seq 1: must be the log's genesis hash) |
| `size`, `root` | the Merkle root over the first `size` entries: exactly the `SEQ:ROOT` anchor `log ls` prints |
| `path` | sibling hashes from the entry's chain hash up to `root`, comma-separated (levels where the node is the odd last one pair with themselves and add none) |
| `head-chain`, `head-t`, `signer`, `sig` | only when `size` is the HEAD of a signed log: the HEAD's own fields, so its Ed25519 signature can be checked |
| `handover-1`, `handover-2`, … | only in a signed proof whose log was rotated before `size`: the full INDEX lines of those signer handovers, oldest first (see "Signer rotation") |

What `check-proof` verifies, in order: the line's `chain=` equals `SHA-256("sigil-log-entry-v1\0" ‖
prev ‖ line before " chain=")` (so the line is exactly what was appended); the path leads from that
hash at position `seq` to `root` with the right number of steps for `size`; if signed, the HEAD
signature over `id`, `size`, `head-chain`, `root`, `head-t` verifies. Options add requirements:
`--signer KEY` (must be signed by that key, or by a key it handed the log over to: the proof's
`handover-N` lines must each verify under the outgoing key and lead from KEY to the HEAD's signer), `--anchor SEQ:ROOT` (must be against exactly that
pinned anchor), `--file F` (F must be the entry's plain bytes: SHA-256 and length; for a compaction
entry that is the concatenation of the merged batches). Exit 0 = verifies, 2 = it does not (the
message says which check failed).

* **What it proves.** "Entry *N* with exactly this content is the *N*-th entry of the log whose first
  `size` entries have this root." Each line names its own `seq` and the chain covers it, so an entry
  cannot be passed off at another position (the duplicate-last-leaf padding of the Merkle tree
  cannot be abused for a fake extra leaf).
* **What it does not prove.** That the entry was not tombstoned or shredded *after* `size` (a
  receipt is a point-in-time statement; deletions are later entries, provable with their own
  receipt). Nor that the root is "the" log: an **unsigned** proof is only as strong as the root you
  compare it with, so check it with `--anchor` against an anchor you pinned, or use a signed log and
  `--signer`. Inclusion of one log state in a later one (consistency proofs) is deferred.
* **Any entry type.** Segments, compaction entries and tombstones (a deletion receipt) all prove.
  Tombstones and compaction never rewrite the INDEX, so a receipt cut before them keeps verifying
  against its anchor, and `prove --at M` regenerates it at any later time.
* **Which root.** Default: the HEAD the log vouches for (the same rule as gc: a signed log needs a
  HEAD signed by the pinned key, else `prove` refuses). `--at M` proves against the first `M` entries
  regardless of HEAD; it is signed only when `M` is the HEAD's seq. A damaged INDEX refuses (`log
  verify` first).
* **Additive.** Nothing is written to the log; no format change, no manifest bump.

## Signer rotation (`sigil log rotate-signer`, `log=4`)

A signed log is pinned to one Ed25519 key at `init`. To retire that key (a new machine, a new
owner, a key you suspect is exposed), its holder **hands the log over** to a new key:

```sh
sigil log rotate-signer events --identity old.sgk --new new.pub   # only the new PUBLIC key is needed
sigil log append events day9.json --identity new.sgk              # from now on: the new key
sigil log verify events --signer old.pub                          # still fine: old → new is a signed chain
sigil log verify events --signer new.pub
```

* **The handover entry.** `rotate-signer` appends one chain-covered INDEX line
  `op=signer from=<old> to=<new> sig=<…>`, where `sig` is the **outgoing** key's Ed25519 signature
  over the log-id, the entry's own seq and both keys (so it cannot be replayed into another log or at
  another position), and re-signs HEAD with the outgoing key. It holds no segment file.
* **Who signs which HEAD.** The HEAD covering the handover entry itself is the outgoing key's (the
  last thing it vouches for); every HEAD covering a later entry must be signed by the new key. Rotating
  again (new → newer) appends another handover; the chain can be as long as needed.
* **The pin stays.** `CONTAINER`'s `signer=` remains the key pinned at `init`: it is the root of the
  chain. The current signer is found by following the handovers from it (`log ls` shows each one and
  `signer handed over N time(s)`; `verify` notes `signer-handovers`).
* **Verification.** `verify` / `read` / `gc` / `prove` check that every handover is from the signer
  in effect at that point and that its signature verifies; a **forged** handover (signed by anyone
  else), one **without** a signature, one in an **unsigned** log, or one under a manifest older than
  `log=4` is an INDEX error (`index-signer`, `index-line`, `log-format`) and writers refuse the log.
  Editing a handover breaks the chain (`index-chain`) like any other entry. HEAD must be signed by
  the signer for its position (`head-signer`). `verify --signer KEY` accepts KEY if it is HEAD's
  signer **or any earlier key of the chain**: pin the key you trust (e.g. the original) and the
  handovers are followed from it.
* **Writers follow the current signer.** `append`, `tombstone`, `shred`, `compact --apply`, `adopt` and
  the next `rotate-signer` need the current signer's `--identity`; the old key is refused ("not this
  log's current signer"), checked again under `LOG.lock`.
* **Earlier state stays valid.** Nothing is rewritten: every pinned anchor, every older HEAD and
  every receipt cut before the handover keeps verifying (an old receipt under the old key). A receipt
  cut after it carries the handover lines (`handover-N=`), so `check-proof --signer old.pub` follows
  the chain offline; `check-proof --signer new.pub` works too.
* **Crash order:** manifest raised to `log=4` → INDEX line (the commit point; the handover is valid
  on its own because it carries the old key's signature) → HEAD. A crash before HEAD leaves a
  `head-lag`; the new key's next write re-covers it.
* **Refused:** an unsigned log (there is no signer to hand over), `--identity` that is not the current
  signer, `--new` equal to the current signer, or a `--new` that is not a valid Ed25519 public key
  (not canonical, or of small order).
* **What it does not do.** A handover is the outgoing key's own statement: if that key was **stolen**,
  the thief can hand the log over too (or sign a rival history). Rotate *before* a key is lost, and
  keep anchors / receipts elsewhere so a rival history is caught. A retired key keeps verifying what
  it signed while it was the signer; it is not "revoked". Adding a signer to an unsigned log is not
  supported (it would be a claim anyone with file access could make).

## Mount (read-only view of a log)

`sigil mount` (and `--export-dir`) of a `kind=log` container shows **one file per live segment**.
Same keys as `log read`: `--pass` / `--identity` unwrap sealed batches (and per-segment key rings);
missing keys fail with a clear error when a file is opened (or when export materializes it).

```sh
# No FUSE needed (CI / box): materialize a read-only tree
sigil mount events ./view --export-dir /tmp/log-view
ls /tmp/log-view
# → 0000000001  0000000003  0000000006 …   (zero-padded seq; matches on-disk basename without .sg1)

# FUSE when /dev/fuse + fusermount3 are available (same path as vault mount)
mkdir -p ./view
sigil mount events ./view
# …
sigil umount ./view
```

* **Tombstones / shreds**: deleted segments are **absent** from the tree (same as a range `log read`
  that skips them). There is no stub or tombstone file.
* **Compaction**: original seqs stay addressable under their own names; the compaction entry itself
  is not a file. Opening `0000000003` cuts that batch out of its holder, exactly like
  `sigil log read events --seq 3`.
* **Read-only**: `--writable` is refused (append with `sigil log append`; never rewrite the log
  through mount). Plain `.sg1` and non-log mounts are unchanged.
* **Naming**: `{seq:010}` (e.g. `0000000007`) — human-readable, stable, and consistent with the
  `segments/NNNN/NNNNNNNNNN.sg1` layout. No extension: the cleartext is the batch bytes, not a star.

See also [VAULT-MOUNT-NEST.md](VAULT-MOUNT-NEST.md) for FUSE vs `--export-dir` on vaults and packs.

## Deferred (later slices)

Done in slice 2: tombstones + compaction. Done in slice 3: per-segment keys + crypto-shredding
(above). Done: `sigil mount` view of a log; `sigil log adopt` for loose piles of stars; inclusion proofs
(`log prove` / `log check-proof`); signer rotation (`log rotate-signer`). Still deferred:

* **Nested hierarchical cards**: a card of cards (daily → monthly roll-ups) with their own Merkle roots.
* Adding a signer to an unsigned log after `init`; *consistency proofs* (this anchor is a prefix of that one) without the full INDEX.
* Streaming appends / segments above memory size (work-pack chunking); metadata-hiding INDEX.
* INDEX roll-up / pruning of very old history (needs the hierarchical cards: it is chain-breaking by nature).
* Automatic, scheduled retention (`compact` is explicit today; a monthly `doctor` + `compact --dry-run` routine is the intended shape).
* Re-wrapping the key ring to new recipients / rotating a recipient (today: `compact` re-seals live batches under new keys wrapped to the new recipients), shredding one batch inside a compaction segment without rewriting it, and enabling segment keys on an existing log (init-time only, by design: no layout fork).
