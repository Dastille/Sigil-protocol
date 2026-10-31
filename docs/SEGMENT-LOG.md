# Segment log (`sigil log …`)

## Abstract

A Sigil segment log is an append-only, tamper-evident log of opaque batches, stored as a plain
directory. Each batch is sealed as an ordinary `.sg1` star (Reed–Solomon erasure coding inside the
file, optional AES-256-GCM per batch). An `INDEX` of one text line per entry links every line to
its predecessor with a domain-separated SHA-256 hash chain anchored to a random log id. A `HEAD`
commits to the chain and to a Merkle root over all chain hashes, and can be signed with Ed25519.
The design borrows the core of Certificate Transparency (RFC 6962): a Merkle tree over an
append-only sequence, a signed tree head, short offline inclusion proofs, and small `SEQ:ROOT`
anchors pinned outside the log. To that it adds what CT does not need for a single-owner store:
erasure-coded segments that `mend` heals in place, tombstones and compaction that never rewrite
the index, opt-in crypto-shredding of per-segment keys, and signer rotation. CT and similar
systems provide consistency proofs and public monitoring. This log provides consistency proofs
(`log prove-consistency`, see below) but no gossip or monitors, so rollback and fork detection depend on anchors the reader
keeps (see "Prior work" and "Threat model").

Status: **slice 1 shipped** (append, ls, read, verify, mend, gc / doctor support),
**slice 2 shipped** (tombstones + compaction, `log=2`), **slice 3 shipped** (opt-in per-segment
keys and crypto-shredding, `log=3`), and **log mount shipped** (`sigil mount` / `--export-dir` of a
`kind=log` container), **`log adopt` shipped** (tidy a loose pile of `.sg1` stars into a log), and **inclusion proofs
shipped** (`log prove` / `log check-proof`: an offline receipt that one entry is in the log), and **signer
rotation shipped** (`log rotate-signer`, `log=4`: hand a signed log over to a new key), and **adding a
signer later shipped** (`log add-signer`: pin a first key on a log created unsigned), and **folder
backup shipped** (`log add LOG DIR`: seal only the files that are new or changed since the last add), and the
**private INDEX shipped** (`log init --private-index`, `log=5`: sizes, SHA-256s and file names sealed in the
INDEX). Approved 2026-10-06 as a general-purpose mode (not tied to any one
application); built after the tidy-container track. Roll-up **cards** shipped as an MVP (`log card` / `log check-card`,
see "Cards"); INDEX roll-up / pruning stays **deferred** (see the end).

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
`log=5` = a **private INDEX** (`privindex=1`, an `IXKEY.sg1` member, sealed `box=` entries); only
`sigil log init` with `--pass` / `--to` (or `--private-index`) creates it, from its first byte, and a
log created without a key or with `--public-index` never becomes `log=5` (see "Private INDEX" below).
`log=6` = a private log's tombstone / shred lines may carry a **sealed reason** (`box=` on an
`op=tomb` line); a private log is raised to `log=6` only by its first `tombstone` / `shred` with
`--reason` (manifest first), so a sigil that knows only `log=5` refuses it instead of calling the line
damaged. Private logs without a sealed reason stay `log=5`; public logs never become `log=6`.
`log=7` = **padded segments** (`pad=padme` in `CONTAINER`, private INDEX only): set by `log init
--pad` or `sigil log pad LOG` (manifest only; existing segments keep their bytes). See "Padding".
`log=8` = **segment keys turned on later** (`segkeys=1` plus `segkeys-from=N` in `CONTAINER`): set
only by `sigil log enable-segment-keys LOG`; segments before seq N have no key-ring record and are
opened as before. Logs made with `init --segment-keys` stay `log=3` (or 5/7) with no `segkeys-from`.
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
  IXKEY.sg1                         only in a private-INDEX log (log=5): the wrapped index key
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
seq=12 t=1760000300 size=0 sha=<star> star=<star> box=<hex> chain=<64 hex>             private segment entry (log=5)
seq=13 t=1760000400 op=tomb del=12 box=<hex> chain=<64 hex>                              private tombstone, sealed reason (log=6)
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
| `src`   | `log adopt`, optional: SHA-256 of the adopted star file (makes re-runs idempotent) |
| `path`  | `log add`, optional: the file's path relative to the folder that was added, `/`-separated, `%XX`-escaped like `reason` (any byte outside `A-Z a-z 0-9 - _ . ~ , : / @`), so any file name round-trips. In an ordinary log the INDEX is not secret: file names are visible in it. In a private log (`log=5`) the path is inside `box` |
| `box`   | private log only (`log=5`): `size`, `sha` and `path` sealed with AES-256-GCM; the visible `size` is then `0` and `sha` repeats `star` (see "Private INDEX"). On an `op=tomb` line (`log=6`) it holds only the `reason` (record `size=0`, `sha=` zeros, `reason=`), and the line then has no `reason=` / `star=` in the clear. Always the last field before `chain` |
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
  new one with `sigil log rotate-signer` (see "Signer rotation"). A log created unsigned can get
  its first signer later with `sigil log add-signer` (see "Adding a signer later").
* The signature binds the log-id, so it cannot be replayed on another log.

## Operations

```sh
sigil log init events [--identity me.sgk] [--segment-keys] [--to me.pub|--pass-file F (private INDEX) [--public-index]]
sigil log append events FILE|-  [--mode glyph|reflection|seal] [--pass-file F|--talisman F] [--to RECIPIENT]… [--identity me.sgk]
sigil log ls events [--pass-file F | --identity …]  # also: sigil ls events (a private INDEX shows sizes/names only with a key)
sigil log ls events --json                          # the same listing as JSON for scripts (see "Listing as JSON")
sigil log read events [--seq N | --from A --to B] [-o out] [--pass-file F | --identity key.sgk]…
sigil log verify events [--quick] [--pass-file F | --identity …] [--signer KEY] [--anchor SEQ:ROOT]… [--json]
sigil log mend events
sigil log adopt events PILE/ [STAR.sg1 …] [--keep] [--dry-run] [--identity me.sgk] [--pass-file F | --unlock K.sgk] [--to R]   # tidy loose stars in
sigil log add events DIR [--dry-run] [--exclude PATTERN]… [--no-ignore-file] [--mode …] [--pass-file F|--talisman F] [--to RECIPIENT]… [--identity me.sgk] [--unlock KEY.sgk]   # back up a folder
sigil log tombstone events --seq N | --from A --to B [--reason TEXT] [--identity me.sgk] [--pass-file F | --unlock K.sgk]   # private log: reason sealed
sigil log shred events --seq N | --from A --to B [--reason TEXT] [--identity me.sgk]    # --segment-keys logs only
sigil log add-signer events --identity me.sgk                     # pin a first signer on a log created unsigned
sigil log rotate-signer events --identity old.sgk --new new.pub   # hand a signed log over to a new key (log=4)
sigil log prove events --seq N [--at M] [-o receipt.proof] [--pass-file F | --identity …]   # receipt: this entry is in the log
sigil log check-proof receipt.proof [--file BATCH] [--signer KEY] [--anchor SEQ:ROOT]   # offline, no log, no keys
sigil log compact events [--keep-last N] [--older-than 30d] [--range A-B] [--apply] [--target-size BYTES]
                         [--pass-file F|--identity …] [--seal-pass-file F|--to RECIPIENT]… [--mode …] [--allow-decrypt]
sigil gc events [--apply]        # orphans of crashed appends, and files the INDEX declares dead
sigil doctor events              # same checks as verify, plus the shared exit codes
sigil mount events ./view [--export-dir DIR] [--pass-file F | --identity key.sgk]…
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

Opt-in at `init`, or later with `sigil log enable-segment-keys` (see "Turning segment keys on later"):

```sh
sigil log init events --segment-keys [--identity me.sgk]
sigil log append events batch.json --to alice.pub          # or --pass-file F, or both
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

### `rewrap` (change who can open the keys)

```sh
sigil log rewrap events --identity alice.sgk --add-to bob.pub             # add a recipient
sigil log rewrap events --identity bob.sgk --remove-to alice.pub          # remove one
sigil log rewrap events --identity bob.sgk --replace --add-to carol.pub --new-pass-file pw   # rotate all
sigil log rewrap events --pass-file old --new-pass-file new               # change the passphrase
sigil log rewrap events --identity carol.sgk --drop-pass                  # keys open to --to only
```

Applies to every **wrapped key** of the log: each record of the per-segment key ring
(`--segment-keys`) and the private-INDEX key (`IXKEY.sg1`). No segment, INDEX line, HEAD or
manifest changes (the keys themselves stay the same, only who they are wrapped to), so the chain,
anchors, receipts and signatures stay valid and no signing key is needed.

* **How.** A wrapped key is an SGTO block: one record per `--to` recipient (X25519) plus at most
  one passphrase record (Argon2id). Every key is unwrapped with the **current** `--pass-file` /
  `--pass -` / `--identity` (that is the authorisation); records that stay are kept byte for byte;
  `--add-to` and `--new-pass-file` add records with the same encodings as `seal --to` / `--pass`.
  `--remove-to` drops the records whose recipient hint matches; `--drop-pass` drops the passphrase
  record; `--new-pass-file` replaces it; `--replace` drops everything first (rotate to exactly the
  given set). A recipient already present is not added twice.
* **Fail closed, all or nothing.** Everything is computed in memory first. Refused before any write:
  no current key given; a key that does not open with it (a mixed ring, wrapped to different people
  per append, needs keys that open every record; give several `--identity`); a damaged ring shard or
  `IXKEY.sg1` (`log mend` first); a result with no recipient and no passphrase (it would lock
  everyone out; there is no opt-in for that: `log shred` is the explicit way to destroy keys);
  `--remove-to` that matches nothing; a log without wrapped keys (each segment sealed straight to
  its recipients: use `compact --seal-pass-file / --to`). `--dry-run` checks and counts only.
* **Crash safety.** Each shard and `IXKEY.sg1` is replaced atomically (the ring's old bytes are
  overwritten best effort, as for `shred`). A crash between files leaves some keys re-wrapped and
  some not; run the same command again with keys that open both (e.g. old and new `--identity`).
* **What it does not do.** It cannot take back what a removed recipient already has: a key they
  unwrapped, bytes they read, or an old copy of the ring or `IXKEY.sg1` (backups, snapshots). It
  changes who can open the keys **from now on**. To make old copies useless, `compact` re-seals
  the live batches under **new** keys (wrapped to the new recipients) and shreds the old ones.
  Adding a passphrase costs one Argon2id derivation per key (about 0.05 s each).

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

### Erasing one batch inside a compaction segment (`shred --rewrite`)

```sh
sigil log shred events --seq 2 --rewrite --pass-file pw.txt --seal-pass-file pw.txt [--reason TEXT]
#   (--seal-to alice.pub for an encrypt-to file; --unlock / --identity open the old file too)
```

**In-place erasure is not possible, so it is not offered.** A segment is one sealed star: one
AEAD key and tag over the whole (compressed, possibly padded) body, plus Reed–Solomon parity.
Overwriting one batch's bytes would break the tag for every batch in the file, and `mend` would
treat the change as bit-rot and put the bytes back from parity. There is no honest way to destroy
part of one AEAD message.

What `--rewrite` does instead is the smallest real rewrite: a tombstone for the batch (with its
reason, sealed in a private log), then a compaction of **only the file(s) holding it**. The other
batches of that file are re-sealed into one new file (in a segment-keys log under a fresh key);
the old file is erased and, with segment keys, its key record destroyed. No other segment file is
read or written (files already dead and waiting for `compact --apply` are erased as usual).
It works in any log, with or without segment keys.

* **Fails closed.** Before anything is written it opens every holder with the given keys and checks
  a key for the new file was given (`--seal-pass-file` / `--seal-to`; a segment-keys or encrypted
  file is never re-written in the clear). A wrong key or a missing one changes nothing. A literal
  `--pass` is refused.
* **Crash between the two steps:** the tombstone is committed and the batch is unreadable through
  the log, but its bytes are still in the old file; `verify` reports `deleted-data` and
  `sigil log compact --apply` finishes the job.
* **What it does not reach:** backups and snapshots of the old file, or of the key ring, still
  hold the batch (as for every shred / compaction). The batch's INDEX line stays (sizes and names in
  the clear for a public INDEX; sealed for a private one), so every pinned anchor still verifies.

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

* **Into a private INDEX (`log=5`).** Give the key that opens the index key:
  `sigil log adopt photos pile/ --pass-file pw.txt` (or `--unlock me.sgk`, or the signing
  `--identity`). Without it (or with a wrong one) adopt is refused before any star is read, planned or
  printed. Each star is **opened** with the same keys (its bytes checked by the unsealer), and its
  plain size and SHA-256 go into the line's sealed box like any private append; the line has no
  `src=` and no size or hash in the clear.
  * An **encrypted v3 (private label) star** these keys open is still copied byte-for-byte (its
    header shows only a keyed fingerprint).
  * **Any other star** (unencrypted, or an older encrypted format whose header shows the plain size
    and SHA-256) is **re-sealed**: its plain bytes are sealed again in the star's ECC mode under
    `--pass-file` / `--to`, as an append would (the plan says `→ re-sealed`). The original file is
    not what ends up in the log.
  * A star that does not open with the given keys is left in place (exit 1).
  * Re-runs: a kept star is "already" when its keyed fingerprint is already a segment; a re-sealed
    one when an opened segment has the same plain SHA-256.
  * Stars adopted into a private log keep no file names (as with append); the source files are
    removed after the commit unless `--keep`.

## Backing up a folder (`sigil log add`)

`sigil log add LOG DIR` makes a folder backup one command. Run it as often as you like: each run
seals only what is **new or changed** since the last add, and a run with nothing to do writes
nothing.

```sh
sigil log init photos --identity me.sgk
sigil log add photos ./Photos --to me.pub --identity me.sgk --dry-run   # plan only
sigil log add photos ./Photos --to me.pub --identity me.sgk
```

```text
  + 2024/trip/beach.jpg  6 bytes  new → segment 7
  + a.jpg  14 bytes  changed (was segment 3) → segment 8
  ! b/c.txt  missing from source (kept: segment 4)
log add photos.sigil from Photos: added 1, changed 1, unchanged 2, missing 1, skipped-special 0  root 3f1c…
```

* **One segment per file.** Each file is sealed by the same path as `log append` (its own star,
  `--mode`, `--pass`, `--to`; in a `--segment-keys` log its own key), and its INDEX line is an
  ordinary segment line plus the additive `path=` key. Nothing else changes: no new entry type,
  no manifest bump (the log stays `log=1` unless it already was newer), no new files in the
  container, `.sg1` layout untouched. `read --seq`, `verify`, `mend`, `prove` / `check-proof
  --file`, `tombstone`, `compact` and `mount` treat these entries like any other; `log ls` also
  shows each entry's path. One file per segment keeps memory to **one file at a time** (the file is
  sealed in memory, so very large single files need that much RAM; streaming is a later slice) and
  lets a single file be read back, proved, tombstoned or shredded on its own.
* **Walk.** `DIR` is walked recursively; files are taken in **byte order of their relative path**
  (stable on every run and machine). Symlinks are never followed; symlinks, devices, pipes, sockets
  and nested sigil containers (including the log itself, if it lives inside `DIR`) are **skipped and
  listed** (`skipped-special`). Empty folders are not recorded. A `DIR` inside a sigil container is
  refused. A file that cannot be read is listed and not added, and the exit code is 1. Output
  shows names with control characters escaped (`\n`), so a file name cannot fake extra lines.
* **What counts as already sealed.** For every path, the latest entry **the HEAD vouches for**
  (the same rule `gc` uses: on a signed log only entries under a valid signature of the current
  signer) gives a size and a SHA-256. A file is *unchanged* only if its size matches, **the SHA-256
  of its current bytes matches**, and the segment file that holds that entry is present and its
  header carries the true-name the INDEX recorded (keyless; one header read). A different size goes
  straight to "changed" without hashing; modification times are never used. So the comparison
  needs **no key**, also for encrypted logs.
* **Changed files are new versions.** A changed file becomes a new segment; the earlier version
  stays readable by its seq. Nothing is overwritten.
* **Nothing is ever deleted because a source file went away.** A path that is still live in the log
  but no longer in `DIR` is listed as `missing from source (kept: segment N)` on every run; no
  tombstone is written. Deleting from the log is always an explicit `log tombstone` / `log shred`.
  If you did tombstone a file and the folder still holds exactly those bytes, `add` does not put it
  back (`same bytes as segment N, deleted by entry T; not re-added`); different bytes at that path
  are added as a new version.
* **Encryption is not dropped by accident.** If the newest file added to the log was sealed with
  `--pass` / `--to`, a run that would seal files without either is refused. An unchanged re-run needs
  no key at all. A `--segment-keys` log needs `--pass` and/or `--to` as for `append`.
* **Signed logs** need the current signer's `--identity`, like every writer; a `--dry-run` needs no
  key.
* **Dry run.** `--dry-run` hashes what it must to decide, prints the same plan (`would have added …`)
  and writes nothing, not even the lock.
* **Skipping files and folders (`--exclude`, `.sigilignore`).** `--exclude PATTERN` (repeatable)
  and a `.sigilignore` file at the top of `DIR` (read automatically when present; one pattern per
  line, blank lines and `#` comment lines ignored, trailing spaces trimmed; `--no-ignore-file`
  switches it off) leave paths out. Patterns are matched against the path **relative to `DIR`**,
  `/`-separated, case-sensitive:

  | Pattern | Skips |
  |---------|-------|
  | `.tools-venv/` | every folder named `.tools-venv`, at any depth, with everything under it (trailing `/` = folders only) |
  | `*.tmp` | every file or folder whose name ends in `.tmp`, at any depth (`*`, `?`, `[a-z]`, `[!a-z]` never cross a `/`) |
  | `raw/*.dng` | `.dng` files directly in `DIR/raw` (a `/` in the pattern anchors it at the top of `DIR`; so does a leading `/`) |
  | `**/cache/` , `logs/**` , `a/**/b` | `**` crosses folders: any depth / everything inside / zero or more folders between |
  | `\*`, `\!x`, `\#x` | a literal `*`, `!x`, `#x` |

  A matching **folder is skipped with its whole subtree, unread** (an unreadable excluded folder
  is not an error). Excluded entries are listed (`x .tools-venv/  excluded by ".tools-venv/"
  (.sigilignore line 3)`) and counted (`excluded N`). Paths **already in the log** that a pattern
  now covers are **left alone**: they are not "missing from source", nothing is tombstoned, they
  stay readable, and they are counted as `excluded-kept N` (listed one by one with `--dry-run`).
  To actually drop them, use `log tombstone` / `log shred` explicitly. `.sigilignore` itself is an
  ordinary file and is backed up unless it excludes itself. Fail closed: a leading `!`
  (`.gitignore`'s re-include) is refused rather than read as a literal, as are an unclosed `[`, a
  lone trailing `\` and an empty pattern, and a `.sigilignore` that is not a regular file; the run
  then stops before reading the folder or writing anything (dry run too).

  ```sh
  printf '# Python tools for the export\n.tools-venv/\n' > ./instagram/.sigilignore
  sigil log add ig ./instagram --dry-run                     # shows the x lines, writes nothing
  sigil log add ig ./instagram --exclude '*.tmp'             # plus a one-off pattern
  ```
* **Crash safety and checkpoints.** Files are sealed one at a time into unindexed segment files;
  their INDEX lines are appended in one write (the commit point), then HEAD, as for `adopt`. A run
  commits a **checkpoint** every 1000 files or 1 GiB of plain data, so a crash during a large first
  backup loses at most one checkpoint: run the same command again and the committed files are
  recognised as unchanged. Uncommitted leftovers are removed on an error, or reclaimed by `gc` /
  overwritten by the next write after a crash.
* **Cost.** Every run reads and hashes every file whose size did not change (about the time of
  reading the folder once). Each segment carries the fixed ~3.2 KB of per-star overhead (see "Size
  notes"): negligible for photos, noticeable for thousands of tiny files. The INDEX grows by about
  170 bytes plus the path per file. Identical files at two paths are stored twice.
* **Skipping the re-hash (`--cache`, opt-in).** `sigil log add LOG DIR --cache` keeps `ADDCACHE`
  in the log folder (owner-only; `verify` / `gc` leave it alone; delete it any time). It records,
  per path, the size, mtime, ctime and inode a file had when its bytes last matched the latest
  version, plus that version's seq and SHA-256. A later `add --cache` skips hashing a file only if
  all four are equal **and** the path's latest vouched version is still that seq and SHA-256; the
  summary says `(N not re-hashed: --cache)`. Anything else (different stamp, a newer or deleted
  version, a cache made for another source folder, a missing, unreadable or malformed cache) means
  a full hash, as without the flag. Stamps less than 2 s older than the cache write are not trusted
  (a write in the same tick could go unseen). The segment file is still checked against the INDEX.
  A file that is sealed is always read in full and the INDEX gets the SHA-256 of those bytes, so the
  log's integrity does not depend on the cache. **It is a speed-up, not a cryptographic check:**
  content can change with the same size and times (tools that reset mtime and ctime, file systems
  with coarse or missing ctime, a clock moved back, a hand-edited cache). When that matters, run
  `add` without `--cache` (always a full hash). Refused for a private INDEX (the cache would show
  names and sizes in clear). Not written by `--dry-run` or a run with unreadable files.
* **One folder per log.** The log remembers paths relative to `DIR`. To back up several sources
  into one log, give them one parent folder (`staging/mum/`, `staging/dad/`) and add that; adding
  two unrelated folders to one log reports each other's files as missing.
* **Getting files back.** `sigil log restore LOG PATH [-o OUT]` brings back a file or a whole
  folder by the path `add` recorded (see below); `sigil log read LOG --seq N -o FILE` restores one
  version by seq (also older versions).

### Restoring by path (`sigil log restore`)

```sh
sigil log restore photos 2024/trip/beach.jpg -o beach.jpg    # one file: its latest version
sigil log restore photos 2024 -o Photos-2024 --identity me.sgk  # a folder: every path under 2024/
sigil log restore photos . -o Photos-all                      # everything (needs -o)
sigil log restore photos 2024 --at 2026-03-01 -o Photos-March   # the folder as it was then
sigil log restore photos notes.txt --at 2026-03-01T09:30:00Z -o notes-old.txt
sigil log restore photos notes.txt --seq 12 -o notes-v12.txt    # one exact version (see log ls)
```

* **Older versions.** `--at TIME` takes, for every path, the newest vouched version appended at or
  before TIME (UTC: unix seconds, `YYYY-MM-DD` = the end of that day, or `YYYY-MM-DDTHH:MM[:SS]Z`
  as `log ls` prints). Paths first added later are not there; a file or folder with no version by
  then is refused. `--seq N` takes exactly entry N, which must be a version of that file (files
  only). Times are the writer's clock at append (in the chained INDEX line, so signed and
  tamper-evident, but not a trusted timestamp: a wrong clock picks the wrong version).
  Deleted-means-deleted below applies to the version picked: if it was tombstoned or shredded since,
  it is refused (file) or left out (folder), never swapped for an even older one.

* **What it picks.** For every path, the latest version among entries the HEAD vouches for (the
  rule `add` and `gc` use; or as of `--at`). `PATH` equal to a recorded path restores that file; otherwise `PATH` is a
  folder (matched at a `/` boundary: `20` does not match `2024/…`) and every path under it is
  written relative to it. No match: refused.
* **Deleted means deleted.** A file whose latest version was tombstoned or shredded is refused on
  its own; inside a folder it is left out and listed (`- path deleted …`). An older version is never
  substituted; ask for one on purpose with `--at` / `--seq`.
* **Byte-exact, all or nothing.** Every file goes through the reader `log read` uses (segment
  header true-name, plain size and SHA-256 against the INDEX, compaction members cut out and
  re-hashed). All files are read and checked **before anything is written**; the result is then
  written under a temporary sibling name and renamed into place. A missing or corrupt segment (or a
  wrong key) fails the whole restore and leaves nothing behind. The destination must not exist:
  restore never overwrites. Default destination: the last component of `PATH` in the current folder.
* **Untrusted names.** A recorded path with an empty, `.` or `..` component, a leading `/` or a NUL
  byte is refused, so a tampered INDEX cannot write outside the destination.
* **Keys.** The same as `log read`: `--pass` / `--identity` for encrypted segments, segment-key logs
  and a private INDEX (whose paths are sealed: without the key nothing is found and no name is
  printed). A damaged log (`verify` errors) is refused; run `log mend` first.
* **Memory.** The files of one restore are held in memory until all are checked (same order of RAM
  as the plain size restored); restore large trees folder by folder.

## Private INDEX (default for `sigil log init --pass/--to`, `log=5`)

**Default.** `log init` with `--pass` and/or `--to` creates a private INDEX; no flag is needed
(`--private-index` is still accepted and means the same). `--public-index` opts out: the log is
created with a public INDEX, `--pass` / `--to` are not used at init (give them to each append to
encrypt the segments), and a warning is printed. `log init` with no key creates a public INDEX (there
is nothing to wrap an index key to) and prints a note saying so. A log keeps the INDEX kind it was
created with (`privindex=1` in `CONTAINER`); to make an existing public log private, copy it with
`sigil log privatize` (below).

A public INDEX shows, for every entry, the batch's plain size, its plain SHA-256 and
(for `log add`) the file's path. Anyone who can read the log folder learns the names and sizes of
everything in it, and can confirm a guess about a file's content by hashing the guess. A private log
seals those three values; everything else about the log works as before.

```sh
sigil log init photos --identity me.sgk --to me.pub                     # or --pass, or both: private by default
sigil log add photos ./Photos --to me.pub --identity me.sgk             # --identity signs and opens the index key
sigil log ls photos                                                     # sizes, hashes, names: "sealed"
sigil log ls photos --identity me.sgk                                   # the full listing
sigil log prove photos --seq 7 --identity me.sgk -o beach.proof         # receipt carries entry 7's key
sigil log check-proof beach.proof --file beach.jpg --signer me.pub      # still checks the file, offline
```

**In plain words.** The log's table of contents is now written in code. Without the key, someone who
finds the backup drive sees only how many entries there are and when they were added, not file
names, sizes or fingerprints. With the key, everything (backing up only new files, receipts, clean-up)
works exactly as before.

### Making an existing log private (`sigil log privatize SRC DEST`)

```sh
sigil log privatize photos photos-private --pass-file pw.txt --sign me.sgk   # and/or --to me.pub
sigil log ls photos-private                       # names, sizes, hashes: sealed
sigil log ls photos-private --pass-file pw.txt    # the full listing
```

Add `--pad` to turn on segment padding (`log=7`, `pad=padme`) in DEST in the same step, exactly
as `sigil log pad DEST` would afterwards: every segment written to DEST from then on is padded.
The segments copied by privatize keep their sizes (a `log compact --apply` on DEST re-seals them
padded). Without `--pad` DEST is a plain private log, as before.

A public INDEX line's chain hash covers its `size=`, `sha=` and `path=` text, so they cannot be sealed
in place without changing every chain hash, the HEAD and every root, which would silently invalidate
receipts, anchors and cards. `privatize` therefore makes a **new** log instead:

* every live segment entry the source HEAD vouches for is read with the checked reader (as `log
  read` / `restore`), sealed again encrypted (`--pass-file` / `--to`, like any private log) into
  DEST with its original time and `log add` path, and its size, SHA-256 and path go into the box.
  Tombstoned / shredded entries and non-data lines are not copied (counted as skipped);
* `--pass-file` (and `--identity`) also open the source's encrypted segments; a segment that does not
  open, a damaged source (`verify` errors) or a HEAD the log does not vouch for refuses the whole run;
* a signed source needs `--sign` with **its** signer (the copy keeps the signer); an already-private
  source is refused (use `log rewrap`); DEST must not exist;
* DEST is built in a hidden temporary sibling (`.DEST.sigil.privatize-PID.sigil`) and renamed into
  place only when complete; an error removes it; a crash can leave it behind (delete it; SRC was only
  read). DEST never exists half-made under its final name;
* DEST has a **new log id, chain and roots**. Old receipts, anchors and cards keep verifying against
  SRC; new ones come from DEST. The report prints SRC's id and `SEQ:ROOT` so the link can be pinned
  (e.g. keep SRC's card, or note the line).

**What it does not do.** It does not erase SRC: the old public INDEX (names, sizes, hashes) stays
where it is, and in every backup, sync copy or snapshot already made of it. After checking DEST,
delete SRC yourself (and know that old backups still show what it held). Segments of SRC that were
stored unencrypted also showed their content to anyone with the folder; they are only re-sealed in
DEST. Entry numbers change (DEST counts from 1, without the skipped ones).

**Format.** A private segment or compaction line is

```text
seq=7 t=1760000000 size=0 sha=<star> star=<star> box=<hex> chain=<hex>
seq=9 t=1760000090 size=0 sha=<star> op=compact of=1,3 star=<star> box=<hex> chain=<hex>
```

* `star` is the segment star's **keyed fingerprint** (the v3 private label; see
  [PRIVATE-LABEL.md](PRIVATE-LABEL.md)): it binds the file to the line without revealing anything
  about its plain bytes. The visible part has exactly the shape of a key-less ("label only") entry,
  so every keyless check (`verify`, `doctor`, `mend`, `gc`, `tombstone`, `shred`, `rotate-signer`)
  runs unchanged and needs no key.
* `box` (hex) = `01` ‖ key commitment (32 bytes) ‖ nonce (12) ‖ AES-256-GCM ciphertext + tag of a
  short text record `sigil-log-box=1`, `size=`, `sha=`, optional `path=` (escaped like `path=`
  above), zero-padded to a multiple of 64 bytes so the box length does not give away the exact
  length of a file name. Associated data: `"sigil-log-box-v1\0"` ‖ log-id ‖ `0x00` ‖ seq (8 bytes,
  big-endian) ‖ the visible part of the line (everything before ` box=`). The box is also covered by
  the hash chain and the Merkle root like every other field.
* **Keys** (HKDF-SHA-256, RFC 5869; AES-256-GCM, NIST SP 800-38D; nothing new):
  * index key: 32 random bytes made at `init`, wrapped with the existing SGTO machinery (X25519
    `--to` recipients and/or an Argon2id `--pass`, exactly as the key ring and `seal --to` do) and
    stored in `IXKEY.sg1`, a small **unencrypted** Seal-mode star that holds only the wrap, so it
    heals with `sigil log mend` and `verify` checks it keylessly (`ixkey-missing`, `bit-rot`);
  * entry key of entry `seq` = HKDF(salt `"sigil-log-box-v1\0"` ‖ log-id, ikm index key, info
    `"sigil log box v1 entry"` ‖ seq as 8 big-endian bytes);
  * from the entry key, HKDF (no salt) with info `"sigil log box v1 aead key"` → the AES-256-GCM key,
    and info `"sigil log box v1 key commitment"` → the 32-byte commitment stored in the box. AES-GCM on
    its own does not commit to its key (one ciphertext can be built to open under two keys; Albertini,
    Duong, Gueron, Kölbl, Luykx, Schmieg, "How to Abuse and Fix Authenticated Encryption Without Key
    Commitment", USENIX Security 2022). Checking the commitment first makes the receipt's key the only
    one that opens its box.
  * Every box gets a fresh random 96-bit nonce; each entry key encrypts one line (a crashed append that
    reuses its seq draws a new nonce), far below GCM's per-key limit.

**Who needs the key.** Everything that must know sizes or names: `log add` (also `--dry-run`: it has
to know what is already in the log), `log append` (to write the box), `log read`, `log compact`
(it cuts batches by their sizes), `log ls` for the full listing, and keyed `log verify`. Writers open
the index key with `--pass`, then their signing `--identity`, then any `--unlock KEY.sgk` (for an
unsigned log, whose `--identity` is refused for signing). A key that does not open it is an error
(`verify` reports `index-key`, exit 2), never a silent fallback. Keyless: `verify`, `doctor`, `mend`,
`gc`, `tombstone`, `shred`, `rotate-signer`, and `prove` (inclusion only).

**What stays the same.** `log add` still skips unchanged files (same path, size and SHA-256, now read
from the opened boxes) and still checks the segment file's header against `star`. Anchors, signed
HEADs and the Merkle root work as before (they cover the lines as written, boxes included).
Tombstones, compaction (compaction lines are sealed too) and crypto-shredding (with
`--segment-keys`, which combines with `--private-index`) are unchanged.

**Receipts.** `log prove --pass/--identity` adds `entry-key=<hex>`: the key of that one box. It
opens only that entry (HKDF is one-way, so no other entry key, nor the index key, can be derived from
it). `check-proof` checks the commitment, opens the box and then compares `--file` with the sealed
size and SHA-256. A receipt without `entry-key=` still proves inclusion, but `--file` is refused
("sealed … ask for a receipt cut with the log's key"). Giving a receipt away discloses that entry's
size, hash and file name to whoever holds it.

**Sealed reasons (`log=6`).** In a private log, `tombstone` / `shred --reason TEXT` seal the reason in
a box on the tombstone line, with the same keys, AAD (log id, seq, visible part of the line) and
key commitment as a segment box; the entry key is the tombstone's own seq. They need the index key:
`--pass-file`, `--unlock KEY.sgk` or the signing `--identity` (a tombstone without `--reason` still
needs no key). Without the key, `log ls` shows `reason: sealed` and the INDEX holds no reason text;
with it, `ls`, `read` errors and `verify` messages show the reason as in a public log. A box moved to
another line fails the chain hash and the box's AAD. What stays visible, as for every tombstone: which
seqs were deleted, when, and whether it was a shred; and the box length (padded to 64 bytes) gives the
reason's length to within 64 bytes.

**Padding (`log init --pad`, `sigil log pad LOG`, `log privatize … --pad`, `log=7`).** A private INDEX hides sizes, but each
segment file's length still shows roughly how big the batch is. With padding on, every **new**
segment (append, add, compaction, and the re-sealed stars of `log adopt`) is sealed from a padded frame:

```text
flag (1 byte: 0 raw, 1 deflate) ‖ body length (8 bytes, big-endian) ‖ body ‖ random fill
```

`body` is the batch deflated when that is smaller (the same deflate the star uses), and the whole
frame is `max(4 KiB, Padmé(9 + body length))` bytes. Padmé (Nikitin et al., "Reducing Metadata
Leakage from Encrypted Files and Communication with PURBs", PETS 2019) rounds a length so that only
O(log log n) bits of it remain, at most ~12% overhead (often far less). Compressing *before* padding
and filling with random bytes means the star's own deflate finds nothing to shrink, so the sealed
length depends only on the bucket. The frame is then sealed and encrypted like any segment: nothing
new cryptographically. The INDEX box keeps the batch's real size and SHA-256; readers (`read`,
`restore`, `mount`, `verify --pass`, compaction) unseal, undo the frame (deflate output capped at the
recorded size) and check that size and SHA-256 as always; a frame that does not parse or a mismatch
fails exactly like a substituted segment. Keyless checks (`verify`, `mend`, `gc`) are unchanged.

* **What it hides:** the exact size, and how compressible a batch is: every batch whose compressed
  form is under ~4 KiB has the same file length; larger ones fall into Padmé buckets.
* **What it does not hide:** how many segments there are and when they were added (the INDEX lists
  them), the bucket (an order of magnitude of the compressed size), and anything about segments
  written before padding was turned on (they keep their bytes; `log compact --apply` re-seals them
  padded). Kept-as-is stars of `log adopt` are not re-padded. Disk usage grows by the fill.
* Public logs refuse `--pad` / `log pad` (their INDEX shows every size anyway). A sigil that knows
  only `log=6` refuses a `log=7` log ("upgrade sigil").

**Refused in a private log (fail closed).** An unencrypted segment (no `--pass` / `--to`, or
`--pass ""`): its header would show the plain size and SHA-256 the INDEX hides; refused before
anything is written. `--reason` on `tombstone` / `shred` **without** the index key (it would have to
be stored in the clear): refused, nothing written. `log adopt` **without** the index key (see "Adopting a pile of stars").
`sigil mount` / `--export-dir` **without** the key (or with a wrong one): refused before any listing,
so no sizes or paths are shown; with `--pass` / `--pass-file` / `--identity` it mounts like any log
(one file per live segment, named by seq; see "Mount"). In the INDEX: a plaintext
segment / compaction line in a private log (`index-private`), a `box=` line in a log without
`privindex=1` (`log-format`), `privindex=1` under `log<5` (manifest error), and with the key, any box
that does not open (`index-box`: altered, truncated, moved to another line, or wrong key).

**What it still shows.** The number of entries, their times (`t=`), the entry types and the
tombstone / compaction structure (`del=`, `of=`), each segment file's size on disk (close to the
compressed batch size), and the signer keys. A file that appears twice is not recognisable as such
from the INDEX (each box and each keyed fingerprint is unique).

**Compatibility.** Additive: a log without `--private-index` is byte-identical to what earlier slices
write, never gets `IXKEY.sg1` and never becomes `log=5`; `.sg1` layout untouched. A sigil that only
knows `log=4` refuses a private log ("newer than this sigil understands; upgrade sigil") instead of
misreading it.

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
8. A private INDEX is opt-in at `init` (`log=5`, `privindex=1`). In it every segment / compaction line
   is sealed and every segment is an encrypted v3 star; a log without it never holds a `box=` line.

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
| `log add`: INDEX edited so a changed file looks already sealed | chain break: `add` refuses (dry run too) and writes nothing |
| `log add`: a line with a valid chain appended to claim new content is in, without the signer's key | not covered by a valid HEAD signature, so `add` ignores it (note) and seals the file |
| `log add`: unsigned log, such a line plus HEAD removed (so the line counts as vouched) | `add` still checks the segment named by the line: missing, or not the star the INDEX recorded → the file is **sealed again**, not skipped. An attacker who can also write a matching star into the log (unsigned log) is the "rewrite consistently" case above: sign the log, keep anchors, and use keyed `verify` |
| `log add`: a source file changed but size and modification time kept | detected: unchanged needs equal SHA-256 of the current bytes |
| `log add`: an exclude pattern covers files already in the log | left alone: not missing, not tombstoned, still readable (`excluded-kept`) |
| `log add`: typo or unsupported syntax in `--exclude` / `.sigilignore` (`!x`, `[abc`, …) | refused before the folder is read; nothing written |
| `log add`: a source file deleted, renamed or emptied | never deletes anything from the log: listed as missing (a rename = missing + new); an emptied file is a new, empty version |
| Attacker with segment write access and the plain data | can replace a segment only by a star with the same true-name = same plain bytes |
| Confidentiality | per segment via `--pass` / `--to`. An ordinary INDEX leaks sequence, time, sizes, plain true-names (hashes of the batches) and `log add` paths: do not use it for low-entropy secrets you cannot afford to have confirmed by guessing. With `--private-index` sizes, true-names and paths are sealed; sequence, times, entry structure and on-disk segment sizes stay visible |
| Private INDEX: box edited, truncated, or moved to another line (and the chain re-computed, unsigned log) | the box does not authenticate (GCM tag over seq, log-id and the visible fields) → `index-box`; readers and writers refuse |
| Private INDEX: wrong `--pass` / `--identity` | the index key does not unwrap → refused (`index-key` in verify); never a silent keyless fallback |
| Private INDEX: a receipt with a forged or swapped `entry-key=` | key commitment mismatch → `check-proof` exit 2 |
| Private INDEX: plaintext line inserted, or `privindex=1` removed from the manifest | `index-private` / `log-format` error, keyless |
| Private INDEX: `IXKEY.sg1` lost | `ixkey-missing` (error); sizes and names cannot be opened, the segments still open with their own keys. Keep copies of the whole container |
| Availability | ECC inside each segment; across segments sigil adds none — keep a second copy (`rsync`, atlas, cold kit) of the container |

Unauthorised concurrent writers are not a security feature: `LOG.lock` is advisory and local. One
writer at a time; do not put the container on a filesystem without atomic `rename` / `create_new`.

## Reader and writer roles (signed logs)

A log has two kinds of key, already separate in the format; this section names them as roles.

* **Writer = the signing key** (`init --identity`, `add-signer`, handed on with `rotate-signer`).
  Every operation that changes the log needs it as `--identity`: `append`, `add`, `adopt`,
  `tombstone`, `shred` (also `--rewrite`), `compact --apply`, `rotate-signer`, and (since this
  slice) `rewrap` (granting / revoking access), `pad` and `enable-segment-keys`. The check runs
  before anything is written; a wrong key is refused.
* **Reader = a key the data is wrapped to** (`--pass-file`, or a recipient added with
  `log rewrap --add-to reader.pub`). It opens a private INDEX and the segments: `ls` (also
  `--json`), `read`, `verify`, `restore`, `mount`, `prove`. It cannot do any of the writes above.

```sh
# owner grants a reader (segment-keys + private INDEX: the ring re-wrap covers every past segment)
sigil log rewrap events --pass-file pw --identity owner.sgk --add-to reader.pub
sigil log read events --seq 7 --identity reader.sgk -o day7.json     # reader: ok
sigil log append events x.json --identity reader.sgk --to reader.pub  # reader: refused
```

**What this is, honestly.** Roles are enforced by the tool and, for the INDEX, by signatures: a
reader who edits files by hand can still damage or truncate a log it can write to on disk, but
cannot produce a HEAD the pinned signer would have signed, so `log verify --signer` / `check-proof
--signer` catch it. Manifest settings (`pad=`, `segkeys=`) are not signed; a hand-edited manifest
is caught only as far as `verify` checks it. Filesystem permissions remain the first line.

* **Unsigned logs have no writer role:** any holder of the data key (or anyone who can write the
  folder) can change them. Sign the log (`log add-signer`) to get roles.
* **A reader keeps what it was given.** `rewrap --remove-to` stops *new* wraps; a reader that
  copied the key ring, old segments or its decrypted output keeps them. Revoke by rotating keys
  for new data (`compact --apply` re-seals under fresh segment keys) and treat old data as read.
* **New segments reach a reader only when wrapped to it:** append with `--to reader.pub`, or
  re-run `rewrap --add-to` (segment-keys logs) after writes.
* **Old writer keys:** after `rotate-signer` the old key can no longer sign the next write, but a
  stolen old key still verifies its own old HEADs; pin anchors.
* A reader-only `.sgk` is an ordinary identity: nothing in the file marks it as a reader. The role
  is "not the signer of this log", checked per log.

## Listing as JSON (`sigil log ls --json`)

One JSON object on stdout, format `"format":"sigil-log-ls=1"` (additive: new keys may appear, existing
keys keep their meaning). Top level: `dir`, `log_id`, `log_format`, `entries`, `signed`, `signer`,
`segment_keys`, `private_index`, `index_opened`, `padded`, `head` (`seq`, `root`, `chain`, `t`,
`anchor` = the `SEQ:ROOT` to pin, or `null`), `pending_deleted_bytes`, and `items`, one per INDEX
entry: `seq`, `t` (unix), `time` (UTC), `op` (`segment` / `compaction` / `tombstone` / `shred` /
`signer`), `status` (`ok` / `missing` / `deleted` / `shredded` / `merged` / `superseded` / `record`),
`size`, `sha256`, `sealed`, `file` (its segment file is on disk), `holder`, `deleted_by`,
`shredded_by`, `path`, plus `of` (compaction), `deletes` / `reason` / `reason_sealed` (tombstone,
shred) and `from` / `to` (signer). It is a listing, not a check: run `sigil log verify --json` for
health. A private INDEX gives `null` sizes, hashes, paths and reasons unless opened with
`--pass-file` / `--identity` (then the same as the text listing; treat the JSON as as sensitive
as the listing).

**More `--json` (same escaping, one object on stdout, additive formats):**

* `log compact --json` (`sigil-log-compact=1`): `applied`, `rule`, `live_segments`, `merges`
  (`sources`, `members`, `dropped`, `plain_bytes`, `new_seq`), `erase` and `merged_sources` (files:
  `seq`, `path` relative to the log, `bytes`, `why`), `bytes_before` / `bytes_after`, `removed`,
  `keys_destroyed`, `root` (`null` on a dry run), `notes`. A dry run still writes nothing.
* `log check-proof --json` (`sigil-log-check-proof=1`): `ok`, `log_id`, `name`, `seq`, `t`, `op`,
  `sealed`, `size` / `sha256` / `path` (`null` when the receipt does not disclose them, as for a
  private entry), `tree_size`, `root`, `anchor`, `signed_by`, `signer_chain`, `file_matched`.
* `log check-consistency --json` (`sigil-log-check-consistency=1`): `ok`, `log_id`, `old` / `new`
  (`SEQ:ROOT`), sizes and roots, `signed_by`, `signer_chain`.
* A failed check prints `{"format":…,"ok":false,"error":"…"}` and exits 2, as the text form does.
  `log verify --json` already reports health (the `doctor` JSON).
* `log restore --json` (`sigil-log-restore=1`): `out`, `folder`, `files` (`path`, `seq`, `size`),
  `bytes`, `deleted_left_out` (`path`, `seq`, `deleted_by`). Paths are the log's paths: as
  sensitive as a private log's listing.
* `log add --json` (`sigil-log-add=1`): `ok` (false when a file could not be read; exit 1),
  `items` (`path`, `size`, `why` = `new`/`changed`/`reseal`, `prev`, `reason`, `seq`; `seq` is
  null in a `--dry-run`), `unchanged`, `cache_hits`, `missing`, `special`, `unreadable`,
  `deleted`, `excluded`, `excluded_kept`, `commits`, `root` (null when nothing was committed),
  `signed`, `notes` (also printed to stderr). Paths are sensitive like a private log's listing.
* `log rewrap --json` (`sigil-log-rewrap=1`, plan with `--dry-run` or apply): `dir`, `dry_run`,
  `shards`, `records`, `index_key`, `removed`. Counts only: never keys, recipients or passphrases.
* `log mend --json` (`sigil-log-mend=1`): `ok`, `checked`, `mended`, `missing`, `unrecoverable`
  (`seq`, `error`), `keys_mended`, `keys_unrecoverable`, `ixkey_mended`, `ixkey_unrecoverable`
  (null when fine). Mend needs no key and reports segment numbers only, so on a private log it
  reveals nothing a key-free `log verify` does not. Exit 2 when `ok` is false.
* Writers: `log init --json` (`sigil-log-init=1`: `dir`, `signer` hex or null, `segment_keys`,
  `private_index`, `pad`); `log append --json` (`sigil-log-append=1`: `seq`, `size`,
  `sealed_bytes`, `sha256`, `segment`, `root`, `signed`; on a private log the size and hash are
  the writer's own, sealed in the INDEX, so keep the output as private as the data);
  `log tombstone --json` (`sigil-log-tombstone=1`: `entry`, `deleted`, `already`,
  `pending_bytes`, `root`, `signed`; the `--reason` is never echoed); `log shred --json`
  (`sigil-log-shred=1`: `rewrite`, `entry`, `erased`, `already`, `rewritten` (segment files
  rewritten by `--rewrite`, else empty), `files_removed`, `keys_destroyed`, `root`, `signed`).
  Notes and warnings stay on stderr. When one of these fails it prints
  `{"format":…,"ok":false,"exit":N,"error":"…"}` and exits with N (the same code as without
  `--json`); passphrases and keys are never printed.

## Monthly retention check (`scripts/monthly-log-retention.sh`)

A read-only routine to schedule once a month: it runs `sigil log verify` (the log's doctor:
INDEX chain, HEAD and signature, every segment's ECC and true-name, strays) and then
`sigil log compact` **without** `--apply`, which prints what would be merged and which deleted
files would be erased. It never changes the log (the tests compare every file before and after).

```sh
SIGIL=/usr/local/bin/sigil scripts/monthly-log-retention.sh ~/logs/photos \
    --pass-file ~/.sigil/pw --older-than 30d --keep-last 50      # private log: key from a file
scripts/monthly-log-retention.sh ~/logs/events --signer owner.pub --strict
# crontab: 1st of the month, 06:00, output mailed by cron
0 6 1 * *  /opt/sigil/scripts/monthly-log-retention.sh /srv/logs/events --older-than 30d
```

Options: `--pass-file` / `--identity` (given to both steps; a private log's INDEX and encrypted
segments need them for a full check and plan), `--signer` / `--quick` (verify only),
`--keep-last` / `--older-than` / `--range` (the compaction rule), `--strict`. Literal passphrases
are not accepted. The last line is a one-line summary for mail subjects:
`== summary: health=healthy|warnings|PROBLEMS  compaction-plan=ok|FAILED`.

Exit codes: `0` healthy (warnings allowed, e.g. a tombstoned file still waiting for `compact
--apply`), `1` warnings with `--strict`, `2` problems found by verify (damage, missing segment,
bad signature: act on it), `3` could not run (bad arguments, `sigil` not found, the plan failed).
**Opt-in apply (`--apply`).** With `--apply` and a rule (`--older-than` / `--keep-last` /
`--range`; refused without one, so fresh batches are never merged), the script runs
`sigil log compact --apply` with the same rule **only** when the health check found no problems
(and no warnings with `--strict`) and the plan worked, then verifies again. Encrypted or
segment-keys logs need `--seal-pass-file F` and/or `--to K.pub` for the merged segments (else the
compaction refuses and nothing changes). The summary gains `applied=yes|SKIPPED|FAILED`; exit
codes are as above, plus `3` when the apply failed and `2` when the verify after it found
problems. A skipped or refused run writes nothing (tested). Compaction erases the files of
deleted batches here; backups and snapshots are not reached.

```sh
0 6 1 * *  /opt/sigil/scripts/monthly-log-retention.sh /srv/logs/events --pass-file /etc/sigil/pw \
               --older-than 90d --apply --seal-pass-file /etc/sigil/pw
```

Without `--apply`, apply it by hand after reading the plan: `sigil log compact LOG --apply …` (same rule options,
plus `--seal-pass-file` / `--to` for encrypted logs). Bot or calendar schedulers can run the same
script; it needs no network and prints nothing secret (a private log's names stay sealed unless
`--pass-file` is given, and then only the plan's seqs and sizes are shown).

## Size notes (measured, slice 1; compaction removes the per-segment overhead for merged batches)

Each segment carries a fixed overhead of about **3.2 KB** (header, keystone, Merkle) plus the
mode's redundancy: Reflection ≈ 1.34×, Seal ≈ 2×, Glyph ≈ 1.003× on incompressible data (text
compresses first). **Batch small events into larger appends** (KBs–MBs, not single lines).
A batch is sealed in memory in one piece; very large single batches should be split. Work-pack
(chunked) segments are deferred: a segment is one `.sg1` star whose header digest is the INDEX
`star=` true-name, read whole by every reader (`read`, `verify`, `mend`, `compact`, `shred`, `gc`,
`add`), so a chunked segment needs a new segment kind and a manifest bump (now `log=9`; `log=8` is taken by `enable-segment-keys`) that older
sigils refuse, plus streaming reads in `read` / `restore` / `mount`. INDEX is ~170 bytes per entry; `append` re-reads it
in full (O(n) hashing, fine into the hundreds of thousands of segments). Measured, release build, a
500,001-entry INDEX (85 MB): `append` ~0.7 s, `read --seq` ~0.8 s, `ls` ~1.4 s; there is no INDEX
cache, by design (see INDEX-PRUNE-DESIGN.md, Option D status).

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
sigil log prove photos --path 2024/beach.jpg -o beach.proof   # by the path `log add` recorded
sigil log check-proof beach.proof --path 2024/beach.jpg --file beach.jpg --signer owner.pub
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
  `--signer`. That one log state is a prefix of a later one: see "Consistency proofs" below.
* **Any entry type.** Segments, compaction entries and tombstones (a deletion receipt) all prove.
  Tombstones and compaction never rewrite the INDEX, so a receipt cut before them keeps verifying
  against its anchor, and `prove --at M` regenerates it at any later time.
* **Which root.** Default: the HEAD the log vouches for (the same rule as gc: a signed log needs a
  HEAD signed by the pinned key, else `prove` refuses). `--at M` proves against the first `M` entries
  regardless of HEAD; it is signed only when `M` is the HEAD's seq. A damaged INDEX refuses (`log
  verify` first).
* **Additive.** Nothing is written to the log; no format change, no manifest bump.

**By path.** `log prove --path P` resolves P to the newest vouched entry `log add` recorded at P
(private logs need the key). It refuses an unknown path and a newest version that is deleted or
shredded (prove the tombstone with `--seq`, or an older version by its seq). `check-proof --path P`
refuses unless the proved entry's `path=` is P; in a private log the path is sealed, so the receipt
must carry `entry-key=`. Limit: the receipt proves *this entry, at this path, is in the log*; that
it is the **latest** version is the prover's word, not proved (that would need a non-membership proof).

## Consistency proofs (`sigil log prove-consistency` / `sigil log check-consistency`)

A receipt that the log state you pinned earlier (`OLD:ROOT`, printed by `log ls`) is a **prefix** of
a later state (`NEW:ROOT`): nothing before `OLD` was rewritten, removed or reordered, only entries
were appended. It is checked offline from the two roots alone: no INDEX, no segments, no keys.

```sh
sigil log prove-consistency events 3:<ROOT3> -o since3.proof     # OLD -> current HEAD (signed if the log is)
sigil log prove-consistency events 3:<ROOT3> 9 -o 3to9.proof     # OLD -> the first 9 entries
sigil log check-consistency since3.proof --old 3:<ROOT3> --signer owner.pub
sigil log check-consistency 3to9.proof --old 3:<ROOT3> --new 9:<ROOT9>
```

`prove-consistency` refuses when the log's root at `OLD` is not the pinned `ROOT` (the log is not an
extension of your anchor), when `OLD` is 0 or `OLD > NEW`, and on a damaged INDEX. `OLD` may be a
bare `SEQ` (then nothing is checked at cut time; the verifier's `--old` pin is what matters).

The proof (`sigil-log-consistency=1`, about 0.4 KB unsigned plus 65 bytes per tree level):

| Field | Meaning |
|-------|---------|
| `log`, `name` | log-id (bound by the HEAD signature), informational name |
| `old-size`, `old-root` | the earlier anchor |
| `new-size`, `new-root` | the later state |
| `leaf` | chain hash of entry `old-size` |
| `path` | that leaf's inclusion path in the tree over the first `new-size` entries |
| `head-chain`, `head-t`, `signer`, `sig`, `handover-N` | as in inclusion proofs, when `new-size` is the HEAD of a signed log |

**Why one path is enough (Sigil's tree, not RFC 6962).** `merkle.rs` builds layers left to right and
pairs an odd last node with itself. For a tree of `n` leaves, leaf `n-1` sits at index
`(n-1) >> k` on layer `k`, which is always the *last* node of that layer. So the old root is a
function of leaf `n-1` and the **left** siblings on its path only (a level without a left sibling
pairs the node with itself). Each left sibling is a complete, aligned subtree over leaves `< n-1`,
which is the same node in every larger tree. In the new tree of `m ≥ n` leaves the same leaf has the
same left siblings plus some **right** siblings (the appended growth). `check-consistency` therefore
rebuilds the old root from `leaf` + left siblings + self-pairing for size `n`, and the new root from
`leaf` + the whole path for size `m` (`merkle::roots_from_consistency`), and requires both to equal
`old-root` and `new-root`. Tree shapes are fixed by the two sizes, so with SHA-256 collision
resistance, matching both roots means the first `n` leaves under `new-root` are exactly the leaves
under `old-root`. RFC 6962 §2.1.2 instead splits at the largest power of two below `n` and uses
`0x00`/`0x01` domain prefixes; its `PROOF(m, D[n])` format does not apply to Sigil roots and RFC
6962 tooling cannot check these proofs (nor the reverse). Leaves are chain hashes, which already
commit to every earlier entry; the Merkle check is what makes the proof short.

What `check-consistency` verifies: `0 < old-size ≤ new-size` (a smaller new size is a size
regression: rollback); the path length matches both sizes; both rebuilt roots match; if signed,
the HEAD signature over `log`, `new-size`, `head-chain`, `new-root`, `head-t` and the handover chain
(as `check-proof`). Options: `--old SEQ:ROOT` / `--new SEQ:ROOT` (must be exactly those pins),
`--signer KEY` (new root signed by KEY or a key it handed over to). Exit 0 = verifies, 2 = it does not.

* **What it proves.** "The log whose first `new-size` entries have `new-root` starts with the log
  whose first `old-size` entries have `old-root`." With `--old` on your pinned anchor and either
  `--signer` or `--new` on a root you trust, a fork or a rewritten past is caught without the INDEX.
* **What it does not prove.** That `new-root` is "the" current log: an unsigned proof is only as
  strong as the `--new` root you compare it with (a forger can extend *their own* fork consistently).
  Nothing about the old side's signature (the old anchor is whatever you pinned). No gossip: two
  readers given different but each self-consistent heads only notice when they compare. Not
  wire-compatible with RFC 6962.
* **Additive.** Nothing is written to the log; no format change.

## Cards (`sigil log card` / `sigil log check-card`): roll-ups of logs and cards

A **card** is a small text file that commits, under its own Merkle root, to a list of children:
the vouched HEAD of a segment log (`SEQ:ROOT`, with that HEAD's Ed25519 signature when the log is
signed), and/or other cards. Cards of cards make roll-ups: daily logs → a monthly card → a yearly
card. Logs are not changed; a card is a separate file (format `sigil-log-card=1`).

```sh
sigil log card day-01 day-02 day-03 --name 2026-10 --identity me.sgk -o 2026-10.card
sigil log card 2026-10.card 2026-11.card --name 2026 --identity me.sgk -o 2026.card
sigil log check-card 2026.card --signer me.pub --child 2026-10.card --child 2026-11.card --all
sigil log check-card 2026-10.card --child day-01 --child day-02 --child day-03 --all
```

```text
sigil-log-card=1
name=2026-10
n=2
child-1=kind=log log=<id> size=31 root=<hex> chain=<hex> t=<unix> [signer=<hex> sig=<hex>]
child-2=kind=card name=2026-10-b size=4 root=<hex> [signer=<hex> sig=<hex>]
root=<hex>
signer=<hex>      (optional: --identity)
sig=<hex>
```

* **Root.** Leaf *i* = `SHA-256("sigil-card-child-v1\0" ‖ i ‖ "\0" ‖ child line)` (the line must be
  in canonical form); root = the same `merkle_root` as logs use. The position is in every leaf, so
  the odd-last-node padding cannot add a phantom child; `n=` must match the lines. The card
  signature covers `"sigil-card-v1\n" name, n, root`.
* **`card`** takes each log's HEAD **only if the log vouches for it** (the `gc` / `prove` rule: on a
  signed log a HEAD signed by the current key; a damaged INDEX refuses). A card file given as a child
  is fully checked first. One entry per log id / card name.
* **`check-card`** always checks the card on its own: canonical lines, `n`, the root, the card
  signature, and every child's embedded signature (the log's HEAD signature over its id, size,
  chain, root and time; a child card's signature). `--signer KEY`: the card must be signed by KEY.
  `--child LOG` (repeatable): the log must be a child (by log id) and the Merkle root of its first
  `size` entries must equal the card's root, so the log may have **grown** since (the card's state
  is a prefix), but not been rewritten or rolled back. `--child CARD`: the card file must be a child
  (by name) with exactly that root and child count. `--all`: every child must be given. Exit 0 = ok,
  2 = does not verify.
* **What it guarantees.** With `--signer` on a key you trust: "the holder of KEY committed, at card
  time, to exactly these log states / cards". With `--child`: "this log (or card) is the one the card
  committed to, and has only been appended to since". Checking a yearly card against its monthly
  cards and each monthly card against its logs checks the whole tree, level by level, with no
  operator's word involved. An **unsigned** card is a checksum: only as strong as the copy you
  compare it with (like an unsigned HEAD).
* **What cards do not do (yet).** A card does not **replace** INDEX history: logs keep every line,
  nothing is pruned, and retention stays explicit (`compact` / `shred`). `check-card --child LOG`
  reads that log's INDEX (chain hashes only; a private INDEX needs no key), so checking a log child
  needs the log; a card child needs only the card file. Child signers are reported, not pinned: pin
  them with `log verify --signer` on the log, or sign the card. Time (`t=`) is the writer's clock,
  not a timestamp authority.

### One-child receipts (`sigil log card-prove` / `sigil log check-card-child`)

```sh
sigil log card-prove 2026-10.card 2 -o day02.cardproof          # by number, log id or card name
sigil log check-card-child day02.cardproof --signer me.pub --expect <LOG-ID> --child day-02
```

A receipt (`sigil-card-proof=1`) holds the card's `name`, `n`, `root` and signature, the one child
line, its position `index` and the Merkle path (32 bytes per level). The other children are not in
it. `check-card-child` recomputes the leaf (position-bound, as in the card), walks the path to
`root`, checks the card signature over `name`, `n`, `root` and the child's own embedded signature.
Options: `--signer KEY` (the card must be signed by KEY), `--expect ID|NAME` (the proved child must
be that log / card), `--child LOG|CARD` (also check that log or card file against the child, exactly
as `check-card --child`). Altered child line, position, `n`, path or name, another signer, or a
different child given: exit 2. It proves "this card lists this child"; it does not prove anything
about the children it hides (not even how many are logs or cards; `n` is shown).

### Card consistency (`sigil log check-card-consistency OLD NEW`)

```sh
sigil log check-card-consistency 2026-10.v1.card 2026-10.v2.card --signer me.pub \
    --child day-01 --proof day02-since.proof --pair week1.v1.card week1.v2.card
```

Cards have no history tree of their own (a card is a flat signed list, not an append-only log), so
"consistent" is defined as **carries forward**, and every step must be proved:

1. Both cards verify on their own, have the same `name`, and NEW is signed by OLD's signer (both by
   `--signer KEY` when given). An unsigned OLD imposes no signer; a signed OLD refuses an unsigned or
   re-keyed NEW.
2. **Every** child of OLD is in NEW (by log id / card name; order does not matter). A dropped
   child fails. NEW may add children (listed as `+ … (new)`).
3. Each kept child is identical, or at a later state **proved** to extend the old one:
   * a log child: same size with a different root, or a smaller size, fails (fork / rollback).
     A larger size needs proof: the log itself (`--child LOG`: both pinned roots are prefixes of
     its INDEX), or a `log prove-consistency` file (`--proof FILE`, checked as `check-consistency`
     with both pins). Same size and root with a new HEAD time / signature counts as the same state;
   * a nested card that changed: both versions given with `--pair OLD NEW` (matched by name, root and
     size) and checked by these same rules, recursively (up to 16 levels).
   Anything not proved fails; nothing is taken on trust from NEW.

It does **not** show that NEW was made after OLD (times are writer clocks) or that no other card
with the same name exists (no gossip); it shows NEW is a faithful extension of OLD.

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
  it signed while it was the signer; it is not "revoked". A log created unsigned has no outgoing key
  to sign a handover; it gets its first key with `log add-signer` (next section) instead.

## Adding a signer later (`sigil log add-signer`)

A log created without `--identity` can be given its first signer at any time:

```sh
sigil log add-signer events --identity me.sgk     # any valid .sgk; the log must be unsigned
sigil log append events day9.json --identity me.sgk
sigil log verify events --signer me.pub
```

* **What it does.** The new key signs the HEAD that covers every entry already in the log (its
  statement "I vouch for this state"), then `CONTAINER` pins it (`signer=`), with
  `signer-added=<N>` recording how many entries were written before it. From then on the log is
  exactly a signed log: every writer needs this `--identity`, HEAD must carry its signature, and it
  can later be handed over with `rotate-signer`. No INDEX line and no new crypto (the same Ed25519
  HEAD signature `init --identity` logs use), so the manifest format is unchanged.
* **Verification.** `verify` notes `signer-added` (info). `verify --signer KEY`, `prove` and
  `check-proof --signer KEY` work as for any signed log. Receipts and anchors cut before the signer
  was added stay valid (unsigned receipts, `SEQ:ROOT` anchors).
* **Refused:** a log that already has a signer (use `rotate-signer`), an unreadable identity, a
  missing log, or a damaged INDEX / HEAD (the usual writer checks, under `LOG.lock`).
* **Crash order:** signed HEAD first (harmless while the log is still unsigned), then the manifest
  (the commit point). A crash in between leaves the log unsigned; run it again.
* **Honest limits.** Entries written before the signer was added were never signed when written: the
  signature only says the key holder vouched for them at add time. Anyone who can write the folder of
  an *unsigned* log can add their own key (as they could already rewrite the whole log), so a
  verifier must pin the key it trusts (`--signer`) or an anchor. Once signed, stripping the pin to
  make it look unsigned again is caught by `verify --signer` just like for a log signed at `init`.

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

* **Private INDEX (`log=5`).** Give the key that opens the index (`--pass` / `--pass-file` /
  `--talisman` / `--identity`, as for `log ls`); files keep their seq names, so the view adds no
  names beyond what `log ls` with the key shows. No key, or a key the index was not wrapped to:
  refused before anything is listed or exported.

See also [VAULT-MOUNT-NEST.md](VAULT-MOUNT-NEST.md) for FUSE vs `--export-dir` on vaults and packs.

## Prior work and how this log differs

Sources checked on 2026-10-16. Statements about other systems are limited to what those sources
say.

| Work | What it is | Same here | Different here |
|------|------------|-----------|----------------|
| **RFC 6962**, *Certificate Transparency* (Laurie, Langley, Kasper, June 2013), <https://www.rfc-editor.org/rfc/rfc6962> | Public append-only logs of TLS certificates: a Merkle Tree Hash over the entries, Signed Tree Heads, audit (inclusion) paths, consistency proofs between two tree heads, and monitors/auditors watching the logs | Merkle root over an append-only sequence (`HEAD` ≈ STH); offline inclusion proofs (`log prove` ≈ audit path); signed head binding size + root | **Tree shape and hashing.** RFC 6962 §2.1 hashes leaves as `SHA-256(0x00 ‖ d)` and nodes as `SHA-256(0x01 ‖ l ‖ r)`, and splits at the largest power of two below *n*. It notes that "this domain separation is required to give second preimage resistance". Sigil's `merkle.rs` hashes `SHA-256(l ‖ r)` with no prefix and pairs an odd last node with itself. Two things keep that sound here. Leaves are chain hashes, which are outputs of `SHA-256("sigil-log-entry-v1\0" ‖ …)`, and `check-proof` only accepts a leaf it recomputed from a full INDEX line. Every line also names its own `seq` (see "Inclusion proofs"). Sigil roots are therefore **not** RFC 6962 roots, and RFC 6962 tooling cannot verify them. **Consistency proofs** exist (`log prove-consistency`) but use Sigil's tree, not RFC 6962 §2.1.2 `PROOF(m, D[n])`, so they are not wire-compatible; no gossip/monitors: rollback or a split view are caught only by a pinned `--anchor` or a newer signed HEAD. **Single writer, private store** instead of a public multi-party log. Entries are sealed, erasure-coded batches, not certificates |
| **RFC 9162**, *Certificate Transparency Version 2.0* (Laurie, Messeri, Stradling, December 2021), <https://www.rfc-editor.org/rfc/rfc9162> | Obsoletes RFC 6962. Same Merkle-tree foundation, revised data structures and API | as above | as above. Sigil follows neither version's wire format |
| **Crosby & Wallach**, *Efficient Data Structures for Tamper-Evident Logging*, USENIX Security 2009, <https://www.usenix.org/conference/usenixsecurity09/technical-sessions/presentation/efficient-data-structures-tamper-evident> | The "history tree": a Merkle tree over a growing log with logarithmic membership and incremental (consistency) proofs between versions, for an untrusted logger and auditors. RFC 6962 says its tree is "essentially the same as the history tree [CrosbyWallach] proposal, except our definition handles non-full trees differently" | Append-only Merkle commitment; membership proofs | Sigil keeps a linear hash chain (each INDEX line commits to all earlier ones) **and** a Merkle root over the chain hashes (short inclusion proofs). Incremental (consistency) proofs: `log prove-consistency`, one Merkle path for Sigil's tree shape (see "Consistency proofs") |
| **Schneier & Kelsey**, *Secure Audit Logs to Support Computer Forensics*, ACM TISSEC 2(2), May 1999, <https://doi.org/10.1145/317087.317089> | Audit log on an untrusted machine, with hash chains and per-record encryption, making "all log entries generated prior to the logging machine's compromise impossible for the attacker to read, and also impossible to modify or destroy undetectably" (abstract) | Hash chain over every entry; per-entry encryption; keys can be destroyed to make entries unreadable (cf. `shred`) | No protection of past entries after a key compromise: whoever steals the signing key can re-sign the whole log (see "Threat model"). Sigil's `shred` is a deliberate, recorded erasure of one segment's key, not forward secrecy |

What is new here, as a combination rather than a primitive: every segment is an erasure-coded
`.sg1`, so the log heals bit rot in place (`mend`) without changing any hash the index commits
to (the chain covers plain bytes, not file bytes). Deletion, compaction, shredding and signer
handover are themselves appended, signed-over entries, so anchors and receipts taken earlier
stay valid. No new cryptography: SHA-256, Ed25519, AES-256-GCM and the existing Sigil
Reed–Solomon code.

## Deferred (later slices)

Done in slice 2: tombstones + compaction. Done in slice 3: per-segment keys + crypto-shredding
(above). Done: a monthly retention check (`scripts/monthly-log-retention.sh`); padded segments for private logs (`log=7`); sealed tombstone / shred reasons in private logs (`log=6`); `sigil mount` view of a log; `sigil log adopt` for loose piles of stars (also into a private INDEX, with its key); inclusion proofs
(`log prove` / `log check-proof`); re-hash skipping for `log add` (`--cache`); restore by path (`log restore`, older versions with `--at` / `--seq`); per-file receipts by path (`log prove --path` / `check-proof --path`); roll-up cards (`log card` / `log check-card`), one-child card receipts (`log card-prove` / `log check-card-child`) and card consistency (`log check-card-consistency`); re-wrapping keys to new recipients (`log rewrap`); consistency proofs (`log prove-consistency` / `log check-consistency`); adding a signer later (`log add-signer`); signer rotation (`log rotate-signer`); making an existing log private (`log privatize`, a copy, optionally padded with `--pad`); turning segment keys on for an existing log (`log enable-segment-keys`, `log=8`); erasing one batch of a compaction segment by rewriting only that file (`log shred --rewrite`). Still deferred:

* Card follow-ups: cards that **replace** old INDEX history (pruning).
* Streaming appends / segments above memory size (work-pack chunking): needs a new segment kind and `log=9` (see "Size notes"). Re-evaluated 2026-10-31: every reader (`read`, `verify`, `mend`, `compact`, `shred --rewrite`, `restore`, `mount`) holds a whole segment in memory and checks it against the INDEX in one piece, so a streaming *append* alone would write segments nothing can read without loading them; not shipped as an MVP.
* Encrypted folder packs (SGDR) hide member names since sealed directories (ver=2); older packs still show them until converted with `sigil seal-folder-names` (see PRIVATE-LABEL.md; old copies keep the names).
* INDEX roll-up / pruning of very old history (cards now give the commitment to roll up into; dropping old INDEX lines is still chain-breaking by nature and not done). Options and open questions: [INDEX-PRUNE-DESIGN.md](INDEX-PRUNE-DESIGN.md) (design note, decision pending).
* Unattended retention by default: the monthly script only applies with an explicit `--apply` and a rule (see "Monthly retention check").
* Shredding one batch inside a compaction segment **without rewriting that segment**: impossible
  with one AEAD tag per segment (see `shred --rewrite`, which rewrites only that file).

## Turning segment keys on later (`sigil log enable-segment-keys`, `log=8`)

```sh
sigil log enable-segment-keys events                      # public INDEX: no key needed to switch
sigil log enable-segment-keys photos --pass-file pw.txt   # private INDEX: its index key must open
sigil log append events batch.json --pass-file pw.txt     # from now on --pass-file and/or --to are required
```

It writes `segkeys=1`, `segkeys-from=N` (N = the next seq) and `log=8` into `CONTAINER` and creates
an empty `keys/` ring; nothing else changes. Running it again prints "already on". A literal
`--pass` is refused (use `--pass-file`); a private log refuses a passphrase or identity that does not
open its index key, before anything is written.

**What it protects, honestly:**

* Only segments written **after** it (append, add, compaction) get their own key and can be
  `shred`ded. Segments 1..N-1 keep their exact bytes: clear segments stay clear, passphrase /
  encrypt-to segments keep that protection. `shred` refuses them ("written before segment keys were
  turned on"); erase them with `log tombstone` + `log compact --apply`.
* `log compact --apply --seal-pass-file F` (or `--to`) re-seals merged old batches under fresh
  segment keys, which is the way to bring old data under the key ring. Old copies, backups and any
  ciphertext of the old segments elsewhere are untouched by any of this.
* In a public-INDEX log, sizes, SHA-256s and file names stay in the clear INDEX; segment keys hide
  only the contents. Use `log privatize` for the INDEX.
* A sigil that knows only `log=7` refuses the log ("upgrade sigil") instead of looking for keys of
  old segments that never had any.

## Private label (v3)

Encrypted segments are v3 marks. INDEX lines gain an additive `star=<hex>` field holding the star label digest (keyed fingerprint); verify/mend compare it keylessly. `size` and `sha` remain the plaintext values (receipts and compaction rely on them), so the INDEX still reveals them, unless the log was created with `--private-index` (see "Private INDEX"). Adopted v3 stars are label-only (`star` = `sha`) and are not merged by compaction.
