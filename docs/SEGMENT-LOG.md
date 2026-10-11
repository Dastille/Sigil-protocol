# Segment log (`sigil log …`)

Status: **slice 1 shipped** (append, ls, read, verify, mend, gc / doctor support).
Approved 2026-10-06 as a general-purpose mode (not tied to any one application); built after
the tidy-container track. Tombstones + compaction, per-segment keys and nested cards are
**deferred** (see the end).

A segment log is an **append-only, tamper-evident sequence of sealed batches**. Each
`sigil log append` seals one blob of bytes — a day of events, a chunk of a journal, a
database change-set, a batch of sensor readings — as an **immutable segment star** (an ordinary
`.sg1`), and extends a hash-chained, Merkle-rooted index. Nothing is ever rewritten in place.

Strictly additive: the `.sg1` byte layout is unchanged, plain `.sg1` files keep opening forever,
and the container format stays `sigil-container=1` (a log is just `kind=log` plus a few extra
manifest keys). A sigil without log support does not recognise the kind (its `gc` / `doctor` refuse it as "not a vault or constellation"); upgrade rather than point older tools at a log.

## Layout

```text
events.sigil/                       one container per log
  CONTAINER                         sigil-container=1  kind=log  name=events
                                    log=1  log-id=<32 hex>  [signer=<64 hex Ed25519 key>]
  INDEX                             sigil-log-index=1, then one chained line per segment
  HEAD                              sigil-log-head=1: latest seq, chain, Merkle root [, signature]
  segments/0000/0000000001.sg1      segment 1 … 1000 per shard folder (seq / 1000)
  segments/0000/0000000002.sg1
  segments/0001/0000001000.sg1
```

* A **segment** is a normal star made by the normal seal path: ECC (Glyph / Reflection / Seal
  modes), `--pass`, `--to` (encrypt-to), compression — all unchanged. `sigil unseal`,
  `sigil mend`, `sigil verify` work on a segment by itself.
* **Sequence numbers** start at 1 and have no gaps.
* The **plain bytes of a segment are opaque** to sigil: the log does not parse, split or merge
  them. One append = one segment = whatever bytes you pipe in. `log read` returns them
  unchanged and concatenated in order, so framing inside a segment (lines, records, length
  prefixes) is the application's business.

### INDEX line

```text
seq=7 t=1760000000 size=4096 sha=<64 hex> chain=<64 hex>
```

| Field   | Meaning |
|---------|---------|
| `seq`   | 1-based, must equal the line's position |
| `t`     | unix seconds at append (informational; not trusted for ordering) |
| `size`  | plain length in bytes |
| `sha`   | SHA-256 of the **plain** bytes — the star's true-name, readable from its header without any key |
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
the same log reproduces that root from its first 7 entries.

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
sigil gc events [--apply]        # orphans of crashed appends only
sigil doctor events              # same checks as verify, plus the shared exit codes
```

`PATH` may be `events` or `events.sigil`. `append` accepts `-` for stdin.
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
older than `--temp-age` (default 3600 s), abandoned `*.part` / `LOG.lock`, emptied shard folders.
A segment with an INDEX entry is never a candidate, whatever its state. gc **refuses to run** if the
INDEX is damaged or HEAD claims more entries than INDEX holds (the "extra" segments may then be live).
`doctor` reports the same things plus bit rot / missing segments; `doctor --fix` runs `gc --apply` and
nothing else. Report-only by default, exactly like for vaults and constellations.

## Invariants

1. A segment, once appended, is never modified except by ECC repair that preserves its plain bytes.
2. `INDEX` is append-only; entry *n*'s chain hash commits to entries 1..*n* and to the log-id.
3. A segment is live iff it has an INDEX entry. Tools delete only non-live files, only when old
   enough, only after the INDEX is proven readable.
4. Absence of `kind=log` / `log=` means "not a segment log"; a log is invisible to older readers.
5. Plain `.sg1` stars, constellations and vaults are untouched by this feature.

## Threat model

| Adversary / event | Outcome |
|-------------------|---------|
| Random bit rot, torn writes in a segment | detected by `verify`, healed by `mend` (within the seal's ECC budget) |
| Edit / reorder / delete an entry in the middle of INDEX | chain break → `verify` and `read` refuse |
| Swap a segment for another valid star, or for an altered copy | header true-name ≠ INDEX `sha` → `segment-digest` (no key needed) |
| Cut entries off the end of INDEX only | HEAD ahead of INDEX → `head-truncated`; append and gc refuse |
| Rewrite INDEX **and** HEAD consistently, **unsigned** log | **not detectable** from the log alone — an unsigned HEAD is a checksum. Use `--anchor SEQ:ROOT` pins kept elsewhere, or sign |
| Same, **signed** log, attacker lacks the key | HEAD signature fails (`head-signature`) |
| Roll back to an older, validly signed INDEX+HEAD pair | **not detectable** without an external pin; `--anchor` (or any copy of a newer HEAD) catches it |
| Signer key stolen | attacker can extend or re-sign; out of scope (rotate by starting a new log; key rotation deferred) |
| Attacker with segment write access and the plain data | can replace a segment only by a star with the same true-name = same plain bytes |
| Confidentiality | per segment via `--pass` / `--to`; INDEX leaks sequence, time, sizes and plain true-names (hashes of the batches). Do not use it for low-entropy secrets you cannot afford to have confirmed by guessing. Hiding that metadata = deferred |
| Availability | ECC inside each segment; across segments sigil adds none — keep a second copy (`rsync`, atlas, cold kit) of the container |

Unauthorised concurrent writers are not a security feature: `LOG.lock` is advisory and local. One
writer at a time; do not put the container on a filesystem without atomic `rename` / `create_new`.

## Size notes (measured, slice 1)

Each segment carries a fixed overhead of about **3.2 KB** (header, keystone, Merkle) plus the
mode's redundancy: Reflection ≈ 1.34×, Seal ≈ 2×, Glyph ≈ 1.003× on incompressible data (text
compresses first). **Batch small events into larger appends** (KBs–MBs, not single lines).
A batch is sealed in memory in one piece in this slice; very large single batches should be split
(work-pack chunking for segments is deferred). INDEX is ~170 bytes per entry; `append` re-reads it
in full (O(n) hashing, fine into the hundreds of thousands of segments).

## Deferred (later slices)

* **Tombstones + compaction** governed by a retention rule: a tombstone is an additive INDEX entry
  (covered by the chain, so deletion is itself tamper-evident); compaction rewrites live segments
  into fewer larger ones in a new generation and drops the old files via the same
  write-INDEX-first, delete-after discipline as `constellation remove` / `gc`.
* **Per-segment keys / crypto-shredding**: each segment under its own key, wrapped for the log's
  recipients, so destroying a key makes that segment unreadable while the chain still verifies.
* **Nested hierarchical cards**: a card of cards (daily → monthly roll-ups) with their own Merkle roots.
* Adding or rotating a signer after `init`; signed *inclusion proofs* for a single entry.
* Streaming appends / segments above memory size (work-pack chunking); metadata-hiding INDEX.
* `sigil mount` view of a log (one file per segment) and `tidy` migration from ad-hoc segment folders.
