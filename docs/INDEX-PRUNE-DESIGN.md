# INDEX pruning: design options (decision pending)

**Status: design note only. Nothing here is implemented. No option is approved; the
"recommended default" below is a proposal pending Ashlynn's decision. Numbers are estimates from
the format, not measurements, unless marked otherwise.**

## Abstract

A Sigil segment log ([SEGMENT-LOG.md](SEGMENT-LOG.md)) keeps one `INDEX` line per entry forever:
segments, tombstones, compactions, shreds and signer handovers. Every line is chained to its
predecessor (`SHA-256("sigil-log-entry-v1\0" ‖ prev ‖ line)`, starting from a genesis hash bound
to the log id), and `HEAD` commits to the chain and to a Merkle root over all chain hashes.
Compaction and shredding erase *data*, never *lines*, which is what keeps every pinned
`SEQ:ROOT` anchor, inclusion proof and consistency proof valid. The cost is an INDEX that only
grows. This note states the problem precisely, lists four ways to bound it with what each breaks,
and asks the questions that must be answered before any code is written.

## 1. Problem

* **Size.** About 170 bytes per entry (more with `path=` from `log add`, more again with a
  private INDEX's sealed `box=`), plus one line per compaction / tombstone / shred. A log that
  appends once a minute reaches ~525,000 entries a year: on the order of 90–100 MB of INDEX
  (estimate).
* **Time.** `append`, `verify`, `ls`, `prove` re-read and re-hash the whole INDEX (O(n));
  SEGMENT-LOG.md "Size notes" calls this fine into the hundreds of thousands of entries.
* **Exposure.** In a public-INDEX log every old line keeps its size, SHA-256 and path in the clear
  long after `compact --apply` / `shred` erased the data. A private INDEX (`log=5`) seals those
  fields, but the line count, timestamps and op types remain.
* **What people ask for.** "Fold everything older than a year into a card and drop it."

## 2. Why this needs a decision, not just code

Removing or replacing lines touches every guarantee already shipped:

| Shipped feature | Depends on old lines how |
|---|---|
| Hash chain / `verify` | Line N+1's `chain=` covers line N's hash; `verify` walks from genesis. |
| Merkle root, `SEQ:ROOT` anchors | The root over the first N leaves needs every leaf, or a stored frontier (the left-subtree hashes, ~log2 N of them). |
| Inclusion proofs (`log prove`, `--at`) | Need the entry's line and its sibling path; `prove --at M` rebuilds old roots from all leaves. |
| Consistency proofs | Need the leaf at `old-size` and its path in the new tree. Proofs from an anchor inside a pruned range need pruned data. |
| Tombstones / compaction / shred lines | Name earlier seqs (`del=`, `members=`); compaction cuts batches by the *sizes in the old lines*. Live data inside a compaction segment depends on its members' lines. |
| `restore --at DATE` / `--seq`, `log add` versions | Walk old `path=` lines to find the version at a date. |
| Private INDEX, sealed reasons (`log=5`/`6`) | Old `box=` fields only open with the index key; a prune must not need, or leak, plaintext. |
| Signer rotation (`op=signer`) | `check-proof --signer` follows the handover chain from the first key; proofs carry `handover-N` lines. |
| Cards (`log card`) | A card already commits to a log's `SEQ:ROOT` (and its HEAD signature): the natural thing to fold history into. |

Any option that deletes lines in place is a **chain-breaking format change** for that log. That is
why this is deferred, not forgotten.

## 3. Options

### Option A — Epoch rollover (new log, old log archived) — *no format change*

Close the current log at HEAD `N:ROOT`, sign a card over it (`log card old --identity …`), start a
**new** log whose first entry records the predecessor (`op=epoch prev-log=<id> prev-size=N
prev-root=<ROOT> card=<sha256 of card>`), and copy only the still-live batches across (as
`log privatize` already copies a log into a new one). The old log directory becomes a read-only
archive; it may be moved offline or deleted later by the operator.

* **Gains:** a small INDEX from day one of the new epoch; old guarantees untouched (the old log is
  byte-identical, so every anchor, inclusion and consistency proof against it still verifies);
  dropping old *data* exposure is a separate, explicit choice (delete the archive).
* **Breaks / unreachable:** nothing in the old log. Across epochs there is no single Merkle root:
  "entry X is in the history" becomes a two-step proof (card → old log's root → entry). Seqs
  restart (or are offset, see Q3). `restore --at` before the epoch needs the archive.
* **Recovery:** keep the archive and the card → full history; lose the archive → the card still
  proves *that* the old log had root R at size N, but not its contents.
* **Private / sealed / segment keys:** the new log is created with the same flags and keys; old
  boxes are never opened except to copy live batches (needs the key, as `privatize`).
* **Cost to build:** smallest. Reuses card + privatize-style copy; one new entry kind in the *new*
  log (additive; likely a manifest bump only for the new log). The `epoch` line could even be
  avoided by making the card the only link (Q2).

### Option B — Checkpoint base + archived prefix — *format bump (`log=10`; 9 is reserved for streaming)*

Keep one log id. Write `INDEX.base` = `{size N, chain hash of N, Merkle frontier (≤ ~64 hashes),
signer-at-N, HEAD signature at N}` and move lines 1..N to `INDEX.archive` (or delete them).
New lines keep chaining from the stored chain hash; new roots are computed from the frontier, so
**anchors ≥ N and proofs about entries > N keep working unchanged**.

* **Gains:** INDEX file and per-operation cost bounded by entries since the last base; one log id,
  one root sequence, no seq renumbering.
* **Breaks / unreachable:** inclusion proofs for entries ≤ N, `prove --at M` with M < N, and
  consistency proofs from anchors < N (all need the archive, or become impossible if it is
  deleted). `verify` can only check the chain from the base, so a forged base is accepted unless
  it is signed and the reader has an anchor ≥ N or the signer key. `restore --at` before N, old
  versions in `log add`. A sigil that knows only `log≤9` must refuse the log.
* **Hard constraint:** cannot prune past any line that live data still depends on: a live
  segment, a compaction segment with a live member, a tombstone / shred target that still has a
  file, or the last signer handover. In practice "compact, then base at the oldest still-needed
  seq − 1".
* **Recovery:** with `INDEX.archive` kept, a `log unbase` could restore the full INDEX exactly
  (the archive's chain must end in the base's chain hash). Without it, history before N is
  reduced to the base's commitment.
* **Private / sealed:** the base carries only hashes, so it needs no key and leaks nothing new;
  the archive keeps its `box=` fields sealed.
* **Cost to build:** large: a new file, a frontier-based Merkle path in `merkle.rs`, every reader
  (verify, prove, consistency, gc, compact, restore, mount, card) taught the base, plus crash
  ordering for the move.

### Option C — Re-genesis in place (rewrite the INDEX) — *not recommended*

Rewrite the INDEX keeping only live lines and recompute the chain and root from a new genesis.

* **Gains:** smallest possible INDEX.
* **Breaks:** every anchor, inclusion proof, consistency proof and card that names this log, and
  the property that the log is append-only. Indistinguishable from an attack to anyone holding
  an old anchor. Listed only so the decision is explicit.

### Option D — Do nothing to the format; make big INDEXes cheaper — *no format change*

Keep every line; add an optional, rebuildable cache (e.g. a parsed-state + Merkle frontier sidecar
keyed by INDEX length and last chain hash, like `log add --cache`), and an "archive old lines to
a sealed side file" *copy* for exposure reasons only (the INDEX itself is unchanged).

* **Gains:** O(new lines) append/ls instead of O(n); nothing breaks.
* **Does not solve:** disk size or metadata exposure in a public INDEX (use `log privatize`).

**Status of Option D (2026-10-31): hot-path speedups shipped; no sidecar cache.** Measured on one
Linux box, release build, a synthetic 500,001-entry public INDEX (85 MB): hashing the whole INDEX
takes ~65 ms, while parsing it took ~725 ms, so the cost was parsing, not the hash chain. A sidecar
cache can only be trusted after re-hashing the whole INDEX (or by trusting file metadata, which is
not acceptable for an integrity tool) and would then have to deserialize every entry, which costs
about what an optimized parse costs. Shipped instead, with the format and every check unchanged:
a cheaper line parser (459 ms for the same INDEX), one segment-folder scan in `log ls` instead of a
`stat` per entry, and one INDEX parse instead of two in `log read --seq`. Before → after on that
log: `log read --seq` 2.0 s → 0.8 s, `log ls` 1.9 s → 1.4 s (most of the rest is printing 500k
rows), `log append` 0.87 s → 0.69 s. Pruning (A/B) is still pending the questions in section 7.

### Comparison

| | A epoch | B base | C re-genesis | D cache |
|---|---|---|---|---|
| Format change | new log only | yes (`log=10`) | yes, chain-breaking | none |
| Old anchors / proofs | all keep verifying | only ≥ N without archive | all broken | all keep |
| One root for all history | no (card links) | yes | yes (new) | yes |
| Bounded INDEX | yes | yes | yes | no (bounded *cost*) |
| Build size | small | large | medium | small |

## 4. Recommended default (proposal, pending Ashlynn's OK)

**Option A (epoch rollover), plus Option D's cache if INDEX parsing is measured to matter** (it was measured: see the Option D status; the speedups shipped, a cache did not pay).
Reasons: it removes nothing from any existing log, so no shipped guarantee changes; it reuses
cards (already the documented roll-up target) and the `privatize` copy path; and it can be
undone (keep the archive). Option B is the right answer only if "one root for all history" and
unchanged seq numbers are requirements; it should then be built after A, with A's tests as the
baseline. Option C should be rejected explicitly.

This recommendation is **unverified**: no prototype, no measurements of INDEX parse time at
10^6 entries have been taken for this note.

## 5. Threat model

Same attacker as SEGMENT-LOG.md "Threat model": can read and modify the log directory, cannot
forge Ed25519 signatures or find SHA-256 collisions, and the reader holds anchors / the signer
key out of band.

* **Rollback / forged history.** A: the epoch link and the card are signed; a reader with an old
  anchor checks it against the archive or the card. B: a forged `INDEX.base` with a fake frontier
  passes `verify` unless the base is signed by the pinned signer and/or the reader has an anchor
  ≥ N; unsigned logs with only anchors < N lose rollback detection for the pruned range. C: no
  detection possible; that is why it is rejected.
* **Deletion as concealment.** Any prune lets an owner hide that an entry ever existed from
  readers who did not pin an anchor before it. Cards and pinned anchors are the only defence;
  this is inherent, not fixable by format.
* **Metadata exposure.** Pruning reduces what a *future* copy shows; it does nothing about
  copies, backups or anchors already taken. A private INDEX is the stronger fix for exposure.
* **Crash safety.** B and A both need a write order (write new state, fsync, then switch) so a
  crash leaves either the old or the new state, never a log `verify` calls damaged.

## 6. Limitations and non-goals

* Not streaming / chunked segments (`log=9`, separate deferred item).
* Not shredding inside a segment in place (impossible with one AEAD tag per segment; see
  `log shred --rewrite`).
* Not a way to erase data: data erasure is `compact --apply` / `shred`; pruning is about INDEX
  lines.
* No gossip / monitoring is added: detection still depends on anchors the reader keeps.
* Interop with RFC 6962 tooling is not a goal (Sigil's tree and consistency proofs already differ;
  see SEGMENT-LOG.md "Consistency proofs").

## 7. Open questions for Ashlynn (answer before any code)

1. Which option (A, B, both, neither)? Is "one Merkle root for the whole history" a requirement?
2. Option A: should the new log carry an explicit `op=epoch` first line, or is a signed card the
   only link?
3. Seq numbers: restart at 1 per epoch, or continue (offset stored in the manifest)?
4. Is deleting the archive allowed by the tool (`--drop-archive`), or always left to the operator?
5. Trigger: manual only, or also from `scripts/monthly-log-retention.sh` (e.g. `--epoch-after 1y`)?
6. Unsigned logs: allow pruning at all, given the weaker rollback story (§5)?
7. Option B: is a frontier-based root acceptable as a new verification path, and must `log unbase`
   (exact restore from the archive) exist from day one?
8. `restore --at` / `log add` history before the cut: acceptable to require the archive?

## Prior work in this repo

* [SEGMENT-LOG.md](SEGMENT-LOG.md): "Tombstones and compaction" (data erased, lines kept),
  "Inclusion proofs", "Consistency proofs" (Sigil's tree, why one path suffices), "Cards"
  (signed roll-ups of `SEQ:ROOT`), "Private INDEX", "Signer rotation", `log privatize` (copying a
  log into a new one), "Size notes" (INDEX ~170 bytes/entry), "Threat model".
* RFC 6962 (Certificate Transparency): Merkle tree heads and consistency proofs; CT logs are
  never pruned in place either; operators shard by time into new logs (temporal sharding), which
  is the model Option A follows.
