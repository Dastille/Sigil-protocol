# Streaming segments for segment logs (`log=9`): design options (decision pending)

Status: **design note only.** Nothing here is implemented; there is no `log=9` code, no new
segment kind and no format change. The recommendation below is **unverified and pending
Ashlynn's OK**. See SEGMENT-LOG.md ("Size notes", "Deferred").

## 1. Problem

A segment is one `.sg1` star. Its header digest is the INDEX `star=` true name, and its body is
one AEAD message (AES-GCM, one tag over the whole compressed, possibly padded, body) plus
Reed–Solomon parity. Consequences today:

* `log append` seals a batch **in memory in one piece**: RAM ≈ batch size × (1 + redundancy).
* **Every reader loads a whole segment** and checks it against the INDEX in one piece:
  `read`, `restore`, `verify`, `mend`, `compact`, `shred --rewrite`, `gc`, `add`, `mount`.
* So segments above available memory cannot be written or read.

Honest point: **streaming append alone is not enough.** A writer that streams a huge segment
to disk produces something every current reader must still load whole (and an older sigil
cannot read at all if the layout changes). Any real fix has to cover the readers, mend and
compaction too, or it just moves the out-of-memory failure from `append` to `read`.

Workaround today: split large inputs into several appends (a batch per file or per N MiB), or
keep very large files outside the log as work packs (`sigil seal`, chunked 4 MiB stars, already
streamed) and append only a small manifest or receipt to the log.

## 2. Options

### A. Chunked segment = work pack inside the log (recommended direction)

A new segment kind whose star is an SGWK work pack: independent ~4 MiB chunk stars, each a
complete `.sg1` with its **own** AEAD tag and RS parity, plus the pack head and facet list
(already shipped for single files: PACK-HEAD-REPAIR.md, `index_pack`, `unseal_range`).

* No new crypto: each chunk is the existing seal; the chunk list (SGFC trailer) and the INDEX
  true name bind the chunks together. Order/truncation/swap of chunks is caught by the facet
  digests and the pack's chunk count, exactly as `de-scribe` checks a big file today.
* Readers can stream chunk by chunk (bounded RAM ≈ one chunk), and `mend` already repairs
  work packs one star at a time.
* Needs: a segment-kind marker, INDEX `star=` meaning "pack true name" (or a new key), and a
  manifest bump to `log=9` so older sigils refuse the log instead of misreading it.

### B. Chunked AEAD frames inside one star (STREAM / segmented AEAD)

One star, body split into frames, each framed AEAD with a counter nonce and a last-frame flag
(the STREAM construction, as in age / Tink streaming AEAD).

* Bounded RAM for reading and writing; one RS layer over the whole star still needs either the
  whole star in memory or a new interleaved RS layout.
* This is a **new on-disk crypto construction** for Sigil (nonce derivation, final-frame flag,
  key commitment). Not to be invented here: it would need an existing, reviewed scheme adopted as
  is, plus test vectors. Larger review burden than A for little gain over A.

### C. External streaming seal, log stores a reference

Large payloads are sealed outside the log (`sigil seal` work pack, already streaming); the log
appends a small segment holding the pack's true name, size and path hint.

* No format change at all; works today by convention.
* The log no longer guarantees the bytes are present: `log verify` checks only the reference,
  shred / retention / compaction do not reach the external pack, and `restore` needs the file.

### D. Defer

Keep "batch size ≤ memory" as a documented limit. Cheapest; honest; blocks nothing else.

## 3. Threat model

Same as the log today: an attacker may read, reorder, truncate, replace or corrupt files on the
storage; they do not hold the log's keys. Requirements for any streaming form:

* **No silent truncation or reordering:** a reader must detect a missing last chunk, a swapped
  chunk from the same or another segment, and a chunk replayed from an older version. (A: facet
  list + chunk count + INDEX true name; B: final-frame flag + counter nonces.)
* **Fail closed on partial reads:** streamed output is written to a part file and renamed only
  after every chunk checks out (same rule as `de-scribe` / `log restore`).
* **No new metadata leak:** chunk count reveals size to ~4 MiB granularity unless padded.

## 4. Interaction with existing features

| Feature | A (work-pack segment) | B (framed AEAD) | C (external) |
|---|---|---|---|
| `pad=padme` (`log=7`) | pad the final chunk / total; chunk count still leaks coarse size | pad the last frame | not covered |
| segment keys (`segkeys`, shred) | one key per segment wraps all chunks; shred unchanged | same | external pack has its own key; log shred does not erase it |
| private INDEX (`log=5`) | sealed `box=` keeps size/name/hash; pack head must not show a name (`total_hidden`) | same | the reference itself must be sealed |
| `mend` | per chunk (exists for work packs) | needs new RS layout | separate `sigil mend` |
| `verify` / `--read-data` | per chunk, streaming | per frame | reference only |
| `compact` | must stream-copy chunks; never merge huge segments in RAM | same | n/a |
| `shred --rewrite` | rewrite one chunked segment streaming; or forbid on chunked segments at first | same | n/a |
| `mount` / `read --range` | random access by chunk (exists: `unseal_range`) | by frame | via the external pack |
| cards / proofs | unchanged (INDEX lines, true names) | unchanged | unchanged |

## 5. Recommended default (unverified, pending Ashlynn's OK)

**D now, A when needed.** Keep the documented limit and the work-pack workaround (C by hand)
until a real user needs segments above memory size. If that happens, implement **A** in this
order: readers first (`read` / `restore` / `verify` / `mend` stream chunked segments), then
`append` writing them behind `log=9`, then `compact` / `shred --rewrite` (or refuse them on
chunked segments at first). Do not pursue B: it is new crypto layout for no gain over A.

## 6. Open questions for Ashlynn

1. Is there a real workload with single batches above memory (size, machine)? If not, D.
2. Is C (external pack + reference segment) acceptable as the documented pattern meanwhile?
3. For A: may `compact` / `shred --rewrite` refuse chunked segments in the first slice?
4. Chunk size: keep 4 MiB (matches work packs) or make it a log setting?
5. Should a chunked segment be allowed in a log without segment keys / private INDEX, or only
   in new logs created with `--chunked`?

## 7. Limitations of this note

* No prototype and no measurements: RAM and speed figures for A are expectations from the
  existing work-pack code, not measured on logs.
* Interactions with cards, consistency proofs and `adopt` were checked only on paper.
