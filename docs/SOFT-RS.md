# Soft-decision RS for Sigil (research note #2)

## Problem
CRC-kill whole shards → pure erasures. Bit-rot in a live shard fails late (Merkle/true-name),
or a chewed CRC trailer discards an otherwise intact body.

## v0 (this crate)
- Keep GF(256) Vandermonde RS; Seal (8,16) / Reflection (12,16)
- Graded gather: CRC pass → Hard; present but CRC fail → Soft; else Missing
- Stripe size 4096 B within shard payload (`rs::SOFT_STRIPE`)
- Soft symbols fill gaps when Hard < k; GMD-lite flips ≤ (n−k) lowest-reliability
  soft shards (then soft stripes) to erasure and retries
- Accept only if Merkle of re-encoded shards matches the header; when not Warded,
  plaintext SHA-256 (true-name) must match too
- Opt-in: `sigil mend --soft torn.sg1 -o healed.sg1` (hard path first, soft fallback);
  since November 2026 plain `sigil mend` does the same by default (`--hard-only` to skip)
- Glyph unchanged (all-or-nothing; `--soft` does not relax it)
- Non-goals: Keystone/Ember byte change; replace RaptorQ; Ward substitute

## v1: column repair (October 2026, decoder only)
- `sigil mend --soft` now first decodes every **byte column** on its own
  (`rs::decode_column_errors`): byte j of each shard is one Reed–Solomon codeword
  (evaluations at x = index + 1 of a degree < k polynomial), so a flipped bit is one
  wrong symbol in one column, not a lost shard.
- Clean columns are found with one matrix pass (predict the other shards from the first k
  and compare). Each dirty column is decoded with Berlekamp–Welch; it is corrected only if
  at most (present − k) / 2 symbols disagree. Missing shards count as erasures
  (2·errors + erasures ≤ n − k per column). Any column past that budget fails the call.
- Accepted only through the same gate: Merkle binding of the re-encoded shards, plus the
  true name when not encrypted. Then the old GMD-lite path runs as before.
- No byte layout change. Old Sigils benefit as-is. Plain `unseal` is unchanged (plain `mend`
  uses this path by default since November 2026).
- Measured numbers and limits: `docs/research/DEEP-SPACE.md`.
- Also fixed while measuring: when every front header copy is gone and bit rot leaves no
  CRC-good shard, the body offset is chosen by where surviving Embers sit (tie-break after
  CRC count), and a header rebuilt from an Ember no longer keeps that Ember's slot number
  in the entropy word.

## v2: easy-first column repair (November 2026, decoder only)
`sigil mend --soft` used to try candidate after candidate (every soft-shard pair × every
4 KiB stripe) and re-encode, re-hash and Merkle-check the **whole file for each one**. On a
10 MB star with heavy damage that ran for 16+ minutes on one machine and 40+ minutes on a second, slower machine (shared
with other trials), then failed anyway. It now works column by column, easiest first, and
locks in each settled column (`crate/sigil/src/soft_ratchet.rs`):

1. **Clean columns**: one matrix pass; a column where every present byte agrees is locked.
2. **Wiped / garbage shards**: a sample of dirty columns shows which soft shards are wrong
   almost everywhere; those are treated as missing (erasures), so they do not use up every
   column's error budget.
3. **Berlekamp–Welch** (errors-and-erasures) on each dirty column; CRC-good shards are
   trusted and never changed.
4. **Erasure guesses** for still-stuck columns, fewest erasures first and most suspicious
   shards first. A guess locks only when **two** spare bytes confirm it and no other guess
   of the same size gives a different answer.
5. **Per-shard CRC ratchet**: a soft shard whose stored CRC-32 now matches is right
   everywhere, so it becomes trusted; repeat 4 with fewer unknowns.
6. **CRC match for the last few columns** (up to 64): CRC-32 is linear, so each candidate
   fix's effect on every shard's CRC is one table lookup; a meet-in-the-middle search keyed
   on three reliable shards picks the combination that makes the stored CRCs match. It must
   win clearly (2+ more matching shards than any other) and explain every shard except wiped
   ones and at most one rotten trailer.
7. Anything left gets a best guess (most reliable `k` bytes).

Then the result is checked **once** (re-encode all shards, Merkle root, and the true name
when not encrypted). Only if that fails are the old shard-order GMD-lite candidates tried
(at most 2(n−k)+1 more checks; the old stripe×pair search is gone). Steps 3–4 run on up to
8 CPU threads (std only; no GPU), and so do those fallback candidates (step 3 of the R1 list). Same acceptance gate as before: a wrong guess can only make
the repair fail, never return wrong bytes. No byte layout change.

Measured (box, release build; harness `mend_soft_timing` in `crate/sigil/src/mend_soft_tests.rs`,
numbers in the PR): Reflection 12/16, 10 MB, 2 wiped shards + BER 1e-3 (the R1 hang class):
old 963 s then refused, new under 1 s (0.6–0.8 s) then refused (10 full checks). Where the old search
finished with a result, the new path returns the same bytes (test
`mend_soft_matches_old_path_on_damage_corpus`).

R1 slices, in this order:

1. **Done (17 November 2026): easy repair by default.** Plain `sigil mend` tries the fast
   hard repair first, then falls back to soft repair on its own (same code path as `--soft`,
   so the same acceptance gate: Merkle root of the re-encoded shards, plus the true name when
   not encrypted). It says in plain words when the deeper repair was used. `--soft` keeps
   working; `--hard-only` skips the fallback. If `-o` is omitted the output goes next to the
   input as `<stem>.mended.<ext>` (`-2`, `-3`, … when taken; `crate/sigil/src/mend_out.rs`);
   it is never the input and never an existing file (a name that appears during the repair
   is not replaced either). When nothing passes the check, mend writes nothing, exits 2 and
   prints full copyable next commands (`--hard-only` dropped; another copy pooled). The
   `doctor` and `scry` hints print the full `sigil mend <file>` command. Folder packs, atlas
   bags and work packs get the same fallback; several copies at once stay hard-only.
   Also: an encrypted private-label (v3) Sigil whose key wrap (SGTO) is damaged is now
   refused by mend instead of being "repaired" into a copy that could never be opened.
   Since 17 November 2026 new encrypted seals keep a second copy of the key wrap at the end
   (SGTO v3 + `SGTS` spare, docs/KEYWRAP-SPARE.md), so mend rebuilds them exactly; only
   files whose two copies are both unreadable (or older one-copy files) are refused.
   Tests: `crate/sigil/tests/cli_mend_default.rs`.
2. Wait screen (Wednesday–Thursday 18–19 November 2026; one roadmap item, estimated at two
   weekday slices — that size is a guess). After a short scan, the tool will estimate how long
   the repair will take. Short repairs will just run. Long repairs will ask first, then show
   progress and a way to Stop. The time cut-offs come from the 11 November 2026 wait-UX notes.
   First half done 18 November 2026: `mend --scan` (look only), the damage kind (clean,
   truncated, one region, scattered, mixed) and repair path (quick, deeper, deeper-hard,
   not enough), a padded time estimate, plain `mend` telling the scan from 10 s, and
   `--max-secs` for unattended jobs (exit 4, nothing written). See docs/MEND-SCAN.md.
   Second half done 19 November 2026: progress line on a terminal (after 5 s), ask before
   repairs over ~2 minutes (terminal only; `--yes` skips), unattended skip over 15 minutes
   (exit 4), and Ctrl-C stop that writes nothing (exit 130). Still to do: live re-estimates,
   asking after the quick part instead of before, and a "finish later" option.
3. **Done (22 November 2026): racing regions across threads, with a way to cancel**
   (`crate/sigil/src/race.rs`, std threads only, no GPU, no format change).
   - Column work (Berlekamp–Welch and erasure guesses) is no longer split into 8 fixed
     chunks: up to 8 workers take small blocks of columns from a shared counter, so a slow
     region does not leave the other threads idle. Results go back in column order.
   - The fallback candidates (decode + whole-file check each, up to 2(n−k)+1) used to run
     one after another. They now race across threads. As soon as one passes, no later
     candidate is started and running later ones drop out before their check. Every
     earlier candidate still finishes, so the winner is the same one a single thread
     would pick. Workers hold about one decoded copy each, capped at 1 GiB in total.
   - One shared flag stops every worker at its next column or candidate on Ctrl-C (or a
     crashed worker), and a stopped race is an error: nothing is written (exit 130 as before).
   - Same bytes whatever the thread count: tests `mend_soft_same_bytes_any_thread_count`
     (1, 2, 8 threads on 300 KB stars) and `mend_soft_matches_old_path_on_damage_corpus`
     (now also 1 and 3 threads per case). The single final check is unchanged, so a wrong
     guess can still only fail, never return wrong bytes.
   - Measured (box, 8 cores, release, `mend_soft_timing`, one run each, before = the main
     build of 20 November 2026, after = 8 threads; receipts `sigil-1122-race-baseline-b3cdb92.txt` and
     `sigil-1122-race-after.txt` in the run's receipts folder). 10 MB: Reflection 2 lost +
     BER 1e-5 repaired 1.012 s → 0.599 s; Seal 4 lost + BER 1e-5 repaired 0.955 s → 0.629 s;
     refusals (beyond repair) 0.687 → 0.503 s, 0.371 → 0.142 s, 1.032 → 0.514 s. 1 MiB:
     0.037–0.142 s → 0.026–0.091 s. On 1 thread the 10 MB repairs take 2.5–2.8 s (the
     time a single-core machine would see). Damage corpus: 36 of 60 repaired before
     and after (old search 18 of 60): threads make it faster, not stronger.
   - Still to do from slice 2: live re-estimates, asking after the quick part, "finish later".
3f. **Measured, parked (22–23 November 2026): routing by damage kind.** No gain on the
   current corpus, so `mend` keeps today's order and the code was not merged (the patch
   is kept outside the repo, as `sigil-1123-route-parked-code.patch`).
   Plan approved 20 November: the scan's damage kind picks the repair (truncated or one wiped region → quick RS; scattered flips →
   easy-first column repair; mixed → race the two cheapest; unsure → today's order).
   - What the code already does: quick RS from CRC-good shards runs first and is skipped
     at once when fewer than k shards are whole. So for truncated, one-region and
     scattered damage the "routed" order **is** today's order. The only real change is
     mixed damage, where the branch races the column repair against the shard-order
     fallback, each on half the threads (column repair wins a tie, so bytes and refusals
     are the same as today on 1 or 8 threads; test `mend_route_same_answer_as_fixed_order`).
   - Measured (box, 8 cores, release, median of 20 runs, `mend_route_timing`, receipt
     `sigil-1122-route-measure.txt`). Corpus: 36 of 60 repaired either way. Mixed (36
     cases) 426 ms → 528 ms in total (**24% slower**); scattered (24 cases) 318 → 318 ms
     (no change). 1 MiB: mixed 50–64% slower (repairs 0.055 → 0.082 s, refusals 0.045 →
     0.074 s and 0.074 → 0.103 s); scattered, one-region and truncated unchanged (within
     ±7%, noise; 0.016–0.035 s).
   - Second try (23 November): column repair keeps all threads and the fallback races on
     one extra thread. Closer but still never faster: corpus mixed 497 → 511 ms (+2.8%),
     scattered 386 → 385 ms; 1 MiB mixed repairs +9% and +21%, refusals −2% to +4%;
     still 36 of 60 (receipt `sigil-1123-route-variantA.txt`; the test machine was busier than on
     the 22nd, so compare within a run only).
   - Why it loses: the column repair alone wins every repair in the corpus (the fallback
     won 0 of 720 runs), so a raced fallback can only cost: it shares the CPU and runs
     whole-file checks the column repair then makes pointless (10 instead of 1 on the R1
     repro; tests `mend_soft_old_search_rehashes_per_candidate_new_checks_once` and
     `mend_soft_new_path_encrypted_stuck_columns_and_wrong_key` fail on both variants).
     Truncated and one-region damage already go straight to quick RS today, so there is
     nothing to route there.
   - Decision: keep today's order. The scan stays a time-estimate and wording hint. A
     race is worth trying again only if a second method starts winning real cases (for
     example joint solving, step 5), and then as "try the cheap one first, start the
     other after a short head start", not a split from the start.
4. Then: a GPU option, with a CPU path that must still work.
5. Then: joint solving for more than 64 stuck columns. Heavy scattered damage past the
   per-column Reed–Solomon limit will still need the stripe sidecar (PR #101).

## Damage-adaptive preview
- Missing clean: hard RS erasure
- Present dirty: soft RS/GMD (`--soft`)
- Rateless rain: RaptorQ

## Citations
- Koetter & Vardy, IEEE TIT 2003
- Forney GMD
- Xia et al., HACFS, USENIX FAST 2015
