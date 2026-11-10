use ratchet_measure::decoders::{self, DeltaCache, Input, RatchetOpts};
use ratchet_measure::harness::{root_of, Rng};
use ratchet_measure::rs::{bw_column, Code, K, N};
use ratchet_measure::sidecar::{self, Check, Mode, Sidecar, Spec};
use sha2::{Digest, Sha256};

type Shards = Vec<Vec<u8>>;
type Fixture = (Code, Shards, Shards, [u8; 32], [u8; 32]);

fn setup(len: usize, seed: u64) -> Fixture {
    let code = Code::new().expect("tables");
    let mut rng = Rng::new(seed);
    let mut payload = vec![0u8; len * K];
    rng.fill(&mut payload);
    let data: Vec<Vec<u8>> = payload.chunks(len).map(|c| c.to_vec()).collect();
    let shards = code.encode(&data);
    let root = root_of(&shards);
    let name: [u8; 32] = Sha256::digest(&payload).into();
    (code, data, shards, root, name)
}

#[test]
fn encoder_matches_sigil_bytes() {
    let (_, _, shards, _, _) = setup(1000, 1);
    let mut payload = Vec::new();
    for s in shards.iter().take(K) {
        payload.extend_from_slice(s);
    }
    let theirs = sigil::rs_bench::encode_shards(&payload, K, N).expect("sigil encode");
    assert_eq!(
        theirs, shards,
        "harness RS must equal Sigil's Seal RS(16,8)"
    );
}

#[test]
fn bw_fixes_four_hidden_errors() {
    let (_, _, shards, _, _) = setup(64, 2);
    let pos: Vec<usize> = (0..N).collect();
    let mut ys: Vec<u8> = (0..N).map(|i| shards[i][5]).collect();
    for i in [0, 3, 9, 15] {
        ys[i] ^= 0x5a;
    }
    let cw = bw_column(&pos, &ys).expect("4 errors fit 2e <= 8");
    for i in 0..N {
        assert_eq!(cw[i], shards[i][5]);
    }
}

#[test]
fn sidecar_file_roundtrip_and_hostile_parse() {
    let (_, _, shards, root, name) = setup(4096, 3);
    for mode in [Mode::Independent, Mode::Chained] {
        let spec = Spec {
            cell: 64,
            check: Check::Crc32,
            mode,
        };
        let sc = Sidecar::build(spec, &shards, root, name).expect("build");
        let bytes = sc.to_bytes();
        let dir = std::env::temp_dir().join(format!("rm-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("x.sg1.stripes");
        std::fs::write(&path, &bytes).expect("write");
        let back = std::fs::read(&path).expect("read");
        let p = Sidecar::parse(&back, &root, &name).expect("parse");
        assert_eq!(p.entries, sc.entries);
        let _ = std::fs::remove_dir_all(&dir);
        // hostile inputs
        assert!(Sidecar::parse(&back[..back.len() - 1], &root, &name).is_err());
        assert!(Sidecar::parse(&back[..10], &root, &name).is_err());
        assert!(
            Sidecar::parse(&back, &[0u8; 32], &name).is_err(),
            "wrong binding refused"
        );
        let mut bad = back.clone();
        bad[0] ^= 1;
        assert!(Sidecar::parse(&bad, &root, &name).is_err());
        // one flipped bit in group 0 loses that group's entries only
        let mut rot = back.clone();
        rot[100] ^= 4;
        let r = Sidecar::parse(&rot, &root, &name).expect("parse rotted");
        assert!(r.entries[..sidecar::GROUP].iter().all(|e| e.is_none()));
        assert!(r.entries[sidecar::GROUP..].iter().all(|e| e.is_some()));
    }
}

#[test]
fn crc_delta_trick_is_exact() {
    let mut rng = Rng::new(4);
    let mut m = vec![0u8; 7 + 64];
    rng.fill(&mut m);
    let d = sidecar::crc_deltas(7, 64);
    for p in [0usize, 13, 511] {
        let mut f = m.clone();
        f[7 + p / 8] ^= 1 << (p % 8);
        assert_eq!(crc32fast::hash(&m) ^ d[p], crc32fast::hash(&f));
    }
}

fn run_all(
    code: &Code,
    rx: &[Option<Vec<u8>>],
    shards: &[Vec<u8>],
    sc: &Sidecar,
    opts: RatchetOpts,
) -> (Option<Shards>, Option<Shards>) {
    let crcs: Vec<u32> = shards.iter().map(|s| crc32fast::hash(s)).collect();
    let crc_ok: Vec<bool> = (0..N)
        .map(|i| {
            rx[i]
                .as_ref()
                .is_some_and(|s| crc32fast::hash(s) == crcs[i])
        })
        .collect();
    let inp = Input {
        code,
        rx,
        crc_ok: &crc_ok,
        shard_len: shards[0].len(),
        oracle: shards,
    };
    let mut dc = DeltaCache::default();
    (
        decoders::current(&inp).data,
        decoders::ratchet(&inp, Some(sc), opts, &mut dc).data,
    )
}

#[test]
fn ratchet_passes_fifty_percent_with_bit_guess() {
    // 8 of 16 pieces lost and one flipped bit in a surviving data piece:
    // RS alone has no redundancy left; the per-cell check plus a 1-bit search does.
    let (code, data, shards, root, name) = setup(4096, 5);
    let mut rx: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
    for r in rx.iter_mut().skip(8) {
        *r = None;
    }
    if let Some(s) = rx[2].as_mut() {
        s[1000] ^= 0x10;
    }
    let spec = Spec {
        cell: 64,
        check: Check::Crc32,
        mode: Mode::Independent,
    };
    let sc = Sidecar::build(spec, &shards, root, name).expect("build");
    let opts = RatchetOpts {
        iterate: true,
        bits: 1,
        chain_pure: false,
    };
    let (cur, rat) = run_all(&code, &rx, &shards, &sc, opts);
    assert_ne!(
        cur,
        Some(data.clone()),
        "today's repair cannot do this (the gate rejects whatever it proposes)"
    );
    assert_eq!(rat.expect("ratchet output"), data);
    let no_bits = RatchetOpts { bits: 0, ..opts };
    let (_, nb) = run_all(&code, &rx, &shards, &sc, no_bits);
    assert_ne!(nb, Some(data), "without guessing the cell cannot be fixed");
}

#[test]
fn ratchet_beats_unique_decoding_on_heavy_scatter() {
    // 6 wrong symbols in one column: past the 4-error unique budget.
    let (code, data, shards, root, name) = setup(4096, 6);
    let mut rx: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
    for i in [0usize, 2, 5, 7, 11, 13] {
        if let Some(s) = rx[i].as_mut() {
            s[777] ^= 0x81;
        }
    }
    // every other shard gets one flip elsewhere, so no shard passes its whole CRC
    for i in [1usize, 3, 4, 6, 8, 9, 10, 12, 14, 15] {
        if let Some(s) = rx[i].as_mut() {
            s[2000 + i * 100] ^= 0x01;
        }
    }
    let spec = Spec {
        cell: 64,
        check: Check::Crc32,
        mode: Mode::Independent,
    };
    let sc = Sidecar::build(spec, &shards, root, name).expect("build");
    let opts = RatchetOpts {
        iterate: true,
        bits: 0,
        chain_pure: false,
    };
    let (cur, rat) = run_all(&code, &rx, &shards, &sc, opts);
    assert_ne!(
        cur,
        Some(data.clone()),
        "unique decoding cannot fix 6 hidden errors"
    );
    assert_eq!(rat.expect("ratchet output"), data);
}

#[test]
fn pure_chain_blocks_after_unrecoverable_slice_hybrid_does_not() {
    // Shard 3, block 0 is garbage AND 9 shards have garbage in block 0 so block 0
    // is unrecoverable; later blocks of shard 3 carry one flipped bit that only a
    // verified check can fix (8 pieces lost elsewhere is not needed here: use
    // 8 lost pieces so RS has no slack).
    let (code, data, shards, root, name) = setup(256, 7);
    let mut rx: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
    for r in rx.iter_mut().skip(8) {
        *r = None;
    }
    if let Some(s) = rx[3].as_mut() {
        for b in s[..64].iter_mut() {
            *b ^= 0xff; // block 0 of shard 3: unrecoverable (no slack, 32 flips/byte-col)
        }
        s[64 + 5] ^= 0x01; // block 1: one bit
    }
    let spec = Spec {
        cell: 64,
        check: Check::Crc32,
        mode: Mode::Chained,
    };
    let sc = Sidecar::build(spec, &shards, root, name).expect("build");
    let pure = RatchetOpts {
        iterate: true,
        bits: 2,
        chain_pure: true,
    };
    let hybrid = RatchetOpts {
        chain_pure: false,
        ..pure
    };
    let (_, p) = run_all(&code, &rx, &shards, &sc, pure);
    let (_, h) = run_all(&code, &rx, &shards, &sc, hybrid);
    let p = p.expect("best effort output");
    let h = h.expect("best effort output");
    // block 1 of shard 3 (data row 3, bytes 64..128)
    assert_ne!(
        p[3][64..128],
        data[3][64..128],
        "pure chain cannot verify after the break"
    );
    assert_eq!(
        h[3][64..128],
        data[3][64..128],
        "hybrid resumes from the stored check"
    );
}
