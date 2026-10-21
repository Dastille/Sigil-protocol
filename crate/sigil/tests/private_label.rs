//! v3 private label for new encrypted seals: what it hides, that it fails closed,
//! and that old files keep opening. See `src/privacy.rs` and docs/sigil-v1.txt.

use sigil::{
    locate_header, mend_bytes, seal_kn_to, seal_kn_to_opts, unseal_ex_keys, unseal_meta_keys,
    verify, FingerprintKey, Identity, Mode, SealOpts, DEFAULT_PIECE, HEADER_SIZE,
};
use std::path::{Path, PathBuf};

const NAME: &str = "quarterly-secret-plan.pdf";
/// A distinctive length so its encodings are unlikely to occur by chance.
const LEN: usize = 123_457;

fn plain() -> Vec<u8> {
    // Some structure (compressible) plus noise, so deflate does real work.
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..LEN)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if i % 3 == 0 {
                b'a' + (i % 26) as u8
            } else {
                x as u8
            }
        })
        .collect()
}

fn seal_pass(data: &[u8], mode: Mode) -> Vec<u8> {
    seal_kn_to(
        data,
        mode,
        Some("pw"),
        NAME,
        false,
        "",
        &[],
        None,
        DEFAULT_PIECE,
        &[],
    )
    .unwrap()
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-private-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Every encoding of the plaintext's identity a stranger could grep for.
fn leaks(bytes: &[u8], data: &[u8], name: &str) -> Vec<String> {
    let sha = sigil::sha256(data);
    let len = data.len() as u64;
    let mut out = Vec::new();
    let probes: Vec<(&str, Vec<u8>)> = vec![
        ("sha256 raw", sha.to_vec()),
        ("sha256 hex", sigil::hex32(&sha).into_bytes()),
        ("sha256 first 8", sha[..8].to_vec()),
        ("name", name.as_bytes().to_vec()),
        (
            "name first 16",
            name.as_bytes()[..16.min(name.len())].to_vec(),
        ),
        ("len u64 le", len.to_le_bytes().to_vec()),
        ("len u32 le", (len as u32).to_le_bytes().to_vec()),
        ("len decimal", format!("{len}").into_bytes()),
    ];
    for (what, p) in probes {
        if contains(bytes, &p) {
            out.push(what.to_string());
        }
    }
    out
}

/// Rewrite one field of the label everywhere (primary, Keystone copies, every Ember)
/// with valid CRCs, as an attacker who understands the format would.
fn rewrite_label(file: &mut [u8], f: impl Fn(&mut [u8])) {
    let mut at: Vec<usize> = (0..4).map(|i| i * HEADER_SIZE).collect();
    let mut i = 0;
    while i + HEADER_SIZE <= file.len() {
        if &file[i..i + 4] == b"SGEM" {
            at.push(i);
            i += HEADER_SIZE;
        } else {
            i += 1;
        }
    }
    for o in at {
        let h = &mut file[o..o + HEADER_SIZE];
        f(h);
        h[108..112].fill(0);
        let crc = crc32(h);
        h[108..112].copy_from_slice(&crc.to_le_bytes());
    }
}

fn crc32(b: &[u8]) -> u32 {
    // Same CRC-32 (IEEE) the format uses.
    let mut c = 0xffff_ffffu32;
    for &x in b {
        c ^= x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

#[test]
fn round_trip_every_encrypted_mode_and_key_kind() {
    let data = plain();
    let alice = Identity::generate().unwrap();
    for mode in [Mode::Glyph, Mode::Reflection, Mode::Seal] {
        for (pass, to) in [
            (Some("pw"), vec![]),
            (None, vec![alice.public()]),
            (Some("pw"), vec![alice.public()]),
        ] {
            let s = seal_kn_to(
                &data,
                mode,
                pass,
                NAME,
                false,
                "",
                &[],
                None,
                DEFAULT_PIECE,
                &to,
            )
            .unwrap();
            let (h, _, _) = locate_header(&s).unwrap();
            assert_eq!(h.version, 3, "new encrypted seals use the private label");
            assert!(h.private_label() && h.encrypted());
            assert_eq!((h.orig_len, h.entropy_milli, h.name.as_str()), (0, 0, ""));
            assert_ne!(h.digest, sigil::sha256(&data));
            let ids = if to.is_empty() {
                vec![]
            } else {
                vec![alice.clone()]
            };
            let open_pass = if ids.is_empty() { pass } else { None };
            let (got, meta) = unseal_meta_keys(&s, open_pass, &[], &ids).unwrap();
            assert_eq!(got, data, "{mode:?}");
            let m = meta.unwrap();
            assert_eq!((m.name.as_str(), m.orig_len), (NAME, LEN as u64));
            assert_eq!(m.digest, sigil::sha256(&data));
            if pass.is_some() {
                assert_eq!(unseal_ex_keys(&s, Some("pw"), &[], &[]).unwrap(), data);
            }
            assert!(
                leaks(&s, &data, NAME).is_empty(),
                "{mode:?}: {:?}",
                leaks(&s, &data, NAME)
            );
        }
    }
}

#[test]
fn plain_seals_keep_the_v2_label() {
    let data = plain();
    let s = seal_kn_to(
        &data,
        Mode::Reflection,
        None,
        NAME,
        false,
        "",
        &[],
        None,
        DEFAULT_PIECE,
        &[],
    )
    .unwrap();
    let (h, _, _) = locate_header(&s).unwrap();
    assert_eq!(
        (h.version, h.orig_len, h.name.as_str()),
        (2, LEN as u64, &NAME[..16])
    );
    assert_eq!(h.digest, sigil::sha256(&data));
}

#[test]
fn empty_and_tiny_payloads_round_trip() {
    for data in [vec![], vec![7u8], b"hi".to_vec()] {
        let s = seal_pass(&data, Mode::Reflection);
        assert_eq!(unseal_ex_keys(&s, Some("pw"), &[], &[]).unwrap(), data);
    }
}

#[test]
fn wrong_key_fails_closed() {
    let data = plain();
    let s = seal_pass(&data, Mode::Reflection);
    assert!(unseal_ex_keys(&s, Some("nope"), &[], &[]).is_err());
    assert!(unseal_ex_keys(&s, None, &[], &[]).is_err());
    let eve = Identity::generate().unwrap();
    assert!(unseal_ex_keys(&s, None, &[], &[eve]).is_err());
}

#[test]
fn every_label_field_is_authenticated() {
    let data = plain();
    let s = seal_pass(&data, Mode::Reflection);
    // (what, edit) pairs: each consistent rewrite of the whole label must fail to open.
    type Edit = (&'static str, Box<dyn Fn(&mut [u8])>);
    let edits: Vec<Edit> = vec![
        (
            "flags: drop deflate/graph bits",
            Box::new(|h| h[5] ^= 1 << 4),
        ),
        ("orig_len", Box::new(|h| h[8] ^= 1)),
        ("keyed fingerprint", Box::new(|h| h[30] ^= 0x40)),
        ("salt", Box::new(|h| h[60] ^= 1)),
        ("nonce", Box::new(|h| h[75] ^= 1)),
        ("tag", Box::new(|h| h[90] ^= 1)),
        ("entropy", Box::new(|h| h[104] ^= 1)),
        ("name", Box::new(|h| h[112] = b'x')),
        ("merkle", Box::new(|h| h[140] ^= 1)),
    ];
    for (what, e) in edits {
        let mut t = s.clone();
        rewrite_label(&mut t, |h| e(h));
        assert!(
            unseal_ex_keys(&t, Some("pw"), &[], &[]).is_err(),
            "editing {what} must fail closed"
        );
    }
    // Downgrade to the v2 label (no AAD, outer fields trusted) must not open either.
    let mut t = s.clone();
    rewrite_label(&mut t, |h| h[4] = 2);
    assert!(
        unseal_ex_keys(&t, Some("pw"), &[], &[]).is_err(),
        "version downgrade"
    );
}

#[test]
fn swapped_labels_and_fields_fail_closed() {
    let data = plain();
    let a = seal_pass(&data, Mode::Reflection);
    let b = seal_pass(b"some other file entirely", Mode::Reflection);
    // Swap salt and nonce between two seals made with the same passphrase.
    for (lo, hi) in [(56usize, 72usize), (72, 84), (24, 56)] {
        let field = a[lo..hi].to_vec();
        let mut t = b.clone();
        rewrite_label(&mut t, |h| h[lo..hi].copy_from_slice(&field));
        assert!(
            unseal_ex_keys(&t, Some("pw"), &[], &[]).is_err(),
            "swapped {lo}..{hi}"
        );
    }
    // A whole label from another seal on this body.
    let label = a[..HEADER_SIZE].to_vec();
    let mut t = b.clone();
    rewrite_label(&mut t, |h| h.copy_from_slice(&label));
    assert!(unseal_ex_keys(&t, Some("pw"), &[], &[]).is_err());
}

#[test]
fn crc_consistent_bit_flips_in_parts_fail_closed() {
    let data = plain();
    let s = seal_pass(&data, Mode::Reflection);
    let (h, prefix, _) = locate_header(&s).unwrap();
    let stride = HEADER_SIZE + h.shard_len as usize + 4;
    for shard in [0usize, 1, h.n as usize - 1] {
        let mut t = s.clone();
        let off = prefix + shard * stride + HEADER_SIZE;
        t[off + 5] ^= 0x10;
        let body = &t[off..off + h.shard_len as usize];
        let crc = crc32(body).to_le_bytes();
        t[off + h.shard_len as usize..off + h.shard_len as usize + 4].copy_from_slice(&crc);
        if let Ok(p) = unseal_ex_keys(&t, Some("pw"), &[], &[]) {
            assert_eq!(p, data, "never different bytes");
        }
    }
    // Plain CRC-detected flips are repaired.
    let mut t = s.clone();
    t[prefix + HEADER_SIZE + 3] ^= 1;
    assert_eq!(unseal_ex_keys(&t, Some("pw"), &[], &[]).unwrap(), data);
}

#[test]
fn truncation_never_returns_different_bytes() {
    let data = plain();
    let s = seal_pass(&data, Mode::Reflection);
    for cut in (0..s.len()).step_by(s.len() / 97 + 1) {
        if let Ok(p) = unseal_ex_keys(&s[..cut], Some("pw"), &[], &[]) {
            assert_eq!(p, data, "cut at {cut}");
        }
    }
    assert!(unseal_ex_keys(&s[..s.len() / 2], Some("pw"), &[], &[]).is_err());
}

#[test]
fn mend_repairs_new_encrypted_seals_without_the_key() {
    let data = plain();
    for mode in [Mode::Reflection, Mode::Seal] {
        let s = seal_pass(&data, mode);
        let (h, prefix, _) = locate_header(&s).unwrap();
        let stride = HEADER_SIZE + h.shard_len as usize + 4;
        let mut torn = s.clone();
        // Smash the primary header and two whole parts.
        torn[..HEADER_SIZE].fill(0);
        for k in [1usize, 3] {
            let o = prefix + k * stride;
            torn[o..o + stride].fill(0xAA);
        }
        let (_, closed, _, _, _) = verify(&torn).unwrap();
        assert!(!closed, "damage visible keylessly");
        let healed = mend_bytes(&torn).unwrap(); // no key
        let (hh, closed, live, _, _) = verify(&healed).unwrap();
        assert!(closed && live == hh.n as usize, "{mode:?} healed clean");
        assert_eq!(healed, s, "mend restores the exact seal");
        assert_eq!(unseal_ex_keys(&healed, Some("pw"), &[], &[]).unwrap(), data);
    }
}

#[test]
fn keyed_fingerprint_is_per_file_by_default_and_shared_only_on_request() {
    let data = plain();
    let a = seal_pass(&data, Mode::Reflection);
    let b = seal_pass(&data, Mode::Reflection);
    let fp = |s: &[u8]| locate_header(s).unwrap().0.digest;
    assert_ne!(fp(&a), fp(&b), "same file twice: unlinkable by default");
    let secret = [42u8; 32];
    let opts = SealOpts {
        fingerprint: FingerprintKey::Shared(secret),
        ..Default::default()
    };
    let shared = |pass: &str| {
        seal_kn_to_opts(
            &data,
            Mode::Reflection,
            Some(pass),
            NAME,
            false,
            "",
            &[],
            None,
            DEFAULT_PIECE,
            &[],
            &opts,
        )
        .unwrap()
    };
    let (c, d) = (shared("pw"), shared("other"));
    assert_eq!(
        fp(&c),
        fp(&d),
        "shared dedupe key: equal files match across seals"
    );
    assert_eq!(
        fp(&c),
        sigil::privacy::shared_fingerprint(&secret, &data).unwrap()
    );
    assert_ne!(fp(&c), sigil::sha256(&data));
    assert_eq!(unseal_ex_keys(&c, Some("pw"), &[], &[]).unwrap(), data);
    // The key holder can check a live file against the seal without opening the body.
    assert!(sigil::keyed_fingerprint_matches(&a, Some("pw"), &[], &data).unwrap());
    assert!(!sigil::keyed_fingerprint_matches(&a, Some("pw"), &[], b"changed").unwrap());
    assert!(sigil::keyed_fingerprint_matches(&a, Some("bad"), &[], &data).is_err());
}

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/enc-v2");

fn fix(name: &str) -> PathBuf {
    Path::new(FIX).join(name)
}

#[test]
fn files_written_before_the_private_label_still_open() {
    let want = std::fs::read(fix("plain.txt")).unwrap();
    let id = Identity::load(&fix("id.sgk")).unwrap();
    for (f, pass, ids) in [
        ("pass-v2.sg1", Some("fixture-pass"), vec![]),
        ("to-v2.sg1", None, vec![id.clone()]),
        ("plain-v2.sg1", None, vec![]),
    ] {
        let s = std::fs::read(fix(f)).unwrap();
        let (h, _, _) = locate_header(&s).unwrap();
        assert_eq!(h.version, 2, "{f} is a v2 fixture");
        assert_eq!(h.digest, sigil::sha256(&want), "{f}: v2 label as before");
        let (got, meta) = unseal_meta_keys(&s, pass, &[], &ids).unwrap();
        assert_eq!(got, want, "{f}");
        assert!(meta.is_none(), "{f}: no inner block");
        // and they still mend keylessly
        assert_eq!(mend_bytes(&s).unwrap(), s);
    }
    // large-file pack written by the old writer (plain head, plaintext facets)
    let d = tmp("fix-pack");
    let out = d.join("big.out");
    sigil::unseal_path_keys(&fix("pack-to-v2.sg1"), &out, None, &[], &[id]).unwrap();
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(fix("big.bin")).unwrap()
    );
    // folder pack written by the old writer
    let dest = d.join("dir");
    sigil::unseal_dir(&fix("folder-pass-v2.sg1"), &dest, Some("fixture-pass"), &[]).unwrap();
    for rel in ["a.txt", "sub/b.bin"] {
        assert_eq!(
            std::fs::read(dest.join(rel)).unwrap(),
            std::fs::read(fix("dir").join(rel)).unwrap(),
            "{rel}"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn large_file_packs_hide_name_total_and_chunk_hashes() {
    let d = tmp("pack");
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let data: Vec<u8> = (0..3_000_017usize)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    let input = d.join(NAME);
    std::fs::write(&input, &data).unwrap();
    let alice = Identity::generate().unwrap();
    for cdc in [None, Some(sigil::CDC_DEDUP)] {
        let pack = d.join("p.sg1");
        let (_, stars, is_pack) = sigil::inscribe_path_to(
            &input,
            &pack,
            Mode::Reflection,
            None,
            "",
            &[],
            512 * 1024,
            None,
            DEFAULT_PIECE,
            sigil::DEFAULT_OVERTURE_MB,
            cdc,
            &[alice.public()],
        )
        .unwrap();
        assert!(is_pack && stars > 1);
        let bytes = std::fs::read(&pack).unwrap();
        assert!(
            leaks(&bytes, &data, NAME).is_empty(),
            "{:?}",
            leaks(&bytes, &data, NAME)
        );
        // no chunk's plaintext SHA-256 either (facet list, star labels, guards)
        let (_, locs) = sigil::index_pack(&pack).unwrap();
        let mut off = 0usize;
        let facets = sigil::read_facet_digests(&pack).unwrap();
        for (i, l) in locs.iter().enumerate() {
            let star = &bytes[l.file_off as usize..(l.file_off + l.star_len) as usize];
            let chunk = unseal_ex_keys(star, None, &[], std::slice::from_ref(&alice)).unwrap();
            let sha = sigil::sha256(&chunk);
            assert!(!contains(&bytes, &sha), "chunk {i} SHA-256 visible");
            assert_ne!(facets[i], sha);
            off += chunk.len();
        }
        assert_eq!(off, data.len());
        assert!(sigil::scry_path(&pack).unwrap().contains("name=(locked)"));
        let out = d.join("out.bin");
        sigil::unseal_path_keys(&pack, &out, None, &[], std::slice::from_ref(&alice)).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data);
        assert_eq!(
            sigil::payload_label_keys(&pack, None, &[], std::slice::from_ref(&alice)).unwrap(),
            Some((NAME.to_string(), data.len() as u64))
        );
        // exact offsets with the key (show / ranges)
        let (head, locs) =
            sigil::index_pack_keys(&pack, None, &[], std::slice::from_ref(&alice)).unwrap();
        assert_eq!(head.orig_total, data.len() as u64);
        let (_, plain_locs) = sigil::index_pack(&pack).unwrap();
        for (a, b) in locs.iter().zip(&plain_locs) {
            assert_eq!(
                (a.file_off, a.star_len),
                (b.file_off, b.star_len),
                "same star tiling"
            );
        }
        let last = locs.last().unwrap();
        assert_eq!(last.orig_off + last.orig_len as u64, data.len() as u64);
        // keyless mend of a torn chunk star
        let mut torn = bytes.clone();
        let l = &locs[1];
        let star = &bytes[l.file_off as usize..(l.file_off + l.star_len) as usize];
        let (sh, sp, _) = locate_header(star).unwrap();
        let mid = l.file_off as usize + sp + HEADER_SIZE + 2;
        assert!(
            torn[mid..mid + 16].iter().any(|&b| b != 0),
            "shard {} {}",
            sh.k,
            sh.n
        );
        torn[mid..mid + 16].fill(0);
        std::fs::write(&pack, &torn).unwrap();
        let rep = sigil::mend_pack_path(&pack, &pack, false).unwrap();
        assert_eq!(rep.mended, vec![1]);
        sigil::unseal_path_keys(&pack, &out, None, &[], std::slice::from_ref(&alice)).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data);
        // swapping two chunk stars is refused
        let b = std::fs::read(&pack).unwrap();
        let (_, locs) = sigil::index_pack(&pack).unwrap();
        if locs[0].star_len == locs[1].star_len {
            let (a0, a1) = (
                locs[0].file_off as usize,
                (locs[0].file_off + locs[0].star_len) as usize,
            );
            let (b0, b1) = (
                locs[1].file_off as usize,
                (locs[1].file_off + locs[1].star_len) as usize,
            );
            let mut sw = b.clone();
            let s0 = b[a0..a1].to_vec();
            let s1 = b[b0..b1].to_vec();
            sw[a0..a1].copy_from_slice(&s1);
            sw[b0..b1].copy_from_slice(&s0);
            std::fs::write(&pack, &sw).unwrap();
            assert!(
                sigil::unseal_path_keys(&pack, &out, None, &[], std::slice::from_ref(&alice))
                    .is_err()
            );
        }
    }
    let _ = std::fs::remove_dir_all(&d);
}
