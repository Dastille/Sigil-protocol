//! CLI end to end for the v3 private label: what lands on disk for new encrypted
//! seals, packs, constellation stars and log segments holds no plaintext SHA-256,
//! no file name and no exact-length encoding; keyless mend and doctor still work.
mod common;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const NAME: &str = "board-minutes-private.txt";

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn ok(o: Output) -> String {
    assert!(
        o.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
}

fn setup(tag: &str, len: usize) -> (common::Scratch, Vec<u8>) {
    let dir = common::scratch(&format!("cli-priv-{tag}"));
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let data: Vec<u8> = (0..len)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if i % 4 == 0 {
                b'x'
            } else {
                (x >> 24) as u8
            }
        })
        .collect();
    std::fs::write(dir.join(NAME), &data).unwrap();
    ok(sigil(&dir, &["keygen", "-o", "me.sgk"]));
    (dir, data)
}

fn has(hay: &[u8], n: &[u8]) -> bool {
    hay.windows(n.len()).any(|w| w == n)
}

/// Probes shorter than this are matched by chance in random bytes often enough to
/// matter: a 4-byte probe turns up in a 1.5 MB pack of ciphertext about once in 2,800
/// runs (expected 2^-32 per byte offset), which made this suite fail now and then.
const CHANCE_SAFE_PROBE: usize = 8;

/// All files under `root`, read whole (test outputs are small).
fn files_under(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    walk(root)
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
}

/// Fail if the outputs under `first` and `second` (the same input sealed twice, each
/// with fresh salts, nonces and keys) carry an encoding of the plaintext's identity.
///
/// Probes of 8 bytes or more must not appear in either output at all (chance of a
/// random match: below 2^-40 per run). A shorter probe (the 4-byte length) is a leak
/// only when it appears in *both* outputs: a field that encodes the length is written
/// on every seal, while a chance match in ciphertext would have to happen twice in
/// independent outputs (about 1 in 10^7 runs for the largest pack here).
fn assert_no_leak(first: &Path, second: &Path, data: &[u8]) {
    let sha = sigil::sha256(data);
    let len = data.len() as u64;
    let probes: Vec<(&str, Vec<u8>)> = vec![
        ("sha256", sha.to_vec()),
        ("sha256 hex", sigil::hex32(&sha).into_bytes()),
        ("name", NAME.as_bytes().to_vec()),
        ("name prefix", NAME.as_bytes()[..16].to_vec()),
        ("len u64", len.to_le_bytes().to_vec()),
        ("len u32", (len as u32).to_le_bytes().to_vec()),
    ];
    let (a, b) = (files_under(first), files_under(second));
    assert!(!a.is_empty() && !b.is_empty(), "nothing to check");
    for (what, n) in &probes {
        let in_a: Vec<&PathBuf> = a.iter().filter(|(_, x)| has(x, n)).map(|f| &f.0).collect();
        let in_b: Vec<&PathBuf> = b.iter().filter(|(_, x)| has(x, n)).map(|f| &f.0).collect();
        if n.len() >= CHANCE_SAFE_PROBE {
            assert!(
                in_a.is_empty() && in_b.is_empty(),
                "{in_a:?} {in_b:?} leak {what}"
            );
        } else {
            assert!(
                in_a.is_empty() || in_b.is_empty(),
                "{in_a:?} and {in_b:?} both carry {what}: a field encodes it"
            );
            if !(in_a.is_empty() && in_b.is_empty()) {
                eprintln!("note: {what} matched by chance in one output only: {in_a:?} {in_b:?}");
            }
        }
    }
}

#[test]
fn seal_pass_and_to_hide_identity_and_mend_keylessly() {
    let (dir, data) = setup("single", 123_457);
    for (tag, extra) in [
        ("pass", vec!["--pass", "pw"]),
        ("to", vec!["--to", "me.sgk.pub"]),
        ("both", vec!["--pass", "pw", "--to", "me.sgk.pub"]),
        ("seal-mode", vec!["--pass", "pw", "--mode", "seal"]),
        ("glyph", vec!["--pass", "pw", "--mode", "glyph"]),
    ] {
        let out_dir = dir.join(format!("out-{tag}"));
        let again_dir = dir.join(format!("again-{tag}"));
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::create_dir_all(&again_dir).unwrap();
        let out = format!("out-{tag}/x.sg1");
        let again = format!("again-{tag}/x.sg1");
        for o in [&out, &again] {
            let mut a = vec!["seal", "-o", o.as_str(), NAME];
            a.extend(&extra);
            ok(sigil(&dir, &a));
        }
        assert_no_leak(&out_dir, &again_dir, &data);
        let scry = ok(sigil(&dir, &["scry", &out]));
        assert!(
            !scry.contains(NAME) && !scry.contains("123457"),
            "{tag}: {scry}"
        );
        assert!(scry.contains("label=private"), "{tag}: {scry}");
        // tear the front and mend with no key (Glyph has no parity; skip)
        if tag != "glyph" {
            let mut b = std::fs::read(dir.join(&out)).unwrap();
            b[..160].fill(0);
            let mid = b.len() / 2;
            b[mid..mid + 32].fill(0xFF);
            std::fs::write(dir.join(&out), &b).unwrap();
            ok(sigil(&dir, &["mend", "-o", &out, &out]));
        }
        let back = format!("out-{tag}.back");
        let key: Vec<&str> = if tag == "to" {
            vec!["--identity", "me.sgk"]
        } else {
            vec!["--pass", "pw"]
        };
        let mut u = vec!["unseal", "-o", &back, &out];
        u.extend(&key);
        ok(sigil(&dir, &u));
        assert_eq!(std::fs::read(dir.join(&back)).unwrap(), data, "{tag}");
        // wrong key refuses and writes nothing
        let bad = format!("out-{tag}.bad");
        let o = sigil(&dir, &["unseal", "-o", &bad, &out, "--pass", "wrong"]);
        assert!(!o.status.success() && !dir.join(&bad).exists(), "{tag}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn big_file_pack_hides_name_size_and_chunk_hashes() {
    let (dir, data) = setup("pack", 1_300_017);
    for sub in ["p", "p2"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
        let out = format!("{sub}/big.sg1");
        ok(sigil(
            &dir,
            &[
                "seal", "-o", &out, NAME, "--pass", "pw", "--chunk", "262144",
            ],
        ));
    }
    assert_no_leak(&dir.join("p"), &dir.join("p2"), &data);
    for i in 0..(data.len() / 262_144 + 1) {
        let c = &data[i * 262_144..((i + 1) * 262_144).min(data.len())];
        let b = std::fs::read(dir.join("p/big.sg1")).unwrap();
        assert!(!has(&b, &sigil::sha256(c)), "chunk {i} sha visible");
    }
    let b = std::fs::read(dir.join("p/big.sg1")).unwrap();
    assert_eq!(&b[..4], b"SGWK", "a work pack");
    let scry = ok(sigil(&dir, &["scry", "p/big.sg1"]));
    assert!(!scry.contains(NAME), "{scry}");
    ok(sigil(
        &dir,
        &["unseal", "-o", "big.back", "p/big.sg1", "--pass", "pw"],
    ));
    assert_eq!(std::fs::read(dir.join("big.back")).unwrap(), data);
    // slice by star still works with the key
    ok(sigil(
        &dir,
        &[
            "unseal",
            "-o",
            "s1",
            "p/big.sg1",
            "--pass",
            "pw",
            "--star",
            "1",
        ],
    ));
    assert_eq!(
        std::fs::read(dir.join("s1")).unwrap(),
        &data[262_144..524_288]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn constellation_and_log_stars_are_private() {
    let (dir, data) = setup("sky", 54_321);
    ok(sigil(
        &dir,
        &["constellation", "add", "sky", NAME, "--to", "me.sgk.pub"],
    ));
    // stars are named by a ciphertext id, not by the plaintext hash
    let stars: Vec<_> = walk(&dir.join("sky"));
    assert!(!stars.iter().any(|p| p
        .to_string_lossy()
        .contains(&sigil::hex32(&sigil::sha256(&data))[..12])));
    for s in stars
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "sg1"))
    {
        let b = std::fs::read(s).unwrap();
        assert!(!has(&b, &sigil::sha256(&data)), "{}", s.display());
        assert!(!has(&b, NAME.as_bytes()), "{}", s.display());
    }
    // adding the same file again does not mint a second star
    let before = walk(&dir.join("sky")).len();
    ok(sigil(
        &dir,
        &[
            "constellation",
            "add",
            "sky",
            NAME,
            "--to",
            "me.sgk.pub",
            "--identity",
            "me.sgk",
        ],
    ));
    assert_eq!(walk(&dir.join("sky")).len(), before);

    ok(sigil(&dir, &["log", "init", "lg"]));
    ok(sigil(&dir, &["log", "append", "lg", NAME, "--pass", "pw"]));
    let o = ok(sigil(&dir, &["log", "verify", "lg"]));
    assert!(!o.contains("problem"), "{o}");
    ok(sigil(
        &dir,
        &["log", "read", "lg", "-o", "lg.back", "--pass", "pw"],
    ));
    assert_eq!(std::fs::read(dir.join("lg.back")).unwrap(), data);
    for s in walk(&dir.join("lg.sigil"))
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "sg1"))
    {
        let b = std::fs::read(s).unwrap();
        assert!(
            !has(&b, &sigil::sha256(&data)) && !has(&b, NAME.as_bytes()),
            "{}",
            s.display()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut st = vec![root.to_path_buf()];
    while let Some(p) = st.pop() {
        if p.is_dir() {
            for e in std::fs::read_dir(&p).unwrap() {
                st.push(e.unwrap().path());
            }
        } else {
            out.push(p);
        }
    }
    out
}

/// Noise of `n` bytes with `plant` written at `at` (the checker's own tests).
fn planted(n: usize, at: usize, plant: &[u8]) -> Vec<u8> {
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut v: Vec<u8> = (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    v[at..at + plant.len()].copy_from_slice(plant);
    v
}

/// Two output folders holding `a` and `b`, for the checker's own tests.
fn two_outputs(tag: &str, a: &[u8], b: &[u8]) -> (common::Scratch, PathBuf, PathBuf) {
    let dir = common::scratch(&format!("cli-priv-check-{tag}"));
    let (pa, pb) = (dir.join("a"), dir.join("b"));
    std::fs::create_dir_all(&pa).unwrap();
    std::fs::create_dir_all(&pb).unwrap();
    std::fs::write(pa.join("x.sg1"), a).unwrap();
    std::fs::write(pb.join("x.sg1"), b).unwrap();
    (dir, pa, pb)
}

const CHECK_LEN: usize = 1_300_017;

/// The length written in both outputs (as a field would be) is still caught.
#[test]
#[should_panic(expected = "a field encodes it")]
fn checker_catches_a_length_written_on_every_seal() {
    let l = (CHECK_LEN as u32).to_le_bytes();
    let (_d, a, b) = two_outputs("both", &planted(4096, 100, &l), &planted(4096, 900, &l));
    assert_no_leak(&a, &b, &vec![b'x'; CHECK_LEN]);
}

/// A 4-byte match in one output only (what the old check failed on now and then) passes.
#[test]
fn checker_ignores_a_chance_match_in_one_output() {
    let l = (CHECK_LEN as u32).to_le_bytes();
    let (_d, a, b) = two_outputs("one", &planted(4096, 100, &l), &planted(4096, 0, b"zz"));
    assert_no_leak(&a, &b, &vec![b'x'; CHECK_LEN]);
}

/// A long probe (the name) in a single output is a leak.
#[test]
#[should_panic(expected = "leak name")]
fn checker_catches_a_long_probe_in_one_output() {
    let (_d, a, b) = two_outputs(
        "name",
        &planted(4096, 7, NAME.as_bytes()),
        &planted(4096, 0, b"zz"),
    );
    assert_no_leak(&a, &b, &vec![b'x'; CHECK_LEN]);
}
