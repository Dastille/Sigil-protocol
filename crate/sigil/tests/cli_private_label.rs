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
        .args(args)
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

/// Fail if any file under `root` carries an encoding of the plaintext's identity.
fn assert_no_leak(root: &Path, data: &[u8]) {
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
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            for e in std::fs::read_dir(&p).unwrap() {
                stack.push(e.unwrap().path());
            }
            continue;
        }
        let b = std::fs::read(&p).unwrap();
        for (what, n) in &probes {
            assert!(!has(&b, n), "{} leaks {what}", p.display());
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
        std::fs::create_dir_all(&out_dir).unwrap();
        let out = format!("out-{tag}/x.sg1");
        let mut a = vec!["seal", "-o", &out, NAME];
        a.extend(&extra);
        ok(sigil(&dir, &a));
        assert_no_leak(&out_dir, &data);
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
    std::fs::create_dir_all(dir.join("p")).unwrap();
    ok(sigil(
        &dir,
        &[
            "seal",
            "-o",
            "p/big.sg1",
            NAME,
            "--pass",
            "pw",
            "--chunk",
            "262144",
        ],
    ));
    assert_no_leak(&dir.join("p"), &data);
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
