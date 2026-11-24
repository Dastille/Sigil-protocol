//! Library API: an empty passphrase (`Some("")`) is refused on the way out too, not
//! only by the CLI. It never quietly means "no passphrase"; old files keep opening.

mod common;

use sigil::{
    keyed_fingerprint_matches, seal, seal_kn_to, seal_meta_keys, unseal, unseal_ex_keys,
    unseal_meta_keys, unseal_repair_keys, Identity, Mode, DEFAULT_PIECE,
};
use std::path::{Path, PathBuf};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/enc-v2");

fn fix(name: &str) -> PathBuf {
    Path::new(FIX).join(name)
}

fn refused<T>(r: sigil::Result<T>, what: &str) {
    match r {
        Ok(_) => panic!("{what}: empty passphrase was accepted"),
        Err(e) => assert!(
            e.to_string().contains("empty passphrase"),
            "{what}: wrong error: {e}"
        ),
    }
}

#[test]
fn unseal_refuses_empty_passphrase_on_every_kind_of_seal() {
    let data = b"empty passphrase must not open anything".repeat(20);
    let plain = seal(&data, Mode::Seal, None, "p.txt", false).unwrap();
    let pw = seal(&data, Mode::Seal, Some("pw"), "e.txt", false).unwrap();
    let id = Identity::generate().unwrap();
    let to = seal_kn_to(
        &data,
        Mode::Seal,
        None,
        "t.txt",
        false,
        "",
        &[],
        None,
        DEFAULT_PIECE,
        &[id.public()],
    )
    .unwrap();
    for (f, name) in [(&plain, "plain"), (&pw, "passphrase"), (&to, "encrypt-to")] {
        refused(unseal(f, Some("")), name);
        refused(unseal_meta_keys(f, Some(""), &[], &[]), name);
        refused(unseal_repair_keys(f, Some(""), &[], &[]), name);
        refused(seal_meta_keys(f, Some(""), &[]), name);
    }
    // Even with a key that would open it: the empty passphrase is a caller bug, not "none".
    refused(
        unseal_ex_keys(&to, Some(""), &[], std::slice::from_ref(&id)),
        "to+id",
    );
    refused(
        keyed_fingerprint_matches(&pw, Some(""), &[], &data),
        "fingerprint",
    );
    // A bit flip does not turn the refusal into something else.
    let mut flipped = pw.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0x01;
    refused(unseal(&flipped, Some("")), "flipped");
    // Truncated: still refused (or fails closed), never opens.
    assert!(unseal(&pw[..pw.len() / 2], Some("")).is_err());

    // Round trips still work with the real key or none.
    assert_eq!(unseal(&plain, None).unwrap(), data);
    assert_eq!(unseal(&pw, Some("pw")).unwrap(), data);
    assert!(unseal(&pw, Some("wrong")).is_err());
    assert!(unseal(&pw, None).is_err());
    assert_eq!(unseal_ex_keys(&to, None, &[], &[id]).unwrap(), data);
}

#[test]
fn folder_and_large_file_packs_refuse_empty_passphrase() {
    let d = common::scratch("emptypass-packs");
    let src = d.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("sub/b.txt"), b"beta").unwrap();
    let plain_dir = d.join("plain.sg1");
    let pw_dir = d.join("pw.sg1");
    sigil::inscribe_dir(&src, &plain_dir, Mode::Seal, None, "", &[], 0, &[]).unwrap();
    sigil::inscribe_dir(&src, &pw_dir, Mode::Seal, Some("pw"), "", &[], 0, &[]).unwrap();
    for (p, name) in [(&plain_dir, "plain folder"), (&pw_dir, "locked folder")] {
        let out = d.join(format!("out-{}", name.replace(' ', "-")));
        refused(sigil::unseal_dir(p, &out, Some(""), &[]), name);
        assert!(!out.join("a.txt").exists(), "{name}: wrote a member");
    }
    let ok = d.join("ok");
    sigil::unseal_dir(&pw_dir, &ok, Some("pw"), &[]).unwrap();
    assert_eq!(std::fs::read(ok.join("sub/b.txt")).unwrap(), b"beta");

    let big = d.join("big.bin");
    std::fs::write(&big, vec![7u8; 300_000]).unwrap();
    let pack = d.join("big.sg1");
    sigil::inscribe_path(
        &big,
        &pack,
        Mode::Seal,
        Some("pw"),
        "",
        &[],
        65_536,
        None,
        DEFAULT_PIECE,
        0,
        None,
    )
    .unwrap();
    let out = d.join("big.out");
    refused(
        sigil::unseal_path(&pack, &out, Some(""), &[]),
        "large-file pack",
    );
    assert!(!out.exists(), "large-file pack: wrote output");
    sigil::unseal_path(&pack, &out, Some("pw"), &[]).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), vec![7u8; 300_000]);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn old_files_still_open_and_still_refuse_empty() {
    let want = std::fs::read(fix("plain.txt")).unwrap();
    let id = Identity::load(&fix("id.sgk")).unwrap();
    for (f, pass, ids) in [
        ("pass-v2.sg1", Some("fixture-pass"), vec![]),
        ("to-v2.sg1", None, vec![id.clone()]),
        ("plain-v2.sg1", None, vec![]),
    ] {
        let s = std::fs::read(fix(f)).unwrap();
        assert_eq!(unseal_ex_keys(&s, pass, &[], &ids).unwrap(), want, "{f}");
        refused(unseal_ex_keys(&s, Some(""), &[], &ids), f);
    }
    let kdf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kdf-v0");
    let ward = std::fs::read(kdf.join("ward-pbkdf2-80k.sg1")).unwrap();
    refused(unseal(&ward, Some("")), "legacy ward");
    assert_eq!(
        unseal(&ward, Some("correct horse battery")).unwrap(),
        std::fs::read(kdf.join("plain.bin")).unwrap()
    );
}
