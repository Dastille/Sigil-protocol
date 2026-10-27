//! A passphrase that is only whitespace is refused like an empty one, when sealing and
//! when opening, on every kind of file. Real passphrases with leading/trailing spaces
//! keep their exact meaning (new files: exact match; legacy Ward files: trimmed, as
//! they always were).

use sigil::{seal, unseal, unseal_ex_keys, Identity, Mode, DEFAULT_PIECE};
use std::path::Path;

const BLANKS: [&str; 4] = [" ", "   ", "\t", " \n\t "];

fn refused<T>(r: sigil::Result<T>, what: &str) {
    match r {
        Ok(_) => panic!("{what}: blank passphrase was accepted"),
        Err(e) => assert!(
            e.to_string().contains("only spaces"),
            "{what}: wrong error: {e}"
        ),
    }
}

#[test]
fn sealing_with_a_blank_passphrase_is_refused() {
    let data = b"blank must not protect".repeat(10);
    for b in BLANKS {
        refused(seal(&data, Mode::Seal, Some(b), "x.txt", false), "seal");
    }
    let d = std::env::temp_dir().join(format!("sigil-blank-seal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("src")).unwrap();
    std::fs::write(d.join("src/a.txt"), b"a").unwrap();
    refused(
        sigil::inscribe_dir(
            &d.join("src"),
            &d.join("f.sg1"),
            Mode::Seal,
            Some("  "),
            "",
            &[],
            0,
            &[],
        ),
        "folder seal",
    );
    std::fs::write(d.join("big.bin"), vec![1u8; 200_000]).unwrap();
    refused(
        sigil::inscribe_path(
            &d.join("big.bin"),
            &d.join("big.sg1"),
            Mode::Seal,
            Some("  "),
            "",
            &[],
            65_536,
            None,
            DEFAULT_PIECE,
            0,
            None,
        ),
        "large-file seal",
    );
    assert!(!d.join("f.sg1").exists() && !d.join("big.sg1").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn opening_with_a_blank_passphrase_is_refused() {
    let data = b"blank must not open".repeat(10);
    let plain = seal(&data, Mode::Seal, None, "p.txt", false).unwrap();
    let pw = seal(&data, Mode::Seal, Some("pw"), "e.txt", false).unwrap();
    let id = Identity::generate().unwrap();
    let to = sigil::seal_kn_to(
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
    for b in BLANKS {
        refused(unseal(&plain, Some(b)), "plain");
        refused(unseal(&pw, Some(b)), "passphrase");
        refused(
            unseal_ex_keys(&to, Some(b), &[], std::slice::from_ref(&id)),
            "to+id",
        );
    }
    let kdf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kdf-v0");
    let ward = std::fs::read(kdf.join("ward-pbkdf2-80k.sg1")).unwrap();
    for b in BLANKS {
        refused(unseal(&ward, Some(b)), "legacy ward");
    }
}

#[test]
fn spaces_around_a_real_passphrase_keep_their_meaning() {
    let data = b"spaces are part of a real passphrase".repeat(10);
    // New files: exact. " pw " and "pw" are different passphrases.
    let s = seal(&data, Mode::Seal, Some(" pw "), "s.txt", false).unwrap();
    assert_eq!(unseal(&s, Some(" pw ")).unwrap(), data);
    assert!(unseal(&s, Some("pw")).is_err());
    // Legacy Ward files always trimmed: surrounding spaces still open them.
    let kdf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kdf-v0");
    let ward = std::fs::read(kdf.join("ward-pbkdf2-80k.sg1")).unwrap();
    let want = std::fs::read(kdf.join("plain.bin")).unwrap();
    assert_eq!(unseal(&ward, Some("correct horse battery")).unwrap(), want);
    assert_eq!(
        unseal(&ward, Some("  correct horse battery ")).unwrap(),
        want
    );
}
