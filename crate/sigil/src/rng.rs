//! Randomness for salts, nonces, content keys and identity keys.
//!
//! Every draw comes from the operating system's cryptographically secure random number
//! generator through the `getrandom` crate (0.2). Its documented sources
//! (<https://docs.rs/getrandom/0.2.17/getrandom/#supported-targets>) include the
//! `getrandom` system call on Linux (falling back to `/dev/urandom` only after
//! `/dev/random` has been polled successfully), `BCryptGenRandom` on Windows and
//! `getentropy` on macOS. The crate returns an error instead of weak bytes, and so does
//! [`getrandom`] here: a failure refuses the seal or key before anything is written.
//! There is no fallback.

use crate::{Error, Result};
use std::io::Read;
use std::path::Path;

#[cfg(test)]
thread_local! {
    static TEST_RANDOM_SEED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static TEST_RANDOM_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Tests only: make salts, nonces and keys drawn on this thread come from a fixed
/// sequence (`Some(seed)`) so a test's sealed bytes, and every count measured on them,
/// are the same on every run; `None` goes back to the system source.
#[cfg(test)]
pub(crate) fn set_test_random_seed(seed: Option<u64>) {
    TEST_RANDOM_SEED.with(|c| c.set(seed));
}

/// Tests only: make every draw on this thread fail, as if the system source were gone.
#[cfg(test)]
pub(crate) fn set_test_random_fail(fail: bool) {
    TEST_RANDOM_FAIL.with(|c| c.set(fail));
}

fn unavailable(why: &str) -> Error {
    Error::Msg(format!(
        "the system random number generator failed ({why}); refusing to make salts, nonces \
         or keys without it. Nothing was written"
    ))
}

/// Fill `buf` with bytes from the operating system's secure random number generator.
///
/// Fails closed: on any error `buf` must not be used and the caller stops (no seal, key
/// or file is made). Never returns zeros in place of random bytes.
pub(crate) fn getrandom(buf: &mut [u8]) -> Result<()> {
    #[cfg(test)]
    {
        if TEST_RANDOM_FAIL.with(|c| c.get()) {
            return Err(unavailable("test: injected failure"));
        }
        if let Some(mut x) = TEST_RANDOM_SEED.with(|c| c.get()) {
            for b in buf.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            TEST_RANDOM_SEED.with(|c| c.set(Some(x | 1)));
            return Ok(());
        }
    }
    getrandom::getrandom(buf).map_err(|e| unavailable(&e.to_string()))
}

/// Header prefix read by [`weak_random_warning`]: a header and its name fit well inside.
const WARN_PREFIX: u64 = 64 * 1024;

/// A warning when the seal or large-file pack at `path` (its first star) carries an
/// all-zero salt or nonce.
///
/// Such a seal was made while the random source was failing: earlier builds read
/// `/dev/urandom` and silently kept zeros when it could not be opened or read (always,
/// on Windows). For an encrypted seal the content key was then zero as well, so the
/// lock gives no protection. A real draw is all zeros with chance 2^-96 or less. Reads
/// one header from a bounded prefix; anything it cannot read gives `None` (the normal
/// checks report damage). The format is unchanged.
pub fn weak_random_warning(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut mag = [0u8; 4];
    f.read_exact(&mut mag).ok()?;
    let (off, len) = if mag == crate::WORK_MAGIC {
        let l = crate::packhead::layout_path(path).ok()?;
        *l.stars.first()?
    } else {
        (0, f.metadata().ok()?.len())
    };
    let take = usize::try_from(len.min(WARN_PREFIX)).ok()?;
    let mut buf = vec![0u8; take];
    let mut f = std::fs::File::open(path).ok()?;
    std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(off)).ok()?;
    f.read_exact(&mut buf).ok()?;
    let (h, _, _) = crate::locate_header(&buf).ok()?;
    let zero_salt = h.salt.iter().all(|&b| b == 0);
    let zero_nonce = h.nonce.iter().all(|&b| b == 0);
    if !(zero_salt || zero_nonce) {
        return None;
    }
    let locked = if h.private_label() {
        " It is encrypted, and its content key was most likely all zeros too, so treat \
         its contents as readable by anyone: open it, then Inscribe it again with this \
         version and delete the old copies."
    } else {
        " It is not encrypted, so only its checks are weaker; Inscribe it again to be safe."
    };
    Some(format!(
        "{} has an all-zero {}: it was made while the system random number generator was \
         failing.{locked}",
        path.display(),
        match (zero_salt, zero_nonce) {
            (true, true) => "salt and nonce",
            (true, false) => "salt",
            _ => "nonce",
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mds, privacy::SealOpts, Mode};
    use std::path::PathBuf;

    fn dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "sigil-rng-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn names(d: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// Runs `f` with every draw on this thread failing, then restores the system source.
    fn failing<T>(f: impl FnOnce() -> T) -> T {
        set_test_random_fail(true);
        let r = f();
        set_test_random_fail(false);
        r
    }

    fn file_seal(input: &Path, out: &Path, pass: Option<&str>) -> Result<Option<u64>> {
        let be = mds::backend_by_name("vandermonde").unwrap();
        crate::classic::seal(
            input,
            out,
            Mode::Reflection,
            pass,
            "f.bin",
            false,
            "",
            &[],
            None,
            crate::DEFAULT_PIECE,
            &*be,
            &[],
            &SealOpts::default(),
        )
    }

    #[test]
    fn failing_source_refuses_file_seals_and_writes_nothing() {
        for pass in [None, Some("correct horse battery")] {
            let d = dir("file");
            let input = d.join("f.bin");
            std::fs::write(&input, vec![7u8; 300_000]).unwrap();
            let out = d.join("f.sg1");
            let e = failing(|| file_seal(&input, &out, pass)).unwrap_err();
            assert!(
                e.to_string().contains("random number generator failed"),
                "{e}"
            );
            assert!(e.to_string().contains("Nothing was written"), "{e}");
            assert_eq!(names(&d), vec!["f.bin".to_string()], "pass={pass:?}");
            // The source back: the same call works.
            file_seal(&input, &out, pass).unwrap();
            assert!(out.exists());
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn failing_source_refuses_large_file_packs_and_writes_nothing() {
        let d = dir("pack");
        let input = d.join("big.bin");
        std::fs::write(&input, vec![3u8; 600_000]).unwrap();
        let out = d.join("big.sg1");
        for pass in [None, Some("correct horse battery")] {
            let e = failing(|| {
                crate::work::inscribe_path(
                    &input,
                    &out,
                    Mode::Reflection,
                    pass,
                    "",
                    &[],
                    262_144,
                    None,
                    0,
                    0,
                    None,
                )
            })
            .unwrap_err();
            assert!(
                e.to_string().contains("random number generator failed"),
                "{e}"
            );
            assert_eq!(names(&d), vec!["big.bin".to_string()], "pass={pass:?}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn failing_source_refuses_in_memory_seals_and_keys() {
        let e = failing(|| crate::seal(b"hello", Mode::Reflection, Some("pw pw pw"), "h", false))
            .unwrap_err();
        assert!(
            e.to_string().contains("random number generator failed"),
            "{e}"
        );
        assert!(failing(|| crate::seal(b"hello", Mode::Reflection, None, "h", false)).is_err());
        assert!(failing(crate::keys::Identity::generate).is_err());
        assert!(failing(crate::rain_lane).is_err());
        assert!(crate::keys::Identity::generate().is_ok());
    }

    #[test]
    fn failing_source_refuses_keygen_and_tomes_and_writes_nothing() {
        let d = dir("keygen");
        let key = d.join("me.sgk");
        assert!(failing(|| crate::keys::keygen_ecc(&key, None)).is_err());
        assert!(failing(|| crate::keys::keygen_ecc_with_pass(&key, None, b"pw pw pw")).is_err());
        assert!(names(&d).is_empty(), "{:?}", names(&d));
        let src = d.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"a").unwrap();
        std::fs::write(src.join("b.bin"), vec![9u8; 300_000]).unwrap();
        let tome = d.join("t.sg1");
        for pass in [None, Some("correct horse battery")] {
            let r = failing(|| {
                crate::folder::inscribe_dir(
                    &src,
                    &tome,
                    Mode::Reflection,
                    pass,
                    "",
                    &[],
                    65_536,
                    &[],
                )
            });
            assert!(r.is_err(), "pass={pass:?}");
            assert_eq!(names(&d), vec!["src".to_string()], "pass={pass:?}");
        }
        crate::keys::keygen_ecc(&key, None).unwrap();
        assert!(key.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn two_seals_draw_different_salts_and_nonces() {
        let a = crate::seal(
            b"same bytes",
            Mode::Reflection,
            Some("pw pw pw"),
            "s",
            false,
        )
        .unwrap();
        let b = crate::seal(
            b"same bytes",
            Mode::Reflection,
            Some("pw pw pw"),
            "s",
            false,
        )
        .unwrap();
        let (ha, _, _) = crate::locate_header(&a).unwrap();
        let (hb, _, _) = crate::locate_header(&b).unwrap();
        assert_ne!(ha.salt, hb.salt);
        assert_ne!(ha.nonce, hb.nonce);
        for h in [&ha, &hb] {
            assert!(h.salt.iter().any(|&x| x != 0) && h.nonce.iter().any(|&x| x != 0));
        }
        let p = crate::seal(b"same bytes", Mode::Reflection, None, "s", false).unwrap();
        let q = crate::seal(b"same bytes", Mode::Reflection, None, "s", false).unwrap();
        let (hp, _, _) = crate::locate_header(&p).unwrap();
        let (hq, _, _) = crate::locate_header(&q).unwrap();
        assert_ne!((hp.salt, hp.nonce), (hq.salt, hq.nonce));
    }

    #[test]
    fn scry_warns_on_a_zero_salt_seal_only() {
        let d = dir("warn");
        let good = d.join("good.sg1");
        std::fs::write(
            &good,
            crate::seal(b"x", Mode::Reflection, Some("pw pw pw"), "x", false).unwrap(),
        )
        .unwrap();
        assert_eq!(weak_random_warning(&good), None);
        // Seed 0 makes the xorshift draw all zeros: the salt comes out zero, as the old
        // fail-open path produced.
        set_test_random_seed(Some(0));
        let bad = crate::seal(b"x", Mode::Reflection, Some("pw pw pw"), "x", false);
        set_test_random_seed(None);
        let weak = d.join("weak.sg1");
        std::fs::write(&weak, bad.unwrap()).unwrap();
        let w = weak_random_warning(&weak).unwrap();
        assert!(
            w.contains("all-zero salt") && w.contains("readable by anyone"),
            "{w}"
        );
        // A large-file pack is checked through its first star.
        let input = d.join("big.bin");
        std::fs::write(&input, vec![5u8; 600_000]).unwrap();
        let pack = d.join("big.sg1");
        crate::work::inscribe_path(
            &input,
            &pack,
            Mode::Reflection,
            None,
            "",
            &[],
            262_144,
            None,
            0,
            0,
            None,
        )
        .unwrap();
        assert_eq!(weak_random_warning(&pack), None);
        // Not a seal at all: no warning, no panic.
        assert_eq!(weak_random_warning(&input), None);
        assert_eq!(weak_random_warning(&d.join("missing")), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
