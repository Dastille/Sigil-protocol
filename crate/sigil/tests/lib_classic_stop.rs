//! Library: once a stop is requested (Ctrl-C in the CLI), the streamed seal, open and
//! mend of a single-file seal return a "repair stopped" error and keep nothing: no
//! archive, no part file, no plaintext. Own test binary: the stop flag is process-wide.
mod common;
use sigil::repair_ctl::{clear_stop, request_stop, STOPPED};
use std::path::Path;

fn data(n: usize) -> Vec<u8> {
    let mut x = 0x5eed_u64 | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn seal(input: &Path, out: &Path, pass: Option<&str>) -> sigil::Result<u64> {
    sigil::seal_file_classic(
        input,
        out,
        sigil::Mode::Seal,
        pass,
        "in.bin",
        "",
        &[],
        None,
        0,
        &sigil::VandermondeRs,
        &[],
        &sigil::privacy::SealOpts::default(),
    )
}

fn leftovers(d: &Path) -> Vec<String> {
    std::fs::read_dir(d)
        .expect("dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("part") || n.contains("spool") || n.starts_with('.'))
        .collect()
}

#[test]
fn stop_request_ends_streamed_seal_open_and_mend_with_nothing_kept() {
    let t = common::scratch("classic-stop");
    let d = t.path();
    let input = d.join("in.bin");
    let plain = data(3_000_000);
    std::fs::write(&input, &plain).expect("write");
    for pass in [None, Some("stop-pw")] {
        let tag = if pass.is_some() { "warded" } else { "plain" };
        let sealed = d.join(format!("{tag}.sg1"));

        // A stop before sealing: no archive and no part file.
        request_stop();
        let e = seal(&input, &sealed, pass).expect_err("stopped seal");
        assert!(e.to_string().contains(STOPPED), "{tag}: {e}");
        assert!(!sealed.exists(), "{tag}: archive kept after stop");
        assert!(leftovers(d).is_empty(), "{tag}: {:?}", leftovers(d));
        clear_stop();
        seal(&input, &sealed, pass).expect("seal");

        // A stop before opening: an error and not one byte of output.
        request_stop();
        let mut out = Vec::new();
        let e = sigil::unseal_file_classic_verified(&sealed, &mut out, pass, &[], &[], &sealed)
            .expect_err("stopped open");
        assert!(e.to_string().contains(STOPPED), "{tag}: {e}");
        assert!(out.is_empty(), "{tag}: {} bytes released", out.len());
        assert!(leftovers(d).is_empty(), "{tag}: {:?}", leftovers(d));
        clear_stop();
        let n = sigil::unseal_file_classic_verified(&sealed, &mut out, pass, &[], &[], &sealed)
            .expect("open")
            .expect("streamed");
        assert_eq!(n as usize, plain.len());
        assert!(out == plain, "{tag}: round trip");

        // Damage one part, then stop the mend: the plan or the run refuses, and the
        // output stays absent.
        let mut b = std::fs::read(&sealed).expect("read");
        let mid = b.len() / 2;
        for x in &mut b[mid..mid + 4096] {
            *x ^= 0x5a;
        }
        let bad = d.join(format!("{tag}-bad.sg1"));
        std::fs::write(&bad, &b).expect("write");
        let fixed = d.join(format!("{tag}-fixed.sg1"));
        let (plan, _scan) = sigil::classic_mend_plan(&bad, &bad)
            .expect("plan")
            .expect("streamed plan");
        request_stop();
        let e = sigil::classic_mend_run(plan, &fixed, false).expect_err("stopped mend");
        assert!(e.to_string().contains(STOPPED), "{tag}: {e}");
        assert!(!fixed.exists(), "{tag}: mended output kept after stop");
        assert!(leftovers(d).is_empty(), "{tag}: {:?}", leftovers(d));
        let e = sigil::classic_mend_plan(&bad, &bad)
            .map(|_| ())
            .expect_err("stopped plan");
        assert!(e.to_string().contains(STOPPED), "{tag}: {e}");
        clear_stop();
        let (plan, _) = sigil::classic_mend_plan(&bad, &bad)
            .expect("plan")
            .expect("streamed plan");
        sigil::classic_mend_run(plan, &fixed, false)
            .expect("mend")
            .expect("streamed mend");
        assert!(std::fs::read(&fixed).expect("read") == std::fs::read(&sealed).expect("read"));
        std::fs::remove_file(&fixed).expect("rm");
    }
}
