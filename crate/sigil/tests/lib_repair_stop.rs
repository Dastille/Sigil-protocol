//! Library: once a stop is requested (Ctrl-C in the CLI), the deeper repair and the
//! large-file pack repair return a "repair stopped" error and leave no file behind.
//! Own test binary: the stop flag is process-wide.
mod common;
use std::path::Path;
use std::process::Command;

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn seal(dir: &Path, n: usize, name: &str) -> Vec<u8> {
    std::fs::write(dir.join("in.bin"), data(n, 0xc0ffee)).expect("write");
    let o = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(["seal", "-o", name, "in.bin"])
        .output()
        .expect("run sigil");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    std::fs::read(dir.join(name)).expect("read")
}

fn rot(b: &mut [u8], step: usize) {
    let mut i = 4096;
    while i < b.len() {
        b[i] ^= 0x10;
        i += step;
    }
}

#[test]
fn stop_request_fails_closed_for_seal_and_pack() {
    let t = common::scratch("repair-stop");
    let d = t.path();
    let mut one = seal(d, 200_000, "one.sg1");
    rot(&mut one, 1000);
    // Repairs normally …
    sigil::repair_ctl::clear_stop();
    assert!(sigil::mend_bytes_ex(&one, true).is_ok());

    let mut pack = seal(d, 9_000_000, "pack.sg1");
    assert!(
        sigil::is_work_pack(&d.join("pack.sg1")),
        "expected a large-file pack"
    );
    rot(&mut pack, 5000);
    std::fs::write(d.join("pack.sg1"), &pack).expect("write");

    // … and after a stop request, both refuse with "repair stopped".
    sigil::repair_ctl::request_stop();
    let e = sigil::mend_bytes_ex(&one, true).expect_err("stopped");
    assert!(e.to_string().contains(sigil::repair_ctl::STOPPED), "{e}");
    let out = d.join("pack.mended.sg1");
    let e = sigil::mend_pack_path(&d.join("pack.sg1"), &out, true).expect_err("stopped");
    assert!(e.to_string().contains(sigil::repair_ctl::STOPPED), "{e}");
    assert!(!out.exists());
    assert!(!d.join("pack.mended.sg1.mend-part").exists());
    sigil::repair_ctl::clear_stop();
    assert!(sigil::mend_pack_path(&d.join("pack.sg1"), &out, true).is_ok());
    assert!(out.exists());
}
