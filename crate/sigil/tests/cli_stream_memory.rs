//! Peak memory of `sigil` on a Tome with one large member stays near one chunk, not the
//! member's size: seal, scry, unseal, mount export and mend, for a plain and a Warded Tome. The same
//! holds for a single file sealed whole (one classic seal, no chunking).
//! Measured as the child's peak resident set (`wait4` rusage), Linux only.
#![cfg(target_os = "linux")]
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

/// Size of the large member: far above the memory limit below.
const BIG: usize = 48 << 20;
/// Most a command's peak resident set may grow (KiB) when the member grows from 1 MiB
/// to `BIG`; reading the member whole would add at least 47 MiB.
const MARGIN_KIB: i64 = 16 << 10;

/// Write `n` bytes of a fixed pseudo-random stream to `path`, 1 MiB at a time. The test
/// process itself must stay small: a child's peak resident set as reported by `wait4`
/// starts from the parent's high-water mark (the child begins life as a copy of it).
fn write_noise(path: &Path, n: usize) {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(fs::File::create(path).unwrap());
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut left = n;
    let mut buf = Vec::with_capacity(1 << 20);
    while left > 0 {
        buf.clear();
        while buf.len() < (1 << 20).min(left) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            buf.extend_from_slice(&x.to_le_bytes());
        }
        buf.truncate((1 << 20).min(left));
        f.write_all(&buf).unwrap();
        left -= buf.len();
    }
    f.flush().unwrap();
}

/// True when the two files hold the same bytes (compared 1 MiB at a time).
fn same_file(a: &Path, b: &Path) -> bool {
    use std::io::Read;
    let (mut fa, mut fb) = (fs::File::open(a).unwrap(), fs::File::open(b).unwrap());
    if fa.metadata().unwrap().len() != fb.metadata().unwrap().len() {
        return false;
    }
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let n = fa.read(&mut ba).unwrap();
        if n == 0 {
            return true;
        }
        fb.read_exact(&mut bb[..n]).unwrap();
        if ba[..n] != bb[..n] {
            return false;
        }
    }
}

/// Run `sigil args…` in `dir`; returns (exit code, peak RSS in KiB).
// The child is reaped by the `wait4` call below (std's `wait` cannot report rusage).
#[allow(clippy::zombie_processes)]
fn run_rss(dir: &Path, args: &[&str]) -> (i32, i64) {
    let child = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run sigil");
    let pid = child.id() as libc::pid_t;
    let mut status: libc::c_int = 0;
    // SAFETY: `rusage` is a plain C struct of integers; all-zero bytes are a valid value.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `pid` is our own child, not yet waited for (std's `Child` is never waited
    // on here), and `status` / `ru` are valid, writable locals for the whole call.
    let r = unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
    assert_eq!(r, pid, "wait4 failed");
    let code = if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    };
    (code, ru.ru_maxrss)
}

/// Run one command that must succeed; returns its peak RSS (KiB).
fn rss_ok(dir: &Path, what: &str, args: &[&str]) -> i64 {
    let (code, kib) = run_rss(dir, args);
    assert_eq!(code, 0, "{what}: exit {code}");
    kib
}

/// Flip 4 KiB in the middle of `p` (in place, without reading the file whole).
fn damage(p: &Path) {
    use std::io::{Seek, SeekFrom, Write};
    let len = fs::metadata(p).unwrap().len();
    let mut f = fs::OpenOptions::new().write(true).open(p).unwrap();
    f.seek(SeekFrom::Start(len / 2)).unwrap();
    f.write_all(&[0xa5u8; 4096]).unwrap();
}

/// Seal, scry, unseal, mend and unseal again a plain and a Warded Tome holding one
/// `member`-byte file; returns `(command, peak RSS KiB)` in order.
fn measure(member: usize) -> Vec<(String, i64)> {
    let d = common::scratch("stream-mem");
    let src = d.join("src");
    fs::create_dir_all(&src).unwrap();
    let big = src.join("big.bin");
    write_noise(&big, member);
    fs::write(src.join("small.txt"), b"small").unwrap();
    let dp = d.path();
    let mut out = Vec::new();
    for (tag, extra) in [("plain", &[][..]), ("warded", &["--pass", "stream-pw"][..])] {
        let pack = format!("{tag}.sg1");
        let mut seal = vec!["seal", "src", "-o", &pack, "--chunk", "1048576"];
        seal.extend_from_slice(extra);
        out.push((format!("{tag} seal"), rss_ok(dp, "seal", &seal)));
        out.push((format!("{tag} scry"), rss_ok(dp, "scry", &["scry", &pack])));
        let o1 = format!("{tag}-out");
        let mut un = vec!["unseal", &pack, "-o", &o1];
        un.extend_from_slice(extra);
        out.push((format!("{tag} unseal"), rss_ok(dp, "unseal", &un)));
        assert!(same_file(&d.join(&o1).join("big.bin"), &big), "{tag}");
        let ex = format!("{tag}-export");
        let mut mo = vec!["mount", &pack, "unused-mountpoint", "--export-dir", &ex];
        mo.extend_from_slice(extra);
        out.push((format!("{tag} mount export"), rss_ok(dp, "mount", &mo)));
        assert!(same_file(&d.join(&ex).join("big.bin"), &big), "{tag}");
        let bad = format!("{tag}-bad.sg1");
        fs::copy(d.join(&pack), d.join(&bad)).unwrap();
        damage(&d.join(&bad));
        let fixed = format!("{tag}-fixed.sg1");
        let mend = ["mend", bad.as_str(), "-o", fixed.as_str(), "-y"];
        out.push((format!("{tag} mend"), rss_ok(dp, "mend", &mend)));
        let o2 = format!("{tag}-out2");
        let mut un2 = vec!["unseal", &fixed, "-o", &o2];
        un2.extend_from_slice(extra);
        out.push((format!("{tag} unseal mended"), rss_ok(dp, "unseal", &un2)));
        assert!(same_file(&d.join(&o2).join("big.bin"), &big), "{tag}");
    }
    out
}

/// Each command's peak memory with a 48 MiB member stays within `MARGIN_KIB` of the
/// same command with a 1 MiB member (the passphrase KDF alone takes tens of MiB, so an
/// absolute limit would not say much). Reading the member whole would add >= 48 MiB.
#[test]
fn tome_commands_hold_one_chunk_not_the_member() {
    let small = measure(1 << 20);
    let large = measure(BIG);
    for ((what, s), (_, l)) in small.iter().zip(&large) {
        eprintln!("{what}: 1 MiB member {s} KiB, 48 MiB member {l} KiB");
        assert!(
            *l < *s + MARGIN_KIB,
            "{what}: peak {l} KiB with a {} KiB member vs {s} KiB with 1 MiB: memory grows with the member",
            BIG >> 10
        );
    }
}

/// Seal one `member`-byte file whole (a single classic seal), then scry, unseal (to a
/// file and to stdout), mend and unseal again, plain and Warded; `(command, KiB)`.
fn measure_classic(member: usize) -> Vec<(String, i64)> {
    let d = common::scratch("stream-mem-classic");
    let big = d.join("big.bin");
    write_noise(&big, member);
    let dp = d.path();
    let mut out = Vec::new();
    for (tag, extra) in [("plain", &[][..]), ("warded", &["--pass", "stream-pw"][..])] {
        let pack = format!("{tag}.sg1");
        let mut seal = vec!["seal", "big.bin", "-o", &pack, "--chunk", "4294967295"];
        seal.extend_from_slice(extra);
        out.push((format!("{tag} single seal"), rss_ok(dp, "seal", &seal)));
        assert!(
            !sigil::is_work_pack(&d.join(&pack)),
            "{tag}: expected one classic seal"
        );
        out.push((
            format!("{tag} single scry"),
            rss_ok(dp, "scry", &["scry", &pack]),
        ));
        let o1 = format!("{tag}-out.bin");
        let mut un = vec!["unseal", &pack, "-o", &o1];
        un.extend_from_slice(extra);
        out.push((format!("{tag} single unseal"), rss_ok(dp, "unseal", &un)));
        assert!(same_file(&d.join(&o1), &big), "{tag}");
        let mut un_out = vec!["unseal", &pack, "-o", "-"];
        un_out.extend_from_slice(extra);
        out.push((
            format!("{tag} single unseal stdout"),
            rss_ok(dp, "unseal", &un_out),
        ));
        let bad = format!("{tag}-bad.sg1");
        fs::copy(d.join(&pack), d.join(&bad)).unwrap();
        damage(&d.join(&bad));
        let fixed = format!("{tag}-fixed.sg1");
        let mend = ["mend", bad.as_str(), "-o", fixed.as_str(), "-y"];
        out.push((format!("{tag} single mend"), rss_ok(dp, "mend", &mend)));
        assert!(same_file(&d.join(&fixed), &d.join(&pack)), "{tag}: mend");
        let o2 = format!("{tag}-out2.bin");
        let mut un2 = vec!["unseal", &fixed, "-o", &o2];
        un2.extend_from_slice(extra);
        out.push((
            format!("{tag} single unseal mended"),
            rss_ok(dp, "unseal", &un2),
        ));
        assert!(same_file(&d.join(&o2), &big), "{tag}");
    }
    out
}

/// A single file sealed whole: each command's peak memory with a 96 MiB file stays under
/// `SINGLE_CAP_KIB`, below the file's own size. The streamed paths work in column
/// windows of at most about 32 MiB in all (whatever the file size), plus 1 MiB buffers
/// and the passphrase KDF; reading the file whole would take >= 96 MiB, and the
/// in-memory mend several times that.
#[test]
fn single_seal_commands_hold_a_window_not_the_file() {
    const SINGLE_BIG: usize = 96 << 20;
    const SINGLE_CAP_KIB: i64 = 72 << 10;
    for (what, kib) in measure_classic(SINGLE_BIG) {
        eprintln!("{what}: 96 MiB file {kib} KiB");
        assert!(
            kib < SINGLE_CAP_KIB,
            "{what}: peak {kib} KiB with a 96 MiB file (cap {SINGLE_CAP_KIB} KiB)"
        );
    }
}
