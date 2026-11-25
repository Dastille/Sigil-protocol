//! Integration tests for recovery hints, consistent exit codes, Warded/Tome wording,
//! and the `scry` / `unseal` / `open` bit-rot regression (`exit 5`, never false `NOT recoverable`).
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .stdin(Stdio::null())
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn combined(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn noise(n: usize, mut x: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Flip one bit inside every shard of a classic `.sg1` so `live == 0 < k` while
/// remaining well within `sigil mend` deeper repair.
fn flip_every_shard(sg1: &[u8]) -> Vec<u8> {
    let (h, prefix, _) = sigil::locate_header(sg1).expect("header");
    let n = h.n as usize;
    let sl = h.shard_len as usize;
    let stride = 8 + sl;
    let mut out = sg1.to_vec();
    for i in 0..n {
        let pos = prefix + i * stride + 8 + (sl / 2);
        assert!(pos < out.len(), "shard {i} in bounds");
        out[pos] ^= 0x01;
    }
    out
}

#[test]
fn scry_unseal_open_bitrot_all_shards_regression() {
    let d = common::scratch("rec-bitrot");
    let data = noise(64 * 1024, 0x1234_5678_9abc_def0);
    fs::write(d.join("data.bin"), &data).unwrap();
    let o = sigil(&d, &["seal", "-o", "rot.sg1", "data.bin"]);
    assert!(o.status.success(), "{}", combined(&o));

    let rotted = flip_every_shard(&fs::read(d.join("rot.sg1")).unwrap());
    fs::write(d.join("rot.sg1"), rotted).unwrap();

    // Verify prerequisite: 0 shards pass per-shard CRC, yet deeper repair works.
    let (_, _, live, k, _) = sigil::verify(&fs::read(d.join("rot.sg1")).unwrap()).unwrap();
    assert_eq!(live, 0, "every shard must fail CRC for this regression");
    assert!(k > 0);

    // 1. scry must NOT say "NOT recoverable"; says "damaged — run sigil mend", exits 5.
    let o = sigil(&d, &["scry", "rot.sg1"]);
    assert_eq!(o.status.code(), Some(5), "{}", combined(&o));
    let t = combined(&o);
    assert!(!t.contains("NOT recoverable"), "{t}");
    assert!(t.contains("damaged — run sigil mend"), "{t}");
    assert!(t.contains("What you can try:"), "{t}");
    assert!(t.contains("sigil mend --scan"), "{t}");
    assert!(t.contains("sigil unseal --repair"), "{t}");
    assert!(t.contains("sigil mend rot.sg1 other-copy.sg1"), "{t}");

    // 2. scry --json keeps backward-compatible structure, exit 5, health=needs-repair, + hints.
    let o = sigil(&d, &["scry", "rot.sg1", "--json"]);
    assert_eq!(o.status.code(), Some(5), "{}", combined(&o));
    let j = String::from_utf8_lossy(&o.stdout);
    assert_eq!(j.lines().count(), 1, "{j}");
    assert!(j.contains("\"ok\":false"), "{j}");
    assert!(j.contains("\"exit\":5"), "{j}");
    assert!(j.contains("\"health\":\"needs-repair\""), "{j}");
    assert!(j.contains("\"hints\":["), "{j}");
    assert!(!j.contains("NOT recoverable"), "{j}");

    // 3. unseal (without --repair) and open say damaged & point to mend (never "need 12 pieces, have 0").
    for args in [
        &["unseal", "rot.sg1", "-o", "out.bin"][..],
        &["open", "--keep", "rot.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(5), "{args:?}: {}", combined(&o));
        let t = combined(&o);
        assert!(!t.contains("need 12 pieces, have 0"), "{t}");
        assert!(t.contains("damaged — run sigil mend"), "{t}");
        assert!(t.contains("What you can try:"), "{t}");
        assert!(t.contains("sigil mend"), "{t}");
        assert!(t.contains("sigil unseal --repair"), "{t}");
    }
    assert!(!d.join("out.bin").exists());

    // 4. mend repairs it cleanly (exit 0) and unseal recovers exact bytes.
    let o = sigil(&d, &["mend", "rot.sg1", "-o", "fixed.sg1"]);
    assert_eq!(o.status.code(), Some(0), "{}", combined(&o));
    let o = sigil(&d, &["unseal", "fixed.sg1", "-o", "back.bin"]);
    assert_eq!(o.status.code(), Some(0), "{}", combined(&o));
    assert_eq!(fs::read(d.join("back.bin")).unwrap(), data);
}

#[test]
fn unrecoverable_single_archive_hints_and_exit_2() {
    let d = common::scratch("rec-dead");
    let data = noise(64 * 1024, 0xfeed_face);
    fs::write(d.join("dead.bin"), &data).unwrap();
    assert!(sigil(&d, &["seal", "-o", "dead.sg1", "dead.bin"])
        .status
        .success());

    let mut b = fs::read(d.join("dead.sg1")).unwrap();
    let (a, z) = (b.len() * 25 / 100, b.len() * 90 / 100);
    b[a..z].fill(0);
    fs::write(d.join("dead.sg1"), &b).unwrap();

    for args in [
        &["scry", "dead.sg1"][..],
        &["mend", "dead.sg1"][..],
        &["unseal", "dead.sg1", "-o", "nope.bin"][..],
        &["open", "--keep", "dead.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", combined(&o));
        let t = combined(&o);
        assert!(t.contains("What you can try:"), "{args:?}: {t}");
        assert!(
            t.contains("sigil mend dead.sg1 other-copy.sg1"),
            "{args:?}: {t}"
        );
        assert!(t.contains("sigil gather"), "{args:?}: {t}");
        assert!(t.contains("sigil frost mend"), "{args:?}: {t}");
        assert!(t.contains("sigil vault versions"), "{args:?}: {t}");
        // Must NOT suggest single-copy `sigil mend dead.sg1` alone when already unrecoverable.
        assert!(!t.contains("--repair"), "{args:?}: {t}");
    }
    assert!(!d.join("nope.bin").exists());

    // --hard-only failure explicitly suggests dropping --hard-only.
    let o = sigil(&d, &["mend", "--hard-only", "dead.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", combined(&o));
    let t = combined(&o);
    assert!(t.contains("drop --hard-only"), "{t}");
}

#[test]
fn wrong_key_and_missing_key_ward_wording_and_fail_closed() {
    let d = common::scratch("rec-ward");
    let data = noise(8192, 0xaaaa_1111);
    fs::write(d.join("sec.bin"), &data).unwrap();
    fs::write(d.join("good.pw"), "correct horse battery\n").unwrap();
    fs::write(d.join("bad.pw"), "wrong passphrase\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("good.pw"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(d.join("bad.pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(sigil(
        &d,
        &[
            "seal",
            "--pass-file",
            "good.pw",
            "-o",
            "locked.sg1",
            "sec.bin"
        ]
    )
    .status
    .success());

    // Wrong key: exit 1, Ward wording, no CEK jargon, helpful options.
    for args in [
        &[
            "unseal",
            "--pass-file",
            "bad.pw",
            "-o",
            "out.bin",
            "locked.sg1",
        ][..],
        &["open", "--pass-file", "bad.pw", "--keep", "locked.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(1), "{args:?}: {}", combined(&o));
        let t = combined(&o);
        assert!(!t.contains("CEK"), "{t}");
        assert!(
            t.contains("Wrong passphrase or key — this Sigil Archive is Warded"),
            "{t}"
        );
        assert!(t.contains("What you can try:"), "{t}");
        assert!(t.contains("--identity"), "{t}");
        assert!(t.contains("no password reset"), "{t}");
    }
    assert!(!d.join("out.bin").exists());

    // Missing key: exit 1, Warded wording + options.
    let o = sigil(&d, &["unseal", "-o", "out.bin", "locked.sg1"]);
    assert_eq!(o.status.code(), Some(1), "{}", combined(&o));
    let t = combined(&o);
    assert!(!t.contains("CEK"), "{t}");
    assert!(
        t.contains("passphrase or --identity required — this Sigil Archive is Warded"),
        "{t}"
    );
    assert!(t.contains("What you can try:"), "{t}");
    assert!(!d.join("out.bin").exists());

    // Tampered encrypted archive (beyond shard-CRC tolerance) fails closed even with the right key.
    let mut tampered = fs::read(d.join("locked.sg1")).unwrap();
    let mid = tampered.len() / 2;
    for b in &mut tampered[mid..mid + 4000] {
        *b ^= 0xff;
    }
    fs::write(d.join("tampered.sg1"), tampered).unwrap();
    let o = sigil(
        &d,
        &[
            "unseal",
            "--pass-file",
            "good.pw",
            "-o",
            "tamper.bin",
            "tampered.sg1",
        ],
    );
    assert!(!o.status.success());
    assert!(!d.join("tamper.bin").exists());
}

#[test]
fn tome_damaged_member_mendable_member_and_truncated_tome() {
    let d = common::scratch("rec-tome");
    fs::create_dir_all(d.join("box")).unwrap();
    let alpha = b"alpha intact content\n".to_vec();
    let beta = noise(60_000, 0x5555_2222);
    fs::write(d.join("box/alpha.txt"), &alpha).unwrap();
    fs::write(d.join("box/beta.bin"), &beta).unwrap();
    assert!(sigil(&d, &["seal", "-o", "tome.sg1", "box"])
        .status
        .success());

    // Build a Tome where beta.bin has scattered bit rot (mendable!) and alpha.txt is intact.
    let mut raw = fs::read(d.join("tome.sg1")).unwrap();
    let beta_star = sigil::read_dir_entry_star(d.join("tome.sg1").as_path(), "beta.bin").unwrap();
    let beta_off = raw
        .windows(beta_star.len())
        .position(|w| w == beta_star.as_slice())
        .expect("locate beta star");
    let rotted_beta = flip_every_shard(&beta_star);
    raw[beta_off..beta_off + beta_star.len()].copy_from_slice(&rotted_beta);
    fs::write(d.join("tome-rot.sg1"), &raw).unwrap();

    for args in [
        &["scry", "tome-rot.sg1"][..],
        &["unseal", "tome-rot.sg1", "-o", "out-rot"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(5), "{args:?}: {}", combined(&o));
        let t = combined(&o);
        assert!(!t.contains("NOT recoverable"), "{t}");
        assert!(t.contains("damaged — run sigil mend"), "{t}");
        assert!(t.contains("sigil unseal --only alpha.txt"), "{t}");
        assert!(t.contains("Intact members (1): alpha.txt"), "{t}");
    }
    assert!(sigil(&d, &["mend", "tome-rot.sg1", "-o", "tome-fixed.sg1"])
        .status
        .success());
    assert!(sigil(&d, &["unseal", "tome-fixed.sg1", "-o", "out-fixed"])
        .status
        .success());
    assert_eq!(fs::read(d.join("out-fixed/beta.bin")).unwrap(), beta);

    // Destroy beta.bin beyond repair while alpha.txt stays intact.
    let mut dead = fs::read(d.join("tome.sg1")).unwrap();
    let wipe_a = beta_off + beta_star.len() * 20 / 100;
    let wipe_z = beta_off + beta_star.len() * 90 / 100;
    dead[wipe_a..wipe_z].fill(0);
    fs::write(d.join("tome-dead.sg1"), &dead).unwrap();

    for args in [
        &["scry", "tome-dead.sg1"][..],
        &["mend", "tome-dead.sg1"][..],
        &["unseal", "tome-dead.sg1", "-o", "out-dead"][..],
        &["open", "--keep", "tome-dead.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", combined(&o));
        let t = combined(&o);
        assert!(t.contains("beta.bin"), "{args:?}: {t}");
        assert!(t.contains("What you can try:"), "{args:?}: {t}");
        assert!(t.contains("sigil unseal --only alpha.txt"), "{args:?}: {t}");
        assert!(t.contains("Intact members (1): alpha.txt"), "{args:?}: {t}");
        assert!(!t.contains("folder pack"), "{args:?}: {t}");
    }
    // Verify the suggested `--only` rescue command actually succeeds.
    let o = sigil(
        &d,
        &[
            "unseal",
            "--only",
            "alpha.txt",
            "-o",
            "rescued",
            "tome-dead.sg1",
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", combined(&o));
    assert_eq!(fs::read(d.join("rescued/alpha.txt")).unwrap(), alpha);

    // Truncated Tome: plain message, NO "star bytes", NO "folder pack", exit 2.
    let full = fs::read(d.join("tome.sg1")).unwrap();
    fs::write(d.join("tome-cut.sg1"), &full[..full.len() - 400]).unwrap();
    for args in [
        &["scry", "tome-cut.sg1"][..],
        &["mend", "tome-cut.sg1"][..],
        &["unseal", "tome-cut.sg1", "-o", "out-cut"][..],
        &["open", "--keep", "tome-cut.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", combined(&o));
        let t = combined(&o);
        assert!(!t.contains("star bytes"), "{args:?}: {t}");
        assert!(!t.contains("folder pack"), "{args:?}: {t}");
        assert!(t.contains("truncated Tome"), "{args:?}: {t}");
        assert!(t.contains("What you can try:"), "{args:?}: {t}");
        assert!(!t.contains("--only"), "{args:?}: {t}");
    }
}

#[test]
fn channel_gather_and_frost_mend_short_hints() {
    let d = common::scratch("rec-chan-frost");
    let data = noise(64 * 1024, 0x9999_8888);
    fs::write(d.join("file.bin"), &data).unwrap();
    assert!(sigil(&d, &["seal", "-o", "file.sg1", "file.bin"])
        .status
        .success());

    // 1. Channel .mana short.
    assert!(sigil(
        &d,
        &[
            "deluge",
            "--channel",
            "--extra",
            "2",
            "file.sg1",
            "-o",
            "mana"
        ]
    )
    .status
    .success());
    let mut files: Vec<_> = fs::read_dir(d.join("mana"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("mana"))
        .collect();
    files.sort();
    for p in files.iter().take(6) {
        fs::remove_file(p).unwrap();
    }
    let o = sigil(&d, &["gather", "mana", "-o", "rebuilt.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", combined(&o));
    let t = combined(&o);
    assert!(t.contains("not enough mana"), "{t}");
    assert!(t.contains("What you can try:"), "{t}");
    assert!(t.contains("sigil gather --report"), "{t}");
    assert!(t.contains("sigil deluge --channel"), "{t}");
    assert!(t.contains("--answer"), "{t}");
    assert!(t.contains("sigil gather --partial"), "{t}");

    // 2. Plain .sgp pieces short.
    assert!(sigil(&d, &["scatter", "file.sg1", "-o", "pcs"])
        .status
        .success());
    let mut sgp: Vec<_> = fs::read_dir(d.join("pcs"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("sgp"))
        .collect();
    sgp.sort();
    for p in sgp.iter().take(6) {
        fs::remove_file(p).unwrap();
    }
    let o = sigil(&d, &["gather", "pcs", "-o", "rebuilt2.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", combined(&o));
    let t = combined(&o);
    assert!(t.contains("What you can try:"), "{t}");
    assert!(t.contains(".sgp"), "{t}");
    assert!(t.contains("sigil frost mend"), "{t}");
    assert!(!t.contains(".mana"), "{t}");

    // 3. Frost Rune short on usb-* drives.
    assert!(sigil(&d, &["frost", "place", "file.sg1", "-o", "frost"])
        .status
        .success());
    fs::remove_dir_all(d.join("frost/usb-0")).unwrap();
    fs::remove_dir_all(d.join("frost/usb-1")).unwrap();
    let o = sigil(&d, &["frost", "mend", "frost", "-o", "frost-back.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", combined(&o));
    let t = combined(&o);
    assert!(t.contains("Not enough Frost Rune pieces yet"), "{t}");
    assert!(t.contains("What you can try:"), "{t}");
    assert!(t.contains("usb-*"), "{t}");
    assert!(t.contains("sigil frost mend"), "{t}");
    assert!(t.contains("sigil gather"), "{t}");
}

#[test]
fn work_pack_and_sealed_tome_options_stay_accurate() {
    let d = common::scratch("rec-work-sealed");
    // Work pack (> 4 MiB default chunk threshold -> SGWK pack).
    let big = noise(5_000_000, 0x3333_4444);
    fs::write(d.join("big.bin"), &big).unwrap();
    assert!(sigil(&d, &["seal", "-o", "big.sg1", "big.bin"])
        .status
        .success());
    assert!(sigil::is_work_pack(&d.join("big.sg1")));

    // Flip 1 bit in every shard of the first chunk star.
    let mut pack = fs::read(d.join("big.sg1")).unwrap();
    let (_, locs) = sigil::index_pack(&d.join("big.sg1")).unwrap();
    let off0 = locs[0].file_off as usize;
    let len0 = locs[0].star_len as usize;
    let rotted0 = flip_every_shard(&pack[off0..off0 + len0]);
    pack[off0..off0 + len0].copy_from_slice(&rotted0);
    fs::write(d.join("big-rot.sg1"), &pack).unwrap();

    let o = sigil(&d, &["scry", "big-rot.sg1"]);
    assert_eq!(o.status.code(), Some(5), "{}", combined(&o));
    let t = combined(&o);
    assert!(!t.contains("NOT recoverable"), "{t}");
    assert!(t.contains("damaged — run sigil mend"), "{t}");
    // Work pack must NOT advertise single-file `--repair` or multi-copy pooling.
    assert!(!t.contains("unseal --repair"), "{t}");
    assert!(!t.contains("other-copy.sg1"), "{t}");

    // Sealed (Warded) Tome wrong key vs missing key.
    fs::create_dir_all(d.join("secdir")).unwrap();
    fs::write(d.join("secdir/a.txt"), b"secret a").unwrap();
    fs::write(d.join("pw"), "tome-secret\n").unwrap();
    fs::write(d.join("wrong"), "nope\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(d.join("wrong"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(sigil(
        &d,
        &[
            "seal",
            "--pass-file",
            "pw",
            "-o",
            "warded-tome.sg1",
            "secdir"
        ]
    )
    .status
    .success());
    let o = sigil(&d, &["scry", "--pass-file", "wrong", "warded-tome.sg1"]);
    assert_eq!(o.status.code(), Some(1), "{}", combined(&o));
    let t = combined(&o);
    assert!(!t.contains("CEK"), "{t}");
    assert!(
        t.contains("Wrong passphrase or key — this Sigil Archive is Warded"),
        "{t}"
    );
    assert!(t.contains("What you can try:"), "{t}");
}
