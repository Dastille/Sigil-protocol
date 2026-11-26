//! Recovery guidance: exit codes 5 / 6 / 2 / 1, the exact "What you can try" lines for
//! each case, and every printed command actually run (placeholders filled in). Also the
//! repair-probe contract: "repairable" (exit 5) only when `sigil mend` really repairs it,
//! a time limit (exit 6 when it runs out), no files written, and Warded Tomes never
//! showing member names.
//!
//! `scry_unseal_open_bitrot_all_shards_regression` fails on the code before this change
//! (there `scry` said `NOT recoverable`, exit 2, for a file `sigil mend` repairs).
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"));
    c.current_dir(dir).stdin(Stdio::null()).args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().expect("run sigil")
}

fn sigil(dir: &Path, args: &[&str]) -> Output {
    run(dir, args, &[])
}

fn all(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil(dir, args);
    assert!(o.status.success(), "{args:?}: {}", all(&o));
    all(&o)
}

/// The "What you can try" lines printed on stderr.
fn hints(o: &Output) -> Vec<String> {
    let e = String::from_utf8_lossy(&o.stderr);
    let Some((_, rest)) = e.split_once("\nWhat you can try:\n") else {
        return Vec::new();
    };
    rest.lines()
        .map_while(|l| l.strip_prefix("  - "))
        .map(str::to_string)
        .collect()
}

/// The JSON `hints` array of a `--json` failure line, decoded.
fn json_hints(o: &Output) -> Vec<String> {
    let j = String::from_utf8_lossy(&o.stdout);
    let Some((_, rest)) = j.split_once(",\"hints\":[") else {
        return Vec::new();
    };
    let body = &rest[..rest.find("]}").expect("end of hints")];
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    let mut esc = false;
    for ch in body.chars() {
        if inside {
            if esc {
                cur.push(ch);
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                inside = false;
                out.push(std::mem::take(&mut cur));
            } else {
                cur.push(ch);
            }
        } else if ch == '"' {
            inside = true;
        }
    }
    out
}

fn first_err_line(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

fn noise(n: usize, mut x: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Flip one bit in the middle of every shard: no shard passes its checksum (`live == 0`),
/// yet the deeper repair of `sigil mend` restores it.
fn flip_every_shard(sg1: &[u8]) -> Vec<u8> {
    let (h, prefix, _) = sigil::locate_header(sg1).expect("header");
    let sl = h.shard_len as usize;
    let mut out = sg1.to_vec();
    for i in 0..h.n as usize {
        out[prefix + i * (8 + sl) + 8 + sl / 2] ^= 0x01;
    }
    out
}

fn private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

/// Split a printed command line like a shell would (double quotes only; the hints never
/// use anything else).
fn words(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for ch in cmd.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The `sigil …` commands a hint line prints (after its first `: `, split at `, then `).
fn commands_in(line: &str) -> Vec<String> {
    let Some(i) = line.find(": sigil ") else {
        return Vec::new();
    };
    line[i + 2..]
        .split(", then ")
        .map(|c| c.trim().to_string())
        .collect()
}

/// Run every command printed in `lines`, with each `<placeholder>` replaced from `subs`.
/// Each must be accepted by the command-line parser (no usage error, no unknown
/// placeholder left). Returns `(command, output)` pairs for further checks.
fn run_hints(dir: &Path, lines: &[String], subs: &[(&str, &str)]) -> Vec<(String, Output)> {
    let mut ran = Vec::new();
    for line in lines {
        for cmd in commands_in(line) {
            let mut filled = cmd.clone();
            for (k, v) in subs {
                filled = filled.replace(k, v);
            }
            assert!(
                !filled.contains('<'),
                "placeholder left unfilled in {filled:?} (from {line:?})"
            );
            let w = words(&filled);
            assert_eq!(w[0], "sigil", "{filled}");
            let args: Vec<&str> = w[1..].iter().map(String::as_str).collect();
            let o = sigil(dir, &args);
            let e = String::from_utf8_lossy(&o.stderr);
            assert!(
                !e.contains("Usage: sigil")
                    && !e.contains("unexpected argument")
                    && !e.contains("unrecognized subcommand")
                    && !e.contains("invalid value"),
                "printed command is not valid: {filled}\n{}",
                all(&o)
            );
            ran.push((filled, o));
        }
    }
    ran
}

fn ran_ok(ran: &[(String, Output)], prefix: &str) -> bool {
    ran.iter()
        .any(|(c, o)| c.starts_with(prefix) && o.status.success())
}

const VAULT_LINE: &str = "If it is kept in a Vault, restore an earlier version: sigil vault versions <vault>, then sigil vault restore --version <N> <vault>";
const GATHER_LINE: &str = "If you kept .sgp pieces or Channel mana for it, rebuild from them: sigil gather <folder> -o <rebuilt.sg1>";
const FROST_LINE: &str = "If it is on Frost Rune drives, rebuild from them: sigil frost mend <frost-folder> -o <rebuilt.sg1>";
const COPY_AGAIN: &str =
    "Copy it again from where it came from (the original, a backup, or the sender)";

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn scry_unseal_open_bitrot_all_shards_regression() {
    let d = common::scratch("rec-bitrot");
    let data = noise(64 * 1024, 0x1234_5678_9abc_def0);
    fs::write(d.join("data.bin"), &data).unwrap();
    ok(&d, &["seal", "-o", "clean.sg1", "data.bin"]);
    let clean = fs::read(d.join("clean.sg1")).unwrap();
    fs::write(d.join("rot.sg1"), flip_every_shard(&clean)).unwrap();
    let (_, _, live, _, _) = sigil::verify(&fs::read(d.join("rot.sg1")).unwrap()).unwrap();
    assert_eq!(live, 0, "every shard fails its checksum");

    let want = s(&[
        "See what is damaged and how long a repair takes: sigil mend --scan rot.sg1",
        "Repair it into a new file (the original is kept): sigil mend rot.sg1",
        "Or open it with a one-off repair in memory: sigil unseal --repair -o <out-file> rot.sg1",
        "If you have another copy (backup, cloud, USB stick), combine them: sigil mend rot.sg1 <other-copy.sg1>",
    ]);
    let o = sigil(&d, &["scry", "rot.sg1"]);
    assert_eq!(o.status.code(), Some(5), "{}", all(&o));
    let t = all(&o);
    assert!(!t.contains("NOT recoverable"), "{t}");
    assert!(
        t.starts_with("damaged  v2  live=0/16"),
        "report marks it damaged: {t}"
    );
    assert!(
        first_err_line(&o)
            == "damaged — run sigil mend rot.sg1 (0 of 16 shards intact, 12 needed; the deeper repair restores it)",
        "{t}"
    );
    assert_eq!(hints(&o), want);

    // --json: one line, same fields as before plus the optional hints array.
    let o = sigil(&d, &["scry", "rot.sg1", "--json"]);
    assert_eq!(o.status.code(), Some(5), "{}", all(&o));
    let j = String::from_utf8_lossy(&o.stdout).to_string();
    assert_eq!(j.lines().count(), 1, "{j}");
    for key in [
        "{\"ok\":false,\"cmd\":\"scry\",\"exit\":5,\"error\":\"damaged — run sigil mend rot.sg1",
        "\"report\":",
        "\"status\":{\"schema\":1,\"kind\":\"mark\",\"health\":\"needs-repair\"",
    ] {
        assert!(j.contains(key), "{key} in {j}");
    }
    assert_eq!(json_hints(&o), want);
    assert!(hints(&o).is_empty(), "no human hint list in --json mode");

    // unseal / open: same verdict and the same next steps; nothing written.
    for args in [
        &["unseal", "rot.sg1", "-o", "out.bin"][..],
        &["open", "--keep", "rot.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(5), "{args:?}: {}", all(&o));
        assert!(
            first_err_line(&o).starts_with("Cannot open rot.sg1: damaged — run sigil mend rot.sg1"),
            "{}",
            all(&o)
        );
        assert_eq!(hints(&o), want, "{args:?}");
    }
    assert!(!d.join("out.bin").exists());

    // Every printed command runs; the repairs really repair.
    let ran = run_hints(
        &d,
        &want,
        &[
            ("<out-file>", "opened.bin"),
            ("<other-copy.sg1>", "clean.sg1"),
        ],
    );
    assert!(ran_ok(&ran, "sigil mend --scan rot.sg1"));
    assert!(ran_ok(&ran, "sigil mend rot.sg1"));
    assert!(ran_ok(&ran, "sigil unseal --repair"));
    assert_eq!(fs::read(d.join("opened.bin")).unwrap(), data);
    ok(&d, &["unseal", "rot.mended.sg1", "-o", "back.bin"]);
    assert_eq!(fs::read(d.join("back.bin")).unwrap(), data);
}

#[test]
fn unrecoverable_single_archive_hints_run_and_exit_2() {
    let d = common::scratch("rec-dead");
    let data = noise(64 * 1024, 0xfeed_face);
    fs::write(d.join("data.bin"), &data).unwrap();
    ok(&d, &["seal", "-o", "dead.sg1", "data.bin"]);
    // Backups the hints point to: pieces, Frost Rune drives, another copy.
    ok(&d, &["scatter", "dead.sg1", "-o", "pcs"]);
    ok(&d, &["frost", "place", "dead.sg1", "-o", "frost"]);
    fs::copy(d.join("dead.sg1"), d.join("backup.sg1")).unwrap();
    let mut b = fs::read(d.join("dead.sg1")).unwrap();
    let (a, z) = (b.len() * 25 / 100, b.len() * 90 / 100);
    b[a..z].fill(0);
    fs::write(d.join("dead.sg1"), &b).unwrap();

    let want = s(&[
        "If you have another copy (backup, cloud, USB stick), combine them: sigil mend dead.sg1 <other-copy.sg1>",
        GATHER_LINE,
        FROST_LINE,
        VAULT_LINE,
    ]);
    for args in [
        &["scry", "dead.sg1"][..],
        &["verify", "dead.sg1"][..],
        &["mend", "dead.sg1"][..],
        &["unseal", "dead.sg1", "-o", "nope.bin"][..],
        &["open", "--keep", "dead.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", all(&o));
        assert!(all(&o).contains("too damaged"), "{args:?}: {}", all(&o));
        assert_eq!(hints(&o), want, "{args:?}");
    }
    assert!(!d.join("nope.bin").exists());

    // Only the quick repair ran: the deeper one is offered first.
    let o = sigil(&d, &["mend", "--hard-only", "dead.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    let mut deeper = s(&["Try the deeper repair too (leave out --hard-only): sigil mend dead.sg1"]);
    deeper.extend(want.clone());
    assert_eq!(hints(&o), deeper);

    let ran = run_hints(
        &d,
        &want,
        &[
            ("<other-copy.sg1>", "backup.sg1"),
            ("<folder>", "pcs"),
            ("<frost-folder>", "frost"),
            ("<rebuilt.sg1>", "rebuilt.sg1"),
            ("<vault>", "no-such-vault"),
            ("<N>", "1"),
        ],
    );
    assert!(ran_ok(&ran, "sigil mend dead.sg1 backup.sg1"));
    assert!(ran_ok(&ran, "sigil gather pcs"));
    assert!(ran_ok(&ran, "sigil frost mend frost"));
    ok(&d, &["unseal", "rebuilt.sg1", "-o", "r.bin"]);
    assert_eq!(fs::read(d.join("r.bin")).unwrap(), data);
}

#[test]
fn keys_wrong_or_missing_exit_1_and_fail_closed() {
    let d = common::scratch("rec-ward");
    let data = noise(8192, 0xaaaa_1111);
    fs::write(d.join("sec.bin"), &data).unwrap();
    fs::write(d.join("good.pw"), "correct horse battery\n").unwrap();
    fs::write(d.join("bad.pw"), "wrong passphrase\n").unwrap();
    private(&d.join("good.pw"));
    private(&d.join("bad.pw"));
    ok(
        &d,
        &[
            "seal",
            "--pass-file",
            "good.pw",
            "-o",
            "locked.sg1",
            "sec.bin",
        ],
    );

    let wrong = s(&[
        "Check the passphrase and try again: type it when asked (--pass -) or give --pass-file <file>",
        "If it was Warded to a key, give that key: --identity <key.sgk> (or --talisman <file>)",
        "If it was Warded to several people, anyone on the list can open it with their own key",
        "A Ward has no reset: if the passphrase or key is lost, use an unencrypted backup or an earlier Vault version",
    ]);
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
        assert_eq!(o.status.code(), Some(1), "{args:?}: {}", all(&o));
        let t = all(&o);
        assert!(
            t.contains("Wrong passphrase or key — this Sigil Archive is Warded"),
            "{t}"
        );
        assert!(!t.contains("CEK") && !t.contains("damaged"), "{t}");
        assert_eq!(hints(&o), wrong, "{args:?}");
    }
    let o = sigil(&d, &["unseal", "-o", "out.bin", "locked.sg1"]);
    assert_eq!(o.status.code(), Some(1), "{}", all(&o));
    assert!(all(&o).contains("passphrase or --identity required — this Sigil Archive is Warded"));
    assert_eq!(
        hints(&o),
        s(&[
            "Give the passphrase: type it when asked (--pass -) or give --pass-file <file>",
            "If it was Warded to a key, give that key: --identity <key.sgk> (or --talisman <file>)",
        ])
    );
    assert!(!d.join("out.bin").exists());

    // The flags the hints name exist on unseal (a usage error would print "Usage:").
    for extra in [
        &["--pass-file", "good.pw"][..],
        &["--identity", "missing.sgk"][..],
        &["--talisman", "missing.talisman"][..],
        &["--pass", "-"][..],
    ] {
        let mut args = vec!["unseal", "-o", "flag.bin"];
        args.extend_from_slice(extra);
        args.push("locked.sg1");
        let o = sigil(&d, &args);
        assert!(!all(&o).contains("Usage: sigil"), "{extra:?}: {}", all(&o));
    }
    assert_eq!(
        fs::read(d.join("flag.bin")).unwrap(),
        data,
        "--pass-file opens it"
    );

    // Tamper beyond the checksums: fails closed even with the right key; no output.
    let mut t = fs::read(d.join("locked.sg1")).unwrap();
    let mid = t.len() / 2;
    for b in &mut t[mid..mid + 4000] {
        *b ^= 0xff;
    }
    fs::write(d.join("tampered.sg1"), t).unwrap();
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
fn tome_member_rot_dead_member_and_truncation() {
    let d = common::scratch("rec-tome");
    fs::create_dir_all(d.join("box")).unwrap();
    let alpha = b"alpha intact content\n".to_vec();
    let beta = noise(60_000, 0x5555_2222);
    fs::write(d.join("box/alpha.txt"), &alpha).unwrap();
    fs::write(d.join("box/beta.bin"), &beta).unwrap();
    ok(&d, &["seal", "-o", "tome.sg1", "box"]);
    let raw = fs::read(d.join("tome.sg1")).unwrap();
    let star = sigil::read_dir_entry_star(&d.join("tome.sg1"), "beta.bin").unwrap();
    let at = raw
        .windows(star.len())
        .position(|w| w == star.as_slice())
        .unwrap();

    // beta.bin: bit rot that `sigil mend` repairs.
    let mut rot = raw.clone();
    rot[at..at + star.len()].copy_from_slice(&flip_every_shard(&star));
    fs::write(d.join("tome-rot.sg1"), &rot).unwrap();
    let want = s(&[
        "Repair it into a new file (the original is kept): sigil mend tome-rot.sg1",
        "Get the undamaged files out now (one --only per file): sigil unseal --only alpha.txt -o <out-folder> tome-rot.sg1",
        "Undamaged files (1): alpha.txt",
    ]);
    for args in [
        &["scry", "tome-rot.sg1"][..],
        &["unseal", "tome-rot.sg1", "-o", "out-rot"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(5), "{args:?}: {}", all(&o));
        assert!(
            all(&o).contains("damaged — run sigil mend tome-rot.sg1"),
            "{}",
            all(&o)
        );
        assert_eq!(hints(&o), want, "{args:?}");
    }
    let ran = run_hints(&d, &want, &[("<out-folder>", "rescued-rot")]);
    assert!(ran_ok(&ran, "sigil mend tome-rot.sg1"));
    assert_eq!(fs::read(d.join("rescued-rot/alpha.txt")).unwrap(), alpha);
    ok(&d, &["unseal", "tome-rot.mended.sg1", "-o", "out-fixed"]);
    assert_eq!(fs::read(d.join("out-fixed/beta.bin")).unwrap(), beta);

    // beta.bin destroyed; alpha.txt still comes out.
    let mut dead = raw.clone();
    dead[at + star.len() / 5..at + star.len() * 9 / 10].fill(0);
    fs::write(d.join("tome-dead.sg1"), &dead).unwrap();
    let want = s(&[
        "Get the undamaged files out now (one --only per file): sigil unseal --only alpha.txt -o <out-folder> tome-dead.sg1",
        "Undamaged files (1): alpha.txt",
        GATHER_LINE,
        FROST_LINE,
        VAULT_LINE,
        COPY_AGAIN,
    ]);
    for args in [
        &["scry", "tome-dead.sg1"][..],
        &["mend", "tome-dead.sg1"][..],
        &["unseal", "tome-dead.sg1", "-o", "out-dead"][..],
        &["open", "--keep", "tome-dead.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", all(&o));
        let t = all(&o);
        assert!(
            t.contains("beta.bin") && !t.contains("folder pack"),
            "{args:?}: {t}"
        );
        assert_eq!(hints(&o), want, "{args:?}");
    }
    let ran = run_hints(
        &d,
        &want,
        &[
            ("<out-folder>", "rescued"),
            ("<folder>", "no-pieces"),
            ("<frost-folder>", "no-frost"),
            ("<rebuilt.sg1>", "rebuilt.sg1"),
            ("<vault>", "no-vault"),
            ("<N>", "1"),
        ],
    );
    assert!(ran_ok(&ran, "sigil unseal --only alpha.txt"));
    assert_eq!(fs::read(d.join("rescued/alpha.txt")).unwrap(), alpha);

    // Cut short: plain wording, never offers extraction (the framing is gone).
    fs::write(d.join("tome-cut.sg1"), &raw[..raw.len() - 400]).unwrap();
    let want = s(&[
        "This copy is cut short: copy it again from where it came from (the original, a backup, or the sender)",
        GATHER_LINE,
        FROST_LINE,
        VAULT_LINE,
    ]);
    for args in [
        &["scry", "tome-cut.sg1"][..],
        &["mend", "tome-cut.sg1"][..],
        &["unseal", "tome-cut.sg1", "-o", "out-cut"][..],
        &["open", "--keep", "tome-cut.sg1"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", all(&o));
        let t = all(&o);
        assert!(t.contains("truncated Tome"), "{args:?}: {t}");
        assert!(
            !t.contains("star bytes") && !t.contains("folder pack"),
            "{args:?}: {t}"
        );
        assert_eq!(hints(&o), want, "{args:?}");
    }
}

#[test]
fn warded_tome_never_shows_member_names() {
    let d = common::scratch("rec-warded-names");
    let secret = "Quarterly-Layoff-Plan-ZX81.txt";
    fs::create_dir_all(d.join("vaultdir")).unwrap();
    fs::write(d.join("vaultdir").join(secret), noise(50_000, 0x77)).unwrap();
    fs::write(d.join("pw"), "tome-secret\n").unwrap();
    fs::write(d.join("wrong"), "nope\n").unwrap();
    private(&d.join("pw"));
    private(&d.join("wrong"));
    ok(
        &d,
        &["seal", "--pass-file", "pw", "-o", "w.sg1", "vaultdir"],
    );
    let raw = fs::read(d.join("w.sg1")).unwrap();
    let (_, body) = sigil::sealed_dir_body(&d.join("w.sg1")).unwrap().unwrap();
    let at = raw
        .windows(body.len())
        .position(|w| w == body.as_slice())
        .unwrap();

    let mut rot = raw.clone();
    rot[at..at + body.len()].copy_from_slice(&flip_every_shard(&body));
    fs::write(d.join("w-rot.sg1"), &rot).unwrap();
    let mut dead = raw.clone();
    dead[at + body.len() / 5..at + body.len() * 9 / 10].fill(0);
    fs::write(d.join("w-dead.sg1"), &dead).unwrap();
    fs::write(d.join("w-cut.sg1"), &raw[..raw.len() - 300]).unwrap();

    for f in ["w.sg1", "w-rot.sg1", "w-dead.sg1", "w-cut.sg1"] {
        for args in [
            vec!["scry", f],
            vec!["scry", "--json", f],
            vec!["verify", f],
            vec!["scry", "--pass-file", "wrong", f],
            vec!["unseal", "-o", "o1", f],
            vec!["unseal", "--pass-file", "wrong", "-o", "o2", f],
            vec!["open", "--pass-file", "wrong", "--keep", f],
            vec!["mend", "-o", "m.sg1", f],
            vec!["mend", "--json", "-o", "m2.sg1", f],
        ] {
            let o = sigil(&d, &args);
            let t = all(&o);
            assert!(!t.contains(secret), "{args:?} leaked a member name: {t}");
            assert!(!t.contains("Layoff"), "{args:?}: {t}");
        }
        let _ = fs::remove_file(d.join("m.sg1"));
        let _ = fs::remove_file(d.join("m2.sg1"));
    }
    // With the right key on damaged copies: still no name in any failure text.
    for f in ["w-rot.sg1", "w-dead.sg1", "w-cut.sg1"] {
        let o = sigil(&d, &["unseal", "--pass-file", "pw", "-o", "o3", f]);
        assert!(!o.status.success(), "{f}: {}", all(&o));
        assert!(!all(&o).contains(secret), "{f}: {}", all(&o));
    }

    // Bit rot only the deeper repair can fix: `sigil mend` runs the deeper repair on a
    // Warded Tome's body (as on a single .sg1), so scry promises the repair (exit 5),
    // mend delivers it, and `--hard-only` still refuses (exit 2, nothing written).
    let o = sigil(&d, &["scry", "w-rot.sg1"]);
    assert_eq!(o.status.code(), Some(5), "{}", all(&o));
    assert!(!all(&o).contains(secret), "{}", all(&o));
    let o = sigil(&d, &["mend", "--hard-only", "-o", "mh.sg1", "w-rot.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(!d.join("mh.sg1").exists());
    let o = sigil(&d, &["mend", "-o", "m.sg1", "w-rot.sg1"]);
    assert_eq!(o.status.code(), Some(0), "{}", all(&o));
    assert!(!all(&o).contains(secret), "{}", all(&o));
    let o = sigil(&d, &["unseal", "--pass-file", "pw", "-o", "o4", "m.sg1"]);
    assert!(o.status.success(), "{}", all(&o));
    let o = sigil(&d, &["unseal", "--pass-file", "pw", "-o", "o5", "w.sg1"]);
    assert!(o.status.success(), "{}", all(&o));
    assert_eq!(
        fs::read(d.join("o4").join(secret)).unwrap(),
        fs::read(d.join("o5").join(secret)).unwrap()
    );
}

#[test]
fn probe_time_limit_gives_exit_6_and_bad_setting_is_refused() {
    let d = common::scratch("rec-probe-off");
    fs::write(d.join("data.bin"), noise(64 * 1024, 0x42)).unwrap();
    ok(&d, &["seal", "-o", "c.sg1", "data.bin"]);
    fs::write(
        d.join("rot.sg1"),
        flip_every_shard(&fs::read(d.join("c.sg1")).unwrap()),
    )
    .unwrap();
    let off = [("SIGIL_SCRY_PROBE_SECS", "0")];
    let o = run(&d, &["scry", "rot.sg1"], &off);
    assert_eq!(o.status.code(), Some(6), "{}", all(&o));
    assert!(
        first_err_line(&o)
            .starts_with("damaged — run sigil mend rot.sg1 to find out whether it can be repaired"),
        "{}",
        all(&o)
    );
    assert!(
        all(&o).contains("repair check turned off by SIGIL_SCRY_PROBE_SECS=0"),
        "{}",
        all(&o)
    );
    // Not confirmed: no promise of a one-off repair.
    assert_eq!(
        hints(&o),
        s(&[
            "See what is damaged and how long a repair takes: sigil mend --scan rot.sg1",
            "Repair it into a new file (the original is kept): sigil mend rot.sg1",
            "If you have another copy (backup, cloud, USB stick), combine them: sigil mend rot.sg1 <other-copy.sg1>",
        ])
    );
    let o = run(&d, &["unseal", "rot.sg1", "-o", "x.bin"], &off);
    assert_eq!(o.status.code(), Some(6), "{}", all(&o));
    let o = run(&d, &["scry", "--json", "rot.sg1"], &off);
    assert!(String::from_utf8_lossy(&o.stdout).contains("\"exit\":6"));
    assert!(String::from_utf8_lossy(&o.stdout).contains("\"health\":\"needs-repair\""));

    let o = run(
        &d,
        &["scry", "rot.sg1"],
        &[("SIGIL_SCRY_PROBE_SECS", "soon")],
    );
    assert_eq!(o.status.code(), Some(1), "{}", all(&o));
    assert!(all(&o).contains("SIGIL_SCRY_PROBE_SECS"), "{}", all(&o));
}

#[cfg(unix)]
#[test]
fn probe_writes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let d = common::scratch("rec-ro");
    fs::create_dir_all(d.join("ro")).unwrap();
    fs::create_dir_all(d.join("tmp")).unwrap();
    fs::write(d.join("data.bin"), noise(64 * 1024, 0x99)).unwrap();
    ok(&d, &["seal", "-o", "c.sg1", "data.bin"]);
    fs::write(
        d.join("ro/rot.sg1"),
        flip_every_shard(&fs::read(d.join("c.sg1")).unwrap()),
    )
    .unwrap();
    fs::set_permissions(d.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
    let tmp = d.join("tmp");
    let env = [("TMPDIR", tmp.to_str().unwrap())];
    let o = run(&d.join("ro"), &["scry", "rot.sg1"], &env);
    let o2 = run(&d.join("ro"), &["unseal", "rot.sg1", "-o", "-"], &env);
    fs::set_permissions(d.join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(o.status.code(), Some(5), "{}", all(&o));
    assert_eq!(o2.status.code(), Some(5), "{}", all(&o2));
    let names: Vec<_> = fs::read_dir(d.join("ro")).unwrap().flatten().collect();
    assert_eq!(names.len(), 1, "only the archive: {names:?}");
    assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0, "nothing in TMPDIR");
}

#[test]
fn channel_pieces_and_frost_shortage_hints_run() {
    let d = common::scratch("rec-chan-frost");
    let data = noise(64 * 1024, 0x9999_8888);
    fs::write(d.join("file.bin"), &data).unwrap();
    ok(&d, &["seal", "-o", "file.sg1", "file.bin"]);

    // Channel mana short.
    ok(
        &d,
        &[
            "deluge",
            "--channel",
            "--extra",
            "2",
            "file.sg1",
            "-o",
            "mana",
        ],
    );
    let mut mana: Vec<_> = fs::read_dir(d.join("mana"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("mana"))
        .collect();
    mana.sort();
    for p in mana.iter().take(6) {
        fs::remove_file(p).unwrap();
    }
    let o = sigil(&d, &["gather", "mana", "-o", "rebuilt.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(all(&o).contains("not enough mana yet"), "{}", all(&o));
    let want = s(&[
        "Make a one-line report of what is missing: sigil gather --report mana",
        "Send that line to the sender, who runs: sigil deluge --channel <file.sg1> --answer \"<report-line>\" -o <mana-folder>",
        "Or ask the sender for more mana: sigil deluge --channel <file.sg1> --extra <N> -o <mana-folder>",
        "Save a progress receipt (no archive is written): sigil gather --partial -o <rebuilt.sg1> mana",
    ]);
    assert_eq!(hints(&o), want);
    let o = sigil(&d, &["gather", "--partial", "mana", "-o", "rebuilt.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert_eq!(
        hints(&o),
        want[..3].to_vec(),
        "receipt already saved: not offered again"
    );
    // Run them: the report line, answered by the sender, completes the rebuild.
    let report = ok(&d, &["gather", "--report", "mana"]);
    let line = report.lines().next().unwrap().trim().to_string();
    let ran = run_hints(
        &d,
        &want,
        &[
            ("<file.sg1>", "file.sg1"),
            ("<report-line>", &line),
            ("<mana-folder>", "mana"),
            ("<N>", "2"),
            ("<rebuilt.sg1>", "partial.sg1"),
        ],
    );
    assert!(ran_ok(&ran, "sigil deluge --channel file.sg1 --answer"));
    ok(&d, &["gather", "mana", "-o", "rebuilt.sg1"]);
    ok(&d, &["unseal", "rebuilt.sg1", "-o", "r1.bin"]);
    assert_eq!(fs::read(d.join("r1.bin")).unwrap(), data);

    // .sgp pieces short.
    ok(&d, &["scatter", "file.sg1", "-o", "pcs"]);
    fs::create_dir_all(d.join("spare")).unwrap();
    let mut sgp: Vec<_> = fs::read_dir(d.join("pcs"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("sgp"))
        .collect();
    sgp.sort();
    for p in sgp.iter().take(6) {
        fs::rename(p, d.join("spare").join(p.file_name().unwrap())).unwrap();
    }
    let o = sigil(&d, &["gather", "pcs", "-o", "rebuilt2.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    let want = s(&[
        "Add more .sgp pieces to the folder (another drive, or ask the sender), then run: sigil gather pcs -o <rebuilt.sg1>",
        FROST_LINE,
        VAULT_LINE,
    ]);
    assert_eq!(hints(&o), want);
    for p in fs::read_dir(d.join("spare")).unwrap().flatten() {
        fs::rename(p.path(), d.join("pcs").join(p.file_name())).unwrap();
    }
    let ran = run_hints(&d, &want[..1], &[("<rebuilt.sg1>", "rebuilt2.sg1")]);
    assert!(ran_ok(&ran, "sigil gather pcs"));

    // Frost Rune short on usb-* drives.
    ok(&d, &["frost", "place", "file.sg1", "-o", "frost"]);
    fs::rename(d.join("frost/usb-0"), d.join("usb-0-elsewhere")).unwrap();
    fs::rename(d.join("frost/usb-1"), d.join("usb-1-elsewhere")).unwrap();
    let o = sigil(&d, &["frost", "mend", "frost", "-o", "frost-back.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(
        all(&o).contains("Not enough Frost Rune pieces to rebuild"),
        "{}",
        all(&o)
    );
    let want = s(&[
        "Copy the usb-* folder from another drive of this Frost Rune set into frost, then run: sigil frost mend frost -o <rebuilt.sg1>",
        GATHER_LINE,
        VAULT_LINE,
    ]);
    assert_eq!(hints(&o), want);
    assert!(!d.join("frost-back.sg1").exists());
    fs::rename(d.join("usb-0-elsewhere"), d.join("frost/usb-0")).unwrap();
    fs::rename(d.join("usb-1-elsewhere"), d.join("frost/usb-1")).unwrap();
    let ran = run_hints(&d, &want[..1], &[("<rebuilt.sg1>", "frost-back.sg1")]);
    assert!(ran_ok(&ran, "sigil frost mend frost"));

    // Not a shortage (no such folder): the plain error and its own exit code, no hints.
    let o = sigil(&d, &["gather", "no-such-folder", "-o", "x.sg1"]);
    assert_eq!(o.status.code(), Some(1), "{}", all(&o));
    assert!(hints(&o).is_empty());
}

#[test]
fn large_file_archive_hints_run() {
    let d = common::scratch("rec-work");
    let big = noise(5_000_000, 0x3333_4444);
    fs::write(d.join("big.bin"), &big).unwrap();
    ok(&d, &["seal", "-o", "big.sg1", "big.bin"]);
    assert!(sigil::is_work_pack(&d.join("big.sg1")));
    let mut pack = fs::read(d.join("big.sg1")).unwrap();
    let (_, locs) = sigil::index_pack(&d.join("big.sg1")).unwrap();
    let (o0, l0) = (locs[0].file_off as usize, locs[0].star_len as usize);
    let rot = flip_every_shard(&pack[o0..o0 + l0]);
    pack[o0..o0 + l0].copy_from_slice(&rot);
    fs::write(d.join("big-rot.sg1"), &pack).unwrap();

    let o = sigil(&d, &["scry", "big-rot.sg1"]);
    assert_eq!(o.status.code(), Some(5), "{}", all(&o));
    let want = s(&[
        "See what is damaged and how long a repair takes: sigil mend --scan big-rot.sg1",
        "Repair it into a new file (the original is kept): sigil mend big-rot.sg1",
    ]);
    assert_eq!(hints(&o), want);
    let ran = run_hints(&d, &want, &[]);
    assert!(ran_ok(&ran, "sigil mend --scan"));
    assert!(ran_ok(&ran, "sigil mend big-rot.sg1"));
    ok(&d, &["unseal", "big-rot.mended.sg1", "-o", "back.bin"]);
    assert_eq!(fs::read(d.join("back.bin")).unwrap(), big);
}

/// Damage a seal at random (seeded): flipped bits, zeroed runs, a cut-off tail.
fn damage(seal: &[u8], seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = |m: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % m.max(1) as u64) as usize
    };
    let (h, prefix, _) = sigil::locate_header(seal).expect("header");
    let sl = h.shard_len as usize;
    let mut out = seal.to_vec();
    match seed % 4 {
        // Bit rot in a random number of shards, at random places.
        0 | 1 => {
            let hit = 1 + next(h.n as usize);
            for _ in 0..hit {
                let i = next(h.n as usize);
                for _ in 0..1 + next(4) {
                    out[prefix + i * (8 + sl) + 8 + next(sl)] ^= 1 << next(8);
                }
            }
        }
        // A zeroed run of random length anywhere after the header.
        2 => {
            let a = prefix + next(out.len() - prefix);
            let z = (a + 1 + next(out.len() / 2)).min(out.len());
            out[a..z].fill(0);
        }
        // Cut off at a random point.
        _ => out.truncate(prefix + next(out.len() - prefix)),
    }
    out
}

/// Property: "repairable" exactly when `sigil mend`'s repair succeeds and restores the
/// original bytes; "opens as-is" exactly when it opens; "not recoverable" never when the
/// repair would have worked.
#[test]
fn verdict_matches_what_mend_and_unseal_do() {
    use sigil::recovery::{assess_seal, Condition, MendMode, ProbeBudget};
    let data = noise(30_000, 0xabcdef);
    let clean = sigil::seal(&data, sigil::Mode::Reflection, None, "p.bin", false).unwrap();
    let mut seen = [0usize; 3];
    for seed in 0..48u64 {
        let bad = damage(&clean, seed);
        let mut budget = ProbeBudget::with_secs(60);
        let c = assess_seal(&bad, MendMode::Deep, &mut budget);
        let mended = sigil::mend_bytes_ex(&bad, true)
            .ok()
            .filter(|(h, _)| matches!(sigil::verify(h), Ok((_, true, _, _, false))));
        let opens = sigil::unseal(&bad, None)
            .map(|b| b == data)
            .unwrap_or(false);
        match &c {
            Condition::Healthy | Condition::Torn(_) => {
                seen[0] += 1;
                assert!(opens, "seed {seed}: {c:?} but it does not open");
            }
            Condition::Repairable(_) => {
                seen[1] += 1;
                assert!(!opens, "seed {seed}: opens as-is, so not 'damaged'");
                let (h, _) = mended
                    .as_ref()
                    .unwrap_or_else(|| panic!("seed {seed}: called repairable, but mend fails"));
                assert_eq!(sigil::unseal(h, None).unwrap(), data, "seed {seed}");
            }
            Condition::Unrecoverable(_) => {
                seen[2] += 1;
                assert!(!opens, "seed {seed}");
                assert!(mended.is_none(), "seed {seed}: mend works, verdict says no");
            }
            Condition::Unconfirmed { .. } => {
                panic!("seed {seed}: a 60 s budget answers on a 30 KB seal: {c:?}");
            }
        }
    }
    assert!(
        seen[0] > 0 && seen[1] > 0 && seen[2] > 0,
        "cases covered: {seen:?}"
    );
}

/// The CLI side of the same contract: exit 5 from scry means `sigil mend` exits 0.
#[test]
fn scry_exit_5_means_mend_succeeds() {
    let d = common::scratch("rec-prop-cli");
    let data = noise(30_000, 0x5eed);
    let clean = sigil::seal(&data, sigil::Mode::Reflection, None, "p.bin", false).unwrap();
    let mut fives = 0;
    for seed in 0..16u64 {
        let f = format!("s{seed}.sg1");
        fs::write(d.join(&f), damage(&clean, seed)).unwrap();
        let o = sigil(&d, &["scry", &f]);
        let code = o.status.code();
        let m = sigil(&d, &["mend", &f, "-o", &format!("m{seed}.sg1")]);
        match code {
            Some(5) => {
                fives += 1;
                assert!(m.status.success(), "seed {seed}: {}\n{}", all(&o), all(&m));
            }
            Some(2) => assert_eq!(m.status.code(), Some(2), "seed {seed}: {}", all(&m)),
            _ => {}
        }
    }
    assert!(fives > 0);
}
