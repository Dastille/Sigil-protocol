use clap::{Parser, Subcommand, ValueEnum};
use sigil::{
    add_to_constellation, attest, backend_by_name, copy_sigil_binary, deluge_pieces,
    format_bakeoff_report, gather_pieces, hex32, inject_initrd, inscribe_dir_to,
    inscribe_dir_to_names_visible, inscribe_path_to, inscribe_stars_dir_to, install_hooks,
    is_constellation_input, is_dir_pack, is_fountain_dir, keygen_ecc, keygen_legacy, mend_boot,
    mend_bytes_ex, mend_kit, mend_scan, overture_report, path_extract_keys, path_walk_keys,
    place_kit, prepare_boot, resolve_recipient, run_bakeoff, run_mount_keys, run_open_keys,
    run_showing, scatter_pieces, seal_kn_mds_to, sha256, sha256_path, talisman_pass, tally_pieces,
    umount_path, unseal_dir_only_keys, unseal_ex, unseal_ex_mds_keys, unseal_path_keys,
    unseal_range_keys, vault_commit_ex, vault_commit_from_export_ex, vault_format_recipients,
    vault_format_retention, vault_format_status, vault_format_versions, vault_get_recipients,
    vault_get_retention, vault_list_versions, vault_maybe_prune_after_commit, vault_prune_with,
    vault_restore_ex, vault_set_recipients, vault_set_retention, vault_status, vault_track_ex,
    vessel_present, write_vessel, AddOpts, BootOutcome, CdcProfile, Identity, Mode, VaultRetention,
    CDC_DEDUP, CDC_MEDIA, DEFAULT_CHUNK, MAX_NEST_DEPTH, OVERTURE, VESSEL,
};
use std::fs;
use std::io::Read;

/// When set, human status lines go to stderr so stdout stays clean (`--json`, `-o -`).
static HUMAN_TO_STDERR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Extra fields (already JSON, each starting with `,`) for the `--json` result line.
static JSON_EXTRA: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

/// A human status line: stdout normally, stderr when stdout carries data or JSON.
macro_rules! say {
    ($($t:tt)*) => {
        if HUMAN_TO_STDERR.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!($($t)*);
        } else {
            println!($($t)*);
        }
    };
}

fn json_extra(field: &str) {
    if let Ok(mut g) = JSON_EXTRA.lock() {
        g.push_str(field);
    }
}

/// A JSON string literal.
fn jq(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// `sigil seal - -o X`: stdin copied into a private temp folder beside X (so a large
/// pipe takes the normal large-file path), removed again when the seal ends.
struct StdinStage {
    dir: PathBuf,
    file: PathBuf,
}

impl StdinStage {
    fn from_input(
        input: &Path,
        output: &Path,
        name: Option<&str>,
    ) -> Result<Option<StdinStage>, Box<dyn std::error::Error>> {
        if input.as_os_str() != "-" {
            if name.is_some() {
                return Err("--stdin-name is only for `sigil seal -` (data on stdin)".into());
            }
            return Ok(None);
        }
        if output.as_os_str() == "-" {
            return Err(
                "seal writes a mark file: give -o PATH (stdout output is not supported)".into(),
            );
        }
        {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                return Err("`sigil seal -` reads data from a pipe, but stdin is a terminal. Try: some-command | sigil seal - -o out.sg1".into());
            }
        }
        let name = name.unwrap_or("stdin");
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name == "."
            || name == ".."
        {
            return Err("--stdin-name must be a plain file name (no slashes)".into());
        }
        let parent = match output.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let leaf = output
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "mark".into());
        let dir = parent.join(format!(".{leaf}.stdin-{}", std::process::id()));
        let mut b = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&dir)?;
        let stage = StdinStage {
            file: dir.join(name),
            dir,
        };
        let n = {
            let mut f = fs::File::create(&stage.file)?;
            std::io::copy(&mut std::io::stdin().lock(), &mut f)?
        };
        if n == 0 {
            return Err(
                "stdin was empty: refusing to seal nothing (did the command before the pipe fail?)"
                    .into(),
            );
        }
        Ok(Some(stage))
    }
}

impl Drop for StdinStage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.file);
        let _ = fs::remove_dir(&self.dir);
    }
}

/// `sigil unseal X -o -`: one file's original bytes to stdout. A large-file pack is
/// streamed one checked part at a time; if a later part fails the exit code is non-zero
/// (treat the output as incomplete).
fn unseal_to_stdout(
    input: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
    star: Option<u32>,
    from_mb: Option<u32>,
    to_mb: Option<u32>,
) -> Result<u64, Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    if sigil::is_work_pack(input) {
        let (head, locs) = sigil::index_pack_keys(input, pass, companions, identities)?;
        let mib =
            |mb: u32| ((u64::from(mb) * 1024 * 1024) / u64::from(head.chunk_size.max(1))) as u32;
        let from = star.or(from_mb.map(mib)).unwrap_or(0);
        let to = star
            .or(to_mb.map(mib))
            .unwrap_or(head.stars.saturating_sub(1));
        let mut n = 0u64;
        let mut want = from;
        for loc in locs.iter().filter(|l| l.index >= from && l.index <= to) {
            if loc.index != want {
                return Err(format!("work pack incomplete: part {want} is missing").into());
            }
            let plain = sigil::unseal_star_at_keys(input, loc, pass, companions, identities)?;
            out.write_all(&plain)?;
            n += plain.len() as u64;
            want += 1;
        }
        if want <= to && want < head.stars {
            return Err(format!("work pack incomplete: part {want} is missing").into());
        }
        out.flush()?;
        return Ok(n);
    }
    if star.is_some() || from_mb.is_some() || to_mb.is_some() {
        return Err("--star / --from-mb / --to-mb are for a large-file pack".into());
    }
    let data = fs::read(input)?;
    let plain = sigil::unseal_ex_keys(&data, pass, companions, identities)?;
    out.write_all(&plain)?;
    out.flush()?;
    Ok(plain.len() as u64)
}

/// `--json` result context: (command, output path) when the parsed command asked for it.
fn json_ctx(cmd: &Cmd) -> Option<(&'static str, Option<PathBuf>)> {
    match cmd {
        Cmd::Seal {
            json: true, output, ..
        } => Some(("seal", Some(output.clone()))),
        Cmd::Unseal {
            json: true, output, ..
        } => Some(("unseal", Some(output.clone()))),
        Cmd::Verify { json: true, .. } => Some(("verify", None)),
        Cmd::Gather {
            json: true, output, ..
        } => Some(("gather", output.clone())),
        _ => None,
    }
}
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(
    name = "sigil",
    version = concat!(env!("CARGO_PKG_VERSION"), " (commit ", env!("SIGIL_GIT_COMMIT"), ")"),
    about = "Wrap a file so a damaged copy can still be restored, and so you can tell if it was swapped.",
    long_about = "Inscribe makes a .sg1. Scry checks it without unpacking. De-scribe gets the original back.\nDefault lock style is Reflection (~1.3× size, ~25% repair). Seal is opt-in for worse damage.\nFriendly start page (recipes + guide links): docs/START.md in the repo.\nGitHub: tag v1.0 yourself — this tool does not log in for you.",
    after_long_help = "See docs/START.md in the repo for a plain-English map of everyday commands."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Inscribe a file or a folder. Optional Dispatch after pack.
    #[command(visible_alias = "inscribe")]
    Seal {
        /// File or folder to wrap, or `-` to read the data from stdin (a pipe)
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// With `-` input: the name stored inside the mark (default `stdin`)
        #[arg(long = "stdin-name", value_name = "NAME")]
        stdin_name: Option<String>,
        /// Machine-readable result on stdout (one JSON line); human lines go to stderr
        #[arg(long)]
        json: bool,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        /// USB/file key (Talisman). Hex of its hash becomes the Ward. Instead of --pass.
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Encrypt-to recipient: .pub / .sgk / OpenPGP cv25519 .asc / hex X25519 pk (repeatable). Implies encrypted.
        /// Alone is enough; with --pass, either passphrase OR matching --identity opens.
        #[arg(long = "to")]
        to: Vec<String>,
        /// Per-file password inside a folder wrap: --ward photos/cat.jpg=secret (repeatable).
        /// Needs --pass or --to as well, so the file names stay hidden.
        #[arg(long = "ward")]
        ward: Vec<String>,
        /// Per-file password from a file, like --pass-file: --ward-file photos/cat.jpg=PWFILE
        /// (repeatable; first line, owner-only permissions). Keeps it off the command line.
        #[arg(long = "ward-file", value_name = "PATH=PWFILE")]
        ward_file: Vec<String>,
        /// Opt-in (less safe): allow --ward without --pass / --to. File names and sizes in the
        /// pack are then readable without any key; only the warded files' contents are locked.
        #[arg(long = "ward-names-visible")]
        ward_names_visible: bool,
        #[arg(long)]
        covenant: Option<String>,
        #[arg(long = "bind")]
        bind: Vec<PathBuf>,
        #[arg(long, default_value_t = DEFAULT_CHUNK)]
        chunk: u32,
        /// Target size of one part in MiB (auto count). Default 4.
        #[arg(long, default_value_t = 4)]
        piece_mb: u32,
        /// Force number of parts (16–254). Overrides auto.
        #[arg(long)]
        shards: Option<u8>,
        /// First this many MiB are the boot (Overture). Copy those first; Play can start. 0 = whole file.
        #[arg(long, default_value_t = sigil::DEFAULT_OVERTURE_MB)]
        overture_mb: u32,
        /// Opt-in FastCDC chunking: `media` (1/4/8 MiB) or `dedup` (256KiB/1/4 MiB). Default = fixed 4 MiB.
        #[arg(long, value_enum)]
        cdc: Option<CdcArg>,
        /// MDS backend: vandermonde (default) or cauchy (opt-in after bake-off win). Env SIGIL_MDS.
        /// Cauchy is experimental (no header marker) — De-scribe with the same --mds. Single-star .sg1 only.
        #[arg(long, default_value = "vandermonde")]
        mds: String,
        #[arg(long)]
        pieces: Option<PathBuf>,
        /// rsync destination, e.g. user@host:/backup/  (your usual truck)
        #[arg(long)]
        rsync: Option<String>,
        /// rclone destination, e.g. remote:bucket/path
        #[arg(long)]
        rclone: Option<String>,
        /// run `wormhole send` on the mark (needs magic-wormhole installed)
        #[arg(long)]
        wormhole: bool,
    },
    #[command(visible_aliases = ["de-scribe", "describe"])]
    Unseal {
        input: PathBuf,
        /// Where to write; `-` streams one file's bytes to stdout
        #[arg(short, long)]
        output: PathBuf,
        /// Machine-readable result on stdout (one JSON line); not with `-o -`
        #[arg(long)]
        json: bool,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity file (.sgk) to unwrap encrypt-to CEK (repeatable). Tried before failing passphrase-required.
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        #[arg(long = "ward")]
        ward: Vec<String>,
        /// Per-file password from a file, like --pass-file: --ward-file photos/cat.jpg=PWFILE
        /// (repeatable; first line, owner-only permissions). Keeps it off the command line.
        #[arg(long = "ward-file", value_name = "PATH=PWFILE")]
        ward_file: Vec<String>,
        #[arg(long = "bind")]
        bind: Vec<PathBuf>,
        /// Pull only these paths out of a folder wrap (repeatable). e.g. --only photos/cat.jpg
        #[arg(long = "only")]
        only: Vec<String>,
        /// Work pack: only this slice number (0-based)
        #[arg(long)]
        star: Option<u32>,
        /// Work pack: start at this payload offset (MiB)
        #[arg(long)]
        from_mb: Option<u32>,
        /// Work pack: stop at this payload offset (MiB)
        #[arg(long)]
        to_mb: Option<u32>,
        /// Must match Inscribe --mds when Cauchy was used. Env SIGIL_MDS.
        #[arg(long, default_value = "vandermonde")]
        mds: String,
        /// Opt-in: if the mark will not open, repair scattered bit flips in memory (same
        /// salvage as `mend --soft`, Merkle + true name checked) and open that. Writes no
        /// mended file; output is written only on success. Plain .sg1 only.
        #[arg(long)]
        repair: bool,
    },
    Verify {
        input: PathBuf,
        /// Machine-readable result on stdout (one JSON line)
        #[arg(long)]
        json: bool,
        /// Deep read: open every part to the original bytes (decrypt + true-name check)
        #[arg(long = "read-data", conflicts_with = "read_data_subset")]
        read_data: bool,
        /// Deep read a rolling sample of parts, e.g. 10% (moves each day)
        #[arg(long = "read-data-subset", value_name = "P%", value_parser = sigil::readdata::parse_subset)]
        read_data_subset: Option<f64>,
        /// Fix the sample start instead of the daily rolling one
        #[arg(long = "subset-offset", value_name = "N")]
        subset_offset: Option<u64>,
        /// Key for an encrypted folder pack: list its (hidden) member names
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    #[command(visible_alias = "gaze")]
    Scry {
        input: PathBuf,
        /// Key for an encrypted folder pack: list its (hidden) member names
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    Scatter {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Extra pieces: keep raining until the far side has any k. Alias: rain.
    #[command(visible_alias = "rain")]
    Deluge {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// How many extra pieces (max index 254).
        #[arg(long, default_value_t = 16)]
        extra: u8,
        /// First extra part number (16–254). Different people pick different numbers so their rain does not overlap.
        #[arg(long)]
        from: Option<u8>,
        /// Write only the new drops (for “they’re one short”).
        #[arg(long)]
        only_rain: bool,
        #[arg(long)]
        rsync: Option<String>,
        #[arg(long)]
        rclone: Option<String>,
        #[arg(long)]
        wormhole: bool,
        /// Make one extra part, copy, see if they have enough, repeat until they do.
        #[arg(long)]
        watch: bool,
        /// RaptorQ rain (no 255 cap). Writes .rq packets. Gather rebuilds from any enough set.
        /// Each packet gets a random symbol ID from RaptorQ's full 24-bit space (RFC 6330 3.2),
        /// so independent senders rarely overlap and partial shares can be pooled.
        #[arg(long)]
        fountain: bool,
        /// With --fountain: number packets 0, 1, 2, ... (the old order) instead of at random.
        /// Two senders using this send the same packets
        #[arg(long, requires = "fountain")]
        sequential: bool,
        /// With --fountain: expected packet loss (0.1 or 10%). Sigil works out the extra
        /// packets per block so the chance the far side cannot rebuild without a resend is at
        /// most 1 in 10 000, assuming each packet is lost independently (no bursts). Replaces --extra.
        #[arg(long, value_name = "P", requires = "fountain", conflicts_with = "extra", value_parser = sigil::fountain_loss::parse_loss)]
        loss: Option<f64>,
        /// With --fountain: answer a receiver's `gather --report` line by writing exactly
        /// the packets each block is missing (fresh random IDs). A report for another file is refused.
        #[arg(long, value_name = "REPORT", requires = "fountain", conflicts_with_all = ["extra", "loss", "sequential", "watch"])]
        answer: Option<String>,
    },
    Gather {
        input: PathBuf,
        #[arg(short, long, required_unless_present = "report")]
        output: Option<PathBuf>,
        /// Fountain folder: print a one-line "have / need" receiver report (fits one
        /// uplink packet) instead of rebuilding. Send it back; the sender runs
        /// `sigil deluge --fountain --answer "<line>"` to send exactly what is missing.
        #[arg(long, conflicts_with_all = ["watch", "open"])]
        report: bool,
        #[arg(long)]
        open: bool,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        /// Wait for parts to show up. Write VESSEL when rebuilt so the sender can stop.
        #[arg(long)]
        watch: bool,
        /// If it cannot fully rebuild: still exit 2 and write no mark, but leave a JSON
        /// progress receipt at OUTPUT.partial.json (or on stdout with --json)
        #[arg(long, conflicts_with_all = ["watch", "report"])]
        partial: bool,
        /// Machine-readable result on stdout (one JSON line)
        #[arg(long, conflicts_with = "report")]
        json: bool,
    },
    /// Rebuild a healthy .sg1 from live shards in a torn mark (no passphrase). Alias: repair.
    /// A large-file work pack (SGWK) heals every torn chunk star in one go; -o may be the input.
    #[command(visible_alias = "repair")]
    Mend {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Salvage CRC-failed (bit-rotten) shard bodies: per-column Reed-Solomon error
        /// correction (scattered bit flips), then soft-RS / GMD-lite. Output is kept only if
        /// the Merkle binding and true name match
        #[arg(long)]
        soft: bool,
    },
    /// Copy an existing mark with rsync, rclone, and/or wormhole.
    #[command(visible_alias = "send")]
    Dispatch {
        input: PathBuf,
        #[arg(long)]
        rsync: Option<String>,
        #[arg(long)]
        rclone: Option<String>,
        #[arg(long)]
        wormhole: bool,
        /// Send only the Overture (boot) bytes first
        #[arg(long)]
        overture: bool,
    },
    /// Share a rain folder with others. First to rebuild starts Deluge. Alias: coven.
    #[command(visible_alias = "coven")]
    Circle {
        /// Local folder of parts
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Other people's rain folders: user@host:rain/ or a local path
        #[arg(long = "peer")]
        peers: Vec<String>,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        open: bool,
        /// New parts to mint each time we are already whole (for the others)
        #[arg(long, default_value_t = 8)]
        extra: u8,
    },
    /// Plex/Jellyfin or any HTTP player: De-scribe the bytes they ask for (work-pack slices). Alias: showing, unveil.
    #[command(visible_aliases = ["showing", "unveil"])]
    Show {
        input: PathBuf,
        /// e.g. 127.0.0.1:7845 (Plex on this machine)
        #[arg(long, default_value = "127.0.0.1:7845")]
        bind: String,
        /// URL written into the .strm (change if Plex is on another PC)
        #[arg(long, default_value = "http://127.0.0.1:7845")]
        public: String,
        /// Write Title.strm into this Plex/Jellyfin library folder
        #[arg(long)]
        plex: Option<PathBuf>,
        /// Write this exact .strm path
        #[arg(long)]
        strm: Option<PathBuf>,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        /// Seconds with no reads before the temp copy is deleted (default 20 min)
        #[arg(long, default_value_t = 1200)]
        idle: u64,
    },
    /// What to copy first so Play can start (Blizzard-style boot).
    Overture { input: PathBuf },
    /// De-scribe to temp, open in the usual app, delete when you press Enter.
    Open {
        input: PathBuf,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        #[arg(long = "ward")]
        ward: Vec<String>,
        /// Per-file password from a file, like --pass-file: --ward-file photos/cat.jpg=PWFILE
        /// (repeatable; first line, owner-only permissions). Keeps it off the command line.
        #[arg(long = "ward-file", value_name = "PATH=PWFILE")]
        ward_file: Vec<String>,
        #[arg(long = "only")]
        only: Vec<String>,
        /// Don't delete the temp copy
        #[arg(long)]
        keep: bool,
    },
    /// Write an identity key. Default: modern .sgk (X25519 encrypt-to + Ed25519 attest).
    /// Use --legacy / --attest-only for the old raw 32-byte Ed25519/Talisman seed.
    Keygen {
        #[arg(short, long)]
        output: PathBuf,
        /// Also write public half here (default: <output>.pub)
        #[arg(long = "pub-out")]
        pub_out: Option<PathBuf>,
        /// Legacy raw 32-byte Ed25519 attest seed (also Talisman). Alias: --attest-only.
        #[arg(long = "legacy", alias = "attest-only")]
        legacy: bool,
        /// Force modern ECC identity even if defaults change later.
        #[arg(long = "ecc", default_value_t = true)]
        ecc: bool,
        /// Protect the new identity with a FIDO2 passkey (hmac-secret / PRF) — the plain
        /// secret is never written to disk. Needs a build with `--features passkey`.
        #[arg(long, conflicts_with = "legacy")]
        passkey: bool,
        /// Relying-party id for the passkey credential.
        #[arg(long = "rp-id", default_value = sigil::passkey::DEFAULT_RP_ID, requires = "passkey")]
        rp_id: String,
        /// Touch-only passkey (skip PIN / user verification). Default requires UV.
        #[arg(long = "no-uv", requires = "passkey")]
        no_uv: bool,
    },
    /// Identity key-file tools: passkey protect / unprotect / backup keys / info.
    #[command(name = "identity")]
    IdentityTool {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Import an OpenPGP Curve25519 key (Ed25519 primary + cv25519/X25519 subkey; v4 or RFC 9580 v6).
    /// Public key → .pub for --to. Secret key (plain, CFB, or AEAD/Argon2-protected) + -o → .sgk for --identity.
    #[command(name = "import-pgp", visible_alias = "pgp-import")]
    ImportPgp {
        /// Armored (.asc) or binary OpenPGP key export
        input: PathBuf,
        /// Write the secret identity here (.sgk v2); needs a secret export (asks for its passphrase if protected)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Write the public half here (default: <output>.pub, else <input>.pub)
        #[arg(long = "pub-out")]
        pub_out: Option<PathBuf>,
        /// Read the secret key's passphrase from the first line of this file
        /// (else $SIGIL_PGP_PASSPHRASE, else a no-echo prompt). Never logged.
        #[arg(long = "passphrase-file", requires = "output")]
        passphrase_file: Option<PathBuf>,
        /// Lock the imported identity to a FIDO2 passkey (plain secret never written).
        #[arg(long, requires = "output")]
        passkey: bool,
    },
    /// Sign a mark (writes file.sg1.sig). Alias: attest.
    #[command(visible_alias = "attest")]
    Sign {
        input: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Live USB: wrap squashfs so initrd can Scry and mend before it mounts. Alias: keystone.
    #[command(visible_alias = "keystone")]
    Boot {
        #[command(subcommand)]
        cmd: BootCmd,
    },
    /// Move an old-layout vault (`x.sgv/`) or flat constellation folder into a tidy
    /// `name.sigil/` container. Copies, verifies fingerprints, then removes the old files.
    Tidy {
        /// Vault live path / `.sgv` chart dir, or constellation folder
        path: PathBuf,
        /// Show what would move; change nothing
        #[arg(long)]
        dry_run: bool,
        /// Optional: open the card to also check no star goes missing
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens an encrypt-to card (repeatable; optional)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    /// Reclaim orphan stars / versions and abandoned temp files from a container (report-only
    /// unless --apply). Never deletes anything the card / CHART lists, nor cold/ kits.
    Gc {
        /// Vault live path / `.sigil` / `.sgv`, or constellation folder / `.sigil`
        path: PathBuf,
        /// Delete for real (default: report only)
        #[arg(long)]
        apply: bool,
        /// Report only (this is already the default; kept so scripts can say so)
        #[arg(long = "dry-run", conflicts_with = "apply")]
        dry_run: bool,
        /// Passphrase of a warded constellation card (gc must read the list)
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens an encrypt-to card (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        /// Only reclaim temp files older than this many seconds (default 3600)
        #[arg(long = "temp-age", default_value_t = sigil::gc::DEFAULT_TEMP_AGE_SECS)]
        temp_age: u64,
    },
    /// Read-only health check of a vault or constellation: manifest, old layout, missing
    /// members, bit rot (ECC verify), orphans/temp files, cold kits. Exit 0 healthy, 1 warnings,
    /// 2 problems, 3 could not check. `--fix` only tidies an old layout and runs gc --apply.
    Doctor {
        /// Vault live path / `.sigil` / `.sgv`, or constellation folder / `.sigil`
        path: PathBuf,
        /// Machine-readable report on stdout
        #[arg(long)]
        json: bool,
        /// Safe fixes only: `sigil tidy` an old layout, then `sigil gc --apply`. Never touches bit rot, missing members or cold kits
        #[arg(long)]
        fix: bool,
        /// Skip bit-level verification (existence and structure only)
        #[arg(long)]
        quick: bool,
        /// Treat PATH as a folder of .sg1 marks: repair scattered bit flips (as `mend --soft`)
        /// and rewrite a mark only when Merkle + true name pass; uncorrectable marks are
        /// reported and left byte-identical. Exit 2 if any are uncorrectable.
        #[arg(long, conflicts_with_all = ["json", "fix", "quick"])]
        scrub: bool,
        /// Passphrase of a warded constellation card
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens an encrypt-to card (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        /// Only count temp files older than this many seconds as abandoned (default 3600)
        #[arg(long = "temp-age", default_value_t = sigil::gc::DEFAULT_TEMP_AGE_SECS)]
        temp_age: u64,
    },
    /// Append-only segment log: each append seals one batch as an immutable segment star,
    /// chained in a Merkle/hash-chained INDEX (optionally Ed25519-signed). Lives in `name.sigil/`.
    Log {
        #[command(subcommand)]
        cmd: LogCmd,
    },
    /// Named list of stars. Add unique files; rsync the folder; atlas to carry the bag.
    Constellation {
        #[command(subcommand)]
        cmd: SkyCmd,
    },
    /// Cold-USB kit: spread a Seal across sticks (Option A placement). Alias: cold-usb.
    #[command(visible_alias = "cold-usb")]
    Kit {
        #[command(subcommand)]
        cmd: KitCmd,
    },
    /// Walk nested .sg1 seals (breadcrumb) without unpacking the durable store. Aliases: walk, ls.
    #[command(visible_aliases = ["walk", "ls"])]
    Path {
        /// Outer .sg1 (folder pack or single-file mark)
        input: PathBuf,
        /// Breadcrumb segments (positional). Same as repeating --into.
        segments: Vec<String>,
        /// Descend into this entry / nest layer (repeatable). Use `.` to unwrap a single-file nest.
        #[arg(long = "into")]
        into: Vec<String>,
        /// Key for an encrypted folder pack (and locked members): walk its hidden names
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        #[arg(long = "ward")]
        ward: Vec<String>,
        /// Per-file password from a file, like --pass-file: --ward-file photos/cat.jpg=PWFILE
        /// (repeatable; first line, owner-only permissions). Keeps it off the command line.
        #[arg(long = "ward-file", value_name = "PATH=PWFILE")]
        ward_file: Vec<String>,
        /// Max nest depth (hard cap 32).
        #[arg(long, default_value_t = MAX_NEST_DEPTH)]
        depth: usize,
        /// Extract the current view (nested mark or leaf bytes) to this path — temp-friendly; outer .sg1 unchanged.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Human inspect card: framed header, tree of members, seal health for a single mark.
        /// Color when stdout is a terminal (NO_COLOR off; CLICOLOR_FORCE=1 forces). SIGIL_ASCII=1 for +-| frames.
        /// Default output stays plain and stable for scripts.
        #[arg(long)]
        pretty: bool,
    },
    /// Version tip + drift detect for a live path (sidecar `.sgv` chart). Alias: backup.
    #[command(visible_alias = "backup")]
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
    /// FUSE mount (read-only) or export-dir of a .sg1 / SGDR pack, vault tip, or segment log. Alias: fuse.
    /// Durable seal / log is never rewritten. Use --export-dir --writable for a dirty cleartext vault tree.
    /// A `kind=log` container mounts as one file per live segment (tombstones omitted).
    #[command(visible_alias = "fuse")]
    Mount {
        /// .sg1 / SGDR pack, vault live path / `.sgv` (with --vault), or segment log (`events` / `events.sigil`)
        input: PathBuf,
        /// Empty directory mountpoint (ignored with --export-dir)
        mountpoint: PathBuf,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        #[arg(long = "ward")]
        ward: Vec<String>,
        /// Per-file password from a file, like --pass-file: --ward-file photos/cat.jpg=PWFILE
        /// (repeatable; first line, owner-only permissions). Keeps it off the command line.
        #[arg(long = "ward-file", value_name = "PATH=PWFILE")]
        ward_file: Vec<String>,
        /// Mount the vault tip seal for this live path / `.sgv` dir
        #[arg(long)]
        vault: bool,
        /// Materialize a tree here instead of FUSE (seal still intact)
        #[arg(long)]
        export_dir: Option<PathBuf>,
        /// With --export-dir: writable cleartext + `.sigil-dirty` sidecar (re-seal via vault commit --from-export)
        #[arg(long)]
        writable: bool,
    },
    /// Unmount a Sigil FUSE mountpoint (`fusermount3 -u`). Alias: unmount.
    #[command(visible_alias = "unmount")]
    Umount { mountpoint: PathBuf },
    /// Bake-off Vandermonde vs Cauchy MDS (encode + multi-erasure decode MiB/s).
    #[command(name = "bench-mds")]
    BenchMds {
        /// Iterations per (backend, k/n, size). Default 3.
        #[arg(long, default_value_t = 3)]
        iters: usize,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Wrap a plain .sgk (v1 or imported v2) under a FIDO2 passkey (SGKW key file).
    Protect {
        input: PathBuf,
        /// Write the protected identity here
        #[arg(short, long, required_unless_present = "in_place")]
        output: Option<PathBuf>,
        /// Replace the input file (atomic rename). Delete other plain copies yourself.
        #[arg(long = "in-place", conflicts_with = "output")]
        in_place: bool,
        /// Required: the protection method (only passkeys today)
        #[arg(long, required = true)]
        passkey: bool,
        #[arg(long = "rp-id", default_value = sigil::passkey::DEFAULT_RP_ID)]
        rp_id: String,
        /// Touch-only (no PIN / user verification)
        #[arg(long = "no-uv")]
        no_uv: bool,
    },
    /// Add a backup passkey slot (unlock with an existing one, then register a new key).
    #[command(name = "add-passkey")]
    AddPasskey {
        input: PathBuf,
        #[arg(long = "rp-id", default_value = sigil::passkey::DEFAULT_RP_ID)]
        rp_id: String,
        #[arg(long = "no-uv")]
        no_uv: bool,
    },
    /// Remove passkey slot N (see `identity info`). Refuses to drop the last slot.
    #[command(name = "remove-passkey")]
    RemovePasskey {
        input: PathBuf,
        #[arg(long)]
        slot: usize,
    },
    /// Write a plain .sgk back out (unlocks with the passkey).
    Unprotect {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Show identity kind, public keys and passkey slots (no unlock, no secrets).
    Info { input: PathBuf },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Start tracking a live file or folder: create `<path>.sgv/` chart + seal v1. Alias: init.
    /// A folder becomes a folder vault (each version is an SGDR pack).
    #[command(visible_alias = "init")]
    Track {
        /// Live file or folder to protect
        path: PathBuf,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Encrypt-to recipient (.pub / .sgk / hex pk); repeatable
        #[arg(long = "to")]
        to: Vec<String>,
        /// Folder vault: per-file password, --ward photos/cat.jpg=secret (repeatable)
        #[arg(long = "ward")]
        ward: Vec<String>,
        /// Per-file password from a file, like --pass-file: --ward-file photos/cat.jpg=PWFILE
        /// (repeatable; first line, owner-only permissions). Keeps it off the command line.
        #[arg(long = "ward-file", value_name = "PATH=PWFILE")]
        ward_file: Vec<String>,
    },
    /// Report drift of live bytes vs tip true-name (match | changed | missing-seal | missing-live).
    Status {
        /// Live file or its `.sgv` chart dir
        path: PathBuf,
    },
    /// Re-seal live (or a dirty --from-export tree) into the next version; tip moves.
    /// Skips when already matching unless --force.
    Commit {
        /// Live file or `.sgv` (optional when --from-export supplies the target via sidecar)
        path: Option<PathBuf>,
        /// Dirty export dir from `mount … --export-dir DIR --writable`
        #[arg(long = "from-export")]
        from_export: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Encrypt-to recipient (.pub / .sgk / hex pk); repeatable
        #[arg(long = "to")]
        to: Vec<String>,
        /// Folder vault: per-file password, --ward photos/cat.jpg=secret (repeatable)
        #[arg(long = "ward")]
        ward: Vec<String>,
        /// Per-file password from a file, like --pass-file: --ward-file photos/cat.jpg=PWFILE
        /// (repeatable; first line, owner-only permissions). Keeps it off the command line.
        #[arg(long = "ward-file", value_name = "PATH=PWFILE")]
        ward_file: Vec<String>,
        /// Commit even when cleartext already matches tip
        #[arg(long)]
        force: bool,
        /// After commit, keep only the newest N version seals (overrides light policy for this commit)
        #[arg(long)]
        keep: Option<u32>,
        /// Cold kit root for auto-prune / --keep (DIR/vN/); required when light policy would drop
        #[arg(long)]
        cold: Option<PathBuf>,
        /// Light auto-prune: discard without --cold
        #[arg(long = "force-drop")]
        force_drop: bool,
    },
    /// List version stack (v1…tip) from the chart.
    Versions { path: PathBuf },
    /// Restore tip (or --version N) over the live path. Mends a torn seal if needed.
    Restore {
        path: PathBuf,
        /// Version number (default: tip)
        #[arg(long)]
        version: Option<u32>,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) to unwrap encrypt-to CEK (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        /// Folder vault: per-file password, --ward photos/cat.jpg=secret (repeatable)
        #[arg(long = "ward")]
        ward: Vec<String>,
        /// Per-file password from a file, like --pass-file: --ward-file photos/cat.jpg=PWFILE
        /// (repeatable; first line, owner-only permissions). Keeps it off the command line.
        #[arg(long = "ward-file", value_name = "PATH=PWFILE")]
        ward_file: Vec<String>,
        /// Folder vault: overwrite a live folder that has uncommitted edits
        #[arg(long)]
        force: bool,
    },
    /// Drop old version seals; keep the newest N (always keeps tip).
    Prune {
        path: PathBuf,
        /// How many newest versions to keep (≥ 1)
        #[arg(long)]
        keep: u32,
        /// Before deleting a version seal, archive it under DIR/vN/ (kit place or plain .sg1)
        #[arg(long)]
        cold: Option<PathBuf>,
        /// Light retention: allow dropping seals without --cold (discards history)
        #[arg(long = "force-drop")]
        force_drop: bool,
        /// Archive into the container's own `cold/` folder (tidy containers only)
        #[arg(long = "cold-here", conflicts_with = "cold")]
        cold_here: bool,
    },
    /// Remove one named old version (never the tip). Light retention needs --cold/--cold-here or --force-drop.
    #[command(visible_alias = "rm")]
    Remove {
        /// Live file / folder or its `.sigil` / `.sgv` chart dir
        path: PathBuf,
        /// Version number to remove (see `vault versions`)
        #[arg(long)]
        version: u32,
        /// Archive the seal under DIR/vN/ first (kit place or plain .sg1)
        #[arg(long)]
        cold: Option<PathBuf>,
        /// Archive into the container's own `cold/` folder (tidy containers only)
        #[arg(long = "cold-here", conflicts_with = "cold")]
        cold_here: bool,
        /// Discard without a cold kit (light retention)
        #[arg(long = "force-drop")]
        force_drop: bool,
        /// Show what would happen; change nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Show or set remembered encrypt-to recipients (public keys in CHART).
    /// `vault commit` reuses them when no --to is given; --to on commit replaces them.
    Recipients {
        /// Live file / folder or its `.sgv` chart dir
        path: PathBuf,
        /// Replace the remembered set (.pub / .sgk / OpenPGP / hex pk); repeatable
        #[arg(long = "to", conflicts_with = "clear")]
        to: Vec<String>,
        /// Forget all recipients: future versions are NOT encrypt-to (old seals unchanged)
        #[arg(long)]
        clear: bool,
    },
    /// Show or set chart retention (full = keep all; light = keep newest N hot).
    Retention {
        /// Live file or its `.sgv` chart dir
        path: PathBuf,
        /// Keep every version seal in the chart (Bitcoin full-node style)
        #[arg(long, conflicts_with = "light")]
        full: bool,
        /// Keep only newest N hot; older seals need --cold on prune (pruned-node style)
        #[arg(long, conflicts_with = "full")]
        light: bool,
        /// With --light: how many newest versions stay hot (≥ 1)
        #[arg(long)]
        keep: Option<u32>,
    },
}

#[derive(Subcommand)]
enum KitCmd {
    /// Round-robin pieces into usb-0..usb-(N-1) plus a KIT manifest (Option A).
    Place {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// How many USB directories (default 4 → 4 shards each for Seal 16).
        #[arg(long, default_value_t = 4)]
        drives: usize,
    },
    /// Rebuild a healthy .sg1 from the remaining usb-* folders after a drive loss.
    Mend {
        /// Kit folder that still has the surviving usb-* dirs (+ KIT).
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum BootCmd {
    /// Wrap live/filesystem.squashfs (or casper/) as a Seal on a mounted USB.
    Prepare {
        /// Mounted USB root (contains live/ or casper/)
        root: PathBuf,
        #[arg(long, value_enum, default_value = "seal")]
        mode: ModeArg,
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Delete the original squashfs after wrapping (needs a writable stick).
        #[arg(long)]
        only_mark: bool,
        /// Do not rewrite the USB's initrd.
        #[arg(long)]
        no_inject: bool,
    },
    /// Scry the mark; De-scribe the squashfs if it was chewed. Exit 2 = too damaged, 3 = no mark.
    Mend {
        /// Mounted USB root. Omit with --scan to search disks.
        root: Option<PathBuf>,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long, default_value = "/run/sigil")]
        stage: PathBuf,
        /// Scan known live-boot mounts and block devices.
        #[arg(long)]
        scan: bool,
    },
    /// Write Debian live-boot + dracut hooks under a prefix (default /usr). Then rebuild the initrd.
    Install {
        #[arg(default_value = "/usr")]
        prefix: PathBuf,
    },
}

#[derive(Subcommand)]
enum LogCmd {
    /// Create an empty log container (`PATH` or `PATH.sigil`). With --identity every append must be signed by that key.
    Init {
        path: PathBuf,
        /// Identity (.sgk) whose Ed25519 key signs HEAD; pinned in the manifest. Omit for an unsigned log
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Opt in to per-segment keys (crypto-shredding): every segment is sealed under its own key, kept
        /// in a small key ring wrapped to the --pass / --to given at each append. The log becomes `log=3`
        #[arg(long = "segment-keys")]
        segment_keys: bool,
        /// Keep the INDEX private: each entry's size, SHA-256 and file name are sealed (AES-256-GCM)
        /// under an index key wrapped to --to and/or --pass; every segment must be encrypted. The log
        /// becomes `log=5`. Keyless verify / mend / gc keep working. This is the default whenever
        /// --pass or --to is given; the flag is kept for scripts
        #[arg(long = "private-index", conflicts_with = "public_index")]
        private_index: bool,
        /// Opt out of the private INDEX for a log created with --pass / --to: sizes, SHA-256s and
        /// file names are written in the clear (as in a log created with no key). Prints a warning
        #[arg(long = "public-index")]
        public_index: bool,
        /// Private INDEX: passphrase the index key is wrapped to
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Private INDEX: recipient the index key is wrapped to: .pub / .sgk / OpenPGP cv25519 .asc / hex (repeatable)
        #[arg(long = "to")]
        to: Vec<String>,
    },
    /// Seal FILE (or `-` for stdin) as the next immutable segment and extend the chain.
    Append {
        path: PathBuf,
        /// File to append, or `-` for stdin
        input: String,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Encrypt-to recipient for this segment: .pub / .sgk / OpenPGP cv25519 .asc / hex (repeatable).
        /// In a --segment-keys log they wrap the segment's own key instead
        #[arg(long = "to")]
        to: Vec<String>,
        /// Signing identity (.sgk); required exactly when the log was created with --identity
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Private INDEX: another identity (.sgk) that opens the log's index key, when it is not
        /// the signing --identity (repeatable)
        #[arg(long = "unlock")]
        unlock: Vec<PathBuf>,
    },
    /// Back up a folder: seal every file under DIR that is new or changed since the last add as its
    /// own segment (recursive, stable order; symlinks and special files are skipped and listed).
    /// Unchanged files (same path, size and SHA-256) are skipped; files gone from DIR are reported,
    /// never deleted from the log. Re-running with no changes writes nothing.
    ///
    /// Skipping: `--exclude PATTERN` (repeatable) and DIR/.sigilignore (one pattern per line,
    /// `#` comments) leave files and whole folders out. Patterns match the path relative to DIR:
    /// `*` `?` `[a-z]` stay inside one folder, `**` crosses folders, a name without `/` matches at
    /// any depth, a `/` anchors at DIR, a trailing `/` means folders only. Excluded paths already
    /// in the log are kept (never reported missing, never tombstoned).
    Add {
        path: PathBuf,
        /// Folder to back up (its relative paths are what the log remembers)
        dir: PathBuf,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Encrypt-to recipient for each new segment: .pub / .sgk / OpenPGP cv25519 .asc / hex (repeatable).
        /// In a --segment-keys log they wrap each segment's own key instead
        #[arg(long = "to")]
        to: Vec<String>,
        /// Signing identity (.sgk); required exactly when the log was created with --identity
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Show what would be added, skipped, excluded and missing; write nothing
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// Skip files/folders matching PATTERN (relative to DIR; a matching folder skips its whole
        /// subtree). Repeatable, e.g. --exclude .tools-venv/ --exclude '*.tmp'
        #[arg(long = "exclude", value_name = "PATTERN")]
        exclude: Vec<String>,
        /// Do not read DIR/.sigilignore (only --exclude patterns apply)
        #[arg(long = "no-ignore-file")]
        no_ignore_file: bool,
        /// Remember each file's size + mtime/ctime/inode in ADDCACHE (log folder) and skip
        /// re-hashing files whose stamp is unchanged since they last matched (a speed-up, not a
        /// cryptographic check; refused for a private INDEX)
        #[arg(long)]
        cache: bool,
        /// Private INDEX: another identity (.sgk) that opens the log's index key, when it is not
        /// the signing --identity (repeatable)
        #[arg(long = "unlock")]
        unlock: Vec<PathBuf>,
    },
    /// List segments (from the INDEX; reads no segment bytes). A private INDEX shows its sizes,
    /// hashes and file names only with --pass / --identity.
    Ls {
        path: PathBuf,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens a private INDEX (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    /// Write segment bytes (checked against the INDEX) to stdout or -o. Default: all, in order.
    Read {
        path: PathBuf,
        /// One segment
        #[arg(long, conflicts_with_all = ["from", "to"])]
        seq: Option<u64>,
        /// First segment (1-based, inclusive)
        #[arg(long)]
        from: Option<u64>,
        /// Last segment (inclusive)
        #[arg(long)]
        to: Option<u64>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// In a range, fail on a deleted segment instead of skipping it
        #[arg(long)]
        strict: bool,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens encrypt-to segments (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    /// Get a file or a whole folder back by the path `log add` recorded (latest version of each,
    /// or an older one with --at TIME / --seq N).
    /// Every file is checked against the INDEX before anything is written; never overwrites;
    /// refuses a deleted (tombstoned / shredded) file. `PATH` `.` = everything (needs -o).
    Restore {
        log: PathBuf,
        /// A file or folder path as `log ls` shows it (relative to the folder given to `log add`)
        path: String,
        /// Where to create the file / folder (must not exist; default: its name, here)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Older version: as it was at this UTC time (unix seconds, YYYY-MM-DD = end of that day,
        /// or YYYY-MM-DDTHH:MM:SSZ as `log ls` prints); file or folder
        #[arg(long, value_name = "TIME", conflicts_with = "seq")]
        at: Option<String>,
        /// Older version: exactly this entry (a seq `log ls` shows for that file); file only
        #[arg(long)]
        seq: Option<u64>,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens encrypt-to segments or a private INDEX (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    /// Change who can open the log's wrapped keys (per-segment key ring of a --segment-keys log,
    /// index key of a private INDEX) without touching any segment: add or remove `--to`
    /// recipients, set or drop the passphrase, or --replace them all. Needs the current keys.
    /// Does not take back what a removed recipient already opened (use `log compact` for that).
    Rewrap {
        path: PathBuf,
        /// Current passphrase: only `-` (hidden prompt); scripts use --pass-file
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the current passphrase from the first line of a file only you can read
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Current identity (.sgk) that opens the keys (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        /// Recipient to add (.pub / .sgk / 64-hex; repeatable)
        #[arg(long = "add-to", value_name = "RECIPIENT")]
        add_to: Vec<String>,
        /// Recipient to remove (repeatable)
        #[arg(long = "remove-to", value_name = "RECIPIENT")]
        remove_to: Vec<String>,
        /// New passphrase (replaces the current one): only `-` (asks twice)
        #[arg(value_parser = PassParser(true), long = "new-pass")]
        new_pass: Option<String>,
        /// New passphrase from the first line of a file only you can read
        #[arg(long = "new-pass-file", value_name = "PATH", conflicts_with = "new_pass", value_parser = parse_pass_file)]
        new_pass_file: Option<String>,
        /// Remove the passphrase (the keys stay open to the --to recipients only)
        #[arg(long = "drop-pass")]
        drop_pass: bool,
        /// Drop every current recipient and passphrase; wrap to exactly --add-to / --new-pass-file
        #[arg(long)]
        replace: bool,
        /// Check that every key opens and count; write nothing
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
    /// Make a card: a small signed file committing, under its own Merkle root, to the vouched
    /// HEADs (SEQ:ROOT) of segment logs and/or to other cards (daily logs -> monthly card ->
    /// yearly card). Check it with `log check-card`.
    Card {
        /// Child segment logs and/or card files, in order
        #[arg(required = true)]
        children: Vec<PathBuf>,
        /// Card name (1-128 of A-Z a-z 0-9 . _ - :), e.g. 2026-10
        #[arg(long)]
        name: String,
        /// Sign the card with this identity (.sgk)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Write the card here (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Check a card offline (root, signatures); with --child, also check those logs / cards
    /// against it. Exit 0 ok, 2 does not verify.
    CheckCard {
        card: PathBuf,
        /// A child log or card file to check against the card (repeatable)
        #[arg(long)]
        child: Vec<PathBuf>,
        /// Require every child of the card to be given with --child
        #[arg(long)]
        all: bool,
        /// Require the card signed by this key (64-hex, .pub or .sgk)
        #[arg(long)]
        signer: Option<String>,
    },
    /// Copy a log with a public INDEX into a NEW log with a private INDEX (names, sizes and hashes
    /// sealed). SRC is only read; DEST gets a new log id and chain (old receipts stay valid for SRC).
    Privatize {
        src: PathBuf,
        dest: PathBuf,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        /// Passphrase: only `-` (hidden prompt); scripts use --pass-file
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Passphrase file: opens SRC's encrypted segments and wraps DEST's index key and segments
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Recipient DEST's index key and segments are wrapped to (repeatable)
        #[arg(long = "to")]
        to: Vec<String>,
        /// Identity (.sgk) that opens SRC's encrypted segments (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        /// Sign DEST with this identity (.sgk); required (and must be SRC's signer) when SRC is signed
        #[arg(long)]
        sign: Option<PathBuf>,
    },
    /// Receipt for one child of a card (its line + Merkle path + the card's signed root), so the
    /// rest of the card need not be shown. CHILD: a number, a log id or a card name.
    CardProve {
        card: PathBuf,
        child: String,
        /// Write the receipt here (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Check a card child receipt offline. Exit 0 ok, 2 does not verify.
    CheckCardChild {
        receipt: PathBuf,
        /// Require the card signed by this key (64-hex, .pub or .sgk)
        #[arg(long)]
        signer: Option<String>,
        /// Require the proved child to be this log id or card name
        #[arg(long)]
        expect: Option<String>,
        /// Also check this log / card file against the proved child
        #[arg(long)]
        child: Option<PathBuf>,
    },
    /// Check that NEW card carries every child of OLD card at the same or a proved later state
    /// (same name and signer; added children allowed). Exit 0 ok, 2 not consistent.
    CheckCardConsistency {
        old: PathBuf,
        new: PathBuf,
        /// Require both cards signed by this key
        #[arg(long)]
        signer: Option<String>,
        /// A child log whose INDEX proves its growth (repeatable)
        #[arg(long)]
        child: Vec<PathBuf>,
        /// A `log prove-consistency` file proving a child log's growth (repeatable)
        #[arg(long)]
        proof: Vec<PathBuf>,
        /// Old and new versions of a nested card that changed (repeatable: --pair OLD NEW)
        #[arg(long, num_args = 2, value_names = ["OLD", "NEW"])]
        pair: Vec<PathBuf>,
    },
    /// Check INDEX chain, HEAD (+signature), every segment's ECC and true-name. Needs no keys;
    /// with --pass / --identity it also unseals each segment. Exit 0 ok, 1 warnings, 2 problems.
    Verify {
        path: PathBuf,
        /// Skip bit-level ECC verification (existence + header digest only)
        #[arg(long)]
        quick: bool,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        /// Require HEAD signed by this key, or by a key it handed the log over to (`log rotate-signer`):
        /// 64-hex Ed25519 public key, or a .pub / .sgk file
        #[arg(long)]
        signer: Option<String>,
        /// Pinned `SEQ:ROOT` (printed by `log ls`); fails if the log was rolled back or rewritten (repeatable)
        #[arg(long)]
        anchor: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long = "temp-age", default_value_t = sigil::gc::DEFAULT_TEMP_AGE_SECS)]
        temp_age: u64,
    },
    /// Heal repairable segments in place (ECC); INDEX and HEAD never change.
    Mend { path: PathBuf },
    /// Write a receipt that one entry is in this log: its INDEX line plus a Merkle path to the
    /// anchor root (and the HEAD signature on a signed log). Anyone can check it offline with
    /// `sigil log check-proof`, without the log and without keys.
    Prove {
        path: PathBuf,
        /// The entry to prove (any INDEX entry: segment, compaction or tombstone)
        #[arg(
            long,
            required_unless_present = "file_path",
            conflicts_with = "file_path"
        )]
        seq: Option<u64>,
        /// Prove the latest version of this file (a path `log add` recorded, as `log ls` shows it)
        #[arg(long = "path", id = "file_path", value_name = "PATH")]
        file_path: Option<String>,
        /// Prove against the root over the first N entries (an anchor you pinned earlier) instead
        /// of the current HEAD; signed only when N is the HEAD
        #[arg(long)]
        at: Option<u64>,
        /// Write the proof here (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Private INDEX: open the index key so the receipt carries this entry's key (and
        /// `check-proof --file` can compare the bytes)
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    /// Check a proof from `log prove` offline. Exit 0 when it verifies, 2 when it does not.
    CheckProof {
        proof: PathBuf,
        /// Also require that this file is exactly the entry's plain bytes (e.g. the batch you appended)
        #[arg(long)]
        file: Option<PathBuf>,
        /// Require it signed by this key, or by a key it handed the log over to (the proof carries the
        /// handovers): 64-hex Ed25519 public key, or a .pub / .sgk file
        #[arg(long)]
        signer: Option<String>,
        /// Require it to be against this pinned `SEQ:ROOT`
        #[arg(long)]
        anchor: Option<String>,
        /// Require the entry to be the file `log add` recorded at this path
        #[arg(long = "path", value_name = "PATH")]
        file_path: Option<String>,
    },
    /// Write a receipt that the log state OLD (an anchor `SEQ:ROOT` you pinned, or just `SEQ`) is a
    /// prefix of a later state NEW (default: the current HEAD): one Merkle path from which both
    /// roots rebuild. Anyone can check it offline with `sigil log check-consistency`, without the
    /// INDEX and without keys. Refuses when the log's root at OLD is not the pinned ROOT.
    ProveConsistency {
        path: PathBuf,
        /// Old anchor: `SEQ:ROOT` (as printed by `log ls`; checked here) or `SEQ`
        old: String,
        /// New state: `SEQ` or `SEQ:ROOT` (default: the HEAD the log vouches for; signed when it is
        /// a signed HEAD)
        new: Option<String>,
        /// Write the proof here (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Check a proof from `log prove-consistency` offline: OLD is a prefix of NEW. Exit 0 when it
    /// verifies, 2 when it does not.
    CheckConsistency {
        proof: PathBuf,
        /// Require the old side to be this pinned `SEQ:ROOT`
        #[arg(long)]
        old: Option<String>,
        /// Require the new side to be this `SEQ:ROOT`
        #[arg(long)]
        new: Option<String>,
        /// Require the new root signed by this key, or by a key it handed the log over to:
        /// 64-hex Ed25519 public key, or a .pub / .sgk file
        #[arg(long)]
        signer: Option<String>,
    },
    /// Pin a first signing key on a log created unsigned. The key signs the HEAD covering every
    /// entry already in the log (it vouches for that state), and the manifest pins it; from then on
    /// every write needs --identity, like a log signed at init. Refused on a log that is already
    /// signed (use rotate-signer).
    AddSigner {
        path: PathBuf,
        /// The new signer's identity (.sgk)
        #[arg(long)]
        identity: PathBuf,
    },
    /// Hand a signed log over to a new signing key. The current signer (--identity) appends a
    /// handover entry naming the new key, signed with its own key; from the next write on, HEAD must
    /// be signed by the new key. Earlier HEADs, anchors and proofs stay valid; `verify --signer` and
    /// `check-proof --signer` accept any key of the chain. The log becomes `log=4`.
    RotateSigner {
        path: PathBuf,
        /// The current signer's identity (.sgk)
        #[arg(long)]
        identity: PathBuf,
        /// The new signer's public key: 64-hex Ed25519 key, or a .pub / .sgk file (only its public half is used)
        #[arg(long = "new")]
        new: String,
    },
    /// Tidy loose `.sg1` stars (files, or a folder of them in natural name order) into this log as
    /// new segments, byte-for-byte: nothing is unsealed, so no keys are needed and each star keeps
    /// its own ECC and protection. Originals are removed once committed (unless --keep). Re-running
    /// is safe: stars already adopted are recognised and not appended twice.
    Adopt {
        path: PathBuf,
        /// Stars and/or folders of `*.sg1` (a folder is not searched recursively)
        #[arg(required = true)]
        sources: Vec<PathBuf>,
        /// Signing identity (.sgk); required exactly when the log was created with --identity
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Leave the original files in place
        #[arg(long)]
        keep: bool,
        /// Show the plan, change nothing
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
    /// Mark segments as deleted (chain-covered, permanent). Reads honour it at once; the bytes are
    /// erased by `log compact --apply` (or `gc --apply`). The log becomes `log=2`.
    Tombstone {
        path: PathBuf,
        /// One segment
        #[arg(long, conflicts_with_all = ["from", "to"], required_unless_present_any = ["from", "to"])]
        seq: Option<u64>,
        /// First segment of a range (needs --to)
        #[arg(long, requires = "to")]
        from: Option<u64>,
        /// Last segment of a range (needs --from)
        #[arg(long, requires = "from")]
        to: Option<u64>,
        /// Why (free text, kept in the INDEX; do not put secrets here)
        #[arg(long)]
        reason: Option<String>,
        /// Signing identity (.sgk); required exactly when the log was created with --identity
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Crypto-shred segments of a `--segment-keys` log: record it in the INDEX, destroy the segment's
    /// key and unlink its ciphertext. Needs no key. Anchors and verify keep working; the data cannot
    /// be recovered from this log afterwards (copies of the key or of the old files are out of reach)
    Shred {
        path: PathBuf,
        /// One segment
        #[arg(long, conflicts_with_all = ["from", "to"], required_unless_present_any = ["from", "to"])]
        seq: Option<u64>,
        /// First segment of a range (needs --to)
        #[arg(long, requires = "to")]
        from: Option<u64>,
        /// Last segment of a range (needs --from)
        #[arg(long, requires = "from")]
        to: Option<u64>,
        /// Why (free text, kept in the INDEX; do not put secrets here)
        #[arg(long)]
        reason: Option<String>,
        /// Signing identity (.sgk); required exactly when the log was created with --identity
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Merge live segments into fewer, larger ones and erase the files of deleted / merged-away
    /// segments. Dry run unless --apply. The INDEX keeps every old entry, so pinned anchors still verify.
    Compact {
        path: PathBuf,
        /// Leave the newest N batches alone
        #[arg(long = "keep-last")]
        keep_last: Option<u64>,
        /// Only merge batches appended at least this long ago (e.g. 30d, 12h, 90m, 3600)
        #[arg(long = "older-than")]
        older_than: Option<String>,
        /// Only merge batches with original seq in A-B
        #[arg(long)]
        range: Option<String>,
        /// Do it (default: only show the plan)
        #[arg(long)]
        apply: bool,
        /// Stop growing a merged segment at about this many plain bytes
        #[arg(long = "target-size", default_value_t = 64 << 20)]
        target_size: u64,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        /// Passphrase that opens the source segments
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens encrypt-to segments; for a signed log also the signing key (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        /// Passphrase for the merged segments
        #[arg(value_parser = PassParser(true), long = "seal-pass")]
        seal_pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "seal-pass-file", value_name = "PATH", conflicts_with = "seal_pass", value_parser = parse_pass_file)]
        seal_pass_file: Option<String>,
        /// Encrypt-to recipient for the merged segments (repeatable)
        #[arg(long = "to")]
        to: Vec<String>,
        /// Allow merging encrypted batches into an unencrypted segment
        #[arg(long = "allow-decrypt")]
        allow_decrypt: bool,
    },
}

#[derive(Subcommand)]
enum SkyCmd {
    /// Wrap a file (or a folder of files) as a star and put it on the list. Skips bytes you already have.
    Add {
        /// Folder that holds the card and the stars
        sky: PathBuf,
        /// File or folder to add
        input: PathBuf,
        #[arg(long)]
        name: Option<String>,
        /// Name of this file on the list (single file only)
        #[arg(long = "as")]
        as_name: Option<String>,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        #[arg(value_parser = PassParser(true), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long)]
        covenant: Option<String>,
        #[arg(long = "bind")]
        bind: Vec<PathBuf>,
        #[arg(long, default_value_t = DEFAULT_CHUNK)]
        chunk: u32,
        #[arg(long)]
        rsync: Option<String>,
        #[arg(long)]
        rclone: Option<String>,
        #[arg(long)]
        wormhole: bool,
        /// Encrypt-to recipient for new stars and the card: .pub / .sgk / OpenPGP cv25519 .asc / hex (repeatable).
        /// Give the same set on every add; an encrypt-to card refuses an add without --to.
        #[arg(long = "to")]
        to: Vec<String>,
        /// Identity (.sgk) that opens an existing encrypt-to card (repeatable).
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    /// Pack the card and every star into one atlas (.sga) so they cannot scatter.
    Atlas {
        sky: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Passphrase of a warded card (the card is read to find every star)
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens an encrypt-to card (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
    /// Take names off the list and free the stars nothing else needs. A trailing `/` removes a folder.
    /// The card is rewritten first (atomically); an encrypt-to card needs the same --to as `add`.
    #[command(visible_alias = "rm")]
    Remove {
        sky: PathBuf,
        /// List name(s) to remove (`docs/a.txt`, or `docs/` for everything under it)
        names: Vec<String>,
        /// Passphrase of a warded card
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Encrypt-to recipient(s) the rewritten card keeps (same as on add)
        #[arg(long = "to")]
        to: Vec<String>,
        /// Identity (.sgk) that opens an encrypt-to card (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
        /// Leave star files on disk (`sigil gc` reclaims them later)
        #[arg(long = "keep-stars")]
        keep_stars: bool,
        /// Show what would be removed; change nothing
        #[arg(long)]
        dry_run: bool,
    },
    Scry {
        sky: PathBuf,
        #[arg(value_parser = PassParser(false), long)]
        pass: Option<String>,
        /// Read the passphrase from the first line of a file only you can read (for scripts; see --pass)
        #[arg(long = "pass-file", value_name = "PATH", conflicts_with = "pass", value_parser = parse_pass_file)]
        pass_file: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Identity (.sgk) that opens an encrypt-to card (repeatable)
        #[arg(long = "identity")]
        identity: Vec<PathBuf>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum ModeArg {
    Glyph,
    Reflection,
    Seal,
}

#[derive(Copy, Clone, ValueEnum)]
enum CdcArg {
    Media,
    Dedup,
}

impl From<CdcArg> for CdcProfile {
    fn from(v: CdcArg) -> Self {
        match v {
            CdcArg::Media => CDC_MEDIA,
            CdcArg::Dedup => CDC_DEDUP,
        }
    }
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Glyph => Mode::Glyph,
            ModeArg::Reflection => Mode::Reflection,
            ModeArg::Seal => Mode::Seal,
        }
    }
}

fn binds(paths: &[PathBuf]) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    paths.iter().map(|p| Ok(sha256(&fs::read(p)?))).collect()
}

const EMPTY_PASS: &str =
    "an empty passphrase (--pass \"\", or only spaces) is refused: it would not protect anything. \
Leave out --pass for an unencrypted file, or use --pass - to type one without it showing";

/// `--pass` / `--seal-pass`: only `-` (ask on the terminal, hidden; `true` = ask twice, for
/// something new) is accepted; an empty or literal value is refused. A custom parser so the error
/// does not repeat the value (clap's default "invalid value 'X'" would echo the secret).
#[derive(Clone, Copy)]
struct PassParser(bool);

impl clap::builder::TypedValueParser for PassParser {
    type Value = String;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<String, clap::Error> {
        let v = value.to_str().unwrap_or("\u{fffd}");
        pass_arg(v, self.0).map_err(|m| {
            let flag = arg
                .map(|a| a.to_string())
                .unwrap_or_else(|| "--pass".into());
            clap::Error::raw(
                clap::error::ErrorKind::ValueValidation,
                format!("{flag}: {m}\n"),
            )
        })
    }
}

fn pass_arg(v: &str, confirm: bool) -> Result<String, String> {
    if v.trim().is_empty() {
        return Err(EMPTY_PASS.into());
    }
    if v == "-" {
        return prompt_pass("Passphrase: ", confirm).map_err(|e| e.to_string());
    }
    Err(LITERAL_PASS_REFUSED.into())
}

/// Refused (before any key is derived or any file is written) when a passphrase is typed straight
/// onto the command line: it would be visible to other programs (process list) and saved in shell
/// history.
const LITERAL_PASS_REFUSED: &str =
    "a passphrase given as --pass VALUE is refused: it is visible to other programs on this \
computer (process list) and may be saved in your shell history. Use --pass-file PATH (a file only \
you can read, e.g. --pass-file <(pass show sigil)) or --pass - (type it, hidden)";

/// Largest passphrase file accepted: a passphrase, not a document.
const PASS_FILE_MAX: u64 = 64 * 1024;

/// `--pass-file PATH` (and `--seal-pass-file`): the passphrase from [`read_pass_file`].
fn parse_pass_file(v: &str) -> Result<String, String> {
    read_pass_file(Path::new(v)).map(|p| p.as_str().to_owned())
}

/// Read a passphrase file: the first line, minus its `\n` / `\r\n` ending.
/// Fails closed: a missing or unreadable file, an empty first line, text that is not
/// UTF-8, a file over 64 KiB, or (on unix) a regular file that other users can read
/// or change (any group/other permission bit) is refused. Pipes such as `/dev/fd/3`
/// or `<(pass show sigil)` are accepted; they have no lasting permissions to check.
fn read_pass_file(path: &Path) -> Result<zeroize::Zeroizing<String>, String> {
    use std::io::Read;
    let shown = path.display();
    let file = fs::File::open(path)
        .map_err(|e| format!("cannot read passphrase file {shown}: {e}; nothing was done"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot read passphrase file {shown}: {e}; nothing was done"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if meta.is_file() && mode & 0o077 != 0 {
            return Err(format!(
                "passphrase file {shown} can be read or changed by other users (mode {mode:03o}); \
run  chmod 600 {shown}  so only you can, then try again. Nothing was done"
            ));
        }
    }
    if meta.is_dir() {
        return Err(format!(
            "passphrase file {shown} is a folder; nothing was done"
        ));
    }
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    file.take(PASS_FILE_MAX + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("cannot read passphrase file {shown}: {e}; nothing was done"))?;
    if raw.len() as u64 > PASS_FILE_MAX {
        return Err(format!(
            "passphrase file {shown} is larger than 64 KiB; it should hold one line"
        ));
    }
    let line = raw.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(format!(
            "passphrase file {shown} is empty (or its first line is, or holds only spaces): an empty passphrase \
would not protect anything; nothing was done"
        ));
    }
    let text = std::str::from_utf8(line)
        .map_err(|_| format!("passphrase file {shown} is not UTF-8 text; nothing was done"))?;
    Ok(zeroize::Zeroizing::new(text.to_owned()))
}

/// Read a passphrase from the terminal without echo (rpassword). Refuses an empty one;
/// with `confirm`, asks again and refuses a mismatch.
fn prompt_pass(label: &str, confirm: bool) -> Result<String, Box<dyn std::error::Error>> {
    let first = rpassword::prompt_password(label).map_err(|e| {
        format!(
            "could not read a passphrase from the terminal ({e}); use --pass-file PATH in scripts"
        )
    })?;
    if first.trim().is_empty() {
        return Err(EMPTY_PASS.into());
    }
    if confirm {
        let again = rpassword::prompt_password("Same passphrase again: ")
            .map_err(|e| format!("could not read a passphrase from the terminal ({e})"))?;
        if again != first {
            return Err("the two passphrases do not match; nothing was written".into());
        }
    }
    Ok(first)
}

/// True when stdin and stderr are a terminal (someone can answer a prompt).
fn can_prompt() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The error says a key is needed (as opposed to a wrong key or damage).
fn needs_key(msg: &str) -> bool {
    msg.contains("passphrase or --identity required")
        || msg.contains("member names are hidden")
        || msg.contains("this pack is locked")
}

fn resolve_pass(
    pass: Option<String>,
    talisman: Option<PathBuf>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(p) = talisman {
        return Ok(Some(talisman_pass(&p)?));
    }
    Ok(pass)
}

/// PGP secret passphrase: --passphrase-file (same rules as --pass-file: [`read_pass_file`]),
/// $SIGIL_PGP_PASSPHRASE, or prompt.
fn pgp_passphrase(
    file: Option<&Path>,
) -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    if let Some(f) = file {
        return Ok(read_pass_file(f)?);
    }
    if let Ok(v) = std::env::var("SIGIL_PGP_PASSPHRASE") {
        return Ok(zeroize::Zeroizing::new(v));
    }
    Ok(zeroize::Zeroizing::new(rpassword::prompt_password(
        "OpenPGP secret key passphrase: ",
    )?))
}

fn load_identities(paths: &[PathBuf]) -> Result<Vec<Identity>, Box<dyn std::error::Error>> {
    paths.iter().map(|p| Ok(Identity::load(p)?)).collect()
}

fn load_recipients(
    specs: &[String],
) -> Result<Vec<sigil::PublicIdentity>, Box<dyn std::error::Error>> {
    specs.iter().map(|s| Ok(resolve_recipient(s)?)).collect()
}

/// Ward passwords from `--ward PATH=PASSWORD` and `--ward-file PATH=PWFILE`.
/// `--ward PATH=-` asks on the terminal (hidden; twice when `new` encrypts something).
/// A literal password is refused (process list, shell history), as is an empty one; nothing is
/// read or written before this runs.
/// One path given twice is refused rather than silently picking one.
fn parse_wards(
    v: &[String],
    files: &[String],
    new: bool,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(v.len() + files.len());
    for s in v {
        let (path, pw) = match s.split_once('=') {
            Some((a, "")) => return Err(format!("--ward {a}=: {EMPTY_PASS}").into()),
            Some((a, b)) => (a, b),
            None => return Err("--ward needs PATH=PASSWORD (or PATH=- to type it)".into()),
        };
        let pw = if pw == "-" {
            if !can_prompt() {
                return Err(format!(
                    "--ward {path}=- types the ward password on a terminal, and there is none here \
(input is piped or redirected); use --ward-file {path}=PWFILE in scripts. Nothing was done"
                )
                .into());
            }
            prompt_pass(&format!("Ward password for {path}: "), new)?
        } else if pw.trim().is_empty() {
            return Err(format!("--ward {path}=: {EMPTY_PASS}").into());
        } else {
            return Err(format!("--ward {path}=…: {LITERAL_WARD_REFUSED}").into());
        };
        out.push((path.to_string(), pw));
    }
    for s in files {
        let Some((path, file)) = s.split_once('=') else {
            return Err("--ward-file needs PATH=PWFILE".into());
        };
        if file.is_empty() {
            return Err(format!("--ward-file {path}= names no password file").into());
        }
        let pw = read_pass_file(Path::new(file))?;
        out.push((path.to_string(), pw.as_str().to_owned()));
    }
    for (i, (a, _)) in out.iter().enumerate() {
        if out[..i].iter().any(|(b, _)| b == a) {
            return Err(
                format!("ward {a} is given more than once; give each file one password").into(),
            );
        }
    }
    Ok(out)
}

/// Refused when a ward password is typed straight onto the command line (the value is not echoed).
const LITERAL_WARD_REFUSED: &str =
    "a ward password given as --ward PATH=PASSWORD is refused: it is visible to other programs on \
this computer (process list) and may be saved in your shell history. Use --ward-file PATH=PWFILE \
(a file only you can read) or --ward PATH=- (type it, hidden). Nothing was done";

fn companion_bytes(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    paths.iter().map(|p| Ok(fs::read(p)?)).collect()
}

fn print_hash(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let h = sha256_path(path)?;
    println!("envelope sha256 {}", hex32(&h));
    Ok(())
}

fn run_cmd(bin: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(bin)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    match status {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("{bin} is not installed. Install it, or copy the .sg1 yourself.").into())
        }
        Err(e) => Err(e.into()),
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("{bin} failed ({s})").into()),
    }
}

fn run_cmd_quiet(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn slash(dest: &str) -> String {
    if dest.ends_with('/') {
        dest.to_string()
    } else {
        format!("{dest}/")
    }
}

fn rsync_file(src: &Path, dest: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dest = slash(dest);
    let path = src.to_str().ok_or("path")?;
    println!("rsync {} → {dest}", src.display());
    run_cmd("rsync", &["-av", "--partial", path, &dest])
}

fn vessel_at(dest: &str) -> bool {
    let dest = slash(dest);
    if dest.contains(':') {
        let tmp = std::env::temp_dir().join("sigil-vessel-probe");
        let _ = fs::remove_file(&tmp);
        let spec = format!("{dest}{VESSEL}");
        run_cmd_quiet("rsync", &["-q", &spec, tmp.to_str().unwrap_or("/dev/null")]) && tmp.is_file()
    } else {
        Path::new(dest.trim_end_matches('/')).join(VESSEL).is_file()
    }
}

fn rsync_dir(src: &str, dest: &str) -> Result<(), Box<dyn std::error::Error>> {
    let src = slash(src);
    let dest = slash(dest);
    println!("rsync {src} ↔ {dest}");
    run_cmd(
        "rsync",
        &[
            "-av",
            "--partial",
            "--exclude",
            VESSEL,
            "--exclude",
            "manifest.txt",
            &src,
            &dest,
        ],
    )
}

fn all_peers_vessel(peers: &[String]) -> bool {
    !peers.is_empty() && peers.iter().all(|p| vessel_at(p))
}

fn dispatch(
    file: &Path,
    rsync: &Option<String>,
    rclone: &Option<String>,
    wormhole: bool,
    overture: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if rsync.is_none() && rclone.is_none() && !wormhole {
        return Ok(());
    }
    print_hash(file)?;
    let send_path: PathBuf = if overture {
        let (head, locs) = sigil::index_pack(file)?;
        let end = locs
            .iter()
            .filter(|l| l.index < head.overture)
            .map(|l| l.file_off + l.star_len)
            .max()
            .unwrap_or(0);
        if end == 0 {
            file.to_path_buf()
        } else {
            let tmp = std::env::temp_dir().join(format!("sigil-overture-{}", std::process::id()));
            let src = fs::File::open(file)?;
            let mut dst = fs::File::create(&tmp)?;
            let mut taken = src.take(end);
            let n = std::io::copy(&mut taken, &mut dst)?;
            say!("Overture slice {n} bytes (boot) — did not load the whole file");
            tmp
        }
    } else {
        file.to_path_buf()
    };
    let path = send_path.to_str().ok_or("path is not utf-8")?;
    if let Some(dest) = rsync {
        say!("dispatch rsync → {dest}");
        run_cmd("rsync", &["-av", "--partial", "--progress", path, dest])?;
    }
    if let Some(dest) = rclone {
        say!("dispatch rclone → {dest}");
        run_cmd("rclone", &["copy", path, dest])?;
    }
    if wormhole {
        say!("dispatch wormhole send (you and the other person type the code)");
        run_cmd("wormhole", &["send", path])?;
    }
    say!("far side: sha256sum the copy, then  sigil scry <file>  and  sigil de-scribe -o restored <file>");
    Ok(())
}

/// `gather --partial` after a failed rebuild: collect progress, write the receipt (file,
/// or JSON fields on the stdout result line with `--json`), and return the exit-2 error.
/// Writes no mark: nothing that looks complete is left behind.
fn gather_partial(
    input: &Path,
    output: &Path,
    fountain: bool,
    json: bool,
    why: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let fields = if fountain {
        let p = sigil::fountain_progress(input);
        format!(
            ",\"partial\":true,\"kind\":\"fountain\",\"packets_accepted\":{},\"packets_usable\":{},\"packets_needed\":{},\"packets_more\":{},\"blocks\":{},\"damaged_files\":{},\"stray_files\":{},\"duplicates\":{},\"report\":{},\"artifact\":null",
            p.packets_accepted,
            p.usable,
            p.needed,
            p.more,
            p.blocks,
            p.damaged,
            p.stray,
            p.duplicates,
            p.report.as_deref().map(jq).unwrap_or_else(|| "null".into()),
        )
    } else {
        let (have, k, _) = tally_pieces(input).unwrap_or((0, 0, 0));
        format!(
            ",\"partial\":true,\"kind\":\"pieces\",\"packets_accepted\":{have},\"packets_needed\":{k},\"packets_more\":{},\"artifact\":null",
            k.saturating_sub(have)
        )
    };
    let msg = format!("gather incomplete (too damaged to rebuild from these packets yet): {why}");
    if json {
        json_extra(&fields);
    } else {
        let mut rp = output.as_os_str().to_os_string();
        rp.push(".partial.json");
        let rp = PathBuf::from(rp);
        fs::write(
            &rp,
            format!(
                "{{\"ok\":false,\"cmd\":\"gather\",\"exit\":2,\"output\":null,\"reason\":{}{fields}}}\n",
                jq(why)
            ),
        )?;
        eprintln!("partial receipt → {} (no mark written)", rp.display());
    }
    Ok(msg)
}

/// `verify` / `scry`: the cheap structural check, plus the opt-in deep read.
fn verify_cmd(
    input: PathBuf,
    pass: Option<String>,
    talisman: Option<PathBuf>,
    identity: Vec<PathBuf>,
    subset: Option<f64>,
    subset_offset: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_constellation_input(&input) {
        let (text, bad) = sigil::scry_constellation_checked(&input, None, &[]).map_err(|e| {
            format!("{e}\n(locked card: use `sigil constellation scry <sky> --pass/--identity`)")
        })?;
        say!("{text}");
        json_extra(&format!(",\"report\":{}", jq(&text)));
        if let Some(why) = bad {
            return Err(not_recoverable(&why).into());
        }
    } else if is_dir_pack(&input) {
        let pass = resolve_pass(pass.clone(), talisman.clone())?;
        let identities = load_identities(&identity)?;
        let (text, bad) = sigil::scry_dir_checked(&input, pass.as_deref(), &[], &identities)?;
        say!("{text}");
        json_extra(&format!(",\"report\":{}", jq(&text)));
        if let Some(why) = bad {
            return Err(not_recoverable(&why).into());
        }
    } else {
        let (text, bad) = sigil::scry_path_checked(&input)?;
        say!("{text}");
        json_extra(&format!(",\"report\":{}", jq(&text)));
        if let Some(why) = bad {
            return Err(not_recoverable(&why).into());
        }
    }
    if let Some(pct) = subset {
        if is_constellation_input(&input) || is_dir_pack(&input) {
            return Err("--read-data is for one .sg1 or a large-file pack (not a folder wrap or constellation yet)".into());
        }
        let pass = resolve_pass(pass, talisman)?;
        let identities = load_identities(&identity)?;
        let offset = subset_offset.unwrap_or_else(sigil::readdata::rolling_offset);
        let r =
            sigil::readdata::read_data_subset(&input, pass.as_deref(), &identities, pct, offset)?;
        say!(
            "read-data {pct}%: opened {} of {} part(s), {} bytes, {} failed",
            r.checked.len(),
            r.total_parts,
            r.bytes_read,
            r.failed.len()
        );
        for (i, why) in &r.failed {
            say!("  part {i}: {why}");
        }
        json_extra(&format!(
            ",\"read_data\":{{\"kind\":\"{}\",\"percent\":{},\"offset\":{},\"total_parts\":{},\"checked\":[{}],\"bytes_read\":{},\"failed\":[{}]}}",
            r.kind,
            pct,
            offset,
            r.total_parts,
            r.checked.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","),
            r.bytes_read,
            r.failed
                .iter()
                .map(|(i, w)| format!("{{\"part\":{i},\"why\":{}}}", jq(w)))
                .collect::<Vec<_>>()
                .join(",")
        ));
        if !r.ok() {
            return Err(not_recoverable(&format!(
                "deep read: {} of {} sampled part(s) would not open",
                r.failed.len(),
                r.checked.len()
            ))
            .into());
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let jctx = json_ctx(&cli.cmd);
    let piped_out = matches!(&cli.cmd, Cmd::Unseal { output, .. } if output.as_os_str() == "-");
    if jctx.is_some() || piped_out {
        HUMAN_TO_STDERR.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let res = run(cli);
    let extra = JSON_EXTRA.lock().map(|g| g.clone()).unwrap_or_default();
    match (res, jctx) {
        (Ok(()), None) => {}
        (Ok(()), Some((cmd, out))) => {
            let mut line = format!("{{\"ok\":true,\"cmd\":\"{cmd}\",\"exit\":0");
            if let Some(o) = out {
                line.push_str(&format!(",\"output\":{}", jq(&o.to_string_lossy())));
                if let Ok(m) = fs::metadata(&o) {
                    if m.is_file() {
                        line.push_str(&format!(",\"output_bytes\":{}", m.len()));
                    }
                }
            }
            line.push_str(&extra);
            println!("{line}}}");
        }
        (Err(e), j) => {
            let code = classify_exit(&e.to_string());
            eprintln!("{e}");
            if let Some((cmd, _)) = j {
                println!(
                    "{{\"ok\":false,\"cmd\":\"{cmd}\",\"exit\":{code},\"error\":{}{extra}}}",
                    jq(&e.to_string())
                );
            }
            std::process::exit(code);
        }
    }
}

/// Fountain gather that prints which packet files were skipped (stderr).
fn gather_fountain_noted(
    dir: &Path,
) -> Result<(Vec<u8>, sigil::FountainReport), Box<dyn std::error::Error>> {
    let (data, rep) = sigil::gather_fountain_report(dir)?;
    for (p, why) in &rep.bad {
        eprintln!("skipped {}: {why}", p.display());
    }
    for p in &rep.stray {
        eprintln!("skipped {}: belongs to another file", p.display());
    }
    Ok((data, rep))
}

/// Error text for a file `scry` / `verify` found beyond repair (exit 2: "too damaged").
fn not_recoverable(why: &str) -> String {
    format!(
        "NOT recoverable ({why}): too damaged to restore from this copy; \
         find another copy or more pieces (sigil gather), then try again"
    )
}

fn classify_exit(msg: &str) -> i32 {
    if msg.contains("no boot mark") {
        3
    } else if msg.contains("too damaged")
        || msg.contains("will not guess")
        || msg.contains("work pack incomplete")
        || msg.contains("Attest refused")
        || msg.contains("missing a star")
    {
        2
    } else {
        1
    }
}

fn resolve_mds(cli: &str) -> Result<Box<dyn sigil::MdsBackend>, String> {
    let from_cli = cli.trim().to_ascii_lowercase();
    let name = if from_cli != "vandermonde" && !from_cli.is_empty() {
        from_cli
    } else {
        std::env::var("SIGIL_MDS")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "vandermonde".into())
    };
    // Bake-off measured a clear win; --mds cauchy is opt-in. Vandermonde stays default.
    // Feature `mds-cauchy` documents the opt-in; Cauchy code is always compiled for benches.
    let _ = cfg!(feature = "mds-cauchy");
    backend_by_name(&name).map_err(|e| e.to_string())
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.cmd {
        Cmd::Seal {
            input,
            output,
            stdin_name,
            json: _,
            mode,
            pass,
            pass_file,
            talisman,
            to,
            ward,
            ward_file,
            ward_names_visible,
            covenant,
            bind,
            chunk,
            piece_mb,
            shards,
            overture_mb,
            cdc,
            mds,
            pieces,
            rsync,
            rclone,
            wormhole,
        } => {
            // wards first: a refused literal ward password must stop before stdin is staged
            let wards = parse_wards(&ward, &ward_file, true)?;
            let stage = StdinStage::from_input(&input, &output, stdin_name.as_deref())?;
            let input = stage.as_ref().map(|s| s.file.clone()).unwrap_or(input);
            let pass = pass.or(pass_file);
            let geas = binds(&bind)?;
            let cov = covenant.as_deref().unwrap_or("");
            let pass = resolve_pass(pass, talisman)?;
            let recipients = load_recipients(&to)?;
            if ward_names_visible && (wards.is_empty() || pass.is_some() || !recipients.is_empty())
            {
                return Err(
                    "--ward-names-visible only applies to a folder sealed with --ward and no --pass / --to"
                        .into(),
                );
            }
            let piece_bytes = piece_mb.saturating_mul(1024 * 1024).max(64 * 1024);
            let mds_be = resolve_mds(&mds)?;
            if mds_be.name() != "vandermonde" {
                if input.is_dir() || pieces.is_some() || cdc.is_some() {
                    return Err(
                        "Cauchy --mds is single-star .sg1 only (no folder / --pieces / --cdc yet)"
                            .into(),
                    );
                }
                let data = fs::read(&input)?;
                let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file");
                let sg1 = seal_kn_mds_to(
                    &data,
                    mode.into(),
                    pass.as_deref(),
                    name,
                    false,
                    cov,
                    &geas,
                    shards,
                    piece_bytes,
                    &*mds_be,
                    &recipients,
                )?;
                fs::write(&output, &sg1)?;
                say!(
                    "inscribed {} bytes → {} (mds {}{})",
                    data.len(),
                    output.display(),
                    mds_be.name(),
                    if recipients.is_empty() {
                        ""
                    } else {
                        ", encrypt-to"
                    },
                );
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
                return Ok(());
            }
            if input.is_dir() {
                if pieces.is_some() {
                    return Err("folder Inscribe writes one pack. Omit --pieces.".into());
                }
                let seal_dir = if ward_names_visible {
                    eprintln!(
                        "WARNING: --ward-names-visible: every file name and size in {} is readable without a key; only the warded files' contents are locked",
                        output.display()
                    );
                    inscribe_dir_to_names_visible
                } else {
                    inscribe_dir_to
                };
                let (n, orig) = seal_dir(
                    &input,
                    &output,
                    mode.into(),
                    pass.as_deref(),
                    cov,
                    &geas,
                    chunk,
                    &wards,
                    &recipients,
                )?;
                say!(
                    "folder {n} files, {orig} bytes → {}{}",
                    output.display(),
                    if recipients.is_empty() {
                        ""
                    } else {
                        " (encrypt-to)"
                    },
                );
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
            } else if let Some(dir) = pieces {
                let meta = fs::metadata(&input)?;
                if meta.len() <= chunk as u64 {
                    let data = fs::read(&input)?;
                    let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file");
                    let sg1 = seal_kn_mds_to(
                        &data,
                        mode.into(),
                        pass.as_deref(),
                        name,
                        false,
                        cov,
                        &geas,
                        shards,
                        piece_bytes,
                        &*mds_be,
                        &recipients,
                    )?;
                    let n = scatter_pieces(&sg1, &dir)?;
                    say!("scattered {n} pieces into {}", dir.display());
                } else {
                    let (orig, stars) = inscribe_stars_dir_to(
                        &input,
                        &dir,
                        mode.into(),
                        pass.as_deref(),
                        cov,
                        &geas,
                        chunk,
                        shards,
                        piece_bytes,
                        overture_mb,
                        cdc.map(Into::into),
                        &recipients,
                    )?;
                    say!(
                        "wrote {stars} stars ({orig} bytes) into {}{}",
                        dir.display(),
                        if recipients.is_empty() {
                            ""
                        } else {
                            " (encrypt-to)"
                        },
                    );
                    say!("Overture list: {}/{OVERTURE}", dir.display());
                }
            } else if !recipients.is_empty() && cdc.is_none() {
                // Single-star encrypt-to (vandermonde / explicit mds already handled above).
                let data = fs::read(&input)?;
                let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file");
                let sg1 = seal_kn_mds_to(
                    &data,
                    mode.into(),
                    pass.as_deref(),
                    name,
                    false,
                    cov,
                    &geas,
                    shards,
                    piece_bytes,
                    &*mds_be,
                    &recipients,
                )?;
                fs::write(&output, &sg1)?;
                say!(
                    "inscribed {} bytes → {} (encrypt-to {} recipient{})",
                    data.len(),
                    output.display(),
                    recipients.len(),
                    if recipients.len() == 1 { "" } else { "s" },
                );
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
            } else {
                let (orig, stars, work) = inscribe_path_to(
                    &input,
                    &output,
                    mode.into(),
                    pass.as_deref(),
                    cov,
                    &geas,
                    chunk,
                    shards,
                    piece_bytes,
                    overture_mb,
                    cdc.map(Into::into),
                    &recipients,
                )?;
                if work {
                    say!(
                        "work pack {stars} stars, {orig} bytes → {}{}",
                        output.display(),
                        if recipients.is_empty() {
                            ""
                        } else {
                            " (encrypt-to)"
                        },
                    );
                    say!(
                        "Overture: first {overture_mb} MiB is boot. sigil overture {}",
                        output.display()
                    );
                } else {
                    say!(
                        "inscribed {orig} bytes → {}{}",
                        output.display(),
                        if recipients.is_empty() {
                            ""
                        } else {
                            " (encrypt-to)"
                        },
                    );
                }
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
            }
        }
        Cmd::Unseal {
            input,
            output,
            json,
            pass,
            pass_file,
            talisman,
            identity,
            ward,
            ward_file,
            bind,
            only,
            star,
            from_mb,
            to_mb,
            mds,
            repair,
        } => {
            let pass = pass.or(pass_file);
            let companions = companion_bytes(&bind)?;
            let wards = parse_wards(&ward, &ward_file, false)?;
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let mds_be = resolve_mds(&mds)?;
            let to_stdout = output.as_os_str() == "-";
            if to_stdout {
                if json {
                    return Err("--json and -o - both want stdout; pick one".into());
                }
                if repair
                    || mds_be.name() != "vandermonde"
                    || !only.is_empty()
                    || is_dir_pack(&input)
                    || is_constellation_input(&input)
                {
                    return Err("-o - streams one file only (not a folder wrap, constellation, --only, --repair or --mds)".into());
                }
            }
            let attempt = |pass: Option<&str>| -> Result<(), Box<dyn std::error::Error>> {
                if to_stdout {
                    let n = unseal_to_stdout(
                        &input,
                        pass,
                        &companions,
                        &identities,
                        star,
                        from_mb,
                        to_mb,
                    )?;
                    say!("de-scribed {n} bytes → stdout");
                    return Ok(());
                }
                if repair {
                    if mds_be.name() != "vandermonde"
                        || star.is_some()
                        || from_mb.is_some()
                        || to_mb.is_some()
                        || !only.is_empty()
                        || is_dir_pack(&input)
                        || is_constellation_input(&input)
                        || sigil::is_work_pack(&input)
                    {
                        return Err(
                            "--repair is for a plain .sg1 only (use `sigil mend --soft` for packs)"
                                .into(),
                        );
                    }
                    let data = fs::read(&input)?;
                    let (plain, repaired) =
                        sigil::unseal_repair_keys(&data, pass, &companions, &identities)?;
                    if repaired {
                        eprintln!("warning: --repair corrected damage in memory (Merkle + true name checked); the mark on disk is still damaged — run `sigil mend --soft` to keep a healthy copy");
                    }
                    let mut tmp = output.as_os_str().to_os_string();
                    tmp.push(".unseal-part");
                    let tmp = PathBuf::from(tmp);
                    fs::write(&tmp, &plain)?;
                    fs::rename(&tmp, &output)?;
                    say!(
                        "de-scribed {} bytes → {}{}",
                        plain.len(),
                        output.display(),
                        if repaired {
                            " (repaired in memory)"
                        } else {
                            ""
                        }
                    );
                    return Ok(());
                }
                if mds_be.name() != "vandermonde" {
                    if star.is_some()
                        || from_mb.is_some()
                        || to_mb.is_some()
                        || is_dir_pack(&input)
                        || is_constellation_input(&input)
                    {
                        return Err("Cauchy --mds De-scribe is plain .sg1 only for now".into());
                    }
                    let data = fs::read(&input)?;
                    let plain =
                        unseal_ex_mds_keys(&data, pass, &companions, &*mds_be, &identities)?;
                    let n = plain.len();
                    fs::write(&output, &plain)?;
                    say!(
                        "de-scribed {n} bytes → {} (mds {})",
                        output.display(),
                        mds_be.name()
                    );
                    return Ok(());
                }
                if star.is_some() || from_mb.is_some() || to_mb.is_some() {
                    let (head, _) = sigil::index_pack(&input)?;
                    let from = if let Some(s) = star {
                        s
                    } else {
                        let mb = from_mb.unwrap_or(0) as u64;
                        ((mb * 1024 * 1024) / head.chunk_size.max(1) as u64) as u32
                    };
                    let to = if let Some(s) = star {
                        s
                    } else if let Some(mb) = to_mb {
                        (((mb as u64) * 1024 * 1024) / head.chunk_size.max(1) as u64) as u32
                    } else {
                        head.stars.saturating_sub(1)
                    };
                    let (n, stars) = unseal_range_keys(
                        &input,
                        &output,
                        pass,
                        &companions,
                        from,
                        to,
                        &identities,
                    )?;
                    say!(
                        "de-scribed {stars} slices ({n} bytes) → {}",
                        output.display()
                    );
                } else if is_dir_pack(&input) {
                    let n = unseal_dir_only_keys(
                        &input,
                        &output,
                        pass,
                        &companions,
                        &only,
                        &wards,
                        &identities,
                    )?;
                    say!("de-scribed {n} files → {}", output.display());
                } else if is_constellation_input(&input) {
                    let n = sigil::unseal_constellation_keys(
                        &input,
                        &output,
                        pass,
                        &companions,
                        &only,
                        &identities,
                    )?;
                    say!("de-scribed {n} files → {}", output.display());
                } else {
                    if !only.is_empty() {
                        return Err("--only is for a folder wrap. This is one file.".into());
                    }
                    let n = unseal_path_keys(&input, &output, pass, &companions, &identities)?;
                    say!("de-scribed {n} bytes → {}", output.display());
                }
                Ok(())
            };
            match attempt(pass.as_deref()) {
                // Encrypted and no key given: ask on the terminal (hidden) instead of failing.
                Err(e)
                    if pass.is_none()
                        && identities.is_empty()
                        && needs_key(&e.to_string())
                        && can_prompt() =>
                {
                    let typed = prompt_pass("Passphrase: ", false)?;
                    attempt(Some(&typed))?;
                }
                r => r?,
            }
        }
        Cmd::Verify {
            input,
            json: _,
            read_data,
            read_data_subset,
            subset_offset,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            let subset = if read_data {
                Some(100.0)
            } else {
                read_data_subset
            };
            verify_cmd(
                input,
                pass.or(pass_file),
                talisman,
                identity,
                subset,
                subset_offset,
            )?;
        }
        Cmd::Scry {
            input,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            verify_cmd(input, pass.or(pass_file), talisman, identity, None, None)?;
        }
        Cmd::Scatter { input, output } => {
            let data = fs::read(input)?;
            let n = scatter_pieces(&data, &output)?;
            println!("scattered {n} pieces into {}", output.display());
        }
        Cmd::Deluge {
            input,
            output,
            extra,
            from,
            only_rain,
            rsync,
            rclone,
            wormhole,
            watch,
            fountain,
            sequential,
            loss,
            answer,
        } => {
            let data = fs::read(&input)?;
            if let Some(line) = answer {
                let n = sigil::deluge_answer_report(&data, &output, &line)?;
                println!(
                    "answered report: wrote {n} missing packets → {}",
                    output.display()
                );
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
                return Ok(());
            }
            if fountain {
                let (count, what) = match loss {
                    Some(p) => {
                        let plan = sigil::fountain_loss::loss_plan(
                            data.len() as u64,
                            p,
                            sigil::fountain_loss::LOSS_TARGET_FAILURE,
                        )?;
                        println!(
                            "--loss {:.4}%: {} extra packets per block ({} block(s), {} packets); chance of needing a resend at most {:.1e} if losses are independent",
                            p * 100.0,
                            plan.extra,
                            plan.blocks.len(),
                            plan.packets(),
                            plan.failure_bound
                        );
                        if sequential {
                            println!("note: with --sequential that chance is measured, not guaranteed (RFC 6330 5.8 assumes random symbol IDs)");
                        }
                        (
                            plan.extra,
                            format!("--loss {:.4}% = {} extra", p * 100.0, plan.extra),
                        )
                    }
                    None => (u32::from(extra), format!("--extra {extra}")),
                };
                let rep = sigil::deluge_fountain_report(&data, &output, count, sequential)?;
                for (p, why) in &rep.bad {
                    eprintln!("not counted {}: {why}", p.display());
                }
                for p in &rep.stray {
                    eprintln!("not counted {}: belongs to another file", p.display());
                }
                println!(
                    "fountain {} packets (.rq, {} symbol IDs) → {}",
                    rep.total(),
                    if sequential { "sequential" } else { "random" },
                    output.display()
                );
                if rep.kept > 0 {
                    if rep.written == 0 {
                        println!(
                            "already {} packets of this file there (target {} = source symbols + {what}): nothing written",
                            rep.kept, rep.target
                        );
                    } else {
                        println!(
                            "topped up to {} (source symbols + {what}): kept {} already there, wrote {} new",
                            rep.target, rep.kept, rep.written
                        );
                    }
                }
                println!("far side: sigil gather -o rebuilt.sg1 <folder>");
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
            } else {
                let from = from.or_else(|| watch.then(sigil::rain_lane));
                if let Some(f) = from {
                    println!("this lane starts at part {f} (other people should pick a different --from so rain does not overlap)");
                }
                if watch {
                    fs::create_dir_all(&output)?;
                    println!("sending parts one at a time. Stops when the far side writes VESSEL.");
                    for round in 1..=extra {
                        if vessel_present(&output)
                            || rsync.as_deref().map(vessel_at).unwrap_or(false)
                        {
                            println!("Vessel is full. Stopping.");
                            break;
                        }
                        let before: std::collections::HashSet<_> = fs::read_dir(&output)
                            .ok()
                            .into_iter()
                            .flatten()
                            .flatten()
                            .filter_map(|e| e.file_name().into_string().ok())
                            .collect();
                        deluge_pieces(&data, round, &output, only_rain, from)?;
                        let new_files: Vec<_> = fs::read_dir(&output)?
                            .flatten()
                            .map(|e| e.path())
                            .filter(|p| {
                                p.extension().and_then(|x| x.to_str()) == Some("sgp")
                                    && p.file_name()
                                        .and_then(|n| n.to_str())
                                        .map(|n| !before.contains(n))
                                        .unwrap_or(false)
                            })
                            .collect();
                        for f in &new_files {
                            println!("new part {}", f.display());
                            if let Some(d) = &rsync {
                                rsync_file(f, d)?;
                            }
                        }
                        if rsync.is_none() {
                            println!("copy the new part to them, or use --rsync user@host:rain/");
                        }
                        if rsync.as_deref().map(vessel_at).unwrap_or(false)
                            || vessel_present(&output)
                        {
                            println!("Vessel is full. Stopping.");
                            break;
                        }
                    }
                    if wormhole {
                        dispatch(&output, &None, &None, true, false)?;
                    }
                    if let Some(d) = &rclone {
                        dispatch(&output, &None, &Some(d.clone()), false, false)?;
                    }
                } else {
                    let n = deluge_pieces(&data, extra, &output, only_rain, from)?;
                    if only_rain {
                        println!("rained {n} new pieces → {}", output.display());
                    } else {
                        println!("deluge {n} pieces → {}", output.display());
                    }
                    println!("far side can: sigil gather --watch -o rebuilt.sg1 <folder>");
                    dispatch(&output, &rsync, &rclone, wormhole, false)?;
                }
            }
        }
        Cmd::Gather {
            input,
            output,
            open,
            pass,
            pass_file,
            watch,
            report,
            partial,
            json,
        } => {
            let pass = pass.or(pass_file);
            if report {
                say!("{}", sigil::receiver_report(&input)?);
                return Ok(());
            }
            let output = output.ok_or("gather needs -o")?;
            if watch {
                say!(
                    "watching {}. Rebuilds when enough parts arrive, then writes {VESSEL} so the sender stops.",
                    input.display()
                );
                loop {
                    let fountain = is_fountain_dir(&input);
                    let mut ft_count = None;
                    let gathered = if fountain {
                        gather_fountain_noted(&input).map(|(d, r)| {
                            ft_count = Some((r.packets, r.needed as usize));
                            d
                        })
                    } else {
                        gather_pieces(&input).map_err(|e| e.into())
                    };
                    let gathered: Result<Vec<u8>, Box<dyn std::error::Error>> = gathered;
                    match gathered {
                        Ok(sg1) => {
                            let (have, k, _) = match ft_count {
                                Some((h, k)) => (h, k, 0),
                                None => tally_pieces(&input).unwrap_or((0, 0, 0)),
                            };
                            if open {
                                let plain = unseal_ex(&sg1, pass.as_deref(), &[])?;
                                fs::write(&output, plain)?;
                                say!("enough ({have} ≥ {k}). De-scribed → {}", output.display());
                            } else {
                                fs::write(&output, sg1)?;
                                say!("enough ({have} ≥ {k}). Gathered → {}", output.display());
                            }
                            write_vessel(&input, have, k)?;
                            say!("Vessel is full. Sender can stop.");
                            break;
                        }
                        Err(e) if fountain => {
                            say!("waiting… {e}");
                            std::thread::sleep(std::time::Duration::from_secs(1));
                        }
                        Err(_) => {
                            if let Ok((have, k, _)) = tally_pieces(&input) {
                                say!("waiting… {have} good parts, need {k}");
                            } else {
                                say!("waiting for the first part…");
                            }
                            std::thread::sleep(std::time::Duration::from_secs(1));
                        }
                    }
                }
            } else {
                let fountain = is_fountain_dir(&input);
                let got: Result<Vec<u8>, Box<dyn std::error::Error>> = if fountain {
                    gather_fountain_noted(&input).map(|r| r.0)
                } else {
                    gather_pieces(&input).map_err(|e| e.into())
                };
                let sg1 = match got {
                    Ok(b) => b,
                    Err(e) if partial => {
                        return Err(gather_partial(
                            &input,
                            &output,
                            fountain,
                            json,
                            &e.to_string(),
                        )?
                        .into());
                    }
                    Err(e) => return Err(e),
                };
                if open {
                    let plain = unseal_ex(&sg1, pass.as_deref(), &[])?;
                    fs::write(&output, plain)?;
                    say!("gathered and de-scribed → {}", output.display());
                } else {
                    fs::write(&output, sg1)?;
                    say!("gathered mark → {}", output.display());
                }
            }
        }
        Cmd::Mend {
            input,
            output,
            soft: _,
        } if sigil::is_sealed_dir_pack(&input) => {
            println!("{}", sigil::mend_sealed_dir(&input, &output)?);
        }
        Cmd::Mend {
            input,
            output,
            soft,
        } if sigil::is_plain_dir_pack(&input) => {
            println!("{}", sigil::mend_plain_dir(&input, &output, soft)?);
        }
        Cmd::Mend {
            input,
            output,
            soft,
        } if sigil::is_work_pack(&input) => {
            mend_pack_report(&input, &output, soft)?;
        }
        Cmd::Mend {
            input,
            output,
            soft,
        } => {
            let data = fs::read(&input)?;
            let (healed, used_soft) = match mend_bytes_ex(&data, soft) {
                Ok(v) => v,
                // A large-file pack whose head (even its magic) is damaged looks like
                // several seals back to back; rebuild the head when that is unambiguous.
                Err(e) => {
                    drop(data);
                    if sigil::is_damaged_work_pack(&input) {
                        mend_pack_report(&input, &output, soft)?;
                        return Ok(());
                    }
                    return Err(e.into());
                }
            };
            let mut tmp = output.as_os_str().to_os_string();
            tmp.push(".mend-part");
            let tmp = PathBuf::from(tmp);
            fs::write(&tmp, &healed)?;
            fs::rename(&tmp, &output)?;
            let (h, merkle_ok, live, k, _) = sigil::verify(&healed)?;
            println!(
                "mended {} → {} (live {live}/{n}, need {k}, merkle {ok}{soft_note})",
                input.display(),
                output.display(),
                n = h.n,
                ok = if merkle_ok { "ok" } else { "open" },
                soft_note = if used_soft { ", soft salvage" } else { "" }
            );
        }
        Cmd::Dispatch {
            input,
            rsync,
            rclone,
            wormhole,
            overture,
        } => {
            if rsync.is_none() && rclone.is_none() && !wormhole {
                return Err("dispatch needs --rsync, --rclone, and/or --wormhole".into());
            }
            dispatch(&input, &rsync, &rclone, wormhole, overture)?;
        }
        Cmd::Circle {
            input,
            output,
            peers,
            pass,
            pass_file,
            open,
            extra,
        } => {
            let pass = pass.or(pass_file);
            fs::create_dir_all(&input)?;
            println!(
                "Coven on {}. Share parts. First to rebuild mints new parts. Ctrl-C to stop.",
                input.display()
            );
            if peers.is_empty() {
                println!("no --peer: using this folder as the pool (Syncthing/USB/NFS).");
            }
            let lane = sigil::rain_lane();
            println!("this machine’s new parts start at {lane}");
            let mut rained = false;
            loop {
                for p in &peers {
                    let _ = rsync_dir(p, input.to_str().unwrap_or("."));
                }
                match gather_pieces(&input) {
                    Ok(sg1) => {
                        if !vessel_present(&input) {
                            let (have, k, _) = tally_pieces(&input).unwrap_or((0, 0, 0));
                            if open {
                                let plain = unseal_ex(&sg1, pass.as_deref(), &[])?;
                                fs::write(&output, plain)?;
                                println!("whole ({have} ≥ {k}). De-scribed → {}", output.display());
                            } else {
                                fs::write(&output, &sg1)?;
                                println!("whole ({have} ≥ {k}). Gathered → {}", output.display());
                            }
                            write_vessel(&input, have, k)?;
                        }
                        if !rained {
                            let n = deluge_pieces(&sg1, extra.max(1), &input, true, Some(lane))?;
                            println!(
                                "raining {n} new parts from lane {lane} for people still short"
                            );
                            rained = true;
                        }
                    }
                    Err(_) => {
                        if let Ok((have, k, _)) = tally_pieces(&input) {
                            println!("not whole: {have}/{k} unique parts");
                        } else {
                            println!("waiting for parts…");
                        }
                    }
                }
                let local = input.to_str().unwrap_or(".");
                for p in &peers {
                    let _ = rsync_dir(local, p);
                }
                if vessel_present(&input) && !peers.is_empty() && all_peers_vessel(&peers) {
                    println!("everyone in --peer has a Vessel. Coven is done.");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        }
        Cmd::Show {
            input,
            bind,
            public,
            plex,
            strm,
            pass,
            pass_file,
            idle,
        } => {
            let pass = pass.or(pass_file);
            if plex.is_none() && strm.is_none() {
                eprintln!("tip: pass --plex /path/to/Plex/Movies so a .strm stub is written there");
            }
            run_showing(
                &input,
                &bind,
                plex.as_deref(),
                strm.as_deref(),
                &public,
                pass.as_deref(),
                idle,
            )?;
        }
        Cmd::Overture { input } => {
            println!("{}", overture_report(&input)?);
        }
        Cmd::Open {
            input,
            pass,
            pass_file,
            talisman,
            identity,
            ward,
            ward_file,
            only,
            keep,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            run_open_keys(
                &input,
                pass.as_deref(),
                &parse_wards(&ward, &ward_file, false)?,
                &only,
                keep,
                &identities,
            )?;
        }
        Cmd::Keygen {
            output,
            pub_out,
            legacy,
            ecc: _,
            passkey,
            rp_id,
            no_uv,
        } => {
            if passkey {
                let id = Identity::generate()?;
                let mut auth = sigil::passkey::default_authenticator()?;
                let w = sigil::passkey::Wrapped::protect(&id, auth.as_mut(), &rp_id, !no_uv)?;
                w.write(&output)?;
                let pub_path = pub_out.unwrap_or_else(|| {
                    let mut p = output.as_os_str().to_os_string();
                    p.push(".pub");
                    PathBuf::from(p)
                });
                w.public.write(&pub_path)?;
                println!(
                    "identity → {}  (passkey-protected, {})  x25519 {}",
                    output.display(),
                    if w.slots[0].uv {
                        "PIN/UV"
                    } else {
                        "touch only"
                    },
                    hex32(&w.public.x25519_pk)
                );
                println!(
                    "public → {}  (encrypt-to: --to {})",
                    pub_path.display(),
                    pub_path.display()
                );
                println!(
                    "add a backup key now: sigil identity add-passkey {}",
                    output.display()
                );
            } else if legacy {
                let pk = keygen_legacy(&output)?;
                println!(
                    "legacy attest key → {}  public {}",
                    output.display(),
                    hex32(&pk)
                );
                println!("same file is a Talisman: --talisman {}", output.display());
            } else {
                let pk = keygen_ecc(&output, pub_out.as_deref())?;
                let pub_path = pub_out.unwrap_or_else(|| {
                    let mut p = output.as_os_str().to_os_string();
                    p.push(".pub");
                    PathBuf::from(p)
                });
                println!(
                    "identity → {}  x25519 {}",
                    output.display(),
                    hex32(&pk.x25519_pk)
                );
                println!(
                    "public → {}  (encrypt-to: --to {})",
                    pub_path.display(),
                    pub_path.display()
                );
                println!(
                    "attest seed is inside .sgk; sign with --key {}",
                    output.display()
                );
            }
        }
        Cmd::ImportPgp {
            input,
            output,
            pub_out,
            passphrase_file,
            passkey,
        } => {
            let raw = zeroize::Zeroizing::new(fs::read(&input)?);
            let mut imp = sigil::pgp::import(&raw)?;
            if output.is_some() && imp.secret.is_none() && sigil::pgp::secret_is_protected(&raw) {
                let pass = pgp_passphrase(passphrase_file.as_deref())?;
                imp = sigil::pgp::import_with_passphrase(&raw, Some(pass.as_bytes()))?;
            }
            let pub_path = pub_out.unwrap_or_else(|| {
                let base = output.as_ref().unwrap_or(&input);
                let mut p = base.with_extension("").into_os_string();
                p.push(".pub");
                PathBuf::from(p)
            });
            if let Some(out) = &output {
                let Some(id) = imp.secret.as_ref() else {
                    return Err(format!(
                        "no secret identity written: {}",
                        sigil::pgp::secret_unavailable_reason(&raw)
                    )
                    .into());
                };
                if passkey {
                    let mut auth = sigil::passkey::default_authenticator()?;
                    let w = sigil::passkey::Wrapped::protect(
                        id,
                        auth.as_mut(),
                        sigil::passkey::DEFAULT_RP_ID,
                        true,
                    )?;
                    w.write(out)?;
                    println!("identity → {}  (passkey-protected; add a backup: sigil identity add-passkey {})", out.display(), out.display());
                } else {
                    id.write(out)?;
                    println!("identity → {}  (.sgk v2, owner-only)", out.display());
                }
            } else if imp.had_secret_packets {
                println!(
                    "note: secret packets ignored (public only); pass -o me.sgk to import them"
                );
            }
            imp.public.write(&pub_path)?;
            println!(
                "pgp {}  {}{}",
                hex::encode_upper(&imp.primary_fpr),
                imp.user_id.as_deref().unwrap_or("(no verified user id)"),
                if imp.key_version == 6 {
                    "  (OpenPGP v6)"
                } else {
                    ""
                }
            );
            println!("encrypt subkey {}", hex::encode_upper(&imp.subkey_fpr));
            println!(
                "public → {}  x25519 {}  (encrypt-to: --to {})",
                pub_path.display(),
                hex32(&imp.public.x25519_pk),
                pub_path.display()
            );
        }
        Cmd::Sign { input, key } => {
            let dest = attest(&input, &key)?;
            println!("attestation → {}", dest.display());
        }
        Cmd::Boot { cmd } => run_boot(cmd)?,
        Cmd::Constellation { cmd } => run_sky(cmd)?,
        Cmd::Log { cmd } => run_log(cmd)?,
        Cmd::Tidy {
            path,
            dry_run,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let report = sigil::container::tidy(
                &path,
                &sigil::container::TidyOpts {
                    dry_run,
                    pass: pass.as_deref(),
                    identities: &identities,
                    fault: None,
                },
            )?;
            print!("{}", report.render());
        }
        Cmd::Doctor {
            path,
            json,
            fix,
            quick,
            scrub,
            pass,
            pass_file,
            talisman,
            identity,
            temp_age,
        } => {
            if scrub {
                match sigil::scrub::scrub_dir(&path) {
                    Ok(r) => {
                        print!("{}", r.render());
                        std::process::exit(r.exit_code());
                    }
                    Err(e) => {
                        eprintln!("sigil doctor --scrub: {e}");
                        std::process::exit(3);
                    }
                }
            }
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            match sigil::doctor::doctor(
                &path,
                &sigil::doctor::DoctorOpts {
                    pass: pass.as_deref(),
                    identities: &identities,
                    quick,
                    fix,
                    temp_age_secs: temp_age,
                },
            ) {
                Ok(r) => {
                    if json {
                        print!("{}", r.to_json());
                    } else {
                        print!("{}", r.render());
                    }
                    std::process::exit(r.exit_code());
                }
                Err(e) => {
                    eprintln!("sigil doctor: {e}");
                    std::process::exit(3);
                }
            }
        }
        Cmd::Gc {
            path,
            apply,
            dry_run: _,
            pass,
            pass_file,
            talisman,
            identity,
            temp_age,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let r = sigil::gc::gc(
                &path,
                &sigil::gc::GcOpts {
                    apply,
                    pass: pass.as_deref(),
                    identities: &identities,
                    temp_age_secs: temp_age,
                },
            )?;
            print!("{}", r.render());
        }
        Cmd::Kit { cmd } => run_kit(cmd)?,
        Cmd::Path {
            input,
            segments,
            into,
            pass,
            pass_file,
            talisman,
            identity,
            ward,
            ward_file,
            depth,
            output,
            pretty,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let wards = parse_wards(&ward, &ward_file, false)?;
            let mut steps = into;
            steps.extend(segments);
            // Containers: list / address members by their own names (`Sky.sigil`, `notes.txt.sigil`).
            let mut input = input;
            if !input.is_file() && sigil::seglog::is_log(&input) {
                print!("{}", sigil::seglog::list(&input)?.render());
                return Ok(());
            }
            if !input.is_file() {
                if let Some(sky) = sigil::names::sky_dir(&input) {
                    let entries = sigil::names::sky_entries(&sky, pass.as_deref(), &identities)?;
                    let first = steps
                        .first()
                        .map(|s| s.trim().trim_start_matches("./").to_string());
                    match first
                        .as_deref()
                        .and_then(|f| entries.iter().find(|e| e.name == f))
                    {
                        Some(e) => {
                            input = e.star.clone().ok_or_else(|| {
                                format!("star for {} is missing (see `sigil doctor`)", e.name)
                            })?;
                            steps.remove(0);
                        }
                        None => {
                            let prefix = first.unwrap_or_default();
                            if !prefix.is_empty()
                                && !entries.iter().any(|e| e.name.starts_with(&prefix))
                            {
                                return Err(format!("nothing named {prefix:?} on the list").into());
                            }
                            print!("{}", sigil::names::render_sky(&sky, &entries, &prefix));
                            return Ok(());
                        }
                    }
                } else if let Some(vdir) = sigil::names::vault_dir(&input) {
                    match steps.first().map(|s| sigil::names::parse_version_ref(s)) {
                        None => {
                            print!("{}", sigil::names::render_vault(&vdir)?);
                            return Ok(());
                        }
                        Some(Some(n)) => {
                            input = sigil::names::version_seal(&vdir, n)?;
                            steps.remove(0);
                        }
                        Some(None) => {
                            return Err(format!(
                                "{:?} is not a version (try v1, @2, or notes.txt@v3)",
                                steps[0]
                            )
                            .into());
                        }
                    }
                }
            }
            let view = path_walk_keys(&input, &steps, pass.as_deref(), &wards, depth, &identities)?;
            if pretty {
                use std::io::IsTerminal;
                let style = sigil::pretty::Style::from_env(std::io::stdout().is_terminal());
                // Condition comes from the same Scry verdicts `sigil scry` prints;
                // only the outer file (no breadcrumb) is checked.
                let mut extra = sigil::pretty::Extra::default();
                let mark_scry = if steps.is_empty() && view.kind == sigil::NestKind::Mark {
                    sigil::scry_path_checked(&input).ok()
                } else {
                    None
                };
                if let Some((text, bad)) = &mark_scry {
                    let line = text.lines().next().unwrap_or_default();
                    extra.health = sigil::pretty::health_from_mark_scry(line, bad.as_deref());
                    extra.scry_line = Some(line);
                }
                if steps.is_empty() && view.kind == sigil::NestKind::DirPack {
                    if let Ok((text, bad)) =
                        sigil::scry_dir_checked(&input, pass.as_deref(), &[], &identities)
                    {
                        extra.health =
                            Some(sigil::pretty::health_from_dir_scry(&text, bad.as_deref()));
                    }
                }
                println!("{}", sigil::pretty::render_path_view(&view, &extra, &style));
            } else {
                println!("{}", view.format());
            }
            if let Some(dest) = output {
                let (written, trail) = path_extract_keys(
                    &input,
                    &steps,
                    &dest,
                    pass.as_deref(),
                    &wards,
                    depth,
                    &identities,
                )?;
                println!(
                    "extracted {} → {} (outer .sg1 unchanged)",
                    trail.join(" → "),
                    written.display()
                );
            }
        }
        Cmd::Vault { cmd } => run_vault(cmd)?,
        Cmd::IdentityTool { cmd } => run_identity(cmd)?,
        Cmd::Mount {
            input,
            mountpoint,
            pass,
            pass_file,
            talisman,
            identity,
            ward,
            ward_file,
            vault,
            export_dir,
            writable,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let pass = match pass {
                Some(p) => Some(p),
                None => match std::env::var("SIGIL_WARD") {
                    Ok(s) if !s.trim().is_empty() => Some(s),
                    _ => None,
                },
            };
            let wards = parse_wards(&ward, &ward_file, false)?;
            run_mount_keys(
                &input,
                &mountpoint,
                pass.as_deref(),
                &wards,
                vault,
                export_dir.as_deref(),
                &identities,
                writable,
            )?;
        }
        Cmd::Umount { mountpoint } => {
            umount_path(&mountpoint)?;
            println!("unmounted {}", mountpoint.display());
        }
        Cmd::BenchMds { iters } => {
            let rows = run_bakeoff(iters)?;
            let (report, _keep) = format_bakeoff_report(&rows);
            print!("{report}");
        }
    }
    Ok(())
}

fn write_atomic_secret(
    dest: &Path,
    w: &sigil::passkey::Wrapped,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tmp = dest.as_os_str().to_os_string();
    tmp.push(".sigil-tmp");
    let tmp = PathBuf::from(tmp);
    w.write(&tmp)?;
    fs::rename(&tmp, dest)?;
    Ok(())
}

fn run_identity(cmd: IdentityCmd) -> Result<(), Box<dyn std::error::Error>> {
    use sigil::passkey::{default_authenticator, is_wrapped, Wrapped};
    match cmd {
        IdentityCmd::Protect {
            input,
            output,
            in_place,
            passkey: _,
            rp_id,
            no_uv,
        } => {
            let raw = fs::read(&input)?;
            if is_wrapped(&raw) {
                return Err(
                    "already passkey-protected; use `identity add-passkey` for a backup key".into(),
                );
            }
            let id = Identity::load(&input)?;
            let mut auth = default_authenticator()?;
            let w = Wrapped::protect(&id, auth.as_mut(), &rp_id, !no_uv)?;
            // Prove the new file opens before anything is replaced.
            Wrapped::parse(&w.to_bytes())?.unlock(auth.as_mut())?;
            let dest = if in_place {
                input.clone()
            } else {
                output.unwrap()
            };
            write_atomic_secret(&dest, &w)?;
            println!(
                "protected → {}  ({}, rp {})",
                dest.display(),
                if w.slots[0].uv {
                    "PIN/UV"
                } else {
                    "touch only"
                },
                rp_id
            );
            if !in_place {
                println!("the plain copy {} still exists — delete it (shred -u) once you've tested the new file", input.display());
            }
            println!(
                "add a backup key: sigil identity add-passkey {}",
                dest.display()
            );
        }
        IdentityCmd::AddPasskey {
            input,
            rp_id,
            no_uv,
        } => {
            let mut w = Wrapped::load(&input)?;
            let mut unlock = default_authenticator()?;
            let mut new_auth = default_authenticator()?;
            eprintln!(
                "passkey: unlock with an existing key first; then plug in the new key when asked"
            );
            w.add_slot(unlock.as_mut(), new_auth.as_mut(), &rp_id, !no_uv)?;
            write_atomic_secret(&input, &w)?;
            println!(
                "added passkey slot #{} → {}",
                w.slots.len() - 1,
                input.display()
            );
        }
        IdentityCmd::RemovePasskey { input, slot } => {
            let mut w = Wrapped::load(&input)?;
            w.remove_slot(slot)?;
            write_atomic_secret(&input, &w)?;
            println!("removed passkey slot #{slot}; {} left", w.slots.len());
        }
        IdentityCmd::Unprotect { input, output } => {
            let id = Identity::load(&input)?;
            id.write(&output)?;
            println!(
                "plain identity → {}  (owner-only; anyone with this file can open your seals)",
                output.display()
            );
        }
        IdentityCmd::Info { input } => {
            let raw = fs::read(&input)?;
            if is_wrapped(&raw) {
                print!("{}", Wrapped::parse(&raw)?.describe());
            } else {
                let pk = sigil::PublicIdentity::load(&input)?;
                let kind = if raw.len() > 4 && raw[0..4] == sigil::ID_MAGIC {
                    match raw[4] {
                        1 => "plain identity (.sgk v1, unprotected)",
                        2 => "plain identity (.sgk v2 imported, unprotected)",
                        _ => "identity (unknown version)",
                    }
                } else {
                    "public key"
                };
                println!(
                    "{kind}\n  x25519 {}\n  ed25519 {}",
                    hex32(&pk.x25519_pk),
                    hex32(&pk.ed25519_pk)
                );
            }
        }
    }
    Ok(())
}

fn run_vault(cmd: VaultCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        VaultCmd::Track {
            path,
            mode,
            pass,
            pass_file,
            talisman,
            to,
            ward,
            ward_file,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let recipients = load_recipients(&to)?;
            let wards = parse_wards(&ward, &ward_file, true)?;
            let report = vault_track_ex(&path, mode.into(), pass.as_deref(), &recipients, &wards)?;
            println!(
                "vault track → {}  v{}  {} bytes  digest={}",
                report.vault_dir.display(),
                report.version,
                report.size,
                &hex32(&report.digest)[..12]
            );
            if !recipients.is_empty() {
                println!(
                    "encrypt-to {} recipient{}",
                    recipients.len(),
                    if recipients.len() == 1 { "" } else { "s" }
                );
            }
            println!("{}", vault_format_status(&vault_status(&path)?));
        }
        VaultCmd::Status { path } => {
            println!("{}", vault_format_status(&vault_status(&path)?));
        }
        VaultCmd::Commit {
            path,
            from_export,
            mode,
            pass,
            pass_file,
            talisman,
            to,
            ward,
            ward_file,
            force,
            keep,
            cold,
            force_drop,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let recipients = load_recipients(&to)?;
            let wards = parse_wards(&ward, &ward_file, true)?;
            let (report, status_path) = if let Some(export) = from_export {
                let report = vault_commit_from_export_ex(
                    &export,
                    mode.into(),
                    pass.as_deref(),
                    force,
                    &recipients,
                    &wards,
                )?;
                let meta = sigil::VaultDirtyMeta::read(&export)?;
                let live = meta
                    .live
                    .ok_or("dirty export missing live= (not vault-tracked)")?;
                (report, live)
            } else {
                let path = path.ok_or("vault commit needs a live path, or --from-export DIR")?;
                let report = vault_commit_ex(
                    &path,
                    mode.into(),
                    pass.as_deref(),
                    force,
                    &recipients,
                    &wards,
                )?;
                (report, path)
            };
            if report.skipped {
                println!(
                    "vault commit skipped (matches tip v{})  digest={}",
                    report.version,
                    &hex32(&report.digest)[..12]
                );
            } else {
                println!(
                    "vault commit → v{}  {} bytes  digest={}",
                    report.version,
                    report.size,
                    &hex32(&report.digest)[..12]
                );
            }
            if let Some(note) = &report.note {
                println!("note: {note}");
            }
            if !report.skipped {
                let effective = vault_get_recipients(&status_path)?;
                if !effective.is_empty() {
                    println!(
                        "encrypt-to {} recipient{}{}",
                        effective.len(),
                        if effective.len() == 1 { "" } else { "s" },
                        if recipients.is_empty() {
                            " (remembered)"
                        } else {
                            " (now remembered)"
                        }
                    );
                }
            }
            // Explicit --keep, or chart light policy: prune after a real commit.
            if !report.skipped {
                if let Some(p) =
                    vault_maybe_prune_after_commit(&status_path, keep, cold.as_deref(), force_drop)?
                {
                    if !p.removed.is_empty() {
                        let where_cold = p
                            .cold_dir
                            .as_ref()
                            .map(|d| format!("  cold={}", d.display()))
                            .unwrap_or_default();
                        println!(
                            "pruned v{{{}}}  kept={}{}",
                            p.removed
                                .iter()
                                .map(|n| n.to_string())
                                .collect::<Vec<_>>()
                                .join(","),
                            p.kept,
                            where_cold
                        );
                    }
                }
            }
            println!("{}", vault_format_status(&vault_status(&status_path)?));
        }
        VaultCmd::Versions { path } => {
            print!("{}", vault_format_versions(&vault_list_versions(&path)?));
        }
        VaultCmd::Restore {
            path,
            version,
            pass,
            pass_file,
            talisman,
            identity,
            ward,
            ward_file,
            force,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let wards = parse_wards(&ward, &ward_file, false)?;
            let report =
                vault_restore_ex(&path, version, pass.as_deref(), &identities, &wards, force)?;
            println!(
                "vault restore → {}  v{}  {} bytes  digest={}{}",
                report.path.display(),
                report.version,
                report.size,
                &hex32(&report.digest)[..12],
                if report.mended { "  (mended seal)" } else { "" }
            );
            println!("{}", vault_format_status(&vault_status(&path)?));
        }
        VaultCmd::Prune {
            path,
            keep,
            cold,
            force_drop,
            cold_here,
        } => {
            let cold = if cold_here {
                Some(sigil::vault_cold_here(&path)?)
            } else {
                cold
            };
            let p = vault_prune_with(&path, keep, cold.as_deref(), force_drop)?;
            let removed = if p.removed.is_empty() {
                "(none)".to_string()
            } else {
                p.removed
                    .iter()
                    .map(|n| format!("v{n}"))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let where_cold = p
                .cold_dir
                .as_ref()
                .map(|d| format!("  cold={}", d.display()))
                .unwrap_or_default();
            println!(
                "vault prune kept={} tip=v{} removed={}{}",
                p.kept, p.tip, removed, where_cold
            );
            print!("{}", vault_format_versions(&vault_list_versions(&path)?));
        }
        VaultCmd::Remove {
            path,
            version,
            cold,
            cold_here,
            force_drop,
            dry_run,
        } => {
            let cold = if cold_here {
                Some(sigil::vault_cold_here(&path)?)
            } else {
                cold
            };
            let r =
                sigil::vault_remove_version(&path, version, cold.as_deref(), force_drop, dry_run)?;
            println!(
                "{}vault remove v{} tip=v{} remaining={}{}",
                if r.dry_run { "dry run: would " } else { "" },
                r.removed,
                r.tip,
                r.remaining,
                r.cold_dir
                    .as_ref()
                    .map(|d| format!("  cold={}", d.display()))
                    .unwrap_or_default()
            );
            if !r.dry_run {
                print!("{}", vault_format_versions(&vault_list_versions(&path)?));
            }
        }
        VaultCmd::Recipients { path, to, clear } => {
            if clear {
                vault_set_recipients(&path, &[])?;
                println!("vault recipients cleared — future versions are not encrypt-to (existing seals unchanged)");
            } else if !to.is_empty() {
                let rs = load_recipients(&to)?;
                vault_set_recipients(&path, &rs)?;
            }
            print!("{}", vault_format_recipients(&vault_get_recipients(&path)?));
        }
        VaultCmd::Retention {
            path,
            full,
            light,
            keep,
        } => {
            if full {
                let p = vault_set_retention(&path, VaultRetention::Full)?;
                println!("vault retention → {}", vault_format_retention(p));
            } else if light {
                let k = keep.ok_or("light retention needs --keep N (≥ 1)")?;
                if k == 0 {
                    return Err("light --keep must be ≥ 1".into());
                }
                let p = vault_set_retention(&path, VaultRetention::Light { keep: k })?;
                println!("vault retention → {}", vault_format_retention(p));
            } else if keep.is_some() {
                return Err("pass --light with --keep N, or --full".into());
            } else {
                let p = vault_get_retention(&path)?;
                println!("vault {}  {}", path.display(), vault_format_retention(p));
            }
            print!("{}", vault_format_versions(&vault_list_versions(&path)?));
        }
    }
    Ok(())
}

fn run_kit(cmd: KitCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        KitCmd::Place {
            input,
            output,
            drives,
        } => {
            let data = fs::read(&input)?;
            let report = place_kit(&data, &output, drives)?;
            println!(
                "cold-USB kit Option A → {}  drives={} pieces={} ({} each) star={}",
                output.display(),
                report.drives,
                report.pieces,
                report
                    .per_drive
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join("/"),
                &report.star_id[..8.min(report.star_id.len())],
            );
            println!("copy each usb-* folder to its own stick. Lose one stick → sigil kit mend");
        }
        KitCmd::Mend { input, output } => {
            let healed = mend_kit(&input)?;
            let n = healed.len();
            fs::write(&output, &healed)?;
            println!("kit mend {n} bytes → {}", output.display());
        }
    }
    Ok(())
}

/// `--signer`: 64-hex Ed25519 public key, or a .pub / .sgk file.
fn parse_signer(spec: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let p = Path::new(spec);
    if p.is_file() {
        if let Ok(pk) = sigil::PublicIdentity::load(p) {
            return Ok(pk.ed25519_pk);
        }
        return Ok(Identity::load(p)?.public().ed25519_pk);
    }
    let b = hex::decode(spec.trim())
        .map_err(|_| format!("--signer: not a file and not hex: {spec}"))?;
    b.try_into()
        .map_err(|_| "--signer hex must be 32 bytes (64 hex chars)".into())
}

/// `90`, `45s`, `30m`, `12h`, `7d`, `2w` → seconds.
fn parse_duration_secs(spec: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let t = spec.trim();
    let (num, mult) = match t.chars().last() {
        Some('s') => (&t[..t.len() - 1], 1),
        Some('m') => (&t[..t.len() - 1], 60),
        Some('h') => (&t[..t.len() - 1], 3600),
        Some('d') => (&t[..t.len() - 1], 86400),
        Some('w') => (&t[..t.len() - 1], 7 * 86400),
        _ => (t, 1),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("bad duration {spec:?}: use e.g. 90, 30m, 12h, 7d, 2w"))?;
    Ok(n.saturating_mul(mult))
}

fn parse_anchor(spec: &str) -> Result<(u64, [u8; 32]), Box<dyn std::error::Error>> {
    let (n, r) = spec
        .split_once(':')
        .ok_or("--anchor needs SEQ:ROOT (as printed by `sigil log ls`)")?;
    let root: [u8; 32] = hex::decode(r.trim())
        .map_err(|_| "--anchor ROOT is not hex")?
        .try_into()
        .map_err(|_| "--anchor ROOT must be 32 bytes (64 hex chars)")?;
    Ok((n.trim().parse()?, root))
}

fn run_log(cmd: LogCmd) -> Result<(), Box<dyn std::error::Error>> {
    use sigil::seglog;
    match cmd {
        LogCmd::Init {
            path,
            identity,
            segment_keys,
            private_index,
            public_index,
            pass,
            pass_file,
            talisman,
            to,
        } => {
            let pass = pass.or(pass_file);
            let id = identity.as_deref().map(Identity::load).transpose()?;
            let mut pass = resolve_pass(pass, talisman)?;
            let mut recipients = load_recipients(&to)?;
            let keyed = pass.is_some() || !recipients.is_empty();
            // Safe by default: a log created with a key gets a private INDEX.
            let private_index = private_index || (keyed && !public_index);
            if public_index {
                eprintln!(
                    "WARNING: --public-index: every entry's file name, size and SHA-256 will be \
                     readable by anyone who can see the log folder (and a guessed file can be \
                     confirmed by hashing it). Leave out --public-index to seal them."
                );
                if keyed {
                    eprintln!(
                        "WARNING: --pass / --to are not used by a public INDEX; give them to each \
                         `log append` / `log add` to encrypt the segments."
                    );
                    pass = None;
                    recipients.clear();
                }
            }
            let log = seglog::init_opts(
                &path,
                &seglog::InitOpts {
                    sign: id.as_ref(),
                    segment_keys,
                    private_index,
                    index_pass: pass.as_deref(),
                    index_to: &recipients,
                },
            )?;
            println!(
                "log {}  created ({}{})",
                log.dir.display(),
                match &log.signer {
                    Some(pk) => format!("signed; signer {}", hex::encode(pk)),
                    None => "unsigned: HEAD is a checksum, not a signature (use --identity for authenticity)".to_string(),
                },
                if segment_keys { "; per-segment keys: append with --pass and/or --to to wrap each segment's key, then `sigil log shred` can destroy it" } else { "" }
            );
            if private_index {
                println!("private INDEX: sizes, hashes and file names are sealed; writers and readers need the --pass / --identity the index key was wrapped to");
            } else if !public_index {
                println!("public INDEX: no --pass / --to given, so file names, sizes and SHA-256s are stored in the clear (create the log with --pass or --to to seal them)");
            }
        }
        LogCmd::Append {
            path,
            input,
            mode,
            pass,
            pass_file,
            talisman,
            to,
            identity,
            unlock,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let recipients = load_recipients(&to)?;
            let id = identity.as_deref().map(Identity::load).transpose()?;
            let unlock = load_identities(&unlock)?;
            let data = if input == "-" {
                use std::io::Read;
                let mut b = Vec::new();
                std::io::stdin().lock().read_to_end(&mut b)?;
                b
            } else {
                fs::read(&input)?
            };
            let r = seglog::append(
                &path,
                &data,
                &seglog::AppendOpts {
                    mode: mode.into(),
                    pass: pass.as_deref(),
                    recipients: &recipients,
                    identity: id.as_ref(),
                    unlock: &unlock,
                },
            )?;
            for n in &r.notes {
                eprintln!("note: {n}");
            }
            println!(
                "segment {}  {} bytes → {} sealed  sha256 {}…  head {}:{}{}",
                r.seq,
                r.size,
                r.sealed_bytes,
                &hex::encode(r.sha)[..16],
                r.seq,
                hex::encode(r.root),
                if r.signed { "  (signed)" } else { "" }
            );
        }
        LogCmd::Add {
            path,
            dir,
            mode,
            pass,
            pass_file,
            talisman,
            to,
            identity,
            dry_run,
            exclude,
            no_ignore_file,
            cache,
            unlock,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let recipients = load_recipients(&to)?;
            let id = identity.as_deref().map(Identity::load).transpose()?;
            let unlock = load_identities(&unlock)?;
            let r = seglog::add(
                &path,
                &dir,
                &seglog::AddOpts {
                    mode: mode.into(),
                    pass: pass.as_deref(),
                    recipients: &recipients,
                    identity: id.as_ref(),
                    dry_run,
                    exclude: &exclude,
                    no_ignore_file,
                    unlock: &unlock,
                    cache,
                    ..Default::default()
                },
            )?;
            for n in &r.notes {
                eprintln!("note: {n}");
            }
            print!("{}", r.render());
            if !r.unreadable.is_empty() {
                std::process::exit(1);
            }
        }
        LogCmd::Ls {
            path,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            print!(
                "{}",
                seglog::list_with(&path, pass.as_deref(), &identities)?.render()
            )
        }
        LogCmd::Restore {
            log,
            path,
            output,
            at,
            seq,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let ver = seglog::Version {
                at: at.as_deref().map(seglog::parse_utc).transpose()?,
                seq,
            };
            let r = seglog::restore_version(
                &log,
                &path,
                output.as_deref(),
                &seglog::ReadOpts {
                    pass: pass.as_deref(),
                    identities: &identities,
                },
                &ver,
            )?;
            print!("{}", r.render());
        }
        LogCmd::Rewrap {
            path,
            pass,
            pass_file,
            talisman,
            identity,
            add_to,
            remove_to,
            new_pass,
            new_pass_file,
            drop_pass,
            replace,
            dry_run,
        } => {
            let pass = resolve_pass(pass.or(pass_file), talisman)?;
            let identities = load_identities(&identity)?;
            let add = load_recipients(&add_to)?;
            let remove = load_recipients(&remove_to)?;
            let new_pass = new_pass.or(new_pass_file);
            let r = seglog::rewrap(
                &path,
                &seglog::RewrapOpts {
                    pass: pass.as_deref(),
                    identities: &identities,
                    add: &add,
                    remove: &remove,
                    new_pass: new_pass.as_deref(),
                    drop_pass,
                    replace,
                    dry_run,
                },
            )?;
            print!("{}", r.render());
        }
        LogCmd::Card {
            children,
            name,
            identity,
            output,
        } => {
            let id = identity.as_deref().map(Identity::load).transpose()?;
            let c = seglog::make_card(&name, &children, id.as_ref())?;
            let text = c.render();
            match output {
                Some(o) => {
                    fs::write(&o, &text)?;
                    eprintln!(
                        "card {} ({} children, {}) root {} written to {}",
                        c.name,
                        c.children.len(),
                        if c.signer.is_some() {
                            "signed"
                        } else {
                            "unsigned"
                        },
                        hex::encode(c.root),
                        o.display()
                    );
                }
                None => print!("{text}"),
            }
        }
        LogCmd::CheckCard {
            card,
            child,
            all,
            signer,
        } => {
            let text =
                fs::read_to_string(&card).map_err(|e| format!("read {}: {e}", card.display()))?;
            let opts = seglog::CardCheckOpts {
                signer: signer.as_deref().map(parse_signer).transpose()?,
                children: &child,
                all,
            };
            match seglog::Card::parse(&text).and_then(|c| seglog::check_card(&c, &opts)) {
                Ok(c) => print!("{}", c.render()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
        LogCmd::Privatize {
            src,
            dest,
            mode,
            pass,
            pass_file,
            talisman,
            to,
            identity,
            sign,
        } => {
            let pass = resolve_pass(pass.or(pass_file), talisman)?;
            let recipients = load_recipients(&to)?;
            let identities = load_identities(&identity)?;
            let sign = sign.as_deref().map(Identity::load).transpose()?;
            let r = seglog::privatize(
                &src,
                &dest,
                &seglog::PrivatizeOpts {
                    pass: pass.as_deref(),
                    identities: &identities,
                    to: &recipients,
                    sign: sign.as_ref(),
                    mode: mode.into(),
                },
            )?;
            print!("{}", r.render());
        }
        LogCmd::CardProve {
            card,
            child,
            output,
        } => {
            let text =
                fs::read_to_string(&card).map_err(|e| format!("read {}: {e}", card.display()))?;
            let p = seglog::prove_card_child(&seglog::Card::parse(&text)?, &child)?;
            match output {
                Some(o) => {
                    fs::write(&o, p.render())?;
                    eprintln!(
                        "receipt for child-{} of {} ({}) written to {}",
                        p.index,
                        p.name,
                        p.child.describe(),
                        o.display()
                    );
                }
                None => print!("{}", p.render()),
            }
        }
        LogCmd::CheckCardChild {
            receipt,
            signer,
            expect,
            child,
        } => {
            let text = fs::read_to_string(&receipt)
                .map_err(|e| format!("read {}: {e}", receipt.display()))?;
            let opts = seglog::CardChildCheckOpts {
                signer: signer.as_deref().map(parse_signer).transpose()?,
                expect: expect.as_deref(),
                child: child.as_deref(),
            };
            match seglog::CardChildProof::parse(&text)
                .and_then(|p| seglog::check_card_child(&p, &opts))
            {
                Ok(c) => print!("{}", c.render()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
        LogCmd::CheckCardConsistency {
            old,
            new,
            signer,
            child,
            proof,
            pair,
        } => {
            let read = |p: &PathBuf| {
                fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))
            };
            let (ot, nt) = (read(&old)?, read(&new)?);
            let pairs: Vec<(PathBuf, PathBuf)> = pair
                .chunks(2)
                .filter_map(|c| match c {
                    [a, b] => Some((a.clone(), b.clone())),
                    _ => None,
                })
                .collect();
            let opts = seglog::CardConsistencyOpts {
                signer: signer.as_deref().map(parse_signer).transpose()?,
                logs: &child,
                proofs: &proof,
                pairs: &pairs,
            };
            let r = seglog::Card::parse(&ot).and_then(|o| {
                seglog::Card::parse(&nt).and_then(|n| seglog::check_card_consistency(&o, &n, &opts))
            });
            match r {
                Ok(c) => print!("{}", c.render()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
        LogCmd::Read {
            path,
            seq,
            from,
            to,
            output,
            strict,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let n = seglog::list(&path)?.entries.len() as u64;
            let (a, b) = match seq {
                Some(s) => (s, s),
                None => (from.unwrap_or(1), to.unwrap_or(n)),
            };
            if n == 0 {
                return Err("the log is empty".into());
            }
            let mode = if seq.is_some() {
                seglog::ReadMode::Single
            } else if strict {
                seglog::ReadMode::Strict
            } else {
                seglog::ReadMode::SkipDeleted
            };
            let got = seglog::read_range(
                &path,
                a,
                b,
                &seglog::ReadOpts {
                    pass: pass.as_deref(),
                    identities: &identities,
                },
                mode,
            )?;
            if !got.skipped_deleted.is_empty() {
                eprintln!(
                    "note: skipped {} deleted segment(s): {}",
                    got.skipped_deleted.len(),
                    seglog::fmt_ranges(&seglog::compress(&got.skipped_deleted))
                );
            }
            let parts = got.parts;
            let mut out: Box<dyn std::io::Write> = match &output {
                Some(p) => Box::new(fs::File::create(p)?),
                None => Box::new(std::io::stdout().lock()),
            };
            for (_, bytes) in parts {
                out.write_all(&bytes)?;
            }
            out.flush()?;
        }
        LogCmd::Verify {
            path,
            quick,
            pass,
            pass_file,
            talisman,
            identity,
            signer,
            anchor,
            json,
            temp_age,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let signer = signer.as_deref().map(parse_signer).transpose()?;
            let anchors = anchor
                .iter()
                .map(|a| parse_anchor(a))
                .collect::<Result<Vec<_>, _>>()?;
            match seglog::check(
                &path,
                &seglog::CheckOpts {
                    pass: pass.as_deref(),
                    identities: &identities,
                    quick,
                    signer,
                    anchors: &anchors,
                    temp_age_secs: temp_age,
                },
            ) {
                Ok(c) => {
                    let dir = sigil::seglog::Log::open(&path)
                        .map(|l| l.dir)
                        .unwrap_or(path.clone());
                    let r = sigil::doctor::DoctorReport {
                        kind: "log".into(),
                        root: dir,
                        layout: format!(
                            "container, {} segment(s){}{}",
                            c.segments,
                            if c.signed {
                                if c.handovers > 0 {
                                    format!(", signed (signer handed over {}×)", c.handovers)
                                } else {
                                    ", signed".to_string()
                                }
                            } else {
                                String::new()
                            },
                            if c.format >= 2 {
                                format!(
                                    ", log={}: {} deleted, {} compaction(s){}",
                                    c.format,
                                    c.deleted,
                                    c.compactions,
                                    if c.segkeys {
                                        format!(", per-segment keys, {} shredded", c.shredded)
                                    } else {
                                        String::new()
                                    }
                                )
                            } else {
                                String::new()
                            }
                        ),
                        container_version: c.container_version,
                        findings: c.findings,
                        verified: c.verified,
                        fixed: Vec::new(),
                    };
                    if json {
                        print!("{}", r.to_json());
                    } else {
                        print!("{}", r.render_as("log verify"));
                    }
                    std::process::exit(r.exit_code());
                }
                Err(e) => {
                    eprintln!("sigil log verify: {e}");
                    std::process::exit(3);
                }
            }
        }
        LogCmd::Tombstone {
            path,
            seq,
            from,
            to,
            reason,
            identity,
        } => {
            let id = identity.as_deref().map(Identity::load).transpose()?;
            let target = match (seq, from, to) {
                (Some(s), _, _) => seglog::TombTarget::Seq(s),
                (None, Some(a), Some(b)) => seglog::TombTarget::Range(a, b),
                _ => return Err("give --seq N, or --from A --to B".into()),
            };
            let r = seglog::tombstone(&path, target, reason.as_deref(), id.as_ref())?;
            for n in &r.notes {
                eprintln!("note: {n}");
            }
            println!(
                "tombstone {}: deleted segment(s) {}{}  head {}:{}{}",
                r.entry,
                seglog::fmt_ranges(&seglog::compress(&r.deleted)),
                if r.already.is_empty() {
                    String::new()
                } else {
                    format!(" ({} already deleted, skipped)", r.already.len())
                },
                r.entry,
                hex::encode(r.root),
                if r.signed { "  (signed)" } else { "" }
            );
            println!("  reads and `log ls` honour it now; {} byte(s) stay on disk until `sigil log compact --apply` (or `gc --apply`)", r.pending_bytes);
        }
        LogCmd::Shred {
            path,
            seq,
            from,
            to,
            reason,
            identity,
        } => {
            let id = identity.as_deref().map(Identity::load).transpose()?;
            let target = match (seq, from, to) {
                (Some(s), _, _) => seglog::TombTarget::Seq(s),
                (None, Some(a), Some(b)) => seglog::TombTarget::Range(a, b),
                _ => return Err("give --seq N, or --from A --to B".into()),
            };
            let r = seglog::shred(&path, target, reason.as_deref(), id.as_ref())?;
            for n in &r.notes {
                eprintln!("note: {n}");
            }
            println!(
                "shred {}: crypto-shredded segment(s) {}{}  head {}:{}{}",
                r.entry,
                seglog::fmt_ranges(&seglog::compress(&r.shredded)),
                if r.already.is_empty() {
                    String::new()
                } else {
                    format!(" ({} already shredded, skipped)", r.already.len())
                },
                r.entry,
                hex::encode(r.root),
                if r.signed { "  (signed)" } else { "" }
            );
            println!(
                "  {} key record(s) destroyed, {} ciphertext file(s) unlinked; the INDEX entries and every pinned anchor still verify.\n  Copies of the key or of the old files (backups, snapshots, an exported key ring) are not reached: see docs/SEGMENT-LOG.md",
                r.keys_destroyed, r.files_removed
            );
        }
        LogCmd::Compact {
            path,
            keep_last,
            older_than,
            range,
            apply,
            target_size,
            mode,
            pass,
            pass_file,
            talisman,
            identity,
            seal_pass,
            seal_pass_file,
            to,
            allow_decrypt,
        } => {
            let pass = pass.or(pass_file);
            let seal_pass = seal_pass.or(seal_pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let recipients = load_recipients(&to)?;
            let older = older_than.as_deref().map(parse_duration_secs).transpose()?;
            let range = match range.as_deref() {
                Some(r) => {
                    let (a, b) = r.split_once('-').ok_or("--range needs A-B")?;
                    Some((a.trim().parse::<u64>()?, b.trim().parse::<u64>()?))
                }
                None => None,
            };
            let rep = seglog::compact(
                &path,
                &seglog::CompactOpts {
                    keep_last,
                    older_than_secs: older,
                    range,
                    apply,
                    target_size,
                    mode: mode.into(),
                    seal_pass: seal_pass.as_deref(),
                    recipients: &recipients,
                    allow_decrypt,
                    read: seglog::ReadOpts {
                        pass: pass.as_deref(),
                        identities: &identities,
                    },
                    ..Default::default()
                },
            )?;
            let dir = seglog::Log::open(&path)
                .map(|l| l.dir)
                .unwrap_or(path.clone());
            print!("{}", rep.render(&dir));
        }
        LogCmd::Adopt {
            path,
            sources,
            identity,
            keep,
            dry_run,
        } => {
            let id = identity.as_deref().map(Identity::load).transpose()?;
            let r = seglog::adopt(
                &path,
                &sources,
                &seglog::AdoptOpts {
                    identity: id.as_ref(),
                    keep,
                    dry_run,
                },
            )?;
            for n in &r.notes {
                eprintln!("note: {n}");
            }
            print!("{}", r.render());
            if !r.skipped.is_empty() {
                std::process::exit(1);
            }
        }
        LogCmd::AddSigner { path, identity } => {
            let id = Identity::load(&identity)?;
            let r = seglog::add_signer(&path, &id)?;
            for n in &r.notes {
                eprintln!("note: {n}");
            }
            println!(
                "signer added: {}…  head {}:{}  (signed by the new key; {} earlier entr{} written unsigned)",
                &hex::encode(r.signer)[..16],
                r.covered,
                hex::encode(r.root),
                r.covered,
                if r.covered == 1 { "y" } else { "ies" }
            );
            println!(
                "  from now on every write needs --identity; verify with --signer {}",
                hex::encode(r.signer)
            );
        }
        LogCmd::RotateSigner {
            path,
            identity,
            new,
        } => {
            let id = Identity::load(&identity)?;
            let new = parse_signer(&new).map_err(|e| e.to_string().replace("--signer", "--new"))?;
            let r = seglog::rotate_signer(&path, &id, new)?;
            for n in &r.notes {
                eprintln!("note: {n}");
            }
            println!(
                "signer handover {}: {}… → {}…  head {}:{}  (signed by the outgoing key)",
                r.entry,
                &hex::encode(r.from)[..16],
                &hex::encode(r.to)[..16],
                r.entry,
                hex::encode(r.root)
            );
            println!(
                "  from the next write on, sign with the new key (--identity NEW.sgk); earlier HEADs, anchors and proofs stay valid.\n  verify --signer / check-proof --signer accept any key of the chain ({} handover(s) so far)",
                r.handovers
            );
        }
        LogCmd::Prove {
            path,
            seq,
            file_path,
            at,
            output,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let seq = match (seq, &file_path) {
                (Some(s), _) => s,
                (None, Some(fp)) => seglog::seq_for_path(&path, fp, pass.as_deref(), &identities)?,
                (None, None) => return Err("give --seq N or --path FILE".into()),
            };
            let p = seglog::prove_with(&path, seq, at, pass.as_deref(), &identities)?;
            let text = p.render();
            match output {
                Some(o) => {
                    fs::write(&o, &text)?;
                    eprintln!(
                        "proof of entry {seq} against {}:{} ({}) written to {}",
                        p.size,
                        hex::encode(p.root),
                        if p.head.is_some() {
                            "signed"
                        } else {
                            "unsigned"
                        },
                        o.display()
                    );
                }
                None => print!("{text}"),
            }
        }
        LogCmd::CheckProof {
            proof,
            file,
            signer,
            anchor,
            file_path,
        } => {
            let text =
                fs::read_to_string(&proof).map_err(|e| format!("read {}: {e}", proof.display()))?;
            let opts = seglog::ProofCheckOpts {
                signer: signer.as_deref().map(parse_signer).transpose()?,
                anchor: anchor.as_deref().map(parse_anchor).transpose()?,
                path: file_path.map(|p| p.trim_matches('/').as_bytes().to_vec()),
                file: match &file {
                    Some(f) => {
                        let b = fs::read(f).map_err(|e| format!("read {}: {e}", f.display()))?;
                        Some((sigil::sha256(&b), b.len() as u64))
                    }
                    None => None,
                },
            };
            match seglog::Proof::parse(&text).and_then(|p| seglog::check_proof(&p, &opts)) {
                Ok(c) => print!("{}", c.render()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
        LogCmd::ProveConsistency {
            path,
            old,
            new,
            output,
        } => {
            let seq_root = |spec: &str| -> Result<SeqRoot, Box<dyn std::error::Error>> {
                if spec.contains(':') {
                    let (s, r) = parse_anchor(spec)?;
                    Ok((s, Some(r)))
                } else {
                    Ok((
                        spec.trim()
                            .parse()
                            .map_err(|_| "anchor must be SEQ or SEQ:ROOT")?,
                        None,
                    ))
                }
            };
            let (o, oroot) = seq_root(&old)?;
            let (n, nroot) = match new.as_deref().map(seq_root).transpose()? {
                Some((n, r)) => (Some(n), r),
                None => (None, None),
            };
            let c = seglog::prove_consistency(&path, o, oroot, n)?;
            if let Some(r) = nroot {
                if r != c.new_root {
                    return Err(format!(
                        "this log's root at {} is {}, not {}",
                        c.new_size,
                        hex::encode(c.new_root),
                        hex::encode(r)
                    )
                    .into());
                }
            }
            let text = c.render();
            match output {
                Some(f) => {
                    fs::write(&f, &text)?;
                    eprintln!(
                        "consistency proof {}:{} -> {}:{} ({}) written to {}",
                        c.old_size,
                        hex::encode(c.old_root),
                        c.new_size,
                        hex::encode(c.new_root),
                        if c.head.is_some() {
                            "signed"
                        } else {
                            "unsigned"
                        },
                        f.display()
                    );
                }
                None => print!("{text}"),
            }
        }
        LogCmd::CheckConsistency {
            proof,
            old,
            new,
            signer,
        } => {
            let text =
                fs::read_to_string(&proof).map_err(|e| format!("read {}: {e}", proof.display()))?;
            let opts = seglog::ConsistencyCheckOpts {
                old: old.as_deref().map(parse_anchor).transpose()?,
                new: new.as_deref().map(parse_anchor).transpose()?,
                signer: signer.as_deref().map(parse_signer).transpose()?,
            };
            match seglog::Consistency::parse(&text)
                .and_then(|c| seglog::check_consistency(&c, &opts))
            {
                Ok(c) => print!("{}", c.render()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
        LogCmd::Mend { path } => {
            let r = seglog::mend(&path)?;
            println!(
                "log mend: checked {} segment(s), healed {}{}",
                r.checked,
                r.mended.len(),
                if r.mended.is_empty() {
                    String::new()
                } else {
                    format!(
                        " ({})",
                        r.mended
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            );
            if !r.keys_mended.is_empty() {
                println!(
                    "  key ring shard(s) healed: {}",
                    r.keys_mended
                        .iter()
                        .map(|s| format!("{s:04}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            for (s, m) in &r.keys_unrecoverable {
                println!("  key ring shard {s:04}: cannot be healed: {m}");
            }
            if r.ixkey_mended {
                println!("  {} (wrapped index key) healed", seglog::IXKEY_FILE);
            }
            if let Some(m) = &r.ixkey_unrecoverable {
                println!(
                    "  {}: cannot be healed: {m} (restore it from a copy)",
                    seglog::IXKEY_FILE
                );
            }
            for s in &r.missing {
                println!("  segment {s}: file missing (restore from a copy)");
            }
            for (s, m) in &r.unrecoverable {
                println!("  segment {s}: cannot be healed: {m}");
            }
            if !r.missing.is_empty()
                || !r.unrecoverable.is_empty()
                || !r.keys_unrecoverable.is_empty()
                || r.ixkey_unrecoverable.is_some()
            {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

fn run_sky(cmd: SkyCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        SkyCmd::Add {
            sky,
            input,
            name,
            as_name,
            mode,
            pass,
            pass_file,
            talisman,
            covenant,
            bind,
            chunk,
            rsync,
            rclone,
            wormhole,
            to,
            identity,
        } => {
            let pass = pass.or(pass_file);
            let geas = binds(&bind)?;
            let pass = resolve_pass(pass, talisman)?;
            let cov = covenant.unwrap_or_default();
            let recipients = load_recipients(&to)?;
            let identities = load_identities(&identity)?;
            let sky = sigil::container::sky_for_add(&sky);
            let report = add_to_constellation(
                &sky,
                &input,
                AddOpts {
                    title: name.as_deref(),
                    mode: mode.into(),
                    pass: pass.as_deref(),
                    covenant: &cov,
                    geas: &geas,
                    chunk,
                    as_name: as_name.as_deref(),
                    recipients: &recipients,
                    identities: &identities,
                },
            )?;
            println!(
                "constellation {}  added={} linked={} skipped={} replaced={} new_bytes={}",
                sky.display(),
                report.added,
                report.linked,
                report.skipped,
                report.replaced,
                report.bytes_new
            );
            if !recipients.is_empty() {
                println!(
                    "encrypt-to {} recipient{} (new stars + card)",
                    recipients.len(),
                    if recipients.len() == 1 { "" } else { "s" }
                );
            }
            if let Some(chart) = report.chart.as_ref() {
                println!("{}", sigil::scry_chart(&sky, chart));
            }
            if rsync.is_some() || rclone.is_some() {
                let src = sky.to_str().ok_or("path")?;
                if let Some(dest) = rsync {
                    rsync_dir(src, &dest)?;
                }
                if let Some(dest) = rclone {
                    println!("rclone {src} → {dest}");
                    run_cmd("rclone", &["copy", src, &dest])?;
                }
            }
            if wormhole {
                let bag = sky.join(format!(
                    "{}.sga",
                    sky.file_name()
                        .and_then(|s| s.to_str())
                        .map(sigil::container::strip_suffix)
                        .unwrap_or("constellation")
                ));
                let chart = report
                    .chart
                    .as_ref()
                    .ok_or("constellation list missing after add")?;
                sigil::pack_atlas_chart(&sky, chart, &bag)?;
                dispatch(&bag, &None, &None, true, false)?;
            }
        }
        SkyCmd::Atlas {
            sky,
            output,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let sky = sigil::container::sky_for_read(&sky);
            let dest = output.unwrap_or_else(|| {
                let stem = sky
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(sigil::container::strip_suffix)
                    .unwrap_or("constellation");
                sky.join(format!("{stem}.sga"))
            });
            let n = sigil::pack_atlas_keys(&sky, &dest, pass.as_deref(), &identities)?;
            println!("atlas {n} files → {}", dest.display());
        }
        SkyCmd::Remove {
            sky,
            names,
            pass,
            pass_file,
            talisman,
            to,
            identity,
            keep_stars,
            dry_run,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let recipients = load_recipients(&to)?;
            let identities = load_identities(&identity)?;
            let r = sigil::constellation_remove(
                &sky,
                &names,
                sigil::ConstellationRemoveOpts {
                    pass: pass.as_deref(),
                    recipients: &recipients,
                    identities: &identities,
                    keep_stars,
                    dry_run,
                },
            )?;
            let verb = if r.dry_run { "would remove" } else { "removed" };
            for n in &r.removed {
                println!("  {verb} {n}");
            }
            for p in &r.stars_freed {
                println!(
                    "  {} star {}",
                    if r.dry_run { "would delete" } else { "deleted" },
                    p.display()
                );
            }
            println!(
                "{}constellation {}: {} name(s) off the list, {} star file(s) freed, {} name(s) remain",
                if r.dry_run { "dry run: " } else { "" },
                sky.display(),
                r.removed.len(),
                r.stars_freed.len(),
                r.remaining
            );
        }
        SkyCmd::Scry {
            sky,
            pass,
            pass_file,
            talisman,
            identity,
        } => {
            let pass = pass.or(pass_file);
            let pass = resolve_pass(pass, talisman)?;
            let identities = load_identities(&identity)?;
            let (text, bad) =
                sigil::scry_constellation_checked(&sky, pass.as_deref(), &identities)?;
            println!("{text}");
            if let Some(why) = bad {
                return Err(not_recoverable(&why).into());
            }
        }
    }
    Ok(())
}

fn boot_pass(
    pass: Option<String>,
    talisman: Option<PathBuf>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let p = resolve_pass(pass, talisman)?;
    if p.is_some() {
        return Ok(p);
    }
    match std::env::var("SIGIL_WARD") {
        Ok(s) if !s.trim().is_empty() => Ok(Some(s)),
        _ => Ok(None),
    }
}

fn run_boot(cmd: BootCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        BootCmd::Prepare {
            root,
            mode,
            pass,
            pass_file,
            talisman,
            only_mark,
            no_inject,
        } => {
            let pass = pass.or(pass_file);
            let pass = boot_pass(pass, talisman)?;
            let find = prepare_boot(&root, mode.into(), pass.as_deref(), only_mark)?;
            println!(
                "wrapped {} → {} ({})",
                find.payload.display(),
                find.mark.display(),
                match mode {
                    ModeArg::Glyph => "Glyph",
                    ModeArg::Reflection => "Reflection",
                    ModeArg::Seal => "Seal",
                }
            );
            if only_mark {
                println!("original squashfs removed (--only-mark). Stick must be writable, or initrd will De-scribe into RAM.");
            }
            let exe = std::env::current_exe()?;
            match copy_sigil_binary(&root, &exe) {
                Ok(p) => println!("helper → {}", p.display()),
                Err(e) => eprintln!("could not copy sigil onto the stick: {e}"),
            }
            if no_inject {
                println!("skipped initrd. Hook will run if the initrd already carries it, or: sigil boot install && rebuild the live initrd.");
            } else {
                match inject_initrd(&root, &exe) {
                    Ok(p) => println!("initrd injected → {} (backup next to it as .bak)", p.display()),
                    Err(e) => eprintln!(
                        "initrd not injected ({e}). The stick still has live/sigil. Put the hook in the initrd, or: sigil boot install && rebuild the live initrd."
                    ),
                }
            }
            println!("boot: firmware still loads GRUB + kernel + initrd. Initrd Scrys, De-scribes if chewed, then the live image mounts.");
        }
        BootCmd::Mend {
            root,
            pass,
            pass_file,
            talisman,
            stage,
            scan,
        } => {
            let pass = pass.or(pass_file);
            let pass = boot_pass(pass, talisman)?;
            let out = if scan {
                mend_scan(&stage, pass.as_deref())?
            } else {
                let root = root.ok_or("boot mend needs a mounted USB path, or --scan")?;
                mend_boot(&root, pass.as_deref(), &stage)?
            };
            match out {
                BootOutcome::Intact { find } => {
                    println!("boot intact: {} is itself", find.payload.display());
                }
                BootOutcome::Mended { find, wrote } => {
                    println!(
                        "boot mended: {} ← {}",
                        find.payload.display(),
                        wrote.display()
                    );
                }
            }
        }
        BootCmd::Install { prefix } => {
            let wrote = install_hooks(&prefix)?;
            for p in &wrote {
                println!("wrote {}", p.display());
            }
            println!("rebuild the live USB's initrd so the stick carries these (update-initramfs / dracut), or run sigil boot prepare on the mounted stick.");
        }
    }
    Ok(())
}

/// `sigil mend` on a large-file pack: heal, then print what was done.
fn mend_pack_report(
    input: &std::path::Path,
    output: &std::path::Path,
    soft: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let rep = sigil::mend_pack_path(input, output, soft)?;
    let healed = if rep.mended.is_empty() {
        "no damage".to_string()
    } else {
        let list: Vec<String> = rep.mended.iter().map(|i| i.to_string()).collect();
        format!(
            "healed {} chunk star(s): {}",
            rep.mended.len(),
            list.join(", ")
        )
    };
    let healed = match rep.head {
        sigil::HeadSource::Intact => healed,
        sigil::HeadSource::FacetList => {
            format!("pack head rebuilt from the facet list; {healed}")
        }
        sigil::HeadSource::Guard => format!("pack head restored from a guard copy; {healed}"),
    };
    let healed = if rep.guards_restored > 0 {
        format!("restored {} star guard(s); {healed}", rep.guards_restored)
    } else {
        healed
    };
    let healed = if rep.facets_rebuilt {
        format!("facet list rebuilt; {healed}")
    } else {
        healed
    };
    println!(
        "mended work pack {} → {} ({healed}; {} stars verified{}{})",
        input.display(),
        output.display(),
        rep.stars,
        if rep.facets_checked {
            ", facets ok"
        } else {
            ", no facet trailer"
        },
        if rep.soft_used { ", soft salvage" } else { "" }
    );
    Ok(())
}

/// `SEQ` or `SEQ:ROOT` (root optional).
type SeqRoot = (u64, Option<[u8; 32]>);
