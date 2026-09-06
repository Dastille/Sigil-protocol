use clap::{Parser, Subcommand, ValueEnum};
use sigil::{
    add_to_constellation, attest, attest_keygen, copy_sigil_binary, deluge_fountain, deluge_pieces,
    backend_by_name, format_bakeoff_report, gather_fountain, gather_pieces, hex32, inject_initrd, inscribe_dir, inscribe_path, inscribe_stars_dir,
    install_hooks, is_constellation_input, is_dir_pack, is_fountain_dir, mend_boot, mend_bytes_ex,
    mend_scan, overture_report, pack_atlas, prepare_boot, run_bakeoff, run_open, run_showing, scry_constellation,
    scry_dir, scry_path, scatter_pieces, seal_kn_mds, sha256, sha256_path, talisman_pass, tally_pieces, unseal_constellation,
    place_kit, mend_kit,
    unseal_dir_only, unseal_ex, unseal_ex_mds, unseal_path, unseal_range, vessel_present, write_vessel, AddOpts,
    BootOutcome, CdcProfile, Mode, CDC_DEDUP, CDC_MEDIA, DEFAULT_CHUNK, OVERTURE, VESSEL,
};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(
    name = "sigil",
    about = "Wrap a file so a damaged copy can still be restored, and so you can tell if it was swapped.",
    long_about = "Inscribe makes a .sg1. Scry checks it without unpacking. De-scribe gets the original back.\nDefault lock style is Reflection (~1.3× size, ~25% repair). Seal is opt-in for worse damage.\nGitHub: tag v1.0 yourself — this tool does not log in for you."
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
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "reflection")]
        mode: ModeArg,
        #[arg(long)]
        pass: Option<String>,
        /// USB/file key (Talisman). Hex of its hash becomes the Ward. Instead of --pass.
        #[arg(long)]
        talisman: Option<PathBuf>,
        /// Per-file password inside a folder wrap: --ward photos/cat.jpg=secret (repeatable)
        #[arg(long = "ward")]
        ward: Vec<String>,
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
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        pass: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
        #[arg(long = "ward")]
        ward: Vec<String>,
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
    },
    Verify {
        input: PathBuf,
    },
    #[command(visible_alias = "gaze")]
    Scry {
        input: PathBuf,
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
        #[arg(long)]
        fountain: bool,
    },
    Gather {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        open: bool,
        #[arg(long)]
        pass: Option<String>,
        /// Wait for parts to show up. Write VESSEL when rebuilt so the sender can stop.
        #[arg(long)]
        watch: bool,
    },
    /// Rebuild a healthy .sg1 from live shards in a torn mark (no passphrase). Alias: repair.
    #[command(visible_alias = "repair")]
    Mend {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Salvage CRC-failed (bit-rotten) shard bodies with soft-RS / GMD-lite
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
        #[arg(long)]
        pass: Option<String>,
        #[arg(long)]
        open: bool,
        /// New parts to mint each time we are already whole (for the others)
        #[arg(long, default_value_t = 8)]
        extra: u8,
    },
    /// Plex/Jellyfin or any HTTP player: De-scribe the bytes they ask for (work-pack slices). Alias: showing, mount, unveil.
    #[command(visible_aliases = ["showing", "mount", "unveil"])]
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
        #[arg(long)]
        pass: Option<String>,
        /// Seconds with no reads before the temp copy is deleted (default 20 min)
        #[arg(long, default_value_t = 1200)]
        idle: u64,
    },
    /// What to copy first so Play can start (Blizzard-style boot).
    Overture {
        input: PathBuf,
    },
    /// De-scribe to temp, open in the usual app, delete when you press Enter.
    Open {
        input: PathBuf,
        #[arg(long)]
        pass: Option<String>,
        #[arg(long = "ward")]
        ward: Vec<String>,
        #[arg(long = "only")]
        only: Vec<String>,
        /// Don't delete the temp copy
        #[arg(long)]
        keep: bool,
        #[arg(long)]
        talisman: Option<PathBuf>,
    },
    /// Write a 32-byte signing key (also usable as a Talisman).
    Keygen {
        #[arg(short, long)]
        output: PathBuf,
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
    /// Bake-off Vandermonde vs Cauchy MDS (encode + multi-erasure decode MiB/s).
    #[command(name = "bench-mds")]
    BenchMds {
        /// Iterations per (backend, k/n, size). Default 3.
        #[arg(long, default_value_t = 3)]
        iters: usize,
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
        #[arg(long)]
        pass: Option<String>,
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
        #[arg(long)]
        pass: Option<String>,
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
        #[arg(long)]
        pass: Option<String>,
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
    },
    /// Pack the card and every star into one atlas (.sga) so they cannot scatter.
    Atlas {
        sky: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Scry {
        sky: PathBuf,
        #[arg(long)]
        pass: Option<String>,
        #[arg(long)]
        talisman: Option<PathBuf>,
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

fn resolve_pass(
    pass: Option<String>,
    talisman: Option<PathBuf>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(p) = talisman {
        return Ok(Some(talisman_pass(&p)?));
    }
    Ok(pass)
}

fn parse_wards(v: &[String]) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    v.iter()
        .map(|s| {
            s.split_once('=')
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .ok_or_else(|| format!("--ward needs path=password, got {s}").into())
        })
        .collect()
}

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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "{bin} is not installed. Install it, or copy the .sg1 yourself."
        )
        .into()),
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
        &["-av", "--partial", "--exclude", VESSEL, "--exclude", "manifest.txt", &src, &dest],
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
            let mut src = fs::File::open(file)?;
            let mut dst = fs::File::create(&tmp)?;
            let mut taken = src.take(end);
            let n = std::io::copy(&mut taken, &mut dst)?;
            println!("Overture slice {n} bytes (boot) — did not load the whole file");
            tmp
        }
    } else {
        file.to_path_buf()
    };
    let path = send_path.to_str().ok_or("path is not utf-8")?;
    if let Some(dest) = rsync {
        println!("dispatch rsync → {dest}");
        run_cmd("rsync", &["-av", "--partial", "--progress", path, dest])?;
    }
    if let Some(dest) = rclone {
        println!("dispatch rclone → {dest}");
        run_cmd("rclone", &["copy", path, dest])?;
    }
    if wormhole {
        println!("dispatch wormhole send (you and the other person type the code)");
        run_cmd("wormhole", &["send", path])?;
    }
    println!("far side: sha256sum the copy, then  sigil scry <file>  and  sigil de-scribe -o restored <file>");
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("{e}");
        std::process::exit(classify_exit(&e.to_string()));
    }
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
            mode,
            pass,
            talisman,
            ward,
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
            let geas = binds(&bind)?;
            let cov = covenant.as_deref().unwrap_or("");
            let wards = parse_wards(&ward)?;
            let pass = resolve_pass(pass, talisman)?;
            let piece_bytes = piece_mb.saturating_mul(1024 * 1024).max(64 * 1024);
            let mds_be = resolve_mds(&mds)?;
            if mds_be.name() != "vandermonde" {
                if input.is_dir() || pieces.is_some() || cdc.is_some() {
                    return Err(
                        "Cauchy --mds is single-star .sg1 only (no folder / --pieces / --cdc yet)".into(),
                    );
                }
                let data = fs::read(&input)?;
                let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file");
                let sg1 = seal_kn_mds(
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
                )?;
                fs::write(&output, &sg1)?;
                println!(
                    "inscribed {} bytes → {} (mds {})",
                    data.len(),
                    output.display(),
                    mds_be.name()
                );
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
                return Ok(());
            }
            if input.is_dir() {
                if pieces.is_some() {
                    return Err("folder Inscribe writes one pack. Omit --pieces.".into());
                }
                let (n, orig) =
                    inscribe_dir(&input, &output, mode.into(), pass.as_deref(), cov, &geas, chunk, &wards)?;
                println!("folder {n} files, {orig} bytes → {}", output.display());
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
            } else if let Some(dir) = pieces {
                let meta = fs::metadata(&input)?;
                if meta.len() <= chunk as u64 {
                    let data = fs::read(&input)?;
                    let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file");
                    let sg1 = sigil::seal_kn(
                        &data,
                        mode.into(),
                        pass.as_deref(),
                        name,
                        false,
                        cov,
                        &geas,
                        shards,
                        piece_bytes,
                    )?;
                    let n = scatter_pieces(&sg1, &dir)?;
                    println!("scattered {n} pieces into {}", dir.display());
                } else {
                    let (orig, stars) = inscribe_stars_dir(
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
                    )?;
                    println!("wrote {stars} stars ({orig} bytes) into {}", dir.display());
                    println!("Overture list: {}/{OVERTURE}", dir.display());
                }
            } else {
                let (orig, stars, work) = inscribe_path(
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
                )?;
                if work {
                    println!("work pack {stars} stars, {orig} bytes → {}", output.display());
                    println!("Overture: first {overture_mb} MiB is boot. sigil overture {}", output.display());
                } else {
                    println!("inscribed {orig} bytes → {}", output.display());
                }
                dispatch(&output, &rsync, &rclone, wormhole, false)?;
            }
        }
        Cmd::Unseal {
            input,
            output,
            pass,
            talisman,
            ward,
            bind,
            only,
            star,
            from_mb,
            to_mb,
            mds,
        } => {
            let companions = companion_bytes(&bind)?;
            let wards = parse_wards(&ward)?;
            let pass = resolve_pass(pass, talisman)?;
            let mds_be = resolve_mds(&mds)?;
            if mds_be.name() != "vandermonde" {
                if star.is_some() || from_mb.is_some() || to_mb.is_some() || is_dir_pack(&input) || is_constellation_input(&input) {
                    return Err("Cauchy --mds De-scribe is plain .sg1 only for now".into());
                }
                let data = fs::read(&input)?;
                let plain = unseal_ex_mds(&data, pass.as_deref(), &companions, &*mds_be)?;
                let n = plain.len();
                fs::write(&output, &plain)?;
                println!("de-scribed {n} bytes → {} (mds {})", output.display(), mds_be.name());
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
                let (n, stars) = unseal_range(&input, &output, pass.as_deref(), &companions, from, to)?;
                println!("de-scribed {stars} slices ({n} bytes) → {}", output.display());
            } else if is_dir_pack(&input) {
                let n = unseal_dir_only(&input, &output, pass.as_deref(), &companions, &only, &wards)?;
                println!("de-scribed {n} files → {}", output.display());
            } else if is_constellation_input(&input) {
                let n = unseal_constellation(&input, &output, pass.as_deref(), &companions, &only)?;
                println!("de-scribed {n} files → {}", output.display());
            } else {
                if !only.is_empty() {
                    return Err("--only is for a folder wrap. This is one file.".into());
                }
                let n = unseal_path(&input, &output, pass.as_deref(), &companions)?;
                println!("de-scribed {n} bytes → {}", output.display());
            }
        }
        Cmd::Verify { input } | Cmd::Scry { input } => {
            if is_constellation_input(&input) {
                println!("{}", scry_constellation(&input, None)?);
            } else if is_dir_pack(&input) {
                println!("{}", scry_dir(&input)?);
            } else {
                println!("{}", scry_path(&input)?);
            }
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
        } => {
            let data = fs::read(&input)?;
            if fountain {
                let n = deluge_fountain(&data, &output, extra as u32)?;
                println!("fountain {n} packets (.rq) → {}", output.display());
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
                    if vessel_present(&output) || rsync.as_deref().map(vessel_at).unwrap_or(false) {
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
                    if rsync.as_deref().map(vessel_at).unwrap_or(false) || vessel_present(&output) {
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
            watch,
        } => {
            if watch {
                println!(
                    "watching {}. Rebuilds when enough parts arrive, then writes {VESSEL} so the sender stops.",
                    input.display()
                );
                loop {
                    let gathered = if is_fountain_dir(&input) {
                        gather_fountain(&input)
                    } else {
                        gather_pieces(&input)
                    };
                    match gathered {
                        Ok(sg1) => {
                            let (have, k, _) = tally_pieces(&input).unwrap_or((0, 0, 0));
                            if open {
                                let plain = unseal_ex(&sg1, pass.as_deref(), &[])?;
                                fs::write(&output, plain)?;
                                println!("enough ({have} ≥ {k}). De-scribed → {}", output.display());
                            } else {
                                fs::write(&output, sg1)?;
                                println!("enough ({have} ≥ {k}). Gathered → {}", output.display());
                            }
                            write_vessel(&input, have, k)?;
                            println!("Vessel is full. Sender can stop.");
                            break;
                        }
                        Err(_) => {
                            if let Ok((have, k, _)) = tally_pieces(&input) {
                                println!("waiting… {have} good parts, need {k}");
                            } else {
                                println!("waiting for the first part…");
                            }
                            std::thread::sleep(std::time::Duration::from_secs(1));
                        }
                    }
                }
            } else {
                let sg1 = if is_fountain_dir(&input) {
                    gather_fountain(&input)?
                } else {
                    gather_pieces(&input)?
                };
                if open {
                    let plain = unseal_ex(&sg1, pass.as_deref(), &[])?;
                    fs::write(&output, plain)?;
                    println!("gathered and de-scribed → {}", output.display());
                } else {
                    fs::write(&output, sg1)?;
                    println!("gathered mark → {}", output.display());
                }
            }
        }
        Cmd::Mend { input, output, soft } => {
            let data = fs::read(&input)?;
            let (healed, used_soft) = mend_bytes_ex(&data, soft)?;
            fs::write(&output, &healed)?;
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
            open,
            extra,
        } => {
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
                            println!("raining {n} new parts from lane {lane} for people still short");
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
            idle,
        } => {
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
            ward,
            only,
            keep,
            talisman,
        } => {
            let pass = resolve_pass(pass, talisman)?;
            run_open(&input, pass.as_deref(), &parse_wards(&ward)?, &only, keep)?;
        }
        Cmd::Keygen { output } => {
            let pk = attest_keygen(&output)?;
            println!("key → {}  public {}", output.display(), hex32(&pk));
            println!("same file is a Talisman: --talisman {}", output.display());
        }
        Cmd::Sign { input, key } => {
            let dest = attest(&input, &key)?;
            println!("attestation → {}", dest.display());
        }
        Cmd::Boot { cmd } => run_boot(cmd)?,
        Cmd::Constellation { cmd } => run_sky(cmd)?,
        Cmd::Kit { cmd } => run_kit(cmd)?,
        Cmd::BenchMds { iters } => {
            let rows = run_bakeoff(iters);
            let (report, _keep) = format_bakeoff_report(&rows);
            print!("{report}");
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

fn run_sky(cmd: SkyCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        SkyCmd::Add {
            sky,
            input,
            name,
            as_name,
            mode,
            pass,
            talisman,
            covenant,
            bind,
            chunk,
            rsync,
            rclone,
            wormhole,
        } => {
            let geas = binds(&bind)?;
            let pass = resolve_pass(pass, talisman)?;
            let cov = covenant.unwrap_or_default();
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
            println!("{}", scry_constellation(&sky, pass.as_deref())?);
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
                    sky.file_name().and_then(|s| s.to_str()).unwrap_or("constellation")
                ));
                pack_atlas(&sky, &bag)?;
                dispatch(&bag, &None, &None, true, false)?;
            }
        }
        SkyCmd::Atlas { sky, output } => {
            let dest = output.unwrap_or_else(|| {
                let stem = sky
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("constellation");
                sky.join(format!("{stem}.sga"))
            });
            let n = pack_atlas(&sky, &dest)?;
            println!("atlas {n} files → {}", dest.display());
        }
        SkyCmd::Scry { sky, pass, talisman } => {
            let pass = resolve_pass(pass, talisman)?;
            println!("{}", scry_constellation(&sky, pass.as_deref())?);
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
            talisman,
            only_mark,
            no_inject,
        } => {
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
            talisman,
            stage,
            scan,
        } => {
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
