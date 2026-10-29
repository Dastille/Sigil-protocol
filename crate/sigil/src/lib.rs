//! Sigil protocol v1 — same .sg1 layout as the lab.
//!
//! # Panic policy
//! Input files, headers, pieces and I/O are untrusted: parsers return `Error`, never panic.
//! Library (non-test) code has no `unwrap()` or `expect()` at all, enforced by
//! `#![deny(clippy::unwrap_used, clippy::expect_used)]` below and the CI clippy job.
//! Fixed-width fields convert with `try_into().map_err(short_field)?`, and internal
//! invariants (Vandermonde inverse on distinct points, Merkle path in range, mount inode
//! tables, seglog cache) surface as an `Error` if they were ever broken, never a panic.
//! Every `unsafe` block carries a `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks`).
//!
//! Mutex locks use `unwrap_or_else(PoisonError::into_inner)`: the guarded data (caches,
//! progress stage) stays valid even if another thread panicked mid-update.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![deny(clippy::undocumented_unsafe_blocks)]
mod attest;
mod boot;
mod cdc;
mod chaos;
mod constellation;
pub mod container;
pub mod doctor;
mod folder;
mod fountain;
pub mod fountain_loss;
pub mod gc;
mod gf;
mod header;
mod keys;
mod kit;
mod mds;
mod merkle;
mod mount;
pub mod names;
mod nest;
mod open;
mod packhead;
pub mod passkey;
pub mod pgp;
mod pieces;
pub mod pretty;
pub mod privacy;
pub mod readdata;
mod rs;
mod rs_ref;
pub mod scrub;
pub mod seglog;

/// Benchmark / oracle hooks for the RS codec (not a stable API).
#[doc(hidden)]
pub mod rs_bench {
    pub use crate::gf::kernel_name;
    pub use crate::mds::{CauchyRs, MdsBackend};
    pub use crate::rs::{decode_indexed, encode_shards};
    /// Frozen pre-speedup scalar implementation (baseline).
    pub mod reference {
        pub use crate::rs_ref::{decode_indexed, encode_shards};
    }
}
mod show;
mod staging;
mod vault;
mod work;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub use attest::{attest, keygen as attest_keygen, talisman_pass, verify_attestation};
pub use boot::{
    copy_sigil_binary, find_boot_mark, inject_initrd, install_hooks, mend_boot, mend_scan,
    prepare_boot, BootFind, BootOutcome,
};
pub use cdc::{
    chunk_file_ranges, chunk_owned, chunk_ranges, ChunkRange, Profile as CdcProfile,
    DEDUP as CDC_DEDUP, FLOOR as CDC_FLOOR, MEDIA as CDC_MEDIA,
};
pub use constellation::{
    add_to_constellation, is_atlas_file, is_constellation_dir, is_constellation_input,
    is_constellation_mark, member_star_path as constellation_member_star, pack_atlas,
    pack_atlas_chart, pack_atlas_keys, remove_members as constellation_remove, scry_chart,
    scry_constellation, scry_constellation_checked, scry_constellation_keys, unseal_constellation,
    unseal_constellation_keys, AddOpts, AddReport, Chart, RemoveOpts as ConstellationRemoveOpts,
    RemoveReport as ConstellationRemoveReport,
};
pub use folder::{
    inscribe_dir, inscribe_dir_to, inscribe_dir_to_names_visible, is_dir_pack, is_plain_dir_pack,
    is_sealed_dir_pack, list_dir_pack, list_dir_pack_keys, looks_like_nest_name, mend_plain_dir,
    mend_sealed_dir, read_dir_entry_star, scry_dir, scry_dir_checked, scry_dir_keys,
    sealed_dir_body, unseal_dir, unseal_dir_mend_keys, unseal_dir_only, unseal_dir_only_keys,
    DirEntry,
};
pub use fountain::{
    deluge_answer_report, deluge_fountain, deluge_fountain_opts, deluge_fountain_report,
    fountain_progress, gather_fountain, gather_fountain_report, is_fountain_dir, parse_report_for,
    receiver_report, DelugeReport, FountainProgress, FountainReport, MAX_ESI, NAK_MAGIC,
};
pub use header::{
    locate_header, read_header, write_header, Header, HEADER_SIZE, KEYSTONE_SPAN, VERSION,
};
pub use keys::{
    keygen_ecc, keygen_legacy, resolve_recipient, Identity, PublicIdentity, ID_MAGIC, PUB_MAGIC,
    SGTO_MAGIC,
};
pub use kit::{
    is_kit_dir, mend as mend_kit, place as place_kit, PlaceReport, DEFAULT_DRIVES, KIT_MANIFEST,
};
pub use mds::{
    backend_by_name, default_backend, format_bakeoff_report, run_bakeoff, CauchyRs, MdsBackend,
    MdsBenchRow, VandermondeRs,
};
pub use merkle::merkle_root;
pub use mount::{
    fuse_available, mount_fuse, run_mount, run_mount_keys, umount as umount_path, VaultFs,
};
pub use nest::{
    is_nestable_bytes, kind_of_bytes, path_extract, path_extract_keys, path_list, path_walk,
    path_walk_keys, refuse_if_cycle, NestKind, PathEntry, PathView, MAX_NEST_DEPTH,
};
pub use open::{run_open, run_open_keys};
pub use packhead::HeadSource;
pub use pieces::{
    deluge as deluge_pieces, gather as gather_pieces, gather_dirs as gather_piece_dirs, mend_bytes,
    mend_bytes_ex, scatter as scatter_pieces, tally as tally_pieces, vessel_present, write_vessel,
    VESSEL,
};
pub use privacy::{FingerprintKey, Pad, SealMeta, SealOpts};
pub use show::run_showing;
pub use vault::tip_seal_path as vault_tip_seal_path;
pub use vault::{
    cold_here as vault_cold_here, commit_ex as vault_commit_ex,
    commit_from_export_ex as vault_commit_from_export_ex,
    format_recipients as vault_format_recipients, get_recipients as vault_get_recipients,
    remove_version as vault_remove_version, restore_ex as vault_restore_ex,
    set_recipients as vault_set_recipients, track_ex as vault_track_ex,
    tree_digest as vault_tree_digest, ChartKind as VaultChartKind,
    RemoveVersionReport as VaultRemoveVersionReport,
};
pub use vault::{
    commit as vault_commit, commit_from_export as vault_commit_from_export,
    dirty_meta_for as vault_dirty_meta_for, format_retention as vault_format_retention,
    format_status as vault_format_status, format_versions as vault_format_versions,
    get_retention as vault_get_retention, list_versions as vault_list_versions,
    maybe_prune_after_commit as vault_maybe_prune_after_commit, prune as vault_prune,
    prune_with as vault_prune_with, restore as vault_restore, set_retention as vault_set_retention,
    status as vault_status, track as vault_track, vault_dir_for, CommitReport as VaultCommitReport,
    DirtyMeta as VaultDirtyMeta, Drift as VaultDrift, PruneReport as VaultPruneReport,
    RestoreReport as VaultRestoreReport, RetentionPolicy as VaultRetention,
    StatusReport as VaultStatusReport, TrackReport as VaultTrackReport, CHART_NAME as VAULT_CHART,
    DIRTY_NAME as VAULT_DIRTY, VAULT_SUFFIX,
};
pub use work::{
    choose_overture, index_pack, index_pack_keys, inscribe_path, inscribe_path_to,
    inscribe_stars_dir, inscribe_stars_dir_to, is_damaged_work_pack, is_work_pack, mend_pack_path,
    overture_report, path_unrecoverable, payload_label_keys, payload_name, read_facet_digests,
    scry_facets, scry_path, scry_path_checked, star_bytes_unrecoverable, suggested_output_name,
    unseal_path, unseal_path_keys, unseal_range, unseal_range_keys, unseal_star_at,
    unseal_star_at_keys, PackMendReport, DEFAULT_CHUNK, DEFAULT_OVERTURE_MB, OVERTURE, WORK_MAGIC,
};

pub const DEFAULT_PIECE: u32 = 4 * 1024 * 1024;

pub fn rain_lane() -> u8 {
    let mut b = [0u8; 1];
    getrandom(&mut b);
    16 + (b[0] % 200)
}
/// Legacy passphrase KDF work factor (PBKDF2-HMAC-SHA256). Not stored in files, so it can
/// never change for existing seals: used only to *read* legacy Ward / KIND_PASS wraps.
/// New seals use Argon2id with stored parameters (`keys::ARGON2_*`).
pub const PBKDF2_ITERS: u32 = 80_000;

/// Pick how many parts. Repair ratio stays the same (Seal = half, Reflection = quarter).
/// Bigger file → more, smaller parts (cap 254). `--shards` wins if set.
pub fn choose_kn(mode: Mode, len: u64, piece_bytes: u32, shards: Option<u8>) -> (usize, usize) {
    let target = piece_bytes.max(64 * 1024) as u64;
    match mode {
        Mode::Glyph => {
            let n = shards.map(|s| s as usize).unwrap_or(16).clamp(16, 254);
            (n, n)
        }
        Mode::Seal => {
            let mut n = if let Some(s) = shards {
                s as usize
            } else if len == 0 {
                16
            } else {
                ((2 * len) / target).clamp(16, 254) as usize
            };
            n &= !1;
            if n < 16 {
                n = 16;
            }
            (n / 2, n)
        }
        Mode::Reflection => {
            let mut n = if let Some(s) = shards {
                s as usize
            } else if len == 0 {
                16
            } else {
                ((4 * len) / (3 * target.max(1))).clamp(16, 252) as usize
            };
            n -= n % 4;
            if n < 16 {
                n = 16;
            }
            (3 * n / 4, n)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Glyph,
    Reflection,
    Seal,
}

impl Mode {
    pub fn kn(self) -> (usize, usize) {
        match self {
            Mode::Glyph => (16, 16),
            Mode::Reflection => (12, 16),
            Mode::Seal => (8, 16),
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "glyph" => Some(Mode::Glyph),
            "reflection" => Some(Mode::Reflection),
            "seal" => Some(Mode::Seal),
            _ => None,
        }
    }
    pub fn flag(self) -> u8 {
        match self {
            Mode::Glyph => 0,
            Mode::Reflection => 1 << 2,
            Mode::Seal => 2 << 2,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Error for a fixed-width field whose slice did not have the field's width.
///
/// Callers check lengths before slicing, so this path should be unreachable; it exists so
/// that a missed check fails closed with an `Error` instead of panicking.
pub(crate) fn short_field(_: std::array::TryFromSliceError) -> Error {
    Error::Msg("internal: fixed-width field length mismatch (refusing to guess)".into())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_path(path: &std::path::Path) -> Result<[u8; 32]> {
    use std::io::Read;
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(path).map_err(|e| Error::Msg(e.to_string()))?;
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(|e| Error::Msg(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

pub fn hex32(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn maybe_deflate(data: &[u8]) -> (Vec<u8>, bool) {
    if data.len() < 24 {
        return (data.to_vec(), false);
    }
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    if enc.write_all(data).is_err() {
        return (data.to_vec(), false);
    }
    match enc.finish() {
        Ok(z) if z.len() < data.len() => (z, true),
        _ => (data.to_vec(), false),
    }
}

fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut dec = DeflateDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| Error::Msg(e.to_string()))?;
    Ok(out)
}

/// Why an empty passphrase is refused when sealing.
const EMPTY_PASS_SEAL: &str = "an empty passphrase (or one that is only spaces) is refused: it would not protect anything (leave out the passphrase for an unencrypted file)";

/// Why an empty passphrase is refused when opening.
const EMPTY_PASS_OPEN: &str = "an empty passphrase (or one that is only spaces) is refused: it is never the same as no passphrase (leave out the passphrase to open an unencrypted file, or give the real one)";

/// Fail closed on `Some("")` and on a passphrase that is only whitespace: the library
/// never reads a blank passphrase as "none", and never seals or opens with one (on
/// legacy Ward files it trimmed to empty anyway). `None` (no passphrase) is fine.
/// Real passphrases with leading/trailing spaces are untouched.
fn refuse_empty_pass(pass: Option<&str>, why: &str) -> Result<()> {
    if pass.is_some_and(|p| p.trim().is_empty()) {
        return Err(Error::Msg(why.into()));
    }
    Ok(())
}

/// [`refuse_empty_pass`] for seal entry points that write files, checked before any
/// output is created (no empty decoy file is left behind).
pub(crate) fn refuse_empty_seal_pass(pass: Option<&str>) -> Result<()> {
    refuse_empty_pass(pass, EMPTY_PASS_SEAL)
}

/// [`refuse_empty_pass`] for every open path (unseal, scry with a key, packs, folders).
pub(crate) fn refuse_empty_open_pass(pass: Option<&str>) -> Result<()> {
    refuse_empty_pass(pass, EMPTY_PASS_OPEN)
}

/// Legacy Ward key (read path only).
fn derive_key(pass: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pass.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

pub fn seal(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
) -> Result<Vec<u8>> {
    seal_ex(data, mode, pass, name, graph, "", &[])
}

pub fn seal_ex(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
) -> Result<Vec<u8>> {
    seal_kn(
        data,
        mode,
        pass,
        name,
        graph,
        covenant,
        geas,
        None,
        DEFAULT_PIECE,
    )
}

// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn seal_kn(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
) -> Result<Vec<u8>> {
    seal_kn_to(
        data,
        mode,
        pass,
        name,
        graph,
        covenant,
        geas,
        shards,
        piece_bytes,
        &[],
    )
}

/// Like `seal_kn`, with optional encrypt-to recipients (`--to`).
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn seal_kn_to(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
    recipients: &[keys::PublicIdentity],
) -> Result<Vec<u8>> {
    seal_kn_mds_to(
        data,
        mode,
        pass,
        name,
        graph,
        covenant,
        geas,
        shards,
        piece_bytes,
        &*mds::default_backend(),
        recipients,
    )
}

/// Like `seal_kn`, but encode with an explicit MDS backend (Cauchy opt-in).
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn seal_kn_mds(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
    mds_be: &dyn mds::MdsBackend,
) -> Result<Vec<u8>> {
    seal_kn_mds_to(
        data,
        mode,
        pass,
        name,
        graph,
        covenant,
        geas,
        shards,
        piece_bytes,
        mds_be,
        &[],
    )
}

/// Seal with optional encrypt-to recipients (`--to`). When `recipients` is non-empty,
/// body is AES-GCM'd under a random CEK; SGTO holds X25519 wraps (and a passphrase
/// wrap if `pass` is also set). Encrypt-to alone is enough; with both, either opens.
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn seal_kn_mds_to(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
    mds_be: &dyn mds::MdsBackend,
    recipients: &[keys::PublicIdentity],
) -> Result<Vec<u8>> {
    seal_kn_mds_to_opts(
        data,
        mode,
        pass,
        name,
        graph,
        covenant,
        geas,
        shards,
        piece_bytes,
        mds_be,
        recipients,
        &privacy::SealOpts::default(),
    )
}

/// Like [`seal_kn_to`], with private-label options (keyed-fingerprint key, opt-in padding).
// Justification: see `seal_kn_mds_to`.
#[allow(clippy::too_many_arguments)]
pub fn seal_kn_to_opts(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
    recipients: &[keys::PublicIdentity],
    opts: &privacy::SealOpts,
) -> Result<Vec<u8>> {
    seal_kn_mds_to_opts(
        data,
        mode,
        pass,
        name,
        graph,
        covenant,
        geas,
        shards,
        piece_bytes,
        &*mds::default_backend(),
        recipients,
        opts,
    )
}

/// The seal itself. Encrypted seals (passphrase and/or encrypt-to) are written
/// with the v3 private label (see [`privacy`]); plain seals keep the v2 label.
// Justification: see `seal_kn_mds_to`.
#[allow(clippy::too_many_arguments)]
pub fn seal_kn_mds_to_opts(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
    mds_be: &dyn mds::MdsBackend,
    recipients: &[keys::PublicIdentity],
    opts: &privacy::SealOpts,
) -> Result<Vec<u8>> {
    // Safe by default: an empty passphrase would silently write an unencrypted file.
    refuse_empty_pass(pass, EMPTY_PASS_SEAL)?;
    let pass_nonempty = pass.filter(|s| !s.is_empty());
    // New passphrase seals go through SGTO too: random CEK, wrapped with Argon2id whose
    // parameters are stored in the wrap record. The legacy Ward (PBKDF2, fixed 80k iterations,
    // nothing stored) is read-only; see `keys::KIND_PASS_ARGON2ID`.
    let use_to = !recipients.is_empty() || pass_nonempty.is_some();
    if !use_to {
        return seal_plain(
            data,
            mode,
            name,
            graph,
            covenant,
            geas,
            shards,
            piece_bytes,
            mds_be,
        );
    }
    let digest = sha256(data);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom(&mut salt);
    getrandom(&mut nonce);
    let (body, compressed) = maybe_deflate(data);
    let entropy_milli = (shannon(data) * 1000.0).round() as u32;
    let mut cek = zeroize::Zeroizing::new([0u8; 32]);
    getrandom(&mut cek[..]);
    let sgto_block = keys::build_sgto(&cek, recipients, pass_nonempty, &salt)?;
    let fp_key = privacy::fingerprint_key(&cek, &salt, &opts.fingerprint)?;
    let keyed = privacy::keyed_fingerprint(&fp_key, data)?;
    let mut meta = privacy::SealMeta {
        name: name.to_string(),
        orig_len: data.len() as u64,
        digest,
        body_len: body.len() as u64,
        entropy_milli,
        compressed,
        group_total: opts.group_total,
        shared_fingerprint: matches!(opts.fingerprint, privacy::FingerprintKey::Shared(_)),
        pad_len: 0,
    };
    let inner_len = privacy::write_inner(&meta).len() as u64;
    let unpadded = inner_len + body.len() as u64;
    meta.pad_len = privacy::padded_len(unpadded, opts.pad) - unpadded;
    let mut inner = privacy::write_inner(&meta);
    inner.extend_from_slice(&chaos::fold(&body, &salt));
    let pad = usize::try_from(meta.pad_len).map_err(|_| Error::Msg("padding too large".into()))?;
    inner.resize(inner.len() + pad, 0);
    // Part counts follow the ciphertext length (what is visible anyway), not the plain size.
    let (k, n) = choose_kn(mode, inner.len() as u64, piece_bytes, shards);
    let mut flags = mode.flag() | 2;
    if graph {
        flags |= 1 << 4;
    }
    flags |= header::FLAG_KEYSTONE | header::FLAG_EMBER;
    let has_vow = !covenant.is_empty() || !geas.is_empty();
    if has_vow {
        flags |= header::FLAG_VOW;
    }
    let mut h = header::Header {
        version: privacy::PRIVATE_VERSION,
        flags,
        k: k as u8,
        n: n as u8,
        orig_len: 0,
        folded_len: inner.len() as u64,
        digest: keyed,
        salt,
        nonce,
        tag: [0u8; 16],
        shard_len: 0,
        entropy_milli: 0,
        name: String::new(),
        merkle: [0u8; 32],
    };
    let aad = privacy::label_aad(&write_header(&h))?;
    let cipher = Aes256Gcm::new_from_slice(&cek[..]).map_err(|e| Error::Msg(e.to_string()))?;
    let mut packed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Msg("encrypt failed".into()))?;
    let t = packed
        .len()
        .checked_sub(16)
        .ok_or_else(|| Error::Msg("encrypt failed".into()))?;
    h.tag.copy_from_slice(&packed[t..]);
    packed.truncate(t);
    let shards = if matches!(mode, Mode::Glyph) {
        rs::stripe(&packed, n)
    } else {
        mds_be.encode(&packed, k, n)?
    };
    let leaves: Vec<[u8; 32]> = shards.iter().map(|s| sha256(s)).collect();
    h.merkle = merkle::merkle_root(&leaves);
    h.shard_len = shards.first().map(|s| s.len() as u32).unwrap_or(1);
    Ok(assemble(
        &write_header(&h),
        Some(&sgto_block),
        covenant,
        geas,
        &shards,
    ))
}

/// Keystone + optional SGTO + optional vow + ember-framed shards.
fn assemble(
    hdr: &[u8],
    sgto: Option<&[u8]>,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = header::wrap_keystone(hdr);
    // SGTO sits after keystone, before vow (detected by magic — no flag bit).
    if let Some(sg) = sgto {
        out.extend_from_slice(sg);
    }
    let has_vow = !covenant.is_empty() || !geas.is_empty();
    let vow = if has_vow {
        Some(header::write_vow(covenant, geas))
    } else {
        None
    };
    if let Some(v) = &vow {
        out.extend_from_slice(v);
    }
    for (i, s) in shards.iter().enumerate() {
        out.extend_from_slice(&header::write_ember(hdr, i as u8));
        if let Some(v) = &vow {
            out.extend_from_slice(v);
        }
        out.extend_from_slice(s);
        out.extend_from_slice(&crc32fast::hash(s).to_le_bytes());
    }
    out
}

/// Plain (unencrypted) seal: the v2 label, unchanged.
// Justification: see `seal_kn_mds_to`.
#[allow(clippy::too_many_arguments)]
fn seal_plain(
    data: &[u8],
    mode: Mode,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
    mds_be: &dyn mds::MdsBackend,
) -> Result<Vec<u8>> {
    let (k, n) = choose_kn(mode, data.len() as u64, piece_bytes, shards);
    let digest = sha256(data);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom(&mut salt);
    getrandom(&mut nonce);
    let (body, compressed) = maybe_deflate(data);
    let folded = chaos::fold(&body, &salt);
    let shards = if matches!(mode, Mode::Glyph) {
        rs::stripe(&folded, n)
    } else {
        mds_be.encode(&folded, k, n)?
    };
    let leaves: Vec<[u8; 32]> = shards.iter().map(|s| sha256(s)).collect();
    let merkle = merkle::merkle_root(&leaves);
    let mut flags = mode.flag();
    if compressed {
        flags |= 1;
    }
    if graph {
        flags |= 1 << 4;
    }
    flags |= header::FLAG_KEYSTONE;
    flags |= header::FLAG_EMBER;
    if !covenant.is_empty() || !geas.is_empty() {
        flags |= header::FLAG_VOW;
    }
    let entropy_milli = (shannon(data) * 1000.0).round() as u32;
    let hdr = write_header(&header::Header {
        version: header::VERSION,
        flags,
        k: k as u8,
        n: n as u8,
        orig_len: data.len() as u64,
        folded_len: folded.len() as u64,
        digest,
        salt,
        nonce,
        tag: [0u8; 16],
        shard_len: shards.first().map(|s| s.len() as u32).unwrap_or(1),
        entropy_milli,
        name: name.to_string(),
        merkle,
    });
    Ok(assemble(&hdr, None, covenant, geas, &shards))
}

pub fn unseal(file: &[u8], pass: Option<&str>) -> Result<Vec<u8>> {
    unseal_ex(file, pass, &[])
}

pub fn unseal_ex(file: &[u8], pass: Option<&str>, companions: &[Vec<u8>]) -> Result<Vec<u8>> {
    unseal_ex_mds(file, pass, companions, &*mds::default_backend())
}

/// Like `unseal_ex`, but decode with an explicit MDS backend (must match seal).
pub fn unseal_ex_mds(
    file: &[u8],
    pass: Option<&str>,
    companions: &[Vec<u8>],
    mds_be: &dyn mds::MdsBackend,
) -> Result<Vec<u8>> {
    unseal_ex_mds_keys(file, pass, companions, mds_be, &[])
}

/// Unseal with optional `--identity` keys. Tries SGTO CEK unwrap (identity or passphrase
/// wrap) before falling back to legacy PBKDF2 body decrypt for passphrase-only seals.
pub fn unseal_ex_mds_keys(
    file: &[u8],
    pass: Option<&str>,
    companions: &[Vec<u8>],
    mds_be: &dyn mds::MdsBackend,
    identities: &[keys::Identity],
) -> Result<Vec<u8>> {
    unseal_meta(file, pass, companions, mds_be, identities).map(|(p, _)| p)
}

/// Like [`unseal_ex_keys`], also returning the private label of a v3 seal
/// (`None` for v1/v2 seals, whose label is on the outside).
pub fn unseal_meta_keys(
    file: &[u8],
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[keys::Identity],
) -> Result<(Vec<u8>, Option<privacy::SealMeta>)> {
    unseal_meta(file, pass, companions, &*mds::default_backend(), identities)
}

/// Name, size and plaintext SHA-256 of a seal: from the outer label for v1/v2 and
/// plain seals, from inside the ciphertext for v3 (needs the key; opens the seal).
pub fn seal_meta_keys(
    file: &[u8],
    pass: Option<&str>,
    identities: &[keys::Identity],
) -> Result<privacy::SealMeta> {
    refuse_empty_open_pass(pass)?;
    let (h, _, _) = locate_header(file)?;
    if !h.private_label() {
        return Ok(privacy::SealMeta {
            name: h.name.clone(),
            orig_len: h.orig_len,
            digest: h.digest,
            body_len: 0,
            entropy_milli: h.entropy_milli,
            compressed: h.compressed(),
            group_total: 0,
            shared_fingerprint: false,
            pad_len: 0,
        });
    }
    match unseal_meta(file, pass, &[], &*mds::default_backend(), identities)? {
        (_, Some(m)) => Ok(m),
        (_, None) => Err(Error::Msg("private label missing".into())),
    }
}

/// Change check for the key holder (option 4): does `data` match the keyed
/// fingerprint on the outside of this v3 seal? Unwraps the content key only; the
/// body is not decrypted. Per-file fingerprints only: a seal made with a shared
/// dedupe key compares against [`privacy::shared_fingerprint`] instead, which needs
/// no seal key at all. Errors on v1/v2 seals and on a wrong key.
pub fn keyed_fingerprint_matches(
    file: &[u8],
    pass: Option<&str>,
    identities: &[keys::Identity],
    data: &[u8],
) -> Result<bool> {
    refuse_empty_open_pass(pass)?;
    let (h, _, _) = locate_header(file)?;
    if !h.private_label() {
        return Err(Error::Msg("not a v3 private-label seal".into()));
    }
    let block = header::sgto_slice(&h, file)
        .ok_or_else(|| Error::Msg("v3 seal has no key wrap (SGTO)".into()))?;
    let cek = keys::unwrap_cek(block, identities, pass.filter(|s| !s.is_empty()), &h.salt)?;
    let fk = privacy::fingerprint_key(&cek, &h.salt, &privacy::FingerprintKey::PerFile)?;
    let fp = privacy::keyed_fingerprint(&fk, data)?;
    Ok(subtle_eq(&fp, &h.digest))
}

fn subtle_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn unseal_meta(
    file: &[u8],
    pass: Option<&str>,
    companions: &[Vec<u8>],
    mds_be: &dyn mds::MdsBackend,
    identities: &[keys::Identity],
) -> Result<(Vec<u8>, Option<privacy::SealMeta>)> {
    refuse_empty_open_pass(pass)?;
    let (h, prefix, _) = locate_header(file)?;
    header::ensure_single_seal(file, &h, prefix)?;
    if h.vow() {
        let vow_off = prefix.saturating_sub(header::VOW_SIZE);
        let mut got = file
            .get(vow_off..vow_off + header::VOW_SIZE)
            .and_then(header::read_vow);
        if got.is_none() {
            let ember_vow = prefix + HEADER_SIZE;
            got = file
                .get(ember_vow..ember_vow + header::VOW_SIZE)
                .and_then(header::read_vow);
        }
        if let Some((_, need)) = got {
            let have: Vec<[u8; 32]> = companions.iter().map(|c| sha256(c)).collect();
            for n in &need {
                if !have.iter().any(|hsh| hsh == n) {
                    return Err(Error::Msg(
                        "Geas not met — companion missing or changed.".into(),
                    ));
                }
            }
        }
    }
    if h.private_label() && !h.encrypted() {
        return Err(Error::Msg(
            "v3 label on an unencrypted seal; refusing".into(),
        ));
    }
    // Entropy lives inside the lock on v3; the outer slot (outside the AAD, since
    // Embers reuse its high byte for the piece index) must stay zero.
    if h.private_label() && h.entropy_milli & 0x00FF_FFFF != 0 {
        return Err(Error::Msg(
            "v3 label carries an outer entropy score; refusing".into(),
        ));
    }
    let live = header::gather_live_shards(file, &h, prefix);
    let k = h.k as usize;
    let folded = if h.mode() == Mode::Glyph {
        rs::unstripe(&live, h.folded_len as usize)?
    } else if mds_be.name() == "vandermonde" {
        rs::decode_shards(&live, k, h.folded_len as usize, h.version >= 2)?
    } else {
        mds_be.decode(&live, k, h.folded_len as usize)?
    };
    let mut folded = folded;
    let p = pass.unwrap_or("").trim();
    let mut cek_kept: Option<zeroize::Zeroizing<[u8; 32]>> = None;
    if h.encrypted() {
        let sgto = header::sgto_slice(&h, file);
        let key = if let Some(block) = sgto {
            // Encrypt-to (and optional passphrase wrap in SGTO).
            match keys::unwrap_cek(block, identities, pass.filter(|s| !s.is_empty()), &h.salt) {
                Ok(cek) => cek,
                Err(e) => {
                    if identities.is_empty() && p.is_empty() {
                        return Err(Error::Msg("passphrase or --identity required".into()));
                    }
                    return Err(e);
                }
            }
        } else if h.private_label() {
            return Err(Error::Msg(
                "v3 seal has no key wrap (SGTO) left; past repair".into(),
            ));
        } else {
            // Legacy passphrase Ward.
            if p.is_empty() {
                if !identities.is_empty() {
                    return Err(Error::Msg(
                        "seal has no encrypt-to recipients; passphrase required".into(),
                    ));
                }
                return Err(Error::Msg("passphrase required".into()));
            }
            derive_key(p, &h.salt)
        };
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| Error::Msg(e.to_string()))?;
        let mut packed = folded;
        if h.private_label() {
            // The Merkle root is computed after encryption, so GCM cannot cover it:
            // re-encode the ciphertext and require the label's root.
            let shards = if h.mode() == Mode::Glyph {
                rs::stripe(&packed, h.n as usize)
            } else {
                mds_be.encode(&packed, k, h.n as usize)?
            };
            let leaves: Vec<[u8; 32]> = shards.iter().map(|s| sha256(s)).collect();
            if merkle::merkle_root(&leaves) != h.merkle {
                return Err(Error::Msg(
                    "label does not match the parts (Merkle root); refusing".into(),
                ));
            }
        }
        packed.extend_from_slice(&h.tag);
        let aad = if h.private_label() {
            privacy::label_aad(&write_header(&h))?
        } else {
            Vec::new()
        };
        folded = cipher
            .decrypt(
                Nonce::from_slice(&h.nonce),
                aes_gcm::aead::Payload {
                    msg: &packed,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                Error::Msg("wrong passphrase/identity, label edited, or past repair".into())
            })?;
        let mut kept = zeroize::Zeroizing::new([0u8; 32]);
        kept.copy_from_slice(&key[..32.min(key.len())]);
        cek_kept = Some(kept);
    } else if !p.is_empty() {
        return Err(Error::Msg("seal was not encrypted".into()));
    }
    if h.private_label() {
        let (meta, off) = privacy::read_inner(&folded)?;
        let end = off + meta.body_len as usize;
        let unfolded = chaos::unfold(&folded[off..end], &h.salt);
        let plain = if meta.compressed {
            inflate(&unfolded)?
        } else {
            unfolded
        };
        if plain.len() as u64 != meta.orig_len {
            return Err(Error::Msg("length mismatch".into()));
        }
        if sha256(&plain) != meta.digest {
            return Err(Error::Msg("SHA-256 mismatch".into()));
        }
        if !meta.shared_fingerprint {
            let cek = cek_kept.ok_or_else(|| Error::Msg("no key".into()))?;
            let fk = privacy::fingerprint_key(&cek, &h.salt, &privacy::FingerprintKey::PerFile)?;
            if privacy::keyed_fingerprint(&fk, &plain)? != h.digest {
                return Err(Error::Msg("keyed fingerprint mismatch".into()));
            }
        }
        return Ok((plain, Some(meta)));
    }
    let unfolded = chaos::unfold(&folded, &h.salt);
    let plain = if h.compressed() {
        inflate(&unfolded)?
    } else {
        unfolded
    };
    if plain.len() != h.orig_len as usize {
        return Err(Error::Msg("length mismatch".into()));
    }
    if sha256(&plain) != h.digest {
        return Err(Error::Msg("SHA-256 mismatch".into()));
    }
    Ok((plain, None))
}

/// Convenience: unseal with identities (default MDS).
pub fn unseal_ex_keys(
    file: &[u8],
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[keys::Identity],
) -> Result<Vec<u8>> {
    unseal_ex_mds_keys(file, pass, companions, &*mds::default_backend(), identities)
}

/// Opt-in repair-then-open (`sigil unseal --repair`). First tries a normal open; if that
/// fails, runs the same in-memory salvage as `mend --soft` (per-column Reed-Solomon error
/// correction, then soft-RS / GMD-lite, each accepted only when the Merkle binding and true
/// name match) and opens the repaired bytes. Nothing is written to disk. Wrong keys and
/// damage beyond repair still fail closed. Returns `(plaintext, repaired)`.
pub fn unseal_repair_keys(
    file: &[u8],
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[keys::Identity],
) -> Result<(Vec<u8>, bool)> {
    refuse_empty_open_pass(pass)?;
    match unseal_ex_keys(file, pass, companions, identities) {
        Ok(p) => Ok((p, false)),
        Err(first) => {
            let healed = match mend_bytes_ex(file, true) {
                Ok((h, _)) => h,
                Err(_) => return Err(first),
            };
            unseal_ex_keys(&healed, pass, companions, identities).map(|p| (p, true))
        }
    }
}

pub fn verify(file: &[u8]) -> Result<(Header, bool, usize, usize, bool)> {
    let (h, prefix, recovered) = locate_header(file)?;
    let live_s = header::gather_live_shards(file, &h, prefix);
    let live = live_s.iter().filter(|s| s.is_some()).count();
    let all_ok = live == h.n as usize;
    let merkle_ok = if all_ok {
        let leaves: Vec<[u8; 32]> = live_s
            .iter()
            .filter_map(|s| s.as_ref().map(|b| sha256(b)))
            .collect();
        merkle::merkle_root(&leaves) == h.merkle
    } else {
        false
    };
    let k = h.k as usize;
    Ok((h, merkle_ok, live, k, recovered))
}

fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut c = [0u32; 256];
    for &b in data {
        c[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for n in c {
        if n == 0 {
            continue;
        }
        let p = n as f64 / len;
        h -= p * p.log2();
    }
    h
}

fn getrandom(buf: &mut [u8]) {
    // Prefer getrandom if present; fall back to /dev/urandom.
    if let Ok(f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read as _;
        let mut f = f;
        let _ = f.read_exact(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast RS must still fail closed: wrong key, truncation and corruption
    /// beyond the parity budget are refused, never returned as wrong bytes.
    #[test]
    fn rs_fast_path_fails_closed() {
        let msg: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
            .collect();
        for pass in [None, Some("correct horse")] {
            let bytes = seal(&msg, Mode::Seal, pass, "big.bin", false).unwrap();
            assert_eq!(unseal(&bytes, pass).unwrap(), msg);
            if pass.is_some() {
                assert!(unseal(&bytes, Some("wrong horse")).is_err());
                assert!(unseal(&bytes, None).is_err());
            }
            for cut in [bytes.len() / 2, bytes.len() - 1, HEADER_SIZE + 10] {
                if let Ok(out) = unseal(&bytes[..cut], pass) {
                    assert_eq!(out, msg, "truncated to {cut} returned wrong bytes");
                }
            }
            let h = read_header(&bytes).unwrap();
            let stride = header::shard_stride(&h);
            let prefix = if h.keystone() {
                KEYSTONE_SPAN
            } else {
                HEADER_SIZE
            };
            // Bit flips in every shard body: more damage than parity can repair.
            let mut flipped = bytes.clone();
            for i in 0..h.n as usize {
                let off = prefix + i * stride + stride / 2;
                if off < flipped.len() {
                    flipped[off] ^= 0x10;
                }
            }
            if let Ok(out) = unseal(&flipped, pass) {
                assert_eq!(out, msg, "bit flips returned wrong bytes");
            }
            // Within budget: flips in n-k shards are repaired exactly.
            let mut some = bytes.clone();
            for i in 0..(h.n - h.k) as usize {
                some[prefix + i * stride + stride / 2] ^= 0x01;
            }
            assert_eq!(unseal(&some, pass).unwrap(), msg);
        }
    }

    #[test]
    fn roundtrip_seal() {
        let msg = b"The river is a circle.";
        let bytes = seal(msg, Mode::Seal, None, "t.txt", false).unwrap();
        let out = unseal(&bytes, None).unwrap();
        assert_eq!(out, msg);
        let (_, merkle_ok, live, k, recovered) = verify(&bytes).unwrap();
        assert!(merkle_ok);
        assert_eq!(live, 16);
        assert_eq!(k, 8);
        assert!(!recovered);
    }

    #[test]
    fn rs_budget() {
        let msg = b"repair me please -- a little longer for deflate";
        let bytes = seal(msg, Mode::Seal, None, "t.txt", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let mut torn = bytes.clone();
        let stride = header::shard_stride(&h);
        let prefix = if h.keystone() {
            KEYSTONE_SPAN
        } else {
            HEADER_SIZE
        };
        for i in 0..8 {
            let off = prefix + i * stride;
            torn[off..off + stride].fill(0);
            torn[off] = 3;
        }
        let out = unseal(&torn, None).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn keystone_smashed_front() {
        let msg = b"header can die";
        let bytes = seal(msg, Mode::Seal, None, "t.txt", false).unwrap();
        let mut smashed = bytes.clone();
        smashed[..HEADER_SIZE].fill(0);
        smashed[0] = 0x58;
        let out = unseal(&smashed, None).unwrap();
        assert_eq!(out, msg);
        let mut burned = bytes.clone();
        burned[..KEYSTONE_SPAN].fill(0);
        burned[0] = 0x58;
        let from_ember = unseal(&burned, None).unwrap();
        assert_eq!(from_ember, msg);
    }

    #[test]
    fn covenant_geas() {
        let msg = b"bound save";
        let companion = b"game-build";
        let g = sha256(companion);
        let bytes = seal_ex(msg, Mode::Seal, None, "s.bin", false, "app=test", &[g]).unwrap();
        assert!(unseal(&bytes, None).is_err());
        let out = unseal_ex(&bytes, None, &[companion.to_vec()]).unwrap();
        assert_eq!(out, msg);
        let mut burned = bytes.clone();
        burned[..KEYSTONE_SPAN].fill(0);
        burned[0] = 0x58;
        let from_ember = unseal_ex(&burned, None, &[companion.to_vec()]).unwrap();
        assert_eq!(from_ember, msg);
    }

    #[test]
    fn work_pack_and_pieces() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("sigil-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("in.bin");
        let mut f = std::fs::File::create(&src).unwrap();
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        f.write_all(&payload).unwrap();
        drop(f);
        let pack = dir.join("out.sgwk");
        let (orig, stars, work) = crate::work::inscribe_path(
            &src,
            &pack,
            Mode::Seal,
            None,
            "",
            &[],
            64 * 1024,
            None,
            crate::DEFAULT_PIECE,
            1,
            None,
        )
        .unwrap();
        assert!(work);
        assert_eq!(orig, payload.len() as u64);
        assert!(stars > 1);
        let back = dir.join("back.bin");
        crate::work::unseal_path(&pack, &back, None, &[]).unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), payload);
        let (head, locs) = crate::work::index_pack(&pack).unwrap();
        assert!(head.overture >= 1);
        assert_eq!(locs.len() as u32, stars);
        let report = crate::work::overture_report(&pack).unwrap();
        assert!(report.contains("Overture"), "{report}");

        let one = crate::seal(b"piece-me", Mode::Seal, None, "p.txt", false).unwrap();
        let pdir = dir.join("pieces");
        crate::pieces::scatter(&one, &pdir).unwrap();
        // drop 8 pieces (seal budget)
        for i in 0..8 {
            let _ = std::fs::remove_file(pdir.join(format!("piece-{i:03}.sgp")));
        }
        let rebuilt = crate::pieces::gather(&pdir).unwrap();
        let plain = crate::unseal(&rebuilt, None).unwrap();
        assert_eq!(plain, b"piece-me");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn folder_pack() {
        let dir = std::env::temp_dir().join(format!("sigil-folder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let src = dir.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"alpha").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"beta-file").unwrap();
        let pack = dir.join("tree.sg1");
        let (n, _) = crate::folder::inscribe_dir(
            &src,
            &pack,
            Mode::Reflection,
            None,
            "",
            &[],
            4 * 1024 * 1024,
            &[],
        )
        .unwrap();
        assert_eq!(n, 2);
        let dest = dir.join("out");
        crate::folder::unseal_dir(&pack, &dest, None, &[]).unwrap();
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(dest.join("sub/b.txt")).unwrap(), b"beta-file");
        let listing = crate::folder::scry_dir(&pack).unwrap();
        assert!(listing.contains("file  a.txt"), "{listing}");
        assert!(listing.contains("file  sub/b.txt"), "{listing}");
        assert!(listing.contains("dir   sub/"), "{listing}");
        let one = dir.join("one");
        let n = crate::folder::unseal_dir_only(&pack, &one, None, &[], &["sub/b.txt".into()], &[])
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(std::fs::read(one.join("sub/b.txt")).unwrap(), b"beta-file");
        assert!(!one.join("a.txt").exists());
        let locked = dir.join("locked.sg1");
        crate::folder::inscribe_dir(
            &src,
            &locked,
            Mode::Glyph,
            Some("house"),
            "",
            &[],
            4 * 1024 * 1024,
            &[("sub/b.txt".into(), "room".into())],
        )
        .unwrap();
        let mixed = dir.join("mixed");
        crate::folder::unseal_dir_only(
            &locked,
            &mixed,
            Some("house"),
            &[],
            &[],
            &[("sub/b.txt".into(), "room".into())],
        )
        .unwrap();
        assert_eq!(std::fs::read(mixed.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            std::fs::read(mixed.join("sub/b.txt")).unwrap(),
            b"beta-file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shifted_byte_and_bom() {
        let msg = b"notepad deletes one character in the middle of a seal";
        let bytes = seal(msg, Mode::Seal, None, "t.txt", false).unwrap();
        let mid = bytes.len() / 2;
        let mut shifted = Vec::with_capacity(bytes.len() - 1);
        shifted.extend_from_slice(&bytes[..mid]);
        shifted.extend_from_slice(&bytes[mid + 1..]);
        let out = unseal(&shifted, None).unwrap();
        assert_eq!(out, msg);
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(&bytes);
        let out = unseal(&bom, None).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn deluge_rain_only() {
        let msg = b"send any eight rain drops, not the whole lake";
        let bytes = seal(msg, Mode::Seal, None, "lake.txt", false).unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-rain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::pieces::deluge(&bytes, 16, &dir, false, None).unwrap();
        // keep only extra pieces 16..23 (k=8)
        for i in 0..16u8 {
            let _ = std::fs::remove_file(dir.join(format!("piece-{i:03}.sgp")));
        }
        for i in 24..32u8 {
            let _ = std::fs::remove_file(dir.join(format!("piece-{i:03}.sgp")));
        }
        let rebuilt = crate::pieces::gather(&dir).unwrap();
        let plain = unseal(&rebuilt, None).unwrap();
        assert_eq!(plain, msg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn triad_lanes() {
        let msg = b"A and B mint different coupons for C";
        let bytes = seal(msg, Mode::Seal, None, "t.txt", false).unwrap();
        let a = std::env::temp_dir().join(format!("sigil-lane-a-{}", std::process::id()));
        let c = std::env::temp_dir().join(format!("sigil-lane-c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&c);
        crate::pieces::deluge(&bytes, 8, &a, true, Some(40)).unwrap();
        crate::pieces::deluge(&bytes, 8, &c, true, Some(80)).unwrap();
        // C's folder: 4 from A (40-43) + 4 from B (80-83) = 8 for Seal
        for i in 40..44u8 {
            std::fs::copy(
                a.join(format!("piece-{i:03}.sgp")),
                c.join(format!("piece-{i:03}.sgp")),
            )
            .unwrap();
        }
        for i in 84..88u8 {
            let _ = std::fs::remove_file(c.join(format!("piece-{i:03}.sgp")));
        }
        let rebuilt = crate::pieces::gather(&c).unwrap();
        assert_eq!(unseal(&rebuilt, None).unwrap(), msg);
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&c);
    }

    #[test]
    fn fountain_raptorq() {
        let msg = b"raptorq rain has no 255 ceiling";
        let bytes = seal(msg, Mode::Seal, None, "fq.txt", false).unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-ft-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::fountain::deluge_fountain(&bytes, &dir, 8).unwrap();
        let mut rqs: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rq"))
            .collect();
        rqs.sort();
        let drop_n = (rqs.len() / 4).max(1);
        for p in rqs.iter().take(drop_n) {
            let _ = std::fs::remove_file(p);
        }
        let rebuilt = crate::fountain::gather_fountain(&dir).unwrap();
        assert_eq!(unseal(&rebuilt, None).unwrap(), msg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn choose_kn_scales() {
        assert_eq!(choose_kn(Mode::Seal, 1_000, DEFAULT_PIECE, None), (8, 16));
        assert_eq!(
            choose_kn(Mode::Seal, 64 * 1024 * 1024, DEFAULT_PIECE, None),
            (16, 32)
        );
        assert_eq!(
            choose_kn(Mode::Seal, 64 * 1024 * 1024, DEFAULT_PIECE, Some(64)),
            (32, 64)
        );
        assert_eq!(
            choose_kn(Mode::Reflection, 1_000, DEFAULT_PIECE, None),
            (12, 16)
        );
        assert_eq!(
            choose_kn(Mode::Glyph, 99_000_000, DEFAULT_PIECE, None),
            (16, 16)
        );
    }

    #[test]
    fn original_name_survives_and_is_a_basename() {
        let bytes = seal(b"hi", Mode::Glyph, None, "circle.txt", false).unwrap();
        let h = read_header(&bytes).unwrap();
        assert_eq!(h.name, "circle.txt");
        let dir = std::env::temp_dir().join(format!("sigil-name-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let mark = dir.join("x.sg1");
        std::fs::write(&mark, &bytes).unwrap();
        assert_eq!(payload_name(&mark).unwrap(), "circle.txt");
        assert_eq!(suggested_output_name(&mark), "circle.txt");

        let evil = seal(b"x", Mode::Glyph, None, "../../etc/passwd", false).unwrap();
        let em = dir.join("e.sg1");
        std::fs::write(&em, &evil).unwrap();
        assert_eq!(suggested_output_name(&em), "passwd");

        let src = dir.join("notes.txt");
        std::fs::write(&src, b"keep my name").unwrap();
        let packed = dir.join("notes.sg1");
        inscribe_path(
            &src,
            &packed,
            Mode::Glyph,
            None,
            "",
            &[],
            DEFAULT_CHUNK,
            None,
            0,
            64,
            None,
        )
        .unwrap();
        assert_eq!(suggested_output_name(&packed), "notes.txt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mend_torn_seal() {
        let msg = b"mend me in place please -- longer for deflate";
        let bytes = seal(msg, Mode::Seal, None, "t.txt", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let mut torn = bytes.clone();
        let stride = header::shard_stride(&h);
        let prefix = if h.keystone() {
            KEYSTONE_SPAN
        } else {
            HEADER_SIZE
        };
        // Smash half the shards (Seal budget = 8 of 16).
        for i in 0..8 {
            let off = prefix + i * stride;
            torn[off..off + stride].fill(0);
            torn[off] = 3;
        }
        let healed = crate::pieces::mend_bytes(&torn).unwrap();
        let (_, merkle_ok, live, k, _) = verify(&healed).unwrap();
        assert!(merkle_ok);
        assert_eq!(live, 16);
        assert_eq!(k, 8);
        assert_eq!(unseal(&healed, None).unwrap(), msg);
    }

    #[test]
    fn mend_glyph_errors() {
        let msg = b"glyph cannot mend a missing shard";
        let bytes = seal(msg, Mode::Glyph, None, "g.txt", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let mut torn = bytes.clone();
        let stride = header::shard_stride(&h);
        let prefix = if h.keystone() {
            KEYSTONE_SPAN
        } else {
            HEADER_SIZE
        };
        torn[prefix..prefix + stride].fill(0);
        torn[prefix] = 3;
        assert!(crate::pieces::mend_bytes(&torn).is_err());
        // Soft does not change Glyph: still all-or-nothing.
        assert!(crate::pieces::mend_bytes_ex(&torn, true).is_err());
        // All shards present: mend succeeds and round-trips.
        let healed = crate::pieces::mend_bytes(&bytes).unwrap();
        assert_eq!(unseal(&healed, None).unwrap(), msg);
    }

    #[test]
    fn mend_soft_salvages_crc_trailer_bitrot() {
        let msg = b"soft salvage bit-rotten CRC trailers before giving up -- pad for deflate xx";
        let bytes = seal(msg, Mode::Seal, None, "soft.txt", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let stride = header::shard_stride(&h);
        let prefix = header::body_prefix(&h);
        let lead =
            if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { header::VOW_SIZE } else { 0 };
        let sl = h.shard_len as usize;
        let mut torn = bytes.clone();
        // Wipe 8 shards (Seal budget edge): indices 0..7 gone.
        for i in 0..8usize {
            let off = prefix + i * stride;
            torn[off..off + stride].fill(0);
            torn[off] = 3;
        }
        // Corrupt CRC trailers on shards 8 and 9 (bodies intact) → hard live = 6 < 8.
        for i in [8usize, 9] {
            let crc_off = prefix + i * stride + lead + sl;
            torn[crc_off] ^= 0xff;
        }
        let hard = header::gather_live_shards(&torn, &h, prefix);
        let hard_n = hard.iter().filter(|s| s.is_some()).count();
        assert!(hard_n < h.k as usize, "hard live {hard_n}");
        assert!(crate::pieces::mend_bytes(&torn).is_err());
        let (healed, used_soft) = crate::pieces::mend_bytes_ex(&torn, true).unwrap();
        assert!(used_soft);
        let (_, merkle_ok, live, k, _) = verify(&healed).unwrap();
        assert!(merkle_ok);
        assert_eq!(live, 16);
        assert_eq!(k, 8);
        assert_eq!(unseal(&healed, None).unwrap(), msg);
        assert_eq!(sha256(msg), read_header(&healed).unwrap().digest);
    }

    /// Flip `count` distinct random bits anywhere in `bytes` (xorshift, fixed seed).
    fn flip_scattered_bits(bytes: &[u8], count: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        let mut out = bytes.to_vec();
        let mut done = std::collections::BTreeSet::new();
        while done.len() < count {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let bit = (x % (bytes.len() as u64 * 8)) as usize;
            if done.insert(bit) {
                out[bit / 8] ^= 1 << (bit % 8);
            }
        }
        out
    }

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn mend_soft_column_repair_fixes_scattered_bit_flips() {
        let msg = noise(200_000, 0x5eed);
        for mode in [Mode::Reflection, Mode::Seal] {
            let bytes = seal(&msg, mode, None, "flips.bin", false).unwrap();
            for (count, seed) in [(16usize, 1u64), (64, 2), (256, 3)] {
                let torn = flip_scattered_bits(&bytes, count, seed);
                // Classic erasure decode loses: every shard has a bad CRC.
                assert!(unseal(&torn, None).is_err(), "{mode:?} {count}");
                assert!(crate::pieces::mend_bytes(&torn).is_err());
                let (healed, used_soft) = crate::pieces::mend_bytes_ex(&torn, true).unwrap();
                assert!(used_soft);
                assert_eq!(
                    healed, bytes,
                    "{mode:?} {count}: mend rewrites the exact original mark"
                );
                assert_eq!(unseal(&healed, None).unwrap(), msg);
            }
        }
    }

    #[test]
    fn mend_soft_column_repair_encrypted_and_wrong_key() {
        let msg = noise(120_000, 0xc0de);
        let bytes = seal(&msg, Mode::Reflection, Some("deep space"), "enc.bin", false).unwrap();
        let torn = flip_scattered_bits(&bytes, 64, 9);
        assert!(unseal(&torn, Some("deep space")).is_err());
        // No passphrase needed to mend; the Merkle binding gates the ciphertext.
        let (healed, _) = crate::pieces::mend_bytes_ex(&torn, true).unwrap();
        assert_eq!(unseal(&healed, Some("deep space")).unwrap(), msg);
        assert!(unseal(&healed, Some("wrong")).is_err());
    }

    #[test]
    fn mend_soft_column_repair_with_truncation_and_flips() {
        let msg = noise(200_000, 0x7a11);
        let bytes = seal(&msg, Mode::Seal, None, "cut.bin", false).unwrap();
        // Cut the last ~3 shards off (erasures) and flip bits in what is left.
        let cut = &bytes[..bytes.len() * 13 / 16];
        let torn = flip_scattered_bits(cut, 32, 4);
        let (healed, _) = crate::pieces::mend_bytes_ex(&torn, true).unwrap();
        assert_eq!(unseal(&healed, None).unwrap(), msg);
    }

    #[test]
    fn mend_soft_column_repair_fails_closed_when_flooded() {
        // Far past the per-column budget: refuse, never wrong bytes.
        let msg = noise(50_000, 0xf100d);
        let bytes = seal(&msg, Mode::Reflection, None, "flood.bin", false).unwrap();
        let torn = flip_scattered_bits(&bytes, bytes.len() * 8 / 20, 5);
        match crate::pieces::mend_bytes_ex(&torn, true) {
            Err(_) => {}
            Ok((healed, _)) => assert_eq!(unseal(&healed, None).unwrap(), msg),
        }
        assert!(unseal(&torn, None).is_err());
        // Payload columns rewritten consistently (an attacker, not radiation)
        // re-encode to a different Merkle root: refused.
        let h = read_header(&bytes).unwrap();
        let prefix = header::body_prefix(&h);
        let stride = header::shard_stride(&h);
        let lead =
            if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { header::VOW_SIZE } else { 0 };
        let sl = h.shard_len as usize;
        let mut forged = bytes.clone();
        let mut p = unseal_folded_for_test(&bytes);
        p[100] ^= 0x55;
        for (i, s) in (0..h.n as usize)
            .map(|i| crate::rs::encode_shard_index(&p, h.k as usize, i, true).unwrap())
            .enumerate()
        {
            let off = prefix + i * stride + lead;
            forged[off..off + sl].copy_from_slice(&s);
        }
        assert!(crate::pieces::mend_bytes_ex(&forged, true).is_err());
        assert!(unseal(&forged, None).is_err());
    }

    #[test]
    fn mend_from_ember_header_restores_exact_front_header() {
        // All four front header copies and shard 0's Ember are gone, so the
        // header comes from a later Ember (which stores its slot in the
        // entropy word). The mended mark must carry the original header bytes,
        // and an encrypted (v3) mark must still unlock after the mend.
        let msg = noise(60_000, 0xe4be);
        for pass in [None, Some("ember pass")] {
            let bytes = seal(&msg, Mode::Reflection, pass, "ember.bin", false).unwrap();
            let h = read_header(&bytes).unwrap();
            let prefix = header::body_prefix_file(&h, &bytes);
            let mut torn = bytes.clone();
            torn[..header::KEYSTONE_SPAN].fill(0);
            torn[prefix..prefix + HEADER_SIZE].fill(0);
            let healed = crate::pieces::mend_bytes(&torn).unwrap();
            assert_eq!(unseal(&healed, pass).unwrap(), msg);
            assert_eq!(healed, bytes, "pass={pass:?}");
        }
    }

    #[test]
    fn mend_soft_finds_body_offset_when_front_header_and_all_crcs_are_gone() {
        // Front header + Keystone wiped, 13 of 16 Embers damaged and one flipped
        // bit in every shard body: no shard passes its CRC, so the body offset
        // must come from where the surviving Embers sit, not from CRC-good shards.
        let msg = noise(100_000, 0x0ff5e7);
        let bytes = seal(&msg, Mode::Seal, None, "offset.bin", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let prefix = header::body_prefix_file(&h, &bytes);
        let stride = header::shard_stride(&h);
        let lead =
            if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { header::VOW_SIZE } else { 0 };
        let mut torn = bytes.clone();
        torn[..header::KEYSTONE_SPAN].fill(0);
        for i in 0..h.n as usize {
            torn[prefix + i * stride + lead + 17 * (i + 1)] ^= 0x10;
            // Most Embers are hit too (so their bodies are found only by
            // offset); three stay readable.
            if ![5usize, 9, 12].contains(&i) {
                torn[prefix + i * stride + 50] ^= 0x01;
            }
        }
        let live = header::gather_live_shards(&torn, &h, prefix);
        assert!(live.iter().all(|s| s.is_none()));
        let (healed, used_soft) = crate::pieces::mend_bytes_ex(&torn, true).unwrap();
        assert!(used_soft);
        assert_eq!(healed, bytes);
        assert_eq!(unseal(&healed, None).unwrap(), msg);
    }

    /// The folded payload of a healthy plain mark (data shards concatenated).
    fn unseal_folded_for_test(bytes: &[u8]) -> Vec<u8> {
        let h = read_header(bytes).unwrap();
        let prefix = header::body_prefix(&h);
        let live = header::gather_live_shards(bytes, &h, prefix);
        let parts: Vec<(usize, Vec<u8>)> = live
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|b| (i, b.clone())))
            .collect();
        crate::rs::decode_indexed(&parts, h.k as usize, h.folded_len as usize, true).unwrap()
    }

    #[test]
    fn mend_soft_true_name_rejects_garbage() {
        let msg = b"true-name must gate soft accept -- longer payload for shards";
        let bytes = seal(msg, Mode::Seal, None, "tn.txt", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let stride = header::shard_stride(&h);
        let prefix = header::body_prefix(&h);
        let lead =
            if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { header::VOW_SIZE } else { 0 };
        let sl = h.shard_len as usize;
        let mut torn = bytes.clone();
        // Destroy 9 shards so even soft present count may be tight; flip body bytes on all survivors.
        for i in 0..9usize {
            let off = prefix + i * stride;
            torn[off..off + stride].fill(0);
            torn[off] = 7;
        }
        for i in 9..16usize {
            let body_off = prefix + i * stride + lead;
            for j in 0..sl.min(64) {
                torn[body_off + j] ^= 0xa5;
            }
        }
        assert!(crate::pieces::mend_bytes_ex(&torn, true).is_err());
    }

    #[test]
    fn attest_roundtrip() {
        let msg = b"sign me";
        let bytes = seal(msg, Mode::Glyph, None, "s.txt", false).unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-at-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let mark = dir.join("m.sg1");
        std::fs::write(&mark, &bytes).unwrap();
        let key = dir.join("k.bin");
        crate::attest_keygen(&key).unwrap();
        crate::attest(&mark, &key).unwrap();
        let v = crate::verify_attestation(&mark).unwrap();
        assert!(v.contains("good"), "{v}");
        std::fs::remove_file(format!("{}.sig", mark.display())).unwrap();
        let none = crate::verify_attestation(&mark).unwrap();
        assert!(none.contains("none"), "{none}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cdc_inscribe_roundtrip() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("sigil-cdc-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("in.bin");
        let payload: Vec<u8> = (0..900_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::File::create(&src)
            .unwrap()
            .write_all(&payload)
            .unwrap();
        let pack = dir.join("out.sgwk");
        let fine = crate::CdcProfile {
            name: "test",
            min: crate::CDC_FLOOR,
            avg: 128 * 1024,
            max: 256 * 1024,
        };
        let (orig, stars, work) = crate::work::inscribe_path(
            &src,
            &pack,
            Mode::Seal,
            None,
            "",
            &[],
            DEFAULT_CHUNK,
            None,
            crate::DEFAULT_PIECE,
            1,
            Some(fine),
        )
        .unwrap();
        assert_eq!(orig, payload.len() as u64);
        assert!(work, "expected multi-star work pack");
        assert!(stars >= 2);
        let back = dir.join("back.bin");
        crate::work::unseal_path(&pack, &back, None, &[]).unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), payload);
        let facets = crate::work::scry_facets(&pack).unwrap();
        assert_eq!(facets.len() as u32, stars);
        let mut off = 0u64;
        for f in &facets {
            assert_eq!(f.orig_off, off);
            assert!(f.orig_len as usize <= fine.max);
            off += f.orig_len as u64;
        }
        assert_eq!(off, orig);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cauchy_seal_unseal_true_name() {
        let msg: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
        let be = crate::CauchyRs::new();
        let bytes = seal_kn_mds(
            &msg,
            Mode::Seal,
            None,
            "c.bin",
            false,
            "",
            &[],
            Some(16),
            DEFAULT_PIECE,
            &be,
        )
        .unwrap();
        let out = unseal_ex_mds(&bytes, None, &[], &be).unwrap();
        assert_eq!(out, msg);
        assert_eq!(sha256(&out), sha256(&msg));
        // Intact systematic mark: both backends can take the data-shard fast path.
        // Wipe data shards 0..7 so decode must use Cauchy parity — Vandermonde then fails.
        let h = read_header(&bytes).unwrap();
        let stride = header::shard_stride(&h);
        let prefix = if h.keystone() {
            KEYSTONE_SPAN
        } else {
            HEADER_SIZE
        };
        let mut torn = bytes.clone();
        for i in 0..8 {
            let off = prefix + i * stride;
            torn[off..off + stride].fill(0);
            torn[off] = 3;
        }
        assert!(
            unseal(&torn, None).is_err(),
            "Vandermonde must not decode Cauchy parity"
        );
        let healed = unseal_ex_mds(&torn, None, &[], &be).unwrap();
        assert_eq!(healed, msg);
    }

    #[test]
    fn cdc_edit_locality_inscribe() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("sigil-cdc-edit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fine = crate::CdcProfile {
            name: "test",
            min: crate::CDC_FLOOR,
            avg: 128 * 1024,
            max: 256 * 1024,
        };
        let mut payload: Vec<u8> = (0..900_000u32).map(|i| ((i * 13) % 251) as u8).collect();
        let src = dir.join("a.bin");
        std::fs::File::create(&src)
            .unwrap()
            .write_all(&payload)
            .unwrap();
        let pack_a = dir.join("a.sgwk");
        let (_, stars_a, work_a) = crate::work::inscribe_path(
            &src,
            &pack_a,
            Mode::Glyph,
            None,
            "",
            &[],
            DEFAULT_CHUNK,
            None,
            crate::DEFAULT_PIECE,
            1,
            Some(fine),
        )
        .unwrap();
        assert!(work_a && stars_a >= 3);
        let dig_a = crate::work::read_facet_digests(&pack_a).unwrap();
        let mid = payload.len() / 2;
        for i in 0..64 {
            payload[mid + i] ^= 0xa5;
        }
        std::fs::File::create(&src)
            .unwrap()
            .write_all(&payload)
            .unwrap();
        let pack_b = dir.join("b.sgwk");
        crate::work::inscribe_path(
            &src,
            &pack_b,
            Mode::Glyph,
            None,
            "",
            &[],
            DEFAULT_CHUNK,
            None,
            crate::DEFAULT_PIECE,
            1,
            Some(fine),
        )
        .unwrap();
        let dig_b = crate::work::read_facet_digests(&pack_b).unwrap();
        let kept = dig_a.iter().filter(|d| dig_b.contains(d)).count();
        assert!(
            kept + 2 >= dig_a.len() && kept >= dig_a.len().saturating_sub(3).max(1),
            "expected most facet digests to survive middle edit; kept {kept} of {}",
            dig_a.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_to_roundtrip() {
        let alice = crate::Identity::generate().unwrap();
        let bob = crate::Identity::generate().unwrap();
        let msg = b"encrypt-to river circle";
        let bytes = seal_kn_mds_to(
            msg,
            Mode::Seal,
            None,
            "t.txt",
            false,
            "",
            &[],
            Some(16),
            DEFAULT_PIECE,
            &*mds::default_backend(),
            &[alice.public()],
        )
        .unwrap();
        assert!(bytes.windows(4).any(|w| w == b"SGTO"));
        let out = unseal_ex_keys(&bytes, None, &[], &[alice]).unwrap();
        assert_eq!(out, msg);
        assert!(unseal_ex_keys(&bytes, None, &[], &[bob]).is_err());
        assert!(unseal(&bytes, None).is_err());
    }

    #[test]
    fn encrypt_to_or_passphrase() {
        let alice = crate::Identity::generate().unwrap();
        let msg = b"either key opens";
        let bytes = seal_kn_mds_to(
            msg,
            Mode::Reflection,
            Some("ward-pass"),
            "t.txt",
            false,
            "",
            &[],
            Some(16),
            DEFAULT_PIECE,
            &*mds::default_backend(),
            &[alice.public()],
        )
        .unwrap();
        assert_eq!(unseal_ex_keys(&bytes, None, &[], &[alice]).unwrap(), msg);
        assert_eq!(
            unseal_ex_keys(&bytes, Some("ward-pass"), &[], &[]).unwrap(),
            msg
        );
        assert!(unseal_ex_keys(&bytes, Some("wrong"), &[], &[]).is_err());
    }

    #[test]
    fn passphrase_only_still_works() {
        // New passphrase seals carry an Argon2id SGTO wrap; legacy (no-SGTO) Ward files are
        // covered by `kdf_tests::old_files_keep_opening` with fixtures from the old writer.
        let msg = b"passphrase ward";
        let bytes = seal(msg, Mode::Seal, Some("secret"), "t.txt", false).unwrap();
        assert!(bytes.windows(4).any(|w| w == b"SGTO"));
        assert_eq!(unseal(&bytes, Some("secret")).unwrap(), msg);
        assert!(unseal(&bytes, Some("nope")).is_err());
    }

    #[test]
    fn folder_encrypt_to_identity_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sigil-folder-to-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src/sub")).unwrap();
        std::fs::write(dir.join("src/a.txt"), b"alpha-to").unwrap();
        std::fs::write(dir.join("src/sub/b.txt"), b"beta-to").unwrap();
        let alice = crate::Identity::generate().unwrap();
        let bob = crate::Identity::generate().unwrap();
        let pack = dir.join("pack.sg1");
        crate::folder::inscribe_dir_to(
            &dir.join("src"),
            &pack,
            Mode::Reflection,
            None,
            "",
            &[],
            4 * 1024 * 1024,
            &[],
            &[alice.public()],
        )
        .unwrap();
        let dest = dir.join("out");
        let n = crate::folder::unseal_dir_only_keys(&pack, &dest, None, &[], &[], &[], &[alice])
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha-to");
        assert_eq!(std::fs::read(dest.join("sub/b.txt")).unwrap(), b"beta-to");
        assert!(crate::folder::unseal_dir_only_keys(
            &pack,
            &dir.join("bad"),
            None,
            &[],
            &[],
            &[],
            &[bob],
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn work_pack_encrypt_to_identity() {
        let dir = std::env::temp_dir().join(format!("sigil-work-to-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("big.bin");
        let payload = vec![0x5au8; 200 * 1024];
        std::fs::write(&src, &payload).unwrap();
        let alice = crate::Identity::generate().unwrap();
        let pack = dir.join("w.sgwk");
        let (orig, stars, work) = crate::work::inscribe_path_to(
            &src,
            &pack,
            Mode::Glyph,
            None,
            "",
            &[],
            64 * 1024,
            None,
            DEFAULT_PIECE,
            1,
            None,
            &[alice.public()],
        )
        .unwrap();
        assert!(work && stars >= 2);
        assert_eq!(orig, payload.len() as u64);
        let back = dir.join("back.bin");
        crate::work::unseal_path_keys(&pack, &back, None, &[], &[alice]).unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_walk_identity_nested_mark() {
        let dir = std::env::temp_dir().join(format!("sigil-path-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let alice = crate::Identity::generate().unwrap();
        let inner = seal_kn_to(
            b"nested-clear",
            Mode::Glyph,
            None,
            "leaf.txt",
            false,
            "",
            &[],
            None,
            DEFAULT_PIECE,
            &[alice.public()],
        )
        .unwrap();
        let outer = seal_kn_to(
            &inner,
            Mode::Glyph,
            None,
            "inner.sg1",
            false,
            "",
            &[],
            None,
            DEFAULT_PIECE,
            &[alice.public()],
        )
        .unwrap();
        let mark = dir.join("outer.sg1");
        std::fs::write(&mark, &outer).unwrap();
        let view =
            crate::path_walk_keys(&mark, &[], None, &[], 8, std::slice::from_ref(&alice)).unwrap();
        assert!(
            view.nest_payload,
            "outer encrypt-to mark should advertise nested payload"
        );
        // --into . unwraps outer → inner .sg1 bytes (still a seal); then identity-unseal leaf.
        let dest = dir.join("inner.sg1");
        crate::path_extract_keys(
            &mark,
            &[".".into()],
            &dest,
            None,
            &[],
            8,
            std::slice::from_ref(&alice),
        )
        .unwrap();
        let leaf = unseal_ex_keys(&std::fs::read(&dest).unwrap(), None, &[], &[alice]).unwrap();
        assert_eq!(leaf, b"nested-clear");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_keygen_attest_seed() {
        let dir = std::env::temp_dir().join(format!("sigil-legkey-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let key = dir.join("legacy.bin");
        let pk = crate::keygen_legacy(&key).unwrap();
        assert_eq!(std::fs::read(&key).unwrap().len(), 32);
        let mark = dir.join("m.sg1");
        let bytes = seal(b"x", Mode::Glyph, None, "x", false).unwrap();
        std::fs::write(&mark, &bytes).unwrap();
        crate::attest(&mark, &key).unwrap();
        let v = crate::verify_attestation(&mark).unwrap();
        assert!(v.contains("good"), "{v}");
        assert_eq!(pk.len(), 32);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod kdf_tests {
    use super::*;

    const PASS: &str = "correct horse battery";

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kdf-v0");
        std::fs::read(p.join(name)).unwrap()
    }

    /// (offset of the SGTO block, its length) in a sealed file.
    fn sgto_span(f: &[u8]) -> (usize, usize) {
        let (h, _, _) = locate_header(f).unwrap();
        let off = header::maps_len(&h);
        (off, keys::sgto_len_at(f, off))
    }

    /// Rewrite the SGTO CRC after a deliberate edit (so the edit reaches the KDF/AEAD).
    fn fix_sgto_crc(f: &mut [u8], off: usize, len: usize) {
        let crc = crc32fast::hash(&f[off..off + len - 4]);
        f[off + len - 4..off + len].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn new_passphrase_seal_uses_argon2id_with_stored_params() {
        let data = b"argon2id ward round trip".repeat(50);
        let f = seal(&data, Mode::Seal, Some(PASS), "a2", false).unwrap();
        let (off, len) = sgto_span(&f);
        assert!(len > 0, "passphrase seal must carry an SGTO block");
        assert_eq!(f[off + 4], keys::SGTO_VERSION_ARGON2);
        let rec = off + 8;
        assert_eq!(f[rec], 3, "KIND_PASS_ARGON2ID");
        let u = |o: usize| u32::from_le_bytes(f[rec + o..rec + o + 4].try_into().unwrap());
        assert_eq!(
            (u(17), u(21), u(25)),
            (keys::ARGON2_M_KIB, keys::ARGON2_T, keys::ARGON2_P)
        );
        assert_eq!(unseal(&f, Some(PASS)).unwrap(), data);
        assert!(unseal(&f, Some("wrong horse")).is_err());
        assert!(unseal(&f, None).is_err());
    }

    #[test]
    fn old_files_keep_opening() {
        let plain = fixture("plain.bin");
        // Legacy Ward: PBKDF2-HMAC-SHA256 80k, no SGTO (written by main @ c88d682).
        let ward = fixture("ward-pbkdf2-80k.sg1");
        assert_eq!(sgto_span(&ward).1, 0);
        assert_eq!(unseal(&ward, Some(PASS)).unwrap(), plain);
        assert!(unseal(&ward, Some("wrong horse")).is_err());
        // SGTO v1 with a KIND_PASS (PBKDF2 80k) wrap next to an X25519 recipient.
        let to = fixture("sgto-passwrap-pbkdf2-80k.sg1");
        let (off, len) = sgto_span(&to);
        assert!(len > 0);
        assert_eq!(to[off + 4], keys::SGTO_VERSION);
        assert_eq!(unseal(&to, Some(PASS)).unwrap(), plain);
        assert!(unseal(&to, Some("wrong horse")).is_err());
    }

    #[test]
    fn encrypt_to_plus_passphrase_round_trip() {
        let data = b"to + pass".repeat(100);
        let id = keys::Identity::generate().unwrap();
        let f = seal_kn_mds_to(
            &data,
            Mode::Reflection,
            Some(PASS),
            "tp",
            false,
            "",
            &[],
            None,
            DEFAULT_PIECE,
            &*mds::default_backend(),
            &[id.public()],
        )
        .unwrap();
        assert_eq!(unseal(&f, Some(PASS)).unwrap(), data);
        assert_eq!(
            unseal_ex_keys(&f, None, &[], std::slice::from_ref(&id)).unwrap(),
            data
        );
        assert!(unseal(&f, Some("wrong horse")).is_err());
    }

    #[test]
    fn tampered_or_hostile_params_fail_closed() {
        let data = b"tamper".repeat(200);
        let f = seal(&data, Mode::Reflection, Some(PASS), "t", false).unwrap();
        let (off, len) = sgto_span(&f);
        let rec = off + 8 + 1; // after the kind byte
        let set = |o: usize, v: u32| {
            let mut g = f.clone();
            g[rec + o..rec + o + 4].copy_from_slice(&v.to_le_bytes());
            fix_sgto_crc(&mut g, off, len);
            g
        };
        // Different (still valid) memory cost: wrong key, AEAD rejects.
        assert!(unseal(&set(16, keys::ARGON2_M_KIB + 1024), Some(PASS)).is_err());
        // Hostile memory / passes / lanes / zero: rejected before any derivation (DoS bound).
        let t0 = std::time::Instant::now();
        for (o, v) in [
            (16, u32::MAX),
            (16, keys::ARGON2_MAX_M_KIB + 1),
            (20, 1000),
            (24, 64),
            (20, 0),
        ] {
            let e = unseal(&set(o, v), Some(PASS)).unwrap_err().to_string();
            assert!(e.contains("rejected"), "{o}={v}: {e}");
        }
        assert!(
            t0.elapsed().as_secs() < 5,
            "bounds must short-circuit, not allocate"
        );
        // Flipped salt / wrapped CEK byte: AEAD rejects.
        for o in [0usize, 60] {
            let mut g = f.clone();
            g[rec + o] ^= 1;
            fix_sgto_crc(&mut g, off, len);
            assert!(unseal(&g, Some(PASS)).is_err(), "byte {o}");
        }
    }
}
