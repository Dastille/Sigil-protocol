//! Sigil protocol v1 — same .sg1 layout as the lab.
mod attest;
mod boot;
mod cdc;
mod chaos;
mod constellation;
mod folder;
mod fountain;
mod gf;
mod header;
mod keys;
mod kit;
mod mds;
mod merkle;
mod mount;
mod nest;
mod open;
mod pieces;
mod rs;
mod show;
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
pub use boot::{copy_sigil_binary, find_boot_mark, inject_initrd, install_hooks, mend_boot, mend_scan, prepare_boot, BootFind, BootOutcome};
pub use constellation::{
    add_to_constellation, is_atlas_file, is_constellation_dir, is_constellation_input, is_constellation_mark,
    pack_atlas, scry_constellation, unseal_constellation, AddOpts, AddReport,
};
pub use folder::{inscribe_dir, inscribe_dir_to, is_dir_pack, list_dir_pack, looks_like_nest_name, read_dir_entry_star, scry_dir, unseal_dir, unseal_dir_only, unseal_dir_only_keys, DirEntry};
pub use nest::{
    is_nestable_bytes, kind_of_bytes, path_extract, path_extract_keys, path_list, path_walk,
    path_walk_keys, refuse_if_cycle, NestKind, PathEntry, PathView, MAX_NEST_DEPTH,
};
pub use fountain::{deluge_fountain, gather_fountain, is_fountain_dir};
pub use header::{locate_header, read_header, write_header, Header, HEADER_SIZE, KEYSTONE_SPAN, VERSION};
pub use merkle::merkle_root;
pub use mds::{
    backend_by_name, default_backend, format_bakeoff_report, run_bakeoff, CauchyRs, MdsBackend,
    MdsBenchRow, VandermondeRs,
};
pub use open::{run_open, run_open_keys};
pub use pieces::{
    deluge as deluge_pieces, gather as gather_pieces, gather_dirs as gather_piece_dirs, mend_bytes,
    mend_bytes_ex, scatter as scatter_pieces, tally as tally_pieces, vessel_present, write_vessel,
    VESSEL,
};
pub use keys::{
    keygen_ecc, keygen_legacy, resolve_recipient, Identity, PublicIdentity, ID_MAGIC, PUB_MAGIC,
    SGTO_MAGIC,
};
pub use kit::{is_kit_dir, mend as mend_kit, place as place_kit, PlaceReport, DEFAULT_DRIVES, KIT_MANIFEST};
pub use vault::{
    commit as vault_commit, commit_from_export as vault_commit_from_export,
    dirty_meta_for as vault_dirty_meta_for, format_retention as vault_format_retention,
    format_status as vault_format_status, format_versions as vault_format_versions,
    get_retention as vault_get_retention, list_versions as vault_list_versions,
    maybe_prune_after_commit as vault_maybe_prune_after_commit, prune as vault_prune,
    prune_with as vault_prune_with, restore as vault_restore,
    set_retention as vault_set_retention, status as vault_status, track as vault_track,
    vault_dir_for, CommitReport as VaultCommitReport, DirtyMeta as VaultDirtyMeta,
    Drift as VaultDrift, PruneReport as VaultPruneReport, RestoreReport as VaultRestoreReport,
    RetentionPolicy as VaultRetention, StatusReport as VaultStatusReport,
    TrackReport as VaultTrackReport, CHART_NAME as VAULT_CHART, DIRTY_NAME as VAULT_DIRTY,
    VAULT_SUFFIX,
};
pub use cdc::{chunk_file_ranges, chunk_owned, chunk_ranges, ChunkRange, Profile as CdcProfile, DEDUP as CDC_DEDUP, FLOOR as CDC_FLOOR, MEDIA as CDC_MEDIA};
pub use work::{
    choose_overture, index_pack, inscribe_path, inscribe_path_to, inscribe_stars_dir,
    inscribe_stars_dir_to, is_work_pack, overture_report, payload_name, read_facet_digests,
    scry_facets, scry_path, suggested_output_name, unseal_path, unseal_path_keys, unseal_range,
    unseal_range_keys, unseal_star_at, unseal_star_at_keys, DEFAULT_CHUNK, DEFAULT_OVERTURE_MB,
    OVERTURE, WORK_MAGIC,
};
pub use show::run_showing;
pub use mount::{
    fuse_available, mount_fuse, run_mount, run_mount_keys, umount as umount_path, VaultFs,
};
pub use vault::tip_seal_path as vault_tip_seal_path;

pub const DEFAULT_PIECE: u32 = 4 * 1024 * 1024;

pub fn rain_lane() -> u8 {
    let mut b = [0u8; 1];
    getrandom(&mut b);
    16 + (b[0] % 200)
}
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

fn derive_key(pass: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pass.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

pub fn seal(data: &[u8], mode: Mode, pass: Option<&str>, name: &str, graph: bool) -> Result<Vec<u8>> {
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
    seal_kn(data, mode, pass, name, graph, covenant, geas, None, DEFAULT_PIECE)
}

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
    seal_kn_to(data, mode, pass, name, graph, covenant, geas, shards, piece_bytes, &[])
}

/// Like `seal_kn`, with optional encrypt-to recipients (`--to`).
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
        data, mode, pass, name, graph, covenant, geas, shards, piece_bytes, mds_be, &[],
    )
}

/// Seal with optional encrypt-to recipients (`--to`). When `recipients` is non-empty,
/// body is AES-GCM'd under a random CEK; SGTO holds X25519 wraps (and a passphrase
/// wrap if `pass` is also set). Encrypt-to alone is enough; with both, either opens.
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
    let (k, n) = choose_kn(mode, data.len() as u64, piece_bytes, shards);
    let digest = sha256(data);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom(&mut salt);
    getrandom(&mut nonce);
    let (body, compressed) = maybe_deflate(data);
    let mut folded = chaos::fold(&body, &salt);
    let mut tag = [0u8; 16];
    let mut encrypted = false;
    let mut sgto_block: Option<Vec<u8>> = None;
    let use_to = !recipients.is_empty();
    let pass_nonempty = pass.filter(|s| !s.is_empty());
    if use_to {
        // Random CEK; wrap for each recipient (+ optional passphrase wrap).
        let mut cek = [0u8; 32];
        getrandom(&mut cek);
        let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|e| Error::Msg(e.to_string()))?;
        let packed = cipher
            .encrypt(Nonce::from_slice(&nonce), folded.as_ref())
            .map_err(|_| Error::Msg("encrypt failed".into()))?;
        let t = packed.len() - 16;
        tag.copy_from_slice(&packed[t..]);
        folded = packed[..t].to_vec();
        encrypted = true;
        sgto_block = Some(keys::build_sgto(&cek, recipients, pass_nonempty, &salt)?);
    } else if let Some(p) = pass_nonempty {
        // Legacy passphrase Ward: PBKDF2 → AES-GCM on folded body (unchanged).
        let key = derive_key(p, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| Error::Msg(e.to_string()))?;
        let packed = cipher
            .encrypt(Nonce::from_slice(&nonce), folded.as_ref())
            .map_err(|_| Error::Msg("encrypt failed".into()))?;
        let t = packed.len() - 16;
        tag.copy_from_slice(&packed[t..]);
        folded = packed[..t].to_vec();
        encrypted = true;
    }
    let shards = if matches!(mode, Mode::Glyph) {
        rs::stripe(&folded, n)
    } else {
        mds_be.encode(&folded, k, n)
    };
    let leaves: Vec<[u8; 32]> = shards.iter().map(|s| sha256(s)).collect();
    let merkle = merkle::merkle_root(&leaves);
    let mut flags = mode.flag();
    if compressed {
        flags |= 1;
    }
    if encrypted {
        flags |= 2;
    }
    if graph {
        flags |= 1 << 4;
    }
    flags |= header::FLAG_KEYSTONE;
    flags |= header::FLAG_EMBER;
    let has_vow = !covenant.is_empty() || !geas.is_empty();
    if has_vow {
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
        tag,
        shard_len: shards.first().map(|s| s.len() as u32).unwrap_or(1),
        entropy_milli,
        name: name.to_string(),
        merkle,
    });
    let mut out = header::wrap_keystone(&hdr);
    // SGTO sits after keystone, before vow (detected by magic — no flag bit).
    if let Some(sg) = &sgto_block {
        out.extend_from_slice(sg);
    }
    let vow = if has_vow {
        Some(header::write_vow(covenant, geas))
    } else {
        None
    };
    if let Some(v) = &vow {
        out.extend_from_slice(v);
    }
    for (i, s) in shards.iter().enumerate() {
        out.extend_from_slice(&header::write_ember(&hdr, i as u8));
        if let Some(v) = &vow {
            out.extend_from_slice(v);
        }
        out.extend_from_slice(s);
        out.extend_from_slice(&crc32fast::hash(s).to_le_bytes());
    }
    Ok(out)
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
    let (h, prefix, _) = locate_header(file)?;
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
                    return Err(Error::Msg("Geas not met — companion missing or changed.".into()));
                }
            }
        }
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
    if h.encrypted() {
        let sgto = header::sgto_slice(&h, file);
        let key = if let Some(block) = sgto {
            // Encrypt-to (and optional passphrase wrap in SGTO).
            match keys::unwrap_cek(block, identities, pass.filter(|s| !s.is_empty()), &h.salt) {
                Ok(cek) => cek,
                Err(e) => {
                    if identities.is_empty() && p.is_empty() {
                        return Err(Error::Msg(
                            "passphrase or --identity required".into(),
                        ));
                    }
                    return Err(e);
                }
            }
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
        packed.extend_from_slice(&h.tag);
        folded = cipher
            .decrypt(Nonce::from_slice(&h.nonce), packed.as_ref())
            .map_err(|_| Error::Msg("wrong passphrase/identity, or past repair".into()))?;
    } else if !p.is_empty() {
        return Err(Error::Msg("seal was not encrypted".into()));
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
    Ok(plain)
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
        let prefix = if h.keystone() { KEYSTONE_SPAN } else { HEADER_SIZE };
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
        let (orig, stars, work) =
            crate::work::inscribe_path(&src, &pack, Mode::Seal, None, "", &[], 64 * 1024, None, crate::DEFAULT_PIECE, 1, None).unwrap();
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
        let (n, _) = crate::folder::inscribe_dir(&src, &pack, Mode::Reflection, None, "", &[], 4 * 1024 * 1024, &[]).unwrap();
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
        let n = crate::folder::unseal_dir_only(&pack, &one, None, &[], &["sub/b.txt".into()], &[]).unwrap();
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
        assert_eq!(std::fs::read(mixed.join("sub/b.txt")).unwrap(), b"beta-file");
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
            std::fs::copy(a.join(format!("piece-{i:03}.sgp")), c.join(format!("piece-{i:03}.sgp"))).unwrap();
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
        assert_eq!(choose_kn(Mode::Seal, 64 * 1024 * 1024, DEFAULT_PIECE, None), (16, 32));
        assert_eq!(choose_kn(Mode::Seal, 64 * 1024 * 1024, DEFAULT_PIECE, Some(64)), (32, 64));
        assert_eq!(choose_kn(Mode::Reflection, 1_000, DEFAULT_PIECE, None), (12, 16));
        assert_eq!(choose_kn(Mode::Glyph, 99_000_000, DEFAULT_PIECE, None), (16, 16));
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
        inscribe_path(&src, &packed, Mode::Glyph, None, "", &[], DEFAULT_CHUNK, None, 0, 64, None).unwrap();
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
        let prefix = if h.keystone() { KEYSTONE_SPAN } else { HEADER_SIZE };
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
        let prefix = if h.keystone() { KEYSTONE_SPAN } else { HEADER_SIZE };
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
        let lead = if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { header::VOW_SIZE } else { 0 };
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

    #[test]
    fn mend_soft_true_name_rejects_garbage() {
        let msg = b"true-name must gate soft accept -- longer payload for shards";
        let bytes = seal(msg, Mode::Seal, None, "tn.txt", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let stride = header::shard_stride(&h);
        let prefix = header::body_prefix(&h);
        let lead = if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { header::VOW_SIZE } else { 0 };
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
        std::fs::File::create(&src).unwrap().write_all(&payload).unwrap();
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
        let prefix = if h.keystone() { KEYSTONE_SPAN } else { HEADER_SIZE };
        let mut torn = bytes.clone();
        for i in 0..8 {
            let off = prefix + i * stride;
            torn[off..off + stride].fill(0);
            torn[off] = 3;
        }
        assert!(unseal(&torn, None).is_err(), "Vandermonde must not decode Cauchy parity");
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
        std::fs::File::create(&src).unwrap().write_all(&payload).unwrap();
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
        std::fs::File::create(&src).unwrap().write_all(&payload).unwrap();
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
        assert_eq!(unseal_ex_keys(&bytes, Some("ward-pass"), &[], &[]).unwrap(), msg);
        assert!(unseal_ex_keys(&bytes, Some("wrong"), &[], &[]).is_err());
    }

    #[test]
    fn passphrase_only_still_works() {
        let msg = b"legacy ward";
        let bytes = seal(msg, Mode::Seal, Some("secret"), "t.txt", false).unwrap();
        assert!(!bytes.windows(4).any(|w| w == b"SGTO"));
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
        let n = crate::folder::unseal_dir_only_keys(
            &pack, &dest, None, &[], &[], &[], &[alice],
        )
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha-to");
        assert_eq!(std::fs::read(dest.join("sub/b.txt")).unwrap(), b"beta-to");
        assert!(crate::folder::unseal_dir_only_keys(
            &pack, &dir.join("bad"), None, &[], &[], &[], &[bob],
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
        let view = crate::path_walk_keys(&mark, &[], None, &[], 8, &[alice.clone()]).unwrap();
        assert!(view.nest_payload, "outer encrypt-to mark should advertise nested payload");
        // --into . unwraps outer → inner .sg1 bytes (still a seal); then identity-unseal leaf.
        let dest = dir.join("inner.sg1");
        crate::path_extract_keys(&mark, &[".".into()], &dest, None, &[], 8, &[alice.clone()]).unwrap();
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
