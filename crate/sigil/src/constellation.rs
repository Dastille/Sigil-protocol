//! Constellation: a named list of stars (SIGG), kept as loose .sg1 files.
//! The card is a Seal whose payload is the list. An atlas (.sga) is the bag.

use crate::keys::{Identity, PublicIdentity};
use crate::{hex32, locate_header, sha256_path, unseal_ex_keys, Mode, Result, DEFAULT_CHUNK};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

pub const GRAPH_MAGIC: [u8; 4] = *b"SIGG";
pub const ATLAS_MAGIC: [u8; 4] = *b"ATLS";

fn io(e: std::io::Error) -> crate::Error {
    crate::Error::Msg(e.to_string())
}

fn err(s: impl Into<String>) -> crate::Error {
    crate::Error::Msg(s.into())
}

#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    pub digest: [u8; 32],
    pub merkle: [u8; 32],
    pub orig_len: u64,
    pub mode: Mode,
    pub index: u16,
    pub total: u16,
    /// Embedded star bytes (lab packed charts). Empty when stars live as files.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Chart {
    pub title: String,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, Default)]
pub struct AddReport {
    pub added: u32,
    pub linked: u32,
    pub skipped: u32,
    pub replaced: u32,
    pub bytes_new: u64,
    /// The list as written (lets callers scry or bag it without reopening an encrypt-to card).
    pub chart: Option<Chart>,
}

#[derive(Clone)]
pub struct AddOpts<'a> {
    pub title: Option<&'a str>,
    pub mode: Mode,
    pub pass: Option<&'a str>,
    pub covenant: &'a str,
    pub geas: &'a [[u8; 32]],
    pub chunk: u32,
    pub as_name: Option<&'a str>,
    /// Encrypt-to recipients for new stars and the rewritten card (empty = passphrase / clear).
    pub recipients: &'a [PublicIdentity],
    /// Identities that open an encrypt-to card when adding to an existing constellation.
    pub identities: &'a [Identity],
}

impl<'a> Default for AddOpts<'a> {
    fn default() -> Self {
        Self {
            title: None,
            mode: Mode::Reflection,
            pass: None,
            covenant: "",
            geas: &[],
            chunk: DEFAULT_CHUNK,
            as_name: None,
            recipients: &[],
            identities: &[],
        }
    }
}

pub fn is_atlas_file(path: &Path) -> bool {
    let mut mag = [0u8; 4];
    match File::open(path).and_then(|mut f| f.read_exact(&mut mag)) {
        Ok(()) => mag == ATLAS_MAGIC,
        Err(_) => false,
    }
}

pub fn is_constellation_mark(path: &Path) -> bool {
    if crate::work::is_work_pack(path) || is_atlas_file(path) {
        return false;
    }
    peek_header(path).map(|(h, _)| h.graph()).unwrap_or(false)
}

pub fn is_constellation_dir(path: &Path) -> bool {
    path.is_dir() && find_card(path).is_some()
}

pub fn is_constellation_input(path: &Path) -> bool {
    let resolved = crate::container::sky_for_read(path);
    let path = resolved.as_path();
    is_constellation_dir(path) || is_atlas_file(path) || is_constellation_mark(path)
}

fn peek_header(path: &Path) -> Result<(crate::Header, Vec<u8>)> {
    let mut f = File::open(path).map_err(io)?;
    let mut buf = vec![0u8; 96 * 1024];
    let n = f.read(&mut buf).map_err(io)?;
    buf.truncate(n);
    let (h, _, _) = locate_header(&buf)?;
    Ok((h, buf))
}

pub(crate) fn peek_digest(path: &Path) -> Option<[u8; 32]> {
    if crate::work::is_work_pack(path) {
        return None;
    }
    peek_header(path).ok().map(|(h, _)| h.digest)
}

/// Keyless id of a new encrypted star, which shows no plaintext SHA-256: a v3 mark's
/// Merkle root (a fingerprint of its ciphertext parts), or for a large-file pack with a
/// hidden head the SHA-256 over its facet list. `None` for plain and older stars, which
/// are found by the plaintext digest on their label. Members record it in `merkle`.
pub(crate) fn private_star_id(path: &Path) -> Option<[u8; 32]> {
    if crate::work::is_work_pack(path) {
        let (head, _) = crate::work::index_pack(path).ok()?;
        if !crate::work::total_hidden(&head) {
            return None;
        }
        let facets = crate::work::read_facet_digests(path).ok()?;
        return Some(crate::sha256(&facets.concat()));
    }
    let (h, _) = peek_header(path).ok()?;
    h.private_label().then_some(h.merkle)
}

/// The star at `p` is the one `m` lists.
pub(crate) fn star_is_member(p: &Path, m: &Member) -> bool {
    match private_star_id(p) {
        Some(id) => id == m.merkle,
        None => crate::work::is_work_pack(p) || peek_digest(p) == Some(m.digest),
    }
}

/// Index key of a star file: its private id, else its plaintext digest.
pub(crate) fn star_key(p: &Path) -> Option<[u8; 32]> {
    private_star_id(p).or_else(|| peek_digest(p))
}

pub fn star_file_name(list_path: &str) -> String {
    let safe = list_path.replace('\\', "/");
    let safe = safe.trim_start_matches('/');
    let safe = safe.replace("..", "_");
    format!("{}.sg1", safe.replace('/', "__"))
}

pub(crate) fn default_title(dir: &Path) -> String {
    dir.components()
        .as_path()
        .file_name()
        .and_then(|s| s.to_str())
        .map(crate::container::strip_suffix)
        .filter(|s| !s.is_empty())
        .unwrap_or("constellation")
        .to_string()
}

fn card_name(title: &str) -> String {
    let t = title.trim();
    if t.is_empty() {
        "constellation.sg1".into()
    } else {
        format!("{t}.sg1")
    }
}

pub fn find_card(dir: &Path) -> Option<PathBuf> {
    let mut cards = Vec::new();
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("sg1") {
            continue;
        }
        if is_constellation_mark(&p) {
            cards.push(p);
        }
    }
    if cards.is_empty() {
        return None;
    }
    let want = dir.join(card_name(&default_title(dir)));
    if let Some(p) = cards.iter().find(|c| *c == &want) {
        return Some(p.clone());
    }
    cards.sort();
    Some(cards.remove(0))
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let rd = fs::read_dir(dir).map_err(io)?;
    let mut ents: Vec<_> = rd.collect::<std::io::Result<Vec<_>>>().map_err(io)?;
    ents.sort_by_key(|e| e.file_name());
    for e in ents {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if p.is_dir() {
            walk_files(&p, out)?;
        } else if p.is_file() {
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if ext == "sg1" || ext == "sga" {
                continue;
            }
            out.push(p);
        }
    }
    Ok(())
}

fn rel_name(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

fn safe_out_path(dest: &Path, rel: &str) -> Result<PathBuf> {
    if rel.contains("..") || Path::new(rel).is_absolute() {
        return Err(err("refusing unsafe path in constellation"));
    }
    Ok(dest.join(rel))
}

pub fn pack_chart(chart: &Chart) -> Result<Vec<u8>> {
    if chart.members.is_empty() {
        return Err(err("constellation is empty"));
    }
    if chart.members.len() > 65535 {
        return Err(err("constellation cap is 65535 stars"));
    }
    let title = chart.title.as_bytes();
    let tlen = title.len().min(255);
    let mut out = Vec::new();
    out.extend_from_slice(&GRAPH_MAGIC);
    out.push(2);
    out.push(0); // not embedded — stars stay as files
    out.extend_from_slice(&(chart.members.len() as u16).to_le_bytes());
    out.push(tlen as u8);
    out.extend_from_slice(&title[..tlen]);
    out.push(0); // work file name empty
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for m in &chart.members {
        let name = m.name.as_bytes();
        let nlen = name.len().min(255);
        let has = !m.bytes.is_empty();
        let mut flags = 0u8;
        if has {
            flags |= 1;
        }
        if m.total > 1 {
            flags |= 2;
        }
        out.push(flags);
        out.push(nlen as u8);
        out.extend_from_slice(&name[..nlen]);
        out.extend_from_slice(&m.digest);
        out.extend_from_slice(&m.merkle);
        let orig = m.orig_len.min(u32::MAX as u64) as u32;
        let sealed = if has {
            (m.bytes.len() as u64).min(u32::MAX as u64) as u32
        } else {
            0
        };
        out.extend_from_slice(&orig.to_le_bytes());
        out.extend_from_slice(&sealed.to_le_bytes());
        out.push(match m.mode {
            Mode::Glyph => 0,
            Mode::Reflection => 1,
            Mode::Seal => 2,
        });
        out.extend_from_slice(&m.index.to_le_bytes());
        out.extend_from_slice(&m.total.to_le_bytes());
        if has {
            out.extend_from_slice(&m.bytes);
        }
    }
    Ok(out)
}

pub fn unpack_chart(data: &[u8]) -> Result<Chart> {
    if data.len() < 8 || data[0..4] != GRAPH_MAGIC {
        return Err(err("not a constellation (missing SIGG)"));
    }
    let version = data[4];
    if version == 1 {
        return unpack_v1(data);
    }
    if version != 2 {
        return Err(err(format!("unknown constellation version {version}")));
    }
    let count = u16::from_le_bytes(data[6..8].try_into().map_err(crate::short_field)?) as usize;
    let mut o = 8;
    let tlen = *data.get(o).ok_or_else(|| err("truncated constellation"))? as usize;
    o += 1;
    if o + tlen > data.len() {
        return Err(err("truncated constellation title"));
    }
    let title = String::from_utf8_lossy(&data[o..o + tlen]).into_owned();
    o += tlen;
    let fnlen = *data.get(o).ok_or_else(|| err("truncated constellation"))? as usize;
    o += 1 + fnlen;
    if o + 12 > data.len() {
        return Err(err("truncated constellation"));
    }
    o += 12; // work totalOrig + chunkSize
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        if o + 2 > data.len() {
            return Err(err("truncated constellation member"));
        }
        let flags = data[o];
        o += 1;
        let nlen = data[o] as usize;
        o += 1;
        if o + nlen + 32 + 32 + 4 + 4 + 1 + 2 + 2 > data.len() {
            return Err(err("truncated constellation member"));
        }
        let name = String::from_utf8_lossy(&data[o..o + nlen]).into_owned();
        o += nlen;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[o..o + 32]);
        o += 32;
        let mut merkle = [0u8; 32];
        merkle.copy_from_slice(&data[o..o + 32]);
        o += 32;
        let orig_len =
            u32::from_le_bytes(data[o..o + 4].try_into().map_err(crate::short_field)?) as u64;
        o += 4;
        let sealed =
            u32::from_le_bytes(data[o..o + 4].try_into().map_err(crate::short_field)?) as usize;
        o += 4;
        let mode = match data[o] {
            2 => Mode::Seal,
            1 => Mode::Reflection,
            _ => Mode::Glyph,
        };
        o += 1;
        let index = u16::from_le_bytes(data[o..o + 2].try_into().map_err(crate::short_field)?);
        o += 2;
        let total = u16::from_le_bytes(data[o..o + 2].try_into().map_err(crate::short_field)?);
        o += 2;
        let has = flags & 1 != 0;
        let bytes = if has {
            if o + sealed > data.len() {
                return Err(err("truncated embedded star"));
            }
            let b = data[o..o + sealed].to_vec();
            o += sealed;
            b
        } else {
            Vec::new()
        };
        members.push(Member {
            name,
            digest,
            merkle,
            orig_len,
            mode,
            index,
            total: total.max(1),
            bytes,
        });
    }
    Ok(Chart {
        title: if title.is_empty() {
            "constellation".into()
        } else {
            title
        },
        members,
    })
}

fn unpack_v1(data: &[u8]) -> Result<Chart> {
    let count = data[5] as usize;
    let mut o = 8;
    let mut members = Vec::with_capacity(count);
    for i in 0..count {
        if o + 4 > data.len() {
            return Err(err("truncated v1 constellation"));
        }
        let byte_len =
            u32::from_le_bytes(data[o..o + 4].try_into().map_err(crate::short_field)?) as usize;
        o += 4;
        let nlen = *data
            .get(o)
            .ok_or_else(|| err("truncated v1 constellation"))? as usize;
        o += 1;
        if o + nlen + 32 + 32 + 4 + 8 + 1 + byte_len > data.len() {
            return Err(err("truncated v1 constellation"));
        }
        let name = String::from_utf8_lossy(&data[o..o + nlen]).into_owned();
        o += nlen;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[o..o + 32]);
        o += 32;
        let mut merkle = [0u8; 32];
        merkle.copy_from_slice(&data[o..o + 32]);
        o += 32;
        let orig_len =
            u32::from_le_bytes(data[o..o + 4].try_into().map_err(crate::short_field)?) as u64;
        o += 8;
        let mode = match data[o] {
            2 => Mode::Seal,
            1 => Mode::Reflection,
            _ => Mode::Glyph,
        };
        o += 1;
        let bytes = data[o..o + byte_len].to_vec();
        o += byte_len;
        members.push(Member {
            name,
            digest,
            merkle,
            orig_len,
            mode,
            index: i as u16,
            total: count as u16,
            bytes,
        });
    }
    Ok(Chart {
        title: "constellation".into(),
        members,
    })
}

fn write_card(
    dir: &Path,
    chart: &Chart,
    pass: Option<&str>,
    recipients: &[PublicIdentity],
) -> Result<PathBuf> {
    let packed = pack_chart(chart)?;
    let name = card_name(&chart.title);
    let dest = dir.join(&name);
    let sg1 = crate::seal_kn_to(
        &packed,
        Mode::Seal,
        pass,
        &name,
        true,
        "",
        &[],
        None,
        crate::DEFAULT_PIECE,
        recipients,
    )?;
    // Write beside, then rename: a crash mid-write must not eat the only list.
    let part = dir.join(format!("{name}.part"));
    fs::write(&part, sg1).map_err(io)?;
    fs::rename(&part, &dest).map_err(|e| {
        let _ = fs::remove_file(&part);
        io(e)
    })?;
    Ok(dest)
}

/// True when the card mark is sealed to at least one recipient (SGTO with an X25519 wrap).
fn card_is_encrypt_to(path: &Path) -> bool {
    fs::read(path)
        .ok()
        .and_then(|data| {
            let (h, _, _) = locate_header(&data).ok()?;
            Some(crate::header::sgto_slice(&h, &data).is_some_and(crate::keys::sgto_has_recipients))
        })
        .unwrap_or(false)
}

fn unseal_card(data: &[u8], pass: Option<&str>, identities: &[Identity]) -> Result<Vec<u8>> {
    unseal_ex_keys(data, pass, &[], identities).map_err(|e| {
        let (h, _, _) = match locate_header(data) {
            Ok(x) => x,
            Err(_) => return e,
        };
        let said = e.to_string();
        if said.contains("--identity") {
            e
        } else if identities.is_empty()
            && crate::header::sgto_slice(&h, data).is_some_and(crate::keys::sgto_has_recipients)
        {
            err(format!(
                "{e} (this constellation's card is encrypt-to; pass --identity <key.sgk>)"
            ))
        } else {
            e
        }
    })
}

pub(crate) fn load_chart_from_mark(
    path: &Path,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<Chart> {
    let data = fs::read(path).map_err(io)?;
    let plain = unseal_card(&data, pass, identities)?;
    unpack_chart(&plain)
}

/// Read a constellation's list (folder, card, or atlas), trying `pass` and
/// `identities` on a locked card.
pub fn load_chart_keys(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<(Chart, PathBuf)> {
    let resolved = crate::container::sky_for_read(input);
    let input = resolved.as_path();
    if input.is_dir() {
        let card = find_card(input).ok_or_else(|| err("no constellation card in this folder"))?;
        let chart = load_chart_from_mark(&card, pass, identities)?;
        return Ok((chart, input.to_path_buf()));
    }
    if is_atlas_file(input) {
        let parent = input.parent().unwrap_or(Path::new(".")).to_path_buf();
        let chart = load_chart_from_atlas(input, pass, identities)?;
        return Ok((chart, parent));
    }
    if is_constellation_mark(input) {
        let chart = load_chart_from_mark(input, pass, identities)?;
        let parent = input.parent().unwrap_or(Path::new(".")).to_path_buf();
        return Ok((chart, parent));
    }
    Err(err(
        "not a constellation (folder, card .sg1, or atlas .sga)",
    ))
}

pub(crate) fn index_stars(dir: &Path, card: Option<&Path>) -> HashMap<[u8; 32], PathBuf> {
    let mut map = HashMap::new();
    // Container layout: `stars/ab/<fp>.sg1` (and `stars/by-name/*`). File name is a hint only;
    // the digest is read from each star's header like the flat layout.
    let stars = dir.join(crate::container::STARS_DIR);
    if stars.is_dir() {
        let mut shards: Vec<_> = fs::read_dir(&stars)
            .map(|r| r.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        shards.sort();
        for shard in shards.into_iter().filter(|p| p.is_dir()) {
            let mut files: Vec<_> = fs::read_dir(&shard)
                .map(|r| r.flatten().map(|e| e.path()).collect())
                .unwrap_or_default();
            files.sort();
            for p in files {
                if p.extension().and_then(|x| x.to_str()) != Some("sg1") || !p.is_file() {
                    continue;
                }
                if let Some(d) = star_key(&p) {
                    map.entry(d).or_insert(p);
                }
            }
        }
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return map,
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("sg1") {
            continue;
        }
        if let Some(c) = card {
            if p == *c {
                continue;
            }
        }
        if is_constellation_mark(&p) {
            continue;
        }
        if let Some(d) = star_key(&p) {
            map.entry(d).or_insert(p);
        }
    }
    map
}

fn member_from_star(path: &Path, list_name: &str, digest: [u8; 32]) -> Result<Member> {
    if crate::work::is_work_pack(path) {
        let meta = fs::metadata(path).map_err(io)?;
        return Ok(Member {
            name: list_name.to_string(),
            digest,
            merkle: private_star_id(path).unwrap_or([0u8; 32]),
            orig_len: meta.len(),
            mode: Mode::Reflection,
            index: 0,
            total: 1,
            bytes: Vec::new(),
        });
    }
    let (h, _) = peek_header(path)?;
    Ok(Member {
        name: list_name.to_string(),
        digest,
        merkle: h.merkle,
        orig_len: h.orig_len,
        mode: h.mode(),
        index: 0,
        total: 1,
        bytes: Vec::new(),
    })
}

pub(crate) fn find_member_star(
    dir: &Path,
    member: &Member,
    by_digest: &HashMap<[u8; 32], PathBuf>,
) -> Option<PathBuf> {
    if !member.bytes.is_empty() {
        return None;
    }
    if let Some(p) = by_digest.get(&member.digest) {
        return Some(p.clone());
    }
    // New encrypted stars are indexed and named by their keyless private id.
    if member.merkle != [0u8; 32] {
        if let Some(p) = by_digest.get(&member.merkle) {
            return Some(p.clone());
        }
        let sharded = crate::container::star_path(dir, &member.merkle);
        if sharded.is_file() && star_is_member(&sharded, member) {
            return Some(sharded);
        }
    }
    let sharded = crate::container::star_path(dir, &member.digest);
    if sharded.is_file() {
        return Some(sharded);
    }
    let named = dir.join(star_file_name(&member.name));
    if named.is_file() {
        return Some(named);
    }
    let fp_named = dir.join(format!("{}.sg1", &hex32(&member.digest)[..12]));
    if fp_named.is_file() && !is_constellation_mark(&fp_named) {
        return Some(fp_named);
    }
    let by_name = dir
        .join(crate::container::STARS_DIR)
        .join(crate::container::BY_NAME_DIR)
        .join(star_file_name(&member.name));
    if by_name.is_file() {
        return Some(by_name);
    }
    None
}

/// Star file that holds list entry `name` of the constellation at `sky` (opens the card,
/// so a locked card needs its key). New encrypted stars are filed under a keyless
/// private id rather than the plaintext SHA-256 or the list name.
pub fn member_star_path(
    sky: &Path,
    name: &str,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<PathBuf> {
    let sky = crate::container::sky_for_read(sky);
    let card = find_card(&sky).ok_or_else(|| err("no constellation card"))?;
    let chart = load_chart_from_mark(&card, pass, identities)?;
    let m = chart
        .members
        .iter()
        .find(|m| m.name == name)
        .ok_or_else(|| err(format!("no list entry {name}")))?;
    find_member_star(&sky, m, &index_stars(&sky, Some(&card)))
        .ok_or_else(|| err(format!("star for {name} is missing")))
}

fn missing_stars(dir: &Path, chart: &Chart, card: Option<&Path>) -> Vec<String> {
    let by_digest = index_stars(dir, card);
    let mut missing = Vec::new();
    for m in &chart.members {
        if !m.bytes.is_empty() {
            continue;
        }
        if find_member_star(dir, m, &by_digest).is_none() {
            missing.push(format!("{} ({})", m.name, hex32(&m.digest)));
        }
    }
    missing
}

/// Stars listed on the card but not found in `dir` (for `sigil tidy` verification).
pub fn missing_in(dir: &Path, pass: Option<&str>, identities: &[Identity]) -> Result<Vec<String>> {
    let card = find_card(dir).ok_or_else(|| err("no constellation card in this folder"))?;
    let chart = load_chart_from_mark(&card, pass, identities)?;
    Ok(missing_stars(dir, &chart, Some(&card)))
}

fn refuse_missing(missing: &[String]) -> Result<()> {
    if missing.is_empty() {
        return Ok(());
    }
    let list = missing.join(", ");
    Err(err(format!(
        "constellation is missing a star: {list}. Put the star next to the card, or De-scribe the atlas."
    )))
}

pub fn add_to_constellation(sky: &Path, input: &Path, opts: AddOpts<'_>) -> Result<AddReport> {
    if !input.exists() {
        return Err(err(format!("not found: {}", input.display())));
    }
    // New constellations get the tidy container (`SKY.sigil/`); old flat folders stay flat.
    let sky_owned = crate::container::sky_for_add(sky);
    let sky = sky_owned.as_path();
    if crate::container::new_sky_is_container(sky) {
        crate::container::ensure(sky, "constellation", &default_title(sky))?;
    } else {
        fs::create_dir_all(sky).map_err(io)?;
    }
    let title = opts
        .title
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            find_card(sky).and_then(|c| {
                load_chart_from_mark(&c, opts.pass, opts.identities)
                    .ok()
                    .map(|ch| ch.title)
            })
        })
        .unwrap_or_else(|| default_title(sky));

    let mut chart = if let Some(card) = find_card(sky) {
        if opts.recipients.is_empty() && card_is_encrypt_to(&card) {
            // Rewriting the card without --to would drop it to passphrase / clear.
            return Err(err(
                "this constellation's card is encrypt-to; pass the same --to recipients (and --identity to open the card) when adding",
            ));
        }
        load_chart_from_mark(&card, opts.pass, opts.identities)?
    } else {
        Chart {
            title: title.clone(),
            members: Vec::new(),
        }
    };
    if opts.title.is_some() {
        chart.title = title.clone();
    }

    let mut files = Vec::new();
    let names_root: PathBuf;
    if input.is_dir() {
        walk_files(input, &mut files)?;
        names_root = input.to_path_buf();
        if files.is_empty() {
            return Err(err("folder is empty"));
        }
    } else {
        files.push(input.to_path_buf());
        names_root = input.parent().unwrap_or(Path::new(".")).to_path_buf();
    }

    let mut report = AddReport::default();
    let card_now = find_card(sky);
    let mut by_digest = index_stars(sky, card_now.as_deref());

    for file in &files {
        let list_name = if files.len() == 1 {
            opts.as_name
                .map(|s| s.replace('\\', "/"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    file.file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("file")
                        .to_string()
                })
        } else {
            rel_name(&names_root, file)
        };
        if list_name.contains("..") {
            return Err(err("refusing unsafe path"));
        }
        let digest = sha256_path(file)?;
        let existing_idx = chart.members.iter().position(|m| m.name == list_name);
        let same_digest_idx = chart.members.iter().position(|m| m.digest == digest);

        if let Some(i) = existing_idx {
            if chart.members[i].digest == digest {
                // List already has this path and these bytes. Still remint if the star file was lost.
                let _ = mint_or_reuse(sky, file, &list_name, digest, &mut by_digest, &opts)?;
                report.skipped += 1;
                continue;
            }
            // Path stays, bytes changed: new star, update the list.
            let already = by_digest.contains_key(&digest);
            let star_path = mint_or_reuse(sky, file, &list_name, digest, &mut by_digest, &opts)?;
            let member = member_from_star(&star_path, &list_name, digest)?;
            let size = fs::metadata(file).map(|m| m.len()).unwrap_or(0);
            chart.members[i] = member;
            by_digest.entry(digest).or_insert(star_path);
            report.replaced += 1;
            if !already {
                report.bytes_new += size;
            }
            continue;
        }

        if let Some(i) = same_digest_idx {
            let mut linked = chart.members[i].clone();
            linked.name = list_name;
            linked.bytes.clear();
            chart.members.push(linked);
            report.linked += 1;
            continue;
        }

        let size = fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        let already = by_digest.contains_key(&digest);
        let star_path = mint_or_reuse(sky, file, &list_name, digest, &mut by_digest, &opts)?;
        let member = member_from_star(&star_path, &list_name, digest)?;
        by_digest.entry(digest).or_insert(star_path);
        chart.members.push(member);
        report.added += 1;
        if !already {
            report.bytes_new += size;
        }
    }

    if chart.members.is_empty() {
        return Err(err("constellation is empty"));
    }
    if report.added + report.linked + report.replaced > 0 || find_card(sky).is_none() {
        write_card(sky, &chart, opts.pass, opts.recipients)?;
    }
    report.chart = Some(chart);
    Ok(report)
}

/// Options for [`remove_members`].
#[derive(Clone, Default)]
pub struct RemoveOpts<'a> {
    pub pass: Option<&'a str>,
    /// Encrypt-to recipients the rewritten card must keep (same set as on `add`).
    pub recipients: &'a [PublicIdentity],
    /// Identities that open an encrypt-to card.
    pub identities: &'a [Identity],
    /// Leave star files on disk even when nothing on the list needs them any more.
    pub keep_stars: bool,
    /// Report what would happen; change nothing.
    pub dry_run: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RemoveReport {
    /// List names taken off the card.
    pub removed: Vec<String>,
    /// Star files deleted because no remaining name needs them (would-be when dry run).
    pub stars_freed: Vec<PathBuf>,
    /// Remaining list size.
    pub remaining: usize,
    pub dry_run: bool,
}

/// Take names off a constellation's list (and free stars nothing else needs).
///
/// A name ending in `/` removes everything under that folder. The card is rewritten
/// atomically *first*; star files go afterwards, so a crash leaves at worst an orphan
/// star that `sigil gc` reclaims — never a list entry without its star. A star shared
/// by another name (same bytes) is kept. Removing the last name is refused.
pub fn remove_members(sky: &Path, names: &[String], opts: RemoveOpts<'_>) -> Result<RemoveReport> {
    let sky_owned = crate::container::sky_for_read(sky);
    let sky = sky_owned.as_path();
    let card = find_card(sky).ok_or_else(|| err("not a constellation folder (no card)"))?;
    if names.is_empty() {
        return Err(err("give at least one name to remove"));
    }
    if opts.recipients.is_empty() && card_is_encrypt_to(&card) {
        return Err(err(
            "this constellation's card is encrypt-to; pass the same --to recipients (and --identity to open the card) when removing",
        ));
    }
    let mut chart = load_chart_from_mark(&card, opts.pass, opts.identities)?;
    let mut drop_idx = std::collections::BTreeSet::new();
    for want in names {
        let want = want.replace('\\', "/");
        let hits: Vec<usize> = chart
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                if want.ends_with('/') {
                    m.name.starts_with(&want)
                } else {
                    m.name == want
                }
            })
            .map(|(i, _)| i)
            .collect();
        if hits.is_empty() {
            return Err(err(format!("not on the list: {want}")));
        }
        drop_idx.extend(hits);
    }
    if drop_idx.len() >= chart.members.len() {
        return Err(err(
            "that would empty the list; delete the whole constellation folder instead",
        ));
    }
    let dropped: Vec<Member> = drop_idx.iter().map(|&i| chart.members[i].clone()).collect();
    let remaining: Vec<Member> = chart
        .members
        .iter()
        .enumerate()
        .filter(|(i, _)| !drop_idx.contains(i))
        .map(|(_, m)| m.clone())
        .collect();
    let by_digest = index_stars(sky, Some(&card));
    let mut freed = Vec::new();
    for m in &dropped {
        if remaining.iter().any(|r| r.digest == m.digest) {
            continue;
        }
        if let Some(p) = find_member_star(sky, m, &by_digest) {
            let ok = star_is_member(&p, m);
            if ok && !is_constellation_mark(&p) && !freed.contains(&p) {
                freed.push(p);
            }
        }
    }
    let report = RemoveReport {
        removed: dropped.iter().map(|m| m.name.clone()).collect(),
        stars_freed: if opts.keep_stars {
            Vec::new()
        } else {
            freed.clone()
        },
        remaining: remaining.len(),
        dry_run: opts.dry_run,
    };
    if opts.dry_run {
        return Ok(report);
    }
    chart.members = remaining;
    write_card(sky, &chart, opts.pass, opts.recipients)?;
    if !opts.keep_stars {
        for p in &freed {
            let _ = fs::remove_file(p);
            if let Some(parent) = p.parent() {
                // Drop an emptied shard folder (`stars/ab/`), never the container itself.
                if parent.file_name().map(|n| n.len() == 2).unwrap_or(false)
                    && parent
                        .parent()
                        .map(|g| g.ends_with(crate::container::STARS_DIR))
                        .unwrap_or(false)
                {
                    let _ = fs::remove_dir(parent);
                }
            }
        }
    }
    Ok(report)
}

fn mint_or_reuse(
    sky: &Path,
    file: &Path,
    list_name: &str,
    digest: [u8; 32],
    by_digest: &mut HashMap<[u8; 32], PathBuf>,
    opts: &AddOpts<'_>,
) -> Result<PathBuf> {
    if let Some(p) = by_digest.get(&digest) {
        return Ok(p.clone());
    }
    let encrypted = opts.pass.is_some_and(|p| !p.is_empty()) || !opts.recipients.is_empty();
    if encrypted {
        // The file name must not carry the plaintext SHA-256 or the list name: seal
        // beside, then name the star by its keyless private id.
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).map_err(|e| err(e.to_string()))?;
        let tmp = sky.join(format!(".mint-{}.part", hex::encode(nonce)));
        let sealed = crate::work::inscribe_path_to(
            file,
            &tmp,
            opts.mode,
            opts.pass,
            opts.covenant,
            opts.geas,
            opts.chunk,
            None,
            crate::DEFAULT_PIECE,
            crate::work::DEFAULT_OVERTURE_MB,
            None,
            opts.recipients,
        )
        .and_then(|_| {
            private_star_id(&tmp).ok_or_else(|| err("new encrypted star has no private id"))
        });
        let id = match sealed {
            Ok(id) => id,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        let dest = if crate::container::is_container(sky) {
            crate::container::star_path(sky, &id)
        } else {
            sky.join(format!("{}.sg1", &hex32(&id)[..12]))
        };
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(io)?;
        }
        fs::rename(&tmp, &dest).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            io(e)
        })?;
        return Ok(dest);
    }
    if crate::container::is_container(sky) {
        let dest = crate::container::star_path(sky, &digest);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(io)?;
        }
        if !dest.exists() || peek_digest(&dest) != Some(digest) && !crate::work::is_work_pack(&dest)
        {
            crate::work::inscribe_path_to(
                file,
                &dest,
                opts.mode,
                opts.pass,
                opts.covenant,
                opts.geas,
                opts.chunk,
                None,
                crate::DEFAULT_PIECE,
                crate::work::DEFAULT_OVERTURE_MB,
                None,
                opts.recipients,
            )?;
        }
        return Ok(dest);
    }
    let mut dest = sky.join(star_file_name(list_name));
    if dest.file_name() == Some(std::ffi::OsStr::new(&card_name(&default_title(sky))))
        || is_constellation_mark(&dest)
    {
        dest = sky.join(format!("{}.sg1", &hex32(&digest)[..12]));
    }
    if dest.exists() && peek_digest(&dest) != Some(digest) {
        dest = sky.join(format!("{}.sg1", &hex32(&digest)[..12]));
    }
    if !dest.exists() || peek_digest(&dest) != Some(digest) {
        crate::work::inscribe_path_to(
            file,
            &dest,
            opts.mode,
            opts.pass,
            opts.covenant,
            opts.geas,
            opts.chunk,
            None,
            crate::DEFAULT_PIECE,
            crate::work::DEFAULT_OVERTURE_MB,
            None,
            opts.recipients,
        )?;
    }
    Ok(dest)
}

pub fn scry_constellation(input: &Path, pass: Option<&str>) -> Result<String> {
    scry_constellation_keys(input, pass, &[])
}

/// Like [`scry_constellation`], also trying `identities` on an encrypt-to card.
pub fn scry_constellation_keys(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<String> {
    let resolved = crate::container::sky_for_read(input);
    let input = resolved.as_path();
    let (chart, dir) = load_chart_keys(input, pass, identities)?;
    let card = if input.is_dir() {
        find_card(input)
    } else if is_constellation_mark(input) {
        Some(input.to_path_buf())
    } else {
        find_card(&dir)
    };
    Ok(render_scry(
        &chart,
        &dir,
        card.as_deref(),
        is_atlas_file(input),
    ))
}

/// [`scry_constellation_keys`] plus a recoverability verdict, like
/// [`crate::work::scry_path_checked`] for one file. The verdict is `Some(reason)`
/// when at least one listed member cannot be restored from this copy: its star is
/// missing (or too damaged to be recognised), or the star is present but beyond
/// repair. The report then ends with a `NOT recoverable: <reason>` line. Stars
/// that are damaged but still repairable do not count (`sigil doctor` lists them).
/// Atlas bags are not checked star by star here; use `sigil doctor` on the bag's sky.
pub fn scry_constellation_checked(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<(String, Option<String>)> {
    let resolved = crate::container::sky_for_read(input);
    let input = resolved.as_path();
    let (chart, dir) = load_chart_keys(input, pass, identities)?;
    let card = if input.is_dir() {
        find_card(input)
    } else if is_constellation_mark(input) {
        Some(input.to_path_buf())
    } else {
        find_card(&dir)
    };
    let in_atlas = is_atlas_file(input);
    let text = render_scry(&chart, &dir, card.as_deref(), in_atlas);
    let verdict = if in_atlas {
        None
    } else {
        constellation_verdict(&chart, &dir, card.as_deref())
    };
    Ok(match verdict {
        None => (text, None),
        Some(why) => (format!("{text}\nNOT recoverable: {why}"), Some(why)),
    })
}

/// Why a constellation in `dir` cannot be fully restored, or `None` if every
/// member is packed in the card or has a star that is healthy or repairable.
fn constellation_verdict(chart: &Chart, dir: &Path, card: Option<&Path>) -> Option<String> {
    let by_digest = index_stars(dir, card);
    let mut missing: Vec<&str> = Vec::new();
    let mut broken: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for m in chart.members.iter().filter(|m| m.bytes.is_empty()) {
        match find_member_star(dir, m, &by_digest) {
            None => missing.push(&m.name),
            Some(p) => {
                if !seen.insert(p.clone()) {
                    continue;
                }
                if let Some(why) = crate::doctor::star_unrecoverable(&p) {
                    broken.push(format!("{}: {why}", m.name));
                }
            }
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if !missing.is_empty() {
        parts.push(format!(
            "{} star(s) missing: {}",
            missing.len(),
            missing.join(", ")
        ));
    }
    if !broken.is_empty() {
        parts.push(format!(
            "{} star(s) beyond repair: {}",
            broken.len(),
            broken.join("; ")
        ));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// Scry text for a list already in hand (e.g. the one `add` just wrote).
pub fn scry_chart(sky: &Path, chart: &Chart) -> String {
    let card = find_card(sky);
    render_scry(chart, sky, card.as_deref(), false)
}

fn render_scry(chart: &Chart, dir: &Path, card: Option<&Path>, in_atlas: bool) -> String {
    let missing = if in_atlas {
        Vec::new()
    } else {
        missing_stars(dir, chart, card)
    };
    let by_digest = index_stars(dir, card);
    let mut out = format!(
        "constellation  title={}  stars={}  unique={}\n",
        chart.title,
        chart.members.len(),
        unique_digests(chart)
    );
    for m in &chart.members {
        let where_ = if !m.bytes.is_empty() {
            "packed"
        } else if in_atlas {
            "atlas"
        } else if find_member_star(dir, m, &by_digest).is_some() {
            "star"
        } else {
            "MISSING"
        };
        out.push_str(&format!(
            "star  {where_}  {}  {} bytes  {}\n",
            m.name,
            m.orig_len,
            hex32(&m.digest)
        ));
    }
    if !missing.is_empty() {
        out.push_str("missing  ");
        out.push_str(&missing.join(", "));
        out.push('\n');
    }
    out.trim_end().to_string()
}

fn unique_digests(chart: &Chart) -> usize {
    let mut v: Vec<_> = chart.members.iter().map(|m| m.digest).collect();
    v.sort_unstable();
    v.dedup();
    v.len()
}

pub fn unseal_constellation(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
) -> Result<u32> {
    unseal_constellation_keys(input, dest, pass, companions, only, &[])
}

/// De-scribe a constellation (folder, card, or atlas), unwrapping encrypt-to
/// card and stars with `identities` (passphrase still works where it was set).
pub fn unseal_constellation_keys(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    identities: &[Identity],
) -> Result<u32> {
    let resolved = crate::container::sky_for_read(input);
    let input = resolved.as_path();
    if is_atlas_file(input) {
        return unseal_atlas(input, dest, pass, companions, only, identities);
    }
    let (chart, dir) = load_chart_keys(input, pass, identities)?;
    let card = if input.is_dir() {
        find_card(input)
    } else if is_constellation_mark(input) {
        Some(input.to_path_buf())
    } else {
        find_card(&dir)
    };
    let missing = missing_stars(&dir, &chart, card.as_deref());
    refuse_missing(&missing)?;
    restore_chart(
        &chart,
        dest,
        pass,
        companions,
        only,
        Some(&dir),
        card.as_deref(),
        identities,
    )
}

fn wanted(rel: &str, only: &[String]) -> bool {
    if only.is_empty() {
        return true;
    }
    only.iter().any(|p| {
        let p = p.trim().trim_start_matches("./");
        rel == p
            || rel.starts_with(&(p.to_string() + "/"))
            || (p.ends_with('/') && rel.starts_with(p))
    })
}

// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
fn restore_chart(
    chart: &Chart,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    dir: Option<&Path>,
    card: Option<&Path>,
    identities: &[Identity],
) -> Result<u32> {
    // All-or-nothing: members land as part files and are renamed into place
    // only after every wanted member has unsealed and verified.
    let mut staged = crate::staging::Staging::new();
    staged.make_dir(dest)?;
    let by_digest = dir.map(|d| index_stars(d, card)).unwrap_or_default();
    let mut got = 0u32;
    for m in &chart.members {
        if !wanted(&m.name, only) {
            continue;
        }
        let out_path = safe_out_path(dest, &m.name)?;
        if !m.bytes.is_empty() {
            if m.bytes.starts_with(&crate::work::WORK_MAGIC) {
                staged.write_with(&out_path, |w| {
                    crate::work::unseal_bytes_into(&m.bytes, w, pass, companions, identities)
                })?;
            } else {
                let plain = unseal_ex_keys(&m.bytes, pass, companions, identities)?;
                staged.write(&out_path, &plain)?;
            }
        } else {
            let dir = dir.ok_or_else(|| err("constellation is missing a star"))?;
            let star = find_member_star(dir, m, &by_digest)
                .ok_or_else(|| err(format!("constellation is missing a star: {}", m.name)))?;
            staged.write_with(&out_path, |w| {
                crate::work::unseal_path_into(&star, w, pass, companions, identities)
            })?;
        }
        got += 1;
    }
    if !only.is_empty() && got == 0 {
        return Err(err(
            "nothing matched --only (Scry the constellation to see paths)",
        ));
    }
    staged.commit()?;
    Ok(got)
}

pub fn pack_atlas(sky: &Path, output: &Path) -> Result<u32> {
    pack_atlas_keys(sky, output, None, &[])
}

/// Bag a constellation into one `.sga`. The card is read (with `pass` or
/// `identities` when it is locked) only to find every star; bytes are copied
/// as-is, so encrypt-to stars stay encrypt-to inside the bag.
pub fn pack_atlas_keys(
    sky: &Path,
    output: &Path,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<u32> {
    let (chart, dir) = load_chart_keys(sky, pass, identities)?;
    pack_atlas_chart(&dir, &chart, output)
}

/// Bag `sky` using a list already in hand (no card unlock needed), e.g. right
/// after `add --to` when the sender does not hold a recipient key.
pub fn pack_atlas_chart(sky: &Path, chart: &Chart, output: &Path) -> Result<u32> {
    let dir = sky.to_path_buf();
    let card = find_card(&dir).ok_or_else(|| err("no constellation card in this folder"))?;
    let missing = missing_stars(&dir, chart, Some(&card));
    refuse_missing(&missing)?;
    let mut files: Vec<(String, PathBuf)> = vec![(card_name(&chart.title), card.clone())];
    let by_digest = index_stars(&dir, Some(&card));
    let mut seen = HashMap::new();
    for m in &chart.members {
        if let Some(p) = find_member_star(&dir, m, &by_digest) {
            let mut name = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("star.sg1")
                .to_string();
            // Container stars travel under their old flat name so any sigil (old or new)
            // finds them in the bag, work packs included.
            if private_star_id(&p).is_some() {
                // An encrypted star never travels under its list name.
                name = format!("{}.sg1", &hex32(&m.merkle)[..12]);
            } else if p.starts_with(dir.join(crate::container::STARS_DIR)) {
                name = star_file_name(&m.name);
                if name == card_name(&chart.title) {
                    name = format!("{}.sg1", &hex32(&m.digest)[..12]);
                }
            }
            if seen.insert(m.digest, ()).is_none() {
                files.push((name, p));
            }
        }
    }
    let mut writer = BufWriter::new(File::create(output).map_err(io)?);
    writer.write_all(&ATLAS_MAGIC).map_err(io)?;
    writer.write_all(&[2u8]).map_err(io)?;
    writer
        .write_all(&(files.len() as u32).to_le_bytes())
        .map_err(io)?;
    for (name, path) in &files {
        let nb = name.as_bytes();
        let nlen = nb.len().min(255) as u8;
        writer.write_all(&[nlen]).map_err(io)?;
        writer.write_all(&nb[..nlen as usize]).map_err(io)?;
        let size = fs::metadata(path).map_err(io)?.len();
        writer.write_all(&size.to_le_bytes()).map_err(io)?;
        let mut f = File::open(path).map_err(io)?;
        std::io::copy(&mut f, &mut writer).map_err(io)?;
    }
    writer.flush().map_err(io)?;
    Ok(files.len() as u32)
}

fn load_chart_from_atlas(
    path: &Path,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<Chart> {
    let mut last_err: Option<crate::Error> = None;
    let mut reader = BufReader::new(File::open(path).map_err(io)?);
    let mut mag = [0u8; 4];
    reader.read_exact(&mut mag).map_err(io)?;
    if mag != ATLAS_MAGIC {
        return Err(err("not an atlas"));
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver).map_err(io)?;
    let (count, v2) = match ver[0] {
        1 => {
            let mut b = [0u8; 2];
            reader.read_exact(&mut b).map_err(io)?;
            (u16::from_le_bytes(b) as u32, false)
        }
        2 => {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b).map_err(io)?;
            (u32::from_le_bytes(b), true)
        }
        v => return Err(err(format!("unknown atlas version {v}"))),
    };
    for _ in 0..count {
        let mut nlen = [0u8; 1];
        reader.read_exact(&mut nlen).map_err(io)?;
        let mut nameb = vec![0u8; nlen[0] as usize];
        if !nameb.is_empty() {
            reader.read_exact(&mut nameb).map_err(io)?;
        }
        let size = if v2 {
            let mut b = [0u8; 8];
            reader.read_exact(&mut b).map_err(io)?;
            u64::from_le_bytes(b)
        } else {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b).map_err(io)?;
            u32::from_le_bytes(b) as u64
        };
        let name = String::from_utf8_lossy(&nameb);
        if size <= 32 * 1024 * 1024 && name.ends_with(".sg1") {
            let mut bytes = vec![0u8; size as usize];
            reader.read_exact(&mut bytes).map_err(io)?;
            // Only graph-flagged marks are cards; skip stars without unsealing them.
            let is_card = locate_header(&bytes)
                .map(|(h, _, _)| h.graph())
                .unwrap_or(false);
            if is_card {
                match unseal_card(&bytes, pass, identities) {
                    Ok(plain) => {
                        if let Ok(chart) = unpack_chart(&plain) {
                            return Ok(chart);
                        }
                    }
                    Err(e) => last_err = Some(e),
                }
            }
        } else {
            let mut left = size;
            let mut buf = vec![0u8; 64 * 1024];
            while left > 0 {
                let n = left.min(buf.len() as u64) as usize;
                reader.read_exact(&mut buf[..n]).map_err(io)?;
                left -= n as u64;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| err("atlas has no constellation card")))
}

fn unseal_atlas(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    identities: &[Identity],
) -> Result<u32> {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!("sigil-atlas-{}-{seq}", std::process::id()));
    fs::create_dir_all(&tmp).map_err(io)?;
    let result = (|| {
        extract_atlas(input, &tmp)?;
        let (chart, dir) = load_chart_keys(&tmp, pass, identities)?;
        let card = find_card(&dir);
        let missing = missing_stars(&dir, &chart, card.as_deref());
        refuse_missing(&missing)?;
        restore_chart(
            &chart,
            dest,
            pass,
            companions,
            only,
            Some(&dir),
            card.as_deref(),
            identities,
        )
    })();
    let _ = fs::remove_dir_all(&tmp);
    result
}

fn extract_atlas(input: &Path, dest: &Path) -> Result<u32> {
    fs::create_dir_all(dest).map_err(io)?;
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let mut mag = [0u8; 4];
    reader.read_exact(&mut mag).map_err(io)?;
    if mag != ATLAS_MAGIC {
        return Err(err("not an atlas"));
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver).map_err(io)?;
    let (count, v2) = match ver[0] {
        1 => {
            let mut b = [0u8; 2];
            reader.read_exact(&mut b).map_err(io)?;
            (u16::from_le_bytes(b) as u32, false)
        }
        2 => {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b).map_err(io)?;
            (u32::from_le_bytes(b), true)
        }
        v => return Err(err(format!("unknown atlas version {v}"))),
    };
    for _ in 0..count {
        let mut nlen = [0u8; 1];
        reader.read_exact(&mut nlen).map_err(io)?;
        let mut nameb = vec![0u8; nlen[0] as usize];
        if !nameb.is_empty() {
            reader.read_exact(&mut nameb).map_err(io)?;
        }
        let name = String::from_utf8_lossy(&nameb).into_owned();
        let size = if v2 {
            let mut b = [0u8; 8];
            reader.read_exact(&mut b).map_err(io)?;
            u64::from_le_bytes(b)
        } else {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b).map_err(io)?;
            u32::from_le_bytes(b) as u64
        };
        let out = safe_out_path(dest, &name)?;
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(io)?;
        }
        let mut f = File::create(&out).map_err(io)?;
        let mut left = size;
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..n]).map_err(io)?;
            f.write_all(&buf[..n]).map_err(io)?;
            left -= n as u64;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Old flat layout: an existing non-empty folder stays flat on add (no container).
    fn legacy_sky(root: &Path, name: &str) -> PathBuf {
        let sky = root.join(name);
        fs::create_dir_all(&sky).unwrap();
        fs::write(sky.join(".flat"), b"").unwrap();
        sky
    }
    use crate::sha256;

    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sigil-sky-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn add_unique_link_skip_and_restore() {
        let root = scratch("add");
        let sky = legacy_sky(&root, "Taxes");
        let a = root.join("tax-2025.pdf");
        let b = root.join("notes.txt");
        let copy = root.join("copy.pdf");
        fs::write(&a, b"tax-bytes").unwrap();
        fs::write(&b, b"note-bytes").unwrap();
        fs::write(&copy, b"tax-bytes").unwrap();

        let opts = AddOpts {
            title: Some("Taxes"),
            mode: Mode::Glyph,
            ..AddOpts::default()
        };
        let r1 = add_to_constellation(&sky, &a, opts.clone()).unwrap();
        assert_eq!(r1.added, 1);
        let r2 = add_to_constellation(&sky, &b, opts.clone()).unwrap();
        assert_eq!(r2.added, 1);
        let r3 = add_to_constellation(
            &sky,
            &copy,
            AddOpts {
                as_name: Some("dup.pdf"),
                ..opts.clone()
            },
        )
        .unwrap();
        assert_eq!(r3.linked, 1);
        assert_eq!(r3.added, 0);
        let r4 = add_to_constellation(&sky, &a, opts.clone()).unwrap();
        assert_eq!(r4.skipped, 1);

        let stars: Vec<_> = fs::read_dir(&sky)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".sg1") && n != "Taxes.sg1")
            .collect();
        assert_eq!(
            stars.len(),
            2,
            "duplicate bytes must not mint a third star: {stars:?}"
        );

        let out = root.join("out");
        let n = unseal_constellation(&sky, &out, None, &[], &[]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(fs::read(out.join("tax-2025.pdf")).unwrap(), b"tax-bytes");
        assert_eq!(fs::read(out.join("notes.txt")).unwrap(), b"note-bytes");
        assert_eq!(fs::read(out.join("dup.pdf")).unwrap(), b"tax-bytes");
        assert_eq!(
            sha256(&fs::read(out.join("dup.pdf")).unwrap()),
            sha256(b"tax-bytes")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_star_refuses() {
        let root = scratch("miss");
        let sky = legacy_sky(&root, "Taxes");
        let a = root.join("a.txt");
        let b = root.join("b.txt");
        fs::write(&a, b"alpha").unwrap();
        fs::write(&b, b"beta").unwrap();
        let opts = AddOpts {
            title: Some("Taxes"),
            mode: Mode::Glyph,
            ..AddOpts::default()
        };
        add_to_constellation(&sky, &a, opts.clone()).unwrap();
        add_to_constellation(&sky, &b, opts.clone()).unwrap();
        let star_b = sky.join(star_file_name("b.txt"));
        fs::remove_file(&star_b).unwrap();
        let err = unseal_constellation(&sky, &root.join("out"), None, &[], &[]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("missing a star"), "{msg}");
        assert!(msg.contains("b.txt"), "{msg}");
        add_to_constellation(&sky, &b, opts).unwrap();
        let out = root.join("out");
        unseal_constellation(&sky, &out, None, &[], &[]).unwrap();
        assert_eq!(fs::read(out.join("b.txt")).unwrap(), b"beta");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn atlas_roundtrip() {
        let root = scratch("atlas");
        let sky = legacy_sky(&root, "Taxes");
        let a = root.join("a.txt");
        fs::write(&a, b"alpha-file").unwrap();
        add_to_constellation(
            &sky,
            &a,
            AddOpts {
                title: Some("Taxes"),
                mode: Mode::Glyph,
                ..AddOpts::default()
            },
        )
        .unwrap();
        let bag = root.join("Taxes.sga");
        let n = pack_atlas(&sky, &bag).unwrap();
        assert!(n >= 2);
        let out = root.join("from-atlas");
        let got = unseal_constellation(&bag, &out, None, &[], &[]).unwrap();
        assert_eq!(got, 1);
        assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"alpha-file");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn replace_same_path_new_bytes() {
        let root = scratch("rep");
        let sky = legacy_sky(&root, "Taxes");
        let a = root.join("notes.txt");
        fs::write(&a, b"v1").unwrap();
        let opts = AddOpts {
            title: Some("Taxes"),
            mode: Mode::Glyph,
            ..AddOpts::default()
        };
        add_to_constellation(&sky, &a, opts.clone()).unwrap();
        fs::write(&a, b"v2-changed").unwrap();
        let r = add_to_constellation(&sky, &a, opts).unwrap();
        assert_eq!(r.replaced, 1);
        let out = root.join("out");
        unseal_constellation(&sky, &out, None, &[], &[]).unwrap();
        assert_eq!(fs::read(out.join("notes.txt")).unwrap(), b"v2-changed");
        let _ = fs::remove_dir_all(&root);
    }

    fn noise(n: usize, seed: u64) -> Vec<u8> {
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

    /// Every file under `dir`, relative, sorted.
    fn files_under(dir: &Path) -> Vec<String> {
        fn go(base: &Path, d: &Path, out: &mut Vec<String>) {
            if let Ok(rd) = fs::read_dir(d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        go(base, &p, out);
                    } else if let Ok(r) = p.strip_prefix(base) {
                        out.push(r.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
        let mut v = Vec::new();
        go(dir, dir, &mut v);
        v.sort();
        v
    }

    #[test]
    fn failed_constellation_restore_writes_nothing_and_keeps_existing_files() {
        let root = scratch("atomic");
        let sky = legacy_sky(&root, "Sky");
        fs::create_dir_all(root.join("in")).unwrap();
        let names = ["a.txt", "big.bin", "z.txt"];
        let big = noise(200_000, 11);
        fs::write(root.join("in/a.txt"), b"alpha").unwrap();
        fs::write(root.join("in/big.bin"), &big).unwrap();
        fs::write(root.join("in/z.txt"), b"omega").unwrap();
        let opts = AddOpts {
            title: Some("Sky"),
            mode: Mode::Seal,
            chunk: 64 * 1024,
            ..AddOpts::default()
        };
        for n in names {
            add_to_constellation(&sky, &root.join("in").join(n), opts.clone()).unwrap();
        }
        let z_star = sky.join(star_file_name("z.txt"));
        let big_star = sky.join(star_file_name("big.bin"));
        assert!(crate::work::is_work_pack(&big_star));
        let z_good = fs::read(&z_star).unwrap();
        let big_good = fs::read(&big_star).unwrap();
        let mut z_bad = z_good.clone();
        z_bad.fill(0);
        let mut big_bad = big_good.clone();
        let (lo, hi) = (big_bad.len() / 3, big_bad.len() * 2 / 3);
        big_bad[lo..hi].fill(0);
        let atlas_dir = root.join("atlas");
        fs::create_dir_all(&atlas_dir).unwrap();
        for (what, star, bad, good) in [
            ("last star", &z_star, &z_bad, &z_good),
            ("work-pack star", &big_star, &big_bad, &big_good),
        ] {
            fs::write(star, bad).unwrap();
            let atlas = atlas_dir.join("sky.atlas.sg1");
            let _ = fs::remove_file(&atlas);
            pack_atlas(&sky, &atlas).unwrap();
            for input in [&sky, &atlas] {
                let dest = root.join("fresh");
                let _ = fs::remove_dir_all(&dest);
                assert!(unseal_constellation(input, &dest, None, &[], &[]).is_err());
                assert!(!dest.exists(), "{what}: left {:?}", files_under(&dest));
                let keep = root.join("keep");
                let _ = fs::remove_dir_all(&keep);
                fs::create_dir_all(&keep).unwrap();
                fs::write(keep.join("a.txt"), b"previous").unwrap();
                assert!(unseal_constellation(input, &keep, None, &[], &[]).is_err());
                assert_eq!(files_under(&keep), vec!["a.txt"], "{what}");
                assert_eq!(fs::read(keep.join("a.txt")).unwrap(), b"previous");
            }
            fs::write(star, good).unwrap();
        }
        let keep = root.join("keep");
        assert_eq!(
            unseal_constellation(&sky, &keep, None, &[], &[]).unwrap(),
            3
        );
        assert_eq!(files_under(&keep), names.to_vec());
        assert_eq!(fs::read(keep.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(keep.join("big.bin")).unwrap(), big);
        let _ = fs::remove_dir_all(&root);
    }

    fn has_sgto(path: &Path) -> bool {
        card_is_encrypt_to(path)
    }

    #[test]
    fn encrypt_to_constellation_add_scry_restore() {
        let root = scratch("to");
        let sky = legacy_sky(&root, "Vault");
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let eve = Identity::generate().unwrap();
        let to = [alice.public(), bob.public()];
        let small = root.join("note.txt");
        let big = root.join("big.bin");
        fs::write(&small, b"secret note").unwrap();
        let big_bytes = noise(200_000, 7);
        fs::write(&big, &big_bytes).unwrap();

        let opts = AddOpts {
            title: Some("Vault"),
            chunk: 64 * 1024,
            recipients: &to,
            ..AddOpts::default()
        };
        let r = add_to_constellation(&sky, &small, opts.clone()).unwrap();
        assert_eq!(r.added, 1);
        // Adding to an encrypt-to card needs an identity to read the list.
        let e = add_to_constellation(&sky, &big, opts.clone())
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("--identity"), "{e}");
        let ids = [bob.clone()];
        let r = add_to_constellation(
            &sky,
            &big,
            AddOpts {
                identities: &ids,
                ..opts.clone()
            },
        )
        .unwrap();
        assert_eq!(r.added, 1);
        assert!(r.chart.as_ref().unwrap().members.len() == 2);

        let card = find_card(&sky).unwrap();
        assert!(has_sgto(&card), "card must be encrypt-to");
        // Encrypted stars never carry the list name (or the plaintext hash) in their file name.
        assert!(!sky.join(star_file_name("note.txt")).exists());
        let ids = [alice.clone()];
        let note_star = member_star_path(&sky, "note.txt", None, &ids).unwrap();
        assert!(has_sgto(&note_star), "star must be encrypt-to");
        let big_star = member_star_path(&sky, "big.bin", None, &ids).unwrap();
        assert!(crate::work::is_work_pack(&big_star));
        let probe = root.join("probe.bin");
        assert!(crate::work::unseal_path(&big_star, &probe, None, &[]).is_err());
        crate::work::unseal_path_keys(&big_star, &probe, None, &[], std::slice::from_ref(&alice))
            .unwrap();
        assert_eq!(fs::read(&probe).unwrap(), big_bytes);

        // A later add without --to would rewrite the card in the clear: refused.
        let e = add_to_constellation(
            &sky,
            &small,
            AddOpts {
                recipients: &[],
                identities: &ids,
                ..opts.clone()
            },
        )
        .err()
        .unwrap()
        .to_string();
        assert!(e.contains("encrypt-to") && e.contains("--to"), "{e}");
        assert!(has_sgto(&find_card(&sky).unwrap()));

        // Scry: locked without a key, readable with either recipient.
        let e = scry_constellation(&sky, None).unwrap_err().to_string();
        assert!(e.contains("--identity"), "{e}");
        let text = scry_constellation_keys(&sky, None, std::slice::from_ref(&alice)).unwrap();
        assert!(
            text.contains("stars=2") && !text.contains("MISSING"),
            "{text}"
        );

        // De-scribe: wrong identity refused; each recipient restores everything.
        assert!(
            unseal_constellation_keys(&sky, &root.join("eve"), None, &[], &[], &[eve]).is_err()
        );
        assert!(unseal_constellation(&sky, &root.join("none"), None, &[], &[]).is_err());
        for (tag, who) in [("a", &alice), ("b", &bob)] {
            let out = root.join(format!("out-{tag}"));
            let n =
                unseal_constellation_keys(&sky, &out, None, &[], &[], std::slice::from_ref(who))
                    .unwrap();
            assert_eq!(n, 2);
            assert_eq!(fs::read(out.join("note.txt")).unwrap(), b"secret note");
            assert_eq!(fs::read(out.join("big.bin")).unwrap(), big_bytes);
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn encrypt_to_atlas_bag_and_missing_star_refusal() {
        let root = scratch("to-atlas");
        let sky = legacy_sky(&root, "Bag");
        let alice = Identity::generate().unwrap();
        let to = [alice.public()];
        let a = root.join("a.txt");
        let b = root.join("b.bin");
        fs::write(&a, b"alpha").unwrap();
        let b_bytes = noise(150_000, 9);
        fs::write(&b, &b_bytes).unwrap();
        let src = root.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::copy(&a, src.join("a.txt")).unwrap();
        fs::copy(&b, src.join("sub/b.bin")).unwrap();
        let report = add_to_constellation(
            &sky,
            &src,
            AddOpts {
                title: Some("Bag"),
                chunk: 64 * 1024,
                recipients: &to,
                ..AddOpts::default()
            },
        )
        .unwrap();
        assert_eq!(report.added, 2);

        // Sender without the recipient key can still bag right after add.
        let bag1 = root.join("sent.sga");
        let n = pack_atlas_chart(&sky, report.chart.as_ref().unwrap(), &bag1).unwrap();
        assert_eq!(n, 3);
        // From disk: the locked card needs the identity.
        let bag2 = root.join("kept.sga");
        assert!(pack_atlas(&sky, &bag2).is_err());
        let ids = [alice.clone()];
        assert_eq!(pack_atlas_keys(&sky, &bag2, None, &ids).unwrap(), 3);

        for bag in [&bag1, &bag2] {
            let e = unseal_constellation(bag, &root.join("x"), None, &[], &[])
                .unwrap_err()
                .to_string();
            assert!(e.contains("--identity"), "{e}");
            let text = scry_constellation_keys(bag, None, &ids).unwrap();
            assert!(text.contains("stars=2"), "{text}");
            let out = root.join(format!(
                "out-{}",
                bag.file_stem().unwrap().to_string_lossy()
            ));
            let n = unseal_constellation_keys(bag, &out, None, &[], &[], &ids).unwrap();
            assert_eq!(n, 2);
            assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"alpha");
            assert_eq!(fs::read(out.join("sub/b.bin")).unwrap(), b_bytes);
        }

        // A named star gone: de-scribe and atlas still refuse, even with the key.
        let star = member_star_path(&sky, "a.txt", None, &ids).unwrap();
        fs::remove_file(&star).unwrap();
        let e = unseal_constellation_keys(&sky, &root.join("m"), None, &[], &[], &ids)
            .unwrap_err()
            .to_string();
        assert!(e.contains("missing a star") && e.contains("a.txt"), "{e}");
        let e = pack_atlas_keys(&sky, &root.join("m.sga"), None, &ids)
            .unwrap_err()
            .to_string();
        assert!(e.contains("missing a star"), "{e}");
        let text = scry_constellation_keys(&sky, None, &ids).unwrap();
        assert!(text.contains("MISSING"), "{text}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn warded_and_dual_card_atlas() {
        let root = scratch("ward-atlas");
        let alice = Identity::generate().unwrap();
        let a = root.join("a.txt");
        fs::write(&a, b"warded alpha").unwrap();
        // Passphrase-only constellation: atlas used to read the card with no pass.
        let sky = legacy_sky(&root, "W");
        add_to_constellation(
            &sky,
            &a,
            AddOpts {
                title: Some("W"),
                pass: Some("pw"),
                ..AddOpts::default()
            },
        )
        .unwrap();
        let bag = root.join("w.sga");
        assert!(pack_atlas(&sky, &bag).is_err());
        assert_eq!(pack_atlas_keys(&sky, &bag, Some("pw"), &[]).unwrap(), 2);
        let out = root.join("w-out");
        unseal_constellation(&bag, &out, Some("pw"), &[], &[]).unwrap();
        assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"warded alpha");

        // --to plus --pass: either the passphrase or the identity opens.
        let to = [alice.public()];
        let sky2 = root.join("D");
        add_to_constellation(
            &sky2,
            &a,
            AddOpts {
                title: Some("D"),
                pass: Some("pw2"),
                recipients: &to,
                ..AddOpts::default()
            },
        )
        .unwrap();
        let o1 = root.join("d-pass");
        unseal_constellation(&sky2, &o1, Some("pw2"), &[], &[]).unwrap();
        assert_eq!(fs::read(o1.join("a.txt")).unwrap(), b"warded alpha");
        let o2 = root.join("d-id");
        unseal_constellation_keys(&sky2, &o2, None, &[], &[], std::slice::from_ref(&alice))
            .unwrap();
        assert_eq!(fs::read(o2.join("a.txt")).unwrap(), b"warded alpha");
        let _ = fs::remove_dir_all(&root);
    }
}
