//! Constellation: a named list of stars (SIGG), kept as loose .sg1 files.
//! The card is a Seal whose payload is the list. An atlas (.sga) is the bag.

use crate::{hex32, locate_header, seal, sha256_path, unseal, unseal_ex, Mode, Result, DEFAULT_CHUNK};
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
}

#[derive(Clone, Debug)]
pub struct AddOpts<'a> {
    pub title: Option<&'a str>,
    pub mode: Mode,
    pub pass: Option<&'a str>,
    pub covenant: &'a str,
    pub geas: &'a [[u8; 32]],
    pub chunk: u32,
    pub as_name: Option<&'a str>,
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

fn peek_digest(path: &Path) -> Option<[u8; 32]> {
    if crate::work::is_work_pack(path) {
        return None;
    }
    peek_header(path).ok().map(|(h, _)| h.digest)
}

pub fn star_file_name(list_path: &str) -> String {
    let safe = list_path.replace('\\', "/");
    let safe = safe.trim_start_matches('/');
    let safe = safe.replace("..", "_");
    format!("{}.sg1", safe.replace('/', "__"))
}

fn default_title(dir: &Path) -> String {
    dir.file_name()
        .and_then(|s| s.to_str())
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

fn walk_files(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
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
            walk_files(&p, root, out)?;
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
    let count = u16::from_le_bytes(data[6..8].try_into().unwrap()) as usize;
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
        let orig_len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as u64;
        o += 4;
        let sealed = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
        o += 4;
        let mode = match data[o] {
            2 => Mode::Seal,
            1 => Mode::Reflection,
            _ => Mode::Glyph,
        };
        o += 1;
        let index = u16::from_le_bytes(data[o..o + 2].try_into().unwrap());
        o += 2;
        let total = u16::from_le_bytes(data[o..o + 2].try_into().unwrap());
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
        let byte_len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
        o += 4;
        let nlen = *data.get(o).ok_or_else(|| err("truncated v1 constellation"))? as usize;
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
        let orig_len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as u64;
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

fn write_card(dir: &Path, chart: &Chart, pass: Option<&str>) -> Result<PathBuf> {
    let packed = pack_chart(chart)?;
    let name = card_name(&chart.title);
    let dest = dir.join(&name);
    let sg1 = seal(&packed, Mode::Seal, pass, &name, true)?;
    fs::write(&dest, sg1).map_err(io)?;
    Ok(dest)
}

fn load_chart_from_mark(path: &Path, pass: Option<&str>) -> Result<Chart> {
    let data = fs::read(path).map_err(io)?;
    let plain = unseal(&data, pass).or_else(|_| unseal_ex(&data, pass, &[]))?;
    unpack_chart(&plain)
}

pub fn load_chart(input: &Path, pass: Option<&str>) -> Result<(Chart, PathBuf)> {
    if input.is_dir() {
        let card = find_card(input).ok_or_else(|| err("no constellation card in this folder"))?;
        let chart = load_chart_from_mark(&card, pass)?;
        return Ok((chart, input.to_path_buf()));
    }
    if is_atlas_file(input) {
        let parent = input.parent().unwrap_or(Path::new(".")).to_path_buf();
        let chart = load_chart_from_atlas(input, pass)?;
        return Ok((chart, parent));
    }
    if is_constellation_mark(input) {
        let chart = load_chart_from_mark(input, pass)?;
        let parent = input.parent().unwrap_or(Path::new(".")).to_path_buf();
        return Ok((chart, parent));
    }
    Err(err("not a constellation (folder, card .sg1, or atlas .sga)"))
}

fn index_stars(dir: &Path, card: Option<&Path>) -> HashMap<[u8; 32], PathBuf> {
    let mut map = HashMap::new();
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
        if let Some(d) = peek_digest(&p) {
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
            merkle: [0u8; 32],
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

fn find_member_star(
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
    let named = dir.join(star_file_name(&member.name));
    if named.is_file() {
        return Some(named);
    }
    None
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
    fs::create_dir_all(sky).map_err(io)?;
    let title = opts
        .title
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| find_card(sky).and_then(|c| load_chart_from_mark(&c, opts.pass).ok().map(|ch| ch.title)))
        .unwrap_or_else(|| default_title(sky));

    let mut chart = if let Some(card) = find_card(sky) {
        load_chart_from_mark(&card, opts.pass)?
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
        walk_files(input, input, &mut files)?;
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
        write_card(sky, &chart, opts.pass)?;
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
        crate::work::inscribe_path(
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
        )?;
    }
    Ok(dest)
}

pub fn scry_constellation(input: &Path, pass: Option<&str>) -> Result<String> {
    let (chart, dir) = load_chart(input, pass)?;
    let card = if input.is_dir() {
        find_card(input)
    } else if is_constellation_mark(input) {
        Some(input.to_path_buf())
    } else {
        find_card(&dir)
    };
    let missing = if is_atlas_file(input) {
        Vec::new()
    } else {
        missing_stars(&dir, &chart, card.as_deref())
    };
    let mut out = format!(
        "constellation  title={}  stars={}  unique={}\n",
        chart.title,
        chart.members.len(),
        unique_digests(&chart)
    );
    for m in &chart.members {
        let where_ = if !m.bytes.is_empty() {
            "packed"
        } else if is_atlas_file(input) {
            "atlas"
        } else if find_member_star(&dir, m, &index_stars(&dir, card.as_deref())).is_some() {
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
    Ok(out.trim_end().to_string())
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
    if is_atlas_file(input) {
        return unseal_atlas(input, dest, pass, companions, only);
    }
    let (chart, dir) = load_chart(input, pass)?;
    let card = if input.is_dir() {
        find_card(input)
    } else if is_constellation_mark(input) {
        Some(input.to_path_buf())
    } else {
        find_card(&dir)
    };
    let missing = missing_stars(&dir, &chart, card.as_deref());
    refuse_missing(&missing)?;
    restore_chart(&chart, dest, pass, companions, only, Some(&dir), card.as_deref())
}

fn wanted(rel: &str, only: &[String]) -> bool {
    if only.is_empty() {
        return true;
    }
    only.iter().any(|p| {
        let p = p.trim().trim_start_matches("./");
        rel == p || rel.starts_with(&(p.to_string() + "/")) || (p.ends_with('/') && rel.starts_with(p))
    })
}

fn restore_chart(
    chart: &Chart,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    dir: Option<&Path>,
    card: Option<&Path>,
) -> Result<u32> {
    fs::create_dir_all(dest).map_err(io)?;
    let by_digest = dir.map(|d| index_stars(d, card)).unwrap_or_default();
    let mut got = 0u32;
    for m in &chart.members {
        if !wanted(&m.name, only) {
            continue;
        }
        let out_path = safe_out_path(dest, &m.name)?;
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(io)?;
        }
        if !m.bytes.is_empty() {
            if m.bytes.starts_with(&crate::work::WORK_MAGIC) {
                let tmp = out_path.with_extension("sgwk");
                fs::write(&tmp, &m.bytes).map_err(io)?;
                crate::work::unseal_path(&tmp, &out_path, pass, companions)?;
                let _ = fs::remove_file(&tmp);
            } else {
                let plain = unseal_ex(&m.bytes, pass, companions)?;
                fs::write(&out_path, plain).map_err(io)?;
            }
        } else {
            let dir = dir.ok_or_else(|| err("constellation is missing a star"))?;
            let star = find_member_star(dir, m, &by_digest)
                .ok_or_else(|| err(format!("constellation is missing a star: {}", m.name)))?;
            crate::work::unseal_path(&star, &out_path, pass, companions)?;
        }
        got += 1;
    }
    if !only.is_empty() && got == 0 {
        return Err(err("nothing matched --only (Scry the constellation to see paths)"));
    }
    Ok(got)
}

pub fn pack_atlas(sky: &Path, output: &Path) -> Result<u32> {
    let (chart, dir) = load_chart(sky, None)?;
    let card = find_card(&dir).ok_or_else(|| err("no constellation card in this folder"))?;
    let missing = missing_stars(&dir, &chart, Some(&card));
    refuse_missing(&missing)?;
    let mut files: Vec<(String, PathBuf)> = vec![(card_name(&chart.title), card.clone())];
    let by_digest = index_stars(&dir, Some(&card));
    let mut seen = HashMap::new();
    for m in &chart.members {
        if let Some(p) = find_member_star(&dir, m, &by_digest) {
            let name = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("star.sg1")
                .to_string();
            if seen.insert(m.digest, ()).is_none() {
                files.push((name, p));
            }
        }
    }
    let mut writer = BufWriter::new(File::create(output).map_err(io)?);
    writer.write_all(&ATLAS_MAGIC).map_err(io)?;
    writer.write_all(&[2u8]).map_err(io)?;
    writer.write_all(&(files.len() as u32).to_le_bytes()).map_err(io)?;
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

fn load_chart_from_atlas(path: &Path, pass: Option<&str>) -> Result<Chart> {
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
            if let Ok(plain) = unseal(&bytes, pass) {
                if let Ok(chart) = unpack_chart(&plain) {
                    return Ok(chart);
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
    Err(err("atlas has no constellation card"))
}

fn unseal_atlas(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
) -> Result<u32> {
    let tmp = std::env::temp_dir().join(format!("sigil-atlas-{}", std::process::id()));
    fs::create_dir_all(&tmp).map_err(io)?;
    let result = (|| {
        extract_atlas(input, &tmp)?;
        let (chart, dir) = load_chart(&tmp, pass)?;
        let card = find_card(&dir);
        let missing = missing_stars(&dir, &chart, card.as_deref());
        refuse_missing(&missing)?;
        restore_chart(&chart, dest, pass, companions, only, Some(&dir), card.as_deref())
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
        let sky = root.join("Taxes");
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
        let r3 = add_to_constellation(&sky, &copy, AddOpts {
            as_name: Some("dup.pdf"),
            ..opts.clone()
        })
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
        assert_eq!(stars.len(), 2, "duplicate bytes must not mint a third star: {stars:?}");

        let out = root.join("out");
        let n = unseal_constellation(&sky, &out, None, &[], &[]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(fs::read(out.join("tax-2025.pdf")).unwrap(), b"tax-bytes");
        assert_eq!(fs::read(out.join("notes.txt")).unwrap(), b"note-bytes");
        assert_eq!(fs::read(out.join("dup.pdf")).unwrap(), b"tax-bytes");
        assert_eq!(sha256(&fs::read(out.join("dup.pdf")).unwrap()), sha256(b"tax-bytes"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_star_refuses() {
        let root = scratch("miss");
        let sky = root.join("Taxes");
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
        let sky = root.join("Taxes");
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
        let sky = root.join("Taxes");
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
}
