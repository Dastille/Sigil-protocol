//! The key ring of a segment log made with `init --segment-keys` (slice 3).
//!
//! Every segment is sealed under its own random 32-byte key (`encrypt-to` an identity derived from
//! it, so the existing seal / unseal path is used unchanged). The keys live here, one record per
//! segment, each **wrapped with the existing SGTO machinery** to the recipients / passphrase the
//! writer gave at append time. Records are grouped like segments, 1000 per shard:
//!
//! ```text
//! keys/0000.sg1     a star (Reflection ECC, not encrypted) whose plain bytes are
//!                       sigil-log-keys=1
//!                       seq=7 salt=<32 hex> wrap=<hex of an SGTO block>
//! ```
//!
//! The shard is an ordinary star so it heals with the same ECC as everything else and `sigil
//! verify` / `mend` apply to it; it needs no key to open because every record is already wrapped.
//! Appending a record therefore needs only the *public* recipients, and destroying a record
//! (`shred`, `compact`, `gc`) needs no secret at all. Destroying rewrites the shard without the
//! record and, best effort, overwrites the old shard's bytes with zeros first.
//!
//! The ring is not part of the INDEX chain: the chain proves what the log said, the ring only holds
//! keys. A missing or altered record can make a segment unreadable but can never make a wrong
//! plaintext verify (the segment's true-name is in the chain).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::*;
use crate::keys;

const RING_MAGIC: &str = "sigil-log-keys=1";

pub fn shard_of(seq: u64) -> u64 {
    seq / SEGMENTS_PER_FOLDER
}

pub fn shard_path(dir: &Path, shard: u64) -> PathBuf {
    dir.join(KEYS_DIR).join(format!("{shard:04}.sg1"))
}

/// `NNNN.sg1` → shard number.
pub(super) fn shard_of_file(p: &Path) -> Option<u64> {
    let stem = p.file_name()?.to_str()?.strip_suffix(".sg1")?;
    (stem.len() == 4 && stem.bytes().all(|b| b.is_ascii_digit())).then(|| stem.parse().ok())?
}

#[derive(Clone, Debug)]
pub(super) struct Frame {
    salt: [u8; 16],
    /// SGTO block holding the segment key.
    wrap: Vec<u8>,
}

type Frames = BTreeMap<u64, Frame>;

fn render(frames: &Frames) -> String {
    let mut s = format!("{RING_MAGIC}\n");
    for (seq, f) in frames {
        s.push_str(&format!(
            "seq={seq} salt={} wrap={}\n",
            hex::encode(f.salt),
            hex::encode(&f.wrap)
        ));
    }
    s
}

fn parse(text: &str, shard: u64) -> Result<Frames> {
    let bad = |what: String| err(format!("key ring {}: {what}", shard_name(shard)));
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some(RING_MAGIC) {
        return Err(bad("not a sigil key ring".into()));
    }
    let mut out = Frames::new();
    for l in lines.filter(|l| !l.trim().is_empty()) {
        let mut kv: BTreeMap<&str, &str> = BTreeMap::new();
        for t in l.split_whitespace() {
            if let Some((k, v)) = t.split_once('=') {
                kv.entry(k).or_insert(v);
            }
        }
        let seq = kv
            .get("seq")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| shard_of(*s) == shard);
        let salt = kv
            .get("salt")
            .and_then(|v| hex::decode(v).ok())
            .and_then(|b| <[u8; 16]>::try_from(b).ok());
        let wrap = kv
            .get("wrap")
            .and_then(|v| hex::decode(v).ok())
            .filter(|w| keys::sgto_len_at(w, 0) == w.len());
        let (Some(seq), Some(salt), Some(wrap)) = (seq, salt, wrap) else {
            return Err(bad(format!("bad record {l:?}")));
        };
        if out.insert(seq, Frame { salt, wrap }).is_some() {
            return Err(bad(format!("segment {seq} appears twice")));
        }
    }
    Ok(out)
}

fn shard_name(shard: u64) -> String {
    format!("{KEYS_DIR}/{shard:04}.sg1")
}

/// One shard's records (`None`: no such file).
pub(super) fn load_shard(dir: &Path, shard: u64) -> Result<Option<Frames>> {
    let p = shard_path(dir, shard);
    let file = match fs::read(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(err(format!("key ring {}: {e}", shard_name(shard)))),
    };
    let plain = crate::unseal_ex_keys(&file, None, &[], &[])
        .map_err(|e| err(format!("key ring {} is unreadable ({e}); `sigil log mend` heals what ECC can, else restore it from a copy", shard_name(shard))))?;
    parse(&String::from_utf8_lossy(&plain), shard).map(Some)
}

fn scrub(p: &Path) {
    use std::io::Seek;
    if let Ok(mut f) = fs::OpenOptions::new().write(true).open(p) {
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let zeros = vec![0u8; 64 * 1024];
        let mut left = len;
        let _ = f.rewind();
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            if f.write_all(&zeros[..n]).is_err() {
                break;
            }
            left -= n as u64;
        }
        let _ = f.sync_all();
    }
    let _ = fs::remove_file(p);
}

/// Replace (or, with `None`, delete) a shard file. The old bytes are overwritten with zeros
/// *after* the new file is in place, through a second hard link to the old inode, so a crash can
/// never leave the ring half-written. Best effort only: see "Crypto-shredding" in
/// `docs/SEGMENT-LOG.md` (journals, copy-on-write file systems, SSD wear levelling, backups).
fn replace_scrubbing(path: &Path, data: Option<&[u8]>) -> Result<()> {
    let mut link = path.as_os_str().to_os_string();
    link.push(".scrub.part");
    let link = PathBuf::from(link);
    let _ = fs::remove_file(&link);
    let linked = path.is_file() && fs::hard_link(path, &link).is_ok();
    let done = match data {
        Some(d) => write_atomic(path, d),
        None => fs::remove_file(path).map_err(io),
    };
    match done {
        Ok(()) => {
            if linked {
                scrub(&link);
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&link);
            Err(e)
        }
    }
}

fn store_shard(dir: &Path, shard: u64, frames: &Frames) -> Result<()> {
    let p = shard_path(dir, shard);
    if frames.is_empty() {
        if p.is_file() {
            replace_scrubbing(&p, None)?;
        }
        return Ok(());
    }
    let sealed = crate::seal_kn_to(
        render(frames).as_bytes(),
        Mode::Reflection,
        None,
        &format!("keys-{shard:04}"),
        false,
        "",
        &[],
        None,
        crate::DEFAULT_PIECE,
        &[],
    )?;
    replace_scrubbing(&p, Some(&sealed))
}

/// Wrap `master` (the segment's key) for the recipients / passphrase and store it under `seq`
/// (replacing a leftover record of a crashed append at the same seq). Caller holds the lock.
pub(super) fn put(
    log: &Log,
    seq: u64,
    master: &[u8; 32],
    pass: Option<&str>,
    recipients: &[PublicIdentity],
) -> Result<()> {
    let pass = pass.filter(|p| !p.is_empty());
    if pass.is_none() && recipients.is_empty() {
        return Err(err(
            "this log has per-segment keys: give --pass and/or --to so the segment key can be wrapped and kept in the key ring",
        ));
    }
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|e| err(e.to_string()))?;
    let wrap = keys::build_sgto(master, recipients, pass, &salt)?;
    let shard = shard_of(seq);
    let mut frames = load_shard(&log.dir, shard)?.unwrap_or_default();
    frames.insert(seq, Frame { salt, wrap });
    store_shard(&log.dir, shard, &frames)
}

/// Destroy the records of `seqs`; returns those that existed. Caller holds the lock.
pub(super) fn destroy(log: &Log, seqs: &[u64]) -> Result<Vec<u64>> {
    let mut by_shard: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &s in seqs {
        by_shard.entry(shard_of(s)).or_default().push(s);
    }
    let mut gone = Vec::new();
    for (shard, list) in by_shard {
        let Some(mut frames) = load_shard(&log.dir, shard)? else {
            continue;
        };
        let before = frames.len();
        for s in &list {
            if frames.remove(s).is_some() {
                gone.push(*s);
            }
        }
        if frames.len() != before {
            store_shard(&log.dir, shard, &frames)?;
        }
    }
    gone.sort_unstable();
    Ok(gone)
}

/// A fresh random segment key and the identity it stands for.
pub(super) fn new_key() -> Result<([u8; 32], Identity)> {
    let mut m = [0u8; 32];
    getrandom::getrandom(&mut m).map_err(|e| err(e.to_string()))?;
    let id = Identity::from_master(m)?;
    Ok((m, id))
}

/// Shards loaded on demand while reading many segments.
pub(super) struct RingCache {
    dir: PathBuf,
    shards: HashMap<u64, Frames>,
}

impl RingCache {
    pub fn new(log: &Log) -> Self {
        RingCache {
            dir: log.dir.clone(),
            shards: HashMap::new(),
        }
    }

    fn frame(&mut self, seq: u64) -> Result<Option<Frame>> {
        let shard = shard_of(seq);
        if !self.shards.contains_key(&shard) {
            let f = load_shard(&self.dir, shard)?.unwrap_or_default();
            self.shards.insert(shard, f);
        }
        Ok(self.shards[&shard].get(&seq).cloned())
    }

    /// The identity that opens segment `seq`, unwrapped with `--pass` / `--identity`.
    pub fn identity(&mut self, seq: u64, pass: Option<&str>, ids: &[Identity]) -> Result<Identity> {
        let Some(f) = self.frame(seq)? else {
            return Err(err(format!(
                "segment {seq} has no key in the key ring: it was crypto-shredded, its key was destroyed with it, or the ring lost the record"
            )));
        };
        let m = keys::unwrap_cek(&f.wrap, ids, pass, &f.salt)
            .map_err(|_| err(format!("cannot open the key of segment {seq}: give the --pass / --identity its key was wrapped to")))?;
        Identity::from_master(m)
    }
}

/// Which records a shard holds (`Err` = the shard cannot be read).
pub(super) type ShardScan = std::result::Result<BTreeSet<u64>, String>;

/// Which records every shard holds.
pub(super) fn scan(log: &Log) -> BTreeMap<u64, ShardScan> {
    let mut out = BTreeMap::new();
    for p in sorted(&log.dir.join(KEYS_DIR)) {
        if let Some(shard) = shard_of_file(&p) {
            out.insert(
                shard,
                load_shard(&log.dir, shard)
                    .map(|f| f.unwrap_or_default().keys().copied().collect())
                    .map_err(|e| e.to_string()),
            );
        }
    }
    out
}

/// (healed shards, unrecoverable shards)
pub(super) type MendedShards = (Vec<u64>, Vec<(u64, String)>);

/// Heal shards with repairable ECC damage in place. Returns (healed shards, unrecoverable shards).
pub(super) fn mend_shards(log: &Log) -> Result<MendedShards> {
    let (mut mended, mut bad) = (Vec::new(), Vec::new());
    for p in sorted(&log.dir.join(KEYS_DIR)) {
        let Some(shard) = shard_of_file(&p) else {
            continue;
        };
        let Ok(bytes) = fs::read(&p) else { continue };
        match health_bytes(&bytes) {
            Health::Ok => {}
            Health::Damaged(m) => bad.push((shard, m)),
            Health::Mendable(_) => match crate::mend_bytes(&bytes) {
                Ok(healed) => {
                    if healed != bytes {
                        write_atomic(&p, &healed)?;
                        mended.push(shard);
                    }
                }
                Err(e) => bad.push((shard, e.to_string())),
            },
        }
    }
    Ok((mended, bad))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shards_hold_1000_segments_and_empty_shards_disappear() {
        assert_eq!((shard_of(1), shard_of(999), shard_of(1000)), (0, 0, 1));
        let dir = std::env::temp_dir().join(format!("sigil-keyring-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let log = init_with(&dir.join("k"), None, true).unwrap();
        let me = Identity::generate().unwrap();
        let (m1, _) = new_key().unwrap();
        let (m2, _) = new_key().unwrap();
        put(&log, 5, &m1, None, &[me.public()]).unwrap();
        put(&log, 1500, &m2, Some("pw"), &[]).unwrap();
        assert!(shard_path(&log.dir, 0).is_file() && shard_path(&log.dir, 1).is_file());
        let mut rc = RingCache::new(&log);
        assert_eq!(
            rc.identity(5, None, std::slice::from_ref(&me))
                .unwrap()
                .master,
            m1
        );
        assert_eq!(rc.identity(1500, Some("pw"), &[]).unwrap().master, m2);
        assert!(rc
            .identity(1500, Some("nope"), std::slice::from_ref(&me))
            .is_err());
        assert!(rc
            .identity(6, None, std::slice::from_ref(&me))
            .err()
            .unwrap()
            .to_string()
            .contains("no key"));
        // replacing a record (a crashed append's leftover) keeps one record per seq
        put(&log, 5, &m2, None, &[me.public()]).unwrap();
        let mut rc = RingCache::new(&log);
        assert_eq!(
            rc.identity(5, None, std::slice::from_ref(&me))
                .unwrap()
                .master,
            m2
        );
        // nothing to wrap to: refused
        assert!(put(&log, 7, &m1, None, &[]).is_err());
        // destroy: reports what existed, drops an emptied shard file, leaves other shards alone
        assert_eq!(destroy(&log, &[5, 6, 1500]).unwrap(), vec![5, 1500]);
        assert!(!shard_path(&log.dir, 0).exists() && !shard_path(&log.dir, 1).exists());
        assert!(scan(&log).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn records_are_validated() {
        assert!(parse("nope\n", 0).is_err());
        let ok = format!("{RING_MAGIC}\n");
        assert!(parse(&ok, 0).unwrap().is_empty());
        // bad hex, wrong shard, truncated wrap
        for l in [
            "seq=1 salt=zz wrap=00",
            "seq=2000 salt=00000000000000000000000000000000 wrap=00",
            "seq=1 salt=00000000000000000000000000000000 wrap=0102",
        ] {
            assert!(parse(&format!("{ok}{l}\n"), 0).is_err(), "{l}");
        }
    }
}
