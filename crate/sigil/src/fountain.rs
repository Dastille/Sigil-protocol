//! RaptorQ rain (RFC 6330). Extra packets are not limited to 255 RS indices.

use crate::Result;
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use std::fs;
use std::path::Path;

pub const FT_MAGIC: [u8; 4] = *b"SGFT";
const MTU: u16 = 16 * 1024;

fn write_rq(dir: &Path, i: u32, cfg: &[u8; 12], pkt: &EncodingPacket) -> Result<()> {
    let ser = pkt.serialize();
    let mut out = Vec::with_capacity(4 + 1 + 12 + ser.len());
    out.extend_from_slice(&FT_MAGIC);
    out.push(1);
    out.extend_from_slice(cfg);
    out.extend_from_slice(&ser);
    fs::write(dir.join(format!("rain-{i:05}.rq")), out)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(())
}

fn read_rq(path: &Path) -> Result<([u8; 12], EncodingPacket)> {
    let b = fs::read(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if b.len() < 17 || b[0..4] != FT_MAGIC {
        return Err(crate::Error::Msg(format!(
            "not a fountain packet: {}",
            path.display()
        )));
    }
    let mut cfg = [0u8; 12];
    cfg.copy_from_slice(&b[5..17]);
    Ok((cfg, EncodingPacket::deserialize(&b[17..])))
}

/// Write source packets plus `repair` extra RaptorQ packets of the whole .sg1.
pub fn deluge_fountain(file: &[u8], dir: &Path, repair: u32) -> Result<u32> {
    if file.len() >= 4 && file.starts_with(&crate::work::WORK_MAGIC) {
        return Err(crate::Error::Msg(
            "work pack: fountain each star, or Scatter the pack first.".into(),
        ));
    }
    fs::create_dir_all(dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let enc = Encoder::with_defaults(file, MTU);
    let cfg = enc.get_config().serialize();
    let packets = enc.get_encoded_packets(repair);
    let mut n = 0u32;
    for (i, pkt) in packets.iter().enumerate() {
        let path = dir.join(format!("rain-{i:05}.rq"));
        if path.exists() {
            n += 1;
            continue;
        }
        write_rq(dir, i as u32, &cfg, pkt)?;
        n += 1;
    }
    Ok(n)
}

pub fn gather_fountain(dir: &Path) -> Result<Vec<u8>> {
    let mut cfg: Option<[u8; 12]> = None;
    let mut pkts = Vec::new();
    let rd = fs::read_dir(dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("rq") {
            continue;
        }
        let (c, pkt) = read_rq(&p)?;
        if let Some(old) = cfg {
            if old != c {
                return Err(crate::Error::Msg(
                    "mixed fountain configs in this folder".into(),
                ));
            }
        } else {
            cfg = Some(c);
        }
        pkts.push(pkt);
    }
    let cfg = cfg.ok_or_else(|| crate::Error::Msg("no .rq fountain packets here".into()))?;
    let oti = ObjectTransmissionInformation::deserialize(&cfg);
    let mut dec = Decoder::new(oti);
    for pkt in pkts {
        if let Some(data) = dec.decode(pkt) {
            return Ok(data);
        }
    }
    Err(crate::Error::Msg(
        "not enough fountain packets yet (keep raining)".into(),
    ))
}

pub fn is_fountain_dir(dir: &Path) -> bool {
    fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rq"))
}
