//! FastCDC gear-hash chunking for opt-in work-pack stars.
//!
//! Profiles: Media (1/4/8 MiB), Dedup (256 KiB / 1 MiB / 4 MiB). Floor 64 KiB.
//! No overlap. Deterministic for the same bytes + profile.

/// Hard lower bound for any chunk size.
pub const FLOOR: usize = 64 * 1024;

/// Media: large binaries / video — fewer, bigger stars.
pub const MEDIA: Profile = Profile {
    name: "media",
    min: 1 * 1024 * 1024,
    avg: 4 * 1024 * 1024,
    max: 8 * 1024 * 1024,
};

/// Dedup: finer cuts for edit locality / backup-style workloads.
pub const DEDUP: Profile = Profile {
    name: "dedup",
    min: 256 * 1024,
    avg: 1 * 1024 * 1024,
    max: 4 * 1024 * 1024,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub name: &'static str,
    pub min: usize,
    pub avg: usize,
    pub max: usize,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "media" => Some(MEDIA),
            "dedup" => Some(DEDUP),
            _ => None,
        }
    }

    /// Clamp so min ≥ FLOOR and min ≤ avg ≤ max.
    pub fn normalized(self) -> Self {
        let min = self.min.max(FLOOR);
        let avg = self.avg.max(min);
        let max = self.max.max(avg);
        Self {
            name: self.name,
            min,
            avg,
            max,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRange {
    pub offset: usize,
    pub length: usize,
}

impl ChunkRange {
    pub fn end(self) -> usize {
        self.offset + self.length
    }
}

/// Split `data` into non-overlapping ranges (FastCDC).
pub fn chunk_ranges(data: &[u8], profile: Profile) -> Vec<ChunkRange> {
    let p = profile.normalized();
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let window = &data[off..];
        let n = find_cut(window, p.min, p.avg, p.max);
        out.push(ChunkRange {
            offset: off,
            length: n,
        });
        off += n;
    }
    out
}

/// Same as [`chunk_ranges`], but returns owned byte slices.
pub fn chunk_owned(data: &[u8], profile: Profile) -> Vec<Vec<u8>> {
    chunk_ranges(data, profile)
        .into_iter()
        .map(|r| data[r.offset..r.end()].to_vec())
        .collect()
}

/// Chunk a file by reading into a max-sized window (streaming-friendly).
pub fn chunk_file_ranges(
    path: &std::path::Path,
    profile: Profile,
) -> crate::Result<Vec<ChunkRange>> {
    use std::io::Read;
    let p = profile.normalized();
    let meta = std::fs::metadata(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let total = meta.len() as usize;
    if total == 0 {
        return Ok(vec![ChunkRange {
            offset: 0,
            length: 0,
        }]);
    }
    let mut f = std::fs::File::open(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut buf = Vec::with_capacity(p.max);
    let mut file_off = 0usize;
    let mut out = Vec::new();
    while file_off < total {
        buf.clear();
        let want = (total - file_off).min(p.max);
        buf.resize(want, 0);
        f.read_exact(&mut buf)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let cut = find_cut(&buf, p.min, p.avg, p.max);
        out.push(ChunkRange {
            offset: file_off,
            length: cut,
        });
        // Put unused tail back by seeking (we over-read if cut < want).
        if cut < want {
            use std::io::Seek;
            f.seek(std::io::SeekFrom::Current(-((want - cut) as i64)))
                .map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        file_off += cut;
    }
    Ok(out)
}

/// Find next cut length in `window` (prefix of remaining file data).
fn find_cut(window: &[u8], min: usize, avg: usize, max: usize) -> usize {
    let n = window.len();
    if n == 0 {
        return 0;
    }
    if n <= min {
        return n;
    }
    let max = max.min(n);
    let avg = avg.min(max);
    let (mask_s, mask_l) = masks_for_avg(avg);

    let mut hash = 0u64;
    let mut i = 0usize;
    // Skip / warm hash through min (no boundary test).
    while i < min {
        hash = (hash << 1).wrapping_add(GEAR[window[i] as usize]);
        i += 1;
    }
    // [min, avg): stricter mask
    while i < avg {
        hash = (hash << 1).wrapping_add(GEAR[window[i] as usize]);
        if hash & mask_s == 0 {
            return i + 1;
        }
        i += 1;
    }
    // [avg, max): looser mask
    while i < max {
        hash = (hash << 1).wrapping_add(GEAR[window[i] as usize]);
        if hash & mask_l == 0 {
            return i + 1;
        }
        i += 1;
    }
    max
}

fn masks_for_avg(avg: usize) -> (u64, u64) {
    // Normalization level 1: stricter below avg, looser above.
    let bits = bits_for(avg);
    let mask_s = mask_bits(bits.saturating_add(1));
    let mask_l = mask_bits(bits.saturating_sub(1).max(1));
    (mask_s, mask_l)
}

fn bits_for(avg: usize) -> u32 {
    if avg <= 1 {
        return 1;
    }
    // Round to nearest log2 (FastCDC / paper style).
    let floor = (usize::BITS - 1 - avg.leading_zeros()) as u32;
    let pow = 1usize << floor;
    let to_floor = avg - pow;
    let to_ceil = (pow << 1) - avg;
    if to_floor <= to_ceil {
        floor.max(1)
    } else {
        (floor + 1).max(1)
    }
}

fn mask_bits(bits: u32) -> u64 {
    if bits >= 63 {
        u64::MAX >> 1
    } else {
        (1u64 << bits) - 1
    }
}

// Deterministic gear table (splitmix64 seed 0x534947494C434443 = "SIGILCDC").
#[rustfmt::skip]
const GEAR: [u64; 256] = [
    0x2df7d53ccb865e6b, 0x0688a57d4b518a4e, 0xfd60f38fa12f1f60, 0x3845077ab5b998f6,
    0xe7ad55675002e788, 0xd09fbd14161d5de6, 0x9c1d6ae18c3b07bb, 0x6e1820fd51f2542d,
    0xbe6e04106b5eade0, 0x51e5ff14c445672a, 0x7d4205dd770a0916, 0x73c56de80644300d,
    0xe922ca4257c98ee2, 0x9a819ae2b461b0b0, 0x24edce752b6146e1, 0x76a3fe95643086ad,
    0xe54a5c8e2c8dea4e, 0x1d3a0b531b535522, 0xbc5423d25e910fe6, 0xc2fa9f97bf56c59b,
    0x111316bd46c1eed6, 0x2c597cd8faa4266c, 0x38f3f48f5560ecac, 0x6d82586aaf5c0442,
    0x6bb5f5cf652bd2be, 0x1ea53b52f5ee249f, 0x858544c0166d891c, 0x7b916ced498bcfe7,
    0xae0942fefdbd205c, 0xc82a91c1fae4f45a, 0x56bdfcb44703624d, 0x9dee5e54fc874ede,
    0xa045282cc835c4c8, 0xa097c131f3122686, 0x50ce417271d25efc, 0xfb3a13866805e105,
    0xe911861c207e8bed, 0x739d006751b9bc10, 0xa343ca3e2eb3dce7, 0xf514023d5a567d97,
    0x63ab4e1192ba3435, 0xe1ed8df8d29f0f6e, 0x46b06a1fee98df61, 0x044240fd61bb2872,
    0x927d1dd810c6831d, 0x7550913908a8ce9f, 0x9f81ab409f9e71fd, 0x27087eee65cbd536,
    0x330f4bbc2da849ed, 0x7f04842961864c27, 0xba07f7d12d74a267, 0x94209d714d51581d,
    0x268fd8d4d4cb9904, 0xd51d3e91ebf335e2, 0xc4b8e6ca52ee2486, 0x6504a648a072d8b5,
    0x73fd4ac43d41d17f, 0x9b325192e7b8e95b, 0xe3e10561669881a6, 0x707d112118f34792,
    0x44ce2a6ddb98fe6c, 0xddfc8f1c513b5f97, 0x7ff5abd85bcf12f5, 0xb3205ac78142cf74,
    0x494156daccc428a9, 0x201f1dcc2d6bc22b, 0x159b4f3f6f616fa9, 0xb3f0a2af055aaf90,
    0x0edbaa932057a1bc, 0xf5e8990a2c8a1667, 0x7d04dbbdca45ab88, 0x731c54b608a6bd20,
    0xa6f877499eae02e3, 0x7ca676acde78b874, 0x778f24dfaae8216b, 0xa5edb87e7f4d7bd7,
    0xa3e60fc511072f97, 0x0f3f032415603ff4, 0x6d3b69c04bf68c81, 0xbde76a4727097871,
    0x2cf0dfd798010be6, 0x218e5838e92b5eb2, 0x339cd02d60639230, 0x2678c6baef45619a,
    0x5123dfa9109084d5, 0x6a86783cdaddfe60, 0xe0457fb15145194f, 0xc327522560ab8e6a,
    0x49df5e7327248798, 0xfb9129775c9a1331, 0xf97b8374a19fcc1e, 0xe3bd344c0ef91651,
    0x4d1f5ba4a5a78162, 0xc1d9d4ad25d16dd7, 0x2294978c603c0a3b, 0xa71fdbdf3e3cd5f8,
    0xe088d7c7f237e74b, 0x9094442e9cbef96b, 0xee9a4d631887a865, 0xd74f8d40e9f3f14d,
    0xa98c19a6ac706bc9, 0x070c0326909f0295, 0xe33ff5d01136b073, 0xfbe463e5277ed80b,
    0xb04091fa53ad3ee3, 0xcb38cd0909899084, 0x6d2ae9f5bcbf8bf6, 0x967bbac6f5e1f7c2,
    0xbafc3290cc62abfd, 0x73e915bd65e6f988, 0xdd23b94f4693a9e5, 0x69cd3e81d37b5573,
    0x8f15fc1a076e496c, 0xdfdce27f9a00d721, 0xc401c3ff0b5503e4, 0xba3e5208311bbc50,
    0x49a5a94a51deaa18, 0xa1ef6160116488f0, 0xd64302ac1a305ec5, 0xdc5ec2e782592be4,
    0xc9b9d2679b523f0a, 0x19cc191c283d589d, 0x285a702e8a99537a, 0x85a28889d910fcba,
    0x300c04d44e9432c6, 0x2647e4f8c877e05a, 0x3e91001e0b189758, 0x1be0a20e432a1b61,
    0x51b013bbf014c6fb, 0x00907d62c45360e8, 0xd878821523fa5bf7, 0x8a39e399072fda60,
    0x97e0be199a0c91a1, 0x9c4a78429764a715, 0x7d0e50efb6ee9a56, 0xddef48df3ea32e6c,
    0xb4625fb98ab95972, 0x66e2d37fc8bb7c26, 0x76563f78bdc1a8f9, 0xd04d8a4ffb525ddd,
    0x514284bc399598f6, 0x89e9ef6546ab519d, 0x52c72928a7b073e9, 0xa1d73d0f0fcb8bd0,
    0xa1e4b978ded5e3f8, 0x1b8bd5643e41bc69, 0x2622056e21316d29, 0xacce56a093d91644,
    0xca144571f930ad97, 0xaa6a26753af0b83b, 0x80157ff29f8b1dfd, 0x130f811a2bc6ce0b,
    0xe525a6a9619cb203, 0x7890780734bbed1f, 0x7836c9cc7b1d003b, 0x356fdad26ee15d6a,
    0x4cbf6b60661db43d, 0xb270283b8f6fca5d, 0xe9b19092d658af79, 0x24b714596d0cff5c,
    0x86153fb61598fcbe, 0xe9e5124421a211a9, 0x5ee98d924967f480, 0x66402dc82ea14b55,
    0x27e680adf69641e2, 0x32c3edc927533ca0, 0x67c81ba65843356d, 0x37f8fed2372b2d4a,
    0x2173bb35aa305740, 0x7c4a6750b385ef61, 0xa1892ea575d33d24, 0x32753d5df00975a7,
    0x222fe796c65fb7b0, 0x4e4a4d4862eb8c99, 0x2e6ff6a5150d6670, 0x833fe02e175dcf17,
    0x0ab6de31dfa0febe, 0x5fd6ff511bb3fca5, 0x10ec24ac7088f1a7, 0xfbb56fcd8c621d4e,
    0x8c72da6a91ceeac3, 0x56fa940cbbf566b4, 0xac9e4ecdb3059a12, 0x4b55176176f6d4d5,
    0xa98f7b86a1cad8ea, 0x5cffe790c91f432c, 0x21852809385a8e1a, 0x8e5d39a5e22cfcc8,
    0xce221f48ac660f7d, 0x4be49766443dc6f0, 0x42d657bb6d6cedc9, 0x6e07b5e306e7ee1d,
    0x038074ac294905e5, 0x7cb2e9444cfe28ee, 0xf9835841c9d4dee5, 0x14c7c0d11edf1c01,
    0xe2c44c0772791e14, 0xec9f0b65bb8a0d7e, 0xa0c5904e9c6c12ba, 0x446db5797c1e437a,
    0xafc9e2a7423c2e67, 0xe63a41532dafc983, 0xcfe5dce69e8614f5, 0x010d668d9b8fe73c,
    0x035cf8cc8785c34c, 0x1c711bb2bfeecf8f, 0x9604275bbc06ff65, 0x1279605b48770e39,
    0xe51987afc7cf814d, 0x5cdbc08b99dd3e16, 0xd0d2408a91aae232, 0x68e19742ab6ad6bf,
    0x58b8539934eb23b2, 0xbffdb2e883648d60, 0x5e937c8053e558a1, 0xd14b29fcd7ec5483,
    0xb7b9aa06faab6b94, 0x30aa2829fee5d919, 0x7d048f42dddc140e, 0x8c362f5fc6d66907,
    0xa9a787ac5f7304b8, 0x42b0c558b66582d1, 0xd7d2af99f0ca4fa4, 0x4b47a3266a682099,
    0xb6e6bea05f93f699, 0x747326f88f1536f3, 0xe0fa31ed30c54a8b, 0x27b9820e1e1a4801,
    0xdbd6de23d9acffb4, 0xc504917e52a9c46f, 0x69e082728a9ce000, 0x36102e3f090f1b4a,
    0xfd402386ec9125a9, 0x220a2fd9b273c77b, 0x519d310ca3bd0efc, 0xd01a43d909a3689a,
    0x3ed1b8469d5183fb, 0x2c00509425e7af55, 0xa4dfacdf74a6d6d8, 0xdf1bf9c00bafe3b3,
    0xd35080588e88956a, 0xcbbd49f3374eed90, 0xa4773f455131cb5a, 0x50f5661b454c2413,
    0x9e14545837197e5d, 0x298a7a1d8d140b3e, 0x4be063404b6077e2, 0xf2a442a6629b7bf0,
    0x090c54942c2350d0, 0xab852f375ff24fa6, 0xb94a611eb8ad5250, 0x019cb5c1e266fff0,
    0x410542b714fc8685, 0xab4777f174429484, 0x780576c77f29f974, 0xe62f9e9e457f7ed0,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn patterned(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| ((i * 17 + (i >> 8) * 3) % 251) as u8)
            .collect()
    }

    #[test]
    fn determinism() {
        let data = patterned(12 * 1024 * 1024);
        let a = chunk_ranges(&data, MEDIA);
        let b = chunk_ranges(&data, MEDIA);
        assert_eq!(a, b);
        let owned = chunk_owned(&data, MEDIA);
        assert_eq!(owned.len(), a.len());
        assert_eq!(owned.iter().map(|c| c.len()).sum::<usize>(), data.len());
    }

    #[test]
    fn media_max_cap() {
        let data = patterned(20 * 1024 * 1024);
        for r in chunk_ranges(&data, MEDIA) {
            assert!(r.length <= MEDIA.max, "chunk {} > max", r.length);
            if r.end() < data.len() {
                assert!(r.length >= MEDIA.min || r.length >= FLOOR);
            }
        }
    }

    #[test]
    fn covers_all_bytes_no_overlap() {
        let data = patterned(5 * 1024 * 1024 + 123);
        let ranges = chunk_ranges(&data, DEDUP);
        let mut pos = 0;
        for r in &ranges {
            assert_eq!(r.offset, pos);
            pos = r.end();
        }
        assert_eq!(pos, data.len());
    }

    #[test]
    fn edit_locality_middle() {
        // Small profile for a fast test: reuse DEDUP-ish ratios on tiny sizes via custom.
        let custom = Profile {
            name: "tiny",
            min: FLOOR,
            avg: 128 * 1024,
            max: 256 * 1024,
        };
        let mut data = patterned(900 * 1024);
        let before = chunk_ranges(&data, custom);
        let digests: Vec<_> = before
            .iter()
            .map(|r| crate::sha256(&data[r.offset..r.end()]))
            .collect();
        // Flip a few bytes in the middle.
        let mid = data.len() / 2;
        for i in 0..32 {
            data[mid + i] ^= 0x5a;
        }
        let after = chunk_ranges(&data, custom);
        let after_d: Vec<_> = after
            .iter()
            .map(|r| crate::sha256(&data[r.offset..r.end()]))
            .collect();
        let kept = digests.iter().filter(|d| after_d.contains(d)).count();
        // Most chunks should survive a middle edit.
        assert!(
            kept + 2 >= digests.len(),
            "edit-locality weak: kept {kept} of {}",
            digests.len()
        );
        assert!(kept >= digests.len().saturating_sub(3).max(1));
    }

    #[test]
    fn parse_profiles() {
        assert_eq!(Profile::parse("media"), Some(MEDIA));
        assert_eq!(Profile::parse("DEDUP"), Some(DEDUP));
        assert!(Profile::parse("nope").is_none());
    }
}
