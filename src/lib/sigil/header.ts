import { crc32, crc32bytes, readCrc32 } from "./crc32";
import {
  FLAG_COMPRESSED,
  FLAG_ENCRYPTED,
  FLAG_GRAPH,
  FLAG_KEYSTONE,
  FLAG_EMBER,
  FLAG_VOW,
  flagMode,
  HEADER_SIZE,
  KEYSTONE_COPIES,
  KEYSTONE_SPAN,
  MAGIC,
  MAGIC_EMBER,
  MAX_COVENANT,
  MAX_GEAS,
  MODE_PARAMS,
  modeFlag,
  SHARD_CRC,
  VOW_SIZE,
  type ResilienceMode,
  type Sg1Header,
  VERSION,
} from "./types";

function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  dv.setUint32(0, lo, true);
  dv.setUint32(4, hi, true);
  return b;
}

function readU64le(b: Uint8Array, o: number): number {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const lo = dv.getUint32(o, true);
  const hi = dv.getUint32(o + 4, true);
  return hi * 0x100000000 + lo;
}

function encodeName(name: string): Uint8Array {
  const raw = new TextEncoder().encode(name).slice(0, 16);
  const out = new Uint8Array(16);
  out.set(raw);
  return out;
}

function decodeName(b: Uint8Array): string {
  let end = b.length;
  while (end > 0 && b[end - 1] === 0) end--;
  try {
    return new TextDecoder().decode(b.subarray(0, end)).replace(/[^\x20-\x7e]/g, "");
  } catch {
    return "";
  }
}

export function writeHeader(h: Omit<Sg1Header, "version"> & { version?: number }): Uint8Array {
  const buf = new Uint8Array(HEADER_SIZE);
  buf.set(MAGIC, 0);
  buf[4] = h.version ?? VERSION;
  buf[5] = h.flags;
  buf[6] = h.k;
  buf[7] = h.n;
  buf.set(u64le(h.origLen), 8);
  buf.set(u64le(h.foldedLen), 16);
  buf.set(h.digest.subarray(0, 32), 24);
  buf.set(h.salt.subarray(0, 16), 56);
  buf.set(h.nonce.subarray(0, 12), 72);
  buf.set(h.tag.subarray(0, 16), 84);
  const dv = new DataView(buf.buffer);
  dv.setUint32(100, h.shardLen, true);
  dv.setUint32(104, h.entropyMilli, true);
  buf.set(encodeName(h.name), 112);
  buf.set((h.merkle ?? new Uint8Array(32)).subarray(0, 32), 128);
  buf.set(crc32bytes(buf), 108);
  return buf;
}

/** Same map as the header, marked SGEM so a piece-copy is not mistaken for the front of the file. */
export function writeEmber(header: Uint8Array, index = 0): Uint8Array {
  const buf = new Uint8Array(HEADER_SIZE);
  buf.set(header.subarray(0, HEADER_SIZE));
  buf.set(MAGIC_EMBER, 0);
  buf[107] = index & 0xff;
  buf.fill(0, 108, 112);
  buf.set(crc32bytes(buf), 108);
  return buf;
}

function parseHeader(buf: Uint8Array, magic: Uint8Array): Sg1Header {
  if (buf.length < HEADER_SIZE) throw new Error("not a Sigil file: truncated header");
  if (buf[0] !== magic[0] || buf[1] !== magic[1] || buf[2] !== magic[2] || buf[3] !== magic[3]) {
    throw new Error("not a Sigil file: missing magic");
  }
  const version = buf[4];
  if (version !== 1 && version !== VERSION) {
    throw new Error(`unsupported Sigil version ${version} (this lab reads v1 and v${VERSION})`);
  }
  const probe = new Uint8Array(HEADER_SIZE);
  probe.set(buf.subarray(0, HEADER_SIZE));
  probe.fill(0, 108, 112);
  const expect = crc32(probe);
  const got = readCrc32(buf, 108);
  if (expect !== got) throw new Error("header CRC mismatch");
  const flags = buf[5];
  const k = buf[6];
  const n = buf[7];
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const mode = flagMode(flags);
  return {
    version,
    flags,
    mode,
    k,
    n,
    origLen: readU64le(buf, 8),
    foldedLen: readU64le(buf, 16),
    digest: buf.slice(24, 56),
    salt: buf.slice(56, 72),
    nonce: buf.slice(72, 84),
    tag: buf.slice(84, 100),
    shardLen: dv.getUint32(100, true),
    entropyMilli: dv.getUint32(104, true),
    compressed: (flags & FLAG_COMPRESSED) !== 0,
    encrypted: (flags & FLAG_ENCRYPTED) !== 0,
    graph: (flags & FLAG_GRAPH) !== 0,
    keystone: (flags & FLAG_KEYSTONE) !== 0,
    ember: (flags & FLAG_EMBER) !== 0,
    vow: (flags & FLAG_VOW) !== 0,
    covenant: "",
    geas: [],
    name: decodeName(buf.subarray(112, 128)),
    merkle: buf.slice(128, 160),
  };
}

export function readHeader(buf: Uint8Array): Sg1Header {
  return parseHeader(buf, MAGIC);
}

export function tryReadHeaderAt(buf: Uint8Array, offset: number): Sg1Header | null {
  if (offset < 0 || offset + HEADER_SIZE > buf.length) return null;
  try {
    return parseHeader(buf.subarray(offset, offset + HEADER_SIZE), MAGIC);
  } catch {
    return null;
  }
}

export function tryReadEmberAt(buf: Uint8Array, offset: number): Sg1Header | null {
  if (offset < 0 || offset + HEADER_SIZE > buf.length) return null;
  try {
    return parseHeader(buf.subarray(offset, offset + HEADER_SIZE), MAGIC_EMBER);
  } catch {
    return null;
  }
}

export type HeaderFix = {
  header: Sg1Header;
  prefix: number;
  slot: number;
  recovered: boolean;
  source: "primary" | "keystone" | "ember";
};

export function shardStride(header: Sg1Header): number {
  const lead = (header.ember ? HEADER_SIZE : 0) + (header.vow ? VOW_SIZE : 0);
  return lead + header.shardLen + SHARD_CRC;
}

export function bodyPrefix(header: Sg1Header): number {
  const maps = header.keystone ? KEYSTONE_SPAN : HEADER_SIZE;
  return maps + (header.vow ? VOW_SIZE : 0);
}

export function writeVow(covenant: string, geas: Uint8Array[]): Uint8Array {
  const buf = new Uint8Array(VOW_SIZE);
  const cov = new TextEncoder().encode(covenant).slice(0, MAX_COVENANT);
  const binds = geas.slice(0, MAX_GEAS).map((g) => g.subarray(0, 32));
  buf[0] = cov.length;
  buf[1] = binds.length;
  buf.set(cov, 2);
  binds.forEach((g, i) => buf.set(g, 50 + i * 32));
  buf.fill(0, 124, 128);
  buf.set(crc32bytes(buf.subarray(0, 124)), 124);
  return buf;
}

export function readVow(buf: Uint8Array, offset = 0): { covenant: string; geas: Uint8Array[] } | null {
  if (offset + VOW_SIZE > buf.length) return null;
  const slab = buf.subarray(offset, offset + VOW_SIZE);
  const expect = crc32(slab.subarray(0, 124));
  const got = readCrc32(slab, 124);
  if (expect !== got) return null;
  const covLen = Math.min(slab[0], MAX_COVENANT);
  const geasN = Math.min(slab[1], MAX_GEAS);
  let covenant = "";
  try {
    covenant = new TextDecoder("utf-8", { fatal: true }).decode(slab.subarray(2, 2 + covLen)).replace(/[\u0000]/g, "");
  } catch {
    covenant = "";
  }
  const geas: Uint8Array[] = [];
  for (let i = 0; i < geasN; i++) geas.push(slab.slice(50 + i * 32, 50 + (i + 1) * 32));
  return { covenant, geas };
}

export function applyVow(header: Sg1Header, vow: { covenant: string; geas: Uint8Array[] } | null): Sg1Header {
  if (!vow) return header;
  return { ...header, vow: true, covenant: vow.covenant, geas: vow.geas };
}

function scorePrefix(file: Uint8Array, header: Sg1Header, prefix: number): number {
  if (prefix < 0) return -1;
  const stride = shardStride(header);
  const body = file.subarray(prefix);
  let live = 0;
  for (let i = 0; i < header.n; i++) {
    const off = i * stride;
    const payload = off + (header.ember ? HEADER_SIZE : 0) + (header.vow ? VOW_SIZE : 0);
    if (payload + header.shardLen + SHARD_CRC > body.length) continue;
    const bytes = body.subarray(payload, payload + header.shardLen);
    const crc = readCrc32(body, payload + header.shardLen);
    if (crc32(bytes) === crc) live++;
  }
  return live;
}

function locateFromEmber(file: Uint8Array): HeaderFix | null {
  const hits: { header: Sg1Header; offset: number }[] = [];
  for (let i = 0; i + HEADER_SIZE <= file.length; i++) {
    if (
      file[i] !== MAGIC_EMBER[0] ||
      file[i + 1] !== MAGIC_EMBER[1] ||
      file[i + 2] !== MAGIC_EMBER[2] ||
      file[i + 3] !== MAGIC_EMBER[3]
    ) {
      continue;
    }
    const h = tryReadEmberAt(file, i);
    if (h?.ember) hits.push({ header: h, offset: i });
  }
  let best: HeaderFix | null = null;
  let bestScore = -1;
  for (const hit of hits) {
    const stride = shardStride(hit.header);
    if (stride <= 0) continue;
    const prefixes = new Set<number>([0, KEYSTONE_SPAN, KEYSTONE_SPAN + VOW_SIZE]);
    for (let i = 0; i < hit.header.n; i++) {
      const p = hit.offset - i * stride;
      if (p >= 0) prefixes.add(p);
    }
    for (const prefix of prefixes) {
      const score = scorePrefix(file, hit.header, prefix);
      if (score > bestScore) {
        bestScore = score;
        best = {
          header: applyVow(hit.header, hit.header.vow ? readVow(file, hit.offset + HEADER_SIZE) : null),
          prefix,
          slot: 4,
          recovered: true,
          source: "ember",
        };
      }
    }
  }
  if (best && bestScore >= 0) return best;
  return null;
}

/** Find a living header. Slot 0 is the front; 1–3 are Keystone copies; pieces hold Embers. */
export function locateHeader(file: Uint8Array): HeaderFix {
  const primary = tryReadHeaderAt(file, 0);
  if (primary) {
    const vow = primary.vow ? readVow(file, primary.keystone ? KEYSTONE_SPAN : HEADER_SIZE) : null;
    return {
      header: applyVow(primary, vow),
      prefix: bodyPrefix(primary),
      slot: 0,
      recovered: false,
      source: "primary",
    };
  }
  for (let slot = 1; slot <= KEYSTONE_COPIES; slot++) {
    const h = tryReadHeaderAt(file, slot * HEADER_SIZE);
    if (h?.keystone) {
      const vow = h.vow ? readVow(file, KEYSTONE_SPAN) : null;
      return { header: applyVow(h, vow), prefix: bodyPrefix(h), slot, recovered: true, source: "keystone" };
    }
  }
  const hunt = Math.min(file.length, 8192);
  for (let i = 1; i < hunt; i++) {
    if (
      file[i] !== MAGIC[0] ||
      file[i + 1] !== MAGIC[1] ||
      file[i + 2] !== MAGIC[2] ||
      file[i + 3] !== MAGIC[3]
    ) {
      continue;
    }
    const h = tryReadHeaderAt(file, i);
    if (h) {
      const vow = h.vow ? readVow(file, i + (h.keystone ? KEYSTONE_SPAN : HEADER_SIZE)) : null;
      return {
        header: applyVow(h, vow),
        prefix: i + bodyPrefix(h),
        slot: 0,
        recovered: true,
        source: "keystone",
      };
    }
  }
  const ember = locateFromEmber(file);
  if (ember) return ember;
  throw new Error(
    "The header (the map at the front of the file) is damaged, and no Keystone or Ember survived.",
  );
}

export function wrapKeystone(header: Uint8Array): Uint8Array {
  const out = new Uint8Array(KEYSTONE_SPAN);
  for (let i = 0; i <= KEYSTONE_COPIES; i++) out.set(header, i * HEADER_SIZE);
  return out;
}

/** Zero the front 160 bytes. Spare copies stay. Used by the lab’s Shatter Keystone. */
export function shatterPrimary(file: Uint8Array): Uint8Array {
  const out = new Uint8Array(file);
  const n = Math.min(HEADER_SIZE, out.length);
  out.fill(0, 0, n);
  if (n > 0) out[0] = 0x58;
  return out;
}

export function shatterAllKeystones(file: Uint8Array): Uint8Array {
  const out = new Uint8Array(file);
  out.fill(0, 0, Math.min(KEYSTONE_SPAN, out.length));
  if (out.length > 0) out[0] = 0x58;
  return out;
}

export function buildFlags(
  mode: ResilienceMode,
  compressed: boolean,
  encrypted: boolean,
  graph = false,
  keystone = true,
  ember = true,
  vow = false,
): number {
  let f = modeFlag(mode);
  if (compressed) f |= FLAG_COMPRESSED;
  if (encrypted) f |= FLAG_ENCRYPTED;
  if (graph) f |= FLAG_GRAPH;
  if (keystone) f |= FLAG_KEYSTONE;
  if (ember) f |= FLAG_EMBER;
  if (vow) f |= FLAG_VOW;
  return f;
}

export function paramsFor(mode: ResilienceMode) {
  return MODE_PARAMS[mode];
}
