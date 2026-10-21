import { puncture, seal, unseal } from "./codec";
import {
  ATLAS_MAGIC,
  CHUNK_PLAIN,
  GRAPH_MAGIC,
  MAX_BYTES,
  MAX_STARS,
  MAX_WORK,
  type ResilienceMode,
  type SealResult,
} from "./types";

export { CHUNK_PLAIN, MAX_STARS, MAX_WORK };

export interface GraphMember {
  id: string;
  name: string;
  bytes: Uint8Array;
  digestHex: string;
  merkleHex: string;
  mode: ResilienceMode;
  origLen: number;
  index: number;
  total: number;
}

export interface WorkSpec {
  fileName: string;
  totalOrig: number;
  chunkSize: number;
}

export interface ChartSpec {
  title: string;
  work: WorkSpec | null;
  members: GraphMember[];
  embedded: boolean;
}

function u16(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}
function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}
function u64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, n >>> 0, true);
  dv.setUint32(4, Math.floor(n / 0x100000000), true);
  return b;
}
function readU16(b: Uint8Array, o: number): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint16(o, true);
}
function readU32(b: Uint8Array, o: number): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(o, true);
}
function readU64(b: Uint8Array, o: number): number {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return dv.getUint32(o, true) + dv.getUint32(o + 4, true) * 0x100000000;
}
function concat(parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function encName(s: string, max = 255): Uint8Array {
  return new TextEncoder().encode(s).slice(0, max);
}

function memberOf(partial: Omit<GraphMember, "id" | "index" | "total"> & { index?: number; total?: number }): GraphMember {
  return {
    ...partial,
    id: partial.digestHex,
    index: partial.index ?? 0,
    total: partial.total ?? 1,
  };
}

/** SIGG v2 chart. v1 packed graphs still open. */
export function packGraph(members: GraphMember[], opts?: { title?: string; work?: WorkSpec | null; embed?: boolean }): Uint8Array {
  return packChart({
    title: opts?.title ?? "constellation",
    work: opts?.work ?? null,
    members,
    embedded: opts?.embed !== false,
  });
}

export function packChart(spec: ChartSpec): Uint8Array {
  if (spec.members.length < 1) throw new Error("constellation is empty");
  if (spec.members.length > MAX_STARS) throw new Error(`constellation cap is ${MAX_STARS} stars`);
  const title = encName(spec.title || "constellation");
  const fileName = encName(spec.work?.fileName ?? "");
  const parts: Uint8Array[] = [
    GRAPH_MAGIC,
    new Uint8Array([2, spec.embedded ? 1 : 0]),
    u16(spec.members.length),
    new Uint8Array([title.length]),
    title,
    new Uint8Array([fileName.length]),
    fileName,
    u64(spec.work?.totalOrig ?? 0),
    u32(spec.work?.chunkSize ?? 0),
  ];
  for (const m of spec.members) {
    const name = encName(m.name);
    const digest = hexToBytes(m.digestHex);
    const merkle = hexToBytes(m.merkleHex);
    const has = spec.embedded && m.bytes.length > 0;
    const flags = (has ? 1 : 0) | (m.total > 1 ? 2 : 0);
    const head = new Uint8Array(1 + 1 + name.length + 32 + 32 + 4 + 4 + 1 + 2 + 2);
    let o = 0;
    head[o++] = flags;
    head[o++] = name.length;
    head.set(name, o);
    o += name.length;
    head.set(digest, o);
    o += 32;
    head.set(merkle, o);
    o += 32;
    head.set(u32(m.origLen), o);
    o += 4;
    head.set(u32(has ? m.bytes.length : 0), o);
    o += 4;
    head[o++] = m.mode === "seal" ? 2 : m.mode === "reflection" ? 1 : 0;
    head.set(u16(m.index), o);
    o += 2;
    head.set(u16(m.total), o);
    parts.push(head);
    if (has) parts.push(m.bytes);
  }
  return concat(parts);
}

export function unpackGraph(data: Uint8Array): GraphMember[] {
  return unpackChart(data).members;
}

export function unpackChart(data: Uint8Array): ChartSpec {
  if (data.length < 8) throw new Error("not a constellation");
  if (data[0] !== 0x53 || data[1] !== 0x49 || data[2] !== 0x47 || data[3] !== 0x47) {
    throw new Error("not a constellation (missing SIGG)");
  }
  const version = data[4];
  if (version === 1) return unpackV1(data);
  if (version !== 2) throw new Error(`unknown constellation version ${version}`);
  const embedded = data[5] === 1;
  const count = readU16(data, 6);
  let o = 8;
  const titleLen = data[o++];
  const title = new TextDecoder().decode(data.subarray(o, o + titleLen));
  o += titleLen;
  const fnLen = data[o++];
  const fileName = new TextDecoder().decode(data.subarray(o, o + fnLen));
  o += fnLen;
  const totalOrig = readU64(data, o);
  o += 8;
  const chunkSize = readU32(data, o);
  o += 4;
  const members: GraphMember[] = [];
  for (let i = 0; i < count; i++) {
    const flags = data[o++];
    const has = (flags & 1) !== 0;
    const nameLen = data[o++];
    const name = new TextDecoder().decode(data.subarray(o, o + nameLen));
    o += nameLen;
    const digest = data.subarray(o, o + 32);
    o += 32;
    const merkle = data.subarray(o, o + 32);
    o += 32;
    const origLen = readU32(data, o);
    o += 4;
    const sealedLen = readU32(data, o);
    o += 4;
    const modeByte = data[o++];
    const index = readU16(data, o);
    o += 2;
    const total = readU16(data, o);
    o += 2;
    const bytes = has ? data.slice(o, o + sealedLen) : new Uint8Array(0);
    if (has) o += sealedLen;
    const digestHex = bytesToHex(digest);
    members.push({
      id: digestHex,
      name,
      bytes,
      digestHex,
      merkleHex: bytesToHex(merkle),
      mode: modeByte === 2 ? "seal" : modeByte === 1 ? "reflection" : "glyph",
      origLen,
      index,
      total,
    });
  }
  return {
    title: title || "constellation",
    work: totalOrig > 0 && fileName ? { fileName, totalOrig, chunkSize } : null,
    members,
    embedded,
  };
}

function unpackV1(data: Uint8Array): ChartSpec {
  const count = data[5];
  const members: GraphMember[] = [];
  let o = 8;
  for (let i = 0; i < count; i++) {
    const byteLen = readU32(data, o);
    o += 4;
    const nameLen = data[o++];
    const name = new TextDecoder().decode(data.subarray(o, o + nameLen));
    o += nameLen;
    const digest = data.subarray(o, o + 32);
    o += 32;
    const merkle = data.subarray(o, o + 32);
    o += 32;
    const origLen = readU32(data, o);
    o += 8;
    const modeByte = data[o++];
    const bytes = data.slice(o, o + byteLen);
    o += byteLen;
    const digestHex = bytesToHex(digest);
    members.push({
      id: digestHex,
      name,
      bytes,
      digestHex,
      merkleHex: bytesToHex(merkle),
      mode: modeByte === 2 ? "seal" : modeByte === 1 ? "reflection" : "glyph",
      origLen,
      index: i,
      total: count,
    });
  }
  return { title: "constellation", work: null, members, embedded: true };
}

export function chartFitsPacked(members: GraphMember[]): boolean {
  const total = members.reduce((s, m) => s + m.bytes.length, 0);
  return total > 0 && total + 2048 < MAX_BYTES;
}

export async function sealGraph(members: GraphMember[], passphrase?: string, title = "constellation"): Promise<SealResult> {
  return sealChart({ title, work: null, members, embedded: chartFitsPacked(members) }, passphrase);
}

export async function sealChart(spec: ChartSpec, passphrase?: string): Promise<SealResult> {
  const packed = packChart(spec);
  if (packed.length > MAX_BYTES) {
    if (spec.embedded) {
      return sealChart({ ...spec, embedded: false }, passphrase);
    }
    throw new Error("chart is too large to inscribe");
  }
  return seal({
    data: packed,
    mode: "seal",
    passphrase,
    name: `${spec.title || "constellation"}.sg1`,
    graph: true,
  });
}

export async function openGraph(file: Uint8Array, passphrase?: string): Promise<GraphMember[]> {
  return (await openChart(file, passphrase)).members;
}

export async function openChart(file: Uint8Array, passphrase?: string): Promise<ChartSpec> {
  const out = await unseal(file, passphrase);
  return unpackChart(out.data);
}

export async function inscribeWork(
  data: Uint8Array,
  opts: {
    mode: ResilienceMode;
    passphrase?: string;
    name: string;
    chunkSize?: number;
    onStar?: (i: number, n: number) => void;
  },
): Promise<{ members: GraphMember[]; work: WorkSpec }> {
  if (data.length > MAX_WORK) {
    throw new Error(`file is ${data.length} bytes; constellation cap is ${MAX_WORK.toLocaleString()}`);
  }
  const chunkSize = opts.chunkSize ?? CHUNK_PLAIN;
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += chunkSize) chunks.push(data.subarray(i, i + chunkSize));
  if (chunks.length > MAX_STARS) throw new Error(`needs ${chunks.length} stars; cap is ${MAX_STARS}`);
  const members: GraphMember[] = [];
  for (let i = 0; i < chunks.length; i++) {
    opts.onStar?.(i + 1, chunks.length);
    const sealed = await seal({
      data: chunks[i],
      mode: opts.mode,
      passphrase: opts.passphrase,
      name: `${opts.name}.star${String(i).padStart(2, "0")}`,
    });
    members.push(
      memberOf({
        name: `${opts.name} · star ${i + 1}/${chunks.length}`,
        bytes: sealed.bytes,
        digestHex: sealed.digestHex,
        merkleHex: sealed.merkleHex,
        mode: opts.mode,
        origLen: chunks[i].length,
        index: i,
        total: chunks.length,
      }),
    );
  }
  return {
    members,
    work: { fileName: opts.name, totalOrig: data.length, chunkSize },
  };
}

export async function assembleWork(
  members: GraphMember[],
  work: WorkSpec,
  passphrase?: string,
): Promise<Uint8Array> {
  const ordered = [...members].sort((a, b) => a.index - b.index);
  if (ordered.some((m) => m.bytes.length === 0)) {
    throw new Error("this chart has no stars attached — drop the star files or an atlas first");
  }
  const parts: Uint8Array[] = [];
  for (const m of ordered) {
    const out = await unseal(m.bytes, passphrase);
    parts.push(out.data);
  }
  const plain = concat(parts);
  if (plain.length !== work.totalOrig) {
    throw new Error("assembled length does not match the chart");
  }
  return plain;
}

export function packAtlas(chart: Uint8Array, members: GraphMember[], title: string): Uint8Array {
  const files: { name: string; bytes: Uint8Array }[] = [
    { name: `${title || "chart"}.sg1`, bytes: chart },
  ];
  for (const m of members) {
    if (m.bytes.length === 0) continue;
    files.push({ name: `${m.digestHex.slice(0, 12)}.sg1`, bytes: m.bytes });
  }
  const parts: Uint8Array[] = [ATLAS_MAGIC, new Uint8Array([1]), u16(files.length)];
  for (const f of files) {
    const name = encName(f.name);
    parts.push(new Uint8Array([name.length]), name, u32(f.bytes.length), f.bytes);
  }
  return concat(parts);
}

export function unpackAtlas(data: Uint8Array): { name: string; bytes: Uint8Array }[] {
  if (data.length < 7 || data[0] !== 0x41 || data[1] !== 0x54 || data[2] !== 0x4c || data[3] !== 0x53) {
    throw new Error("not an atlas");
  }
  const version = data[4];
  if (version === 1) {
    const count = readU16(data, 5);
    return readAtlasFiles(data, 7, count, 4);
  }
  if (version === 2) {
    if (data.length < 9) throw new Error("truncated atlas");
    const count = readU32(data, 5);
    return readAtlasFiles(data, 9, count, 8);
  }
  throw new Error("unknown atlas version");
}

function readAtlasFiles(
  data: Uint8Array,
  start: number,
  count: number,
  sizeBytes: 4 | 8,
): { name: string; bytes: Uint8Array }[] {
  let o = start;
  const files: { name: string; bytes: Uint8Array }[] = [];
  for (let i = 0; i < count; i++) {
    const nameLen = data[o++];
    const name = new TextDecoder().decode(data.subarray(o, o + nameLen));
    o += nameLen;
    const size = sizeBytes === 8 ? readU64(data, o) : readU32(data, o);
    o += sizeBytes;
    files.push({ name, bytes: data.slice(o, o + size) });
    o += size;
  }
  return files;
}

export function isAtlas(data: Uint8Array): boolean {
  return data.length >= 4 && data[0] === 0x41 && data[1] === 0x54 && data[2] === 0x4c && data[3] === 0x53;
}

export async function graphSelfTest(): Promise<string[]> {
  const log: string[] = [];
  const a = await seal({ data: new TextEncoder().encode("alpha"), mode: "glyph", name: "a.txt" });
  const b = await seal({ data: new TextEncoder().encode("beta"), mode: "reflection", name: "b.txt" });
  const starA = memberOf({
    name: "a.txt",
    bytes: a.bytes,
    digestHex: a.digestHex,
    merkleHex: a.merkleHex,
    mode: "glyph",
    origLen: a.stats.orig,
  });
  const starB = memberOf({
    name: "b.txt",
    bytes: b.bytes,
    digestHex: b.digestHex,
    merkleHex: b.merkleHex,
    mode: "reflection",
    origLen: b.stats.orig,
  });
  const packed = await sealGraph([starA, starB]);
  if (!packed.header.graph) throw new Error("graph flag missing");
  const torn = puncture(packed.bytes, [0, 1, 2, 3, 4, 5, 6, 7]);
  const members = await openGraph(torn);
  if (members.length !== 2) throw new Error("graph member count");
  const roundA = await unseal(members[0].bytes);
  const roundB = await unseal(members[1].bytes);
  if (roundA.text !== "alpha" || roundB.text !== "beta") throw new Error("graph member unfold");
  log.push("constellation: packed, half-erased, members unfolded");

  const orion = packChart({ title: "Orion", work: null, members: [starA, starB], embedded: false });
  const lyra = packChart({ title: "Lyra", work: null, members: [starA], embedded: false });
  const o = unpackChart(orion);
  const l = unpackChart(lyra);
  if (o.members[0].digestHex !== l.members[0].digestHex) throw new Error("shared star true name drifted");
  if (o.members.length !== 2 || l.members.length !== 1) throw new Error("shared membership");
  log.push("constellation: same star in two charts");

  const payload = new Uint8Array(90);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 7 + 3) & 0xff;
  const work = await inscribeWork(payload, { mode: "reflection", name: "dump.bin", chunkSize: 40 });
  if (work.members.length !== 3) throw new Error("chunk count");
  const back = await assembleWork(work.members, work.work);
  if (back.length !== 90 || back[10] !== payload[10] || back[89] !== payload[89]) {
    throw new Error("chunk assemble");
  }
  const chart = await sealChart({
    title: "dump.bin",
    work: work.work,
    members: work.members,
    embedded: false,
  });
  const atlas = packAtlas(chart.bytes, work.members, "dump.bin");
  const files = unpackAtlas(atlas);
  if (files.length !== 4) throw new Error("atlas file count");
  log.push("constellation: chunked work + atlas roundtrip");
  return log;
}

function hexToBytes(h: string): Uint8Array {
  const clean = h.replace(/[^0-9a-f]/gi, "");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32 && i * 2 + 1 < clean.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}
