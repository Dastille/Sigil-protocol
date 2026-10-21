/**
 * Private label (header v3) for encrypted marks. Mirrors `crate/sigil/src/privacy.rs`:
 * name, sizes, entropy and plaintext SHA-256 travel in an SGIN block inside the
 * AES-256-GCM plaintext; the 160-byte label is associated data; the true-name slot
 * holds a keyed fingerprint, HMAC-SHA-256 (RFC 2104) under HKDF-SHA-256 (RFC 5869).
 */
import { hkdfSha256, hmacSha256 } from "./crypto";
import { HEADER_SIZE } from "./types";

const enc = new TextEncoder();
const INNER_MAGIC = enc.encode("SGIN");
const INNER_VERSION = 1;
export const INNER_FIXED = 72;
const FP_INFO = enc.encode("sigil v3 keyed fingerprint");
const AAD_DOMAIN = enc.encode("sigil v3 label\0");
const IF_COMPRESSED = 1;
const IF_SHARED_FP = 2;

export interface InnerMeta {
  name: string;
  origLen: number;
  bodyLen: number;
  digest: Uint8Array;
  entropyMilli: number;
  compressed: boolean;
  groupTotal: number;
  sharedFingerprint: boolean;
}

/** Associated data: domain || label with magic forced to SGIL and post-encryption fields zeroed. */
export function labelAad(header: Uint8Array): Uint8Array {
  if (header.length < HEADER_SIZE) throw new Error("truncated header");
  const base = AAD_DOMAIN.length;
  const aad = new Uint8Array(base + HEADER_SIZE);
  aad.set(AAD_DOMAIN, 0);
  aad.set(header.subarray(0, HEADER_SIZE), base);
  aad.set(enc.encode("SGIL"), base);
  aad.fill(0, base + 84, base + 112);
  aad.fill(0, base + 128, base + 160);
  return aad;
}

export async function perFileFingerprint(cek: Uint8Array, salt: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await hkdfSha256(cek, salt, FP_INFO);
  const fp = await hmacSha256(key, data);
  key.fill(0);
  return fp;
}

function putU64(b: Uint8Array, at: number, v: number): void {
  new DataView(b.buffer, b.byteOffset).setBigUint64(at, BigInt(v), true);
}

function getU64(b: Uint8Array, at: number): number {
  const v = new DataView(b.buffer, b.byteOffset).getBigUint64(at, true);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("private label: length out of range");
  return Number(v);
}

export function writeInner(m: InnerMeta): Uint8Array {
  const nb = enc.encode(m.name).subarray(0, 0xffff);
  const b = new Uint8Array(INNER_FIXED + nb.length);
  b.set(INNER_MAGIC, 0);
  b[4] = INNER_VERSION;
  b[5] = (m.compressed ? IF_COMPRESSED : 0) | (m.sharedFingerprint ? IF_SHARED_FP : 0);
  new DataView(b.buffer).setUint16(6, nb.length, true);
  putU64(b, 8, m.origLen);
  putU64(b, 16, m.bodyLen);
  b.set(m.digest.subarray(0, 32), 24);
  new DataView(b.buffer).setUint32(56, m.entropyMilli, true);
  putU64(b, 60, m.groupTotal);
  b.set(nb, INNER_FIXED);
  return b;
}

/** Parse the inner block; returns metadata and the body offset. Padding after the body must be zero. */
export function readInner(plain: Uint8Array): { meta: InnerMeta; bodyOff: number } {
  const bad = (s: string) => new Error(`private label: ${s}`);
  if (plain.length < INNER_FIXED || !INNER_MAGIC.every((c, i) => plain[i] === c)) throw bad("inner block missing");
  if (plain[4] !== INNER_VERSION) throw bad("unknown inner block version");
  const dv = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const nlen = dv.getUint16(6, true);
  const origLen = getU64(plain, 8);
  const bodyLen = getU64(plain, 16);
  const bodyOff = INNER_FIXED + nlen;
  if (bodyOff > plain.length) throw bad("name runs past the end");
  const bodyEnd = bodyOff + bodyLen;
  if (bodyEnd > plain.length) throw bad("body runs past the end");
  for (let i = bodyEnd; i < plain.length; i++) if (plain[i] !== 0) throw bad("padding is not zero");
  let name: string;
  try {
    name = new TextDecoder("utf-8", { fatal: true }).decode(plain.subarray(INNER_FIXED, bodyOff));
  } catch {
    throw bad("name is not UTF-8");
  }
  return {
    meta: {
      name,
      origLen,
      bodyLen,
      digest: plain.slice(24, 56),
      entropyMilli: dv.getUint32(56, true),
      compressed: (plain[5] & IF_COMPRESSED) !== 0,
      groupTotal: getU64(plain, 60),
      sharedFingerprint: (plain[5] & IF_SHARED_FP) !== 0,
    },
    bodyOff,
  };
}
