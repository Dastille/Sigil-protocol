/**
 * SGTO companion block: the key-wrap records that sit right after the Keystone in an
 * encrypted seal. Mirrors `crate/sigil/src/keys.rs` (build_sgto / read_sgto_at / unwrap_cek).
 *
 * Layout: "SGTO" | version u8 | count u8 | flags u8 | pad u8 | records… | CRC32 (LE) of all before.
 * Each record starts with a kind byte:
 *   1  X25519 recipient: hint(8) eph_pk(32) nonce(12) tag(16) ct(32)      (lab cannot open these)
 *   2  passphrase, PBKDF2-HMAC-SHA256 80k with the header salt: nonce(12) tag(16) ct(32)  (legacy, read only)
 *   3  passphrase, Argon2id: salt(16) m_kib u32 t u32 p u32 nonce(12) tag(16) ct(32)      (written since PR #44)
 *
 * To support a new format version, add it to `SGTO_VERSIONS`; to support a new record kind,
 * add an entry to `RECORD_KINDS` (its length, and an `open` if the lab can unwrap it).
 */
import { crc32, readCrc32 } from "./crc32";
import { aesGcmOpen, aesGcmSeal, argon2idBytes, pbkdf2Bytes, randomBytes } from "./crypto";

export const SGTO_MAGIC = new Uint8Array([0x53, 0x47, 0x54, 0x4f]); // SGTO
const SGTO_HEADER = 8;
const FLAG_HAS_PASS_WRAP = 1;

/** Versions this reader accepts (same set as the Rust reader). Unknown versions fail closed. */
export const SGTO_VERSIONS: ReadonlySet<number> = new Set([1, 2]);
export const SGTO_VERSION_ARGON2 = 2;

export const KIND_X25519 = 1;
export const KIND_PASS_PBKDF2 = 2;
export const KIND_PASS_ARGON2ID = 3;

/** New-file Argon2id defaults: OWASP minimum m=19456 KiB, t=2, p=1 (same as Rust `keys.rs`). */
export const ARGON2_M_KIB = 19_456;
export const ARGON2_T = 2;
export const ARGON2_P = 1;
/** Reader caps, identical to the Rust reader: a crafted file cannot demand unbounded work. */
export const ARGON2_MAX_M_KIB = 1 << 20;
export const ARGON2_MAX_T = 16;
export const ARGON2_MAX_P = 8;
export const ARGON2_MAX_WORK = 1 << 22;

type OpenFn = (rec: Uint8Array, pass: string, headerSalt: Uint8Array) => Promise<Uint8Array | null>;

const RECORD_KINDS: Record<number, { len: number; open?: OpenFn }> = {
  [KIND_X25519]: { len: 8 + 32 + 12 + 16 + 32 },
  [KIND_PASS_PBKDF2]: {
    len: 12 + 16 + 32,
    open: async (r, pass, headerSalt) => {
      const key = await pbkdf2Bytes(pass, headerSalt);
      return aesGcmOpen(key, r.subarray(0, 12), r.subarray(28, 60), r.subarray(12, 28));
    },
  },
  [KIND_PASS_ARGON2ID]: {
    len: 16 + 4 + 4 + 4 + 12 + 16 + 32,
    open: async (r, pass) => {
      const dv = new DataView(r.buffer, r.byteOffset, r.byteLength);
      const mKib = dv.getUint32(16, true);
      const t = dv.getUint32(20, true);
      const p = dv.getUint32(24, true);
      // Out-of-bounds parameters are an error, not a skip: fail closed (as Rust does).
      argon2ParamsOk(mKib, t, p);
      const key = await argon2idBytes(pass, r.subarray(0, 16), mKib, t, p);
      return aesGcmOpen(key, r.subarray(28, 40), r.subarray(56, 88), r.subarray(40, 56));
    },
  },
};

/** Validate stored Argon2id parameters against RFC 9106 minimums and Sigil's caps. */
export function argon2ParamsOk(mKib: number, t: number, p: number): void {
  const bad = (why: string) => new Error(`Argon2id wrap parameters rejected: ${why}`);
  if (t === 0 || p === 0 || mKib < 8 * p)
    throw bad("below RFC 9106 minimums (t >= 1, p >= 1, m >= 8p KiB)");
  if (mKib > ARGON2_MAX_M_KIB || t > ARGON2_MAX_T || p > ARGON2_MAX_P)
    throw bad("above Sigil's resource caps");
  if (mKib * t > ARGON2_MAX_WORK) throw bad("passes x memory above Sigil's work budget");
}

export type SgtoRecord = { kind: number; body: Uint8Array };
export type SgtoBlock = {
  bytes: Uint8Array;
  version: number;
  flags: number;
  records: SgtoRecord[];
};

/** Parse an SGTO block at `off`, or `null` if none is there (bad magic, version, length or CRC). */
export function readSgtoAt(file: Uint8Array, off: number): SgtoBlock | null {
  if (off < 0 || off + SGTO_HEADER > file.length) return null;
  for (let i = 0; i < 4; i++) if (file[off + i] !== SGTO_MAGIC[i]) return null;
  const version = file[off + 4];
  if (!SGTO_VERSIONS.has(version)) return null;
  const count = file[off + 5];
  const flags = file[off + 6];
  const records: SgtoRecord[] = [];
  let i = off + SGTO_HEADER;
  for (let r = 0; r < count; r++) {
    if (i >= file.length) return null;
    const kind = file[i];
    const spec = RECORD_KINDS[kind];
    if (!spec) return null;
    i += 1;
    if (i + spec.len > file.length) return null;
    records.push({ kind, body: file.subarray(i, i + spec.len) });
    i += spec.len;
  }
  if (i + 4 > file.length) return null;
  if (crc32(file.subarray(off, i)) !== readCrc32(file, i)) return null;
  return { bytes: file.subarray(off, i + 4), version, flags, records };
}

export function sgtoLenAt(file: Uint8Array, off: number): number {
  return readSgtoAt(file, off)?.bytes.length ?? 0;
}

/** True when the block holds a wrap for an X25519 recipient (needs a key file, not a passphrase). */
export function sgtoHasRecipients(block: SgtoBlock): boolean {
  return block.records.some((r) => r.kind === KIND_X25519);
}

/** Unwrap the 32-byte content key with a passphrase; throws when nothing opens (fail closed). */
export async function unwrapCekWithPass(
  block: SgtoBlock,
  pass: string,
  headerSalt: Uint8Array,
): Promise<Uint8Array> {
  let passRecords = 0;
  for (const rec of block.records) {
    const open = RECORD_KINDS[rec.kind]?.open;
    if (!open) continue;
    passRecords++;
    const cek = await open(rec.body, pass, headerSalt);
    if (cek && cek.length === 32) return cek;
  }
  if (passRecords === 0 && sgtoHasRecipients(block)) {
    throw new Error(
      "this seal is locked to recipients' keys; the lab can only open passphrase seals",
    );
  }
  throw new Error("unseal failed: wrong passphrase, or the payload is past repair");
}

/** Build the SGTO block Rust `main` writes for a passphrase-only seal: v2, one Argon2id record. */
export async function buildSgtoPass(cek: Uint8Array, pass: string): Promise<Uint8Array> {
  const salt = randomBytes(16);
  const key = await argon2idBytes(pass, salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P);
  const nonce = randomBytes(12);
  const { cipher, tag } = await aesGcmSeal(key, nonce, cek);
  if (cipher.length !== 32) throw new Error("unexpected CEK ciphertext length");
  const rec = new Uint8Array(1 + RECORD_KINDS[KIND_PASS_ARGON2ID].len);
  const dv = new DataView(rec.buffer);
  rec[0] = KIND_PASS_ARGON2ID;
  rec.set(salt, 1);
  dv.setUint32(17, ARGON2_M_KIB, true);
  dv.setUint32(21, ARGON2_T, true);
  dv.setUint32(25, ARGON2_P, true);
  rec.set(nonce, 29);
  rec.set(tag, 41);
  rec.set(cipher, 57);
  const out = new Uint8Array(SGTO_HEADER + rec.length + 4);
  out.set(SGTO_MAGIC, 0);
  out[4] = SGTO_VERSION_ARGON2;
  out[5] = 1;
  out[6] = FLAG_HAS_PASS_WRAP;
  out[7] = 0;
  out.set(rec, SGTO_HEADER);
  const crc = crc32(out.subarray(0, SGTO_HEADER + rec.length));
  new DataView(out.buffer).setUint32(SGTO_HEADER + rec.length, crc, true);
  return out;
}
