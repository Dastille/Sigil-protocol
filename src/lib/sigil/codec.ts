import { fold, unfold } from "./chaos";
import { maybeDeflate, inflate } from "./compress";
import { crc32, crc32bytes, readCrc32 } from "./crc32";
import { aesGcmOpen, aesGcmSeal, decryptAesGcm, hex, randomBytes, sha256 } from "./crypto";
import { buildSgtoPass, unwrapCekWithPass } from "./sgto";
import { shannonEntropy } from "./entropy";
import { residualGlyph } from "./fibonacci";
import {
  buildFlags,
  locateHeader,
  readHeader,
  shatterAllKeystones,
  shatterPrimary,
  shardStride,
  wrapKeystone,
  writeEmber,
  writeHeader,
  writeVow,
} from "./header";
import { equal32, shardMerkle } from "./merkle";
import { rsDecodeShards, rsEncodeShards, stripeShards, unstripeShards } from "./reedsolomon";
import {
  HEADER_SIZE,
  MAGIC_EMBER,
  MAX_BYTES,
  MAX_COVENANT,
  MAX_GEAS,
  MODE_PARAMS,
  SHARD_CRC,
  VOW_SIZE,
  type ResilienceMode,
  type SealResult,
  type ShardView,
  type UnsealResult,
  type VerifyResult,
} from "./types";

export { MODE_PARAMS, MAX_BYTES };
export type { ResilienceMode, SealResult, ShardView, UnsealResult, VerifyResult };
export { shatterAllKeystones, shatterPrimary };

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

function packShards(shards: Uint8Array[], header: Uint8Array, vow?: Uint8Array): Uint8Array {
  return concat(
    shards.map((s, i) => concat([writeEmber(header, i), vow ?? new Uint8Array(0), s, crc32bytes(s)])),
  );
}

function emptyView(index: number, shardLen: number): ShardView {
  return {
    index,
    bytes: new Uint8Array(shardLen),
    crc: 0,
    crcOk: false,
    parity: false,
    entropy: 0,
    leafHex: "",
  };
}

function unpackShards(
  body: Uint8Array,
  n: number,
  shardLen: number,
  ember = false,
  vow = false,
): { views: ShardView[]; live: (Uint8Array | null)[] } {
  const lead = (ember ? HEADER_SIZE : 0) + (vow ? VOW_SIZE : 0);
  const stride = lead + shardLen + SHARD_CRC;
  const views: ShardView[] = [];
  const live: (Uint8Array | null)[] = [];
  for (let i = 0; i < n; i++) {
    const off = i * stride + lead;
    if (off + shardLen + SHARD_CRC > body.length) {
      views.push(emptyView(i, shardLen));
      live.push(null);
      continue;
    }
    const bytes = body.slice(off, off + shardLen);
    const crc = readCrc32(body, off + shardLen);
    const crcOk = crc32(bytes) === crc;
    views.push({
      index: i,
      bytes,
      crc,
      crcOk,
      parity: false,
      entropy: shannonEntropy(bytes),
      leafHex: "",
    });
    live.push(crcOk ? bytes : null);
  }
  return { views, live };
}

function gatherFromEmberScan(
  file: Uint8Array,
  n: number,
  shardLen: number,
  vow: boolean,
): { views: ShardView[]; live: (Uint8Array | null)[] } {
  const lead = HEADER_SIZE + (vow ? VOW_SIZE : 0);
  const views: ShardView[] = Array.from({ length: n }, (_, i) => emptyView(i, shardLen));
  const live: (Uint8Array | null)[] = Array(n).fill(null);
  const hits: { slot: number; bytes: Uint8Array; crc: number; crcOk: boolean }[] = [];
  for (let i = 0; i + HEADER_SIZE <= file.length; i++) {
    if (
      file[i] !== MAGIC_EMBER[0] ||
      file[i + 1] !== MAGIC_EMBER[1] ||
      file[i + 2] !== MAGIC_EMBER[2] ||
      file[i + 3] !== MAGIC_EMBER[3]
    ) {
      continue;
    }
    const slotHint = file[i + 107];
    const off = i + lead;
    if (off + shardLen + SHARD_CRC > file.length) {
      i += HEADER_SIZE - 1;
      continue;
    }
    const bytes = file.slice(off, off + shardLen);
    const crc = readCrc32(file, off + shardLen);
    const crcOk = crc32(bytes) === crc;
    hits.push({ slot: slotHint, bytes, crc, crcOk });
    i += HEADER_SIZE - 1;
  }
  const unique = new Set(hits.filter((h) => h.crcOk && h.slot < n).map((h) => h.slot));
  const useOrder = unique.size < 2;
  hits.forEach((h, order) => {
    const slot = useOrder ? order : h.slot;
    if (slot < 0 || slot >= n) return;
    if (live[slot] && !h.crcOk) return;
    views[slot] = {
      index: slot,
      bytes: h.bytes,
      crc: h.crc,
      crcOk: h.crcOk,
      parity: false,
      entropy: shannonEntropy(h.bytes),
      leafHex: "",
    };
    live[slot] = h.crcOk ? h.bytes : null;
  });
  return { views, live };
}

function pickShardViews(
  file: Uint8Array,
  prefix: number,
  n: number,
  shardLen: number,
  ember: boolean,
  vow: boolean,
): { views: ShardView[]; live: (Uint8Array | null)[] } {
  const stride = unpackShards(file.subarray(prefix), n, shardLen, ember, vow);
  if (!ember) return stride;
  const scanned = gatherFromEmberScan(file, n, shardLen, vow);
  const views = stride.views.map((v, i) => {
    if (v.crcOk) return v;
    const s = scanned.views[i];
    if (s?.crcOk) return s;
    return v;
  });
  return { views, live: views.map((v) => (v.crcOk ? v.bytes : null)) };
}

/**
 * Writers for new encrypted seals, by format name. `ENCRYPTED_WRITE_FORMAT` must name what
 * Rust `main` writes today (`lib.rs` seal_kn_mds_to + `keys.rs` build_sgto): a random content
 * key encrypts the folded body (AES-256-GCM, header nonce and tag), and an SGTO v2 block
 * after the Keystone wraps that key with an Argon2id passphrase record. When the format
 * changes, add a writer here and point `ENCRYPTED_WRITE_FORMAT` at it; readers for old
 * formats stay in `unseal` / `sgto.ts`.
 */
type EncryptedWriter = (
  folded: Uint8Array,
  pass: string,
  nonce: Uint8Array,
) => Promise<{ cipher: Uint8Array; tag: Uint8Array; sgto: Uint8Array }>;

const ENCRYPTED_WRITERS: Record<string, EncryptedWriter> = {
  "sgto-v2-argon2id": async (folded, pass, nonce) => {
    const cek = randomBytes(32);
    const { cipher, tag } = await aesGcmSeal(cek, nonce, folded);
    const sgto = await buildSgtoPass(cek, pass);
    cek.fill(0);
    return { cipher, tag, sgto };
  },
};

export const ENCRYPTED_WRITE_FORMAT = "sgto-v2-argon2id";

export async function seal(opts: {
  data: Uint8Array;
  mode: ResilienceMode;
  passphrase?: string;
  name?: string;
  graph?: boolean;
  covenant?: string;
  geas?: Uint8Array[];
}): Promise<SealResult> {
  if (opts.data.length > MAX_BYTES) {
    throw new Error(`this bench caps a single mark at ${MAX_BYTES} bytes`);
  }
  const { k, n } = MODE_PARAMS[opts.mode];
  const digest = await sha256(opts.data);
  const salt = randomBytes(16);
  const shrunk = await maybeDeflate(opts.data);
  const folded = fold(shrunk.bytes, salt);
  let payload = folded;
  let nonce = new Uint8Array(12);
  let tag = new Uint8Array(16);
  let encrypted = false;
  let sgto: Uint8Array = new Uint8Array(0);
  // As in Rust: an all-blank passphrase means "not encrypted"; otherwise it is used as typed.
  const pass = opts.passphrase ?? "";
  if (pass.trim()) {
    encrypted = true;
    nonce = new Uint8Array(randomBytes(12));
    const enc = await ENCRYPTED_WRITERS[ENCRYPTED_WRITE_FORMAT](payload, pass, nonce);
    payload = new Uint8Array(enc.cipher);
    tag = new Uint8Array(enc.tag);
    sgto = enc.sgto;
  }
  const shards =
    opts.mode === "glyph" ? stripeShards(payload, n) : rsEncodeShards(payload, k, n);
  const tree = await shardMerkle(shards);
  const cov = (opts.covenant ?? "").slice(0, MAX_COVENANT);
  const geas = (opts.geas ?? []).slice(0, MAX_GEAS);
  const hasVow = Boolean(cov || geas.length);
  const flags = buildFlags(opts.mode, shrunk.compressed, encrypted, opts.graph ?? false, true, true, hasVow);
  const header = writeHeader({
    flags,
    mode: opts.mode,
    k,
    n,
    origLen: opts.data.length,
    foldedLen: payload.length,
    digest,
    salt,
    nonce,
    tag,
    shardLen: shards[0]?.length ?? 1,
    entropyMilli: Math.round(shannonEntropy(opts.data) * 1000),
    compressed: shrunk.compressed,
    encrypted,
    graph: opts.graph ?? false,
    keystone: true,
    ember: true,
    vow: hasVow,
    covenant: cov,
    geas,
    name: opts.name ?? "",
    merkle: tree.root,
  });
  const vow = hasVow ? writeVow(cov, geas) : undefined;
  // SGTO sits after the Keystone and before the Vow, as in Rust.
  const bytes = concat([wrapKeystone(header), sgto, vow ?? new Uint8Array(0), packShards(shards, header, vow)]);
  const parsed = readHeader(header);
  if (hasVow) {
    parsed.vow = true;
    parsed.covenant = cov;
    parsed.geas = geas;
  }
  const { views } = unpackShards(
    bytes.subarray(bytes.length - shards.length * (HEADER_SIZE + (hasVow ? VOW_SIZE : 0) + shards[0].length + SHARD_CRC)),
    n,
    shards[0].length,
    true,
    hasVow,
  );
  for (let i = 0; i < views.length; i++) {
    views[i].parity = i >= k;
    views[i].leafHex = hex(tree.leaves[i] ?? new Uint8Array(32));
  }
  return {
    bytes,
    header: parsed,
    shards: views,
    stats: {
      orig: opts.data.length,
      compressed: shrunk.bytes.length,
      folded: folded.length,
      sealed: bytes.length,
      entropy: shannonEntropy(opts.data),
      ratio: bytes.length / Math.max(1, opts.data.length),
      repairBudget: n - k,
      usedCompression: shrunk.compressed,
      encrypted,
    },
    digestHex: hex(digest),
    merkleHex: hex(tree.root),
    residual: residualGlyph(digest),
  };
}

export async function unseal(
  file: Uint8Array,
  passphrase?: string,
  companions?: Uint8Array[],
): Promise<UnsealResult> {
  const { header, prefix, source, sgto } = locateHeader(file);
  if (header.geas.length) {
    const have = await Promise.all((companions ?? []).map((c) => sha256(c)));
    const need = header.geas;
    const ok = need.every((n) => have.some((h) => equal32(h, n)));
    if (!ok) throw new Error("Geas not met — companion missing or changed.");
  }
  const { views, live } = pickShardViews(
    file,
    prefix,
    header.n,
    header.shardLen,
    header.ember,
    header.vow,
  );
  for (const v of views) v.parity = v.index >= header.k;
  const repaired = views.filter((v) => !v.crcOk).map((v) => v.index);

  let folded: Uint8Array;
  if (header.mode === "glyph") folded = unstripeShards(live, header.foldedLen);
  else folded = rsDecodeShards(live, header.k, header.foldedLen, header.version >= 2);

  const pass = passphrase?.trim() ?? "";
  if (header.encrypted) {
    if (!pass) throw new Error("this seal is encrypted — a passphrase is required");
    if (sgto) {
      // Since PR #44 (and for encrypt-to): the SGTO block wraps a random content key.
      // Rust uses the passphrase as typed here; only the legacy Ward trims it.
      const cek = await unwrapCekWithPass(sgto, passphrase ?? "", header.salt);
      const open = await aesGcmOpen(cek, header.nonce, folded, header.tag);
      cek.fill(0);
      if (!open) throw new Error("unseal failed: wrong passphrase, or the payload is past repair");
      folded = open;
    } else {
      // Legacy Ward: PBKDF2-HMAC-SHA256 (80k) of the passphrase with the header salt.
      folded = await decryptAesGcm(folded, header.tag, pass, header.salt, header.nonce);
    }
  } else if (pass) {
    throw new Error("this seal was not encrypted; leave the passphrase empty");
  }

  const unfolded = unfold(folded, header.salt);
  const plain = header.compressed ? await inflate(unfolded) : unfolded;
  if (plain.length !== header.origLen) {
    throw new Error("length mismatch after unfold — the residual does not close");
  }
  const digest = await sha256(plain);
  for (let i = 0; i < 32; i++) {
    if (digest[i] !== header.digest[i]) {
      throw new Error("SHA-256 mismatch — regeneration produced a different object");
    }
  }

  let text: string | null = null;
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(plain);
    if (!decoded.includes("\u0000")) text = decoded;
  } catch {
    text = null;
  }

  return {
    data: plain,
    header,
    repaired,
    text,
    keystoneRecovered: source === "keystone",
    emberRecovered: source === "ember",
  };
}

export async function verify(file: Uint8Array): Promise<VerifyResult> {
  const { header, prefix, source } = locateHeader(file);
  const { views, live } = pickShardViews(
    file,
    prefix,
    header.n,
    header.shardLen,
    header.ember,
    header.vow,
  );
  const dead = views.filter((v) => !v.crcOk).map((v) => v.index);
  const liveCount = header.n - dead.length;
  const needed = header.k;
  const canRepair = liveCount >= needed;
  let merkleOk = false;
  if (dead.length === 0) {
    const shards = live.map((s) => s ?? new Uint8Array(header.shardLen));
    const tree = await shardMerkle(shards);
    merkleOk = equal32(tree.root, header.merkle);
  }
  const envelope = await sha256(file);
  return {
    header,
    live: liveCount,
    needed,
    canRepair,
    merkleOk,
    merkleHex: hex(header.merkle),
    trueNameHex: hex(header.digest),
    envelopeHex: hex(envelope),
    dead,
    graph: header.graph,
    keystone: source === "keystone" || source === "ember" ? "recovered" : header.keystone ? "intact" : "legacy",
    source,
  };
}

export function puncture(file: Uint8Array, indices: number[]): Uint8Array {
  const { header, prefix } = locateHeader(file);
  const stride = shardStride(header);
  const out = new Uint8Array(file);
  for (const i of indices) {
    if (i < 0 || i >= header.n) continue;
    const off = prefix + i * stride;
    out.fill(0, off, off + stride);
    out[off] = (i * 17 + 3) & 0xff;
  }
  return out;
}

export function inspectShards(file: Uint8Array): ShardView[] {
  const { header, prefix } = locateHeader(file);
  const { views } = pickShardViews(file, prefix, header.n, header.shardLen, header.ember, header.vow);
  for (const v of views) v.parity = v.index >= header.k;
  return views;
}

export async function selfTest(): Promise<string[]> {
  const log: string[] = [];
  const msg = new TextEncoder().encode("The river is a circle. What is lost can be folded back.");
  for (const mode of ["glyph", "reflection", "seal"] as ResilienceMode[]) {
    const sealed = await seal({ data: msg, mode, name: "circle.txt" });
    const round = await unseal(sealed.bytes);
    if (round.text !== new TextDecoder().decode(msg)) throw new Error(`${mode}: roundtrip failed`);
    const v = await verify(sealed.bytes);
    if (!v.merkleOk) throw new Error(`${mode}: merkle failed on intact seal`);
    log.push(`${mode}: roundtrip + merkle ok (${sealed.bytes.length} B)`);
    if (mode === "glyph") continue;
    const budget = MODE_PARAMS[mode].n - MODE_PARAMS[mode].k;
    const kill = Array.from({ length: budget }, (_, i) => i);
    const torn = puncture(sealed.bytes, kill);
    const check = await verify(torn);
    if (!check.canRepair) throw new Error(`${mode}: verify said unrepairable`);
    const regen = await unseal(torn);
    if (regen.text !== round.text) throw new Error(`${mode}: repair failed`);
    log.push(`${mode}: repaired ${budget} erased shards`);
  }
  const locked = await seal({ data: msg, mode: "seal", passphrase: "regent" });
  const open = await unseal(locked.bytes, "regent");
  if (open.text !== new TextDecoder().decode(msg)) throw new Error("encrypt roundtrip failed");
  const lockedVerify = await verify(locked.bytes);
  if (!lockedVerify.merkleOk) throw new Error("locked merkle failed");
  log.push("ward: roundtrip + merkle ok");

  const named = await seal({ data: msg, mode: "seal", name: "test.test.jpg" });
  const back = await unseal(named.bytes);
  if (back.header.name !== "test.test.jpg") throw new Error("multi-dot name lost");
  const shifted = new Uint8Array(named.bytes.length - 1);
  const mid = Math.floor(named.bytes.length / 2);
  shifted.set(named.bytes.subarray(0, mid));
  shifted.set(named.bytes.subarray(mid + 1), mid);
  const fromShift = await unseal(shifted);
  if (fromShift.text !== roundText(msg)) throw new Error("shifted-byte repair failed");
  log.push("name + one-byte delete repair ok");
  return log;
}

function roundText(msg: Uint8Array): string {
  return new TextDecoder().decode(msg);
}
