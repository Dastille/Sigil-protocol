import { gfPolyEval, gfSolveVandermonde } from "./gf256";

/**
 * v1: coefficients of p(x) are the data; symbols are p(1)…p(n).
 * v2: first k shards ARE the data (systematic); the rest are extra evaluations.
 */

export function rsEncodeColumn(data: Uint8Array, n: number): Uint8Array {
  const k = data.length;
  if (n < k) throw new Error("rs: n must be >= k");
  if (n > 255) throw new Error("rs: n must be < 256");
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = gfPolyEval(data, i + 1);
  }
  return out;
}

export function rsDecodeColumn(
  codeword: Uint8Array,
  k: number,
  erased: boolean[],
): Uint8Array {
  const n = codeword.length;
  const xs = new Uint8Array(k);
  const ys = new Uint8Array(k);
  let filled = 0;
  for (let i = 0; i < n && filled < k; i++) {
    if (erased[i]) continue;
    xs[filled] = i + 1;
    ys[filled] = codeword[i];
    filled++;
  }
  if (filled < k) {
    throw new Error(
      `rs: need ${k} live shards, have ${filled} (${n - erased.filter(Boolean).length} surviving of ${n})`,
    );
  }
  return gfSolveVandermonde(xs, ys);
}

export function rsEncodeShards(
  payload: Uint8Array,
  k: number,
  n: number,
  systematic = true,
): Uint8Array[] {
  if (k < 1 || n < k) throw new Error("rs: invalid k,n");
  const shardLen = Math.ceil(payload.length / k) || 1;
  const padded = new Uint8Array(shardLen * k);
  padded.set(payload);

  const shards = Array.from({ length: n }, () => new Uint8Array(shardLen));
  const col = new Uint8Array(k);
  const xs = new Uint8Array(k);
  for (let i = 0; i < k; i++) xs[i] = i + 1;
  for (let s = 0; s < shardLen; s++) {
    for (let i = 0; i < k; i++) col[i] = padded[i * shardLen + s];
    if (systematic) {
      const coeffs = gfSolveVandermonde(xs, col);
      for (let i = 0; i < k; i++) shards[i][s] = col[i];
      for (let i = k; i < n; i++) shards[i][s] = gfPolyEval(coeffs, i + 1);
    } else {
      const coded = rsEncodeColumn(col, n);
      for (let i = 0; i < n; i++) shards[i][s] = coded[i];
    }
  }
  return shards;
}

export function rsDecodeShards(
  shards: (Uint8Array | null)[],
  k: number,
  payloadLen: number,
  systematic = true,
): Uint8Array {
  const n = shards.length;
  const erased = shards.map((s) => s == null);
  const live = shards.find((s) => s != null);
  if (!live) throw new Error("rs: no surviving shards");
  const shardLen = live.length;
  const surviving = n - erased.filter(Boolean).length;
  if (surviving < k) {
    throw new Error(
      `rs: ${surviving} of ${n} shards survive; need ${k} (lost ${Math.round(((n - surviving) / n) * 100)}%)`,
    );
  }

  if (systematic && shards.slice(0, k).every((s) => s != null)) {
    const padded = new Uint8Array(shardLen * k);
    for (let i = 0; i < k; i++) padded.set(shards[i]!.subarray(0, shardLen), i * shardLen);
    return padded.slice(0, payloadLen);
  }

  const padded = new Uint8Array(shardLen * k);
  const col = new Uint8Array(n);
  for (let s = 0; s < shardLen; s++) {
    for (let i = 0; i < n; i++) {
      col[i] = shards[i] ? shards[i]![s] : 0;
    }
    const coeffs = rsDecodeColumn(col, k, erased);
    if (systematic) {
      for (let i = 0; i < k; i++) padded[i * shardLen + s] = gfPolyEval(coeffs, i + 1);
    } else {
      for (let i = 0; i < k; i++) padded[i * shardLen + s] = coeffs[i];
    }
  }
  return padded.slice(0, payloadLen);
}

/** Stripe payload across n shards with no parity (Glyph mode). */
export function stripeShards(payload: Uint8Array, n: number): Uint8Array[] {
  const shardLen = Math.ceil(payload.length / n) || 1;
  const padded = new Uint8Array(shardLen * n);
  padded.set(payload);
  return Array.from({ length: n }, (_, i) => padded.slice(i * shardLen, (i + 1) * shardLen));
}

export function unstripeShards(
  shards: (Uint8Array | null)[],
  payloadLen: number,
): Uint8Array {
  if (shards.some((s) => s == null)) {
    const missing = shards.map((s, i) => (s == null ? i : -1)).filter((i) => i >= 0);
    throw new Error(
      `glyph: shard${missing.length === 1 ? "" : "s"} ${missing.join(", ")} missing — Glyph has no parity`,
    );
  }
  const parts = shards as Uint8Array[];
  const out = new Uint8Array(parts.reduce((n, s) => n + s.length, 0));
  let o = 0;
  for (const s of parts) {
    out.set(s, o);
    o += s.length;
  }
  return out.slice(0, payloadLen);
}
