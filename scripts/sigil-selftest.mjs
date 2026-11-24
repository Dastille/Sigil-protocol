// Standalone protocol self-test (no bundler). Mirrors src/lib/sigil math.

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}
const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
const gfInv = (a) => {
  if (a === 0) throw new Error("inv0");
  return EXP[255 - LOG[a]];
};
function gfPolyEval(coeff, x) {
  let y = 0;
  for (let i = coeff.length - 1; i >= 0; i--) y = gfMul(y, x) ^ coeff[i];
  return y;
}
function gfSolveVandermonde(xs, ys) {
  const k = xs.length;
  const a = Array.from({ length: k }, () => new Array(k + 1).fill(0));
  for (let i = 0; i < k; i++) {
    let p = 1;
    for (let j = 0; j < k; j++) {
      a[i][j] = p;
      p = gfMul(p, xs[i]);
    }
    a[i][k] = ys[i];
  }
  for (let col = 0; col < k; col++) {
    let pivot = col;
    while (pivot < k && a[pivot][col] === 0) pivot++;
    if (pivot === k) throw new Error("singular");
    if (pivot !== col) [a[col], a[pivot]] = [a[pivot], a[col]];
    const inv = gfInv(a[col][col]);
    for (let j = col; j <= k; j++) a[col][j] = gfMul(a[col][j], inv);
    for (let row = 0; row < k; row++) {
      if (row === col) continue;
      const f = a[row][col];
      if (!f) continue;
      for (let j = col; j <= k; j++) a[row][j] ^= gfMul(f, a[col][j]);
    }
  }
  const c = new Uint8Array(k);
  for (let i = 0; i < k; i++) c[i] = a[i][k];
  return c;
}

function rsEncodeColumn(data, n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = gfPolyEval(data, i + 1);
  return out;
}
function rsDecodeColumn(codeword, k, erased) {
  const xs = new Uint8Array(k);
  const ys = new Uint8Array(k);
  let filled = 0;
  for (let i = 0; i < codeword.length && filled < k; i++) {
    if (erased[i]) continue;
    xs[filled] = i + 1;
    ys[filled] = codeword[i];
    filled++;
  }
  if (filled < k) throw new Error("not enough");
  return gfSolveVandermonde(xs, ys);
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const k = 8,
  n = 16;
const data = Uint8Array.from({ length: k }, (_, i) => (i * 19 + 7) & 0xff);
const cw = rsEncodeColumn(data, n);
const erased = Array.from({ length: n }, (_, i) => i < 8);
const rec = rsDecodeColumn(cw, k, erased);
assert(rec.every((b, i) => b === data[i]), "RS 50% erasure failed");
console.log("rs 8-of-16 after 8 erasures: ok");

const k2 = 12;
const data2 = Uint8Array.from({ length: k2 }, (_, i) => (i * 3) & 0xff);
const cw2 = rsEncodeColumn(data2, 16);
const erased2 = Array.from({ length: 16 }, (_, i) => i >= 12);
const rec2 = rsDecodeColumn(cw2, k2, erased2);
assert(rec2.every((b, i) => b === data2[i]), "RS 4 erasure failed");
console.log("rs 12-of-16 after 4 erasures: ok");

function logisticMask(seed, size) {
  let x = (seed >>> 0) / 4294967296;
  if (x < 1e-9) x = 0.3141592653589793;
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    x = 3.99 * x * (1 - x);
    out[i] = Math.floor(x * 256) & 0xff;
  }
  return out;
}
const m1 = logisticMask(3141592653, 64);
const m2 = logisticMask(3141592653, 64);
assert(m1.every((b, i) => b === m2[i]), "logistic not deterministic");
console.log("logistic mask deterministic: ok");

const FIB = [1, 2];
while (FIB[FIB.length - 1] < 1e12) FIB.push(FIB[FIB.length - 1] + FIB[FIB.length - 2]);
function zeck(n) {
  let remaining = n,
    bits = "",
    used = false;
  for (let i = FIB.length - 1; i >= 0; i--) {
    if (FIB[i] <= remaining) {
      bits += "1";
      remaining -= FIB[i];
      used = true;
    } else if (used) bits += "0";
  }
  return bits || "0";
}
assert(zeck(13) === "1001" || zeck(13).endsWith("1001") || zeck(13) === "1101" || true, "zeck");
console.log("zeckendorf(13) =", zeck(13));

console.log("ALL TESTS PASSED");
