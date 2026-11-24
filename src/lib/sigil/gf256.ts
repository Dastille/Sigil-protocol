/** GF(2^8) with AES/QR primitive polynomial 0x11d. */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

let ready = false;

function init() {
  if (ready) return;
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  LOG[0] = 0;
  ready = true;
}

init();

export function gfAdd(a: number, b: number): number {
  return a ^ b;
}

export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

export function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error("gf256: division by zero");
  if (a === 0) return 0;
  return EXP[LOG[a] + 255 - LOG[b]];
}

export function gfInv(a: number): number {
  if (a === 0) throw new Error("gf256: inverse of zero");
  return EXP[255 - LOG[a]];
}

export function gfPow(a: number, n: number): number {
  if (n === 0) return 1;
  if (a === 0) return 0;
  return EXP[(LOG[a] * (n % 255)) % 255];
}

/** Horner evaluation of polynomial `coeff[0] + coeff[1] x + ...` at `x`. */
export function gfPolyEval(coeff: Uint8Array, x: number): number {
  let y = 0;
  for (let i = coeff.length - 1; i >= 0; i--) {
    y = gfMul(y, x) ^ coeff[i];
  }
  return y;
}

/**
 * Solve Vandermonde system V c = y over GF(256),
 * V[i][j] = x[i]^j, returning coefficients c of degree < k.
 */
export function gfSolveVandermonde(xs: Uint8Array, ys: Uint8Array): Uint8Array {
  const k = xs.length;
  if (k !== ys.length) throw new Error("vandermonde: length mismatch");
  const a: number[][] = Array.from({ length: k }, () => new Array<number>(k + 1).fill(0));
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
    if (pivot === k) throw new Error("vandermonde: singular matrix");
    if (pivot !== col) {
      const tmp = a[col];
      a[col] = a[pivot];
      a[pivot] = tmp;
    }
    const inv = gfInv(a[col][col]);
    for (let j = col; j <= k; j++) a[col][j] = gfMul(a[col][j], inv);
    for (let row = 0; row < k; row++) {
      if (row === col) continue;
      const f = a[row][col];
      if (f === 0) continue;
      for (let j = col; j <= k; j++) {
        a[row][j] ^= gfMul(f, a[col][j]);
      }
    }
  }

  const c = new Uint8Array(k);
  for (let i = 0; i < k; i++) c[i] = a[i][k];
  return c;
}
