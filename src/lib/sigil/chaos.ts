import { gfDiv, gfMul } from "./gf256";

/**
 * Deterministic chaos fold — rebuilt from ChaosRegenerationFlow
 * without the original's non-deterministic RNG XOR.
 *
 * Logistic map x_{n+1} = r x_n (1 - x_n), r = 3.99, x0 from π-mixed salt.
 * Three masks (π, φ, logistic) XOR a GF(256) multiply by a rotating prime.
 * Fully reversible given the same 16-byte salt.
 */

export const LOGISTIC_R = 3.99;
export const PI_SEED = 3141592653;
export const PHI_SEED = 1618033988;
export const E_SEED = 2718281828;
export const PRIMES = [0xfb, 0xf1, 0xef] as const; // 251, 241, 239 as field elements

function mix32(a: number, b: number): number {
  let x = (a ^ b) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x7feb352d);
  x = Math.imul(x ^ (x >>> 15), 0x846ca68b);
  return (x ^ (x >>> 16)) >>> 0;
}

export function logisticMask(seed: number, size: number, r = LOGISTIC_R): Uint8Array {
  let x = (seed >>> 0) / 4294967296;
  if (x < 1e-9) x = 0.3141592653589793;
  if (x > 1 - 1e-9) x = 0.2718281828459045;
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    x = r * x * (1 - x);
    if (x <= 0 || x >= 1 || Number.isNaN(x)) x = 0.5 + (i % 97) / 200;
    out[i] = Math.floor(x * 256) & 0xff;
  }
  return out;
}

export function deriveMasks(salt: Uint8Array, size: number) {
  const s0 = (salt[0] << 24) | (salt[1] << 16) | (salt[2] << 8) | salt[3];
  const s1 = (salt[4] << 24) | (salt[5] << 16) | (salt[6] << 8) | salt[7];
  const s2 = (salt[8] << 24) | (salt[9] << 16) | (salt[10] << 8) | salt[11];
  const pi = logisticMask(mix32(PI_SEED, s0 >>> 0), size);
  const phi = logisticMask(mix32(PHI_SEED, s1 >>> 0), size);
  const log = logisticMask(mix32(E_SEED, s2 >>> 0), size);
  const prime = PRIMES[salt[12] % PRIMES.length];
  return { pi, phi, log, prime };
}

export function chaosOrbit(seed: number, count: number, r = LOGISTIC_R): number[] {
  let x = (seed >>> 0) / 4294967296;
  if (x < 1e-9) x = 0.3141592653589793;
  const pts: number[] = [];
  for (let i = 0; i < count; i++) {
    x = r * x * (1 - x);
    pts.push(x);
  }
  return pts;
}

export function fold(data: Uint8Array, salt: Uint8Array): Uint8Array {
  const { pi, phi, log, prime } = deriveMasks(salt, data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    let b = data[i] ^ pi[i];
    b = gfMul(b === 0 ? 0 : b, prime);
    b ^= phi[i];
    out[i] = b;
  }
  if (out.length >= 2) {
    for (let i = 0; i + 1 < out.length; i += 2) {
      const t = out[i];
      out[i] = out[i + 1];
      out[i + 1] = t;
    }
  }
  for (let i = 0; i < out.length; i++) out[i] ^= log[i];
  return out;
}

export function unfold(data: Uint8Array, salt: Uint8Array): Uint8Array {
  const { pi, phi, log, prime } = deriveMasks(salt, data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ log[i];
  if (out.length >= 2) {
    for (let i = 0; i + 1 < out.length; i += 2) {
      const t = out[i];
      out[i] = out[i + 1];
      out[i + 1] = t;
    }
  }
  for (let i = 0; i < out.length; i++) {
    let b = out[i] ^ phi[i];
    b = b === 0 ? 0 : gfDiv(b, prime);
    out[i] = b ^ pi[i];
  }
  return out;
}
