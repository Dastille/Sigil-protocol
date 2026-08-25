/** Zeckendorf representation — every integer as a unique sum of non-adjacent Fibonaccis. */

const FIB: number[] = [1, 2];
while (FIB[FIB.length - 1] < Number.MAX_SAFE_INTEGER / 2) {
  FIB.push(FIB[FIB.length - 1] + FIB[FIB.length - 2]);
}

export function zeckendorf(n: number): string {
  if (n <= 0) return "0";
  let remaining = Math.floor(n);
  let bits = "";
  let used = false;
  for (let i = FIB.length - 1; i >= 0; i--) {
    if (FIB[i] <= remaining) {
      bits += "1";
      remaining -= FIB[i];
      used = true;
    } else if (used) {
      bits += "0";
    }
  }
  return bits || "0";
}

export function zeckendorfOfHash(hash: Uint8Array): string {
  let n = 0;
  const take = Math.min(6, hash.length);
  for (let i = 0; i < take; i++) n = n * 256 + hash[i];
  return zeckendorf(n);
}

export function decodeZeckendorf(bits: string): number {
  const s = bits.replace(/^0+/, "") || "0";
  if (s === "0") return 0;
  let n = 0;
  const start = s.length - 1;
  for (let i = 0; i < s.length; i++) {
    if (s[start - i] === "1") n += FIB[i] ?? 0;
  }
  return n;
}

export function residualGlyph(hash: Uint8Array): string {
  const bits = zeckendorfOfHash(hash);
  return bits.replace(/1/g, "▮").replace(/0/g, "▯");
}
