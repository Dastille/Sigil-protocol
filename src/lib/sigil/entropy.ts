/** Shannon entropy in bits per byte. H = -Σ p_i log2(p_i) */
export function shannonEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) counts[data[i]]++;
  const len = data.length;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c === 0) continue;
    const p = c / len;
    h -= p * Math.log2(p);
  }
  return h;
}

export function entropyMilli(data: Uint8Array): number {
  return Math.round(shannonEntropy(data) * 1000);
}

export function histogram(data: Uint8Array): number[] {
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < data.length; i++) counts[data[i]]++;
  return counts;
}
