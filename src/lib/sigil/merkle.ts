import { hex, sha256 } from "./crypto";

/** SHA-256 parent: H(left || right). Odd last leaf is duplicated. */
export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  let layer = leaves.map((l) => l);
  while (layer.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const a = layer[i];
      const b = layer[i + 1] ?? a;
      const cat = new Uint8Array(a.length + b.length);
      cat.set(a);
      cat.set(b, a.length);
      next.push(await sha256(cat));
    }
    layer = next;
  }
  return layer[0];
}

export async function shardLeaves(shards: Uint8Array[]): Promise<Uint8Array[]> {
  const out: Uint8Array[] = [];
  for (const s of shards) out.push(await sha256(s));
  return out;
}

export async function shardMerkle(shards: Uint8Array[]): Promise<{
  root: Uint8Array;
  leaves: Uint8Array[];
  hexes: string[];
}> {
  const leaves = await shardLeaves(shards);
  const root = await merkleRoot(leaves);
  return { root, leaves, hexes: leaves.map((l) => hex(l, 8)) };
}

export function equal32(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length < 32 || b.length < 32) return false;
  for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return false;
  return true;
}
