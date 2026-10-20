export type ResilienceMode = "glyph" | "reflection" | "seal";

export interface ModeSpec {
  k: number;
  n: number;
  label: string;
  metaphor: string;
  layout: string;
  loss: string;
  cost: string;
  blurb: string;
  essence: string;
  useful: string[];
  survives: string;
  fails: string;
  example: string;
}

export const MODES: ResilienceMode[] = ["glyph", "reflection", "seal"];

export const MODE_PARAMS: Record<ResilienceMode, ModeSpec> = {
  glyph: {
    k: 16,
    n: 16,
    label: "Glyph",
    metaphor: "Fingerprint",
    layout: "16 data · 0 spare",
    loss: "detect only",
    cost: "smallest",
    blurb: "Checks that nothing changed. It cannot repair a damaged file.",
    essence:
      "Use Glyph when you need proof, not repair. It is the smallest mark. If any piece is missing or damaged, it stops and will not rebuild the file.",
    useful: [
      "Evidence you must prove untouched — a court packet, a dump, a contract",
      "A file you already keep a second copy of",
      "When you care more about a small file than about repair",
    ],
    survives: "Works if the copy is complete and unchanged.",
    fails: "If even one piece is damaged, it stops. It will not rebuild missing bytes.",
    example: "You keep a Glyph of a contract. Later, Scry tells you it is still the same file.",
  },
  reflection: {
    k: 12,
    n: 16,
    label: "Reflection",
    metaphor: "QR code",
    layout: "12 data · 4 spare",
    loss: "25% repair",
    cost: "~1.3×",
    blurb: "Can rebuild the file if up to 4 of 16 pieces are lost or damaged.",
    essence:
      "Use Reflection for USB sticks, email, and bad connections. The mark is a bit larger. Any 12 of the 16 pieces are enough to get the original back.",
    useful: [
      "Sending a file across a channel that routinely drops or corrupts blocks",
      "Everyday copies where a little extra size is fine",
      "When you want repair without doubling the file",
    ],
    survives: "Any 12 of 16 pieces. About 25% damage is OK.",
    fails: "If 5 or more pieces are dead, it stops. It will not guess.",
    example: "You send a dump over a flaky connection. A quarter of it is garbled. Reflection still gives the file back.",
  },
  seal: {
    k: 8,
    n: 16,
    label: "Seal",
    metaphor: "Vault",
    layout: "8 data · 8 spare",
    loss: "50% repair",
    cost: "~2×",
    blurb: "Can rebuild the file if up to 8 of 16 pieces are lost. About twice the size.",
    essence:
      "Use Seal when this is the only copy that matters. Half the pieces can vanish and you can still get the original back. Folders (constellations) are packed as a Seal.",
    useful: [
      "Archives you cannot replace — keys-adjacent notes, photos, a disk image slice",
      "Backups on a cheap disk, a USB in a drawer, or a machine you do not trust",
      "A file you want a constellation to be able to rebuild",
    ],
    survives: "Any 8 of 16 pieces. About 50% damage is OK.",
    fails: "If 9 or more pieces are dead, it stops. It will not guess.",
    example: "The only export of an archive. The USB is half-corrupt. Seal still gives the file back.",
  },
};

export const MAGIC = new Uint8Array([0x53, 0x47, 0x49, 0x4c]); // SGIL
export const MAGIC_EMBER = new Uint8Array([0x53, 0x47, 0x45, 0x4d]); // SGEM
export const VERSION = 2;
/** Private label: new encrypted marks (name, size, SHA-256 inside the AEAD). */
export const PRIVATE_VERSION = 3;
export const HEADER_SIZE = 160;
export const KEYSTONE_COPIES = 3;
/** Primary header + spare copies. Pieces start here on new marks. */
export const KEYSTONE_SPAN = HEADER_SIZE * (1 + KEYSTONE_COPIES);
/** Covenant + Geas slab after the map (and after each Ember). */
export const VOW_SIZE = 128;
export const MAX_GEAS = 2;
export const MAX_COVENANT = 48;
export const SHARD_CRC = 4;
export const MAX_BYTES = 1_500_000;
export const GRAPH_MAGIC = new Uint8Array([0x53, 0x49, 0x47, 0x47]); // SIGG
export const ATLAS_MAGIC = new Uint8Array([0x41, 0x54, 0x4c, 0x53]); // ATLS
/** Plaintext per star when a file is too big for one mark. */
export const CHUNK_PLAIN = 384 * 1024;
export const MAX_STARS = 32;
export const MAX_WORK = CHUNK_PLAIN * MAX_STARS;

export const FLAG_COMPRESSED = 1 << 0;
export const FLAG_ENCRYPTED = 1 << 1;
export const FLAG_GRAPH = 1 << 4;
export const FLAG_KEYSTONE = 1 << 5;
export const FLAG_EMBER = 1 << 6;
export const FLAG_VOW = 1 << 7;

export function modeFlag(mode: ResilienceMode): number {
  if (mode === "reflection") return 1 << 2;
  if (mode === "seal") return 2 << 2;
  return 0;
}

export function flagMode(flags: number): ResilienceMode {
  const m = (flags >> 2) & 0b11;
  if (m === 1) return "reflection";
  if (m === 2) return "seal";
  return "glyph";
}

export interface Sg1Header {
  version: number;
  flags: number;
  mode: ResilienceMode;
  k: number;
  n: number;
  origLen: number;
  foldedLen: number;
  digest: Uint8Array;
  salt: Uint8Array;
  nonce: Uint8Array;
  tag: Uint8Array;
  shardLen: number;
  entropyMilli: number;
  compressed: boolean;
  encrypted: boolean;
  graph: boolean;
  keystone: boolean;
  ember: boolean;
  vow: boolean;
  covenant: string;
  geas: Uint8Array[];
  name: string;
  merkle: Uint8Array;
}

export interface ShardView {
  index: number;
  bytes: Uint8Array;
  crc: number;
  crcOk: boolean;
  parity: boolean;
  entropy: number;
  leafHex: string;
}

export interface SealStats {
  orig: number;
  compressed: number;
  folded: number;
  sealed: number;
  entropy: number;
  ratio: number;
  repairBudget: number;
  usedCompression: boolean;
  encrypted: boolean;
}

export interface SealResult {
  bytes: Uint8Array;
  header: Sg1Header;
  shards: ShardView[];
  stats: SealStats;
  digestHex: string;
  merkleHex: string;
  residual: string;
}

export interface UnsealResult {
  data: Uint8Array;
  header: Sg1Header;
  repaired: number[];
  text: string | null;
  keystoneRecovered: boolean;
  emberRecovered: boolean;
}

export interface VerifyResult {
  header: Sg1Header;
  live: number;
  needed: number;
  canRepair: boolean;
  merkleOk: boolean;
  merkleHex: string;
  trueNameHex: string;
  envelopeHex: string;
  dead: number[];
  graph: boolean;
  keystone: "intact" | "recovered" | "legacy";
  source: "primary" | "keystone" | "ember";
}
