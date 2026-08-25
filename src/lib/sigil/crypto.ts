const PBKDF2_ITERS = 80_000;

function toBuf(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", toBuf(data));
  return new Uint8Array(digest);
}

export function hex(data: Uint8Array, n = data.length): string {
  const take = Math.min(n, data.length);
  let s = "";
  for (let i = 0; i < take; i++) s += data[i].toString(16).padStart(2, "0");
  return s;
}

export async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    "raw",
    toBuf(new TextEncoder().encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: toBuf(salt), iterations: PBKDF2_ITERS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptAesGcm(
  data: Uint8Array,
  passphrase: string,
  salt: Uint8Array,
  nonce: Uint8Array,
): Promise<{ cipher: Uint8Array; tag: Uint8Array }> {
  const key = await deriveKey(passphrase, salt);
  const packed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: toBuf(nonce), tagLength: 128 }, key, toBuf(data)),
  );
  return {
    cipher: packed.subarray(0, packed.length - 16),
    tag: packed.subarray(packed.length - 16),
  };
}

export async function decryptAesGcm(
  cipher: Uint8Array,
  tag: Uint8Array,
  passphrase: string,
  salt: Uint8Array,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  const key = await deriveKey(passphrase, salt);
  const packed = new Uint8Array(cipher.length + tag.length);
  packed.set(cipher);
  packed.set(tag, cipher.length);
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toBuf(nonce), tagLength: 128 },
      key,
      toBuf(packed),
    );
    return new Uint8Array(plain);
  } catch {
    throw new Error("unseal failed: wrong passphrase, or the payload is past repair");
  }
}
