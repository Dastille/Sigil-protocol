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

/** Raw 32-byte PBKDF2-HMAC-SHA256 key (legacy Ward and legacy SGTO passphrase wraps). */
export async function pbkdf2Bytes(passphrase: string, salt: Uint8Array, iterations = PBKDF2_ITERS): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey(
    "raw",
    toBuf(new TextEncoder().encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: toBuf(salt), iterations, hash: "SHA-256" },
    base,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Argon2id (RFC 9106, version 0x13) to a 32-byte key, via hash-wasm (maintained, audited
 * reference C code compiled to WebAssembly, no native addon). Loaded on first use so the
 * WebAssembly is only fetched when a passphrase seal is made or opened.
 */
export async function argon2idBytes(
  passphrase: string,
  salt: Uint8Array,
  mKib: number,
  t: number,
  p: number,
): Promise<Uint8Array> {
  const { argon2id } = await import("hash-wasm");
  return argon2id({
    password: new TextEncoder().encode(passphrase),
    salt,
    parallelism: p,
    iterations: t,
    memorySize: mKib,
    hashLength: 32,
    outputType: "binary",
  });
}

async function aesKey(raw: Uint8Array, use: KeyUsage): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toBuf(raw), { name: "AES-GCM" }, false, [use]);
}

/** AES-256-GCM under a raw key: returns ciphertext and 16-byte tag separately (Sigil layout). */
export async function aesGcmSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
): Promise<{ cipher: Uint8Array; tag: Uint8Array }> {
  const k = await aesKey(key, "encrypt");
  const packed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: toBuf(nonce), tagLength: 128 }, k, toBuf(data)),
  );
  return { cipher: packed.slice(0, packed.length - 16), tag: packed.slice(packed.length - 16) };
}

/** AES-256-GCM open under a raw key; `null` when the tag does not verify (fail closed). */
export async function aesGcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  cipher: Uint8Array,
  tag: Uint8Array,
): Promise<Uint8Array | null> {
  const k = await aesKey(key, "decrypt");
  const packed = new Uint8Array(cipher.length + tag.length);
  packed.set(cipher);
  packed.set(tag, cipher.length);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: toBuf(nonce), tagLength: 128 }, k, toBuf(packed)),
    );
  } catch {
    return null;
  }
}
