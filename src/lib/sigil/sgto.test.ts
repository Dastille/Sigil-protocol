// Web lab passphrase seals vs the Rust CLI. Run: npm run test:lab
// Set SIGIL_BIN to a built `sigil` binary to also cross-check live in both directions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { seal, unseal } from "./codec";
import { locateHeader } from "./header";
import { crc32 } from "./crc32";
import { KEYSTONE_SPAN } from "./types";
import {
  ARGON2_M_KIB,
  ARGON2_P,
  ARGON2_T,
  KIND_PASS_ARGON2ID,
  readSgtoAt,
  SGTO_VERSION_ARGON2,
} from "./sgto";

const PASS = "correct horse battery";
const FIX = join(import.meta.dirname, "../../../crate/sigil/tests/fixtures");
const fx = (p: string) => new Uint8Array(readFileSync(join(FIX, p)));
const PLAIN2 = fx("kdf-v2/plain.txt");
const PLAIN0 = fx("kdf-v0/plain.bin");

/** SGTO span of a file: [offset, length]. */
function sgtoSpan(f: Uint8Array): [number, number] {
  const { sgto } = locateHeader(f);
  assert.ok(sgto, "expected an SGTO block");
  return [sgto.bytes.byteOffset - f.byteOffset, sgto.bytes.length];
}

/** Rewrite the SGTO CRC after a deliberate edit, so the edit reaches the KDF / AEAD. */
function fixCrc(f: Uint8Array, off: number, len: number) {
  new DataView(f.buffer, f.byteOffset).setUint32(
    off + len - 4,
    crc32(f.subarray(off, off + len - 4)),
    true,
  );
}

for (const name of [
  "pass-reflection.sg1",
  "pass-seal-vow.sg1",
  "pass-and-to.sg1",
]) {
  test(`opens Rust Argon2id seal ${name}`, async () => {
    const f = fx(`kdf-v2/${name}`);
    const [off] = sgtoSpan(f);
    assert.equal(f[off + 4], SGTO_VERSION_ARGON2);
    const out = await unseal(f, PASS);
    assert.deepEqual(out.data, PLAIN2);
    if (name.includes("vow")) assert.equal(out.header.covenant, "lab fixture");
  });

  test(`wrong passphrase fails closed: ${name}`, async () => {
    await assert.rejects(
      unseal(fx(`kdf-v2/${name}`), "wrong horse"),
      /wrong passphrase/,
    );
    await assert.rejects(
      unseal(fx(`kdf-v2/${name}`), ""),
      /passphrase is required/,
    );
  });
}

test("encrypt-to only seal is refused with a clear message", async () => {
  await assert.rejects(
    unseal(fx("kdf-v2/to-only.sg1"), PASS),
    /recipients' keys/,
  );
});

test("legacy PBKDF2 Ward (no SGTO) still opens", async () => {
  const f = fx("kdf-v0/ward-pbkdf2-80k.sg1");
  assert.equal(locateHeader(f).sgto, null);
  assert.deepEqual((await unseal(f, PASS)).data, PLAIN0);
  await assert.rejects(unseal(f, "wrong horse"));
});

test("legacy SGTO v1 PBKDF2 passphrase wrap still opens", async () => {
  const f = fx("kdf-v0/sgto-passwrap-pbkdf2-80k.sg1");
  const [off] = sgtoSpan(f);
  assert.equal(f[off + 4], 1);
  assert.deepEqual((await unseal(f, PASS)).data, PLAIN0);
  await assert.rejects(unseal(f, "wrong horse"));
});

test("tampered wrapped key fails closed", async () => {
  const f = fx("kdf-v2/pass-reflection.sg1");
  const [off, len] = sgtoSpan(f);
  f[off + 8 + 1 + 87] ^= 1; // last byte of the wrapped key
  fixCrc(f, off, len);
  await assert.rejects(unseal(f, PASS), /wrong passphrase/);
});

test("tampered SGTO without CRC fix fails closed", async () => {
  const f = fx("kdf-v2/pass-reflection.sg1");
  const [off] = sgtoSpan(f);
  f[off + 20] ^= 0xff;
  await assert.rejects(unseal(f, PASS));
});

test("Argon2id parameters above the Rust caps are rejected before hashing", async () => {
  const cases: [number, number, number][] = [
    [(1 << 20) + 1, 1, 1], // memory > 1 GiB
    [19_456, 17, 1], // passes > 16
    [19_456, 1, 9], // lanes > 8
    [1 << 20, 5, 1], // work budget 2^22 exceeded
    [7, 1, 1], // below RFC 9106 minimum m >= 8p
    [19_456, 0, 1], // t = 0
  ];
  for (const [m, t, p] of cases) {
    const f = fx("kdf-v2/pass-reflection.sg1");
    const [off, len] = sgtoSpan(f);
    const dv = new DataView(f.buffer, f.byteOffset);
    const rec = off + 8 + 1;
    dv.setUint32(rec + 16, m, true);
    dv.setUint32(rec + 20, t, true);
    dv.setUint32(rec + 24, p, true);
    fixCrc(f, off, len);
    await assert.rejects(
      unseal(f, PASS),
      /parameters rejected/,
      `m=${m} t=${t} p=${p}`,
    );
  }
});

test("lab writes what Rust main writes: SGTO v2, one Argon2id record, OWASP params", async () => {
  const msg = new TextEncoder().encode("lab round trip ".repeat(64));
  const s = await seal({
    data: msg,
    mode: "reflection",
    passphrase: PASS,
    name: "lab.txt",
  });
  const sg = readSgtoAt(s.bytes, KEYSTONE_SPAN);
  assert.ok(sg, "SGTO right after the Keystone");
  assert.equal(sg.version, SGTO_VERSION_ARGON2);
  assert.equal(sg.records.length, 1);
  assert.equal(sg.records[0].kind, KIND_PASS_ARGON2ID);
  const dv = new DataView(
    sg.records[0].body.buffer,
    sg.records[0].body.byteOffset,
  );
  assert.deepEqual(
    [dv.getUint32(16, true), dv.getUint32(20, true), dv.getUint32(24, true)],
    [ARGON2_M_KIB, ARGON2_T, ARGON2_P],
  );
  assert.deepEqual((await unseal(s.bytes, PASS)).data, msg);
  await assert.rejects(unseal(s.bytes, "wrong horse"), /wrong passphrase/);
  // Covenant (Vow) sits after SGTO and still reads back.
  const v = await seal({
    data: msg,
    mode: "seal",
    passphrase: PASS,
    covenant: "pact",
  });
  const back = await unseal(v.bytes, PASS);
  assert.equal(back.header.covenant, "pact");
  assert.deepEqual(back.data, msg);
});

const BIN = process.env.SIGIL_BIN;
test(
  "live cross-check with the Rust binary (SIGIL_BIN)",
  { skip: !BIN && "SIGIL_BIN not set" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "sigil-lab-"));
    const msg = new TextEncoder().encode(
      "from the lab to the CLI ".repeat(100),
    );
    // The CLI refuses a literal --pass VALUE: hand it owner-only passphrase files.
    const passFile = join(dir, "pass");
    const wrongFile = join(dir, "wrong");
    writeFileSync(passFile, PASS + "\n", { mode: 0o600 });
    writeFileSync(wrongFile, "wrong horse\n", { mode: 0o600 });
    // Lab writes, Rust reads.
    for (const mode of ["reflection", "seal", "glyph"] as const) {
      const s = await seal({
        data: msg,
        mode,
        passphrase: PASS,
        name: "lab.txt",
      });
      writeFileSync(join(dir, `lab-${mode}.sg1`), s.bytes);
      execFileSync(BIN!, [
        "unseal",
        "--pass-file",
        passFile,
        "-o",
        join(dir, `out-${mode}`),
        join(dir, `lab-${mode}.sg1`),
      ]);
      assert.deepEqual(
        new Uint8Array(readFileSync(join(dir, `out-${mode}`))),
        msg,
      );
      assert.throws(() =>
        execFileSync(
          BIN!,
          [
            "unseal",
            "--pass-file",
            wrongFile,
            "-o",
            join(dir, "nope"),
            join(dir, `lab-${mode}.sg1`),
          ],
          {
            stdio: "pipe",
          },
        ),
      );
    }
    // Rust writes (fresh, from this binary), lab reads.
    writeFileSync(join(dir, "in.txt"), msg);
    assert.throws(() =>
      execFileSync(
        BIN!,
        [
          "seal",
          "--pass",
          PASS,
          "-o",
          join(dir, "lit.sg1"),
          join(dir, "in.txt"),
        ],
        {
          stdio: "pipe",
        },
      ),
    );
    assert.throws(() => readFileSync(join(dir, "lit.sg1")));
    execFileSync(BIN!, [
      "seal",
      "--pass-file",
      passFile,
      "-o",
      join(dir, "rust.sg1"),
      join(dir, "in.txt"),
    ]);
    const f = new Uint8Array(readFileSync(join(dir, "rust.sg1")));
    assert.deepEqual((await unseal(f, PASS)).data, msg);
    await assert.rejects(unseal(f, "wrong horse"));
  },
);

test("lab encrypted seals use the private label (v3) and fail closed on label edits", async () => {
  const msg = new TextEncoder().encode(
    "private label from the lab ".repeat(50),
  );
  const s = await seal({
    data: msg,
    mode: "reflection",
    passphrase: PASS,
    name: "secret-name.txt",
  });
  const { header } = locateHeader(s.bytes);
  assert.equal(header.version, 3);
  assert.equal(header.origLen, 0);
  assert.equal(header.name, "");
  const sha = new Uint8Array(await crypto.subtle.digest("SHA-256", msg));
  const has = (n: Uint8Array) => {
    outer: for (let i = 0; i + n.length <= s.bytes.length; i++) {
      for (let j = 0; j < n.length; j++)
        if (s.bytes[i + j] !== n[j]) continue outer;
      return true;
    }
    return false;
  };
  assert.ok(!has(sha), "plaintext SHA-256 visible");
  assert.ok(!has(new TextEncoder().encode("secret-name")), "name visible");
  const back = await unseal(s.bytes, PASS);
  assert.deepEqual(back.data, msg);
  assert.equal(back.header.name, "secret-name.txt");
  // Rewrite the original-length field in every label copy with fresh CRCs: refused.
  const t = new Uint8Array(s.bytes);
  for (let o = 0; o + 160 <= t.length; o++) {
    const m = String.fromCharCode(t[o], t[o + 1], t[o + 2], t[o + 3]);
    if ((m === "SGIL" && o % 160 === 0 && o < KEYSTONE_SPAN) || m === "SGEM") {
      t[o + 8] ^= 1;
      t.fill(0, o + 108, o + 112);
      new DataView(t.buffer).setUint32(
        o + 108,
        crc32(t.subarray(o, o + 160)),
        true,
      );
    }
  }
  await assert.rejects(unseal(t, PASS));
  await assert.rejects(unseal(s.bytes, "wrong horse"));
});
