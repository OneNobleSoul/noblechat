import { test } from "node:test";
import assert from "node:assert/strict";
import {
  seal, open, randomBytes, utf8ToBytes, bytesToUtf8, timingSafeEqual,
  generateKemKeypair, kemPublicBundle, encapsulate, decapsulate,
  generateSignKeypair, signPublicBundle, sign, verify,
  randomUnitFloat, randomIndex, keysFingerprint,
} from "./src/index.js";

test("AEAD round-trips and rejects tampering", () => {
  const key = randomBytes(32);
  const msg = utf8ToBytes("hello aincrad");
  const sealed = seal(key, msg);
  assert.equal(bytesToUtf8(open(key, sealed)), "hello aincrad");
  sealed[sealed.length - 1] ^= 0x01; // flip a tag bit
  assert.throws(() => open(key, sealed));
});

test("hybrid KEM: both sides derive the same secret", () => {
  const bob = generateKemKeypair();
  const { header, sharedSecret } = encapsulate(kemPublicBundle(bob));
  const recovered = decapsulate(bob, header);
  assert.ok(timingSafeEqual(sharedSecret, recovered));
  assert.equal(sharedSecret.length, 32);
});

test("hybrid KEM: wrong recipient cannot recover the secret", () => {
  const bob = generateKemKeypair();
  const mallory = generateKemKeypair();
  const { header, sharedSecret } = encapsulate(kemPublicBundle(bob));
  const wrong = decapsulate(mallory, header);
  assert.ok(!timingSafeEqual(sharedSecret, wrong));
});

test("end-to-end: encapsulate then encrypt a message", () => {
  const bob = generateKemKeypair();
  const { header, sharedSecret } = encapsulate(kemPublicBundle(bob));
  const ct = seal(sharedSecret, utf8ToBytes("link start"));
  const bobSecret = decapsulate(bob, header);
  assert.equal(bytesToUtf8(open(bobSecret, ct)), "link start");
});

test("hybrid signatures verify and reject forgery", () => {
  const id = generateSignKeypair();
  const pub = signPublicBundle(id);
  const msg = utf8ToBytes("i am kirito");
  const sig = sign(id, msg);
  assert.ok(verify(pub, msg, sig));
  assert.ok(!verify(pub, utf8ToBytes("i am not kirito"), sig));
  // breaking only the classical half must still fail verification
  sig.ed[0] ^= 0x01;
  assert.ok(!verify(pub, msg, sig));
});

test("randomUnitFloat stays in [0,1) and varies", () => {
  let min = 1, max = 0; const seen = new Set();
  for (let i = 0; i < 5000; i++) {
    const v = randomUnitFloat();
    assert.ok(v >= 0 && v < 1, `out of range: ${v}`);
    min = Math.min(min, v); max = Math.max(max, v); seen.add(v);
  }
  assert.ok(seen.size > 4900, "should not repeat much"); // CSPRNG, not a constant
  assert.ok(min < 0.1 && max > 0.9, "should cover the range");
});

test("randomIndex is uniform-ish over [0,n) and never out of bounds", () => {
  assert.equal(randomIndex(1), 0);
  assert.equal(randomIndex(0), 0);
  const n = 5; const counts = new Array(n).fill(0);
  for (let i = 0; i < 20000; i++) {
    const x = randomIndex(n);
    assert.ok(Number.isInteger(x) && x >= 0 && x < n, `out of range: ${x}`);
    counts[x]++;
  }
  // every bucket hit, none wildly skewed (expected ~4000 each)
  for (const c of counts) assert.ok(c > 3000 && c < 5000, `skewed bucket: ${c}`);
});

test("keysFingerprint is order-independent and change-sensitive", () => {
  const k = (a, b) => ({ ed: new Uint8Array(a), dsa: new Uint8Array(b) });
  const set1 = [k([1, 2, 3], [4, 5]), k([9], [8])];
  const set2 = [set1[1], set1[0]]; // same keys, different order
  const set3 = [k([1, 2, 3], [4, 5]), k([9], [7])]; // one dsa byte changed
  assert.equal(keysFingerprint(set1), keysFingerprint(set2));
  assert.notEqual(keysFingerprint(set1), keysFingerprint(set3));
  assert.match(keysFingerprint(set1), /^[0-9a-f]{64}$/);
  assert.equal(keysFingerprint([]), keysFingerprint([]));
});
