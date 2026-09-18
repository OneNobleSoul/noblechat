import { test } from "node:test";
import assert from "node:assert/strict";
import {
  seal, open, randomBytes, utf8ToBytes, bytesToUtf8, timingSafeEqual,
  generateKemKeypair, kemPublicBundle, encapsulate, decapsulate,
  generateSignKeypair, signPublicBundle, sign, verify,
  randomUnitFloat, randomIndex, keysFingerprint, poissonDelay,
  toB64, fromB64, toHex, fromHex, concatBytes,
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

test("poissonDelay is never negative and averages out near its mean", () => {
  assert.equal(poissonDelay(0), 0);
  let sum = 0; const n = 20000; const mean = 40;
  for (let i = 0; i < n; i++) {
    const d = poissonDelay(mean);
    assert.ok(d >= 0, `negative delay: ${d}`);
    sum += d;
  }
  const avg = sum / n;
  // exponential distribution: sample mean converges to the parameter, allow
  // generous slack since this is a statistical test, not an exact one
  assert.ok(avg > mean * 0.85 && avg < mean * 1.15, `sample mean ${avg} far from ${mean}`);
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

// toB64/fromB64 carry every key, card, and message payload across the wire
// and into localStorage, yet had no direct test anywhere - a round-trip bug
// here would silently corrupt everything downstream instead of failing loud.
test("toB64/fromB64 round-trip arbitrary bytes, including every byte value and empty input", () => {
  assert.equal(toB64(new Uint8Array(0)), "");
  assert.deepEqual(fromB64(""), new Uint8Array(0));
  const full = new Uint8Array(256);
  for (let i = 0; i < 256; i++) full[i] = i;
  assert.deepEqual(fromB64(toB64(full)), full);
  const random = randomBytes(97); // odd length, forces base64 padding
  assert.deepEqual(fromB64(toB64(random)), random);
});

// toB64/fromB64 branch on `typeof Buffer` to also work in a browser, where
// there is no Buffer and only atob/btoa exist. That branch never runs under
// Node's own test runner otherwise, since Node always has Buffer - hide it
// the same way tests/keystore.test.js hides indexedDB to reach its fallback.
test("toB64/fromB64 round-trip the same way without Buffer, as in a real browser", () => {
  const hadBuffer = "Buffer" in globalThis;
  const prevBuffer = globalThis.Buffer;
  delete globalThis.Buffer;
  try {
    const random = randomBytes(33);
    const b64 = toB64(random);
    assert.equal(typeof b64, "string");
    assert.deepEqual(fromB64(b64), random);
  } finally {
    if (hadBuffer) globalThis.Buffer = prevBuffer;
  }
});

test("toHex/fromHex round-trip and toHex matches the well-known lowercase form", () => {
  const bytes = new Uint8Array([0, 1, 15, 16, 255, 128]);
  assert.equal(toHex(bytes), "00010f10ff80");
  assert.deepEqual(fromHex(toHex(bytes)), bytes);
  assert.deepEqual(fromHex(""), new Uint8Array(0));
});

test("concatBytes joins arrays in order and leaves the inputs untouched", () => {
  const a = new Uint8Array([1, 2]);
  const b = new Uint8Array([]);
  const c = new Uint8Array([3, 4, 5]);
  assert.deepEqual(concatBytes(a, b, c), new Uint8Array([1, 2, 3, 4, 5]));
  assert.deepEqual(concatBytes(), new Uint8Array(0));
  // inputs are copied, not aliased
  const out = concatBytes(a, c);
  out[0] = 99;
  assert.equal(a[0], 1);
});
