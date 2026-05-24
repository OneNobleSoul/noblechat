import { test } from "node:test";
import assert from "node:assert/strict";
import {
  seal, open, randomBytes, utf8ToBytes, bytesToUtf8, timingSafeEqual,
  generateKemKeypair, kemPublicBundle, encapsulate, decapsulate,
  generateSignKeypair, signPublicBundle, sign, verify,
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
