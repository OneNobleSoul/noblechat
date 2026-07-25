import { test } from "node:test";
import assert from "node:assert/strict";
import { pack, unpack } from "./src/wire.js";
import {
  mailboxId, encodeContent, decodeContent, sealEnvelope, openEnvelope,
  packInner, unpackInner, MAILBOX_LEN,
} from "./src/protocol.js";
import {
  generateKemKeypair, kemPublicBundle, generateSignKeypair, signPublicBundle,
  encapsulate, decapsulate, seal, open, utf8ToBytes, bytesToUtf8,
} from "../crypto/src/index.js";

test("wire: pack/unpack round-trips multiple fields, including an empty one", () => {
  const a = utf8ToBytes("alpha");
  const b = utf8ToBytes("");
  const c = new Uint8Array([1, 2, 3, 255]);
  const [ra, rb, rc] = unpack(pack([a, b, c]), 3);
  assert.equal(bytesToUtf8(ra), "alpha");
  assert.equal(rb.length, 0);
  assert.deepEqual([...rc], [1, 2, 3, 255]);
});

test("wire: unpack rejects a truncated length prefix", () => {
  const bytes = pack([utf8ToBytes("x")]).subarray(0, 1);
  assert.throws(() => unpack(bytes, 1), /truncated/);
});

test("wire: unpack rejects a field shorter than its declared length", () => {
  const bytes = pack([utf8ToBytes("hello")]).subarray(0, 4); // length says 5, only 2 bytes follow
  assert.throws(() => unpack(bytes, 1), /truncated field/);
});

test("wire: pack rejects a field over the 16-bit length limit", () => {
  assert.throws(() => pack([new Uint8Array(0x10000)]), /too large/);
});

test("mailboxId is deterministic, fixed length, and key-sensitive", () => {
  const bundle = kemPublicBundle(generateKemKeypair());
  const id1 = mailboxId(bundle);
  const id2 = mailboxId(bundle);
  assert.equal(id1.length, MAILBOX_LEN);
  assert.deepEqual([...id1], [...id2]);
  const otherId = mailboxId(kemPublicBundle(generateKemKeypair()));
  assert.notDeepEqual([...id1], [...otherId]);
});

test("content encode/decode round-trips arbitrary JSON", () => {
  const obj = { t: "msg", body: "hello éé", n: 3, list: [1, 2, 3] };
  assert.deepEqual(decodeContent(encodeContent(obj)), obj);
});

test("sealEnvelope requires a sender signature keypair", () => {
  const bob = generateKemKeypair();
  assert.throws(
    () => sealEnvelope(kemPublicBundle(bob), encodeContent({ t: "x" }), null),
    /sender signature keypair required/,
  );
});

test("envelope round-trips content and verifies against the real sender", () => {
  const alice = generateSignKeypair();
  const bob = generateKemKeypair();
  const content = encodeContent({ t: "msg", body: "hi bob" });
  const env = sealEnvelope(kemPublicBundle(bob), content, alice);
  const { content: got, verify } = openEnvelope(bob, env);
  assert.deepEqual(decodeContent(got), { t: "msg", body: "hi bob" });
  assert.ok(verify(signPublicBundle(alice)));
});

test("envelope verification fails against an impostor's key", () => {
  const alice = generateSignKeypair();
  const mallory = generateSignKeypair();
  const bob = generateKemKeypair();
  const env = sealEnvelope(kemPublicBundle(bob), encodeContent({ t: "msg" }), alice);
  const { verify } = openEnvelope(bob, env);
  assert.ok(!verify(signPublicBundle(mallory)));
});

test("openEnvelope rejects a tampered ciphertext", () => {
  const alice = generateSignKeypair();
  const bob = generateKemKeypair();
  const env = sealEnvelope(kemPublicBundle(bob), encodeContent({ t: "msg" }), alice);
  env[env.length - 1] ^= 0x01;
  assert.throws(() => openEnvelope(bob, env));
});

test("openEnvelope rejects the wrong recipient", () => {
  const alice = generateSignKeypair();
  const bob = generateKemKeypair();
  const eve = generateKemKeypair();
  const env = sealEnvelope(kemPublicBundle(bob), encodeContent({ t: "msg" }), alice);
  assert.throws(() => openEnvelope(eve, env));
});

test("openEnvelope rejects a legacy envelope with no version byte or signature", () => {
  const bob = generateKemKeypair();
  // Build an envelope the pre-signing way: raw content sealed straight into
  // the AEAD, no version byte and no signature wrapper.
  const { header, sharedSecret } = encapsulate(kemPublicBundle(bob));
  const aead = seal(sharedSecret, encodeContent({ t: "legacy" }));
  const legacyEnvelope = pack([header.epk, header.kct, aead]);
  assert.throws(() => openEnvelope(bob, legacyEnvelope), /unsigned or unknown version/);
});

// This is the exact hole PR #51 closed: encryption alone doesn't authenticate
// a sender, so the signature has to be bound to the intended recipient. Verify
// here that a dishonest recipient who takes the decrypted signed bytes and
// simply re-seals them for someone else cannot make them verify there.
test("a signed envelope re-sealed to a different recipient fails verification there", () => {
  const alice = generateSignKeypair();
  const bob = generateKemKeypair();
  const carol = generateKemKeypair();
  const content = encodeContent({ t: "msg", body: "just between us" });
  const envelopeToBob = sealEnvelope(kemPublicBundle(bob), content, alice);

  // Bob decrypts and recovers the exact signed inner bytes (version byte plus
  // packed content/signature) that Alice produced for him.
  const [epk, kct, aead] = unpack(envelopeToBob, 3);
  const sharedSecret = decapsulate(bob, { epk, kct });
  const signedPlain = open(sharedSecret, aead);

  // Bob re-seals those exact bytes for Carol, unchanged, hoping she believes
  // it came from Alice.
  const { header: carolHeader, sharedSecret: carolSecret } = encapsulate(kemPublicBundle(carol));
  const forgedEnvelope = pack([carolHeader.epk, carolHeader.kct, seal(carolSecret, signedPlain)]);

  const { verify } = openEnvelope(carol, forgedEnvelope);
  assert.ok(!verify(signPublicBundle(alice)), "forged re-seal must not verify as Alice for Carol");
});

test("packInner/unpackInner round-trips mailbox and envelope bytes", () => {
  const mailbox = new Uint8Array([9, 8, 7]);
  const envelope = utf8ToBytes("opaque-envelope-bytes");
  const inner = packInner(mailbox, envelope);
  const { mailbox: gotMailbox, envelope: gotEnvelope } = unpackInner(inner);
  assert.deepEqual([...gotMailbox], [9, 8, 7]);
  assert.equal(bytesToUtf8(gotEnvelope), "opaque-envelope-bytes");
});
