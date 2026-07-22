import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateNodeKey, createPacket, processPacket, PAYLOAD_LEN, HOP_ID_LEN,
} from "./src/sphinx.js";
import { randomBytes, utf8ToBytes, bytesToUtf8 } from "../crypto/src/util.js";

function nodeWithId() {
  return { key: generateNodeKey(), id: randomBytes(HOP_ID_LEN) };
}

test("3-hop route: each hop learns only the next, exit recovers payload", () => {
  const hops = [nodeWithId(), nodeWithId(), nodeWithId()];
  const path = hops.map((h) => ({ id: h.id, public: h.key.public }));

  const msg = utf8ToBytes("this is a real onion-routed message through the mixnet");
  let pkt = createPacket(path, msg);

  // hop 0 -> should point at hop 1
  const r0 = processPacket(hops[0].key.secret, pkt);
  assert.equal(r0.final, false);
  assert.deepEqual(r0.nextId, hops[1].id);

  // hop 1 -> should point at hop 2
  const r1 = processPacket(hops[1].key.secret, r0.packet);
  assert.equal(r1.final, false);
  assert.deepEqual(r1.nextId, hops[2].id);

  // hop 2 -> exit, payload recovered
  const r2 = processPacket(hops[2].key.secret, r1.packet);
  assert.equal(r2.final, true);
  assert.equal(bytesToUtf8(r2.payload.subarray(0, msg.length)), bytesToUtf8(msg));
});

test("full 5-hop route round-trips the payload through every LIONESS layer", () => {
  const hops = [nodeWithId(), nodeWithId(), nodeWithId(), nodeWithId(), nodeWithId()];
  const path = hops.map((h) => ({ id: h.id, public: h.key.public }));
  const msg = utf8ToBytes("five hops deep and the wide-block cipher still peels cleanly");
  let cur = createPacket(path, msg);
  for (let i = 0; i < 4; i++) {
    const r = processPacket(hops[i].key.secret, cur);
    assert.equal(r.final, false);
    assert.deepEqual(r.nextId, hops[i + 1].id);
    cur = r.packet;
  }
  const last = processPacket(hops[4].key.secret, cur);
  assert.equal(last.final, true);
  assert.equal(bytesToUtf8(last.payload.subarray(0, msg.length)), bytesToUtf8(msg));
});

test("packets are constant size regardless of hop count", () => {
  const one = [nodeWithId()];
  const five = [nodeWithId(), nodeWithId(), nodeWithId(), nodeWithId(), nodeWithId()];
  const p1 = createPacket(one.map((h) => ({ id: h.id, public: h.key.public })), utf8ToBytes("hi"));
  const p5 = createPacket(five.map((h) => ({ id: h.id, public: h.key.public })), utf8ToBytes("hi"));
  assert.equal(p1.header.beta.length, p5.header.beta.length);
  assert.equal(p1.payload.length, PAYLOAD_LEN);
  assert.equal(p5.payload.length, PAYLOAD_LEN);
});

test("a wrong mix key cannot process the packet (MAC fails)", () => {
  const hops = [nodeWithId(), nodeWithId()];
  const path = hops.map((h) => ({ id: h.id, public: h.key.public }));
  const pkt = createPacket(path, utf8ToBytes("secret"));
  const attacker = generateNodeKey();
  assert.throws(() => processPacket(attacker.secret, pkt), /MAC/);
});

test("payload is a wide-block PRP: a single tampered bit avalanches (tagging resistance)", () => {
  // A malicious hop that flips payload bits to tag a packet must NOT get a
  // recognisable mark at the exit. With the LIONESS wide-block cipher, changing
  // one bit mid-route randomises the whole decrypted block, so the tag is
  // destroyed (and the message dies at the end-to-end AEAD) rather than
  // surviving as a correlatable pattern.
  const hops = [nodeWithId(), nodeWithId(), nodeWithId()];
  const path = hops.map((h) => ({ id: h.id, public: h.key.public }));
  const msg = utf8ToBytes("carry me across the mixnet without a tag");
  const pkt = createPacket(path, msg);

  // clean run to get the reference exit payload
  const c0 = processPacket(hops[0].key.secret, pkt);
  const c1 = processPacket(hops[1].key.secret, c0.packet);
  const clean = processPacket(hops[2].key.secret, c1.packet).payload;

  // tampered run: flip one bit in the payload after hop 0 (an in-path attacker)
  const t0 = processPacket(hops[0].key.secret, pkt);
  t0.packet.payload[100] ^= 0x01;
  const t1 = processPacket(hops[1].key.secret, t0.packet);
  const tampered = processPacket(hops[2].key.secret, t1.packet).payload;

  assert.equal(tampered.length, clean.length);
  let diff = 0;
  for (let i = 0; i < clean.length; i++) if (clean[i] !== tampered[i]) diff++;
  // a plain XOR onion would differ in exactly 1 bit; a wide-block PRP avalanches
  // across roughly half the block. Require a large fraction to have changed.
  assert.ok(diff > clean.length * 0.3, `expected avalanche, only ${diff}/${clean.length} bytes changed`);
});

test("an inner payload larger than PAYLOAD_LEN is rejected, not silently truncated", () => {
  const hops = [nodeWithId()];
  const path = hops.map((h) => ({ id: h.id, public: h.key.public }));
  assert.throws(() => createPacket(path, new Uint8Array(PAYLOAD_LEN + 1)), /payload too large/);
});
