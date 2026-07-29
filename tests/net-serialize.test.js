// packages/net/src/serialize.js has zero coverage anywhere in the suite even
// though it is the exact boundary between the browser client and everything
// sent over the wire: a broken round trip here means alpha/beta/gamma header
// bytes come out mangled, or a restored identity can no longer decrypt its
// own mail. Covers packet/card/identity round trips and the browser-side
// pickPath() helper.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  serializePacket, deserializePacket, serializeCard, deserializeCard,
  serializeIdentity, deserializeIdentity, makeBrowserNet,
} from "../packages/net/src/serialize.js";
import { buildTestnet } from "../packages/net/src/directory.js";
import { generateIdentity, buildOutgoing, openIncoming } from "../packages/net/src/client.js";
import { sealEnvelope, encodeContent } from "../packages/protocol/src/protocol.js";

test("serializePacket/deserializePacket round trip preserves header and payload bytes exactly", () => {
  const dir = buildTestnet();
  const bob = generateIdentity("bob", dir.providers[0].id);
  const alice = generateIdentity("alice", dir.providers[0].id);
  const { packet } = buildOutgoing(dir, bob.card, { t: "msg", body: "hi", ts: 1 }, alice.sign);

  const restored = deserializePacket(serializePacket(packet));
  assert.deepStrictEqual(restored.header.alpha, packet.header.alpha);
  assert.deepStrictEqual(restored.header.beta, packet.header.beta);
  assert.deepStrictEqual(restored.header.gamma, packet.header.gamma);
  assert.deepStrictEqual(restored.payload, packet.payload);
});

test("serializeCard/deserializeCard round trip is a plain JSON-safe object and restores exactly", () => {
  const dir = buildTestnet();
  const alice = generateIdentity("alice", dir.providers[0].id);

  const wire = serializeCard(alice.card);
  // every field must be JSON-safe (string), since this is what crosses the network
  assert.equal(typeof wire.handle, "string");
  assert.equal(typeof wire.providerId, "string");
  assert.equal(typeof wire.mailbox, "string");
  assert.equal(typeof wire.kem.x, "string");
  assert.equal(typeof wire.kem.kem, "string");
  assert.equal(typeof wire.sign.ed, "string");
  assert.equal(typeof wire.sign.dsa, "string");
  assert.doesNotThrow(() => JSON.stringify(wire));

  const restored = deserializeCard(wire);
  assert.equal(restored.handle, alice.card.handle);
  assert.deepStrictEqual(restored.providerId, alice.card.providerId);
  assert.deepStrictEqual(restored.mailbox, alice.card.mailbox);
  assert.deepStrictEqual(restored.kem.x, alice.card.kem.x);
  assert.deepStrictEqual(restored.kem.kem, alice.card.kem.kem);
  assert.deepStrictEqual(restored.sign.ed, alice.card.sign.ed);
  assert.deepStrictEqual(restored.sign.dsa, alice.card.sign.dsa);
});

test("serializeIdentity/deserializeIdentity round trip restores a usable identity (can still decrypt its own mail)", () => {
  const dir = buildTestnet();
  const bob = generateIdentity("bob", dir.providers[0].id);
  const alice = generateIdentity("alice", dir.providers[0].id);

  // this is what main.js persists to localStorage and reloads on auto-login
  const wire = serializeIdentity(bob);
  assert.doesNotThrow(() => JSON.stringify(wire));
  const restoredBob = deserializeIdentity(wire);

  assert.equal(restoredBob.handle, "bob");
  assert.deepStrictEqual(restoredBob.mailbox, bob.mailbox);
  assert.deepStrictEqual(restoredBob.card, bob.card);

  // the real test: an envelope sealed for the ORIGINAL identity's card must
  // still open under the RESTORED identity's secret keys (skip the mixnet
  // routing itself, which is covered elsewhere - just the E2E envelope layer
  // that serializeIdentity/deserializeIdentity has to preserve correctly)
  const envelope = sealEnvelope(bob.card.kem, encodeContent({ t: "msg", body: "still works after reload", ts: 1 }), alice.sign);
  const opened = openIncoming(restoredBob, envelope);
  assert.equal(opened.content.body, "still works after reload");
  assert.equal(opened.verify(alice.card.sign), true);
});

test("makeBrowserNet exposes a JSON-safe public view as real byte arrays and pickPath selects a full path", () => {
  const dir = buildTestnet({ layers: 3, perLayer: 4, providers: 2 });
  const net = makeBrowserNet(dir.publicView());

  assert.equal(net.layers.length, 3);
  for (const row of net.layers) {
    assert.equal(row.length, 4);
    for (const n of row) assert.ok(n.id instanceof Uint8Array);
  }
  assert.equal(net.providers.length, 2);

  const path = net.pickPath(dir.providers[1].id);
  assert.equal(path.length, 4); // 3 mix layers + the chosen provider
  assert.deepStrictEqual(path[3].id, dir.providers[1].id); // last hop is the requested provider
  for (let i = 0; i < 3; i++) {
    const row = dir.layers[i];
    assert.ok(row.some((n) => Buffer.from(n.id).equals(Buffer.from(path[i].id))));
  }
});

test("makeBrowserNet.pickPath throws for a provider id absent from the directory", () => {
  const dir = buildTestnet({ providers: 1 });
  const net = makeBrowserNet(dir.publicView());
  assert.throws(() => net.pickPath(new Uint8Array(16)), /unknown provider/);
});
