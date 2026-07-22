import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTestnet } from "./src/directory.js";
import { Mixnet } from "./src/router.js";
import { makeReplayGuard } from "./src/replay.js";
import { generateIdentity, buildOutgoing, openIncoming, buildCoverLoop } from "./src/client.js";
import { sealEnvelope, openEnvelope, encodeContent } from "../protocol/src/protocol.js";

function waitFor(fn, ms = 3000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    fn((v) => {
      clearTimeout(t);
      resolve(v);
    });
  });
}

test("end-to-end: a message travels through the mixnet and only the recipient can read it", async () => {
  const dir = buildTestnet({ layers: 3, perLayer: 2, providers: 2 });
  const mix = new Mixnet(dir, { meanDelayMs: 3 });

  const alice = generateIdentity("alice", dir.providers[0].id);
  const bob = generateIdentity("bob", dir.providers[1].id);

  const got = waitFor((done) => {
    mix.subscribe(bob.providerId, bob.mailbox, (env) => done(openIncoming(bob, env)));
  });

  const { firstNodeId, packet } = buildOutgoing(dir, bob.card, {
    t: "msg", from: "alice", body: "meet me at the town of beginnings", ts: 1,
  }, alice.sign);
  mix.inject(firstNodeId, packet);

  const { content: msg, verify } = await got;
  assert.equal(msg.body, "meet me at the town of beginnings");
  assert.equal(msg.from, "alice");
  // the signature proves it really came from alice's keys...
  assert.equal(verify(alice.card.sign), true);
  // ...and no one else's
  assert.equal(verify(bob.card.sign), false);
  // it really traversed all 4 hops (3 mix layers + provider)
  assert.ok(mix.stats.forwarded >= 4);
});

test("a message claiming to be from alice but signed by eve fails verification", async () => {
  const dir = buildTestnet();
  const mix = new Mixnet(dir, { meanDelayMs: 1 });
  const alice = generateIdentity("alice", dir.providers[0].id);
  const eve = generateIdentity("eve", dir.providers[0].id);
  const bob = generateIdentity("bob", dir.providers[0].id);

  const got = waitFor((done) => {
    mix.subscribe(bob.providerId, bob.mailbox, (env) => done(openIncoming(bob, env)));
  });
  // eve knows bob's public card and forges a message with from:"alice"
  const { firstNodeId, packet } = buildOutgoing(dir, bob.card, {
    t: "msg", from: "alice", to: "bob", body: "give eve your password", ts: 1,
  }, eve.sign);
  mix.inject(firstNodeId, packet);

  const { content: msg, verify } = await got;
  assert.equal(msg.from, "alice"); // the claim decrypts fine...
  assert.equal(verify(alice.card.sign), false); // ...but alice never signed it
});

test("a signed message re-encrypted to a third party fails verification there", () => {
  const alice = generateIdentity("alice", new Uint8Array(16));
  const bob = generateIdentity("bob", new Uint8Array(16));
  const carol = generateIdentity("carol", new Uint8Array(16));

  const content = encodeContent({ t: "msg", from: "alice", to: "bob", body: "for bob only", ts: 1 });
  // alice -> bob, legitimately signed
  const toBob = sealEnvelope(bob.card.kem, content, alice.sign);
  assert.equal(openEnvelope(bob.kem, toBob).verify(alice.card.sign), true);
  // bob (or anyone) re-seals the exact same content for carol; even if he could
  // splice alice's signature in, the transcript binds bob's KEM bundle, so
  // carol's check against her own bundle cannot pass with alice's key
  const toCarol = sealEnvelope(carol.card.kem, content, bob.sign);
  const opened = openEnvelope(carol.kem, toCarol);
  assert.equal(opened.verify(alice.card.sign), false);
  assert.equal(opened.verify(bob.card.sign), true); // it only proves BOB sent it
});

test("a third party subscribed to the wrong mailbox learns nothing", async () => {
  const dir = buildTestnet();
  const mix = new Mixnet(dir, { meanDelayMs: 1 });
  const alice = generateIdentity("alice", dir.providers[0].id);
  const bob = generateIdentity("bob", dir.providers[0].id);
  const eve = generateIdentity("eve", dir.providers[0].id);

  let eveHeard = 0;
  mix.subscribe(eve.providerId, eve.mailbox, () => eveHeard++);
  const got = waitFor((done) =>
    mix.subscribe(bob.providerId, bob.mailbox, () => done(true)),
  );
  const { firstNodeId, packet } = buildOutgoing(dir, bob.card, { t: "msg", body: "secret", ts: 1 }, alice.sign);
  mix.inject(firstNodeId, packet);
  await got;
  assert.equal(eveHeard, 0);
});

test("cover traffic is delivered and recognised, then dropped by the client", async () => {
  const dir = buildTestnet();
  const mix = new Mixnet(dir, { meanDelayMs: 1 });
  const alice = generateIdentity("alice", dir.providers[0].id);

  const got = waitFor((done) => {
    mix.subscribe(alice.providerId, alice.mailbox, (env) => done(openIncoming(alice, env)));
  });
  const { firstNodeId, packet } = buildCoverLoop(dir, alice);
  mix.inject(firstNodeId, packet);
  const { content: msg } = await got;
  assert.equal(msg.t, "cover"); // client would drop this instead of showing it
});

test("replay guard drops a repeated packet tag and rolls epochs", () => {
  const g = makeReplayGuard({ epochMs: 1000, maxPerEpoch: 1e9 });
  assert.equal(g.seen("alpha-A", 0), false); // first sight
  assert.equal(g.seen("alpha-A", 10), true); // verbatim replay -> dropped
  assert.equal(g.seen("alpha-B", 20), false); // a different packet is fine
  // still remembered within the same epoch
  assert.equal(g.seen("alpha-A", 500), true);
  // after two epoch rotations the old tag has fallen out and is accepted again
  g.seen("x", 1000); // rotate 1 (cur->prev, A now in prev)
  g.seen("y", 2000); // rotate 2 (A drops out of both sets)
  assert.equal(g.seen("alpha-A", 2001), false);
});

test("replay guard caps memory by size and rejects duplicates across the cap", () => {
  const g = makeReplayGuard({ epochMs: 1e9, maxPerEpoch: 3 });
  assert.equal(g.seen("a", 0), false);
  assert.equal(g.seen("b", 0), false);
  assert.equal(g.seen("c", 0), false); // fills the epoch -> next call rotates
  assert.equal(g.seen("a", 0), true); // "a" still in prev after rotation
  assert.equal(g.seen("d", 0), false);
});
