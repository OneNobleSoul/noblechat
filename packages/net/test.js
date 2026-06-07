import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTestnet } from "./src/directory.js";
import { Mixnet } from "./src/router.js";
import { generateIdentity, buildOutgoing, openIncoming, buildCoverLoop } from "./src/client.js";

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
  });
  mix.inject(firstNodeId, packet);

  const msg = await got;
  assert.equal(msg.body, "meet me at the town of beginnings");
  assert.equal(msg.from, "alice");
  // it really traversed all 4 hops (3 mix layers + provider)
  assert.ok(mix.stats.forwarded >= 4);
});

test("a third party subscribed to the wrong mailbox learns nothing", async () => {
  const dir = buildTestnet();
  const mix = new Mixnet(dir, { meanDelayMs: 1 });
  const bob = generateIdentity("bob", dir.providers[0].id);
  const eve = generateIdentity("eve", dir.providers[0].id);

  let eveHeard = 0;
  mix.subscribe(eve.providerId, eve.mailbox, () => eveHeard++);
  const got = waitFor((done) =>
    mix.subscribe(bob.providerId, bob.mailbox, () => done(true)),
  );
  const { firstNodeId, packet } = buildOutgoing(dir, bob.card, { t: "msg", body: "secret", ts: 1 });
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
  const msg = await got;
  assert.equal(msg.t, "cover"); // client would drop this instead of showing it
});
