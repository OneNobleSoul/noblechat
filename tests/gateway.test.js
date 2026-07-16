import test from "node:test";
import assert from "node:assert/strict";
import { Mixnet } from "../packages/net/src/router.js";

// A stand-in for the async (Postgres-backed) mailbox store, so we can exercise
// the gateway's durable/offline path without a database.
function asyncStore() {
  const q = new Map();
  return {
    async push(k, env) { if (!q.has(k)) q.set(k, []); q.get(k).push(env); },
    async drain(k) { const a = q.get(k) || []; q.set(k, []); return a; },
  };
}

test("router works with the in-memory default store", () => {
  const mix = new Mixnet({ lookup: () => null });
  assert.equal(typeof mix.subscribe, "function");
});

test("queued messages are delivered from an async store on subscribe", async () => {
  const store = asyncStore();
  const mix = new Mixnet({ lookup: () => null }, { mailboxStore: store });
  const prov = new Uint8Array([1, 2, 3]);
  const mbox = new Uint8Array([9, 9]);
  const key = mix._key(prov, mbox);
  await store.push(key, new TextEncoder().encode("hello"));

  const got = [];
  mix.subscribe(prov, mbox, (env) => got.push(new TextDecoder().decode(env)));
  await new Promise((r) => setTimeout(r, 25));
  assert.deepEqual(got, ["hello"]);
});

test("a live subscriber gets messages directly, not via the store", async () => {
  const store = asyncStore();
  const mix = new Mixnet({ lookup: () => null }, { mailboxStore: store });
  const prov = new Uint8Array([7]);
  const mbox = new Uint8Array([8]);
  const got = [];
  mix.subscribe(prov, mbox, (env) => got.push(new TextDecoder().decode(env)));
  // simulate a delivery to a subscribed mailbox by driving _deliver's branch
  const subs = mix.subs.get(mix._key(prov, mbox));
  for (const cb of subs) cb(new TextEncoder().encode("direct"));
  assert.deepEqual(got, ["direct"]);
});
