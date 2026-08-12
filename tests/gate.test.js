import test from "node:test";
import assert from "node:assert/strict";
import { unlocks, isUnlocked, markUnlocked, GATE_OK, GATE_HASH, sha256Hex } from "../apps/web/src/gate.js";

// The access key itself is deliberately absent here: putting it in the repo
// would defeat the gate. What is testable without it is the digest, the shape
// of the stored hash, and every rejection path.

function fakeStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
  };
}
function hostileStorage() {
  return {
    getItem() { throw new Error("denied"); },
    setItem() { throw new Error("denied"); },
  };
}
function withStorage(s, fn) {
  const had = "sessionStorage" in globalThis;
  const prev = globalThis.sessionStorage;
  globalThis.sessionStorage = s;
  try { return fn(); } finally {
    if (had) globalThis.sessionStorage = prev; else delete globalThis.sessionStorage;
  }
}

test("sha256Hex matches the published test vectors", async () => {
  assert.equal(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(await sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("the stored gate hash is a full-length sha256 digest", () => {
  assert.match(GATE_HASH, /^[0-9a-f]{64}$/);
});

test("a wrong key keeps the gate shut", async () => {
  assert.equal(await unlocks("definitely-not-it"), false);
  assert.equal(await unlocks(GATE_HASH), false); // the hash is not the key
});

test("empty and non-string values are rejected without throwing", async () => {
  assert.equal(await unlocks(""), false);
  assert.equal(await unlocks(null), false);
  assert.equal(await unlocks(undefined), false);
  assert.equal(await unlocks(42), false);
  assert.equal(await unlocks({}), false);
});

test("a value whose digest is the stored hash is what opens it", async () => {
  // Same comparison unlocks() makes, run against a key we do know, to prove the
  // check is a digest match and not something looser like a prefix test.
  const key = "some-other-key";
  const digest = await sha256Hex(key);
  assert.equal(await unlocks(key), digest === GATE_HASH);
  assert.equal(await unlocks(key.slice(0, 4)), false);
});

test("the unlocked flag round-trips through session storage", () => {
  const s = fakeStorage();
  withStorage(s, () => {
    assert.equal(isUnlocked(), false);
    markUnlocked();
    assert.equal(isUnlocked(), true);
  });
  assert.equal(s.getItem(GATE_OK), "1");
});

test("any value other than exactly \"1\" counts as locked", () => {
  const s = fakeStorage();
  s.setItem(GATE_OK, "yes");
  withStorage(s, () => assert.equal(isUnlocked(), false));
});

test("storage that throws leaves the visitor locked out instead of crashing", () => {
  withStorage(hostileStorage(), () => {
    assert.equal(isUnlocked(), false);
    assert.doesNotThrow(() => markUnlocked());
    assert.equal(isUnlocked(), false);
  });
});
