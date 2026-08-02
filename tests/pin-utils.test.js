import test from "node:test";
import assert from "node:assert/strict";
import { parsePinsJson, pinsToObject, mergeSyncedPin } from "../apps/web/src/pin-utils.js";

test("parsePinsJson round-trips a normal pin store", () => {
  const raw = JSON.stringify({ alice: { fp: "AAAA", ok: true }, bob: { fp: "BBBB", ok: false } });
  const pins = parsePinsJson(raw);
  assert.deepEqual(pins.get("alice"), { fp: "AAAA", ok: true });
  assert.deepEqual(pins.get("bob"), { fp: "BBBB", ok: false });
});

test("parsePinsJson tolerates the older format where a pin was a bare fingerprint string", () => {
  const pins = parsePinsJson(JSON.stringify({ alice: "AAAA" }));
  assert.deepEqual(pins.get("alice"), { fp: "AAAA", ok: true });
});

test("parsePinsJson treats missing ok as trusted, only explicit false as unverified", () => {
  const pins = parsePinsJson(JSON.stringify({ alice: { fp: "AAAA" } }));
  assert.equal(pins.get("alice").ok, true);
});

test("parsePinsJson falls back to an empty map for missing or corrupt input", () => {
  assert.equal(parsePinsJson(undefined).size, 0);
  assert.equal(parsePinsJson("").size, 0);
  assert.equal(parsePinsJson("not json").size, 0);
});

test("pinsToObject serializes a pin map back to the on-disk shape", () => {
  const pins = new Map([["alice", { fp: "AAAA", ok: true }], ["bob", { fp: "BBBB", ok: false }]]);
  assert.deepEqual(pinsToObject(pins), {
    alice: { fp: "AAAA", ok: true },
    bob: { fp: "BBBB", ok: false },
  });
});

test("parsePinsJson/pinsToObject round-trip is stable", () => {
  const raw = JSON.stringify({ alice: { fp: "AAAA", ok: true }, bob: { fp: "BBBB", ok: false } });
  assert.deepEqual(pinsToObject(parsePinsJson(raw)), JSON.parse(raw));
});

test("mergeSyncedPin: a fresh device with no local pin adopts the synced one", () => {
  assert.deepEqual(mergeSyncedPin(undefined, { fp: "AAAA", ok: true }), { fp: "AAAA", ok: true });
  assert.deepEqual(mergeSyncedPin(undefined, { fp: "AAAA" }), { fp: "AAAA", ok: true });
});

test("mergeSyncedPin: an empty or fingerprint-less synced entry changes nothing", () => {
  const local = { fp: "AAAA", ok: true };
  assert.equal(mergeSyncedPin(local, undefined), local);
  assert.equal(mergeSyncedPin(local, {}), local);
  assert.equal(mergeSyncedPin(undefined, {}), undefined);
});

test("mergeSyncedPin: matching, trusted fingerprints on both sides stay unchanged", () => {
  const local = { fp: "AAAA", ok: true };
  assert.equal(mergeSyncedPin(local, { fp: "AAAA", ok: true }), local);
});

test("mergeSyncedPin: a fingerprint mismatch keeps the LOCAL fingerprint but flags unverified", () => {
  const local = { fp: "AAAA", ok: true };
  assert.deepEqual(mergeSyncedPin(local, { fp: "ZZZZ", ok: true }), { fp: "AAAA", ok: false });
});

test("mergeSyncedPin: a synced 'verified' can never clear a local unverified flag", () => {
  const local = { fp: "AAAA", ok: false };
  assert.deepEqual(mergeSyncedPin(local, { fp: "AAAA", ok: true }), { fp: "AAAA", ok: false });
});

test("mergeSyncedPin: a synced unverified flag propagates even if the local side was trusted", () => {
  const local = { fp: "AAAA", ok: true };
  assert.deepEqual(mergeSyncedPin(local, { fp: "AAAA", ok: false }), { fp: "AAAA", ok: false });
});
