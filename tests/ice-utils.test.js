import test from "node:test";
import assert from "node:assert/strict";
import { isTurnServer } from "../apps/web/src/ice-utils.js";

test("isTurnServer is true for a single turn: url string", () => {
  assert.equal(isTurnServer({ urls: "turn:relay.example.com:3478" }), true);
});

test("isTurnServer is true when any entry in a urls array is turn:", () => {
  assert.equal(isTurnServer({ urls: ["turn:relay.example.com:3478?transport=udp", "turn:relay.example.com:3478?transport=tcp"] }), true);
});

test("isTurnServer is false for a stun: only server", () => {
  assert.equal(isTurnServer({ urls: ["stun:stun.l.google.com:19302"] }), false);
});

test("isTurnServer is false when stun and turn are mixed but none start with turn:", () => {
  assert.equal(isTurnServer({ urls: ["stun:a.example.com", "stuns:b.example.com"] }), false);
});

test("isTurnServer matches turns: as not-turn (relay TLS uses a different scheme prefix)", () => {
  // turns: (TURN over TLS) does not start with "turn:", so it is intentionally
  // excluded here; this mirrors the exact string the app configures today and
  // avoids silently reclassifying a scheme nobody has wired up yet.
  assert.equal(isTurnServer({ urls: ["turns:relay.example.com:5349"] }), false);
});

test("isTurnServer is case-insensitive", () => {
  assert.equal(isTurnServer({ urls: ["TURN:relay.example.com:3478"] }), true);
});

test("isTurnServer tolerates a missing or malformed entry instead of throwing", () => {
  assert.equal(isTurnServer(undefined), false);
  assert.equal(isTurnServer(null), false);
  assert.equal(isTurnServer({}), false);
  assert.equal(isTurnServer({ urls: undefined }), false);
  assert.equal(isTurnServer({ urls: [null, 42, {}] }), false);
});

test("isTurnServer handles urls being a single non-array value", () => {
  assert.equal(isTurnServer({ urls: "stun:stun.l.google.com:19302" }), false);
});
