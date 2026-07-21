import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { turnCredentials, turnIceServers } from "../apps/server/turn.js";

test("turnCredentials derives a username/expiry pair and an HMAC-SHA1 password", () => {
  const now = 1_700_000_000_000;
  const { username, credential, expiry } = turnCredentials("supersecret", 3600, now);
  assert.equal(expiry, Math.floor(now / 1000) + 3600);
  assert.equal(username, `${expiry}:noblechat`);
  const expected = crypto.createHmac("sha1", "supersecret").update(username).digest("base64");
  assert.equal(credential, expected);
});

test("turnCredentials clamps a too-short ttl so credentials don't expire instantly", () => {
  const now = 1_700_000_000_000;
  const { expiry } = turnCredentials("s", 5, now);
  assert.equal(expiry, Math.floor(now / 1000) + 60);
});

test("turnCredentials is deterministic for the same inputs (coturn derives it independently)", () => {
  const now = 1_700_000_000_000;
  const a = turnCredentials("shared", 600, now);
  const b = turnCredentials("shared", 600, now);
  assert.deepEqual(a, b);
});

test("turnIceServers is empty when no TURN server is configured", () => {
  assert.deepEqual(turnIceServers({ turnSecret: "", turnUris: [] }), []);
  assert.deepEqual(turnIceServers({ turnSecret: "x", turnUris: [] }), []);
  assert.deepEqual(turnIceServers({ turnSecret: "", turnUris: ["turn:x:3478"] }), []);
});

test("turnIceServers returns one entry with fresh time-limited credentials", () => {
  const now = 1_700_000_000_000;
  const uris = ["turn:chat.example.com:3478?transport=udp", "turn:chat.example.com:3478?transport=tcp"];
  const servers = turnIceServers({ turnSecret: "supersecret", turnUris: uris, turnTtlSec: 3600 }, now);
  assert.equal(servers.length, 1);
  assert.deepEqual(servers[0].urls, uris);
  assert.ok(servers[0].username.endsWith(":noblechat"));
  assert.ok(servers[0].credential.length > 0);
});
