import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  HANDLE_RE, HEX_RE, isB64, validCard,
  readBody, readBodyBuffer, timingEqual,
  hashPassword, verifyPassword, clampExpireSec,
} from "../apps/server/util.js";

test("handle format matches what the account routes accept", () => {
  assert.ok(HANDLE_RE.test("kirito"));
  assert.ok(HANDLE_RE.test("a_b_9"));
  assert.ok(!HANDLE_RE.test("ab")); // too short
  assert.ok(!HANDLE_RE.test("Has-Caps"));
  assert.ok(!HANDLE_RE.test("x".repeat(25))); // too long
});

test("device ids must be lowercase hex, 8-64 chars", () => {
  assert.ok(HEX_RE.test("a1b2c3d4"));
  assert.ok(!HEX_RE.test("nothex!!"));
  assert.ok(!HEX_RE.test("abc")); // too short
});

test("isB64 rejects non-strings and bad charsets", () => {
  assert.ok(isB64("YWJjZA=="));
  assert.equal(isB64(123), false);
  assert.equal(isB64(null), false);
  assert.equal(isB64("not base64!"), false);
});

test("validCard requires a full, well-formed device card", () => {
  const good = {
    handle: "kirito",
    providerId: "YWJj", mailbox: "ZGVm",
    kem: { x: "eA==", kem: "a2Vt" },
    sign: { ed: "ZWQ=", dsa: "ZHNh" },
  };
  assert.ok(validCard(good));
  assert.ok(!validCard({ ...good, handle: "Not Valid" }));
  assert.ok(!validCard({ ...good, kem: { x: "eA==" } })); // missing kem.kem
  assert.ok(!validCard(null));
  assert.ok(!validCard("kirito"));
});

test("hashPassword/verifyPassword round-trip and reject wrong passwords", () => {
  const stored = hashPassword("correct horse battery staple");
  assert.ok(verifyPassword("correct horse battery staple", stored));
  assert.ok(!verifyPassword("wrong password", stored));
  // malformed stored values (no salt separator) never verify, never throw
  assert.ok(!verifyPassword("anything", "not-a-hash"));
});

test("timingEqual compares values, not just lengths", () => {
  assert.ok(timingEqual("secret-token", "secret-token"));
  assert.ok(!timingEqual("secret-token", "secret-tokeN"));
  assert.ok(!timingEqual("short", "much-longer-value"));
});

test("clampExpireSec: default/absent means no expiry cap requested", () => {
  assert.equal(clampExpireSec(undefined, 2592000), 0);
  assert.equal(clampExpireSec("", 2592000), 0);
});

test("clampExpireSec: garbage and negative values fall back to 0, not NaN or negative", () => {
  assert.equal(clampExpireSec("not-a-number", 2592000), 0);
  assert.equal(clampExpireSec(-500, 2592000), 0);
  assert.equal(clampExpireSec("-10", 2592000), 0);
});

test("clampExpireSec: fractional seconds are floored", () => {
  assert.equal(clampExpireSec("59.9", 2592000), 59);
});

test("clampExpireSec: values past the cap are clamped down to it", () => {
  const cap = 30 * 24 * 3600; // 30 days, same cap the upload route uses
  assert.equal(clampExpireSec(cap + 1000, cap), cap);
  assert.equal(clampExpireSec(10, cap), 10);
});

function withServer(handler, fn) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", async () => {
      try {
        const { port } = server.address();
        await fn(port);
        resolve();
      } catch (e) {
        reject(e);
      } finally {
        server.close();
      }
    });
  });
}

test("readBody resolves the full text body when under the limit", () => withServer(
  async (req, res) => { const body = await readBody(req, 1024); res.end(body); },
  async (port) => {
    const res = await fetch(`http://127.0.0.1:${port}/`, { method: "POST", body: "hello world" });
    assert.equal(await res.text(), "hello world");
  },
));

// readBody's real caller (the /api/upload etc. routes) relies on it rejecting
// mid-stream once the limit is crossed, so the caller can bail out before
// buffering the rest of an oversized body. Drive that with a fake req
// (EventEmitter) instead of a real socket: readBody calls req.destroy() on
// overflow, which on a real connection also kills the response, making the
// client-visible behavior (a reset) awkward to assert reliably.
import { EventEmitter } from "node:events";

function fakeReq() {
  const req = new EventEmitter();
  req.destroy = () => {}; // readBody calls this on overflow; nothing to clean up here
  return req;
}

test("readBody rejects once the body exceeds maxBytes", async () => {
  const req = fakeReq();
  const pending = readBody(req, 4);
  req.emit("data", Buffer.from("way more than four bytes"));
  await assert.rejects(pending, /body too large/);
});

test("readBody resolves normally when the body stays under the limit (fake req)", async () => {
  const req = fakeReq();
  const pending = readBody(req, 100);
  req.emit("data", Buffer.from("fits fine"));
  req.emit("end");
  assert.equal(await pending, "fits fine");
});

test("readBodyBuffer returns raw bytes, not decoded text", () => withServer(
  async (req, res) => {
    const buf = await readBodyBuffer(req, 1024);
    res.writeHead(200, { "content-type": "application/octet-stream" }).end(buf);
  },
  async (port) => {
    const payload = new Uint8Array([0, 255, 16, 200]);
    const res = await fetch(`http://127.0.0.1:${port}/`, { method: "POST", body: payload });
    const back = new Uint8Array(await res.arrayBuffer());
    assert.deepEqual([...back], [...payload]);
  },
));

// streamToFile is the upload path's memory fix: the body goes chunk by chunk
// to disk instead of being buffered whole. Exercise it over a real socket.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { streamToFile } from "../apps/server/util.js";

const tmpFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "nc-up-")), "f");

test("streamToFile writes the body to disk and reports its size", () => withServer(
  async (req, res) => {
    const dest = tmpFile();
    const size = await streamToFile(req, dest, 1024);
    const back = fs.readFileSync(dest);
    res.end(JSON.stringify({ size, bytes: [...back] }));
  },
  async (port) => {
    const payload = new Uint8Array([7, 0, 255, 42]);
    const res = await fetch(`http://127.0.0.1:${port}/`, { method: "POST", body: payload });
    const j = await res.json();
    assert.equal(j.size, 4);
    assert.deepEqual(j.bytes, [...payload]);
  },
));

test("streamToFile rejects past the limit and removes the partial file", async () => {
  const { PassThrough } = await import("node:stream");
  const body = new PassThrough();
  const dest = tmpFile();
  const pending = streamToFile(body, dest, 4);
  body.write(Buffer.from("way more than four bytes"));
  await assert.rejects(pending, /body too large/);
  assert.equal(fs.existsSync(dest), false);
});
