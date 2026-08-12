import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  HANDLE_RE, HEX_RE, isB64, validCard,
  readBody, readBodyBuffer, timingEqual, originAllowed,
  hashPassword, verifyPassword, clampExpireSec,
  tryAcquireConn, releaseConn, staticRelPath,
  clientIp, makeLockout, asHandle, asToken,
} from "../apps/server/util.js";

test("handle fields are type-checked, not coerced", () => {
  assert.equal(asHandle("Kirito"), "kirito");
  // String(["kirito"]) is "kirito", so an array used to walk straight through
  // the handle check. Every non-string shape is rejected outright now.
  assert.equal(asHandle(["kirito"]), null);
  assert.equal(asHandle([["kirito"]]), null);
  assert.equal(asHandle(["kirito", "extra"]), null);
  assert.equal(asHandle(123), null);
  assert.equal(asHandle({ $ne: null }), null);
  assert.equal(asHandle(null), null);
  assert.equal(asHandle(undefined), null);
  assert.equal(asHandle("ab"), null, "still has to satisfy the handle format");
  assert.equal(asHandle("has-dash"), null);
});

test("token fields must be plain bounded strings", () => {
  assert.equal(asToken("abc123"), "abc123");
  assert.equal(asToken(["abc123"]), null);
  assert.equal(asToken(""), null);
  assert.equal(asToken({}), null);
  assert.equal(asToken("x".repeat(257)), null);
  assert.equal(asToken("x".repeat(256)), "x".repeat(256));
});

const reqWith = (xff, remote = "10.0.0.1") => ({
  headers: xff === null ? {} : { "x-forwarded-for": xff },
  socket: { remoteAddress: remote },
});

test("clientIp takes the entry our own proxy appended, not the client's", () => {
  // One proxy in front: it appends the address it saw, so the rightmost entry
  // is the real caller and everything left of it is client-supplied noise.
  assert.equal(clientIp(reqWith("203.0.113.9"), 1), "203.0.113.9");
  assert.equal(clientIp(reqWith("1.2.3.4, 203.0.113.9"), 1), "203.0.113.9");
  // The spoofing attempt that made the login throttle useless: a forged
  // leftmost entry must not become the rate-limit key.
  assert.notEqual(clientIp(reqWith("1.2.3.4, 203.0.113.9"), 1), "1.2.3.4");
});

test("clientIp counts trusted hops from the right", () => {
  const xff = "1.2.3.4, 198.51.100.7, 192.0.2.5";
  assert.equal(clientIp(reqWith(xff), 1), "192.0.2.5");
  assert.equal(clientIp(reqWith(xff), 2), "198.51.100.7");
});

test("clientIp ignores the header without a trusted proxy, and when it is too short", () => {
  assert.equal(clientIp(reqWith("1.2.3.4"), 0), "10.0.0.1");
  // Two hops claimed but only one entry present: the chain is not what we
  // expect, so trust the socket instead of a forgeable single entry.
  assert.equal(clientIp(reqWith("1.2.3.4"), 2), "10.0.0.1");
  assert.equal(clientIp(reqWith(null), 1), "10.0.0.1");
  assert.equal(clientIp(reqWith("  ,  "), 1), "10.0.0.1");
});

test("lockout stays quiet until the threshold, then backs off exponentially", () => {
  const lo = makeLockout({ threshold: 3, baseDelayMs: 1000, maxDelayMs: 60000 });
  const now = 1_000_000;
  for (let i = 0; i < 2; i++) lo.fail("kirito", now);
  assert.equal(lo.retryAfter("kirito", now), 0, "a couple of typos must not lock anyone out");
  lo.fail("kirito", now); // 3rd -> 1s
  assert.equal(lo.retryAfter("kirito", now), 1);
  lo.fail("kirito", now); // 4th -> 2s
  assert.equal(lo.retryAfter("kirito", now), 2);
  lo.fail("kirito", now); // 5th -> 4s
  assert.equal(lo.retryAfter("kirito", now), 4);
});

test("lockout expires, is capped, and a correct password clears it", () => {
  const lo = makeLockout({ threshold: 1, baseDelayMs: 1000, maxDelayMs: 5000 });
  const now = 1_000_000;
  for (let i = 0; i < 10; i++) lo.fail("kirito", now);
  assert.equal(lo.retryAfter("kirito", now), 5, "backoff must not grow past the cap");
  assert.equal(lo.retryAfter("kirito", now + 5001), 0, "and must expire on its own");

  lo.fail("asuna", now);
  assert.ok(lo.retryAfter("asuna", now) > 0);
  lo.succeed("asuna");
  assert.equal(lo.retryAfter("asuna", now), 0);
});

test("waiting out a lock does not hand back a fresh batch of free guesses", () => {
  const lo = makeLockout({ threshold: 3, baseDelayMs: 1000, maxDelayMs: 60000, forgetAfterMs: 3600_000 });
  let now = 1_000_000;
  for (let i = 0; i < 3; i++) lo.fail("kirito", now);
  assert.equal(lo.retryAfter("kirito", now), 1);
  now += 2000; // sit out the delay
  assert.equal(lo.retryAfter("kirito", now), 0, "the lock itself must lapse");
  // ...but the next failure continues the escalation instead of starting over.
  lo.fail("kirito", now);
  assert.equal(lo.retryAfter("kirito", now), 2);
  // Only a long quiet period forgets the history entirely.
  assert.equal(lo.retryAfter("kirito", now + 3600_001), 0);
  lo.fail("kirito", now + 3600_001);
  assert.equal(lo.retryAfter("kirito", now + 3600_001), 0, "history forgotten, back below the threshold");
});

test("lockout does not grow without bound", () => {
  const lo = makeLockout({ threshold: 1, baseDelayMs: 1000, maxEntries: 50 });
  const now = 1_000_000;
  for (let i = 0; i < 500; i++) lo.fail("handle" + i, now);
  assert.ok(lo.size() <= 50, `expected the map to stay capped, got ${lo.size()}`);
});

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

test("hashPassword/verifyPassword round-trip and reject wrong passwords", async () => {
  const stored = await hashPassword("correct horse battery staple");
  assert.ok(await verifyPassword("correct horse battery staple", stored));
  assert.ok(!(await verifyPassword("wrong password", stored)));
  // malformed stored values (no salt separator) never verify, never throw
  assert.ok(!(await verifyPassword("anything", "not-a-hash")));
  // a corrupt entry with an empty hash after the separator must not match
  // everything (scrypt with keylen 0 would happily return an empty buffer)
  const salt = stored.slice(0, stored.indexOf("$"));
  assert.ok(!(await verifyPassword("anything", salt + "$")));
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
  // the limit error is tagged so the upload route can answer 413 for "too big"
  // but not for a disk error or aborted stream
  await assert.rejects(pending, (e) => e.code === "E_TOO_LARGE" && /body too large/.test(e.message));
  assert.equal(fs.existsSync(dest), false);
});

test("tryAcquireConn allows up to max and rejects past it", () => {
  const m = new Map();
  assert.ok(tryAcquireConn(m, "1.2.3.4", 2));
  assert.ok(tryAcquireConn(m, "1.2.3.4", 2));
  assert.equal(m.get("1.2.3.4"), 2);
  assert.ok(!tryAcquireConn(m, "1.2.3.4", 2));
  // a rejected attempt must not bump the stored count, or the IP would
  // creep further past the limit on every retry and never recover
  assert.equal(m.get("1.2.3.4"), 2);
});

test("tryAcquireConn: a rejected attempt does not need releaseConn, and does not affect other IPs", () => {
  const m = new Map();
  tryAcquireConn(m, "1.1.1.1", 1);
  assert.ok(!tryAcquireConn(m, "1.1.1.1", 1));
  assert.ok(tryAcquireConn(m, "2.2.2.2", 1));
  assert.equal(m.get("1.1.1.1"), 1);
  assert.equal(m.get("2.2.2.2"), 1);
});

test("releaseConn removes the entry once it hits zero, instead of leaving a stale 0", () => {
  const m = new Map();
  tryAcquireConn(m, "1.2.3.4", 5);
  releaseConn(m, "1.2.3.4");
  assert.equal(m.has("1.2.3.4"), false);
});

test("acquire/reject/release cycle: an IP can reconnect once a slot actually frees up", () => {
  const m = new Map();
  tryAcquireConn(m, "1.2.3.4", 1);
  // a second attempt while the first connection is still open is rejected
  assert.ok(!tryAcquireConn(m, "1.2.3.4", 1));
  // this is the bug this fix closes: the rejected attempt above must not have
  // been counted, otherwise closing the one real connection still leaves the
  // IP permanently over the limit
  releaseConn(m, "1.2.3.4");
  assert.ok(tryAcquireConn(m, "1.2.3.4", 1));
});

test("gateway origin check accepts same-origin and blocks cross-origin browsers", () => {
  // native client (no Origin header) is allowed; the session check gates it
  assert.ok(originAllowed(undefined, "chat.example.com", []));
  // browser page served from the same host as the gateway
  assert.ok(originAllowed("https://chat.example.com", "chat.example.com", []));
  // a foreign site trying to open a socket in a visitor's browser
  assert.ok(!originAllowed("https://evil.example", "chat.example.com", []));
  // explicit allowlist entry (page host differs from gateway host)
  assert.ok(originAllowed("https://app.example.com", "gw.example.com", ["https://app.example.com"]));
  // a malformed Origin is rejected rather than trusted
  assert.ok(!originAllowed("not a url", "chat.example.com", []));
});

test("static routing: the landing page is at / and the chat client at /app", () => {
  assert.equal(staticRelPath("/"), "/index.html");
  assert.equal(staticRelPath("/app"), "/app.html");
  // browsers append a slash when someone types the bare path
  assert.equal(staticRelPath("/app/"), "/app.html");
  // the query string never reaches the filesystem
  assert.equal(staticRelPath("/app?v=abc"), "/app.html");
  assert.equal(staticRelPath("/?utm=x"), "/index.html");
});

test("static routing: everything else maps one to one", () => {
  assert.equal(staticRelPath("/info.html"), "/info.html");
  assert.equal(staticRelPath("/style.css?v=deadbeef"), "/style.css");
  assert.equal(staticRelPath("/icons/icon-192.png"), "/icons/icon-192.png");
  // /app is an exact route, not a prefix: it must not swallow real files
  assert.equal(staticRelPath("/app.bundle.js"), "/app.bundle.js");
  assert.equal(staticRelPath("/apple-touch-icon.png"), "/apple-touch-icon.png");
});

test("static routing: traversal attempts are passed through for the caller to reject", () => {
  // staticRelPath only maps URLs; containment is enforced against PUBLIC in
  // serveStatic, so the raw path must survive unchanged rather than be
  // silently cleaned up here
  assert.equal(staticRelPath("/../../etc/passwd"), "/../../etc/passwd");
  assert.equal(staticRelPath(""), "/index.html");
  assert.equal(staticRelPath(undefined), "/index.html");
});

test("an oversized body is refused as such, not by dropping the connection", async () => {
  // Dropping it left the caller with no status at all, which a reverse proxy
  // turns into a bare 502. The error is tagged so routes can answer 413.
  const server = http.createServer(async (req, res) => {
    try { await readBody(req, 16); res.writeHead(200).end("ok"); }
    catch (e) { res.writeHead(e.code === "E_TOO_LARGE" ? 413 : 400).end(e.code || "err"); }
  });
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  try {
    // Declared up front: refused before anything is buffered.
    const big = await fetch(`http://127.0.0.1:${port}/`, { method: "POST", body: "x".repeat(500) });
    assert.equal(big.status, 413);
    assert.equal(await big.text(), "E_TOO_LARGE");
    // Within the limit still works.
    const ok = await fetch(`http://127.0.0.1:${port}/`, { method: "POST", body: "hi" });
    assert.equal(ok.status, 200);
  } finally { server.close(); }
});
