// Small side-effect-free helpers shared by the gateway server. Split out of
// server.js so they can be unit tested directly: server.js connects to
// Postgres and starts listening the moment it's imported, which makes it
// awkward to pull individual pieces into a test file.
import crypto from "node:crypto";
import fs from "node:fs";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

export const HANDLE_RE = /^[a-z0-9_]{3,24}$/;
export const B64_RE = /^[A-Za-z0-9+/=]{1,4096}$/;
export const HEX_RE = /^[a-f0-9]{8,64}$/;
// What clients send instead of a password: 256 bits, lowercase hex, derived
// browser-side under the auth salt. Fixed length, so it is checked exactly
// rather than coerced.
export const AUTH_SECRET_RE = /^[a-f0-9]{64}$/;

export const isB64 = (s) => typeof s === "string" && B64_RE.test(s);

// Request fields are type-checked rather than coerced.
//
// String(x) turns ["kirito"] into "kirito" and [["kirito"]] into "kirito" too,
// so a JSON array walked straight through the handle check. It was not an auth
// bypass - the password was still verified - but coercion is the kind of
// looseness that turns into one after an innocent-looking refactor, and it
// hands anything downstream a value of a shape it never expected.
//
// Returns the normalised handle, or null when the field is not a plain string
// of the right shape. Callers treat null as "reject".
export function asHandle(v) {
  if (typeof v !== "string") return null;
  const h = v.toLowerCase();
  return HANDLE_RE.test(h) ? h : null;
}

// A token/id field: must be a string, and bounded so an oversized value never
// reaches the database layer.
export function asToken(v, maxLen = 256) {
  return typeof v === "string" && v.length > 0 && v.length <= maxLen ? v : null;
}

export function validCard(c) {
  return c && typeof c === "object" && typeof c.handle === "string" && HANDLE_RE.test(c.handle.toLowerCase()) &&
    isB64(c.providerId) && isB64(c.mailbox) && c.kem && isB64(c.kem.x) && isB64(c.kem.kem) &&
    c.sign && isB64(c.sign.ed) && isB64(c.sign.dsa);
}

// Read a JSON-sized request body, refusing anything over the limit.
//
// The overflow case used to call req.destroy(), which drops the connection
// mid-request: the caller never gets a status, and a reverse proxy in front
// turns that into a bare 502. An oversized body is the client's mistake and
// deserves to be told so, hence the tagged error the routes turn into 413.
//
// An honest Content-Length is rejected before a single byte is buffered; the
// running count still guards chunked bodies that declare nothing (or lie).
export function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const tooLarge = () => Object.assign(new Error("body too large"), { code: "E_TOO_LARGE" });
    const declared = Number((req.headers || {})["content-length"]);
    if (Number.isFinite(declared) && declared > maxBytes) { reject(tooLarge()); return; }
    let size = 0; const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > maxBytes) { chunks.length = 0; reject(tooLarge()); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export function readBodyBuffer(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > maxBytes) { req.destroy(); reject(new Error("body too large")); return; } chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// Stream a request body straight to a file, enforcing the size limit as the
// bytes arrive. Nothing is buffered in memory, so a 500 MB upload costs a few
// chunk-sized buffers instead of half a gigabyte of process RAM. Returns the
// byte count; on any failure (limit exceeded, disk error, aborted request)
// the partial file is removed and the error rethrown.
export async function streamToFile(req, filePath, maxBytes) {
  let size = 0;
  const limit = new Transform({
    transform(chunk, _enc, cb) {
      size += chunk.length;
      // tag the limit error so the caller can tell "too big" (413) apart from a
      // disk error or an aborted upload (which are not the client's fault)
      if (size > maxBytes) cb(Object.assign(new Error("body too large"), { code: "E_TOO_LARGE" }));
      else cb(null, chunk);
    },
  });
  try {
    await pipeline(req, limit, fs.createWriteStream(filePath, { flags: "wx" }));
    return size;
  } catch (e) {
    try { await fs.promises.unlink(filePath); } catch { /* never existed */ }
    throw e;
  }
}

export function json(res, code, obj) { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); }

export function timingEqual(a, b) { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }

// Decide whether a WebSocket handshake's Origin may open the gateway. Browsers
// always send Origin, so a cross-origin page can't silently open a socket on a
// visitor's behalf. Native clients send no Origin and are allowed (the session
// check on subscribe is the real gate). Same-origin (page host == gateway host)
// always passes; extra hosts come from the allowlist.
export function originAllowed(originHeader, hostHeader, allowedOrigins = []) {
  if (!originHeader) return true; // non-browser client
  let host;
  try { host = new URL(originHeader).host; } catch { return false; }
  if (hostHeader && host === hostHeader) return true;
  return allowedOrigins.includes(originHeader);
}

// scrypt runs on libuv's thread pool via the async API. The sync variant
// blocked the whole event loop for the duration of the KDF, which froze every
// websocket and all message routing while someone logged in (or hammered the
// login endpoint on purpose).
const scrypt = (pw, salt, keylen) =>
  new Promise((resolve, reject) => crypto.scrypt(pw, salt, keylen, (err, key) => (err ? reject(err) : resolve(key))));

export async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(pw, salt, 64);
  return salt.toString("hex") + "$" + hash.toString("hex");
}

export async function verifyPassword(pw, stored) {
  const i = String(stored).indexOf("$"); if (i < 0) return false;
  const salt = Buffer.from(stored.slice(0, i), "hex"); const want = Buffer.from(stored.slice(i + 1), "hex");
  // a corrupt stored value with an empty hash would make keylen 0 and match
  // every password, so refuse it outright
  if (salt.length !== 16 || want.length === 0) return false;
  let got; try { got = await scrypt(pw, salt, want.length); } catch { return false; }
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

// Work out who is actually calling, from behind our reverse proxy.
//
// X-Forwarded-For is append-only and every hop trusts the value it was handed,
// so the LEFTMOST entry is whatever the client felt like sending - it is not
// evidence of anything. Reading that entry made every per-IP limit here
// (login/register throttling, connection caps) trivially bypassable: send a
// fresh fake XFF on each request and every attempt looks like a new visitor.
//
// Only the entries our own proxies appended can be trusted. Each hop appends
// the address it received the connection from, so with `hops` trusted proxies
// in front of us the real client address is the `hops`-th entry counted from
// the right. Anything to the left of it is attacker-controlled and ignored.
// With no proxy in front (hops = 0) we ignore the header entirely and use the
// socket address, which cannot be forged.
export function clientIp(req, hops = 1) {
  const n = Math.max(0, Math.floor(Number(hops) || 0));
  const direct = (req.socket && req.socket.remoteAddress) || "unknown";
  if (n === 0) return direct;
  const raw = req.headers && req.headers["x-forwarded-for"];
  if (!raw) return direct;
  const parts = String(raw).split(",").map((s) => s.trim()).filter(Boolean);
  // Fewer entries than trusted hops means the header did not come through the
  // expected chain; fall back to the socket rather than trusting a short list.
  if (parts.length < n) return direct;
  return parts[parts.length - n] || direct;
}

// Per-IP WebSocket connection accounting for the gateway's connection cap.
// A slot is only counted once a connection is actually accepted; releaseConn
// undoes exactly that accounting when it later closes. Counting a rejected
// attempt (over the limit) and never releasing it would let the map entry for
// that IP only ever grow, since a socket that never opened also never fires
// a close event to release it, permanently locking that IP out.
export function tryAcquireConn(map, ip, max) {
  const n = (map.get(ip) || 0) + 1;
  if (n > max) return false;
  map.set(ip, n);
  return true;
}

export function releaseConn(map, ip) {
  const left = (map.get(ip) || 1) - 1;
  if (left <= 0) map.delete(ip); else map.set(ip, left);
}

// Per-account login throttle with exponential backoff.
//
// The per-IP token bucket alone is not enough: an attacker with a pool of
// addresses gets a fresh allowance from each one, while a single account is
// hammered as hard as they like. This tracks failures per handle instead, so
// guessing one account's password gets slower no matter where the attempts
// come from.
//
// Keyed on the submitted handle whether or not it exists, so a locked-out
// response never doubles as an account-existence oracle.
//
// Deliberately capped and self-pruning: a map keyed by attacker-supplied
// handles is otherwise an unbounded-growth sink. Entries expire once the
// backoff has elapsed, and at the cap the oldest entries are dropped first
// (Map iterates in insertion order).
// The failure count deliberately outlives the current backoff window
// (`forgetAfterMs`). If the counter reset the moment a lock expired, an
// attacker would simply wait out each delay and get another full `threshold`
// of free guesses forever - the backoff would never actually escalate.
export function makeLockout({ threshold = 5, baseDelayMs = 1000, maxDelayMs = 15 * 60 * 1000, forgetAfterMs = 60 * 60 * 1000, maxEntries = 10000 } = {}) {
  const hits = new Map();
  const delayFor = (fails) => {
    if (fails < threshold) return 0;
    const steps = Math.min(fails - threshold, 20); // 2^20 already exceeds maxDelayMs
    return Math.min(maxDelayMs, baseDelayMs * 2 ** steps);
  };
  const prune = (now) => {
    for (const [k, e] of hits) if (e.forgetAt <= now) hits.delete(k);
    while (hits.size > maxEntries) hits.delete(hits.keys().next().value);
  };
  return {
    // How long this key must wait, in seconds. 0 means "go ahead".
    retryAfter(key, now = Date.now()) {
      const e = hits.get(key);
      if (!e) return 0;
      if (e.forgetAt <= now) { hits.delete(key); return 0; }
      if (e.until <= now) return 0; // lock elapsed, but the history stays
      return Math.ceil((e.until - now) / 1000);
    },
    fail(key, now = Date.now()) {
      const prev = hits.get(key);
      const e = prev && prev.forgetAt > now ? prev : { fails: 0, until: 0, forgetAt: 0 };
      e.fails += 1;
      e.until = now + delayFor(e.fails);
      e.forgetAt = Math.max(now + forgetAfterMs, e.until);
      // Re-insert so the entry counts as recently used for the cap eviction.
      hits.delete(key); hits.set(key, e);
      if (hits.size > maxEntries || e.fails % 32 === 0) prune(now);
      return Math.ceil(delayFor(e.fails) / 1000);
    },
    // A correct password clears the record, so a legitimate user who mistyped
    // a few times is not left throttled.
    succeed(key) { hits.delete(key); },
    size() { return hits.size; },
  };
}

// Map a request URL onto a path under the public directory. "/" serves the
// public landing page; the chat client itself lives at "/app" (it used to be
// at "/", so the old URL still has to land somewhere sensible for anyone who
// bookmarked it - the landing page links straight on). A trailing slash is
// accepted because browsers add one when a user types the bare path.
// Everything else maps one to one and is resolved against PUBLIC by the
// caller, which is also where the path-traversal check happens.
export function staticRelPath(url) {
  const p = String(url || "/").split("?")[0];
  if (p === "/") return "/index.html";
  if (p === "/app" || p === "/app/") return "/app.html";
  return p;
}

// How long an uploaded attachment's ciphertext should live, in seconds. The
// client sends this as the x-expire-sec header; 0/absent means "keep for the
// usual mailbox TTL", negative and non-numeric values fall back to that same
// default, and anything past the cap is clamped down to it.
export function clampExpireSec(raw, maxSec) {
  return Math.min(Math.max(0, Math.floor(Number(raw) || 0)), maxSec);
}
