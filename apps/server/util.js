// Small side-effect-free helpers shared by the gateway server. Split out of
// server.js so they can be unit tested directly: server.js connects to
// Postgres and starts listening the moment it's imported, which makes it
// awkward to pull individual pieces into a test file.
import crypto from "node:crypto";

export const HANDLE_RE = /^[a-z0-9_]{3,24}$/;
export const B64_RE = /^[A-Za-z0-9+/=]{1,4096}$/;
export const HEX_RE = /^[a-f0-9]{8,64}$/;

export const isB64 = (s) => typeof s === "string" && B64_RE.test(s);

export function validCard(c) {
  return c && typeof c === "object" && typeof c.handle === "string" && HANDLE_RE.test(c.handle.toLowerCase()) &&
    isB64(c.providerId) && isB64(c.mailbox) && c.kem && isB64(c.kem.x) && isB64(c.kem.kem) &&
    c.sign && isB64(c.sign.ed) && isB64(c.sign.dsa);
}

export function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > maxBytes) { req.destroy(); reject(new Error("body too large")); return; } chunks.push(c); });
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

export function json(res, code, obj) { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); }

export function timingEqual(a, b) { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }

export function hashPassword(pw) { const salt = crypto.randomBytes(16); const hash = crypto.scryptSync(pw, salt, 64); return salt.toString("hex") + "$" + hash.toString("hex"); }

export function verifyPassword(pw, stored) {
  const i = String(stored).indexOf("$"); if (i < 0) return false;
  const salt = Buffer.from(stored.slice(0, i), "hex"); const want = Buffer.from(stored.slice(i + 1), "hex");
  let got; try { got = crypto.scryptSync(pw, salt, want.length); } catch { return false; }
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

// How long an uploaded attachment's ciphertext should live, in seconds. The
// client sends this as the x-expire-sec header; 0/absent means "keep for the
// usual mailbox TTL", negative and non-numeric values fall back to that same
// default, and anything past the cap is clamped down to it.
export function clampExpireSec(raw, maxSec) {
  return Math.min(Math.max(0, Math.floor(Number(raw) || 0)), maxSec);
}
