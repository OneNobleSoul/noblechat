// Small byte helpers shared across NobleChat crypto.
import { randomBytes } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha2";

export { randomBytes };

// Cryptographically secure float in [0, 1). Math.random is NOT a CSPRNG and is
// predictable, which would weaken mix-path selection and mixing/cover-traffic
// timing (an observer who can predict them shrinks the anonymity set). Draws 56
// bits of CSPRNG entropy via randomBytes (crypto.getRandomValues / node crypto).
export function randomUnitFloat() {
  const b = randomBytes(7);
  let v = 0;
  for (let i = 0; i < 7; i++) v = v * 256 + b[i];
  return v / 72057594037927936; // 2**56
}

// Uniform integer in [0, n) from the CSPRNG, using rejection sampling so there
// is no modulo bias. Used to pick mix nodes for a path.
export function randomIndex(n) {
  if (n <= 1) return 0;
  const limit = Math.floor(0x100000000 / n) * n; // largest multiple of n <= 2**32
  let x;
  do {
    const b = randomBytes(4);
    x = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  } while (x >= limit);
  return x % n;
}

export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

const enc = new TextEncoder();
const dec = new TextDecoder();
export const utf8ToBytes = (s) => enc.encode(s);
export const bytesToUtf8 = (b) => dec.decode(b);

export function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Constant-time comparison to avoid timing side channels.
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// base64 (works in Node and browser)
export function toB64(bytes) {
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
export function fromB64(b64) {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(b64, "base64"));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Order-independent fingerprint (hex SHA-256) of a set of signing public-key
// pairs (each { ed, dsa } as bytes). Used for TOFU key pinning: a stable id for
// "whose signing keys are these", so a later silent substitution by a malicious
// server can be detected and surfaced to the user.
export function keysFingerprint(signKeys) {
  const parts = (signKeys || []).map((k) => toB64(k.ed) + "." + toB64(k.dsa)).sort();
  return toHex(sha256(utf8ToBytes(parts.join("|"))));
}
