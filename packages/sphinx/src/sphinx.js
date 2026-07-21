// NobleSphinx - a Sphinx-style mix packet with real key blinding.
//
// Every packet is the SAME fixed size. It is wrapped in one encryption layer
// per mix hop; each hop peels exactly one layer, learns ONLY the next hop, and
// re-blinds the ephemeral key so the packet looks unrelated to what it forwards
// (bitwise unlinkability). Built on Ristretto255 (prime-order group) so the
// blinding arithmetic is exact.
//
// Faithful to Danezis-Goldberg Sphinx (header + filler + payload onion).
import { RistrettoPoint, ed25519 } from "@noble/curves/ed25519";
import { chacha20 } from "@noble/ciphers/chacha";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha2";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes, concatBytes, utf8ToBytes } from "../../crypto/src/util.js";

const L = ed25519.CURVE.n;
export const K = 16; // security parameter / block half
export const MAX_HOPS = 5;
export const R = MAX_HOPS;
export const BETA_LEN = (2 * R + 1) * K; // 176
// Holds a full ML-KEM-768 ciphertext (1088B) + hybrid signature (Ed25519 64B
// + ML-DSA-65 3309B) + content, with headroom for file metadata and group
// member lists. Constant for every packet, so size leaks nothing.
export const PAYLOAD_LEN = 8192;
export const HOP_ID_LEN = K; // 16
export const HEADER_LEN = 32 + BETA_LEN + K; // alpha + beta + gamma

// A 16-byte marker in the "next hop id" slot meaning "you are the exit".
export const FINAL_MARKER = utf8ToBytes("NOBLECHAT::FINAL");

// ---- scalar helpers -------------------------------------------------------
function mod(a, m = L) {
  return ((a % m) + m) % m;
}
function bytesToNumberLE(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}
function randScalar() {
  const n = mod(bytesToNumberLE(sha512(randomBytes(32))));
  return n === 0n ? 1n : n;
}

// ---- symmetric primitives keyed by the per-hop shared secret --------------
function subkey(name, sBytes) {
  return sha256(concatBytes(utf8ToBytes(name), sBytes)); // 32 bytes
}
function prg(key, len) {
  return chacha20(key, new Uint8Array(12), new Uint8Array(len));
}
function mac(key, data) {
  return hmac(sha512, key, data).subarray(0, K);
}
function blindingFactor(alphaBytes, sBytes) {
  const h = sha512(concatBytes(utf8ToBytes("blind"), alphaBytes, sBytes));
  const b = mod(bytesToNumberLE(h));
  return b === 0n ? 1n : b;
}
function xorBytes(a, b) {
  const n = Math.min(a.length, b.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = a[i] ^ b[i];
  return out;
}
function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ---- node keys ------------------------------------------------------------
export function generateNodeKey(seed = null) {
  // With a seed the key is deterministic (stable topology across restarts);
  // without one it stays random, exactly as before.
  let secret;
  if (seed) {
    const n = mod(bytesToNumberLE(sha512(seed)));
    secret = n === 0n ? 1n : n;
  } else {
    secret = randScalar();
  }
  const pub = RistrettoPoint.BASE.multiply(secret).toRawBytes();
  return { secret, public: pub };
}

// ---- shared secrets along a path -----------------------------------------
function computeSharedSecrets(pathPubs) {
  const x = randScalar();
  let acc = x;
  const alphas = [];
  const secrets = [];
  for (let i = 0; i < pathPubs.length; i++) {
    const alpha = RistrettoPoint.BASE.multiply(acc);
    const pk = RistrettoPoint.fromHex(pathPubs[i]);
    const s = pk.multiply(acc).toRawBytes();
    const alphaBytes = alpha.toRawBytes();
    alphas.push(alphaBytes);
    secrets.push(s);
    acc = mod(acc * blindingFactor(alphaBytes, s));
  }
  return { alphas, secrets };
}

// ---- header construction --------------------------------------------------
function createHeader(path, secrets, alphas) {
  const nu = path.length;

  // filler string φ
  let phi = new Uint8Array(0);
  for (let i = 1; i < nu; i++) {
    const min = (2 * (R - i) + 3) * K;
    const rho = prg(subkey("rho", secrets[i - 1]), BETA_LEN + 2 * K);
    const ext = concatBytes(phi, new Uint8Array(2 * K));
    phi = xorBytes(ext, rho.subarray(min));
  }

  // last hop beta
  const finalLen = (2 * (R - nu) + 3) * K;
  const finalBlock = new Uint8Array(finalLen);
  finalBlock.set(FINAL_MARKER, 0); // "you are the exit"
  let beta = concatBytes(
    xorBytes(finalBlock, prg(subkey("rho", secrets[nu - 1]), finalLen)),
    phi,
  );
  let gamma = mac(subkey("mu", secrets[nu - 1]), beta);

  // wrap backwards
  for (let i = nu - 2; i >= 0; i--) {
    const routing = concatBytes(path[i + 1].id, gamma, beta).subarray(0, BETA_LEN);
    beta = xorBytes(routing, prg(subkey("rho", secrets[i]), BETA_LEN));
    gamma = mac(subkey("mu", secrets[i]), beta);
  }
  return { alpha: alphas[0], beta, gamma };
}

// ---- payload onion (length-preserving) -----------------------------------
function onionEncrypt(secrets, inner) {
  // refuse oversized payloads loudly - silently truncating would corrupt the
  // envelope and the message would vanish without a trace at the recipient
  if (inner.length > PAYLOAD_LEN) throw new Error(`payload too large: ${inner.length} > ${PAYLOAD_LEN}`);
  let p = inner;
  if (p.length < PAYLOAD_LEN) p = concatBytes(p, new Uint8Array(PAYLOAD_LEN - p.length));
  for (let i = secrets.length - 1; i >= 0; i--) {
    p = xorBytes(p, prg(subkey("pi", secrets[i]), PAYLOAD_LEN));
  }
  return p;
}

/**
 * Build a mix packet.
 * @param path  array of { id: Uint8Array(16), public: Uint8Array(32) } mix hops
 * @param innerPayload  up to PAYLOAD_LEN bytes (already end-to-end encrypted)
 */
export function createPacket(path, innerPayload) {
  if (path.length === 0 || path.length > MAX_HOPS) throw new Error("bad path length");
  const { alphas, secrets } = computeSharedSecrets(path.map((h) => h.public));
  const header = createHeader(path, secrets, alphas);
  const payload = onionEncrypt(secrets, innerPayload);
  return { header, payload };
}

/**
 * Process one hop. Returns either
 *   { final: true, payload }                          (this node is the exit)
 * or { final: false, nextId, packet: {header,payload} } (forward it on)
 */
export function processPacket(nodeSecret, packet) {
  const { header, payload } = packet;
  const alpha = RistrettoPoint.fromHex(header.alpha);
  const s = alpha.multiply(nodeSecret).toRawBytes();

  // integrity: reject anything tampered (defeats tagging attacks)
  if (!eqBytes(mac(subkey("mu", s), header.beta), header.gamma)) {
    throw new Error("sphinx: MAC verification failed");
  }

  // unwrap one routing layer
  const stream = prg(subkey("rho", s), BETA_LEN + 2 * K);
  const B = xorBytes(concatBytes(header.beta, new Uint8Array(2 * K)), stream);
  const nextId = B.subarray(0, HOP_ID_LEN);
  const nextGamma = B.subarray(K, 2 * K);
  const nextBeta = B.subarray(2 * K, 2 * K + BETA_LEN);

  // peel the payload onion layer
  const nextPayload = xorBytes(payload, prg(subkey("pi", s), PAYLOAD_LEN));

  if (eqBytes(nextId, FINAL_MARKER)) {
    return { final: true, payload: nextPayload };
  }

  // re-blind for the next hop
  const b = blindingFactor(header.alpha, s);
  const nextAlpha = alpha.multiply(b).toRawBytes();
  return {
    final: false,
    nextId,
    packet: { header: { alpha: nextAlpha, beta: nextBeta, gamma: nextGamma }, payload: nextPayload },
  };
}
