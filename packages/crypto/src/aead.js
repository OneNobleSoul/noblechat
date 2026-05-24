// Authenticated encryption with XChaCha20-Poly1305 (24-byte random nonce).
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes, concatBytes } from "./util.js";

export const NONCE_LEN = 24;

// Returns nonce || ciphertext(+tag) as one Uint8Array.
export function seal(key, plaintext, aad) {
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return concatBytes(nonce, ct);
}

// Consumes nonce || ciphertext; throws if authentication fails.
export function open(key, sealed, aad) {
  const nonce = sealed.subarray(0, NONCE_LEN);
  const ct = sealed.subarray(NONCE_LEN);
  return xchacha20poly1305(key, nonce, aad).decrypt(ct);
}

// Deterministic variant (caller supplies nonce) — used by the Sphinx layer
// where a fresh symmetric key per packet makes a zero nonce safe.
export function sealWithNonce(key, nonce, plaintext, aad) {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}
export function openWithNonce(key, nonce, ct, aad) {
  return xchacha20poly1305(key, nonce, aad).decrypt(ct);
}
