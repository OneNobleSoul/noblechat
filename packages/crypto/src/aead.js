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
