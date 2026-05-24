// Key derivation + hashing.
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { utf8ToBytes } from "./util.js";

export function hash(bytes) {
  return sha256(bytes);
}

// HKDF-SHA256. `info` may be a string or bytes.
export function deriveKey(ikm, salt, info, length = 32) {
  const infoBytes = typeof info === "string" ? utf8ToBytes(info) : info;
  const saltBytes = salt ?? new Uint8Array(0);
  return hkdf(sha256, ikm, saltBytes, infoBytes, length);
}
