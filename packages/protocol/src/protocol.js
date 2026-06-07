// Content + end-to-end envelope + addressing for NobleChat.
//
// Layering: [ mix payload ] wraps [ mailboxId | E2E envelope ] and the E2E
// envelope wraps the hybrid-KEM ciphertext + AEAD of the actual content JSON.
// Mix nodes and the provider never see plaintext; only the recipient's keys
// open the envelope.
import {
  encapsulate, decapsulate, seal, open, hash,
  utf8ToBytes, bytesToUtf8, concatBytes,
} from "../../crypto/src/index.js";
import { pack, unpack } from "./wire.js";

export const MAILBOX_LEN = 16;

// Stable mailbox address derived from a recipient's public KEM bundle.
export function mailboxId(kemBundle) {
  return hash(concatBytes(kemBundle.x, kemBundle.kem)).subarray(0, MAILBOX_LEN);
}

// ---- content ----
export function encodeContent(obj) {
  return utf8ToBytes(JSON.stringify(obj));
}
export function decodeContent(bytes) {
  return JSON.parse(bytesToUtf8(bytes));
}

// ---- end-to-end envelope (hybrid PQ KEM + AEAD) ----
export function sealEnvelope(recipientKemBundle, contentBytes) {
  const { header, sharedSecret } = encapsulate(recipientKemBundle);
  const aead = seal(sharedSecret, contentBytes);
  return pack([header.epk, header.kct, aead]);
}
export function openEnvelope(kemKeypair, envelopeBytes) {
  const [epk, kct, aead] = unpack(envelopeBytes, 3);
  const sharedSecret = decapsulate(kemKeypair, { epk, kct });
  return open(sharedSecret, aead);
}

// ---- mix inner payload: [ mailboxId | envelope ] ----
export function packInner(mailbox, envelope) {
  return pack([mailbox, envelope]);
}
export function unpackInner(inner) {
  const [mailbox, envelope] = unpack(inner, 2);
  return { mailbox, envelope };
}
