// Content + end-to-end envelope + addressing for NobleChat.
//
// Layering: [ mix payload ] wraps [ mailboxId | E2E envelope ] and the E2E
// envelope wraps the hybrid-KEM ciphertext + AEAD of the actual content JSON.
// Mix nodes and the provider never see plaintext; only the recipient's keys
// open the envelope.
import {
  encapsulate, decapsulate, seal, open, hash, kemPublicBundle,
  sign, verify, utf8ToBytes, bytesToUtf8, concatBytes,
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

// ---- end-to-end envelope (hybrid PQ KEM + AEAD, sender-signed) ----
//
// Encryption alone does not authenticate the sender: anyone holding the
// recipient's public bundle could seal an envelope claiming any `from`. So the
// content is signed with the sender's hybrid signature keypair and the
// signature travels INSIDE the AEAD, where only the recipient sees it.
//
// The signature covers a transcript that also binds the recipient's KEM
// bundle. That closes the classic sign-then-encrypt hole: a recipient who
// re-encrypts a captured signed content to a third party produces an envelope
// whose signature fails there, because the third party checks the transcript
// against their own bundle.
const SIGNED_V1 = 0x01;

function signedTranscript(recipientKemBundle, contentBytes) {
  return hash(concatBytes(
    utf8ToBytes("noblechat/signed-envelope/v1"),
    recipientKemBundle.x, recipientKemBundle.kem, contentBytes,
  ));
}

export function sealEnvelope(recipientKemBundle, contentBytes, senderSignKp) {
  if (!senderSignKp) throw new Error("sealEnvelope: sender signature keypair required");
  const sig = sign(senderSignKp, signedTranscript(recipientKemBundle, contentBytes));
  const plain = concatBytes(new Uint8Array([SIGNED_V1]), pack([contentBytes, sig.ed, sig.dsa]));
  const { header, sharedSecret } = encapsulate(recipientKemBundle);
  const aead = seal(sharedSecret, plain);
  return pack([header.epk, header.kct, aead]);
}

// Returns { content, verify }. The caller MUST call verify() with the claimed
// sender's published sign bundle (any of their device cards) and only trust
// the content's `from` field if it returns true.
export function openEnvelope(kemKeypair, envelopeBytes) {
  const [epk, kct, aead] = unpack(envelopeBytes, 3);
  const sharedSecret = decapsulate(kemKeypair, { epk, kct });
  const plain = open(sharedSecret, aead);
  if (!plain.length || plain[0] !== SIGNED_V1) throw new Error("envelope: unsigned or unknown version");
  const [content, ed, dsa] = unpack(plain.subarray(1), 3);
  const transcript = signedTranscript(kemPublicBundle(kemKeypair), content);
  return {
    content,
    verify: (senderSignBundle) => verify(senderSignBundle, transcript, { ed, dsa }),
  };
}

// ---- mix inner payload: [ mailboxId | envelope ] ----
export function packInner(mailbox, envelope) {
  return pack([mailbox, envelope]);
}
export function unpackInner(inner) {
  const [mailbox, envelope] = unpack(inner, 2);
  return { mailbox, envelope };
}
