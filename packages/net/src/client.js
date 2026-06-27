// Isomorphic client helpers (run in Node tests and in the browser).
import {
  generateKemKeypair, kemPublicBundle, generateSignKeypair, signPublicBundle,
} from "../../crypto/src/index.js";
import { createPacket } from "../../sphinx/src/sphinx.js";
import {
  mailboxId, encodeContent, decodeContent, sealEnvelope, openEnvelope, packInner,
} from "../../protocol/src/protocol.js";

// A full identity keeps secrets; `card` is the public contact info others use.
export function generateIdentity(handle, providerId) {
  const kem = generateKemKeypair();
  const sign = generateSignKeypair();
  const kemBundle = kemPublicBundle(kem);
  const mailbox = mailboxId(kemBundle);
  return {
    handle,
    providerId,
    kem,
    sign,
    mailbox,
    card: { handle, providerId, mailbox, kem: kemBundle, sign: signPublicBundle(sign) },
  };
}

// Yield back to the event loop so the browser can paint between the heavy,
// synchronous key-generation steps. (setTimeout(0) also flushes rendering,
// which a bare microtask/await would not.)
const yieldToPaint = () => new Promise((r) => setTimeout(r, 0));

// Same result as generateIdentity(), but async and instrumented: it reports
// real, staged progress via onProgress(percent, label) and hands control back
// to the browser between stages so the UI stays alive. Any exception thrown by
// the crypto propagates to the caller instead of vanishing.
export async function generateIdentityStaged(handle, providerId, onProgress = () => {}) {
  onProgress(6, "starting");
  await yieldToPaint();

  onProgress(24, "hybrid key exchange · X25519 + ML-KEM-768");
  await yieldToPaint();
  const kem = generateKemKeypair();

  onProgress(58, "post-quantum signatures · Ed25519 + ML-DSA-65");
  await yieldToPaint();
  const sign = generateSignKeypair();

  onProgress(82, "assembling your identity card");
  await yieldToPaint();
  const kemBundle = kemPublicBundle(kem);
  const mailbox = mailboxId(kemBundle);
  const card = { handle, providerId, mailbox, kem: kemBundle, sign: signPublicBundle(sign) };

  onProgress(100, "ready");
  await yieldToPaint();
  return { handle, providerId, kem, sign, mailbox, card };
}

// Build a mix packet carrying an end-to-end encrypted message for `recipientCard`.
// `net` must expose pickPath(providerId).
export function buildOutgoing(net, recipientCard, contentObj) {
  const path = net.pickPath(recipientCard.providerId);
  const envelope = sealEnvelope(recipientCard.kem, encodeContent(contentObj));
  const inner = packInner(recipientCard.mailbox, envelope);
  const packet = createPacket(path, inner);
  return { firstNodeId: path[0].id, packet };
}

// Decrypt a delivered envelope with our own keys.
export function openIncoming(identity, envelope) {
  return decodeContent(openEnvelope(identity.kem, envelope));
}

// A cover-traffic loop: a real, indistinguishable packet addressed to ourselves.
// The recipient (us) recognises the {t:"cover"} marker after decryption and
// silently drops it. To the network it is identical to a genuine message.
export function buildCoverLoop(net, identity) {
  return buildOutgoing(net, identity.card, { t: "cover", ts: 0 });
}
