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
