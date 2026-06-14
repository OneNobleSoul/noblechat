// JSON-safe (base64) serialization for transport between browser and gateway,
// plus a browser-side view of the network that can pick paths.
import { toB64, fromB64 } from "../../crypto/src/util.js";

export function serializePacket(pkt) {
  return {
    a: toB64(pkt.header.alpha),
    b: toB64(pkt.header.beta),
    g: toB64(pkt.header.gamma),
    p: toB64(pkt.payload),
  };
}
export function deserializePacket(o) {
  return {
    header: { alpha: fromB64(o.a), beta: fromB64(o.b), gamma: fromB64(o.g) },
    payload: fromB64(o.p),
  };
}

function serBundleKem(k) { return { x: toB64(k.x), kem: toB64(k.kem) }; }
function deBundleKem(k) { return { x: fromB64(k.x), kem: fromB64(k.kem) }; }
function serBundleSign(k) { return { ed: toB64(k.ed), dsa: toB64(k.dsa) }; }
function deBundleSign(k) { return { ed: fromB64(k.ed), dsa: fromB64(k.dsa) }; }

export function serializeCard(card) {
  return {
    handle: card.handle,
    providerId: toB64(card.providerId),
    mailbox: toB64(card.mailbox),
    kem: serBundleKem(card.kem),
    sign: serBundleSign(card.sign),
  };
}
export function deserializeCard(o) {
  return {
    handle: o.handle,
    providerId: fromB64(o.providerId),
    mailbox: fromB64(o.mailbox),
    kem: deBundleKem(o.kem),
    sign: deBundleSign(o.sign),
  };
}

function serKp(kp) { return { publicKey: toB64(kp.publicKey), secretKey: toB64(kp.secretKey) }; }
function deKp(kp) { return { publicKey: fromB64(kp.publicKey), secretKey: fromB64(kp.secretKey) }; }

export function serializeIdentity(id) {
  return {
    handle: id.handle,
    providerId: toB64(id.providerId),
    mailbox: toB64(id.mailbox),
    kem: { x: serKp(id.kem.x), kem: serKp(id.kem.kem) },
    sign: { ed: serKp(id.sign.ed), dsa: serKp(id.sign.dsa) },
    card: serializeCard(id.card),
  };
}
export function deserializeIdentity(o) {
  return {
    handle: o.handle,
    providerId: fromB64(o.providerId),
    mailbox: fromB64(o.mailbox),
    kem: { x: deKp(o.kem.x), kem: deKp(o.kem.kem) },
    sign: { ed: deKp(o.sign.ed), dsa: deKp(o.sign.dsa) },
    card: deserializeCard(o.card),
  };
}

// Build a client-side network object from the public directory view.
export function makeBrowserNet(view) {
  const layers = view.layers.map((row) => row.map((n) => ({ id: fromB64(n.id), public: fromB64(n.public) })));
  const providers = view.providers.map((p) => ({ id: fromB64(p.id), public: fromB64(p.public), label: p.label }));
  return {
    layers,
    providers,
    pickPath(providerIdBytes) {
      const pid = toB64(providerIdBytes);
      const path = layers.map((row) => row[Math.floor(Math.random() * row.length)]);
      const provider = providers.find((p) => toB64(p.id) === pid);
      if (!provider) throw new Error("unknown provider");
      path.push(provider);
      return path.map((n) => ({ id: n.id, public: n.public }));
    },
  };
}
