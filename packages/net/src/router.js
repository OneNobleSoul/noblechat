// In-process mix network router.
//
// Each hop peels one Sphinx layer, waits an *exponentially distributed* delay
// (Poisson mixing — no fixed batch an observer could time), then forwards to
// the next hop. The provider at the end delivers the inner payload to a mailbox.
// The router itself can NOT tell real messages from cover traffic: every packet
// is the same size and equally opaque.
import { processPacket } from "../../sphinx/src/sphinx.js";
import { unpackInner } from "../../protocol/src/protocol.js";
import { toB64 } from "../../crypto/src/util.js";

function poissonDelay(meanMs) {
  return -meanMs * Math.log(1 - Math.random());
}

// Default mailbox store: in-memory queue per mailbox. The gateway swaps in a
// durable (SQLite-backed) store so ciphertext survives restarts and reaches
// recipients who were offline. Interface: push(key, env), drain(key) -> env[].
function memMailboxStore() {
  const m = new Map();
  return {
    push(k, env) { const a = m.get(k); if (a) a.push(env); else m.set(k, [env]); },
    drain(k) { const a = m.get(k); if (!a || !a.length) return []; m.set(k, []); return a; },
  };
}

export class Mixnet {
  constructor(directory, { meanDelayMs = 40, onHop = null, mailboxStore = null } = {}) {
    this.dir = directory;
    this.meanDelayMs = meanDelayMs;
    this.onHop = onHop;
    this.mailboxStore = mailboxStore || memMailboxStore();
    this.subs = new Map(); // key -> Set<cb>
    this.stats = { forwarded: 0, delivered: 0 };
  }

  _key(providerId, mailbox) {
    return toB64(providerId) + ":" + toB64(mailbox);
  }

  subscribe(providerId, mailbox, cb) {
    const k = this._key(providerId, mailbox);
    if (!this.subs.has(k)) this.subs.set(k, new Set());
    this.subs.get(k).add(cb);
    // flush anything queued while this mailbox was offline
    for (const env of this.mailboxStore.drain(k)) cb(env);
    return () => this.subs.get(k)?.delete(cb);
  }

  _deliver(providerId, payload) {
    let inner;
    try {
      inner = unpackInner(payload);
    } catch {
      return; // malformed / cover that didn't parse — silently drop
    }
    const k = this._key(providerId, inner.mailbox);
    this.stats.delivered++;
    const subs = this.subs.get(k);
    if (subs && subs.size) {
      for (const cb of subs) cb(inner.envelope);
    } else {
      this.mailboxStore.push(k, inner.envelope);
    }
  }

  // Inject a packet at a given node id (the client sends to the first hop).
  inject(nodeId, packet) {
    const node = this.dir.lookup(nodeId);
    if (!node) return; // unknown node → drop
    let result;
    try {
      result = processPacket(node.key.secret, packet);
    } catch {
      return; // failed MAC / tampered → drop
    }
    if (this.onHop) this.onHop(node.label);
    this.stats.forwarded++;
    if (result.final) {
      this._deliver(node.id, result.payload);
      return;
    }
    setTimeout(() => this.inject(result.nextId, result.packet), poissonDelay(this.meanDelayMs));
  }
}
