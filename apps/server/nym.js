// Connection to the nym-client sidecar. The sidecar keeps a long-lived
// identity on the public Nym mixnet; browsers in "nym" transport mode send
// their (already end-to-end encrypted) packets to its address instead of into
// our internal mix fleet. We receive them here and hand them to the same
// mailbox delivery path the internal providers use.
//
// Wire format of a payload arriving over Nym: a JSON string
//   { v: 1, p: <b64 providerId>, i: <b64 inner bytes> }
// where `i` is the exact inner packet (mailbox + envelope) the internal
// providers produce, so delivery code downstream stays identical.

import WebSocket from "ws";

export function parseNymPayload(text, maxBytes = 256 * 1024) {
  if (typeof text !== "string" || text.length > maxBytes) return null;
  let m;
  try { m = JSON.parse(text); } catch { return null; }
  if (!m || m.v !== 1 || typeof m.p !== "string" || typeof m.i !== "string") return null;
  if (!/^[A-Za-z0-9+/=]{1,128}$/.test(m.p) || !/^[A-Za-z0-9+/=]{1,262144}$/.test(m.i)) return null;
  return { providerId: m.p, inner: m.i };
}

// Maintains a websocket to the sidecar with reconnect + backoff. `onPayload`
// gets (providerIdB64, innerB64) for every valid incoming mixnet message.
export function connectNym(url, { onPayload = () => {}, onLog = () => {} } = {}) {
  let ws = null;
  let address = null;
  let connected = false;
  let closed = false;
  let backoff = 1000;

  function open() {
    if (closed) return;
    ws = new WebSocket(url);
    ws.on("open", () => {
      backoff = 1000;
      try { ws.send(JSON.stringify({ type: "selfAddress" })); } catch { /* */ }
    });
    ws.on("message", (raw) => {
      let m;
      try { m = JSON.parse(raw.toString()); } catch { return; }
      if (m.type === "selfAddress" && typeof m.address === "string") {
        address = m.address;
        if (!connected) { connected = true; onLog("info", "nym sidecar connected", address.slice(0, 24) + "..."); }
        return;
      }
      if (m.type === "received" && typeof m.message === "string") {
        const p = parseNymPayload(m.message);
        if (p) onPayload(p.providerId, p.inner);
      }
    });
    const down = () => {
      if (connected) onLog("warn", "nym sidecar disconnected");
      connected = false; address = null;
      if (closed) return;
      setTimeout(open, backoff);
      backoff = Math.min(backoff * 2, 30000);
    };
    ws.on("close", down);
    ws.on("error", () => { try { ws.close(); } catch { /* */ } });
  }
  open();

  return {
    isConnected: () => connected,
    getAddress: () => address,
    close: () => { closed = true; try { ws && ws.close(); } catch { /* */ } },
  };
}
