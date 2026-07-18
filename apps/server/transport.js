// Transport selection for the gateway. "internal" is our own mix network
// (the docker-compose node fleet); "nym" routes through the public Nym mixnet
// and needs a reachable nym-client sidecar before it can be enabled.
import net from "node:net";

export const TRANSPORTS = ["internal", "nym"];

export function isTransport(mode) {
  return TRANSPORTS.includes(mode);
}

// Cheap reachability probe for the nym-client sidecar: can we open a TCP
// connection to it? The sidecar speaks websocket on its port, so a plain HTTP
// request would hang - a connect + immediate close is enough to know it is up.
export function probeTcp(url, timeoutMs = 1500) {
  let host, port;
  try {
    const u = new URL(url);
    host = u.hostname;
    port = Number(u.port || 1977);
  } catch {
    return Promise.resolve(false);
  }
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    const done = (ok) => { try { sock.destroy(); } catch { /* */ } resolve(ok); };
    sock.setTimeout(timeoutMs, () => done(false));
    sock.on("connect", () => done(true));
    sock.on("error", () => done(false));
  });
}
