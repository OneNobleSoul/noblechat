// Headless end-to-end check against a RUNNING NobleChat instance: two clients
// talk exactly like the browser would (fetch + WebSocket + serialized
// packets), covering account registration, device cards, the full mix path,
// sender signature verification and the file upload round-trip.
//
// Point it at any deployment (the compose stack, or production):
//   SMOKE_URL=http://localhost:8790 npm run smoke
// It registers two throwaway accounts (smokea<ts>/smokeb<ts>); an admin can
// remove them afterwards from the admin panel.
import crypto from "node:crypto";
import { WebSocket } from "ws";
import { makeBrowserNet, serializePacket, serializeCard, deserializeCard } from "../packages/net/src/serialize.js";
import { generateIdentity, buildOutgoing, openIncoming } from "../packages/net/src/client.js";
import { toB64, fromB64 } from "../packages/crypto/src/util.js";

const BASE = (process.env.SMOKE_URL || "http://localhost:8790").replace(/\/$/, "");
const WS_BASE = BASE.replace(/^http/, "ws");
const run = Date.now().toString(36).slice(-6);

async function api(path, body, token) {
  const headers = {};
  if (token) headers.Authorization = "Bearer " + token;
  if (body !== undefined) headers["content-type"] = "application/json";
  const r = await fetch(`${BASE}${path}`, body === undefined ? { headers } : {
    method: "POST", headers, body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${path} -> ${r.status} ${j.error || ""}`);
  return j;
}

async function makeClient(handle) {
  const { view } = await api("/api/net");
  const net = makeBrowserNet(view);
  const provider = net.providers[handle.charCodeAt(0) % net.providers.length];
  const id = generateIdentity(handle, provider.id);

  // real account flow, same as the browser: register, then publish this
  // device's card under the session
  const { token } = await api("/api/account/register", { username: handle, password: "smoke-" + run + "-pass" });
  await api("/api/account/device", { token, deviceId: crypto.randomBytes(8).toString("hex"), card: serializeCard(id.card) });

  const ws = new WebSocket(`${WS_BASE}/gateway`);
  const waiters = [];
  await new Promise((res, rej) => { ws.on("open", res); ws.on("error", rej); });
  ws.on("message", (raw) => {
    const m = JSON.parse(raw.toString());
    if (m.t === "deliver") {
      const { content, verify } = openIncoming(id, fromB64(m.envelope));
      if (content.t === "msg") waiters.shift()?.({ content, verify });
    }
  });
  ws.send(JSON.stringify({ t: "subscribe", token, provider: toB64(id.providerId), mailbox: toB64(id.mailbox) }));
  return {
    id, net, ws, token, handle,
    async peerCard(toHandle) {
      const { devices } = await api(`/api/bundle?handle=${toHandle}`, undefined, token);
      return deserializeCard(devices[0]);
    },
    async send(toHandle, body) {
      const card = await this.peerCard(toHandle);
      const { firstNodeId, packet } = buildOutgoing(net, card, { v: 1, t: "msg", from: handle, to: toHandle, body, ts: Date.now() }, id.sign);
      ws.send(JSON.stringify({ t: "submit", node: toB64(firstNodeId), packet: serializePacket(packet) }));
    },
    next() { return new Promise((res, rej) => { const t = setTimeout(() => rej(new Error("timeout waiting for delivery")), 15000); waiters.push((v) => { clearTimeout(t); res(v); }); }); },
  };
}

const aliceName = `smokea${run}`, bobName = `smokeb${run}`;
const alice = await makeClient(aliceName);
const bob = await makeClient(bobName);
await new Promise((r) => setTimeout(r, 100));

await alice.send(bobName, "hey bob, over the mixnet");
const got = await bob.next();
console.log("bob received:", JSON.stringify(got.content));
const aliceCard = await bob.peerCard(aliceName);
const sigOk = got.verify(aliceCard.sign) === true;
const noForge = got.verify(bob.id.card.sign) === false;
console.log("signature verifies against alice:", sigOk, "| against bob (must be false):", noForge);

await bob.send(aliceName, "got it, fully encrypted");
const got2 = await alice.next();
console.log("alice received:", JSON.stringify(got2.content));

// file upload round-trip: opaque bytes in, identical bytes out
const payload = new Uint8Array([1, 2, 3, 251, 252, 253]);
const up = await fetch(`${BASE}/api/upload`, {
  method: "POST", headers: { "content-type": "application/octet-stream", Authorization: "Bearer " + alice.token }, body: payload,
});
const { id: fileId } = await up.json();
const downRes = await fetch(`${BASE}/api/file?id=${fileId}`, { headers: { Authorization: "Bearer " + alice.token } });
const down = new Uint8Array(await downRes.arrayBuffer());
const fileOk = up.ok && down.length === payload.length && down.every((b, i) => b === payload[i]);
console.log("file upload/download round-trip:", fileOk);
// The media type must not come back from the server: it belongs in the
// encrypted message, not in a header on an otherwise opaque blob.
const mimeHidden = !downRes.headers.get("x-file-type");
console.log("server does not echo a media type:", mimeHidden);

// Both routes used to be open. Check they now turn away a caller with no
// session, so this can't quietly regress.
const anonBundle = await fetch(`${BASE}/api/bundle?handle=${alice.handle}`);
const anonFile = await fetch(`${BASE}/api/file?id=${fileId}`);
const anonBlocked = anonBundle.status === 401 && anonFile.status === 401;
console.log("bundle and file reject anonymous callers:", anonBlocked);

const ok = got.content.body === "hey bob, over the mixnet"
  && got2.content.body === "got it, fully encrypted"
  && sigOk && noForge && fileOk && mimeHidden && anonBlocked;
console.log(ok ? "SMOKE OK" : "SMOKE FAILED");
process.exit(ok ? 0 : 1);
