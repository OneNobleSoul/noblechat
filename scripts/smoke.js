// Headless end-to-end check of the whole gateway path: two clients talk exactly
// like the browser would (fetch + WebSocket + serialized packets).
import { WebSocket } from "ws";
import { makeBrowserNet, serializePacket, serializeCard, deserializeCard } from "../packages/net/src/serialize.js";
import { generateIdentity, buildOutgoing, openIncoming } from "../packages/net/src/client.js";
import { toB64, fromB64 } from "../packages/crypto/src/util.js";

process.env.PORT = process.env.PORT || "8791";
process.env.MEAN_DELAY_MS = "5";
const BASE = `http://localhost:${process.env.PORT}`;
await import("../apps/server/server.js");
await new Promise((r) => setTimeout(r, 300));

async function makeClient(handle) {
  const { view } = await (await fetch(`${BASE}/api/net`)).json();
  const net = makeBrowserNet(view);
  const provider = net.providers[handle.charCodeAt(0) % net.providers.length];
  const id = generateIdentity(handle, provider.id);
  await fetch(`${BASE}/api/publish`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(serializeCard(id.card)) });
  const ws = new WebSocket(`ws://localhost:${process.env.PORT}/gateway`);
  const inbox = [];
  const waiters = [];
  await new Promise((res) => ws.on("open", res));
  ws.on("message", (raw) => {
    const m = JSON.parse(raw.toString());
    if (m.t === "deliver") {
      const content = openIncoming(id, fromB64(m.envelope));
      if (content.t === "msg") { inbox.push(content); waiters.shift()?.(content); }
    }
  });
  ws.send(JSON.stringify({ t: "subscribe", provider: toB64(id.providerId), mailbox: toB64(id.mailbox) }));
  return {
    id, net, ws,
    async send(toHandle, body) {
      const card = deserializeCard(await (await fetch(`${BASE}/api/card?handle=${toHandle}`)).json());
      const { firstNodeId, packet } = buildOutgoing(net, card, { v: 1, t: "msg", from: handle, body, ts: Date.now() });
      ws.send(JSON.stringify({ t: "submit", node: toB64(firstNodeId), packet: serializePacket(packet) }));
    },
    next() { return new Promise((res, rej) => { const t = setTimeout(() => rej(new Error("timeout")), 4000); waiters.push((v) => { clearTimeout(t); res(v); }); }); },
  };
}

const alice = await makeClient("alice");
const bob = await makeClient("bob");
await new Promise((r) => setTimeout(r, 100));

await alice.send("bob", "hey bob, over the mixnet");
const got = await bob.next();
console.log("bob received:", JSON.stringify(got));

await bob.send("alice", "got it, fully encrypted");
const got2 = await alice.next();
console.log("alice received:", JSON.stringify(got2));

const ok = got.body === "hey bob, over the mixnet" && got2.body === "got it, fully encrypted";
console.log(ok ? "SMOKE OK ✅" : "SMOKE FAILED ❌");
process.exit(ok ? 0 : 1);
