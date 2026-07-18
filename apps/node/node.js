// A single NobleChat mix node. It holds exactly ONE node's secret key. It peels
// one Sphinx layer off each packet it receives, waits an exponentially
// distributed delay (Poisson mixing), then forwards to the NEXT node over the
// network. A node never learns more than its own hop: the previous sender and
// the next hop, nothing about the rest of the path or the content.
import http from "node:http";
import { buildTestnet } from "../../packages/net/src/directory.js";
import { processPacket } from "../../packages/sphinx/src/sphinx.js";
import { deserializePacket, serializePacket } from "../../packages/net/src/serialize.js";
import { toB64 } from "../../packages/crypto/src/util.js";

const CFG = {
  label: process.env.NODE_LABEL,
  seed: process.env.NET_SEED || null,
  gateway: process.env.GATEWAY_URL || "http://noblechat:8790",
  token: process.env.INTERNAL_TOKEN || "",
  port: Number(process.env.PORT || 8890),
  meanDelayMs: Number(process.env.MEAN_DELAY_MS || 60),
  layers: Number(process.env.LAYERS || 3),
  perLayer: Number(process.env.PER_LAYER || 2),
  providers: Number(process.env.PROVIDERS || 2),
};

const dir = buildTestnet({ layers: CFG.layers, perLayer: CFG.perLayer, providers: CFG.providers, seed: CFG.seed, mixPort: CFG.port });

let self = null;
for (const row of dir.layers) for (const n of row) if (n.label === CFG.label) self = n;
for (const p of dir.providers) if (p.label === CFG.label) self = p;
if (!self) { console.error("mix node: unknown NODE_LABEL", CFG.label); process.exit(1); }

const poisson = (m) => -m * Math.log(1 - Math.random());
async function post(url, body) {
  try { await fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-internal": CFG.token }, body: JSON.stringify(body) }); }
  catch { /* drop on failure — a dropped packet is indistinguishable from cover */ }
}

function handlePacket(pktObj) {
  let pkt; try { pkt = deserializePacket(pktObj); } catch { return; }
  let result; try { result = processPacket(self.key.secret, pkt); } catch { return; } // bad MAC / tampered → drop
  post(CFG.gateway + "/internal/hop", { label: CFG.label }); // best-effort viz
  if (result.final) {
    post(CFG.gateway + "/internal/deliver", { providerId: toB64(self.id), payload: toB64(result.payload) });
  } else {
    const url = dir.urlOf(result.nextId);
    if (url) setTimeout(() => post(url, { packet: serializePacket(result.packet) }), poisson(CFG.meanDelayMs));
  }
}

const server = http.createServer((req, res) => {
  if (req.url === "/healthz") { res.writeHead(200).end("ok"); return; }
  if (req.url === "/mix" && req.method === "POST") {
    if (!CFG.token || req.headers["x-internal"] !== CFG.token) { res.writeHead(401).end(); return; }
    let body = ""; let size = 0;
    req.on("data", (c) => { size += c.length; if (size > 256 * 1024) req.destroy(); else body += c; });
    req.on("end", () => {
      res.writeHead(202).end();
      let m; try { m = JSON.parse(body); } catch { return; }
      if (m && m.packet) handlePacket(m.packet);
    });
    req.on("error", () => {});
    return;
  }
  res.writeHead(404).end();
});
server.listen(CFG.port, () => console.log(`mix node ${CFG.label} on :${CFG.port} → forwards to peers`));
process.on("uncaughtException", (e) => console.error("uncaught", e));
process.on("unhandledRejection", (e) => console.error("unhandled", e));
