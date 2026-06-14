// NobleChat gateway + local testnet.
//
// This process runs the mix network (directory + mix nodes + providers) and a
// thin gateway. It is deliberately ZERO-KNOWLEDGE about content: browsers do all
// key generation and encryption locally and only ever hand the gateway opaque,
// fixed-size onion packets plus a mailbox to deliver ciphertext to. The key
// directory below stores nothing but public contact cards.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import { buildTestnet } from "../../packages/net/src/directory.js";
import { Mixnet } from "../../packages/net/src/router.js";
import { deserializePacket } from "../../packages/net/src/serialize.js";
import { fromB64, toB64 } from "../../packages/crypto/src/util.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.resolve(__dirname, "../web/public");
const PORT = Number(process.env.PORT || 8790);
const MEAN_DELAY_MS = Number(process.env.MEAN_DELAY_MS || 60);

const dir = buildTestnet({ layers: 3, perLayer: 3, providers: 2 });

// broadcast hop events (node labels only) so the UI can visualise the flow
const sockets = new Set();
const mix = new Mixnet(dir, {
  meanDelayMs: MEAN_DELAY_MS,
  onHop: (label) => {
    const msg = JSON.stringify({ t: "hop", label });
    for (const ws of sockets) if (ws.readyState === 1) ws.send(msg);
  },
});

// in-memory public key directory (public cards only)
const cards = new Map();

const MIME = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".json": "application/json" };

function serveStatic(req, res) {
  let rel = req.url.split("?")[0];
  if (rel === "/") rel = "/index.html";
  const file = path.join(PUBLIC, path.normalize(rel).replace(/^(\.\.[/\\])+/, ""));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403).end(); return; }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404).end("not found"); return; }
    res.writeHead(200, { "content-type": MIME[path.extname(file)] || "application/octet-stream" });
    res.end(data);
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => resolve(b));
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/api/net") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ view: dir.publicView(), meanDelayMs: MEAN_DELAY_MS }));
    return;
  }
  if (url.pathname === "/api/publish" && req.method === "POST") {
    try {
      const card = JSON.parse(await readBody(req));
      if (!card.handle) throw new Error("no handle");
      cards.set(card.handle.toLowerCase(), card);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    } catch (e) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(e.message) }));
    }
    return;
  }
  if (url.pathname === "/api/card") {
    const c = cards.get((url.searchParams.get("handle") || "").toLowerCase());
    if (!c) { res.writeHead(404).end("{}"); return; }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(c));
    return;
  }
  serveStatic(req, res);
});

const wss = new WebSocketServer({ server, path: "/gateway" });
wss.on("connection", (ws) => {
  sockets.add(ws);
  let unsub = null;
  ws.on("message", (raw) => {
    let m;
    try { m = JSON.parse(raw.toString()); } catch { return; }
    if (m.t === "submit") {
      try { mix.inject(fromB64(m.node), deserializePacket(m.packet)); } catch {}
    } else if (m.t === "subscribe") {
      if (unsub) unsub();
      unsub = mix.subscribe(fromB64(m.provider), fromB64(m.mailbox), (env) => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ t: "deliver", envelope: toB64(env) }));
      });
    }
  });
  ws.on("close", () => { sockets.delete(ws); if (unsub) unsub(); });
});

server.listen(PORT, () => {
  console.log(`NobleChat gateway on http://localhost:${PORT}  (mix delay ~${MEAN_DELAY_MS}ms/hop)`);
});
