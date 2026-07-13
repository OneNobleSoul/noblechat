// NobleChat gateway.
//
// Runs the mix network (directory + mix nodes + providers) and a hardened HTTP
// gateway. It is deliberately ZERO-KNOWLEDGE about content: browsers do all key
// generation and encryption locally and only ever hand the gateway opaque,
// fixed-size onion packets plus a mailbox to deliver ciphertext to. Durable
// state (public contact cards + queued ciphertext for offline recipients) lives
// in SQLite; no plaintext and no keys are ever stored.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import { buildTestnet } from "../../packages/net/src/directory.js";
import { Mixnet } from "../../packages/net/src/router.js";
import { deserializePacket } from "../../packages/net/src/serialize.js";
import { fromB64, toB64 } from "../../packages/crypto/src/util.js";
import { openStore } from "./store.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.resolve(__dirname, "../web/public");

const CFG = {
  port: Number(process.env.PORT || 8790),
  meanDelayMs: Number(process.env.MEAN_DELAY_MS || 60),
  netSeed: process.env.NET_SEED || null,
  dataDir: process.env.DATA_DIR || path.resolve(__dirname, "../../data"),
  maxBodyBytes: Number(process.env.MAX_BODY_BYTES || 64 * 1024),
  maxWsMsgBytes: Number(process.env.MAX_WS_MSG_BYTES || 128 * 1024),
  maxConnPerIp: Number(process.env.MAX_CONN_PER_IP || 20),
  mailboxTtlMs: Number(process.env.MAILBOX_TTL_MS || 7 * 24 * 3600 * 1000),
  maxPerMailbox: Number(process.env.MAX_PER_MAILBOX || 1000),
};

const store = openStore(path.join(CFG.dataDir, "noblechat.db"), {
  mailboxTtlMs: CFG.mailboxTtlMs,
  maxPerMailbox: CFG.maxPerMailbox,
});

// Adapt the byte-oriented mailbox interface the router expects onto the
// base64 SQLite store.
const mailboxStore = {
  push: (k, env) => store.pushEnvelope(k, toB64(env)),
  drain: (k) => store.drainEnvelopes(k).map(fromB64),
};

const dir = buildTestnet({ layers: 3, perLayer: 3, providers: 2, seed: CFG.netSeed });

const sockets = new Set();
const mix = new Mixnet(dir, {
  meanDelayMs: CFG.meanDelayMs,
  mailboxStore,
  onHop: (label) => {
    const msg = JSON.stringify({ t: "hop", label });
    for (const ws of sockets) if (ws.readyState === 1) ws.send(msg);
  },
});

// ---- helpers --------------------------------------------------------------
const MIME = {
  ".html": "text/html", ".css": "text/css", ".js": "text/javascript",
  ".svg": "image/svg+xml", ".json": "application/json",
  ".webmanifest": "application/manifest+json", ".png": "image/png", ".ico": "image/x-icon",
};

const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "img-src 'self' data:",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "script-src 'self'",
  "connect-src 'self' ws: wss:",
  "manifest-src 'self'",
  "worker-src 'self'",
].join("; ");

function setSecurityHeaders(res) {
  res.setHeader("Content-Security-Policy", CSP);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}

function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

// Token-bucket rate limiter (per key). Cheap, single-process, self-cleaning.
function rateLimiter({ capacity, refillPerSec }) {
  const buckets = new Map();
  const iv = setInterval(() => {
    const now = Date.now();
    for (const [k, b] of buckets) if (now - b.last > 600000) buckets.delete(k);
  }, 300000);
  iv.unref();
  return (key, cost = 1) => {
    const now = Date.now();
    let b = buckets.get(key);
    if (!b) { b = { tokens: capacity, last: now }; buckets.set(key, b); }
    b.tokens = Math.min(capacity, b.tokens + ((now - b.last) / 1000) * refillPerSec);
    b.last = now;
    if (b.tokens < cost) return false;
    b.tokens -= cost;
    return true;
  };
}
const httpLimit = rateLimiter({ capacity: 60, refillPerSec: 10 });   // per-IP HTTP API
const submitLimit = rateLimiter({ capacity: 120, refillPerSec: 40 }); // per-connection packet submit

const HANDLE_RE = /^[a-z0-9_]{1,24}$/;
const B64_RE = /^[A-Za-z0-9+/=]{1,4096}$/;

function isB64(s) { return typeof s === "string" && B64_RE.test(s); }
function validCard(c) {
  return c && typeof c === "object" &&
    typeof c.handle === "string" && HANDLE_RE.test(c.handle.toLowerCase()) &&
    isB64(c.providerId) && isB64(c.mailbox) &&
    c.kem && isB64(c.kem.x) && isB64(c.kem.kem) &&
    c.sign && isB64(c.sign.ed) && isB64(c.sign.dsa);
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > maxBytes) { req.destroy(); reject(new Error("body too large")); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function json(res, code, obj) {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}

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

// ---- http -----------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);
  const url = new URL(req.url, "http://x");
  const ip = clientIp(req);

  if (url.pathname === "/healthz") { res.writeHead(200).end("ok"); return; }
  if (url.pathname === "/readyz") {
    try { store.stats(); res.writeHead(200).end("ready"); }
    catch { res.writeHead(503).end("not ready"); }
    return;
  }

  if (url.pathname === "/api/net") {
    if (!httpLimit(ip)) return json(res, 429, { error: "rate limited" });
    return json(res, 200, { view: dir.publicView(), meanDelayMs: CFG.meanDelayMs });
  }

  if (url.pathname === "/api/publish" && req.method === "POST") {
    if (!httpLimit(ip, 2)) return json(res, 429, { error: "rate limited" });
    try {
      const card = JSON.parse(await readBody(req, CFG.maxBodyBytes));
      if (!validCard(card)) throw new Error("invalid card");
      store.putCard(card.handle.toLowerCase(), card);
      return json(res, 200, { ok: true });
    } catch (e) {
      const tooBig = /too large/.test(String(e.message));
      return json(res, tooBig ? 413 : 400, { error: tooBig ? "payload too large" : "invalid card" });
    }
  }

  if (url.pathname === "/api/card") {
    if (!httpLimit(ip)) return json(res, 429, { error: "rate limited" });
    const handle = (url.searchParams.get("handle") || "").toLowerCase();
    if (!HANDLE_RE.test(handle)) { res.writeHead(400).end("{}"); return; }
    const c = store.getCard(handle);
    if (!c) { res.writeHead(404).end("{}"); return; }
    return json(res, 200, c);
  }

  if (req.method !== "GET") { res.writeHead(405).end(); return; }
  serveStatic(req, res);
});

// ---- websocket gateway ----------------------------------------------------
const wss = new WebSocketServer({ server, path: "/gateway", maxPayload: CFG.maxWsMsgBytes });
const connPerIp = new Map();

wss.on("connection", (ws, req) => {
  const ip = clientIp(req);
  const n = (connPerIp.get(ip) || 0) + 1;
  connPerIp.set(ip, n);
  if (n > CFG.maxConnPerIp) { ws.close(1013, "too many connections"); return; }

  sockets.add(ws);
  let unsub = null;

  ws.on("message", (raw) => {
    let m;
    try { m = JSON.parse(raw.toString()); } catch { return; }

    if (m.t === "submit") {
      if (!submitLimit(ws)) return; // drop excess silently
      if (!isB64(m.node)) return;
      let pkt;
      try { pkt = deserializePacket(m.packet); } catch { return; }
      try { mix.inject(fromB64(m.node), pkt); } catch { /* drop */ }
      return;
    }

    if (m.t === "subscribe") {
      if (!isB64(m.provider) || !isB64(m.mailbox)) return;
      if (unsub) unsub();
      unsub = mix.subscribe(fromB64(m.provider), fromB64(m.mailbox), (env) => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ t: "deliver", envelope: toB64(env) }));
      });
    }
  });

  ws.on("close", () => {
    sockets.delete(ws);
    if (unsub) unsub();
    const left = (connPerIp.get(ip) || 1) - 1;
    if (left <= 0) connPerIp.delete(ip); else connPerIp.set(ip, left);
  });
  ws.on("error", () => { /* keep the process alive on socket errors */ });
});

// ---- background maintenance + lifecycle -----------------------------------
const pruneTimer = setInterval(() => { try { store.prune(); } catch { /* ignore */ } }, 3600 * 1000);
pruneTimer.unref();

let shuttingDown = false;
function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(pruneTimer);
  try { wss.close(); } catch { /* ignore */ }
  for (const ws of sockets) { try { ws.close(1001, "server shutting down"); } catch { /* ignore */ } }
  try { store.close(); } catch { /* ignore */ }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 4000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("uncaughtException", (e) => { console.error("uncaughtException", e); });
process.on("unhandledRejection", (e) => { console.error("unhandledRejection", e); });

server.listen(CFG.port, () => {
  const s = store.stats();
  console.log(`NobleChat gateway on :${CFG.port}  (mix ~${CFG.meanDelayMs}ms/hop, ${s.cards} cards, ${s.queued} queued)`);
});
