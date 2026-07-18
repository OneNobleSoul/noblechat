// NobleChat gateway.
//
// Runs the mix network and a hardened HTTP gateway. Zero-knowledge about
// content: browsers do all key generation and encryption locally. Accounts add
// authenticated handle ownership and multi-device fan-out WITHOUT weakening
// end-to-end encryption: the server only ever stores a password *hash*, public
// per-device cards, opaque ciphertext, and an opaque (client-encrypted)
// contacts blob. Durable state lives in PostgreSQL.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import { buildTestnet } from "../../packages/net/src/directory.js";
import { Mixnet } from "../../packages/net/src/router.js";
import { deserializePacket } from "../../packages/net/src/serialize.js";
import { fromB64, toB64 } from "../../packages/crypto/src/util.js";
import { openStore } from "./store.js";
import { createLog } from "./log.js";
import { isTransport, probeTcp } from "./transport.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.resolve(__dirname, "../web/public");

const CFG = {
  port: Number(process.env.PORT || 8790),
  meanDelayMs: Number(process.env.MEAN_DELAY_MS || 60),
  netSeed: process.env.NET_SEED || null,
  databaseUrl: process.env.DATABASE_URL || "postgres://noblechat:noblechat@localhost:5432/noblechat",
  adminToken: process.env.ADMIN_TOKEN || "",
  sessionTtlMs: Number(process.env.SESSION_TTL_MS || 30 * 24 * 3600 * 1000),
  maxBodyBytes: Number(process.env.MAX_BODY_BYTES || 64 * 1024),
  maxBlobBytes: Number(process.env.MAX_BLOB_BYTES || 512 * 1024),
  maxWsMsgBytes: Number(process.env.MAX_WS_MSG_BYTES || 128 * 1024),
  maxConnPerIp: Number(process.env.MAX_CONN_PER_IP || 20),
  mailboxTtlMs: Number(process.env.MAILBOX_TTL_MS || 7 * 24 * 3600 * 1000),
  maxPerMailbox: Number(process.env.MAX_PER_MAILBOX || 1000),
  mixPort: Number(process.env.MIX_PORT || 8890),
  layers: Number(process.env.LAYERS || 3),
  perLayer: Number(process.env.PER_LAYER || 2),
  providers: Number(process.env.PROVIDERS || 2),
  internalToken: process.env.INTERNAL_TOKEN || "",
  nymClientUrl: process.env.NYM_CLIENT_URL || "",
};

function computeVersion() {
  try { return crypto.createHash("sha256").update(fs.readFileSync(path.join(PUBLIC, "app.bundle.js"))).digest("hex").slice(0, 12); }
  catch { return "dev"; }
}
const APP_VERSION = process.env.APP_VERSION || computeVersion();

const MIME = {
  ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml",
  ".json": "application/json", ".webmanifest": "application/manifest+json", ".png": "image/png", ".ico": "image/x-icon",
};
const CSP = [
  "default-src 'self'", "base-uri 'self'", "object-src 'none'", "frame-ancestors 'none'",
  "img-src 'self' data:", "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com", "script-src 'self'",
  "connect-src 'self' ws: wss:", "manifest-src 'self'", "worker-src 'self'",
].join("; ");
function setSecurityHeaders(res) {
  res.setHeader("Content-Security-Policy", CSP);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}
function clientIp(req) { const xff = req.headers["x-forwarded-for"]; if (xff) return String(xff).split(",")[0].trim(); return (req.socket && req.socket.remoteAddress) || "unknown"; }
function rateLimiter({ capacity, refillPerSec }) {
  const buckets = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (now - b.last > 600000) buckets.delete(k); }, 300000).unref();
  return (key, cost = 1) => {
    const now = Date.now(); let b = buckets.get(key);
    if (!b) { b = { tokens: capacity, last: now }; buckets.set(key, b); }
    b.tokens = Math.min(capacity, b.tokens + ((now - b.last) / 1000) * refillPerSec); b.last = now;
    if (b.tokens < cost) return false; b.tokens -= cost; return true;
  };
}
const HANDLE_RE = /^[a-z0-9_]{3,24}$/;
const B64_RE = /^[A-Za-z0-9+/=]{1,4096}$/;
const HEX_RE = /^[a-f0-9]{8,64}$/;
const isB64 = (s) => typeof s === "string" && B64_RE.test(s);
function validCard(c) {
  return c && typeof c === "object" && typeof c.handle === "string" && HANDLE_RE.test(c.handle.toLowerCase()) &&
    isB64(c.providerId) && isB64(c.mailbox) && c.kem && isB64(c.kem.x) && isB64(c.kem.kem) &&
    c.sign && isB64(c.sign.ed) && isB64(c.sign.dsa);
}
function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > maxBytes) { req.destroy(); reject(new Error("body too large")); return; } chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
function json(res, code, obj) { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); }
function timingEqual(a, b) { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }
function hashPassword(pw) { const salt = crypto.randomBytes(16); const hash = crypto.scryptSync(pw, salt, 64); return salt.toString("hex") + "$" + hash.toString("hex"); }
function verifyPassword(pw, stored) {
  const i = String(stored).indexOf("$"); if (i < 0) return false;
  const salt = Buffer.from(stored.slice(0, i), "hex"); const want = Buffer.from(stored.slice(i + 1), "hex");
  let got; try { got = crypto.scryptSync(pw, salt, want.length); } catch { return false; }
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

async function main() {
  const store = await openStore(CFG.databaseUrl, { mailboxTtlMs: CFG.mailboxTtlMs, maxPerMailbox: CFG.maxPerMailbox });
  const mailboxStore = {
    push: (k, env) => store.pushEnvelope(k, toB64(env)),
    drain: (k) => store.drainEnvelopes(k).then((list) => list.map(fromB64)),
  };
  const dir = buildTestnet({ layers: CFG.layers, perLayer: CFG.perLayer, providers: CFG.providers, seed: CFG.netSeed, mixPort: CFG.mixPort });
  const sockets = new Set();
  const mbkeySockets = new Map();
  const bannedMbkeys = new Set();
  // The mix RELAY runs in separate node processes now; this Mixnet instance is
  // used only for mailbox bookkeeping (subscriptions + durable queue). Providers
  // hand final deliveries back to us over /internal/deliver.
  const mix = new Mixnet(dir, { meanDelayMs: CFG.meanDelayMs, mailboxStore });
  async function forwardToNode(url, packetObj) {
    try { await fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-internal": CFG.internalToken }, body: JSON.stringify({ packet: packetObj }) }); } catch { /* drop */ }
  }
  const internalOk = (req) => CFG.internalToken && req.headers["x-internal"] === CFG.internalToken;

  const live = { maintenance: (await store.getSetting("maintenance", "off")) === "on", maintenanceMsg: (await store.getSetting("maintenance_msg", "")) || "", announcement: (await store.getSetting("announcement", "")) || "", transport: (await store.getSetting("transport", "internal")) || "internal" };
  if (!isTransport(live.transport)) live.transport = "internal";
  for (const k of await store.allBannedMbkeys()) bannedMbkeys.add(k);

  // Ops state for the admin panel: an in-memory event log plus a few counters.
  const elog = createLog();
  const startedAt = Date.now();
  const counters = { submitted: 0, delivered: 0, registered: 0, logins: 0 };
  // If a previous run enabled nym and the sidecar is gone, fall back rather
  // than silently dropping every submit.
  if (live.transport === "nym" && !(CFG.nymClientUrl && (await probeTcp(CFG.nymClientUrl)))) {
    live.transport = "internal";
    await store.setSetting("transport", "internal");
    elog.add("warn", "transport fallback", "nym sidecar unreachable at boot, using internal mixnet");
  }

  function broadcast(obj) { const s = JSON.stringify(obj); for (const ws of sockets) if (ws.readyState === 1) ws.send(s); }
  function statusObj() { return { version: APP_VERSION, announcement: live.announcement, maintenance: live.maintenance, maintenanceMsg: live.maintenanceMsg, transport: live.transport }; }
  function broadcastStatus() { broadcast({ t: "status", ...statusObj() }); }
  async function refreshBans() { bannedMbkeys.clear(); for (const k of await store.allBannedMbkeys()) bannedMbkeys.add(k); }

  const httpLimit = rateLimiter({ capacity: 60, refillPerSec: 10 });
  const authLimit = rateLimiter({ capacity: 10, refillPerSec: 0.5 }); // login/register brute-force guard
  const submitLimit = rateLimiter({ capacity: 120, refillPerSec: 40 });

  const requireAdmin = (req, res) => {
    const m = /^Bearer (.+)$/.exec(req.headers["authorization"] || "");
    if (!CFG.adminToken || !m || !timingEqual(m[1], CFG.adminToken)) { json(res, 401, { error: "unauthorized" }); return false; }
    return true;
  };
  async function sessionUser(token) { if (!token || typeof token !== "string") return null; const s = await store.getSession(token); return s ? s.username : null; }

  function serveStatic(req, res) {
    let rel = req.url.split("?")[0]; if (rel === "/") rel = "/index.html";
    const file = path.join(PUBLIC, path.normalize(rel).replace(/^(\.\.[/\\])+/, ""));
    if (!file.startsWith(PUBLIC)) { res.writeHead(403).end(); return; }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404).end("not found"); return; }
      res.writeHead(200, { "content-type": MIME[path.extname(file)] || "application/octet-stream" });
      res.end(data);
    });
  }

  const server = http.createServer(async (req, res) => {
    setSecurityHeaders(res);
    const url = new URL(req.url, "http://x");
    const ip = clientIp(req);
    try {
      if (url.pathname === "/healthz") { res.writeHead(200).end("ok"); return; }
      if (url.pathname === "/readyz") { try { await store.stats(); res.writeHead(200).end("ready"); } catch { res.writeHead(503).end("not ready"); } return; }

      // ---- internal (mix nodes only; gated by a shared secret) ----
      if (url.pathname === "/internal/deliver" && req.method === "POST") {
        if (!internalOk(req)) { res.writeHead(401).end(); return; }
        try { const b = JSON.parse(await readBody(req, CFG.maxWsMsgBytes)); mix._deliver(fromB64(b.providerId), fromB64(b.payload)); counters.delivered++; } catch { /* */ }
        res.writeHead(202).end(); return;
      }
      if (url.pathname === "/internal/hop" && req.method === "POST") {
        if (!internalOk(req)) { res.writeHead(401).end(); return; }
        try { const b = JSON.parse(await readBody(req, 4096)); if (b.label) broadcast({ t: "hop", label: String(b.label).slice(0, 40) }); } catch { /* */ }
        res.writeHead(202).end(); return;
      }
      if (url.pathname === "/api/net") { if (!httpLimit(ip)) return json(res, 429, { error: "rate limited" }); return json(res, 200, { view: dir.publicView(), meanDelayMs: CFG.meanDelayMs }); }
      if (url.pathname === "/api/status") { if (!httpLimit(ip)) return json(res, 429, { error: "rate limited" }); return json(res, 200, statusObj()); }

      // ---- accounts ----
      if (url.pathname === "/api/account/register" && req.method === "POST") {
        if (!authLimit(ip)) return json(res, 429, { error: "too many attempts" });
        try {
          const b = JSON.parse(await readBody(req, CFG.maxBodyBytes));
          const username = String(b.username || "").toLowerCase();
          if (!HANDLE_RE.test(username)) return json(res, 400, { error: "handle must be 3-24 chars: a-z 0-9 _" });
          if (typeof b.password !== "string" || b.password.length < 8) return json(res, 400, { error: "password too short (min 8)" });
          if (await store.getAccount(username)) return json(res, 409, { error: "handle already taken" });
          await store.createAccount(username, hashPassword(b.password));
          counters.registered++;
          elog.add("info", "account registered", username);
          const token = crypto.randomBytes(32).toString("hex");
          await store.createSession(token, username, CFG.sessionTtlMs);
          return json(res, 200, { token, username });
        } catch (e) { return json(res, 400, { error: "bad request" }); }
      }
      if (url.pathname === "/api/account/login" && req.method === "POST") {
        if (!authLimit(ip)) return json(res, 429, { error: "too many attempts" });
        try {
          const b = JSON.parse(await readBody(req, CFG.maxBodyBytes));
          const username = String(b.username || "").toLowerCase();
          const acc = await store.getAccount(username);
          if (!acc || !verifyPassword(String(b.password || ""), acc.pass)) return json(res, 401, { error: "wrong handle or password" });
          if (acc.banned) return json(res, 403, { error: "account suspended" });
          counters.logins++;
          const token = crypto.randomBytes(32).toString("hex");
          await store.createSession(token, username, CFG.sessionTtlMs);
          return json(res, 200, { token, username });
        } catch (e) { return json(res, 400, { error: "bad request" }); }
      }
      if (url.pathname === "/api/account/logout" && req.method === "POST") {
        try { const b = JSON.parse(await readBody(req, CFG.maxBodyBytes)); await store.deleteSession(String(b.token || "")); } catch { /* */ }
        return json(res, 200, { ok: true });
      }
      if (url.pathname === "/api/account/device" && req.method === "POST") {
        if (!httpLimit(ip, 2)) return json(res, 429, { error: "rate limited" });
        try {
          const b = JSON.parse(await readBody(req, CFG.maxBodyBytes));
          const username = await sessionUser(b.token);
          if (!username) return json(res, 401, { error: "not signed in" });
          if (await store.isBanned(username)) return json(res, 403, { error: "account suspended" });
          if (typeof b.deviceId !== "string" || !HEX_RE.test(b.deviceId)) return json(res, 400, { error: "bad device id" });
          if (!validCard(b.card) || b.card.handle.toLowerCase() !== username) return json(res, 400, { error: "card must match your handle" });
          await store.addDevice(b.deviceId, username, b.card, `${b.card.providerId}:${b.card.mailbox}`);
          return json(res, 200, { ok: true });
        } catch (e) { return json(res, 400, { error: "bad request" }); }
      }
      if (url.pathname === "/api/bundle") {
        if (!httpLimit(ip)) return json(res, 429, { error: "rate limited" });
        const handle = (url.searchParams.get("handle") || "").toLowerCase();
        if (!HANDLE_RE.test(handle)) { res.writeHead(400).end("{}"); return; }
        const devices = await store.deviceBundle(handle);
        if (!devices.length) { res.writeHead(404).end("{}"); return; }
        return json(res, 200, { handle, devices });
      }
      if (url.pathname === "/api/account/blob") {
        if (req.method === "GET") {
          if (!httpLimit(ip)) return json(res, 429, { error: "rate limited" });
          const username = await sessionUser(url.searchParams.get("token"));
          if (!username) return json(res, 401, { error: "not signed in" });
          return json(res, 200, { blob: await store.getBlob(username) });
        }
        if (req.method === "POST") {
          if (!httpLimit(ip)) return json(res, 429, { error: "rate limited" });
          try {
            const b = JSON.parse(await readBody(req, CFG.maxBlobBytes));
            const username = await sessionUser(b.token);
            if (!username) return json(res, 401, { error: "not signed in" });
            await store.setBlob(username, String(b.blob || "").slice(0, CFG.maxBlobBytes));
            return json(res, 200, { ok: true });
          } catch (e) { return json(res, 400, { error: "bad request" }); }
        }
      }

      // ---- admin ----
      if (url.pathname.startsWith("/api/admin/")) {
        if (!requireAdmin(req, res)) return;
        if (url.pathname === "/api/admin/status" && req.method === "GET") {
          const s = await store.stats();
          return json(res, 200, {
            ...statusObj(),
            users: Number(s.accounts), devices: Number(s.devices), queued: Number(s.queued), banned: Number(s.banned),
            uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
            memRssMb: Math.round(process.memoryUsage().rss / (1024 * 1024)),
            connections: sockets.size,
            counters: { ...counters },
            nymConfigured: !!CFG.nymClientUrl,
          });
        }
        if (url.pathname === "/api/admin/users" && req.method === "GET") {
          return json(res, 200, { users: await store.listAccounts(500) });
        }
        if (url.pathname === "/api/admin/logs" && req.method === "GET") {
          const since = Number(url.searchParams.get("since") || 0) || 0;
          return json(res, 200, { logs: elog.list(since) });
        }
        if (url.pathname === "/api/admin/mixnodes" && req.method === "GET") {
          const nodes = [...dir.layers.flat(), ...dir.providers];
          const checks = await Promise.all(nodes.map(async (n) => {
            const base = n.url.replace(/\/mix$/, "");
            try {
              const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 1500);
              const r = await fetch(base + "/healthz", { signal: ac.signal });
              clearTimeout(t);
              return { label: n.label, ok: r.ok };
            } catch { return { label: n.label, ok: false }; }
          }));
          return json(res, 200, { nodes: checks });
        }
        if (req.method === "POST") {
          const body = JSON.parse((await readBody(req, CFG.maxBodyBytes)) || "{}");
          const handle = String(body.handle || body.username || "").toLowerCase();
          if (url.pathname === "/api/admin/announce") { live.announcement = String(body.text || "").slice(0, 500); await store.setSetting("announcement", live.announcement); elog.add("info", live.announcement ? "announcement published" : "announcement cleared"); broadcastStatus(); return json(res, 200, { ok: true }); }
          if (url.pathname === "/api/admin/maintenance") { live.maintenance = !!body.on; live.maintenanceMsg = String(body.message || "").slice(0, 500); await store.setSetting("maintenance", live.maintenance ? "on" : "off"); await store.setSetting("maintenance_msg", live.maintenanceMsg); elog.add("warn", "maintenance " + (live.maintenance ? "enabled" : "disabled")); broadcastStatus(); return json(res, 200, { ok: true, maintenance: live.maintenance }); }
          if (url.pathname === "/api/admin/transport") {
            const mode = String(body.mode || "");
            if (!isTransport(mode)) return json(res, 400, { error: "unknown transport" });
            if (mode === "nym") {
              if (!CFG.nymClientUrl) return json(res, 409, { error: "nym sidecar not configured (NYM_CLIENT_URL)" });
              if (!(await probeTcp(CFG.nymClientUrl))) return json(res, 409, { error: "nym sidecar not reachable" });
            }
            if (mode !== live.transport) {
              live.transport = mode;
              await store.setSetting("transport", mode);
              elog.add("warn", "transport switched", mode);
              broadcastStatus();
            }
            return json(res, 200, { ok: true, transport: live.transport });
          }
          if (url.pathname === "/api/admin/ban") { if (!HANDLE_RE.test(handle)) return json(res, 400, { error: "bad handle" }); const mbk = await store.banAccount(handle, String(body.reason || "").slice(0, 200)); await refreshBans(); elog.add("warn", "account banned", handle); for (const k of mbk) { const set = mbkeySockets.get(k); if (set) for (const ws of set) { try { ws.close(4003, "banned"); } catch { /* */ } } } return json(res, 200, { ok: true }); }
          if (url.pathname === "/api/admin/unban") { await store.unbanAccount(handle); await refreshBans(); elog.add("info", "account unbanned", handle); return json(res, 200, { ok: true }); }
          if (url.pathname === "/api/admin/delete") { const mbk = await store.deleteAccount(handle); await refreshBans(); elog.add("warn", "account deleted", handle); for (const k of mbk) { const set = mbkeySockets.get(k); if (set) for (const ws of set) { try { ws.close(4004, "removed"); } catch { /* */ } } } return json(res, 200, { ok: true }); }
        }
        return json(res, 404, { error: "not found" });
      }

      if (req.method !== "GET") { res.writeHead(405).end(); return; }
      serveStatic(req, res);
    } catch (e) { json(res, 500, { error: "server error" }); }
  });

  const wss = new WebSocketServer({ server, path: "/gateway", maxPayload: CFG.maxWsMsgBytes });
  const connPerIp = new Map();
  wss.on("connection", (ws, req) => {
    const ip = clientIp(req);
    const n = (connPerIp.get(ip) || 0) + 1; connPerIp.set(ip, n);
    if (n > CFG.maxConnPerIp) { ws.close(1013, "too many connections"); return; }
    sockets.add(ws);
    let unsub = null; let myMbkey = null;
    try { ws.send(JSON.stringify({ t: "status", ...statusObj() })); } catch { /* */ }

    ws.on("message", (raw) => {
      let m; try { m = JSON.parse(raw.toString()); } catch { return; }
      if (m.t === "submit") {
        if (live.maintenance) return;
        if (!submitLimit(ws)) return;
        if (!isB64(m.node)) return;
        try { deserializePacket(m.packet); } catch { return; } // validate shape only
        const url = dir.urlOf(fromB64(m.node));                // forward to the entry mix node
        if (url) { counters.submitted++; forwardToNode(url, m.packet); }
        return;
      }
      if (m.t === "subscribe") {
        if (!isB64(m.provider) || !isB64(m.mailbox)) return;
        const mbkey = m.provider + ":" + m.mailbox;
        if (bannedMbkeys.has(mbkey)) { ws.close(4003, "banned"); return; }
        if (unsub) unsub();
        myMbkey = mbkey;
        if (!mbkeySockets.has(mbkey)) mbkeySockets.set(mbkey, new Set());
        mbkeySockets.get(mbkey).add(ws);
        unsub = mix.subscribe(fromB64(m.provider), fromB64(m.mailbox), (env) => { if (ws.readyState === 1) ws.send(JSON.stringify({ t: "deliver", envelope: toB64(env) })); });
      }
    });
    ws.on("close", () => {
      sockets.delete(ws);
      if (unsub) unsub();
      if (myMbkey) { const set = mbkeySockets.get(myMbkey); if (set) { set.delete(ws); if (!set.size) mbkeySockets.delete(myMbkey); } }
      const left = (connPerIp.get(ip) || 1) - 1; if (left <= 0) connPerIp.delete(ip); else connPerIp.set(ip, left);
    });
    ws.on("error", () => { /* */ });
  });

  const pruneTimer = setInterval(() => { store.prune().catch(() => {}); }, 3600 * 1000); pruneTimer.unref();
  let downFlag = false;
  function shutdown() {
    if (downFlag) return; downFlag = true;
    clearInterval(pruneTimer);
    try { wss.close(); } catch { /* */ }
    for (const ws of sockets) { try { ws.close(1001, "server shutting down"); } catch { /* */ } }
    store.close().catch(() => {});
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 4000).unref();
  }
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  process.on("uncaughtException", (e) => console.error("uncaughtException", e));
  process.on("unhandledRejection", (e) => console.error("unhandledRejection", e));

  elog.add("info", "gateway started", `v${APP_VERSION}, transport=${live.transport}`);
  server.listen(CFG.port, () => console.log(`NobleChat gateway on :${CFG.port}  (v${APP_VERSION}, mix ~${CFG.meanDelayMs}ms/hop, transport=${live.transport}, maintenance=${live.maintenance})`));
}

main().catch((e) => { console.error("fatal:", e); process.exit(1); });
