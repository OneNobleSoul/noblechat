// NobleChat browser client. All key generation and encryption happen HERE,
// locally. The gateway only ever receives opaque, fixed-size onion packets.
import {
  generateIdentityStaged, buildOutgoing, openIncoming, buildCoverLoop,
} from "../../../packages/net/src/client.js";
import {
  makeBrowserNet, serializePacket, serializeCard, deserializeCard,
  serializeIdentity, deserializeIdentity,
} from "../../../packages/net/src/serialize.js";
import { toB64, fromB64 } from "../../../packages/crypto/src/util.js";

const $ = (s) => document.querySelector(s);
const ID_KEY = "noblechat:id";
const CONTACTS_KEY = "noblechat:contacts";

// --- temporary access gate (testing only) ---------------------------------
// A client-side speed bump so the instance isn't wide open while we test.
// GATE_HASH is the SHA-256 of the shared test password. This is NOT real
// security (anyone can read the bundle) — it just keeps casual visitors out.
const GATE_HASH = "b34f7fb73eea21931199bcd983951029b3df3ef407a7e58d617cf03747014f1a";
const GATE_OK = "noblechat:gate-ok";

const state = {
  ws: null, net: null, meanDelayMs: 60,
  identity: null, contacts: new Map(), convos: new Map(),
  active: null, coverOn: true, coverTimer: null,
  netCols: [], stats: { sent: 0, cover: 0, recv: 0 },
};

function toast(msg) {
  const t = $("#toast"); t.hidden = false; t.textContent = msg;
  requestAnimationFrame(() => t.classList.add("show"));
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.classList.remove("show"); setTimeout(() => (t.hidden = true), 250); }, 2400);
}
function simpleHash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h; }
function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function poisson(mean) { return -mean * Math.log(1 - Math.random()); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- boot / gate ----------
async function boot() {
  await passGate();
  await init();
}

function passGate() {
  return new Promise((resolve) => {
    const g = $("#gate");
    if (sessionStorage.getItem(GATE_OK) === "1") { g.hidden = true; resolve(); return; }
    g.hidden = false;
    const input = $("#gate-input"), btn = $("#gate-go"), err = $("#gate-err");
    input.focus();
    async function tryUnlock() {
      const v = input.value;
      if (!v) return;
      btn.disabled = true;
      let ok = false;
      try { ok = (await sha256Hex(v)) === GATE_HASH; } catch { ok = false; }
      if (ok) {
        try { sessionStorage.setItem(GATE_OK, "1"); } catch {}
        g.classList.add("gone");
        setTimeout(() => { g.hidden = true; resolve(); }, 340);
      } else {
        err.hidden = false;
        input.value = ""; input.focus();
        g.classList.remove("shake"); void g.offsetWidth; g.classList.add("shake");
        btn.disabled = false;
      }
    }
    btn.addEventListener("click", tryUnlock);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") tryUnlock(); });
  });
}

// ---------- init ----------
async function init() {
  const res = await fetch("/api/net");
  const { view, meanDelayMs } = await res.json();
  state.net = makeBrowserNet(view);
  state.meanDelayMs = meanDelayMs;
  buildNetViz();

  let saved = null;
  try { saved = localStorage.getItem(ID_KEY); } catch {}
  if (saved) {
    try {
      const id = deserializeIdentity(JSON.parse(saved));
      // The identity carries a provider id from whenever it was created. If the
      // network no longer has that provider (e.g. this identity predates a
      // topology change), routing back to us is impossible — start fresh.
      const provOk = state.net.providers.some((p) => toB64(p.id) === toB64(id.providerId));
      if (!provOk) throw new Error("identity belongs to an old network");
      state.identity = id;
      loadContacts();
      startApp();
      return;
    } catch {
      // corrupt or stale stored identity — start fresh
      try { localStorage.removeItem(ID_KEY); localStorage.removeItem(CONTACTS_KEY); } catch {}
    }
  }
  $("#setup").hidden = false;
  $("#setup-go").addEventListener("click", createIdentity);
  $("#setup-handle").addEventListener("keydown", (e) => e.key === "Enter" && createIdentity());
  $("#setup-handle").focus();
}

// ---------- key generation with live progress ----------
const KG_CIRC = 2 * Math.PI * 52; // stroke length of the progress ring

function showKeygen(pct, label) {
  $(".setup-card").classList.add("busy");
  $("#keygen").hidden = false;
  const p = Math.max(0, Math.min(100, pct));
  const arc = $(".kg-arc");
  arc.style.strokeDasharray = String(KG_CIRC);
  arc.style.strokeDashoffset = String(KG_CIRC * (1 - p / 100));
  $("#kg-num").textContent = String(Math.round(p));
  if (label) $("#kg-label").textContent = label;
}
function resetSetupForm() {
  $(".setup-card").classList.remove("busy");
  $("#keygen").hidden = true;
  $("#setup-go").disabled = false;
}

async function createIdentity() {
  const handle = $("#setup-handle").value.trim().toLowerCase().replace(/\s+/g, "");
  if (!handle) { $("#setup-handle").focus(); return; }
  $("#setup-err").hidden = true;
  $("#setup-go").disabled = true;

  const provider = state.net.providers[simpleHash(handle) % state.net.providers.length];
  showKeygen(0, "starting");

  try {
    const id = await generateIdentityStaged(handle, provider.id, (pct, label) => showKeygen(pct, label));
    state.identity = id;
    try {
      localStorage.setItem(ID_KEY, JSON.stringify(serializeIdentity(id)));
    } catch {
      toast("keys kept for this session only (storage unavailable)");
    }
    await sleep(260); // let the 100% state be seen
    $("#setup").hidden = true;
    startApp();
  } catch (e) {
    resetSetupForm();
    const msg = (e && e.message) ? e.message : String(e);
    const el = $("#setup-err");
    el.textContent = "Key generation failed: " + msg;
    el.hidden = false;
    toast("key generation failed");
    // Surface it for debugging too.
    console.error("[noblechat] key generation failed", e);
  }
}

function startApp() {
  $("#app").hidden = false;
  $("#me-handle").textContent = state.identity.handle;
  connectWS();
  wireUI();
  renderContacts();
}

// ---------- transport ----------
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/gateway`);
  state.ws = ws;
  ws.addEventListener("open", async () => {
    await fetch("/api/publish", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(serializeCard(state.identity.card)),
    });
    ws.send(JSON.stringify({ t: "subscribe", provider: toB64(state.identity.providerId), mailbox: toB64(state.identity.mailbox) }));
    if (state.coverOn) scheduleCover();
  });
  ws.addEventListener("message", (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.t === "deliver") onDeliver(fromB64(m.envelope));
    else if (m.t === "hop") pulseHop(m.label);
  });
  ws.addEventListener("close", () => setTimeout(connectWS, 1500));
}

function onDeliver(envelope) {
  let content;
  try { content = openIncoming(state.identity, envelope); } catch { return; }
  if (content.t === "cover") return; // our own loop coming back — drop silently
  if (content.t !== "msg") return;
  const from = content.from || "unknown";
  if (!state.contacts.has(from)) fetchCard(from); // so we can reply
  pushMessage(from, { dir: "in", body: content.body, ts: content.ts || Date.now() });
  state.stats.recv++; updateStats();
  if (state.active !== from) toast(`new message from ${from}`);
}

// ---------- messaging ----------
function sendMessage() {
  const input = $("#msg-input"); const body = input.value.trim();
  if (!body || !state.active) return;
  const card = state.contacts.get(state.active);
  if (!card) return;
  const content = { v: 1, t: "msg", from: state.identity.handle, body, ts: Date.now() };
  try {
    const { firstNodeId, packet } = buildOutgoing(state.net, card, content);
    state.ws.send(JSON.stringify({ t: "submit", node: toB64(firstNodeId), packet: serializePacket(packet) }));
  } catch (e) {
    if (String(e.message).includes("unknown provider")) {
      toast("contact's routing info was stale — refreshing, please resend");
      fetchCard(state.active);
    } else {
      toast("send failed: " + e.message);
    }
    return;
  }
  pushMessage(state.active, { dir: "out", body, ts: content.ts });
  state.stats.sent++; updateStats();
  input.value = "";
}

async function fetchCard(handle, { silent = true } = {}) {
  handle = handle.trim().toLowerCase();
  if (!handle) return;
  if (handle === state.identity.handle) { if (!silent) toast("that's you"); return; }
  try {
    const res = await fetch("/api/card?handle=" + encodeURIComponent(handle));
    if (!res.ok) { if (!silent) toast("no such handle online"); return; }
    const card = deserializeCard(await res.json());
    state.contacts.set(handle, card);
    saveContacts();
    renderContacts();
    if (!silent) setActive(handle);
  } catch { if (!silent) toast("lookup failed"); }
}

// ---------- state + persistence ----------
function pushMessage(handle, msg) {
  if (!state.convos.has(handle)) state.convos.set(handle, []);
  state.convos.get(handle).push(msg);
  if (state.active === handle) renderMessages();
}
function saveContacts() {
  try {
    const arr = [...state.contacts.values()].map(serializeCard);
    localStorage.setItem(CONTACTS_KEY, JSON.stringify(arr));
  } catch {}
}
function loadContacts() {
  try {
    const arr = JSON.parse(localStorage.getItem(CONTACTS_KEY) || "[]");
    for (const c of arr) state.contacts.set(c.handle.toLowerCase(), deserializeCard(c));
  } catch {}
}

// ---------- rendering ----------
function setActive(handle) {
  state.active = handle;
  $("#chat-empty").hidden = true;
  $("#chat-view").hidden = false;
  $("#chat-with").textContent = handle;
  renderContacts();
  renderMessages();
  $("#msg-input").focus();
}
function renderContacts() {
  const el = $("#contacts");
  el.innerHTML = [...state.contacts.values()].map((c) => {
    const h = c.handle.toLowerCase();
    return `<div class="contact ${h === state.active ? "active" : ""}" data-h="${esc(h)}">
      <div class="avatar">${esc(c.handle[0] || "?").toUpperCase()}</div>
      <div><div class="h">${esc(c.handle)}</div><div class="s">post-quantum · mixnet</div></div>
    </div>`;
  }).join("") || `<div class="net-note" style="padding:12px">No contacts yet. Add someone by their handle above.</div>`;
  el.querySelectorAll(".contact").forEach((n) => n.addEventListener("click", () => setActive(n.dataset.h)));
}
function renderMessages() {
  const el = $("#messages");
  const msgs = state.convos.get(state.active) || [];
  el.innerHTML = msgs.map((m) => {
    const time = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return `<div class="msg ${m.dir}">${esc(m.body)}<span class="t">${time}</span></div>`;
  }).join("");
  el.scrollTop = el.scrollHeight;
}
function updateStats() {
  $("#stat-sent").textContent = state.stats.sent;
  $("#stat-cover").textContent = state.stats.cover;
  $("#stat-recv").textContent = state.stats.recv;
}

// ---------- cover traffic ----------
function toggleCover() {
  state.coverOn = !state.coverOn;
  const b = $("#cover-toggle");
  b.textContent = "cover: " + (state.coverOn ? "on" : "off");
  b.classList.toggle("on", state.coverOn);
  if (state.coverOn) { toast("cover traffic on — hiding when you talk"); scheduleCover(); }
  else clearTimeout(state.coverTimer);
}
function scheduleCover() {
  clearTimeout(state.coverTimer);
  state.coverTimer = setTimeout(() => {
    sendCover();
    if (state.coverOn) scheduleCover();
  }, poisson(3500) + 800);
}
function sendCover() {
  if (!state.ws || state.ws.readyState !== 1) return;
  try {
    const { firstNodeId, packet } = buildCoverLoop(state.net, state.identity);
    state.ws.send(JSON.stringify({ t: "submit", node: toB64(firstNodeId), packet: serializePacket(packet) }));
    state.stats.cover++; updateStats();
  } catch {}
}

// ---------- mix network visualisation ----------
function buildNetViz() {
  const wrap = $("#net-layers");
  const cols = state.net.layers.length + 1;
  const labels = state.net.layers.map((_, i) => "L" + (i + 1)).concat(["exit"]);
  let html = "";
  for (let i = 0; i < cols; i++) {
    html += `<div class="net-col"><div class="net-node" data-col="${i}">◆</div><div class="net-lbl">${labels[i]}</div></div>`;
    if (i < cols - 1) html += `<div class="net-arrow">→</div>`;
  }
  wrap.innerHTML = html;
  state.netCols = [...wrap.querySelectorAll(".net-node")];
}
function pulseHop(label) {
  let col = -1;
  const m = /^mix-L(\d+)/.exec(label);
  if (m) col = Number(m[1]);
  else if (label.startsWith("provider")) col = state.net.layers.length;
  const node = state.netCols[col];
  if (!node) return;
  node.classList.add("pulse");
  setTimeout(() => node.classList.remove("pulse"), 320);
}

// ---------- wire ui ----------
function wireUI() {
  $("#add-go").addEventListener("click", () => { fetchCard($("#add-handle").value, { silent: false }); $("#add-handle").value = ""; });
  $("#add-handle").addEventListener("keydown", (e) => { if (e.key === "Enter") { fetchCard($("#add-handle").value, { silent: false }); $("#add-handle").value = ""; } });
  $("#msg-send").addEventListener("click", sendMessage);
  $("#msg-input").addEventListener("keydown", (e) => e.key === "Enter" && sendMessage());
  const cover = $("#cover-toggle");
  cover.addEventListener("click", toggleCover);
  cover.textContent = "cover: " + (state.coverOn ? "on" : "off");
  cover.classList.toggle("on", state.coverOn);
  updateStats();
}

boot();
