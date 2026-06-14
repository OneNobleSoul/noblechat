// NobleChat browser client. All key generation and encryption happen HERE,
// locally. The gateway only ever receives opaque, fixed-size onion packets.
import {
  generateIdentity, buildOutgoing, openIncoming, buildCoverLoop,
} from "../../../packages/net/src/client.js";
import {
  makeBrowserNet, serializePacket, serializeCard, deserializeCard,
  serializeIdentity, deserializeIdentity,
} from "../../../packages/net/src/serialize.js";
import { toB64, fromB64 } from "../../../packages/crypto/src/util.js";

const $ = (s) => document.querySelector(s);
const ID_KEY = "noblechat:id";
const CONTACTS_KEY = "noblechat:contacts";

const state = {
  ws: null, net: null, meanDelayMs: 60,
  identity: null, contacts: new Map(), convos: new Map(),
  active: null, coverOn: false, coverTimer: null,
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

// ---------- init ----------
async function init() {
  const res = await fetch("/api/net");
  const { view, meanDelayMs } = await res.json();
  state.net = makeBrowserNet(view);
  state.meanDelayMs = meanDelayMs;
  buildNetViz();

  const saved = localStorage.getItem(ID_KEY);
  if (saved) {
    state.identity = deserializeIdentity(JSON.parse(saved));
    loadContacts();
    startApp();
  } else {
    $("#setup").hidden = false;
    $("#setup-go").addEventListener("click", createIdentity);
    $("#setup-handle").addEventListener("keydown", (e) => e.key === "Enter" && createIdentity());
  }
}

function createIdentity() {
  const handle = $("#setup-handle").value.trim().toLowerCase().replace(/\s+/g, "");
  if (!handle) return;
  const provider = state.net.providers[simpleHash(handle) % state.net.providers.length];
  $("#setup-go").textContent = "generating keys…";
  setTimeout(() => {
    state.identity = generateIdentity(handle, provider.id);
    localStorage.setItem(ID_KEY, JSON.stringify(serializeIdentity(state.identity)));
    $("#setup").hidden = true;
    startApp();
  }, 30);
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
  } catch (e) { toast("send failed: " + e.message); return; }
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
  const arr = [...state.contacts.values()].map(serializeCard);
  localStorage.setItem(CONTACTS_KEY, JSON.stringify(arr));
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
  $("#cover-toggle").addEventListener("click", toggleCover);
  updateStats();
}

init();
