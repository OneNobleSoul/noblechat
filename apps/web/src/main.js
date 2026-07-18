// NobleChat browser client. All key generation and encryption happen HERE,
// locally. Accounts add authenticated handle ownership + multi-device fan-out
// without ever handing the server a private key or a plaintext password.
import {
  generateIdentityStaged, buildOutgoing, buildInner, openIncoming,
} from "../../../packages/net/src/client.js";
import {
  makeBrowserNet, serializePacket, serializeCard, deserializeCard,
  serializeIdentity, deserializeIdentity,
} from "../../../packages/net/src/serialize.js";
import { toB64, fromB64 } from "../../../packages/crypto/src/util.js";

const $ = (s) => document.querySelector(s);
const K = { token: "noblechat:token", user: "noblechat:user", dev: "noblechat:deviceId", id: "noblechat:id", bkey: "noblechat:bkey", contacts: "noblechat:contacts", prefs: "noblechat:prefs" };
const GATE_HASH = "b34f7fb73eea21931199bcd983951029b3df3ef407a7e58d617cf03747014f1a";
const GATE_OK = "noblechat:gate-ok";

const state = {
  ws: null, net: null, meanDelayMs: 60,
  token: null, user: null, deviceId: null, identity: null, blobKey: null,
  myBundle: [], contacts: new Map(), convos: new Map(), active: null,
  coverOn: true, coverTimer: null, netCols: [], stats: { sent: 0, cover: 0, recv: 0 },
  seen: new Set(), version: null, maintenance: false, statusTimer: null, authMode: "login",
  transport: "internal", nymAddress: null,
  soundOn: true, muted: new Set(), blocked: new Set(), unread: new Map(),
};

const ls = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* */ } }, del: (k) => { try { localStorage.removeItem(k); } catch { /* */ } } };
const randHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
function toast(msg) { const t = $("#toast"); t.hidden = false; t.textContent = msg; requestAnimationFrame(() => t.classList.add("show")); clearTimeout(toast._t); toast._t = setTimeout(() => { t.classList.remove("show"); setTimeout(() => (t.hidden = true), 250); }, 2600); }
function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function simpleHash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h; }
function poisson(mean) { return -mean * Math.log(1 - Math.random()); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function sha256Hex(str) { const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str)); return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join(""); }

// ---- preferences (sound, per-chat mutes, blocks) ----
// Persisted locally for this device and, for mutes/blocks, mirrored into the
// same end-to-end encrypted blob as the contact list so they follow the account.
function loadPrefs() {
  try {
    const p = JSON.parse(ls.get(K.prefs) || "{}");
    if (typeof p.soundOn === "boolean") state.soundOn = p.soundOn;
    if (Array.isArray(p.muted)) state.muted = new Set(p.muted);
    if (Array.isArray(p.blocked)) state.blocked = new Set(p.blocked);
  } catch { /* */ }
}
function savePrefs() {
  ls.set(K.prefs, JSON.stringify({ soundOn: state.soundOn, muted: [...state.muted], blocked: [...state.blocked] }));
}

// ---- notification sound (WebAudio, no asset needed) ----
let audioCtx = null;
function beep() {
  if (!state.soundOn) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === "suspended") audioCtx.resume();
    const now = audioCtx.currentTime;
    const notes = [660, 880];
    notes.forEach((freq, i) => {
      const o = audioCtx.createOscillator(); const g = audioCtx.createGain();
      o.type = "sine"; o.frequency.value = freq;
      const t0 = now + i * 0.09;
      g.gain.setValueAtTime(0, t0);
      g.gain.linearRampToValueAtTime(0.14, t0 + 0.012);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.16);
      o.connect(g).connect(audioCtx.destination);
      o.start(t0); o.stop(t0 + 0.18);
    });
  } catch { /* audio not available */ }
}

// ---- contacts-blob crypto (client-side; server only sees ciphertext) ----
async function deriveBlobKey(password, username) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: enc.encode("noblechat:" + username), iterations: 100000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}
async function exportKey(k) { return toB64(new Uint8Array(await crypto.subtle.exportKey("raw", k))); }
async function importKey(b64) { return crypto.subtle.importKey("raw", fromB64(b64), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]); }
async function encryptBlob(key, obj) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(obj)))); const out = new Uint8Array(iv.length + ct.length); out.set(iv); out.set(ct, iv.length); return toB64(out); }
async function decryptBlob(key, b64) { const raw = fromB64(b64); const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, key, raw.slice(12)); return JSON.parse(new TextDecoder().decode(pt)); }

// ---------- boot / gate ----------
async function boot() { await passGate(); await init(); }
function passGate() {
  return new Promise((resolve) => {
    const g = $("#gate");
    if (sessionStorage.getItem(GATE_OK) === "1") { g.hidden = true; resolve(); return; }
    g.hidden = false;
    const input = $("#gate-input"), btn = $("#gate-go"), err = $("#gate-err");
    input.focus();
    async function tryUnlock() {
      const v = input.value; if (!v) return; btn.disabled = true;
      let ok = false; try { ok = (await sha256Hex(v)) === GATE_HASH; } catch { ok = false; }
      if (ok) { try { sessionStorage.setItem(GATE_OK, "1"); } catch { /* */ } g.classList.add("gone"); setTimeout(() => { g.hidden = true; resolve(); }, 340); }
      else { err.hidden = false; input.value = ""; input.focus(); g.classList.remove("shake"); void g.offsetWidth; g.classList.add("shake"); btn.disabled = false; }
    }
    btn.addEventListener("click", tryUnlock);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") tryUnlock(); });
  });
}

// ---------- init / auto-login ----------
async function init() {
  const { view, meanDelayMs } = await (await fetch("/api/net")).json();
  state.net = makeBrowserNet(view); state.meanDelayMs = meanDelayMs; buildNetViz();
  pollStatus(); if (!state.statusTimer) state.statusTimer = setInterval(pollStatus, 45000);

  const token = ls.get(K.token), user = ls.get(K.user), idRaw = ls.get(K.id), dev = ls.get(K.dev), bkey = ls.get(K.bkey);
  if (token && user && idRaw && dev) {
    try {
      state.token = token; state.user = user; state.deviceId = dev;
      state.identity = deserializeIdentity(JSON.parse(idRaw));
      state.blobKey = bkey ? await importKey(bkey) : null;
      if (!state.net.providers.some((p) => toB64(p.id) === toB64(state.identity.providerId))) throw new Error("stale-net");
      await registerDevice(); // 401 if the session expired
      await afterAuth();
      return;
    } catch { clearSession(); }
  }
  showAuth();
}
function clearSession() { for (const k of Object.values(K)) ls.del(k); state.token = state.user = state.identity = state.blobKey = null; }

// ---------- auth ui ----------
function showAuth() {
  const setup = $("#setup"); setup.hidden = false;
  const setMode = (m) => {
    state.authMode = m;
    $("#tab-login").classList.toggle("active", m === "login");
    $("#tab-register").classList.toggle("active", m === "register");
    $("#auth-go").textContent = m === "login" ? "Sign in" : "Create account";
    $("#auth-pass").setAttribute("autocomplete", m === "login" ? "current-password" : "new-password");
  };
  setMode("login");
  $("#tab-login").onclick = () => setMode("login");
  $("#tab-register").onclick = () => setMode("register");
  $("#auth-go").onclick = doAuth;
  $("#auth-pass").addEventListener("keydown", (e) => { if (e.key === "Enter") doAuth(); });
  $("#auth-user").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#auth-pass").focus(); });
  $("#auth-user").focus();
}
function resetSetupForm() { $(".setup-card").classList.remove("busy"); $("#keygen").hidden = true; $("#auth-go").disabled = false; }

async function doAuth() {
  const user = $("#auth-user").value.trim().toLowerCase().replace(/\s+/g, "");
  const pass = $("#auth-pass").value;
  const err = $("#setup-err"); err.hidden = true;
  if (!/^[a-z0-9_]{3,24}$/.test(user)) { err.textContent = "Handle: 3-24 chars, a-z 0-9 _"; err.hidden = false; return; }
  if (pass.length < 8) { err.textContent = "Password must be at least 8 characters."; err.hidden = false; return; }
  $("#auth-go").disabled = true;

  try {
    const ep = state.authMode === "register" ? "/api/account/register" : "/api/account/login";
    const r = await fetch(ep, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: user, password: pass }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || "authentication failed");

    state.token = j.token; state.user = user;
    ls.set(K.token, j.token); ls.set(K.user, user);
    state.deviceId = ls.get(K.dev) || randHex(16); ls.set(K.dev, state.deviceId);

    // reuse this device's keypair if it already belongs to this handle, else make one
    let id = null; const idRaw = ls.get(K.id);
    if (idRaw) { try { const cand = deserializeIdentity(JSON.parse(idRaw)); if (cand.handle === user && state.net.providers.some((p) => toB64(p.id) === toB64(cand.providerId))) id = cand; } catch { /* */ } }
    if (!id) {
      showKeygen(0, "starting");
      const provider = state.net.providers[simpleHash(user) % state.net.providers.length];
      id = await generateIdentityStaged(user, provider.id, (p, l) => showKeygen(p, l));
      ls.set(K.id, JSON.stringify(serializeIdentity(id)));
    }
    state.identity = id;
    state.blobKey = await deriveBlobKey(pass, user); ls.set(K.bkey, await exportKey(state.blobKey));

    await registerDevice();
    await afterAuth();
    $("#setup").hidden = true;
  } catch (e) {
    resetSetupForm();
    err.textContent = String(e.message || e); err.hidden = false;
  }
}

async function registerDevice() {
  const r = await fetch("/api/account/device", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: state.token, deviceId: state.deviceId, card: serializeCard(state.identity.card) }) });
  if (r.status === 401) throw new Error("session expired");
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || "device registration failed"); }
}

async function afterAuth() {
  loadPrefs();
  await loadMyBundle();
  loadContactsLocal();
  startApp();
  loadContactsFromBlob(); // async refresh from encrypted server backup
}

// ---------- key generation ring ----------
const KG_CIRC = 2 * Math.PI * 52;
function showKeygen(pct, label) {
  $(".setup-card").classList.add("busy"); $("#keygen").hidden = false;
  const p = Math.max(0, Math.min(100, pct));
  const arc = $(".kg-arc"); arc.style.strokeDasharray = String(KG_CIRC); arc.style.strokeDashoffset = String(KG_CIRC * (1 - p / 100));
  $("#kg-num").textContent = String(Math.round(p)); if (label) $("#kg-label").textContent = label;
}

function startApp() {
  $("#app").hidden = false;
  $("#me-handle").textContent = state.user;
  setMobileView("list");
  connectWS(); wireUI(); renderContacts();
}

// ---------- account bundle + contacts ----------
async function loadMyBundle() {
  try { const r = await fetch("/api/bundle?handle=" + encodeURIComponent(state.user)); if (r.ok) { const j = await r.json(); state.myBundle = (j.devices || []).map(deserializeCard); } } catch { /* */ }
}
function loadContactsLocal() {
  try { const arr = JSON.parse(ls.get(K.contacts) || "[]"); for (const entry of arr) state.contacts.set(entry.handle, entry.cards.map(deserializeCard)); } catch { /* */ }
}
function saveContactsLocal() {
  const arr = [...state.contacts.entries()].map(([handle, cards]) => ({ handle, cards: cards.map(serializeCard) }));
  ls.set(K.contacts, JSON.stringify(arr));
}
async function uploadContactsBlob() {
  if (!state.blobKey || !state.token) return;
  try {
    const payload = { v: 2, contacts: [...state.contacts.keys()], muted: [...state.muted], blocked: [...state.blocked] };
    const blob = await encryptBlob(state.blobKey, payload);
    await fetch("/api/account/blob", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: state.token, blob }) });
  } catch { /* */ }
}
async function loadContactsFromBlob() {
  if (!state.blobKey) return;
  try {
    const r = await fetch("/api/account/blob?token=" + encodeURIComponent(state.token));
    if (!r.ok) return;
    const { blob } = await r.json();
    if (!blob) return;
    const data = await decryptBlob(state.blobKey, blob);
    // v1 blobs were a bare array of handles; v2 carries mutes/blocks too.
    const handles = Array.isArray(data) ? data : (data.contacts || []);
    if (!Array.isArray(data)) {
      for (const h of (data.muted || [])) state.muted.add(h);
      for (const h of (data.blocked || [])) state.blocked.add(h);
      savePrefs();
    }
    for (const h of handles) if (!state.contacts.has(h) && !state.blocked.has(h)) await fetchBundle(h, { silent: true, noSave: true });
    renderContacts();
  } catch { /* */ }
}

async function fetchBundle(handle, { silent = true, noSave = false } = {}) {
  handle = String(handle).trim().toLowerCase();
  if (!handle) return false;
  if (handle === state.user) { if (!silent) toast("that's you"); return false; }
  if (state.blocked.has(handle)) { if (!silent) toast(`${handle} is blocked - unblock them first`); return false; }
  try {
    const r = await fetch("/api/bundle?handle=" + encodeURIComponent(handle));
    if (!r.ok) { if (!silent) toast("no such handle online"); return false; }
    const j = await r.json();
    state.contacts.set(handle, (j.devices || []).map(deserializeCard));
    saveContactsLocal(); if (!noSave) uploadContactsBlob();
    renderContacts();
    if (!silent) setActive(handle);
    return true;
  } catch { if (!silent) toast("lookup failed"); return false; }
}
function ensureContact(handle) { if (!state.contacts.has(handle)) fetchBundle(handle, { silent: true }); }

// ---------- transport ----------
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/gateway`);
  state.ws = ws;
  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ t: "subscribe", provider: toB64(state.identity.providerId), mailbox: toB64(state.identity.mailbox) }));
    if (state.coverOn) scheduleCover();
  });
  ws.addEventListener("message", (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.t === "deliver") onDeliver(fromB64(m.envelope));
    else if (m.t === "hop") pulseHop(m.label);
    else if (m.t === "status") applyStatus(m);
  });
  ws.addEventListener("close", (ev) => {
    if (ev.code === 4003) { toast("this account has been suspended"); clearSession(); location.reload(); return; }
    if (ev.code === 4004) { toast("this account was removed"); clearSession(); location.reload(); return; }
    setTimeout(connectWS, 1500);
  });
}

function onDeliver(envelope) {
  let content; try { content = openIncoming(state.identity, envelope); } catch { return; }
  if (content.t === "cover") return;
  if (content.t !== "msg") return;
  if (content.id && state.seen.has(content.id)) return;
  if (content.id) state.seen.add(content.id);
  const me = state.user;
  if (content.from === me) {
    const peer = content.to || "unknown"; ensureContact(peer);
    pushMessage(peer, { dir: "out", body: content.body, ts: content.ts || Date.now(), id: content.id });
  } else {
    const from = content.from || "unknown";
    if (state.blocked.has(from)) return; // blocked sender: drop silently
    ensureContact(from);
    pushMessage(from, { dir: "in", body: content.body, ts: content.ts || Date.now(), id: content.id });
    state.stats.recv++; updateStats();
    const muted = state.muted.has(from);
    if (state.active !== from) bumpUnread(from);
    if (!muted && (state.active !== from || document.hidden)) {
      beep();
      if (state.active !== from) toast(`new message from ${from}`);
    }
  }
}

// ---------- transport dispatch ----------
// The server announces which transport is active: "internal" is our own mix
// network, "nym" the public Nym mixnet. All sends go through this dispatch.
//
// The nym client is a heavy WASM bundle, so it is loaded lazily the first time
// nym mode is seen and takes a few seconds to connect to a gateway. Until it is
// ready (or if it fails), nym.submit() falls back to the internal path so no
// message is ever silently dropped during the switch-over. Receiving keeps
// using the gateway websocket subscription in both modes; only the uplink is
// anonymised over Nym at this stage.
function internalSubmit(card, content) {
  const { firstNodeId, packet } = buildOutgoing(state.net, card, content);
  state.ws.send(JSON.stringify({ t: "submit", node: toB64(firstNodeId), packet: serializePacket(packet) }));
}

const nymClient = { loading: false, script: false, api: null };

function loadNymScript() {
  if (nymClient.script) return Promise.resolve(true);
  return new Promise((resolve) => {
    const s = document.createElement("script");
    s.src = "/nym-transport.bundle.js";
    s.onload = () => { nymClient.script = true; resolve(true); };
    s.onerror = () => resolve(false);
    document.head.appendChild(s);
  });
}

async function ensureNymClient() {
  if (nymClient.api) return nymClient.api;
  if (nymClient.loading) return null;
  nymClient.loading = true;
  try {
    const ok = await loadNymScript();
    if (!ok || !window.NobleNym) return null;
    nymClient.api = await window.NobleNym.create({
      onReady: () => toast("connected to the Nym mixnet"),
      onError: (m) => toast("nym client error: " + m),
    });
    return nymClient.api;
  } catch { return null; }
  finally { nymClient.loading = false; }
}

const transports = {
  internal: { submit: internalSubmit },
  nym: {
    submit(card, content) {
      const c = nymClient.api;
      // Not ready yet: keep messaging working over the internal path and warm
      // up the nym client in the background for subsequent sends.
      if (!c || !c.isReady() || !state.nymAddress) { ensureNymClient(); internalSubmit(card, content); return; }
      const { providerId, inner } = buildInner(card, content);
      const payload = JSON.stringify({ v: 1, p: toB64(providerId), i: toB64(inner) });
      c.send(payload, state.nymAddress).catch(() => internalSubmit(card, content));
    },
  },
};
function activeTransport() { return transports[state.transport] || transports.internal; }

// ---------- messaging ----------
function sendToCard(card, content) {
  try { activeTransport().submit(card, content); return true; }
  catch (e) { if (String(e.message).includes("unknown provider")) fetchBundle(state.active, { silent: true }); return false; }
}
async function sendMessage() {
  const input = $("#msg-input"); const body = input.value.trim();
  if (!body || !state.active) return;
  const target = state.active;
  // freshen the recipient's device list (and our own) so a device added on
  // another session still receives this message.
  await fetchBundle(target, { silent: true, noSave: true });
  await loadMyBundle();
  const bundle = state.contacts.get(target);
  if (!bundle || !bundle.length) { toast("contact has no devices online"); return; }
  const content = { v: 1, t: "msg", from: state.user, to: target, id: randHex(8), body, ts: Date.now() };
  let ok = false;
  for (const card of bundle) if (sendToCard(card, content)) ok = true;         // every recipient device
  const mine = toB64(state.identity.card.mailbox);
  for (const card of state.myBundle) if (toB64(card.mailbox) !== mine) sendToCard(card, content); // sync my own devices
  if (!ok) { toast("send failed"); return; }
  state.seen.add(content.id);
  pushMessage(target, { dir: "out", body, ts: content.ts, id: content.id });
  state.stats.sent++; updateStats();
  input.value = "";
}

// ---------- state + render ----------
function pushMessage(handle, msg) {
  if (!state.convos.has(handle)) state.convos.set(handle, []);
  const arr = state.convos.get(handle);
  if (msg.id && arr.some((m) => m.id === msg.id)) return;
  arr.push(msg);
  if (state.active === handle) renderMessages();
}
function setActive(handle) {
  state.active = handle; $("#chat-empty").hidden = true; $("#chat-view").hidden = false; $("#chat-with").textContent = handle;
  clearUnread(handle);
  renderContacts(); renderMessages(); setMobileView("chat");
  const mi = $("#msg-input"); if (mi) mi.focus();
}
function bumpUnread(handle) { state.unread.set(handle, (state.unread.get(handle) || 0) + 1); renderContacts(); }
function clearUnread(handle) { if (state.unread.delete(handle)) renderContacts(); }

// On phones the sidebar and the chat occupy the same space; #app[data-view]
// decides which one is shown. On wide screens both are always visible and the
// attribute is ignored by the CSS.
function setMobileView(view) { const app = $("#app"); if (app) app.dataset.view = view; }

function renderContacts() {
  const el = $("#contacts");
  const handles = [...state.contacts.keys()];
  if (!handles.length) {
    el.innerHTML = `<div class="net-note" style="padding:12px">No contacts yet. Add someone by their handle above.</div>`;
  } else {
    el.innerHTML = handles.map((h) => {
      const unread = state.unread.get(h) || 0;
      const badge = unread ? `<span class="badge">${unread > 99 ? "99+" : unread}</span>` : "";
      const muteIcon = state.muted.has(h) ? `<span class="mini-icon" title="muted">🔕</span>` : "";
      return `<div class="contact ${h === state.active ? "active" : ""} ${unread ? "has-unread" : ""}" data-h="${esc(h)}">
        <div class="avatar">${esc(h[0] || "?").toUpperCase()}</div>
        <div class="c-main"><div class="h">${esc(h)} ${muteIcon}</div><div class="s">post-quantum · mixnet</div></div>
        ${badge}
        <button class="row-menu" data-menu="${esc(h)}" title="Options" aria-label="Options">⋮</button>
      </div>`;
    }).join("");
  }
  el.querySelectorAll(".contact").forEach((n) => n.addEventListener("click", (e) => {
    if (e.target.closest(".row-menu")) return; // menu button handled separately
    setActive(n.dataset.h);
  }));
  el.querySelectorAll(".row-menu").forEach((b) => b.addEventListener("click", (e) => { e.stopPropagation(); openContactMenu(b.dataset.menu, b); }));
  renderBlocked();
}

function renderBlocked() {
  const wrap = $("#blocked-wrap"); if (!wrap) return;
  const list = [...state.blocked];
  wrap.hidden = list.length === 0;
  $("#blocked-count").textContent = String(list.length);
  const box = $("#blocked-list");
  box.innerHTML = list.map((h) => `<div class="blocked-row"><span>${esc(h)}</span><button class="btn-sm unblock" data-h="${esc(h)}">Unblock</button></div>`).join("");
  box.querySelectorAll(".unblock").forEach((b) => b.addEventListener("click", () => unblock(b.dataset.h)));
}

// ---------- per-chat actions: mute, block, delete ----------
function toggleMute(handle) {
  if (state.muted.has(handle)) { state.muted.delete(handle); toast(`unmuted ${handle}`); }
  else { state.muted.add(handle); toast(`muted ${handle}`); }
  savePrefs(); uploadContactsBlob(); renderContacts();
}
function deleteChat(handle) {
  state.convos.delete(handle); state.contacts.delete(handle); state.unread.delete(handle); state.muted.delete(handle);
  if (state.active === handle) { state.active = null; $("#chat-view").hidden = true; $("#chat-empty").hidden = false; setMobileView("list"); }
  saveContactsLocal(); savePrefs(); uploadContactsBlob(); renderContacts();
  toast(`deleted chat with ${handle}`);
}
function clearMessages(handle) {
  state.convos.set(handle, []);
  if (state.active === handle) renderMessages();
  toast(`cleared messages with ${handle}`);
}
function block(handle) {
  state.blocked.add(handle);
  state.convos.delete(handle); state.contacts.delete(handle); state.unread.delete(handle); state.muted.delete(handle);
  if (state.active === handle) { state.active = null; $("#chat-view").hidden = true; $("#chat-empty").hidden = false; setMobileView("list"); }
  saveContactsLocal(); savePrefs(); uploadContactsBlob(); renderContacts();
  toast(`blocked ${handle}`);
}
function unblock(handle) {
  state.blocked.delete(handle); savePrefs(); uploadContactsBlob(); renderContacts();
  toast(`unblocked ${handle}`);
}

// ---------- small popup menu ----------
function closeMenus() { document.querySelectorAll(".menu-pop.open").forEach((m) => { m.classList.remove("open"); m.hidden = true; }); }
function buildMenu(pop, handle, { includeClear = false } = {}) {
  const muted = state.muted.has(handle);
  const items = [
    { label: muted ? "🔔 Unmute" : "🔕 Mute", act: () => toggleMute(handle) },
  ];
  if (includeClear) items.push({ label: "🧹 Clear messages", act: () => clearMessages(handle) });
  items.push({ label: "🚫 Block", act: () => block(handle), danger: true });
  items.push({ label: "🗑 Delete chat", act: () => deleteChat(handle), danger: true });
  pop.innerHTML = "";
  for (const it of items) {
    const b = document.createElement("button");
    b.className = "menu-item" + (it.danger ? " danger" : "");
    b.textContent = it.label;
    b.addEventListener("click", (e) => { e.stopPropagation(); closeMenus(); it.act(); });
    pop.appendChild(b);
  }
}
function openContactMenu(handle, anchor) {
  const existing = document.getElementById("row-menu-pop");
  const pop = existing || Object.assign(document.createElement("div"), { id: "row-menu-pop", className: "menu-pop" });
  if (!existing) document.body.appendChild(pop);
  buildMenu(pop, handle);
  const r = anchor.getBoundingClientRect();
  pop.style.position = "fixed"; pop.style.top = `${r.bottom + 4}px`; pop.style.left = `${Math.min(r.left, window.innerWidth - 190)}px`;
  const wasOpen = pop.classList.contains("open"); closeMenus();
  if (!wasOpen) { pop.hidden = false; pop.classList.add("open"); }
}
function openChatMenu() {
  const pop = $("#chat-menu-pop"); if (!state.active) return;
  buildMenu(pop, state.active, { includeClear: true });
  const wasOpen = pop.classList.contains("open"); closeMenus();
  if (!wasOpen) { pop.hidden = false; pop.classList.add("open"); }
}
function renderMessages() {
  const el = $("#messages"); const msgs = state.convos.get(state.active) || [];
  el.innerHTML = msgs.map((m) => { const time = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); return `<div class="msg ${m.dir}">${esc(m.body)}<span class="t">${time}</span></div>`; }).join("");
  el.scrollTop = el.scrollHeight;
}
function updateStats() { $("#stat-sent").textContent = state.stats.sent; $("#stat-cover").textContent = state.stats.cover; $("#stat-recv").textContent = state.stats.recv; }

// ---------- cover traffic ----------
function toggleCover() {
  state.coverOn = !state.coverOn;
  const b = $("#cover-toggle"); b.textContent = "cover: " + (state.coverOn ? "on" : "off"); b.classList.toggle("on", state.coverOn);
  if (state.coverOn) { toast("cover traffic on - hiding when you talk"); scheduleCover(); } else clearTimeout(state.coverTimer);
}
function scheduleCover() { clearTimeout(state.coverTimer); state.coverTimer = setTimeout(() => { sendCover(); if (state.coverOn) scheduleCover(); }, poisson(3500) + 800); }
function sendCover() { if (!state.ws || state.ws.readyState !== 1) return; try { activeTransport().submit(state.identity.card, { t: "cover", ts: 0 }); state.stats.cover++; updateStats(); } catch { /* */ } }

// ---------- notification sound toggle ----------
function renderSoundToggle() { const b = $("#sound-toggle"); if (!b) return; b.textContent = state.soundOn ? "🔔" : "🔕"; b.classList.toggle("on", state.soundOn); b.title = state.soundOn ? "Message sound: on" : "Message sound: off"; }
function toggleSound() {
  state.soundOn = !state.soundOn; savePrefs(); renderSoundToggle();
  if (state.soundOn) { beep(); toast("message sound on"); } else toast("message sound off");
}

// ---------- mix viz ----------
function buildNetViz() {
  const wrap = $("#net-layers"); const cols = state.net.layers.length + 1;
  const labels = state.net.layers.map((_, i) => "L" + (i + 1)).concat(["exit"]); let html = "";
  for (let i = 0; i < cols; i++) { html += `<div class="net-col"><div class="net-node" data-col="${i}">◆</div><div class="net-lbl">${labels[i]}</div></div>`; if (i < cols - 1) html += `<div class="net-arrow">→</div>`; }
  wrap.innerHTML = html; state.netCols = [...wrap.querySelectorAll(".net-node")];
}
function pulseHop(label) { let col = -1; const m = /^mix-L(\d+)/.exec(label); if (m) col = Number(m[1]); else if (label.startsWith("provider")) col = state.net.layers.length; const node = state.netCols[col]; if (!node) return; node.classList.add("pulse"); setTimeout(() => node.classList.remove("pulse"), 320); }

// ---------- wire ui ----------
function wireUI() {
  $("#add-go").addEventListener("click", () => { fetchBundle($("#add-handle").value, { silent: false }); $("#add-handle").value = ""; });
  $("#add-handle").addEventListener("keydown", (e) => { if (e.key === "Enter") { fetchBundle($("#add-handle").value, { silent: false }); $("#add-handle").value = ""; } });
  $("#msg-send").addEventListener("click", sendMessage);
  $("#msg-input").addEventListener("keydown", (e) => e.key === "Enter" && sendMessage());
  const cover = $("#cover-toggle"); cover.addEventListener("click", toggleCover); cover.textContent = "cover: " + (state.coverOn ? "on" : "off"); cover.classList.toggle("on", state.coverOn);
  const lo = $("#logout-btn"); if (lo) lo.addEventListener("click", logout);
  const snd = $("#sound-toggle"); if (snd) snd.addEventListener("click", toggleSound); renderSoundToggle();
  const back = $("#chat-back"); if (back) back.addEventListener("click", () => setMobileView("list"));
  const cmenu = $("#chat-menu"); if (cmenu) cmenu.addEventListener("click", (e) => { e.stopPropagation(); openChatMenu(); });
  const btgl = $("#blocked-toggle"); if (btgl) btgl.addEventListener("click", () => { const l = $("#blocked-list"); l.hidden = !l.hidden; });
  document.addEventListener("click", (e) => { if (!e.target.closest(".menu-pop") && !e.target.closest(".row-menu") && !e.target.closest("#chat-menu")) closeMenus(); });
  window.addEventListener("focus", () => { if (state.active) clearUnread(state.active); });
  updateStats();
}
async function logout() {
  try { await fetch("/api/account/logout", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: state.token }) }); } catch { /* */ }
  clearSession(); location.reload();
}

// ---------- server status: announcements, maintenance, auto-update ----------
function ensureEl(id, cls, parent) { let el = document.getElementById(id); if (!el) { el = document.createElement("div"); el.id = id; el.className = cls; (parent || document.body).appendChild(el); } return el; }
async function pollStatus() { try { const r = await fetch("/api/status"); if (r.ok) applyStatus(await r.json()); } catch { /* */ } }
function applyStatus(s) {
  if (s.transport && s.transport !== state.transport) state.transport = s.transport;
  if (typeof s.nymAddress === "string") state.nymAddress = s.nymAddress;
  if (state.transport === "nym") ensureNymClient();
  if (s.version) { if (state.version && s.version !== state.version) offerUpdate(); else if (!state.version) state.version = s.version; }
  const ann = String(s.announcement || "").trim(); const banner = ensureEl("nc-announce", "nc-announce");
  if (ann) { banner.textContent = "\u{1F4E2}  " + ann; banner.hidden = false; } else banner.hidden = true;
  state.maintenance = !!s.maintenance; const mo = ensureEl("nc-maint", "nc-maint");
  if (s.maintenance) { mo.innerHTML = ""; const box = document.createElement("div"); box.className = "nc-maint-box"; const t = document.createElement("div"); t.className = "nc-maint-title"; t.textContent = "◆ Under maintenance"; const p = document.createElement("div"); p.className = "nc-maint-msg"; p.textContent = s.maintenanceMsg || "NobleChat is briefly undergoing maintenance. Please check back shortly."; box.appendChild(t); box.appendChild(p); mo.appendChild(box); mo.hidden = false; } else mo.hidden = true;
}
function offerUpdate() {
  const input = $("#msg-input"); if (!input || !input.value.trim()) { location.reload(); return; }
  const bar = ensureEl("nc-update", "nc-update"); bar.innerHTML = "";
  const span = document.createElement("span"); span.textContent = "A new version is available."; const btn = document.createElement("button"); btn.className = "btn-sm"; btn.textContent = "Update"; btn.addEventListener("click", () => location.reload());
  bar.appendChild(span); bar.appendChild(btn); bar.hidden = false;
}

boot();
