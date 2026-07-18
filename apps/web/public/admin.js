// NobleChat admin panel logic. Talks to /api/admin/* with a Bearer token kept
// only in this tab's sessionStorage.
const $ = (s) => document.querySelector(s);
const TOKEN_KEY = "nc-admin-token";
let token = sessionStorage.getItem(TOKEN_KEY) || "";

async function api(path, method = "GET", body) {
  const res = await fetch(path, { method, headers: { authorization: "Bearer " + token, ...(body ? { "content-type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined });
  if (res.status === 401) { signOut(); throw new Error("unauthorized"); }
  return res.json().catch(() => ({}));
}
function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function fmtTime(ms) { try { return new Date(Number(ms)).toLocaleString(); } catch { return "—"; } }
function showDash(on) { $("#login").classList.toggle("hidden", on); $("#dash").classList.toggle("hidden", !on); }

async function signIn(t) {
  token = t;
  try {
    const s = await api("/api/admin/status");
    if (s && typeof s.users !== "undefined") { sessionStorage.setItem(TOKEN_KEY, token); showDash(true); renderStatus(s); await loadUsers(); }
    else throw new Error("bad");
  } catch { $("#login-err").classList.remove("hidden"); }
}
function signOut() { sessionStorage.removeItem(TOKEN_KEY); token = ""; showDash(false); }

function renderStatus(s) {
  $("#ver").textContent = "version " + (s.version || "—");
  $("#s-users").textContent = s.users ?? 0;
  $("#s-queued").textContent = s.queued ?? 0;
  $("#s-banned").textContent = s.banned ?? 0;
  $("#s-maint").textContent = s.maintenance ? "ON" : "off";
  $("#s-maint").style.color = s.maintenance ? "var(--warn)" : "var(--ok)";
  const pill = $("#maint-pill"); pill.textContent = s.maintenance ? "enabled" : "disabled"; pill.className = "pill " + (s.maintenance ? "on" : "off");
  if (document.activeElement !== $("#ann")) $("#ann").value = s.announcement || "";
  if (document.activeElement !== $("#maint-msg")) $("#maint-msg").value = s.maintenanceMsg || "";
}
async function refresh() { renderStatus(await api("/api/admin/status")); await loadUsers(); }

async function loadUsers() {
  const d = await api("/api/admin/users");
  const users = (d && d.users) || [];
  const active = users.filter((u) => !u.banned);
  const banned = users.filter((u) => u.banned);

  const tb = $("#users"); tb.innerHTML = "";
  $("#users-empty").classList.toggle("hidden", active.length > 0);
  for (const u of active) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(u.username)}</td><td>${u.devices || 0}</td><td class="muted">${fmtTime(u.created_at)}</td>`;
    const td = document.createElement("td"); td.style.textAlign = "right";
    const ban = document.createElement("button"); ban.className = "btn warn"; ban.textContent = "Ban"; ban.onclick = () => act("ban", u.username);
    const del = document.createElement("button"); del.className = "btn danger"; del.textContent = "Delete"; del.onclick = () => act("delete", u.username);
    td.appendChild(ban); td.appendChild(del); tr.appendChild(td); tb.appendChild(tr);
  }

  const bt = $("#bans"); bt.innerHTML = "";
  $("#bans-empty").classList.toggle("hidden", banned.length > 0);
  for (const u of banned) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(u.username)}</td><td class="muted">${esc(u.reason || "")}</td>`;
    const td = document.createElement("td"); td.style.textAlign = "right";
    const un = document.createElement("button"); un.className = "btn ghost"; un.textContent = "Unban"; un.onclick = () => act("unban", u.username);
    const del = document.createElement("button"); del.className = "btn danger"; del.textContent = "Delete"; del.onclick = () => act("delete", u.username);
    td.appendChild(un); td.appendChild(del); tr.appendChild(td); bt.appendChild(tr);
  }
}
async function act(kind, handle) {
  if (kind === "ban") { const reason = prompt("Ban " + handle + " — reason (optional):", ""); if (reason === null) return; await api("/api/admin/ban", "POST", { handle, reason }); }
  else if (kind === "delete") { if (!confirm("Delete account " + handle + "? Removes all its devices and queued messages.")) return; await api("/api/admin/delete", "POST", { handle }); }
  else if (kind === "unban") { await api("/api/admin/unban", "POST", { handle }); }
  await refresh();
}

$("#login-go").addEventListener("click", () => signIn($("#token").value.trim()));
$("#token").addEventListener("keydown", (e) => { if (e.key === "Enter") signIn($("#token").value.trim()); });
$("#refresh").addEventListener("click", refresh);
$("#logout").addEventListener("click", signOut);
$("#ann-save").addEventListener("click", async () => { await api("/api/admin/announce", "POST", { text: $("#ann").value }); await refresh(); });
$("#ann-clear").addEventListener("click", async () => { $("#ann").value = ""; await api("/api/admin/announce", "POST", { text: "" }); await refresh(); });
$("#maint-on").addEventListener("click", async () => { await api("/api/admin/maintenance", "POST", { on: true, message: $("#maint-msg").value }); await refresh(); });
$("#maint-off").addEventListener("click", async () => { await api("/api/admin/maintenance", "POST", { on: false, message: $("#maint-msg").value }); await refresh(); });

if (token) signIn(token); else showDash(false);
