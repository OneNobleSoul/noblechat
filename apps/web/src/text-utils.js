// Small pure helpers pulled out of main.js so they can be unit tested
// directly: main.js touches the DOM and browser APIs the moment it runs,
// which makes it awkward to import individual pieces into a test file.

export function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

export function simpleHash(s) {
  let h = 0;
  for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return h;
}

// map extensions to a mime when the browser gives us none (common for .mov)
export const MEDIA_EXT = { mov: "video/quicktime", mp4: "video/mp4", m4v: "video/mp4", webm: "video/webm", ogv: "video/ogg", mkv: "video/x-matroska", mp3: "audio/mpeg", m4a: "audio/mp4", wav: "audio/wav", ogg: "audio/ogg", oga: "audio/ogg", aac: "audio/aac", flac: "audio/flac", opus: "audio/ogg" };

export function fileMime(file) {
  if (file.type) return file.type;
  const ext = (file.name.split(".").pop() || "").toLowerCase();
  return MEDIA_EXT[ext] || "application/octet-stream";
}

// which inline preview a mime gets: image, video, audio, or "" (download only)
export function mimeKind(mime) {
  const m = String(mime || "");
  return m.startsWith("image/") ? "image" : m.startsWith("video/") ? "video" : m.startsWith("audio/") ? "audio" : "";
}

// human-readable file size for attachment rows (B/KB/MB, no fractional bytes)
export function fmtSize(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(0) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

// how much time is left on an auto-delete timer, in the coarsest unit that
// still fits (seconds up to a minute, then minutes/hours/days)
export function fmtRemaining(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.round(s / 60) + "m";
  if (s < 86400) return Math.round(s / 3600) + "h";
  return Math.round(s / 86400) + "d";
}

// A received message's `file` object is attacker-controlled: coerce every field
// to the exact type/shape the UI expects before it is ever stored or rendered,
// so a crafted value can't break out of an HTML attribute or class. Decryption
// fields (id/key/mime/enc) are kept as plain strings; they only feed
// encodeURIComponent/fromB64, never raw HTML.
export function normalizeFile(f) {
  if (!f || typeof f !== "object") return undefined;
  const out = {
    name: String(f.name || "file").slice(0, 120),
    mime: String(f.mime || "application/octet-stream").slice(0, 100),
    size: Number(f.size) || 0,
    id: String(f.id || ""),
    key: String(f.key || ""),
    enc: String(f.enc || ""),
  };
  if (f.expireAt != null && Number.isFinite(Number(f.expireAt))) out.expireAt = Number(f.expireAt);
  return out;
}
