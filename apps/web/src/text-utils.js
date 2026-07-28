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
