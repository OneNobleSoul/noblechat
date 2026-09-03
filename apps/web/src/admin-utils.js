// Pure helpers pulled out of admin.js so they can be unit tested directly.
// admin.js touches the DOM the moment it runs (it wires up its own event
// listeners at the bottom of the file, right after `const $ = ...` reads
// sessionStorage), the same reason main.js's pure pieces already live in
// text-utils.js, message-utils.js, pin-utils.js, card-utils.js and
// ice-utils.js instead of inline.

// Escape text before it goes into innerHTML. Matches the chat client's
// esc() in text-utils.js, including the single quote: admin.js only ever
// places this inside double-quoted attributes or plain text today, but a
// future template that lands a value inside a single-quoted attribute
// should not have to remember to swap escape functions first.
export function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Absolute timestamp for the log table and the users table. Server-supplied
// `ts`/`created_at` values are trusted numbers in practice, but coercion can
// still throw on the odd malformed input (e.g. a Symbol), and a stray render
// exception should not blank out the rest of the row.
export function fmtTime(ms) {
  try { return new Date(Number(ms)).toLocaleString(); } catch { return "-"; }
}

// Server uptime in the coarsest two units that still fit, e.g. "3h 42m".
// Unlike fmtSize/fmtRemaining in text-utils.js this never rounds: every
// return path is a Math.floor of the exact seconds, so a value can't tip
// past the unit boundary it was just placed in.
export function fmtUptime(sec) {
  sec = Number(sec) || 0;
  if (sec < 3600) return Math.floor(sec / 60) + "m";
  if (sec < 86400) return Math.floor(sec / 3600) + "h " + Math.floor((sec % 3600) / 60) + "m";
  return Math.floor(sec / 86400) + "d " + Math.floor((sec % 86400) / 3600) + "h";
}
