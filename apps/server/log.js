// Small in-memory event log backing the admin panel. Content-free by design:
// entries carry operational metadata only - never message content, mailbox ids
// or client IPs. It is a ring buffer, so memory stays bounded and old entries
// simply fall off. Restarting the server clears it; that is fine for an ops
// log (durable history would itself become a metadata trove).

export const LOG_LEVELS = ["info", "warn", "error"];

export function createLog(limit = 400) {
  const entries = [];
  let seq = 0;
  return {
    add(level, event, detail = "") {
      if (!LOG_LEVELS.includes(level)) level = "info";
      entries.push({
        seq: ++seq,
        ts: Date.now(),
        level,
        event: String(event).slice(0, 60),
        detail: String(detail).slice(0, 200),
      });
      if (entries.length > limit) entries.shift();
      return seq;
    },
    // Everything after `since` (a seq previously seen by the caller), oldest
    // first, so the admin UI can poll incrementally.
    list(since = 0) {
      return entries.filter((e) => e.seq > since);
    },
    size() { return entries.length; },
  };
}
