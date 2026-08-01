// Pure helpers for the key-pinning state (see the block comment above
// checkPin() in main.js for the trust model). Pulled out so the round-trip
// through localStorage and the synced-blob merge can be unit tested directly
// instead of only ever running inside a live session.

// A pin is { fp, ok }: ok === false means "keys changed, awaiting the user".
// Tolerates the older format where a pin was just the bare fingerprint string.
export function parsePinsJson(raw) {
  try {
    const o = JSON.parse(raw || "{}");
    return new Map(Object.entries(o).map(([h, v]) => [
      h,
      typeof v === "string" ? { fp: v, ok: true } : { fp: String(v.fp || ""), ok: v.ok !== false },
    ]));
  } catch {
    return new Map();
  }
}

export function pinsToObject(pins) {
  const o = {};
  for (const [h, p] of pins) o[h] = { fp: p.fp, ok: p.ok !== false };
  return o;
}

// Combine this device's pin for a handle with one synced from the encrypted
// contacts blob, on login/sync. A fresh device with no local pin simply
// adopts the synced one. On any conflict (different fingerprint, or either
// side already flagged unverified) the LOCAL fingerprint wins but the result
// is marked unverified - a synced "verified" pin can never silently paper
// over a local key change, only a fresh safety-number check can clear it.
export function mergeSyncedPin(local, synced) {
  if (!synced || !synced.fp) return local;
  if (!local) return { fp: String(synced.fp), ok: synced.ok !== false };
  if (local.fp !== synced.fp || local.ok === false || synced.ok === false) {
    return { fp: local.fp, ok: false };
  }
  return local;
}
