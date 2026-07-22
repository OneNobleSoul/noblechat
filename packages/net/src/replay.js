// Sphinx anti-replay for a mix node. `processPacket` is deterministic, so a
// captured packet re-injected verbatim would peel to the same next hop and be
// forwarded again - letting an observer trace a flow or force a double delivery.
// Each node remembers the packets it has already processed (keyed by the
// packet's ephemeral alpha, which is unique per packet-at-this-hop) and drops
// duplicates. Memory is bounded by keeping only two rolling epochs of tags: a
// tag older than ~2 epochs falls out, by which time the packet is long past its
// mixing delay and can no longer be usefully replayed.
export function makeReplayGuard({ epochMs = 2 * 60 * 1000, maxPerEpoch = 200000 } = {}) {
  let cur = new Set();
  let prev = new Set();
  let epochStart = null; // null (not 0) so a legitimate now===0 still initialises
  function rotate(now) { prev = cur; cur = new Set(); epochStart = now; }
  return {
    // Records `tag` and returns false the first time it is seen; returns true
    // (a replay) if the same tag was seen within the last ~2 epochs.
    seen(tag, now = Date.now()) {
      if (epochStart === null) epochStart = now;
      if (now - epochStart >= epochMs || cur.size >= maxPerEpoch) rotate(now);
      if (cur.has(tag) || prev.has(tag)) return true;
      cur.add(tag);
      return false;
    },
    size() { return cur.size + prev.size; },
  };
}
