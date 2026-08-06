// Pure helpers for applying an incoming reaction/unsend to an already-stored
// message. Pulled out of main.js so the reaction toggle math and the unsend
// authorization check can be unit tested directly, without a live convos map,
// DOM, or state.user around them.

// Returns the reactions map for a message after toggling `who`'s reaction
// with `emoji` on or off. Never mutates the input map. Drops the emoji key
// entirely once its list of reactors is empty, so an empty reactions object
// never lingers on a message.
export function reactionsAfterToggle(reactions, emoji, who, remove) {
  const out = { ...(reactions || {}) };
  const arr = out[emoji] || [];
  const next = remove ? arr.filter((h) => h !== who) : (arr.includes(who) ? arr : [...arr, who]);
  if (next.length) out[emoji] = next; else delete out[emoji];
  return out;
}

// A "delete for everyone" is only honored if it comes from whoever actually
// sent the message. `message.sender` is the authoritative field (set on every
// stored message, in and out, 1:1 and group); the `dir === "out"` fallback
// covers older locally-cached messages saved before `sender` was always set.
export function canUnsend(message, fromHandle, selfHandle) {
  const origin = message.sender || (message.dir === "out" ? selfHandle : null);
  return !origin || fromHandle === origin;
}

// Keeps the newest `cap` entries of a conversation's message list, dropping
// the oldest ones once it grows past that. Without this, a conversation left
// open for days accumulates messages in memory without bound (only the
// on-disk copy was ever capped, via HISTORY_PER_CHAT at save time) - the same
// class of leak SEEN_CAP already guards against for state.seen. Returns the
// input array unchanged (same reference) when it's already within the cap,
// so callers can skip a state.convos.set() when nothing actually changed.
export function trimHistory(arr, cap) {
  return arr.length > cap ? arr.slice(arr.length - cap) : arr;
}

// Decides whether the message list should auto-scroll to the newest message
// after a re-render. renderMessages() rebuilds the whole list on things that
// have nothing to do with what the user is currently looking at: a reaction
// someone else added, a remote "delete for everyone", or the 5s sweep that
// marks expired image attachments. Without this check every one of those
// snapped the scroll position to the bottom, yanking it away from whoever
// had scrolled up to read older messages. Only stick to the bottom if the
// view was already close to it (small pixel slack via `threshold` since
// browsers don't always report an exact 0).
export function shouldStickToBottom(scrollTop, scrollHeight, clientHeight, threshold = 80) {
  return scrollHeight - scrollTop - clientHeight <= threshold;
}
