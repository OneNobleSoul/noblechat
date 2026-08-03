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
