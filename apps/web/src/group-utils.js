// Pure diff helper for group membership. Pulled out of main.js's ensureGroup()
// so the "who got added" logic can be unit tested without a DOM (same reason
// card-utils.js and message-utils.js exist as separate files).
//
// Every group message carries the sender's local copy of the member list and
// ensureGroup() adopts it wholesale - nothing today checks who is allowed to
// add someone. Surfacing additions to the user (the same treatment a key
// change already gets) turns a silent expansion of a private conversation
// into a visible one instead.
export function addedMembers(oldMembers, newMembers) {
  const old = Array.isArray(oldMembers) ? oldMembers : [];
  const next = Array.isArray(newMembers) ? newMembers : [];
  return next.filter((h) => h && !old.includes(h));
}
