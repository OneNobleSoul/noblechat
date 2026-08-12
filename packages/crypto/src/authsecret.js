// The value a client sends to prove who it is.
//
// Sign-in used to post the raw password. That handed the server everything it
// needed to open the "end-to-end encrypted" contacts blob it stores for that
// account: the blob key is PBKDF2 over the same password, salted with the
// handle, which the server obviously knows. Contacts, group membership and the
// key pins - the very thing protecting users against a server that swaps
// someone's keys - were all readable by the party they were being kept from.
//
// The fix is domain separation. The server is given a value derived under a
// different salt: enough to authenticate, and not something the blob key can
// be computed from. The blob key keeps its original salt on purpose, so blobs
// written before this change stay readable and no re-encryption pass is needed.
//
// Deliberately shared by the web client, the admin panel and the smoke test:
// three copies of a KDF is three chances for one of them to drift and start
// locking people out.
const ITERATIONS = 600000; // matches the blob key; current OWASP guidance for PBKDF2-HMAC-SHA256

export const AUTH_SALT_PREFIX = "noblechat:auth:";

export async function deriveAuthSecret(password, username) {
  const enc = new TextEncoder();
  const subtle = globalThis.crypto.subtle;
  const base = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(AUTH_SALT_PREFIX + username), iterations: ITERATIONS, hash: "SHA-256" },
    base,
    256,
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
