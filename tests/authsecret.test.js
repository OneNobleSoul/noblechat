import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { deriveAuthSecret, AUTH_SALT_PREFIX } from "../packages/crypto/src/authsecret.js";
import { AUTH_SECRET_RE } from "../apps/server/util.js";

// The blob key's derivation, copied here so the test can prove the two are
// genuinely different rather than trusting that they look different.
const blobSalt = (username) => "noblechat:" + username;

test("auth secret is 256 bits of lowercase hex, which is what the server accepts", async () => {
  const s = await deriveAuthSecret("correct horse battery staple", "kirito");
  assert.ok(AUTH_SECRET_RE.test(s), `server would reject ${s}`);
});

test("auth secret is deterministic and bound to the handle", async () => {
  const a = await deriveAuthSecret("hunter2hunter2", "kirito");
  const b = await deriveAuthSecret("hunter2hunter2", "kirito");
  const c = await deriveAuthSecret("hunter2hunter2", "asuna");
  assert.equal(a, b, "same password and handle must sign in twice");
  assert.notEqual(a, c, "a secret must not be replayable under another handle");
});

// The point of the whole exercise: what the server receives must not be the
// blob key, and must not be a step on the way to it.
test("the value the server sees is not the blob key", async () => {
  const password = "hunter2hunter2";
  const username = "kirito";
  const authSecret = await deriveAuthSecret(password, username);
  const blobKey = crypto.pbkdf2Sync(password, blobSalt(username), 600000, 32, "sha256").toString("hex");
  assert.notEqual(authSecret, blobKey);
  // And confirm the salts are actually separated, not accidentally equal.
  assert.notEqual(AUTH_SALT_PREFIX + username, blobSalt(username));
});

test("the blob key cannot be recomputed from what the server stores", async () => {
  // A server holding the auth secret would have to invert PBKDF2 to get back
  // to the password before it could derive the blob key. Standing in for that:
  // treating the auth secret as if it were the password produces a different
  // key, so possession of it buys nothing.
  const username = "kirito";
  const authSecret = await deriveAuthSecret("hunter2hunter2", username);
  const realBlobKey = crypto.pbkdf2Sync("hunter2hunter2", blobSalt(username), 600000, 32, "sha256").toString("hex");
  const fromSecret = crypto.pbkdf2Sync(authSecret, blobSalt(username), 600000, 32, "sha256").toString("hex");
  assert.notEqual(fromSecret, realBlobKey);
});
