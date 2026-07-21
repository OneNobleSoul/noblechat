import crypto from "node:crypto";

// coturn's "REST API" long-term credential scheme (use-auth-secret in
// turnserver.conf): the username is "<unix-expiry>:<label>" and the password
// is base64(HMAC-SHA1(secret, username)). coturn derives the same value from
// its own copy of the shared secret, so we never store or hand out a
// permanent TURN password, only a value that stops working after ttlSec.
export function turnCredentials(secret, ttlSec = 3600, now = Date.now()) {
  const expiry = Math.floor(now / 1000) + Math.max(60, ttlSec);
  const username = `${expiry}:noblechat`;
  const credential = crypto.createHmac("sha1", secret).update(username).digest("base64");
  return { username, credential, expiry };
}

// Builds the iceServers entry the client should merge into its
// RTCPeerConnection config. Empty when no TURN server is configured, so
// calls keep working STUN-only exactly like before this existed.
export function turnIceServers(cfg, now = Date.now()) {
  if (!cfg.turnSecret || !cfg.turnUris || !cfg.turnUris.length) return [];
  const { username, credential } = turnCredentials(cfg.turnSecret, cfg.turnTtlSec, now);
  return [{ urls: cfg.turnUris, username, credential }];
}
