import test from "node:test";
import assert from "node:assert/strict";
import { isHttpUrl, sameOrigin } from "../clients/desktop/url-guards.js";

test("isHttpUrl accepts http and https", () => {
  assert.equal(isHttpUrl("https://chat.noblesoul.tech/app"), true);
  assert.equal(isHttpUrl("http://localhost:8790/app"), true);
});

test("isHttpUrl rejects non-http schemes", () => {
  assert.equal(isHttpUrl("file:///etc/passwd"), false);
  assert.equal(isHttpUrl("mailto:someone@example.com"), false);
  assert.equal(isHttpUrl("noblechat-desktop://foo"), false);
});

test("isHttpUrl rejects unparseable input instead of throwing", () => {
  assert.equal(isHttpUrl("not a url"), false);
  assert.equal(isHttpUrl(""), false);
});

test("sameOrigin is true for an identical origin, ignoring path/query", () => {
  assert.equal(sameOrigin("https://chat.noblesoul.tech/app/inbox?x=1", "https://chat.noblesoul.tech"), true);
});

test("sameOrigin is false for a different host", () => {
  assert.equal(sameOrigin("https://evil.example/app", "https://chat.noblesoul.tech"), false);
});

test("sameOrigin is false for a different scheme or port", () => {
  assert.equal(sameOrigin("http://chat.noblesoul.tech/app", "https://chat.noblesoul.tech"), false);
  assert.equal(sameOrigin("https://chat.noblesoul.tech:8443/app", "https://chat.noblesoul.tech"), false);
});

test("sameOrigin rejects unparseable input instead of throwing", () => {
  assert.equal(sameOrigin("not a url", "https://chat.noblesoul.tech"), false);
});
