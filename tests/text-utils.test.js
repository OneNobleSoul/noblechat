import test from "node:test";
import assert from "node:assert/strict";
import { esc, simpleHash, fileMime, mimeKind } from "../apps/web/src/text-utils.js";

test("esc escapes every HTML-significant character used to render messages", () => {
  assert.equal(esc("<script>alert('hi')</script>"), "&lt;script&gt;alert(&#39;hi&#39;)&lt;/script&gt;");
  assert.equal(esc('"quoted" & <tag>'), "&quot;quoted&quot; &amp; &lt;tag&gt;");
  assert.equal(esc("plain text"), "plain text");
});

test("esc coerces non-strings instead of throwing", () => {
  assert.equal(esc(42), "42");
  assert.equal(esc(null), "null");
  assert.equal(esc(undefined), "undefined");
});

test("simpleHash is deterministic and stays an unsigned 32-bit int", () => {
  assert.equal(simpleHash("noblesoul"), simpleHash("noblesoul"));
  assert.notEqual(simpleHash("noblesoul"), simpleHash("unterwegs"));
  assert.ok(simpleHash("x".repeat(500)) >= 0);
});

test("fileMime trusts the browser-supplied type first", () => {
  assert.equal(fileMime({ type: "image/png", name: "photo.png" }), "image/png");
});

test("fileMime falls back to the extension map when type is empty (common for .mov)", () => {
  assert.equal(fileMime({ type: "", name: "clip.MOV" }), "video/quicktime");
  assert.equal(fileMime({ type: "", name: "song.flac" }), "audio/flac");
});

test("fileMime falls back to application/octet-stream for an unknown or missing extension", () => {
  assert.equal(fileMime({ type: "", name: "noext" }), "application/octet-stream");
  assert.equal(fileMime({ type: "", name: "archive.zip" }), "application/octet-stream");
});

test("mimeKind buckets image/video/audio mimes and rejects everything else", () => {
  assert.equal(mimeKind("image/png"), "image");
  assert.equal(mimeKind("video/mp4"), "video");
  assert.equal(mimeKind("audio/mpeg"), "audio");
  assert.equal(mimeKind("application/pdf"), "");
  assert.equal(mimeKind(""), "");
  assert.equal(mimeKind(undefined), "");
});
