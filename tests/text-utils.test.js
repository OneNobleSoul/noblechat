import test from "node:test";
import assert from "node:assert/strict";
import { esc, simpleHash, fileMime, mimeKind, fmtSize, fmtRemaining } from "../apps/web/src/text-utils.js";

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

test("fmtSize stays in bytes under 1 KB, whole KB under 1 MB, one decimal MB above", () => {
  assert.equal(fmtSize(0), "0 B");
  assert.equal(fmtSize(512), "512 B");
  assert.equal(fmtSize(1023), "1023 B");
  assert.equal(fmtSize(1024), "1 KB");
  assert.equal(fmtSize(2048), "2 KB");
  assert.equal(fmtSize(1048576), "1.0 MB");
  assert.equal(fmtSize(5242880), "5.0 MB");
});

test("fmtSize treats missing or bogus input as 0 bytes instead of NaN", () => {
  assert.equal(fmtSize(undefined), "0 B");
  assert.equal(fmtSize("not a number"), "0 B");
});

test("fmtRemaining picks the coarsest unit that still fits: s, m, h, d", () => {
  assert.equal(fmtRemaining(5000), "5s");
  assert.equal(fmtRemaining(59000), "59s");
  assert.equal(fmtRemaining(60000), "1m");
  assert.equal(fmtRemaining(90 * 60 * 1000), "2h");
  assert.equal(fmtRemaining(3 * 86400 * 1000), "3d");
});

test("fmtRemaining clamps a past deadline to 0 instead of a negative number", () => {
  assert.equal(fmtRemaining(-5000), "0s");
});
