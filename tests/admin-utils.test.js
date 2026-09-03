import test from "node:test";
import assert from "node:assert/strict";
import { esc, fmtTime, fmtUptime } from "../apps/web/src/admin-utils.js";

test("esc escapes every HTML-significant character, same set as the chat client's esc()", () => {
  assert.equal(esc("<script>alert('hi')</script>"), "&lt;script&gt;alert(&#39;hi&#39;)&lt;/script&gt;");
  assert.equal(esc('"quoted" & <tag>'), "&quot;quoted&quot; &amp; &lt;tag&gt;");
  assert.equal(esc("plain text"), "plain text");
});

test("esc coerces non-strings instead of throwing", () => {
  assert.equal(esc(42), "42");
  assert.equal(esc(null), "null");
  assert.equal(esc(undefined), "undefined");
});

test("fmtTime renders a valid timestamp", () => {
  assert.equal(fmtTime(0), new Date(0).toLocaleString());
});

test("fmtTime falls back to a dash only when Number()/Date() actually throw, not merely on NaN", () => {
  // A non-numeric string or undefined coerces to NaN, and `new Date(NaN)` is a
  // valid (if useless) Date object whose toLocaleString() returns the string
  // "Invalid Date" rather than throwing - the try/catch here exists for
  // inputs that throw during coercion instead, such as a Symbol.
  assert.equal(fmtTime("not a timestamp"), "Invalid Date");
  assert.equal(fmtTime(undefined), "Invalid Date");
  assert.equal(fmtTime(Symbol("x")), "-");
});

test("fmtUptime stays in minutes under an hour", () => {
  assert.equal(fmtUptime(0), "0m");
  assert.equal(fmtUptime(59), "0m");
  assert.equal(fmtUptime(120), "2m");
  assert.equal(fmtUptime(3599), "59m");
});

test("fmtUptime switches to hours+minutes between one hour and one day", () => {
  assert.equal(fmtUptime(3600), "1h 0m");
  assert.equal(fmtUptime(3660), "1h 1m");
  assert.equal(fmtUptime(86399), "23h 59m");
});

test("fmtUptime switches to days+hours at and above one day", () => {
  assert.equal(fmtUptime(86400), "1d 0h");
  assert.equal(fmtUptime(90000), "1d 1h");
  assert.equal(fmtUptime(864000), "10d 0h");
});

test("fmtUptime treats missing or bogus input as 0 seconds instead of NaN", () => {
  assert.equal(fmtUptime(undefined), "0m");
  assert.equal(fmtUptime("not a number"), "0m");
});
