import test from "node:test";
import assert from "node:assert/strict";
import { reactionsAfterToggle, canUnsend } from "../apps/web/src/message-utils.js";

test("reactionsAfterToggle adds a first reactor for an emoji", () => {
  const out = reactionsAfterToggle(undefined, "👍", "alice", false);
  assert.deepEqual(out, { "👍": ["alice"] });
});

test("reactionsAfterToggle appends a second reactor without duplicating an existing one", () => {
  const out = reactionsAfterToggle({ "👍": ["alice"] }, "👍", "bob", false);
  assert.deepEqual(out, { "👍": ["alice", "bob"] });
  const same = reactionsAfterToggle(out, "👍", "alice", false);
  assert.deepEqual(same, { "👍": ["alice", "bob"] });
});

test("reactionsAfterToggle removes a reactor and drops the emoji key once empty", () => {
  const out = reactionsAfterToggle({ "👍": ["alice"] }, "👍", "alice", true);
  assert.deepEqual(out, {});
});

test("reactionsAfterToggle removing one reactor keeps the rest under the same emoji", () => {
  const out = reactionsAfterToggle({ "👍": ["alice", "bob"] }, "👍", "alice", true);
  assert.deepEqual(out, { "👍": ["bob"] });
});

test("reactionsAfterToggle leaves other emoji untouched", () => {
  const out = reactionsAfterToggle({ "❤️": ["carol"] }, "👍", "alice", false);
  assert.deepEqual(out, { "❤️": ["carol"], "👍": ["alice"] });
});

test("reactionsAfterToggle never mutates the input map", () => {
  const input = { "👍": ["alice"] };
  const out = reactionsAfterToggle(input, "👍", "bob", false);
  assert.deepEqual(input, { "👍": ["alice"] });
  assert.notEqual(out, input);
});

test("canUnsend allows the recorded sender to retract their own message", () => {
  assert.equal(canUnsend({ sender: "alice" }, "alice", "alice"), true);
});

test("canUnsend blocks anyone else from retracting a message with a recorded sender", () => {
  assert.equal(canUnsend({ sender: "alice" }, "mallory", "bob"), false);
});

test("canUnsend falls back to dir=out plus selfHandle for older cached messages without sender", () => {
  assert.equal(canUnsend({ dir: "out" }, "alice", "alice"), true);
  assert.equal(canUnsend({ dir: "out" }, "mallory", "alice"), false);
});

test("canUnsend allows the retraction when neither sender nor an out direction can identify an origin", () => {
  assert.equal(canUnsend({}, "anyone", "alice"), true);
});
