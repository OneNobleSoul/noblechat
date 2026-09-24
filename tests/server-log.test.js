import test from "node:test";
import assert from "node:assert/strict";
import { createLog, LOG_LEVELS } from "../apps/server/log.js";

test("add returns a monotonically increasing seq", () => {
  const log = createLog();
  const a = log.add("info", "one");
  const b = log.add("info", "two");
  const c = log.add("info", "three");
  assert.equal(a, 1);
  assert.equal(b, 2);
  assert.equal(c, 3);
});

test("an unknown level falls back to info instead of being dropped or stored raw", () => {
  const log = createLog();
  log.add("critical", "weird level");
  const [entry] = log.list(0);
  assert.equal(entry.level, "info");
  for (const lvl of LOG_LEVELS) {
    const l2 = createLog();
    l2.add(lvl, "check");
    assert.equal(l2.list(0)[0].level, lvl);
  }
});

test("event and detail are capped so a caller can never smuggle unbounded text in", () => {
  const log = createLog();
  log.add("info", "e".repeat(200), "d".repeat(500));
  const [entry] = log.list(0);
  assert.equal(entry.event.length, 60);
  assert.equal(entry.detail.length, 200);
});

test("detail defaults to an empty string when omitted", () => {
  const log = createLog();
  log.add("info", "no detail given");
  assert.equal(log.list(0)[0].detail, "");
});

test("non-string event/detail are coerced via String() rather than throwing", () => {
  const log = createLog();
  log.add("warn", 404, { code: "x" });
  const [entry] = log.list(0);
  assert.equal(entry.event, "404");
  assert.equal(entry.detail, "[object Object]");
});

test("ring buffer trims the oldest entry once the limit is exceeded", () => {
  const log = createLog(3);
  log.add("info", "first");
  log.add("info", "second");
  log.add("info", "third");
  log.add("info", "fourth");
  assert.equal(log.size(), 3);
  const events = log.list(0).map((e) => e.event);
  assert.deepEqual(events, ["second", "third", "fourth"]);
});

test("seq keeps climbing across rotation instead of resetting", () => {
  const log = createLog(2);
  log.add("info", "a");
  log.add("info", "b");
  const thirdSeq = log.add("info", "c");
  assert.equal(thirdSeq, 3);
  assert.equal(log.list(0)[0].seq, 2, "the oldest surviving entry keeps its original seq");
});

test("list(since) returns only strictly newer entries, oldest first", () => {
  const log = createLog();
  log.add("info", "a");
  log.add("info", "b");
  log.add("info", "c");
  const fromZero = log.list(0).map((e) => e.event);
  assert.deepEqual(fromZero, ["a", "b", "c"]);
  const fromOne = log.list(1).map((e) => e.event);
  assert.deepEqual(fromOne, ["b", "c"]);
  assert.deepEqual(log.list(999), []);
});

test("list() defaults since to 0, returning everything", () => {
  const log = createLog();
  log.add("info", "only entry");
  assert.equal(log.list().length, 1);
});

test("size() tracks the current entry count, capped at the limit", () => {
  const log = createLog(2);
  assert.equal(log.size(), 0);
  log.add("info", "a");
  assert.equal(log.size(), 1);
  log.add("info", "b");
  log.add("info", "c");
  assert.equal(log.size(), 2);
});

test("each createLog() call owns an independent buffer and sequence counter", () => {
  const logA = createLog();
  const logB = createLog();
  logA.add("info", "only in A");
  logA.add("info", "still only in A");
  assert.equal(logA.size(), 2);
  assert.equal(logB.size(), 0);
  assert.equal(logB.add("info", "first in B"), 1, "B's seq counter starts fresh, unaffected by A");
});
