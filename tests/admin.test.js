import test from "node:test";
import assert from "node:assert/strict";
import { createLog } from "../apps/server/log.js";
import { isTransport, probeTcp } from "../apps/server/transport.js";
import net from "node:net";

test("event log keeps entries in order and supports incremental reads", () => {
  const log = createLog();
  log.add("info", "server started");
  const mark = log.add("info", "user registered", "alice");
  log.add("warn", "maintenance enabled");

  const all = log.list();
  assert.equal(all.length, 3);
  assert.equal(all[0].event, "server started");
  assert.equal(all[2].level, "warn");

  const fresh = log.list(mark);
  assert.equal(fresh.length, 1);
  assert.equal(fresh[0].event, "maintenance enabled");
});

test("event log is a bounded ring buffer", () => {
  const log = createLog(5);
  for (let i = 0; i < 12; i++) log.add("info", "e" + i);
  assert.equal(log.size(), 5);
  const list = log.list();
  assert.equal(list[0].event, "e7");
  assert.equal(list[4].event, "e11");
});

test("event log clamps oversized fields and unknown levels", () => {
  const log = createLog();
  log.add("debugish", "x".repeat(500), "y".repeat(500));
  const [e] = log.list();
  assert.equal(e.level, "info");
  assert.equal(e.event.length, 60);
  assert.equal(e.detail.length, 200);
});

test("transport names validate strictly", () => {
  assert.ok(isTransport("internal"));
  assert.ok(isTransport("nym"));
  assert.ok(!isTransport("tor"));
  assert.ok(!isTransport(""));
  assert.ok(!isTransport(undefined));
});

test("probe reports a listening tcp port as reachable", async () => {
  const srv = net.createServer(() => {});
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  assert.equal(await probeTcp(`ws://127.0.0.1:${port}`), true);
  srv.close();
});

test("probe reports closed ports and garbage urls as unreachable", async () => {
  assert.equal(await probeTcp("ws://127.0.0.1:1"), false);
  assert.equal(await probeTcp("not a url"), false);
});
