import test from "node:test";
import assert from "node:assert/strict";
import { ownDevicesOnly } from "../apps/web/src/card-utils.js";

test("ownDevicesOnly keeps only cards whose handle matches", () => {
  const devices = [{ handle: "alice", n: 1 }, { handle: "mallory", n: 2 }, { handle: "alice", n: 3 }];
  const { mine, droppedCount } = ownDevicesOnly(devices, "alice");
  assert.deepEqual(mine, [{ handle: "alice", n: 1 }, { handle: "alice", n: 3 }]);
  assert.equal(droppedCount, 1);
});

test("ownDevicesOnly matches case-insensitively (handles are stored lowercase)", () => {
  const devices = [{ handle: "Alice" }, { handle: "ALICE" }, { handle: "bob" }];
  const { mine, droppedCount } = ownDevicesOnly(devices, "alice");
  assert.equal(mine.length, 2);
  assert.equal(droppedCount, 1);
});

test("ownDevicesOnly reports zero dropped when every card belongs to the handle", () => {
  const devices = [{ handle: "alice" }, { handle: "alice" }];
  const { mine, droppedCount } = ownDevicesOnly(devices, "alice");
  assert.equal(mine.length, 2);
  assert.equal(droppedCount, 0);
});

test("ownDevicesOnly drops every card when none match", () => {
  const devices = [{ handle: "mallory" }, { handle: "eve" }];
  const { mine, droppedCount } = ownDevicesOnly(devices, "alice");
  assert.deepEqual(mine, []);
  assert.equal(droppedCount, 2);
});

test("ownDevicesOnly tolerates a missing or malformed devices list", () => {
  assert.deepEqual(ownDevicesOnly(undefined, "alice"), { mine: [], droppedCount: 0 });
  assert.deepEqual(ownDevicesOnly(null, "alice"), { mine: [], droppedCount: 0 });
  assert.deepEqual(ownDevicesOnly("not an array", "alice"), { mine: [], droppedCount: 0 });
});

test("ownDevicesOnly skips falsy entries in the list instead of throwing", () => {
  const devices = [null, undefined, { handle: "alice" }];
  const { mine, droppedCount } = ownDevicesOnly(devices, "alice");
  assert.equal(mine.length, 1);
  assert.equal(droppedCount, 2);
});

test("ownDevicesOnly treats an entry with no handle field as not matching", () => {
  const devices = [{}, { handle: "alice" }];
  const { mine, droppedCount } = ownDevicesOnly(devices, "alice");
  assert.equal(mine.length, 1);
  assert.equal(droppedCount, 1);
});

test("ownDevicesOnly does not mutate the input array", () => {
  const devices = [{ handle: "alice" }, { handle: "bob" }];
  const copy = [...devices];
  ownDevicesOnly(devices, "alice");
  assert.deepEqual(devices, copy);
});
