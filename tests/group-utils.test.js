import test from "node:test";
import assert from "node:assert/strict";
import { addedMembers } from "../apps/web/src/group-utils.js";

test("addedMembers reports handles present only in the new list", () => {
  assert.deepEqual(addedMembers(["alice", "bob"], ["alice", "bob", "mallory"]), ["mallory"]);
});

test("addedMembers returns empty when membership is unchanged", () => {
  assert.deepEqual(addedMembers(["alice", "bob"], ["alice", "bob"]), []);
});

test("addedMembers ignores members that were removed, not added", () => {
  assert.deepEqual(addedMembers(["alice", "bob", "mallory"], ["alice", "bob"]), []);
});

test("addedMembers reports every handle when there was no prior list", () => {
  assert.deepEqual(addedMembers([], ["alice", "bob"]), ["alice", "bob"]);
});

test("addedMembers tolerates a missing or malformed member list", () => {
  assert.deepEqual(addedMembers(undefined, ["alice"]), ["alice"]);
  assert.deepEqual(addedMembers(null, ["alice"]), ["alice"]);
  assert.deepEqual(addedMembers(["alice"], undefined), []);
  assert.deepEqual(addedMembers(["alice"], null), []);
  assert.deepEqual(addedMembers("not an array", "also not an array"), []);
});

test("addedMembers skips falsy entries in the new list", () => {
  assert.deepEqual(addedMembers(["alice"], ["alice", "", null, undefined, "bob"]), ["bob"]);
});

test("addedMembers does not mutate either input array", () => {
  const oldMembers = ["alice"];
  const newMembers = ["alice", "bob"];
  const oldCopy = [...oldMembers];
  const newCopy = [...newMembers];
  addedMembers(oldMembers, newMembers);
  assert.deepEqual(oldMembers, oldCopy);
  assert.deepEqual(newMembers, newCopy);
});
