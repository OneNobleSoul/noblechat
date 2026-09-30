import test from "node:test";
import assert from "node:assert/strict";
import { reconnectDelay } from "../apps/web/src/reconnect-utils.js";

test("reconnectDelay doubles per attempt, jitter aside", () => {
  const noJitter = () => 0.5; // rand() = 0.5 -> jitter factor 1.0
  assert.equal(reconnectDelay(0, { rand: noJitter }), 1500);
  assert.equal(reconnectDelay(1, { rand: noJitter }), 3000);
  assert.equal(reconnectDelay(2, { rand: noJitter }), 6000);
  assert.equal(reconnectDelay(3, { rand: noJitter }), 12000);
});

test("reconnectDelay caps at max instead of growing forever", () => {
  const noJitter = () => 0.5;
  assert.equal(reconnectDelay(10, { rand: noJitter }), 30000);
  assert.equal(reconnectDelay(1000, { rand: noJitter }), 30000);
});

test("reconnectDelay treats negative or fractional attempts as attempt 0", () => {
  const noJitter = () => 0.5;
  assert.equal(reconnectDelay(-5, { rand: noJitter }), 1500);
  assert.equal(reconnectDelay(0.9, { rand: noJitter }), 1500);
});

test("reconnectDelay applies roughly +/-20% jitter around the base value", () => {
  const low = reconnectDelay(0, { rand: () => 0 });
  const high = reconnectDelay(0, { rand: () => 1 });
  assert.equal(low, 1200); // 1500 * 0.8
  assert.equal(high, 1800); // 1500 * 1.2
});

test("reconnectDelay honors custom base and max", () => {
  const noJitter = () => 0.5;
  assert.equal(reconnectDelay(0, { base: 1000, rand: noJitter }), 1000);
  assert.equal(reconnectDelay(5, { base: 1000, max: 5000, rand: noJitter }), 5000);
});
