import test from "node:test";
import assert from "node:assert/strict";
import { WebSocketServer } from "ws";
import { parseNymPayload, connectNym } from "../apps/server/nym.js";

test("nym payload parser accepts the wire format and rejects junk", () => {
  const ok = parseNymPayload(JSON.stringify({ v: 1, p: "YWJj", i: "ZGVm" }));
  assert.deepEqual(ok, { providerId: "YWJj", inner: "ZGVm" });

  assert.equal(parseNymPayload("not json"), null);
  assert.equal(parseNymPayload(JSON.stringify({ v: 2, p: "YWJj", i: "ZGVm" })), null);
  assert.equal(parseNymPayload(JSON.stringify({ v: 1, p: "$bad$", i: "ZGVm" })), null);
  assert.equal(parseNymPayload(JSON.stringify({ v: 1, p: "YWJj" })), null);
  assert.equal(parseNymPayload("x".repeat(300 * 1024)), null);
});

test("connectNym learns its address and forwards received payloads", async () => {
  // A stand-in for the nym-client sidecar: answers selfAddress and pushes one
  // received message once the client is known to listen.
  const wss = new WebSocketServer({ port: 0 });
  const port = wss.address().port;
  wss.on("connection", (sock) => {
    sock.on("message", (raw) => {
      const m = JSON.parse(raw.toString());
      if (m.type === "selfAddress") {
        sock.send(JSON.stringify({ type: "selfAddress", address: "testaddr.abc@gateway" }));
        sock.send(JSON.stringify({ type: "received", message: JSON.stringify({ v: 1, p: "cHJvdg==", i: "aW5uZXI=" }) }));
        sock.send(JSON.stringify({ type: "received", message: "garbage that must be ignored" }));
      }
    });
  });

  const got = [];
  const logs = [];
  const nym = connectNym(`ws://127.0.0.1:${port}`, {
    onPayload: (p, i) => got.push([p, i]),
    onLog: (lvl, ev) => logs.push(lvl + ":" + ev),
  });

  await new Promise((r) => setTimeout(r, 300));
  assert.equal(nym.isConnected(), true);
  assert.equal(nym.getAddress(), "testaddr.abc@gateway");
  assert.deepEqual(got, [["cHJvdg==", "aW5uZXI="]]);
  assert.ok(logs.some((l) => l.startsWith("info:nym sidecar connected")));

  nym.close();
  wss.close();
});

test("connectNym reports unreachable sidecars as disconnected", async () => {
  const nym = connectNym("ws://127.0.0.1:1", { onLog: () => {} });
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(nym.isConnected(), false);
  assert.equal(nym.getAddress(), null);
  nym.close();
});
