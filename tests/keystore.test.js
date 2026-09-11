import test from "node:test";
import assert from "node:assert/strict";
import { putKey, getKey, clearKeys } from "../apps/web/src/keystore.js";

// keystore.js talks to IndexedDB directly, so these fakes stand in for the
// browser API. A single fakeIndexedDB() instance keeps its data around for
// the lifetime of one test the same way a real per-tab connection would.

function fakeIndexedDB() {
  const data = new Map();
  let storeCreated = false;
  return {
    open() {
      const req = {};
      queueMicrotask(() => {
        const db = {
          objectStoreNames: { contains: () => storeCreated },
          createObjectStore() { storeCreated = true; return {}; },
          close() {},
          transaction() {
            return {
              objectStore() {
                return {
                  put(value, key) {
                    const r = {};
                    queueMicrotask(() => { data.set(key, value); r.result = key; r.onsuccess && r.onsuccess(); });
                    return r;
                  },
                  get(key) {
                    const r = {};
                    queueMicrotask(() => { r.result = data.get(key); r.onsuccess && r.onsuccess(); });
                    return r;
                  },
                  clear() {
                    const r = {};
                    queueMicrotask(() => { data.clear(); r.onsuccess && r.onsuccess(); });
                    return r;
                  },
                };
              },
            };
          },
        };
        req.result = db;
        if (!storeCreated) req.onupgradeneeded && req.onupgradeneeded();
        req.onsuccess && req.onsuccess();
      });
      return req;
    },
  };
}

function brokenIndexedDB() {
  return {
    open() {
      const req = {};
      queueMicrotask(() => { req.error = new Error("blocked by browser settings"); req.onerror && req.onerror(); });
      return req;
    },
  };
}

async function withIndexedDB(db, fn) {
  const had = "indexedDB" in globalThis;
  const prev = globalThis.indexedDB;
  globalThis.indexedDB = db;
  try { return await fn(); } finally {
    if (had) globalThis.indexedDB = prev; else delete globalThis.indexedDB;
  }
}

test("putKey then getKey round-trips the same value", async () => {
  await withIndexedDB(fakeIndexedDB(), async () => {
    const handle = { notExtractable: true };
    assert.equal(await putKey("blob", handle), true);
    assert.deepEqual(await getKey("blob"), handle);
  });
});

test("getKey returns null for a name that was never stored", async () => {
  await withIndexedDB(fakeIndexedDB(), async () => {
    assert.equal(await getKey("never-stored"), null);
  });
});

test("clearKeys empties the store", async () => {
  await withIndexedDB(fakeIndexedDB(), async () => {
    await putKey("blob", "secret");
    await clearKeys();
    assert.equal(await getKey("blob"), null);
  });
});

test("a database that refuses to open leaves callers with safe fallbacks instead of throwing", async () => {
  await withIndexedDB(brokenIndexedDB(), async () => {
    assert.equal(await putKey("blob", "x"), false);
    assert.equal(await getKey("blob"), null);
    await assert.doesNotReject(() => clearKeys());
  });
});

test("no indexedDB at all, as in private browsing, is handled the same way as a failing one", async () => {
  const had = "indexedDB" in globalThis;
  const prev = globalThis.indexedDB;
  delete globalThis.indexedDB;
  try {
    assert.equal(await putKey("blob", "x"), false);
    assert.equal(await getKey("blob"), null);
    await assert.doesNotReject(() => clearKeys());
  } finally {
    if (had) globalThis.indexedDB = prev;
  }
});
