// Where the contacts blob key lives on this device.
//
// It used to be exported to raw bytes and parked in localStorage, right next
// to the session token. Any script running on the page could read both, so a
// single XSS meant not just account takeover but the plaintext of everything
// the blob protects - contact list, groups, key pins.
//
// IndexedDB can store a CryptoKey object directly (structured clone), so the
// key is derived non-extractable and handed here as an opaque handle. Script
// on the page can still ask it to decrypt, but it cannot read the key material
// out and post it somewhere. That is a real reduction in blast radius, not a
// fix for XSS itself.
const DB_NAME = "noblechat";
const STORE = "keys";

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => { if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE); };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function withStore(mode, fn) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } finally { db.close(); }
}

// All three swallow failures: private browsing modes and storage-blocking
// settings can refuse IndexedDB entirely, and the app has to keep working
// (the key is simply re-derived at the next password sign-in).
export async function putKey(name, key) {
  try { await withStore("readwrite", (s) => s.put(key, name)); return true; } catch { return false; }
}
export async function getKey(name) {
  try { return (await withStore("readonly", (s) => s.get(name))) || null; } catch { return null; }
}
export async function clearKeys() {
  try { await withStore("readwrite", (s) => s.clear()); } catch { /* nothing to clear */ }
}
