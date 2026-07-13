// Durable storage for NobleChat's gateway: the public key directory and the
// per-mailbox queue of delivered ciphertext waiting for an offline recipient.
//
// Uses the built-in node:sqlite (no native deps). The gateway stays
// zero-knowledge: it only ever stores public contact cards and opaque,
// already-onion-decrypted envelopes addressed to a mailbox id — never plaintext,
// never keys.
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";

const require = createRequire(import.meta.url);
const { DatabaseSync } = require("node:sqlite");

export function openStore(dbPath, { mailboxTtlMs = 7 * 24 * 3600 * 1000, maxPerMailbox = 1000 } = {}) {
  if (dbPath !== ":memory:") fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS cards (
      handle TEXT PRIMARY KEY,
      json TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mailbox (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mbkey TEXT NOT NULL,
      envelope TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_mailbox_key ON mailbox(mbkey, id);
  `);

  const q = {
    putCard: db.prepare(
      "INSERT INTO cards(handle,json,updated_at) VALUES(?,?,?) " +
      "ON CONFLICT(handle) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at"),
    getCard: db.prepare("SELECT json FROM cards WHERE handle=?"),
    push: db.prepare("INSERT INTO mailbox(mbkey,envelope,created_at) VALUES(?,?,?)"),
    count: db.prepare("SELECT COUNT(*) AS c FROM mailbox WHERE mbkey=?"),
    list: db.prepare("SELECT id,envelope FROM mailbox WHERE mbkey=? ORDER BY id ASC LIMIT ?"),
    del: db.prepare("DELETE FROM mailbox WHERE id=?"),
    trim: db.prepare("DELETE FROM mailbox WHERE id IN (SELECT id FROM mailbox WHERE mbkey=? ORDER BY id ASC LIMIT ?)"),
    prune: db.prepare("DELETE FROM mailbox WHERE created_at < ?"),
    totals: db.prepare("SELECT (SELECT COUNT(*) FROM cards) AS cards, (SELECT COUNT(*) FROM mailbox) AS queued"),
  };

  return {
    db,
    putCard(handle, obj) { q.putCard.run(handle, JSON.stringify(obj), Date.now()); },
    getCard(handle) { const r = q.getCard.get(handle); return r ? JSON.parse(r.json) : null; },

    // Queue one envelope (base64 string) for a mailbox, enforcing the per-mailbox cap
    // by dropping the oldest entries first (bounded memory / disk under abuse).
    pushEnvelope(mbkey, envB64) {
      const c = q.count.get(mbkey).c;
      if (c >= maxPerMailbox) q.trim.run(mbkey, c - maxPerMailbox + 1);
      q.push.run(mbkey, envB64, Date.now());
    },

    // Return and remove all queued envelopes for a mailbox (delivered on reconnect).
    drainEnvelopes(mbkey, limit = 5000) {
      const rows = q.list.all(mbkey, limit);
      const out = [];
      for (const r of rows) { out.push(r.envelope); q.del.run(r.id); }
      return out;
    },

    prune() { q.prune.run(Date.now() - mailboxTtlMs); },
    stats() { return q.totals.get(); },
    close() { try { db.close(); } catch { /* already closed */ } },
  };
}
