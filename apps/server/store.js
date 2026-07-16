// Durable storage for the NobleChat gateway, backed by PostgreSQL.
//
// The gateway stays zero-knowledge: this stores only public contact cards,
// opaque already-onion-decrypted envelopes addressed to a mailbox id, admin
// settings, and a ban list. Never plaintext, never private keys.
import pg from "pg";

const { Pool } = pg;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS cards (
  handle      TEXT PRIMARY KEY,
  json        TEXT NOT NULL,
  mbkey       TEXT,
  updated_at  BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS mailbox (
  id          BIGSERIAL PRIMARY KEY,
  mbkey       TEXT NOT NULL,
  envelope    TEXT NOT NULL,
  created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mailbox_key ON mailbox (mbkey, id);
CREATE TABLE IF NOT EXISTS bans (
  handle      TEXT PRIMARY KEY,
  reason      TEXT,
  mbkey       TEXT,
  created_at  BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL
);
`;

async function withRetry(fn, { tries = 30, delayMs = 1000 } = {}) {
  let last;
  for (let i = 0; i < tries; i++) {
    try { return await fn(); } catch (e) { last = e; await new Promise((r) => setTimeout(r, delayMs)); }
  }
  throw last;
}

export async function openStore(databaseUrl, { mailboxTtlMs = 7 * 24 * 3600 * 1000, maxPerMailbox = 1000 } = {}) {
  const pool = new Pool({ connectionString: databaseUrl, max: 10, idleTimeoutMillis: 30000 });
  await withRetry(() => pool.query("SELECT 1"));
  await pool.query(SCHEMA);
  const now = () => Date.now();

  return {
    pool,

    async putCard(handle, obj) {
      const mbkey = obj && obj.providerId && obj.mailbox ? `${obj.providerId}:${obj.mailbox}` : null;
      await pool.query(
        `INSERT INTO cards(handle,json,mbkey,updated_at) VALUES($1,$2,$3,$4)
         ON CONFLICT(handle) DO UPDATE SET json=EXCLUDED.json, mbkey=EXCLUDED.mbkey, updated_at=EXCLUDED.updated_at`,
        [handle, JSON.stringify(obj), mbkey, now()]);
    },
    async getCard(handle) {
      const r = await pool.query("SELECT json FROM cards WHERE handle=$1", [handle]);
      return r.rows[0] ? JSON.parse(r.rows[0].json) : null;
    },

    async pushEnvelope(mbkey, envB64) {
      await pool.query("INSERT INTO mailbox(mbkey,envelope,created_at) VALUES($1,$2,$3)", [mbkey, envB64, now()]);
      // keep only the newest `maxPerMailbox` for this recipient
      await pool.query(
        `DELETE FROM mailbox WHERE mbkey=$1 AND id NOT IN
           (SELECT id FROM mailbox WHERE mbkey=$1 ORDER BY id DESC LIMIT $2)`,
        [mbkey, maxPerMailbox]);
    },
    async drainEnvelopes(mbkey, limit = 5000) {
      const r = await pool.query(
        `WITH d AS (
           DELETE FROM mailbox WHERE id IN
             (SELECT id FROM mailbox WHERE mbkey=$1 ORDER BY id ASC LIMIT $2)
           RETURNING id, envelope
         ) SELECT envelope FROM d ORDER BY id ASC`,
        [mbkey, limit]);
      return r.rows.map((x) => x.envelope);
    },
    async purgeMailbox(mbkey) {
      if (!mbkey) return;
      await pool.query("DELETE FROM mailbox WHERE mbkey=$1", [mbkey]);
    },
    async prune() {
      await pool.query("DELETE FROM mailbox WHERE created_at < $1", [now() - mailboxTtlMs]);
    },

    // ----- admin / moderation -----
    async isBanned(handle) {
      const r = await pool.query("SELECT 1 FROM bans WHERE handle=$1", [handle]);
      return r.rowCount > 0;
    },
    async bannedMbkeys() {
      const r = await pool.query("SELECT mbkey FROM bans WHERE mbkey IS NOT NULL");
      return r.rows.map((x) => x.mbkey);
    },
    async banHandle(handle, reason) {
      const c = await pool.query("SELECT mbkey FROM cards WHERE handle=$1", [handle]);
      const mbkey = c.rows[0] ? c.rows[0].mbkey : null;
      await pool.query(
        `INSERT INTO bans(handle,reason,mbkey,created_at) VALUES($1,$2,$3,$4)
         ON CONFLICT(handle) DO UPDATE SET reason=EXCLUDED.reason, mbkey=EXCLUDED.mbkey`,
        [handle, reason || null, mbkey, now()]);
      await pool.query("DELETE FROM cards WHERE handle=$1", [handle]);
      if (mbkey) await pool.query("DELETE FROM mailbox WHERE mbkey=$1", [mbkey]);
      return mbkey;
    },
    async unbanHandle(handle) {
      await pool.query("DELETE FROM bans WHERE handle=$1", [handle]);
    },
    async deleteHandle(handle) {
      const c = await pool.query("SELECT mbkey FROM cards WHERE handle=$1", [handle]);
      const mbkey = c.rows[0] ? c.rows[0].mbkey : null;
      await pool.query("DELETE FROM cards WHERE handle=$1", [handle]);
      if (mbkey) await pool.query("DELETE FROM mailbox WHERE mbkey=$1", [mbkey]);
      return mbkey;
    },
    async listUsers(limit = 500) {
      const r = await pool.query(
        `SELECT c.handle, c.updated_at,
                (SELECT COUNT(*) FROM mailbox m WHERE m.mbkey=c.mbkey) AS queued
         FROM cards c ORDER BY c.updated_at DESC LIMIT $1`, [limit]);
      const b = await pool.query("SELECT handle, reason, created_at FROM bans ORDER BY created_at DESC LIMIT $1", [limit]);
      return { users: r.rows, bans: b.rows };
    },

    // ----- settings -----
    async getSetting(key, dflt = null) {
      const r = await pool.query("SELECT value FROM settings WHERE key=$1", [key]);
      return r.rows[0] ? r.rows[0].value : dflt;
    },
    async setSetting(key, value) {
      await pool.query(
        `INSERT INTO settings(key,value) VALUES($1,$2)
         ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, [key, String(value)]);
    },

    async stats() {
      const r = await pool.query(
        `SELECT (SELECT COUNT(*) FROM cards) AS cards,
                (SELECT COUNT(*) FROM mailbox) AS queued,
                (SELECT COUNT(*) FROM bans) AS banned`);
      return r.rows[0];
    },
    async close() { await pool.end(); },
  };
}
