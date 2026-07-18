// Durable storage for the NobleChat gateway, backed by PostgreSQL.
//
// Zero-knowledge: stores only public device cards, opaque onion-delivered
// ciphertext, password *hashes* (never passwords or private keys), sessions,
// an encrypted per-account contacts blob (opaque to us), admin settings, bans.
import pg from "pg";

const { Pool } = pg;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS accounts (
  username    TEXT PRIMARY KEY,
  pass        TEXT NOT NULL,
  created_at  BIGINT NOT NULL,
  banned      BOOLEAN NOT NULL DEFAULT FALSE,
  is_admin    BOOLEAN NOT NULL DEFAULT FALSE
);
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS devices (
  device_id   TEXT PRIMARY KEY,
  username    TEXT NOT NULL REFERENCES accounts(username) ON DELETE CASCADE,
  card        TEXT NOT NULL,
  mbkey       TEXT,
  created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices (username);
CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  username    TEXT NOT NULL,
  created_at  BIGINT NOT NULL,
  expires_at  BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS blobs (
  username    TEXT PRIMARY KEY,
  blob        TEXT NOT NULL,
  updated_at  BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS mailbox (
  id          BIGSERIAL PRIMARY KEY,
  mbkey       TEXT NOT NULL,
  envelope    TEXT NOT NULL,
  created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mailbox_key ON mailbox (mbkey, id);
CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL
);
`;

async function withRetry(fn, { tries = 30, delayMs = 1000 } = {}) {
  let last;
  for (let i = 0; i < tries; i++) { try { return await fn(); } catch (e) { last = e; await new Promise((r) => setTimeout(r, delayMs)); } }
  throw last;
}

export async function openStore(databaseUrl, { mailboxTtlMs = 7 * 24 * 3600 * 1000, maxPerMailbox = 1000 } = {}) {
  const pool = new Pool({ connectionString: databaseUrl, max: 10, idleTimeoutMillis: 30000 });
  await withRetry(() => pool.query("SELECT 1"));
  await pool.query(SCHEMA);
  const now = () => Date.now();

  return {
    pool,

    // ---- accounts ----
    async createAccount(username, passStr) {
      await pool.query("INSERT INTO accounts(username,pass,created_at) VALUES($1,$2,$3)", [username, passStr, now()]);
    },
    async getAccount(username) {
      const r = await pool.query("SELECT username,pass,banned,is_admin FROM accounts WHERE username=$1", [username]);
      return r.rows[0] || null;
    },
    async isAdmin(username) {
      const r = await pool.query("SELECT is_admin FROM accounts WHERE username=$1", [username]);
      return r.rows[0] ? !!r.rows[0].is_admin : false;
    },
    async setAdmin(username, on) {
      const r = await pool.query("UPDATE accounts SET is_admin=$2 WHERE username=$1", [username, !!on]);
      return r.rowCount > 0;
    },

    // ---- devices ----
    async addDevice(deviceId, username, card, mbkey) {
      await pool.query(
        `INSERT INTO devices(device_id,username,card,mbkey,created_at) VALUES($1,$2,$3,$4,$5)
         ON CONFLICT(device_id) DO UPDATE SET card=EXCLUDED.card, mbkey=EXCLUDED.mbkey`,
        [deviceId, username, JSON.stringify(card), mbkey, now()]);
    },
    async removeDevice(deviceId, username) {
      await pool.query("DELETE FROM devices WHERE device_id=$1 AND username=$2", [deviceId, username]);
    },
    async deviceBundle(username) { // public cards for a handle
      const r = await pool.query("SELECT card FROM devices WHERE username=$1 ORDER BY created_at ASC", [username]);
      return r.rows.map((x) => JSON.parse(x.card));
    },
    async deviceMbkeys(username) {
      const r = await pool.query("SELECT mbkey FROM devices WHERE username=$1 AND mbkey IS NOT NULL", [username]);
      return r.rows.map((x) => x.mbkey);
    },

    // ---- sessions ----
    async createSession(token, username, ttlMs) {
      await pool.query("INSERT INTO sessions(token,username,created_at,expires_at) VALUES($1,$2,$3,$4)", [token, username, now(), now() + ttlMs]);
    },
    async getSession(token) {
      const r = await pool.query("SELECT username,expires_at FROM sessions WHERE token=$1", [token]);
      const s = r.rows[0];
      if (!s) return null;
      if (Number(s.expires_at) < now()) { await pool.query("DELETE FROM sessions WHERE token=$1", [token]); return null; }
      return { username: s.username };
    },
    async deleteSession(token) { await pool.query("DELETE FROM sessions WHERE token=$1", [token]); },
    async deleteSessionsForUser(username) { await pool.query("DELETE FROM sessions WHERE username=$1", [username]); },

    // ---- encrypted contacts blob ----
    async getBlob(username) {
      const r = await pool.query("SELECT blob FROM blobs WHERE username=$1", [username]);
      return r.rows[0] ? r.rows[0].blob : null;
    },
    async setBlob(username, blob) {
      await pool.query(
        `INSERT INTO blobs(username,blob,updated_at) VALUES($1,$2,$3)
         ON CONFLICT(username) DO UPDATE SET blob=EXCLUDED.blob, updated_at=EXCLUDED.updated_at`,
        [username, blob, now()]);
    },

    // ---- mailbox (durable queue) ----
    async pushEnvelope(mbkey, envB64) {
      await pool.query("INSERT INTO mailbox(mbkey,envelope,created_at) VALUES($1,$2,$3)", [mbkey, envB64, now()]);
      await pool.query(`DELETE FROM mailbox WHERE mbkey=$1 AND id NOT IN (SELECT id FROM mailbox WHERE mbkey=$1 ORDER BY id DESC LIMIT $2)`, [mbkey, maxPerMailbox]);
    },
    async drainEnvelopes(mbkey, limit = 5000) {
      const r = await pool.query(
        `WITH d AS (DELETE FROM mailbox WHERE id IN (SELECT id FROM mailbox WHERE mbkey=$1 ORDER BY id ASC LIMIT $2) RETURNING id, envelope)
         SELECT envelope FROM d ORDER BY id ASC`, [mbkey, limit]);
      return r.rows.map((x) => x.envelope);
    },
    async prune() { await pool.query("DELETE FROM mailbox WHERE created_at < $1", [now() - mailboxTtlMs]); },

    // ---- admin / moderation (account-level) ----
    async isBanned(username) {
      const r = await pool.query("SELECT banned FROM accounts WHERE username=$1", [username]);
      return r.rows[0] ? r.rows[0].banned : false;
    },
    async allBannedMbkeys() {
      const r = await pool.query(
        `SELECT d.mbkey FROM devices d JOIN accounts a ON a.username=d.username WHERE a.banned=TRUE AND d.mbkey IS NOT NULL`);
      return r.rows.map((x) => x.mbkey);
    },
    async banAccount(username, reason) {
      const mbk = await this.deviceMbkeys(username);
      await pool.query("UPDATE accounts SET banned=TRUE WHERE username=$1", [username]);
      await pool.query("INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", [`banreason:${username}`, String(reason || "")]);
      await pool.query("DELETE FROM sessions WHERE username=$1", [username]);
      for (const k of mbk) await pool.query("DELETE FROM mailbox WHERE mbkey=$1", [k]);
      return mbk;
    },
    async unbanAccount(username) {
      await pool.query("UPDATE accounts SET banned=FALSE WHERE username=$1", [username]);
      await pool.query("DELETE FROM settings WHERE key=$1", [`banreason:${username}`]);
    },
    async deleteAccount(username) {
      const mbk = await this.deviceMbkeys(username);
      await pool.query("DELETE FROM sessions WHERE username=$1", [username]);
      await pool.query("DELETE FROM blobs WHERE username=$1", [username]);
      await pool.query("DELETE FROM accounts WHERE username=$1", [username]); // devices cascade
      for (const k of mbk) await pool.query("DELETE FROM mailbox WHERE mbkey=$1", [k]);
      return mbk;
    },
    async listAccounts(limit = 500) {
      const r = await pool.query(
        `SELECT a.username, a.created_at, a.banned, a.is_admin,
                (SELECT COUNT(*) FROM devices d WHERE d.username=a.username) AS devices,
                COALESCE((SELECT s.value FROM settings s WHERE s.key='banreason:'||a.username),'') AS reason
         FROM accounts a ORDER BY a.created_at DESC LIMIT $1`, [limit]);
      return r.rows;
    },

    // ---- settings ----
    async getSetting(key, dflt = null) { const r = await pool.query("SELECT value FROM settings WHERE key=$1", [key]); return r.rows[0] ? r.rows[0].value : dflt; },
    async setSetting(key, value) { await pool.query("INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", [key, String(value)]); },

    async stats() {
      const r = await pool.query(
        `SELECT (SELECT COUNT(*) FROM accounts) AS accounts,
                (SELECT COUNT(*) FROM devices) AS devices,
                (SELECT COUNT(*) FROM mailbox) AS queued,
                (SELECT COUNT(*) FROM accounts WHERE banned=TRUE) AS banned`);
      return r.rows[0];
    },
    async close() { await pool.end(); },
  };
}
