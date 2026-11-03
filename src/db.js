const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL não configurada.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS access_keys (
      id BIGSERIAL PRIMARY KEY,
      key_hash CHAR(64) UNIQUE NOT NULL,
      label TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS access_keys_active_idx
      ON access_keys (key_hash)
      WHERE revoked_at IS NULL;
  `);
}

module.exports = { pool, initDb };