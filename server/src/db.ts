/**
 * Server storage (SQLite via node:sqlite, no native dependencies).
 *
 * Everything stored here is either public (identity and prekey public keys)
 * or ciphertext (sealed envelopes, attachment blobs). Timestamps are coarsened
 * to the hour/day: we keep only what expiry needs.
 */
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

export type DB = DatabaseSync;

export function openDb(dataDir: string): DB {
  mkdirSync(join(dataDir, 'blobs'), { recursive: true });
  const db = new DatabaseSync(join(dataDir, 'obscura.db'));
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA secure_delete = ON;
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      sig_pub BLOB NOT NULL,
      dh_pub BLOB NOT NULL,
      dh_sig BLOB NOT NULL,
      access_hash BLOB NOT NULL,
      created_day TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS signed_prekeys (
      account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
      key_id INTEGER NOT NULL, pub BLOB NOT NULL, sig BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pq_last_resort (
      account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
      key_id INTEGER NOT NULL, pub BLOB NOT NULL, sig BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS one_time_prekeys (
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      key_id INTEGER NOT NULL, pub BLOB NOT NULL,
      PRIMARY KEY (account_id, key_id)
    );
    CREATE TABLE IF NOT EXISTS pq_one_time_prekeys (
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      key_id INTEGER NOT NULL, pub BLOB NOT NULL, sig BLOB NOT NULL,
      PRIMARY KEY (account_id, key_id)
    );
    CREATE TABLE IF NOT EXISTS envelopes (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      data BLOB NOT NULL,
      received_hour INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS envelopes_by_account ON envelopes(account_id);
    CREATE TABLE IF NOT EXISTS blobs (
      id TEXT PRIMARY KEY,
      delete_hash BLOB NOT NULL,
      size INTEGER NOT NULL,
      created_hour INTEGER NOT NULL
    );
  `);
  return db;
}

export const hourNow = () => Math.floor(Date.now() / 3600_000);
export const dayNow = () => new Date().toISOString().slice(0, 10);
