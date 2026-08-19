// backend/lib/db.js
// Data layer using better-sqlite3 (works on any Node.js version, unlike node:sqlite which
// requires Node 22+ and is not available on most hosting platforms like Render).
// Every entity (Product, Order, Wallet, ...) is stored as a JSON document in one
// generic `records` table, keyed by entity name — this mirrors how Base44 itself
// treats entities (schema-flexible documents), and means adding a new entity to
// base44/entities/*.jsonc doesn't require a migration.
import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'tiko.sqlite'));

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    entity TEXT NOT NULL,
    data TEXT NOT NULL,
    created_date TEXT NOT NULL,
    updated_date TEXT NOT NULL,
    created_by TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_records_entity ON records(entity);

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    phone TEXT,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_date TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sent_emails (
    id TEXT PRIMARY KEY,
    to_email TEXT,
    subject TEXT,
    body TEXT,
    created_date TEXT NOT NULL
  );
`);

function now() {
  return new Date().toISOString();
}

/* ---------------- generic entity records ---------------- */

export function createRecord(entity, data, createdBy) {
  const id = data.id || randomUUID();
  const ts = now();
  const row = { ...data, id };
  db.prepare(
    `INSERT INTO records (id, entity, data, created_date, updated_date, created_by) VALUES (?, ?, ?, ?, ?, ?)`
  ).run(id, entity, JSON.stringify(row), ts, ts, createdBy || null);
  return { ...row, created_date: ts, updated_date: ts, created_by: createdBy || null };
}

export function getRecord(entity, id) {
  const r = db.prepare(`SELECT * FROM records WHERE entity = ? AND id = ?`).get(entity, id);
  if (!r) return null;
  return rowToRecord(r);
}

export function listRecords(entity) {
  const rows = db.prepare(`SELECT * FROM records WHERE entity = ?`).all(entity);
  return rows.map(rowToRecord);
}

export function updateRecord(entity, id, patch) {
  const existing = getRecord(entity, id);
  if (!existing) return null;
  const merged = { ...existing, ...patch, id };
  const ts = now();
  db.prepare(`UPDATE records SET data = ?, updated_date = ? WHERE entity = ? AND id = ?`).run(
    JSON.stringify(merged),
    ts,
    entity,
    id
  );
  return { ...merged, updated_date: ts };
}

export function deleteRecord(entity, id) {
  const info = db.prepare(`DELETE FROM records WHERE entity = ? AND id = ?`).run(entity, id);
  return info.changes > 0;
}

function rowToRecord(row) {
  const data = JSON.parse(row.data);
  return {
    ...data,
    id: row.id,
    created_date: row.created_date,
    updated_date: row.updated_date,
    created_by: row.created_by,
  };
}

/* ---------------- users ---------------- */

export function createUser({ email, fullName, role, phone, passwordHash, passwordSalt }) {
  const id = randomUUID();
  const ts = now();
  db.prepare(
    `INSERT INTO users (id, email, full_name, role, phone, password_hash, password_salt, created_date)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(id, email.toLowerCase(), fullName || null, role || 'user', phone || null, passwordHash, passwordSalt, ts);
  return getUserById(id);
}

export function getUserByEmail(email) {
  return db.prepare(`SELECT * FROM users WHERE email = ?`).get(email.toLowerCase()) || null;
}

export function getUserById(id) {
  return db.prepare(`SELECT * FROM users WHERE id = ?`).get(id) || null;
}

export function listUsers() {
  return db.prepare(`SELECT id, email, full_name, role, phone, created_date FROM users`).all();
}

export function updateUser(id, patch) {
  const existing = getUserById(id);
  if (!existing) return null;
  const merged = { ...existing, ...patch };
  db.prepare(`UPDATE users SET full_name = ?, role = ?, phone = ? WHERE id = ?`).run(
    merged.full_name,
    merged.role,
    merged.phone,
    id
  );
  return getUserById(id);
}

export function sanitizeUser(u) {
  if (!u) return null;
  const { password_hash, password_salt, ...safe } = u;
  return safe;
}

/* ---------------- emails (stubbed outbound mail) ---------------- */

export function logSentEmail({ to, subject, body }) {
  const id = randomUUID();
  db.prepare(`INSERT INTO sent_emails (id, to_email, subject, body, created_date) VALUES (?, ?, ?, ?, ?)`).run(
    id,
    to || null,
    subject || null,
    body || null,
    now()
  );
  return id;
}

export default db;