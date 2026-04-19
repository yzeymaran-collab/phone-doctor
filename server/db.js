'use strict';
const { DatabaseSync } = require('node:sqlite');
const bcrypt           = require('bcryptjs');
const path             = require('path');

const db = new DatabaseSync(path.join(__dirname, 'data.db'));

// Performance + Integrität
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

// ─── Schema ──────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS benutzer (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    rolle         TEXT    NOT NULL DEFAULT 'user',
    aktiv         INTEGER NOT NULL DEFAULT 1,
    last_login    TEXT,
    created_at    TEXT    DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS kunden (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    telefon    TEXT,
    email      TEXT,
    typ        TEXT    NOT NULL DEFAULT 'Käufer',
    notizen    TEXT,
    created_at TEXT    DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS geraete (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    typ              TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'Ankauf',
    marke            TEXT    NOT NULL,
    modell           TEXT    NOT NULL,
    imei             TEXT,
    speicher         TEXT,
    zustand          TEXT    DEFAULT 'Gut',
    ankaufspreis     REAL,
    reparaturkosten  REAL,
    verkaufspreis    REAL,
    ankaufsdatum     TEXT,
    verkaufsdatum    TEXT,
    verkaeufer_id    INTEGER REFERENCES kunden(id) ON DELETE SET NULL,
    kaeufer_id       INTEGER REFERENCES kunden(id) ON DELETE SET NULL,
    notizen          TEXT,
    fotos            TEXT    DEFAULT '[]',
    created_at       TEXT    DEFAULT (datetime('now','localtime')),
    updated_at       TEXT    DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS protokoll (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    DEFAULT (datetime('now','localtime')),
    user_id     INTEGER,
    user_name   TEXT,
    user_rolle  TEXT,
    action      TEXT    NOT NULL,
    entity      TEXT    DEFAULT '',
    entity_id   INTEGER,
    description TEXT,
    details     TEXT
  );

  CREATE TABLE IF NOT EXISTS einstellungen (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS foto_uploads (
    token      TEXT PRIMARY KEY,
    geraet_id  INTEGER,
    foto       TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS reparaturen (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    kunden_name         TEXT    NOT NULL,
    kunden_telefon      TEXT,
    kunden_email        TEXT,
    kunden_adresse      TEXT,
    hersteller          TEXT,
    modell              TEXT,
    farbe               TEXT,
    zustand             TEXT    DEFAULT 'Gut',
    imei                TEXT,
    pin_code            TEXT,
    entsperrmuster      TEXT,
    abholtermin         TEXT,
    schadenbeschreibung TEXT,
    schadenshergang     TEXT,
    reparatur_liste     TEXT    DEFAULT '[]',
    status              TEXT    DEFAULT 'Offen',
    kostenvoranschlag   REAL,
    notizen             TEXT,
    created_at          TEXT    DEFAULT (datetime('now','localtime')),
    updated_at          TEXT    DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS zeiterfassung (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    user_name      TEXT    NOT NULL,
    einstempel_ts  TEXT    NOT NULL,
    ausstempel_ts  TEXT,
    pause_minuten  INTEGER DEFAULT 0,
    notizen        TEXT,
    created_at     TEXT    DEFAULT (datetime('now','localtime'))
  );
`);

// ─── Migrations: fehlende Spalten ergänzen ───────────────────────────────────
const geraeteCols = db.prepare("PRAGMA table_info(geraete)").all().map(c => c.name);
if (!geraeteCols.includes('speicher')) {
  db.exec("ALTER TABLE geraete ADD COLUMN speicher TEXT");
  console.log('  Migration: geraete.speicher hinzugefügt');
}

// ─── Standard-Super-Admin anlegen ────────────────────────────────────────────
const existing = db.prepare('SELECT id FROM benutzer WHERE username = ?').get('superadmin');
if (!existing) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(`
    INSERT INTO benutzer (username, password_hash, name, rolle)
    VALUES (?, ?, ?, ?)
  `).run('superadmin', hash, 'Super Administrator', 'superadmin');
  console.log('  Standard-Account angelegt: superadmin / admin123');
}

// ─── Standard-Mitarbeiter anlegen ────────────────────────────────────────────
const mitarbeiter = [
  { username: 'mike.pingel',         name: 'Mike Pingel',         rolle: 'admin' },
  { username: 'cem.altun',           name: 'Cem Altun',           rolle: 'user'  },
  { username: 'anastasia.taspinar',  name: 'Anastasia Taspinar',  rolle: 'user'  },
  { username: 'elias.hachmuth',      name: 'Elias Hachmuth',      rolle: 'user'  },
];

for (const m of mitarbeiter) {
  const ex = db.prepare('SELECT id FROM benutzer WHERE username = ?').get(m.username);
  if (!ex) {
    const hash = bcrypt.hashSync('phonedoctor', 10);
    db.prepare('INSERT INTO benutzer (username, password_hash, name, rolle) VALUES (?,?,?,?)')
      .run(m.username, hash, m.name, m.rolle);
    console.log(`  Mitarbeiter angelegt: ${m.username} / phonedoctor`);
  }
}

// ─── Hilfsfunktion: lastInsertRowid als Number ────────────────────────────────
// node:sqlite gibt BigInt zurück – für unsere IDs reicht Number
function lastId(result) {
  return Number(result.lastInsertRowid);
}

module.exports = { db, lastId };
