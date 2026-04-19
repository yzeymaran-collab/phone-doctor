'use strict';
const express = require('express');
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');
const path    = require('path');
const QRCode  = require('qrcode');
const { db, lastId } = require('./db');

const app        = express();
const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'phone-dr-2024-geheim';

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '25mb' }));           // Platz für Base64-Bilder
app.use(express.static(path.join(__dirname, '..'))); // Statisches Frontend

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

/** JWT prüfen und User an req hängen */
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ message: 'Nicht autorisiert – bitte anmelden' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Sitzung abgelaufen – bitte neu anmelden' });
  }
}

/** Rolle(n) prüfen */
function can(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.rolle))
      return res.status(403).json({ message: 'Keine Berechtigung für diese Aktion' });
    next();
  };
}

/** Protokolleintrag schreiben */
function log(req, action, entity, entityId, description) {
  db.prepare(`
    INSERT INTO protokoll (user_id, user_name, user_rolle, action, entity, entity_id, description)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    req.user.id, req.user.name, req.user.rolle,
    action, entity || '', entityId || null, description || ''
  );
}

/** JSON-Fotos-Array aus DB-Zeile parsen */
function parseFotos(row) {
  if (row) row.fotos = JSON.parse(row.fotos || '[]');
  return row;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ message: 'Benutzername und Passwort erforderlich' });

  const user = db.prepare('SELECT * FROM benutzer WHERE username = ? AND aktiv = 1').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ message: 'Benutzername oder Passwort falsch, oder Konto deaktiviert' });

  db.prepare(`UPDATE benutzer SET last_login = datetime('now','localtime') WHERE id = ?`).run(user.id);

  const payload = { id: user.id, username: user.username, name: user.name, rolle: user.rolle };
  const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

  // Login loggen (kein req.user vorhanden → direkt eintragen)
  db.prepare(`
    INSERT INTO protokoll (user_id, user_name, user_rolle, action, entity, description)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(user.id, user.name, user.rolle, 'login', '', `${user.name} hat sich angemeldet`);

  res.json({ token, user: payload });
});

app.post('/api/auth/logout', auth, (req, res) => {
  log(req, 'logout', '', null, `${req.user.name} hat sich abgemeldet`);
  res.status(204).end();
});

// ═══════════════════════════════════════════════════════════════════════════════
// GERÄTE
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/geraete', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM geraete ORDER BY id DESC').all();
  res.json(rows.map(parseFotos));
});

app.post('/api/geraete', auth, (req, res) => {
  const g = req.body;
  const fotos = JSON.stringify(Array.isArray(g.fotos) ? g.fotos : []);

  const result = db.prepare(`
    INSERT INTO geraete
      (typ, status, marke, modell, imei, speicher, zustand, ankaufspreis, reparaturkosten,
       verkaufspreis, ankaufsdatum, verkaufsdatum, verkaeufer_id, kaeufer_id, notizen, fotos)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    g.typ, g.status, g.marke, g.modell,
    g.imei        || null,
    g.speicher    || null,
    g.zustand     || 'Gut',
    g.ankaufspreis     != null ? g.ankaufspreis     : null,
    g.reparaturkosten  != null ? g.reparaturkosten  : null,
    g.verkaufspreis    != null ? g.verkaufspreis    : null,
    g.ankaufsdatum  || null,
    g.verkaufsdatum || null,
    g.verkaeufer    || null,
    g.kaeufer       || null,
    g.notizen       || null,
    fotos
  );

  const neu = parseFotos(db.prepare('SELECT * FROM geraete WHERE id = ?').get(lastId(result)));
  log(req, 'created', 'Gerät', neu.id, `${g.marke} ${g.modell} (${g.typ}) angelegt – Status: ${g.status}`);
  res.status(201).json(neu);
});

app.put('/api/geraete/:id', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const g  = req.body;

  const existing = db.prepare('SELECT * FROM geraete WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ message: 'Gerät nicht gefunden' });

  // User-Rolle darf EK-Preise nicht überschreiben
  const ankauf = req.user.rolle === 'user' ? existing.ankaufspreis    : (g.ankaufspreis    != null ? g.ankaufspreis    : null);
  const repa   = req.user.rolle === 'user' ? existing.reparaturkosten : (g.reparaturkosten != null ? g.reparaturkosten : null);
  const fotos  = JSON.stringify(Array.isArray(g.fotos) ? g.fotos : []);

  db.prepare(`
    UPDATE geraete SET
      typ=?, status=?, marke=?, modell=?, imei=?, speicher=?, zustand=?,
      ankaufspreis=?, reparaturkosten=?, verkaufspreis=?,
      ankaufsdatum=?, verkaufsdatum=?,
      verkaeufer_id=?, kaeufer_id=?, notizen=?, fotos=?,
      updated_at=datetime('now','localtime')
    WHERE id=?
  `).run(
    g.typ, g.status, g.marke, g.modell,
    g.imei      || null,
    g.speicher  || null,
    g.zustand   || 'Gut',
    ankauf, repa,
    g.verkaufspreis != null ? g.verkaufspreis : null,
    g.ankaufsdatum  || null,
    g.verkaufsdatum || null,
    g.verkaeufer    || null,
    g.kaeufer       || null,
    g.notizen       || null,
    fotos, id
  );

  const updated = parseFotos(db.prepare('SELECT * FROM geraete WHERE id = ?').get(id));

  // Status-Änderung besonders protokollieren
  const changes = [];
  if (existing.status !== g.status) changes.push(`Status: ${existing.status} → ${g.status}`);
  log(req, 'updated', 'Gerät', id,
    `${g.marke} ${g.modell} bearbeitet${changes.length ? ' (' + changes.join(', ') + ')' : ''}`
  );
  res.json(updated);
});

app.delete('/api/geraete/:id', auth, can('superadmin'), (req, res) => {
  const id = parseInt(req.params.id);
  const g  = db.prepare('SELECT * FROM geraete WHERE id = ?').get(id);
  if (!g) return res.status(404).json({ message: 'Gerät nicht gefunden' });

  db.prepare('DELETE FROM geraete WHERE id = ?').run(id);
  log(req, 'deleted', 'Gerät', id, `${g.marke} ${g.modell} gelöscht`);
  res.status(204).end();
});

// ═══════════════════════════════════════════════════════════════════════════════
// KUNDEN
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/kunden', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM kunden ORDER BY name COLLATE NOCASE').all());
});

app.post('/api/kunden', auth, (req, res) => {
  const k = req.body;
  const result = db.prepare(`
    INSERT INTO kunden (name, telefon, email, typ, notizen)
    VALUES (?, ?, ?, ?, ?)
  `).run(k.name, k.telefon || null, k.email || null, k.typ || 'Käufer', k.notizen || null);

  const neu = db.prepare('SELECT * FROM kunden WHERE id = ?').get(lastId(result));
  log(req, 'created', 'Kunde', neu.id, `${k.name} angelegt (${k.typ})`);
  res.status(201).json(neu);
});

app.put('/api/kunden/:id', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const k  = req.body;

  const existing = db.prepare('SELECT * FROM kunden WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ message: 'Kunde nicht gefunden' });

  db.prepare('UPDATE kunden SET name=?, telefon=?, email=?, typ=?, notizen=? WHERE id=?')
    .run(k.name, k.telefon || null, k.email || null, k.typ || 'Käufer', k.notizen || null, id);

  const updated = db.prepare('SELECT * FROM kunden WHERE id = ?').get(id);
  log(req, 'updated', 'Kunde', id, `${k.name} bearbeitet`);
  res.json(updated);
});

app.delete('/api/kunden/:id', auth, can('superadmin'), (req, res) => {
  const id = parseInt(req.params.id);
  const k  = db.prepare('SELECT * FROM kunden WHERE id = ?').get(id);
  if (!k) return res.status(404).json({ message: 'Kunde nicht gefunden' });

  db.prepare('DELETE FROM kunden WHERE id = ?').run(id);
  log(req, 'deleted', 'Kunde', id, `${k.name} gelöscht`);
  res.status(204).end();
});

// ═══════════════════════════════════════════════════════════════════════════════
// BENUTZER  (nur Super Admin)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/benutzer', auth, can('superadmin'), (req, res) => {
  res.json(db.prepare(
    'SELECT id, username, name, rolle, aktiv, last_login, created_at FROM benutzer ORDER BY name'
  ).all());
});

app.post('/api/benutzer', auth, can('superadmin'), (req, res) => {
  const b = req.body;
  if (!b.password || b.password.length < 6)
    return res.status(400).json({ message: 'Passwort muss mindestens 6 Zeichen haben' });

  const dup = db.prepare('SELECT id FROM benutzer WHERE username = ?').get(b.username);
  if (dup) return res.status(409).json({ message: 'Benutzername bereits vergeben' });

  const hash   = bcrypt.hashSync(b.password, 10);
  const result = db.prepare(`
    INSERT INTO benutzer (username, password_hash, name, rolle, aktiv)
    VALUES (?, ?, ?, ?, ?)
  `).run(b.username, hash, b.name, b.rolle || 'user', b.aktiv ? 1 : 0);

  const neu = db.prepare(
    'SELECT id, username, name, rolle, aktiv, last_login, created_at FROM benutzer WHERE id = ?'
  ).get(lastId(result));

  log(req, 'created', 'Benutzer', neu.id, `${b.name} (${b.username}) angelegt – Rolle: ${b.rolle}`);
  res.status(201).json(neu);
});

app.put('/api/benutzer/:id', auth, can('superadmin'), (req, res) => {
  const id       = parseInt(req.params.id);
  const b        = req.body;
  const existing = db.prepare('SELECT * FROM benutzer WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ message: 'Benutzer nicht gefunden' });

  // Doppelten Benutzernamen verhindern
  const dup = db.prepare('SELECT id FROM benutzer WHERE username = ? AND id != ?').get(b.username, id);
  if (dup) return res.status(409).json({ message: 'Benutzername bereits vergeben' });

  // Letzten Super Admin schützen
  if (existing.rolle === 'superadmin' && b.rolle !== 'superadmin') {
    const cnt = db.prepare("SELECT COUNT(*) AS c FROM benutzer WHERE rolle='superadmin'").get();
    if (cnt.c <= 1)
      return res.status(400).json({ message: 'Letzter Super Admin – Rolle kann nicht geändert werden' });
  }

  let hash = existing.password_hash;
  if (b.password && b.password.length >= 6) hash = bcrypt.hashSync(b.password, 10);

  db.prepare(`
    UPDATE benutzer SET username=?, password_hash=?, name=?, rolle=?, aktiv=? WHERE id=?
  `).run(b.username, hash, b.name, b.rolle || existing.rolle, b.aktiv ? 1 : 0, id);

  const updated = db.prepare(
    'SELECT id, username, name, rolle, aktiv, last_login, created_at FROM benutzer WHERE id = ?'
  ).get(id);

  log(req, 'updated', 'Benutzer', id, `${b.name} bearbeitet`);
  res.json(updated);
});

app.delete('/api/benutzer/:id', auth, can('superadmin'), (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.user.id)
    return res.status(400).json({ message: 'Eigenes Konto kann nicht gelöscht werden' });

  const b = db.prepare('SELECT * FROM benutzer WHERE id = ?').get(id);
  if (!b) return res.status(404).json({ message: 'Benutzer nicht gefunden' });

  if (b.rolle === 'superadmin') {
    const cnt = db.prepare("SELECT COUNT(*) AS c FROM benutzer WHERE rolle='superadmin'").get();
    if (cnt.c <= 1)
      return res.status(400).json({ message: 'Letzter Super Admin kann nicht gelöscht werden' });
  }

  db.prepare('DELETE FROM benutzer WHERE id = ?').run(id);
  log(req, 'deleted', 'Benutzer', id, `${b.name} gelöscht`);
  res.status(204).end();
});

// ═══════════════════════════════════════════════════════════════════════════════
// PROTOKOLL
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/protokoll', auth, (req, res) => {
  const { action, user, date, q } = req.query;
  let   sql    = 'SELECT * FROM protokoll WHERE 1=1';
  const params = [];

  if (action) { sql += ' AND action = ?';            params.push(action); }
  if (user)   { sql += ' AND user_name = ?';          params.push(user); }
  if (date)   { sql += ' AND ts LIKE ?';              params.push(date + '%'); }
  if (q) {
    sql += ' AND (description LIKE ? OR user_name LIKE ? OR entity LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }

  sql += ' ORDER BY id DESC LIMIT 500';
  res.json(db.prepare(sql).all(...params));
});

app.get('/api/protokoll/export', auth, (req, res) => {
  const rows   = db.prepare('SELECT * FROM protokoll ORDER BY id DESC').all();
  const header = 'Zeitstempel,Benutzer,Rolle,Aktion,Objekt,Beschreibung\n';
  const body   = rows.map(r =>
    [r.ts, r.user_name, r.user_rolle, r.action,
     `${r.entity || ''} ${r.entity_id || ''}`.trim(), r.description || '']
      .map(c => `"${String(c).replace(/"/g, '""')}"`)
      .join(',')
  ).join('\n');

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition',
    `attachment; filename="protokoll_${new Date().toISOString().split('T')[0]}.csv"`);
  res.send('\uFEFF' + header + body);
});

// ═══════════════════════════════════════════════════════════════════════════════
// STATISTIKEN  (kompakte Zusammenfassung für das Dashboard)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/statistiken', auth, (req, res) => {
  const stats = db.prepare(`
    SELECT
      COUNT(*)                                              AS total,
      SUM(CASE WHEN status != 'Verkauft' THEN 1 ELSE 0 END) AS bestand,
      SUM(CASE WHEN status  = 'Verkauft' THEN 1 ELSE 0 END) AS verkauft,
      SUM(COALESCE(verkaufspreis,0))                        AS umsatz,
      SUM(COALESCE(ankaufspreis,0))                         AS einkauf,
      SUM(COALESCE(reparaturkosten,0))                      AS reparatur,
      SUM(CASE WHEN verkaufspreis IS NOT NULL
               THEN verkaufspreis - COALESCE(ankaufspreis,0) - COALESCE(reparaturkosten,0)
               ELSE 0 END)                                  AS gewinn
    FROM geraete
  `).get();

  const typen = db.prepare(`
    SELECT typ, COUNT(*) AS anzahl FROM geraete GROUP BY typ
  `).all();

  const statusVert = db.prepare(`
    SELECT status, COUNT(*) AS anzahl FROM geraete GROUP BY status
  `).all();

  const topDeals = db.prepare(`
    SELECT id, marke, modell, typ, ankaufsdatum, verkaufsdatum,
           ankaufspreis, reparaturkosten, verkaufspreis,
           (COALESCE(verkaufspreis,0) - COALESCE(ankaufspreis,0) - COALESCE(reparaturkosten,0)) AS gewinn
    FROM geraete
    WHERE verkaufspreis IS NOT NULL
    ORDER BY gewinn DESC
    LIMIT 10
  `).all();

  const letzteVerkauefe = db.prepare(`
    SELECT id, marke, modell, verkaufsdatum,
           (COALESCE(verkaufspreis,0) - COALESCE(ankaufspreis,0) - COALESCE(reparaturkosten,0)) AS gewinn
    FROM geraete
    WHERE verkaufspreis IS NOT NULL
    ORDER BY verkaufsdatum DESC, id DESC
    LIMIT 10
  `).all();

  res.json({ stats, typen, statusVert, topDeals, letzteVerkauefe });
});

// ═══════════════════════════════════════════════════════════════════════════════
// REPARATUR-AUFTRÄGE
// ═══════════════════════════════════════════════════════════════════════════════

function parseReparatur(row) {
  if (row) row.reparatur_liste = JSON.parse(row.reparatur_liste || '[]');
  return row;
}

app.get('/api/reparaturen', auth, (req, res) => {
  const { q, status } = req.query;
  let   sql    = 'SELECT * FROM reparaturen WHERE 1=1';
  const params = [];
  if (status) { sql += ' AND status = ?'; params.push(status); }
  if (q) {
    sql += ' AND (kunden_name LIKE ? OR kunden_telefon LIKE ? OR modell LIKE ? OR imei LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
  }
  sql += ' ORDER BY id DESC';
  res.json(db.prepare(sql).all(...params).map(parseReparatur));
});

app.get('/api/reparaturen/:id', auth, (req, res) => {
  const row = db.prepare('SELECT * FROM reparaturen WHERE id = ?').get(parseInt(req.params.id));
  if (!row) return res.status(404).json({ message: 'Auftrag nicht gefunden' });
  res.json(parseReparatur(row));
});

app.post('/api/reparaturen', auth, (req, res) => {
  const r = req.body;
  const liste = JSON.stringify(Array.isArray(r.reparatur_liste) ? r.reparatur_liste : []);
  const result = db.prepare(`
    INSERT INTO reparaturen
      (kunden_name, kunden_telefon, kunden_email, kunden_adresse,
       hersteller, modell, farbe, zustand, imei, pin_code, entsperrmuster,
       abholtermin, schadenbeschreibung, schadenshergang, reparatur_liste,
       status, kostenvoranschlag, notizen)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    r.kunden_name, r.kunden_telefon||null, r.kunden_email||null, r.kunden_adresse||null,
    r.hersteller||null, r.modell||null, r.farbe||null, r.zustand||'Gut',
    r.imei||null, r.pin_code||null, r.entsperrmuster||null,
    r.abholtermin||null, r.schadenbeschreibung||null, r.schadenshergang||null, liste,
    r.status||'Offen', r.kostenvoranschlag!=null?r.kostenvoranschlag:null, r.notizen||null
  );
  const neu = parseReparatur(db.prepare('SELECT * FROM reparaturen WHERE id = ?').get(lastId(result)));
  log(req, 'created', 'Reparatur', neu.id, `Auftrag für ${r.kunden_name} – ${r.hersteller||''} ${r.modell||''} angelegt`);
  res.status(201).json(neu);
});

app.put('/api/reparaturen/:id', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const r  = req.body;
  const existing = db.prepare('SELECT * FROM reparaturen WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ message: 'Auftrag nicht gefunden' });
  const liste = JSON.stringify(Array.isArray(r.reparatur_liste) ? r.reparatur_liste : []);
  db.prepare(`
    UPDATE reparaturen SET
      kunden_name=?, kunden_telefon=?, kunden_email=?, kunden_adresse=?,
      hersteller=?, modell=?, farbe=?, zustand=?, imei=?, pin_code=?, entsperrmuster=?,
      abholtermin=?, schadenbeschreibung=?, schadenshergang=?, reparatur_liste=?,
      status=?, kostenvoranschlag=?, notizen=?,
      updated_at=datetime('now','localtime')
    WHERE id=?
  `).run(
    r.kunden_name, r.kunden_telefon||null, r.kunden_email||null, r.kunden_adresse||null,
    r.hersteller||null, r.modell||null, r.farbe||null, r.zustand||'Gut',
    r.imei||null, r.pin_code||null, r.entsperrmuster||null,
    r.abholtermin||null, r.schadenbeschreibung||null, r.schadenshergang||null, liste,
    r.status||'Offen', r.kostenvoranschlag!=null?r.kostenvoranschlag:null, r.notizen||null,
    id
  );
  const updated = parseReparatur(db.prepare('SELECT * FROM reparaturen WHERE id = ?').get(id));
  log(req, 'updated', 'Reparatur', id, `Auftrag ${r.kunden_name} bearbeitet (Status: ${r.status})`);
  res.json(updated);
});

app.delete('/api/reparaturen/:id', auth, can('superadmin'), (req, res) => {
  const id = parseInt(req.params.id);
  const r  = db.prepare('SELECT * FROM reparaturen WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ message: 'Auftrag nicht gefunden' });
  db.prepare('DELETE FROM reparaturen WHERE id = ?').run(id);
  log(req, 'deleted', 'Reparatur', id, `Auftrag #${id} (${r.kunden_name}) gelöscht`);
  res.status(204).end();
});

// ─── PUBLIC: Auftragsstatus (kein Auth) ──────────────────────────────────────
app.get('/api/status/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const r  = db.prepare('SELECT * FROM reparaturen WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ message: 'Auftrag nicht gefunden' });
  // Return only public fields - no PIN, no pattern, no internal notes
  res.json({
    id:                r.id,
    kunden_name:       r.kunden_name,
    hersteller:        r.hersteller,
    modell:            r.modell,
    farbe:             r.farbe,
    zustand:           r.zustand,
    status:            r.status,
    abholtermin:       r.abholtermin,
    schadenbeschreibung: r.schadenbeschreibung,
    reparatur_liste:   JSON.parse(r.reparatur_liste || '[]'),
    kostenvoranschlag: r.kostenvoranschlag,
    created_at:        r.created_at,
    updated_at:        r.updated_at,
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// EINSTELLUNGEN  (nur Super Admin)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/einstellungen', auth, can('superadmin'), (req, res) => {
  const rows = db.prepare('SELECT key, value FROM einstellungen').all();
  const obj  = {};
  rows.forEach(r => { obj[r.key] = r.value; });
  // Mask token: just indicate whether it's set
  if (obj.lexware_token) {
    obj.lexware_token_masked = '••••••••' + obj.lexware_token.slice(-4);
    delete obj.lexware_token;
  }
  if (obj.hellocash_token) {
    obj.hellocash_token_masked = '••••••••' + obj.hellocash_token.slice(-4);
    delete obj.hellocash_token;
  }
  if (obj.imei_api_key) {
    obj.imei_api_key_masked = '••••••••' + obj.imei_api_key.slice(-4);
    delete obj.imei_api_key;
  }
  res.json(obj);
});

app.put('/api/einstellungen', auth, can('superadmin'), (req, res) => {
  const data = req.body || {};
  const stmt = db.prepare('INSERT OR REPLACE INTO einstellungen (key, value) VALUES (?, ?)');
  for (const [k, v] of Object.entries(data)) {
    if (typeof v === 'string' && v.trim() !== '') stmt.run(k, v.trim());
  }
  log(req, 'updated', 'Einstellungen', null, 'Systemeinstellungen gespeichert');
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// LEXWARE INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

async function lexwareReq(method, path, body, token) {
  const url  = 'https://api.lexware.io' + path;
  const opts = {
    method,
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type':  'application/json',
      'Accept':        'application/json',
    },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const resp = await fetch(url, opts);
  let data;
  try { data = await resp.json(); } catch { data = {}; }
  return { status: resp.status, data };
}

function getLexToken() {
  const row = db.prepare("SELECT value FROM einstellungen WHERE key = 'lexware_token'").get();
  return row?.value || null;
}

// ── Verbindung testen ─────────────────────────────────────────────────────────
app.get('/api/lexware/test', auth, can('superadmin'), async (req, res) => {
  const token = getLexToken();
  if (!token) return res.status(400).json({ message: 'Kein API-Token konfiguriert' });
  try {
    const r = await lexwareReq('GET', '/v1/profile', undefined, token);
    res.status(r.status).json(r.data);
  } catch (err) {
    res.status(500).json({ message: 'Verbindungsfehler: ' + err.message });
  }
});

// ── Rechnung erstellen ────────────────────────────────────────────────────────
app.post('/api/lexware/rechnung', auth, async (req, res) => {
  const token = getLexToken();
  if (!token) return res.status(400).json({
    message: 'Kein Lexware API-Token konfiguriert. Bitte unter Einstellungen hinterlegen.'
  });

  const { reparatur_id, lineItems, voucherDate, taxType, finalize } = req.body;

  const r = db.prepare('SELECT * FROM reparaturen WHERE id = ?').get(parseInt(reparatur_id));
  if (!r) return res.status(404).json({ message: 'Auftrag nicht gefunden' });

  try {
    // 1. Kontakt in Lexware suchen oder anlegen
    let contactId = null;
    const searchName = r.kunden_name.trim().slice(0, 50);
    const searchR = await lexwareReq('GET',
      `/v1/contacts?name=${encodeURIComponent(searchName)}&customer=true`,
      undefined, token
    );
    if (searchR.status === 200 && searchR.data?.content?.length > 0) {
      contactId = searchR.data.content[0].id;
    } else {
      // Name in Vor- und Nachname aufteilen
      const parts     = r.kunden_name.trim().split(/\s+/);
      const lastName  = parts.length > 1 ? parts.slice(1).join(' ') : parts[0];
      const firstName = parts.length > 1 ? parts[0] : '';
      const contactBody = {
        version: 0,
        roles: { customer: {} },
        person: { lastName, ...(firstName ? { firstName } : {}) },
      };
      if (r.kunden_telefon) contactBody.phoneNumbers   = { mobile:   r.kunden_telefon.trim() };
      if (r.kunden_email)   contactBody.emailAddresses = { business: r.kunden_email.trim()   };
      if (r.kunden_adresse) {
        contactBody.addresses = {
          billing: [{ name: r.kunden_name, street: r.kunden_adresse, countryCode: 'DE' }]
        };
      }
      const cR = await lexwareReq('POST', '/v1/contacts', contactBody, token);
      if (cR.status === 201) contactId = cR.data.id;
    }

    // 2. Rechnung erstellen
    const invoiceBody = {
      voucherDate:       voucherDate || new Date().toISOString(),
      address:           contactId
        ? { contactId }
        : { name: r.kunden_name, countryCode: 'DE' },
      lineItems:         lineItems,
      totalPrice:        { currency: 'EUR' },
      taxConditions:     { taxType: taxType || 'gross' },
      shippingConditions: {
        shippingType: 'service',
        shippingDate: new Date().toISOString()
      },
      note: `Reparaturauftrag #${r.id} · phone doctor\n${[r.hersteller, r.modell].filter(Boolean).join(' ')}`.trim(),
    };

    const suffix = finalize ? '?finalize=true' : '';
    const invR   = await lexwareReq('POST', '/v1/invoices' + suffix, invoiceBody, token);

    if (invR.status === 201) {
      log(req, 'created', 'Lexware-Rechnung', r.id,
        `Rechnung für Auftrag #${r.id} (${r.kunden_name}) in Lexware erstellt`);
      res.status(201).json({ ...invR.data, contactId });
    } else {
      res.status(invR.status).json(invR.data);
    }
  } catch (err) {
    res.status(500).json({ message: 'Fehler: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// HELLOCASH INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

async function helloCashReq(method, path, body, token) {
  const url  = 'https://api.hellocash.business/api/v1' + path;
  const opts = {
    method,
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type':  'application/json',
      'Accept':        'application/json',
    },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const resp = await fetch(url, opts);
  let data;
  try { data = await resp.json(); } catch { data = {}; }
  return { status: resp.status, data };
}

function getHelloCashToken() {
  const row = db.prepare("SELECT value FROM einstellungen WHERE key = 'hellocash_token'").get();
  return row?.value || null;
}

// ── Verbindung testen ─────────────────────────────────────────────────────────
app.get('/api/hellocash/test', auth, can('superadmin'), async (req, res) => {
  const token = getHelloCashToken();
  if (!token) return res.status(400).json({ message: 'Kein helloCash API-Token konfiguriert' });
  try {
    const r = await helloCashReq('GET', '/invoices?limit=1', undefined, token);
    if (r.status === 200) {
      res.json({ ok: true, message: 'Verbindung erfolgreich' });
    } else {
      res.status(r.status).json(r.data);
    }
  } catch (err) {
    res.status(500).json({ message: 'Verbindungsfehler: ' + err.message });
  }
});

// ── Rechnung erstellen ────────────────────────────────────────────────────────
app.post('/api/hellocash/rechnung', auth, async (req, res) => {
  const token = getHelloCashToken();
  if (!token) return res.status(400).json({
    message: 'Kein helloCash API-Token konfiguriert. Bitte unter Einstellungen hinterlegen.'
  });

  const { reparatur_id, items, paymentMethod, invoiceText, testMode, locale, invoiceType } = req.body;

  const r = db.prepare('SELECT * FROM reparaturen WHERE id = ?').get(parseInt(reparatur_id));
  if (!r) return res.status(404).json({ message: 'Auftrag nicht gefunden' });

  try {
    // Rechnungs-Body für helloCash erstellen
    const invoiceBody = {
      invoice_testMode:      !!testMode,
      invoice_paymentMethod: paymentMethod || 'Bar',
      invoice_text:          invoiceText || `Reparaturauftrag #${r.id} · phone doctor\n${[r.hersteller, r.modell].filter(Boolean).join(' ')}`.trim(),
      invoice_type:          invoiceType || 'json',
      locale:                locale || 'de_DE',
      items: (items || []).map(item => ({
        item_name:           item.name,
        item_quantity:       String(item.quantity || 1),
        item_price:          String(item.price || 0),
        item_taxRate:        String(item.taxRate != null ? item.taxRate : 19),
        item_discount_unit:  'percent',
        item_discount_value: '0',
        item_type:           'service',
      })),
    };

    const invR = await helloCashReq('POST', '/invoices', invoiceBody, token);

    if (invR.status === 200 || invR.status === 201) {
      log(req, 'created', 'helloCash-Rechnung', r.id,
        `Rechnung für Auftrag #${r.id} (${r.kunden_name}) in helloCash erstellt`);
      res.status(201).json(invR.data);
    } else {
      res.status(invR.status).json(invR.data);
    }
  } catch (err) {
    res.status(500).json({ message: 'Fehler: ' + err.message });
  }
});

// ── Rechnung als PDF abrufen ──────────────────────────────────────────────────
app.get('/api/hellocash/rechnung/:id/pdf', auth, async (req, res) => {
  const token = getHelloCashToken();
  if (!token) return res.status(400).json({ message: 'Kein helloCash API-Token konfiguriert' });
  try {
    const r = await helloCashReq('GET', `/invoices/${req.params.id}/pdf?locale=de_DE`, undefined, token);
    res.status(r.status).json(r.data);
  } catch (err) {
    res.status(500).json({ message: 'Fehler: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// IMEI.INFO – IMEI-DATENBANK-ABFRAGE
// ═══════════════════════════════════════════════════════════════════════════════

function getImeiApiKey() {
  const row = db.prepare("SELECT value FROM einstellungen WHERE key = 'imei_api_key'").get();
  return row?.value || null;
}

const IMEI_API_BASE = 'https://dash.imei.info/api';

async function imeiReq(path, apiKey) {
  const sep  = path.includes('?') ? '&' : '?';
  const url  = IMEI_API_BASE + path + sep + 'API_KEY=' + encodeURIComponent(apiKey);
  const resp = await fetch(url, {
    headers: { 'Accept': 'application/json' },
  });
  let data;
  try { data = await resp.json(); } catch {
    const text = await resp.text().catch(() => '');
    return { status: resp.status, data: { detail: text || 'Keine Antwort' } };
  }
  return { status: resp.status, data };
}

// ── Verbindung testen (MUSS vor /:imei stehen!) ─────────────────────────────
app.get('/api/imei-lookup/test/connection', auth, can('superadmin'), async (req, res) => {
  const apiKey = getImeiApiKey();
  if (!apiKey) return res.status(400).json({ message: 'Kein IMEI.info API-Key konfiguriert' });
  try {
    const r = await imeiReq('/account/account/', apiKey);
    if (r.status === 401 || r.status === 403) {
      return res.status(401).json({ message: 'API-Key ungültig oder deaktiviert' });
    }
    if (r.status === 200 && r.data) {
      const bal = r.data.balance != null ? r.data.balance : null;
      res.json({
        ok:       true,
        balance:  bal,
        username: r.data.username || null,
        message:  'Verbindung erfolgreich'
      });
    } else {
      res.json({ ok: true, message: 'API erreichbar (Status ' + r.status + ')' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Verbindungsfehler: ' + err.message });
  }
});

// ── IMEI abfragen ────────────────────────────────────────────────────────────
// Endpunkt: GET /check/{service}/?imei={imei}&API_KEY={key}
// Service 0 = Basic IMEI Check (brand + model, sofort, $0.02)
app.get('/api/imei-lookup/:imei', auth, async (req, res) => {
  const apiKey = getImeiApiKey();
  if (!apiKey) return res.status(400).json({
    message: 'Kein IMEI.info API-Key konfiguriert. Bitte unter Einstellungen hinterlegen.'
  });

  const imei    = (req.params.imei || '').replace(/\s+/g, '');
  const service = req.query.service || '0';   // Default: Service 0 (Basic IMEI Check)

  if (!/^\d{15,16}$/.test(imei)) {
    return res.status(400).json({ message: 'Ungültige IMEI-Nummer. Muss 15 oder 16 Ziffern enthalten.' });
  }

  try {
    const r = await imeiReq(`/check/${service}/?imei=${imei}`, apiKey);

    if (r.status === 401) {
      return res.status(401).json({ message: 'API-Key ungültig' });
    }

    if (r.status === 402 || r.status === 403 || (r.data?.detail || '').toLowerCase().includes('expensive')) {
      return res.status(402).json({ message: 'Kein Guthaben – bitte auf dash.imei.info aufladen' });
    }

    if (r.status === 200) {
      const d = r.data;
      // Ergebnis normalisieren: result kann ein Objekt oder String sein
      const result = typeof d.result === 'object' ? d.result : {};
      const brand  = result.brand_name || result.brand || '?';
      const model  = result.model || '?';

      log(req, 'queried', 'IMEI-Lookup', null, `IMEI ${imei} abgefragt → ${brand} ${model}`);

      // Einheitliches Response-Format
      return res.json({
        imei:       d.imei || imei,
        brand:      result.brand_name || result.brand || null,
        model:      result.model || null,
        status:     d.status,            // "Done", "Rejected", etc.
        service:    d.service,           // "Basic IMEI Check"
        result:     d.result,            // Original-Ergebnis
        price:      d.token_request_price,
        created_at: d.created_at,
      });
    }

    res.status(r.status >= 400 ? r.status : 400).json({
      message: r.data?.detail || r.data?.error || r.data?.message || 'IMEI-Abfrage fehlgeschlagen',
      data:    r.data
    });
  } catch (err) {
    res.status(500).json({ message: 'IMEI-Abfrage fehlgeschlagen: ' + err.message });
  }
});

// ─── FOTO-UPLOAD (QR-Kamera-System) ──────────────────────────────────────────

// Neues Upload-Token erstellen + QR-Code als Data-URL generieren
app.post('/api/foto-upload/new', auth, async (req, res) => {
  const token = require('crypto').randomUUID();
  db.prepare('INSERT INTO foto_uploads (token) VALUES (?)').run(token);
  // Detect server URL (use host header so it works on local network)
  const protocol = req.secure ? 'https' : 'http';
  const host     = req.headers.host || `localhost:${PORT}`;
  const uploadUrl = `${protocol}://${host}/foto-upload/${token}`;
  try {
    const qrDataUrl = await QRCode.toDataURL(uploadUrl, {
      width: 200, margin: 1,
      color: { dark: '#0f172a', light: '#ffffff' }
    });
    res.json({ token, url: `/foto-upload/${token}`, qrDataUrl, uploadUrl });
  } catch {
    res.json({ token, url: `/foto-upload/${token}`, qrDataUrl: null, uploadUrl });
  }
});

// Status abfragen (Polling)
app.get('/api/foto-upload/:token', auth, (req, res) => {
  const row = db.prepare('SELECT foto FROM foto_uploads WHERE token = ?').get(req.params.token);
  if (!row) return res.status(404).json({ message: 'Token nicht gefunden' });
  res.json({ ready: !!row.foto, foto: row.foto || null });
});

// Foto vom Handy empfangen (kein Auth – kommt vom Handy)
app.post('/api/foto-upload/:token', (req, res) => {
  const { foto } = req.body;
  if (!foto) return res.status(400).json({ message: 'Kein Foto übermittelt' });
  const row = db.prepare('SELECT token FROM foto_uploads WHERE token = ?').get(req.params.token);
  if (!row) return res.status(404).json({ message: 'Token ungültig' });
  db.prepare('UPDATE foto_uploads SET foto = ? WHERE token = ?').run(foto, req.params.token);
  res.json({ ok: true });
});

// Token löschen (Cleanup nach Verwendung)
app.delete('/api/foto-upload/:token', auth, (req, res) => {
  db.prepare('DELETE FROM foto_uploads WHERE token = ?').run(req.params.token);
  res.status(204).end();
});

// Mobile Upload-Seite (HTML)
app.get('/foto-upload/:token', (req, res) => {
  const token = req.params.token;
  const row = db.prepare('SELECT token, foto FROM foto_uploads WHERE token = ?').get(token);
  if (!row) return res.status(404).send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:40px;"><h2>⚠️ Link ungültig oder abgelaufen</h2></body></html>`);
  if (row.foto) return res.send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:40px;background:#f0fdf4;"><h2 style="color:#16a34a;">✓ Foto wurde bereits hochgeladen</h2></body></html>`);

  res.send(`<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>Phone-dr · Gerät fotografieren</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#f1f5f9;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;}
.card{background:#1e293b;border-radius:20px;padding:28px 24px;width:100%;max-width:400px;text-align:center;}
.logo{width:60px;height:60px;border-radius:14px;background:#1d4ed8;display:flex;align-items:center;justify-content:center;margin:0 auto 18px;font-size:26px;}
h1{font-size:20px;font-weight:800;margin-bottom:8px;}
p{font-size:13.5px;color:#94a3b8;line-height:1.6;margin-bottom:22px;}
.preview{width:100%;border-radius:12px;margin-bottom:14px;display:none;max-height:280px;object-fit:cover;border:2px solid #334155;}
label.btn-cam{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:16px;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer;background:#1d4ed8;color:#fff;box-shadow:0 6px 20px rgba(29,78,216,.4);margin-bottom:12px;transition:all .15s;}
label.btn-cam:active{transform:scale(.97);}
.btn-send{display:none;width:100%;padding:14px;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer;background:#059669;color:#fff;border:none;box-shadow:0 6px 20px rgba(5,150,105,.35);transition:all .15s;}
.btn-send:active{transform:scale(.97);}
.btn-send:disabled{opacity:.6;cursor:not-allowed;}
.status{margin-top:14px;font-size:14px;font-weight:600;min-height:22px;}
.ok{color:#34d399;}.err{color:#f87171;}
input[type=file]{display:none;}
.retake{display:none;background:none;border:none;color:#64748b;font-size:13px;text-decoration:underline;cursor:pointer;margin-top:8px;}
</style>
</head>
<body>
<div class="card">
  <div class="logo">📱</div>
  <h1>Gerät fotografieren</h1>
  <p>Kamera auf das Gerät richten, Foto aufnehmen und dem Ankauf hinzufügen.</p>
  <img id="preview" class="preview" alt="Vorschau">
  <label class="btn-cam" for="cam">
    <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-width="2" d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/><circle cx="12" cy="13" r="4" stroke-width="2"/></svg>
    Kamera öffnen
  </label>
  <input type="file" id="cam" accept="image/*" capture="environment">
  <button class="btn-send" id="sendBtn" onclick="upload()">Foto hinzufügen ✓</button>
  <button class="retake" id="retakeBtn" onclick="retake()">Neu aufnehmen</button>
  <div class="status" id="status"></div>
</div>
<script>
let data=null;
document.getElementById('cam').addEventListener('change',function(e){
  const f=e.target.files[0]; if(!f)return;
  const r=new FileReader();
  r.onload=function(ev){
    const img=new Image();
    img.onload=function(){
      const MAX=1400;let w=img.width,h=img.height;
      if(w>MAX||h>MAX){if(w>h){h=Math.round(h*MAX/w);w=MAX;}else{w=Math.round(w*MAX/h);h=MAX;}}
      const c=document.createElement('canvas');c.width=w;c.height=h;
      c.getContext('2d').drawImage(img,0,0,w,h);
      data=c.toDataURL('image/jpeg',.8);
      document.getElementById('preview').src=data;
      document.getElementById('preview').style.display='block';
      document.getElementById('sendBtn').style.display='block';
      document.getElementById('retakeBtn').style.display='block';
      document.getElementById('status').textContent='';
    };
    img.src=ev.target.result;
  };
  r.readAsDataURL(f);
});
function retake(){
  data=null;
  document.getElementById('cam').value='';
  document.getElementById('preview').style.display='none';
  document.getElementById('sendBtn').style.display='none';
  document.getElementById('retakeBtn').style.display='none';
}
async function upload(){
  if(!data)return;
  const btn=document.getElementById('sendBtn');
  const st=document.getElementById('status');
  btn.disabled=true; btn.textContent='Wird gesendet…';
  try{
    const resp=await fetch('/api/foto-upload/${token}',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({foto:data})
    });
    if(resp.ok){
      st.innerHTML='<span class="ok">✓ Foto erfolgreich hinzugefügt!</span>';
      btn.textContent='✓ Gesendet';
      btn.style.background='#059669';
      document.getElementById('retakeBtn').style.display='none';
    } else { throw new Error('Sendefehler'); }
  }catch(err){
    st.innerHTML='<span class="err">✕ '+err.message+'</span>';
    btn.disabled=false; btn.textContent='Foto hinzufügen ✓';
  }
}
</script>
</body>
</html>`);
});

// ═══════════════════════════════════════════════════════════════════════════════
// ZEITERFASSUNG (Stechuhr)
// ═══════════════════════════════════════════════════════════════════════════════

// Aktuell offener Eintrag für eingeloggten User
app.get('/api/zeit/aktuell', auth, (req, res) => {
  const row = db.prepare(
    'SELECT * FROM zeiterfassung WHERE user_id = ? AND ausstempel_ts IS NULL ORDER BY id DESC LIMIT 1'
  ).get(req.user.id);
  res.json(row || null);
});

// Einträge (eigene oder alle für admins)
app.get('/api/zeit', auth, (req, res) => {
  const { datum, user_id } = req.query;
  const isAdmin = ['admin','superadmin'].includes(req.user.rolle);
  let sql    = 'SELECT * FROM zeiterfassung WHERE 1=1';
  const params = [];
  if (!isAdmin) { sql += ' AND user_id = ?'; params.push(req.user.id); }
  else if (user_id) { sql += ' AND user_id = ?'; params.push(parseInt(user_id)); }
  if (datum) { sql += ' AND DATE(einstempel_ts) = ?'; params.push(datum); }
  sql += ' ORDER BY id DESC';
  res.json(db.prepare(sql).all(...params));
});

// Heute-Zusammenfassung (alle Mitarbeiter, nur admins)
app.get('/api/zeit/heute', auth, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const rows  = db.prepare(
    "SELECT * FROM zeiterfassung WHERE DATE(einstempel_ts) = ? ORDER BY einstempel_ts ASC"
  ).all(today);
  res.json(rows);
});

// Einstempeln
app.post('/api/zeit/einstempeln', auth, (req, res) => {
  // Prüfen ob bereits eingestempelt
  const open = db.prepare(
    'SELECT id FROM zeiterfassung WHERE user_id = ? AND ausstempel_ts IS NULL'
  ).get(req.user.id);
  if (open) return res.status(409).json({ message: 'Bereits eingestempelt – bitte zuerst ausstempeln' });

  const ts = new Date().toISOString().replace('T',' ').substring(0,19);
  const result = db.prepare(
    'INSERT INTO zeiterfassung (user_id, user_name, einstempel_ts, notizen) VALUES (?,?,?,?)'
  ).run(req.user.id, req.user.name, ts, req.body?.notizen || null);

  const neu = db.prepare('SELECT * FROM zeiterfassung WHERE id = ?').get(Number(result.lastInsertRowid));
  log(req, 'created', 'Zeiterfassung', neu.id, `${req.user.name} eingestempelt`);
  res.status(201).json(neu);
});

// Ausstempeln
app.post('/api/zeit/ausstempeln', auth, (req, res) => {
  const open = db.prepare(
    'SELECT * FROM zeiterfassung WHERE user_id = ? AND ausstempel_ts IS NULL ORDER BY id DESC LIMIT 1'
  ).get(req.user.id);
  if (!open) return res.status(404).json({ message: 'Nicht eingestempelt' });

  const ts    = new Date().toISOString().replace('T',' ').substring(0,19);
  const pause = parseInt(req.body?.pause_minuten) || 0;
  const notiz = req.body?.notizen || null;
  db.prepare(
    'UPDATE zeiterfassung SET ausstempel_ts = ?, pause_minuten = ?, notizen = ? WHERE id = ?'
  ).run(ts, pause, notiz, open.id);

  const updated = db.prepare('SELECT * FROM zeiterfassung WHERE id = ?').get(open.id);
  log(req, 'updated', 'Zeiterfassung', open.id, `${req.user.name} ausgestempelt`);
  res.json(updated);
});

// Eintrag löschen (nur superadmin)
app.delete('/api/zeit/:id', auth, can('superadmin'), (req, res) => {
  const id = parseInt(req.params.id);
  const z  = db.prepare('SELECT * FROM zeiterfassung WHERE id = ?').get(id);
  if (!z) return res.status(404).json({ message: 'Eintrag nicht gefunden' });
  db.prepare('DELETE FROM zeiterfassung WHERE id = ?').run(id);
  log(req, 'deleted', 'Zeiterfassung', id, `Zeiteintrag #${id} (${z.user_name}) gelöscht`);
  res.status(204).end();
});

// ─── Catch-all: SPA-Fallback ─────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'hardware-verwaltung.html'));
});

// ─── Server starten ──────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ╔═══════════════════════════════════════╗');
  console.log('  ║   phone doctor Verwaltungssystem        ║');
  console.log(`  ║   http://localhost:${PORT}                ║`);
  console.log('  ╠═══════════════════════════════════════╣');
  console.log('  ║   Standard-Login: superadmin          ║');
  console.log('  ║   Passwort:       admin123            ║');
  console.log('  ╚═══════════════════════════════════════╝');
  console.log('');
});
