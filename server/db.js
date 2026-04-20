'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.local') });
const pg      = require('pg');
const bcrypt  = require('bcryptjs');

// PostgreSQL Connection Pool
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

// ─── Initialize default users ────────────────────────────────────────────────
async function initializeDefaults() {
  try {
    // Standard-Super-Admin
    const existing = await pool.query('SELECT id FROM benutzer WHERE username = $1', ['superadmin']);
    if (existing.rows.length === 0) {
      const hash = bcrypt.hashSync('admin123', 10);
      await pool.query(
        `INSERT INTO benutzer (username, password_hash, name, rolle)
         VALUES ($1, $2, $3, $4)`,
        ['superadmin', hash, 'Super Administrator', 'superadmin']
      );
      console.log('  Standard-Account angelegt: superadmin / admin123');
    }

    // Standard-Mitarbeiter
    const mitarbeiter = [
      { username: 'mike.pingel',         name: 'Mike Pingel',         rolle: 'admin' },
      { username: 'cem.altun',           name: 'Cem Altun',           rolle: 'user'  },
      { username: 'anastasia.taspinar',  name: 'Anastasia Taspinar',  rolle: 'user'  },
      { username: 'elias.hachmuth',      name: 'Elias Hachmuth',      rolle: 'user'  },
    ];

    for (const m of mitarbeiter) {
      const ex = await pool.query('SELECT id FROM benutzer WHERE username = $1', [m.username]);
      if (ex.rows.length === 0) {
        const hash = bcrypt.hashSync('phonedoctor', 10);
        await pool.query(
          `INSERT INTO benutzer (username, password_hash, name, rolle)
           VALUES ($1, $2, $3, $4)`,
          [m.username, hash, m.name, m.rolle]
        );
        console.log(`  Mitarbeiter angelegt: ${m.username} / phonedoctor`);
      }
    }
  } catch (error) {
    console.error('Error initializing defaults:', error);
  }
}

// Run initialization on startup
initializeDefaults();

module.exports = { pool };
