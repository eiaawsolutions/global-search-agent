// Migration runner: applies schema.sql (idempotent — all CREATE IF NOT EXISTS)
// and, if no tenants exist yet, bootstraps one and prints its API key + the
// webhook secret ONCE. After that the plaintext key is unrecoverable.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import db, { global, uuid } from './index.js';
import { config } from '../config.js';
import { generateApiKey, hashApiKey } from '../utils/crypto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Additive column migrations for databases created before a column existed.
// schema.sql uses CREATE TABLE IF NOT EXISTS, so an existing table is never
// re-created — new columns must be ALTERed in. Each entry is idempotent: we
// check the live column set first and skip anything already present.
function applyColumnMigrations(silent) {
  const pending = [
    { table: 'connectors', column: 'kind',
      ddl: `ALTER TABLE connectors ADD COLUMN kind TEXT NOT NULL DEFAULT 'generic'` },
    { table: 'connectors', column: 'meta_json',
      ddl: `ALTER TABLE connectors ADD COLUMN meta_json TEXT NOT NULL DEFAULT '{}'` },
  ];
  for (const m of pending) {
    const cols = db.prepare(`PRAGMA table_info(${m.table})`).all();
    if (cols.some((c) => c.name === m.column)) continue;
    db.exec(m.ddl);
    if (!silent) console.log(`✔ Column added: ${m.table}.${m.column}`);
  }
}

export function migrate({ silent = false } = {}) {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  db.exec(schema);
  applyColumnMigrations(silent);
  if (!silent) console.log('✔ Schema applied:', config.dbPath);

  let createdKey = null;
  if (global.countTenants() === 0) {
    // Prefer operator-pinned credentials (set via env on a containerized
    // deploy so they survive scrolled-away logs); otherwise generate them.
    const pinnedKey = config.bootstrapApiKey;
    if (pinnedKey && pinnedKey.length < 24) {
      throw new Error('BOOTSTRAP_API_KEY must be at least 24 characters.');
    }
    const apiKey = pinnedKey || generateApiKey('gsa');
    const webhookSecret =
      config.bootstrapWebhookSecret || generateApiKey('whsec');
    const pinned = !!pinnedKey;

    global.createTenant({
      id: uuid(),
      name: config.bootstrapTenantName,
      plan: 'pro',
      apiKeyHash: hashApiKey(apiKey),
      webhookSecret,
    });
    createdKey = { apiKey, webhookSecret, pinned };
    if (!silent) {
      console.log('\n┌─ Bootstrap tenant created ───────────────────────────');
      console.log(`│ Name           : ${config.bootstrapTenantName}`);
      if (pinned) {
        // The key came from env — don't echo the secret into logs.
        console.log('│ API key        : (from BOOTSTRAP_API_KEY env var)');
        console.log('│ Webhook secret : (from env / generated)');
      } else {
        console.log(`│ API key        : ${apiKey}`);
        console.log(`│ Webhook secret : ${webhookSecret}`);
        console.log('│ Store these now — the API key is not recoverable.');
      }
      console.log('└──────────────────────────────────────────────────────\n');
    }
  } else if (!silent) {
    console.log('✔ Tenants already exist — skipping bootstrap.');
  }
  return createdKey;
}

// Run directly: `npm run migrate`. Compare resolved file paths via
// pathToFileURL so the check works on Windows (backslashes, drive letters)
// as well as POSIX.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  migrate();
}
