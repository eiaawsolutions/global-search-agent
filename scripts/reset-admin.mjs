// One-shot admin reset.
//
// Wipes the operator-side identity surface on the active database so the
// admin re-enrols from scratch on next visit:
//   • admin_sessions          (every cookie invalidated)
//   • admins                  (every admin row + scrypt hash + TOTP secret)
//   • app_settings.proxy_tenant_id  (Settings forgets which tenant to proxy)
//
// Tenants, connectors, jobs, results, webhook deliveries, and audit log are
// untouched. After this runs:
//   • The Settings page shows "no admin enrolled yet" — re-enrol from /setup
//     (or, if ADMIN_USERNAME / ADMIN_PASSWORD are set on the environment when
//     this script runs, one admin is seeded immediately; you still complete a
//     fresh TOTP enrollment in the UI).
//   • GET /api/connectors returns 503 not_configured until the new admin
//     re-saves the tenant key in Settings.
//
// Usage:
//   node scripts/reset-admin.mjs --yes
//
// On Railway:
//   railway run --service "Global search agent" -- node scripts/reset-admin.mjs --yes
// (so the script attaches to the live container's volume-mounted SQLite file)
import db, { admins, adminSessions, settings, uuid } from '../src/db/index.js';
import { config } from '../src/config.js';
import { hashPassword } from '../src/utils/crypto.js';

const PROXY_TENANT_KEY = 'proxy_tenant_id';

function counts() {
  return {
    admins: db.prepare('SELECT COUNT(*) AS n FROM admins').get().n,
    sessions: db.prepare('SELECT COUNT(*) AS n FROM admin_sessions').get().n,
    proxy: settings.get(PROXY_TENANT_KEY) || null,
  };
}

function main() {
  if (!process.argv.includes('--yes')) {
    console.error(
      'Refusing to run without --yes. This deletes every admin row, every ' +
        'admin session, and the configured proxy tenant key.\n' +
        '  node scripts/reset-admin.mjs --yes'
    );
    process.exit(2);
  }

  const before = counts();
  console.log('Reset target:', config.dbPath);
  console.log('Before:', before);

  // Single transaction so a mid-flight crash leaves nothing half-cleared.
  const wipe = db.transaction(() => {
    db.prepare('DELETE FROM admin_sessions').run();
    db.prepare('DELETE FROM admins').run();
    db.prepare('DELETE FROM app_settings WHERE key = ?').run(PROXY_TENANT_KEY);
  });
  wipe();

  // Optional re-seed in the same run, so a fresh admin can log in immediately.
  // Reads ADMIN_USERNAME / ADMIN_PASSWORD from the same env the migrator uses.
  let seeded = null;
  if (admins.count() === 0 && config.adminUsername && config.adminPassword) {
    admins.create({
      id: uuid(),
      username: config.adminUsername,
      passwordHash: hashPassword(config.adminPassword),
    });
    seeded = config.adminUsername;
  }

  const after = counts();
  console.log('After: ', after);
  if (seeded) {
    console.log(`✔ Seeded admin "${seeded}" from env. Complete 2FA enrolment via Settings.`);
  } else {
    console.log('No admin seeded — set ADMIN_USERNAME + ADMIN_PASSWORD or use /setup.');
  }
}

main();
