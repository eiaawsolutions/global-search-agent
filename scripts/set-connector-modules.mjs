// One-shot: set a connector's meta.modules array.
//
// The /api/connectors route only accepts modules at creation time — there's
// no PATCH endpoint to change them later. Rather than delete + re-register
// (which would lose the connector id and cascade jobs/results away with the
// connector row), this script updates the meta_json in place.
//
// Usage:
//   node scripts/set-connector-modules.mjs <connector_id> <module> [<module> ...]
//
// Example — expand to all 4 Vistage modules:
//   node scripts/set-connector-modules.mjs 58424cce-389f-4df8-80bb-186f51504992 Member Lead Contact Account
import db, { raw } from '../src/db/index.js';

const VISTAGE_MODULES = ['Lead', 'Member', 'Contact', 'Account'];

const [, , connectorId, ...modulesArg] = process.argv;

if (!connectorId || modulesArg.length === 0) {
  console.error(
    'Usage: node scripts/set-connector-modules.mjs <connector_id> <module> [<module> ...]'
  );
  console.error(`Allowed modules: ${VISTAGE_MODULES.join(', ')}`);
  process.exit(2);
}

const bad = modulesArg.filter((m) => !VISTAGE_MODULES.includes(m));
if (bad.length) {
  console.error(`Unknown module(s): ${bad.join(', ')}`);
  console.error(`Allowed: ${VISTAGE_MODULES.join(', ')}`);
  process.exit(2);
}

const row = raw
  .prepare('SELECT id, name, kind, meta_json FROM connectors WHERE id = ?')
  .get(connectorId);
if (!row) {
  console.error(`Connector ${connectorId} not found.`);
  process.exit(1);
}
if (row.kind !== 'vistage') {
  console.error(`Connector ${connectorId} is kind=${row.kind}, not vistage.`);
  process.exit(1);
}

let meta = {};
try {
  meta = JSON.parse(row.meta_json || '{}');
} catch {
  console.error('meta_json is corrupt; refusing to overwrite.');
  process.exit(1);
}

const before = Array.isArray(meta.modules) ? meta.modules.slice() : null;
meta.modules = modulesArg;
raw
  .prepare('UPDATE connectors SET meta_json = ? WHERE id = ?')
  .run(JSON.stringify(meta), connectorId);

console.log(`Connector ${row.name} (${row.id})`);
console.log(`  modules before: ${JSON.stringify(before)}`);
console.log(`  modules after : ${JSON.stringify(meta.modules)}`);
