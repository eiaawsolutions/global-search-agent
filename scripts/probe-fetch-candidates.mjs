// Call our Vistage adapter's fetchCandidates() directly with a chosen query
// and print everything it returns. Helps tell the difference between
// "Vistage doesn't return rows for our query" vs "Vistage returns rows
// but we drop them in canonicalization".
//
// Usage:
//   node scripts/probe-fetch-candidates.mjs "Levina Chin Lee Peng"
import { raw as db } from '../src/db/index.js';
import { fetchCandidates } from '../src/connectors/vistage.js';

const name = process.argv[2] || 'Levina Chin Lee Peng';
const connector = db.prepare(`SELECT * FROM connectors WHERE kind='vistage' LIMIT 1`).get();
if (!connector) {
  console.error('No vistage connector in DB');
  process.exit(1);
}
console.log(`Using connector ${connector.id}  base_url=${connector.base_url}`);
console.log(`Query: name=${JSON.stringify(name)}\n`);

const rows = await fetchCandidates(connector, { name }, ['name'], 200, {});
console.log(`fetchCandidates returned ${rows.length} candidate row(s):`);
for (const r of rows) {
  console.log(`  module=${r.raw._vistage_module}  id=${r.raw.id || r.raw.Id}  canonical.name=${JSON.stringify(r.canonical.name)}  name1=${JSON.stringify(r.raw.name1)}  name2=${JSON.stringify(r.raw.name2)}  cell.FullName=${JSON.stringify(r.raw.cell?.FullName)}`);
}
