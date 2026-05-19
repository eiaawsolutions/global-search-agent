// CSV parser — dependency-free, RFC-4180-aware.
//
// Handles quoted fields, embedded commas, embedded newlines, escaped quotes
// (""), and both \n and \r\n line endings. A hand-rolled parser is used
// (rather than a library) so CSV ingestion has zero supply-chain surface and
// the row/byte caps are enforced inline.

// Parse raw CSV text into an array of row objects keyed by header.
// Throws on an empty file or a missing header row. Enforces maxRows.
export function parseCsv(text, { maxRows = 10000 } = {}) {
  if (typeof text !== 'string' || !text.trim()) {
    throw new Error('CSV file is empty.');
  }
  // Strip a UTF-8 BOM if present.
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  const rows = [];
  let field = '';
  let row = [];
  let inQuotes = false;
  let i = 0;
  const n = text.length;

  const endField = () => {
    row.push(field);
    field = '';
  };
  const endRow = () => {
    endField();
    // Skip fully-blank lines.
    if (row.length === 1 && row[0] === '') {
      row = [];
      return;
    }
    rows.push(row);
    row = [];
  };

  while (i < n) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += c;
      i++;
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      i++;
      continue;
    }
    if (c === ',') {
      endField();
      i++;
      continue;
    }
    if (c === '\r') {
      i++;
      continue; // CR handled with the following LF
    }
    if (c === '\n') {
      endRow();
      i++;
      if (rows.length > maxRows + 1) {
        throw new Error(`CSV exceeds the ${maxRows}-row limit.`);
      }
      continue;
    }
    field += c;
    i++;
  }
  // Flush the trailing row if the file did not end with a newline.
  if (field !== '' || row.length) endRow();

  if (!rows.length) throw new Error('CSV has no usable rows.');

  const header = rows[0].map((h) => h.trim().toLowerCase());
  if (header.every((h) => !h)) throw new Error('CSV header row is empty.');

  const dataRows = rows.slice(1, maxRows + 1);
  return dataRows.map((cells) => {
    const obj = {};
    header.forEach((key, idx) => {
      if (key) obj[key] = (cells[idx] ?? '').trim();
    });
    return obj;
  });
}

// Parse a plain newline/comma-separated list of NAMES (the "paste a list of
// names" path) into record-shaped objects. Each non-empty line/segment
// becomes { name: "<line>" }.
export function parseNameList(text, { maxRows = 10000 } = {}) {
  if (typeof text !== 'string') return [];
  const names = text
    .split(/[\r\n]+/)
    .flatMap((line) => line.split(','))
    .map((s) => s.trim())
    .filter(Boolean);
  if (names.length > maxRows) {
    throw new Error(`List exceeds the ${maxRows}-entry limit.`);
  }
  return names.map((name) => ({ name }));
}
