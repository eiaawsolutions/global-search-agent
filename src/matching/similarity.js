// String-similarity primitives. Pure functions, no dependencies — keeping
// these in-repo means the matching logic is fully auditable and identical
// across environments. All return a score in [0, 1].

// Levenshtein edit distance (iterative, two-row — O(n) memory).
export function levenshtein(a, b) {
  a = a || '';
  b = b || '';
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = new Array(b.length + 1);
  let curr = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1] + 1, // insertion
        prev[j] + 1, // deletion
        prev[j - 1] + cost // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

// Normalized Levenshtein similarity → 1 = identical, 0 = fully different.
export function levenshteinSim(a, b) {
  a = a || '';
  b = b || '';
  if (!a.length && !b.length) return 1;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  return 1 - levenshtein(a, b) / maxLen;
}

// Jaro similarity.
function jaro(a, b) {
  a = a || '';
  b = b || '';
  if (a === b) return 1;
  if (!a.length || !b.length) return 0;
  const matchWindow = Math.max(0, Math.floor(Math.max(a.length, b.length) / 2) - 1);
  const aMatches = new Array(a.length).fill(false);
  const bMatches = new Array(b.length).fill(false);
  let matches = 0;
  for (let i = 0; i < a.length; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(i + matchWindow + 1, b.length);
    for (let j = start; j < end; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = bMatches[j] = true;
      matches++;
      break;
    }
  }
  if (matches === 0) return 0;
  // Count transpositions.
  let k = 0;
  let transpositions = 0;
  for (let i = 0; i < a.length; i++) {
    if (!aMatches[i]) continue;
    while (!bMatches[k]) k++;
    if (a[i] !== b[k]) transpositions++;
    k++;
  }
  transpositions /= 2;
  return (
    (matches / a.length +
      matches / b.length +
      (matches - transpositions) / matches) /
    3
  );
}

// Jaro-Winkler — boosts scores for strings sharing a common prefix. This is
// the best general-purpose name/company comparator: tolerant of typos and
// truncations, strong on human names.
export function jaroWinkler(a, b, prefixScale = 0.1) {
  a = a || '';
  b = b || '';
  const j = jaro(a, b);
  if (j < 0.7) return j; // only boost already-similar strings
  let prefix = 0;
  const maxPrefix = Math.min(4, a.length, b.length);
  for (let i = 0; i < maxPrefix; i++) {
    if (a[i] === b[i]) prefix++;
    else break;
  }
  return j + prefix * prefixScale * (1 - j);
}

// Token-sort ratio: sort the words of each string before comparing, so word
// order stops mattering ("Jane Doe" vs "Doe Jane", "Acme Global" vs
// "Global Acme"). Returns the Jaro-Winkler of the sorted forms.
export function tokenSortRatio(a, b) {
  const sortTokens = (s) =>
    (s || '').split(/\s+/).filter(Boolean).sort().join(' ');
  return jaroWinkler(sortTokens(a), sortTokens(b));
}

// Token-set containment — handles partial names ("John Smith" vs
// "John Michael Smith") and abbreviated companies ("Acme" vs "Acme Global
// Trading"). The score is the geometric mean of two ratios:
//   precision = overlap / smaller set   (how much of the short string matched)
//   recall    = overlap / larger set    (how much of the long string matched)
// Using BOTH is deliberate: a subset that fully matches the short string but
// covers only a fraction of the long one ("Acme" inside "Acme Global
// Trading") must NOT score 1.0 — containment is evidence of similarity, not
// proof of equivalence. The geometric mean keeps full equality at 1.0 while
// pulling small-subset matches down into "review" territory.
export function tokenContainment(a, b) {
  const setA = new Set((a || '').split(/\s+/).filter(Boolean));
  const setB = new Set((b || '').split(/\s+/).filter(Boolean));
  if (!setA.size || !setB.size) return 0;
  const [small, large] = setA.size <= setB.size ? [setA, setB] : [setB, setA];
  let hit = 0;
  for (const t of small) if (large.has(t)) hit++;
  if (hit === 0) return 0;
  const precision = hit / small.size;
  const recall = hit / large.size;
  return Math.sqrt(precision * recall);
}
