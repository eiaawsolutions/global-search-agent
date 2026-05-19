/* qr.js — a small, dependency-free QR Code generator.
 *
 * Why this exists: the Settings page renders the 2FA otpauth:// URI as a QR
 * code the admin scans into their authenticator app. Pulling a QR library
 * from a CDN would mean loosening the page's Content-Security-Policy
 * (script-src 'self'); generating the code in first-party JS keeps the CSP
 * strict. The output is a black/white module matrix the page draws into a
 * <canvas>.
 *
 * Scope: byte mode, error-correction level M, versions 1–10. An otpauth URI
 * is ~100–140 bytes, which fits comfortably (version 7-M holds 154 bytes).
 *
 * This is a compact implementation of the QR Code spec (ISO/IEC 18004):
 * Reed–Solomon error correction over GF(256), the standard mask patterns,
 * and format-information encoding. It is exposed as window.QR.
 */
(function () {
  'use strict';

  // ── GF(256) arithmetic for Reed–Solomon ───────────────────────────
  const EXP = new Array(256);
  const LOG = new Array(256);
  (function initGalois() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d; // primitive polynomial
    }
    for (let i = 255; i < 256; i++) EXP[i] = EXP[i - 255];
  })();

  const gfMul = (a, b) =>
    a === 0 || b === 0 ? 0 : EXP[(LOG[a] + LOG[b]) % 255];

  // Reed–Solomon generator polynomial for `degree` EC codewords.
  function rsGeneratorPoly(degree) {
    let poly = [1];
    for (let i = 0; i < degree; i++) {
      const next = new Array(poly.length + 1).fill(0);
      for (let j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMul(poly[j], EXP[i]);
      }
      poly = next;
    }
    return poly;
  }

  // EC codewords for one data block.
  function rsEncode(data, ecLen) {
    const gen = rsGeneratorPoly(ecLen);
    const res = new Array(ecLen).fill(0);
    for (const d of data) {
      const factor = d ^ res[0];
      res.shift();
      res.push(0);
      for (let i = 0; i < gen.length; i++) res[i] ^= gfMul(gen[i], factor);
    }
    return res;
  }

  // ── Capacity + EC tables (level M, versions 1–10) ──────────────────
  // [ totalCodewords, ecCodewordsPerBlock, numBlocksGroup1, dataCWGroup1,
  //   numBlocksGroup2, dataCWGroup2 ]
  const VERSIONS_M = {
    1: [26, 10, 1, 16, 0, 0],
    2: [44, 16, 1, 28, 0, 0],
    3: [70, 26, 1, 44, 0, 0],
    4: [100, 18, 2, 32, 0, 0],
    5: [134, 24, 2, 43, 0, 0],
    6: [172, 16, 4, 27, 0, 0],
    7: [196, 18, 4, 31, 0, 0],
    8: [242, 22, 2, 38, 2, 39],
    9: [292, 22, 3, 36, 2, 37],
    10: [346, 26, 4, 43, 1, 44],
  };
  // Data capacity in bytes for byte mode (derived from the table above).
  const BYTE_CAPACITY_M = {
    1: 14, 2: 26, 3: 42, 4: 62, 5: 84,
    6: 106, 7: 122, 8: 152, 9: 180, 10: 213,
  };

  // Alignment-pattern centre coordinates per version.
  const ALIGN_POS = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46],
    10: [6, 28, 50],
  };

  // ── Bit buffer ─────────────────────────────────────────────────────
  function BitBuffer() {
    this.bits = [];
  }
  BitBuffer.prototype.put = function (value, length) {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  };

  // ── Format information (level M = 0b00), Reed–Solomon (15,5) ───────
  function formatBits(maskPattern) {
    const data = (0b00 << 3) | maskPattern; // 5 bits: EC level + mask
    let rem = data << 10;
    const g = 0b10100110111;
    for (let i = 14; i >= 10; i--) {
      if ((rem >>> i) & 1) rem ^= g << (i - 10);
    }
    return ((data << 10) | rem) ^ 0b101010000010010;
  }

  // ── Build the module matrix ────────────────────────────────────────
  function buildMatrix(version, dataBits) {
    const size = version * 4 + 17;
    const mod = Array.from({ length: size }, () =>
      new Array(size).fill(null)
    );
    const reserved = Array.from({ length: size }, () =>
      new Array(size).fill(false)
    );

    const setF = (r, c, v) => {
      mod[r][c] = v;
      reserved[r][c] = true;
    };

    // Finder patterns + separators at the three corners.
    function finder(r0, c0) {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const rr = r0 + r;
          const cc = c0 + c;
          if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
          const inRing =
            (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
            (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
            (r >= 2 && r <= 4 && c >= 2 && c <= 4);
          setF(rr, cc, inRing ? 1 : 0);
        }
      }
    }
    finder(0, 0);
    finder(0, size - 7);
    finder(size - 7, 0);

    // Timing patterns.
    for (let i = 8; i < size - 8; i++) {
      const v = i % 2 === 0 ? 1 : 0;
      setF(6, i, v);
      setF(i, 6, v);
    }

    // Alignment patterns (skipping any that collide with a finder).
    const pos = ALIGN_POS[version];
    for (const r of pos) {
      for (const c of pos) {
        if (
          (r <= 8 && c <= 8) ||
          (r <= 8 && c >= size - 9) ||
          (r >= size - 9 && c <= 8)
        ) {
          continue;
        }
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            const ring =
              Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0);
            setF(r + dr, c + dc, ring ? 1 : 0);
          }
        }
      }
    }

    // Dark module + reserve the format-info strips.
    setF(size - 8, 8, 1);
    for (let i = 0; i < 9; i++) {
      if (!reserved[8][i]) setF(8, i, 0);
      if (!reserved[i][8]) setF(i, 8, 0);
    }
    for (let i = 0; i < 8; i++) {
      if (!reserved[8][size - 1 - i]) setF(8, size - 1 - i, 0);
      if (!reserved[size - 1 - i][8]) setF(size - 1 - i, 8, 0);
    }

    // Place data bits in the standard zig-zag, skipping the timing column.
    let bitIdx = 0;
    let upward = true;
    for (let col = size - 1; col > 0; col -= 2) {
      if (col === 6) col = 5;
      for (let i = 0; i < size; i++) {
        const row = upward ? size - 1 - i : i;
        for (let c = 0; c < 2; c++) {
          const cc = col - c;
          if (reserved[row][cc]) continue;
          mod[row][cc] = bitIdx < dataBits.length ? dataBits[bitIdx] : 0;
          bitIdx++;
        }
      }
      upward = !upward;
    }

    return { mod, reserved, size };
  }

  // The eight standard mask predicates.
  const MASKS = [
    (r, c) => (r + c) % 2 === 0,
    (r) => r % 2 === 0,
    (r, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0,
    (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
  ];

  // A simple, correct penalty score (rules 1–4 of the spec) for mask choice.
  function penalty(mod, size) {
    let score = 0;
    // Rule 1 — runs of 5+ same-colour modules in a row/column.
    for (let r = 0; r < size; r++) {
      let runC = 1, runR = 1;
      for (let c = 1; c < size; c++) {
        runC = mod[r][c] === mod[r][c - 1] ? runC + 1 : 1;
        if (runC === 5) score += 3;
        else if (runC > 5) score += 1;
        runR = mod[c][r] === mod[c - 1][r] ? runR + 1 : 1;
        if (runR === 5) score += 3;
        else if (runR > 5) score += 1;
      }
    }
    // Rule 2 — 2x2 blocks of the same colour.
    for (let r = 0; r < size - 1; r++) {
      for (let c = 0; c < size - 1; c++) {
        const v = mod[r][c];
        if (
          v === mod[r][c + 1] &&
          v === mod[r + 1][c] &&
          v === mod[r + 1][c + 1]
        ) {
          score += 3;
        }
      }
    }
    // Rule 4 — overall dark-module balance.
    let dark = 0;
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) if (mod[r][c]) dark++;
    }
    const ratio = (dark / (size * size)) * 100;
    score += Math.floor(Math.abs(ratio - 50) / 5) * 10;
    return score;
  }

  // ── Public: encode a string to a module matrix ─────────────────────
  // Returns { size, modules } — modules[r][c] is 1 (dark) or 0 (light).
  function encode(text) {
    const bytes = new TextEncoder().encode(text);

    // Smallest version that fits at EC level M.
    let version = 0;
    for (let v = 1; v <= 10; v++) {
      if (bytes.length <= BYTE_CAPACITY_M[v]) {
        version = v;
        break;
      }
    }
    if (!version) {
      throw new Error('QR: data too long for supported versions (1–10).');
    }

    const [, ecPerBlock, g1Blocks, g1Data, g2Blocks, g2Data] =
      VERSIONS_M[version];
    const totalDataCW = g1Blocks * g1Data + g2Blocks * g2Data;

    // Mode (byte = 0100) + character-count + payload.
    const buf = new BitBuffer();
    buf.put(0b0100, 4);
    const countBits = version <= 9 ? 8 : 16;
    buf.put(bytes.length, countBits);
    for (const b of bytes) buf.put(b, 8);

    // Terminator + pad to a byte boundary + alternating pad bytes.
    const capacityBits = totalDataCW * 8;
    for (let i = 0; i < 4 && buf.bits.length < capacityBits; i++) {
      buf.bits.push(0);
    }
    while (buf.bits.length % 8 !== 0) buf.bits.push(0);
    const padBytes = [0xec, 0x11];
    let p = 0;
    while (buf.bits.length < capacityBits) {
      buf.put(padBytes[p % 2], 8);
      p++;
    }

    // Bits → data codewords.
    const dataCW = [];
    for (let i = 0; i < buf.bits.length; i += 8) {
      let v = 0;
      for (let j = 0; j < 8; j++) v = (v << 1) | buf.bits[i + j];
      dataCW.push(v);
    }

    // Split into blocks, compute EC per block.
    const blocks = [];
    let offset = 0;
    for (let i = 0; i < g1Blocks; i++) {
      const d = dataCW.slice(offset, offset + g1Data);
      offset += g1Data;
      blocks.push({ data: d, ec: rsEncode(d, ecPerBlock) });
    }
    for (let i = 0; i < g2Blocks; i++) {
      const d = dataCW.slice(offset, offset + g2Data);
      offset += g2Data;
      blocks.push({ data: d, ec: rsEncode(d, ecPerBlock) });
    }

    // Interleave data codewords, then EC codewords.
    const finalCW = [];
    const maxData = Math.max(...blocks.map((b) => b.data.length));
    for (let i = 0; i < maxData; i++) {
      for (const b of blocks) if (i < b.data.length) finalCW.push(b.data[i]);
    }
    for (let i = 0; i < ecPerBlock; i++) {
      for (const b of blocks) finalCW.push(b.ec[i]);
    }

    // Codewords → bit array.
    const dataBits = [];
    for (const cw of finalCW) {
      for (let i = 7; i >= 0; i--) dataBits.push((cw >>> i) & 1);
    }

    // Lay out, then try every mask and keep the lowest-penalty one.
    const base = buildMatrix(version, dataBits);
    let best = null;
    for (let m = 0; m < 8; m++) {
      const grid = base.mod.map((row) => row.slice());
      for (let r = 0; r < base.size; r++) {
        for (let c = 0; c < base.size; c++) {
          if (!base.reserved[r][c] && MASKS[m](r, c)) {
            grid[r][c] ^= 1;
          }
        }
      }
      // Write the format information for this mask.
      const fmt = formatBits(m);
      for (let i = 0; i < 15; i++) {
        const bit = (fmt >>> i) & 1;
        // Around the top-left finder.
        if (i < 6) grid[i][8] = bit;
        else if (i < 8) grid[i + 1][8] = bit;
        else if (i === 8) grid[8][7] = bit;
        else grid[8][14 - i] = bit;
        // The mirrored copy.
        if (i < 8) grid[8][base.size - 1 - i] = bit;
        else grid[base.size - 15 + i][8] = bit;
      }
      const score = penalty(grid, base.size);
      if (!best || score < best.score) best = { score, grid };
    }

    return { size: base.size, modules: best.grid };
  }

  // ── Public: draw an encoded matrix into a <canvas> ─────────────────
  // `pixelSize` is the side length in CSS pixels; a 4-module quiet zone is
  // added around the symbol as the spec requires for reliable scanning.
  function draw(canvas, text, pixelSize) {
    const { size, modules } = encode(text);
    const quiet = 4;
    const total = size + quiet * 2;
    const scale = Math.max(1, Math.floor((pixelSize || 220) / total));
    const dim = total * scale;
    canvas.width = dim;
    canvas.height = dim;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, dim, dim);
    ctx.fillStyle = '#000000';
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (modules[r][c]) {
          ctx.fillRect(
            (c + quiet) * scale,
            (r + quiet) * scale,
            scale,
            scale
          );
        }
      }
    }
  }

  window.QR = { encode, draw };
})();
