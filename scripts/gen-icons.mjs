/**
 * Generates the PhishGuard shield icons as RGBA PNGs without any image
 * library, by rasterizing a shield silhouette pixel-by-pixel and writing
 * raw PNG chunks. Good enough for development and store screenshots;
 * swap in designed artwork any time by replacing public/icons/*.png.
 */
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';

const crcTable = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/** Half-width of the shield at vertical position t ∈ [0,1] (0 = top). */
function shieldHalfWidth(t, w0) {
  if (t < 0.45) return w0;
  return w0 * Math.cos(((t - 0.45) / 0.55) * (Math.PI / 2)) ** 0.9;
}

/** Signed "insideness" of a pixel, with supersampling for soft edges. */
function coverage(x, y, size) {
  const top = 0.06 * size;
  const bottom = 0.97 * size;
  const w0 = 0.42 * size;
  const cx = size / 2;
  let hits = 0;
  const SS = 3;
  for (let sy = 0; sy < SS; sy++) {
    for (let sx = 0; sx < SS; sx++) {
      const px = x + (sx + 0.5) / SS;
      const py = y + (sy + 0.5) / SS;
      const t = (py - top) / (bottom - top);
      if (t < 0 || t > 1) continue;
      if (Math.abs(px - cx) <= shieldHalfWidth(t, w0)) hits++;
    }
  }
  return hits / (SS * SS);
}

/** Check-mark stroke distance test (in shield-local coordinates). */
function inCheck(x, y, size) {
  const p = [x / size, y / size];
  const a = [0.32, 0.46];
  const b = [0.45, 0.60];
  const c = [0.70, 0.30];
  const w = 0.055;
  const distSeg = (p, s, e) => {
    const dx = e[0] - s[0];
    const dy = e[1] - s[1];
    const t = Math.max(0, Math.min(1, ((p[0] - s[0]) * dx + (p[1] - s[1]) * dy) / (dx * dx + dy * dy)));
    return Math.hypot(p[0] - (s[0] + t * dx), p[1] - (s[1] + t * dy));
  };
  return Math.min(distSeg(p, a, b), distSeg(p, b, c)) < w;
}

function png(size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type: RGBA
  const rows = [];
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let x = 0; x < size; x++) {
      const cov = coverage(x, y, size);
      if (cov === 0) continue;
      const o = 1 + x * 4;
      if (size >= 32 && inCheck(x, y, size)) {
        row[o] = 255; row[o + 1] = 255; row[o + 2] = 255;
      } else {
        // Vertical gradient blue
        const g = y / size;
        row[o] = Math.round(27 + 14 * g);
        row[o + 1] = Math.round(108 - 30 * g);
        row[o + 2] = Math.round(196 - 40 * g);
      }
      row[o + 3] = Math.round(255 * cov);
    }
    rows.push(row);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(Buffer.concat(rows))),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

mkdirSync('public/icons', { recursive: true });
for (const size of [16, 32, 48, 128]) {
  writeFileSync(`public/icons/icon-${size}.png`, png(size));
}
console.log('icons generated');
