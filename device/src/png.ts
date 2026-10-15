/**
 * @veil/device — minimal pure-TS PNG codec for steganography.
 *
 * The web embeds/extracts through a 2D canvas (any carrier image type). The
 * native shell has no canvas pixel access, so we decode/encode PNG ourselves:
 *   decode: 8-bit, colour types 0 (gray), 2 (RGB), 3 (palette), 4 (gray+a),
 *   6 (RGBA); no interlace. Output is always RGBA.
 *   encode: RGBA, filter 0 rows, zlib (pako). Valid PNG readable by any
 *   decoder — including the web canvas, so native-embedded images extract
 *   on the web and vice versa (the LSB payload is byte-identical).
 */
import { inflate as pakoInflate, deflate as pakoDeflate } from 'pako';

export interface PngImage {
  width: number;
  height: number;
  /** RGBA, 4 bytes/pixel, row-major */
  rgba: Uint8Array;
}

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

let CRC_TABLE: Uint32Array | null = null;
function crcTable(): Uint32Array {
  if (CRC_TABLE) return CRC_TABLE;
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  CRC_TABLE = t;
  return t;
}
function crc32(bytes: Uint8Array): number {
  const t = crcTable();
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = t[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function readU32(b: Uint8Array, o: number): number {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}

/** Un-filter one scanline in place (PNG filters 0-4). */
function unfilter(raw: Uint8Array, bpp: number, row: Uint8Array, prev: Uint8Array, stride: number): void {
  const type = raw[0];
  const data = raw.subarray(1, 1 + stride);
  switch (type) {
    case 0:
      row.set(data);
      break;
    case 1: // Sub
      for (let i = 0; i < stride; i++) {
        row[i] = (data[i] + (i >= bpp ? row[i - bpp] : 0)) & 0xff;
      }
      break;
    case 2: // Up
      for (let i = 0; i < stride; i++) {
        row[i] = (data[i] + prev[i]) & 0xff;
      }
      break;
    case 3: // Average
      for (let i = 0; i < stride; i++) {
        row[i] = (data[i] + (((i >= bpp ? row[i - bpp] : 0) + prev[i]) >> 1)) & 0xff;
      }
      break;
    case 4: // Paeth
      for (let i = 0; i < stride; i++) {
        const a = i >= bpp ? row[i - bpp] : 0;
        const b = prev[i];
        const c = i >= bpp ? prev[i - bpp] : 0;
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        const pred = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
        row[i] = (data[i] + pred) & 0xff;
      }
      break;
    default:
      throw new Error('Corrupted PNG: unknown filter');
  }
}

export function decodePng(bytes: Uint8Array): PngImage {
  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== PNG_SIG[i]) throw new Error('Not a PNG file');
  }
  let pos = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let interlace = 0;
  let palette: Uint8Array | null = null;
  let trns: Uint8Array | null = null;
  const idat: Uint8Array[] = [];
  while (pos + 8 <= bytes.length) {
    const len = readU32(bytes, pos);
    const type = String.fromCharCode(bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7]);
    const data = bytes.subarray(pos + 8, pos + 8 + len);
    if (type === 'IHDR') {
      width = readU32(data, 0);
      height = readU32(data, 4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === 'PLTE') {
      palette = data;
    } else if (type === 'tRNS') {
      trns = data;
    } else if (type === 'IDAT') {
      idat.push(data);
    } else if (type === 'IEND') {
      break;
    }
    pos += 12 + len;
  }
  if (!width || !height) throw new Error('Corrupted PNG: no IHDR');
  if (bitDepth !== 8) throw new Error('Unsupported PNG: only 8-bit images are supported');
  if (interlace) throw new Error('Unsupported PNG: interlaced images are not supported');

  let channels: number;
  switch (colorType) {
    case 0: channels = 1; break; // gray
    case 2: channels = 3; break; // RGB
    case 3: channels = 1; break; // palette index
    case 4: channels = 2; break; // gray + alpha
    case 6: channels = 4; break; // RGBA
    default: throw new Error('Unsupported PNG colour type');
  }

  const idatLen = idat.reduce((n, c) => n + c.length, 0);
  const idatBytes = new Uint8Array(idatLen);
  let off = 0;
  for (const c of idat) {
    idatBytes.set(c, off);
    off += c.length;
  }
  const raw = pakoInflate(idatBytes) as Uint8Array;

  const stride = width * channels;
  const rgba = new Uint8Array(width * height * 4);
  const row = new Uint8Array(stride);
  const prev = new Uint8Array(stride);
  const bpp = channels;
  for (let y = 0; y < height; y++) {
    const rawRow = raw.subarray(y * (stride + 1), (y + 1) * (stride + 1));
    unfilter(rawRow, bpp, row, prev, stride);
    for (let x = 0; x < width; x++) {
      const ri = x * channels;
      const wi = (y * width + x) * 4;
      if (colorType === 0) {
        rgba[wi] = rgba[wi + 1] = rgba[wi + 2] = row[ri];
        rgba[wi + 3] = 255;
      } else if (colorType === 2) {
        rgba[wi] = row[ri];
        rgba[wi + 1] = row[ri + 1];
        rgba[wi + 2] = row[ri + 2];
        rgba[wi + 3] = 255;
      } else if (colorType === 3) {
        const pi = row[ri] * 3;
        const p = palette as Uint8Array;
        rgba[wi] = p[pi];
        rgba[wi + 1] = p[pi + 1];
        rgba[wi + 2] = p[pi + 2];
        rgba[wi + 3] = trns && row[ri] < trns.length ? trns[row[ri]] : 255;
      } else if (colorType === 4) {
        rgba[wi] = rgba[wi + 1] = rgba[wi + 2] = row[ri];
        rgba[wi + 3] = row[ri + 1];
      } else {
        rgba[wi] = row[ri];
        rgba[wi + 1] = row[ri + 1];
        rgba[wi + 2] = row[ri + 2];
        rgba[wi + 3] = row[ri + 3];
      }
    }
    prev.set(row);
  }
  return { width, height, rgba };
}

/**
 * (b57 FIX) The old encoder built the PNG as a JS number[] using
 * `out.push(...body)` — spreading a MULTI-MEGABYTE IDAT chunk as function
 * arguments blew the Hermes stack ("Maximum call stack size exceeded") on
 * any real carrier photo. This version writes into ONE preallocated
 * Uint8Array; no spread, no number[], no size ceiling.
 */
function chunkInto(out: Uint8Array, off: number, type: string, data: Uint8Array): number {
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(off, data.length);
  for (let i = 0; i < 4; i++) out[off + 4 + i] = type.charCodeAt(i);
  out.set(data, off + 8);
  // CRC covers exactly the type+data span
  view.setUint32(off + 8 + data.length, crc32(out.subarray(off + 4, off + 8 + data.length)));
  return 8 + data.length + 4; // len + type + data + crc
}

function chunkSize(data: Uint8Array): number {
  return 8 + data.length + 4;
}

export function encodePng(img: PngImage): Uint8Array {
  const { width, height, rgba } = img;
  const stride = width * 4;
  // filter 0 rows: 1 filter byte + RGBA bytes per scanline
  const raw = new Uint8Array(height * (stride + 1));
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    raw.set(rgba.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
  }
  // b111: level 1 — level 6 on multi-MB RGBA in pure-JS pako under Hermes (no
  // JIT) took tens of seconds on a full-res photo; level 1 is several times
  // faster and the PNG is only marginally larger. Payload is unaffected: the
  // LSB stream is byte-identical regardless of PNG compression level.
  const compressed = pakoDeflate(raw, { level: 1 }) as Uint8Array;

  const ihdr = new Uint8Array(13);
  new DataView(ihdr.buffer).setUint32(0, width);
  new DataView(ihdr.buffer).setUint32(4, height);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type RGBA

  const total = PNG_SIG.length + chunkSize(ihdr) + chunkSize(compressed) + chunkSize(new Uint8Array(0));
  const out = new Uint8Array(total);
  out.set(new Uint8Array(PNG_SIG), 0);
  let off = PNG_SIG.length;
  off += chunkInto(out, off, 'IHDR', ihdr);
  off += chunkInto(out, off, 'IDAT', compressed);
  off += chunkInto(out, off, 'IEND', new Uint8Array(0));
  if (off !== total) throw new Error('png: encoder size mismatch');
  return out;
}
