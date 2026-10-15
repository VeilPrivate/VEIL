/**
 * @veil/crypto-core — padded plaintext buckets + cover framing (ub()/db() in the bundle).
 * Frame: [1 byte cover flag][2 bytes big-endian length][plaintext][zero padding]
 * Bucket sizes: 1024 / 4096. Larger payloads throw.
 */

import { utf8, fromUtf8 } from './bytes';
import { PAD_FRAME_HEADER_BYTES, PADDED_BUCKETS } from './constants';

export function padPlaintext(text: string, cover: boolean): Uint8Array {
  const payload = utf8(text);
  const total = PAD_FRAME_HEADER_BYTES + payload.length;
  const bucket = PADDED_BUCKETS.find((b) => b >= total);
  if (!bucket) throw new Error('Message too long for the padded bucket sizes');
  const frame = new Uint8Array(bucket);
  frame[0] = cover ? 1 : 0;
  new DataView(frame.buffer).setUint16(1, payload.length);
  frame.set(payload, PAD_FRAME_HEADER_BYTES);
  return frame;
}

/**
 * b197 (audit M-4): split text into chunks that each fit the largest padded
 * bucket, at UTF-8-safe code-point boundaries (a surrogate pair or multi-byte
 * character is never split). No-op for messages that already fit.
 */
export function splitForBuckets(text: string): string[] {
  const max = PADDED_BUCKETS[PADDED_BUCKETS.length - 1] - PAD_FRAME_HEADER_BYTES;
  if (utf8(text).length <= max) return [text];
  const enc = new TextEncoder();
  const chunks: string[] = [];
  let cur = '';
  let curBytes = 0;
  for (const ch of Array.from(text)) { // code points — surrogate-safe
    const b = enc.encode(ch).length;
    if (curBytes + b > max && cur) { chunks.push(cur); cur = ''; curBytes = 0; }
    cur += ch;
    curBytes += b;
  }
  if (cur) chunks.push(cur);
  return chunks;
}

export function unpadPlaintext(bytes: Uint8Array): { cover: boolean; text: string } {
  if (bytes.length < PAD_FRAME_HEADER_BYTES) throw new Error('Corrupted message payload');
  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(1);
  if (PAD_FRAME_HEADER_BYTES + len > bytes.length) throw new Error('Corrupted message payload');
  return {
    cover: bytes[0] === 1,
    text: fromUtf8(bytes.subarray(PAD_FRAME_HEADER_BYTES, PAD_FRAME_HEADER_BYTES + len)),
  };
}
