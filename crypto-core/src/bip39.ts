/**
 * @veil/crypto-core — BIP39 (24-word) mnemonic module.
 * Ported from the bundle: entropy is exactly 32 bytes; checksum is the first
 * byte of SHA-256(entropy) appended as a 33rd index byte; words encode 11 bits
 * each (24 words -> 264 bits -> 33 bytes). Standard BIP39 checksum semantics.
 */

import { utf8 } from './bytes';
import { sha256 } from './kdf';
import { BIP39_WORDLIST } from './bip39-wordlist';

function bitsToBytes(bits: string): Uint8Array {
  const bytes = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i += 8) {
    bytes[i / 8] = parseInt(bits.slice(i, i + 8), 2);
  }
  return bytes;
}

function bytesToBits(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(2).padStart(8, '0')).join('');
}

/** 32 bytes of entropy -> 24 words (rv() in the bundle). */
export async function entropyToWords(entropy: Uint8Array): Promise<string[]> {
  if (entropy.length !== 32) throw new Error('BIP39 needs exactly 32 bytes of entropy');
  const checksum = (await sha256(entropy))[0];
  const data = new Uint8Array(33);
  data.set(entropy, 0);
  data[32] = checksum;
  const bits = bytesToBits(data);
  const words: string[] = [];
  for (let i = 0; i < 264; i += 11) {
    words.push(BIP39_WORDLIST[parseInt(bits.slice(i, i + 11), 2)]);
  }
  return words;
}

export interface ParsedPhrase {
  words: string[];
  entropy: Uint8Array;
  checksum: number;
}

/** Lh: NFKD + lowercase + trim + split — the loose word normalizer. */
export function normalizeWords(phrase: string): string[] {
  return String(phrase || '').normalize('NFKD').toLowerCase().trim().split(/\s+/).filter(Boolean);
}

/** Hh: 24 words -> entropy + checksum. Throws the exact bundle errors. */
export function parsePhrase(phrase: string): ParsedPhrase {
  const words = normalizeWords(phrase);
  if (words.length !== 24) throw new Error(`A recovery phrase has exactly 24 words (got ${words.length}).`);
  const out = new Uint8Array(33);
  for (let i = 0; i < 24; i++) {
    const idx = BIP39_WORDLIST.indexOf(words[i]);
    if (idx === -1) throw new Error(`Unknown recovery word: "${words[i]}"`);
    for (let b = 0; b < 11; b++) {
      const bit = (idx >> (10 - b)) & 1;
      const a = i * 11 + b;
      if (bit) out[a >> 3] |= 1 << (7 - (a & 7));
    }
  }
  return { words, entropy: out.slice(0, 32), checksum: out[32] };
}

/** Validate phrase checksum (av() in the bundle). */
export async function validatePhrase(phrase: string): Promise<string[]> {
  const { words, entropy, checksum } = parsePhrase(phrase);
  if (checksum !== (await sha256(entropy))[0]) {
    throw new Error('This phrase is invalid — check every word.');
  }
  return words;
}

/** 512-bit BIP39 seed (ov() in the bundle). */
export async function phraseSeed(words: string[]): Promise<Uint8Array> {
  const material = utf8(words.join(' '));
  const key = await crypto.subtle.importKey('raw', material as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-512', salt: utf8('mnemonic') as BufferSource, iterations: 2048 },
    key,
    512,
  );
  return new Uint8Array(bits);
}
