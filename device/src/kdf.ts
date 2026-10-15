/**
 * @veil/device — PBKDF2-SHA256 with a native fast path (shared by vaults + stego).
 *
 * Contract: identical bytes to WebCrypto
 *   crypto.subtle.importKey('raw', utf8(pw), 'PBKDF2').deriveBits(...SHA-256, 32)
 * i.e. PBKDF2-HMAC-SHA256, single block, dkLen 32.
 *
 * Native: iOS CommonCrypto (local Expo module `veil-crypto`) computes it in
 * milliseconds. JS fallback = noble pbkdf2 (node tests, old dev clients) —
 * on-device Hermes this is slow (minutes at 600k), so the native path is the
 * real one; the fallback mirrors applock.ts's pre-b35 situation.
 */
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { utf8 } from '../../crypto-core/src/index';

const toHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string): Uint8Array =>
  new Uint8Array(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));

export const VAULT_PBKDF2_ITERATIONS = 600000;
export const VAULT_KDF_LABEL = 'PBKDF2-SHA256-600000';

type NativeVeilCrypto = { pbkdf2Sha256(password: string, saltHex: string, iterations: number, dkLen: number): Promise<string> };

let fallbackLogged = false;

function getNativeCrypto(): NativeVeilCrypto | null {
  try {
    // b51 FIX (Sept 19): this used to read NativeModulesProxy.VeilCrypto — the
    // legacy unimodules bridge. Our veil-crypto module is a modern Expo module
    // and is ONLY exposed via requireNativeModule('VeilCrypto'). The proxy
    // lookup silently returned undefined, so every vault unlock/create and
    // stego passphrase encryption ran the 600k-iteration JS PBKDF2 on Hermes
    // — minutes per operation. Same bug class as the applock.ts b45 fix.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireNativeModule?: <T>(name: string) => T };
    if (typeof emc?.requireNativeModule !== 'function') {
      if (!fallbackLogged) { fallbackLogged = true; console.log('[veil-kdf] no requireNativeModule export — vaults/stego on slow JS pbkdf2'); }
      return null;
    }
    const mod = emc.requireNativeModule<NativeVeilCrypto>('VeilCrypto');
    if (typeof mod?.pbkdf2Sha256 !== 'function') {
      if (!fallbackLogged) { fallbackLogged = true; console.log('[veil-kdf] VeilCrypto resolved but pbkdf2Sha256 missing — slow JS pbkdf2'); }
      return null;
    }
    return mod;
  } catch {
    // tests / no native module compiled in yet -> JS fallback
    if (!fallbackLogged) { fallbackLogged = true; console.log('[veil-kdf] requireNativeModule threw — vaults/stego on slow JS pbkdf2'); }
    return null;
  }
}

/**
 * PBKDF2-SHA256 → raw key bytes. Byte-identical to the web $E() deriveKey
 * (same algorithm, same 256-bit output). Native-first.
 */
export async function pbkdf2Sha256Bytes(
  password: string,
  salt: Uint8Array,
  iterations: number,
  dkLen = 32,
): Promise<Uint8Array> {
  const native = getNativeCrypto();
  if (native) {
    const t0 = Date.now();
    try {
      const hex = await native.pbkdf2Sha256(password, toHex(salt), iterations, dkLen);
      console.log(`[veil-kdf] pbkdf2 done NATIVE in ${Date.now() - t0} ms`);
      return fromHex(hex);
    } catch (e) {
      console.log('[veil-kdf] native pbkdf2 failed, falling back to JS:', String(e));
    }
  }
  return pbkdf2(sha256, utf8(password), salt, { c: iterations, dkLen });
}

/** AES-GCM-256 CryptoKey from raw key bytes (works under WebCrypto + noble shim). */
export async function aesGcmKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', keyBytes as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
