/**
 * @veil/device — b93 P2 anti-forensics: overwrite-before-delete.
 *
 * The Sept 20 roadmap item: duress + sign-out wipes must OVERWRITE key
 * material, not just dereference it. A bare `remove()` is a logical delete —
 * on iOS the backing store (SQLite/MMKV/keychain-backed adapter) keeps the
 * plaintext bytes in its file until the region is reused, so a Cellebrite-
 * class logical extraction of the store file reads the "deleted" keyvault,
 * session keys and ratchet states verbatim.
 *
 * `secureRemove` first rewrites the key's value IN PLACE with a same-length
 * block of zeroes — forcing the storage engine to overwrite the stored
 * record with junk — and only then deletes the key. After the pass the
 * store file contains zeros where the key material lived, not the keys.
 * (Flash wear-leveling still applies below the file layer; this closes the
 * application-layer gap, which is what a logical forensic extraction sees.)
 *
 * Best-effort by design: a failed overwrite still proceeds to the delete,
 * and callers under duress must never be blocked by a storage hiccup.
 */

import type { VeilStorage } from '../../crypto-core/src/index';

/** Zero-fill a key in place, then delete it. */
export async function secureRemove(storage: VeilStorage, key: string): Promise<void> {
  let len = 0;
  try {
    const cur = await storage.get(key);
    if (typeof cur === 'string') len = cur.length;
  } catch { /* unreadable — delete anyway */ }
  if (len > 0) {
    try { await storage.set(key, '0'.repeat(len)); } catch { /* overwrite is best-effort */ }
  }
  try { await storage.remove(key); } catch { /* already gone */ }
}

/** Zero-fill + delete every key under a prefix (rk, gk, msgcache, ...). */
export async function secureRemovePrefix(storage: VeilStorage, prefix: string): Promise<void> {
  let keys: string[] = [];
  try { keys = await storage.keys(prefix); } catch { return; }
  for (const k of keys) await secureRemove(storage, k);
}
