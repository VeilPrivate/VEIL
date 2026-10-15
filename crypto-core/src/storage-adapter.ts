/**
 * @veil/crypto-core — storage adapter (Phase-A seam).
 *
 * THE ONLY seam between the crypto core and the platform. The web app talks to
 * localStorage directly behind keys like `veil_rk_<token>` / `veil_keyvault_*`;
 * crypto-core must never import localStorage or any DOM/Node API. Native
 * (Expo) will implement this over Keychain/Keystore.
 */

export interface VeilStorage {
  /** Read a raw string value. Returns null when absent. */
  get(key: string): Promise<string | null>;
  /** Write a raw string value. Returns false when the write failed (quota, lock). */
  set(key: string, value: string): Promise<boolean>;
  /** Remove a key. Never throws. */
  remove(key: string): Promise<void>;
  /** Enumerate keys with a given prefix (session-state sweep, wipes, export). */
  keys(prefix: string): Promise<string[]>;
}

/** In-memory adapter — tests, ephemeral Nothing-at-Rest mode. */
export class MemoryStorage implements VeilStorage {
  private map = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.map.get(key) ?? null;
  }
  async set(key: string, value: string): Promise<boolean> {
    this.map.set(key, value);
    return true;
  }
  async remove(key: string): Promise<void> {
    this.map.delete(key);
  }
  async keys(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

/**
 * localStorage adapter (web). Imported lazily so this module stays loadable in
 * React Native environments that never touch it.
 */
export function createWebStorage(): VeilStorage {
  return {
    async get(key) {
      try {
        return localStorage.getItem(key);
      } catch {
        return null;
      }
    },
    async set(key, value) {
      try {
        localStorage.setItem(key, value);
        return true;
      } catch {
        return false;
      }
    },
    async remove(key) {
      try {
        localStorage.removeItem(key);
      } catch {
        /* noop */
      }
    },
    async keys(prefix) {
      const out: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith(prefix)) out.push(k);
      }
      return out;
    },
  };
}

/** Adapter a storage adapter with automatic JSON (en)decoding. */
export function jsonStorage(inner: VeilStorage) {
  return {
    async get<T>(key: string): Promise<T | null> {
      const raw = await inner.get(key);
      if (!raw) return null;
      try {
        return JSON.parse(raw) as T;
      } catch {
        return null;
      }
    },
    async set(key: string, value: unknown): Promise<boolean> {
      return inner.set(key, JSON.stringify(value));
    },
    remove: (key: string) => inner.remove(key),
    keys: (prefix: string) => inner.keys(prefix),
  };
}
