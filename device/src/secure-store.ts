/**
 * @veil/device — secure storage over the platform keystore.
 *
 * The ONLY primitive the Expo shell must implement: SecureStore
 * (react-native-keychain / expo-secure-store / Keychain on iOS, Keystore on
 * Android). Keychain-style stores are not enumerable, so VeilStorage's
 * keys(prefix) sweep is served through a maintained index record.
 *
 * Everything the web app kept in localStorage under veil_* keys lives here:
 * NO plaintext key material ever touches AsyncStorage or plain files.
 */

import type { VeilStorage } from '../../crypto-core/src/index';

/** Platform primitive the Expo shell provides. Never returns secrets in logs. */
export interface SecureStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

const INDEX_KEY = 'veil_keychain_index';

/** VeilStorage over a non-enumerable secure store, with a key index. */
export class KeychainStorage implements VeilStorage {
  constructor(private store: SecureStore) {}

  private async readIndex(): Promise<string[]> {
    try {
      return JSON.parse((await this.store.get(INDEX_KEY)) || '[]');
    } catch {
      return [];
    }
  }

  private async writeIndex(keys: string[]): Promise<void> {
    await this.store.set(INDEX_KEY, JSON.stringify(keys));
  }

  async get(key: string): Promise<string | null> {
    return this.store.get(key);
  }

  async set(key: string, value: string): Promise<boolean> {
    try {
      await this.store.set(key, value);
      if (key !== INDEX_KEY) {
        const keys = await this.readIndex();
        if (!keys.includes(key)) {
          keys.push(key);
          await this.writeIndex(keys);
        }
      }
      return true;
    } catch (e) {
      // b196-r7: never swallow silently — Metro must see the native failure
      // (user-facing copy stays sanitized elsewhere; this is the developer log).
      console.error('[veil-secure] KeychainStorage.set failed:', key, e);
      return false;
    }
  }

  async remove(key: string): Promise<void> {
    try {
      await this.store.delete(key);
      if (key !== INDEX_KEY) {
        const keys = await this.readIndex();
        const i = keys.indexOf(key);
        if (i >= 0) {
          keys.splice(i, 1);
          await this.writeIndex(keys);
        }
      }
    } catch {
      /* never throws */
    }
  }

  async keys(prefix: string): Promise<string[]> {
    return (await this.readIndex()).filter((k) => k.startsWith(prefix));
  }

  /** Wipe every key under the prefixes (duress / storage-mode flip / end-session). */
  async wipe(...prefixes: string[]): Promise<number> {
    const all = await this.readIndex();
    let n = 0;
    for (const k of all) {
      if (prefixes.some((p) => k.startsWith(p))) {
        await this.store.delete(k);
        n++;
      }
    }
    await this.writeIndex(all.filter((k) => !prefixes.some((p) => k.startsWith(p))));
    return n;
  }
}
