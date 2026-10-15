/**
 * @veil/device — device-local pinned contacts + nicknames.
 *
 * ANTI-GOAL ENFORCED BY DESIGN: this module imports NO network code. Pins and
 * nicknames NEVER leave the device — never transmitted, never synced, never
 * stored server-side (the VeilContact server-table mistake stays dead).
 *
 * Ported from the web app's veil_pins_v1 / veil_nicks_v1 localStorage keys.
 */

import { verifySpkSig } from '../../crypto-core/src/index';

export interface PinnedContact {
  /** pinned identity key — THE trust anchor; pin = identity */
  ikPubB64: string;
  /** peer's Veil id at pin time (display only; key is authoritative) */
  veilId: string;
  pinnedAt: string;
  /** set once the user completes "I compared the fingerprint" */
  verified: boolean;
}

export interface Nickname {
  veilId: string;
  nickname: string;
}

const PINS_KEY = 'veil_pins_v1';
const NICKS_KEY = 'veil_nicks_v1';

type PinMap = Record<string, PinnedContact>;
type NickMap = Record<string, string>;

export class PinStore {
  constructor(private get: (k: string) => Promise<string | null>, private set: (k: string, v: string) => Promise<boolean>) {}

  private async pins(): Promise<PinMap> {
    try { return JSON.parse((await this.get(PINS_KEY)) || '{}'); } catch { return {}; }
  }
  private async nicks(): Promise<NickMap> {
    try { return JSON.parse((await this.get(NICKS_KEY)) || '{}'); } catch { return {}; }
  }

  async pin(veilId: string, ikPubB64: string): Promise<void> {
    const map = await this.pins();
    map[veilId] = { ikPubB64, veilId, pinnedAt: new Date().toISOString(), verified: false };
    await this.set(PINS_KEY, JSON.stringify(map));
  }

  /** Two-tap "unpin?" confirmation happens in the UI; storage just removes. */
  async unpin(veilId: string): Promise<void> {
    const map = await this.pins();
    delete map[veilId];
    await this.set(PINS_KEY, JSON.stringify(map));
    const nicks = await this.nicks();
    delete nicks[veilId];
    await this.set(NICKS_KEY, JSON.stringify(nicks));
  }

  async markVerified(veilId: string): Promise<void> {
    const map = await this.pins();
    if (map[veilId]) {
      map[veilId].verified = true;
      await this.set(PINS_KEY, JSON.stringify(map));
    }
  }

  async getPin(veilId: string): Promise<PinnedContact | null> {
    return (await this.pins())[veilId] ?? null;
  }

  async listPins(): Promise<PinnedContact[]> {
    return Object.values(await this.pins());
  }

  async setNickname(veilId: string, nickname: string): Promise<void> {
    const nicks = await this.nicks();
    nicks[veilId] = nickname;
    await this.set(NICKS_KEY, JSON.stringify(nicks));
  }

  async getNickname(veilId: string): Promise<string | null> {
    return (await this.nicks())[veilId] ?? null;
  }

  /**
   * MITM guard (client-side, before trusting published prekeys):
   * SPK_sig must verify against the PINNED IK — not the lookup response's IK.
   * Returns the prekeys only when the signature checks out.
   */
  async verifyPeerPrekeys(veilId: string, published: { IK_pub: string; SPK_pub: string; SPK_sig: string }): Promise<{ trusted: true; spkPubB64: string } | { trusted: false; reason: string }> {
    const pin = await this.getPin(veilId);
    if (!pin) return { trusted: false, reason: 'not-pinned' };
    if (published.IK_pub !== pin.ikPubB64) {
      return { trusted: false, reason: 'identity-key-changed' };
    }
    if (!(await verifySpkSig(pin.ikPubB64, published.SPK_pub, published.SPK_sig))) {
      return { trusted: false, reason: 'spk-sig-invalid' };
    }
    return { trusted: true, spkPubB64: published.SPK_pub };
  }
}
