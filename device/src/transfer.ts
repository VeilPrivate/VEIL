/**
 * @veil/device — Device transfer (web parity, build 39).
 *
 * Web contract extracted from the live bundle (createDeviceTransfer /
 * confirmDeviceLink / deviceLink backend fn):
 *
 * SENDER
 *   1. bundle = { v: 2, clientId, sessions: {token: serializedState}, groups: [],
 *                identity: keyvaultJson | null }
 *      (serialized states are the veil_rk_* family — byte-exact with the web)
 *   2. AES-256-GCM: fresh 32-byte key (base64 in the link fragment), fresh
 *      12-byte IV; blob = JSON.stringify({ iv: b64, ct: b64 })
 *   3. blob → UploadPrivateFile (private storage, never public)
 *   4. deviceLink { action:'store', token, container_uri, byte_length }
 *   5. link = {origin}/?deviceLink={token}#k={encodeURIComponent(keyB64)}
 *      — single-use, ~10-minute TTL enforced server-side
 *
 * RECEIVER
 *   1. deviceLink { action:'fetch', token } → { blob } | { signed_url }
 *   2. decrypt with the fragment key → bundle (accepts v1 and v2)
 *   3. import each session not already present; import identity into the
 *      keyvault (kept-safe rule below); groups restored where present
 *
 * Native deviation (disclosed): the web overwrites the local keyvault with the
 * transferred identity unconditionally. Native imports the identity only when
 * this device has none, or when it is the SAME identity — a different local
 * identity is kept (transfer still imports the sessions) and the summary
 * says so, so an accidental paste can never wipe the identity you are using.
 */
import { randomBytes, toB64, fromB64, utf8 } from '../../crypto-core/src/index';
import type { RatchetStateSerialized } from '../../crypto-core/src/ratchet';
import type { SessionStore } from './session-store';
import type { IdentityVault } from './keyvault';
import type { VeilRelay } from './relay';

export interface TransferBundleV2 {
  v: 2;
  clientId: string;
  sessions: Record<string, RatchetStateSerialized>;
  groups: unknown[];
  identity: KeyvaultIdentityRef | null;
}

/** Shape of the keyvault identity JSON (keyvault.ts owns the full type;
 *  the bundle carries it as-is so the formats stay web-identical). */
export interface KeyvaultIdentityRef {
  veilId: string;
  [k: string]: unknown;
}

export interface DeviceTransferLink {
  link: string;
  sessionCount: number;
  groupCount: number;
  hasIdentity: boolean;
}

export interface DeviceTransferResult {
  sessionCount: number;
  importedCount: number;
  skippedExisting: number;
  identityImported: boolean;
  identityKept: boolean;
}

export interface TransferDeps {
  sessions: SessionStore;
  vault: IdentityVault;
  relay: VeilRelay;
  /** web origin for the shareable link (the web app opens it natively;
   *  the native app accepts the same link pasted into Settings) */
  webBaseUrl: string;
  fetchImpl?: typeof fetch;
}

async function aesGcmEncrypt(keyBytes: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, plaintext as unknown as BufferSource);
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(keyBytes: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, ciphertext as unknown as BufferSource);
  return new Uint8Array(pt);
}

/** Sender: build the bundle, upload it encrypted, return the single-use link. */
export async function createDeviceTransfer(
  deps: TransferDeps,
  opts?: { clientId?: string },
): Promise<DeviceTransferLink> {
  const tokens = await deps.sessions.listTokens();
  const sessions: Record<string, RatchetStateSerialized> = {};
  for (const token of tokens) {
    const state = await deps.sessions.load(token);
    if (state) sessions[token] = state;
  }
  const identity = await deps.vault.load();
  const bundle: TransferBundleV2 = {
    v: 2,
    clientId: opts?.clientId ?? identity?.veilId ?? '',
    sessions,
    groups: [],
    identity: identity as unknown as KeyvaultIdentityRef | null,
  };
  if (!Object.keys(sessions).length && !identity) {
    throw new Error('There are no conversation keys on this device to transfer. Use VEIL on this device first, then try again. (ref TF-01)');
  }

  const keyBytes = randomBytes(32);
  const iv = randomBytes(12);
  const ct = await aesGcmEncrypt(keyBytes, iv, utf8(JSON.stringify(bundle)));
  const blob = JSON.stringify({ iv: toB64(iv), ct: toB64(ct) });

  // private storage — the bundle never travels anywhere readable but the link
  const containerUri = await deps.relay.uploadPrivateFile({
    bytes: utf8(blob),
    name: 'veil-transfer',
  });
  const token = toB64(randomBytes(16));
  await deps.relay.invoke('deviceLink', {
    action: 'store',
    token,
    container_uri: containerUri,
    byte_length: blob.length,
  });

  const base = deps.webBaseUrl.replace(/\/$/, '');
  const link = `${base}/?deviceLink=${encodeURIComponent(token)}#k=${encodeURIComponent(toB64(keyBytes))}`;
  return {
    link,
    sessionCount: Object.keys(sessions).length,
    groupCount: 0,
    hasIdentity: !!identity,
  };
}

/** Parse a transfer link (either from the web app URL or shared as text). */
export function parseTransferLink(link: string): { token: string; key: string } {
  const tokenMatch = link.match(/deviceLink=([^&#\s]+)/i);
  const keyMatch = link.match(/[#&?]k=([^&#\s]+)/i);
  if (!tokenMatch) throw new Error('That is not a device-transfer link — ask for a fresh one.');
  const token = decodeURIComponent(tokenMatch[1]);
  const key = keyMatch ? decodeURIComponent(keyMatch[1]) : '';
  if (!key) throw new Error('The link is missing its key fragment — ask for a fresh one.');
  return { token, key };
}

/** Receiver: fetch the container, decrypt, import sessions (+ identity). */
export async function receiveDeviceTransfer(
  deps: TransferDeps,
  link: string,
): Promise<DeviceTransferResult> {
  const { token, key } = parseTransferLink(link);
  const fetchImpl = deps.fetchImpl ?? fetch;

  const r = await deps.relay.invoke('deviceLink', { action: 'fetch', token });
  const d = (r.data ?? {}) as { blob?: string; signed_url?: string; data?: { blob?: string; signed_url?: string } };
  let blob: string = d.blob ?? d.data?.blob ?? '';
  if (!blob && (d.signed_url ?? d.data?.signed_url)) {
    const res = await fetchImpl(d.signed_url ?? d.data!.signed_url!);
    if (!res.ok) throw new Error('The transfer container could not be fetched — the link may have expired. Ask for a fresh one. (ref DL-04)');
    blob = await res.text();
  }
  if (!blob) throw new Error('Transfer link not found — expired or already used.');

  let bundle: TransferBundleV2;
  try {
    const envelope = JSON.parse(blob) as { iv: string; ct: string };
    const keyBytes = fromB64(key);
    const iv = fromB64(envelope.iv);
    const ct = fromB64(envelope.ct);
    const pt = await aesGcmDecrypt(keyBytes, iv, ct);
    const parsed = JSON.parse(new TextDecoder().decode(pt)) as { v: number; sessions?: Record<string, RatchetStateSerialized>; groups?: unknown[]; identity?: KeyvaultIdentityRef | null; clientId?: string };
    if ((parsed.v !== 1 && parsed.v !== 2) || !parsed.sessions) {
      throw new Error('not a bundle');
    }
    bundle = parsed as TransferBundleV2;
  } catch {
    throw new Error('The bundle could not be decrypted with this link — ask for a fresh one. (ref DL-05)');
  }

  // import sessions not already on this device (web parity: never overwrite)
  let importedCount = 0;
  let skippedExisting = 0;
  for (const [sessToken, state] of Object.entries(bundle.sessions)) {
    if (await deps.sessions.load(sessToken)) { skippedExisting += 1; continue; }
    await deps.sessions.save(sessToken, state);
    importedCount += 1;
  }

  // identity: import when absent or identical; a different local identity is kept
  const local = await deps.vault.load();
  let identityImported = false;
  let identityKept = false;
  if (bundle.identity) {
    if (!local || local.veilId === bundle.identity.veilId) {
      await deps.vault.save(bundle.identity as never);
      identityImported = true;
    } else {
      identityKept = true;
    }
  }

  return {
    sessionCount: Object.keys(bundle.sessions).length,
    importedCount,
    skippedExisting,
    identityImported,
    identityKept,
  };
}
