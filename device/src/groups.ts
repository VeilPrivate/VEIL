/**
 * @veil/device — GROUP messaging protocol (veil-group-1), ported byte-exact
 * from the live web bundle (extracted Sept 19, 2026).
 *
 * Wire contract summary (all verified against the bundle):
 *  - Envelope header: JSON {v:'veil-group-1', sid:<sender tag>, ge:<epoch>, n:<send counter>}
 *    plus optional `sig` (per-sender Ed25519 over the concat of the header-JSON
 *    bytes WITHOUT sig and the raw IV bytes).
 *  - Message key: HKDF-SHA256(ikm=GEK, salt=SHA256('veil-group-bind:'+groupToken+':'+epoch+':'+pqPubB64),
 *    info='veil-group-msg:'+sid+':'+n, 32) — AES-256-GCM, IV 12B random,
 *    additionalData = the FULL header JSON (with sig).
 *  - Payload: padded to buckets [1024, 4096]: [1 cover flag][2 BE length][utf8 text][zero pad].
 *  - Sender tag: 'g' + hex(first 6 bytes of SHA-256('veil-group-sender:'+groupToken+':'+epoch+':'+veilId)).
 *  - Replay guard: per-sender {last, skipped[]} — n<=last must be in skipped
 *    (then consumed); n>last skips (last+1..n-1) get buffered (cap 64).
 *  - Rekey: creator encapsulates the new GEK with ML-KEM-768 against EACH
 *    member's published PQ prekey: wrap {to, ct, wk, wi} where
 *    wk = AES-GCM(HKDF(mlkemSecret, salt='veil-group-rekey', info=toVeilId), newGEK).
 *    Broadcast as a group message whose text is JSON
 *    {"__veil_group_rekey":1, ge, pq:<new group pq pub>, wraps:[...]}, then
 *    gate action 'rotate' with the new epoch + group PQ pub. Receivers find
 *    their own wrap, ML-KEM-decapsulate, and move to the new epoch (sendN
 *    resets, recv cleared, new sender tag).
 *  - Epoch fingerprint: SHA-256('veil-group-epoch:'+groupToken+':'+sorted member list joined ',')
 *    → hex, uppercased, grouped in 4s with dashes.
 *  - Creator attest: Ed25519(ikSeed) over b64(JSON{group_token, veil_id, IK_pub, joined_epoch}).
 *  - Evict deny-sig: Ed25519(ikSeed) over b64(JSON{group_token, target_IK_pub, deny_epoch}).
 *  - Group name blob: 'enc1:'+b64(iv)+':'+b64(AES-GCM(GEK, name)).
 *  - Protocol version on submitEnvelope: 'veil-group-1'; group envelopes carry
 *    BOTH session_token and group_token.
 *  - Auto-rotation trigger (creator): 100 envelopes received or 24 h since
 *    epoch start.
 *  - Group record persistence: web stores AES-GCM(JSON record) under
 *    localStorage 'veil_gk_'+token (7-day TTL). Native stores the JSON record
 *    in the OS keychain (SecureStore) under the same logical name — strictly
 *    stronger at rest, same lifetime semantics (no TTL — keys are per-device).
 */
import { toB64, fromB64, utf8, fromUtf8, concat } from '../../crypto-core/src/bytes';
import { hkdf, sha256 } from '../../crypto-core/src/kdf';
import { ikSign, verifyWithIk, veilIdFromIkPub } from '../../crypto-core/src/identity';
import { mlkemEncap, mlkemDecap } from '../../crypto-core/src/mlkem';
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';

export const GROUP_PROTO = 'veil-group-1';
export const GROUP_KEY_PREFIX = 'veil_gk_';
const PAD_BUCKETS = [1024, 4096];
const PAYLOAD_HDR = 3; // 1 cover byte + 2 BE length bytes
const MAX_SKIPPED = 64;
export const EPOCH_MAX_ENVELOPES = 100;
export const EPOCH_MAX_MS = 24 * 60 * 60 * 1000;
export const GROUP_MEMBER_CAP = 100; // b198: the Founding Tester Forum cohort (was 8)

export interface GroupRecvState {
  last: number;
  skipped: number[];
  /** b196-r2: posting-session token the sender's counter `n` belongs to. A
   * re-minted posting session (founder end+rejoin, device restore) restarts
   * the sender chain at n=0 while the sender TAG stays identical — keying the
   * replay guard on (sid, n) alone rejected every message from the new chain
   * as a replay (owner repro Oct 12: fresh founder welcome invisible to any
   * listener that had seen the old chain). */
  chain?: string;
}

export interface GroupRecord {
  groupToken: string;
  /** b198: this member's own group session token (background poll + push
   *  credential). Older records predate it — derive via findMainGroupSession. */
  sessionToken?: string;
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  role: 'creator' | 'member' | 'listener' | 'forum-member';
  epoch: number;
  gekB64: string;
  nameGekB64: string;
  pqPubB64: string;
  myTag: string;
  sendN: number;
  recv: Record<string, GroupRecvState>;
  envCount?: number;
  epochStartedAt?: string;
  /** roster: sender tag -> member IK_pub b64 (for per-sender signature checks) */
  senderKeys?: Record<string, string>;
  /** my own display nickname in this group (used for roster display) */
  myNick?: string;
  /** durable sender tag -> nickname map (intros are one-shot; this survives polls) */
  nicks?: Record<string, string>;
  /** b92 F10: per-group envelope pagination cursor (full-page advance rule) */
  syncSkip?: number;
  /** b195: deletion-immune inbox cursor — server created_date of the last
   *  definitively-processed envelope (−1ms). Replaces the skip cursor for
   *  fetches: skip offsets SHIFT every time the relay purges expired rows,
   *  silently striding past unprocessed backlog at tester volume. */
  syncCursorAt?: string;
  /** b187 lounge: display name (listener records hold no relay session to
   *  fetch the encrypted name blob from, so the descriptor name persists
   *  locally; creator/member records keep using the relay blob). */
  name?: string;
  /** b92 F11: persistently-known envelope ids (marked only after definitive outcome), capped */
  knownEnvIds?: string[];  /** b188 forum mode: token of the SELF-CREATED posting session bound to
   *  this group (forum members have no invite session; they post envelopes
   *  under their own session credential). */
  postingSessionToken?: string;
  /** b190: ms-epoch cooldown — auto-rotation stops re-attempting (identity
   *  lookups) until this time when a member has no published PQ prekey. */
  rotateBlockedUntil?: number;
  /** b190: the server-side session row is gone (deleted group) — the thread
   *  is fail-closed ended; roster polls stop, local history stays readable. */
  sessionEnded?: boolean;
}

export interface GroupEnvelopeHeader {
  v: string; sid: string; ge: number; n: number; sig?: string;  /** b188 forum mode: the sender's veil-id (AEAD-associated — tamper-proof
   *  via GCM auth, not part of the Ed25519 sig set). Lets a receiver resolve
   *  and verify an UNKNOWN sender against the published identity registry. */
  vid?: string;
}

export interface GroupDecryptResult {
  cover: boolean;
  text: string;
  senderVerified: boolean;
}

// ---------- record store (web's nm Map + um persistence) ----------

/**
 * Per-device record caches, keyed by the storage INSTANCE. Two group sessions
 * on different stores (two devices simulated in one process, tests, a future
 * multi-profile build) never share or clobber each other's group state —
 * the send counter, replay window and epoch live with the store that owns them.
 */
const registries = new WeakMap<VeilStorage, Map<string, GroupRecord>>();
function registry(store: VeilStorage): Map<string, GroupRecord> {
  let m = registries.get(store);
  if (!m) { m = new Map(); registries.set(store, m); }
  return m;
}
const sendLocks = new Map<string, Promise<void>>();

async function persist(store: VeilStorage, rec: GroupRecord): Promise<void> {
  try {
    await store.set(GROUP_KEY_PREFIX + rec.groupToken, JSON.stringify(rec));
  } catch (e) {
    console.error('[veil-group] key persistence failed — keys may not survive restart:', e);
  }
}

/** web's dm(): normalize + memory map + persist */
export async function saveGroupRecord(store: VeilStorage, rec: GroupRecord): Promise<GroupRecord> {
  // b198 EPOCH MONOTONICITY (live-caught: One's record regressed 3 → 2 after a
  // rotation — a stale in-flight record save clobbered the advanceEpoch that
  // landed while the pass was running; the background group pass widened that
  // window). Group epochs only ever move FORWARD: a save carrying an OLDER
  // epoch has the newer epoch's key material preserved so the regression can
  // never stick. (Re-join flows re-attest at the CURRENT epoch, so forward is
  // always the right direction.)
  const cur = registry(store).get(rec.groupToken);
  let r: GroupRecord = {
    ...rec,
    recv: rec.recv ?? {},
    envCount: rec.envCount ?? 0,
    epochStartedAt: rec.epochStartedAt ?? new Date().toISOString(),
  };
  if (cur && Number(rec.epoch ?? 0) < Number(cur.epoch ?? 0)) {
    r = {
      ...r,
      epoch: cur.epoch,
      gekB64: cur.gekB64,
      pqPubB64: cur.pqPubB64,
      myTag: cur.myTag,
      sendN: cur.sendN,
      recv: cur.recv ?? r.recv,
      envCount: cur.envCount ?? r.envCount,
      epochStartedAt: cur.epochStartedAt ?? r.epochStartedAt,
    };
    console.log(`[veil-group] stale record save blocked — kept epoch ${cur.epoch} over ${rec.epoch} for ${rec.groupToken.slice(0, 8)}`);
  }
  registry(store).set(r.groupToken, r);
  await persist(store, r);
  return r;
}

export function groupRecord(store: VeilStorage, groupToken: string): GroupRecord | null {
  return registry(store).get(groupToken) ?? null;
}

export function listGroupTokens(store: VeilStorage): string[] {
  return [...registry(store).keys()];
}

export async function forgetGroup(store: VeilStorage, groupToken: string): Promise<void> {
  registry(store).delete(groupToken);
  sendLocks.delete(groupToken);
  try { await store.remove(GROUP_KEY_PREFIX + groupToken); } catch { /* already gone */ }
}

/** web's Am(): export all records (device transfer payload) */
export function exportGroupRecords(store: VeilStorage): GroupRecord[] {
  return [...registry(store).values()].map((r) => ({ ...r }));
}

/** web's jm(): restore records from a device transfer */
export async function importGroupRecords(store: VeilStorage, recs: GroupRecord[]): Promise<number> {
  let n = 0;
  for (const r of recs ?? []) {
    if (!r || !r.groupToken || registry(store).has(r.groupToken)) continue;
    await saveGroupRecord(store, { ...r, recv: r.recv ?? {}, envCount: r.envCount ?? 0, epochStartedAt: r.epochStartedAt ?? new Date().toISOString() });
    n += 1;
  }
  return n;
}

/**
 * Boot-time reload (web's hm() counterpart): the native SecureStore has no key
 * enumeration, so the App layer re-hydrates records from the session rows the
 * gate returns (group sessions carry group_token) plus this explicit loader
 * for tokens the caller knows about.
 */
export async function loadGroupRecord(store: VeilStorage, groupToken: string): Promise<GroupRecord | null> {
  if (registry(store).has(groupToken)) return registry(store).get(groupToken)!;
  try {
    const raw = await store.get(GROUP_KEY_PREFIX + groupToken);
    if (!raw) return null;
    const rec = JSON.parse(raw) as GroupRecord;
    if (!rec?.groupToken) return null;
    rec.recv = rec.recv ?? {};
    rec.envCount = rec.envCount ?? 0;
    rec.epochStartedAt = rec.epochStartedAt ?? new Date().toISOString();
    registry(store).set(rec.groupToken, rec);
    return rec;
  } catch (e) {
    // Do not destroy key material on transient Keychain/read or parse errors.
    console.error('[veil-group] key restore failed — keeping the record for retry', e);
    return null;
  }
}

/**
 * Boot-time reload for ALL persisted groups (web hm() counterpart). The
 * native keychain index is enumerable, so every veil_gk_ record loads in one
 * sweep. Unlike the web's 7-day localStorage TTL, native records do not
 * expire — losing them means losing group access on this device.
 */
export async function loadGroupRecords(store: VeilStorage): Promise<number> {
  let n = 0;
  try {
    const keys = await store.keys(GROUP_KEY_PREFIX);
    for (const k of keys ?? []) {
      const token = k.slice(GROUP_KEY_PREFIX.length);
      if (!token || registry(store).has(token)) continue;
      const raw = await store.get(k);
      if (!raw) continue;
      try {
        const rec = JSON.parse(raw) as GroupRecord;
        if (!rec?.groupToken) continue;
        rec.recv = rec.recv ?? {};
        rec.envCount = rec.envCount ?? 0;
        rec.epochStartedAt = rec.epochStartedAt ?? new Date().toISOString();
        registry(store).set(rec.groupToken, rec);
        n += 1;
      } catch (e) {
        // Preserve unreadable key material so a later unlock/recovery can retry.
        console.error('[veil-group] key restore failed — keeping the record for retry', e);
      }
    }
  } catch (e) {
    console.error('[veil-group] boot restore failed:', e);
  }
  return n;
}

// ---------- primitives ----------

async function sha256HexPrefix(s: string, bytes: number): Promise<string> {
  const h = await sha256(utf8(s));
  return [...h.subarray(0, bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** web's lm(): deterministic per-sender tag for THIS epoch */
export async function senderTag(groupToken: string, epoch: number, veilId: string): Promise<string> {
  return `g${await sha256HexPrefix(`veil-group-sender:${groupToken}:${epoch}:${veilId}`, 6)}`;
}

/**
 * Epoch fingerprint shown to users (web's bm() twin — MUST stay byte-exact
 * with the web app so cross-platform comparisons work).
 *
 * b136 (Sept 27, rotation test finding): the old input bound only
 * groupToken + sorted member veil IDs, so the fingerprint was IDENTICAL
 * across epochs — matching prints proved roster agreement, not KEY
 * agreement. A forked/malicious rekey (different GEKs or group PQ keys
 * delivered to different members) would still show identical
 * fingerprints, defeating the entire purpose of an "epoch" fingerprint.
 * The input now binds the full key-agreement state: epoch number, GEK,
 * and the epoch's group PQ public key. Two members now display the same
 * fingerprint iff they hold the same keys for the same epoch.
 * (SHA-256 of the GEK does not leak it — the fingerprint remains safe to
 * read aloud / compare out-of-band.) Web lockstep change requested from
 * the builder in the same cadence.
 *
 * b137 (builder reconciliation, Sept 27): the member element is the
 * sorted Ed25519 IK PUBS (b64), NOT veil IDs — the web's bm() has always
 * hashed IK pubs, so the native's pre-b136 "web's bm()" comment was wrong
 * and the two platforms were ALREADY fingerprint-divergent before b136.
 * Final cross-platform contract (byte-exact, both sides):
 *   veil-group-epoch:${groupToken}:${epoch}:${gekB64}:${pqPubB64}:${sortedIkPubsCommaJoined}
 * - groupToken: the 40-char hex group token, as-is
 * - epoch: DEVICE-LOCAL applied epoch, decimal, no padding ("2", "3") —
 *   NOT the relay-stamped group_epoch, for the same fork reason as GEK
 * - gekB64 / pqPubB64: device-LOCAL group state (identical to the relay
 *   row in normal operation; divergence under fork is the point)
 * - sortedIkPubs: member Ed25519 IK pub b64 strings, lexical sort, comma
 *   join, no spaces
 */
export async function epochFingerprint(
  groupToken: string,
  epoch: number,
  gekB64: string,
  pqPubB64: string,
  ikPubs: string[],
): Promise<string> {
  const sorted = [...(ikPubs ?? [])].sort();
  const h = await sha256(utf8(`veil-group-epoch:${groupToken}:${epoch}:${gekB64}:${pqPubB64}:${sorted.join(',')}`));
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{1,4}/g)!.join('-');
}

/** web's xm(): per-message AES key */
async function groupMsgKey(rec: GroupRecord, sid: string, n: number): Promise<Uint8Array> {
  const salt = await sha256(utf8(`veil-group-bind:${rec.groupToken}:${rec.epoch}:${rec.pqPubB64}`));
  return hkdf(fromB64(rec.gekB64), salt, `veil-group-msg:${sid}:${n}`, 32);
}

/** web's sm(): pad payload into a fixed bucket so envelope sizes don't leak length */
function padGroupPayload(text: string, cover: boolean): Uint8Array {
  const body = utf8(text);
  const need = PAYLOAD_HDR + body.length;
  const bucket = PAD_BUCKETS.find((b) => b >= need);
  if (!bucket) throw new Error('Message too long for the padded bucket sizes');
  const out = new Uint8Array(bucket);
  out[0] = cover ? 1 : 0;
  new DataView(out.buffer).setUint16(1, body.length);
  out.set(body, PAYLOAD_HDR);
  return out;
}

/** web's cm(): parse the padded payload */
function parseGroupPayload(bytes: Uint8Array): { cover: boolean; text: string } {
  if (bytes.length < PAYLOAD_HDR) throw new Error('Corrupted group message payload');
  const len = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(1);
  if (PAYLOAD_HDR + len > bytes.length) throw new Error('Corrupted group message payload');
  return { cover: bytes[0] === 1, text: fromUtf8(bytes.subarray(PAYLOAD_HDR, PAYLOAD_HDR + len)) };
}

/** web's _m(): encrypted group name blob */
export async function encryptGroupText(gekB64: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', fromB64(gekB64) as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, utf8(text) as unknown as BufferSource));
  return `enc1:${toB64(iv)}:${toB64(ct)}`;
}

/** web's vm(): open a name blob (falls back to the raw string) */
export async function decryptGroupText(gekB64: string, blob: string): Promise<string> {
  const m = /^enc1:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/.exec(String(blob ?? ''));
  if (!m) return String(blob ?? '');
  const key = await crypto.subtle.importKey('raw', fromB64(gekB64) as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(m[1]) as unknown as BufferSource }, key, fromB64(m[2]) as unknown as BufferSource));
  return fromUtf8(pt);
}

// ---------- encrypt / decrypt ----------

export interface GroupEnvelopeOut {
  ciphertext: string; iv: string; header: string; byteLength: number; senderTag: string;
}

/** web's Sm(): send-path encrypt. Serialized under a per-group lock so the
 *  send counter never interleaves. */
export async function encryptGroupMessage(
  store: VeilStorage, groupToken: string, text: string, cover = false,
): Promise<GroupEnvelopeOut> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  const prev = sendLocks.get(groupToken) ?? Promise.resolve();
  let release!: () => void;
  sendLocks.set(groupToken, new Promise<void>((r) => (release = r)));
  await prev;
  try {
    const n = rec.sendN;
    rec.sendN += 1;
    const header: GroupEnvelopeHeader = rec.role === 'forum-member'
      ? { v: GROUP_PROTO, sid: rec.myTag, ge: rec.epoch, n, vid: rec.veilId }
      : { v: GROUP_PROTO, sid: rec.myTag, ge: rec.epoch, n };
    const msgKey = await groupMsgKey(rec, rec.myTag, n);
    const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    let sig = '';
    if (rec.ikSeedB64) {
      // b188: the signature ALWAYS covers the four core fields — the same
      // re-serialization decryptGroupMessage verifies. vid (forum mode) rides
      // in the AEAD additionalData instead: tamper-proof via GCM auth, and
      // the vid->sid->registry bind chain is enforced in the forum policy.
      const core = JSON.stringify({ v: GROUP_PROTO, sid: rec.myTag, ge: rec.epoch, n });
      const hdrBytes = utf8(core);
      sig = await ikSign(rec.ikSeedB64, toB64(concat(hdrBytes, iv)));
    }
    const fullHeader: GroupEnvelopeHeader = sig ? { ...header, sig } : header;
    const headerStr = JSON.stringify(fullHeader);
    const payload = padGroupPayload(text, cover);
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource, additionalData: utf8(headerStr) as unknown as BufferSource },
      key, payload as unknown as BufferSource,
    ));
    await persist(store, rec);
    return { ciphertext: toB64(ct), iv: toB64(iv), header: headerStr, byteLength: payload.length, senderTag: rec.myTag };
  } finally {
    release();
  }
}

/** web's Cm(): receive-path decrypt with replay guard + per-sender sig check. */
export async function decryptGroupMessage(
  store: VeilStorage, groupToken: string, headerStr: string, ciphertextB64: string, ivB64: string,
  chainId?: string,
): Promise<GroupDecryptResult> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  const header = JSON.parse(headerStr) as GroupEnvelopeHeader;
  if (header.v !== GROUP_PROTO) throw new Error('Unsupported group protocol version.');
  const sid = header.sid;
  const n = header.n;
  if (typeof sid !== 'string' || !sid || !Number.isInteger(n) || n < 0) throw new Error('Malformed group message header.');

  const hadSender = Object.prototype.hasOwnProperty.call(rec.recv, sid);
  const saved = rec.recv[sid] ?? { last: -1, skipped: [] };
  // b196-r2 chain switch: a DIFFERENT (or, for pre-r2 records, absent-vs-
  // present) posting-session token means this sender's counter restarted —
  // reset the per-chain baseline and judge `n` on the new chain alone.
  // True replays of old-chain envelopes stay impossible to RENDER: exact
  // duplicates sit below the b195 inbox cursor (never fetched) or in the
  // envelope-id ledger, and anything that does decrypt still has to pass the
  // founder-signature fail-closed policy. Classic groups post through one
  // shared session token, so this never fires there (guard unchanged).
  if (chainId !== undefined && saved.chain !== chainId) {
    saved.last = -1;
    saved.skipped = [];
  }
  const snapshot = { last: saved.last, skipped: [...saved.skipped], chain: saved.chain };
  try {
    if (n <= saved.last) {
      const idx = saved.skipped.indexOf(n);
      if (idx === -1) throw new Error('Replayed or too-old group message.');
      saved.skipped.splice(idx, 1);
    } else {
      // The counter is in unauthenticated JSON until AES-GCM succeeds. Bound
      // the gap before iterating to avoid a hostile huge-counter UI freeze.
      if (n - saved.last > 1_000_000) throw new Error('Group message counter jump too large.');
      // Only the most recent MAX_SKIPPED positions are recoverable; do not
      // loop over the entire unauthenticated gap even when it is legitimate.
      for (let k = Math.max(saved.last + 1, n - MAX_SKIPPED); k < n; k++) saved.skipped.push(k);
      if (saved.skipped.length > MAX_SKIPPED) saved.skipped = saved.skipped.slice(-64);
      saved.last = n;
    }
    rec.recv[sid] = saved;

    const msgKey = await groupMsgKey(rec, sid, n);
    const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource, additionalData: utf8(headerStr) as unknown as BufferSource },
      key, fromB64(ciphertextB64) as unknown as BufferSource,
    ));
    saved.chain = chainId; // b196-r2: only committed after GCM auth succeeds
    const out = parseGroupPayload(pt);
    const result: GroupDecryptResult = { ...out, senderVerified: false };
    if (header.sig && rec.senderKeys?.[sid]) {
      const unsigned = utf8(JSON.stringify({ v: header.v, sid: header.sid, ge: header.ge, n: header.n }));
      const ivBytes = fromB64(ivB64);
      const messageB64 = toB64(concat(unsigned, ivBytes));
      const ok = await verifyWithIk(rec.senderKeys[sid], messageB64, header.sig);
      if (!ok) throw new Error('veil-group-sig: this envelope was not signed by the roster member it claims');
      result.senderVerified = true;
    }
    await persist(store, rec);
    return result;
  } catch (e) {
    if (hadSender) rec.recv[sid] = snapshot;
    else delete rec.recv[sid];
    throw e;
  }
}

/** b123: read-only decrypt of MY OWN group envelope — the inbox poll's
 *  own-echo path uses it to learn which envelope id carries a locally-sent
 *  bubble, so group read receipts can tick that bubble (pairwise already
 *  had this via sendChatMessage's envId). Deliberately does NOT touch the
 *  per-sender recv bookkeeping or the sender-signature check — it only
 *  reads the payload back with the same GEK-derived message key. */
export async function decryptOwnGroupEnvelope(
  store: VeilStorage, groupToken: string, headerStr: string, ciphertextB64: string, ivB64: string,
): Promise<{ cover: boolean; text: string }> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  const header = JSON.parse(headerStr) as { v?: string; sid?: string; n?: number };
  if (header.v !== GROUP_PROTO || typeof header.sid !== 'string' || !header.sid
      || !Number.isInteger(header.n) || (header.n ?? -1) < 0) {
    throw new Error('Malformed group message header.');
  }
  const msgKey = await groupMsgKey(rec, header.sid, header.n as number);
  const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource, additionalData: utf8(headerStr) as unknown as BufferSource },
    key, fromB64(ciphertextB64) as unknown as BufferSource,
  ));
  return parseGroupPayload(pt);
}

/** web's fm(): bump the rotation counter (creator auto-rotate trigger) */
export async function bumpGroupEnvCount(store: VeilStorage, groupToken: string): Promise<number> {
  const rec = registry(store).get(groupToken);
  if (!rec) return 0;
  rec.envCount = (rec.envCount ?? 0) + 1;
  await persist(store, rec);
  return rec.envCount;
}

// ---------- rekey / epoch rotation ----------

export interface GroupRekeyWrap { to: string; ct: string; wk: string; wi: string }
export interface GroupRekeyPayload { ge: number; pq: string; wraps: GroupRekeyWrap[] }

/** web's wm(): wrap the new GEK for one member via their published PQ prekey */
export async function buildRekeyWrap(memberPqPubB64: string, toVeilId: string, newGekB64: string): Promise<GroupRekeyWrap> {
  const { ct, secret } = await mlkemEncap(memberPqPubB64);
  const wrapKey = await hkdf(secret, utf8('veil-group-rekey'), toVeilId, 32);
  const key = await crypto.subtle.importKey('raw', wrapKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wk = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, fromB64(newGekB64) as unknown as BufferSource,
  ));
  return { to: toVeilId, ct, wk: toB64(wk), wi: toB64(iv) };
}

/** web's Tm(): unwrap a new GEK with my PQ private key */
export async function openRekeyWrap(myPqPrivB64: string, wrap: GroupRekeyWrap): Promise<string> {
  const secret = await mlkemDecap(myPqPrivB64, wrap.ct);
  const wrapKey = await hkdf(secret, utf8('veil-group-rekey'), wrap.to, 32);
  const key = await crypto.subtle.importKey('raw', wrapKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(wrap.wi) as unknown as BufferSource }, key, fromB64(wrap.wk) as unknown as BufferSource,
  ));
  return toB64(pt);
}

/** web's Jp(): parse a rekey payload from decrypted group text */
export function parseRekeyPayload(text: string): GroupRekeyPayload | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_group_rekey":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_group_rekey !== 1 || !Number.isInteger(t.ge) || Number(t.ge) < 1 || typeof t.pq !== 'string' || !Array.isArray(t.wraps)) return null;
    return {
      ge: Number(t.ge),
      pq: t.pq,
      wraps: (t.wraps as GroupRekeyWrap[]).filter((w) => w && typeof w.to === 'string' && typeof w.ct === 'string' && typeof w.wk === 'string' && typeof w.wi === 'string'),
    };
  } catch { return null; }
}

/** web's Em(): try to apply a rekey payload to my group record */
export async function applyRekeyPayload(
  store: VeilStorage, groupToken: string, payload: GroupRekeyPayload, myPqPrivB64: string,
): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec) return false;
  const wrap = (payload.wraps || []).find((w) => w && w.to === rec.veilId);
  if (!wrap) return false;
  const newGekB64 = await openRekeyWrap(myPqPrivB64, wrap);
  return advanceEpoch(store, groupToken, Number(payload.ge), newGekB64, String(payload.pq || rec.pqPubB64));
}

/** web's Dm(): move to a new epoch (sendN/recv reset, new sender tag) */
export async function advanceEpoch(
  store: VeilStorage, groupToken: string, epoch: number, gekB64: string, pqPubB64: string,
): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  rec.epoch = epoch;
  rec.gekB64 = gekB64;
  rec.pqPubB64 = pqPubB64;
  rec.myTag = await senderTag(groupToken, epoch, rec.veilId);
  rec.sendN = 0;
  rec.recv = {};
  rec.envCount = 0;
  rec.epochStartedAt = new Date().toISOString();
  await saveGroupRecord(store, rec);
  return true;
}

/** creator: does this group need an auto-rotation? (100 envelopes / 24 h) */
export function groupNeedsRotation(rec: GroupRecord): boolean {
  const byCount = (rec.envCount ?? 0) >= EPOCH_MAX_ENVELOPES;
  const started = rec.epochStartedAt ? Date.parse(rec.epochStartedAt) : Date.now();
  const byAge = Date.now() - started >= EPOCH_MAX_MS;
  return byCount || byAge;
}

// ---------- signatures ----------

/** web's Om(): creator/member attestation signature */
export function attestSignature(ikSeedB64: string, groupToken: string, veilId: string, ikPubB64: string, joinedEpoch: number): Promise<string> {
  return ikSign(ikSeedB64, toB64(utf8(JSON.stringify({ group_token: groupToken, veil_id: veilId, IK_pub: ikPubB64, joined_epoch: joinedEpoch }))));
}

/** web's km(): deny-list eviction signature */
export function denySignature(ikSeedB64: string, groupToken: string, targetIkPubB64: string, denyEpoch: number): Promise<string> {
  return ikSign(ikSeedB64, toB64(utf8(JSON.stringify({ group_token: groupToken, target_IK_pub: targetIkPubB64, deny_epoch: denyEpoch }))));
}

// ---------- intro (web's Kp/Im) ----------

export interface GroupIntro { veilId: string; ikPub: string; nick: string }

export function parseGroupIntro(text: string): { p: string; s: string } | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_intro":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_intro !== 1 || typeof t.p !== 'string' || typeof t.s !== 'string') return null;
    const inner = JSON.parse(t.p) as Record<string, unknown>;
    if (inner.v !== 1 || typeof inner.id !== 'string' || typeof inner.ik !== 'string') return null;
    return { p: t.p, s: t.s };
  } catch { return null; }
}

export async function verifyGroupIntro(intro: { p: string; s: string }): Promise<GroupIntro | null> {
  try {
    const inner = JSON.parse(intro.p) as { v?: number; id?: string; ik?: string; nick?: string };
    const okSig = await verifyWithIk(String(inner.ik), toB64(utf8(intro.p)), intro.s);
    if (!okSig) return null;
    const derived = await veilIdFromIkPub(String(inner.ik));
    if (derived !== String(inner.id)) return null;
    return { veilId: String(inner.id), ikPub: String(inner.ik), nick: typeof inner.nick === 'string' ? inner.nick.slice(0, 40) : '' };
  } catch { return null; }
}
