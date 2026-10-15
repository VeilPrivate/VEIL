/**
 * @veil/crypto-core — veil-ratchet-3 session engine.
 *
 * PORTED VERBATIM from the live web bundle (index-DpU6jXgg.js), Sept 13 2026.
 * Minified-name -> clean-name map (strict invite family):
 *   [contact one-tap family, ported from index-DYGFL-4a.js Sept 13 2026:]
 *   Dm  = createContactSession     (initiator: ephemeral X25519 vs peer SPK + PQ encap)
 *   Om  = acceptContactSession     (responder: SPK priv unwrap + ratchet root)
 *   Em  = contactWriteSecrets      (HKDF 'veil-contact-write-v1' initiator/responder)
 *   am  = completeHandshake contact branch (initiator completes vs responder ratchet pub)
 *   xm/Sm/wm/Tm = X25519 pair / import pub / import priv seed (PKCS8-wrapped) / ECDH
 *   Yp  = createSession          (initiator create)
 *   Xp  = joinSession            (responder join)
 *   Zp  = completeHandshake      (initiator completes; strict + contact branches)
 *   $p  = encryptMessage         (send: symmetric ratchet step + envelope)
 *   em  = decryptMessage         (receive: skipped keys / ratchet step / chain catch-up)
 *   Jp  = stepRatchet            (double-ratchet step, PQ re-key)
 *   qp  = catchUpChain           (out-of-order catch-up, skipped-key store)
 *   Gp  = storeSkipped / Kp = takeSkipped
 *   Fp  = advanceChain           (mk = HMAC(ck,0x01), ck' = HMAC(ck,0x02))
 *   Pp  = deriveRoot             (HKDF-64 {rk,ck}, info='veil-ratchet-3/rk')
 *   Wp  = deriveRk0              (HKDF-32, salt='veil-ratchet-3:'+token, info='rk0')
 *   Up  = derivePpSecret         (HKDF-32, salt='veil-pp:'+token, info='pp')
 *   Hp  = sessionFingerprint     (HEX(SHA-256(shared)) upper, 4-char groups)
 *   Op  = generateEcdhPair (P-256) / kp = exportPubJwk / Ap = importPubJwk
 *   jp  = ecdh (256 bits) / Mp = combine / Np = hkdf / S = mlkemEncap / w = mlkemDecap
 *   C   = mlkemKeypair
 *
 * Hybrid: ECDH P-256 + ML-KEM-768 at handshake AND per-step PQ re-key
 * (header carries our current pqStepPub; peer's next ratchet step folds
 * the secret encapsulated to it, and answers with its own fresh step pub).
 */

import { toB64, fromB64, utf8 } from './bytes';
import { hkdf, hmacSha256, sha256, combine, sessionFingerprint } from './kdf';
import { mlkemKeypair, mlkemEncap, mlkemDecap } from './mlkem';
import { padPlaintext, unpadPlaintext } from './padding';
import { ed25519 } from '@noble/curves/ed25519';
import { RATCHET_VERSION, RATCHET_PROTOCOL_LATEST, RATCHET_PROTOCOL_SUPPORTED, ROOT_KEY_INFO, PP_INFO, RK0_INFO, RATCHET_SIG_INFO } from './constants';

const MAX_COUNTER_GAP = 500;   // fp — max skip ahead before "desynchronised"
const MAX_SKIPPED_PER_CHAIN = 100; // pp
const MAX_PROCESSED_IDS = 500; // mp
const MAX_SEEN_PUBS = 64; // ou — replaced key epochs remembered for stale-header rejection
const MAX_MY_PUBS = 64; // b197-r4 — own ratchet pubs remembered for own-echo rejection (bounded state)

export type SessionRole = 'initiator' | 'responder';

export interface RatchetState {
  role: SessionRole;
  /** protocol tag this session writes into headers (old sessions stay ratchet-3; new ones are ratchet-4) */
  proto: string;
  /** replaced remote ratchet pubs — a header from an already-replaced epoch is rejected */
  seenRemotePubs: Set<string>;
  /** one-tap contact session (bootstraps from pinned IK + published SPK) */
  contact: boolean;
  ready: boolean;
  fingerprint: string | null;
  pq: 'hybrid' | 'classical';
  /** session ECDH (P-256) handshake keypair ("identity" of the session, not the Veil identity) */
  ikPair: CryptoKeyPair;
  ikPubJwk: string;
  bound: { initiatorPubJwk: string; responderPubJwk: string; responderRatchetPubJwk?: string } | null;
  /** ML-KEM handshake key (initiator) */
  pqPriv: string | null;
  /** per-step PQ re-key pair */
  pqStepPriv: string | null;
  pqStepPub: string | null;
  /** ct encapsulated to the peer's current step pub — travels in our next header */
  pendingPqCt: string | null;
  ppSecret: Uint8Array | null;
  /** contact sessions: write secret derived via 'veil-contact-write-v1' (relay authorization) */
  writeSecret: string | null;
  /** b197 (audit H-1): when true, ratchet-key rotations MUST carry a valid Ed25519
   *  signature derived from the session's pre-rotation shared secret — a spoofed
   *  header.rp can no longer splice the session onto attacker-controlled keys.
   *  Opt-in per session; legacy sessions (sigPubB64 === null) are untouched. */
  signed: boolean;
  sigPrivB64: string | null;
  sigPubB64: string | null;
  ratchetPair: CryptoKeyPair;
  ratchetPubJwk: string;
  remoteRatchetPubJwk: string | null;
  myPubs: Set<string>;
  rootKey: Uint8Array;
  sendChain: Uint8Array | null;
  recvChain: Uint8Array | null;
  sendCount: number;
  prevSendCount: number;
  recvCount: number;
  processedIds: Set<string>;
  skipped: Map<string, Map<number, Uint8Array>>;
}

// ---------- P-256 ECDH helpers (Op / kp / Ap / jp) ----------

async function generateEcdhPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as Promise<CryptoKeyPair>;
}

async function exportPubJwk(key: CryptoKey): Promise<string> {
  return JSON.stringify(await crypto.subtle.exportKey('jwk', key));
}

async function importPubJwk(jwk: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', JSON.parse(jwk), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

async function ecdh(priv: CryptoKey, pub: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256));
}

// ---------- X25519 helpers (xm / Sm / wm / Tm) ----------

/** xm: ephemeral X25519 keypair for the contact handshake. */
async function x25519Generate(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as Promise<CryptoKeyPair>;
}

/** Sm: import a raw X25519 public key from base64. */
async function x25519ImportPub(pubB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', fromB64(pubB64) as BufferSource, { name: 'X25519' }, true, []);
}

/** wm: wrap a 32-byte X25519 seed in the fixed PKCS8 prefix and import as a private key. */
const X25519_PKCS8_PREFIX = new Uint8Array([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32]);
async function x25519ImportPrivSeed(privSeedB64: string): Promise<CryptoKey> {
  const der = new Uint8Array(48);
  der.set(X25519_PKCS8_PREFIX, 0);
  der.set(fromB64(privSeedB64), 16);
  return crypto.subtle.importKey('pkcs8', der as BufferSource, { name: 'X25519' }, true, ['deriveBits']);
}

/** Tm: X25519 ECDH -> 256-bit shared secret. */
async function x25519Ecdh(priv: CryptoKey, pub: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256));
}

// ---------- contact write secrets (Em) ----------

/** Em: per-role relay write secrets for contact sessions. */
async function contactWriteSecrets(root: Uint8Array): Promise<{ initiator: string; responder: string }> {
  // SPEC (builder reference, Sept 18): the write credentials are LOWERCASE-HEX
  // strings (64 chars), never base64. The relay stores lowercaseHex(SHA256(utf8(secret)))
  // and the join/fetch/submit calls send the plain hex string — a base64 secret here
  // silently produced a completely different credential than the web client derives.
  const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  const initiator = await hkdf(root, utf8('veil-contact-write-v1'), 'initiator', 32);
  const responder = await hkdf(root, utf8('veil-contact-write-v1'), 'responder', 32);
  return { initiator: hex(initiator), responder: hex(responder) };
}

// ---------- roots / chains (Pp / Fp / Wp / Up / Hp) ----------

/** Pp: HKDF-64 -> {rk, ck}. salt first, ikm (+optional extra) second. */
async function deriveRoot(salt: Uint8Array, ikm: Uint8Array, extra: Uint8Array | null): Promise<{ rk: Uint8Array; ck: Uint8Array }> {
  const material = extra ? combine(ikm, extra) : ikm;
  const out = await hkdf(material, salt, ROOT_KEY_INFO, 64);
  return { rk: out.slice(0, 32), ck: out.slice(32, 64) };
}

/** Wp: the "rk0" handshake root. */
async function deriveRk0(shared: Uint8Array, token: string): Promise<Uint8Array> {
  return hkdf(shared, utf8(`veil-ratchet-3:${token}`), RK0_INFO, 32);
}

/** Up: strict-invite prekey secret from the #w= fragment (never sent to the relay). */
export async function derivePpSecret(inviteSecret: string, token: string): Promise<Uint8Array> {
  if (!inviteSecret) return new Uint8Array();
  return hkdf(utf8(inviteSecret), utf8(`veil-pp:${token}`), PP_INFO, 32);
}

interface ChainKeys { ck: Uint8Array; mk: Uint8Array }

/** Fp: symmetric chain step. */
async function advanceChain(chain: Uint8Array): Promise<ChainKeys> {
  const mk = await hmacSha256(chain, new Uint8Array([1]));
  const ck = await hmacSha256(chain, new Uint8Array([2]));
  return { ck, mk };
}

// ---------- skipped keys (Gp / Kp) ----------

function storeSkipped(state: RatchetState, rp: string, n: number, mk: Uint8Array): void {
  let per = state.skipped.get(rp);
  if (!per) { per = new Map(); state.skipped.set(rp, per); }
  per.set(n, mk);
  while (per.size > MAX_SKIPPED_PER_CHAIN) per.delete(per.keys().next().value as number);
  let total = 0;
  for (const m of state.skipped.values()) total += m.size;
  while (total > MAX_COUNTER_GAP && state.skipped.size > 1) {
    const oldest = state.skipped.keys().next().value as string;
    total -= state.skipped.get(oldest)!.size;
    state.skipped.delete(oldest);
  }
}

function takeSkipped(state: RatchetState, header: EnvelopeHeader): Uint8Array | null {
  const per = state.skipped.get(header.rp);
  if (!per) return null;
  const mk = per.get(header.n);
  if (mk) per.delete(header.n);
  return mk ?? null;
}

/**
 * b185 SPEC CONFORMANCE FIX (Signal Double Ratchet spec, DHRatchet / header.pn):
 * before accepting the peer's NEW ratchet pub and rotating, skip-and-store
 * message keys on the CURRENT receive chain up to header.pn (the length of
 * the sender's previous sending chain). Stragglers from the old chain that
 * arrive after the rotation (relay reordering, re-fetch, offline backlog)
 * then still decrypt from the skipped-key store instead of being rejected
 * forever as a "stale epoch". Receiver-side only — no wire-format change,
 * fully compatible with peers that never rotate mid-backlog.
 */
async function skipOldChainBeforeRotation(state: RatchetState, pn: number): Promise<void> {
  if (!state.recvChain || state.remoteRatchetPubJwk === null) return; // no old chain to protect
  if (pn < state.recvCount || pn - state.recvCount > MAX_COUNTER_GAP) {
    // Desync guard (same rule as messageKeyFor): a pn that rewinds or runs
    // far past our counter is a malformed header — fail closed, change nothing.
    throw new Error('Message counter out of range — the session is desynchronised.');
  }
  while (state.recvCount < pn) {
    const step = await advanceChain(state.recvChain);
    state.recvChain = step.ck;
    storeSkipped(state, state.remoteRatchetPubJwk, state.recvCount, step.mk);
    state.recvCount += 1;
  }
}

// ---------- message header ----------

export interface EnvelopeHeader {
  v: string;
  /** sender's current ratchet pub (JWK string) */
  rp: string;
  /** sender's previous chain length at last ratchet step */
  pn: number;
  /** message counter in the current chain */
  n: number;
  /** per-step PQ: our current step pub */
  pq?: string;
  /** ct encapsulated to the peer's step pub */
  pqct?: string;
  /** b197 (audit H-1): Ed25519 signature over the ratchet pub (signed sessions only) */
  sig?: string;
}

export interface Envelope {
  ciphertext: string;
  iv: string;
  /** serialized JSON header — AES-GCM AAD */
  header: string;
  byteLength?: number;
}

async function importAesKey(mk: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', mk as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---------- authenticated ratchet keys (b197, audit H-1) ----------

/**
 * b197 (audit H-1): derive a session-scoped Ed25519 signing pair from the
 * PRE-ROTATION shared secret (rk0 for strict sessions, the contact root for
 * one-tap sessions). Both peers derive the SAME pair: each side signs its own
 * ratchet pubs and the other verifies. Without this, an on-path attacker who
 * can inject an envelope with their own rp rotates the receiver onto keys the
 * attacker can compute (ECDH is symmetric), then delivers an envelope that
 * authenticates — the classic unsigned-DHr splice. Legacy sessions
 * (sigPubB64 === null) keep the unchanged unsigned behavior: zero wire-compat
 * risk until web-client parity lands.
 */
async function deriveSigPair(shared: Uint8Array, token: string): Promise<{ privB64: string; pubB64: string }> {
  const seed = await hkdf(shared, utf8(`${RATCHET_SIG_INFO}:${token}`), RATCHET_SIG_INFO, 32);
  return { privB64: toB64(seed), pubB64: toB64(ed25519.getPublicKey(seed)) };
}

/** b197: sign the current ratchet pub (no-op on unsigned sessions). */
function signRatchetPub(state: RatchetState, rpJwk: string): string | undefined {
  if (!state.sigPrivB64) return undefined;
  return toB64(ed25519.sign(utf8(`${RATCHET_SIG_INFO}:${rpJwk}`), fromB64(state.sigPrivB64)));
}

/** b197: fail-closed verification on ratchet rotation (no-op on unsigned sessions). */
function verifyRatchetPubSig(state: RatchetState, rpJwk: string, sig: string | undefined): void {
  if (!state.sigPubB64) return;
  if (!sig) throw new Error('Unsigned ratchet rotation rejected — this session requires signed key epochs.');
  // noble v1 order: verify(signature, message, publicKey)
  if (!ed25519.verify(fromB64(sig), utf8(`${RATCHET_SIG_INFO}:${rpJwk}`), fromB64(state.sigPubB64))) {
    throw new Error('Invalid ratchet rotation signature — header did not authenticate against the session.');
  }
}

// ---------- session creation (Yp) ----------

export interface CreatedSession {
  state: RatchetState;
  /** the initiator's session pub JWK — the `initiator_pub_jwk` field */
  initiatorPubJwk: string;
  /** ML-KEM pub (~1184B, b64) — the `initiator_pq_pub` field */
  initiatorPqPub: string | null;
}

/** Initiator creates a strict session (Yp). inviteSecret = the #w= fragment. */
export async function createSession(token: string, inviteSecret: string, hybrid = true, signed = false): Promise<CreatedSession> {
  const ikPair = await generateEcdhPair();
  const ikPubJwk = await exportPubJwk(ikPair.publicKey);
  const ppSecret = await derivePpSecret(inviteSecret, token);
  let pq: { pub: string; priv: string } | null = null;
  if (hybrid) {
    try { pq = await mlkemKeypair(); } catch { pq = null; }
  }
  const state: RatchetState = {
    role: 'initiator',
    proto: RATCHET_PROTOCOL_LATEST,
    seenRemotePubs: new Set(),
    contact: false,
    ready: false,
    fingerprint: null,
    pq: hybrid && pq ? 'hybrid' : 'classical',
    ikPair,
    ikPubJwk,
    bound: null,
    pqPriv: pq?.priv ?? null,
    pqStepPriv: null,
    pqStepPub: null,
    pendingPqCt: null,
    ppSecret: ppSecret.length ? ppSecret : null,
    writeSecret: null,
    signed,
    sigPrivB64: null,
    sigPubB64: null,
    ratchetPair: null as unknown as CryptoKeyPair,
    ratchetPubJwk: '',
    remoteRatchetPubJwk: null,
    myPubs: new Set<string>(),
    rootKey: new Uint8Array(32),
    sendChain: null,
    recvChain: null,
    sendCount: 0,
    prevSendCount: 0,
    recvCount: 0,
    processedIds: new Set<string>(),
    skipped: new Map(),
  };
  return { state, initiatorPubJwk: ikPubJwk, initiatorPqPub: pq ? pq.pub : null };
}

// ---------- responder join (Xp) ----------

export interface JoinedSession {
  state: RatchetState;
  responderPubJwk: string;
  responderRatchetPubJwk: string;
  /** ct encapsulated to the initiator's ML-KEM pub — the `responder_pq_ct` field */
  responderPqCt: string | null;
  fingerprint: string;
}

/** Responder joins (Xp). Session is READY on return (root1 = send chain). */
export async function joinSession(
  token: string,
  inviteSecret: string,
  initiatorPubJwk: string,
  initiatorPqPub: string | null,
  hybrid = true,
  signed = false,
): Promise<JoinedSession> {
  const initiatorPub = await importPubJwk(initiatorPubJwk);
  const ikPair = await generateEcdhPair();
  const dh = await ecdh(ikPair.privateKey, initiatorPub);
  let shared = dh;
  let pqCt: string | null = null;
  let stepPq: { pub: string; priv: string } | null = null;
  if (hybrid && initiatorPqPub) {
    const { ct, secret } = await mlkemEncap(initiatorPqPub);
    shared = combine(dh, secret);
    pqCt = ct;
    try { stepPq = await mlkemKeypair(); } catch { stepPq = null; }
  }
  shared = combine(shared, await derivePpSecret(inviteSecret, token));
  const rk0 = await deriveRk0(shared, token);
  const sig = signed ? await deriveSigPair(rk0, token) : null;
  const ratchetPair = await generateEcdhPair();
  const root1 = await deriveRoot(rk0, await ecdh(ratchetPair.privateKey, initiatorPub), null);
  const fingerprint = await sessionFingerprint(shared);
  const state: RatchetState = {
    role: 'responder',
    proto: RATCHET_PROTOCOL_LATEST,
    seenRemotePubs: new Set(),
    contact: false,
    ready: true,
    fingerprint,
    pq: pqCt ? 'hybrid' : 'classical',
    ikPair,
    ikPubJwk: await exportPubJwk(ikPair.publicKey),
    bound: {
      initiatorPubJwk,
      responderPubJwk: await exportPubJwk(ikPair.publicKey),
      responderRatchetPubJwk: await exportPubJwk(ratchetPair.publicKey),
    },
    pqPriv: null,
    pqStepPriv: stepPq?.priv ?? null,
    signed,
    sigPrivB64: sig?.privB64 ?? null,
    sigPubB64: sig?.pubB64 ?? null,
    pqStepPub: stepPq?.pub ?? null,
    pendingPqCt: null,
    ppSecret: null,
    writeSecret: null,
    ratchetPair,
    ratchetPubJwk: await exportPubJwk(ratchetPair.publicKey),
    remoteRatchetPubJwk: initiatorPubJwk,
    myPubs: new Set<string>(),
    rootKey: root1.rk,
    sendChain: root1.ck,
    recvChain: null,
    sendCount: 0,
    prevSendCount: 0,
    recvCount: 0,
    processedIds: new Set<string>(),
    skipped: new Map(),
  };
  state.myPubs.add(state.ratchetPubJwk);
  return {
    state,
    responderPubJwk: state.ikPubJwk,
    responderRatchetPubJwk: state.ratchetPubJwk,
    responderPqCt: pqCt,
    fingerprint,
  };
}


// ---------- one-tap contact session family (Dm / Om, ported from DYGFL-4a) ----------

export interface ContactPeerPrekeys {
  /** peer's published X25519 SPK (looked up from the identity gate; SPK_sig verified vs pinned IK) */
  spkPubB64: string;
  /** peer's published ML-KEM-768 pub (hybrid) */
  pqPubB64?: string | null;
}

export interface CreatedContactSession {
  state: RatchetState;
  /** ephemeral X25519 pub — travels to the peer in the session request */
  ekPubB64: string;
  /** ML-KEM ct encapsulated to the peer's pq_pub ('' when classical) */
  pqCt: string;
  /** the session-bound P-256 pub JWK presented as the initiator's handshake key */
  ikPubJwk: string;
  writeSecrets: { initiator: string; responder: string };
  fingerprint: string;
}

/** Dm: initiator bootstraps a one-tap session from the pinned peer's published prekeys. */
export async function createContactSession(token: string, peer: ContactPeerPrekeys, signed = false): Promise<CreatedContactSession> {
  const ek = await x25519Generate();
  const ekPubB64 = toB64(new Uint8Array(await crypto.subtle.exportKey('raw', ek.publicKey)));
  let shared = await x25519Ecdh(ek.privateKey, await x25519ImportPub(peer.spkPubB64));
  let pqCt = '';
  let hybrid = false;
  if (peer.pqPubB64) {
    const enc = await mlkemEncap(peer.pqPubB64);
    shared = combine(shared, enc.secret);
    pqCt = enc.ct;
    hybrid = true;
  }
  const rootKey = await deriveRk0(shared, token);
  const sig = signed ? await deriveSigPair(rootKey, token) : null;
  const writeSecrets = await contactWriteSecrets(rootKey);
  const ikPair = await generateEcdhPair();
  const ikPubJwk = await exportPubJwk(ikPair.publicKey);
  const fingerprint = await sessionFingerprint(shared);
  const state: RatchetState = {
    role: 'initiator',
    proto: RATCHET_PROTOCOL_LATEST,
    seenRemotePubs: new Set(),
    contact: true,
    ready: false,
    fingerprint,
    pq: hybrid ? 'hybrid' : 'classical',
    ikPair,
    ikPubJwk,
    bound: null,
    pqPriv: null,
    pqStepPriv: null,
    pqStepPub: null,
    pendingPqCt: null,
    ppSecret: null,
    writeSecret: writeSecrets.initiator,
    signed,
    sigPrivB64: sig?.privB64 ?? null,
    sigPubB64: sig?.pubB64 ?? null,
    ratchetPair: null as unknown as CryptoKeyPair,
    ratchetPubJwk: '',
    remoteRatchetPubJwk: null,
    myPubs: new Set<string>(),
    rootKey,
    sendChain: null,
    recvChain: null,
    sendCount: 0,
    prevSendCount: 0,
    recvCount: 0,
    processedIds: new Set<string>(),
    skipped: new Map(),
  };
  return { state, ekPubB64, pqCt, ikPubJwk, writeSecrets, fingerprint };
}

export interface ContactRequest {
  /** initiator's ephemeral X25519 pub */
  ekPubB64: string;
  /** ct encapsulated to OUR pq_pub (null/'' when the request was classical) */
  pqCt?: string | null;
  /** OUR SPK private seed (device keyvault) */
  spkPrivB64: string;
  /** OUR ML-KEM private key (device keyvault; required to unwrap a hybrid request) */
  pqPrivB64?: string | null;
  /** initiator's session P-256 pub JWK (from the request) */
  initiatorP256Jwk: string;
}

export interface AcceptedContactSession {
  state: RatchetState;
  fingerprint: string;
  responderPubJwk: string;
  responderRatchetPubJwk: string;
  writeSecret: string;
}

/** Om: responder accepts the one-tap request; session is READY on return. */
export async function acceptContactSession(token: string, req: ContactRequest, signed = false): Promise<AcceptedContactSession> {
  let shared = await x25519Ecdh(await x25519ImportPrivSeed(req.spkPrivB64), await x25519ImportPub(req.ekPubB64));
  let hybrid = false;
  if (req.pqCt && req.pqPrivB64) {
    shared = combine(shared, await mlkemDecap(req.pqPrivB64, req.pqCt));
    hybrid = true;
  }
  const rootKey = await deriveRk0(shared, token);
  // b197: MUST mirror the initiator's signed flag — derive only when opted in,
  // otherwise the responder demands sigs the initiator never sends.
  const sig = signed ? await deriveSigPair(rootKey, token) : null;
  const writeSecrets = await contactWriteSecrets(rootKey);
  const initiatorPub = await importPubJwk(req.initiatorP256Jwk);
  const ratchetPair = await generateEcdhPair();
  const root1 = await deriveRoot(rootKey, await ecdh(ratchetPair.privateKey, initiatorPub), null);
  const ikPair = await generateEcdhPair();
  const ikPubJwk = await exportPubJwk(ikPair.publicKey);
  let step: { pub: string; priv: string } | null = null;
  if (hybrid) step = await pqStepPair(); // fail-closed (b118)
  const fingerprint = await sessionFingerprint(shared);
  const ratchetPubJwk = await exportPubJwk(ratchetPair.publicKey);
  const state: RatchetState = {
    role: 'responder',
    proto: RATCHET_PROTOCOL_LATEST,
    seenRemotePubs: new Set(),
    contact: true,
    ready: true,
    fingerprint,
    pq: hybrid ? 'hybrid' : 'classical',
    ikPair,
    ikPubJwk,
    bound: { initiatorPubJwk: req.initiatorP256Jwk, responderPubJwk: ikPubJwk, responderRatchetPubJwk: ratchetPubJwk },
    pqPriv: null,
    pqStepPriv: step?.priv ?? null,
    pqStepPub: step?.pub ?? null,
    pendingPqCt: null,
    ppSecret: null,
    writeSecret: writeSecrets.responder,
    signed,
    sigPrivB64: sig?.privB64 ?? null,
    sigPubB64: sig?.pubB64 ?? null,
    ratchetPair,
    ratchetPubJwk,
    remoteRatchetPubJwk: req.initiatorP256Jwk,
    myPubs: new Set<string>(),
    rootKey: root1.rk,
    sendChain: root1.ck,
    recvChain: null,
    sendCount: 0,
    prevSendCount: 0,
    recvCount: 0,
    processedIds: new Set<string>(),
    skipped: new Map(),
  };
  state.myPubs.add(state.ratchetPubJwk);
  return { state, fingerprint, responderPubJwk: ikPubJwk, responderRatchetPubJwk: ratchetPubJwk, writeSecret: writeSecrets.responder };
}

// ---------- initiator completes the handshake (Zp, strict branch) ----------

/** Completes the handshake from the responder's join material; returns the converged fingerprint. */
export async function completeHandshake(
  state: RatchetState,
  token: string,
  responderPubJwk: string,
  responderRatchetPubJwk: string,
  responderPqCt: string | null,
): Promise<string> {
  if (state.role !== 'initiator') throw new Error('Only the initiator completes the handshake');
  if (state.ready) return state.fingerprint!;

  // contact branch (am): root was already derived at create from the peer's SPK;
  // complete against the responder's ratchet pub. Fingerprint is NOT recomputed.
  if (state.contact) {
    // b197 (audit H-1): derive the signing pair from the pre-rotation contact
    // root BEFORE the root chain below overwrites state.rootKey.
    if (state.signed && !state.sigPrivB64) {
      const sig = await deriveSigPair(state.rootKey, token);
      state.sigPrivB64 = sig.privB64;
      state.sigPubB64 = sig.pubB64;
    }
    const responderRatchetPub = await importPubJwk(responderRatchetPubJwk);
    const root1 = await deriveRoot(state.rootKey, await ecdh(state.ikPair.privateKey, responderRatchetPub), null);
    const ratchetPair = await generateEcdhPair();
    const root2 = await deriveRoot(root1.rk, await ecdh(ratchetPair.privateKey, responderRatchetPub), null);
    state.rootKey = root2.rk;
    state.ratchetPair = ratchetPair;
    state.ratchetPubJwk = await exportPubJwk(ratchetPair.publicKey);
    state.remoteRatchetPubJwk = responderRatchetPubJwk;
    state.bound = { initiatorPubJwk: state.ikPubJwk, responderPubJwk, responderRatchetPubJwk };
    state.sendChain = root2.ck;
    state.recvChain = root1.ck;
    state.sendCount = 0;
    state.prevSendCount = 0;
    state.recvCount = 0;
    state.skipped = new Map();
    state.processedIds = new Set<string>();
    state.ready = true;
    state.myPubs = new Set([state.ratchetPubJwk]);
    let step: { pub: string; priv: string } | null = null;
    if (state.pq === 'hybrid') step = await pqStepPair(); // fail-closed (b118)
    state.pqStepPriv = step?.priv ?? null;
    state.pqStepPub = step?.pub ?? null;
    state.pendingPqCt = null;
    return state.fingerprint!;
  }

  const responderPub = await importPubJwk(responderPubJwk);
  const responderRatchetPub = await importPubJwk(responderRatchetPubJwk);

  const dh = await ecdh(state.ikPair.privateKey, responderPub);
  let shared = dh;
  let stepPq: { pub: string; priv: string } | null = null;
  if (state.pq === 'hybrid' && state.pqPriv && responderPqCt) {
    shared = combine(dh, await mlkemDecap(state.pqPriv, responderPqCt));
    try { stepPq = await mlkemKeypair(); } catch { stepPq = null; }
  }
  shared = combine(shared, state.ppSecret ?? new Uint8Array());
  const rk0 = await deriveRk0(shared, token);
  // b197 (audit H-1): initiator-side signing pair, derived from the same rk0
  // the responder derived theirs from — both sides converge on one keypair.
  if (state.signed && !state.sigPrivB64) {
    const sig = await deriveSigPair(rk0, token);
    state.sigPrivB64 = sig.privB64;
    state.sigPubB64 = sig.pubB64;
  }
  const root1 = await deriveRoot(rk0, await ecdh(state.ikPair.privateKey, responderRatchetPub), null);
  const ratchetPair = await generateEcdhPair();
  const root2 = await deriveRoot(root1.rk, await ecdh(ratchetPair.privateKey, responderRatchetPub), null);

  state.rootKey = root2.rk;
  state.ratchetPair = ratchetPair;
  state.ratchetPubJwk = await exportPubJwk(ratchetPair.publicKey);
  state.remoteRatchetPubJwk = responderRatchetPubJwk;
  state.bound = { initiatorPubJwk: state.ikPubJwk, responderPubJwk, responderRatchetPubJwk };
  state.sendChain = root2.ck;
  state.recvChain = root1.ck;
  state.sendCount = 0;
  state.prevSendCount = 0;
  state.recvCount = 0;
  state.skipped = new Map();
  state.processedIds = new Set<string>();
  state.fingerprint = await sessionFingerprint(shared);
  state.ready = true;
  state.pqStepPriv = stepPq?.priv ?? null;
  state.pqStepPub = stepPq?.pub ?? null;
  state.pendingPqCt = null;
  state.myPubs = new Set([state.ratchetPubJwk]);
  return state.fingerprint;
}

// ---------- ratchet step (Jp) ----------

async function stepRatchet(state: RatchetState, header: EnvelopeHeader): Promise<void> {
  if (header.rp === state.ratchetPubJwk) return; // own pub echoed (multi-tab guard) — no step
  if (state.seenRemotePubs.has(header.rp)) {
    throw new Error('Stale ratchet header — this message belongs to an already-replaced key epoch.');
  }
  // b197 (audit H-1): verify the rotation signature BEFORE any DH work or
  // state mutation. Runs on the isolated candidate state in decryptMessage,
  // so a rejected header changes nothing (same atomicity rule as below).
  verifyRatchetPubSig(state, header.rp, header.sig);
  const pub = await importPubJwk(header.rp);
  let pqRekeySecret: Uint8Array | null = null;
  if (state.pq === 'hybrid' && state.pqStepPriv && header.pqct) {
    pqRekeySecret = await mlkemDecap(state.pqStepPriv, header.pqct);
  }
  let pqAnswerSecret: Uint8Array | null = null;
  if (state.pq === 'hybrid' && header.pq) {
    const { ct, secret } = await mlkemEncap(header.pq);
    pqAnswerSecret = secret;
    state.pendingPqCt = ct;
  }
  const rootA = await deriveRoot(state.rootKey, await ecdh(state.ratchetPair.privateKey, pub), pqRekeySecret);
  const fresh = await generateEcdhPair();
  const rootB = await deriveRoot(rootA.rk, await ecdh(fresh.privateKey, pub), pqAnswerSecret);
  state.prevSendCount = state.sendCount;
  state.sendCount = 0;
  state.recvCount = 0;
  state.rootKey = rootB.rk;
  state.ratchetPair = fresh;
  state.ratchetPubJwk = await exportPubJwk(fresh.publicKey);
  if (state.remoteRatchetPubJwk) {
    state.seenRemotePubs.add(state.remoteRatchetPubJwk);
    while (state.seenRemotePubs.size > MAX_SEEN_PUBS) state.seenRemotePubs.delete(state.seenRemotePubs.keys().next().value as string);
  }
  state.remoteRatchetPubJwk = header.rp;
  state.sendChain = rootB.ck;
  state.recvChain = rootA.ck;
  state.myPubs.add(state.ratchetPubJwk);
  // b197-r4: bound myPubs growth — one pub per rotation, serialized forever
  // otherwise. 64 epochs of own-echo history is far beyond any realistic
  // relay reorder window; evicted echoes fail closed via the counter guard.
  while (state.myPubs.size > MAX_MY_PUBS) state.myPubs.delete(state.myPubs.keys().next().value as string);
  if (state.pq === 'hybrid') {
    const step = await pqStepPair(); // fail-closed (b118)
    state.pqStepPriv = step.priv;
    state.pqStepPub = step.pub;
  }
}

// ---------- chain catch-up (qp) ----------

async function messageKeyFor(state: RatchetState, n: number): Promise<Uint8Array> {
  if (!state.recvChain) throw new Error('No receive chain for this message');
  if (n < state.recvCount || n - state.recvCount > MAX_COUNTER_GAP) {
    throw new Error('Message counter out of range — the session is desynchronised.');
  }
  while (state.recvCount < n) {
    const step = await advanceChain(state.recvChain);
    state.recvChain = step.ck;
    storeSkipped(state, state.remoteRatchetPubJwk!, state.recvCount, step.mk);
    state.recvCount += 1;
  }
  const step = await advanceChain(state.recvChain);
  state.recvChain = step.ck;
  state.recvCount += 1;
  return step.mk;
}

// ---------- per-message pseudonym (Ru in the web reference) ----------

/**
 * SPEC §4: sender_client_id = 'a' + lowercaseHex(SHA-256(UTF8(rp_string)))
 * from the FIRST 6 BYTES of the digest (12 hex chars, 13 total).
 * The relay verifies this against the envelope header — the raw client_id
 * must NEVER travel as sender_client_id (native<->native hid this).
 */
export async function senderPseudonym(headerJson: string): Promise<string> {
  const rp = (JSON.parse(headerJson) as { rp?: string }).rp || '';
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(rp) as unknown as BufferSource));
  return 'a' + [...h.slice(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------- PQ step keys (fail-closed) ----------

/**
 * PQ step-key generation (staged fix, 24 Sep 2026 — owner fail-closed decision).
 * A hybrid session must NEVER silently downgrade to classical: if ML-KEM key
 * generation fails, the operation aborts loudly and the caller retries. The
 * message/handshake is never sent without its post-quantum binding.
 */
async function pqStepPair(): Promise<{ pub: string; priv: string }> {
  try {
    return await mlkemKeypair();
  } catch (e) {
    throw new Error('Post-quantum key generation failed — send aborted to avoid a security downgrade. Please retry.');
  }
}

// ---------- send ($p) ----------

/** Returns the envelope to submit to the relay. */
export async function encryptMessage(state: RatchetState, text: string, opts: { cover?: boolean; envelopeId?: string } = {}): Promise<Envelope> {
  if (!state.ready) throw new Error('Session keys not established. The session may have ended or locked.');
  if (state.pq === 'hybrid' && !state.pqStepPub) {
    const step = await pqStepPair(); // fail-closed (b118)
    state.pqStepPriv = step.priv;
    state.pqStepPub = step.pub;
  }
  const step = await advanceChain(state.sendChain!);
  state.sendChain = step.ck;
  const header: EnvelopeHeader = {
    v: state.proto || RATCHET_VERSION,
    rp: state.ratchetPubJwk,
    pn: state.prevSendCount,
    n: state.sendCount,
  };
  // b197 (audit H-1): signed sessions authenticate every ratchet pub in every
  // header; receivers verify at rotation time.
  const sig = signRatchetPub(state, state.ratchetPubJwk);
  if (sig) header.sig = sig;
  if (state.pq === 'hybrid' && state.pqStepPub) {
    header.pq = state.pqStepPub;
    // b197-r1 (audit follow-up): a b197 draft cleared pendingPqCt after first
    // send ("consume-once"). REVERTED — the b185 DR vector suite caught a real
    // desync: the re-send IS the delivery mechanism for the PQ re-key. If the
    // message carrying the ct is lost/held/reordered, the peer's next rotation
    // would fold NOTHING and the chains diverge (AES auth failure). The ct is
    // re-sent until the sender's NEXT rotation replaces it; a stale ct decaps
    // to a harmless deterministic pseudorandom secret on the peer's CURRENT
    // step key. TRUE per-epoch PQ freshness needs a consumption-ack in the
    // header (protocol change, needs web parity) — tracked as audit follow-up.
    if (state.pendingPqCt) header.pqct = state.pendingPqCt;
  }
  state.sendCount += 1;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = utf8(JSON.stringify(header));
  const key = await importAesKey(step.mk);
  const padded = padPlaintext(text, !!opts.cover);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource }, key, padded as BufferSource);
  return { ciphertext: toB64(new Uint8Array(ct)), iv: toB64(iv), header: JSON.stringify(header), byteLength: padded.length };
}

// ---------- receive (em) ----------

export interface DecryptedMessage { text: string; cover: boolean }

/** Decrypts an envelope. `envelope.header` is the serialized header (AAD). */
export async function decryptMessage(state: RatchetState, envelope: Envelope, envelopeId?: string): Promise<DecryptedMessage | null> {
  if (!state.ready) throw new Error('Session keys not established. The session may have ended or locked.');
  const header = JSON.parse(envelope.header) as EnvelopeHeader;
  if (!(RATCHET_PROTOCOL_SUPPORTED as readonly string[]).includes(header.v)) throw new Error('Unsupported protocol version in message header.');
  // b197-r4 (stress hardening): an envelope whose header rp is one of OUR pubs
  // is our own echo — never decrypt it locally. The sync layer filters these
  // via myPubs before decrypt (chat.ts); this engine-level guard makes the
  // ratchet itself immune to a bypassed filter consuming a REAL message key
  // (counter drift -> desync). Same contract as the replay guard: null =
  // "nothing to decrypt", callers already handle it.
  if (state.myPubs.has(header.rp)) return null;
  if (envelopeId) {
    if (state.processedIds.has(envelopeId)) return null; // idempotent replay guard
    // NOTE (audit fix, Sept 19): mark processed ONLY AFTER a successful decrypt.
    // Marking before meant a single failed/Corrupted envelope was permanently
    // invisible on every later poll (replay guard swallowed the retry) — a
    // silent one-message loss. A failing envelope now retries each poll,
    // deterministically and state-safely (messageKeyFor never rewinds).
  }
  // Work on an isolated candidate state: a malformed envelope must not consume
  // skipped keys, advance receive counters, or rotate root keys before AEAD
  // authentication succeeds. Sets and inner maps are copied because helpers
  // mutate them in place. Their sizes are bounded by the protocol limits.
  const candidate: RatchetState = {
    ...state,
    seenRemotePubs: new Set(state.seenRemotePubs),
    myPubs: new Set(state.myPubs),
    processedIds: new Set(state.processedIds),
    skipped: new Map([...state.skipped].map(([rp, keys]) => [rp, new Map(keys)])),
  };
  let mk = takeSkipped(candidate, header);
  if (!mk) {
    if (header.rp !== state.remoteRatchetPubJwk) {
      // b185: spec DHRatchet — drain the old receive chain (up to header.pn)
      // into the skipped-key store BEFORE rotating, so old-epoch stragglers
      // remain decryptable. Runs on the isolated candidate state, so a
      // malformed envelope changes nothing (same atomicity rule as below).
      await skipOldChainBeforeRotation(candidate, header.pn);
      await stepRatchet(candidate, header);
    }
    mk = await messageKeyFor(candidate, header.n);
  }
  const key = await importAesKey(mk);
  const aad = utf8(envelope.header);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(envelope.iv) as BufferSource, additionalData: aad as BufferSource },
    key,
    fromB64(envelope.ciphertext) as BufferSource,
  );
  const { text, cover } = unpadPlaintext(new Uint8Array(pt));
  if (envelopeId) {
    candidate.processedIds.add(envelopeId);
    if (candidate.processedIds.size > MAX_PROCESSED_IDS) candidate.processedIds.delete(candidate.processedIds.keys().next().value as string);
  }
  Object.assign(state, candidate); // commit only after authenticated decrypt + frame parse
  return { text, cover };
}

// ---------- persistence (serialize / deserialize) ----------
// Mirrors the web bundle's xp() snapshot: CryptoKeys cannot cross a storage
// boundary, so pairs serialize as JWK private keys; raw secrets as b64.

export interface RatchetStateSerialized {
  role: SessionRole;
  proto?: string;
  seenRemotePubs?: string[];
  contact: boolean;
  ready: boolean;
  fingerprint: string | null;
  pq: 'hybrid' | 'classical';
  writeSecret: string | null;
  ikPubJwk: string;
  ikPrivJwk: string;
  bound: RatchetState['bound'];
  pqPriv: string | null;
  pqStepPriv: string | null;
  pqStepPub: string | null;
  pendingPqCt: string | null;
  /** b197 (audit H-1): signed-rotation fields — optional so web-bundle-era state loads unchanged. */
  signed?: boolean;
  sigPrivB64?: string | null;
  sigPubB64?: string | null;
  ppSecretB64: string | null;
  ratchetPubJwk: string;
  ratchetPrivJwk: string;
  remoteRatchetPubJwk: string | null;
  myPubs: string[];
  rootKeyB64: string;
  sendChainB64: string | null;
  recvChainB64: string | null;
  sendCount: number;
  prevSendCount: number;
  recvCount: number;
  processedIds: string[];
  skipped: Array<[string, Array<[number, string]>]>;
}

async function exportPrivJwk(key: CryptoKey): Promise<string> {
  return JSON.stringify(await crypto.subtle.exportKey('jwk', key));
}


export async function serializeRatchetState(state: RatchetState): Promise<RatchetStateSerialized> {
  return {
    role: state.role,
    proto: state.proto,
    seenRemotePubs: [...state.seenRemotePubs],
    contact: state.contact,
    ready: state.ready,
    fingerprint: state.fingerprint,
    pq: state.pq,
    writeSecret: state.writeSecret,
    ikPubJwk: state.ikPubJwk,
    ikPrivJwk: await exportPrivJwk(state.ikPair.privateKey),
    bound: state.bound,
    pqPriv: state.pqPriv,
    pqStepPriv: state.pqStepPriv,
    pqStepPub: state.pqStepPub,
    pendingPqCt: state.pendingPqCt,
    // b197: signed-rotation fields are written ONLY when set — unsigned
    // sessions serialize byte-identically to pre-b197 state (frozen DR fixture
    // byte-equality and web-bundle state snapshots stay valid).
    ...(state.signed ? { signed: true } : {}),
    ...(state.sigPrivB64 ? { sigPrivB64: state.sigPrivB64 } : {}),
    ...(state.sigPubB64 ? { sigPubB64: state.sigPubB64 } : {}),
    ppSecretB64: state.ppSecret ? toB64(state.ppSecret) : null,
    ratchetPubJwk: state.ratchetPubJwk,
    ratchetPrivJwk: state.ratchetPair && state.ratchetPair.privateKey ? await exportPrivJwk(state.ratchetPair.privateKey) : '',
    remoteRatchetPubJwk: state.remoteRatchetPubJwk,
    myPubs: [...state.myPubs],
    rootKeyB64: toB64(state.rootKey),
    sendChainB64: state.sendChain ? toB64(state.sendChain) : null,
    recvChainB64: state.recvChain ? toB64(state.recvChain) : null,
    sendCount: state.sendCount,
    prevSendCount: state.prevSendCount,
    recvCount: state.recvCount,
    processedIds: [...state.processedIds],
    skipped: [...state.skipped.entries()].map(([rp, m]) => [rp, [...m.entries()].map(([n, mk]) => [n, toB64(mk)])] as [string, Array<[number, string]>]),
  };
}

export async function deserializeRatchetState(data: RatchetStateSerialized): Promise<RatchetState> {
  const ikPair = await (async () => {
    const priv = await crypto.subtle.importKey('jwk', JSON.parse(data.ikPrivJwk), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    // public key is recoverable from the private JWK (crv/xy present)
    const jwk = JSON.parse(data.ikPrivJwk);
    delete jwk.d;
    const pub = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    return { privateKey: priv, publicKey: pub } as CryptoKeyPair;
  })();
  const ratchetPair = data.ratchetPrivJwk ? await (async () => {
    const priv = await crypto.subtle.importKey('jwk', JSON.parse(data.ratchetPrivJwk), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const jwk = JSON.parse(data.ratchetPrivJwk);
    delete jwk.d;
    const pub = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    return { privateKey: priv, publicKey: pub } as CryptoKeyPair;
  })() : (null as unknown as CryptoKeyPair);
  return {
    role: data.role,
    proto: (data as unknown as Record<string, unknown>).proto as string ?? RATCHET_VERSION,
    seenRemotePubs: new Set(((data as unknown as Record<string, unknown>).seenRemotePubs as string[] | undefined) ?? []),
    contact: data.contact,
    ready: data.ready,
    fingerprint: data.fingerprint,
    pq: data.pq,
    writeSecret: data.writeSecret ?? null,
    ikPair,
    ikPubJwk: data.ikPubJwk,
    bound: data.bound,
    pqPriv: data.pqPriv,
    pqStepPriv: data.pqStepPriv,
    pqStepPub: data.pqStepPub,
    pendingPqCt: data.pendingPqCt,
    signed: (data as unknown as Record<string, unknown>).signed === true,
    sigPrivB64: ((data as unknown as Record<string, unknown>).sigPrivB64 as string | null | undefined) ?? null,
    sigPubB64: ((data as unknown as Record<string, unknown>).sigPubB64 as string | null | undefined) ?? null,
    ppSecret: data.ppSecretB64 ? fromB64(data.ppSecretB64) : null,
    ratchetPair,
    ratchetPubJwk: data.ratchetPubJwk,
    remoteRatchetPubJwk: data.remoteRatchetPubJwk,
    myPubs: new Set(data.myPubs),
    rootKey: fromB64(data.rootKeyB64),
    sendChain: data.sendChainB64 ? fromB64(data.sendChainB64) : null,
    recvChain: data.recvChainB64 ? fromB64(data.recvChainB64) : null,
    sendCount: data.sendCount,
    prevSendCount: data.prevSendCount,
    recvCount: data.recvCount,
    processedIds: new Set(data.processedIds),
    skipped: new Map(data.skipped.map(([rp, m]) => [rp, new Map(m.map(([n, mkB64]) => [n, fromB64(mkB64)]))])),
  };
}
