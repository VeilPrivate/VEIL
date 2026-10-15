/**
 * @veil/device — one-tap contact sessions ("pin = identity").
 *
 * Exact web contract (extracted from the fixed reference bundle):
 *   1. identityLookup — fetch the peer's published prekeys (public only)
 *   2. verifyPeerPrekeys — SPK_sig checked against the PINNED IK; on mismatch
 *      the session is refused (MITM guard; never silent)
 *   3. createContactSession — ephemeral X25519 vs peer SPK + ML-KEM encap (Dm)
 *   4. sign {v:1,t,ek,to,pq} with the identity key (Ed25519)
 *   5. VeilSession.create server-side (public material + write-secret hashes)
 *   6. ratchet state sealed in the device session store
 */

import {
  createContactSession, acceptContactSession, ikSign, verifyWithIk,
  serializeRatchetState,
  utf8, toB64, randomBytes,
  RATCHET_SIGNING_ENABLED,
} from '../../crypto-core/src/index';
import type { RatchetStateSerialized } from '../../crypto-core/src/index';
import type { VeilRelay, PinStore, SessionStore, KeyvaultIdentity } from './index.js';

export interface OneTapDeps {
  relay: VeilRelay;
  pins: PinStore;
  sessions: SessionStore;
}

export interface OneTapResult {
  token: string;
  state: RatchetStateSerialized;
}

/** Start a one-tap session with a pinned contact. Refuses on any trust failure. */
export interface SessionDials {
  default_ttl_seconds?: number;
  expire_after_seconds?: number;
  key_retention_hours?: number;
  burn_after_open?: boolean;
}

export async function createOneTapSession(
  deps: OneTapDeps,
  identity: KeyvaultIdentity,
  peerVeilId: string,
  clientId: string,
  dials?: SessionDials,
  /** b68: my self-chosen nickname — the peer sees it in this thread's title */
  displayName?: string,
): Promise<OneTapResult> {
  const pin = await deps.pins.getPin(peerVeilId);
  if (!pin) throw new Error('Pin this contact first — the pinned key is the trust anchor.');

  const r = await deps.relay.identityLookup(peerVeilId);
  const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
  const IK_pub = rec?.IK_pub, SPK_pub = rec?.SPK_pub, SPK_sig = rec?.SPK_sig;
  if (!IK_pub || !SPK_pub || !SPK_sig) throw new Error('No published prekeys for that veil-id.');

  const trust = await deps.pins.verifyPeerPrekeys(peerVeilId, { IK_pub, SPK_pub, SPK_sig });
  if (!trust.trusted) throw new Error(`Refusing to start: ${trust.reason}`);

  // b197-r6: handshake stage profiler — the owner reported 5-10s handshake
  // lag; these marks identify which stage eats the time (prime suspects:
  // pure-JS ML-KEM encap on Hermes, relay RTTs, keychain save+verify).
  const HS_T0 = Date.now();
  const hsMark = (label: string) => console.log(`[veil-hs] +${String(Date.now() - HS_T0).padStart(5)}ms ${label}`);
  hsMark('pin + prekey lookup + trust verify done');

  // xu(24) in the web bundle: 24 random bytes, hex — same token format
  const token = [...randomBytes(24)].map((b) => b.toString(16).padStart(2, '0')).join('');
  // b197 (audit H-1): signed ratchet rotations, gated by the master switch
  // (constants.ts RATCHET_SIGNING_ENABLED — flip with web parity, never alone).
  const created = await createContactSession(token, { spkPubB64: trust.spkPubB64, pqPubB64: rec.pq_pub || null }, RATCHET_SIGNING_ENABLED);
  hsMark('crypto core done (X25519 + ML-KEM encap + P-256 keygen) — prime suspect if large');

  const sigMsg = JSON.stringify({ v: 1, t: token, ek: created.ekPubB64, to: peerVeilId, pq: created.pqCt || '' });
  const sig = await ikSign(identity.ikSeedB64, toB64(utf8(sigMsg)));
  hsMark('ikSign done');

  const writeHash = async (secret: string) => {
    const h = await crypto.subtle.digest('SHA-256', utf8(secret) as unknown as BufferSource);
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  await deps.relay.entityCreate('VeilSession', {
    token,
    state: 'pending',
    initiator_client_id: clientId,
    responder_client_id: '',
    initiator_display_name: displayName ?? '',
    responder_display_name: '',
    passphrase_required: false,
    session_fingerprint: '',
    initiator_pub_jwk: created.state.ikPubJwk,
    initiator_pq_pub: '',
    initiator_pq_ct: created.pqCt || '',
    initiator_ek_pub: created.ekPubB64,
    initiator_sig: sig,
    initiator_veil_id: identity.veilId,
    responder_veil_id: peerVeilId,
    contact_session: true,
    initiator_write_hash: await writeHash(created.writeSecrets.initiator),
    responder_write_hash: await writeHash(created.writeSecrets.responder),
    initiator_verified: false,
    responder_verified: false,
    // SPEC §2.11: pending contact request expires after 24h (web: 864e5 ms).
    // Dials = the web's default settings values (wh.burnTtlSeconds/expireAfterSeconds/retentionHours).
    default_ttl_seconds: dials?.default_ttl_seconds ?? 7200,
    // b197-r8l (TWO-DIAL SYNCHRONIZED MODEL, owner spec): BOTH dials are
    // founder-programmable and relay-enforced —
    //   default_ttl_seconds = burn-after-open window (relay copy dies open+N)
    //   expire_after_seconds = unopened-message relay deletion horizon
    //                         (12/24/36/48 h chips)
    expire_after_seconds: dials?.expire_after_seconds ?? 86400,
    key_retention_hours: dials?.key_retention_hours ?? 168,
    burn_after_open: dials?.burn_after_open ?? true,
    last_activity: new Date().toISOString(),
    expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
  });
  hsMark('entityCreate (relay RTT, big payload) done');

  const state = await serializeRatchetState(created.state);
  await deps.sessions.save(token, {
    ...state,
    burnAfterOpen: !!(dials?.burn_after_open ?? true),
    defaultTtlSeconds: dials?.default_ttl_seconds ?? 7200,
    expireAfterSeconds: dials?.expire_after_seconds ?? 86400,
  } as never);
  hsMark('ratchet serialize + keychain save(+verify) done — HANDSHAKE COMPLETE');
  return { token, state };
}

// ---------------------------------------------------------------------------
// Responder side (SPEC §3): verify the initiator's request, re-derive the
// shared root from OUR prekeys, join via the session gate, seal the ratchet.
// ---------------------------------------------------------------------------

/** A pending contact-session record as served by veilSessionGate list/peek. */
export interface IncomingContactRequest {
  token: string;
  state: string;
  initiator_veil_id: string;
  initiator_ek_pub: string;
  initiator_pq_ct?: string | null;
  initiator_pub_jwk: string;
  initiator_sig: string;
  /** b79: stamped by THIS function's own relay.sessionJoin call — empty
   *  until the responder-side crypto join has actually happened. This is
   *  the correct "already joined" signal, NOT req.state (see guard below). */
  responder_pub_jwk?: string;
}

export async function acceptOneTapSession(
  deps: OneTapDeps,
  identity: KeyvaultIdentity,
  req: IncomingContactRequest,
  clientId: string,
  /** b68: my self-chosen nickname — the initiator sees it in this thread's title */
  displayName?: string,
): Promise<OneTapResult> {
  const { relay, pins, sessions } = deps;
  // b79 CRITICAL FIX (owner report: "no accept window comes up on native,
  // it just appears in the conversations box" — a PINNED-CONTACT one-tap
  // re-message session is created ALREADY 'active' by design (trust already
  // exists via the pin; there is deliberately no pending/accept UI step for
  // it). The OLD guard here refused to run unless state==='pending', which
  // meant the crypto join (the part that actually derives this device's
  // ratchet keys and stamps responder_pub_jwk) never ran AT ALL for that
  // flow — advanceHandshake called this every poll, it threw every time, the
  // bare catch swallowed it silently, and the message could never decrypt
  // (peer stuck on "waiting for their device to open it" forever). The
  // correct guard is "has THIS session already been joined", which
  // responder_pub_jwk answers directly — it's empty until the one
  // relay.sessionJoin call below stamps it, regardless of whether the
  // record started 'pending' (first-time request) or 'active' (pinned
  // one-tap re-message).
  if (req.responder_pub_jwk) throw new Error('Session already joined.');
  if (req.state === 'ended') throw new Error('Session has ended.');

  // 1. resolve the trust anchor for the initiator's IK: pinned if available,
  //    otherwise lookup (SPEC §3.1 allows either; we auto-pin on success like web).
  let ikPubB64: string;
  const pin = await pins.getPin(req.initiator_veil_id);
  if (pin) {
    ikPubB64 = pin.ikPubB64;
  } else {
    const r = await relay.identityLookup(req.initiator_veil_id);
    const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
    if (!rec?.IK_pub) throw new Error('Initiator has no published identity.');
    ikPubB64 = rec.IK_pub;
  }

  // 2. verify initiator_sig over the BYTE-EXACT payload {v,t,ek,to,pq} (SPEC §2.10)
  const payload = JSON.stringify({
    v: 1, t: req.token, ek: req.initiator_ek_pub,
    to: identity.veilId, pq: req.initiator_pq_ct || '',
  });
  const ok = await verifyWithIk(ikPubB64, toB64(utf8(payload)), req.initiator_sig);
  if (!ok) throw new Error('Request signature failed verification against the initiator identity key.');

  // 3. reproduce the shared root from OUR prekeys (SPEC §3.2)
  const accepted = await acceptContactSession(req.token, {
    ekPubB64: req.initiator_ek_pub,
    pqCt: req.initiator_pq_ct || null,
    spkPrivB64: identity.spkPrivB64,
    pqPrivB64: identity.pqPrivB64 || null,
    initiatorP256Jwk: req.initiator_pub_jwk,
  }, RATCHET_SIGNING_ENABLED);

  // 4. join (SPEC §3.3) — write_secret is the lowercase-hex responder credential
  await relay.sessionJoin({
    token: req.token,
    write_secret: accepted.writeSecret,
    client_id: clientId,
    display_name: displayName ?? '',
    responder_pub_jwk: accepted.responderPubJwk,
    responder_ratchet_pub_jwk: accepted.responderRatchetPubJwk,
    responder_pq_ct: '',
    fingerprint: accepted.fingerprint,
  });

  // 5. auto-pin the initiator (web contract: accept = pin), device-local only
  if (!pin) await pins.pin(req.initiator_veil_id, ikPubB64);

  const state = await serializeRatchetState(accepted.state);
  await sessions.save(req.token, {
    ...state,
    burnAfterOpen: !!(req as { burn_after_open?: boolean }).burn_after_open,
    defaultTtlSeconds: Number((req as { default_ttl_seconds?: unknown }).default_ttl_seconds) || 7200,
    expireAfterSeconds: Number((req as { expire_after_seconds?: unknown }).expire_after_seconds) || 86400,
  } as never);
  return { token: req.token, state };
}
