/**
 * @veil/device — GROUP session orchestration (create / join / inbox / send /
 * rotate / evict), ported from the live web bundle (Sept 19, 2026).
 *
 * All cryptography lives in groups.ts (veil-group-1, byte-exact web parity).
 * This module owns the relay/gate/entity flows:
 *
 *  CREATE (creator):
 *    groupToken = hex(16), GEK = 32 random bytes, group PQ pub = ML-KEM keypair
 *    main session: invite-style createSession bound to the group
 *      (VeilSession group_token + encrypted group_name blob), state ACTIVE —
 *      it is the creator's broadcast channel; nobody ever joins it 1:1.
 *    N invite sessions: plain invite sessions; links carry #w= plus &g=<GEK>&e=1.
 *    veilGroupGate rotate {new_epoch:1, group_pq_pub} → stamps group_epoch on
 *    the group's sessions; veilGroupGate attest (creator sig over
 *      {group_token, veil_id, IK_pub, joined_epoch}); local group record
 *      (role creator); signed intro broadcast into the group channel.
 *
 *  JOIN (member):
 *    parse link → #w= write secret, &g= GEK, &e= expected epoch.
 *    normal invite join (peek → ratchet join → gate join); the gate's session
 *    record carries group_token / group_epoch / group_pq_pub.
 *    Epoch must equal the link's epoch (rotated-after-invite → fresh link).
 *    veilGroupGate attest (member sig); local record (role member, GEK from
 *      the link fragment); signed intro broadcast.
 *
 *  INBOX (poll, per open group thread):
 *    VeilEnvelope filter {group_token} ascending, 200 — decrypt oldest-first,
 *    skip own (sid === myTag) and foreign-epoch headers, discard cover filler,
 *    apply rekey payloads (ML-KEM unwrap against MY pqPriv), render intros as
 *    system notes, surface receipts/media/text, bump the rotation counter.
 *    Roster: VeilGroupMember filter {group_token} → senderKeys for per-sender
 *    signature checks + tag→veilId names + epoch fingerprint input.
 *
 *  SEND: Sm-encrypt via groups.ts, submitEnvelope with BOTH session_token and
 *    group_token, sender_client_id = group sender tag, protocol_version
 *    'veil-group-1'.
 */
import { toB64, utf8, randomBytes } from '../../crypto-core/src/bytes';
import { ikSign } from '../../crypto-core/src/identity';
import { mlkemKeypair } from '../../crypto-core/src/mlkem';
import { createSession, serializeRatchetState, type RatchetStateSerialized } from '../../crypto-core/src/ratchet';
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';
import type { SessionStore } from './session-store';
import type { VeilRelay } from './relay';
import {
  createInviteSession, groupInviteLink, parseInviteLink, joinInviteSession, writeHashHex,
} from './invite';
import { encryptMedia } from './chat';
import { relayTimestampToIso } from './time';
import {
  GROUP_PROTO, encryptGroupMessage, decryptGroupMessage, saveGroupRecord, loadGroupRecord,
  loadGroupRecords, groupRecord, bumpGroupEnvCount, senderTag, epochFingerprint,
  buildRekeyWrap, parseRekeyPayload, applyRekeyPayload, attestSignature, denySignature,
  encryptGroupText, decryptGroupText, groupNeedsRotation, exportGroupRecords,
  importGroupRecords, forgetGroup, decryptOwnGroupEnvelope, type GroupRecord, type GroupRekeyPayload,
  parseGroupIntro, verifyGroupIntro, advanceEpoch,
} from './groups';
// b185: parseGroupIntro/verifyGroupIntro/advanceEpoch moved to this STATIC import.
// The previous dynamic `await import('./groups')` resolved to a SECOND module
// instance under any loader that separates static and dynamic module graphs
// (node:test/tsx demonstrated it live; some bundler configurations do too) —
// the WeakMap group-key registry silently split in two and a rotation could
// throw "Group keys are not established" while the record sat intact in the
// other instance. One module, one registry, no loader-dependent behavior.

export interface GroupIdentity {
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  /** the member's OWN ML-KEM private key — only used to unwrap rekey GEKs */
  pqPrivB64: string;
}

export interface GroupSessionDeps {
  relay: VeilRelay;
  sessions: SessionStore;
  storage: VeilStorage;
  webBaseUrl: string;
}

export interface InviteDialsInput {
  burnAfterOpen: boolean;
  expireAfterSeconds: number;
  keyRetentionHours: number;
  defaultTtlSeconds: number;
}

export interface CreatedGroup {
  groupToken: string;
  groupName: string;
  mainToken: string;
  inviteLinks: string[];
}

export interface JoinedGroup {
  token: string;
  groupToken: string;
  epoch: number;
}

function hexRand(n: number): string {
  return Array.from(randomBytes(n)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** web's Nm()/Ep(): the signed intro payload broadcast into a group. */
export async function buildIntroPayload(id: GroupIdentity, nickname: string): Promise<string> {
  const nick = (nickname || '').trim().slice(0, 40);
  const p = JSON.stringify({ v: 1, id: id.veilId, ik: id.ikPubB64, nick });
  const s = await ikSign(id.ikSeedB64, toB64(utf8(p)));
  return JSON.stringify({ __veil_intro: 1, p, s });
}

/** b135: the pairwise submit path got assertSubmitOk in b127 after an
 *  HTTP-200-wrapped {error} silently ate a receipt — the GROUP path never
 *  did. Owner repro (Sept 27 lounge test): a harness `say` returned
 *  {ok:true} but its envelope never appeared on the relay (verified by full
 *  ascending page scan of VeilEnvelope rows for the group — every other row
 *  present, that one absent). A 200-wrapped reject must throw here so the
 *  caller can surface it; silence turns a dropped message into a "delivered"
 *  lie. */
function assertGroupSubmitOk(r: { data: unknown; status: number }, what: string): void {
  const d = r.data as { error?: unknown } | null;
  if (r.status >= 400 || (d && typeof d.error === 'string')) {
    throw new Error(`${what} rejected by relay (${r.status}): ${d?.error ?? 'no detail'}`);
  }
}

async function submitGroupEnvelope(
  deps: GroupSessionDeps, opts: {
    groupToken: string; sessionToken: string; clientId: string; text: string; cover?: boolean;
  },
): Promise<{ senderTag: string; byteLength: number }> {
  const sealed = await deps.sessions.load(opts.sessionToken);
  if (!sealed) throw new Error('No session state for this group on this device.');
  const env = await encryptGroupMessage(deps.storage, opts.groupToken, opts.text, opts.cover ?? false);
  const submitRes = await deps.relay.submitEnvelope({
    session_token: opts.sessionToken,
    group_token: opts.groupToken,
    client_id: opts.clientId,
    write_secret: (sealed as RatchetStateSerialized & { writeSecret?: string }).writeSecret ?? null,
    sender_client_id: env.senderTag,
    ciphertext: env.ciphertext,
    iv: env.iv,
    header: env.header,
    byte_length: env.byteLength,
    // b91: group envelopes (messages + receipts) use the session's expire
    // dial, not a hardcoded 1h — same uniform-expiry rule as pairwise
    ttl_seconds: Number((sealed as { expireAfterSeconds?: number }).expireAfterSeconds) || 86400,
    protocolVersion: GROUP_PROTO,
  });
  assertGroupSubmitOk(submitRes, 'group submit'); // b135: no more silent 200-wrapped rejects
  // b198 GROUP PUSH: real group sends (never cover — the caller passes cover
  // only for fillers) ping the other members through the relay's group notify
  // action. Fire-and-forget; the relay coalesces per group+sender.
  if (!opts.cover) {
    void deps.relay.invoke('veilGroupGate', {
      action: 'notify',
      group_token: opts.groupToken,
      session_token: opts.sessionToken,
      write_secret: (sealed as RatchetStateSerialized & { writeSecret?: string }).writeSecret ?? null,
    }).catch(() => undefined);
  }
  return { senderTag: env.senderTag, byteLength: env.byteLength };
}

// ---------- create ----------

export async function createGroup(
  deps: GroupSessionDeps,
  opts: { identity: GroupIdentity; groupName: string; inviteCount: number; clientId: string; dials: InviteDialsInput; nickname?: string },
): Promise<CreatedGroup> {
  const groupToken = hexRand(16);
  const pq = await mlkemKeypair();
  const gek = toB64(randomBytes(32));
  const nameBlob = await encryptGroupText(gek, opts.groupName);

  // creator's MAIN group session — active immediately, bound to the group
  const main = await createInviteSession(deps, {
    clientId: opts.clientId,
    dials: opts.dials,
    group: { groupToken, groupNameBlob: nameBlob, activate: true, epoch: 1, pqPubB64: pq.pub },
  });

  // member invite sessions (plain invite links + group fragments)
  const invites: string[] = [];
  for (let i = 0; i < opts.inviteCount; i++) {
    const inv = await createInviteSession(deps, { clientId: opts.clientId, dials: opts.dials, group: { groupToken, groupNameBlob: nameBlob, epoch: 1, pqPubB64: pq.pub } });
    invites.push(groupInviteLink(inv.link, gek, 1));
  }

  await deps.relay.invoke('veilGroupGate', {
    action: 'rotate',
    group_token: groupToken,
    session_token: main.token,
    write_secret: (await deps.sessions.load(main.token) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
    new_epoch: 1,
    group_pq_pub: pq.pub,
  });

  const sig = await attestSignature(opts.identity.ikSeedB64, groupToken, opts.identity.veilId, opts.identity.ikPubB64, 1);
  await deps.relay.invoke('veilGroupGate', {
    action: 'attest',
    group_token: groupToken,
    session_token: main.token,
    write_secret: (await deps.sessions.load(main.token) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
    veil_id: opts.identity.veilId,
    IK_pub: opts.identity.ikPubB64,
    joined_epoch: 1,
    sig,
  });

  await saveGroupRecord(deps.storage, {
    groupToken,
    sessionToken: main.token, // b198: the member's own group session (background poll + push credential)
    veilId: opts.identity.veilId,
    ikSeedB64: opts.identity.ikSeedB64,
    ikPubB64: opts.identity.ikPubB64,
    role: 'creator',
    epoch: 1,
    gekB64: gek,
    nameGekB64: gek,
    pqPubB64: pq.pub,
    myNick: (opts.nickname ?? '').trim().slice(0, 40) || undefined,
    myTag: await senderTag(groupToken, 1, opts.identity.veilId),
    sendN: 0,
    recv: {},
    envCount: 0,
  });

  try {
    await submitGroupEnvelope(deps, {
      groupToken,
      sessionToken: main.token,
      clientId: opts.clientId,
      text: await buildIntroPayload(opts.identity, opts.nickname ?? ''),
    });
  } catch (e) {
    console.error('group-create:auto-intro-failed', e);
  }

  return { groupToken, groupName: opts.groupName, mainToken: main.token, inviteLinks: invites };
}

// ---------- join ----------

export async function joinGroup(
  deps: GroupSessionDeps,
  opts: { link: string; clientId: string; displayName?: string; identity: GroupIdentity; nickname?: string },
): Promise<JoinedGroup> {
  const parsed = parseInviteLink(opts.link);
  if (!parsed.gek) throw new Error('This group invitation is incomplete — ask for a fresh link.');
  const expectedEpoch = parsed.epoch ?? 1;

  // normal invite join (peek → ratchet → gate join, with all its validations)
  await joinInviteSession(deps, { link: opts.link, clientId: opts.clientId, displayName: opts.displayName });

  // fetch the joined record to read the group binding
  const pk = await deps.relay.invoke('veilSessionGate', { action: 'peek', token: parsed.token, write_secret: parsed.writeSecret });
  const pd = pk.data as { data?: { session?: Record<string, unknown> }; session?: Record<string, unknown> };
  const rec = pd?.data?.session ?? pd?.session;
  if (!rec) throw new Error('Invitation not found or expired.');
  const groupToken = String(rec.group_token ?? '');
  if (!groupToken || Number(rec.group_epoch ?? 0) < 1) throw new Error('This group invitation is incomplete — ask for a fresh link.');
  const epoch = Number(rec.group_epoch) || expectedEpoch || 1;
  if (expectedEpoch && epoch !== expectedEpoch) {
    throw new Error('The group rotated its keys after this invitation was made — ask for a fresh link.');
  }

  const sig = await attestSignature(opts.identity.ikSeedB64, groupToken, opts.identity.veilId, opts.identity.ikPubB64, epoch);
  await deps.relay.invoke('veilGroupGate', {
    action: 'attest',
    group_token: groupToken,
    session_token: parsed.token,
    write_secret: parsed.writeSecret,
    veil_id: opts.identity.veilId,
    IK_pub: opts.identity.ikPubB64,
    joined_epoch: epoch,
    sig,
  });

  await saveGroupRecord(deps.storage, {
    groupToken,
    sessionToken: parsed.token, // b198: the member's own group session (background poll + push credential)
    veilId: opts.identity.veilId,
    ikSeedB64: opts.identity.ikSeedB64,
    ikPubB64: opts.identity.ikPubB64,
    role: 'member',
    epoch,
    gekB64: parsed.gek,
    nameGekB64: parsed.gek,
    pqPubB64: String(rec.group_pq_pub ?? ''),
    myNick: (opts.nickname ?? '').trim().slice(0, 40) || undefined,
    myTag: await senderTag(groupToken, epoch, opts.identity.veilId),
    sendN: 0,
    recv: {},
    envCount: 0,
  });

  try {
    await submitGroupEnvelope(deps, {
      groupToken,
      sessionToken: parsed.token,
      clientId: opts.clientId,
      text: await buildIntroPayload(opts.identity, opts.nickname ?? ''),
    });
  } catch (e) {
    console.error('group-join:auto-intro-failed', e);
  }

  return { token: parsed.token, groupToken, epoch };
}

// ---------- inbox ----------

/** incoming group media (parsed from the __veil_media JSON body) */
export interface GroupIncomingMedia {
  uri: string; k: string; iv: string; mime: string; name: string; size: number; dl?: boolean;
}

export interface GroupMemberRow {
  veilId: string;
  /** display nickname (source of truth when set; '' -> UI falls back to veil id) */
  nick: string;
  ikPub: string;
  role: string;
  joinedEpoch: number;
  tag: string;
}

export interface GroupInboxEvents {
  /** a normal chat message (text may be '' for media/intro-only envelopes) */
  onMessage: (info: { envelopeId: string; text: string; senderTag: string; senderVeilId: string | null; senderNick: string | null; senderVerified: boolean; sentAt: string; media?: GroupIncomingMedia; expiresAt: string | null }) => void;
  /** system line (X joined the group / keys rotated) */
  onSystem: (info: { envelopeId: string; note: string; sentAt: string }) => void;
  /** my envelopes confirmed read by peers */
  onRead: (readIds: string[]) => void;
  /** the group moved to a new post-quantum epoch */
  onRotated: (newEpoch: number) => void;
  /** a sender-signature failure — envelope discarded (possible impersonation) */
  onSenderVerifyFailed: (envelopeId: string) => void;
  /** b191 parity (shell Oct 12): this device is BEHIND the group's key epoch —
   *  it can neither open members' envelopes nor be opened by them until it
   *  rejoins. Fire ONCE per group per poll cycle; the App layer dedupes. */
  onEpochBehind?: (info: { groupToken: string; behindEpoch: number; localEpoch: number }) => void;
  /** b191 parity: a real (non-replay) key/counter failure opening a group
   *  envelope — this device may be out of step with the group keys. The App
   *  layer shows a one-per-group "rejoin to catch up" notice. */
  onDecryptFailed?: (info: { groupToken: string; err: string }) => void;
  /** b123: own-envelope echo — my just-sent bubble's text back with its
   *  envelope id, so the App layer can attach envId to the local bubble and
   *  group read receipts can tick it. Cover envelopes echo too (harmless:
   *  no local bubble matches their filler text). */
  onOwnEcho?: (envelopeId: string, text: string) => void;
}

export interface GroupInboxResult {
  tagToVeilId: Record<string, string>;
  /** sender tag -> display nickname (source of truth when set) */
  tagToNick: Record<string, string>;
  members: GroupMemberRow[];
  fingerprint: string | null;
  needsRotation: boolean;
}

function asEnvelopeRow(raw: unknown): Record<string, unknown> {
  return (raw ?? {}) as Record<string, unknown>;
}

// b138: the direct VeilGroupMember entityList is dead — the roster-fence fix
// (published) made the entity admin-only, so a non-admin read silently
// returned 0 rows, wiping senderKeys/fingerprint and breaking group
// decryption on native. The ONLY client-facing roster read is now the
// veilGroupGate 'roster' action: it clears session + write-credential
// checks, then fences membership (403 membership_gone / session-group
// binding), and its projection drops account_hash and session_token.
async function gateRoster(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string },
): Promise<{ members: Record<string, unknown>[]; epoch: number }> {
  const ws = (await deps.sessions.load(opts.sessionToken) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null;
  const res = await deps.relay.invoke('veilGroupGate', {
    action: 'roster',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: ws,
  }) as { data?: { data?: { members?: Record<string, unknown>[]; epoch?: number }; members?: Record<string, unknown>[]; epoch?: number } };
  // b198 (live-caught, first on-device group test post-flip): the relay returns
  // the BASE44 double-wrapped shape { data: { members, epoch } } and invoke
  // hands back the RAW body — so the roster lived at res.data.data.members,
  // one level deeper than this read. A perfectly good roster read as undefined
  // → "Group roster was rejected by the relay" → and since the poll runs the
  // roster BEFORE the envelope fetch, the whole pass aborted and group
  // messages never arrived (Two's 'hey' never seen on One; rotate looked
  // broken too). Accept both shapes; single source of truth for the parse.
  const body = (res?.data ?? {}) as { data?: { members?: Record<string, unknown>[]; epoch?: number }; members?: Record<string, unknown>[]; epoch?: number };
  const members = Array.isArray(body?.data?.members) ? body.data!.members : (Array.isArray(body?.members) ? body.members : undefined);
  if (!Array.isArray(members)) throw new Error('Group roster was rejected by the relay.');
  // b191 parity: the roster is the only place a device with NO pending
  // foreign-epoch envelope can learn the group has moved on without it.
  const epochRaw = body?.data?.epoch ?? body?.epoch;
  return { members: members as Record<string, unknown>[], epoch: Number(epochRaw ?? 0) };
}

/**
 * One pass over the group's envelopes + roster. The App layer calls this on
 * its poll cycle and keeps a known-id set so processed envelopes are skipped.
 */
export async function pollGroupInbox(
  deps: GroupSessionDeps,
  opts: { groupToken: string; identity: GroupIdentity; knownIds: Set<string>; events: GroupInboxEvents; sessionToken?: string; burnAfterOpen?: boolean },
): Promise<GroupInboxResult | null> {
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec) return null;

  // b132: relay-side burn-after-open for groups. The veilSessionGate 'burn'
  // action authorises any envelope in this group against the CALLER's OWN
  // session credential (session.group_token === env.group_token clause —
  // builder-verified), so a receiving member can burn envelopes it has
  // definitively processed: the group twin of the pairwise burn-on-decrypt
  // in chat.ts. Without this, group envelopes sat at the full 24h submit
  // TTL no matter how many members opened them (owner repro: 5-min lounge,
  // every relay row still +24h after both members opened everything).
  // EXEMPT from burn: rekey payloads (epoch control channel — burning one
  // can permanently desync a member offline past the window) and past-epoch
  // rows (a lagging member can still read those). Own echoes are skipped by
  // the caller below — the sender's envelope serves the OTHER members.
  const burnCred = opts.burnAfterOpen && opts.sessionToken
    ? { token: opts.sessionToken, ws: (await deps.sessions.load(opts.sessionToken))?.writeSecret ?? null }
    : null;
  const burnEnvelope = async (id: string, what: string): Promise<void> => {
    if (!burnCred) return;
    try {
      // b134 (owner Metro log, Sept 27): every burn call — including ones
      // the builder confirmed DID shorten the relay row's TTL — logged
      // "no-op (unknown reason)". relay.invoke() (what sessionBurn calls)
      // returns the WRAPPER shape { data, status }, not the bare response
      // body — burned/reason live at res.data.burned / res.data.reason, one
      // level deeper than this was reading. res.burned was always
      // undefined, so this branch always fell through regardless of the
      // real outcome. Pure logging bug — the burn call itself was fine.
      const wrapped = (await deps.relay.sessionBurn(burnCred.token, burnCred.ws, id)) as { data?: { burned?: boolean; reason?: string } };
      const res = wrapped?.data ?? {};
      console.log(`[veil-group] burn ${what} ${id.slice(0, 8)}: ${res?.burned ? 'burned' : `no-op (${res?.reason ?? 'unknown reason'})`}`);
    } catch (e) {
      // Best-effort by design (same as web); a missed burn leaves the row
      // at its submit TTL. Logged with the id so Metro shows exactly which.
      console.log(`[veil-group] burn FAILED for ${id.slice(0, 8)} (${what}): ${(e as Error).message ?? e}`);
    }
  };

  // ---- roster (web's f()): members + senderKeys + tag->veilId names
  // b138: routed through veilGroupGate 'roster' (entity is admin-only now).
  if (!opts.sessionToken) throw new Error("Group roster requires this member's session.");
  const roster = await gateRoster(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken });
  const memberRows = roster.members.map(asEnvelopeRow);
  // b191 parity: the roster read is the only place a device with no pending
  // foreign-epoch envelope learns the group moved on without it — same
  // onEpochBehind as the envelope-path mismatch above.
  if (roster.epoch > rec.epoch) opts.events.onEpochBehind?.({ groupToken: opts.groupToken, behindEpoch: roster.epoch, localEpoch: rec.epoch });
  const members: GroupMemberRow[] = [];
  const tagToVeilId: Record<string, string> = {};
  const tagToNick: Record<string, string> = { ...(rec.nicks ?? {}) };
  if (rec.myNick) tagToNick[rec.myTag] = rec.myNick;
  const senderKeys: Record<string, string> = {};
  for (const m of memberRows) {
    const veilId = String(m.veil_id ?? '');
    if (!veilId) continue;
    const tag = await senderTag(opts.groupToken, rec.epoch, veilId);
    const ikPub = String(m.IK_pub ?? '');
    members.push({ veilId, nick: '', ikPub, role: String(m.role ?? 'member'), joinedEpoch: Number(m.joined_epoch ?? 0), tag });
    tagToVeilId[tag] = veilId;
    if (ikPub) senderKeys[tag] = ikPub;
  }
  rec.senderKeys = senderKeys;
  const fingerprint = members.length
    ? await epochFingerprint(opts.groupToken, rec.epoch, String(rec.gekB64 ?? ''), String(rec.pqPubB64 ?? ''), members.map((m) => m.ikPub))
    : null;

  // ---- envelopes (web's g()): oldest-first, skip known
  // b92 F10 (b91 audit): the group twin of the b87 pairwise stall — this
  // fetch had NO pagination cursor, so a group past 200 total envelopes
  // (cover traffic accumulates them fast) re-read the same oldest 200
  // forever and NEW group messages silently stopped arriving. Same rule
  // as syncChat: advance the per-group cursor ONLY on a full 200-row
  // page, by (page - margin); a partial page IS the live tail and must
  // stay re-scannable for freshness.
  const GROUP_PAGE = 200;
  const GROUP_MARGIN = 20;
  const startSkip = Math.max(0, Math.floor(Number(rec.syncSkip) || 0));
  const envRaw = await deps.relay.entityList('VeilEnvelope', {
    group_token: opts.groupToken, sort: 'created_date', limit: GROUP_PAGE,
    ...(startSkip > 0 ? { skip: startSkip } : {}),
  });
  const ed = envRaw as unknown[] | { data?: unknown[] };
  const envelopes = (Array.isArray(ed) ? ed : ed.data ?? []).map(asEnvelopeRow);

  let needsRotation = rec.role === 'creator' && groupNeedsRotation(rec);

  // b92 F11 (b91 audit): mark known ONLY after a definitive outcome —
  // successful decrypt, or a permanently-irrelevant row (own envelope,
  // foreign protocol, malformed header, PAST epoch whose keys are gone by
  // design). Previously EVERY row was marked known up-front, so an
  // epoch-transition race (rekey payload landing later in the same fetch)
  // or a transient decrypt failure permanently swallowed a REAL message —
  // the exact bug class the Sept 19 audit fix removed from the pairwise
  // path. Future-epoch rows and failed decrypts stay RETRYABLE; the F10
  // cursor eventually retires them from the fetch window.
  const persistedKnown = new Set<string>(rec.knownEnvIds ?? []);
  const markKnown = (id: string): void => {
    opts.knownIds.add(id);
    persistedKnown.add(id);
  };
  for (const env of envelopes) {
    const id = String(env.id ?? '');
    if (!id || opts.knownIds.has(id) || persistedKnown.has(id)) continue;
    const expiresAt = env.expires_at ? String(env.expires_at) : null;
    if (expiresAt && new Date(expiresAt).getTime() < Date.now()) continue;
    const headerStr = String(env.header ?? '');
    let header: { v?: string; sid?: string; ge?: number };
    if (!headerStr) { markKnown(id); await burnEnvelope(id, 'malformed'); continue; } // malformed — never improves
    try { header = JSON.parse(headerStr); } catch { markKnown(id); await burnEnvelope(id, 'malformed'); continue; }
    if (header.v !== GROUP_PROTO) { markKnown(id); await burnEnvelope(id, 'foreign-proto'); continue; } // permanently irrelevant
    const ge = Number(header.ge);
    // b123: my OWN envelope — read the payload back (own GEK, no recv
    // bookkeeping) and emit the id so the App layer can bind envId to the
    // locally-sent bubble; group read receipts then work like pairwise.
    if (header.sid === rec.myTag) {
      if (opts.events.onOwnEcho && ge === rec.epoch) {
        try {
          const own = await decryptOwnGroupEnvelope(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''));
          if (!own.cover && own.text && !own.text.startsWith('{"__veil_intro"')) opts.events.onOwnEcho(id, own.text);
        } catch { /* cover / malformed own envelope — nothing to bind */ }
      }
      markKnown(id); continue;
    }
    if (ge !== rec.epoch) {
      // b191 parity: shell Oct 12 — a foreign epoch used to vanish with NO
      // trace. Trace both sides + deviceBehind; a NEWER epoch means this
      // device missed a rekey and is blind in both directions, so surface it
      // (onEpochBehind) instead of dropping silently forever.
      console.log('[veil-group] epoch mismatch', { groupToken: opts.groupToken.slice(0, 8), envelopeId: id, senderEpoch: ge, localEpoch: rec.epoch, deviceBehind: ge > rec.epoch });
      if (ge > rec.epoch) opts.events.onEpochBehind?.({ groupToken: opts.groupToken, behindEpoch: ge, localEpoch: rec.epoch });
      if (ge < rec.epoch) markKnown(id); // past epoch — keys gone by design
      continue; // future epoch — RETRYABLE until the rekey envelope lands
    }

    let out;
    try {
      out = await decryptGroupMessage(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''), String(env.session_token ?? '') || undefined);
    } catch (e) {
      // b92 F11: NOT marked known — a transient failure (rekey race,
      // momentary roster gap behind a sender-signature check) must stay
      // retryable, exactly like the pairwise path post Sept 19.
      if (/veil-group-sig/i.test((e as Error).message ?? '')) {
        console.error('Group sender signature failed — envelope discarded', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id);
      } else {
        const dmsg = String((e as Error).message ?? 'unknown');
        // b191 parity: replay rejections stay SILENT (normal re-scan result —
        // the poll re-reads the live tail every pass, so a pre-rotation row
        // correctly refuses forever and must not spam the log); a REAL
        // key/counter failure is traced + surfaced so a stale device gets told
        // to rejoin instead of silently missing messages. b198: the
        // console.error moved INSIDE the guard — it was logging replays too.
        if (!/replayed or too-old/i.test(dmsg)) {
          console.error('[veil-group] envelope decrypt failed', { envelopeId: id, msg: dmsg });
          opts.events.onDecryptFailed?.({ groupToken: opts.groupToken, err: dmsg });
        }
      }
      continue;
    }

    markKnown(id); // b92 F11: definitive outcome — safe to record now
    await bumpGroupEnvCount(deps.storage, opts.groupToken);
    if (out.cover) { await burnEnvelope(id, 'cover'); continue; } // cover traffic — never rendered

    // rekey? (b132: EXEMPT from relay burn — the epoch control channel must
    // outlive any single member's burn window or offline members desync)
    const rekey = parseRekeyPayload(out.text);
    if (rekey) {
      const applied = await applyRekeyPayload(deps.storage, opts.groupToken, rekey, opts.identity.pqPrivB64).catch((e) => {
        console.error('[veil-group] rekey apply failed', e);
        return false;
      });
      if (applied) {
        opts.events.onRotated(rekey.ge);
        opts.events.onSystem({ envelopeId: id, note: 'Group keys rotated — new post-quantum epoch.', sentAt: relayTimestampToIso(env.created_date as string | undefined) });
      }
      continue;
    }

    // read receipts?
    if (out.text.startsWith('{"__veil_receipt":')) {
      try {
        const t = JSON.parse(out.text) as { __veil_receipt?: number; ids?: string[] };
        if (t.__veil_receipt === 1 && Array.isArray(t.ids)) opts.events.onRead(t.ids.slice(0, 20));
      } catch { /* ignore */ }
      await burnEnvelope(id, 'receipt');
      continue;
    }

    // intro?
    if (out.text.startsWith('{"__veil_intro":')) {
      const parsed = parseGroupIntro(out.text);
      const intro = parsed ? await verifyGroupIntro(parsed) : null;
      if (intro) {
        if (intro.nick) tagToNick[String(header.sid)] = intro.nick;
        opts.events.onSystem({
          envelopeId: id,
          note: `${intro.nick || intro.veilId.slice(0, 8)} joined the group`,
          sentAt: relayTimestampToIso(env.created_date as string | undefined),
        });
      }
      await burnEnvelope(id, 'intro');
      continue;
    }

    // normal message (text or media — media rides as __veil_media JSON, same
    // shape as the 1:1 flow; the receiver loads/decrypts the blob by uri)
    let media: { uri: string; k: string; iv: string; mime: string; name: string; size: number; dl?: boolean } | undefined;
    let text = out.text;
    if (out.text.startsWith('{"__veil_media":')) {
      try {
        const t = JSON.parse(out.text) as Record<string, unknown>;
        if (t.__veil_media === 1 && typeof t.uri === 'string' && typeof t.k === 'string' && typeof t.iv === 'string') {
          media = {
            uri: String(t.uri), k: String(t.k), iv: String(t.iv),
            mime: String(t.mime ?? 'application/octet-stream'), name: String(t.name ?? 'media'),
            size: Number(t.size ?? 0), dl: t.dl === 1 ? true : undefined,
          };
          text = '';
        }
      } catch { /* not media after all — render as text */ }
    }
    await burnEnvelope(id, 'message');
    opts.events.onMessage({
      envelopeId: id,
      text,
      senderTag: String(header.sid),
      senderVeilId: tagToVeilId[String(header.sid)] ?? null,
      senderNick: tagToNick[String(header.sid)] ?? null,
      senderVerified: out.senderVerified,
      sentAt: relayTimestampToIso(env.created_date as string | undefined),
      media,
      expiresAt,
    });
  }

  // b92 F10/F11: persist the per-group cursor + known ledger (survives
  // restarts; capped like every other ledger).
  rec.syncSkip = envelopes.length >= GROUP_PAGE
    ? Math.max(0, startSkip + envelopes.length - GROUP_MARGIN)
    : startSkip;
  rec.knownEnvIds = Array.from(persistedKnown).slice(-1000);
  for (const m of members) m.nick = tagToNick[m.tag] ?? '';
  rec.nicks = { ...tagToNick };
  try { await saveGroupRecord(deps.storage, rec); } catch { /* nickname persistence best-effort */ }
  return { tagToVeilId, tagToNick, members, fingerprint, needsRotation };
}

// ---------- send / receipts ----------

export async function sendGroupMessage(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string; text: string; cover?: boolean },
): Promise<{ senderTag: string }> {
  const r = await submitGroupEnvelope(deps, opts);
  return { senderTag: r.senderTag };
}

/** web parity: group read receipts are {__veil_receipt:1, ids, read?} through
 *  the encrypted group channel. */
export async function sendGroupReceipt(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string; ids: string[]; read: boolean },
): Promise<void> {
  if (!opts.ids.length) return;
  const body = opts.read
    ? JSON.stringify({ __veil_receipt: 1, ids: opts.ids.slice(0, 20), read: true })
    : JSON.stringify({ __veil_receipt: 1, ids: opts.ids.slice(0, 20) });
  await submitGroupEnvelope(deps, { ...opts, text: body, cover: false });
}

// ---------- media (web parity: __veil_media JSON through the group channel) ----------

export async function sendGroupMediaMessage(
  deps: GroupSessionDeps,
  opts: {
    groupToken: string; sessionToken: string; clientId: string;
    media: { bytes: Uint8Array; name?: string; mime?: string; size?: number; dl?: boolean };
    localUri?: string;
    uploadCiphertext?: (ciphertext: Uint8Array) => Promise<string>;
  },
): Promise<{ id: string; media: { uri: string; k: string; iv: string; mime: string; name: string; size: number; dl: boolean; localUri?: string } }> {
  const size = opts.media.size ?? opts.media.bytes.byteLength;
  const { ciphertext, keyB64, ivB64 } = await encryptMedia(opts.media.bytes);
  const fileUri = opts.uploadCiphertext
    ? await opts.uploadCiphertext(ciphertext)
    : await deps.relay.uploadPrivateFile({ bytes: ciphertext, name: 'veil-media' });
  const f: Record<string, unknown> = { name: opts.media.name || 'media', mime: opts.media.mime || 'application/octet-stream', size };
  if (opts.media.dl) f.dl = 1;
  const body = JSON.stringify({ __veil_media: 1, uri: fileUri, k: keyB64, iv: ivB64, ...f });
  await submitGroupEnvelope(deps, {
    groupToken: opts.groupToken, sessionToken: opts.sessionToken,
    clientId: opts.clientId, text: body, cover: false,
  });
  // note: media_uri rides on the envelope record server-side; the group
  // receiver reads it from the entity row like the web does.
  return {
    id: `local_${Date.now()}_${Math.floor(Math.random() * 1e6)}`,
    media: { uri: fileUri, k: keyB64, iv: ivB64, mime: String(f.mime), name: String(f.name), size, dl: !!opts.media.dl, localUri: opts.localUri },
  };
}

// ---------- rotate / evict (creator) ----------

export async function rotateGroup(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string },
): Promise<number> {
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('Group keys are not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the group creator can rotate the keys.');

  // b138: routed through veilGroupGate 'roster' (entity is admin-only now).
  const rows = (await gateRoster(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken }))
    .members.filter((m) => m && String(m.veil_id ?? '') && String(m.veil_id) !== rec.veilId);

  const newGek = toB64(randomBytes(32));
  const wraps = [];
  for (const m of rows) {
    const veilId = String(m.veil_id);
    let pqPub = '';
    try {
      pqPub = String(((await deps.relay.invoke('veilIdentityGate', { action: 'lookup', veil_id: veilId })).data as { pq_pub?: string })?.pq_pub ?? '');
    } catch { /* lookup failure handled below */ }
    if (!pqPub) throw new Error(`${veilId} has no published PQ prekey — cannot rotate yet.`);
    wraps.push(await buildRekeyWrap(pqPub, veilId, newGek));
  }

  const pq = await mlkemKeypair();
  const newEpoch = rec.epoch + 1;
  await sendGroupMessage(deps, {
    groupToken: opts.groupToken,
    sessionToken: opts.sessionToken,
    clientId: opts.clientId,
    text: JSON.stringify({ __veil_group_rekey: 1, ge: newEpoch, pq: pq.pub, wraps }),
  });
  await deps.relay.invoke('veilGroupGate', {
    action: 'rotate',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: (await deps.sessions.load(opts.sessionToken) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
    new_epoch: newEpoch,
    group_pq_pub: pq.pub,
  });
  await advanceEpoch(deps.storage, opts.groupToken, newEpoch, newGek, pq.pub);
  return newEpoch;
}

export async function evictGroupMember(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; target: { veilId: string; ikPub: string } },
): Promise<void> {
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('Group keys are not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the group creator can remove members.');
  const deny_sig = await denySignature(rec.ikSeedB64, opts.groupToken, opts.target.ikPub, rec.epoch);
  await deps.relay.invoke('veilGroupGate', {
    action: 'evict',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: (await deps.sessions.load(opts.sessionToken) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
    remover_IK_pub: rec.ikPubB64,
    target_IK_pub: opts.target.ikPub,
    target_veil_id: opts.target.veilId || '',
    deny_sig,
  });
  // web parity: eviction is followed immediately by a key rotation so the
  // evicted member loses access to future messages.
}

// ---------- exports for the App layer ----------

export {
  loadGroupRecords, loadGroupRecord, groupRecord, forgetGroup,
  exportGroupRecords, importGroupRecords,
  decryptGroupText, encryptGroupText, epochFingerprint, senderTag,
  groupNeedsRotation, type GroupRecord, type GroupRekeyPayload,
};

/** creator's main group session finder (web: initiator_client_id === me &&
 *  state active && !responder_client_id). */
export async function findMainGroupSession(
  deps: GroupSessionDeps, groupToken: string, clientId: string,
): Promise<string | null> {
  const raw = await deps.relay.sessionList(clientId);
  const d = raw.data as { data?: Record<string, unknown>[]; sessions?: Record<string, unknown>[] };
  const list = d?.data ?? d?.sessions ?? (raw.data as Record<string, unknown>[] ?? []);
  for (const r of list) {
    if (String(r.group_token ?? '') === groupToken
      && String(r.initiator_client_id ?? '') === clientId
      && String(r.state ?? '') === 'active'
      && !String(r.responder_client_id ?? '')) {
      return String(r.token ?? '');
    }
  }
  return null;
}

/** decrypt a group session row's name blob for display */
export async function groupRowLabel(
  deps: GroupSessionDeps, groupToken: string, nameBlob: string,
): Promise<string | null> {
  const rec = (await loadGroupRecord(deps.storage, groupToken)) ?? groupRecord(deps.storage, groupToken);
  if (!rec) return null;
  try {
    return await decryptGroupText(rec.nameGekB64 || rec.gekB64, nameBlob);
  } catch {
    return null;
  }
}

// re-export writeHashHex (used by callers composing group session records)
export { writeHashHex };

/** unused import guard: createSession/serialize kept for parity with the
 *  main-session ratchet the web stores (harmless, keeps sessions.load working) */
export async function ensureMainSessionRatchet(deps: GroupSessionDeps, token: string, writeSecret: string): Promise<void> {
  const existing = await deps.sessions.load(token);
  if (existing) return;
  const { state } = await createSession(token, '');
  state.writeSecret = writeSecret;
  await deps.sessions.save(token, await serializeRatchetState(state));
}
