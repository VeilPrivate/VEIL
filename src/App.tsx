import { secureRemove } from '../vendor/device/src/secure-wipe';
import { CallManager } from './calls/CallManager';
import { CallOverlay } from './components/CallOverlay';
import { adoptNotesIdentityKey, NOTES_KEY_STORAGE } from '../vendor/device/src/notes';
import { secureEnclaveAvailable, keyvaultEntrySealed, resetSecureEnclaveKey } from './secure-store.rn';
import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Alert, AppState, ActivityIndicator, Linking, View, Text, StyleSheet, Image, Keyboard, SafeAreaView } from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import * as ScreenCapture from 'expo-screen-capture';
import { Audio } from 'expo-av';
import { startScreenWatch } from './screen-watch';
import { createVeilApp, VEIL_BASE_URL, type VeilApp } from './veil-app';
import { purgeIfFreshInstall } from './fresh-install-guard';

import { createDeviceTransfer, receiveDeviceTransfer } from '../vendor/device/src/transfer';
import { createInviteSession, joinInviteSession } from '../vendor/device/src/invite';import * as ImagePicker from 'expo-image-picker';
import * as FileSystem from 'expo-file-system';
import * as MediaLibrary from 'expo-media-library';
import { LoginScreen } from './screens/LoginScreen';
import { OtpScreen } from './screens/OtpScreen';
import { MainScreen } from './screens/MainScreen';
import { IdentityScreen } from './screens/IdentityScreen';
import { ChatScreen, type ChatMessageUI, type PendingPick } from './screens/ChatScreen';
import { LockScreen } from './screens/LockScreen';

/** auto-lock §0: shared module-level last-interaction clock. The root view's
 *  touch responder lives outside <VeilApp/>'s scope, so the inactivity clock
 *  must be module state, not a ref inside the component. */
let VEIL_LAST_ACTIVITY = Date.now();

/**
 * b111 (owner directive: "no errors like that coming up at all"): every error
 * path that reaches the SCREEN must speak human. The raw exception (message +
 * stack) still flows to the Metro console for diagnosis, but the UI never shows
 * internal strings — the build-35 lesson was a mate staring at
 * "Media picker returned nothing (canceled=true…)" like it was a hex dump.
 */
function friendlyError(e: unknown, what: string): string {
  const err = e as Error;
  const raw = String(err?.message ?? e);
  console.log(`[veil-error] ${what}:`, raw, err?.stack ?? '');
  const s = raw.toLowerCase();
  if (s.includes('network') || s.includes('timeout') || s.includes('fetch') || s.includes('request failed'))
    return 'Connection problem — check your internet and try again.';
  if (s.includes('permission') || s.includes('not authorized') || s.includes('denied'))
    return 'A permission was declined — check VEIL in iPhone Settings, then try again.';
  if (s.includes('100 mb') || s.includes('25 mb') || s.includes('too large') || s.includes('size'))
    return 'That file is too large — the limit is 25 MB per message.';
  if (s.includes('session not found') || s.includes('no longer') || s.includes('gone'))
    return 'That session is no longer available.';
  if (s.includes('credentials') || s.includes('password') || s.includes('email'))
    return 'Those sign-in details did not work — check them and try again.';
  if (s.includes('biometr') || s.includes('face id') || s.includes('keychain'))
    return 'Face ID / keychain could not complete — try again.';
  if (s.includes('rate limit'))
    // b175 (owner Metro repro, Oct 2: burst send surfaced a raw-feeling
    // "Something went wrong" during a transient relay throttle): the relay's
    // anti-abuse limiter is a few-second self-healing cooldown, not a real
    // failure — say so plainly instead of falling through to the scary
    // generic bucket. The composer keeps the drafted text either way.
    return 'The server is briefly busy — wait a few seconds and try again.';
  return 'Something went wrong — please try again.';
}

const veilActivityPing = () => { VEIL_LAST_ACTIVITY = Date.now(); };
import { OnboardingScreen } from './screens/OnboardingScreen';
import { AttributionSheet } from './screens/AttributionSheet';
import { WelcomeScreen, fetchLoungePayload } from './screens/WelcomeScreen';
import { type AppLockRecord, type LockoutState, MAX_ATTEMPTS } from '../vendor/device/src/applock';
import { relayTimestampToIso } from '../vendor/device/src/time';
import { registerPushToken, unregisterPushToken, notifyNewMessage, notifyNewInvite } from './notifications';
import * as Notifications from 'expo-notifications';
import { createIdentity, restoreIdentity, type VeilIdentityMaterial } from '../vendor/crypto-core/src/index';
import { provisionIdentity, restoreFromPhrase, createOneTapSession, acceptOneTapSession, syncChat, sendChatMessage, sendCoverEnvelope, sendReadReceipt, completeContactHandshake, sendMediaMessage, loadMediaFile, markEnvelopeDisplayed, markEnvelopesDisplayed, MEDIA_LIMIT_BYTES,
  createGroup, joinGroup, pollGroupInbox, sendGroupMessage, sendGroupReceipt, sendGroupMediaMessage, rotateGroup, evictGroupMember, groupRowLabel, loadGroupRecord, loadGroupRecords, saveGroupRecord, groupRecord, findMainGroupSession, forgetGroup, GROUP_MEMBER_CAP, listGroupTokens, joinLounge, joinForum, sendForumMessage, pollLoungeInbox, parseLoungeDescriptor, loungeThreadToken, FORUM_DESC_VERSION, FORUM_DESC_VERSION_2, exportGroupRecords, type GroupMemberRow } from '../vendor/device/src/index';
import { type VeilSettings, normalizeSettings, AUTO_LOCK_MINUTES, SELF_DESTRUCT_HOURS, SELF_DESTRUCT_WARN_HOURS } from '../vendor/device/src/settings';
import type { KeyvaultIdentity, ChatMessage } from '../vendor/device/src/index';
import { silentLogin } from '../vendor/device/src/silent-auth';
import {
  noteSessionStart, noteAppOpen, noteVeilIdCreated, noteEmailVerified,
  noteFirstSession, saveAttribution, flushPendingAttribution,
} from '../vendor/device/src/funnel';
import { identityFingerprint, toB64 } from '../vendor/crypto-core/src/index';
import type { SessionRow } from './screens/SessionsScreen';
import { collapseGroupRows } from './session-list';
import type { ContactRow, LookupResult } from './screens/ContactsScreen';

type Screen = 'boot' | 'login' | 'otp' | 'identity' | 'onboard' | 'main' | 'chat' | 'welcome';

/**
 * iOS invalidates ALL Keychain items written with
 * ACCESS_CONTROL.BIOMETRY_CURRENT_SET the moment the enrolled biometry
 * changes (Face ID/Touch ID re-enrolled or reset) — SecItemCopyMatching then
 * returns errSecAuthFailed (-25293), rendered as "The user name or
 * passphrase you entered is not correct." That is an OS security feature,
 * not an app bug — but the identity is fully recoverable from the 24-word
 * phrase, so boot must treat it as "no identity on this device" (clear the
 * dead entry, route to the restore flow) instead of dead-ending on the fatal
 * "VEIL could not start" screen.
 */
function isKeychainAuthDead(e: unknown): boolean {
  const m = String((e as Error)?.message || e);
  if (!m.includes('veil_keyvault_identity')) return false;
  return (
    m.includes('user name or passphrase you entered is not correct') ||
    m.includes('-25293') ||
    m.toLowerCase().includes('authfailed') ||
    // b104 FIX (owner hardware crash, Sept 21): "VEIL could not start" —
    // Keychain get('veil_keyvault_identity') failed — original: Biometry is
    // not available for this app. This is a DIFFERENT OS error class than
    // the -25293 re-enrollment case above (LAError.biometryNotAvailable,
    // not errSecAuthFailed) but the same recovery answer applies: the
    // gated entry cannot be read on this device right now, and the identity
    // is fully recoverable from the 24-word phrase — a boot-time read
    // failure must NEVER hard-crash to the fatal screen when a safe
    // fallback (clear + route to restore) exists. Previously this string
    // matched none of the checks above and fell through to `throw e`,
    // taking down the whole app at boot with no recovery UI at all.
    m.toLowerCase().includes('biometry is not available') ||
    m.toLowerCase().includes('biometry is not enrolled')
  );
}

function VeilApp() {
  const [app, setApp] = useState<VeilApp | null>(null);
  const [screen, setScreen] = useState<Screen>('boot');
  /** entry mode for the identity screen — 'confirm-create' when arriving from Generate new Veil ID */
  const [identityEntry, setIdentityEntry] = useState<'choose' | 'confirm-create'>('choose');
  const [identity, setIdentity] = useState<KeyvaultIdentity | null>(null);

  // b62 groups: reload keychain group records at boot (records never expire —
  // losing them means losing group access on this device)
  useEffect(() => {
    if (!app) return;
    loadGroupRecords(app.storage).then((n) => { if (n > 0) console.log(`[veil-group] restored ${n} group record(s)`); }).catch(() => undefined);
  }, [app]);
  const [pendingMaterial, setPendingMaterial] = useState<VeilIdentityMaterial | null>(null);
  // b112: phrase awaiting a classic email sign-in (pre-b112 accounts) — the
  // restore resumes automatically the moment that sign-in succeeds
  const [pendingRestorePhrase, setPendingRestorePhrase] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // b172: the message cache refused a write for this token — surfaced as the
  // honest "couldn't save history" notice instead of silent thread amnesia.
  const [cacheSaveFailed, setCacheSaveFailed] = useState<string | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [tab, setTab] = useState<'sessions' | 'contacts' | 'vaults' | 'stego' | 'notes' | 'settings'>('sessions');
  // b95: owner-approved one-time verify card (see openChat for the gate)
  const [verifyCard, setVerifyCard] = useState(false);
  const [chat, setChat] = useState<{ token: string; title: string; subtitle: string; status: 'pending' | 'active' | 'ended'; peerVeilId: string | null; canNewThread: boolean; myVerified: boolean; peerVerified: boolean; groupToken?: string; lounge?: boolean; forum?: boolean; burnAfterOpen?: boolean; burnSeconds?: number; fingerprint?: string | null; peerPinned?: boolean; contact?: boolean } | null>(null);
  const [groupInfo, setGroupInfo] = useState<{ isCreator: boolean; epoch: number; fingerprint: string | null; members: GroupMemberRow[] } | null>(null);
  /** b123: device-local nickname of the OPEN thread's peer (rename modal prefill) */
  const [chatLocalNick, setChatLocalNick] = useState<string | null>(null);
  const [groupBusy, setGroupBusy] = useState(false);
  const [threadReady, setThreadReady] = useState(false);
  const chatRef = useRef<{ token: string; peerVeilId?: string | null; groupToken?: string } | null>(null); // b123: peerVeilId added for the local rename handler; b198: groupToken for the sync routers
  // b84: when openChat last opened a thread — the banner gate below needs it,
  // because right after an unlock-resume AppState.currentState can still read
  // 'inactive'/'background' for a moment, and the FIRST decrypt of the thread
  // you just opened would slip past the gate and banner you with the message
  // you are visibly reading (owner repro: banner fired right after entering
  // the chat from the lock screen).
  const chatOpenedAtRef = useRef(0);
  // guards against overlapping poll calls (interval tick + foreground + push
  // firing close together) decrypting the SAME envelope twice before either
  // call's advanced ratchet state is persisted — the exact cause of the
  // "everything arrives twice" bug (two concurrent syncChat calls both load
  // the not-yet-saved state and each independently decrypts the new envelope).
  const syncInFlightRef = useRef<Record<string, boolean>>({});
  // b196: adaptive background backoff — per-token next-poll timestamps and
  // quiet-streak counters. A thread that produces nothing new polls half as
  // often each pass (10s → 20s → 40s → 60s cap + jitter); any new content
  // resets it. The foreground open-thread poll is untouched, so open
  // threads stay real-time. Cuts per-account request pressure at tester
  // scale, where quiet threads dominate (owner Metro log Oct 12).
  const pollBackoffRef = useRef<Record<string, number>>({});
  const zeroStreakRef = useRef<Record<string, number>>({});
  // b91: the end-session desync recommendation fires once per thread per
  // app run, not on every poll that sees a key-mismatch/stacking failure
  const desyncPromptedRef = useRef<Record<string, boolean>>({});
  const syncTokenRef = useRef<(t: string) => void>(() => {});
  // b175 (owner Metro repro, Oct 2: rapid-fire burst tripped the relay's
  // anti-abuse rate limiter — burn/heartbeat/list all 500'd "Rate limit
  // exceeded" — but the 1.5s poll loop kept hammering at full speed with no
  // backoff, which is the exact abuse signature behind the historical K-4
  // 10-minute lockout). Per-token cooldown + doubling backoff, reset on the
  // next clean pass.
  const rateLimitCooldownUntilRef = useRef<Record<string, number>>({});
  const rateLimitBackoffMsRef = useRef<Record<string, number>>({});
  const RATE_LIMIT_BACKOFF_BASE_MS = 5000;
  const RATE_LIMIT_BACKOFF_CAP_MS = 60000;
  // b175: heartbeat-side limiter gate — see the heartbeat effect below.
  const hbLimiterHotUntilRef = useRef(0);
  // b196-r8 fail-close sets: sessions proven dead (credential-invalid beat,
  // or a handshake the relay says is already joined) must stop retrying —
  // the pre-r8 loops spammed 403s / 'Session already joined' every 3-7s
  // forever on restored threads whose local state is gone.
  const hbDeadRef = useRef<Set<string>>(new Set());
  // b197-r6: sessionActivate runs at most once per token per app run — repeat
  // opens/supersede auto-switches skipped the redundant relay round trip.
  const activatedOnceRef = useRef<Set<string>>(new Set());
  const hsFailClosedRef = useRef<Set<string>>(new Set());
  const HB_LIMITER_COOLDOWN_MS = 30000;
  const backgroundSyncAllSessionsRef = useRef<() => void>(() => {});
  const [chatMessages, setChatMessages] = useState<(ChatMessage & { sender?: string; senderVerified?: boolean; systemNote?: string })[]>([]);
  // b62 groups: per-thread known-envelope guard (separate from chatKnown because
  // group processing must not race the 1:1 path's set semantics)
  const groupKnownRef = useRef<Set<string>>(new Set());
  // session-token -> group-token map, filled at openChat/join time (survives a
  // stale sessionRows snapshot until the next refresh)
  const groupKnownTokensRef = useRef<Record<string, string>>({});
  // b134: sticky winner-token memory for collapseGroupRows — see
  // session-list.ts for why this exists (message-cache-vanishes-on-reopen
  // fix). Keyed by groupToken -> the token last chosen to represent it.
  const groupWinnerRef = useRef<Record<string, string>>({});
  // b196-r5: Founding Tester Forum banner — visible only to non-members,
  // dismissible for 7 days at a time, one tap = the hosted-descriptor join.
  const [forumJoined, setForumJoined] = useState(true); // true until known — never flash
  const [forumJoining, setForumJoining] = useState(false);
  const [forumBannerDismissedAt, setForumBannerDismissedAt] = useState(0);
  useEffect(() => {
    if (!app) return;
    app.storage.get('veil_forum_banner_dismissed').then((iso) => {
      const t = iso ? Date.parse(String(iso)) || 0 : 0;
      setForumBannerDismissedAt(t);
    }).catch(() => undefined);
  }, [app]);
  const handleDismissForumBanner = useCallback(() => {
    setForumBannerDismissedAt(Date.now());
    const iso = new Date().toISOString();
    (app ? app.storage.set('veil_forum_banner_dismissed', iso) : Promise.resolve()).catch(() => undefined);
  }, [app]);

  const [chatKnown, setChatKnown] = useState<Set<string>>(new Set());
  const [draft, setDraft] = useState('');
  // media: the picked-but-unsent image (confirm dialog), and the per-message
  // decrypt cache (data: URIs in MEMORY — web parity: decrypted blobs never
  // touch disk; on restart they re-fetch + re-decrypt from the relay)
  const [pendingPick, setPendingPick] = useState<PendingPick | null>(null);
  const [allowDl, setAllowDl] = useState(false);

  /**
   * b96 (owner directive: "key phrase should restore everything"): the notes
   * key is DERIVED from the identity's ik seed (itself phrase-derived), so a
   * Nothing-at-Rest wipe + 24-word phrase restore brings every relay-side
   * note back. Existing notes encrypted under the old device-local random
   * key are re-encrypted once, transparently. Best-effort — a failure must
   * never block the app — and safe to call repeatedly (idempotent).
   */
  const ensureNotesKey = useCallback(async (id: KeyvaultIdentity) => {
    if (!app) return;
    try {
      await adoptNotesIdentityKey(app.notes, id.ikSeedB64, {
        get: (k) => app.storage.get(k),
        set: (k, v) => app.storage.set(k, v),
        listRows: async () => {
          const data = (await app.relay.entityList('VeilNote', { sort: '-updated_date', limit: 100 })) as unknown;
          const rows = (Array.isArray(data) ? data : ((data as { data?: unknown[] })?.data ?? [])) as Array<{ id: string; payload_ciphertext: string; payload_iv: string }>;
          return rows;
        },
        updateRow: (rid, rec) => app.relay.entityUpdate('VeilNote', rid, rec),
      });
      // b101 owner backfill: the ghost filter (visibleUnderIdentity) can only
      // classify TAGGED rows, and every note created before this build is
      // untagged. Since the notes key is identity-derived (b96), a row that
      // DECRYPTS under this identity's key provably belongs to it — tag it
      // with owner_veil_id once, so a future identity reset hides it instead
      // of resurrecting it as a "(encrypted on this note key)" ghost forever.
      // Rows that don't decrypt (other identity, web device key, corrupted)
      // stay untagged and visible until deleted. Idempotent; zero crypto work
      // once every row is tagged.
      const data = (await app.relay.entityList('VeilNote', { sort: '-updated_date', limit: 100 })) as unknown;
      const rows = (Array.isArray(data) ? data : ((data as { data?: unknown[] })?.data ?? [])) as Array<{
        id: string; owner_veil_id?: string; payload_ciphertext?: string; payload_iv?: string;
      }>;
      for (const r of rows) {
        if (!r.id || r.owner_veil_id || !r.payload_ciphertext || !r.payload_iv) continue;
        try {
          await app.notes.decryptNote(r.payload_ciphertext, r.payload_iv); // proof of ownership
          await app.relay.entityUpdate('VeilNote', r.id, { owner_veil_id: id.veilId });
        } catch { /* not this identity's key — leave untagged */ }
      }
    } catch (e) {
      console.warn('[veil] notes key adoption failed:', String((e as Error)?.message || e));
    }
  }, [app]);
  const ensureNotesKeyRef = useRef(ensureNotesKey);
  useEffect(() => { ensureNotesKeyRef.current = ensureNotesKey; }, [ensureNotesKey]);

  /**
   * NOTHING-AT-REST v2 (b95, owner spec from hardware verify Sept 21: lock the
   * phone → unlock → "absolutely nothing wiped: no note, no chat, no stego,
   * no vault, no ID"). The old implementation only ever wiped conversation
   * keys + the plaintext cache, and ONLY on a real 'background' event — iOS
   * never delivers one for a screen lock, so locking fired NOTHING, and
   * notes/vaults/stego media were never covered at all.
   * v2: one wipe covering the ENTIRE Veil surface, fired from THREE sites —
   * (1) the moment the dial flips to 'memory', (2) any departure from the
   * foreground ('inactive' = screen lock, 'background' = app switch), and
   * (3) every cold boot while the mode is on (catches a process kill that
   * never delivered an event). Storage only — RAM state is reset by the
   * caller when the user can see it.
   */
  const naRWipeStorage = useCallback(async (): Promise<void> => {
    if (!app) return;
    try { await app.vault.onClose(); } catch { /* conversation layer, best-effort */ }
    // stego images this app saved to Photos — tracked in veil_saved_media at
    // save time; delete silently (same purge the duress wipe uses).
    try {
      const rawIds = await app.storage.get('veil_saved_media');
      const ids = rawIds ? (JSON.parse(rawIds) as string[]) : [];
      if (ids.length) {
        const perm = await MediaLibrary.getPermissionsAsync();
        if (perm.granted) { try { await MediaLibrary.deleteAssetsAsync(ids); } catch { /* best-effort */ } }
      }
    } catch { /* best-effort */ }
    // encrypted vault-container cache + stray temp files (outside the keychain)
    try {
      const cacheDir = FileSystem.cacheDirectory;
      if (cacheDir) {
        for (const f of await FileSystem.readDirectoryAsync(cacheDir)) {
          if (f.startsWith('veil-vault-') || f.startsWith('veil-stego-') || f.startsWith('veil-upload-')) {
            await FileSystem.deleteAsync(cacheDir + f, { idempotent: true }).catch(() => undefined);
          }
        }
      }
    } catch { /* best-effort */ }
    // every veil_ record except the minimum needed to keep the app itself
    // usable: the login session, the mode flag, the privacy dials, the
    // app-lock gate, pinned contacts, and the device's client id. Notes key,
    // vault keys, message caches, ratchet states, identity — all gone.
    const keep = new Set(['veil_auth_session', 'veil_storage_mode', 'veil_settings_v1', 'veil_app_lock', 'veil_pins_v1', 'veil_client_id']);
    for (const k of await app.storage.keys('veil_')) {
      if (keep.has(k)) continue;
      await secureRemove(app.storage, k).catch(() => undefined);
    }
    // b95 NaR v2: the device must go SILENT too — delete this device's push
    // registration server-side so a locked, wiped phone shows NO banner for
    // incoming messages (owner hardware finding: web→iPhone message still
    // notified after a NaR lock). Re-registers only when an identity is
    // restored from the phrase (the App registration effect gates on identity).
    // best-effort at every wipe site; offline flip retries at the boot wipe
    try {
      await unregisterPushToken({
        entityCreate: (e, r) => app.relay.entityCreate(e, r),
        entityList: (e, pr) => app.relay.entityList(e, pr),
        entityDelete: (e, id) => app.relay.entityDelete(e, id),
        getCached: (k) => app.storage.get(k),
        setCached: (k, v) => app.storage.set(k, v),
      });
    } catch { /* never block a wipe on the network */ }
  }, [app]);
  const naRWipeRef = useRef(naRWipeStorage);
  useEffect(() => { naRWipeRef.current = naRWipeStorage; }, [naRWipeStorage]);

  const handleSettingsChange = useCallback(async (s: VeilSettings) => {
    const prevMode = settingsRef.current.storageMode;
    setSettings(s); // instant UI feedback
    settingsRef.current = s; // synchronous — the hardware-gate getter below and the reprotect check need this NOW, not after the next render
    if (app) {
      await app.settings.save(s).catch((e) => console.error('[veil] settings save failed:', e));
      // sync the real key-storage engine (IdentityVault) to the dial: this is what
      // actually wipes veil_rk_*/veil_gk_* at flip under Nothing-at-Rest — the
      // settings field alone only drives the UI unless this call happens.
      await app.vault.setMode(s.storageMode).catch((e) => console.error('[veil] vault mode sync failed:', e));
      // b95 NaR v2: the invariant must hold the instant the dial flips —
      // nothing Veil-stored (notes, vaults, stego, chats, identity material)
      // remains on this device from this moment on. RAM keeps running so the
      // user isn't yanked out of Settings mid-tap; the first lock/close wipes it.
      if (s.storageMode === 'memory' && prevMode !== 'memory') {
        await naRWipeStorage().catch(() => undefined);
      }
      // entering or leaving "hardware" mode needs the identity keyvault re-written
      // once so the biometric gate is actually added/removed on that entry
      // (secure-store.rn.ts reads the mode live at write-time, not at boot).
      if (s.storageMode !== prevMode && (s.storageMode === 'hardware' || prevMode === 'hardware')) {
        try {
          // b98 FIX: this used to re-read the identity from the Keychain
          // (app.vault.load()) purely to immediately write it straight back
          // out with new attributes — a completely unnecessary fresh GET on
          // the one entry most prone to the -25293 ACL-mismatch class of bug
          // (owner hit it live on b97, even with an explicit authentication
          // Prompt on the read: the boot-time load already succeeded and is
          // sitting in memory, RIGHT ON SCREEN, the whole time). There is no
          // reason to re-read what we already have — use the in-memory copy
          // and go straight to the WRITE, which already self-heals the same
          // ACL-mismatch class via delete+retry (secure-store.rn.ts set()).
          const id = identityRef.current;
          // b104 FIX (owner Sept 21: flipped to hardware on b103, "absolutely
          // nothing" happened — no prompt, no error, flip silently completed).
          // Two compounding causes: (1) iOS's biometric GRACE WINDOW — the
          // verification read at the bottom of this block relies on the SE
          // key's kSecAccessControlBiometryCurrentSet ACL to raise system UI,
          // but iOS skips that prompt when a biometric unlock happened
          // recently (the user had just unlocked the phone to open the app),
          // so a flip done right after unlocking legitimately shows nothing;
          // (2) that verification read is `.catch(() => undefined)` — its
          // result is discarded, so a failed/cancelled/no-prompt read was
          // indistinguishable from success. Fix: demand biometrics EXPLICITLY
          // at the top of the flip, via expo-local-authentication's
          // authenticateAsync — this always presents the Face ID sheet (no
          // grace-window shortcut) and its outcome is enforced: cancel/fail
          // aborts the flip and reverts the dial. disableDeviceFallback keeps
          // the semantics identical to the SE gate itself (biometry only, no
          // passcode fallback — the SE key's ACL has none either).
          if (s.storageMode === 'hardware') {
            const bio = await LocalAuthentication.authenticateAsync({
              promptMessage: 'Confirm Face ID to switch key storage to hardware',
              cancelLabel: 'Cancel',
              disableDeviceFallback: true,
            });
            if (!bio.success) {
              throw new Error(`biometric confirmation failed or was cancelled (${bio.warning || bio.error || 'cancelled'})`);
            }
          }
          // b102 FIX: devices that first touched hardware mode before b100
          // carry a persisted SE key created WITHOUT a biometry constraint —
          // loadOrCreateSeKey() reuses it forever, so the seal succeeds and
          // unwrap never prompts Face ID (owner Sept 21: "does not engage
          // Face ID or anything else"). Regenerate the key with today's
          // biometryCurrentSet ACL before sealing; safe because the identity
          // is in memory (identityRef) and is re-sealed under the fresh key
          // by the save below, inside the same try block.
          if (s.storageMode === 'hardware' && id && secureEnclaveAvailable()) {
            await resetSecureEnclaveKey();
          }
          if (id) await app.vault.save(id);
          // b96: PROVE the gate at the flip — read the entry back through the
          // gated path so Face ID is demanded immediately (owner finding:
          // "none of the modes asks me for biometrics" — the gate previously
          // only engaged on a cold boot, so flipping modes mid-session never
          // visibly did anything). A cancelled prompt is fine: the seal is
          // in place and the next boot demands it again.
          if (s.storageMode === 'hardware' && id) {
            if (secureEnclaveAvailable() && (await keyvaultEntrySealed()) === 'plain') {
              throw new Error('Secure Enclave did not accept the seal');
            }
            // b104: stop swallowing this read — its failure was invisible
            // ("absolutely nothing" on b103). A failure here after a
            // successful explicit biometric prompt is a REAL problem worth a
            // Metro line, not a silent pass.
            await app.vault.load().catch((e) => console.warn('[veil] gated verification read after flip failed:', e?.message ?? e));
          }
        } catch (e) {
          console.error('[veil] keyvault re-protect failed:', e);
          // AUDIT FIX (Sept 19): this used to fail silently in the console
          // only — the user saw the toggle "succeed" while the keychain
          // entry was left broken. Now it's surfaced and the dial reverts.
          const reverted = { ...s, storageMode: prevMode };
          setSettings(reverted);
          settingsRef.current = reverted;
          // b97 FIX: the revert above only touched React state — the NEW
          // mode had already been persisted to disk by app.settings.save(s)
          // a few lines above, before this re-protect attempt even ran. A
          // failed flip was leaving settings.json and the actual (unchanged)
          // keychain entry permanently out of sync — every later boot would
          // read back the stale "hardware" mode and try to reconcile a
          // keyvault entry that was never actually re-gated, risking the
          // exact repeated failure this block exists to recover from. Now
          // the revert is persisted too, so a failed flip is fully undone.
          await app.settings.save(reverted).catch(() => undefined);
          // b102: if the failure struck AFTER the SE key was regenerated,
          // any sealed entry is now unreadable (its wrapping key is gone).
          // settingsRef.current is already reverted, so re-writing the vault
          // from the in-memory identity stores it under the reverted mode —
          // the next boot can never hit a sealed blob whose key no longer
          // exists. Best-effort; identity is still in RAM either way.
          if (identityRef.current) await app.vault.save(identityRef.current).catch(() => undefined);
          // (b67) fix: this used to call the app-wide setError(), which
          // ChatScreen also renders — the stale message was bleeding into
          // unrelated chat threads opened afterwards. A native alert is
          // scoped to this action only.
          const authIssue = /auth|passphrase|user name|biometr|cancel/i.test(String((e as Error)?.message || e));
          Alert.alert(
            'Could not switch key storage mode',
            authIssue
              ? 'Face ID / passcode confirmation failed or was cancelled. Reverted — try again and complete the prompt when it appears.'
              : 'Reverted — try again.',
          );
        }
      }
    }
  }, [app]);
  const [settings, setSettings] = useState<VeilSettings>(DEFAULTS);
  useEffect(() => { settingsRef.current = settings; }, [settings]);
  const receiptSentRef = useRef<Set<string>>(new Set());
  const [mediaSaving, setMediaSaving] = useState<Record<string, 'saving' | 'saved' | 'error'>>({});
  /** b62 voice notes: live recorder state for the chat composer */
  const [voiceRec, setVoiceRec] = useState<{ active: boolean; seconds: number }>({ active: false, seconds: 0 });
  const voiceRecRef = useRef<Audio.Recording | null>(null);
  const voiceTickRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const voiceRecStateSecondsRef = useRef(0);
  const [mediaLoad, setMediaLoad] = useState<Record<string, { loading: boolean; uri?: string; fileUri?: string; error?: string }>>({});
  const mediaInFlight = useRef<Record<string, boolean>>({});
  /** b88: consecutive session-list misses per open thread — see the
   *  dead-thread close effect near the b73 title patch. */
  const goneMissRef = useRef<Record<string, number>>({});
  // b164 FIX (owner Metro log Oct 2: the supersede-switch fired 4x for the
  // SAME dead session, flooding veilIdentityGate/veilSessionGate until the
  // relay 500'd with "Rate limit exceeded" and briefly broke the handshake).
  // Root cause: `chat` stays the OLD token until the async switch's
  // setChat() lands, but sessionRows keeps updating in that window (10s
  // poll, 3s sync tick) and re-fires the effect against the same stale
  // chat.token, re-matching the same replacement and re-calling openChat
  // (identity + pin + nickname lookups) each time. This guard blocks a
  // second switch for a token already mid-switch.
  const supersedeInFlightRef = useRef<Set<string>>(new Set());
  // b198 FRESHNESS GATE (the Native-One '+ thread loses its keys' root cause,
  // diagnosed from metro-live.log Oct 15): the b164 gone-detection effect acts
  // on sessionRows — but sessionRows is REACT STATE, updated only when a
  // refreshSessions pass lands. A brand-new '+' thread is NOT in the list yet
  // when its openChat runs, so the effect saw stillListed=false, matched an
  // OLDER same-peer row as the 'replacement', auto-switched, and
  // app.sessions.remove()d the JUST-CREATED thread's local keys — relay row
  // alive, credential gone, verify/heartbeat 403 'Invalid session credential'
  // forever (log evidence: the #48ca↔#0732 and #5fd9↔#d3c0 ping-pong pairs,
  // each bounce deleting one side's keys). The old guard only handled the
  // EMPTY-list case. These two stamps close the stale-list hole for real:
  // chatOpenedAtRef is stamped by openChat; listRefreshedAtRef is stamped by
  // refreshSessions with the time its relay list FETCH STARTED (a fetch that
  // began before the chat opened can never see the new row, so its completion
  // must not count as fresh). The effect refuses to act until a list fetched
  // AFTER the current chat opened has landed.
  const listRefreshedAtRef = useRef(0);
  // b167: identity-gate rate-limit lock window (ms epoch) — see handleMessage.
  const identityLockUntilRef = useRef<number>(0);
  /** b74: last-known relay dials per session token (from refreshSessions) */
  const sessionDialsRef = useRef<Record<string, { burn: boolean; burnSecs: number }>>({});
  // b155 decision A: relay record's contact_session flag per token —
  // contact (pinned) threads show 'Pinned contact', never ceremony state.
  const sessionContactRef = useRef<Record<string, boolean>>({});
  // b155: live view of session rows for the presence heartbeat loop
  const hbRowsRef = useRef<SessionRow[]>([]);

  const [locked, setLocked] = useState(false);
  const lockedRef = useRef(false);
  /** live mirrors so the mount-once AppState/inactivity watchers never read stale state */
  // b164: live mirrors so the mount-once AppState resume handler can call
  // the CURRENT refresh closures (same pattern as the watchers above).
  const refreshSessionsRef = useRef<((force?: boolean) => Promise<void>) | null>(null);
  // b191 parity (shell Oct 12): one-per-group notices for epoch-behind and
  // un-openable envelopes — a stale device must be TOLD, never left guessing.
  const groupBehindNoticeRef = useRef<Set<string>>(new Set());
  const refreshContactsRef = useRef<(() => Promise<void>) | null>(null);
  const identityRef = useRef<KeyvaultIdentity | null>(null);
  useEffect(() => { identityRef.current = identity; }, [identity]);
  const [lockHint, setLockHint] = useState<string | null>(null);
  const backgrounded = useRef(false);
  const autoLockBgAtRef = useRef<number | null>(null);
  const settingsRef = useRef<VeilSettings>(DEFAULTS);
  const [sessionRows, setSessionRows] = useState<SessionRow[]>([]);
  /** b178: session tokens seen by the LAST refreshSessions pass — null until
   *  the first pass seeds it (silent seed, no invite banners on login). */
  const knownSessionTokensRef = useRef<Set<string> | null>(null);
  const [appLock, setAppLock] = useState<AppLockRecord | null>(null);
  const appLockRef = useRef<AppLockRecord | null>(null);
  useEffect(() => { appLockRef.current = appLock; }, [appLock]);
  /** b123: progressive passcode lockout (5 attempts -> 5/10/20/40/60 min) */
  const [lockout, setLockout] = useState<LockoutState | null>(null);
  const [onboardingMode, setOnboardingMode] = useState<'full' | 'introOnly' | 'checkupOnly' | 'idOnly'>('full');
  const [securePrompt, setSecurePrompt] = useState(false);
  // b139 attribution: the skippable one-tap prompt, shown once after a Veil
  // ID is created (attribution-spec). Never gates anything.
  const [showAttribution, setShowAttribution] = useState(false);

  const [decoyMode, setDecoyMode] = useState(false);
  /** b61: live mirrors for the screen-capture watcher — avoids re-subscribing
   *  the native event on every render/state change. */
  const decoyModeRef = useRef(decoyMode);
  useEffect(() => { decoyModeRef.current = decoyMode; }, [decoyMode]);
  useEffect(() => { voiceRecStateSecondsRef.current = voiceRec.seconds; }, [voiceRec]);
  const chatOpenRef = useRef<string | null>(null);
  /** b74: groupToken of the currently open chat (null = 1:1) */
  const chatOpenGroupRef = useRef<string | null>(null); // session token while a conversation is open
  /** (b64) background as STATE: drives the capture-shield effect below */
  const [bgState, setBackgrounded] = useState(false);
  /**
   * (b70) Screenshot shield — CORRECTED after owner device evidence.
   * Metro proved `preventScreenCaptureAsync()` resolves "confirmed" every
   * time yet a screenshot still came out clean. Root cause (confirmed
   * against Expo's own docs, Sept 20): on iOS, preventScreenCaptureAsync
   * ONLY blocks screen *recording* — Apple gives NO app the power to block
   * a screenshot, full stop, and the promise resolving successfully never
   * meant screenshots were blocked. The b64 log line "-> PREVENT ...
   * confirmed" was true but misleading about WHAT it prevented.
   * Fix: split the two real iOS capabilities apart and stop overclaiming:
   *   - preventScreenCaptureAsync/allowScreenCaptureAsync: blocks screen
   *     RECORDING while the dial is on. Real, verifiable, kept.
   *   - enableAppSwitcherProtectionAsync/disableAppSwitcherProtectionAsync:
   *     the ACTUAL API for blurring the backgrounded app-switcher preview —
   *     the b64 comment claimed this already happened via preventScreenCapture,
   *     but that call does nothing for app-switcher snapshots either. Now wired
   *     to the correct API so backgrounding for real blurs the preview.
   *   - Screenshots themselves: UNBLOCKABLE on iOS by design (no exception).
   *     The only honest mitigation is detection + peer notice, already wired
   *     in screen-watch.ts/startScreenWatch below. Settings copy corrected
   *     to say this outright instead of implying screenshots get redacted.
   */
  useEffect(() => {
    // b197-r8 (owner product decision, claims test #1): recording block is
    // ALWAYS ON. The dial existed so users could self-record, but the
    // protection's purpose is the OTHER party's privacy — leaving it in the
    // recorder's hands means the person being captured never consented.
    // Same reasoning that made screenshot alerts always-on (K-18). The
    // settings key is retained for storage compatibility but is no longer read.
    const wantRecordingBlock = true;
    console.log(`[veil-shield] recording-block ALWAYS-ON -> PREVENT (screen recording only — iOS cannot block screenshots)`);
    const call = wantRecordingBlock ? ScreenCapture.preventScreenCaptureAsync() : ScreenCapture.allowScreenCaptureAsync();
    call.then(
      () => { console.log(`[veil-shield] ${wantRecordingBlock ? 'prevent' : 'allow'} confirmed (recording only)`); },
      (e: unknown) => { console.error('[veil-shield] FAILED:', String((e as Error)?.message || e)); },
    );
  }, [settings.screenshotShield]);
  useEffect(() => {
    const wantBlur = true; // b197-r8: always-on (owner decision) — bgState is now irrelevant to the dial
    console.log(`[veil-shield] app-switcher blur ALWAYS-ON bg=${bgState} -> ENABLE`);
    const fn = ScreenCapture as unknown as {
      enableAppSwitcherProtectionAsync?: (intensity?: number) => Promise<void>;
      disableAppSwitcherProtectionAsync?: () => Promise<void>;
    };
    const call = wantBlur ? fn.enableAppSwitcherProtectionAsync?.(0.85) : fn.disableAppSwitcherProtectionAsync?.();
    (call ?? Promise.resolve()).then(
      () => { console.log(`[veil-shield] app-switcher ${wantBlur ? 'blur' : 'unblur'} confirmed`); },
      (e: unknown) => { console.error('[veil-shield] app-switcher FAILED:', String((e as Error)?.message || e)); },
    );
  }, [settings.screenshotShield, bgState]);
  const [codeError, setCodeError] = useState<string | null>(null);
  const [codeVerifying, setCodeVerifying] = useState(false);
  const [codeResetKey, setCodeResetKey] = useState(0);
  const [contactRows, setContactRows] = useState<ContactRow[]>([]);
  const [contactsError, setContactsError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
     try {
      const a = await createVeilApp({ isHardwareGated: () => settingsRef.current.storageMode === 'hardware' });
      // b172 (owner hardware finding Oct 2: threads "deleted" their history
      // on close): the iOS Keychain can refuse large cache writes — surface
      // it in the open thread instead of failing invisibly.
      a.sessions.onCacheWriteFailure = (token) => setCacheSaveFailed(token);
      setApp(a);
      // b170: MUST run before anything below reads the Keychain-stored auth
      // session or identity — a reinstall-with-leftover-Keychain-data sweep
      // happening after that point would be too late (see fresh-install-guard.ts).
      await purgeIfFreshInstall(a).catch((e) => console.error('[veil-fresh-install] guard threw (non-fatal):', String((e as Error)?.message || e)));
      // b104: capture the REAL persisted settings in a local and sync the ref
      // NOW — the dead-entry catch below must act on the actual storageMode,
      // and settingsRef would otherwise still hold DEFAULTS at that point
      // (the [settings] effect hasn't fired yet mid-boot).
      const bootSettings = await a.settings.load();
      settingsRef.current = bootSettings;
      setSettings(bootSettings);
      const lockRec = await a.appLock.load();
      setAppLock(lockRec);
      setLockout(await a.appLock.lockout()); // b123: a surviving lockout window carries across restarts
      const session = await a.auth.currentSession();
      // b139 quality gate: one session_start row per cold start; drains the
      // fatal-interceptor crash flag from the previous run. app_opened /
      // retention markers fire only once an account session exists (a fresh
      // install emits them right after the silent account provisions).
      try {
        await noteSessionStart(a.relay, a.storage);
        if (session) {
          await noteAppOpen(a.relay, a.storage);
          await flushPendingAttribution(a.relay, a.storage);
        }
      } catch { /* instrumentation must never break boot */ }
      // b104 FIX (owner screenshot, Sept 21): Settings > About showed
      // "Signed in as —" on a live, logged-in session. Root cause: `email`
      // state is only ever set from the login-form's local `em` argument on
      // the SIGNUP/OTP-required paths — a normal successful login (see fix
      // #2 below) and every cold-boot session restore (HERE) left it at its
      // initial '' forever. The session we just fetched carries the real
      // account email — populate it now so Settings is correct from the
      // very first render after a restore, not only after a fresh login.
      if (session?.user?.email) setEmail(session.user.email);
      // b95 NaR v2: under Nothing-at-Rest a cold boot finds NOTHING — wipe
      // before anything loads. This also catches a process kill that never
      // delivered an AppState event (jetsam, crash): at most the foreground
      // window's data was on disk; it is gone by the time the app renders.
      try {
        if (await a.vault.mode() === 'memory') await naRWipeRef.current?.();
      } catch { /* mode unreadable → normal boot */ }
      if (session) {
        let id: KeyvaultIdentity | null = null;
        try {
          id = await a.vault.load();
        } catch (e) {
          if (isKeychainAuthDead(e)) {
            // The hardware-gated keychain entry was invalidated by the OS
            // (biometric re-enrollment etc.). The identity itself is safe —
            // it is fully recoverable from the 24-word phrase — so clear the
            // dead entry and continue as if no identity existed on this
            // device. The identity screen offers "Restore a Veil identity".
            await a.vault.clear().catch(() => undefined);
            // b104 CRASH-LOOP PREVENTION (owner device, Sept 21: "Biometry
            // is not available for this app"): when the OS reports biometry
            // is UNAVAILABLE/not enrolled (not merely re-enrolled), a
            // hardware-mode seal can NEVER be read on this device. If we
            // leave storageMode stuck on 'hardware', the phrase-restore the
            // crash screen routes to re-seals the identity right back into
            // the same unreadable state and the app dead-ends forever.
            // Revert key storage to device mode so the app stays usable;
            // the owner can flip back to hardware from Settings once
            // biometry works again (the b104 flip demands it explicitly).
            const msg = String((e as Error)?.message || e).toLowerCase();
            if ((msg.includes('biometry is not available') || msg.includes('biometry is not enrolled'))
                && bootSettings.storageMode === 'hardware') {
              const stDev = { ...bootSettings, storageMode: 'device' as const };
              settingsRef.current = stDev;
              setSettings(stDev);
              await a.settings.save(stDev).catch(() => undefined);
              console.warn('[veil] biometry unavailable for this app — key storage reverted to device mode to avoid an unreadable hardware seal');
            }
          } else {
            throw e; // anything else keeps the existing fatal-error path
          }
        }
        setIdentity(id);
        if (id) {
          const st = await a.settings.load();
          settingsRef.current = st; // sync NOW — the hardware-gate getter and the reconcile below need this before the next render
          // b96: phrase-derived notes key (the phrase restores everything)
          await ensureNotesKeyRef.current?.(id).catch(() => undefined);
          // b96 hardware reconcile: if the keyvault entry failed to seal
          // (crash mid-flip, module unavailable then), re-seal now so the
          // Face ID demand engages — a silently unsealed entry was the
          // owner's "none of the modes asks me for biometrics" finding.
          if (st.storageMode === 'hardware' && secureEnclaveAvailable()) {
            try {
              if (await keyvaultEntrySealed() === 'plain') {
                // b102: regenerate the SE key (legacy ungated-key devices)
                // before re-sealing — see secure-store.rn.ts resetSecureEnclaveKey
                await resetSecureEnclaveKey();
                await a.vault.save(id);
              }
            } catch { /* best-effort */ }
          }
          // b92 F-S3 (settings sweep): the 48h self-destruct clock was only
          // enforced on background→foreground transitions — a COLD START
          // (the exact seizure scenario the feature exists for) skipped the
          // check. Run the identical rule here, before anything renders.
          if (st.selfDestruct && st.selfDestructArmedAt && Date.now() - st.selfDestructArmedAt >= SELF_DESTRUCT_HOURS * 3600000) {
            for (const k of await a.storage.keys('veil_')) {
              if (k === 'veil_auth_session') continue;
              await secureRemove(a.storage, k).catch(() => undefined);
            }
            setAppLock(null); setIdentity(null); setSettings(DEFAULTS);
            knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setLocked(false); setScreen('identity');
          } else if (st.selfDestruct && st.selfDestructArmedAt
            && Date.now() - st.selfDestructArmedAt >= SELF_DESTRUCT_WARN_HOURS * 3600000) {
            // b92 F-S4 (settings sweep): the 12-hours-left warning only
            // existed inside the Settings screen — surface it in the app
            // itself, where the onboarding promise says it appears.
            const left = Math.max(0, SELF_DESTRUCT_HOURS - Math.floor((Date.now() - st.selfDestructArmedAt) / 3600000));
            Alert.alert(
              'Self-destruct countdown',
              `Your self-destruct clock has ${left} hour${left === 1 ? '' : 's'} left. Messaging never resets it. Extend it by another ${SELF_DESTRUCT_HOURS} hours from Settings → Privacy, or let it wipe this device's VEIL data when it reaches zero.`,
            );
          }
          setSettings(st);
          // handoff §1(4): fresh/returning users go straight into the app;
          // the checkup + app lock wait behind the dismissible "Secure your VEIL" prompt
          setScreen('main');
          // b139 funnel fix: the "Secure your VEIL" prompt waits until after
          // the user's first real session — never before.
          setSecurePrompt(!st.setupDone && st.firstSessionDone);
          // b139 attribution: re-arm the one-tap prompt if it was never
          // answered (answered/skipped both park it permanently)
          if (!st.attributionDone) setShowAttribution(true);
          // the app lock engages on every open
          if (lockRec) setLocked(true);
        } else setScreen('identity');
      } else {
        // b112: new users go straight to identity creation — the account is
        // derived silently from the phrase. Existing (email) accounts reach
        // the classic sign-in from the identity screen's account link.
        setScreen('identity');
      }
      // (b64) the shield itself is now applied by the React effect on
      // [settings.screenshotShield, bgState] near the top of the component —
      // driven by state, awaited, and logged to Metro instead of the old
      // fire-and-forget ref callback that failed silently on device.
      const sub = AppState.addEventListener('change', async (s) => {
        try {
          // b95 NaR v2 (owner hardware verify: locking the phone fired NOTHING
          // — iOS delivers 'inactive' for a screen lock, never 'background'):
          // ANY departure from the foreground wipes the full Veil surface —
          // chats, notes, vaults, stego, identity. RAM resets too, so on unlock
          // the user lands on the identity screen (24-word phrase restores it).
          if ((s === 'inactive' || s === 'background') && settingsRef.current.storageMode === 'memory') {
            await naRWipeRef.current?.().catch(() => undefined);
            setIdentity(null); setChat(null); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]);
            setDecoyMode(false); setScreen('identity');
          }
          if (s === 'background') {
            backgrounded.current = true;
            setBackgrounded(true); // (b64) drives the capture-shield effect (app-switcher redaction)
            autoLockBgAtRef.current = Date.now();
            // auto-lock §0: leaving the app (or locking the phone) engages the
            // passcode gate immediately — never wait out the inactivity timer.
            if ((identityRef.current || appLockRef.current) && !lockedRef.current) setLocked(true);
            // (b70) app-switcher snapshot blur — now via the REAL
            // enableAppSwitcherProtectionAsync API (the b64 comment claimed
            // this happened through preventScreenCapture; it does not).
            // Driven by the shield effects above via bgState.
          } else if (s === 'active' && backgrounded.current) {
            backgrounded.current = false;
            setBackgrounded(false); // (b64) shield effect re-applies (iOS drops it in background)
            // back in the foreground: the inactivity clock starts fresh (the
            // immediate lock on background already covered any absence)
            veilActivityPing();
            // b164: resume = instant session/contact refresh instead of
            // waiting up to 10s for the next poll tick (ceremony flags,
            // new threads, presence all feel immediate on return).
            refreshSessionsRef.current?.();
            refreshContactsRef.current?.();
            // self-destruct countdown: fixed 48h clock, messaging never resets it
            const st = settingsRef.current;
            if (st.selfDestruct && st.selfDestructArmedAt && Date.now() - st.selfDestructArmedAt >= SELF_DESTRUCT_HOURS * 3600000) {
              for (const k of await a.storage.keys('veil_')) {
                if (k === 'veil_auth_session') continue;
                await a.storage.remove(k).catch(() => undefined);
              }
              setAppLock(null); setIdentity(null); setSettings(DEFAULTS);
              knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setLocked(false); setScreen('identity');
            }
          }
        } catch { /* listener must never be a crash source */ }
      });
      } catch (e) {
        const err = e as Error;
        setBootError(String(err?.message || e) + '\n\n' + String(err?.stack || ''));
      }
     })();
  }, []);

  /** b112: credential-shaped login failure = "this phrase has no silent
   * account here" (pre-b112 identity) — resume via classic email sign-in.
   * Network/lockout failures are NOT this and surface as errors. */
  const isCredentialFailure = (msg: string): boolean =>
    /credential|password|email|invalid|no account|user not found|unauthor/i.test(msg);

  /** b112: the tail of phrase restore, shared by the silent path (session
   * present) and the resumed path (after classic email sign-in). */
  const completeRestore = useCallback(async (phrase: string) => {
    if (!app) return;
    await restoreFromPhrase({ relay: app.relay, vault: app.vault }, phrase);
    const rid = await app.vault.load();
    setIdentity(rid);
    if (rid) await ensureNotesKey(rid);
    setIdentityEntry('choose');
    const st = await app.settings.load();
    setSettings(st);
    setScreen('main');
    setSecurePrompt(!st.setupDone && st.firstSessionDone);
  }, [app]);

  /** b112: after ANY successful sign-in, resume an identity flow that paused
   * for the classic email login (silent accounts unavailable on the relay,
   * or a pre-b112 email account). Returns true when a flow was resumed. */
  const resumeIdentityFlow = useCallback(async (): Promise<boolean> => {
    if (!app) return false;
    if (pendingMaterial) {
      try {
        const id = await provisionIdentity({ relay: app.relay, vault: app.vault }, pendingMaterial);
        setIdentity(id); setPendingMaterial(null); setIdentityEntry('choose');
        await ensureNotesKey(id);
        setScreen('main');
        setSecurePrompt(false);
        try { await noteVeilIdCreated(app.relay, app.storage); } catch { /* never a blocker */ }
        try { if (!(await app.settings.load()).attributionDone) setShowAttribution(true); } catch { /* best-effort */ }
      } catch (e) { setError(friendlyError(e, 'identity')); }
      return true;
    }
    if (pendingRestorePhrase) {
      const ph = pendingRestorePhrase;
      setPendingRestorePhrase(null);
      try { await completeRestore(ph); } catch (e) { setError(friendlyError(e, 'identity')); }
      return true;
    }
    return false;
  }, [app, pendingMaterial, pendingRestorePhrase, completeRestore]);

  const handleSignup = useCallback(async (em: string, pw: string) => {
    if (!app) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      // b198 ANONYMOUS SIGNUP: one step — register returns the session directly.
      // The OTP screen is retired (the email is a self-declared label: real or
      // invented, never verified, never contacted; the 24-word phrase is the
      // only recovery path). Routing mirrors handleLogin's success path
      // (b104 setEmail + b112 identity-flow resume included).
      await app.auth.signup(em, pw);
      setEmail(em);
      if (await resumeIdentityFlow()) { setBusy(false); return; }
      const id = await app.vault.load();
      setIdentity(id);
      if (id) await ensureNotesKey(id);
      setScreen(id ? 'main' : 'identity');
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, resumeIdentityFlow]);

  const handleLogin = useCallback(async (em: string, pw: string) => {
    if (!app) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      await app.auth.login(em, pw);
      // b104 FIX: the success path never called setEmail — only the
      // OTP-required error path below did. Every login that didn't need an
      // OTP step left `email` state at '' for the rest of the session
      // (Settings showed "Signed in as —" the whole time despite a valid,
      // active login).
      setEmail(em);
      // b112: an identity flow (create or phrase restore) may be waiting on
      // this classic sign-in — resume it instead of the normal routing.
      if (await resumeIdentityFlow()) { setBusy(false); return; }
      const id = await app.vault.load();
      setIdentity(id);
      if (id) await ensureNotesKey(id);
      setScreen(id ? 'main' : 'identity');
    } catch (e) {
      const msg = String((e as Error).message || e);
      if (/otp|code|verif/i.test(msg)) { setEmail(em); setScreen('otp'); }
      else setError(friendlyError(e, 'login'));
    } finally { setBusy(false); }
  }, [app, resumeIdentityFlow]);

  const handleVerify = useCallback(async (code: string) => {
    if (!app) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      await app.auth.verifyOtp(email, code);
      try { await noteEmailVerified(app.relay, app.storage); } catch { /* never a blocker */ }
      // b112: resume a pending identity flow that fell back to email sign-up
      if (await resumeIdentityFlow()) { setBusy(false); return; }
      const id = await app.vault.load();
      setIdentity(id);
      if (id) await ensureNotesKey(id);
      setScreen(id ? 'main' : 'identity');
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, email, resumeIdentityFlow]);

  const handleResend = useCallback(async () => {
    if (!app) return;
    setBusy(true); setError(null);
    try {
      await app.auth.resendOtp(email);
      setInfo('New code sent.');
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, email]);

  const handleForgot = useCallback(async (em: string) => {
    if (!app) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      await app.auth.requestPasswordReset(em);
      setInfo('If that account exists, a reset link is on its way.');
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app]);

  /** web parity: passcode / Decoy / Duress classification (PBKDF2 on-device) */
  const handleCode = useCallback(async (code: string) => {
    if (!app) return;
    // b123: a running lockout window refuses ALL attempts — the countdown
    // survives app restarts (persisted), so killing the app can't skip it.
    const curLock = await app.appLock.lockout();
    setLockout(curLock);
    if (curLock.lockedUntil > Date.now()) {
      setCodeError('Too many incorrect attempts. Wait for the timer, then try again.');
      setCodeResetKey(Date.now());
      return;
    }
    const t0 = Date.now();
    console.log(`[veil-lock] unlock attempt (${code.length} digits)`);
    setCodeVerifying(true); setCodeError(null);
    try {
    const kind = await app.appLock.verify(code);
    console.log(`[veil-lock] verify complete: ${kind ?? 'WRONG'} in ${Date.now() - t0} ms`);
    if (kind === 'real') {
      await app.appLock.clearLockout(); setLockout(null); // b123: fresh 5-attempt budget on a good unlock
      setCodeError(null); setDecoyMode(false); setLocked(false); veilActivityPing();
    } else if (kind === 'decoy') {
      // Decoy: harmless empty environment — real data untouched, real code still unlocks
      await app.appLock.clearLockout(); setLockout(null); // b123: a correct code resets the budget — attacker-safe (they still only see decoy data)
      setCodeError(null); setDecoyMode(true); setLocked(false); setTab('sessions'); veilActivityPing();
    } else if (kind === 'duress') {
      // Duress: NOTHING survives. Server-side first (threads, vaults, notes),
      // then local veil_* storage, then app-saved Photos artifacts and the
      // encrypted-container file cache. Account login itself is the only
      // thing left standing afterwards.
      // (b64) 1. bulk gate purge — service-role delete of every session +
      // envelope this client participates in, incl. peer-created rows the
      // user-scoped entity API cannot touch under RLS.
      try {
        const sess = await app.auth.currentSession();
        if (sess) { await app.relay.sessionPurge(sess.user.id); }
      } catch { /* gate action not deployed yet — per-thread fallback below */ }
      // 2. per-thread end + record delete (still needed until the purge
      // action ships server-side, and as a belt-and-braces pass afterwards)
      try {
        const sess = await app.auth.currentSession();
        if (sess) {
          const r = await app.relay.sessionList(sess.user.id, undefined);
          const list = (r.data as { data?: unknown[] })?.data ?? (r.data as unknown as { sessions?: unknown[] })?.sessions ?? (r.data as unknown[]);
          for (const raw of Array.isArray(list) ? list : []) {
            const rec = raw as Record<string, unknown>;
            const tok = String(rec.token ?? '');
            const rid = String(rec.id ?? '');
            if (!tok) continue;
            let ws: string | null = null;
            try { ws = (await app.sessions.load(tok))?.writeSecret ?? null; } catch { /* no sealed record */ }
            try { await app.relay.sessionEnd(tok, ws, sess.user.id); } catch { /* peer-created or pending: end best-effort */ }
            if (rid) { try { await app.relay.entityDelete('VeilSession', rid); } catch { /* RLS: best-effort */ } }
          }
        }
      } catch { /* server-side wipe best-effort; local wipe below always runs */ }
      // (b64) 3. vaults + notes: OUR relay records (created_by = this
      // account) — delete via the entity API so nothing is left to list
      // after re-login. Loop until the list comes back empty; stop early if
      // nothing was deletable (RLS denial) to avoid spinning.
      try {
        for (const ent of ['VeilVault', 'VeilNote'] as const) {
          for (let guard = 0; guard < 50; guard++) {
            const raw: unknown = await app.relay.entityList(ent, { limit: 100, sort: '-created_date' });
            const rec = raw as { data?: unknown };
            const rows = (Array.isArray(rec?.data) ? rec.data : (Array.isArray(raw) ? raw : [])) as { id?: string }[];
            if (!rows.length) break;
            let removed = 0;
            for (const r of rows) {
              const id = String(r?.id ?? '');
              if (!id) continue;
              try { await app.relay.entityDelete(ent, id); removed++; } catch { /* RLS-denied */ }
            }
            if (removed === 0) break;
          }
        }
      } catch { /* server-side best-effort; local wipe below always runs */ }
      // (b64) 4. stego images this app saved to Photos — tracked in
      // veil_saved_media at save time; delete silently, no permission
      // prompts (a dialog under duress would tip off the attacker).
      try {
        const rawIds = await app.storage.get('veil_saved_media');
        const ids = rawIds ? (JSON.parse(rawIds) as string[]) : [];
        if (ids.length) {
          const perm = await MediaLibrary.getPermissionsAsync();
          if (perm.granted) { try { await MediaLibrary.deleteAssetsAsync(ids); } catch { /* best-effort */ } }
        }
      } catch { /* best-effort */ }
      // (b64) 5. encrypted vault-container file cache (ciphertext, but the
      // duress claim is that NOTHING survives) + stray temp files.
      try {
        const cacheDir = FileSystem.cacheDirectory;
        if (cacheDir) {
          for (const f of await FileSystem.readDirectoryAsync(cacheDir)) {
            if (f.startsWith('veil-vault-') || f.startsWith('veil-stego-') || f.startsWith('veil-upload-')) {
              await FileSystem.deleteAsync(cacheDir + f, { idempotent: true }).catch(() => undefined);
            }
          }
        }
      } catch { /* best-effort */ }
      for (const k of await app.storage.keys('veil_')) {
        if (k === 'veil_auth_session') continue; // account login survives; everything Veil-stored goes
        await secureRemove(app.storage, k).catch(() => undefined);
      }
      setAppLock(null); setIdentity(null); setSettings(DEFAULTS);
      knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setDecoyMode(false);
      setLocked(false); setScreen('identity');
    } else {
      // b123: count the miss — 5 wrong attempts arm the progressive lockout
      const st = await app.appLock.recordFail();
      setLockout(st);
      if (st.lockedUntil > Date.now()) {
        setCodeError(`Too many incorrect attempts — locked out. Try again later.`);
      } else {
        const left = MAX_ATTEMPTS - st.fails;
        setCodeError(left > 1 ? `Incorrect passcode. ${left} attempts remaining.` : left === 1 ? 'Incorrect passcode. 1 attempt remaining.' : 'Incorrect passcode.');
      }
      setCodeResetKey(Date.now());
    }
    } finally { setCodeVerifying(false); }
  }, [app]);

  const handleSetAppLock = useCallback(async (pass: string, decoy?: string | null, duress?: string | null) => {
    if (!app) return;
    const rec = await app.appLock.save(pass, decoy, duress); // throws web-copy errors on rule violations
    setAppLock(rec);
  }, [app]);

  const handleRemoveAppLock = useCallback(async (pass: string): Promise<boolean> => {
    if (!app) return false;
    if ((await app.appLock.verify(pass)) !== 'real') return false;
    await app.appLock.clear();
    setAppLock(null);
    return true;
  }, [app]);

  const handleCreateIdentity = useCallback(async () => {
    // local generation only — nothing touches the network until the phrase is confirmed written down
    const material = await createIdentity();
    setPendingMaterial(material);
    return { phrase: material.mnemonic, veilId: material.veilId };
  }, []);

  const handleFinishCreate = useCallback(async () => {
    if (!app || !pendingMaterial) return;
    // b171 (builder confirmation, Oct 2 2026): the platform cannot create
    // pre-verified accounts — every signup requires a human-read OTP email,
    // and the `veilSilentAccount` function the b112 design assumed never
    // existed server-side and cannot be built as designed. The classic
    // email+OTP flow IS the permanent fresh-install path (it was the silent
    // fallback before). Native therefore no longer fires a guaranteed-404
    // custom-function call on every fresh install; it goes straight to
    // sign-in, and the identity finishes automatically right after.
    if (!(await app.auth.currentSession())) {
      setInfo('One extra step: sign in with (or create) your VEIL account. Your new identity finishes automatically right after.');
      setScreen('login');
      return;
    }
    const id = await provisionIdentity({ relay: app.relay, vault: app.vault }, pendingMaterial);
    setIdentity(id); setPendingMaterial(null); setIdentityEntry('choose');
    await ensureNotesKey(id);
    // b171: funnel is pick a Veil ID, then (per b171 above) the permanent
    // email account step on a fresh install, then land in the app. The
    // privacy checkup + passcode wait
    // behind the dismissible "Secure your VEIL" prompt after the first
    // session; the intro slides stay reachable from Settings.
    setScreen('main');
    setSecurePrompt(false);
    try { await noteVeilIdCreated(app.relay, app.storage); } catch { /* never a blocker */ }
    try { if (!(await app.settings.load()).attributionDone) setShowAttribution(true); } catch { /* best-effort */ }
  }, [app, pendingMaterial]);

  /** Settings > Identity (web parity): local-only phrase check — the phrase never leaves the device */
  const handleVerifyPhrase = useCallback(async (phrase: string): Promise<boolean> => {
    if (!app || !identity) return false;
    try {
      // derive the veil_id from the phrase locally; a phrase from another identity throws
      await restoreIdentity(phrase, identity.veilId, false);
      return true;
    } catch {
      return false;
    }
  }, [app, identity]);

  /** Settings > Identity (web parity "Remove from this device"): drop this device's keyvault copy only.
   *  Sessions, pins and settings are untouched — the identity stays recoverable with its phrase. */
  const handleRemoveIdentity = useCallback(async () => {
    if (!app) return;
    await app.vault.clear();
    setIdentity(null);
  }, [app]);

  /** "Generate new Veil ID" (landing headline feature): the old identity's keyvault copy is
   *  removed first, then the create flow runs — fresh keys, fresh ID, nothing linking old to
   *  new. The 24-word reveal step is mandatory before anything is published. */
  const handleGenerateNewVeilId = useCallback(async () => {
    if (!app) return;
    await app.vault.clear();
    setIdentity(null);
    setIdentityEntry('confirm-create');
    setScreen('identity');
  }, [app]);

  /** Settings > Identity when no identity is on this device — open the create/restore flow */
  const handleOpenIdentityFlow = useCallback(() => {
    setIdentityEntry('choose');
    setScreen('identity');
  }, []);

  const handleRestore = useCallback(async (phrase: string) => {
    if (!app) return;
    // b112: the phrase now recovers the ACCOUNT too. No session on this
    // device → sign in with the phrase-derived credentials first.
    if (!(await app.auth.currentSession())) {
      try {
        await silentLogin({ auth: app.auth, relay: app.relay }, phrase);
      } catch (e) {
        if (isCredentialFailure(String((e as Error).message ?? e))) {
          // pre-b112 email account — classic sign-in, then the restore
          // resumes automatically (resumeIdentityFlow)
          setPendingRestorePhrase(phrase);
          setInfo('Sign in with your existing VEIL account — your identity restores right after.');
          setScreen('login');
          return;
        }
        setError(friendlyError(e, 'restore'));
        return;
      }
    }
    await completeRestore(phrase);
  }, [app, completeRestore]);

    useEffect(() => { lockedRef.current = locked; }, [locked]);

  /** handoff §2 Account: "Lock now" */
  const handleLockNow = useCallback(() => setLocked(true), []);

  /** b139 attribution: record the answer to AttributionSource (never on the
   *  identity record); a relay that can't take it yet parks it locally and
   *  retries on the next open. The prompt never gates anything. */
  const handleAttributionAnswer = useCallback(async (category: string, detail: string | null) => {
    setShowAttribution(false);
    if (!app) return;
    try {
      const st = { ...(await app.settings.load()), attributionDone: true };
      await app.settings.save(st);
      setSettings(st);
    } catch { /* flag is best-effort */ }
    if (identity) {
      try { await saveAttribution(app.relay, app.storage, { veilId: identity.veilId, category, detail }); } catch { /* parked */ }
    }
  }, [app, identity]);

  /** b139 attribution: dismissed without an answer — records nothing. */
  const handleAttributionSkip = useCallback(async () => {
    setShowAttribution(false);
    if (!app) return;
    try {
      const st = { ...(await app.settings.load()), attributionDone: true };
      await app.settings.save(st);
      setSettings(st);
    } catch { /* flag is best-effort */ }
  }, [app]);

  /** b62/b139: join an invite or group link (shared by Conversations and the
   *  welcome thread's Founding Tester Lounge action). */
  const threadTokenOf = (d: { group_token: string }) => loungeThreadToken(d.group_token);
  /** b187: join the Founding Tester Lounge via the hosted veil-lounge-1
   *  descriptor (founder-broadcast, read-only listener). Local-only — no
   *  relay session is created; the thread appears via listener records. */
  const handleJoinLounge = useCallback(async (raw: unknown) => {
    if (!app || !identity) return;
    const d = parseLoungeDescriptor(raw);
    const who = await clientId();
    if (!who) throw new Error('This device is not signed in yet — try again in a moment.');
    // b188: veil-forum-1 descriptors join as WRITING members (one hosted
    // code, one tap, no per-person invites); veil-lounge-1 stays read-only.
    // b188-r9 (owner banner repro): veil-forum-2 descriptors are ALSO
    // writing members, and their group token resolves from the relay peek
    // inside joinForum — openChat must use the JOIN's resolved token, not the
    // descriptor's (empty pre-join) group_token. This branch previously
    // misrouted forum-2 into the read-only lounge path — the exact bug
    // behind the owner's device showing "Founder broadcast · read only".
    let forumGroupToken = '';
    if (d.v === FORUM_DESC_VERSION || d.v === FORUM_DESC_VERSION_2) {
      const join = await joinForum(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
        { descriptor: d, clientId: who, identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64 } },
      );
      forumGroupToken = join.groupToken;
    } else {
      await joinLounge(
        { storage: app.storage },
        { descriptor: d, identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64 } },
      );
    }
    await refreshSessionsRef.current?.();
    const isForum = d.v === FORUM_DESC_VERSION || d.v === FORUM_DESC_VERSION_2;
    const gt = isForum ? forumGroupToken : d.group_token;
    await openChatRef.current?.(loungeThreadToken(gt), d.name ?? 'Lounge', isForum ? 'Founding testers forum' : 'Founder broadcast · read only', 'active', null, true, true, gt);
  }, [app, identity]);

  const handleJoinForumBanner = useCallback(async () => {
    if (!app || !identity || forumJoining) return;
    setForumJoining(true);
    try {
      const payload = await fetchLoungePayload();
      if (!payload?.lounge) throw new Error('unreachable');
      await handleJoinLounge(payload.lounge); // opens the thread on success
    } catch (e) {
      console.log('[veil-forum] banner join failed:', (e as Error)?.message ?? e);
      Alert.alert('Could not join the forum', 'Please try again in a moment.');
    } finally {
      setForumJoining(false);
    }
  }, [app, identity, forumJoining, handleJoinLounge]);

  const handleJoinInvite = useCallback(async (link: string) => {
    if (!app || !identity) throw new Error('Create your Veil identity first — Settings → Identity.');
    const who = await clientId();
    if (!who) throw new Error('Sign in first.');
    if (/[?&]g=/.test(link)) {
      const j = await joinGroup(
        { sessions: app.sessions, relay: app.relay, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
        {
          link, clientId: who,
          identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64, pqPrivB64: identity.pqPrivB64 },
        },
      );
      groupKnownTokensRef.current[j.token] = j.groupToken;
    } else {
      await joinInviteSession(
        { sessions: app.sessions, relay: app.relay, webBaseUrl: VEIL_BASE_URL },
        { link, clientId: who, displayName: settings.nickname || '' },
      );
    }
    await refreshSessions();
  }, [app, identity, settings.nickname]);

  /**
   * b184 deep links: invites arrive via the veil:// scheme or universal links
   * (applinks:tryveil.app). The web marketing page's invite handoff opens this
   * app with the original tryveil.app/?join=...#w=... link (or the token/key
   * in its own query); normalize whatever shape arrives back into the full
   * https link and feed it through the existing handleJoinInvite flow once the
   * user is signed in and unlocked. Survives lock: consumed when unlocked.
   */
  const pendingInviteRef = useRef<string | null>(null);
  const normalizeInviteUrl = useCallback((raw: string): string | null => {
    if (!raw) return null;
    const full = raw.match(/https:\/\/tryveil\.app\/\?[^\s"']*/);
    if (full) return full[0];
    const jm = raw.match(/[?&]join=([A-Za-z0-9]+)/);
    if (!jm) return null;
    const wm = raw.match(/#w=([A-Za-z0-9]+)/);
    return 'https://tryveil.app/?join=' + jm[1] + (wm ? '#w=' + wm[1] : '');
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const init = await Linking.getInitialURL();
        const n = init ? normalizeInviteUrl(init) : null;
        if (n) pendingInviteRef.current = n;
      } catch { /* best-effort */ }
      const sub = Linking.addEventListener('url', ({ url }) => {
        const n = normalizeInviteUrl(url);
        if (n) pendingInviteRef.current = n;
      });
      return () => sub.remove();
    })();
  }, [normalizeInviteUrl]);

  useEffect(() => {
    const link = pendingInviteRef.current;
    if (!link || !app || !identity || locked) return;
    pendingInviteRef.current = null;
    handleJoinInvite(link).catch((e: Error) =>
      Alert.alert('Invite', 'Could not open that invite link: ' + (e?.message || 'unknown error'))
    );
  }, [app, identity, locked]);

  /** b139 welcome thread: "Don't show again" */
  const handleHideWelcome = useCallback(async () => {
    if (!app) return;
    try {
      const st = { ...(await app.settings.load()), welcomeDismissed: true };
      await app.settings.save(st);
      setSettings(st);
    } catch { /* best-effort */ }
    setScreen('main');
  }, [app]);

  /** auto-lock §0: fixed 1-minute INACTIVITY rule, always on — checks every 5s
   *  while the app is foregrounded; any touch resets the clock via the root
   *  responder. Locking the phone / leaving the app is instant (AppState). */
  useEffect(() => {
    const iv = setInterval(() => {
      if (AppState.currentState !== 'active') return;
      if (lockedRef.current) return;
      if (!identityRef.current && !appLockRef.current) return;
      if (Date.now() - VEIL_LAST_ACTIVITY >= AUTO_LOCK_MINUTES * 60000) setLocked(true);
    }, 5000);
    return () => clearInterval(iv);
  }, []);

  /** handoff §2 Account: "Wipe VEIL data from this device" (two-tap armed in UI) —
   *  wipes identity keyvault, session keys, cached messages and local settings, then signs out */
  const handleWipeDevice = useCallback(async () => {
    if (!app) return;
    setBusy(true);
    try {
      for (const k of await app.storage.keys('veil_')) {
        if (k === 'veil_auth_session') continue;
        await app.storage.remove(k).catch(() => undefined);
      }
      await app.auth.logout().catch(() => undefined);
      for (const k of await app.storage.keys('veil_')) await app.storage.remove(k).catch(() => undefined); // login too now
    } finally {
      setIdentity(null); setAppLock(null); setSettings(DEFAULTS);
      knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setLocked(false); setBusy(false);
      setScreen('login');
    }
  }, [app]);

  /** handoff §2(14): Delete account — veilAccountDelete (web parity) then device wipe + sign out */
  const handleDeleteAccount = useCallback(async () => {
    if (!app) return;
    setBusy(true);
    try {
      await app.auth.deleteAccount(identity ? [identity.veilId] : []);
    } catch (e) {
      setBusy(false);
      setError(friendlyError(e, 'action'));
      return;
    }
    try {
      for (const k of await app.storage.keys('veil_')) await app.storage.remove(k).catch(() => undefined);
    } finally {
      setIdentity(null); setAppLock(null); setSettings(DEFAULTS);
      knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setBusy(false); setScreen('login');
    }
  }, [app, identity]);

  const handleSignOut = useCallback(async () => {
    if (!app) return;
    // b94 verify finding: sign-out is a FULL device wipe (the privacy claim),
    // but the button fired it on a single tap with no warning — the identity
    // goes with it and only the 24-word recovery phrase brings it back.
    const confirmed = await new Promise<boolean>((resolve) => {
      Alert.alert(
        'Sign out and wipe this device?',
        'Signing out removes your identity, conversation keys and all local VEIL data from this device — only your 24-word recovery phrase can restore the identity here. Make sure you have it before continuing.',
        [
          { text: 'Cancel', style: 'cancel', onPress: () => resolve(false) },
          { text: 'Sign out & wipe', style: 'destructive', onPress: () => resolve(true) },
        ],
        { cancelable: true, onDismiss: () => resolve(false) },
      );
    });
    if (!confirmed) return;
    setBusy(true);
    try {
      // AUDIT FIX (Sept 19, website claim "Device wipe at sign-out"):
      // signing out used to leave the identity keyvault, every session key
      // and cached message on this device (and iOS keychain survives app
      // uninstall). Sign-out now wipes everything VEIL stored — the login
      // session itself is the last thing to go, inside auth.logout().
      for (const k of await app.storage.keys('veil_')) {
        if (k === 'veil_auth_session') continue; // logout() clears this itself
        await secureRemove(app.storage, k).catch(() => undefined);
      }
      // (b64) sign-out wipe claim says NOTHING recoverable stays on the
      // device — that includes the encrypted vault-container file cache and
      // any stray temp files, which live outside the keychain sweep above.
      try {
        const cacheDir = FileSystem.cacheDirectory;
        if (cacheDir) {
          for (const f of await FileSystem.readDirectoryAsync(cacheDir)) {
            if (f.startsWith('veil-vault-') || f.startsWith('veil-stego-') || f.startsWith('veil-upload-')) {
              await FileSystem.deleteAsync(cacheDir + f, { idempotent: true }).catch(() => undefined);
            }
          }
        }
      } catch { /* cache sweep is best-effort */ }
    } catch { /* wipe is best-effort; logout still proceeds */ }
    try { await app.auth.logout(); } finally {
      setIdentity(null); setScreen('login'); setBusy(false);
    }
  }, [app]);


  const refreshSessions = useCallback(async (force = false) => {
    if (lockedRef.current && settingsRef.current.holdUntilUnlock) return; // hold delivery while locked
    if (!app) return;
    // b190: veilSessionGate(list) is gate traffic — skip while the relay's
    // shared rate-limit quiet window is hot (see relay.ts) instead of
    // burning the budget and re-locking the limiter every 10s.
    // b198 EXCEPTION: deletion-triggered refreshes (cover-send/sync/heartbeat
    // observers of a superseded session) pass force=true — the quiet window
    // must not starve the ONE request that terminates the dead-thread loop
    // (the loop itself burns budget every pass; the refresh is what ends it).
    // Same priority logic as burn-priority mode: ambient traffic yields to
    // the privacy-critical operation, never the reverse.
    if (!force && app.relay.gateHot()) return;
    const session = await app.auth.currentSession();
    if (!session) return;
    // b169 (owner hardware test Oct 2: fresh onboarding, no action taken,
    // "Cannot read property 'id' of undefined" leaked onto the CONTACTS tab
    // — and web->native messages never arrived at all). ROOT CAUSE: this
    // whole function used to run in ONE try/catch around the entire list;
    // a single throw (session.user missing, or one malformed row) aborted
    // EVERY row after it, forever, every 10s poll — so a freshly-onboarded
    // identity could never discover ANY pending session, including one a
    // peer just created from web. Guard the auth shape explicitly first so
    // a transient/incomplete session degrades loudly in Metro, never as a
    // crash, and never paints onto an unrelated tab (contactsError belongs
    // to refreshContacts, not here — see the catch block below).
    if (!session.user?.id) {
      console.error('[veil-sessions] refreshSessions: session.user.id missing — session object:', JSON.stringify(session).slice(0, 200));
      return;
    }
    try {
      // b65: threads the user ended but the relay would not delete (peer-created
      // rows RLS blocks) stay hidden instead of resurrecting on every poll.
      let dismissed: string[] = [];
      try {
        const raw = await app.storage.get('veil_dismissed_sessions');
        dismissed = raw ? (JSON.parse(raw) as string[]) : [];
      } catch { dismissed = []; }
      // b198 FRESHNESS GATE: record when the fetch STARTS, commit the stamp
      // only on success (below). A pass whose fetch began before the current
      // chat opened cannot have seen that chat's row — its result must never
      // satisfy the gone-detection effect's freshness requirement.
      const listFetchStartedAt = Date.now();
      const r = await app.relay.sessionList(session.user.id, identity?.veilId);
      const list = (r.data as { data?: unknown[] })?.data ?? (r.data as unknown as { sessions?: unknown[] })?.sessions ?? (r.data as unknown[]);
      const rows: SessionRow[] = [];
      for (const raw of Array.isArray(list) ? list : []) {
        // b169: per-row isolation — ONE malformed/null row (e.g. a sparse
        // array entry, or an unexpected relay payload shape) must not abort
        // every row after it. Each iteration is now self-contained; a bad
        // row is logged and skipped, the rest of the real list still loads.
        try {
        const rec = raw as Record<string, unknown>;
        if (!rec || typeof rec !== 'object') { console.error('[veil-sessions] skipping malformed session row:', JSON.stringify(raw).slice(0, 120)); continue; }
        const token = String(rec.token ?? '');
        if (!token) continue;
        // b74: keep the relay record's dials per token — openChat's burn
        // countdown needs them when the sealed state lacks the extras
        // (web-created threads joined via accept never had burn_after_open
        // in the pending record, so the flag never reached the sealed state).
        sessionDialsRef.current[token] = {
          burn: !!rec.burn_after_open,
          burnSecs: Number(rec.default_ttl_seconds) || 0,
        };
        sessionContactRef.current[token] = !!rec.contact_session;
        if (dismissed.includes(token)) continue; // b65: locally-ended ghost thread
        const groupToken = rec.group_token ? String(rec.group_token) : '';
        const groupEpoch = Number(rec.group_epoch ?? 0) || 0;
        const isGroup = !!groupToken && groupEpoch >= 1;
        // b198 ORPHAN GROUP ROWS (live-caught: the old test group banner-stormed
        // after its local record was gone): a group row without a LOCAL group
        // record must never render as a 1:1-style thread — the pairwise sync
        // fetches GROUP envelopes and decrypts them with a pairwise ratchet
        // (protocol-version mismatch → 12-failure desync banner). In-memory
        // view filter, deliberately NOT the b65 persisted list: re-joining the
        // group via a link restores the record and the row reappears.
        if (isGroup && !(await loadGroupRecord(app.storage, groupToken))) continue;
        const peerId = String(rec.responder_veil_id || rec.initiator_veil_id || '');
        const mine = rec.initiator_client_id === session.user.id;
        // b99 GHOST-SESSION FIX (owner hardware finding, Sept 21): the relay
        // lists sessions by ACCOUNT id — NaR (or any identity reset) wipes the
        // local identity keyvault and creates a NEW Veil ID but never logs the
        // account out, so rows whose OWN side was the previous (now-extinct)
        // identity keep reappearing forever as unopenable ghosts: the ratchet
        // keys for them died with the old identity, so they can never decrypt
        // anything again. If the row's own-side veil id is known and does NOT
        // match the CURRENT identity, the row belongs to an extinct identity
        // — filter it out here, in memory only. Deliberately NOT persisted to
        // the b65 dismissed list: if the user later phrase-restores the OLD
        // identity, its sessions must come back — this is a view filter, not
        // a deletion. Rows with an EMPTY own-side veil id (not-yet-joined
        // invite links, pre-accept one-taps) can't be classified and are kept.
        if (identity?.veilId) {
          const ownSideVeilId = String((mine ? rec.initiator_veil_id : rec.responder_veil_id) || '');
          if (ownSideVeilId && ownSideVeilId !== identity.veilId) continue;
        }
        // role-aware PEER id: the OTHER party, whichever side we are
        const peerVeilId = String((mine ? rec.responder_veil_id : rec.initiator_veil_id) || peerId || '');
        // b123 FIX (owner live-test screenshot, Sept 24): the TITLE lookup
        // used responder-OR-initiator WITHOUT checking which side we are —
        // so a session the user JOINED (responder side, e.g. the Founder
        // Tester Lounge invite) titled itself with the user's OWN veil-id,
        // because responder_veil_id is US on those rows. The title's peer
        // is always the OTHER party, exactly like peerVeilId: nickname
        // lookup and the raw-ID fallback both use the role-aware id.
        const nick = peerVeilId ? await app.pins.getNickname(peerVeilId) : null;
        // b68: the PEER's own self-chosen nickname (they set it on their side).
        // A name I gave them locally always wins; theirs is the fallback
        // before the raw Veil ID.
        const theirNick = String(
          (mine ? rec.responder_display_name : rec.initiator_display_name) || '',
        ).trim();
        // web parity: verify ceremony is PER-SIDE — badge goes green only when BOTH sides did it
        const myVerified = mine ? !!rec.initiator_verified : !!rec.responder_verified;
        const peerVerified = mine ? !!rec.responder_verified : !!rec.initiator_verified;
        // b162 presence display (web parity): the PEER's last heartbeat on the
        // gate, parsed tz-safe (relay bare-ISO trap, b134). 0 = never seen.
        const peerSeenRaw = String((mine ? rec.responder_seen_at : rec.initiator_seen_at) || '');
        const peerSeenAt = peerSeenRaw ? (Date.parse(relayTimestampToIso(peerSeenRaw)) || 0) : 0;
        let gTitle = nick || theirNick || peerVeilId || 'Anonymous session';
        let gSub = `#${token.slice(0, 4).toUpperCase()} · ${rec.contact_session ? 'pinned contact' : 'invite session'}`;
        if (isGroup) {
          try {
            gTitle = (await groupRowLabel(
              { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
              groupToken, String(rec.group_name ?? ''),
            )) || 'VEIL group';
          } catch { gTitle = 'VEIL group'; }
          gSub = `VEIL group · epoch ${groupEpoch}`;
        }
        // b71 (owner report "groups show up twice"): one group = MANY rows here —
        // the creator's MAIN session + one invite row per link, all sharing the
        // same group_token, ALL participant-scoped into this list. collapseGroupRows()
        // (src/session-list.ts) keeps exactly ONE per group, preferring the MAIN
        // session, then any joined row, then anything this device has state for.
        rows.push({
          token,
          contact: !!rec.contact_session,
          mine,
          recId: String(rec.id ?? ''),
          title: gTitle,
          subtitle: gSub,
          status: rec.state === 'active' ? 'active' : rec.state === 'ended' ? 'ended' : 'pending',
          verified: peerVerified,
          unread: 0,
          peerVeilId,
          myVerified,
          peerVerified,
          ...(isGroup ? { groupToken, mainGroupRow: mine && !peerVeilId } : {}),
          ...(!isGroup && rec.state === 'active' ? { peerSeenAt } : {}),
        });
        } catch (rowErr) {
          // b169: this row is unreadable — skip it, keep the rest of the list.
          console.error(`[veil-sessions] skipping session row ${String((raw as Record<string, unknown>)?.token ?? '?')}: ${String((rowErr as Error).message || rowErr)}`);
        }
      }
      // b89: a burn window that elapses while its thread is CLOSED must not
      // leave plaintext sitting in that session's msgcache either — sweep
      // every active burn session's cache on each list refresh (cheap: a
      // no-op purge is one storage read). Open threads purge themselves on
      // their own 1s tick above.
      for (const r of rows) {
        const d = sessionDialsRef.current[r.token];
        if (r.status === 'active' && d?.burn && d.burnSecs > 0) {
          app.sessions.purgeBurnedMessages(r.token, d.burnSecs).then(async (purged) => {
            // b90: burned rows can no longer be "waiting to read" — decay the
            // badge by the same count so it never points at an empty thread.
            if (purged.length > 0) {
              const cur = await app.sessions.getUnread(r.token);
              if (cur > 0) await app.sessions.bumpUnread(r.token, -Math.min(cur, purged.length));
            }
          }).catch(() => undefined);
        }
        // b90: badge = persisted per-session unread counter
        r.unread = await app.sessions.getUnread(r.token);
      }
      // b196-r4 (owner repro Oct 12, definitive: "Getting Started → Join the
      // lounge brings back the VEIL group every time" — the thread list
      // showed TWO rows for the ONE forum: the synthesized lounge row
      // ('Founding Tester Forum') AND this account's own posting-session
      // relay row, whose groupRowLabel fallback titles it 'VEIL group'. The
      // b187 synthesis dedup compared TOKENS (lounge_<gt> vs the posting
      // session token — different strings, so the duplicate always slipped
      // through), and collapseGroupRows can't help: the synthesized row is
      // appended after collapse. A lounge/forum group renders exactly ONE
      // row — the synthesized lounge row; the member's posting session is
      // relay plumbing and must never paint a second thread row. Classic
      // groups (creator/member roles) keep the full relay-row flow.
      const loungeGts = new Set<string>();
      try {
        await loadGroupRecords(app.storage);
        for (const gt of listGroupTokens(app.storage)) {
          const rec = groupRecord(app.storage, gt);
          if (rec && !rec.sessionEnded && (rec.role === 'listener' || rec.role === 'forum-member')) loungeGts.add(gt);
        }
      } catch { /* registry read is best-effort; classic groups unaffected */ }
      const collapsed = await collapseGroupRows(
        rows.filter((r) => !(r.groupToken && loungeGts.has(r.groupToken))),
        async (t) => !!(await app.sessions.load(t)),
        (gt) => groupWinnerRef.current[gt],
      );
      // b134: remember this round's winner per group so the next refresh
      // (e.g. right after reopening the thread) can't silently pick a
      // different token and read a different — likely empty — msgcache.
      for (const r of collapsed) if (r.groupToken) groupWinnerRef.current[r.groupToken] = r.token;
      // b187: lounge broadcast threads — listener records are LOCAL-only (no
      // relay session exists by design), so they can never appear in the
      // VeilSession rows; synthesize them from the group records. Additive and
      // deduped: a storage hiccup must never take the whole list down.
      try {
        await loadGroupRecords(app.storage);
        // b196-r5: banner visibility — a live forum-member record retires the
        // banner permanently; anything else keeps it eligible.
        let joinedNow = false;
        for (const gt of listGroupTokens(app.storage)) {
          const rec = groupRecord(app.storage, gt);
          if (rec && !rec.sessionEnded && rec.role === 'forum-member') { joinedNow = true; break; }
        }
        setForumJoined(joinedNow);
        const loungeRows = listGroupTokens(app.storage)
          .map((gt) => groupRecord(app.storage, gt))
          // b196-r3 (owner repro Oct 12: "the forum group keeps coming back
          // upon loading new builds"): the b190 fail-close path deliberately
          // KEEPS the record of a forum whose server side is gone (local
          // history for a future restore) with sessionEnded: true — but this
          // synthesis ignored that flag, so every boot repainted a live-looking
          // thread row for a dead group. Dead records keep their history in
          // storage; they must not resurrect as rows.
          .filter((r): r is NonNullable<typeof r> => !!r && !r.sessionEnded && (r.role === 'listener' || r.role === 'forum-member'))
          .map((r) => ({
            token: loungeThreadToken(r.groupToken),
            title: r.name || 'Lounge',
            subtitle: r.role === 'forum-member' ? 'Founding testers forum' : 'Founder broadcast · read only',
            status: 'active' as const,
            verified: true,
            unread: 0,
            lounge: true,
            groupToken: r.groupToken,
          }));
        const have = new Set(collapsed.map((r) => r.token));
        // b196-r4: also skip when a collapsed row already carries this
        // GROUP token — token-string equality can never catch a relay row
        // (different token space), which is how the forum painted twice.
        const haveGt = new Set(collapsed.filter((r) => r.groupToken).map((r) => r.groupToken as string));
        for (const lr of loungeRows) {
          if (!have.has(lr.token) && !haveGt.has(lr.groupToken)) {
            collapsed.push(lr);
            have.add(lr.token);
            haveGt.add(lr.groupToken);
          }
        }
      } catch (e) { console.log('[veil-lounge] row synthesis skipped:', (e as Error).message); }
      setSessionRows(collapsed);
      listRefreshedAtRef.current = listFetchStartedAt; // b198 freshness gate: a successful, post-open fetch
      // b178 (owner report Oct 2: "you don't get push notifications for new
      // chat invites — new contact or pinned contact"). refreshSessions
      // DISCOVERS new invite rows on its 10s poll but never told the user:
      // a pending session just silently appeared in the list. Detection:
      // the FIRST pass after login seeds the known-token set silently (a
      // wipe+restore would otherwise banner-spam every existing thread);
      // every later pass banners rows that (a) newly appeared, (b) this
      // account did NOT initiate (mine), and (c) are not group rows the
      // user just joined via link (those open a thread immediately). The
      // banner body is generic — no sender, no session identity — per the
      // contentless threat model. NOTE the server side: the APNs wake-ping
      // only fires on VeilEnvelope inserts and a fresh invite carries NO
      // envelope, so a fully-backgrounded phone still needs the server
      // trigger (builder work order) — this banner covers the
      // foreground/app-open window.
      try {
        const tokens = collapsed.map((r) => r.token);
        const seenBefore = knownSessionTokensRef.current;
        if (seenBefore === null) {
          knownSessionTokensRef.current = new Set(tokens); // seed silently
        } else {
          const freshInvites = collapsed.filter((r) =>
            !seenBefore.has(r.token) && !r.mine && !r.groupToken && r.status !== 'ended');
          if (freshInvites.length) {
            for (const r of collapsed) seenBefore.add(r.token);
            console.log(`[veil-notify] ${freshInvites.length} new invite session(s) appeared — banner`);
            notifyNewInvite();
          } else {
            for (const r of collapsed) seenBefore.add(r.token);
          }
        }
      } catch { /* banner best-effort */ }
      // b164 (owner hardware test Oct 2: "after the ceremonies it doesn't
      // load — you have to click out and back in for it to become fully
      // verified"): only openChat ever read the per-side ceremony flags,
      // so the open thread's badge went stale the moment either side
      // confirmed. Patch the OPEN chat's flags from the fresh rows so the
      // badge auto-loads within one 10s list refresh — no reopen needed.
      const openTok = chatOpenRef.current;
      if (openTok) {
        const r = collapsed.find((x) => x.token === openTok);
        if (r && (r.myVerified || r.peerVerified)) {
          setChat((c) => (c && c.token === openTok && (c.myVerified !== !!r.myVerified || c.peerVerified !== !!r.peerVerified)
            ? { ...c, myVerified: !!r.myVerified, peerVerified: !!r.peerVerified } : c));
        }
      }
    } catch (e) {
      // b169: this used to call setContactsError — refreshSessions is a
      // background 10s poll with no relation to the Contacts tab, so a
      // transient relay hiccup here painted a raw, permanent red error
      // onto an unrelated screen (owner hardware report, Oct 2). Every
      // other background poller in this file (backgroundSyncAllSessions,
      // syncGroupToken) fails silently to Metro only — match that
      // convention. A real outage still shows up: no sessions load, which
      // is visible in the UI on its own merits, without a scary raw string.
      console.error('[veil-sessions] refreshSessions failed:', String((e as Error).message || e));
    }
  }, [app, identity]);

  // b164: keep the AppState-resume mirrors pointed at the current closures.
  useEffect(() => {
    refreshSessionsRef.current = refreshSessions;
  }, [refreshSessions]);

  const refreshContacts = useCallback(async () => {
    if (!app) return;
    try {
      const pinned = await app.pins.listPins();
      const rows: ContactRow[] = [];
      for (const p of pinned) {
        const nick = await app.pins.getNickname(p.veilId);
        rows.push({ veilId: p.veilId, nickname: nick, verified: p.verified, fingerprint: await identityFingerprint(p.ikPubB64) });
      }
      setContactRows(rows);
      setContactsError(null);
    } catch (e) {
      setContactsError(String((e as Error).message || e));
    }
  }, [app]);

  // b164: contacts mirror for the resume handler.
  useEffect(() => {
    refreshContactsRef.current = refreshContacts;
  }, [refreshContacts]);

  // main screen entered: load both lists once, then keep them LIVE — b72 fix
  // (owner report: a nickname set in Settings took ~10s and a screen-hop to
  // appear). The list previously refreshed ONLY on entry; now it re-polls
  // every 10s while the main screen is visible and the app is foregrounded,
  // so title/subtitle/status changes propagate without navigation.
  // b73 (owner report: nickname only updates if you leave the chat and come
  // back): the poll was gated to screen==='main' only, so sessionRows never
  // refreshed while a chat was open — the open thread's title had nothing
  // fresh to read even on re-render. Now also polls while screen==='chat',
  // and a second effect below patches the open chat's title/subtitle live.
  useEffect(() => {
    if (screen !== 'main' && screen !== 'chat') return;
    refreshSessions(); refreshContacts();
    // b77 FIX: this poll used to only refresh list METADATA (title/subtitle/
    // status) — it never decrypted message content, so sitting on the
    // Conversations list (foreground, no thread open) produced zero
    // notifications no matter how many messages arrived elsewhere.
    // backgroundSyncAllSessions actually decrypts+caches+notifies for every
    // non-open session on the same cadence.
    backgroundSyncAllSessionsRef.current();
    const iv = setInterval(() => {
      if (AppState.currentState !== 'active') return; // backgrounded: skip
      refreshSessions(); refreshContacts();
      backgroundSyncAllSessionsRef.current();
    }, 10000);
    return () => clearInterval(iv);
  }, [screen, refreshSessions, refreshContacts]);

  // b155 PRESENCE HEARTBEAT: web peers show us "online" from the gate's
  // seen_at fields — sessionHeartbeat has existed on the relay client since
  // b77 but NOTHING ever called it, so native users appeared permanently
  // offline to web (owner finding Oct 1: initiator_seen_at empty on a
  // native-initiated thread while web's responder heartbeat was current).
  // Every active pairwise session beats every 30s while the app is in the
  // foreground; backgrounded ticks are skipped exactly like the poll above.
  useEffect(() => { hbRowsRef.current = sessionRows; }, [sessionRows]);
  useEffect(() => {
    if (!app || !identity) return;
    const beat = async () => {
      try {
      if (AppState.currentState !== 'active') return; // backgrounded: skip
      // b175: the relay's anti-abuse limiter throttles heartbeats too (owner
      // Metro repro Oct 2: "sessionHeartbeat ... 500 Rate limit exceeded"
      // looping every 7s through the whole window). Once ANY beat comes back
      // rate-limited, pause ALL beats for 30s — a shared gate because the
      // limiter is server-side per account, not per token. A single
      // successful beat clears it: the limiter has recovered.
      if (Date.now() < hbLimiterHotUntilRef.current) { console.log('[veil-hb] beat skipped — local limiter pause active'); return; }
      // b190: also respect the relay's shared rate-limit quiet window — a
      // locked limiter lasts minutes; the old 30s beat pause kept poking it.
      if (app.relay.gateHot()) { console.log('[veil-hb] beat skipped — relay gateHot quiet window'); return; }
      let beatOk = false;
      let beatTargets = 0;
      // b198 DIAGNOSTIC: the beat loop went SILENT during the Oct 15 live
      // retest (no fail-close, no skip lines, no refresh trigger) while the
      // receiver sat inside a superseded thread. These one-line traces make
      // every silent branch observable; they are cheap (once per 7s pass).
      console.log(`[veil-hb] beat pass: ${hbRowsRef.current.length} row(s), appState=${AppState.currentState}, gateHot=${app.relay.gateHot()}`);
      for (const r of hbRowsRef.current) {
        if (r.status !== 'active' || r.groupToken) continue;
        if (hbDeadRef.current.has(r.token)) continue; // b196-r8: proven dead — stop beating
        try {
          beatTargets++;
          const sealed = (await app.sessions.load(r.token)) as { writeSecret?: string | null } | null;
          await app.relay.sessionHeartbeat(r.token, sealed?.writeSecret ?? null);
          beatOk = true;
        } catch (e) {
          const m = (e as Error)?.message ?? String(e);
          if (/rate limit exceeded/i.test(m)) {
            hbLimiterHotUntilRef.current = Date.now() + HB_LIMITER_COOLDOWN_MS;
            console.log('[veil-hb] relay rate-limited heartbeat — pausing presence beats 30s');
            break;
          }
          // b196-r8: 'Invalid session credential' means the relay row and the
          // local credential no longer match (row ended/swept, or the sealed
          // state never survived the reinstall). Retrying every 7s cannot fix
          // that — fail-close the row and let join/send re-mint where they can.
          if (/invalid session credential/i.test(m)) {
            hbDeadRef.current.add(r.token);
            console.log('[veil-hb] dead session fail-close — stopping presence beats for #' + r.token.slice(0, 4));
            continue;
          }
          // b197-r6 (lag fix): "Session not found" is the same story — the row
          // is gone (superseded/ended/swept) and beating it every 7s forever
          // just burns rate budget (owner hardware log Oct 14: continuous
          // heartbeat 404 spam on a superseded token while the limiter was
          // already hot). Fail-close exactly like the credential case.
          if (/session not found/i.test(m)) {
            hbDeadRef.current.add(r.token);
            console.log('[veil-hb] dead session fail-close (not found) — stopping presence beats for #' + r.token.slice(0, 4));
            // b198 (live retest Oct 15, confirms the handoff's receiver-side
            // live find): the receiver standing INSIDE the deleted thread
            // never sees the b164 auto-switch, because the switch only fires
            // on a LIST REFRESH and nothing refreshes the list while a chat
            // is open. KEY discovery: the envelope sync does NOT error on a
            // deleted session — it cleanly fetches 0 envelopes — so the
            // sync-catch trigger can never fire. The heartbeat is the
            // component that actually OBSERVES the deletion — make it summon
            // the list refresh. Self-terminating: once the refresh lands, the
            // dead row leaves sessionRows, the beat loop stops visiting it,
            // and no further triggers fire.
            refreshSessionsRef.current?.(true);
            continue;
          }
          /* presence must never break the app */ }
      }
      if (beatTargets === 0) console.log('[veil-hb] beat pass: no beatable rows (all dead/ended/groups)');
      if (beatOk) hbLimiterHotUntilRef.current = 0; // limiter recovered
      } catch (e) {
        console.error('[veil-hb] beat loop CRASHED (was silently killing the interval?):', (e as Error)?.message ?? String(e));
      }
    };
    void beat();
    // b161 (parity handoff §3.5): web's shared staleness rule marks a peer
    // offline at 15 s, so a 30 s beat reads offline roughly half the time.
    // Match web exactly: heartbeat 7 s, stale 15 s (raise both together only).
    const iv = setInterval(beat, 7000);
    return () => clearInterval(iv);
  }, [app, identity]);

  // b73: once sessionRows refreshes (every 10s above), patch the OPEN chat's
  // title/subtitle from the matching row so a nickname change is visible
  // live, without leaving the chat screen. Group titles/verify flags already
  // update via their own effects — this only touches title/subtitle to avoid
  // clobbering in-flight state (myVerified/peerVerified etc.) set elsewhere.
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    const row = sessionRows.find((r) => r.token === chat.token);
    if (!row) return;
    // b162 presence (web parity, honest + approximate): show 'peer online'
    // only while the peer's last beat is fresh (< 15 s, web's shared
    // staleness rule). Silence otherwise — no 'offline' nagging.
    const sub = (row.peerSeenAt && Date.now() - row.peerSeenAt < 15000)
      ? `${row.subtitle} · peer online`
      : row.subtitle;
    if (row.title === chat.title && sub === chat.subtitle) return;
    setChat((c) => c && c.token === chat.token ? { ...c, title: row.title, subtitle: sub } : c);
  }, [screen, chat, sessionRows]);

  // b88: DEAD-THREAD DETECTION while a chat is open. The 10s session-list
  // poll above already refreshes sessionRows while a chat is open — but
  // when the open thread's session row disappears server-side (peer ended
  // it, duress purge, relay cleanup, or the peer starting a NEW thread),
  // the list simply stopped containing the token and NOTHING acted on it:
  // the open chat kept polling envelopes (envelope rows outlive the
  // session) and looked perfectly "live". b80's gone-detection only fired
  // on a burn 404, which needs a NEW envelope to decrypt — a dead-but-
  // quiet thread never tripped it. Owner repro (Sept 21 ~02:55 Bris): web
  // tapped "+" to start a new chat; the phone sat in the old, deleted
  // thread "live" until manually exiting, only then seeing the new thread.
  // Now: when two CONSECUTIVE successful list refreshes (>=10s apart, and
  // only when the list is non-empty — never trust a pre-refresh/empty
  // state) do not contain the open token, the thread is closed with the
  // same b80-style local residue cleanup, landing on the conversations
  // list — which is already fresh, so what came next (the new thread) is
  // sitting right there. Group threads are excluded: their rows collapse
  // per group (b71) and their lifecycle is owned by the group flow.
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    if (chat.groupToken) return; // group lifecycle: separate flow
    // b198: the old `sessionRows.length === 0 → return` guard is GONE — the
    // freshness gate below SUBSUMES it. The empty guard's purpose was to not
    // trust a pre-refresh empty list, but a list FETCHED AFTER the chat opened
    // is authoritative even when EMPTY — and an empty fresh list is exactly
    // what the ✕-end of the user's LAST thread produces (live-verified Oct 15:
    // Two sat in the deleted thread forever because the empty guard refused
    // to act on the legitimately-empty refresh). No signal before a post-open
    // fetch; full authority after one — including the empty verdict.
    // b198 FRESHNESS GATE: sessionRows must have been fetched AFTER this chat
    // opened. A list fetched before the thread existed (the normal state for
    // the first seconds of a '+' thread, and for any in-flight poll that
    // completes after openChat) proves nothing about this token's existence —
    // acting on it is how the auto-switch deleted the brand-new thread's
    // keys. Wait for the next refresh instead of counting a bogus miss.
    if (listRefreshedAtRef.current < chatOpenedAtRef.current) return;
    const stillListed = sessionRows.some((r) => r.token === chat.token);
    if (stillListed) { goneMissRef.current[chat.token] = 0; return; }
    if (supersedeInFlightRef.current.has(chat.token)) return; // b164: switch already running for this token
    // b164 (owner hardware test Oct 2: web's '+' supersession is seamless —
    // native kept sitting in the dead thread until the user pressed back).
    // When a SAME-PEER replacement thread is already in the fresh list, the
    // loss is corroborated: switch straight INTO the replacement after a
    // single miss instead of dropping to the list. Web parity — the new
    // thread just appears under your thumb, nothing to press.
    const replacement = sessionRows.find((r) =>
      r.token !== chat.token && !r.groupToken && !!r.peerVeilId && r.peerVeilId === chat.peerVeilId && r.status !== 'ended');
    const misses = (goneMissRef.current[chat.token] ?? 0) + 1;
    goneMissRef.current[chat.token] = misses;
    if (replacement) {
      console.log(`[veil] session #${chat.token.slice(0, 4)} superseded — auto-switching to new thread #${replacement.token.slice(0, 4)} with the same peer`);
      goneMissRef.current[chat.token] = 0;
      const deadToken = chat.token;
      supersedeInFlightRef.current.add(deadToken);
      (async () => {
        try {
          try { await app?.sessions.remove(deadToken); } catch { /* residue already gone */ }
          setError(null);
          await openChatRef.current?.(replacement.token, replacement.title, replacement.subtitle, replacement.status, replacement.peerVeilId ?? null, !!replacement.myVerified, !!replacement.peerVerified, undefined);
        } finally {
          supersedeInFlightRef.current.delete(deadToken);
        }
      })();
      return;
    }
    if (misses < 2) return; // two consecutive misses = genuinely gone
    console.log(`[veil] session #${chat.token.slice(0, 4)} no longer exists server-side (absent from ${misses} consecutive list refreshes) — closing thread, clearing local state`);
    goneMissRef.current[chat.token] = 0;
    (async () => {
      try { await app?.sessions.remove(chat.token); } catch { /* residue already gone */ }
      setChat(null);
      setScreen('main');
      refreshSessions();
    })();
  }, [screen, chat, sessionRows, app, refreshSessions]);

  // b89 (owner burn test Sept 21 ~03:32 Bris: "5 minute burn test and it hit
  // 0 but still on both"): the per-bubble burn countdown (b72) was DISPLAY-
  // ONLY — when a message's window elapsed, the "0m 00s" label sat there
  // while the plaintext stayed on screen and in the msgcache indefinitely,
  // on a product whose core promise is that burned content is gone. This
  // effect makes burn-after-open actually BURN: while a burn thread is
  // open, every second (matching the countdown tick, so messages vanish at
  // the exact moment their label hits 0) expired rows are dropped from the
  // visible thread AND deleted from the local cache via the same rule as
  // SessionStore.purgeBurnedMessages (openedAt + burnSeconds elapsed;
  // system notes and never-displayed rows are kept). The purge is a no-op
  // (no state churn, no storage write) while nothing has expired.
  useEffect(() => {
    if (screen !== 'chat' || !chat?.burnAfterOpen || !chat.burnSeconds) return;
    const token = chat.token;
    const secs = chat.burnSeconds;
    const iv = setInterval(() => {
      const now = Date.now();
      setChatMessages((prev) => {
        const keep = prev.filter((m) => m.systemNote || !m.openedAt || m.openedAt + secs * 1000 > now);
        if (keep.length === prev.length) return prev;
        console.log(`[veil] burn window elapsed for #${token.slice(0, 4)} — removing ${prev.length - keep.length} burned message(s) from view and cache`);
        app?.sessions.purgeBurnedMessages(token, secs).catch(() => undefined);
        return keep;
      });
    }, 1000);
    return () => clearInterval(iv);
  }, [screen, chat, app]);

  const decoyBlocked = () => setContactsError('Could not reach the relay. Try again later.');

  const handleLookup = useCallback(async (veilId: string): Promise<LookupResult | null> => {
    if (decoyMode) { decoyBlocked(); return null; }
    if (!app) return null;
    const r = await app.relay.identityLookup(veilId);
    const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
    if (!rec?.IK_pub) return null;
    return { veilId, fingerprint: await identityFingerprint(rec.IK_pub), ikPubB64: rec.IK_pub };
  }, [app]);

  const handlePin = useCallback(async (lookup: LookupResult) => {
    if (decoyMode) { decoyBlocked(); return; }
    if (!app) return;
    await app.pins.pin(lookup.veilId, lookup.ikPubB64);
    await refreshContacts();
  }, [app, refreshContacts]);

  const handleUnpin = useCallback(async (veilId: string) => {
    if (decoyMode) { decoyBlocked(); return; }
    if (!app) return;
    await app.pins.unpin(veilId);
    await refreshContacts();
  }, [app, refreshContacts]);

  const handleVerifyPin = useCallback(async (veilId: string) => {
    if (decoyMode) { decoyBlocked(); return; }
    if (!app) return;
    await app.pins.markVerified(veilId);
    await refreshContacts();
  }, [app, refreshContacts]);

  const handleNickname = useCallback(async (veilId: string, nickname: string) => {
    if (decoyMode) { decoyBlocked(); return; }
    if (!app) return;
    await app.pins.setNickname(veilId, nickname || '');
    await refreshContacts();
  }, [app, refreshContacts]);

  /** b123: rename the OPEN thread locally — a device-only nickname stored
   *  against the peer's veil-id, feeding the role-aware chat-list title fix
   *  (lounge/mate rows stop rendering raw IDs once named). Never transmitted,
   *  never synced, same store the Contacts nicknames use. */
  const handleRenameThread = useCallback(async (name: string) => {
    if (decoyMode) { decoyBlocked(); return; }
    if (!app) return;
    const cur = chatRef.current;
    if (!cur?.token || !cur.peerVeilId) return;
    await app.pins.setNickname(cur.peerVeilId, name || '');
    setChatLocalNick(name || null);
    // optimistic patch: the 10s list poll re-syncs the title from the rows
    setSessionRows((prev) => prev.map((r) => (r.token === cur.token ? { ...r, title: name || r.title } : r)));
    setChat((c) => (c && c.token === cur.token && name ? { ...c, title: name } : c));
    refreshSessions().catch(() => undefined);
  }, [app, decoyMode, decoyBlocked, refreshSessions]);

  // b164: openChat is declared below (App.tsx order); callbacks/effects that
  // fire before that point in the file read it through this mirror instead.
  const openChatRef = useRef<((token: string, title: string, subtitle: string, status: 'pending' | 'active' | 'ended', peerVeilId: string | null, myVerified?: boolean, peerVerified?: boolean, groupToken?: string) => Promise<void>) | null>(null);

  const handleMessage = useCallback(async (veilId: string) => {
    // b167 (owner hardware test Oct 2: "native's + button doesn't do
    // anything"): every failure below used to set ONLY contactsError —
    // which renders on the Contacts TAB, not in the open chat where the
    // "＋ New" button lives. A failed new-thread start (prekey trust
    // mismatch, missing prekeys, rate limit, pin lookup) was therefore
    // INVISIBLE in-chat: the button appeared to do nothing at all. All
    // failure paths now also set the global error, which ChatScreen
    // renders directly, so the reason shows exactly where the tap
    // happened, and log loudly for Metro.
    if (decoyMode) {
      console.error('[veil-new-thread] blocked: decoy mode is engaged');
      decoyBlocked();
      setError('Decoy mode is on — new threads are disabled.');
      return;
    }
    if (!app || !identity) {
      setContactsError('Create or restore your identity first.');
      setError('Create or restore your identity first.');
      return;
    }
    // b167: the identity gate's rate-limit lock (HTTP 429, retry_minutes)
    // blocks new-thread creation for its whole window — and each extra tap
    // while locked can re-trip it. Remember the window client-side so we
    // fail fast with a clear message instead of hammering the relay.
    if (Date.now() < identityLockUntilRef.current) {
      const waitMin = Math.max(1, Math.ceil((identityLockUntilRef.current - Date.now()) / 60000));
      const m = `Relay rate limit — new threads unlock in about ${waitMin} minute${waitMin === 1 ? '' : 's'}. Existing chats keep working.`;
      setError(m);
      return;
    }
    setBusy(true); setContactsError(null);
    try {
      const session = await app.auth.currentSession();
      if (!session) throw new Error('Not signed in.');
      const { token } = await createOneTapSession(
        { relay: app.relay, pins: app.pins, sessions: app.sessions }, identity, veilId, session.user.id,
        // the Settings dials ride the new session record (web parity)
        {
          // b69 FIX: this callback's deps are [app, identity, refreshSessions] —
          // it does NOT re-close over `settings` when the user changes it in
          // Settings, so a nickname set after app boot silently never rode a
          // new one-tap session (owner report: "nicknames still do not
          // work"). settingsRef.current is the always-fresh mirror kept in
          // sync by the effect near the top of this component — read from
          // there in every callback that isn't recreated on settings change.
          default_ttl_seconds: settingsRef.current.burnTtlSeconds,
          expire_after_seconds: settingsRef.current.expireAfterSeconds,
          key_retention_hours: settingsRef.current.retentionHours,
          burn_after_open: settingsRef.current.burnTtlSeconds > 0,
        },
        // b68: my self-chosen nickname rides the session row — the peer sees
        // it in this thread's title unless they named me locally themselves.
        settingsRef.current.nickname || undefined,
      );
      // b197-r5 (K-17 fix — zombie sessions): creating a new thread with a
      // pinned peer used to leave ALL the peer's previous sessions alive
      // server-side. Those zombies bannered as desynced after any key-state
      // reset (reinstall/wipe), lingered in BOTH users' lists, and made the
      // b164 peer-side auto-switch never fire (the old session never vanished
      // from the server list — no "gone" signal). Now the prior sessions are
      // superseded — server-side (write secret + recId hard-delete fallback)
      // then locally. The peer's EXISTING b164 machinery (old thread vanishes
      // from the list + same-peer replacement present → auto-switch) then
      // completes the wipe on their device with zero new peer-side code.
      // b197-r6 (lag fix, owner report "5-10s lag on everything"): the r5
      // version blocked the new thread's open on N SEQUENTIAL relay round
      // trips, and the inline hammering re-tripped the account limiter (its
      // gateHot window then slowed EVERY action). The supersede now runs in
      // the BACKGROUND, in parallel, AFTER the new thread is opened — the
      // open is instant, the cleanup lands seconds later, and the peer's
      // auto-switch fires on their next refresh exactly as before.
      // b198 (FOUNDER SPEC, supersedes the b197-r6 guard): pressing + must close
      // the old thread on BOTH sides — including the thread the user is standing
      // in. The r6 exclusion (never supersede the open thread) is what kept the
      // old thread alive as a second conversation. The r6 race it guarded
      // (stale hbRowsRef snapshot killing keys of a row that stayed listed) is
      // fixed at the ROOT instead: the supersede list is built from a FRESH
      // relay list right here — never from a stale UI snapshot — and the order
      // is server-delete FIRST, local keys SECOND, open-new LAST, so no listed
      // row ever exists without keys.
      let staleTokens: { token: string; recId: string }[] = [];
      try {
        const lst = await app.relay.sessionList(session.user.id, identity?.veilId);
        const raw = (lst.data as { data?: unknown[] })?.data ?? (lst.data as unknown as { sessions?: unknown[] })?.sessions ?? [];
        // b198 PEACE TREATY (live battery catch: both phones pressing + fought —
        // each superseded the OTHER's brand-new thread, cascading auto-switches
        // killed keys on both sides). Rule: LAST WRITER WINS. A + press may only
        // supersede rows OLDER than the row it just created. If the peer pressed
        // + after me, THEIR thread is newer → mine loses, my app auto-switches
        // to theirs via the existing b164 machinery, and nobody destroys newer
        // work. Deterministic, no coordination needed.
        const allRows = (Array.isArray(raw) ? raw : []) as Record<string, unknown>[];
        const newRow = allRows.find((r) => String(r.token ?? '') === token);
        const newCreated = String(newRow?.created_date ?? '');
        staleTokens = allRows
          .filter((rec) => {
            const tok = String(rec.token ?? '');
            if (!tok || tok === token || rec.group_token) return false;
            const mine = String(rec.initiator_client_id ?? '') === String(session.user.id);
            const peer = String((mine ? rec.responder_veil_id : rec.initiator_veil_id) ?? '');
            if (peer !== veilId || String(rec.state ?? '') === 'ended') return false;
            // never supersede a row NEWER than mine — the peer's newer + wins
            return !newCreated || String(rec.created_date ?? '') <= newCreated;
          })
          .map((rec) => ({ token: String(rec.token), recId: String(rec.id ?? '') }));
      } catch { /* list failure → fall back to no supersede rather than block the open */ }
      for (const stale of staleTokens) {
        try {
          const ws = (await app.sessions.load(stale.token))?.writeSecret ?? null;
          try { await app.relay.sessionEnd(stale.token, ws, session.user.id); } catch { /* best-effort: entityDelete below owns it */ }
          if (stale.recId) { try { await app.relay.entityDelete('VeilSession', stale.recId); } catch { /* already gone */ } }
          try { await app.sessions.remove(stale.token); } catch { /* residue already gone */ }
          console.log(`[veil-new-thread] superseded prior session #${stale.token.slice(0, 4)} for peer ${veilId.slice(0, 8)}…`);
        } catch { /* never break the app on supersede failures */ }
      }
      const nick = await app.pins.getNickname(veilId);
      await openChatRef.current?.(token, nick || veilId, 'pinned contact · PQ session', 'pending', veilId);
      refreshSessions();
    } catch (e) {
      const reason = String((e as Error).message || e);
      console.error(`[veil-new-thread] failed for peer ${veilId.slice(0, 8)}…: ${reason}`);
      // b167: capture the 429 lock window so repeat taps back off locally
      const lockMatch = /locked, try again in about (\d+) minutes?/.exec(reason);
      if (lockMatch) identityLockUntilRef.current = Date.now() + Number(lockMatch[1]) * 60000;
      setContactsError(reason);
      setError(`Couldn't start a new thread: ${reason}`);
    } finally { setBusy(false); }
  }, [app, identity, refreshSessions]);


  /**
   * WEB PARITY — 'New chat thread with the same person' (chat header, next to
   * End): a FRESH one-tap session with the same pinned peer — all-new keys,
   * no new invitation (web title: 'New chat thread with the same person —
   * all-new keys, no new invitation'). Only shown when the peer is pinned.
   */
  const handleNewThread = useCallback(() => {
    // b167: this used to be a SILENT no-op when peerVeilId was missing —
    // another "button does nothing" path. If the button is somehow visible
    // without a peer id, say so instead of swallowing the tap.
    if (chat?.peerVeilId) { handleMessage(chat.peerVeilId); return; }
    console.error('[veil-new-thread] tapped but chat.peerVeilId is empty — thread not pinned-contact based');
    setError('New threads need a pinned contact — open this thread from your Contacts list.');
  }, [chat, handleMessage]);

  /** b95: dismiss the one-time verify card — persisted per token so it never
   *  nags again for this thread. Verifying via the card/badge hides it too
   *  (render condition is !myVerified). */
  const handleDismissVerifyCard = useCallback(() => {
    setVerifyCard(false);
    const token = chat?.token;
    if (!app || !token) return;
    (async () => {
      try {
        const raw = await app.storage.get('veil_vcard_dismissed');
        const dis = raw ? (JSON.parse(raw) as string[]) : [];
        if (!dis.includes(token)) await app.storage.set('veil_vcard_dismissed', JSON.stringify([...dis, token]));
      } catch { /* cosmetic card — never crash */ }
    })();
  }, [app, chat]);

  /**
   * WEB PARITY — per-session verify ceremony ('Verified for this session'):
   * marks MY side only (gate flips the caller's *_verified field). Badge goes
   * fully green only when BOTH sides completed it.
   */
  /**
   * b126: the system Alert is GONE — the ChatScreen verification panel now
   * owns the ceremony UX (fingerprint shown BEFORE "Mark verified" unlocks,
   * and viewable any time post-verification). This handler is only invoked
   * after the user confirmed the out-of-band comparison in that panel.
   */
  const handleVerifySession = useCallback(async (token: string) => {
    if (!app) return;
    try {
      const sealedV = await app.sessions.load(token);
      const ws = sealedV?.writeSecret ?? null;
      // b198 DIAGNOSTIC (verify-NULL hunt): did the state load, and did it carry
      // a credential? Booleans + lengths only — never the secret itself.
      console.log(`[veil-verify-diag] token=${token.slice(0, 6)}… stateLoaded=${!!sealedV} ready=${!!(sealedV as { ready?: boolean } | null)?.ready} ws=${ws ? "present(len " + ws.length + ")" : "NULL"}`);
      // b154 (builder relay audit, Oct 1): sessionPeek is responder-only (the
      // initiator side 403s) and its payload omits the *_verified flags, so
      // the b147 read-back could NEVER confirm the initiator's write — every
      // inviter-side ceremony errored. The gate's verify action returns the
      // updated session record in its own response; native now confirms OUR
      // slot's flag on that response and never peeks.
      const vk = await app.relay.sessionVerify(token, ws);
      const vd = vk.data as { data?: { session?: Record<string, unknown> }; session?: Record<string, unknown> };
      const rec = vd?.data?.session ?? vd?.session ?? (vk.data as Record<string, unknown>);
      const sess = await app.auth.currentSession();
      const mySide = sess ? String(rec.initiator_client_id ?? '') === String(sess.user.id) : null;
      const flagFlipped = mySide === null ? false : !!(mySide ? rec.initiator_verified : rec.responder_verified);
      if (!flagFlipped) {
        console.log('[veil-verify] verify response did not confirm our side', JSON.stringify({ initiator_verified: rec.initiator_verified, responder_verified: rec.responder_verified }));
        return false;
      }
            setChat((c) => c && c.token === token ? { ...c, myVerified: true } : c);
      await refreshSessions();
      return true;
    } catch (e) {
      // b161 (parity handoff §verify-2): failures render INLINE in the
      // ChatScreen verify panel — never the app-wide error state (the
      // toast-suppression rule made this failure invisible for weeks).
      // b197-r6: the catch was SILENT — "verification failed to save" with
      // zero diagnostics. Log the actual relay error (status/lock/gate state)
      // so the retry loop is diagnosable.
      console.error(`[veil-verify] save failed: ${(e as Error)?.message ?? String(e)} | relay gateHot=${app.relay.gateHot()}`);
      return false;
    }
  }, [app, refreshSessions]);

  /**
   * b126 "Pin as contact" (owner-approved Sept 26): promote a verified
   * session's peer into the permanent pins table via the relay's published
   * identity (same IK source the Contacts lookup uses). When both sides
   * completed the session ceremony, the pin carries verified state too.
   * Device-local, like every pin.
   */
  const handlePinFromSession = useCallback(async (token: string, veilId: string) => {
    if (decoyMode) { decoyBlocked(); return; }
    if (!app) return;
    try {
      const lk = await handleLookup(veilId);
      if (!lk) { setError('Could not find that identity on the relay.'); return; }
      await app.pins.pin(veilId, lk.ikPubB64);
      if (chat && chat.token === token && chat.myVerified && chat.peerVerified) {
        await app.pins.markVerified(veilId);
      }
      setChat((c) => c && c.token === token ? { ...c, peerPinned: true } : c);
      await refreshContacts();
    } catch (e) {
      setError('Could not pin that contact — please try again.');
    }
  }, [app, chat, handleLookup, refreshContacts]);

  const handleUnlock = useCallback(async () => {
    setLockHint('Authenticating…');
    try {
      const bio = await LocalAuthentication.authenticateAsync({ promptMessage: 'Unlock Veil' });
      if (bio.success) { setLocked(false); setLockHint(null); veilActivityPing(); }
      else if (bio.error === 'not_available' || !(await LocalAuthentication.hasHardwareAsync())) {
        // no biometrics enrolled on this device — passcode gate is the OS itself
        setLocked(false); setLockHint(null); veilActivityPing();
      } else {
        setLockHint('Authentication failed — try again.');
      }
    } catch {
      // b94: a crashing biometric module must never BECOME the unlock. The
      // not_available / no-hardware branches above already cover the legit
      // no-biometrics case; an unexpected exception keeps the gate shut.
      setLockHint('Unlock failed — try again.');
    }
  }, []);

  // b144 W3: call transport — closures over the live app context so the
  // call glue never outlives a sign-out (transport returns nulls after wipe)
  useEffect(() => {
    CallManager.configure({
      relay: () => app?.relay ?? null,
      sessions: () => app?.sessions ?? null,
      clientId: () => clientId(),
    });
  }, [app]);

  // b157: a call this device never answered (typically the offer was held
  // while the app was locked — hold-until-unlock deliberately keeps a locked
  // phone holding no message data, and call offers are ratcheted exactly
  // like chat so they cannot bypass it) is persisted per-thread and drained
  // into a "Missed call" system notice when the thread next opens.
  useEffect(() => {
    if (!app) return;
    CallManager.onMissedCall = (threadToken: string, peerLabel: string, outgoing?: boolean) => {
      // b158 live-note + b198: BOTH roles trace. The caller's ringout also
      // sends the peer a real notice message ("📞 Call unanswered") so the
      // trace lands in BOTH threads — including a callee whose app was quit
      // (the notice rides the normal sync + push; the offer itself expires).
      const noteText = outgoing
        ? `📞 Outgoing call — no answer.`
        : `📞 Missed call from ${peerLabel} — the call came in while this device was locked or away.`;
      if (chatRef.current?.token === threadToken) {
        const note: (ChatMessage & { systemNote?: string }) = {
          id: `missedcall_live_${Date.now()}`,
          text: '',
          mine: false,
          ts: new Date().toISOString(),
          systemNote: noteText,
        };
        setChatMessages((prev) => (prev.some((m) => m.id === note.id) ? prev : [...prev, note]));
      } else {
        void app.sessions.bumpMissedCalls(threadToken, peerLabel).catch(() => undefined);
      }
      if (outgoing) {
        // the peer's thread needs the trace too — a real notice message rides
        // the sync and pings them (the offer itself expires after 5 minutes).
        void (async () => {
          try {
            const who = await clientId();
            if (!who) return;
            await sendChatMessage(app.relay, app.sessions, threadToken, who, '📞 Call unanswered — no response.');
          } catch (e) { console.log('[veil-calls] missed-call notice send failed (best-effort):', (e as Error).message ?? e); }
        })();
      }
    };
    return () => { CallManager.onMissedCall = null; };
  }, [app]);

  const clientId = async (): Promise<string | null> => {
    if (!app) return null;
    const session = await app.auth.currentSession();
    return session?.user.id ?? null;
  };

  /**
   * Advance the handshake on whichever side we're on, then sync. Role is
   * decided from the session record's veil-ids, never guessed from UI state
   * (VEIL-P0 fix, Sept 18: the responder side previously had no accept path
   * at all — completeContactHandshake is initiator-only and threw forever).
   */
  /**
   * SPEC §3 handshake driver — returns true only when OUR ratchet is ready.
   * PENDING-INITIATOR LOOP: poll the participant-scoped session listing
   * (veilSessionGate {action:'list', client_id}) — the same record the web
   * client polls. Accepted exactly when state === 'active' AND both
   * responder_pub_jwk and responder_ratchet_pub_jwk are non-empty; then the
   * initiator completes the handshake EXACTLY ONCE from the stored
   * request-time state. Web's automatic intro envelope is already waiting on
   * the relay at that point (its header rp = responder_ratchet_pub_jwk) and
   * decrypts with the recv chain the completion derives.
   */
  const advanceHandshake = useCallback(async (token: string, who: string): Promise<boolean> => {
    if (!app || !identity) return false;
    if (hsFailClosedRef.current.has(token)) return false; // b196-r8: relay says already joined; retrying every 3s is noise
    const sealed = await app.sessions.load(token);
    if (sealed?.ready) return true; // joined/active — fast path, no network
    // b198: hoisted OUTSIDE the try so the fail-close below knows whether this
    // device has even ACCEPTED the thread yet (a pending row addressed to us
    // legitimately has no local keys — the accept creates them)
    let recState = 'unknown';
    let joinedHere = true;
    try {
      const r = await app.relay.sessionList(who, identity.veilId);
      const list = (r.data as { data?: unknown[] })?.data ?? (r.data as { sessions?: unknown[] })?.sessions ?? (r.data as unknown as unknown[]);
      const rec = (Array.isArray(list) ? list : []).map((x) => x as Record<string, unknown>)
        .find((x) => String(x.token ?? '') === token);
      if (!rec) return false;
      recState = String(rec.state ?? '');
      // responder: joined iff their join is stamped on the row; initiator: keys exist from creation
      joinedHere = rec.responder_veil_id === identity.veilId ? !!rec.responder_pub_jwk : true;
      const iAmInitiator = rec.initiator_veil_id === identity.veilId;
      const iAmResponder = rec.responder_veil_id === identity.veilId;
      if (iAmResponder && !iAmInitiator) {
        // responder side: accept + join (derives ready chains immediately)
        // b69 FIX: same stale-closure bug as handleMessage above — advanceHandshake's
        // deps are [app, identity] only, so a nickname set after boot never rode the accept.
        await acceptOneTapSession({ relay: app.relay, pins: app.pins, sessions: app.sessions }, identity, rec as never, who, settingsRef.current.nickname || undefined);
        return !!(await app.sessions.load(token))?.ready;
      }
      if (iAmInitiator) {
        // SPEC gate: complete exactly once, only when accepted
        if (rec.state === 'active' && rec.responder_pub_jwk && rec.responder_ratchet_pub_jwk) {
          await completeContactHandshake(app.relay, app.sessions, token, rec);
          return true;
        }
        return false;
      }
      // invite-link sessions carry no veil-ids — legacy initiator path.
      // b125 FIX: `rec` was already fetched via sessionList a few lines up
      // (it's how we got here at all — the `if (!rec) return false;` guard
      // above already proved it exists, complete with responder_pub_jwk /
      // responder_ratchet_pub_jwk once the peer has joined). Discarding it
      // and calling completeContactHandshake with no prefetched record forced
      // its peek() fallback, and the relay's peek gate rejects the SESSION
      // CREATOR outright ("Only the invited side can view this session" —
      // peek is scoped to the joining side, not the creator). Every invite-
      // link initiator was silently stuck at initiator_verified regardless of
      // ceremony state; reusing `rec` here skips peek entirely and completes
      // straight from data we already hold.
      await completeContactHandshake(app.relay, app.sessions, token, rec as never).catch(() => undefined);
      return !!(await app.sessions.load(token))?.ready;
    } catch (e) {
      // b80 (owner report: message "just slipped into conversations, no
      // accept window" but never actually decrypts — even on b79) — this
      // catch used to be completely bare. b79 fixed ONE specific throw
      // inside acceptOneTapSession (the state!=='pending' guard), but ANY
      // other failure in the accept chain (signature check, missing
      // prekeys, relay join rejection, etc.) was — and still would be —
      // swallowed here with zero visibility. Logging instead of guessing.
      const m = (e as Error)?.message ?? String(e);
      // b196-r8: a restored thread whose relay state moved past us ("Session
      // already joined") can never complete its local handshake from here.
      // Fail-close it: log ONCE, stop the 3s retry loop. The thread stays
      // unready locally; ending it (✕) cleans the residue.
      if (/already joined/i.test(m)) {
        hsFailClosedRef.current.add(token);
        console.error(`[veil-handshake] #${token.slice(0, 4)} already joined on relay but not completable locally — fail-close, ending retries`);
        return false;
      }
      // b197-r6: 'No ratchet state for this session on this device' on the
      // advance path means the LOCAL KEYS are gone (rapid-tap supersede race,
      // keychain flake, wipe) while the relay row still says active. Retrying
      // every 3s can NEVER succeed — keys don't come back — and it burns
      // relay budget forever. Fail-close: log once, direct the user to the
      // list ✕ end affordance (K-16/K-17 give every dead thread an exit).
      if (/no ratchet state/i.test(m)) {
        // b198 (live battery catch): a PENDING row this device has NOT accepted
        // yet legitimately has no local keys — the accept creates them. The old
        // guard failed-closed on exactly this and blacklisted brand-new threads
        // the moment an auto-switch surfaced them (the receiver-side "nothing
        // happens / verification failed" loop). Fail-close ONLY when this device
        // was supposed to have keys (joined/active) and they're gone.
        if (recState === 'pending' || !joinedHere) {
          console.log(`[veil-handshake] #${token.slice(0, 4)} pending/not-yet-accepted — no local keys yet is NORMAL; accepting on the next tick`);
          return false;
        }
        hsFailClosedRef.current.add(token);
        console.error(`[veil-handshake] #${token.slice(0, 4)} local keys are GONE (relay row still active) — thread is unrecoverable, fail-close. End it from the conversation list (✕).`);
        return false;
      }
      console.error(`[veil-handshake] advanceHandshake failed for #${token.slice(0, 4)}: ${m}`);
      return false; // pending loop retries on the next 3s tick
    }
  }, [app, identity]);
  /** b76 FIX: the capture effect (deps [app]) runs ONCE at connect, while
   * identity is still null — it captured the identity=null advanceHandshake
   * and returned false FOREVER: every 1:1 screenshot notice silently logged
   * "handshake not ready (pending thread)" on fully-active threads (owner
   * report, repro'd in Metro twice). Route through a live ref instead. */
  const advanceHandshakeRef = useRef(advanceHandshake);
  useEffect(() => { advanceHandshakeRef.current = advanceHandshake; }, [advanceHandshake]);

  const syncToken = useCallback(async (token: string) => {
    if (lockedRef.current && settingsRef.current.holdUntilUnlock) return; // delivery held while locked
    if (!app) return;
    if (syncInFlightRef.current[token]) return; // a sync for this token is already running
    // b175: relay said "slow down" on a recent pass — skip this tick
    // entirely rather than retrying at full 1.5s cadence into the same
    // limiter. Silent: the next eligible tick resumes normally.
    const cooldownUntil = rateLimitCooldownUntilRef.current[token] ?? 0;
    if (Date.now() < cooldownUntil) return;
    syncInFlightRef.current[token] = true;
    try {
      const who = await clientId();
      if (!who) return;
      const ready = await advanceHandshake(token, who);
      setThreadReady(ready);
      // b87: resume from this session's persisted pagination cursor — see
      // SessionStore.syncSkip / chat.ts's syncChat for why a plain skip=0
      // fetch permanently stalls once a session passes 200 total envelopes.
      const startSkip = ready ? await app.sessions.syncSkip(token) : 0;
      const res = ready
        ? await syncChat(app.relay, app.sessions, token, who, chatKnown, false, startSkip)
        : { messages: [] as never[], processedIds: [] as string[], nextSkip: startSkip };
      if (ready && !(res as { ended?: boolean }).ended) {
        await app.sessions.saveSyncSkip(token, (res as { nextSkip: number }).nextSkip);
      }
      // b144 W3: call signals (offer/answer/ice/end) were decrypted and
      // filtered from the chat list inside syncChat — hand them to the call
      // manager so the overlay can ring/connect. Fire-and-forget on purpose:
      // a call setup must never block the message pipeline.
      const callSigs = (res as { callSignals?: { __veil_call: 1; op: 'offer' | 'answer' | 'ice' | 'end'; call_id: string; sdp?: string; k?: string; cand?: string; reason?: string; seq?: number }[] }).callSignals;
      if (ready && callSigs?.length) {
        void CallManager.handleSignals(token, callSigs).catch((e) => console.log(`[veil-call] signal dispatch error: ${(e as Error).message}`));
      }
      // knownIds must include EVERY envelope decrypted this pass (visible
      // chat text + filtered cover/intro/receipt control payloads) or the
      // filtered ones get re-fetched and re-decrypted every poll — a
      // consumed ratchet message key can't be re-derived, so that only
      // spams decrypt-failed logs without ever surfacing anything.
      if ((res as { processedIds?: string[] }).processedIds?.length) {
        setChatKnown((prev) => new Set([...prev, ...(res as { processedIds: string[] }).processedIds]));
      }
      if (res.messages.length) {
        setChatMessages((prev) => [...prev, ...res.messages]);
        // local banner only when the user is NOT looking at this thread
        // (the APNs ping itself stays silent — see notifications.ts)
        // b84: the thread-open grace window covers the unlock-resume race —
        // AppState can lag reality for a second or two after foregrounding.
        const inOpenThread = chatRef.current?.token === token;
        const justOpened = Date.now() - chatOpenedAtRef.current < 4000;
        if ((AppState.currentState !== 'active' && !justOpened) || !inOpenThread) {
          notifyNewMessage();
        }
      }
      // READ-RECEIPT PARITY (web): the user is looking at this thread and
      // these peer messages just rendered — batch-ack them through the
      // encrypted channel. read:true only when the local read-receipts dial
      // is on; ids still flow as delivery state when it's off.
      // b127: receipts must also cover messages that arrived via a
      // BACKGROUND pass while this thread was closed — they render from
      // CACHE on thread-open, never appear in res.messages again, so the
      // old code never acknowledged them no matter how long the user
      // read them (and the old "deferred retry" could never re-send:
      // the lost batch never reappears). Sweep un-receipted cached peer
      // rows every pass while the thread is open, backed by a persistent
      // per-token receipted ledger (SessionStore b127) so restarts don't
      // re-acknowledge the whole thread.
      // b129 FIX (live-found, Sept 26): the b127 sweep was nested inside
      // `if (res.messages.length)` — it only ran on passes that brought
      // NEW messages, so cached rows that arrived while the thread was
      // closed were never receipted on reopen (owner repro: sweep-test
      // A/B on session ae17 got zero receipts across 4+ min open).
      // Hoisted out of the gate: the sweep now runs on EVERY pass while
      // this thread is open (freshIds is simply empty on a cache-only
      // pass), so reopening a thread acks its cached backlog.
      if (chatRef.current?.token === token) {
          const freshIds = (res as { messages: { id: string }[] }).messages.map((m) => m.id);
          const cachedRows = await app.sessions.cachedMessages(token).catch(() => [] as ChatMessage[]);
          const receipted = await app.sessions.receiptedIds(token).catch(() => new Set<string>());
          const cachedIds = cachedRows
            .filter((m) => !m.mine && (m.envId || m.id) && !(m.id ?? '').startsWith('stray_'))
            .map((m) => m.envId ?? m.id)
            .filter((id) => !receipted.has(id));
          const seen = [...new Set([...freshIds, ...cachedIds])]
            .filter((id) => !receiptSentRef.current.has(id));
          if (seen.length) {
            for (const id of seen) receiptSentRef.current.add(id);
            console.log(`[veil-receipt] sending ${seen.length} receipt id(s) (read:${settings.readReceipts})`);
            sendReadReceipt(app.relay, app.sessions, token, who, seen, settings.readReceipts).then(async () => {
              await app.sessions.markReceiptedIds(token, seen).catch(() => undefined);
            }).catch((e) => {
              // Expected + self-healing: iOS suspends background networking while
              // locked, so a receipt send here fails transiently and retries on the
              // next sync — and b127 makes the retry REAL: the ids stay
              // un-ledgered and resurface from the cache sweep next pass.
              console.warn('[veil] receipt send deferred (will retry):', (e as Error).message ?? e);
              for (const id of seen) receiptSentRef.current.delete(id);
            });
          }
        }
      // b91 (web stray-classifier parity): envelopes that failed to decrypt
      // BUT were followed by a successful newer decrypt in the same pass are
      // strays, not a desync — a soft in-thread notice, never the destructive
      // prompt. Ledgered in SessionStore so each stray notices exactly once.
      const strays = (res as { strayIds?: string[] }).strayIds ?? [];
      for (const sid of strays) {
        const notice: (ChatMessage & { systemNote?: string }) = {
          id: `stray_${sid}`,
          text: '',
          mine: false,
          ts: new Date().toISOString(),
          systemNote: strays.length === 1
            ? 'One message could not be opened on this device; the rest of the conversation is unaffected.'
            : `${strays.length} messages could not be opened on this device; the rest of the conversation is unaffected.`,
        };
        setChatMessages((prev) => (prev.some((m) => m.id === notice.id) ? prev : [...prev, notice]));
      }
      // b91: genuine desync signatures (header-key mismatch = epoch
      // divergence, or stacking failures with no newer success) keep the
      // web's end-session recommendation — once per thread per app run.
      if ((res as { desync?: boolean }).desync && chatRef.current?.token === token && !desyncPromptedRef.current[token]) {
        desyncPromptedRef.current[token] = true;
        // b197-r3 (K-16 fix): this banner previously had NO buttons — it told
        // the user to "end this session" while providing no way to do it, and
        // the server-side end silently fails for peer-created sessions (RLS),
        // leaving undeletable dead threads after a reinstall (fresh-install
        // sweep wipes the keys; server rows survive). Wire the close flow the
        // supersede path already uses: best-effort server end (with the local
        // write secret), local state removal, back to main, list refresh.
        Alert.alert(
          'Session out of sync',
          'New messages in this thread can no longer be decrypted on this device. End this session and start a new chat thread with the same contact to keep messaging securely.',
          [
            {
              text: 'End this thread',
              style: 'destructive',
              onPress: () => {
                void (async () => {
                  if (!app) return;
                  let ws: string | null = null;
                  try { ws = (await app.sessions.load(token))?.writeSecret ?? null; } catch { /* no sealed record */ }
                  try {
                    const sess = await app.auth.currentSession();
                    if (sess) await app.relay.sessionEnd(token, ws, sess.user.id);
                  } catch { /* peer-created or pending: local close still proceeds */ }
                  try { await app.sessions.remove(token); } catch { /* residue already gone */ }
                  if (chatRef.current?.token === token) { setChat(null); setScreen('main'); }
                  refreshSessions();
                })();
              },
            },
            { text: 'Later', style: 'cancel' },
          ],
        );
      }
      // COVER-TRAFFIC PARITY (web): each poll cycle, 15% chance to submit a
      // ratchet-encrypted filler envelope through the same channel as real
      // chat, so relay observers cannot tell chatting from idling. Failures
      // are non-fatal — the next poll simply rolls again.
      if (ready && chatRef.current?.token === token && Math.random() < 0.15) {
        sendCoverEnvelope(app.relay, app.sessions, token, who).catch((e) => {
          const m = (e as Error).message ?? String(e);
          console.log('[veil] cover send skipped:', m);
          // b198 (live retest Oct 15): the cover send is the observer that
          // actually REACHES the relay on the open thread every poll cycle.
          // On a superseded/deleted session it is the FIRST component to see
          // "Session not found" (the sync cleanly fetches 0 envelopes; the
          // heartbeat loop may legitimately skip the row if its listed status
          // is stale). Summon the list refresh the b164 auto-switch needs.
          if (/session not found|superseded/i.test(m)) refreshSessionsRef.current?.(true);
        });
      }
      // peer receipts confirm MY messages read — mark the bubbles
      const readIds = (res as { readIds?: string[] }).readIds ?? [];
      if (readIds.length) {
        console.log(`[veil-receipt] peer read ${readIds.length} of my message(s) — marking`);
        const set = new Set(readIds);
        setChatMessages((prev) => prev.map((m) =>
          (m.envId && set.has(m.envId)) || set.has(m.id) ? { ...m, read: true, openedAt: Date.now() } : m)); // b198: burn clock anchors at receipt
        // b69: receipts survive close/reopen (cache previously never updated)
        app.sessions.markCachedRead(token, readIds).catch(() => undefined);
      }
      // b175: a clean pass resets this token's backoff — the limiter only
      // matters while it's actively firing, not as a lingering penalty.
      if (!(res as { rateLimited?: boolean }).rateLimited) {
        delete rateLimitBackoffMsRef.current[token];
        delete rateLimitCooldownUntilRef.current[token];
      }
      if (ready) {
        setChat((c) => c && c.token === token ? { ...c, status: 'active' } : c);
        // b198 (live retest Oct 15): acceptance previously flipped only the
        // CHAT state to 'active' — the session ROW kept its stale 'pending'
        // until the next list refresh. The presence heartbeat skips non-active
        // rows, so the freshly-accepted open thread was invisible to the beat
        // loop (instrumented evidence: "beat pass: no beatable rows") — which
        // also blinded the not-found → refresh trigger. Patch the row so the
        // listed status matches reality the moment acceptance completes.
        setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, status: 'active' as const } : r)));
      }
      if ((res as { rateLimited?: boolean }).rateLimited) {
        const prev = rateLimitBackoffMsRef.current[token] ?? RATE_LIMIT_BACKOFF_BASE_MS / 2;
        const next = Math.min(prev * 2, RATE_LIMIT_BACKOFF_CAP_MS);
        rateLimitBackoffMsRef.current[token] = next;
        rateLimitCooldownUntilRef.current[token] = Date.now() + next;
        console.log(`[veil] sync #${token.slice(0, 4)}: relay rate-limited this pass — backing off ${next}ms before next attempt`);
      }
    } catch (e) {
      const msg = (e as Error).message ?? String(e);
      // b88 (owner repro Sept 21 ~03:15 Bris: "Console Error [veil] sync
      // failed: Network request failed" popped up while a thread was
      // simply open on patchy connectivity): a transient fetch failure is
      // EXACTLY the case b83 already decided should self-heal quietly (the
      // next poll retries 1.5-3s later) — but this foreground catch still
      // used console.error unconditionally, so every ordinary network
      // hiccup while a chat was open painted a full red LogBox screen,
      // unlike backgroundSyncAllSessions's matching catch (console.log)
      // for the identical failure. Only this known-transient RN fetch
      // error message drops to info level; a genuinely unexpected sync
      // failure (bad decrypt, malformed response, etc.) still logs loud.
      if (/rate limit exceeded/i.test(msg)) {
        // b175: the FETCH itself got throttled (owner Metro repro Oct 2:
        // envelopeList 500'd "Rate limit exceeded" alongside burn/heartbeat
        // during the burst). syncChat throws before it can return the
        // rateLimited flag, so without this branch the poll loop would keep
        // its full 1.5s cadence straight through the limiter window.
        const prev = rateLimitBackoffMsRef.current[token] ?? RATE_LIMIT_BACKOFF_BASE_MS / 2;
        const next = Math.min(prev * 2, RATE_LIMIT_BACKOFF_CAP_MS);
        rateLimitBackoffMsRef.current[token] = next;
        rateLimitCooldownUntilRef.current[token] = Date.now() + next;
        console.log(`[veil] sync #${token.slice(0, 4)}: relay rate-limited the fetch itself — backing off ${next}ms`);
      } else if (/network request failed/i.test(msg)) {
        console.log(`[veil] sync skipped for #${token.slice(0, 4)} — network hiccup, next poll retries: ${msg}`);
      } else if (/session not found|superseded/i.test(msg)) {
        // b198 handoff (live find, Oct 15): the receiver sitting INSIDE a
        // deleted thread kept syncing it ("Session not found" ×123) and NEVER
        // refreshed the session list — the b164 auto-switch only fires on a
        // LIST REFRESH, which does not run while a chat is open. Trigger the
        // refresh here so the (freshness-gated) auto-switch can complete the
        // same-peer handoff instead of looping on a dead token.
        console.log(`[veil] sync #${token.slice(0, 4)}: session gone server-side — refreshing list so the auto-switch can run`);
        refreshSessionsRef.current?.(true);
      } else {
        // next poll retries — but never silently
        console.error('[veil] sync failed:', msg);
      }
    } finally {
      syncInFlightRef.current[token] = false;
    }
  }, [app, chatKnown, advanceHandshake, settings]);

  // b77 FIX (owner report: "no notifications at all, even in the app"):
  // syncToken() above only ever ran for the CURRENTLY OPEN thread's token —
  // the push-received listener and the 10s main-screen poll both gated on
  // chatRef.current, so a message arriving on any OTHER session (or while
  // the user sits on the Conversations list, or while backgrounded) was
  // never decrypted at all until that thread was opened by hand, and
  // notifyNewMessage() never got a chance to fire. This is syncToken's
  // decrypt+cache+notify core WITHOUT the open-thread UI side effects
  // (chatMessages append, cover traffic, receipt send/mark, threadReady) —
  // those stay scoped to the foreground poll so background calls can never
  // corrupt the currently-open thread's state. Safe to call for every
  // session token on every wake.
  const backgroundSyncToken = useCallback(async (token: string, peerLabel?: string) => {
    if (lockedRef.current && settingsRef.current.holdUntilUnlock) return;
    if (!app) return;
    if (chatRef.current?.token === token) return; // foreground poll already covers this one
    if (syncInFlightRef.current[token]) return;
    syncInFlightRef.current[token] = true;
    try {
      const who = await clientId();
      if (!who) return;
      const ready = await advanceHandshake(token, who);
      if (!ready) return;
      // b78 CRITICAL FIX: pass a FRESH knownIds set — the app-level chatKnown
      // belongs to whichever thread is/was OPEN. Using it here re-served other
      // sessions' already-consumed envelopes and re-decrypted them; every
      // envelope header carries a PQ rekey, so each re-decrypt rotated both
      // chains and reset the counters — the "Message counter out of range"
      // desync, occurring exactly when the phone was locked (background sync
      // is the only path that runs then). Dedupe is now authoritative in the
      // per-token processed-id ledger inside syncChat (SessionStore).
      // b87: same pagination cursor as the foreground poll — background
      // sync hits the identical 200-row stale-head stall otherwise.
      const startSkip = await app.sessions.syncSkip(token);
      const res = await syncChat(app.relay, app.sessions, token, who, new Set(), false, startSkip);
      if (!res.ended) await app.sessions.saveSyncSkip(token, res.nextSkip);
      // b196: adaptive backoff bookkeeping (see pollBackoffRef)
      const nothingNew = !res.processedIds?.length && !(res as { callSignals?: unknown[] }).callSignals?.length;
      if (nothingNew) {
        const streak = (zeroStreakRef.current[token] ?? 0) + 1;
        zeroStreakRef.current[token] = streak;
        pollBackoffRef.current[token] = Date.now() + Math.min(10_000 * 2 ** (streak - 1), 60_000) + Math.floor(Math.random() * 3_000);
      } else {
        zeroStreakRef.current[token] = 0;
        pollBackoffRef.current[token] = Date.now() + 10_000 + Math.floor(Math.random() * 3_000);
      }
      // b152 CRITICAL (owner repro Oct 1: "unless you're in a chat thread,
      // the phone does nothing at all" when a call comes in): syncChat had
      // ALREADY decrypted and classified call signals for background threads —
      // this loop just dropped them on the floor, so an offer on any
      // non-open session never rang. Forward them to CallManager exactly like
      // the foreground path does (fire-and-forget, never blocks message
      // handling). b149 mounted the overlay on every screen; THIS was the
      // missing half of "calls ring anywhere".
      const bgCallSigs = (res as { callSignals?: { __veil_call: 1; op: 'offer' | 'answer' | 'ice' | 'end'; call_id: string; sdp?: string; k?: string; cand?: string; reason?: string; seq?: number }[] }).callSignals;
      if (bgCallSigs?.length) {
        void CallManager.handleSignals(token, bgCallSigs, peerLabel).catch((e) =>
          console.log(`[veil-call] background signal dispatch error: ${(e as Error).message}`));
      }
      // b92 F1 (b91 audit): a stray or genuine desync classified while this
      // thread was CLOSED must not vanish — the foreground notice renders in
      // React state that is gone by the time the thread opens. Persist the
      // counts; openChat drains them into the same soft-notice bubbles /
      // one-time desync Alert the live path shows.
      const bgRes = res as { strayIds?: string[]; desync?: boolean };
      if (bgRes.strayIds?.length) await app.sessions.bumpPendingStrays(token, bgRes.strayIds.length);
      if (bgRes.desync) await app.sessions.setPendingDesync(token);
      // b127 CRITICAL (owner repro Sept 25: native has NEVER shown a ✓ read
      // tick on any build): receipts are usually processed by THIS background
      // pass — the thread is closed when they arrive, or this loop simply wins
      // the fetch race (both loops share the per-token dedupe ledger, so the
      // loser never sees the envelope again). The foreground path was the only
      // one that applied readIds, so most peer read-confirmations were
      // decrypted, extracted, and thrown away here. Persist to the cache
      // (thread-closed case: the tick is there on next open) and update the
      // live thread state if it happens to be open.
      const bgRead = (res as { readIds?: string[] }).readIds ?? [];
      if (bgRead.length) {
        console.log(`[veil-receipt] background: peer read ${bgRead.length} of my message(s) — marking`);
        await app.sessions.markCachedRead(token, bgRead).catch(() => undefined);
        if (chatRef.current?.token === token) {
          const rset = new Set(bgRead);
          setChatMessages((prev) => prev.map((m) =>
            ((m.envId && rset.has(m.envId)) || rset.has(m.id) ? { ...m, read: true, openedAt: Date.now() } : m))); // b198: burn clock anchors at receipt
        }
      }
      // b92 F9 (b91 audit, traffic-analysis parity): web idles keep emitting
      // cover envelopes while the app is open on any screen; native previously
      // sent cover ONLY while a thread was foregrounded, letting a relay
      // observer tell "native user idle" from "web user idle" by cadence.
      // Same 15% roll as the foreground poll, only while the app is active
      // (a suspended iOS app cannot emit anything, and that's honest too).
      if (ready && AppState.currentState === 'active' && Math.random() < 0.15) {
        sendCoverEnvelope(app.relay, app.sessions, token, who).catch((e) => {
          const m = (e as Error).message ?? String(e);
          console.log('[veil] background cover send skipped:', m);
          // b198: same receiver-side deletion signal as the foreground catch.
          if (/session not found|superseded/i.test(m)) refreshSessionsRef.current?.(true);
        });
      }
      if (res.messages.length) {
        console.log(`[veil-notify] background: ${res.messages.length} new message(s) on #${token.slice(0, 4)} — notifying`);
        // b90: badge the thread. Only messages from the OTHER side count —
        // this path never runs for the open thread, so everything here is
        // unseen by definition.
        const fresh = res.messages.filter((m) => !m.mine).length;
        if (fresh > 0) {
          const next = await app.sessions.bumpUnread(token, fresh);
          setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, unread: next } : r)));
        }
        notifyNewMessage();
      }
    } catch (e) {
      const msg = (e as Error).message ?? String(e);
      console.log(`[veil-notify] background sync failed for #${token.slice(0, 4)}:`, msg);
      // b198 handoff (live find): same receiver-side dead-thread loop as the
      // foreground catch — a background pass discovering the session is gone
      // must also trigger the list refresh that lets b164 auto-switch run.
      if (/session not found|superseded/i.test(msg)) refreshSessionsRef.current?.(true);
      // b83 (owner repro + device log: "Keychain get('veil_rk_...') failed —
      // User interaction is not allowed"): the ratchet/session key is, and
      // stays, gated to WHEN_UNLOCKED — that key IS the message-decryption
      // material, unlike the b81 login-token fix, and it should NOT be
      // loosened. The honest consequence: real content decrypt is
      // architecturally impossible while the screen is actually locked, even
      // during a granted background wake window. Rather than staying
      // completely silent in exactly the case the owner cares about most,
      // fire the SAME zero-content generic banner this already uses for a
      // real decrypt — it reveals nothing new (no sender, no text, no
      // session, matching the existing threat model) and turns "silently
      // failed" into "you were notified something is waiting, open the app
      // to read it." Tradeoff disclosed: this can fire on a cycle that turns
      // out to be nothing but cover traffic once actually decrypted —
      // accepted, because false-silence is worse than an occasional
      // false-positive nudge.
      if (/User interaction is not allowed/i.test(msg)) {
        console.log(`[veil-notify] locked-device decrypt blocked for #${token.slice(0, 4)} — firing generic banner anyway (content stays undecrypted until unlock)`);
        notifyNewMessage();
      }
    } finally {
      syncInFlightRef.current[token] = false;
    }
  }, [app, advanceHandshake]);

  // b78: background sync ACTIVE non-group sessions only. Pending sessions
  // must never be auto-accepted by a background poll — acceptance is the
  // explicit openChat UX (ceremony, nickname). Ended ones have no ratchet.
  // Group inbox has its own poll (syncGroupToken).
  const backgroundSyncAllSessions = useCallback(() => {
    // b196: during an active call, background sync of OTHER threads waits —
    // call signaling (offers/ICE/answers) shares the per-account rate budget
    // with polls, and the owner's Oct 12 log shows 429s eating 4 of 9 ICE
    // sends mid-call while other sessions kept polling. The in-call session
    // is foregrounded by its own paths, so nothing of its own is starved.
    const snap = CallManager.snapshot();
    if (snap && (snap.phase === 'calling' || snap.phase === 'ringing' || snap.phase === 'connecting' || snap.phase === 'active')) return;
    const now = Date.now();
    for (const row of sessionRows) {
      if (row.status !== 'active' || row.groupToken) continue;
      if (now < (pollBackoffRef.current[row.token] ?? 0)) continue; // b196 backoff
      backgroundSyncToken(row.token, row.title).catch(() => undefined);
    }
    // b198 BACKGROUND GROUP DELIVERY: group polls previously ran ONLY while the
    // group thread was open — a group message never arrived unless the
    // recipient was sitting inside the thread (and group sends fired no push,
    // fixed relay-side). This pass polls every known group record NOT
    // currently open (the open thread's own poll covers it), gateHot-respecting
    // and in-flight-guarded, on the same background cadence as pairwise sync.
    void (async () => {
      if (!app || !identity || app.relay.gateHot()) return;
      try {
        await loadGroupRecords(app.storage); // hydrate the registry (returns a count)
        const recs = exportGroupRecords(app.storage);
        const who = await clientId();
        for (const rec of recs) {
          if (rec.sessionEnded) continue;
          let tok = rec.sessionToken ?? '';
          if (!tok && who) {
            // records created before b198 predate the stored token — derive from
            // the relay list (either side: the creator's main row or the member's
            // joined invite row)
            const lst = await app.relay.sessionList(who, identity.veilId);
            const body = (lst.data ?? {}) as { data?: unknown[]; sessions?: unknown[] };
            const list = (Array.isArray(body.data) ? body.data : (body.sessions ?? [])) as Record<string, unknown>[];
            const mine = list.find((r) => String(r.group_token ?? '') === rec.groupToken
              && String(r.state ?? '') === 'active'
              && (String(r.initiator_client_id ?? '') === who || String(r.responder_client_id ?? '') === who));
            if (mine) tok = String(mine.token ?? '');
          }
          if (!tok || chatRef.current?.token === tok) continue; // open thread: its own poll covers it
          if (syncInFlightRef.current[tok]) continue;
          syncInFlightRef.current[tok] = true;
          void pollGroupInbox(
            { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
            {
              groupToken: rec.groupToken,
              sessionToken: tok,
              burnAfterOpen: !!sessionDialsRef.current[tok]?.burn,
              identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64, pqPrivB64: identity.pqPrivB64 },
              knownIds: groupKnownRef.current,
              events: {
                // background arrival: contentless banner + unread badge — the
                // message body renders when the user opens the thread.
                onMessage: () => { void notifyNewMessage(); },
                onSystem: () => { void notifyNewMessage(); },
                onRead: () => undefined,
                onRotated: () => undefined,
                onSenderVerifyFailed: () => undefined,
              },
            },
          ).catch(async (e) => {
            const m = (e as Error).message ?? String(e);
            // b198: the background pass is also the group's gone-detector while
            // the thread is closed — mark ended (stops polling) + refresh so
            // the deleted group's row leaves the list without user action.
            if (/session not found/i.test(m)) {
              const dead = await loadGroupRecord(app.storage, rec.groupToken);
              if (dead && !dead.sessionEnded) {
                await saveGroupRecord(app.storage, { ...dead, sessionEnded: true });
                console.log(`[veil-group] background pass: group #${rec.groupToken.slice(0, 6)} ended server-side — marked ended`);
                refreshSessions();
              }
            } else {
              console.log(`[veil-group] background poll failed for #${rec.groupToken.slice(0, 6)}: ${m}`);
            }
          })
            .finally(() => { syncInFlightRef.current[tok] = false; });
        }
      } catch { /* background group pass is best-effort */ }
    })();
  }, [sessionRows, backgroundSyncToken, app, identity]);

  // b62 groups: live poll for an open group thread (veil-group-1 inbox)
  const syncGroupToken = useCallback(async (token: string) => {
    if (!app || !identity) return;
    // b187: lounge threads poll the veil-group-1 envelope list with the
    // LISTENER policy (founder-tag-only, signature REQUIRED, no roster, no
    // burn, no receipts) — the record carries no session credential.
    if (token.startsWith('lounge_')) {
      const gt = token.slice('lounge_'.length);
      if (syncInFlightRef.current[token]) return;
      syncInFlightRef.current[token] = true;
      try {
        const resL = await pollLoungeInbox(
          { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
          {
            groupToken: gt,
            knownIds: groupKnownRef.current,
            events: {
              onMessage: (info) => {
                const msg: (ChatMessage & { sender?: string; senderVerified?: boolean }) = {
                  id: info.envelopeId,
                  text: info.text,
                  mine: false,
                  ts: info.sentAt,
                  envId: info.envelopeId,
                  sender: info.senderNick || 'Founder',
                  senderVerified: info.senderVerified,
                  openedAt: Date.now(),
                  ...(info.media ? { media: { uri: info.media.uri, k: info.media.k, iv: info.media.iv, mime: info.media.mime, name: info.media.name, size: info.media.size, dl: !!info.media.dl } } : {}),
                };
                setChatMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
                app.sessions.cacheMessages(token, [msg]).catch(() => undefined);
                // b197-r8m (BURN-ON-HUMAN-OPEN): this render IS the human-open
                // moment — unlock the envelope's burn (fires next sync pass).
                if (sessionDialsRef.current[token]?.burn) {
                  void markEnvelopeDisplayed(app.relay, app.sessions, token, info.envelopeId).catch(() => undefined);
                }
                if (AppState.currentState !== 'active' || !chatRef.current || chatRef.current.token !== token) {
                  notifyNewMessage();
                  app.sessions.bumpUnread(token, 1).then((next) => {
                    setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, unread: next } : r)));
                  }).catch(() => undefined);
                }
              },
              // b196-r6: verified forum join announcements render as a system
              // line (same shape as the member path); never as a raw-JSON bubble.
              onSystem: (info) => {
                const sysMsg: (ChatMessage & { systemNote?: string }) = {
                  id: `sys_${info.envelopeId}`,
                  text: '', mine: false, ts: info.sentAt,
                  systemNote: info.note,
                };
                setChatMessages((prev) => (prev.some((m) => m.id === sysMsg.id) ? prev : [...prev, sysMsg]));
              },
              // Fail-closed lounge policy: forged/unsigned/non-founder rows are
              // logged and discarded — never a user-facing error (the lounge
              // contract is "founder-signed only", not "best effort").
              onSenderVerifyFailed: () => undefined,
            },
          },
        );
        void resL;
      } catch (e) {
        console.error('[veil-lounge] inbox poll failed:', (e as Error).message);
      } finally {
        syncInFlightRef.current[token] = false;
      }
      return;
    }
    const row = sessionRows.find((r) => r.token === token);
    const groupToken = row?.groupToken ?? (groupKnownTokensRef.current[token] ?? undefined);
    if (!groupToken) return;
    // b190: roster polls are gate traffic — during the shared rate-limit
    // quiet window the poll would only burn the budget and re-lock the
    // limiter. The lounge/entityList sync above has its own budget and
    // keeps running.
    if (app.relay.gateHot()) return;
    // b190: a record marked sessionEnded (server-side session gone) never
    // polls again — local history stays readable, the relay is left alone.
    const endedRec = await loadGroupRecord(app.storage, groupToken);
    if (endedRec?.sessionEnded) return;
    if (syncInFlightRef.current[token]) return;
    syncInFlightRef.current[token] = true;
    try {
      const who = await clientId();
      if (!who) return;
      const res = await pollGroupInbox(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
        {
          groupToken,
          // b132: relay-side group burn — this member's own session credential
          // (gate group clause authorises it) so opened envelopes don't sit
          // on the relay at the 24h submit TTL forever.
          sessionToken: token,
          burnAfterOpen: !!sessionDialsRef.current[token]?.burn,
          identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64, pqPrivB64: identity.pqPrivB64 },
          knownIds: groupKnownRef.current,
          events: {
            onMessage: (info) => {
              const msg: (ChatMessage & { sender?: string; senderVerified?: boolean }) = {
                id: info.envelopeId,
                text: info.text,
                mine: false,
                ts: info.sentAt,
                envId: info.envelopeId,
                sender: info.senderNick || (info.senderVeilId ? info.senderVeilId.slice(0, 8) : 'member'),
                senderVerified: info.senderVerified,
                // b131: stamp the burn clock at first live display — without
                // openedAt the burn purge treats the row as never-displayed
                // and it can never burn while the thread stays open.
                openedAt: Date.now(),
                ...(info.media ? { media: { uri: info.media.uri, k: info.media.k, iv: info.media.iv, mime: info.media.mime, name: info.media.name, size: info.media.size, dl: !!info.media.dl } } : {}),
              };
              setChatMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
              app.sessions.cacheMessages(token, [msg]).catch(() => undefined); // b62: group history survives reopen
              if (AppState.currentState !== 'active' || !chatRef.current || chatRef.current.token !== token) {
                notifyNewMessage();
                // b90: group messages landing on a closed thread badge it too
                app.sessions.bumpUnread(token, 1).then((next) => {
                  setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, unread: next } : r)));
                }).catch(() => undefined);
              }
              // read receipts (web parity: group receipts through the group channel)
              if (chatRef.current?.token === token && settings.readReceipts && info.envelopeId) {
                sendGroupReceipt(
                  { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
                  { groupToken, sessionToken: token, clientId: who, ids: [info.envelopeId], read: true },
                ).catch(() => undefined);
              }
            },
            // b123: own-envelope echo — bind the relay envelope id to the
            // locally-sent bubble so group read receipts can tick it (the
            // pairwise path has had envId from submit since day one; group
            // submits never learn it, the poll hands it back here).
            onOwnEcho: (envelopeId, text) => {
              setChatMessages((prev) => {
                const idx = prev.findIndex((m) => m.mine && !m.envId && !m.systemNote && m.text === text);
                if (idx === -1) return prev;
                const next = [...prev];
                next[idx] = { ...next[idx], envId: envelopeId };
                const localId = next[idx].id;
                setTimeout(() => { app.sessions.setCachedEnvId(token, localId, envelopeId).catch(() => undefined); }, 0);
                return next;
              });
            },
            onSystem: (info) => {
              const msg: (ChatMessage & { systemNote?: string }) = {
                id: `sys_${info.envelopeId}`,
                text: '', mine: false, ts: info.sentAt,
                systemNote: info.note,
              };
              setChatMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
            },
            onRead: (readIds) => {
              if (!readIds.length) return;
              setChatMessages((prev) => prev.map((m) => {
                if (!m.mine || !m.envId || !readIds.includes(m.envId)) return m;
                return { ...m, read: true, openedAt: Date.now() }; // b198: burn clock anchors at receipt
              }));
              // b69: group read ticks persist across close/reopen too
              app.sessions.markCachedRead(token, readIds).catch(() => undefined);
            },
            onRotated: (newEpoch) => {
              setGroupInfo((gi) => (gi ? { ...gi, epoch: newEpoch } : gi));
            },
            onSenderVerifyFailed: (envelopeId) => {
              const msg: (ChatMessage & { systemNote?: string }) = {
                id: `sig_${envelopeId}`, text: '', mine: false, ts: new Date().toISOString(),
                systemNote: 'A message was discarded — its signature did not match the roster.',
              };
              setChatMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
            },
            onEpochBehind: ({ groupToken: gt, behindEpoch, localEpoch }) => {
              console.log('[veil-group] device behind group epoch — rejoin required', { group: gt.slice(0, 8), localEpoch, behindEpoch });
              if (groupBehindNoticeRef.current.has(`ep_${gt}`)) return;
              groupBehindNoticeRef.current.add(`ep_${gt}`);
              const msg: (ChatMessage & { systemNote?: string }) = {
                id: `epoch_${gt}_${behindEpoch}`, text: '', mine: false, ts: new Date().toISOString(),
                systemNote: 'This group has moved to a newer key epoch. Messages sent since the rotation cannot be opened on this device, and yours cannot be opened by them — rejoin the group (or the forum) to catch up.',
              };
              setChatMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
            },
            onDecryptFailed: ({ groupToken: gt, err }) => {
              if (groupBehindNoticeRef.current.has(`dec_${gt}`)) return;
              groupBehindNoticeRef.current.add(`dec_${gt}`);
              const msg: (ChatMessage & { systemNote?: string }) = {
                id: `dec_${gt}_${Date.now()}`, text: '', mine: false, ts: new Date().toISOString(),
                systemNote: 'A group message could not be opened on this device. If it keeps happening, this device may be out of step with the group keys — rejoin the group to catch up.',
              };
              setChatMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
            },
          },
        },
      );
      if (res) {
        setGroupInfo((gi) => gi ? { ...gi, members: res.members, fingerprint: res.fingerprint } : gi);
        // creator auto-rotation: 100 envelopes / 24 h per epoch (web parity)
        // b190 (owner Metro log Oct 11: auto-rotate re-fired every 3s poll
        // against a member with no published PQ prekey, each attempt doing
        // identity lookups that kept the relay limiter LOCKED — retry_minutes
        // 6→2 over an hour while nobody even wrote). Two guards: (1) never
        // rotate while the shared rate-limit quiet window is hot; (2) cache
        // the prekey miss on the group record for 15 min so a member who
        // hasn't published a PQ prekey stops triggering lookups entirely.
        const rotRec = await loadGroupRecord(app.storage, groupToken);
        const rotBlockedUntil = Number(rotRec?.rotateBlockedUntil ?? 0);
        if (res.needsRotation && chatRef.current?.token === token
            && !app.relay.gateHot() && Date.now() >= rotBlockedUntil) {
          const main = await findMainGroupSession({ relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL }, groupToken, who);
          if (main) {
            rotateGroup({ relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
              { groupToken, sessionToken: main, clientId: who })
              .then((newEpoch) => {
                setGroupInfo((gi) => (gi ? { ...gi, epoch: newEpoch } : gi));
                setChatMessages((prev) => [...prev, { id: `sys_rot_${newEpoch}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: 'Group keys rotated — new post-quantum epoch.' }]);
              })
              .catch(async (e) => {
                const rmsg = String((e as Error)?.message ?? e);
                if (/no published PQ prekey/i.test(rmsg)) {
                  // persist the 15-min cooldown ONLY onto a real record —
                  // never fabricate one (a missing record is its own problem)
                  const rec2 = await loadGroupRecord(app.storage, groupToken);
                  if (rec2) {
                    await saveGroupRecord(app.storage, { ...rec2, rotateBlockedUntil: Date.now() + 15 * 60_000 });
                  }
                  console.log('[veil-group] auto-rotate: member has no published PQ prekey — rotation cool-down 15 min (member must republish)');
                } else {
                  console.error('[veil-group] auto-rotate failed', e);
                }
              });
          }
        }
      }
      // web parity: ~15% of poll cycles emit a cover envelope (padded to the
      // same buckets, cover flag set — undecryptable filler that masks activity)
      // b190: never while the shared rate-limit quiet window is hot.
      // b197 (audit L-2): VARIABLE-LENGTH cover text (16–48 chars) — a fixed
      // 24-char filler at a fixed probability is trivially fingerprintable by
      // size/periodicity; length jitter makes the cover population blend with
      // real short messages (all still inside the same padded buckets).
      if (!app.relay.gateHot() && Math.random() < 0.15) {
        sendGroupMessage(
          { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
          { groupToken, sessionToken: token, clientId: who, text: Array.from({ length: 16 + Math.floor(Math.random() * 33) }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join(''), cover: true },
        ).catch(() => undefined);
      }
    } catch (e) {
      const pmsg = String((e as Error)?.message ?? e);
      // b190 (owner Metro log Oct 11: veilGroupGate(roster) 404 "Session not
      // found" every poll cycle for a group whose server-side session row is
      // gone — e.g. the deleted pre-rotation test forum). Fail-closed like
      // the b186 DM case: mark the record ended once, stop hammering the
      // relay, and say so once instead of spamming errors every 3s.
      if (/session not found/i.test(pmsg)) {
        const deadRec = await loadGroupRecord(app.storage, groupToken);
        if (deadRec && !deadRec.sessionEnded) {
          await saveGroupRecord(app.storage, { ...deadRec, sessionEnded: true });
          console.log('[veil-group] server-side session is gone — thread marked ended, roster polls stopped (local history kept)');
        }
        // b198 (group ✕ peer-close, founder report: same as the pairwise bug —
        // the member sitting INSIDE the group never saw it close): the pairwise
        // gone-detection effect deliberately excludes groups, so the open
        // thread must be closed HERE, the moment the poll proves the group's
        // server rows are gone. Local history stays readable (b190 semantics).
        if (chatRef.current?.token === token) {
          setChat(null);
          setScreen('main');
          refreshSessions();
          console.log('[veil-group] open thread closed — the group was ended server-side');
        }
      } else {
        console.error('[veil-group] inbox poll failed', e);
      }
    } finally {
      syncInFlightRef.current[token] = false;
    }
  }, [app, identity, settings.readReceipts, sessionRows]);

  // b160 K-4 fix (live-found, Oct 1): re-arm the receipt ledger. A peer
  // message acked as delivery-only (read-receipts dial off, or by the
  // pre-b129 sweep that never reached cached rows) is permanently blocked
  // from ever upgrading to a read receipt — the ledger marks it done and
  // the sweep never re-sends it. Re-arm in two cases:
  //   1. every app launch, per token, once (covers the whole b127-b159 era
  //      where cached backlogs were acked delivery-only or not at all);
  //   2. every read-receipts dial flip OFF->ON (messages read while the
  //      dial was off must be re-acknowledged as read).
  // Cost per re-arm: one bounded receipt burst per thread on next open
  // (<=20 ids per envelope, cached rows only). Ledger rebuilt immediately.
  const receiptRearmedRef = useRef<Set<string>>(new Set());
  const readDialPrevRef = useRef<boolean>(settings.readReceipts);
  useEffect(() => {
    if (!app) return;
    if (settings.readReceipts !== readDialPrevRef.current) {
      // dial flipped: full re-arm (incl. threads re-armed earlier this launch)
      readDialPrevRef.current = settings.readReceipts;
      if (settings.readReceipts) {
        receiptSentRef.current = new Set();
        receiptRearmedRef.current = new Set();
        console.log('[veil-receipt] read-receipts dial switched ON — receipt ledgers re-armed');
      }
    }
    for (const row of sessionRows) {
      const t = row.token;
      if (!t || receiptRearmedRef.current.has(t)) continue;
      receiptRearmedRef.current.add(t);
      void app.sessions.clearReceiptedIds(t).catch(() => undefined);
    }
  }, [app, settings.readReceipts, sessionRows]);

  const openChat = useCallback(async (token: string, title: string, subtitle: string, status: 'pending' | 'active' | 'ended', peerVeilId: string | null = null, myVerified = false, peerVerified = false, groupToken?: string) => {
    if (!app) return;
    // b139 funnel fix: the FIRST REAL relay session opened — emits the
    // first_session_started + activation events once, and unlocks the
    // dismissible "Secure your VEIL" prompt (checkup + app lock) which now
    // never appears before this point.
    try {
      const st = await app.settings.load();
      if (!st.firstSessionDone) {
        const st1 = { ...st, firstSessionDone: true };
        await app.settings.save(st1);
        setSettings(st1);
        if (!st1.setupDone) setSecurePrompt(true);
      }
      await noteFirstSession(app.relay, app.storage);
    } catch { /* instrumentation must never break opening a chat */ }
    // (b67) defense-in-depth: clear any stale global error before showing a
    // chat thread — ChatScreen renders the same shared `error` state other
    // screens use, so a leftover Settings/Contacts error could otherwise
    // appear inside an unrelated conversation.
    setError(null);
    // b187: LOUNGE branch — a listener thread has NO relay session, so every
    // session-store call below (clearUnread/ensureOpenedAt/load) is skipped
    // entirely; the thread lives off the local listener record + msg cache.
    if (token.startsWith('lounge_')) {
      const gt = token.slice('lounge_'.length);
      const rec = groupRecord(app.storage, gt);
      if (!rec || (rec.role !== 'listener' && rec.role !== 'forum-member')) return;
      const historyL = await app.sessions.listMessages(token).catch(() => []);
      groupKnownRef.current = new Set(historyL.map((m) => m.id));
      setChatMessages(historyL);
      setChatKnown(new Set(historyL.map((m) => m.id)));
      setChatLocalNick(null);
      setDraft('');
      setThreadReady(false);
      setVerifyCard(false);
      setGroupInfo(null);
      const isForum = rec.role === 'forum-member';
      setChat({
        token, title: rec.name || 'Lounge',
        subtitle: isForum ? 'Founding testers forum' : 'Founder broadcast · read only',
        status: 'active', peerVeilId: null, canNewThread: false,
        myVerified: true, peerVerified: true, contact: false,
        groupToken: gt, lounge: !isForum, forum: isForum,
      });
      setScreen('chat');
      syncGroupToken(token);
      return;
    }
    // b72: cached rows opened for the first time NOW get their burn clock
    // stamped here (web-parity "burn N hours after open" countdown)
    // b90: opening a thread clears its unread badge (persisted + row state)
    await app.sessions.clearUnread(token);
    setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, unread: 0 } : r)));
    const history = await app.sessions.ensureOpenedAt(token);
    setChatMessages(history);
    // b198 CACHE-RENDER LOOPHOLE: this open IS the human-open moment for every
    // cached peer row still awaiting display. Flip their relay burns (media
    // blobs ride along) and re-anchor their view-burn clocks here — background
    // decrypt had stamped machine time, so cache-rendered messages could
    // vanish "on their own" while the relay copy survived (live-caught with
    // the first post-flip voice message). Idempotent; no-ops on non-burn
    // threads (no pending entries) and on reopens (already-displayed).
    // decrypt-cached rows key the envelope id in `id` (live rows carry `envId`);
    // pendingBurn entries use the envelope id either way, so take both.
    const cacheEnvIds = history.filter((m) => !m.mine).map((m) => (m as { envId?: string }).envId ?? m.id);
    if (cacheEnvIds.length) {
      void markEnvelopesDisplayed(app.relay, app.sessions, token, cacheEnvIds).catch((e) =>
        console.log(`[veil] cache display-mark skipped: ${(e as Error).message ?? e}`));
    }
    const sealedInfo = (await app.sessions.load(token)) as { burnAfterOpen?: boolean; defaultTtlSeconds?: number; expireAfterSeconds?: number; fingerprint?: string | null } | null;
    // b92 F1 (b91 audit): drain strays/desync recorded while this thread was
    // closed — the user sees the same soft notice / one-time Alert the live
    // path would have shown, instead of a silently missing message.
    const pendingStrays = await app.sessions.takePendingStrays(token);
    const pendingDesync = await app.sessions.takePendingDesync(token);
    // b89 (owner burn test: window hit 0, messages stayed): purge rows whose
    // burn clock ran out while the thread was closed — they must not render
    // again on reopen, and must not survive in the plaintext cache.
    // b92 F8 (b91 audit): the expireAfterSeconds tail is GONE from both burn
    // chains — the 24h UNOPENED dial must never masquerade as a burn window;
    // defaultTtlSeconds is captured on every create/join path (7200
    // fallback) so the dial-derived value is the honest one.
    const dials0 = sessionDialsRef.current[token];
    const burnSecs0 = Number(sealedInfo?.defaultTtlSeconds) || Number(dials0?.burnSecs) || 0;
    let history0 = history;
    if ((sealedInfo?.burnAfterOpen ?? dials0?.burn) && burnSecs0 > 0) {
      await app.sessions.purgeBurnedMessages(token, burnSecs0);
      history0 = (await app.sessions.listMessages(token));
    }
    if (pendingStrays > 0) {
      const bgNotice: (ChatMessage & { systemNote?: string }) = {
        id: `stray_bg_${Date.now()}`,
        text: '',
        mine: false,
        ts: new Date().toISOString(),
        systemNote: pendingStrays === 1
          ? 'One message could not be opened on this device; the rest of the conversation is unaffected.'
          : `${pendingStrays} messages could not be opened on this device; the rest of the conversation is unaffected.`,
      };
      history0 = [...history0, bgNotice];
    }
    // b157: drain calls missed while this device was locked (offer held by
    // hold-until-unlock) — same soft-notice pattern as the strays above.
    const missedCalls = await app.sessions.takeMissedCalls(token);
    if (missedCalls && missedCalls.n > 0) {
      const mcNotice: (ChatMessage & { systemNote?: string }) = {
        id: `missedcall_bg_${Date.now()}`,
        text: '',
        mine: false,
        ts: new Date().toISOString(),
        systemNote: missedCalls.n === 1
          ? `Missed call from ${missedCalls.peer} — the call came in while this device was locked or away.`
          : `${missedCalls.n} missed calls from ${missedCalls.peer} — the calls came in while this device was locked or away.`,
      };
      history0 = [...history0, mcNotice];
    }
    if (pendingDesync) {
      desyncPromptedRef.current[token] = true; // one-time, matching the live path
      Alert.alert(
        'Session out of sync',
        'New messages in this thread can no longer be decrypted on this device. End this session and start a new chat thread with the same contact to keep messaging securely.',
      );
    }
    groupKnownRef.current = new Set(history0.map((m) => m.id));
    setChatMessages(history0);
    setChatKnown(new Set(history0.map((m) => m.id)));
    // b123: prefill the rename modal with the peer's device-local nickname
    setChatLocalNick(peerVeilId ? await app.pins.getNickname(peerVeilId) : null);
    setDraft('');
    setThreadReady(!!(await app.sessions.load(token))?.ready);
    // web parity: 'New chat thread with the same person' only for PINNED peers
    const canNewThread = !!(peerVeilId && (await app.pins.getPin(peerVeilId)));
    // b74 BURN-COUNTDOWN FIX (owner report: countdown never renders on
    // native while web shows it): TWO bugs. (1) The window used the WRONG
    // dial — expireAfterSeconds is the "unopened messages expire" dial; the
    // burn-after-open window is defaultTtlSeconds (web's "Burn Nh after
    // opens"). (2) The flag came ONLY from the sealed state — a thread
    // created on the WEB side never wrote burn_after_open through the
    // native join path, so sealedInfo.burnAfterOpen was false/undefined and
    // the countdown silently never rendered. Now: sealed extras first, then
    // the relay record's dials (stashed by refreshSessions).
    const dials = sessionDialsRef.current[token];
    const burnOn = sealedInfo?.burnAfterOpen ?? dials?.burn ?? false;
    const burnSecs = Number(sealedInfo?.defaultTtlSeconds) || dials?.burnSecs || 0;
    // b163 (web P1.2 parity): key change revokes prior confirmation — if the
    // peer's CURRENT published identity key no longer matches the pinned one,
    // this thread's ceremony flags are treated as revoked and the gate
    // re-engages. Lookup failures never brick the thread (skip the check).
    let myV = myVerified;
    let peerV = peerVerified;
    if ((sessionContactRef.current[token] ?? false) && peerVeilId) {
      try {
        const pin = await app.pins.getPin(peerVeilId);
        if (pin) {
          const lr = await app.relay.identityLookup(peerVeilId);
          const pub = ((lr.data as { data?: Record<string, string> })?.data ?? (lr.data as Record<string, string>)) || null;
          if (pub?.IK_pub && pub?.SPK_pub && pub?.SPK_sig) {
            const trust = await app.pins.verifyPeerPrekeys(peerVeilId, { IK_pub: pub.IK_pub, SPK_pub: pub.SPK_pub, SPK_sig: pub.SPK_sig });
            if (!trust.trusted) {
              myV = false; peerV = false;
              console.log(`[veil] pin identity mismatch on ${token} — ceremony confirmation revoked (${trust.reason})`);
            }
          }
        }
      } catch { /* relay hiccup: keep existing flags */ }
    }
    // b95/b163 (owner decisions Sept 21 + Oct 2): show the verify card ONCE
    // per unverified pairwise thread — contact threads included now that the
    // ceremony is the gate. Groups surface epoch fingerprints in their sheet.
    let vcard = false;
    if (!myV && !groupToken && status === 'active') {
      try {
        const raw = await app.storage.get('veil_vcard_dismissed');
        const dis = raw ? (JSON.parse(raw) as string[]) : [];
        vcard = !dis.includes(token);
      } catch { vcard = true; }
    }
    setVerifyCard(vcard);
    // b126: fingerprint + pin state travel with the open chat so the
    // verification panel can show them (fingerprint now viewable post-verify).
    const peerPinned = !!(peerVeilId && (await app.pins.getPin(peerVeilId)));
    setChat({ token, title, subtitle, status, peerVeilId, canNewThread, myVerified: myV, peerVerified: peerV, fingerprint: sealedInfo?.fingerprint ?? null, peerPinned, contact: sessionContactRef.current[token] ?? false,
      ...(groupToken ? { groupToken } : {}),
      ...(burnOn ? { burnAfterOpen: true, burnSeconds: burnSecs || 86400 } : {}) });
    setScreen('chat');
    if (groupToken) {
      groupKnownTokensRef.current[token] = groupToken;
      const rec = groupRecord(app.storage, groupToken);
      setGroupInfo(rec ? { isCreator: rec.role === 'creator', epoch: rec.epoch, fingerprint: null, members: [] } : null);
      syncGroupToken(token);
    } else {
      setGroupInfo(null);
      syncToken(token);
    }
    const who = await clientId();
    // b197-r6 (lag fix): activate used to fire on EVERY openChat — including
    // repeat opens of the same thread and the supersede auto-switch — each a
    // relay round trip that mostly returned 404/role rejections (owner log:
    // continuous activate spam while the limiter was hot). Once per token per
    // run is enough: activation is idempotent server-side.
    if (who && status === 'active' && !activatedOnceRef.current.has(token)) {
      activatedOnceRef.current.add(token);
      await app.relay.sessionActivate(token, (await app.sessions.load(token))?.writeSecret ?? null).catch(() => undefined);
    }
  }, [app, syncToken, syncGroupToken]);

  // b164: mirror so earlier-in-file callbacks (handleMessage, the b88
  // supersession switch) always run the CURRENT openChat closure.
  useEffect(() => { openChatRef.current = openChat; }, [openChat]);

  const handleOpenSession = useCallback(async (token: string) => {
    if (!app) return;
    const row = sessionRows.find((r) => r.token === token);
    await openChat(token, row?.title ?? 'Session', row?.subtitle ?? '', row?.status ?? 'pending', row?.peerVeilId ?? null, !!row?.myVerified, !!row?.peerVerified, row?.groupToken);
  }, [app, sessionRows, openChat]);

  // live poll: sync the open pane every 3s until ended/back
  useEffect(() => {
    if (!identity || !app) return;
    // contentless pings — register token with the relay, zero metadata on the wire
    try {
      Promise.resolve(registerPushToken({
        entityCreate: (e, r) => app.relay.entityCreate(e, r),
        entityList: (e, p) => app.relay.entityList(e, p),
        getCached: (k) => app.storage.get(k),
        setCached: (k, v) => app.storage.set(k, v),
      })).catch(() => undefined);
    } catch { /* push registration must never crash the app */ }
  }, [identity, app]);

  // keep refs for the foreground/push re-poll hooks
  // b84: stamp the moment a thread is (re)opened so the syncToken banner gate
  // can suppress the banner during the unlock-resume race window.
  if (chat?.token && chatRef.current?.token !== chat.token) {
    chatOpenedAtRef.current = Date.now();
  }
  chatRef.current = chat;
  syncTokenRef.current = syncToken;
  backgroundSyncAllSessionsRef.current = backgroundSyncAllSessions;
  // b198: the routers (push + foreground-resume) need the GROUP-aware sync —
  // running the pairwise syncChat against a group session fetched its group
  // envelopes and decrypt-failed them into a false desync banner.
  const syncRouterRef = useRef<(token: string) => void>((t) => { syncTokenRef.current(t); });
  syncRouterRef.current = (token: string) => {
    if (chatRef.current?.groupToken) syncGroupToken(chatRef.current.token);
    else syncTokenRef.current(token);
  };

  // ONE poll loop per open thread — covers BOTH jobs (accept detection via
  // advanceHandshake and envelope fetch via syncChat; syncToken already
  // branches on readiness internally). Previously this was two separate
  // intervals (3s + 1.5s) calling the identical logic; since 3000 is a
  // multiple of 1500 they routinely fired together and BOTH decrypted the
  // same new envelope before either call's ratchet-state save landed —
  // that double-decrypt is exactly the "everything arrives twice" bug. The
  // syncInFlightRef mutex above is the backstop against any remaining
  // overlap (foreground/push triggers can still coincide with a tick).
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    if (chat.groupToken) {
      const iv = setInterval(() => { syncGroupToken(chat.token); }, 3000);
      return () => clearInterval(iv);
    }
    const iv = setInterval(() => { syncToken(chat.token); }, threadReady ? 1500 : 3000);
    return () => clearInterval(iv);
  }, [screen, chat, threadReady, syncToken, syncGroupToken]);

  // re-poll on app foreground (returning to the thread pulls immediately)
  useEffect(() => {
    const sub = AppState.addEventListener('change', (st) => {
      // b198: route through the group-aware sync router (a group thread must
      // never be pairwise-synced — see syncRouterRef).
      if (st === 'active' && chatRef.current) syncRouterRef.current(chatRef.current.token);
    });
    return () => sub.remove();
  }, []);

  // re-poll on contentless push (the ping carries no content by design)
  // b77 FIX: previously only re-synced the currently open thread — a push
  // caused by a message on ANY OTHER session did nothing but refresh
  // metadata, so it was never decrypted and never triggered a local banner.
  // Now every non-open session gets checked too.
  useEffect(() => {
    const sub = Notifications.addNotificationReceivedListener(() => {
      // b198: group-aware router (pushes now fire for group messages too —
      // pairwise-syncing the group session here caused the false desync banner).
      if (chatRef.current) syncRouterRef.current(chatRef.current.token);
      refreshSessions();
      backgroundSyncAllSessionsRef.current();
    });
    return () => sub.remove();
  }, [refreshSessions]);

  /**
   * Media receive path (web loader parity): vaultFileSignedUrl → fetch →
   * AES-GCM decrypt with the payload's key/iv → in-memory data: URI for the
   * RN Image. Resolved once per message per open; never written to disk.
   */
  const resolveMedia = useCallback(async (token: string, msgId: string, media: NonNullable<ChatMessage['media']>) => {
    if (mediaInFlight.current[msgId]) return;
    const already = mediaLoad[msgId];
    // b73 FIX (owner report "voice notes viewable but not playable on
    // receive"): audio/video NEED the cache file to play (expo-av refuses
    // data: URIs on iOS — silently, no error, no crash, just a dead ▶). The
    // old guard treated the dataUri fallback as "resolved" forever, so a
    // single cache-write hiccup on the receive path left the note stuck in
    // an unplayable state with no retry. Now: images are done once `uri` is
    // set; audio/video are only done once the actual playable `fileUri` is set.
    const isAv = (media.mime || '').startsWith('audio/') || (media.mime || '').startsWith('video/');
    if (isAv ? already?.fileUri : already?.uri) return;
    if (!app) return;
    mediaInFlight.current[msgId] = true;
    setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: true } }));
    try {
      const bytes = await loadMediaFile(app.relay, app.sessions, token, media);
      const mime = media.mime || 'application/octet-stream';
      const dataUri = `data:${mime};base64,${toB64(bytes)}`;
      // b62: expo-av can't play data: URIs — video/voice notes also get a
      // decrypted cache file (deleted with the app's cache, never synced).
      // b73: retry the write once (transient FS errors) and surface a real
      // error state (with retry) instead of silently degrading to the
      // unplayable data: URI when it still fails.
      let fileUri: string | null = null;
      if (isAv) {
        const ext = mime === 'audio/mp4' ? 'm4a' : (mime.split('/')[1]?.split(';')[0] || 'bin');
        const target = `${FileSystem.cacheDirectory}veil-av-${msgId}.${ext}`;
        const b64 = toB64(bytes);
        for (let attempt = 0; attempt < 2 && !fileUri; attempt++) {
          try {
            await FileSystem.writeAsStringAsync(target, b64, { encoding: FileSystem.EncodingType.Base64 });
            const info = await FileSystem.getInfoAsync(target);
            if (info.exists && info.size > 0) fileUri = target;
            else throw new Error('cache file wrote empty/missing');
          } catch (e) {
            console.log(`[veil-av] cache file write attempt ${attempt + 1}/2 failed:`, String(e));
          }
        }
        if (!fileUri) {
          setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: false, error: 'Voice/video note failed to cache for playback — tap to retry' } }));
          return;
        }
      }
      setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: false, uri: dataUri, fileUri: fileUri ?? undefined } }));
    } catch (e) {
      console.error(`[veil] media ${msgId} failed to load: ${(e as Error).message ?? e}`);
      setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: false, error: String((e as Error).message || e) } }));
    } finally {
      mediaInFlight.current[msgId] = false;
    }
  }, [app, mediaLoad]);

  // auto-resolve media messages in the open thread
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    for (const m of chatMessages) {
      if (!m.media) continue;
      if (m.media.localUri && m.mine) continue; // sender has the plaintext already
      const st = mediaLoad[m.id];
      const isAv = (m.media.mime || '').startsWith('audio/') || (m.media.mime || '').startsWith('video/');
      const resolved = isAv ? st?.fileUri : st?.uri;
      if (resolved || st?.loading || st?.error) continue; // b73: error state waits for an explicit retry tap
      resolveMedia(chat.token, m.id, m.media);
    }
  }, [screen, chat, chatMessages, mediaLoad, resolveMedia]);

  /**
   * b62 voice notes (site parity): tap the mic to record an encrypted voice
   * note — m4a (AAC) straight into the same E2EE media pipeline as photos.
   */
  const handleVoiceRecord = useCallback(async () => {
    if (voiceRec.active) return;
    try {
      Keyboard.dismiss();
      if (voiceRecRef.current) { try { voiceRecRef.current.stopAndUnloadAsync(); } catch { /* stale */ } voiceRecRef.current = null; }
      const perm = await Audio.requestPermissionsAsync();
      if (!perm.granted) throw new Error('Microphone permission was not granted.');
      try { await Audio.setAudioModeAsync({ allowsRecordingIOS: true, playsInSilentModeIOS: true }); } catch { /* mode best-effort */ }
      const rec = new Audio.Recording();
      await rec.prepareToRecordAsync(Audio.RecordingOptionsPresets.HIGH_QUALITY);
      await rec.startAsync();
      voiceRecRef.current = rec;
      voiceTickRef.current = setInterval(() => setVoiceRec((r) => ({ ...r, seconds: r.seconds + 1 })), 1000);
      setVoiceRec({ active: true, seconds: 0 });
      console.log('[veil-voice] recording started');
    } catch (e) {
      console.log('[veil-voice] record start failed:', String(e));
      setError(friendlyError(e, 'voice-start'));
      setVoiceRec({ active: false, seconds: 0 });
    }
  }, [voiceRec.active]);

  const handleVoiceCancel = useCallback(() => {
    try { voiceRecRef.current?.stopAndUnloadAsync(); } catch { /* already stopped */ }
    voiceRecRef.current = null;
    if (voiceTickRef.current) { clearInterval(voiceTickRef.current); voiceTickRef.current = null; }
    setVoiceRec({ active: false, seconds: 0 });
  }, []);

  const handleVoiceSend = useCallback(async () => {
    if (!voiceRec.active) return;
    let uri: string | null = null;
    let durationMs = 0;
    try {
      const rec = voiceRecRef.current;
      if (!rec) throw new Error('Recorder is not running.');
      // capture duration BEFORE stopping (status is invalid after unload)
      const status = await rec.getStatusAsync().catch(() => null);
      durationMs = (status as { durationMillis?: number } | null)?.durationMillis ?? 0;
      await rec.stopAndUnloadAsync();
      uri = rec.getURI() ?? null;
      voiceRecRef.current = null;
      if (voiceTickRef.current) { clearInterval(voiceTickRef.current); voiceTickRef.current = null; }
      setVoiceRec({ active: false, seconds: 0 });
      if (!uri) throw new Error('Recording produced no file — please try again.');
      const secs = Math.max(1, Math.round(durationMs / 1000), voiceRecStateSecondsRef.current);
      const name = `voice-note-${new Date().toISOString().slice(11, 19).replace(/:/g, '')}.m4a`;
      // file size checked at send time against the 100 MB cap (voice is far under)
      setPendingPick({ uri, name, mime: 'audio/mp4', size: 0, voiceSeconds: secs });
    } catch (e) {
      console.log('[veil-voice] send failed:', String(e));
      setError(friendlyError(e, 'voice-send'));
      handleVoiceCancel();
    }
  }, [voiceRec.active]);

  const handleAttach = useCallback(async () => {
    // dismiss the composer keyboard before doing anything else — otherwise the
    // preview overlay (or the native picker itself) can render underneath/behind
    // it, cutting off the Cancel/Send buttons (build 26 bug: box stayed up and
    // obstructed the send button after typing then tapping attach).
    Keyboard.dismiss();
    try {
      // DIAGNOSTICS (build 25 hot-patch): log everything so Metro shows exactly
      // what the picker returns on this device; surface empty results on screen
      // instead of silently returning to chat.
      let perm: ImagePicker.PermissionResponse | undefined;
      try {
        perm = await ImagePicker.getMediaLibraryPermissionsAsync();
        console.log('[veil-media] photo permission:', JSON.stringify(perm));
      } catch { /* permission check is informational only */ }
      const res = await ImagePicker.launchImageLibraryAsync({
        // b62: images AND videos (site claims video; the send pipeline is
        // mime-generic E2EE bytes, so video needed only picker + render work)
        mediaTypes: ['images', 'videos'] as ImagePicker.MediaType[],
        quality: 0.8,
        allowsMultipleSelection: false,
        selectionLimit: 1,
        exif: false,
      });
      const safe: unknown = JSON.parse(JSON.stringify(res, (k, v) => (k === 'base64' ? '[omitted]' : v)));
      console.log('[veil-media] picker result:', JSON.stringify(safe));
      if (res.canceled || !res.assets?.length) {
        // b110: keep raw diagnostics in the console log above (Metro-only);
        // the on-screen banner must never show internal state to the user.
        console.log('[veil-media] empty pick:', JSON.stringify({ canceled: res.canceled, assets: res.assets?.length ?? 0, permission: perm?.status ?? 'unknown' }));
        setError('No photo or video was selected — tap the attach button to try again.');
        return;
      }
      const a = res.assets[0];
      if (!a?.uri) {
        setError('The picker returned media with no file path — please try a different file.');
        return;
      }
      console.log('[veil-media] asset ok:', JSON.stringify({ uri: a.uri, name: a.fileName, mime: a.mimeType, size: a.fileSize }));
      Keyboard.dismiss();
      setPendingPick({ uri: a.uri, name: a.fileName ?? 'media', mime: a.mimeType ?? 'image/jpeg', size: a.fileSize ?? 0 });
      console.log('[veil-media] pendingPick SET — preview modal should now be visible');
    } catch (e) {
      const msg = `${(e as Error).message ?? e}`;
      console.log('[veil-media] picker error:', msg);
      setError(friendlyError(e, 'photo-picker'));
    }
  }, []);

  const handleCancelPick = useCallback(() => setPendingPick(null), []);

  /**
   * Save-to-Photos (web download parity, gated on the sender's dl flag):
   * the already-decrypted in-memory bytes go to a temp cache file, then
   * MediaLibrary adds it to Photos (add-only permission); the temp copy
   * is deleted immediately after. Plaintext never persists in-app.
   */
  const handleMediaSave = useCallback(async (msgId: string) => {
    const entry = mediaLoad[msgId];
    const orig = chatMessages.find((m) => m.id === msgId);
    const dataUri = entry?.uri;
    if (!dataUri?.startsWith('data:') || !orig?.media) return;
    setMediaSaving((prev) => ({ ...prev, [msgId]: 'saving' }));
    let tmp: string | null = null;
    try {
      // b92 F14 (b91 audit): full Photos access (NOT write-only) so the
      // duress purge can delete what the app saves — write-only saves
      // survived a duress wipe.
      const perm = await MediaLibrary.requestPermissionsAsync(false);
      if (!perm.granted) throw new Error('Photos permission was not granted.');
      const b64 = dataUri.slice(dataUri.indexOf(',') + 1);
      const mime = orig.media.mime || 'image/jpeg';
      const ext = mime.split('/')[1]?.split(';')[0] || 'jpg';
      tmp = `${FileSystem.cacheDirectory}veil-save-${Date.now()}.${ext}`;
      await FileSystem.writeAsStringAsync(tmp, b64, { encoding: FileSystem.EncodingType.Base64 });
      await MediaLibrary.saveToLibraryAsync(tmp);
      setMediaSaving((prev) => ({ ...prev, [msgId]: 'saved' }));
    } catch (e) {
      console.error('[veil-media] save failed:', (e as Error).message ?? e);
      setMediaSaving((prev) => ({ ...prev, [msgId]: 'error' }));
    } finally {
      if (tmp) FileSystem.deleteAsync(tmp, { idempotent: true }).catch(() => undefined);
    }
  }, [mediaLoad, chatMessages]);

  const handleSendMedia = useCallback(async () => {
    if (!app || !chat || !pendingPick) return;
    // b163: pairwise media sends are behind the ceremony gate too (text parity).
    if (!chat.groupToken && !(chat.myVerified && chat.peerVerified)) return;
    // b187/b188: lounge + forum threads are text-only for now (media lands
    // with the P1 group-signature pass); both gates stay enforced.
    if (chat.lounge || chat.forum) return;
    const who = await clientId();
    if (!who) return;
    setBusy(true); setError(null);
    try {
      if (chat.groupToken) {
        const b64g = await FileSystem.readAsStringAsync(pendingPick.uri, { encoding: FileSystem.EncodingType.Base64 });
        const bytesG = Uint8Array.from(atob(b64g), (c) => c.charCodeAt(0));
        const sizeG = pendingPick.size || bytesG.byteLength;
        if (sizeG > MEDIA_LIMIT_BYTES) throw new Error('Media is limited to 100 MB per message.');
        const r = await sendGroupMediaMessage(
          { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
          {
            groupToken: chat.groupToken, sessionToken: chat.token, clientId: who,
            media: { bytes: bytesG, name: pendingPick.name, mime: pendingPick.mime, size: sizeG, dl: allowDl },
            localUri: pendingPick.uri,
            uploadCiphertext: async (ct) => {
              const ctFile = `${FileSystem.cacheDirectory}veil-media-${Date.now()}.bin`;
              await FileSystem.writeAsStringAsync(ctFile, toB64(ct), { encoding: FileSystem.EncodingType.Base64 });
              try {
                return await app.relay.uploadPrivateFile({ uri: ctFile, name: 'veil-media' });
              } finally {
                FileSystem.deleteAsync(ctFile, { idempotent: true }).catch(() => undefined);
              }
            },
          },
        );
        setChatMessages((prev) => [...prev, { id: r.id, text: '', mine: true, ts: new Date().toISOString(), sender: 'You', media: { ...r.media, localUri: pendingPick.uri } }]); // b198: no send-time burn clock on own media — anchors at receipt
        setPendingPick(null);
        setError(null); // b180: success clears the banner
        syncGroupToken(chat.token);
        return;
      }
      const ready = await advanceHandshake(chat.token, who);
      if (!ready) throw new Error('Waiting for your contact to accept — messaging unlocks the moment they join.');
      const b64 = await FileSystem.readAsStringAsync(pendingPick.uri, { encoding: FileSystem.EncodingType.Base64 });
      const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      const size = pendingPick.size || bytes.byteLength;
      if (size > MEDIA_LIMIT_BYTES) throw new Error('Media is limited to 100 MB per message.');
      // RN networking: upload the CIPHERTEXT as a cache-file FormData part (the
      // guaranteed file:// path) — encryption happens inside sendMediaMessage
      const msg = await sendMediaMessage(
        app.relay, app.sessions, chat.token, who,
        { bytes, name: pendingPick.name, mime: pendingPick.mime, size, dl: allowDl },
        pendingPick.uri, // instant local preview, never transmitted
        undefined, // web contract: per-envelope TTL 3600 (live bundle send path)
        async (ct) => {
          const ctFile = `${FileSystem.cacheDirectory}veil-media-${Date.now()}.bin`;
          await FileSystem.writeAsStringAsync(ctFile, toB64(ct), { encoding: FileSystem.EncodingType.Base64 });
          try {
            return await app.relay.uploadPrivateFile({ uri: ctFile, name: 'veil-media' });
          } finally {
            FileSystem.deleteAsync(ctFile, { idempotent: true }).catch(() => undefined);
          }
        },
      );
      setChatMessages((prev) => [...prev, msg]);
      setChatKnown((prev) => new Set([...prev, msg.id]));
      setPendingPick(null);
      setError(null); // b180: success clears the banner
      syncToken(chat.token);
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, chat, pendingPick, syncToken, advanceHandshake, allowDl]);

  useEffect(() => {
    chatOpenRef.current = screen === 'chat' && chat ? chat.token : null;
    // b74: group threads need their own capture-notice path — the 1:1
    // advanceHandshake misreads group session rows (they never carry the
    // responder_* fields it looks for) and returns "not ready" even while
    // the group chat is actively exchanging messages.
    chatOpenGroupRef.current = screen === 'chat' && chat ? chat.groupToken ?? null : null;
  }, [screen, chat]);

  /**
   * b61→b70: screenshot / screen-recording watch. iOS cannot block a
   * screenshot — the ONLY real mitigation on the platform — so this fires the
   * instant one happens; if a conversation is open, VEIL sends the other party
   * an E2EE notice (the honest deterrent), regardless of dial state.
   */
  useEffect(() => {
    if (!app) return;
    let lastNoticeAt = 0;
    const stop = startScreenWatch((ev) => {
      const isShot = ev.kind === 'screenshot';
      if (!isShot && !(ev.kind === 'recording' && ev.captured === true)) return;
      const token = chatOpenRef.current;
      if (!token) { console.log('[veil-capture] event fired but no chat open — nothing to notify'); return; }
      if (lockedRef.current) { console.log('[veil-capture] skipped: app locked'); return; }
      if (decoyModeRef.current) { console.log('[veil-capture] skipped: decoy mode'); return; }
      const now = Date.now();
      if (now - lastNoticeAt < 5000) return; // OS can burst-fire; one notice per 5 s
      lastNoticeAt = now;
      const text = isShot
        ? '⚠ A screenshot was taken while this conversation was open.'
        : '⚠ Screen recording was detected while this conversation was open.';
      void (async () => {
        try {
          const who = await clientId();
          if (!who) { console.log('[veil-capture] notice skipped: no clientId'); return; }
          // b74 FIX (owner report: screenshot on a WORKING chat logged
          // "handshake not ready"): the old path only knew 1:1 sessions —
          // on a GROUP thread, advanceHandshake's slow path looks for
          // responder_* fields that group rows never carry, so it returned
          // false and silently skipped the notice on an actively-working
          // chat. Groups now go through the group send path (same dispatch
          // as handleSend); readiness rides the group ratchet itself.
          const groupToken = chatOpenGroupRef.current;
          if (groupToken) {
            // b189 FIX (MissionControl: capture notices failed silently in
            // forum threads): forum threads use lounge_<group> tokens and a
            // forum member has NO classic group session — the old path called
            // sendGroupMessage with the lounge token, which threw and died in
            // the catch below (silent failure). Route forum threads through
            // the member's own posting session (same dispatch as handleSend);
            // read-only lounge threads honestly log that no notice can go out.
            if (token.startsWith('lounge_')) {
              const rec = await loadGroupRecord(app.storage, groupToken);
              if (rec?.role !== 'forum-member') {
                console.log('[veil-capture] read-only lounge thread — no notice can be sent (listener cannot post)');
                return;
              }
              await sendForumMessage(
                { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
                { groupToken, clientId: who, text },
              );
              const capMsgF: (ChatMessage & { sender?: string; systemNote?: string }) = { id: `local_capture_${Date.now()}`, text, mine: true, ts: new Date().toISOString(), sender: 'You', openedAt: Date.now(), systemNote: undefined };
              setChatMessages((prev) => [...prev, capMsgF]);
              app.sessions.cacheMessages(token, [capMsgF]).catch(() => undefined);
              console.log('[veil-capture] forum notice sent (group', groupToken.slice(0, 8) + '…)');
              return;
            }
            await sendGroupMessage(
              { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
              { groupToken, sessionToken: token, clientId: who, text },
            );
            const capMsg: (ChatMessage & { sender?: string; systemNote?: string }) = { id: `local_capture_${Date.now()}`, text, mine: true, ts: new Date().toISOString(), sender: 'You', openedAt: Date.now(), systemNote: undefined }; // b131: burn clock on capture notices
            setChatMessages((prev) => [...prev, capMsg]);
            app.sessions.cacheMessages(token, [capMsg]).catch(() => undefined); // b123: survives reopen
            console.log('[veil-capture] group notice sent (group', groupToken.slice(0, 8) + '…)');
            return;
          }
          const ready = await advanceHandshakeRef.current(token, who);
          if (!ready) { console.log('[veil-capture] notice skipped: handshake not ready (pending thread)'); return; }
          const msg = await sendChatMessage(app.relay, app.sessions, token, who, text);
          setChatMessages((prev) => [...prev, msg]);
          setChatKnown((prev) => new Set([...prev, msg.id]));
          console.log('[veil-capture] notice sent, envId:', msg.envId ?? '(none)');
        } catch (e) {
          // b73 (owner report: screenshot detected in Metro logs but the
          // peer notice never appeared): this catch used to be silent —
          // "best effort" hid the real failure. A desynced ratchet on this
          // thread throws right here on encrypt/send, same class as the
          // known "Message counter out of range" bug — now logged instead
          // of swallowed so the next repro tells us which it is.
          console.log('[veil-capture] notice FAILED to send:', String((e as Error).message ?? e));
        }
      })();
    });
    return () => { stop?.(); };
  }, [app]);

  const handleSend = useCallback(async () => {
    if (!app || !chat || !draft.trim()) return;
    // b187: read-only lounge threads — composer locked; enforced gate.
    if (chat.lounge) return;
    // b188: forum threads — every member posts via their own posting session.
    if (chat.forum && chat.groupToken) {
      const whoF = await clientId();
      if (!whoF) return;
      setBusy(true); setError(null);
      try {
        await sendForumMessage(
          { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
          { groupToken: chat.groupToken, clientId: whoF, text: draft.trim() },
        );
        const now = new Date().toISOString();
        const mineF: (ChatMessage & { sender?: string }) = { id: `local_${Date.now()}`, text: draft.trim(), mine: true, ts: now, sender: 'You' };
        setChatMessages((prev) => [...prev, mineF]);
        app.sessions.cacheMessages(chat.token, [mineF]).catch(() => undefined);
        setDraft('');
      } catch (e) {
        console.log('[veil] forum send FAILED:', String((e as Error).message || e), '\n', (e as Error).stack);
        setError(String((e as Error).message || e));
      } finally { setBusy(false); }
      return;
    }
    // b163 (web P1.2 parity): the composer lock is UX — this is the enforced
    // gate on every pairwise user-content send path. Groups are exempt.
    if (!chat.groupToken && !(chat.myVerified && chat.peerVerified)) return;
    const who = await clientId();
    if (!who) return;
    setBusy(true);
    // b180 (owner report: "server is briefly busy" banner never clears
    // until you exit the thread): clear any stale error from a previous
    // failed send BEFORE the new attempt — a banner that outlives its
    // cause is a lie on screen.
    setError(null);
    try {
      if (chat.groupToken) {
        await sendGroupMessage(
          { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
          { groupToken: chat.groupToken, sessionToken: chat.token, clientId: who, text: draft.trim() },
        );
        const now = new Date().toISOString();
        const mineMsg: (ChatMessage & { sender?: string }) = { id: `local_${Date.now()}`, text: draft.trim(), mine: true, ts: now, sender: 'You' }; // b198: own group sends get no send-time burn clock — anchors at receipt
        setChatMessages((prev) => [...prev, mineMsg]);
        // b123: my own group sends now land in the history cache too (b62
        // gap — reopen previously dropped MY side of group threads) and the
        // own-echo path above binds envId onto this cached copy.
        app.sessions.cacheMessages(chat.token, [mineMsg]).catch(() => undefined);
        setDraft('');
        setError(null); // b180: success clears the banner, not just back-nav
        syncGroupToken(chat.token);
        return;
      }
      const ready = await advanceHandshake(chat.token, who);
      if (!ready) throw new Error('Waiting for your contact to accept — messaging unlocks the moment they join.');
      const msg = await sendChatMessage(app.relay, app.sessions, chat.token, who, draft.trim());
      setChatMessages((prev) => [...prev, msg]);
      setChatKnown((prev) => new Set([...prev, msg.id]));
      setDraft('');
      setError(null); // b180: success clears the banner
      syncToken(chat.token);
    } catch (e) {
      setChat((c) => c); // keep pane; error surfaces below composer
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, chat, draft, syncToken, syncGroupToken, advanceHandshake]);

  // b62 groups: create + admin (creator-only rotate / evict)
  const handleCreateGroup = useCallback(async (groupName: string, inviteCount: number): Promise<{ groupName: string; inviteLinks: string[] }> => {
    if (!app || !identity) throw new Error('Create your Veil identity first — Settings → Identity.');
    const who = await clientId();
    if (!who) throw new Error('Sign in first.');
    const name = groupName.trim().slice(0, 40);
    if (!name) throw new Error('Give the group a name.');
    const n = Math.max(1, Math.min(inviteCount, GROUP_MEMBER_CAP - 1));
    const created = await createGroup(
      { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
      {
        identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64, pqPrivB64: identity.pqPrivB64 },
        groupName: name,
        inviteCount: n,
        clientId: who,
        dials: {
          burnAfterOpen: settings.burnTtlSeconds > 0,
          expireAfterSeconds: settings.expireAfterSeconds,
          keyRetentionHours: settings.retentionHours,
          // b92 F-S6 (settings sweep, live-confirmed on relay rows created
          // 20:55 Sept 20): was hardcoded 3600 — the burn dial silently
          // became a 1-hour burn window on every invite-link + group thread.
          defaultTtlSeconds: settings.burnTtlSeconds,
        },
      },
    );
    await refreshSessions();
    return { groupName: created.groupName, inviteLinks: created.inviteLinks };
  }, [app, identity, settings.burnTtlSeconds, settings.expireAfterSeconds, settings.retentionHours, refreshSessions]);

  const groupMainSession = useCallback(async (): Promise<string> => {
    if (!app || !chat?.groupToken) throw new Error('No group open.');
    const who = await clientId();
    if (!who) throw new Error('Sign in first.');
    const main = await findMainGroupSession(
      { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
      chat.groupToken, who,
    );
    if (!main) throw new Error('This device cannot administer the group (creator session missing).');
    return main;
  }, [app, chat]);

  const handleRotateGroup = useCallback(async (): Promise<void> => {
    if (!app) return;
    setGroupBusy(true);
    try {
      const main = await groupMainSession();
      const who = await clientId();
      if (!who) return;
      const newEpoch = await rotateGroup(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
        { groupToken: chat!.groupToken!, sessionToken: main, clientId: who },
      );
      setGroupInfo((gi) => (gi ? { ...gi, epoch: newEpoch } : gi));
      setChatMessages((prev) => [...prev, { id: `sys_rot_${newEpoch}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: 'Group keys rotated — new post-quantum epoch.' }]);
    } catch (e) {
      setError(friendlyError(e, 'action'));
      throw e;
    } finally { setGroupBusy(false); }
  }, [app, chat, groupMainSession]);

  const handleEvictMember = useCallback(async (member: { veilId: string; ikPub: string }): Promise<void> => {
    if (!app || !chat?.groupToken) return;
    setGroupBusy(true);
    try {
      const main = await groupMainSession();
      const who = await clientId();
      if (!who) return;
      await evictGroupMember(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
        { groupToken: chat.groupToken, sessionToken: main, target: member },
      );
      // web parity: eviction is followed immediately by a key rotation so the
      // evicted member cannot read future messages
      const newEpoch = await rotateGroup(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_BASE_URL },
        { groupToken: chat.groupToken, sessionToken: main, clientId: who },
      );
      setGroupInfo((gi) => (gi ? { ...gi, epoch: newEpoch } : gi));
      setChatMessages((prev) => [...prev, { id: `sys_evict_${Date.now()}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: 'A member was removed and the group keys rotated.' }]);
    } catch (e) {
      setError(friendlyError(e, 'action'));
      throw e;
    } finally { setGroupBusy(false); }
  }, [app, chat, groupMainSession]);

  const handleEndSession = useCallback(async () => {
    if (!app || !chat) return;
    if (chat.groupToken) {
      // (b67) owner request: ✕ must delete group threads too. Groups have no
      // relay "end" — deleting the local group record removes the thread from
      // the list; the underlying main session is ended best-effort server-side.
      setBusy(true);
      try {
        const who = (await clientId()) ?? undefined;
        // b194 (owner repro Oct 12: ✕ on the forum thread ended EVERY relay
        // row tagged with the group — including the shared invite session the
        // hosted descriptor points to, and the gate's group-keyed envelope
        // purge wiped the whole 30-day backlog. One member leaving must never
        // take down the group's front door for 305 testers). Forum threads:
        // end ONLY this device's own posting session — the thread is driven
        // by the local group record, so forgetting it cannot resurrect.
        // Classic groups keep the full b132 sweep below.
        const forumRec = (await loadGroupRecord(app.storage, chat.groupToken)) as
          | ({ role?: string; postingSessionToken?: string })
          | null;
        const forumRole = String(forumRec?.role ?? '');
        if (forumRole.startsWith('forum')) {
          // b196-r1 (owner repro Oct 12: "✕ the forum, it keeps coming back"):
          // b194 scoped the end to the device's own posting session but passed
          // chat.token — the local lounge_* handle, which is NOT a relay row,
          // so sessionEnd was a silent no-op. The founder posting session
          // (group-tagged, owned by this account) survived and refreshSessions
          // rebuilt the thread row from it on every refresh. End the REAL
          // posting session while we still hold its credentials (they live in
          // the sealed ratchet + group record, both destroyed below), then
          // forget. The shared invite session (front door) is never touched —
          // b194's rule stands.
          const pst = String(forumRec?.postingSessionToken ?? '');
          if (pst) {
            const pws = (await app.sessions.load(pst))?.writeSecret ?? null;
            let ended = false;
            // b196-r3: the r1 fix was fire-and-forget — one failed end (429
            // burst, null secret, network blip) left the group-tagged row
            // alive and refreshSessions rebuilt the thread from it on every
                // boot, silently, forever. Retry once (rate limits are bursty),
            // then verify below instead of trusting the fire-and-forget.
            for (let attempt = 0; attempt < 2 && !ended; attempt++) {
              try { await app.relay.sessionEnd(pst, pws, who); ended = true; }
              catch { if (attempt === 0) await new Promise((ok) => setTimeout(ok, 2000)); }
            }
            try { await app.sessions.remove(pst); } catch { /* no local state */ }
          }
          // b196-r3 ghost guard (classic threads have had this since b65;
          // forum threads had nothing): check the live list — if ANY row
          // tagged with this group survived the end attempts, hide it in
          // veil_dismissed_sessions so no refresh or build load can rebuild
          // the thread from it. A later rejoin mints a fresh token, which is
          // never in the hide list.
          try {
            const lr = await app.relay.sessionList(who ?? '');
            const list = (lr.data as { data?: unknown[] })?.data ?? (lr.data as unknown as { sessions?: unknown[] })?.sessions ?? (lr.data as unknown[]);
            const survivors = (Array.isArray(list) ? list : [])
              .map((raw) => raw as Record<string, unknown>)
              .filter((rec) => rec.group_token && String(rec.group_token) === chat.groupToken)
              .map((rec) => String(rec.token ?? ''))
              .filter(Boolean);
            if (survivors.length) {
              console.log(`[veil-end] forum end left ${survivors.length} row(s) alive — adding to the hide list (b196-r3)`);
              const raw = await app.storage.get('veil_dismissed_sessions');
              const hidden: string[] = raw ? (JSON.parse(raw) as string[]) : [];
              for (const t of survivors) if (!hidden.includes(t)) hidden.push(t);
              await app.storage.set('veil_dismissed_sessions', JSON.stringify(hidden));
            }
          } catch { /* list failure → hide skipped, classic-branch parity */ }
          try { await app.sessions.remove(chat.token); } catch { /* no local state */ }
          await forgetGroup(app.storage, chat.groupToken);
          setChat(null); setScreen('main'); refreshSessions();
        } else {

        // b132 (owner repro: lounge needed TWO ✕ before it left the thread
        // list): one group = MANY relay rows (main session + one invite row
        // per link, all sharing the group_token). The old code ended only
        // the OPEN thread's row and then forgot the local group record —
        // the surviving invite rows still carried the group tag and
        // resurrected the thread on the very next refresh. End EVERY row
        // tied to the group, then hide any survivor (peer-owned rows a
        // credential can't reach, b65 class) so nothing resurrects.
        const groupTokens = new Set<string>([chat.token]);
        try {
          const r = await app.relay.sessionList(who ?? '');
          const list = (r.data as { data?: unknown[] })?.data ?? (r.data as unknown as { sessions?: unknown[] })?.sessions ?? (r.data as unknown[]);
          for (const raw of Array.isArray(list) ? list : []) {
            const rec = raw as Record<string, unknown>;
            if (rec.group_token && String(rec.group_token) === chat.groupToken) {
              const t = String(rec.token ?? '');
              if (t) groupTokens.add(t);
            }
          }
        } catch { /* list failure → end just the open token, as before */ }
        const survivors: string[] = [];
        for (const t of groupTokens) {
          let ended = true;
          try { await app.relay.sessionEnd(t, (await app.sessions.load(t))?.writeSecret ?? null, who); }
          catch { ended = false; /* peer-created rows RLS-block the end (b65 class) */ }
          if (!ended) survivors.push(t);
        }
        if (survivors.length) {
          // b65 ghost-thread guard: hide any row we couldn't end server-side
          // so it cannot resurrect the thread after the group is forgotten.
          try {
            const raw = await app.storage.get('veil_dismissed_sessions');
            const list: string[] = raw ? (JSON.parse(raw) as string[]) : [];
            for (const t of survivors) if (!list.includes(t)) list.push(t);
            await app.storage.set('veil_dismissed_sessions', JSON.stringify(list));
          } catch { /* hide is best-effort */ }
        }
        for (const t of groupTokens) { try { await app.sessions.remove(t); } catch { /* no local state for this row */ } }
        await forgetGroup(app.storage, chat.groupToken);
        setChat(null); setScreen('main'); refreshSessions();
        }
      } catch (e) {
        setError(friendlyError(e, 'action'));
      } finally { setBusy(false); }
      return;
    }
    setBusy(true);
    try {
      const ws = (await app.sessions.load(chat.token))?.writeSecret ?? null;
      const who = await clientId();
      try {
        // b65: client_id = participation proof; until the gate update deploys the
        // server may still refuse (403) — the fallbacks below own that case.
        await app.relay.sessionEnd(chat.token, ws, who ?? undefined);
      } catch (e) {
        // 403s happen on sessions whose write secret we never stored (pending /
        // peer-created / restored device). Fall back to deleting the thread
        // record outright; if even that is denied, end locally anyway — the
        // user is never trapped in a thread they cannot leave.
        const recId = sessionRows.find((r) => r.token === chat.token)?.recId;
        let cleared = false;
        if (recId) { try { await app.relay.entityDelete('VeilSession', recId); cleared = true; } catch { /* RLS */ } }
        if (!cleared) {
          // b65: relay keeps the row (RLS-owned by the peer) — hide it locally so
          // the ghost thread cannot resurrect on the next poll. The gate-side
          // participation-proof fix deletes it for real once deployed.
          try {
            const raw = await app.storage.get('veil_dismissed_sessions');
            const list: string[] = raw ? (JSON.parse(raw) as string[]) : [];
            if (!list.includes(chat.token)) {
              list.push(chat.token);
              await app.storage.set('veil_dismissed_sessions', JSON.stringify(list));
            }
          } catch { /* hide is best-effort */ }
        }
        console.warn('[veil-end] relay end rejected, fallback:', String((e as Error).message || e), cleared ? '(record deleted)' : '(hidden locally)');
      }
      await app.sessions.remove(chat.token);
      setChat(null); setScreen('main'); refreshSessions();
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, chat, refreshSessions]);

  if (locked && (identity || appLock)) {
    return (
      <LockScreen
        onUnlock={handleUnlock}
        hint={lockHint}
        onCode={handleCode}
        verifying={codeVerifying}
        resetKey={codeResetKey}
        hasAppLock={!!appLock}
        codeError={codeError}
        lockoutUntil={lockout?.lockedUntil ?? 0}
      />
    );
  }

  if (bootError) {
    return (
      <View style={styles.boot}>
        <Text style={styles.errTitle}>VEIL could not start</Text>
        <Text style={styles.errText}>{bootError}</Text>
        {/* b104: every fatal-screen screenshot must self-identify the JS
            build it ran on — the owner's crash screenshot was visually
            identical on old and new code, so we couldn't tell whether the
            patch had even been applied (it hadn't: the xcopy ran from a
            fresh cmd prompt in the wrong folder). This tag settles it in
            one glance from now on. */}
        <Text style={styles.errText}>build b154-2026-10-01</Text>
      </View>
    );
  }

  if (screen === 'boot' || !app) {
    return (
      <View style={styles.boot}>
        <ActivityIndicator color="#5fd4c4" />
        <Text style={styles.bootText}>Sealing the device…</Text>
      </View>
    );
  }

  if (screen === 'onboard') {
    return (
      <>
      <OnboardingScreen
        settings={settings}
        onApply={handleSettingsChange}
        onDone={() => {
          // the "Secure your VEIL" prompt only clears once the checkup itself ran
          if (onboardingMode === 'full' || onboardingMode === 'checkupOnly') setSecurePrompt(false);
          else setSecurePrompt(true);
          setScreen('main');
        }}
        veilId={identity?.veilId ?? null}
        mode={onboardingMode}
        onCancel={() => setScreen('main')}
        appLockEnabled={!!appLock}
        onSetAppLock={handleSetAppLock}
      />
      <CallOverlay />
      </>
    );
  }

  if (screen === 'login') {
    return (
      <>
      <LoginScreen busy={busy} error={error} info={info} onLogin={handleLogin} onForgotPassword={handleForgot} onSignup={handleSignup} onSwitchToIdentity={() => setScreen('identity')} />
      <CallOverlay />
      </>
    );
  }

  if (screen === 'otp') {
    return (
      <>
      <OtpScreen
        email={email} busy={busy} error={error} info={info}
        onVerify={handleVerify} onResend={handleResend}
        onBack={() => setScreen('login')}
      />
      <CallOverlay />
      </>
    );
  }

  if (screen === 'identity') {
    return (
      <>
      <IdentityScreen
        onCreate={handleCreateIdentity}
        onRestore={handleRestore}
        onFinishCreate={handleFinishCreate}
        onSignOut={handleSignOut}
        onAccountSignIn={() => setScreen('login')}
        initialMode={identityEntry}
      />
      <CallOverlay />
      </>
    );
  }

  if (screen === 'chat' && chat) {
    // combine the device messages with the media decrypt cache for the UI
    const uiMessages: ChatMessageUI[] = chatMessages.map((m) => {
      if (!m.media) return { id: m.id, text: m.text, mine: m.mine, ts: m.ts, sender: m.sender, senderVerified: m.senderVerified, systemNote: m.systemNote, openedAt: m.openedAt, read: m.read };
      const st = mediaLoad[m.id];
      const mime = m.media.mime ?? 'application/octet-stream';
      const isAv = mime.startsWith('audio/') || mime.startsWith('video/');
      // b62: av playback needs the cache file (data: URIs don't play in expo-av);
      // images keep the data URI for the lightbox.
      let src = st?.uri ?? (m.mine ? m.media.localUri ?? null : null);
      if (isAv) src = st?.fileUri ?? st?.uri ?? (m.mine ? m.media.localUri ?? null : null);
      return {
        id: m.id, text: m.text, mine: m.mine, ts: m.ts, sender: m.sender, senderVerified: m.senderVerified, systemNote: m.systemNote, openedAt: m.openedAt, read: m.read,
        media: {
          name: m.media.name ?? 'media',
          mime,
          size: m.media.size ?? 0,
          dl: !!m.media.dl,
          src,
          loading: !!st?.loading,
          error: st?.error ?? null,
        },
      };
    });
    return (
      <>
      <ChatScreen
        threadKey={chat.token}
        onDismissError={() => setError(null)}
        title={chat.title}
        historyNotice={
          (settings.storageMode === 'memory' || settings.localHistory === false)
            ? 'History isn\u2019t saved on this device \u2014 messages vanish when you leave this thread.'
            : (cacheSaveFailed === chat.token
              ? 'Couldn\u2019t save history on this device \u2014 messages may vanish when you leave this thread.'
              : null)
        }
        subtitle={chat.subtitle}
        status={chat.status}
        burnAfterOpen={chat.burnAfterOpen}
        burnSeconds={chat.burnSeconds}
        busy={busy}
        error={error}
        messages={uiMessages}
        draft={draft}
        onDraftChange={setDraft}
        onSend={handleSend}
        onBack={() => { setChat(null); setError(null); refreshSessions(); setScreen('main'); }}
        onStartCall={chat.status !== 'ended' && chat.status !== 'pending' && !chat.groupToken ? () => {
          // b144 W3: 1:1 ready threads only — group calls are post-W4
          CallManager.start(chat.token, chat.title).catch((e) => console.log(`[veil-call] start failed: ${(e as Error).message}`));
        } : undefined}
        onEndSession={handleEndSession}
        canNewThread={!!(chat?.canNewThread && chat.status !== 'ended')}
        onNewThread={handleNewThread}
        contact={!!chat?.contact}
        myVerified={!!chat?.myVerified}
        peerVerified={!!chat?.peerVerified}
        sessionFingerprint={chat?.fingerprint ?? null}
        peerVeilId={chat?.peerVeilId ?? null}
        peerPinned={!!chat?.peerPinned}
        onPinContact={() => chat?.token && chat?.peerVeilId && handlePinFromSession(chat.token, chat.peerVeilId)}
        onVerifySession={async () => { const ok = chat ? await handleVerifySession(chat.token) : false; return !!ok; }}
        showVerifyCard={verifyCard && !chat?.groupToken && !chat?.contact && chat?.status === 'active'}
        onVerifyCardDismiss={handleDismissVerifyCard}
        canRename={!!(chat?.peerVeilId && !chat.groupToken)}
        readOnly={!!chat?.lounge}
        textOnly={!!chat?.forum}
        threadNickname={chatLocalNick}
        onRenameThread={handleRenameThread}
        onAttach={handleAttach}
        pendingPick={pendingPick}
        allowDl={allowDl}
        onAllowDlChange={setAllowDl}
        onMediaSave={handleMediaSave}
        mediaSaving={mediaSaving}
        onSendMedia={handleSendMedia}
        onCancelPick={handleCancelPick}
        onMediaRetry={(id) => {
          const orig = chatMessages.find((x) => x.id === id);
          if (orig?.media && chat) resolveMedia(chat.token, id, orig.media);
        }}
        voiceRec={voiceRec}
        onVoiceRecord={handleVoiceRecord}
        onVoiceCancel={handleVoiceCancel}
        onVoiceSend={handleVoiceSend}
        group={chat.groupToken && groupInfo ? {
          isCreator: groupInfo.isCreator,
          epoch: groupInfo.epoch,
          fingerprint: groupInfo.fingerprint,
          members: groupInfo.members,
          busy: groupBusy,
          onRotate: handleRotateGroup,
          onEvict: handleEvictMember,
        } : undefined}
      />
      {/* b148: chat is an early-return branch — the overlay must mount here too,
          else the call rings "behind" the thread and only shows after backing out. */}
      <CallOverlay />
      </>
    );
  }

  if (screen === 'welcome') {
    return (
      <>
      <WelcomeScreen
        veilId={decoyMode ? null : (identity ? identity.veilId : null)}
        onRunCheckup={() => { setOnboardingMode('checkupOnly'); setScreen('onboard'); }}
        onViewIntro={() => { setOnboardingMode('introOnly'); setScreen('onboard'); }}
        onJoinInvite={handleJoinInvite}
        onJoinLounge={handleJoinLounge}
        onHide={handleHideWelcome}
        onBack={() => setScreen('main')}
      />
      <CallOverlay />
      </>
    );
  }

  return (
    <>
    <MainScreen
      welcomeVisible={!decoyMode && !!identity && !settings.welcomeDismissed}
      forumBannerVisible={!decoyMode && !!identity && !forumJoined && !forumJoining && (Date.now() - forumBannerDismissedAt) > 604800000}
      forumBannerBusy={forumJoining}
      onJoinForum={handleJoinForumBanner}
      onDismissForumBanner={handleDismissForumBanner}
      onOpenWelcome={() => setScreen('welcome')}
      app={app}
      decoyMode={decoyMode}
      veilId={decoyMode ? null : (identity ? identity.veilId : null)}
      email={decoyMode ? null : (email || null)}
      busy={busy}
      onSignOut={handleSignOut}
      sessions={decoyMode ? [] : sessionRows}
      onRefreshSessions={refreshSessions}
      onOpenSession={handleOpenSession}
      onNewSession={() => setTab('contacts')}
      onCreateInvite={async () => {
        if (!app || !identity) throw new Error('Create your Veil identity first — Settings → Identity.');
        const who = await clientId();
        if (!who) throw new Error('Sign in first.');
        const link = (await createInviteSession(
          { sessions: app.sessions, relay: app.relay, webBaseUrl: VEIL_BASE_URL },
          {
            clientId: who,
            dials: {
              burnAfterOpen: settings.burnTtlSeconds > 0,
              expireAfterSeconds: settings.expireAfterSeconds,
              keyRetentionHours: settings.retentionHours,
              // b92 F-S6 (settings sweep, live-confirmed on relay rows created
          // 20:55 Sept 20): was hardcoded 3600 — the burn dial silently
          // became a 1-hour burn window on every invite-link + group thread.
          defaultTtlSeconds: settings.burnTtlSeconds,
            },
            displayName: settings.nickname || '',
          },
        )).link;
        await refreshSessions();
        return link;
      }}
      onJoinInvite={handleJoinInvite}
      contacts={decoyMode ? [] : contactRows}
      contactsError={contactsError}
      onLookup={handleLookup}
      onPin={handlePin}
      onUnpin={handleUnpin}
      onMessage={handleMessage}
      onVerify={handleVerifyPin}
      onSetNickname={handleNickname}
      onCreateGroup={handleCreateGroup}
      tab={tab}
      onTab={setTab}
      settings={settings}
      onSettingsChange={handleSettingsChange}
      onRunCheckup={() => { setOnboardingMode('checkupOnly'); setScreen('onboard'); }}
      onCreateTransfer={async () => {
        if (!app) throw new Error('App is not ready yet — try again in a moment.');
        return createDeviceTransfer(
          { sessions: app.sessions, vault: app.vault, relay: app.relay, webBaseUrl: VEIL_BASE_URL },
          { clientId: identity?.veilId },
        );
      }}
      onReceiveTransfer={async (link: string) => {
        if (!app) throw new Error('App is not ready yet — try again in a moment.');
        const r = await receiveDeviceTransfer(
          { sessions: app.sessions, vault: app.vault, relay: app.relay, webBaseUrl: VEIL_BASE_URL },
          link,
        );
        // refresh everything the import may have changed
        setIdentity(await app.vault.load());
        refreshSessions();
        return r;
      }}
      appLockEnabled={!!appLock}
      onSetAppLock={handleSetAppLock}
      onRemoveAppLock={handleRemoveAppLock}
      onLockNow={handleLockNow}
      onWipeDevice={handleWipeDevice}
      onDeleteAccount={handleDeleteAccount}
      onViewIntro={() => { setOnboardingMode('introOnly'); setScreen('onboard'); }}
      webBaseUrl={VEIL_BASE_URL}
      onVerifyPhrase={handleVerifyPhrase}
      onRemoveIdentity={handleRemoveIdentity}
      onGenerateNewVeilId={handleGenerateNewVeilId}
      onCreateIdentity={handleOpenIdentityFlow}
      securePrompt={securePrompt}
      onDismissSecurePrompt={() => setSecurePrompt(false)}
    />
    {/* b144 W3: encrypted-call surface — rings over any screen */}
    <CallOverlay />
    {showAttribution && identity ? (
      <AttributionSheet
        onAnswer={handleAttributionAnswer}
        onSkip={() => { void handleAttributionSkip(); }}
      />
    ) : null}
    </>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: '#0b0f14' },
  boot: { flex: 1, backgroundColor: '#0b0f14', alignItems: 'center', justifyContent: 'center', padding: 24 },
  bootText: { color: '#5a6b76', marginTop: 14, fontSize: 13, letterSpacing: 1 },
  errTitle: { color: '#ff6b6b', fontSize: 16, fontWeight: '700', marginBottom: 16, textAlign: 'center' },
  errText: { color: '#9fb3c0', fontSize: 11, lineHeight: 16, textAlign: 'left' },
});

class VeilErrorBoundary extends React.Component<{ children: React.ReactNode }, { msg: string | null }> {
  state: { msg: string | null } = { msg: null };
  static getDerivedStateFromError(e: unknown) {
    const err = e as Error;
    return { msg: String(err?.message || e) + '\n\n' + String(err?.stack || '') };
  }
  render() {
    if (this.state.msg) {
      return (
        <View style={styles.boot}>
          <Text style={styles.errTitle}>VEIL hit an error — please screenshot this</Text>
          <Text style={styles.errText}>{this.state.msg}</Text>
        </View>
      );
    }
    return this.props.children;
  }
}


const DEFAULTS = normalizeSettings(null);

export default function App() {
  return (
    // BUG FIXED (Sept 19): no screen accounted for the notch / Dynamic Island
    // safe area, so header content (e.g. Settings/Sign-out in the top-right)
    // rendered too high and got visually clipped by the status bar on iPhones
    // with a notch or Dynamic Island. react-native's own SafeAreaView is
    // iOS-native (no extra pod, no rebuild) and covers every screen from here.
    <SafeAreaView
      style={styles.safeArea}
      // (b66) CAPTURE phase: the non-capture responder was skipped whenever a
      // child (TouchableOpacity, keypad, composer…) claimed the touch, so
      // taps on actual controls never reset the inactivity clock and the
      // passcode gate fired while the app was actively in use. Capture fires
      // for EVERY touch before any child can claim it.
      onStartShouldSetResponderCapture={() => { veilActivityPing(); return false; }}
    >
      <VeilErrorBoundary>
        <VeilApp />
      </VeilErrorBoundary>
    </SafeAreaView>
  );
}
