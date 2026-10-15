/**
 * Contentless push plumbing — iOS 1.0.
 *
 * VEIL's threat model: the push channel must leak NOTHING about who or what.
 * The APNs payload carries no sender, no ciphertext, no session token — the
 * client wakes, polls its own sessions over the encrypted relay, and shows a
 * generic local banner. Server side, the relay's push trigger sends the SAME
 * generic ping regardless of which peer/session/message fired it.
 */
import * as Notifications from 'expo-notifications';
import Constants from 'expo-constants';
import { CallManager } from './calls/CallManager';


// b77 FIX: the handler below used to return the SAME suppressed result for
// every notification, remote or local. The remote APNs wake-ping (contentless,
// fired on every VeilEnvelope insert including cover-traffic decoys) is
// correctly silent by design — but that blanket suppression also silently ate
// the LOCAL "new message" banner scheduled by notifyNewMessage() below,
// after this device had actually decrypted a real message. Net effect:
// notifications never showed at all, foreground or background. (b198: the
// blanket suppression below is retired — see the new posture comment.)
// b198 (owner report: no lock-screen notifications): the OLD posture suppressed
// ALL remote pings and showed a LOCAL banner only after a background wake →
// sync → decrypt cycle. That chain requires the OS to background-wake the app
// on the silent ping — which Metro/dev-client builds cannot do, so the lock
// screen showed NOTHING. On this relay the ping fires ONLY on real text/media
// sends (notifySent — never for cover traffic), so the old reason for the
// suppression is gone: the remote ping itself is now the visible, CONTENTLESS
// lock-screen notification (no sender, no session, no content).
Notifications.setNotificationHandler({
  handleNotification: async (notification) => {
    const d = notification.request.content.data as { veilLocal?: boolean; kind?: string } | null;
    // b198 CALL RING BURST: call pushes (kind 'call', body "Incoming call")
    // display like messages UNTIL the call connects — once the ringing
    // overlay or the call itself is up, the remaining burst banners go silent
    // (the in-call ring + vibration take over; banners would stack over the
    // call UI).
    let callLive = false;
    try { const s = CallManager.snapshot(); callLive = !!s && (s.phase === 'ringing' || s.phase === 'connecting' || s.phase === 'active' || s.phase === 'calling'); } catch { /* no call state */ }
    const show = d?.veilLocal === true || ((d?.kind === 'new-message' || d?.kind === 'call') && !callLive);
    if (d?.kind === 'new-message') lastRemotePingAt = Date.now();
    return {
      shouldShowAlert: show,
      shouldShowBanner: show,
      shouldShowList: show,
      shouldPlaySound: show,
      shouldSetBadge: false,
    };
  },
});

/** b198: when a remote ping just landed, the local post-decrypt banner would
 *  double-fire behind it — skip the local one for a short window. */
let lastRemotePingAt = 0;
const REMOTE_PING_DEDUP_MS = 30_000;

/** Rate limit for local new-message banners (ms). */
const NOTIFY_MIN_INTERVAL_MS = 15_000;
let lastNotifyAt = 0;

/**
 * Generic local banner for an actual new chat message found by polling.
 * Carries no sender, no content, no session — same threat model as the ping.
 * Rate-limited so a burst of arrivals (or a peer's cover stream) can't spam.
 */
/** Rate limit for invite banners (ms) — independent of message banners. */
const NOTIFY_INVITE_MIN_INTERVAL_MS = 30_000;
let lastInviteNotifyAt = 0;

/**
 * b178: generic local banner when a NEW invite session appears on the poll
 * (owner report: invites arrived with zero notification, foreground or
 * background). Same contentless rule as the message banner — no sender,
 * no session identity — the body only says an invite exists. Suppression on
 * the lock screen still requires the server-side VeilSession push trigger
 * (see the b178 note in App.tsx refreshSessions).
 */
export async function notifyNewInvite(): Promise<void> {
  try {
    const now = Date.now();
    if (now - lastInviteNotifyAt < NOTIFY_INVITE_MIN_INTERVAL_MS) return;
    lastInviteNotifyAt = now;
    await Notifications.scheduleNotificationAsync({
      content: { title: 'VEIL', body: 'New chat invite', data: { veilLocal: true } },
      trigger: null,
    });
  } catch { /* notifications are best-effort */ }
}

export async function notifyNewMessage(): Promise<void> {
  try {
    const now = Date.now();
    if (now - lastRemotePingAt < REMOTE_PING_DEDUP_MS) return; // the visible remote ping already covered this
    if (now - lastNotifyAt < NOTIFY_MIN_INTERVAL_MS) return;
    lastNotifyAt = now;
    await Notifications.scheduleNotificationAsync({
      content: { title: 'VEIL', body: 'Notification', data: { veilLocal: true } },
      trigger: null,
    });
  } catch { /* notifications are best-effort */ }
}

export async function ensurePushPermission(): Promise<boolean> {
  try {
    const cur = (await Notifications.getPermissionsAsync()) as unknown as { status: string };
    if (cur.status === 'granted') return true;
    // ask ONCE: after a denial never re-prompt automatically (the OS keeps
    // its answer; repeated requests are the "endless permission prompts")
    if (cur.status === 'denied') return false;
    const req = (await Notifications.requestPermissionsAsync()) as unknown as { status: string };
    return req.status === 'granted';
  } catch { return false; }
}

/** Relay + keychain shapes (injected — keeps this module pure for tests). */
export interface PushRegistrationDeps {
  entityCreate: (entity: string, record: Record<string, unknown>) => Promise<unknown>;
  /** user-scoped entity LIST (own rows only) — used to dedupe before create */
  entityList: (entity: string, params: Record<string, string | number>) => Promise<unknown>;
  /** b198: delete an untagged (pre-acct) row so it can be replaced by a tagged one */
  entityDelete?: (entity: string, id: string) => Promise<unknown>;
  getCached: (key: string) => Promise<string | null>;
  setCached: (key: string, value: string) => Promise<unknown>;
}

/**
 * Register this device's Expo push token with the relay (VeilPushToken).
 * One record per token; re-registers only when the token CHANGES (Expo tokens
 * can rotate across installs). Cached in the secure store to avoid record spam.
 */
export async function registerPushToken(relay: PushRegistrationDeps): Promise<boolean> {
  try {
    const token = await getPushToken();
    if (!token) {
      console.log('[veil-push] registerPushToken: no token available — relay NOT updated');
      return false;
    }
    // b198: the key was bumped once (v2) so existing installs re-register —
    // rows created before the relay tagged them with the owning account could
    // never be matched for push delivery
    const key = 'veil_push_token_cached_v2';
    if ((await relay.getCached(key)) === token) return true; // already registered
    // b69: the cached key dies on sign-out wipe — check the user's OWN rows
    // before creating another one for the same token (each extra row = one
    // extra APNs ping per envelope on the server trigger).
    try {
      const listed = (await relay.entityList('VeilPushToken', { expo_token: token })) as unknown;
      const rows = (Array.isArray(listed) ? listed : ((listed as { data?: unknown[] })?.data ?? [])) as Record<string, unknown>[];
      const mine = rows.find((r) => String(r.expo_token ?? '') === token);
      if (mine) {
        // b198: rows created before the relay tagged them with the owning
        // account can never be matched for push delivery — replace them with
        // a tagged row instead of dedupe-skipping on a dead record
        if (mine.id && !String((mine as { _acct?: string })._acct || '') && relay.entityDelete) {
          await relay.entityDelete('VeilPushToken', String(mine.id)).catch(() => undefined);
        } else {
          await relay.setCached(key, token);
          return true; // live, tagged row already exists — never duplicate
        }
      }
    } catch { /* list unavailable (offline) — fall through to create */ }
    await relay.entityCreate('VeilPushToken', { expo_token: token });
    await relay.setCached(key, token);
    console.log('[veil-push] registered new token with relay');
    return true;
  } catch (e) {
    console.log(`[veil-push] registerPushToken FAILED: ${(e as Error).message ?? e}`);
    return false;
  }
}

/**
 * b95 NaR v2: remove this device's push registration from the relay so a
 * wiped (Nothing-at-Rest) device goes SILENT — no lock-screen banners, no
 * APNs pings — until the identity is restored from the 24-word phrase, at
 * which point the registration effect in App.tsx re-registers it.
 * Server-side the rows are user-scoped, so deleting own rows is authorized.
 */
export async function unregisterPushToken(relay: PushRegistrationDeps & {
  entityDelete: (entity: string, id: string) => Promise<unknown>;
}): Promise<void> {
  try {
    const token = await getPushToken();
    if (token) {
      const listed = (await relay.entityList('VeilPushToken', { expo_token: token })) as unknown;
      const rows = (Array.isArray(listed) ? listed : ((listed as { data?: unknown[] })?.data ?? [])) as Record<string, unknown>[];
      for (const r of rows) {
        if (String(r.expo_token ?? '') === token && r.id) {
          await relay.entityDelete('VeilPushToken', String(r.id)).catch(() => undefined);
        }
      }
    }
    // cached marker dies too — a later re-register (post phrase-restore) must
    // actually create a fresh row, not skip on the stale cache
    await relay.setCached('veil_push_token_cached', '');
  } catch { /* best-effort: offline wipe retries at next boot */ }
}

/**
 * b124 FIX: getExpoPushTokenAsync() needs an explicit projectId on SDK 52 —
 * without one it throws, and the old catch-and-return-null here made that
 * failure invisible (registerPushToken() below just silently never wrote a
 * row to the relay). Root cause of "no remote push ever arrives": a fresh
 * dev-client install had no linked EAS project, so every registration
 * attempt died at this line with zero trace. Now: read the projectId from
 * app.json (baked in at build time) or the EAS update manifest fallback,
 * and log loudly on failure so this can't go dark again.
 */
function resolveProjectId(): string | null {
  const fromExtra = (Constants.expoConfig?.extra as { eas?: { projectId?: string } } | undefined)?.eas?.projectId;
  const fromEasConfig = (Constants as unknown as { easConfig?: { projectId?: string } }).easConfig?.projectId;
  return fromExtra ?? fromEasConfig ?? null;
}

/** Expo push token for the relay's contentless push trigger. */
export async function getPushToken(): Promise<string | null> {
  try {
    if (!(await ensurePushPermission())) {
      console.log('[veil-push] permission not granted — skipping token fetch');
      return null;
    }
    const projectId = resolveProjectId();
    if (!projectId) {
      console.log('[veil-push] FAILED: no EAS projectId found in app config — run `eas init` and rebuild');
      return null;
    }
    const t = await Notifications.getExpoPushTokenAsync({ projectId });
    const token = (t.data as string) ?? null;
    console.log(`[veil-push] token fetched OK: ${token ? token.slice(0, 24) + '…' : 'null'}`);
    return token;
  } catch (e) {
    console.log(`[veil-push] FAILED to fetch push token: ${(e as Error).message ?? e}`);
    return null;
  }
}


