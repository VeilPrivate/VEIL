/**
 * @veil/device — funnel, attribution, activation & session-health instrumentation.
 *
 * ONBOARDING-FUNNEL-FIX-SPEC + LAUNCH MASTER PLAN (Sept 30 work order).
 *
 * Design rules (zero-knowledge discipline):
 *   - Events carry NO message content, NO emails, NO phrases — only the
 *     step name and the auto created_date timestamp the backend adds.
 *   - Everything is best-effort: an event that cannot reach the relay is
 *     either retried on the next attempt (once-steps keep their guard
 *     until the write succeeds) or dropped silently (session_start /
 *     session_crashed). Instrumentation must never break the app or
 *     surface an error to the user.
 *   - The only backend touched is the VEIL relay itself. No analytics SDK,
 *     no third-party tracker — the marketing story depends on that being
 *     literally true.
 *
 * Storage surface (all through the device's encrypted keychain store):
 *   veil_funnel_done_<step>   once-guard flags per install
 *   veil_first_open_ts        ISO ms string, set on first open with an account
 *   veil_sess_crash           '1' written by the polyfills fatal interceptor
 *   veil_attribution_pending  JSON answer that could not reach the relay yet
 */

/** Minimal storage surface (KeychainStorage satisfies this). */
export interface FunnelStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  remove?(key: string): Promise<unknown>;
}

/** Minimal relay surface (VeilRelay satisfies this). */
export interface FunnelRelay {
  entityCreate(entity: string, record: Record<string, unknown>): Promise<unknown>;
}

/** Server-side funnel steps — the onboarding-funnel-fix-spec list, exactly. */
export const FUNNEL_STEPS = {
  /** web-only: logged by the tryveil.app/testflight redirect page (SourceVisit) */
  INSTALL_STARTED: 'install_started',
  APP_OPENED: 'app_opened',
  VEIL_ID_CREATED: 'veil_id_created',
  /** classic email accounts only — silent accounts have no email step by design */
  EMAIL_VERIFIED: 'email_verified',
  ONBOARDING_DONE: 'onboarding_done',
  FIRST_SESSION_STARTED: 'first_session_started',
  /** activation within 24h of first open (launch master plan) */
  ACTIVATED_24H: 'activated_24h',
  /** vault users activate on first successful retrieval, not messaging */
  ACTIVATED_VAULT: 'activated_vault',
  RETENTION_D7: 'retention_d7',
  RETENTION_D30: 'retention_d30',
  /** quality gate: one row per cold start, for the crash-free denominator */
  SESSION_START: 'session_start',
  /** quality gate: previous session hit the JS fatal interceptor (numerator) */
  SESSION_CRASHED: 'session_crashed',
} as const;

export type FunnelStep = (typeof FUNNEL_STEPS)[keyof typeof FUNNEL_STEPS];

const DONE_PREFIX = 'veil_funnel_done_';
const FIRST_OPEN_KEY = 'veil_first_open_ts';
const CRASH_KEY = 'veil_sess_crash';
const ATTR_PENDING_KEY = 'veil_attribution_pending';

export const ONCE_STEPS: ReadonlySet<string> = new Set([
  FUNNEL_STEPS.APP_OPENED,
  FUNNEL_STEPS.VEIL_ID_CREATED,
  FUNNEL_STEPS.EMAIL_VERIFIED,
  FUNNEL_STEPS.ONBOARDING_DONE,
  FUNNEL_STEPS.FIRST_SESSION_STARTED,
  FUNNEL_STEPS.ACTIVATED_24H,
  FUNNEL_STEPS.ACTIVATED_VAULT,
  FUNNEL_STEPS.RETENTION_D7,
  FUNNEL_STEPS.RETENTION_D30,
]);

/** for tests */
export const FUNNEL_INTERNAL_KEYS = { DONE_PREFIX, FIRST_OPEN_KEY, CRASH_KEY, ATTR_PENDING_KEY };

async function emitOnce(relay: FunnelRelay, storage: FunnelStorage, step: FunnelStep, extra?: Record<string, unknown>): Promise<boolean> {
  if (!ONCE_STEPS.has(step)) throw new Error(`emitOnce called for non-once step ${step}`);
  try {
    if (await storage.get(DONE_PREFIX + step)) return false;
  } catch { /* read failure = treat as not done */ }
  try {
    await relay.entityCreate('OnboardingStep', { step, ...(extra ?? {}) });
    await storage.set(DONE_PREFIX + step, '1');
    return true;
  } catch {
    return false; // guard NOT set — retried on the next attempt
  }
}

async function emitRaw(relay: FunnelRelay, step: FunnelStep): Promise<boolean> {
  try {
    await relay.entityCreate('OnboardingStep', { step });
    return true;
  } catch {
    return false; // dropped silently
  }
}

/** One row per cold start (denominator of crash-free sessions). */
export async function noteSessionStart(relay: FunnelRelay, storage: FunnelStorage): Promise<void> {
  // drain the fatal-interceptor flag first: previous session hit a JS fatal.
  // The flag is cleared ONLY when the row actually landed — an offline boot
  // must not swallow the crash silently.
  try {
    if (await storage.get(CRASH_KEY)) {
      if (await emitRaw(relay, FUNNEL_STEPS.SESSION_CRASHED)) {
        await storage.set(CRASH_KEY, ''); // cleared, not removed: an overwrite is
        // lighter than the RN keychain remove() path; empty string is falsy-checked
      }
    }
  } catch { /* never a crash source */ }
  await emitRaw(relay, FUNNEL_STEPS.SESSION_START);
}

/**
 * First open with an account present: stamps the install clock (activation
 * + retention reference point) and emits app_opened once per install.
 * Safe to call on every boot — only the first stamp + emit matter.
 */
export async function noteAppOpen(relay: FunnelRelay, storage: FunnelStorage, now: () => number = Date.now): Promise<void> {
  let tsStr: string | null = null;
  try { tsStr = await storage.get(FIRST_OPEN_KEY); } catch { /* ignore */ }
  if (!tsStr) {
    tsStr = String(now());
    try { await storage.set(FIRST_OPEN_KEY, tsStr); } catch { /* ignore */ }
  }
  await emitOnce(relay, storage, FUNNEL_STEPS.APP_OPENED);
  const firstOpen = Number(tsStr);
  if (Number.isFinite(firstOpen)) {
    const ageMs = now() - firstOpen;
    if (ageMs >= 30 * 24 * 3600 * 1000) {
      await emitOnce(relay, storage, FUNNEL_STEPS.RETENTION_D30);
      await emitOnce(relay, storage, FUNNEL_STEPS.RETENTION_D7); // d30 implies d7 fired
    } else if (ageMs >= 7 * 24 * 3600 * 1000) {
      await emitOnce(relay, storage, FUNNEL_STEPS.RETENTION_D7);
    }
  }
}

/** Registration finished: Veil ID created + onboarding (identity -> app) done. */
export async function noteVeilIdCreated(relay: FunnelRelay, storage: FunnelStorage): Promise<void> {
  await emitOnce(relay, storage, FUNNEL_STEPS.VEIL_ID_CREATED);
  await emitOnce(relay, storage, FUNNEL_STEPS.ONBOARDING_DONE);
}

/** Classic email flow only (silent accounts have no email step). */
export async function noteEmailVerified(relay: FunnelRelay, storage: FunnelStorage): Promise<void> {
  await emitOnce(relay, storage, FUNNEL_STEPS.EMAIL_VERIFIED);
}

/**
 * First REAL session opened (a relay thread — the local welcome note does
 * not count). Also resolves the 24h activation window against first open.
 */
export async function noteFirstSession(relay: FunnelRelay, storage: FunnelStorage, now: () => number = Date.now): Promise<void> {
  await emitOnce(relay, storage, FUNNEL_STEPS.FIRST_SESSION_STARTED);
  try {
    const tsStr = await storage.get(FIRST_OPEN_KEY);
    const firstOpen = Number(tsStr);
    if (tsStr && Number.isFinite(firstOpen) && now() - firstOpen < 24 * 3600 * 1000) {
      await emitOnce(relay, storage, FUNNEL_STEPS.ACTIVATED_24H);
    }
  } catch { /* never a crash source */ }
}

/** First successful vault retrieval (vault users activate on retrieval). */
export async function noteVaultRetrieved(relay: FunnelRelay, storage: FunnelStorage): Promise<void> {
  await emitOnce(relay, storage, FUNNEL_STEPS.ACTIVATED_VAULT);
}

// ---------------------------------------------------------------------------
// Attribution (attribution-spec)
// ---------------------------------------------------------------------------

export const ATTRIBUTION_MAX_DETAIL = 60;

/** Skippable one-tap prompt options — exact spec wording. */
export const ATTRIBUTION_OPTIONS = [
  { label: 'Explainer video', category: 'explainer_video' },
  { label: 'Social media', category: 'social_media' },
  { label: 'YouTube/creator video', category: 'youtube_creator' },
  { label: 'Article', category: 'article' },
  { label: 'Product Hunt', category: 'product_hunt' },
  { label: 'Press/news', category: 'press_news' },
  { label: 'A friend', category: 'friend' },
  { label: 'Other', category: 'other' },
  { label: 'Prefer not to say', category: 'prefer_not_say' },
] as const;

export interface AttributionAnswer {
  veilId: string;
  category: string;
  /** free text (Other) or the web-side veil_src fallback; <= 60 chars */
  detail?: string | null;
}

function clampDetail(detail?: string | null): string | null {
  if (!detail) return null;
  const trimmed = detail.trim().slice(0, ATTRIBUTION_MAX_DETAIL);
  return trimmed || null;
}

/**
 * Persist the answer to the AttributionSource entity — NOT on the identity
 * record. If the relay cannot take it yet (entity not live / offline), the
 * answer is parked locally and flushed on a later open.
 */
export async function saveAttribution(relay: FunnelRelay, storage: FunnelStorage, answer: AttributionAnswer): Promise<boolean> {
  const record = {
    veil_id: answer.veilId,
    source_category: answer.category,
    source_detail: clampDetail(answer.detail),
  };
  try {
    await relay.entityCreate('AttributionSource', record);
    return true;
  } catch {
    try { await storage.set(ATTR_PENDING_KEY, JSON.stringify(record)); } catch { /* best-effort */ }
    return false;
  }
}

/** Retry a parked attribution answer (called on app open). */
export async function flushPendingAttribution(relay: FunnelRelay, storage: FunnelStorage): Promise<boolean> {
  let raw: string | null = null;
  try { raw = await storage.get(ATTR_PENDING_KEY); } catch { return false; }
  if (!raw) return false;
  try {
    await relay.entityCreate('AttributionSource', JSON.parse(raw) as Record<string, unknown>);
    await storage.set(ATTR_PENDING_KEY, '');
    return true;
  } catch {
    return false; // stays parked
  }
}
