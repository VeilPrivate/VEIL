/**
 * b112 — email-free native accounts (owner directive, Sept 22).
 *
 * The account (the thing that authenticates you to the relay) and the Veil
 * identity (the keypair) are separate. Until now the account was always an
 * email + password + OTP login. For the NATIVE app the account is now derived
 * silently from the 24-word identity phrase:
 *
 *   email    = v<sha256("veil:b112:account-email:" + phrase)[0..12]hex>@veil.app
 *   password = base64(sha256("veil:b112:account-pass:" + phrase))   (~44 chars)
 *
 * Properties:
 *   - deterministic: the same phrase on any device derives the SAME
 *     credentials — phrase restore recovers the account too, no email needed.
 *   - derived from a SECRET (the phrase), so a peer who knows your public
 *     veil-id cannot guess the account email and squat it.
 *   - nothing new leaves the device: only the standard register/login
 *     endpoints see (email, password) — exactly what the manual flow sent.
 *   - the phrase is already the root secret (it re-derives the identity keys);
 *     deriving the account from it adds no new compromise surface.
 *
 * Server side: provisioning a NEW account without a human reading an OTP
 * email needs the relay function `veilSilentAccount` (action: 'provision')
 * to create the account pre-verified server-side. Until that function is
 * live, provisionSilentAccount() throws SilentAccountUnavailableError and the
 * caller falls back to the classic email flow — build-35 users and the
 * review binary are never blocked.
 */
import { sha256, utf8, toB64 } from '../../crypto-core/src/index';
import type { VeilRelay } from './relay';
import type { Base44Auth, AuthSession } from './auth';

export interface SilentCredentials {
  email: string;
  password: string;
}

/** Normalise a phrase exactly like the restore flow does (case/space tolerant). */
function normalisePhrase(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/).filter(Boolean).join(' ');
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** Deterministic synthetic credentials for the phrase. */
export async function deriveSilentCredentials(phrase: string): Promise<SilentCredentials> {
  const norm = normalisePhrase(phrase);
  if (!norm) throw new Error('Phrase is empty');
  const emailHash = await sha256(utf8(`veil:b112:account-email:${norm}`));
  const passHash = await sha256(utf8(`veil:b112:account-pass:${norm}`));
  return {
    // 24 hex chars (~96 bits) — unique per phrase, opaque, syntactically valid
    email: `v${hex(emailHash.subarray(0, 12))}@veil.app`,
    password: toB64(passHash),
  };
}

/** Typed "the server can't do silent accounts yet" signal — never fatal. */
export class SilentAccountUnavailableError extends Error {
  constructor(detail?: string) {
    super(detail || 'Silent accounts are not available on this relay yet');
    this.name = 'SilentAccountUnavailableError';
  }
}

export interface SilentAuthDeps {
  auth: Base44Auth;
  relay: VeilRelay;
}

function isUnavailable(e: unknown): boolean {
  const s = String((e as Error)?.message ?? e).toLowerCase();
  // relay rejects unknown functions with "Unknown action"/"not found";
  // anything else (network, lockout, bad credentials) is a REAL failure the
  // caller should surface, not a fallback trigger.
  return s.includes('unknown action') || s.includes('unknown function') || s.includes('not found') || s.includes('function_not_found') || s.includes('404');
}

/**
 * Fresh install, no account yet: ask the relay to create the phrase-derived
 * account server-side (pre-verified), then log in silently. The relay call
 * carries only the synthetic email + password — the phrase never leaves the
 * device.
 */
export async function provisionSilentAccount(deps: SilentAuthDeps, phrase: string): Promise<AuthSession> {
  const creds = await deriveSilentCredentials(phrase);
  try {
    const r = await deps.relay.invoke('veilSilentAccount', { action: 'provision', email: creds.email, password: creds.password });
    if (r.status >= 400) throw new SilentAccountUnavailableError(`relay status ${r.status}`);
  } catch (e) {
    if (isUnavailable(e)) throw new SilentAccountUnavailableError();
    throw e;
  }
  // standard platform login — may itself demand OTP if the server-side
  // provisioning half exists but didn't pre-verify; that surfaces to the
  // caller exactly like a normal login would.
  return deps.auth.login(creds.email, creds.password);
}

/**
 * Returning device / phrase restore: the account already exists — just sign
 * in with the derived credentials. A plain auth failure means this phrase has
 * no account on this relay (pre-b112 identity, or the account was made the
 * classic way): the caller falls back to the email sign-in.
 */
export async function silentLogin(deps: SilentAuthDeps, phrase: string): Promise<AuthSession> {
  const creds = await deriveSilentCredentials(phrase);
  return deps.auth.login(creds.email, creds.password);
}
