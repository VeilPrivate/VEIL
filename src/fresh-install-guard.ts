/**
 * b170 (owner hardware finding, Oct 2, 2026).
 *
 * ROOT CAUSE of the live bug: owner deleted and reinstalled VEIL to test
 * onboarding "fresh", without first using in-app Sign out / Wipe VEIL data.
 * The new "create identity" flow attached its brand-new Veil keypair to the
 * PREVIOUS install's leftover account session — confirmed live by decoding
 * the stuck JWT's `sub` claim, which was the OLD pre-reinstall account
 * email, not a fresh silent account. Symptom: refreshSessions() found
 * session.user missing a usable id on every poll, so the newly-created
 * identity could never list or receive sessions — a message sent from web
 * never reached it.
 *
 * This is standard, documented Apple platform behavior, not a VEIL storage
 * bug on its own: iOS Keychain items are deliberately NOT removed when an
 * app is deleted (that's what lets normal apps restore a login after a
 * reinstall). VEIL's "Sign out" and "Wipe VEIL data from this device"
 * already correctly clear every veil_-prefixed Keychain entry including the
 * auth session (see handleSignOut / handleWipeDevice in App.tsx) — the gap
 * is only the path where a user deletes the app WITHOUT using either of
 * those first, which silently inherits the old install's entire Keychain.
 *
 * Fix: AsyncStorage (unlike Keychain) IS cleared when the app is deleted,
 * so its absence at boot is a reliable "this process is running on top of a
 * possibly-stale Keychain" signal. On that signal, sweep every veil_-
 * prefixed Keychain entry before a single byte of it is ever read — the
 * exact same sweep handleWipeDevice already uses, just run automatically at
 * boot instead of waiting on the user to notice something's broken.
 *
 * Known limitation (stated honestly, not swept under the rug): a full
 * device backup/restore (iCloud or iTunes/Finder) restores the sandbox
 * wholesale, AsyncStorage included — that is a deliberate user action to
 * recover their own device, not a "start fresh" signal, and this guard
 * correctly does nothing in that case.
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import type { VeilApp } from './veil-app';

const LAUNCHED_BEFORE_KEY = 'veil_launched_before_v1';

/** Returns true if a stale-Keychain sweep ran (useful for a one-line Metro log at boot). */
export async function purgeIfFreshInstall(app: VeilApp): Promise<boolean> {
  let launchedBefore: string | null = null;
  try {
    launchedBefore = await AsyncStorage.getItem(LAUNCHED_BEFORE_KEY);
  } catch (e) {
    // fail-safe: a storage read error must NEVER be treated as "fresh" —
    // that would wipe a real returning user's data on a flaky read.
    console.error('[veil-fresh-install] AsyncStorage read failed — treating as a normal launch, no sweep:', String((e as Error)?.message || e));
    return false;
  }
  if (launchedBefore) return false;

  console.log('[veil-fresh-install] no launch sentinel found — sweeping Keychain in case this is a reinstall with leftover data from a previous install');
  try {
    for (const k of await app.storage.keys('veil_')) {
      await app.storage.remove(k).catch(() => undefined);
    }
    // belt-and-braces: logout() also clears veil_auth_session even if the
    // index-based sweep above somehow missed it.
    await app.auth.logout().catch(() => undefined);
  } catch (e) {
    console.error('[veil-fresh-install] sweep failed (non-fatal — boot continues; worst case is a stale session, same as before this fix):', String((e as Error)?.message || e));
  }
  try {
    await AsyncStorage.setItem(LAUNCHED_BEFORE_KEY, '1');
  } catch (e) {
    console.error('[veil-fresh-install] failed to set launch sentinel — this sweep will simply run again next launch, which is harmless:', String((e as Error)?.message || e));
  }
  return true;
}
