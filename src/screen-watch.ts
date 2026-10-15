/**
 * Screen-capture watch (b61).
 *
 * iOS cannot block the hardware screenshot — Apple gives no app that power
 * (FLAG_SECURE is Android-only). It DOES fire two reliable system
 * notifications:
 *
 *   - UIApplication.userDidTakeScreenshotNotification  → a screenshot was
 *     taken while VEIL was on screen
 *   - UIScreen.capturedDidChangeNotification            → an AirPlay /
 *     screen-recording capture started or stopped
 *
 * The native VeilCrypto module (b61 binary) forwards both as
 * `onScreenCapture` events. This file is the JS side: resolve the module,
 * subscribe, and hand each event to the callback. On old binaries (pre-b61),
 * Expo, web or Node the resolver returns null and the watch is inert — no
 * crash, no fake detections.
 */

export type ScreenCaptureEvent =
  | { kind: 'screenshot' }
  | { kind: 'recording'; captured: boolean };

interface NativeScreenWatch {
  addListener?: (name: string, handler: (event: ScreenCaptureEvent) => void) => { remove: () => void };
}

let warned = false;

/** Start the watch. Returns a stop function (or null if unavailable). */
export function startScreenWatch(
  onCapture: (event: ScreenCaptureEvent) => void,
): (() => void) | null {
  try {
    const emc = require('expo-modules-core') as {
      requireNativeModule?: <T = unknown>(name: string) => T;
    };
    if (typeof emc?.requireNativeModule !== 'function') {
      if (!warned) { warned = true; console.log('[veil-capture] no requireNativeModule — capture watch off'); }
      return null;
    }
    const mod = emc.requireNativeModule<NativeScreenWatch>('VeilCrypto');
    if (!mod || typeof mod.addListener !== 'function') {
      if (!warned) { warned = true; console.log('[veil-capture] VeilCrypto has no event emitter (old binary?) — capture watch off'); }
      return null;
    }
    const sub = mod.addListener('onScreenCapture', (event) => {
      try {
        console.log('[veil-capture] native event:', JSON.stringify(event));
        onCapture(event);
      } catch { /* listener must never crash the app */ }
    });
    console.log('[veil-capture] watch armed (screenshots + recording)');
    return () => {
      try { sub.remove(); } catch { /* ignore */ }
    };
  } catch (e) {
    if (!warned) { warned = true; console.log('[veil-capture] unavailable:', String(e)); }
    return null;
  }
}
