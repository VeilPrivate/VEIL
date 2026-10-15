import { useEffect, useState } from 'react';
import { Keyboard, Platform } from 'react-native';

/**
 * b115 (owner report Sept 22: keyboard covering the chat composer, live on
 * the b114 dev-client build — reproduced while the predictive-text bar was
 * actively changing, i.e. mid-typing).
 *
 * ROOT CAUSE: 'keyboardWillChangeFrame' does not ONLY fire on real
 * show/hide/resize — iOS also fires it as the predictive/QuickType
 * suggestion bar updates while typing (autocomplete row content changes),
 * and on some iOS versions that transient frame report comes through with
 * endCoordinates.height momentarily 0 or near-0 even though the keyboard is
 * still fully on screen. The old per-screen handler treated ANY
 * changeFrame height <= 0 as "keyboard gone" and zeroed the padding —
 * snapping the composer straight back down UNDER the still-visible
 * keyboard on every keystroke that changed the suggestion row. A real
 * dismiss is unconditionally reported by 'keyboardWillHide', which is the
 * ONLY event allowed to zero the padding here; changeFrame now ignores any
 * implausibly small reading (<100px — no real keyboard is that short) and
 * simply keeps the last known-good height until the next real update.
 *
 * This was previously duplicated ad hoc (and inconsistently) across
 * ChatScreen, IdentityScreen, LoginScreen, OtpScreen and ThemedPrompt —
 * consolidated into one hook so the fix (and any future one) applies
 * everywhere at once.
 */
const MIN_PLAUSIBLE_KEYBOARD_HEIGHT = 100;

export function useKbPadding(): number {
  const [kbH, setKbH] = useState(0);
  useEffect(() => {
    if (Platform.OS !== 'ios') return;
    const show = Keyboard.addListener('keyboardWillShow', (e) => setKbH(e.endCoordinates.height));
    const change = Keyboard.addListener('keyboardWillChangeFrame', (e) => {
      const h = e.endCoordinates.height;
      if (h >= MIN_PLAUSIBLE_KEYBOARD_HEIGHT) setKbH(h);
      // else: ignore — a transient/spurious low reading (e.g. the
      // predictive-text bar changing mid-keystroke), NOT a real dismiss.
    });
    const hide = Keyboard.addListener('keyboardWillHide', () => setKbH(0));
    return () => { show.remove(); change.remove(); hide.remove(); };
  }, []);
  return kbH;
}
