/**
 * b72: web-parity "burn N hours after open" countdown (chat bubbles).
 * The anchor is the moment the message was FIRST displayed on this device
 * (ChatMessage.openedAt); the window comes from the session's
 * expire-after-open dial (e.g. 7200 = "Burn 2h after opens" on web).
 */

/** Countdown text — "117m 48s", clamped at 0. */
export function burnCountdownText(openedAt: number | undefined, burnSeconds: number, now: number): string {
  const anchor = openedAt ?? now;
  const left = Math.max(0, anchor + burnSeconds * 1000 - now);
  const total = Math.floor(left / 1000);
  // b197-r8 (owner request): MINUTES ONLY — the seconds readout was noise at
  // burn-window scale. Minutes padded to 2 digits keeps tick-to-tick width
  // constant; ceil so the bubble never reads 00m while time remains.
  return `${String(Math.ceil(total / 60)).padStart(2, '0')}m`;
}
