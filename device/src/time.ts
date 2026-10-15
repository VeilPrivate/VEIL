/**
 * b134 (owner repro Sept 27, screenshot: a group message showed "5:08pm"
 * while a same-screen bubble sent moments earlier correctly showed "3:08am"
 * Brisbane — 14h apart on the same short-lived thread): the relay's
 * VeilEnvelope.created_date comes back as a bare ISO string with NO
 * timezone designator, e.g. "2026-09-26T17:07:54.255000" — no trailing 'Z',
 * no +HH:MM offset. Per the ECMAScript Date Time String spec, a date-time
 * string with no timezone designator is parsed as LOCAL time, not UTC. So
 * `new Date(env.created_date)` on a Brisbane device (UTC+10) treated
 * "17:07:54" as if it WERE already 17:07:54 Brisbane time, and
 * toLocaleTimeString() just echoed it back unconverted ("5:08pm") instead of
 * correctly showing 03:07:54 the NEXT day. Every message rendered from a
 * relay row — group AND pairwise — was exposed to this, silently, for as
 * long as the device's timezone differs from UTC. A locally-composed bubble
 * (stamped with `new Date().toISOString()`, which always carries 'Z') was
 * never affected — that's why only the group message reproduced it.
 *
 * Fix: always parse relay timestamps as UTC explicitly. If the string
 * already carries a designator ('Z' or a numeric +HH:MM/-HH:MM offset),
 * trust it as-is; otherwise append 'Z'.
 */
const HAS_TZ = /[Zz]$|[+-]\d{2}:?\d{2}$/;

export function relayTimestampToIso(raw: string | null | undefined): string {
  const s = String(raw ?? '').trim();
  if (!s) return new Date().toISOString();
  return HAS_TZ.test(s) ? s : `${s}Z`;
}
