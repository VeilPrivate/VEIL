import type { SessionRow } from './screens/SessionsScreen';

/**
 * b71 FIX (owner report: "group chats show up twice on native devices").
 *
 * A VEIL group fans out into MULTIPLE VeilSession rows on the relay:
 *   - the creator's MAIN session (activate=true, no responder ever joins it)
 *   - one INVITE session per invite link (plain invite sessions, but each
 *     carries the same group_token)
 * All of those rows are participant-scoped into the CREATOR's session list
 * (the creator is the initiator of every one), and before this fix each
 * rendered as its own thread — a group with one invite showed twice, with
 * two invites three times, etc. Joined members see their own invite row,
 * and some server paths surface the main row too, so both roles can
 * observe duplicates.
 *
 * collapseGroupRows() keeps exactly ONE row per group_token. Selection
 * score (highest wins, first row breaks ties):
 *   +2  this device holds local ratchet state for the row's token
 *       (the row the app can actually open without a re-handshake)
 *   +1  relay state 'active' (joined / activated beats a stale pending link)
 *   +1  it is the creator's MAIN session (mine && no peer on the row) —
 *       the canonical group thread; invite rows have a peer once joined
 * Non-group rows pass through untouched, and the original list ORDER is
 * preserved: a group renders at the position of its first-seen row.
 *
 * b134 FIX (owner repro Sept 27: "left the group chat and came back — every
 * previous message was gone", on a thread only ~1-2 minutes old, far too
 * soon for the 2h burn window to explain it): the message cache is keyed by
 * the WINNING row's token — cacheMessages(token, ...) / listMessages(token).
 * Every call to collapseGroupRows() recomputes the winner FROM SCRATCH: the
 * sealed check is an async local-storage read that can transiently miss
 * mid-write, relay-side status can flip between fetches, and a tie falls
 * back to "first row in the array" — whose ORDER isn't guaranteed stable
 * across two separate relay fetches. If the winner flips between the poll
 * that cached the live messages and the next reopen's fetch, the app opens
 * a DIFFERENT token's (empty) cache — the messages aren't lost, the app is
 * just reading the wrong shelf. Fix: make selection STICKY. A `previousWinner`
 * lookup gives that group's last-chosen token a decisive bonus so it keeps
 * winning across ties and score noise; it only loses if it's no longer among
 * this group's candidate rows at all (session actually ended/gone).
 */
export async function collapseGroupRows(
  rows: SessionRow[],
  hasLocalState: (token: string) => Promise<boolean> | boolean,
  previousWinner?: (groupToken: string) => string | undefined,
): Promise<SessionRow[]> {
  const slots: Array<{ row?: SessionRow; group?: string }> = [];
  const seenGroups = new Set<string>();
  for (const row of rows) {
    if (row.groupToken) {
      // ONE slot per group (first-seen position) — not one per fan-out row
      if (!seenGroups.has(row.groupToken)) { seenGroups.add(row.groupToken); slots.push({ group: row.groupToken }); }
    } else {
      slots.push({ row });
    }
  }
  const winners = new Map<string, { row: SessionRow; score: number }>();

  for (const row of rows) {
    if (!row.groupToken) continue;
    const sealed = await Promise.resolve(hasLocalState(row.token)).catch(() => false);
    // b134: sticky bonus — the row this group last resolved to keeps a
    // dominant lead (+10, unbeatable by the 0-4 base score) so a transient
    // dip in one of the base signals (sealed race, a status flip, array
    // reorder) can never flip which token's message cache the UI reads.
    const stickyToken = previousWinner?.(row.groupToken);
    const sticky = stickyToken && stickyToken === row.token ? 10 : 0;
    const score =
      sticky +
      (sealed ? 2 : 0) +
      (row.status === 'active' ? 1 : 0) +
      (row.mainGroupRow ? 1 : 0);
    const prev = winners.get(row.groupToken);
    if (!prev || score > prev.score) winners.set(row.groupToken, { row, score });
  }

  return slots.map((s) => (s.row ? s.row : winners.get(s.group as string)?.row ?? ({} as SessionRow)))
    .filter((r) => !!r.token);
}
