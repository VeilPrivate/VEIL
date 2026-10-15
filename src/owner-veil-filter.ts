/**
 * b101 ghost-row filter — the VeilNote/VeilVault twin of the b99 session
 * ghost filter in App.tsx.
 *
 * The relay lists these rows by ACCOUNT, and a Nothing-at-Rest identity reset
 * (or any identity reset) creates a NEW Veil ID without logging the account
 * out — so the old identity's rows reappear forever: notes as undecryptable
 * "(encrypted on this note key)" ghosts, vaults with their plaintext name
 * visible. Rows tagged (owner_veil_id) with a different identity than the
 * current local one belong to an extinct identity and are hidden, IN MEMORY
 * ONLY — a phrase-restore of the old identity brings them back. Untagged rows
 * (created before this field existed) can't be classified and stay visible.
 */
export function visibleUnderIdentity<T extends { owner_veil_id?: string | null }>(
  rows: T[],
  veilId: string | null | undefined,
): T[] {
  if (!veilId) return rows; // no identity on this device (or decoy mode) — nothing to filter against
  return rows.filter((r) => !r.owner_veil_id || r.owner_veil_id === veilId);
}
