// Deno KV — the relay's store (built into the runtime, zero-config).
// Phase 1: single KV namespace. Phase 2: swap for Postgres/Mongo behind the
// same helper functions if scale demands it — nothing else changes.
export const KV = await Deno.openKv(Deno.env.get("VEIL_KV_PATH") || undefined);
