// VEIL RELAY — self-hosted Phase 1 (b197-r9)
// The exact URL contract the native client speaks (extracted from relay.ts/auth.ts/chat.ts).
// Deno + Deno KV. Zero external dependencies.
//
// RUN:  deno run -A main.ts          (listens on :8000)
// SEED: deno run -A seed.ts          (creates the founder's user — see seed.ts)
//
// PHASE 1 SCOPE (honest):
//   ✓ auth: login/register/verify-otp/logout (register auto-verifies — OTP email is Phase 2)
//   ✓ generic entity REST: VeilSession, VeilEnvelope, User, VeilAuthNonce, VeilVault, VeilNote...
//   ✓ functions: submitEnvelope, veilSessionGate (activate/notify/burn), purgeExpiredEnvelopes
//   ✓ sweeper: internal interval, purges expired envelopes every 10 min
//   ✗ Phase 2: OTP email delivery, group gate details, agents, vault signed-URLs, TLS (proxy in front)

import { KV } from "./kv.ts";

// Port is env-configurable so a TEST instance can run beside production without
// touching it (systemd sets nothing → 8000; sandbox runs set VEIL_PORT=8001)
const PORT = Number(Deno.env.get("VEIL_PORT") || 8000);
const j = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const json = j; // alias — both spellings used across handlers
const nowIso = () => new Date().toISOString();
const rid = () => crypto.randomUUID().replace(/-/g, "").slice(0, 24);

// ---------- password hashing (PBKDF2-SHA256, 100k — WebCrypto, works in Deno) ----------
async function hashPassword(password: string, salt: string): Promise<string> {
  const keyMaterial = new TextEncoder().encode(salt + ":" + password);
  const key = await crypto.subtle.importKey("raw", keyMaterial, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 100_000, hash: "SHA-256" },
    key,
    256,
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- auth ----------
async function createUser(email: string, password: string) {
  email = email.toLowerCase().trim();
  // b198 ANONYMOUS SIGNUP: the email is a self-declared label — invented
  // addresses are FINE (never verified, never contacted). Only structural
  // sanity is enforced so KV keys stay usable; the signup screen discloses
  // that a forgotten password + lost phrase = unrecoverable account.
  if (!email || email.length > 64 || !email.includes("@")) throw new Error("Enter an email address — it can be invented; it is never verified or contacted");
  const existing = (await KV.get<string>(["user_email", email])).value;
  if (existing) throw new Error("Email already registered");
  const uid = "u_" + rid();
  const salt = crypto.randomUUID().replace(/-/g, "");
  const passHash = await hashPassword(password, salt);
  const user = { id: uid, email, passHash, salt, verified: true, created: nowIso() };
  await KV.set(["user", uid], user);
  await KV.set(["user_email", email], uid);
  return user;
}

async function authUser(req: Request): Promise<{ userId: string; email: string } | null> {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) {
    console.log("[auth-debug] NO TOKEN — header: '" + auth.slice(0, 30) + "' (len " + auth.length + ") | url: " + new URL(req.url).pathname);
    return null;
  }
  if (token.length > MAX_KEY_PART) return null;
  const r = await KV.get<{ userId: string; email: string; exp?: number; last_used?: number }>(["auth", keySafe(token)]);
  // STOLEN-TOKEN WINDOW: auth tokens expire (30 days) and slide while in use —
  // a leaked token is not a lifetime passport. Refresh throttled to 1/hour.
  if (r.value) {
    const now = Date.now();
    if (r.value.exp && r.value.exp < now) { await KV.delete(["auth", keySafe(token)]); return null; }
    if (!r.value.last_used || now - r.value.last_used > 3600_000) {
      await KV.set(["auth", keySafe(token)], { ...r.value, last_used: now, exp: now + 30 * 86400_000 });
    }
  }
  if (!r.value) console.log("[auth-debug] token MISS: prefix='" + token.slice(0, 12) + "' len=" + token.length + " | url: " + new URL(req.url).pathname);
  return r.value ? { userId: r.value.userId, email: r.value.email } : null;
}

/** Client IP as seen through Caddy (X-Forwarded-For) — for per-IP throttles. */
function clientIp(req: Request): string {
  const fwd = req.headers.get("x-forwarded-for") || "";
  return keySafe(fwd.split(",")[0].trim() || "local");
}

// ---------- generic entities ----------
// Rows: ["entity", name, id] → { id, created_date, updated_date, ...fields }
// Token index for VeilSession: ["veil_sess_token", token] → id

async function listEntity(name: string, url: URL, auth?: { userId: string }) {
  const rows: any[] = [];
  for await (const e of KV.list({ prefix: ["entity", name] }, { consistency: "strong" })) {
    rows.push({ ...(e.value as Record<string, unknown>), id: e.key[e.key.length - 1] as string });
  }
  const q = url.searchParams;
  const filters: [string, string][] = [];
  let limit = 200;
  let skip = 0;
  let sortField: string | null = null;
  let sortDesc = false;
  for (const [k, v] of q) {
    if (k === "limit") { limit = Math.max(1, parseInt(v) || 200); continue; }
    if (k === "sort") {
      sortField = v.replace(/^-/, "");
      sortDesc = v.startsWith("-");
      continue;
    }
    if (k === "skip") { skip = Math.max(0, parseInt(v) || 0); continue; }
    if (k === "page" || k === "page_size") continue;
    filters.push([k, v]);
  }
  let out = rows;
  // HARVEST GUARD: shared-entity lists MUST carry their scoping filter — an
  // unfiltered list would dump every user's sessions/envelopes to any
  // authenticated account (metadata + ciphertext harvesting)
  // b198 (live-caught, group battery): GROUP envelopes are scoped by
  // group_token — the group receive channel is one shared stream, so a
  // session_token filter is structurally impossible for groups. A group_token
  // list is accepted as valid scoping ONLY for group members: the gmember row
  // written at attest carries the member's account_hash, so the check is
  // exact and cheap. Every other account keeps the 403 — the guard keeps its
  // teeth (an outsider knowing a group token still cannot read its stream).
  const groupScoped = name === "VeilEnvelope" && !!q.get("group_token");
  const requiredFilter = REQUIRED_LIST_FILTER[name];
  if (requiredFilter && !q.get(requiredFilter) && !groupScoped) {
    return { __blocked: `list requires a ${requiredFilter} filter` } as any;
  }
  if (groupScoped && auth) {
    const acct = await accountHashOf(auth.userId);
    let member = false;
    for await (const e of KV.list({ prefix: ["veil_gmember", keySafe(q.get("group_token") as string)] }, { consistency: "strong" })) {
      if (String((e.value as Record<string, unknown>).account_hash || "") === acct) { member = true; break; }
    }
    if (!member) return { __blocked: "group envelope list requires group membership" } as any;
  }
  // b198 DELETION OBSERVABILITY (live battery Oct 15): a VeilEnvelope list
  // scoped to a session that no longer exists (or has ended) must NOT answer
  // 200 + empty — the native sync reads an empty page as "nothing new" and
  // loops inside a dead thread forever (✕-end, + supersede and the sweeper
  // all left the peer blind; the auto-switch needs the sync ERROR to trigger
  // its forced list refresh). A 404 "Session not found" makes every deletion
  // path observable to every client in one pass.
  if (name === "VeilEnvelope") {
    const st = q.get("session_token");
    if (st) {
      const sess = await findSessionByToken(st);
      if (!sess || String(sess.state || "") === "ended") {
        return { __notfound: "Session not found" } as any;
      }
    }
  }
  // owner-scoped entities only ever answer their owner's queries
  if (auth && OWNER_SCOPED_ENTITIES.has(name)) {
    const acct = await accountHashOf(auth.userId);
    out = out.filter((r) => String((r as any)._acct ?? "") === acct);
  }
  for (const [k, v] of filters) out = out.filter((r) => String((r as any)[k] ?? "") === v);
  if (sortField) {
    out.sort((a, b) => {
      const av = String((a as any)[sortField!] ?? ""), bv = String((b as any)[sortField!] ?? "");
      return sortDesc ? bv.localeCompare(av) : av.localeCompare(bv);
    });
  } else {
    out.sort((a, b) => String(b.created_date ?? "").localeCompare(String(a.created_date ?? "")));
  }
  return out.slice(skip, skip + limit);
}

const OWNER_SCOPED_ENTITIES = new Set(["VeilVault", "VeilNote", "VeilPushToken"]);
const REQUIRED_LIST_FILTER: Record<string, string> = {
  VeilSession: "token",
  VeilEnvelope: "session_token",
  VeilPushToken: "expo_token",
};

async function createEntity(name: string, body: Record<string, unknown>, auth?: { userId: string }) {
  const ridv = (body.id as string) || rid();
  // owner-scoped entities (vaults/notes) are tagged with the creating account
  if (auth && OWNER_SCOPED_ENTITIES.has(name) && !body._acct) {
    body = { ...body, _acct: await accountHashOf(auth.userId) };
  }
  // session tokens are unique pointers — a duplicate create must NOT overwrite
  // the index (it would silently repoint submitEnvelope/burn at a hashless row)
  if (name === "VeilSession" && typeof body.token === "string" && body.token) {
    const existing = (await KV.get<string>(["veil_sess_token", body.token])).value;
    if (existing) return { __conflict: true, id: existing } as any;
    // ATOMIC claim of the token (check-and-set) — closes the concurrent-retry
    // race where two creates could both pass the existence check
    const claim = await KV.atomic()
      .check({ key: ["veil_sess_token", body.token], versionstamp: null })
      .set(["veil_sess_token", body.token], ridv)
      .commit();
    if (!claim.ok) return { __conflict: true, id: (await KV.get<string>(["veil_sess_token", body.token])).value ?? "" } as any;
  }
  const row = { id: ridv, created_date: nowIso(), updated_date: nowIso(), ...body };
  await KV.set(["entity", name, ridv], row);
  // b198 (cutover battery): a NEW 1:1 session addressed to a Veil ID is an
  // invite — the addressee gets NO envelope-insert ping from notifySent (an
  // invite carries no message), so without this they'd never see a lock-screen
  // notification for "someone wants to talk". Fire-and-forget, coalesced per
  // veil id, skipped for groups and peerless rows; the ping is contentless
  // ("Notification") exactly like every other push.
  if (name === "VeilSession") {
    const vid = String((body as Record<string, unknown>).responder_veil_id || "");
    const isPendingInvite = String((body as Record<string, unknown>).state || "") === "pending" && !String((body as Record<string, unknown>).responder_client_id || "");
    if (isPendingInvite && validVeilId(vid) && !(body as Record<string, unknown>).group_token) {
      void pushInvitePing(vid);
    }
  }
  return row;
}

// b198: invite ping — same contentless shape as message pings; coalesced per
// addressee so a burst of + presses can't stack pushes.
async function pushInvitePing(veilId: string) {
  try {
    const ck = ["push_coalesce_invite", keySafe(veilId)];
    if (Date.now() - ((await KV.get<number>(ck)).value ?? 0) < 30000) return;
    await KV.set(ck, Date.now());
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const acct = id ? String(id.account_hash || "") : "";
    if (!acct) return;
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") !== acct) continue;
      const t = String(row.expo_token || "");
      void fetch("https://exp.host/--/api/v2/push/send", { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ to: t, title: "VEIL", body: "Notification", sound: "default", priority: "high", data: { kind: "new-invite" } }) }).then(async (r) => { const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string } } | null; console.log("[push] invite ticket " + t.slice(-10) + ": " + (d?.data?.status ?? r.status) + (d?.data?.message ? " " + d.data.message : "")); }).catch(() => undefined);
    }
  } catch (e) { console.log("[push] invite alert failed (non-fatal)"); }
}

async function getEntity(name: string, eid: string) {
  return (await KV.get(["entity", name, eid])).value ?? null;
}

async function deleteEntity(name: string, eid: string) {
  const row = (await KV.get(["entity", name, eid])).value as Record<string, unknown> | null;
  await KV.delete(["entity", name, eid]);
  if (row && name === "VeilSession" && typeof row.token === "string") {
    await KV.delete(["veil_sess_token", row.token]);
  }
  return row;
}

async function findSessionByToken(token: string) {
  const eid = (await KV.get<string>(["veil_sess_token", keySafe(token)])).value;
  if (!eid) return null;
  return (await KV.get(["entity", "VeilSession", eid])).value as Record<string, unknown> | null;
}

// ---------- functions: submitEnvelope ----------
async function fnSubmitEnvelope(auth: { userId: string }, body: Record<string, any>) {
  // b198 HARDENING (live-caught during the vault battery): Deno KV values cap
  // at 64KB — an oversized envelope used to crash the handler into a 500
  // ("Value too large"). Legit chat never approaches this (M-4 chunks cap at
  // 4096 bytes); the guard turns a hostile/buggy oversized envelope into a
  // clean 413. Media never rides envelopes at all (ciphertext lives in blob
  // storage; the envelope carries only the descriptor).
  const b64Ct = String(body?.ciphertext || "");
  if (b64Ct.length > 48000) return j({ error: "Envelope too large", message: "Envelope too large" }, 413);
  // SPEC §3/§4: 150 envelopes/min per account
  const rl = await rateLimit("env:" + auth.userId, 150, 60_000, 2);
  if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
  const { session_token, client_id, ciphertext, iv, header, expires_at, ttl_seconds } = body;
  if (!session_token || !ciphertext || !iv || !header) {
    return j({ error: "Missing envelope fields", message: "Missing envelope fields" }, 400);
  }
  const session = await findSessionByToken(session_token);
  if (!session) return j({ error: "Session not found", message: "Session not found" }, 404);
  if (session.state !== "active") return j({ error: "Session is not available", message: "Session is not available" }, 409);

  // b198 GROUP CLAUSE — faithful port of the Base44 submit's veil-group-1
  // branch (this was entirely MISSING from my submit: group envelopes were
  // stored without their group_token, so the group-scoped receive channel
  // could never see them — One's 'hey' vanished exactly there).
  let headerObj: Record<string, unknown> | null = null;
  try { headerObj = JSON.parse(String(header)); } catch { /* 1:1 path: opaque header string is fine */ }
  const isGroupEnvelope = !!headerObj && (headerObj as Record<string, unknown>).v === "veil-group-1";
  let groupToken = "";
  if (isGroupEnvelope) {
    const gh = headerObj as Record<string, unknown>;
    groupToken = typeof body.group_token === "string" ? body.group_token : "";
    if (!groupToken || !/^[0-9a-f]{8,128}$/.test(groupToken)) return j({ error: "Missing or invalid group_token", message: "Missing or invalid group_token" }, 400);
    if (gh.v !== "veil-group-1" || typeof gh.sid !== "string" || !gh.sid || !Number.isInteger(gh.ge) || (gh.ge as number) < 0 || !Number.isInteger(gh.n) || (gh.n as number) < 0) {
      return j({ error: "Invalid group message header", message: "Invalid group message header" }, 400);
    }
    if (String(body.sender_client_id || "") !== String(gh.sid)) return j({ error: "Sender tag does not match the group header", message: "Sender tag does not match the group header" }, 400);
  }

  // write-secret authorization: sha256(write_secret) must match a stored hash
  const writeSecret = String(body.write_secret || "");
  const sha256 = async (v: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const wHash = writeSecret ? await sha256(writeSecret) : "";
  const iHash = String(session.initiator_write_hash || "");
  const rHash = String(session.responder_write_hash || "");
  if (!wHash || (wHash !== iHash && wHash !== rHash)) {
    console.log("[submit-debug] MISMATCH — the session row found:\n" + JSON.stringify(session, null, 1).slice(0, 800));
    return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }

  // b198 GROUP VALIDATIONS (Base44 order): session-group binding, header epoch
  // vs the server-side group epoch, and roster membership of the sender tag.
  if (isGroupEnvelope) {
    const gh = headerObj as Record<string, unknown>;
    if (!session.group_token || String(session.group_token) !== groupToken) {
      return j({ error: "This session does not belong to that group", message: "This session does not belong to that group" }, 403);
    }
    if (Number(session.group_epoch || 0) !== Number(gh.ge)) {
      return j({ error: "Message epoch does not match the group epoch", message: "Message epoch does not match the group epoch" }, 400);
    }
    // The fetch limit MUST cover the whole roster — a limit below the cohort
    // cap silently refuses legitimate members (Base44 shared-limits lesson).
    const members: Record<string, unknown>[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
      const m = e.value as Record<string, unknown>;
      if (String(m.group_token || "") === groupToken) members.push(m);
    }
    let rostered = false;
    for (const m of members.slice(0, 100)) { // b198: cohort cap 100
      const vid = String(m.veil_id || "");
      if (!vid) continue;
      const tag = "g" + [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`veil-group-sender:${groupToken}:${gh.ge}:${vid}`))).slice(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
      if (tag === String(body.sender_client_id || "")) { rostered = true; break; }
    }
    if (!rostered) return j({ error: "Sender is not a member of this group epoch", message: "Sender is not a member of this group epoch" }, 403);
  }

  // b198 DIAGNOSTIC (two-dial burn investigation): log the incoming ttl + the
  // session's dials — numbers only, never content. Remove after the root cause lands.
  console.log("[ttl-diag] incoming ttl_seconds=" + String(body.ttl_seconds) + " | session dials: burn=" + session.default_ttl_seconds + " horizon=" + session.expire_after_seconds + " burnAfterOpen=" + session.burn_after_open);
  // b198: the clamp rises to the 30-day tier (the Founding Tester Forum's
  // backlog lifetime) — was 36h, which would have killed a 30-day-dial group's
  // messages in a day and a half.
  const ttl = Math.min(Number(ttl_seconds) || 86400, 2592000);
  const envId = rid();
  const env = {
    id: envId,
    session_token,
    // b198: group envelopes carry their group_token + header epoch — the
    // group-scoped receive channel filters on exactly these.
    ...(groupToken ? { group_token: groupToken, group_epoch: Number((headerObj as Record<string, unknown>).ge) } : {}),
    client_id,
    sender_client_id: String(body.sender_client_id || ""),
    ciphertext: String(body.ciphertext || ""),
    iv: String(body.iv || ""),
    header: String(body.header || ""),
    byte_length: Number(body.byte_length) || 0,
    protocolVersion: String(body.protocolVersion || "veil-ratchet-4"),
    created_date: nowIso(),
    expires_at: new Date(Date.now() + ttl * 1000).toISOString(),
  };
  await KV.set(["entity", "VeilEnvelope", envId], env);
  await KV.set(["veil_env", session_token, envId], env);
  await KV.set(["veil_sess_token", session_token], session.id as string);
  await touchSession(session_token);
  return json({ id: envId });
}

async function touchSession(token: string, side?: "initiator" | "responder") {
  const eid = (await KV.get<string>(["veil_sess_token", keySafe(token)])).value;
  if (!eid) return;
  const row = (await KV.get(["entity", "VeilSession", eid])).value as Record<string, unknown> | null;
  if (!row) return;
  row.last_activity = nowIso();
  // b162 presence parity: the client reads initiator_seen_at / responder_seen_at
  if (side === "initiator") row.initiator_seen_at = nowIso();
  if (side === "responder") row.responder_seen_at = nowIso();
  await KV.set(["entity", "VeilSession", eid], row);
}

// (veilSessionGate moved to the PHASE 2 section below — full action set)

// ---------- functions: purgeExpiredEnvelopes ----------
async function fnPurgeExpired() {
  let deleted = 0;
  const now = Date.now();
  for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    const exp = new Date(String(row.expires_at || "")).getTime();
    if (Number.isFinite(exp) && exp < now) { await KV.delete(e.key); deleted++; }
  }
  return json({ purged: { success: true, deleted }, sessions: { success: true, deleted: 0 }, links: { success: true, deleted: 0 }, loginGuards: { success: true, deleted: 0 }, nonces: { success: true, deleted: 0 } });
}

// ==================== PHASE 2 — full client contract (b198 port) ====================
// Contract extracted from vendor/device/src/{relay,contact,group-session,groups,transfer,
// silent-auth,restore,auth}.ts + docs/audit/RELAY-PORT-SPEC.md. Every response shape
// below matches what the client actually parses (data-wrapped and/or bare).

const enc = new TextEncoder();
const b64e = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64d = (s: string) => new Uint8Array([...atob(s)].map((c) => c.charCodeAt(0)));
const sha256hex = async (v: string) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(v)))].map((b) => b.toString(16).padStart(2, "0")).join("");

async function ed25519Verify(pubB64: string, msgBytes: Uint8Array, sigB64: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", b64d(pubB64) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, b64d(sigB64) as BufferSource, msgBytes as BufferSource);
  } catch (e) {
    console.log("[verify] ed25519 verify error:", String((e as Error).message).slice(0, 120));
    return false;
  }
}

// ---------- per-account rate limiter (SPEC §3: 150 env/min; identity gate 429 shape) ----------
async function rateLimit(key: string, cap: number, windowMs: number, lockMinutes: number): Promise<{ locked: boolean; retry_minutes: number } | null> {
  const bucket = Math.floor(Date.now() / windowMs);
  const k = ["rl", key, String(bucket)];
  const n = ((await KV.get<number>(k)).value ?? 0) + 1;
  await KV.set(k, n);
  if (n > cap) return { locked: true, retry_minutes: lockMinutes };
  return null;
}

async function accountHashOf(userId: string) {
  return "ah_" + (await sha256hex("veil-acct:" + userId));
}

// ---------- veilIdentityGate (public keys only — never private material) ----------
async function fnVeilIdentityGate(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body.action || "");
  const veilId = String(body.veil_id || "").trim();
  if (veilId.length > MAX_VEIL_ID) return j({ error: "Invalid identity", message: "Invalid identity" }, 400); // P7 fix
  if (action === "register") {
    // b198 tuning: 20/min + 10-min lock punished real testing (background
    // loops + manual retries trip it instantly). 60/min + 2-min lock keeps
    // the abuse wall while letting humans + heartbeats coexist.
    const rl = await rateLimit("idreg:" + auth.userId, 60, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    if (!veilId || !body.IK_pub) return j({ error: "Invalid identity", message: "Invalid identity" }, 400);
    // IDENTITY-HIJACK GUARD + b198 RESTORE FIX v2 (the v1 byte-identical rule
    // was wrong: the IK is the identity and derives deterministically from the
    // phrase, but SPK/PQ are FRESHLY GENERATED PREKEYS per restore — no restore
    // can ever reproduce them, and it must not: they are rotatable by design).
    // Rules, mirroring the key hierarchy:
    //   - a DIFFERENT IK on an existing veil_id = a different identity claiming
    //     the label -> 409 always (bound or not — the IK defines the identity);
    //   - same IK + BOUND: prekey rotation allowed ONLY for the bound account
    //     (the signed-in caller proves ownership by session) -> update, 200;
    //   - same IK + UNBOUND: rotate freely (unbound rows are trusted for
    //     nothing until bound).
    const existingId = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    if (existingId) {
      const sameIk = String(existingId.IK_pub || "") === String(body.IK_pub);
      if (!sameIk) {
        console.warn("register-refused", { reason: "different-identity", veilId: veilId.slice(0, 8) });
        return j({ error: "Identity already bound", message: "Identity already bound" }, 409);
      }
      if (existingId.bound === true && String(existingId.account_hash || "") !== String(await accountHashOf(auth.userId))) {
        console.warn("register-refused", { reason: "bound-to-another-account", veilId: veilId.slice(0, 8) });
        return j({ error: "Identity already bound", message: "Identity already bound" }, 409);
      }
      // prekey rotation (SPK/PQ) — binding untouched
      await KV.set(["veil_identity", veilId], { ...existingId, SPK_pub: String(body.SPK_pub || ""), SPK_sig: String(body.SPK_sig || ""), pq_pub: String(body.pq_pub || ""), updated_date: nowIso() });
      return json({ ok: true, data: { veil_id: veilId, restored: existingId.bound === true } });
    }
    const rec = {
      veil_id: veilId,
      IK_pub: String(body.IK_pub),
      SPK_pub: String(body.SPK_pub || ""),
      SPK_sig: String(body.SPK_sig || ""),
      pq_pub: String(body.pq_pub || ""),
      account_hash: await accountHashOf(auth.userId),
      bound: false,
      created_date: nowIso(),
      updated_date: nowIso(),
    };
    await KV.set(["veil_identity", veilId], rec);
    return json({ ok: true, data: { veil_id: veilId } });
  }
  if (action === "challenge") {
    // b167: the 429 body carries ONLY {locked:true, retry_minutes} — NO message field
    const rl = await rateLimit("idchallenge:" + auth.userId, 60, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    if (!veilId) return j({ error: "Invalid identity", message: "Invalid identity" }, 400);
    // nonce is base64 — ikSign(seed, nonce) signs fromB64(nonce), so verification
    // at bind time decodes the nonce the same way
    const nonce = b64e(crypto.getRandomValues(new Uint8Array(32)));
    await KV.set(["id_nonce", veilId], { nonce, exp: Date.now() + 10 * 60_000 });
    return json({ data: { nonce } });
  }
  if (action === "bind") {
    const nonceRow = (await KV.get<{ nonce: string; exp: number }>(["id_nonce", veilId])).value;
    if (!nonceRow || nonceRow.exp < Date.now()) return j({ error: "Nonce expired", message: "Nonce expired" }, 400);
    const rec = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    if (!rec) return j({ error: "Identity not found", message: "Identity not found" }, 404);
    const ok = await ed25519Verify(String(rec.IK_pub), b64d(nonceRow.nonce), String(body.signature || ""));
    if (!ok) return j({ error: "Signature verification failed", message: "Signature verification failed" }, 403);
    rec.bound = true;
    rec.updated_date = nowIso();
    await KV.set(["veil_identity", veilId], rec);
    await KV.delete(["id_nonce", veilId]);
    return json({ ok: true, data: { bound: true } });
  }
  if (action === "lookup") {
    const rl = await rateLimit("idlookup:" + auth.userId, 300, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    const rec = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    // lookup serves BOUND identities only — binding is the key-possession proof;
    // an unbound (unproven) record would let an attacker publish fake keys
    if (!rec || rec.bound !== true) return j({ error: "Identity not found", message: "Identity not found" }, 404);
    // b198: BARE bundle — exactly Base44's lookup shape (Response.json({veil_id,
    // ...keys...})). My {data:...} wrap made the group rotate's pq_pub read
    // resolve undefined ("no published PQ prekey") while the key sat published
    // on the row; the other lookup consumers were already shape-tolerant.
    return json({ veil_id: rec.veil_id, IK_pub: rec.IK_pub, SPK_pub: rec.SPK_pub, SPK_sig: rec.SPK_sig, pq_pub: rec.pq_pub });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- veilSessionGate — the full action set ----------
function wsHashOf(writeSecret: unknown) {
  return writeSecret ? sha256hex(String(writeSecret)) : "";
}

function sessionMatchesClient(session: Record<string, any>, clientId: string, veilId?: string) {
  if (clientId) {
    if (String(session.initiator_client_id || "") === clientId) return true;
    if (String(session.responder_client_id || "") === clientId) return true;
  }
  if (veilId) {
    if (String(session.initiator_veil_id || "") === veilId) return true;
    if (String(session.responder_veil_id || "") === veilId) return true;
  }
  return false;
}

async function listSessionsFor(clientId: string, veilId?: string) {
  const out: Record<string, unknown>[] = [];
  for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    if (sessionMatchesClient(row, clientId, veilId)) out.push({ ...(row as any), id: e.key[e.key.length - 1] });
  }
  out.sort((a, b) => String(b.created_date ?? "").localeCompare(String(a.created_date ?? "")));
  return out.slice(0, 200);
}

async function deleteSessionEnvelopes(sessionToken: string) {
  let n = 0;
  for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    if (String(row.session_token || "") === sessionToken) { await KV.delete(e.key); n++; }
  }
  return n;
}

// ---------- push delivery (b85 parity — zero-content banner) ----------
async function pushNewMessageAlert(session: Record<string, any>, side: "initiator" | "responder") {
  try {
    // resolve the recipient: veil_id → identity → account → push tokens
    const veilId = String(side === "initiator" ? session.initiator_veil_id : session.responder_veil_id || "");
    if (!veilId) return; // invite-link sessions carry no veil ids — cannot map yet
    const identity = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const acct = identity ? String(identity.account_hash || "") : "";
    if (!acct) return;
    const tokens: string[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") === acct) tokens.push(String(row.expo_token || ""));
    }
    if (!tokens.length) return;
    const receipts = await Promise.allSettled(tokens.map(async (t) => {
      const r = await fetch("https://exp.host/--/api/v2/push/send", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ to: t, title: "VEIL", body: "New message", sound: "default", priority: "high", data: { kind: "new-message" } }),
      });
      const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string; details?: { error?: string } } } | null;
      const status = d?.data?.status ?? "http-" + r.status;
      console.log("[push] expo ticket for " + t.slice(-10) + ": " + status + (d?.data?.message ? " — " + d.data.message : "") + (d?.data?.details?.error ? " (" + d.data.details.error + ")" : ""));
      return status;
    }));
    const okN = receipts.filter(r => r.status === "fulfilled" && r.value === "ok").length;
    console.log("[push] new-message alert: " + okN + "/" + tokens.length + " accepted by Expo for " + veilId.slice(0, 8) + "…");
  } catch (e) {
    console.log("[push] notify push failed (non-fatal): " + String((e as Error).message || e).slice(0, 120));
  }
}

// b198 CALL RING BURST: a call must RING, not whisper — a burst of pushes
// across the ring window (one every 2.5s for ~20s) buzzes the callee's lock
// screen on-and-off until they open, and each banner says "Incoming call" so
// it is unmistakable next to a message's "Notification". Same contentless
// threat model: no caller, no session, no content — only "a call is ringing
// on your account right now", which the ring itself announces anyway.
const CALL_BURST_COUNT = 9;
const CALL_BURST_GAP_MS = 2500;
async function pushCallBurst(session: Record<string, any>, side: "initiator" | "responder") {
  try {
    const veilId = String(side === "initiator" ? session.initiator_veil_id : session.responder_veil_id || "");
    if (!veilId) return;
    const identity = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const acct = identity ? String(identity.account_hash || "") : "";
    if (!acct) return;
    const tokens: string[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") === acct) tokens.push(String(row.expo_token || ""));
    }
    if (!tokens.length) return;
    void (async () => {
      for (let i = 0; i < CALL_BURST_COUNT; i++) {
        if (i > 0) await new Promise((res) => setTimeout(res, CALL_BURST_GAP_MS));
        await Promise.allSettled(tokens.map(async (t) => {
          const r = await fetch("https://exp.host/--/api/v2/push/send", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            // b198 (owner): the burst pushes carry the app's ring sound — under
            // Metro it falls back to the default chime; on the EAS build (the
            // sound bundled with the app) the lock screen RINGS with the call.
            body: JSON.stringify({ to: t, title: "VEIL", body: "Incoming call", sound: "veil-ring.wav", priority: "high", data: { kind: "call" } }),
          });
          const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string } } | null;
          console.log("[push] call burst " + (i + 1) + "/" + CALL_BURST_COUNT + " for " + t.slice(-10) + ": " + (d?.data?.status ?? r.status));
        }));
      }
      console.log("[push] call ring burst complete for " + veilId.slice(0, 8) + "…");
    })();
  } catch (e) {
    console.log("[push] call burst failed (non-fatal): " + String((e as Error).message || e).slice(0, 120));
  }
}

async function fnVeilSessionGate(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body.action || "");
  // tokenless actions first — list/purge address the ACCOUNT, not one session
  if (action === "list") {
    const rows = await listSessionsFor(String(body.client_id || ""), body.veil_id ? String(body.veil_id) : undefined);
    return json({ data: rows });
  }
  if (action === "purge") {
    const cid = String(body.client_id || "");
    if (!cid) return j({ error: "client_id required", message: "client_id required" }, 400);
    let deleted = 0;
    for (const row of await listSessionsFor(cid)) {
      await deleteSessionEnvelopes(String(row.token || ""));
      await KV.delete(["entity", "VeilSession", String(row.id)]);
      const tok = String(row.token || "");
      if (tok) await KV.delete(["veil_sess_token", tok]);
      deleted++;
    }
    return json({ ok: true, data: { deleted } });
  }
  const token = String(body.token || "");
  const session = await findSessionByToken(token);
  if (!session) {
    if (action === "burn") return json({ ok: true, already_gone: true, burned: false, reason: "session_gone" });
    if (action === "end") return json({ ok: true, data: { ended: true, already_gone: true } });
    return j({ error: "Session not found", message: "Session not found" }, 404);
  }
  const wHash = await wsHashOf(body.write_secret);
  const isInitiator = !!wHash && wHash === String(session.initiator_write_hash || "");
  const isResponder = !!wHash && wHash === String(session.responder_write_hash || "");
  const isParty = isInitiator || isResponder;

  if (action === "notify") {
    if (!isParty) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
    await touchSession(token, isInitiator ? "initiator" : "responder");
    // b85 LOCKED-SCREEN DELIVERY — relay-side push (Phase 3 item, now wired):
    // fire-and-forget Expo push to the OTHER participant. The push carries
    // ZERO content — same generic-banner threat model as the local post-decrypt
    // banner. Cover traffic never calls notify.
    void pushNewMessageAlert(session, isInitiator ? "responder" : "initiator");
    return json({ ok: true });
  }
  if (action === "activate") {
    // b87/b88 contract: exactly these two rejection messages for role/type mismatches
    if (!isInitiator) {
      if (!session.group_token && !String(session.responder_client_id || "")) {
        return j({ error: "Only group sessions can be activated without a peer", message: "Only group sessions can be activated without a peer" }, 400);
      }
      return j({ error: "Only the session creator can activate", message: "Only the session creator can activate" }, 400);
    }
    if (session.state !== "active") {
      if (session.state === "ended") return j({ error: "Session is not active", message: "Session is not active" }, 409);
      session.state = "active";
      session.updated_date = nowIso();
      await KV.set(["entity", "VeilSession", String(session.id)], session);
    }
    await touchSession(token);
    return json({ ok: true, data: { session } });
  }
  if (action === "join") {
    if (String(session.state || "") === "ended") return j({ error: "Session has ended", message: "Session has ended" }, 409);
    if (!isResponder && !isInitiator) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
    session.responder_client_id = String(body.client_id || "");
    session.responder_display_name = String(body.display_name || "");
    session.responder_pub_jwk = String(body.responder_pub_jwk || "");
    session.responder_ratchet_pub_jwk = String(body.responder_ratchet_pub_jwk || "");
    session.responder_pq_ct = String(body.responder_pq_ct || "");
    session.session_fingerprint = String(body.fingerprint || "");
    session.state = "active";
    session.last_activity = nowIso();
    session.updated_date = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ ok: true, data: { session } });
  }
  if (action === "peek") {
    if (!isParty) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
    return json({ data: { session } });
  }
  if (action === "heartbeat") {
    if (!isParty) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
    await touchSession(token, isInitiator ? "initiator" : "responder");
    return json({ ok: true });
  }
  if (action === "bump") {
    if (!isParty) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
    const horizon = Math.max(300, Number(session.expire_after_seconds) || 86400);
    const cur = new Date(String(session.expires_at || "")).getTime();
    const next = Date.now() + horizon * 1000;
    if (!Number.isFinite(cur) || cur < next) {
      session.expires_at = new Date(next).toISOString();
      session.updated_date = nowIso();
      await KV.set(["entity", "VeilSession", String(session.id)], session);
    }
    await touchSession(token);
    return json({ ok: true, data: { session } });
  }
  if (action === "verify") {
    // b198 DIAGNOSTIC (verify-failure hunt): which side matched, ws present/absent —
    // numbers + booleans only, never secrets. Remove after root cause lands.
    console.log("[verify-diag] token=" + token.slice(0, 8) + "… ws=" + (body.write_secret ? "present(len " + String(body.write_secret).length + ")" : "NULL") + " initMatch=" + isInitiator + " respMatch=" + isResponder + " state=" + session.state);
    if (!isParty) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
    if (isInitiator) session.initiator_verified = true;
    if (isResponder) session.responder_verified = true;
    session.updated_date = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ data: { session } });
  }
  if (action === "end") {
    // b65: client_id is PARTICIPATION PROOF — lets the invited party end peer-created threads
    const cid = String(body.client_id || "");
    const byClient = !!cid && (String(session.initiator_client_id || "") === cid || String(session.responder_client_id || "") === cid);
    if (!isParty && !byClient) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
    // LIVE-RELAY PARITY (the zombie bug): end DELETES the row for real — an
    // ended-but-listed row resurrects as a zombie thread on every poll and
    // breaks the + supersede flow (old + new threads from the same contact)
    const envs = await deleteSessionEnvelopes(token);
    await KV.delete(["entity", "VeilSession", String(session.id)]);
    await KV.delete(["veil_sess_token", keySafe(token)]);
    return json({ ok: true, data: { ended: true, deleted: true, envelopes_deleted: envs } });
  }
  if (action === "burn") {
    const envelopeId = String(body.envelope_id || "");
    const env = (await KV.get(["entity", "VeilEnvelope", envelopeId])).value as Record<string, unknown> | null;
    if (!env || String(env.session_token || "") !== token) {
      return j({ error: `Entity VeilEnvelope with ID ${envelopeId} not found`, message: `Entity VeilEnvelope with ID ${envelopeId} not found` }, 404);
    }
    // two-dial model (owner spec b197-r8l): burn = shorten the relay copy to
    // the session's burn-after-open window; NEVER extends (re-burn is a no-op)
    const burnWindow = Math.max(300, Number(session.default_ttl_seconds) || 300);
    const cur = new Date(String(env.expires_at || "")).getTime();
    const newExp = Date.now() + burnWindow * 1000;
    if (cur > newExp) {
      env.expires_at = new Date(newExp).toISOString();
      await KV.set(["entity", "VeilEnvelope", envelopeId], env);
    }
    await touchSession(token);
    return json({ ok: true, burned: true, reason: "shortened" });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// b198: a group member's registered push tokens (owner-scoped rows).
async function groupMemberPushTokens(acct: string): Promise<string[]> {
  const out: string[] = [];
  for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    if (String(row._acct || "") === acct && String(row.expo_token || "")) out.push(String(row.expo_token));
  }
  return out;
}

// ---------- veilGroupGate ----------
async function groupRecord(groupToken: string) {
  return (await KV.get<Record<string, any>>(["veil_group", groupToken])).value ?? { epoch: 0, pq_pub: "", created_date: nowIso() };
}

async function fnVeilGroupGate(auth: { userId: string; email?: string }, body: Record<string, any>) {
  // b198 FAITHFUL PORT of base44_functions_veilGroupGate_entry.ts (the
  // founder's directive: stop interpreting, mirror the proven source
  // action-for-action). Every response shape, validation order and storage
  // semantic below mirrors the extracted Base44 entry — the client was built
  // against THIS contract, and my improvised KV-row variant diverged from it
  // in four ways (double-wrapped roster, wrong epoch source, no member
  // entity rows, no role/deny-list) which broke groups end to end.
  const tryB64Len = (v: unknown, bytes: number): boolean => {
    if (typeof v !== "string" || !v) return false;
    try {
      const raw = Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
      return raw.length === bytes;
    } catch { return false; }
  };
  const HEX_TOKEN = /^[0-9a-f]{8,128}$/;
  const B58_ID = /^[1-9A-HJ-NP-Za-km-z]{16}$/;
  const action = ["attest", "rotate", "evict", "roster", "notify"].includes(String(body?.action || "")) ? String(body.action) : null;
  if (!action) return j({ error: "Unknown action", message: "Unknown action" }, 400);
  const groupToken = typeof body.group_token === "string" ? body.group_token : "";
  const sessionToken = typeof body.session_token === "string" ? body.session_token : "";
  if (!HEX_TOKEN.test(groupToken) || !HEX_TOKEN.test(sessionToken)) {
    return j({ error: "Invalid group or session token", message: "Invalid group or session token" }, 400);
  }
  const session = await findSessionByToken(sessionToken);
  if (!session) return j({ error: "Session not found", message: "Session not found" }, 404);
  if (!session.group_token || session.group_token !== groupToken) {
    return j({ error: "This session does not belong to that group", message: "This session does not belong to that group" }, 403);
  }
  if (String(session.state || "") !== "active") {
    return j({ error: "This session is not active", message: "This session is not active" }, 400);
  }
  const wHash = await wsHashOf(body?.write_secret);
  const slot = wHash && (wHash === String(session.initiator_write_hash || "") ? "initiator" : (wHash === String(session.responder_write_hash || "") ? "responder" : null));
  if (!slot) {
    console.warn("group-credential-refused", { action, token: sessionToken.slice(0, 8), state: String(session.state), presented: typeof body?.write_secret === "string" ? String(body.write_secret).length : 0 });
    return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }
  // Base44's group-account hash — reproducible from the auth token's email.
  const groupAccountHash = await sha256hex("veil-group-account:" + String(auth.email || "").trim().toLowerCase());
  const callerAcct = await accountHashOf(auth.userId);

  const memberRows = async (): Promise<Record<string, any>[]> => {
    const out: Record<string, any>[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
      const r = e.value as Record<string, any>;
      if (String(r.group_token || "") === groupToken) out.push({ ...r, id: e.key[e.key.length - 1] });
    }
    return out.slice(0, 100); // b198: MAX_GROUP_MEMBERS — the roster page MUST cover the whole cohort
  };
  const denyRows = async (): Promise<Record<string, any>[]> => {
    const out: Record<string, any>[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilGroupDenyEntry"] }, { consistency: "strong" })) {
      const r = e.value as Record<string, any>;
      if (String(r.group_token || "") === groupToken) out.push({ ...r, id: e.key[e.key.length - 1] });
    }
    return out.slice(0, 200); // b198: deny-list page scales with the cohort
  };

  if (action === "roster") {
    const members = await memberRows();
    // Membership fence on CURRENT membership: the credential proves a slot; a
    // slot can outlive the membership it was issued for. Resolved from the
    // roster itself against the bindings written at attestation time.
    const isMember = members.some((m) => m.session_token === sessionToken || (!!groupAccountHash && m.account_hash === groupAccountHash) || (!!callerAcct && m._acct === callerAcct));
    if (!isMember) return j({ error: "You are not a member of this group.", membership_gone: true, message: "You are not a member of this group." }, 403);
    // Deliberately narrow projection — exactly Base44's field set. SINGLE wrap:
    // { members, epoch } at the top level (the client reads res.data.members).
    return json({
      members: members.map((m) => ({ veil_id: m.veil_id || "", IK_pub: m.IK_pub, role: m.role, joined_epoch: m.joined_epoch })),
      epoch: Number(session.group_epoch || 0),
    });
  }

  if (action === "attest") {
    const ikPub = typeof body.IK_pub === "string" ? body.IK_pub : "";
    const veilId = typeof body.veil_id === "string" ? body.veil_id.trim() : "";
    const sig = typeof body.sig === "string" ? body.sig : "";
    const joinedEpoch = Number(body?.joined_epoch);
    if (!tryB64Len(ikPub, 32) || !tryB64Len(sig, 64)) return j({ error: "Invalid attestation material", message: "Invalid attestation material" }, 400);
    if (veilId !== "" && !B58_ID.test(veilId)) return j({ error: "Invalid veil_id", message: "Invalid veil_id" }, 400);
    // Deny-list FIRST — an evicted identity learns they were removed even if
    // their stale attestation no longer matches the current epoch.
    const denies = await denyRows();
    if (denies.some((d) => d.target_IK_pub === ikPub || (veilId !== "" && d.target_veil_id === veilId))) {
      return j({ error: "This identity was removed from the group", message: "This identity was removed from the group" }, 403);
    }
    if (!Number.isInteger(joinedEpoch) || joinedEpoch < 0 || joinedEpoch !== Number(session.group_epoch || 0)) {
      return j({ error: "joined_epoch does not match the current group epoch", message: "joined_epoch does not match the current group epoch" }, 400);
    }
    if (veilId !== "") {
      // Bind to the published identity — nobody joins under someone else's label.
      const identity = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value
        ?? (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
      if (!identity) return j({ error: "Unknown identity", message: "Unknown identity" }, 404);
      if (String(identity.IK_pub || "") !== ikPub) return j({ error: "Identity does not match the published key", message: "Identity does not match the published key" }, 403);
    }
    const payload = enc.encode(JSON.stringify({ group_token: groupToken, veil_id: veilId, IK_pub: ikPub, joined_epoch: joinedEpoch }));
    const sigOk = await ed25519Verify(ikPub, payload, sig);
    if (!sigOk) return j({ error: "Attestation signature verification failed", message: "Attestation signature verification failed" }, 401);
    const members = await memberRows();
    const existing = members.find((m) => m.IK_pub === ikPub);
    if (existing) {
      // Re-attest: rebind to the current session and epoch.
      await KV.set(["entity", "VeilGroupMember", existing.id], { ...existing, veil_id: veilId, account_hash: groupAccountHash, _acct: callerAcct, session_token: sessionToken, joined_epoch: joinedEpoch, attestation_sig: sig, updated_date: nowIso() });
      await KV.set(["veil_gmember", groupToken, ikPub], { veil_id: veilId, ik_pub: ikPub, joined_epoch: joinedEpoch, sig, account_hash: callerAcct, created_date: nowIso() });
      return json({ ok: true, rejoined: true });
    }
    if (members.length >= 100) return j({ error: "This group is full", message: "This group is full" }, 403); // b198: cohort 100
    // W-21: 'creator' belongs to the group's FIRST attester, never to whoever
    // happens to hold an initiator slot.
    const role = members.length === 0 ? "creator" : "member";
    const row = { id: rid(), created_date: nowIso(), updated_date: nowIso(), group_token: groupToken, veil_id: veilId, account_hash: groupAccountHash, _acct: callerAcct, IK_pub: ikPub, session_token: sessionToken, joined_epoch: joinedEpoch, role, attestation_sig: sig };
    await KV.set(["entity", "VeilGroupMember", row.id], row);
    await KV.set(["veil_gmember", groupToken, ikPub], { veil_id: veilId, ik_pub: ikPub, joined_epoch: joinedEpoch, sig, account_hash: callerAcct, created_date: nowIso() });
    return json({ ok: true, role });
  }

  if (action === "rotate") {
    // b198: every rotate refusal is DIAGNOSED (slot/epoch/pq) — silent guards
    // made the stuck-epoch state undebuggable from the journal.
    if (slot !== "initiator") {
      console.warn("rotate-refused", { reason: "slot", slot, token: sessionToken.slice(0, 8), groupEpoch: Number(session.group_epoch || 0) });
      return j({ error: "Only the group creator can rotate the epoch", message: "Only the group creator can rotate the epoch" }, 403);
    }
    const newEpoch = Number(body?.new_epoch);
    if (!Number.isInteger(newEpoch) || newEpoch !== Number(session.group_epoch || 0) + 1) {
      console.warn("rotate-refused", { reason: "epoch", newEpoch: body?.new_epoch, serverEpoch: Number(session.group_epoch || 0), token: sessionToken.slice(0, 8) });
      return j({ error: "new_epoch must be the current epoch + 1", message: "new_epoch must be the current epoch + 1" }, 400);
    }
    // group epochs are PQ-only: raw ML-KEM-768 encapsulation key (FIPS 203).
    if (!tryB64Len(body?.group_pq_pub, 1184)) {
      console.warn("rotate-refused", { reason: "pq", pqLen: typeof body?.group_pq_pub === "string" ? body.group_pq_pub.length : 0 });
      return j({ error: "group_pq_pub must be a base64 ML-KEM-768 public key — group epochs are PQ-only, no silent downgrade", message: "group_pq_pub must be a base64 ML-KEM-768 public key — group epochs are PQ-only, no silent downgrade" }, 400);
    }
    // stamp the new epoch + PQ key on every session row carrying this group
    for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row.group_token || "") === groupToken) {
        await KV.set(e.key, { ...row, group_epoch: newEpoch, group_pq_pub: String(body.group_pq_pub || ""), updated_date: nowIso() });
      }
    }
    const rec = await groupRecord(groupToken);
    await KV.set(["veil_group", groupToken], { ...rec, epoch: newEpoch, pq_pub: String(body.group_pq_pub || ""), updated_date: nowIso() });
    return json({ ok: true, epoch: newEpoch });
  }

  if (action === "evict") {
    if (slot !== "initiator") return j({ error: "Only the group creator can remove members", message: "Only the group creator can remove members" }, 403);
    const removerIkPub = typeof body.remover_IK_pub === "string" ? body.remover_IK_pub : "";
    const targetIkPub = typeof body.target_IK_pub === "string" ? body.target_IK_pub : "";
    const targetVeilId = typeof body.target_veil_id === "string" ? body.target_veil_id.trim() : "";
    const denySig = typeof body.deny_sig === "string" ? body.deny_sig : "";
    if (!tryB64Len(removerIkPub, 32) || !tryB64Len(targetIkPub, 32) || !tryB64Len(denySig, 64)) return j({ error: "Invalid eviction material", message: "Invalid eviction material" }, 400);
    if (removerIkPub === targetIkPub) return j({ error: "The creator cannot evict themselves — end the group instead", message: "The creator cannot evict themselves — end the group instead" }, 400);
    const members = await memberRows();
    const remover = members.find((m) => m.IK_pub === removerIkPub);
    if (!remover || remover.role !== "creator") return j({ error: "Remover is not the group creator", message: "Remover is not the group creator" }, 403);
    const denyEpoch = Number(session.group_epoch || 0);
    const denyPayload = JSON.stringify({ group_token: groupToken, target_IK_pub: targetIkPub, deny_epoch: denyEpoch });
    const denyOk = await ed25519Verify(removerIkPub, enc.encode(denyPayload), denySig);
    if (!denyOk) return j({ error: "Deny-list signature verification failed", message: "Deny-list signature verification failed" }, 401);
    const denyRow = { id: rid(), created_date: nowIso(), group_token: groupToken, target_veil_id: targetVeilId, target_IK_pub: targetIkPub, deny_epoch: denyEpoch, remover_IK_pub: removerIkPub, deny_sig: denySig };
    await KV.set(["entity", "VeilGroupDenyEntry", denyRow.id], denyRow);
    const target = members.find((m) => m.IK_pub === targetIkPub);
    let removedSession = false;
    if (target) {
      await KV.delete(["entity", "VeilGroupMember", target.id]);
      await KV.delete(["veil_gmember", groupToken, targetIkPub]);
      if (target.session_token) {
        // Base44 cascade: the evicted member's envelopes + session row go too.
        for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
          const env = e.value as Record<string, unknown>;
          if (String(env.session_token || "") === String(target.session_token)) await KV.delete(e.key);
        }
        const doomed = await findSessionByToken(String(target.session_token));
        if (doomed) {
          await KV.delete(["entity", "VeilSession", String(doomed.id)]);
          await KV.delete(["veil_sess_token", keySafe(String(target.session_token))]);
          removedSession = true;
        }
      }
    }
    return json({ ok: true, denied: true, removed_session: removedSession });
  }

  // b198 notify — kept from the cutover build: the sender proves membership via
  // the wsOk gate above; every OTHER member's account gets the contentless ping.
  if (action === "notify") {
    if (Date.now() - ((await KV.get<number>(ck)).value ?? 0) < 30000) return json({ ok: true, coalesced: true });
    await KV.set(ck, Date.now());
    const members = await memberRows();
    const recipientAccts = new Set<string>();
    for (const m of members) if (m._acct && m._acct !== callerAcct) recipientAccts.add(String(m._acct));
    let sent = 0;
    for (const acct of recipientAccts) {
      for (const t of await groupMemberPushTokens(acct)) {
        void fetch("https://exp.host/--/api/v2/push/send", { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ to: t, title: "VEIL", body: "Notification", sound: "default", priority: "high", data: { kind: "new-message" } }) }).then(async (r) => { const d = await r.json().catch(() => null) as { data?: { status?: string } } | null; console.log("[push] group ticket " + t.slice(-10) + ": " + (d?.data?.status ?? r.status)); }).catch(() => undefined);
        sent++;
      }
    }
    return json({ ok: true, data: { pinged: sent } });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- deviceLink (device-to-device transfer) ----------
async function fnDeviceLink(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body.action || "");
  const token = String(body.token || "");
  if (action === "store") {
    if (!token || token.length > MAX_KEY_PART) return j({ error: "token required", message: "token required" }, 400);
    await KV.set(["devlink", keySafe(token)], {
      container_uri: String(body.container_uri || ""),
      byte_length: Number(body.byte_length) || 0,
      acct: await accountHashOf(auth.userId),
      exp: Date.now() + 3600_000,
      created_date: nowIso(),
    });
    return json({ ok: true });
  }
  if (action === "fetch") {
    const row = (await KV.get<Record<string, any>>(["devlink", keySafe(token)])).value;
    if (!row || row.exp < Date.now()) {
      await KV.delete(["devlink", keySafe(token)]);
      return j({ error: "Transfer link not found — expired or already used.", message: "Transfer link not found — expired or already used." }, 404);
    }
    // consume-once: the link says "expired or already used" — honor it
    await KV.delete(["devlink", token]);
    const uri = String(row.container_uri || "");
    if (uri.startsWith("blob:")) {
      const blobId = uri.slice(5);
      const path = "/opt/veil-relay/blobs/" + blobId;
      try {
        const text = await Deno.readTextFile(path);
        return json({ data: { blob: text } });
      } catch {
        return j({ error: "Transfer link not found — expired or already used.", message: "Transfer link not found — expired or already used." }, 404);
      }
    }
    return json({ data: { signed_url: uri } });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- veilSilentAccount (duress/silent provisioning — phrase never leaves the device) ----------
async function fnVeilSilentAccount(auth: { userId: string }, body: Record<string, any>) {
  if (String(body.action || "") !== "provision") return j({ error: "Unknown action", message: "Unknown action" }, 400);
  try {
    const user = await createUser(String(body.email || ""), String(body.password || ""));
    const token = "vt_" + rid() + rid();
    await KV.set(["auth", token], { userId: user.id, email: user.email });
    return json({ ok: true, access_token: token, user: { id: user.id, email: user.email } });
  } catch (e) {
    return j({ message: String((e as Error).message) }, 400);
  }
}

// ---------- veilAccountDelete (the K-11 cascade) ----------
async function fnVeilAccountDelete(auth: { userId: string }, body: Record<string, any>) {
  const clientIds = new Set((Array.isArray(body.client_ids) ? body.client_ids : []).map(String));
  const acct = await accountHashOf(auth.userId);
  // this account's published identities
  const veilIds = new Set<string>();
  for await (const e of KV.list({ prefix: ["veil_identity"] }, { consistency: "strong" })) {
    const rec = e.value as Record<string, unknown>;
    if (String(rec.account_hash || "") === acct) { veilIds.add(String(rec.veil_id)); await KV.delete(e.key); }
  }
  // sessions + envelopes: by client_id or by veil_id binding
  let sessions = 0, envelopes = 0;
  const doomed: string[] = [];
  for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    const hit = clientIds.has(String(row.initiator_client_id || "")) || clientIds.has(String(row.responder_client_id || ""))
      || veilIds.has(String(row.initiator_veil_id || "")) || veilIds.has(String(row.responder_veil_id || ""));
    if (hit) doomed.push(e.key[e.key.length - 1] as string);
  }
  for (const id of doomed) {
    const row = (await KV.get<Record<string, unknown>>(["entity", "VeilSession", id])).value;
    if (!row) continue;
    envelopes += await deleteSessionEnvelopes(String(row.token || ""));
    await KV.delete(["entity", "VeilSession", id]);
    const tok = String(row.token || "");
    if (tok) await KV.delete(["veil_sess_token", tok]);
    sessions++;
  }
  // group memberships by account hash
  let memberships = 0;
  for await (const e of KV.list({ prefix: ["veil_gmember"] }, { consistency: "strong" })) {
    const m = e.value as Record<string, unknown>;
    if (String(m.account_hash || "") === acct) { await KV.delete(e.key); memberships++; }
  }
  // vaults + notes (owner-scoped entities)
  let vaults = 0, notes = 0;
  for (const [name, counter] of [["VeilVault", () => vaults++], ["VeilNote", () => notes++]] as const) {
    for await (const e of KV.list({ prefix: ["entity", name] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") === acct) { await KV.delete(e.key); counter(); }
    }
  }
  // transfer links owned by the account
  for await (const e of KV.list({ prefix: ["devlink"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    if (String(row.acct || "") === acct) await KV.delete(e.key);
  }
  // the account itself + its auth tokens
  for await (const e of KV.list({ prefix: ["auth"] }, { consistency: "strong" })) {
    const t = e.value as Record<string, unknown>;
    if (String(t.userId || "") === auth.userId) await KV.delete(e.key);
  }
  await KV.delete(["user", auth.userId]);
  const uRow = (await KV.get(["user", auth.userId])).value; // (already deleted — kept for clarity)
  void uRow;
  return json({ ok: true, data: { deleted: { sessions, envelopes, memberships, vaults, notes, identities: veilIds.size } } });
}

// ---------- private blob storage + signed URLs (encrypted media + vault files) ----------
async function blobSecret(): Promise<CryptoKey> {
  let s = (await KV.get<string>(["secret", "blobSign"])).value;
  if (!s) { s = b64e(crypto.getRandomValues(new Uint8Array(32))); await KV.set(["secret", "blobSign"], s); }
  return crypto.subtle.importKey("raw", b64d(s) as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function signBlobUrl(blobId: string, ttlMs: number, proto: string, host: string) {
  const key = await blobSecret();
  const exp = Date.now() + ttlMs;
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(`${blobId}:${exp}`));
  const m = b64e(new Uint8Array(mac)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${proto}//${host}/files/${blobId}?e=${exp}&m=${m}`;
}

// ---------- router ----------
const routes: [string, RegExp, (req: Request, m: RegExpMatchArray, url: URL) => Promise<Response>][] = [];

function route(method: string, pattern: string, handler: (req: Request, m: RegExpMatchArray, url: URL) => Promise<Response>) {
  routes.push([method, new RegExp("^" + pattern.replace(/:([a-zA-Z]+)/g, "(?<$1>[^/]+)") + "$"), handler]);
}

// b198: getLoungeInvite — the Founding Tester Forum's PUBLIC descriptor
// (faithful port of the Base44 entry). Open by design: both clients fetch it
// BEFORE any relationship with the forum. Serves a static, hand-verified
// descriptor — no user data, no account binding. The descriptor's link
// fragment carries the forum keys; the relay gate still decides every join.
// Fail-closed guards: the link must be an https forum invitation carrying a
// write-secret fragment; the founder key must be a 32-byte Ed25519 pub.
const LOUNGE = {
  v: "veil-forum-2",
  link: "https://relay.tryveil.app/?join=9d00a7fa21fc085f0e4048df41788964108ebbecd40526b6#w=19be5a8bc4d1d62a92a5b89e57c21f9e9b8a80e43401b95716079f131a1853dd&g=T3v8kKmFNMdh2qh2ImwmFA3TT99CD8rf7Hq6nsK0sVE%3D&e=1",
  // b198 CORRECTION (live-caught): the founder of THIS forum is the identity
  // that created + attested it — FQjmCqfA (the recovered identity, and the
  // same founder key as the original Base44 descriptor). The first descriptor
  // wrongly named the regenerated identity, so the member's fail-closed sender
  // check discarded every founder message ("sender without a verifiable
  // veil-id"). The founder of a forum is whoever ATTESTED it — never assumed.
  founder_veil_id: "FQjmCqfArnavGMiJ",
  founder_ik_pub: "HO/IqL6NWS9svDRK1aUrRclzR09XGA7oYh5jO8AomY4=",
  name: "Founding Tester Forum",
};
const LOUNGE_CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
function loungeDescriptorSound(l: Record<string, unknown>): boolean {
  if (typeof l.link !== "string" || !l.link.startsWith("https://")) return false;
  if (!l.link.includes("join=") || !l.link.includes("w=")) return false;
  try { return atob(l.founder_ik_pub).length === 32; } catch { return false; }
}
route("GET", "/api/apps/:appId/functions/getLoungeInvite", () => {
  if (!loungeDescriptorSound(LOUNGE)) {
    console.error("getLoungeInvite: descriptor failed its own guard — refusing to serve");
    return j({ lounge: null }, 200, LOUNGE_CORS);
  }
  return j({ lounge: LOUNGE }, 200, LOUNGE_CORS);
});
route("OPTIONS", "/api/apps/:appId/functions/getLoungeInvite", () => new Response(null, { status: 204, headers: LOUNGE_CORS }));

// auth (open)
route("POST", "/api/apps/:appId/auth/login", async (req) => {
  const body = await readJson(req);
  const email = String(body.email || "").toLowerCase().trim();
  if (email.length > MAX_KEY_PART) return j({ message: "Invalid email or password" }, 401);
  // SPEC §1: the 5-attempt server-side lockout (VeilLoginGuard) — the client
  // surfaces the lock message verbatim
  const guard = (await KV.get<{ fails: number; lockedUntil: number }>(["login_guard", keySafe(email)])).value;
  if (guard && guard.lockedUntil > Date.now()) {
    const mins = Math.max(1, Math.ceil((guard.lockedUntil - Date.now()) / 60_000));
    return j({ message: `Too many failed attempts — try again in ${mins} minute${mins === 1 ? "" : "s"}` }, 429);
  }
  // per-IP throttle: stops distributed guessing across MANY mailboxes from one host
  // ("local" = the server itself / an SSH tunnel — never throttled)
  const ip = clientIp(req);
  const ipLocal = ip === "local";
  const ipGuard = ipLocal ? null : (await KV.get<{ fails: number; lockedUntil: number }>(["login_guard_ip", ip])).value;
  if (ipGuard && ipGuard.lockedUntil > Date.now()) {
    return j({ message: "Too many failed attempts — try again later" }, 429);
  }
  const ipFail = async () => {
    if (ipLocal) return;
    const fails = ((ipGuard?.fails ?? 0) + 1);
    if (fails >= 15) await KV.set(["login_guard_ip", ip], { fails: 0, lockedUntil: Date.now() + 15 * 60_000 });
    else await KV.set(["login_guard_ip", ip], { fails, lockedUntil: 0 });
  };
  const uid = (await KV.get<string>(["user_email", keySafe(email)])).value;
  const user = uid ? (await KV.get<any>(["user", uid])).value : null;
  if (!user) { await ipFail(); return j({ message: "Invalid email or password" }, 401); }
  const hash = await hashPassword(String(body.password || ""), user.salt);
  if (hash !== user.passHash) {
    const fails = ((guard?.fails ?? 0) + 1);
    await ipFail();
    if (fails >= 5) await KV.set(["login_guard", keySafe(email)], { fails: 0, lockedUntil: Date.now() + 10 * 60_000 });
    else await KV.set(["login_guard", keySafe(email)], { fails, lockedUntil: 0 });
    return j({ message: "Invalid email or password" }, 401);
  }
  await KV.delete(["login_guard", keySafe(email)]);
  await KV.delete(["login_guard_ip", ip]);
  const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  await KV.set(["auth", token], { userId: user.id, email: user.email, created: nowIso() });
  return json({ access_token: token, user: { id: user.id, email: user.email } });
});

route("POST", "/api/apps/:appId/auth/register", async (req) => {
  const body = await readJson(req);
  // mass-registration guard (unauthenticated endpoint): 10 accounts/hour/IP
  // ("local" exempt — the server's own console / test batteries)
  const regIp = clientIp(req);
  const regRl = regIp === "local" ? null : await rateLimit("regip:" + regIp, 10, 3600_000, 60);
  if (regRl) return j({ message: "Too many signups from this network — try again later" }, 429);
  try {
    const user = await createUser(String(body.email || ""), String(body.password || ""));
    // b198 ANONYMOUS SIGNUP (founder decision, Oct 15): the email is a
    // SELF-DECLARED account label — real or invented, never verified, never
    // contacted. The Base44-era OTP mandate died with the platform. The
    // account is created + verified + usable in ONE step; the 24-word phrase
    // remains the only recovery path (disclosed at signup). Login lockouts,
    // the per-IP register cap, and the deletion cascade are unchanged.
    user.verified = true;
    await KV.set(["user", user.id], user);
    const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
    await KV.set(["auth", token], { userId: user.id, email: user.email, created: nowIso() });
    return json({ id: user.id, access_token: token, user: { id: user.id, email: user.email }, message: "Account created — no email verification" });
  } catch (e) { return j({ message: String((e as Error).message) }, 400); }
});

route("POST", "/api/apps/:appId/auth/verify-otp", async (req) => {
  const body = await readJson(req);
  // Phase 1: any code is accepted (auto-verify). OTP email delivery is Phase 2.
  const email = String(body.email || "").toLowerCase().trim();
  const uid = (await KV.get<string>(["user_email", keySafe(email)])).value;
  if (!uid) return j({ message: "Account not found" }, 404);
  const user = (await KV.get<any>(["user", uid])).value;
  user.verified = true;
  await KV.set(["user", uid], user);
  const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  await KV.set(["auth", token], { userId: user.id, email, created: nowIso() });
  return json({ access_token: token, user: { id: user.id, email: user.email } });
});

route("POST", "/api/apps/:appId/auth/logout", async (req) => {
  return json({ ok: true });
});

// entities (auth required)
route("GET", "/api/apps/:appId/entities/:entity", async (req, m, url) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const listed = await listEntity(m.groups!.entity!, url, auth);
  if (listed && (listed as any).__blocked) {
    return j({ message: String((listed as any).__blocked) }, 403);
  }
  if (listed && (listed as any).__notfound) {
    return j({ error: String((listed as any).__notfound), message: String((listed as any).__notfound) }, 404);
  }
  return json(listed);
});

route("POST", "/api/apps/:appId/entities/:entity", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  const created = await createEntity(m.groups!.entity!, body, auth);
  if (created && (created as any).__conflict) {
    return j({ error: "Conflict", message: "A session with this token already exists" }, 409);
  }
  return json(created);
});

route("PUT", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  const row = (await KV.get<Record<string, unknown>>(["entity", m.groups!.entity!, m.groups!.id!])).value;
  if (!row) return j({ message: "Not found" }, 404);
  if (m.groups!.entity! === "VeilSession" && !(await sessionParticipant(row, auth))) {
    return j({ message: "Not your session" }, 403);
  }
  const merged = { ...row, ...body, id: m.groups!.id!, updated_date: nowIso() };
  await KV.set(["entity", m.groups!.entity!, m.groups!.id!], merged);
  return json(merged);
});

route("GET", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  const row = await getEntity(m.groups!.entity!, m.groups!.id!);
  return row ? json(row) : j({ message: "Not found" }, 404);
});

// b198 OWNERSHIP GUARD: sessions may only be modified/deleted by their
// participants (client_id IS the account id — b65 participation proof; or a
// veil_id bound to the caller's account). Without this, one device's supersede
// could destroy the OTHER device's brand-new thread (live battery catch).
async function sessionParticipant(session: Record<string, unknown> | null, auth: { userId: string }): Promise<boolean> {
  if (!session) return false;
  if (String(session.initiator_client_id || "") === auth.userId) return true;
  if (String(session.responder_client_id || "") === auth.userId) return true;
  const acct = await accountHashOf(auth.userId);
  for (const vid of [String(session.initiator_veil_id || ""), String(session.responder_veil_id || "")]) {
    if (!vid) continue;
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(vid)])).value;
    if (id && String(id.account_hash || "") === acct) return true;
  }
  return false;
}

route("DELETE", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  if (m.groups!.entity! === "VeilSession") {
    const row = (await KV.get<Record<string, unknown>>(["entity", "VeilSession", m.groups!.id!])).value;
    if (row && !(await sessionParticipant(row, auth))) {
      return j({ message: "Not your session" }, 403);
    }
  }
  const row = await deleteEntity(m.groups!.entity!, m.groups!.id!);
  return row ? json({ ok: true }) : j({ message: "Not found" }, 404);
});

// functions (auth required)
route("POST", "/api/apps/:appId/functions/submitEnvelope", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnSubmitEnvelope(auth, body);
});

route("POST", "/api/apps/:appId/functions/veilSessionGate", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilSessionGateAligned(auth, body);
});

route("POST", "/api/apps/:appId/functions/veilIdentityGate", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilIdentityGate(auth, body);
});

route("POST", "/api/apps/:appId/functions/veilGroupGate", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilGroupGate(auth, body);
});

route("POST", "/api/apps/:appId/functions/deviceLink", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnDeviceLink(auth, body);
});

// b198 (audit P0-2, live-confirmed): provisioning IS the account-creation call —
// the caller definitionally has no credentials yet, so requiring auth here 401'd
// every fresh duress account. The route is pre-auth, guarded by the same per-IP
// register cap as /auth/register.
route("POST", "/api/apps/:appId/functions/veilSilentAccount", async (req) => {
  const regIp = clientIp(req);
  const regRl = regIp === "local" ? null : await rateLimit("regip:" + regIp, 10, 3600_000, 60);
  if (regRl) return j({ message: "Too many signups from this network — try again later" }, 429);
  const body = await readJson(req);
  return fnVeilSilentAccount({ userId: "preauth-provision" }, body);
});

route("POST", "/api/apps/:appId/functions/veilAccountDelete", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilAccountDelete(auth, body);
});

route("POST", "/api/apps/:appId/functions/vaultFileSignedUrl", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  const fileUri = String(body.file_uri || "");
  if (!fileUri.startsWith("blob:") || fileUri.length > MAX_KEY_PART + 5) return j({ error: "Unknown file", message: "Unknown file" }, 404);
  // vault-unlock path passes NO session context; media path passes both — verify when present
  if (body.session_token) {
    const session = await findSessionByToken(String(body.session_token));
    const wHash = await wsHashOf(body.write_secret);
    const ok = !!(session && wHash && (wHash === String(session.initiator_write_hash || "") || wHash === String(session.responder_write_hash || "")));
    if (!ok) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }
  const host = req.headers.get("host") || "relay.tryveil.app";
  // behind Caddy the inner request is http — trust the proxy's forwarded proto.
  // b198 LIVE-CAUGHT BUG (media load "Network request failed" behind TLS): the
  // two branches used INCONSISTENT formats — "https://" (with slashes) vs
  // new URL().protocol ("https:", slash-free) — while the template below is
  // `${proto}//${host}`. The X-Forwarded-Proto branch therefore produced
  // "https:////host/..." — a malformed URL that RN fetch rejects at the
  // connection level. EVERY media/vault download through Caddy TLS was broken
  // since the relay flip. Both branches must be slash-free.
  const fwdProto = req.headers.get("x-forwarded-proto") || "";
  const proto = fwdProto.startsWith("https") ? "https:" : new URL(req.url).protocol;
  const url = await signBlobUrl(fileUri.slice(5), 10 * 60_000, proto, host);
  return json({ signed_url: url });
});

// private blob upload — the web SDK's Core.UploadPrivateFile contract (multipart)
route("POST", "/api/apps/:appId/integration-endpoints/Core/UploadPrivateFile", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  // size gate BEFORE spooling the multipart body into memory/temp files
  // b198 MEDIA CAP ALIGNED (owner decision): 25 MB files, 26 MB gate to allow
  // multipart overhead. The client cap (MEDIA_LIMIT_BYTES) matches exactly.
  if (Number(req.headers.get("content-length") || "0") > 26 * 1024 * 1024) return TOO_LARGE("File too large");
  try {
    const form = await req.formData();
    let file: File | null = null;
    for (const [, v] of form.entries()) { if (v instanceof File) { file = v; break; } }
    if (!file) return j({ message: "No file part" }, 400);
    // disk-fill guard: encrypted media/vault files cap at 25 MB (aligned with
    // the client's MEDIA_LIMIT_BYTES — b198 media cap decision)
    if (file.size > 25 * 1024 * 1024) return j({ message: "File too large" }, 413);
    const id = rid();
    await Deno.mkdir("/opt/veil-relay/blobs", { recursive: true });
    await Deno.writeFile("/opt/veil-relay/blobs/" + id, new Uint8Array(await file.arrayBuffer()));
    return json({ file_uri: "blob:" + id });
  } catch (e) {
    return j({ message: String((e as Error).message).slice(0, 200) }, 500);
  }
});

// b198 MEDIA DELETION: the blob id exists ONLY inside the E2E-encrypted media
// payload (the relay never sees it), so knowledge of an unguessable blob id IS
// the decryption proof — an authenticated caller presenting one is the deletion
// capability. The client's burn/✕ paths call this so burnt media leaves NOTHING
// on the relay's disk (text envelopes were already hard-deleted; this closes the
// media half of the burn/✕ claim). Idempotent: an already-gone blob is success.
route("POST", "/api/apps/:appId/integration-endpoints/Core/DeletePrivateFile", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  let body: Record<string, unknown> = {};
  try { body = await readJson(req); } catch { /* empty body tolerated */ }
  const uri = String(body.file_uri || "");
  if (!uri.startsWith("blob:") || uri.length > MAX_KEY_PART + 5) return j({ message: "Unknown file" }, 404);
  const blobId = keySafe(uri.slice(5));
  if (!blobId || blobId.startsWith("\u0000")) return j({ message: "Unknown file" }, 404);
  try { await Deno.remove("/opt/veil-relay/blobs/" + blobId); } catch { /* already gone — deletion is idempotent */ }
  return json({ ok: true });
});

// pre-signed blob download (HMAC + expiry, no auth header by design)
route("GET", "/files/:id", async (req, m, url) => {
  const blobId = keySafe(m.groups!.id!);
  const exp = Number(url.searchParams.get("e") || "0");
  const mac = url.searchParams.get("m") || "";
  if (!exp || exp < Date.now() || !mac) return j({ error: "Link expired", message: "Link expired" }, 403);
  const key = await blobSecret();
  const expect = b64e(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${blobId}:${exp}`))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (expect !== mac) return j({ error: "Bad signature", message: "Bad signature" }, 403);
  try {
    const data = await Deno.readFile("/opt/veil-relay/blobs/" + blobId);
    return new Response(data, { headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store" } });
  } catch {
    return j({ error: "Not found", message: "Not found" }, 404);
  }
});

// auth extras — resend-otp is a no-op success (phase 1 auto-verifies);
// reset-password is HONESTLY offline until SMTP exists (no fake reset path)
route("POST", "/api/apps/:appId/auth/resend-otp", async () => json({ ok: true }));
route("POST", "/api/apps/:appId/auth/reset-password-request", async () =>
  j({ message: "Password reset email delivery is not available on this relay yet" }, 503));
route("POST", "/api/apps/:appId/auth/reset-password", async () =>
  j({ message: "Reset tokens are not issued while email delivery is offline" }, 400));

route("POST", "/api/apps/:appId/functions/purgeExpiredEnvelopes", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  return fnPurgeExpired();
});

// unknown function → 404 (the client tolerates)
route("POST", "/api/apps/:appId/functions/:fn", async (req, m) => {
  return j({ error: `Backend function '${m.groups!.fn!}' not found or not deployed`, message: `Backend function '${m.groups!.fn!}' not found or not deployed` }, 404);
});

// health
route("GET", "/status", async () => json({ ok: true, relay: "veil-phase1" }));

// ---------- request hardening (b198 attack-probe fixes) ----------
const MAX_JSON_BYTES = 1 * 1024 * 1024;      // JSON routes — envelopes are ≤ ~8 KB
const MAX_KEY_PART = 256;                    // any user string that becomes a KV key part
const MAX_VEIL_ID = 128;                     // veil_ids are short (#veil format)

/** Reads a JSON body with a hard size cap; throws tagged errors on violations. */
async function readJson(req: Request): Promise<Record<string, any>> {
  const len = Number(req.headers.get("content-length") || "0");
  if (len > MAX_JSON_BYTES) throw new Error("__too_large__");
  let body: unknown;
  try { body = await req.json(); } catch { throw new Error("__bad_json__"); } // malformed or over-deep JSON → clean 400
  if (body && typeof body === "object") {
    for (const k of Object.keys(body)) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") {
        throw new Error("__bad_keys__");
      }
    }
  }
  return body ?? {};
}

/** Caps a user-supplied string used as a KV key part — oversized input misses instead of crashing. */
function keySafe(v: unknown): string {
  const s = String(v ?? "");
  return s.length <= MAX_KEY_PART ? s : "\u0000oversized";
}

const TOO_LARGE = (msg = "Request body too large") => j({ error: msg, message: msg }, 413);
const BAD_KEYS = () => j({ error: "Invalid field name", message: "Invalid field name" }, 400);
const BAD_JSON = () => j({ error: "Malformed JSON", message: "Malformed JSON" }, 400);

// ---------- serve ----------
Deno.serve({ port: PORT }, async (req, info) => {
  const url = new URL(req.url);
  for (const [method, re, handler] of routes) {
    if (req.method !== method) continue;
    const m = url.pathname.match(re);
    if (m) {
      try { return await handler(req, m, url); }
      catch (e) {
        const msg = String((e as Error).message || e);
        if (msg === "__too_large__") return TOO_LARGE();
        if (msg === "__bad_keys__") return BAD_KEYS();
        if (msg === "__bad_json__") return BAD_JSON();
        console.error("handler error", url.pathname, e);
        return j({ error: msg.slice(0, 200) }, 500);
      }
    }
  }
  return j({ message: "Not found" }, 404);
});

console.log(`VEIL RELAY Phase 1 — listening on http://localhost:${PORT}`);
console.log("Contract: /api/apps/:appId/{auth/*,entities/*,functions/*} — matches the native client exactly.");

// ---------- sweeper: every 10 min, purge expired envelopes + stale limiter keys (K-30) ----------
// b198 BLOB RETENTION BACKSTOP: media ciphertext whose envelope was deleted
// WITHOUT a client-driven blob delete (never-opened media, ✕ of a session whose
// media was never decrypted) is swept at bounded retention — the max unopened
// horizon (48h chip) + margin. Claim wording: media is deleted at burn, or at
// latest 49h after upload if never opened.
const BLOB_RETENTION_MS = 49 * 3600 * 1000;
setInterval(async () => {
  try { const r = await fnPurgeExpired(); const d = (await r.json()).purged.deleted; if (d) console.log(`[sweeper] purged ${d} expired envelope(s)`); }
  catch (e) { console.error("[sweeper] error", e); }
  try {
    let bn = 0;
    for await (const f of Deno.readDir("/opt/veil-relay/blobs")) {
      if (!f.isFile) continue;
      const st = await Deno.stat("/opt/veil-relay/blobs/" + f.name).catch(() => null);
      if (st && st.mtime && Date.now() - st.mtime.getTime() > BLOB_RETENTION_MS) {
        await Deno.remove("/opt/veil-relay/blobs/" + f.name).catch(() => undefined);
        bn++;
      }
    }
    if (bn) console.log(`[sweeper] deleted ${bn} expired blob file(s)`);
  } catch (e) { console.error("[sweeper] blob cleanup error", e); }
  try {
    // rate-limit buckets live one window; anything from a previous window is dead weight
    const curMinute = Math.floor(Date.now() / 60_000);
    const curHour = Math.floor(Date.now() / 3_600_000);
    let n = 0;
    for await (const e of KV.list({ prefix: ["rl"] }, { consistency: "strong" })) {
      const bucket = Number(e.key[e.key.length - 1]);
      const isMinuteKey = bucket < 1e6; // minute buckets are epoch-minutes; hour keys are epoch-hours
      const stale = isMinuteKey ? bucket < curMinute - 2 : bucket < curHour - 2;
      if (stale) { await KV.delete(e.key); n++; }
    }
    if (n) console.log(`[sweeper] dropped ${n} stale limiter key(s)`);
  } catch (e) { console.error("[sweeper] rl cleanup error", e); }
}, 2 * 60 * 1000); // b198 (audit follow-up): 10-min sweeper granularity left burnt/expired rows visible up to 10 min past their death — an auditor checking right after a burn sees the row and reads the burn as a no-op. 2-min cadence: deletion lands close to the promised moment; scan cost is trivial at current scale.

// ========== BASE44-ALIGNED veilSessionGate (b198 mirror of the proven source) ==========
const validClientId = (v: unknown) => /^[A-Za-z0-9_-]{4,64}$/.test(String(v ?? "").trim());
const validVeilId = (v: unknown) => /^[1-9A-HJ-NP-Za-km-z]{16}$/.test(String(v ?? "").trim());
const retentionMs = (s: Record<string, any>) => { const h = Number(s.key_retention_hours); return h === 0 ? 365 * 24 * 3600 * 1000 : ((Number.isFinite(h) && h) || 168) * 3600 * 1000; };
const declaredMessageMs = (s: Record<string, any>) => { const a = Number(s?.default_ttl_seconds), b = Number(s?.expire_after_seconds); return Math.max(0, Math.max(Number.isFinite(a) ? a : 0, Number.isFinite(b) ? b : 0)) * 1000; };
const sessionHorizonMs = (s: Record<string, any>) => Math.max(retentionMs(s), declaredMessageMs(s));
async function verifyIdentitySignedEnd(session: Record<string, any>, token: string, body: Record<string, any>) {
  const veilId = String(body?.end_veil_id || "");
  if (!veilId || (veilId !== String(session.initiator_veil_id || "") && veilId !== String(session.responder_veil_id || ""))) return false;
  const ts = Number(body?.end_ts);
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > 300000) return false;
  const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
  if (!id) return false;
  return ed25519Verify(String(id.IK_pub || ""), enc.encode(JSON.stringify({ v: 1, end: token, ts })), String(body?.end_sig || ""));
}
async function pushAlertCoalesced(session: Record<string, any>, senderSlot: string) {
  try {
    const side = senderSlot === "initiator" ? "responder" : "initiator";
    const veilId = String(side === "initiator" ? session.initiator_veil_id : session.responder_veil_id || "");
    if (!veilId) return;
    const ck = ["push_coalesce", String(session.token || ""), side];
    if (Date.now() - ((await KV.get<number>(ck)).value ?? 0) < 30000) return;
    await KV.set(ck, Date.now());
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const acct = id ? String(id.account_hash || "") : "";
    if (!acct) return;
    for await (const e of KV.list({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row._acct || "") !== acct) continue;
      const t = String(row.expo_token || "");
      void fetch("https://exp.host/--/api/v2/push/send", { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ to: t, title: "VEIL", body: "Notification", sound: "default", priority: "high", data: { kind: "new-message" } }) }).then(async (r) => { const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string } } | null; console.log("[push] ticket " + t.slice(-10) + ": " + (d?.data?.status ?? r.status) + (d?.data?.message ? " " + d.data.message : "")); }).catch(() => undefined);
    }
  } catch (e) { console.log("[push] alert failed (non-fatal)"); }
}
async function fnVeilSessionGateAligned(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body?.action || "");
  if (action === "list") {
    const clientId = String(body?.client_id || "").trim();
    if (!validClientId(clientId)) return j({ error: "Invalid client id" }, 400);
    const veilId = String(body?.veil_id || "").trim();
    let restoreOk = false;
    if (validVeilId(veilId) && body?.list_ts && body?.list_sig) {
      const ts = Number(body.list_ts);
      if (Number.isFinite(ts) && Math.abs(Date.now() - ts) <= 300000) {
        const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
        if (id) restoreOk = await ed25519Verify(String(id.IK_pub || ""), enc.encode(JSON.stringify({ v: 1, list: clientId, ts })), String(body.list_sig || ""));
      }
    }
    const rows: Record<string, unknown>[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
      const s = e.value as Record<string, unknown>;
      const match = String(s.initiator_client_id || "") === clientId || String(s.responder_client_id || "") === clientId;
      const pendingForMe = !!s.contact_session && String(s.state || "") === "pending" && !String(s.responder_client_id || "") && String(s.responder_veil_id || "") === veilId;
      const identityClause = restoreOk && !!s.contact_session && (String(s.initiator_veil_id || "") === veilId || String(s.responder_veil_id || "") === veilId);
      if (match || pendingForMe || identityClause) rows.push({ ...(s as any), id: e.key[e.key.length - 1] });
    }
    rows.sort((a, b) => String(b.created_date ?? "").localeCompare(String(a.created_date ?? "")));
    return json({ sessions: rows.slice(0, 100) });
  }
  if (action === "purge") {
    const clientId = String(body?.client_id || "").trim();
    if (!validClientId(clientId)) return j({ error: "Invalid client id" }, 400);
    const acct = await accountHashOf(auth.userId);
    const myVeilIds: string[] = [];
    for await (const e of KV.list({ prefix: ["veil_identity"] }, { consistency: "strong" })) { const r = e.value as Record<string, unknown>; if (String(r.account_hash || "") === acct) myVeilIds.push(String(r.veil_id)); }
    let sessions = 0, envelopes = 0;
    const doomed: string[] = [];
    for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) { const s = e.value as Record<string, unknown>; if (String(s.initiator_client_id || "") === clientId || String(s.responder_client_id || "") === clientId || myVeilIds.includes(String(s.initiator_veil_id || "")) || myVeilIds.includes(String(s.responder_veil_id || ""))) doomed.push(String(s.token || "")); }
    for (const tok of doomed) { envelopes += await deleteSessionEnvelopes(tok); }
    for (const tok of doomed) { await KV.delete(["veil_sess_token", keySafe(tok)]); for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) { if (String((e.value as Record<string, unknown>).token || "") === tok) { await KV.delete(e.key); sessions++; } } }
    for (const vid of myVeilIds) await KV.delete(["veil_identity", keySafe(vid)]);
    return json({ ok: true, deleted: { sessions, envelopes, identities: myVeilIds.length } });
  }
  const token = String(body?.token || "");
  const session = await findSessionByToken(token);
  if (!session) {
    if (action === "end") return json({ ok: true });
    if (action === "burn") return json({ ok: true, already_gone: true, burned: false, reason: "session_gone" });
    return j({ error: "Session not found" }, 404);
  }
  const wsHash = body?.write_secret ? await sha256hex(String(body.write_secret)) : "";
  let slot: string | null = wsHash && wsHash === String(session.initiator_write_hash || "") ? "initiator" : (wsHash && wsHash === String(session.responder_write_hash || "") ? "responder" : null);
  if (!slot && action === "end" && !!session.contact_session) {
    const addresseeEnd = String(body?.end_veil_id || "") === String(session.responder_veil_id || "");
    if (!(String(session.state || "") === "pending" && addresseeEnd)) { if (await verifyIdentitySignedEnd(session, token, body)) slot = "participant"; }
  }
  if (!slot && action === "end") {
    const clientId = String(body?.client_id || "").trim();
    const veilId = String(body?.veil_id || "").trim();
    let participant = validClientId(clientId) && (clientId === String(session.initiator_client_id || "") || clientId === String(session.responder_client_id || ""));
    if (!participant && validVeilId(veilId)) {
      const addresseeEnd = veilId === String(session.responder_veil_id || "");
      if (!(String(session.state || "") === "pending" && addresseeEnd) && (veilId === String(session.initiator_veil_id || "") || addresseeEnd)) participant = true;
    }
    if (participant) slot = "participant";
  }
  if (!slot) {
    console.warn("session-credential-refused", { action, token: token.slice(0, 8), state: session.state, presented: typeof body?.write_secret === "string" ? String(body.write_secret).length : 0 });
    return j({ error: "Invalid session credential" }, 403);
  }
  const horizon = () => new Date(Date.now() + sessionHorizonMs(session)).toISOString();
  if (action === "peek") {
    if (slot !== "responder") return j({ error: "Only the invited side can view this session" }, 403);
    return json({ session: { state: session.state, responder_client_id: session.responder_client_id, expires_at: session.expires_at, initiator_pub_jwk: session.initiator_pub_jwk, initiator_pq_pub: session.initiator_pq_pub, passphrase_required: session.passphrase_required, group_token: session.group_token || "", group_epoch: Number(session.group_epoch) || 0, group_name: session.group_name || "", group_pq_pub: session.group_pq_pub || "" } });
  }
  if (action === "join") {
    if (slot !== "responder") return j({ error: "Only the invited side can join this session" }, 403);
    if (String(session.state || "") === "ended") return j({ error: "This session has ended." }, 400);
    if (String(session.state) === "active" && String(session.responder_client_id || "") === String(body?.client_id || "") && (String(session.responder_pub_jwk || "") !== String(body?.responder_pub_jwk || "") || String(session.responder_ratchet_pub_jwk || "") !== String(body?.responder_ratchet_pub_jwk || ""))) return j({ error: "This session was already accepted from this device with different keys — it cannot be re-joined here. Start a new session." }, 409);
    if (String(session.state) === "active" && String(session.responder_client_id || "") && String(session.responder_client_id || "") !== String(body?.client_id || "")) return j({ error: "This session is already in use." }, 400);
    if (String(session.state) === "pending" && new Date(String(session.expires_at)) < new Date()) return j({ error: "Invitation has expired." }, 400);
    for (const [k, v] of Object.entries({ responder_client_id: body?.client_id, responder_pub_jwk: body?.responder_pub_jwk, responder_ratchet_pub_jwk: body?.responder_ratchet_pub_jwk, fingerprint: body?.fingerprint })) { if (typeof v !== "string" || !v) return j({ error: `Missing join field: ${k}` }, 400); }
    session.responder_client_id = String(body.client_id);
    session.responder_display_name = typeof body?.display_name === "string" ? String(body.display_name).slice(0, 64) : "";
    session.state = "active"; session.expires_at = horizon(); session.responder_pub_jwk = String(body.responder_pub_jwk); session.responder_ratchet_pub_jwk = String(body.responder_ratchet_pub_jwk); session.responder_pq_ct = typeof body?.responder_pq_ct === "string" ? String(body.responder_pq_ct) : ""; session.session_fingerprint = String(body.fingerprint); session.last_activity = nowIso(); session.updated_date = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ session });
  }
  if (action === "activate") {
    if (slot !== "initiator") return j({ error: "Only the session creator can activate this session" }, 403);
    if (!session.group_token) return j({ error: "Only group sessions can be activated without a peer" }, 400);
    if (String(session.state || "") === "ended") return j({ error: "This session has ended." }, 400);
    if (String(session.state) === "active") return json({ session });
    session.state = "active"; session.expires_at = horizon(); session.last_activity = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ session });
  }
  if (action === "verify") {
    const early = slot === "initiator" && !!session.contact_session && String(session.state || "") === "pending";
    if (String(session.state || "") !== "active" && !early) return j({ error: "This conversation is not open yet, so the confirmation could not be recorded. Confirm once the other side has accepted the request." }, 409);
    const flag = slot === "initiator" ? "initiator_verified" : "responder_verified";
    (session as any)[flag] = true; session.updated_date = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    console.info("verify-ceremony", { token: token.slice(0, 8), slot, state: session.state, early_confirm: early, iv: !!session.initiator_verified, rv: !!session.responder_verified });
    return json({ session });
  }
  if (action === "bump") {
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    session.last_activity = nowIso(); session.expires_at = horizon();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ ok: true });
  }
  if (action === "notify") {
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    // b198 CALL RING BURST (the live notify path — my first burst branch was
    // placed in the legacy/dead handler, which is why the callee still saw a
    // single "Notification"): a call rings with a BURST of pushes across the
    // 21s ring window, body "Incoming call" — buzzing on-and-off, unmistakable
    // next to a message's single "Notification".
    if (body?.call === true) {
      void pushCallBurst(session, slot === "initiator" ? "responder" : "initiator");
      return json({ ok: true });
    }
    void pushAlertCoalesced(session, slot);
    return json({ ok: true });
  }
  if (action === "burn") {
    const envelopeId = String(body?.envelope_id || "");
    if (!envelopeId) return j({ error: "Missing envelope id" }, 400);
    let policy: Record<string, any> = session;
    if (session.group_token) {
      const gs: Record<string, any>[] = [];
      for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) { const s = e.value as Record<string, any>; if (String(s.group_token || "") === String(session.group_token)) gs.push({ ...s, id: e.key[e.key.length - 1] }); }
      policy = gs.find((s) => s.initiator_client_id && !s.responder_client_id && s.state === "active") || gs[0] || session;
    }
    if (!policy.burn_after_open) return j({ error: "This session is not burn-after-open" }, 400);
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    const env = (await KV.get<Record<string, any>>(["entity", "VeilEnvelope", keySafe(envelopeId)])).value;
    if (!env) return json({ ok: true, already_gone: true, burned: false, reason: "envelope_gone" });
    if (String(env.session_token || "") !== token && !(session.group_token && String(env.group_token || "") === String(session.group_token))) return j({ error: "Envelope does not belong to this session" }, 403);
    const cur = new Date(String(env.expires_at)).getTime();
    if (!Number.isFinite(cur) || cur <= Date.now()) return json({ ok: true, burned: false, reason: "already_expired" });
    const burnSeconds = Number(policy.default_ttl_seconds) || 3600;
    const burnAt = Date.now() + burnSeconds * 1000;
    if (burnAt >= cur) return json({ ok: true, burned: false, reason: "already_within_burn_window", expires_at: env.expires_at, burn_window_seconds: burnSeconds });
    env.expires_at = new Date(burnAt).toISOString(); env.delivery_state = "delivered";
    await KV.set(["entity", "VeilEnvelope", keySafe(envelopeId)], env);
    console.info("burn-executed", { token: token.slice(0, 8), envelope: envelopeId, slot, window: burnSeconds });
    return json({ ok: true, burned: true, reason: "shortened", expires_at: env.expires_at });
  }
  if (action === "heartbeat") {
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    session.last_activity = nowIso();
    if (slot === "initiator") session.initiator_seen_at = nowIso(); else if (slot === "responder") session.responder_seen_at = nowIso();
    await KV.set(["entity", "VeilSession", String(session.id)], session);
    return json({ ok: true });
  }
  if (action === "end") {
    if (!session.group_token) await deleteSessionEnvelopes(token); // W-19: group envelopes are shared history
    await KV.delete(["entity", "VeilSession", String(session.id)]);
    await KV.delete(["veil_sess_token", keySafe(token)]);
    return json({ ok: true });
  }
  return j({ error: "Unknown action" }, 400);
}
