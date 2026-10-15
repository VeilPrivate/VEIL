/**
 * @veil/crypto-core — protocol constants, extracted from the live web bundle
 * (index-ygJsbHvt.js). These MUST NOT drift: the web bundle is the reference
 * implementation until an explicit protocol bump (veil-ratchet-3 -> -4).
 */

export const RATCHET_VERSION = 'veil-ratchet-3' as const; // LEGACY fallback only (deserializeRatchetState defaulting for pre-proto-field sessions). New sessions always stamp RATCHET_PROTOCOL_LATEST at creation (createSession/joinSession/completeHandshake) -- this constant never governs a live session's wire tag.
export const RATCHET_PROTOCOL_LATEST = 'veil-ratchet-4' as const;
export const RATCHET_PROTOCOL_SUPPORTED = ['veil-ratchet-3', 'veil-ratchet-4'] as const;

export const RATCHET_ENGINE_LABEL =
  'Double Ratchet — hybrid ECDH P-256 + ML-KEM-768 (FIPS 203), handshake AND per-step PQ re-key · HKDF-SHA256 · AES-GCM-256 · padded buckets · cover traffic' as const;

/** Padded plaintext buckets (bytes). Anything larger throws in the web app. */
export const PADDED_BUCKETS: readonly number[] = [1024, 4096];
/** Padded frame header: 1 byte cover flag + 2 bytes big-endian length. */
export const PAD_FRAME_HEADER_BYTES = 3;

/** BIP39 (standard English wordlist, 2048 words). */
export const BIP39_SALT = 'mnemonic' as const;
export const BIP39_ITERATIONS = 2048;
export const BIP39_WORDS = 24;

/** HKDF info strings (extracted from bundle). */
export const HKDF_INFO_IDENTITY_ED25519 = 'veil-identity-ed25519' as const;

/** 64-byte root/chain derivation in Pp: info = `veil-ratchet-3/rk` -> {rk, ck}. */
export const ROOT_KEY_INFO = 'veil-ratchet-3/rk' as const;
/** Handshake "rk0" derivation in Wp: HKDF(shared, salt=`veil-ratchet-3:<token>`, info=`rk0`, 32). */
export const RK0_INFO = 'rk0' as const;
/** Invite prekey secret: salt = `veil-pp:<token>`, info = `pp`. */
export const PP_INFO = 'pp' as const;

/** b197 (audit H-1): domain string for session-scoped Ed25519 ratchet-key
 *  signatures. The signing keypair is derived from the session's pre-rotation
 *  shared secret with this info string — both peers converge on the same
 *  pair, so every ratchet rotation can be authenticated against splice. */
export const RATCHET_SIG_INFO = 'veil-ratchet-sig-v1' as const;

/** b197 (audit H-1): MASTER SWITCH for signed ratchet rotations. DEFAULT OFF.
 *  Flip to true ONLY when BOTH native and web clients carry the same
 *  crypto-core (the web bundle shares this file). A signed receiver talking
 *  to an un-upgraded peer rejects the peer's rotations fail-closed — visible
 *  desync, not silent breakage — so this ships as a coordinated flip, never
 *  one-sided. Rollout: flip here + ship both clients + age out old sessions. */
export const RATCHET_SIGNING_ENABLED = false as const;
