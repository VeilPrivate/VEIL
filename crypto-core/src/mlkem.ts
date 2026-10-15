/**
 * @veil/crypto-core — ML-KEM-768 (FIPS 203) helpers.
 * b64 keypair/encap/decap semantics identical to the web bundle (K_/q_/J_).
 *
 * VENDORED SOURCES (mlkem-src/, v2.7.0, MIT): the npm package's CJS build
 * wraps every module in a UMD factory whose `require` is a function PARAMETER —
 * Metro cannot see those requires, so none of the modules are registered in the
 * bundle; the first call dies with "Requiring unknown module" (reproduced:
 * repro/tap-entry.ts). The ESM build instead loads a Deno shim that constructs
 * `new Proxy`, which Hermes cannot run. The vendored copy is plain ESM —
 * Metro-native — with the Deno/Node shim replaced by a direct globalThis.crypto
 * read (always installed first by src/polyfills.ts). Byte-identical ML-KEM math.
 */

import { toB64, fromB64 } from './bytes';
import { MlKem768 } from './mlkem-src/mlKem768.js';

export interface MlKemKeypairB64 {
  pub: string;
  priv: string;
}

export interface MlKemEncap {
  /** encapsulated ciphertext (b64) — travels in envelope header `pqct` */
  ct: string;
  /** shared secret (32 bytes) */
  secret: Uint8Array;
}

let instance: MlKem768 | null = null;

function kem(): MlKem768 {
  if (!instance) instance = new MlKem768();
  return instance;
}

export async function mlkemAvailable(): Promise<boolean> {
  try {
    kem();
    return true;
  } catch {
    return false;
  }
}

/** Generate ML-KEM-768 keypair, b64-encoded (K_ in the bundle). */
export async function mlkemKeypair(): Promise<MlKemKeypairB64> {
  const k = kem();
  const [pub, priv] = await k.generateKeyPair();
  return { pub: toB64(new Uint8Array(pub)), priv: toB64(new Uint8Array(priv)) };
}

/** Encapsulate to a peer's public key (q_ in the bundle). */
export async function mlkemEncap(pubB64: string): Promise<MlKemEncap> {
  const k = kem();
  const [ct, secret] = await k.encap(fromB64(pubB64));
  return { ct: toB64(new Uint8Array(ct)), secret: new Uint8Array(secret) };
}

/** Decapsulate a ciphertext with our private key (J_ in the bundle). */
export async function mlkemDecap(privB64: string, ctB64: string): Promise<Uint8Array> {
  const k = kem();
  return new Uint8Array(await k.decap(fromB64(ctB64), fromB64(privB64)));
}
