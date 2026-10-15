/**
 * @veil/device — deniable encrypted vaults (web parity, extracted from the
 * live bundle index-CXHmaNHA.js + Vaults-DKxWFv05.js on Sept 19 2026).
 *
 * Container format (byte-exact):
 *   - 24 MB fixed-size block of CSPRNG bytes (24 MB = 25,165,824; the size
 *     never hints at content). Legacy containers: 32 MB / 4 MB keep working.
 *   - Volume slot layout at offset T:  [u32 BE ct.length][16B salt][12B iv][ct]
 *     (32-byte header). Outer/decoy volume at offset 0; hidden volume at
 *     12,582,912 (24 MB container) / 16,777,216 (32 MB) / 2,097,152 (4 MB).
 *   - Volume plaintext = JSON { files: [{ name, type, size, data(base64) }] },
 *     encrypted with AES-256-GCM under PBKDF2-SHA256(passphrase, salt, 600k).
 *   - File limit 8 MB; encrypted volume must fit its 12 MB slot.
 *
 * Web flow parity: create -> UploadPrivateFile(container.bin) -> VeilVault
 * record { name, container_uri, byte_length, kdf, cipher: 'AES-GCM-256' }.
 * Unlock -> vaultFileSignedUrl({file_uri}) -> fetch -> try outer, then hidden.
 */
import { randomBytes, toB64, utf8, fromB64 } from '../../crypto-core/src/index';
import { aesGcmKey, pbkdf2Sha256Bytes, VAULT_KDF_LABEL, VAULT_PBKDF2_ITERATIONS } from './kdf';

export const CONTAINER_BYTES = 25165824; // 24 MB (web YE)
export const HIDDEN_OFFSET_24MB = 12582912; // web JE
export const HIDDEN_OFFSET_32MB = 16777216; // web XE (legacy containers)
export const HIDDEN_OFFSET_4MB = 2097152; // web qE (legacy containers)
export const SLOT_BYTES = 12582912; // each volume slot is 12 MB
export const VAULT_FILE_LIMIT_BYTES = 8388608; // 8 MB per file (web KE)
export const VAULT_CIPHER = 'AES-GCM-256';

export interface VaultFileEntry {
  name: string;
  type: string;
  size: number;
  /** base64 file bytes */
  data: string;
}

export interface VaultManifest {
  files: VaultFileEntry[];
}

export interface VolumeBlob {
  salt: Uint8Array;
  iv: Uint8Array;
  ct: Uint8Array;
}

export type VaultStage = 'derive' | 'encrypt' | 'container';

export interface CreateVaultArgs {
  passphrase: string;
  file: { name: string; type: string; bytes: Uint8Array };
  hiddenPassphrase?: string | null;
  hiddenFile?: { name: string; type: string; bytes: Uint8Array } | null;
  onStage?: (s: VaultStage) => void;
}

export interface OpenVaultResult {
  partition: 'outer' | 'hidden';
  manifest: VaultManifest;
}

/** web eD(): file entry with 8 MB limit; data base64 (btoa chunked on web). */
export function vaultFileEntry(name: string, type: string, bytes: Uint8Array): VaultFileEntry {
  if (bytes.byteLength > VAULT_FILE_LIMIT_BYTES) {
    throw new Error('File exceeds the 8 MB limit for deniable containers');
  }
  return { name, type: type || 'application/octet-stream', size: bytes.byteLength, data: toB64(bytes) };
}

/** web GE(): parse `PBKDF2-SHA256-<n>` kdf label -> iterations (default 600k). */
export function parseVaultKdf(kdf: string | undefined): number {
  const m = /(\d+)\s*$/.exec(String(kdf || ''));
  return m ? Math.max(1, parseInt(m[1], 10)) : VAULT_PBKDF2_ITERATIONS;
}

/** web tD(): encrypt a volume payload (fresh 16B salt + 12B IV, AES-256-GCM). */
export async function encryptVolume(passphrase: string, manifest: VaultManifest): Promise<VolumeBlob> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS));
  const plaintext = utf8(JSON.stringify(manifest));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, plaintext as unknown as BufferSource),
  );
  if (32 + ct.length > SLOT_BYTES) throw new Error('Encrypted payload does not fit its slot');
  return { salt, iv, ct };
}

/** web nD(): write a volume into its slot (32-byte header + ciphertext). */
export function writeVolumeSlot(container: Uint8Array, offset: number, vol: VolumeBlob): void {
  const header = new Uint8Array(32);
  new DataView(header.buffer).setUint32(0, vol.ct.length);
  header.set(vol.salt, 4);
  header.set(vol.iv, 20);
  container.set(header, offset);
  container.set(vol.ct, offset + 32);
}

/** web rD(): try to open a volume slot; null on any failure (no error leak). */
export async function readVolumeSlot(
  container: Uint8Array,
  offset: number,
  passphrase: string,
  iterations: number,
): Promise<VaultManifest | null> {
  if (container.length < offset + 32) return null;
  const ctLen = new DataView(container.slice(offset, offset + 4).buffer as ArrayBuffer).getUint32(0);
  if (ctLen < 17 || ctLen > SLOT_BYTES - 32 || offset + 32 + ctLen > container.length) return null;
  try {
    const salt = container.slice(offset + 4, offset + 20);
    const iv = container.slice(offset + 20, offset + 32);
    const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, iterations));
    const pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource },
        key,
        container.slice(offset + 32, offset + 32 + ctLen) as unknown as BufferSource,
      ),
    );
    return JSON.parse(new TextDecoder().decode(pt)) as VaultManifest;
  } catch {
    return null;
  }
}

/**
 * (b57) Native CSPRNG fill — one bridge call for the whole 24 MB container
 * via VeilCrypto.randomBytesBase64 (SecRandomCopyBytes). The old path was 384
 * chunked react-native-get-random-values calls, which cost several seconds on
 * device. Falls back to the exact same chunked JS path on old binaries / Node
 * tests, so output is byte-equivalent either way (both are pure CSPRNG bytes).
 */
async function fillRandom(container: Uint8Array): Promise<void> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireNativeModule?: <T>(name: string) => T };
    const mod = emc?.requireNativeModule?.<{ randomBytesBase64?: (n: number) => Promise<string> }>('VeilCrypto');
    if (mod?.randomBytesBase64) {
      const t0 = Date.now();
      const b64 = await mod.randomBytesBase64(container.length);
      const bytes = fromB64(b64);
      if (bytes.length === container.length) {
        container.set(bytes);
        console.log(`[veil-rng] fill NATIVE ${container.length} B in ${Date.now() - t0} ms`);
        return;
      }
      console.log(`[veil-rng] native length mismatch (${bytes.length} vs ${container.length}) — JS path`);
    }
  } catch { /* module missing on old binaries — JS path below */ }
  console.log('[veil-rng] fill JS (chunked) — native path unavailable');
  const CHUNK = 65536;
  for (let i = 0; i < container.length; i += CHUNK) {
    // CSPRNG fill (react-native-get-random-values on device, WebCrypto in tests)
    globalThis.crypto.getRandomValues(container.subarray(i, Math.min(i + CHUNK, container.length)));
  }
}

/** web iD(): build the 24 MB container (decoy volume at 0, hidden at 12 MB). */
export async function createVaultContainer(args: CreateVaultArgs): Promise<{ container: Uint8Array; byteLength: number; hasHidden: boolean }> {
  if (!args.passphrase) throw new Error('Passphrase is required');
  const stage = (s: VaultStage) => args.onStage?.(s);

  const container = new Uint8Array(CONTAINER_BYTES);
  await fillRandom(container);

  stage('derive');
  writeVolumeSlot(container, 0, await encryptVolume(args.passphrase, { files: [vaultFileEntry(args.file.name, args.file.type, args.file.bytes)] }));

  stage('encrypt');
  if (args.hiddenPassphrase) {
    const hf = args.hiddenFile ?? null;
    writeVolumeSlot(
      container,
      HIDDEN_OFFSET_24MB,
      await encryptVolume(args.hiddenPassphrase, { files: hf ? [vaultFileEntry(hf.name, hf.type, hf.bytes)] : [] }),
    );
  }

  stage('container');
  return { container, byteLength: CONTAINER_BYTES, hasHidden: !!args.hiddenPassphrase };
}

/** web aD(): unlock — try the decoy volume at 0, then the hidden volume. */
export async function openVaultContainer(container: Uint8Array, passphrase: string, kdf: string | undefined): Promise<OpenVaultResult> {
  if (!passphrase) throw new Error('Passphrase is required');
  const iterations = parseVaultKdf(kdf);
  let hiddenOffset = HIDDEN_OFFSET_4MB;
  if (container.length >= 33554432) hiddenOffset = HIDDEN_OFFSET_32MB;
  else if (container.length >= CONTAINER_BYTES) hiddenOffset = HIDDEN_OFFSET_24MB;

  const outer = await readVolumeSlot(container, 0, passphrase, iterations);
  if (outer) return { partition: 'outer', manifest: outer };

  const hidden = await readVolumeSlot(container, hiddenOffset, passphrase, iterations);
  if (hidden) return { partition: 'hidden', manifest: hidden };

  throw new Error('Wrong passphrase, or the container is corrupted');
}

/** The VeilVault entity record created after upload (web parity). */
export function vaultRecord(name: string, containerUri: string, byteLength: number): Record<string, unknown> {
  return {
    name,
    container_uri: containerUri,
    byte_length: byteLength,
    kdf: VAULT_KDF_LABEL,
    cipher: VAULT_CIPHER,
  };
}
