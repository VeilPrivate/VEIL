/**
 * veil-crypto — local Expo module (iOS).
 * Native PBKDF2-SHA256 via CommonCrypto's CCKeyDerivationPBKDF.
 * Output is byte-identical to the web contract (PBKDF2-SHA256-210000):
 * the algorithm is standard; the web runs it in SubtleCrypto, iOS runs it here.
 */
import { requireNativeModule } from 'expo-modules-core';

type VeilCryptoNative = {
  pbkdf2Sha256(password: string, saltHex: string, iterations: number, dkLen: number): Promise<string>;
};

export async function pbkdf2Sha256(password: string, saltHex: string, iterations: number, dkLen: number): Promise<string> {
  const mod = requireNativeModule<VeilCryptoNative>('VeilCrypto');
  return mod.pbkdf2Sha256(password, saltHex, iterations, dkLen);
}
