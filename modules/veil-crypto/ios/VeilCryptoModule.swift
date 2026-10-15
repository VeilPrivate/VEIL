import ExpoModulesCore
import CommonCrypto
import CryptoKit
import UIKit

/**
 * Native PBKDF2-SHA256 via Apple's CommonCrypto (CCKeyDerivationPBKDF).
 * The web app gets native-speed PBKDF2 through SubtleCrypto; this gives the
 * native app the same — the pure-JS path costs ~2 MINUTES per unlock attempt
 * on-device (210k iterations of JS HMAC vs milliseconds here).
 * Byte-identical output to the JS/Node path (asserted in the device test suite).
 */
public class VeilCryptoModule: Module {
  // NOTE (b48 fix): do NOT wrap this in an explicit `ModuleDefinition { ... }`
  // call — in this ExpoModulesCore version ModuleDefinition's initializer is
  // internal and doesn't accept a trailing closure. The function body IS the
  // result-builder DSL; Name(...)/AsyncFunction(...) go directly here.
  public func definition() -> ModuleDefinition {
    Name("VeilCrypto")

    // ---------- Screenshot / screen-recording watch (b61) ----------
    // iOS gives no way to BLOCK the hardware screenshot, but it fires
    // UIApplication.userDidTakeScreenshotNotification the moment one is
    // taken, and UIScreen.capturedDidChangeNotification for AirPlay /
    // screen recording. The JS side turns these into an in-thread
    // notice to the other party (Snapchat-style, post-hoc deterrent).
    Events("onScreenCapture")
    // (b64) BUG FIX: the block-based addObserver returns an observer token
    // that MUST be retained — the previous code discarded it, so the token
    // deallocated immediately and iOS stopped delivering the notifications
    // entirely. On-device symptom: screenshots happened with no notice, no
    // local amber line, nothing ("no deterrent"). Tokens are now held in a
    // static on the module class and removed in OnDestroy.
    OnCreate {
      let shot = NotificationCenter.default.addObserver(
        forName: UIApplication.userDidTakeScreenshotNotification,
        object: nil,
        queue: .main
      ) { [weak self] _ in
        self?.sendEvent("onScreenCapture", ["kind": "screenshot"])
      }
      let rec = NotificationCenter.default.addObserver(
        forName: UIScreen.capturedDidChangeNotification,
        object: nil,
        queue: .main
      ) { [weak self] note in
        if let screen = note.object as? UIScreen {
          self?.sendEvent("onScreenCapture", ["kind": "recording", "captured": screen.isCaptured])
        }
      }
      VeilCryptoModule.captureObservers = [shot, rec]
    }
    OnDestroy {
      VeilCryptoModule.captureObservers.forEach { NotificationCenter.default.removeObserver($0) }
      VeilCryptoModule.captureObservers = []
    }

    // ---------- Secure Enclave hardware seal (b62) ----------
    // "Hardware" key storage: the identity keyvault master key is sealed with
    // an AES-GCM key derived from an ECDH agreement with a P-256 private key
    // that lives ONLY in the Secure Enclave (non-extractable, biometry-gated).
    // The wrapped blob in the keychain is useless off-device; unwrapping
    // demands Face ID / Touch ID at the Secure Enclave key-use itself.
    Function("seIsAvailable") { () -> Bool in
      SecureEnclave.isAvailable
    }

    AsyncFunction("seWrapKey") { (masterKeyB64: String) -> [String: String] in
      let seKey = try VeilCryptoModule.loadOrCreateSeKey()
      let master = Data(base64Encoded: masterKeyB64)
      if master == nil || master!.isEmpty {
        throw NSError(domain: "VeilCrypto", code: 40, userInfo: [NSLocalizedDescriptionKey: "seWrapKey: master key is not valid base64"])
      }
      let eph = try P256.KeyAgreement.PrivateKey()
      let shared = try eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
      var salt = Data(count: 32)
      _ = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
      let sym = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data("veil-se-wrap-v1".utf8), outputByteCount: 32)
      let sealed = try AES.GCM.seal(master!, using: sym)
      guard let combined = sealed.combined else {
        throw NSError(domain: "VeilCrypto", code: 41, userInfo: [NSLocalizedDescriptionKey: "seWrapKey: seal failed"])
      }
      return [
        "eph": eph.publicKey.x963Representation.base64EncodedString(),
        "salt": salt.base64EncodedString(),
        "ct": combined.base64EncodedString(),
      ]
    }

    AsyncFunction("seUnwrapKey") { (ephB64: String, saltB64: String, ctB64: String) -> String in
      guard let seKey = try? VeilCryptoModule.loadSeKey() else {
        throw NSError(domain: "VeilCrypto", code: 42, userInfo: [NSLocalizedDescriptionKey: "seUnwrapKey: Secure Enclave key unavailable (re-enrolled biometrics?)"])
      }
      guard let ephData = Data(base64Encoded: ephB64),
            let salt = Data(base64Encoded: saltB64),
            let ct = Data(base64Encoded: ctB64),
            let ephPub = try? P256.KeyAgreement.PublicKey(x963Representation: ephData) else {
        throw NSError(domain: "VeilCrypto", code: 43, userInfo: [NSLocalizedDescriptionKey: "seUnwrapKey: malformed sealed blob"])
      }
      let shared = try seKey.sharedSecretFromKeyAgreement(with: ephPub) // biometric prompt here
      let sym = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data("veil-se-wrap-v1".utf8), outputByteCount: 32)
      let box = try AES.GCM.SealedBox(combined: ct)
      let plain = try AES.GCM.open(box, using: sym)
      return plain.base64EncodedString()
    }

    // b102: delete the persisted SE key and recreate it with the CURRENT
    // biometry-gated access control. Devices that first touched hardware mode
    // before b100 carry an SE key created by the old seAccessControl flags
    // (no biometry constraint) — loadOrCreateSeKey() happily reuses it
    // forever, so unwrap never prompts Face ID (owner hardware finding,
    // surviving b96-b101: "none of the modes ask me for biometrics"). Only
    // safe to call when the keyvault identity is in memory and is about to be
    // re-sealed: the old sealed blob becomes unreadable the moment this runs.
    AsyncFunction("seResetKey") { () -> Bool in
      SecItemDelete(VeilCryptoModule.seQuery() as CFDictionary)
      _ = try VeilCryptoModule.loadOrCreateSeKey()
      return true
    }

    AsyncFunction("pbkdf2Sha256") { (password: String, saltHex: String, iterations: Int, dkLen: Int) -> String in
        let salt = VeilCryptoModule.hexToBytes(saltHex)
        if salt.isEmpty {
          throw NSError(domain: "VeilCrypto", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid salt hex"])
        }
        let pw = password.cString(using: .utf8) ?? []
        if pw.count < 1 {
          throw NSError(domain: "VeilCrypto", code: 2, userInfo: [NSLocalizedDescriptionKey: "password encoding failed"])
        }
        var derived = [UInt8](repeating: 0, count: dkLen)
        let status: Int32 = pw.withUnsafeBufferPointer { pwBuf -> Int32 in
          salt.withUnsafeBufferPointer { saltBuf -> Int32 in
            derived.withUnsafeMutableBufferPointer { dBuf -> Int32 in
              CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                pwBuf.baseAddress, pw.count - 1, // exclude the NUL terminator; length is explicit
                saltBuf.baseAddress, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                UInt32(iterations),
                dBuf.baseAddress, dkLen)
            }
          }
        }
        if status != kCCSuccess {
          throw NSError(domain: "VeilCrypto", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "CCKeyDerivationPBKDF failed (\(status))"])
        }
        return VeilCryptoModule.bytesToHex(derived)
    }

    // ---------- AES-256-GCM (CryptoKit) ----------
    // Added b54: the pure-JS noble AES-GCM shim costs ~30s+ on Hermes for the
    // multi-MB vault/stego/transfer payloads. CryptoKit's sealed-box layout is
    // ciphertext||tag — byte-identical to noble's combined output, so the JS
    // side can fall in/out without any format change.

    AsyncFunction("aesGcmEncrypt") { (keyHex: String, ivHex: String, plaintextBase64: String, aadHex: String) -> String in
        let keyBytes = VeilCryptoModule.hexToBytes(keyHex)
        if keyBytes.count != 32 {
          throw NSError(domain: "VeilCrypto", code: 10, userInfo: [NSLocalizedDescriptionKey: "aesGcmEncrypt: key must be 32 bytes"])
        }
        let iv = VeilCryptoModule.hexToBytes(ivHex)
        if iv.count != 12 {
          throw NSError(domain: "VeilCrypto", code: 11, userInfo: [NSLocalizedDescriptionKey: "aesGcmEncrypt: iv must be 12 bytes"])
        }
        guard let pt = Data(base64Encoded: plaintextBase64) else {
          throw NSError(domain: "VeilCrypto", code: 12, userInfo: [NSLocalizedDescriptionKey: "aesGcmEncrypt: invalid base64 plaintext"])
        }
        let aad = Data(VeilCryptoModule.hexToBytes(aadHex))
        let key = SymmetricKey(data: Data(keyBytes))
        let nonce = try AES.GCM.Nonce(data: Data(iv))
        let sealed = try AES.GCM.seal(pt, using: key, nonce: nonce, authenticating: aad)
        // combined = ciphertext || tag(16) — same layout noble produces
        return (sealed.ciphertext + sealed.tag).base64EncodedString()
    }

    AsyncFunction("aesGcmDecrypt") { (keyHex: String, ivHex: String, combinedBase64: String, aadHex: String) -> String in
        let keyBytes = VeilCryptoModule.hexToBytes(keyHex)
        if keyBytes.count != 32 {
          throw NSError(domain: "VeilCrypto", code: 13, userInfo: [NSLocalizedDescriptionKey: "aesGcmDecrypt: key must be 32 bytes"])
        }
        let iv = VeilCryptoModule.hexToBytes(ivHex)
        if iv.count != 12 {
          throw NSError(domain: "VeilCrypto", code: 14, userInfo: [NSLocalizedDescriptionKey: "aesGcmDecrypt: iv must be 12 bytes"])
        }
        guard let combined = Data(base64Encoded: combinedBase64) else {
          throw NSError(domain: "VeilCrypto", code: 15, userInfo: [NSLocalizedDescriptionKey: "aesGcmDecrypt: invalid base64 ciphertext"])
        }
        if combined.count < 16 {
          throw NSError(domain: "VeilCrypto", code: 16, userInfo: [NSLocalizedDescriptionKey: "aesGcmDecrypt: ciphertext shorter than a bare GCM tag"])
        }
        let aad = Data(VeilCryptoModule.hexToBytes(aadHex))
        let key = SymmetricKey(data: Data(keyBytes))
        let nonce = try AES.GCM.Nonce(data: Data(iv))
        let ct = combined.prefix(combined.count - 16)
        let tag = combined.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        // GCM tag mismatch (wrong key/passphrase) gets a DISTINCT error code so
        // the JS side can tell "bad passphrase" (must propagate immediately —
        // the JS fallback would burn ~30s reaching the same conclusion) apart
        // from "bridge/module problem" (safe to retry in JS).
        // CryptoKitError is an enum (no isAuthenticationFailure property) —
        // match the .authenticationFailure case directly. (b55 fix: the
        // property-based check doesn't exist on this SDK's CryptoKitError.)
        let pt: Data
        do {
          pt = try AES.GCM.open(box, using: key, authenticating: aad)
        } catch CryptoKitError.authenticationFailure {
          throw NSError(domain: "VeilCrypto", code: 20, userInfo: [NSLocalizedDescriptionKey: "authentication failure (GCM tag mismatch)"])
        }
        return pt.base64EncodedString()
    }

    // ---------- randomBytes (SecRandomCopyBytes) ----------
    // Added b57: the 24 MB vault container fill used to be 384 separate JS
    // bridge calls to react-native-get-random-values (several seconds on
    // device). One native call fills the whole buffer instead.
    AsyncFunction("randomBytesBase64") { (byteLength: Int) -> String in
        if byteLength <= 0 || byteLength > 64 * 1024 * 1024 {
          throw NSError(domain: "VeilCrypto", code: 30, userInfo: [NSLocalizedDescriptionKey: "randomBytesBase64: length out of range"])
        }
        var bytes = [UInt8](repeating: 0, count: byteLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteLength, &bytes)
        if status != errSecSuccess {
          throw NSError(domain: "VeilCrypto", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed (\(status))"])
        }
        return Data(bytes).base64EncodedString()
    }
  }

  // ---------- Secure Enclave key persistence ----------
  // (b64) retained NotificationCenter tokens for the capture watch — see OnCreate
  private static var captureObservers: [NSObjectProtocol] = []
  private static let seKeyService = "au.com.mattthemagicalmentalist.veil.se-key"
  private static let seKeyAccount = "veil-se"

  private static func seAccessControl() -> SecAccessControl? {
    SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      [.privateKeyUsage, .biometryCurrentSet],
      nil
    )
  }

  private static func seQuery() -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: seKeyService,
      kSecAttrAccount as String: seKeyAccount,
      kSecReturnData as String: true,
    ]
  }

  /// Load the stored SE key representation, if any (the raw blob itself is
  /// useless outside this device's Secure Enclave — that is the point).
  private static func loadSeKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    var item: CFTypeRef?
    let status = SecItemCopyMatching(seQuery() as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data,
          let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: data) else {
      throw NSError(domain: "VeilCrypto", code: 44, userInfo: [NSLocalizedDescriptionKey: "SE key not found"])
    }
    return key
  }

  /// Load the existing SE key or create + persist a new biometry-gated one.
  private static func loadOrCreateSeKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    if let existing = try? loadSeKey() { return existing }
    let acl = seAccessControl()
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    if let acl = acl {
      key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl)
    } else {
      key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
    }
    var add = seQuery()
    add[kSecReturnData as String] = nil
    add[kSecValueData as String] = key.dataRepresentation
    SecItemAdd(add as CFDictionary, nil)
    return key
  }

  private static func hexToBytes(_ hex: String) -> [UInt8] {
    let chars = Array(hex.utf8)
    if chars.count % 2 == 1 { return [] }
    var bytes = [UInt8]()
    bytes.reserveCapacity(chars.count / 2)
    var i = 0
    while i < chars.count {
      guard let hi = VeilCryptoModule.hexDigit(chars[i]), let lo = VeilCryptoModule.hexDigit(chars[i + 1]) else { return [] }
      bytes.append(hi << 4 | lo)
      i += 2
    }
    return bytes
  }

  private static func hexDigit(_ c: UInt8) -> UInt8? {
    switch c {
    case 0x30...0x39: return c - 0x30
    case 0x41...0x46: return c - 0x41 + 10
    case 0x61...0x66: return c - 0x61 + 10
    default: return nil
    }
  }

  private static func bytesToHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
  }
}
