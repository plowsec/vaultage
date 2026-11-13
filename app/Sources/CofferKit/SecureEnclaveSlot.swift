import CryptoKit
import Foundation
import LocalAuthentication
import Security
#if os(macOS)
import SystemConfiguration
#endif

/// Touch ID / Face ID key slot: a non-extractable Secure Enclave P-256 key; the slot secret is
/// X9.63-KDF(ECDH(ephemeral, SE key)). Only the SE key blob (useless off this Mac) and the
/// ephemeral public key are stored in the vault header.
public enum SecureEnclaveSlot {
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public static var biometryAvailable: Bool {
        var err: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    }

    #if os(macOS)
    public static var computerName: String {
        (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? Host.current().localizedName ?? "this Mac"
    }
    #else
    /// Set once at launch by the app (UIDevice is main-thread only).
    public nonisolated(unsafe) static var computerName = "this device"
    #endif

    /// "Face ID", "Touch ID", "Optic ID", or nil when no biometry is enrolled.
    public static var biometryName: String? {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else { return nil }
        switch ctx.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        default:
            if #available(macOS 14.0, iOS 17.0, *), ctx.biometryType == .opticID { return "Optic ID" }
            return nil
        }
    }

    public struct Created: @unchecked Sendable {
        /// Goes in `slot_add`'s `public` field.
        public let publicInfo: [String: String]
        public let label: String
        public let secret: SecretBytes
    }

    private static func derive(_ shared: SharedSecret, eph: Data, se: Data) -> SecretBytes {
        let info = Data("coffer-se-v1".utf8) + eph + se
        let key = shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: info, outputByteCount: 32)
        return key.withUnsafeBytes { SecretBytes(copying: $0) }
    }

    /// New SE key + slot secret. Does not prompt. `flags` overrides the access-control flags
    /// (used by the self-test with `.privateKeyUsage` only).
    public static func create(flags override: SecAccessControlCreateFlags? = nil) throws -> Created {
        let biometry = biometryAvailable
        let flags: SecAccessControlCreateFlags = override ?? (biometry ? [.privateKeyUsage, .biometryCurrentSet] : [.privateKeyUsage, .userPresence])
        var cfErr: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &cfErr) else {
            throw cfErr?.takeRetainedValue() ?? CofferError(code: "crypto", message: "could not create access control")
        }
        let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        let sePub = se.publicKey.x963Representation
        let secret = derive(try eph.sharedSecretFromKeyAgreement(with: se.publicKey), eph: ephPub, se: sePub)
        let name = computerName
        return Created(
            publicInfo: [
                "key": se.dataRepresentation.base64EncodedString(),
                "eph": ephPub.base64EncodedString(),
                "auth": biometry ? "biometry" : "presence",
            ],
            label: label(biometry: biometry, name: name),
            secret: secret
        )
    }

    private static func label(biometry: Bool, name: String) -> String {
        #if os(macOS)
        return biometry ? "Touch ID on \(name)" : "Mac password on \(name)"
        #else
        return biometry ? "\(biometryName ?? "Biometrics") on \(name)" : "Passcode on \(name)"
        #endif
    }

    /// Rebuild the slot secret. Prompts for Touch ID / the Mac password (blocks): call off the
    /// main thread. Throws `LAError.userCancel` etc. if the user backs out.
    public static func unlockSecret(publicInfo: [String: String], reason: String, context: LAContext = LAContext()) throws -> SecretBytes {
        guard let keyB64 = publicInfo["key"], let blob = Data(base64Encoded: keyB64),
              let ephB64 = publicInfo["eph"], let eph = Data(base64Encoded: ephB64)
        else { throw CofferError(code: "format", message: "Touch ID slot data is damaged") }
        context.localizedReason = reason
        let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        let ephKey = try P256.KeyAgreement.PublicKey(x963Representation: eph)
        let shared = try se.sharedSecretFromKeyAgreement(with: ephKey)
        return derive(shared, eph: eph, se: se.publicKey.x963Representation)
    }

    /// Whether this Mac's Secure Enclave can load the key blob (no prompt; loading is free,
    /// only key agreement needs authentication).
    public static func canLoad(publicInfo: [String: String]) -> Bool {
        guard let b = publicInfo["key"], let blob = Data(base64Encoded: b) else { return false }
        return (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)) != nil
    }

    public static func isUserCancel(_ error: Error) -> Bool {
        if let la = error as? LAError {
            return [.userCancel, .appCancel, .systemCancel, .userFallback].contains(la.code)
        }
        let ns = error as NSError
        return ns.domain == LAErrorDomain && [LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue].contains(ns.code)
    }
}
