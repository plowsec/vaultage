import CCoffer
import Foundation

/// An error reported by the core. `message` is the core's text; `errorDescription` is the
/// user-facing version.
public struct CofferError: LocalizedError, Equatable, Sendable {
    public let code: String
    public let message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }

    /// Tampering or corruption. Never auto-dismiss these.
    public var isIntegrity: Bool { code == "integrity" }
    public var isWrongSecret: Bool { code == "crypto" }

    public var errorDescription: String? {
        var m = message
        // "No such file or directory (os error 2)" → "No such file or directory"
        if let r = m.range(of: #" \(os error \d+\)$"#, options: .regularExpression) { m.removeSubrange(r) }
        switch code {
        case "crypto":
            return "Wrong passphrase or key."
        case "locked":
            return "This vault is locked. Unlock it and try again."
        case "network":
            return "Can’t reach the sync server. " + Self.sentence(Self.strip(m, "network: "))
        case "server":
            if Self.serverStatus(m) == 507 { return Self.quotaFull }
            return "The sync server refused the request: " + Self.sentence(Self.stripServer(m))
        case "not_found":
            let what = Self.strip(m, "not found: ")
            return what.isEmpty ? "Not found." : "Couldn’t find “\(what)”."
        case "exists":
            let what = Self.strip(m, "already exists: ")
            return "“\(what)” already exists."
        case "integrity":
            return "Integrity check failed: " + Self.sentence(Self.strip(m, "integrity check failed: "))
        case "format":
            return "Unreadable data: " + Self.sentence(Self.strip(m, "bad format: "))
        default:
            return Self.sentence(m)
        }
    }

    public static let quotaFull = "The server’s storage quota for this vault is full. Empty the Trash or delete older versions to free space."

    /// HTTP status in a core message like "server (507): …".
    static func serverStatus(_ m: String) -> Int? {
        guard let r = m.range(of: #"^server \((\d{3})\)"#, options: .regularExpression) else { return nil }
        return Int(m[r].filter(\.isNumber))
    }

    static func stripServer(_ m: String) -> String {
        guard let r = m.range(of: #"^server \(\d{3}\): "#, options: .regularExpression) else { return strip(m, "server ") }
        return String(m[r.upperBound...])
    }

    /// User-facing text for a raw `status.sync.error` string.
    public static func readableSync(_ raw: String) -> String {
        if serverStatus(raw) == 507 || raw.contains("quota") { return quotaFull }
        if serverStatus(raw) != nil { return sentence(stripServer(raw)) }
        return sentence(strip(raw, "network: "))
    }

    static func strip(_ s: String, _ prefix: String) -> String {
        s.hasPrefix(prefix) ? String(s.dropFirst(prefix.count)) : s
    }

    static func sentence(_ s: String) -> String {
        guard let first = s.first else { return "Something went wrong." }
        var out = first.uppercased() + s.dropFirst()
        if !".!?".contains(out.last!) { out += "." }
        return out
    }
}

private struct Envelope<T: Decodable>: Decodable {
    let ok: Bool
    let data: T?
    let code: String?
    let error: String?
}

/// Async front for the blocking C ABI. Every call runs off the main thread on a concurrent queue
/// (the core is thread-safe).
public final class CofferCore: @unchecked Sendable {
    public static let shared = CofferCore()

    private let queue = DispatchQueue(label: "local.coffer.core", qos: .userInitiated, attributes: .concurrent)

    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()

    public init() {}

    /// Apply process hardening; call first thing in `main`.
    public static func harden() -> Posture {
        guard let p = coffer_harden() else { return Posture() }
        defer { coffer_free_string(p) }
        let data = Data(bytes: p, count: strlen(p))
        return (try? decoder.decode(Posture.self, from: data)) ?? Posture()
    }

    private static func encode(_ request: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: request)
    }

    /// Blocking call; use from a background thread only.
    public static func callSync<T: Decodable>(_ requestJSON: Data, secret: SecretBytes?, as: T.Type) throws -> T {
        var json = requestJSON
        json.append(0)
        let raw: UnsafeMutablePointer<CChar>? = json.withUnsafeBytes { req in
            let reqPtr = req.baseAddress!.assumingMemoryBound(to: CChar.self)
            if let secret {
                return secret.withUnsafeBytes { s in
                    coffer_call(reqPtr, s.baseAddress?.assumingMemoryBound(to: UInt8.self), s.count)
                }
            }
            return coffer_call(reqPtr, nil, 0)
        }
        guard let raw else { throw CofferError(code: "internal", message: "no response from core") }
        defer { coffer_free_string(raw) }
        let data = Data(bytes: raw, count: strlen(raw))
        let env: Envelope<T>
        do {
            env = try decoder.decode(Envelope<T>.self, from: data)
        } catch {
            throw CofferError(code: "format", message: "unexpected response from core")
        }
        guard env.ok else {
            throw CofferError(code: env.code ?? "internal", message: env.error ?? "unknown error")
        }
        if let d = env.data { return d }
        if T.self == Nothing.self { return Nothing() as! T }
        throw CofferError(code: "format", message: "empty response from core")
    }

    public func call<T: Decodable>(_ request: [String: Any], secret: SecretBytes? = nil, as type: T.Type = T.self) async throws -> T {
        let json = try Self.encode(request)
        return try await withCheckedThrowingContinuation { cont in
            queue.async {
                cont.resume(with: Result { try Self.callSync(json, secret: secret, as: T.self) })
            }
        }
    }

    public func perform(_ request: [String: Any], secret: SecretBytes? = nil) async throws {
        _ = try await call(request, secret: secret, as: Nothing.self)
    }

    /// Decrypt a file (or one revision) into memory. The returned `Data` wraps the core's buffer
    /// without copying; it is wiped and freed by `coffer_free_bytes` when the last reference goes.
    public func read(vault: String, entry: String, rev: UInt64? = nil) async throws -> Data {
        var req: [String: Any] = ["id": vault, "entry": entry]
        if let rev { req["rev"] = rev }
        var buf = try Self.encode(req)
        buf.append(0)
        let json = buf
        return try await withCheckedThrowingContinuation { cont in
            queue.async {
                var len = 0
                var err: UnsafeMutablePointer<CChar>?
                let ptr = json.withUnsafeBytes { req in
                    coffer_read(req.baseAddress!.assumingMemoryBound(to: CChar.self), &len, &err)
                }
                if let ptr {
                    let data = Data(bytesNoCopy: ptr, count: len, deallocator: .custom { p, n in
                        coffer_free_bytes(p.assumingMemoryBound(to: UInt8.self), n)
                    })
                    cont.resume(returning: data)
                } else {
                    var msg = "could not read file"
                    if let err {
                        msg = String(cString: err)
                        coffer_free_string(err)
                    }
                    // The read path only reports text; classify the common cases.
                    let code: String
                    if msg.hasPrefix("integrity") { code = "integrity" }
                    else if msg == "vault is locked" { code = "locked" }
                    else if msg.hasPrefix("not found") { code = "not_found" }
                    else if msg.hasPrefix("network") { code = "network" }
                    else { code = "io" }
                    cont.resume(throwing: CofferError(code: code, message: msg))
                }
            }
        }
    }
}
