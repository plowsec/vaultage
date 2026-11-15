import Foundation

// Shapes returned by the core's JSON API (crates/core/src/api.rs). Decoded with
// `.convertFromSnakeCase`; all timestamps are unix milliseconds.

public enum SlotKind: String, Codable, Sendable, Hashable {
    case passphrase
    case recovery
    case secureEnclave = "secure-enclave"
    case unknown

    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = SlotKind(rawValue: raw) ?? .unknown
    }

    public var portable: Bool { self == .passphrase || self == .recovery }
}

public struct SlotInfo: Decodable, Identifiable, Hashable, Sendable {
    public let id: String
    public let kind: SlotKind
    public let label: String
    public let created: Int64
    /// String-valued public data (Secure Enclave: key blob, ephemeral key, auth mode).
    public let publicInfo: [String: String]?

    enum CodingKeys: String, CodingKey { case id, kind, label, created, publicInfo = "public" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        kind = try c.decode(SlotKind.self, forKey: .kind)
        label = try c.decode(String.self, forKey: .label)
        created = try c.decode(Int64.self, forKey: .created)
        publicInfo = try? c.decodeIfPresent([String: String].self, forKey: .publicInfo)
    }
}

public struct VaultInfo: Decodable, Identifiable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let path: String
    public let remote: String?
    public let unlocked: Bool
    public let missing: Bool
    public let slots: [SlotInfo]

    public var synced: Bool { remote != nil }
    public var hasPassphrase: Bool { slots.contains { $0.kind == .passphrase } }
    public var hasRecovery: Bool { slots.contains { $0.kind == .recovery } }
}

public struct SyncReport: Decodable, Hashable, Sendable {
    public let pulled: Int
    public let pushed: Int
    public let downloaded: Int
    public let errors: [String]
}

public struct SyncStatus: Decodable, Hashable, Sendable {
    /// local | idle | syncing | offline | error | rekeyed
    public let state: String
    public let lastOkMs: Int64
    public let error: String?
    public let last: SyncReport
}

public struct Summary: Decodable, Hashable, Sendable {
    public let files: UInt64
    public let bytes: UInt64
    public let pending: UInt64
    public let trashed: UInt64
}

public struct Activity: Decodable, Hashable, Sendable {
    public let label: String
    public let done: UInt64
    public let total: UInt64
}

public struct VaultStatus: Decodable, Hashable, Sendable {
    public let sync: SyncStatus
    public let summary: Summary
    public let generation: UInt64
    public let conflicts: [String]
    public let activity: Activity?
    /// A key rotation is staged (prepared, not committed).
    public let rotationPending: Bool?
    public let epoch: UInt64?
    public let synced: Bool?

    public var isRotationPending: Bool { rotationPending == true }
    /// Keys were rotated on another device; sync waits for the new secret.
    public var isRekeyed: Bool { sync.state == "rekeyed" }
}

public struct Item: Decodable, Hashable, Sendable {
    public let name: String
    public let path: String
    public let isDir: Bool
    public let size: UInt64
    public let mtime: Int64
    /// Entry id (files only).
    public let id: String?
    public let pending: Bool
    public let count: UInt64
    public let rev: UInt64
    public let device: String

    // Not Identifiable: `id` is the entry id (nil for folders). Key lists by `path`.
}

public struct Version: Decodable, Identifiable, Hashable, Sendable {
    public let rev: UInt64
    public let ts: Int64
    public let device: String
    public let size: UInt64
    public let path: String
    public let deleted: Bool
    public let pending: Bool
    public let current: Bool
    public var id: UInt64 { rev }
}

public struct TrashItem: Decodable, Identifiable, Hashable, Sendable {
    public let id: String
    public let path: String
    public let size: UInt64
    public let deletedTs: Int64
    public let device: String
}

public struct ImportReport: Decodable, Hashable, Sendable {
    public let files: UInt64
    public let bytes: UInt64
    public let skipped: [String]
    public let sourcesDeleted: UInt64
}

public struct Posture: Decodable, Hashable, Sendable {
    public var coreDumpsOff: Bool = false
    public var attachDenied: Bool = false
    public var hardenedRuntime: Bool?
    public var debuggable: Bool?
    public var sip: Bool?
    public var memoryLocked: Bool = false

    public init() {}

    /// Amber when the process could be inspected by other code on this Mac.
    public var needsAttention: Bool { hardenedRuntime != true || debuggable == true || sip == false }
}

public struct DeviceInfo: Decodable, Hashable, Sendable {
    public let id: String
    public let name: String
}

public struct CreateResult: Decodable, Sendable {
    public let id: String
    public let recoveryKey: String
}

public struct IDResult: Decodable, Sendable { public let id: String }
public struct ListResult: Decodable, Sendable {
    public let items: [Item]
    public let generation: UInt64
}
public struct ItemsResult: Decodable, Sendable { public let items: [Item] }
public struct SlotResult: Decodable, Sendable { public let slot: String }
public struct PathResult: Decodable, Sendable { public let path: String }
public struct WrittenResult: Decodable, Sendable { public let written: [String] }
public struct MovedResult: Decodable, Sendable { public let moved: Int }
public struct DeletedResult: Decodable, Sendable { public let deleted: Int }
public struct PurgedResult: Decodable, Sendable { public let purged: Int }
public struct RecoveryKeyResult: Decodable, Sendable { public let recoveryKey: String }
public struct CodeResult: Decodable, Sendable { public let code: String }
/// `join_invite`: `recoveryKey` is this member's own (one-time invite); nil for an old-style invite.
public struct JoinInviteResult: Decodable, Sendable {
    public let id: String
    public let recoveryKey: String?
}

/// A one-time invite as the vault's members see it (`invites`).
public struct InviteStatus: Decodable, Identifiable, Hashable, Sendable {
    public let id: String
    public let label: String
    public let created: Int64
    public let expires: Int64
    public let claimed: Int64?
    public let revoked: Int64?
    /// waiting | used | expired | revoked
    public let state: String

    public var isWaiting: Bool { state == "waiting" }
}

public struct UsageInfo: Decodable, Hashable, Sendable {
    /// Stored chunk bytes on the server.
    public let bytes: UInt64
    public let chunks: UInt64
    public let records: UInt64
    public let quota: UInt64?
}

/// For ops whose `data` is null.
public struct Nothing: Decodable, Sendable {
    public init() {}
    public init(from decoder: Decoder) throws {}
}
