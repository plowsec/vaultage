import Foundation

/// Short-lived secret (passphrase bytes, recovery key text, Secure Enclave output) in memory we
/// own and zero. Never copy it into a `Data` or `String`.
public final class SecretBytes: @unchecked Sendable {
    private let base: UnsafeMutableRawPointer
    private let capacity: Int
    public let count: Int

    public init(count: Int) {
        capacity = max(count, 1)
        base = .allocate(byteCount: capacity, alignment: 1)
        base.initializeMemory(as: UInt8.self, repeating: 0, count: capacity)
        self.count = count
    }

    /// UTF-8 bytes of `text`. (The String itself can't be wiped; callers drop it right away.)
    public convenience init(utf8 text: String) {
        var text = text
        self.init(count: text.utf8.count)
        text.withUTF8 { src in
            if let p = src.baseAddress, src.count > 0 { base.copyMemory(from: p, byteCount: src.count) }
        }
    }

    public convenience init(copying bytes: UnsafeRawBufferPointer) {
        self.init(count: bytes.count)
        if let p = bytes.baseAddress, bytes.count > 0 { base.copyMemory(from: p, byteCount: bytes.count) }
    }

    public var isEmpty: Bool { count == 0 }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    public func wipe() {
        memset_s(base, capacity, 0, capacity)
    }

    deinit {
        memset_s(base, capacity, 0, capacity)
        base.deallocate()
    }
}
