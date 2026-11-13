import AppKit
import CofferKit
import ImageIO
import UniformTypeIdentifiers

/// Grid thumbnails for images: decrypted off the main thread, downscaled at once, kept only in
/// memory (NSCache) and dropped whenever a vault locks or the app quits.
@MainActor
final class ThumbnailStore {
    static let shared = ThumbnailStore()

    nonisolated static let maxSourceBytes: UInt64 = 20 * 1024 * 1024
    nonisolated static let pixelSize = 256

    private let cache: NSCache<NSString, NSImage> = {
        let c = NSCache<NSString, NSImage>()
        c.countLimit = 600
        c.totalCostLimit = 120 * 1024 * 1024
        return c
    }()
    private var failed: Set<String> = []
    private var inflight: [String: Task<CGImage?, Never>] = [:]
    /// Bumped by `purge`; results from an older epoch are thrown away.
    private var epoch = 0
    private let limiter = Limiter(3)

    static var enabled: Bool { UserDefaults.standard.bool(forKey: Pref.showThumbnails) }

    nonisolated static func eligible(_ item: Item) -> Bool {
        guard !item.isDir, item.id != nil, item.size > 0, item.size <= maxSourceBytes else { return false }
        let t = FileIcon.type(for: item.name, isDir: false)
        return t.conforms(to: .image) && !t.conforms(to: .svg)
    }

    private func key(_ vault: String, _ item: Item) -> String { "\(vault)/\(item.id ?? "")/\(item.rev)" }

    func cached(vault: String, item: Item) -> NSImage? {
        cache.object(forKey: key(vault, item) as NSString)
    }

    func thumbnail(vault: String, item: Item) async -> NSImage? {
        guard Self.enabled, Self.eligible(item), let entry = item.id else { return nil }
        let k = key(vault, item)
        if let img = cache.object(forKey: k as NSString) { return img }
        if failed.contains(k) { return nil }
        if let t = inflight[k] { return await t.value.map(Self.image) }
        let started = epoch
        let limiter = limiter
        let task = Task<CGImage?, Never> {
            await limiter.acquire()
            defer { Task { await limiter.release() } }
            guard !Task.isCancelled, AppModel.shared.sessions[vault] != nil else { return nil }
            return await Self.decode(vault: vault, entry: entry)
        }
        inflight[k] = task
        let img = await task.value.map(Self.image)
        inflight[k] = nil
        guard epoch == started, AppModel.shared.sessions[vault] != nil else { return nil }
        if let img {
            cache.setObject(img, forKey: k as NSString, cost: Int(img.size.width * img.size.height * 4))
        } else if !Task.isCancelled {
            failed.insert(k)
        }
        return img
    }

    private static func image(_ cg: CGImage) -> NSImage {
        NSImage(cgImage: cg, size: NSSize(width: cg.width, height: cg.height))
    }

    /// Decrypt, decode a small bitmap, release the full buffer.
    private nonisolated static func decode(vault: String, entry: String) async -> CGImage? {
        guard let data = try? await CofferCore.shared.read(vault: vault, entry: entry) else { return nil }
        return await Task.detached(priority: .utility) { () -> CGImage? in
            guard let src = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary) else { return nil }
            let opts: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceShouldCacheImmediately: true,
                kCGImageSourceThumbnailMaxPixelSize: pixelSize,
            ]
            guard let thumb = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return nil }
            // Copy into a fresh bitmap so nothing can keep a reference to the decrypted buffer.
            guard let ctx = CGContext(data: nil, width: thumb.width, height: thumb.height, bitsPerComponent: 8, bytesPerRow: 0,
                                      space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
            else { return nil }
            ctx.draw(thumb, in: CGRect(x: 0, y: 0, width: thumb.width, height: thumb.height))
            return ctx.makeImage()
        }.value
    }

    func purge() {
        epoch += 1
        cache.removeAllObjects()
        failed.removeAll()
        for t in inflight.values { t.cancel() }
        inflight.removeAll()
    }
}

/// Counting semaphore for async tasks.
actor Limiter {
    private var free: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(_ n: Int) { free = n }

    func acquire() async {
        if free > 0 { free -= 1; return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty { free += 1 } else { waiters.removeFirst().resume() }
    }
}
