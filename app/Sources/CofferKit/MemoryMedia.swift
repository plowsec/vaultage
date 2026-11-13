import AVFoundation
import Foundation
import UniformTypeIdentifiers

/// Plays decrypted audio/video straight from memory: AVFoundation asks for byte ranges through a
/// custom URL scheme and gets them from `data`. Nothing touches disk.
public final class MemoryMediaLoader: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    public static let scheme = "coffer-mem"
    /// Larger files are not loaded for playback.
    public static let maxBytes: UInt64 = 500 * 1024 * 1024

    private var data: Data?
    private let contentType: String
    private let queue = DispatchQueue(label: "local.coffer.media-loader")
    private let lock = NSLock()
    public let asset: AVURLAsset

    /// `name` only supplies the extension (the type AVFoundation is told about).
    public init(data: Data, name: String) {
        self.data = data
        let ext = (name as NSString).pathExtension.lowercased()
        contentType = UTType(filenameExtension: ext)?.identifier ?? UTType.movie.identifier
        var comps = URLComponents()
        comps.scheme = Self.scheme
        comps.host = "media"
        comps.path = "/" + UUID().uuidString + (ext.isEmpty ? "" : "." + ext)
        asset = AVURLAsset(url: comps.url!)
        super.init()
        asset.resourceLoader.setDelegate(self, queue: queue)
    }

    public static func isPlayable(name: String) -> Bool {
        let ext = (name as NSString).pathExtension.lowercased()
        guard !ext.isEmpty, let t = UTType(filenameExtension: ext) else { return false }
        return t.conforms(to: .audiovisualContent)
    }

    /// Drop the buffer; pending and future requests fail.
    public func release() {
        lock.lock()
        data = nil
        lock.unlock()
        asset.cancelLoading()
    }

    private func buffer() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return data
    }

    public func resourceLoader(_ loader: AVAssetResourceLoader, shouldWaitForLoadingOfRequestedResource req: AVAssetResourceLoadingRequest) -> Bool {
        guard req.request.url?.scheme == Self.scheme, let data = buffer() else { return false }
        if let info = req.contentInformationRequest {
            info.contentType = contentType
            info.contentLength = Int64(data.count)
            info.isByteRangeAccessSupported = true
        }
        if let dr = req.dataRequest {
            let start = Int(dr.currentOffset != 0 ? dr.currentOffset : dr.requestedOffset)
            let end = dr.requestsAllDataToEndOfResource ? data.count : min(data.count, Int(dr.requestedOffset) + dr.requestedLength)
            guard start <= end, start <= data.count else {
                req.finishLoading(with: NSError(domain: NSURLErrorDomain, code: NSURLErrorBadServerResponse))
                return true
            }
            // Hand over in slices so a whole-file request doesn't duplicate the buffer at once.
            let step = 1 << 20
            var off = start
            while off < end {
                if req.isCancelled { return true }
                let n = min(step, end - off)
                dr.respond(with: data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + n)))
                off += n
            }
        }
        req.finishLoading()
        return true
    }
}
