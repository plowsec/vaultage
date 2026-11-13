import AVKit
import AppKit
import CofferKit
import PDFKit
import SwiftUI

struct PreviewPane: View {
    let session: VaultSession

    var body: some View {
        Group {
            switch session.preview {
            case .idle:
                idle
            case .loading(let item):
                VStack(spacing: 0) {
                    ProgressView("Decrypting…").controlSize(.small).frame(maxHeight: .infinity)
                    Divider()
                    MetadataView(item: item, session: session)
                }
            case .loaded(let item, let doc):
                VStack(spacing: 0) {
                    PreviewContentView(doc: doc).frame(maxHeight: .infinity)
                    Divider()
                    MetadataView(item: item, session: session)
                }
            case .metadataOnly(let item, let note):
                VStack(spacing: 0) {
                    BigIcon(item: item, note: note ?? "No preview for this kind of file.").frame(maxHeight: .infinity)
                    Divider()
                    MetadataView(item: item, session: session)
                }
            case .failed(let item, let message):
                VStack(spacing: 0) {
                    BigIcon(item: item, note: message, isError: true).frame(maxHeight: .infinity)
                    Divider()
                    MetadataView(item: item, session: session)
                }
            }
        }
        .animation(.smooth(duration: 0.2), value: session.preview.item?.path)
    }

    @ViewBuilder
    private var idle: some View {
        let sel = session.selectedItems
        if sel.count == 1, sel[0].isDir {
            VStack(spacing: 0) {
                BigIcon(item: sel[0], note: Fmt.count(sel[0].count, "file") + " · " + Fmt.bytes(sel[0].size)).frame(maxHeight: .infinity)
            }
        } else {
            ContentUnavailableView(
                sel.count > 1 ? "\(sel.count) Items Selected" : "No Selection",
                systemImage: sel.count > 1 ? "doc.on.doc" : "eye",
                description: Text(sel.count > 1 ? Fmt.bytes(sel.reduce(0) { $0 + $1.size }) + " in total" : "Select a file to preview it. Previews are decrypted in memory only."))
        }
    }
}

struct PreviewContentView: View {
    let doc: PreviewDoc

    var body: some View {
        switch doc.kind {
        case .image(let img):
            Image(nsImage: img)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .padding(12)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityLabel("Image preview")
        case .pdf(let pdf):
            PDFKitView(document: pdf)
        case .text(let text, let truncated):
            VStack(spacing: 0) {
                TextPreview(text: text)
                if truncated {
                    Text("Showing the first \(Fmt.bytes(UInt64(PreviewDoc.maxTextBytes))).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(6)
                }
            }
        case .media(let loader):
            MediaPlayerView(loader: loader)
                .accessibilityLabel("Media player")
        case .unsupported:
            EmptyView()
        }
    }
}

/// AVPlayerView over a resource-loader asset (bytes come from memory). Pauses and drops the
/// player when it leaves the screen.
struct MediaPlayerView: NSViewRepresentable {
    let loader: MemoryMediaLoader

    final class Coordinator {
        var loader: MemoryMediaLoader?
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> AVPlayerView {
        let v = AVPlayerView()
        v.controlsStyle = .inline
        v.showsFullScreenToggleButton = true
        v.allowsPictureInPicturePlayback = false
        v.updatesNowPlayingInfoCenter = false
        attach(v, context: context)
        return v
    }

    func updateNSView(_ v: AVPlayerView, context: Context) {
        if context.coordinator.loader !== loader { attach(v, context: context) }
    }

    private func attach(_ v: AVPlayerView, context: Context) {
        v.player?.pause()
        context.coordinator.loader = loader
        let player = AVPlayer(playerItem: AVPlayerItem(asset: loader.asset))
        player.allowsExternalPlayback = false
        player.preventsDisplaySleepDuringVideoPlayback = true
        v.player = player
    }

    static func dismantleNSView(_ v: AVPlayerView, coordinator: Coordinator) {
        v.player?.pause()
        v.player?.replaceCurrentItem(with: nil)
        v.player = nil
        coordinator.loader = nil
    }
}

struct BigIcon: View {
    let item: Item
    let note: String
    var isError = false

    var body: some View {
        VStack(spacing: 12) {
            Image(nsImage: FileIcon.image(for: item.name, isDir: item.isDir))
                .resizable()
                .frame(width: 96, height: 96)
            Text(item.name).font(.headline).multilineTextAlignment(.center).lineLimit(3)
            Label(note, systemImage: isError ? "exclamationmark.triangle.fill" : "info.circle")
                .labelStyle(.titleOnly)
                .font(.callout)
                .foregroundStyle(isError ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                .multilineTextAlignment(.center)
        }
        .padding(20)
        .frame(maxWidth: .infinity)
    }
}

struct MetadataView: View {
    let item: Item
    let session: VaultSession

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(item.name).font(.headline).lineLimit(2).textSelection(.enabled)
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                row("Kind", FileIcon.kindDescription(for: item.name, isDir: item.isDir))
                row("Size", Fmt.bytes(item.size) + (item.size >= 1000 ? " (\(item.size.formatted()) bytes)" : ""))
                row("Modified", Fmt.date(item.mtime))
                if !item.device.isEmpty { row("Last changed on", item.device) }
                if item.rev > 0 { row("Revision", "\(item.rev)") }
                if session.synced { row("Sync", item.pending ? "Waiting to upload" : "Synced") }
                if !VaultPath.parent(item.path).isEmpty { row("Folder", VaultPath.parent(item.path)) }
            }
            .font(.callout)
            HStack {
                Button("Versions…") { AppModel.shared.sheet = .versions(session.vaultID, item) }
                Button("Export…") { Task { await session.export([item.path], remove: false) } }
            }
            .controlSize(.small)
            .padding(.top, 2)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(v).textSelection(.enabled).lineLimit(2)
        }
    }
}

struct PDFKitView: NSViewRepresentable {
    let document: PDFDocument

    func makeNSView(context: Context) -> PDFView {
        let v = PDFView()
        v.autoScales = true
        v.displayMode = .singlePageContinuous
        v.backgroundColor = .clear
        v.document = document
        return v
    }

    func updateNSView(_ v: PDFView, context: Context) {
        if v.document !== document { v.document = document }
    }

    static func dismantleNSView(_ v: PDFView, coordinator: ()) {
        v.document = nil
    }
}

/// Read-only, selectable monospaced text (NSTextView handles large text far better than Text).
struct TextPreview: NSViewRepresentable {
    let text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        let tv = scroll.documentView as! NSTextView
        tv.isEditable = false
        tv.isSelectable = true
        tv.isRichText = false
        tv.usesFindBar = true
        tv.isIncrementalSearchingEnabled = true
        tv.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        tv.textContainerInset = NSSize(width: 10, height: 10)
        tv.drawsBackground = false
        tv.isAutomaticSpellingCorrectionEnabled = false
        tv.isContinuousSpellCheckingEnabled = false
        scroll.drawsBackground = false
        tv.string = text
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let tv = scroll.documentView as! NSTextView
        if tv.string != text { tv.string = text }
    }
}
