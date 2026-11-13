import AppKit
import CofferKit
import Observation
import PDFKit
import SwiftUI
import UniformTypeIdentifiers

enum SortKey: String {
    case name, size, modified, status
}

struct SortSpec: Equatable {
    var key: SortKey = .name
    var ascending = true
}

struct Banner: Identifiable {
    enum Style { case success, info, warning }
    let id = UUID()
    var style: Style
    var text: String
    var actionTitle: String?
    var action: (() -> Void)?
    /// Success/info banners go away on their own; warnings stay until closed.
    var sticky: Bool { style == .warning }
}

/// In-memory preview of a decrypted file. Image/PDF keep a reference to the core's buffer (wiped
/// when they're released); text is copied out and the buffer released right away.
struct PreviewDoc {
    enum Kind {
        case image(NSImage)
        case pdf(PDFDocument)
        case text(String, truncated: Bool)
        /// Audio/video played from the decrypted buffer in memory.
        case media(MemoryMediaLoader)
        case unsupported
    }
    let kind: Kind

    static let maxBytes: UInt64 = 200 * 1024 * 1024
    static let maxTextBytes = 1 * 1024 * 1024

    static func isTextual(_ t: UTType) -> Bool {
        [.text, .sourceCode, .json, .xml, .propertyList, .yaml, .script, .shellScript, .commaSeparatedText].contains { t.conforms(to: $0) }
    }

    /// Whether decrypting is worth it for a preview.
    static func canPreview(name: String) -> Bool {
        let t = FileIcon.type(for: name, isDir: false)
        if t.conforms(to: .image) || t.conforms(to: .pdf) || isTextual(t) || MemoryMediaLoader.isPlayable(name: name) { return true }
        // Unknown extension: sniff the content.
        return t.isDynamic || t == .data
    }

    /// Size limit for previewing this kind of file.
    static func limit(name: String) -> UInt64 {
        MemoryMediaLoader.isPlayable(name: name) ? MemoryMediaLoader.maxBytes : maxBytes
    }

    static func make(name: String, data: Data) -> PreviewDoc {
        let t = FileIcon.type(for: name, isDir: false)
        if MemoryMediaLoader.isPlayable(name: name) { return PreviewDoc(kind: .media(MemoryMediaLoader(data: data, name: name))) }
        if t.conforms(to: .pdf), let doc = PDFDocument(data: data) { return PreviewDoc(kind: .pdf(doc)) }
        if t.conforms(to: .image), let img = NSImage(data: data), img.isValid { return PreviewDoc(kind: .image(img)) }
        if isTextual(t) || looksLikeText(data) {
            let truncated = data.count > maxTextBytes
            let text = String(decoding: data.prefix(maxTextBytes), as: UTF8.self)
            return PreviewDoc(kind: .text(text, truncated: truncated))
        }
        return PreviewDoc(kind: .unsupported)
    }

    private static func looksLikeText(_ data: Data) -> Bool {
        let head = data.prefix(4096)
        if head.isEmpty { return true }
        if head.contains(0) { return false }
        return String(data: head, encoding: .utf8) != nil || String(data: head.dropLast(3), encoding: .utf8) != nil
    }
}

enum PreviewState {
    case idle
    case loading(Item)
    case loaded(Item, PreviewDoc)
    case metadataOnly(Item, String?)
    case failed(Item, String)

    var item: Item? {
        switch self {
        case .idle: return nil
        case .loading(let i), .loaded(let i, _), .metadataOnly(let i, _), .failed(let i, _): return i
        }
    }
}

@MainActor
@Observable
final class VaultSession {
    let vaultID: String
    @ObservationIgnored weak var app: AppModel?
    @ObservationIgnored let core = CofferCore.shared

    var path = ""
    var backStack: [String] = []
    var forwardStack: [String] = []
    var items: [Item] = []
    var loadedOnce = false
    var searchText = ""
    var searchResults: [Item]?
    var selection: Set<String> = []
    var sort = SortSpec()
    var showPreview = false
    var preview: PreviewState = .idle
    var status: VaultStatus?
    var busy = 0
    var banner: Banner?
    var integrityIssue: String?
    /// Path whose name the list view should start editing inline.
    var renameRequest: String?
    var trash: [TrashItem] = []
    var trashVisible = false
    /// Server usage (synced vaults), refreshed when Vault Settings opens.
    var usage: UsageInfo?

    @ObservationIgnored private var generation: UInt64?
    @ObservationIgnored private var previewTask: Task<Void, Never>?
    @ObservationIgnored private var searchTask: Task<Void, Never>?
    @ObservationIgnored private var bannerTask: Task<Void, Never>?
    @ObservationIgnored private var closed = false

    init(vaultID: String, app: AppModel) {
        self.vaultID = vaultID
        self.app = app
    }

    var vault: VaultInfo? { app?.vault(vaultID) }
    var name: String { vault?.name ?? "Vault" }
    var synced: Bool { vault?.synced ?? false }

    func start() {
        Task { await reload() }
    }

    /// Drop everything derived from decrypted data.
    func tearDown() {
        closed = true
        previewTask?.cancel()
        searchTask?.cancel()
        bannerTask?.cancel()
        releaseMedia()
        preview = .idle
        ThumbnailStore.shared.purge()
        items = []
        searchResults = nil
        trash = []
        selection = []
    }

    // MARK: Listing

    var isSearching: Bool { !searchText.trimmingCharacters(in: .whitespaces).isEmpty }

    var displayed: [Item] {
        let base = isSearching ? (searchResults ?? []) : items
        return base.sorted(by: comparator)
    }

    private func comparator(_ a: Item, _ b: Item) -> Bool {
        if a.isDir != b.isDir { return a.isDir }
        let asc = sort.ascending
        func byName() -> Bool {
            let r = a.name.localizedStandardCompare(b.name)
            return asc ? r == .orderedAscending : r == .orderedDescending
        }
        switch sort.key {
        case .name: return byName()
        case .size: return a.size == b.size ? byName() : (asc ? a.size < b.size : a.size > b.size)
        case .modified: return a.mtime == b.mtime ? byName() : (asc ? a.mtime < b.mtime : a.mtime > b.mtime)
        case .status: return a.pending == b.pending ? byName() : (asc ? a.pending && !b.pending : !a.pending && b.pending)
        }
    }

    var selectedItems: [Item] {
        displayed.filter { selection.contains($0.path) }
    }

    var singleSelectedFile: Item? {
        let s = selectedItems
        return s.count == 1 && !s[0].isDir ? s[0] : nil
    }

    func reload() async {
        guard !closed else { return }
        do {
            let r: ListResult = try await core.call(["op": "list", "id": vaultID, "path": path])
            guard !closed else { return }
            items = r.items
            generation = r.generation
            loadedOnce = true
            selection = selection.filter { p in r.items.contains { $0.path == p } || (searchResults?.contains { $0.path == p } ?? false) }
            if isSearching { await runSearch() }
            // Always: status.summary.trashed still counts purged entries, so the Trash count comes from here.
            await loadTrash()
            refreshPreview() // the selected file may have a new revision (restore, sync)
        } catch let e as CofferError where e.code == "locked" {
            await app?.refreshVaults()
        } catch {
            report(error)
        }
    }

    func poll() async {
        guard !closed else { return }
        do {
            let st: VaultStatus = try await core.call(["op": "status", "id": vaultID])
            guard !closed else { return }
            if st != status { status = st }
            if let err = st.sync.error, err.hasPrefix("integrity") { integrityIssue = err }
            if let g = generation, g != st.generation { await reload() }
        } catch let e as CofferError where e.code == "locked" {
            await app?.refreshVaults()
        } catch {}
    }

    // MARK: Navigation

    func navigate(to newPath: String) {
        guard newPath != path || isSearching else { return }
        backStack.append(path)
        forwardStack.removeAll()
        go(newPath)
    }

    private func go(_ p: String) {
        path = p
        searchText = ""
        searchResults = nil
        setSelection([])
        Task { await reload() }
    }

    var canGoBack: Bool { !backStack.isEmpty }
    var canGoForward: Bool { !forwardStack.isEmpty }
    var canGoUp: Bool { !path.isEmpty }

    func goBack() {
        guard let p = backStack.popLast() else { return }
        forwardStack.append(path)
        go(p)
    }

    func goForward() {
        guard let p = forwardStack.popLast() else { return }
        backStack.append(path)
        go(p)
    }

    func goUp() {
        guard canGoUp else { return }
        let child = path
        navigate(to: VaultPath.parent(path))
        selection = [child]
    }

    /// Double-click / ⌘↓: enter folders, preview files.
    func open(_ item: Item) {
        if item.isDir {
            navigate(to: item.path)
        } else {
            setSelection([item.path])
            showPreview = true
            refreshPreview()
        }
    }

    // MARK: Search

    func searchChanged() {
        searchTask?.cancel()
        guard isSearching else {
            searchResults = nil
            return
        }
        searchTask = Task {
            try? await Task.sleep(for: .milliseconds(180))
            guard !Task.isCancelled else { return }
            await runSearch()
        }
    }

    private func runSearch() async {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return }
        if let r: ItemsResult = try? await core.call(["op": "search", "id": vaultID, "query": q]), q == searchText.trimmingCharacters(in: .whitespaces) {
            searchResults = r.items
        }
    }

    // MARK: Selection & preview

    func setSelection(_ s: Set<String>) {
        guard s != selection else { return }
        selection = s
        refreshPreview()
    }

    func togglePreview() {
        showPreview.toggle()
        refreshPreview()
    }

    /// Stop playback and drop the in-memory media buffer, if any.
    private func releaseMedia() {
        if case .loaded(_, let doc) = preview, case .media(let m) = doc.kind { m.release() }
    }

    func refreshPreview(rev: UInt64? = nil) {
        previewTask?.cancel()
        guard showPreview, let item = singleSelectedFile, let entry = item.id else {
            releaseMedia()
            preview = .idle
            return
        }
        if case .loaded(let cur, _) = preview, cur == item { return }
        releaseMedia()
        let limit = PreviewDoc.limit(name: item.name)
        guard item.size <= limit else {
            preview = .metadataOnly(item, "Too large to preview (over \(Fmt.bytes(limit))).")
            return
        }
        guard PreviewDoc.canPreview(name: item.name) else {
            preview = .metadataOnly(item, nil)
            return
        }
        preview = .loading(item)
        previewTask = Task {
            do {
                let data = try await core.read(vault: vaultID, entry: entry)
                guard !Task.isCancelled, !closed else { return }
                let doc = PreviewDoc.make(name: item.name, data: data)
                if case .unsupported = doc.kind {
                    preview = .metadataOnly(item, nil)
                } else {
                    preview = .loaded(item, doc)
                }
            } catch {
                guard !Task.isCancelled else { return }
                if let ce = error as? CofferError, ce.isIntegrity { integrityIssue = ce.errorDescription }
                preview = .failed(item, error.localizedDescription)
            }
        }
    }

    // MARK: Errors & banners

    func report(_ error: Error) {
        if let ce = error as? CofferError, ce.isIntegrity { integrityIssue = ce.errorDescription }
        Task { await Alerts.error(error) }
    }

    func show(_ b: Banner) {
        bannerTask?.cancel()
        withAnimation(.snappy) { banner = b }
        guard !b.sticky else { return }
        let id = b.id
        bannerTask = Task {
            try? await Task.sleep(for: .seconds(8))
            guard !Task.isCancelled, banner?.id == id else { return }
            withAnimation(.snappy) { banner = nil }
        }
    }

    // MARK: Import

    func addFiles() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Add to Vault"
        panel.message = "Choose files or folders to encrypt into “\(name)”."
        let move = NSButton(checkboxWithTitle: "Move into vault (delete originals after verifying each encrypted copy)", target: nil, action: nil)
        move.state = Pref.defaultImportMode == .move ? .on : .off
        let box = NSView(frame: NSRect(x: 0, y: 0, width: 480, height: 36))
        move.frame = NSRect(x: 16, y: 8, width: 460, height: 20)
        box.addSubview(move)
        panel.accessoryView = box
        panel.isAccessoryViewDisclosed = true
        let dest = isSearching ? "" : path
        let handle: (NSApplication.ModalResponse) -> Void = { [weak self] r in
            guard r == .OK, let self else { return }
            let urls = panel.urls
            let mode: ImportMode = move.state == .on ? .move : .copy
            Task { await self.importURLs(urls, into: dest, mode: mode, confirmed: true) }
        }
        if let w = NSApp.keyWindow {
            panel.beginSheetModal(for: w, completionHandler: handle)
        } else {
            handle(panel.runModal())
        }
    }

    /// Drops copy in by default; ⌥ (or the "move" setting) moves.
    func handleDrop(_ urls: [URL], into dest: String? = nil) {
        guard !urls.isEmpty else { return }
        var mode = Pref.defaultImportMode
        if NSEvent.modifierFlags.contains(.option) { mode = mode == .copy ? .move : .copy }
        Task { await importURLs(urls, into: dest ?? (isSearching ? "" : path), mode: mode) }
    }

    func importURLs(_ urls: [URL], into dest: String, mode: ImportMode, confirmed: Bool = false) async {
        if mode == .move, !confirmed {
            let n = urls.count
            let ok = await Alerts.confirm(
                "Move \(n == 1 ? "“\(urls[0].lastPathComponent)”" : "\(n) items") into “\(name)”?",
                "Each original is deleted from its current location after its encrypted copy has been verified.",
                action: "Move into Vault", suppressionKey: Pref.skipMoveInConfirm)
            guard ok else { return }
        }
        busy += 1
        defer { busy -= 1 }
        do {
            let rep: ImportReport = try await core.call([
                "op": "import", "id": vaultID, "sources": urls.map { $0.path(percentEncoded: false) }, "dest": dest,
                "delete_source": mode == .move,
            ])
            await reload()
            var text = rep.files == 0 && rep.skipped.isEmpty
                ? "Nothing to add."
                : (mode == .move ? "Moved " : "Encrypted ") + Fmt.count(rep.files, "file") + " (\(Fmt.bytes(rep.bytes)))"
            if mode == .move, rep.sourcesDeleted > 0 { text += " · originals removed" }
            if rep.skipped.isEmpty {
                show(Banner(style: .success, text: text))
            } else {
                let vid = vaultID
                show(Banner(style: .warning, text: text + " · \(rep.skipped.count) skipped", actionTitle: "Details…") {
                    AppModel.shared.sheet = .importReport(vid, rep, moved: mode == .move)
                })
            }
        } catch {
            report(error)
        }
    }

    // MARK: Folder / rename / move / delete

    func newFolder() async {
        guard !isSearching else { return }
        var name = "untitled folder"
        var n = 2
        while items.contains(where: { $0.name == name }) {
            name = "untitled folder \(n)"
            n += 1
        }
        let p = VaultPath.join(path, name)
        do {
            try await core.perform(["op": "mkdir", "id": vaultID, "path": p])
            await reload()
            setSelection([p])
            renameRequest = p
        } catch {
            report(error)
        }
    }

    @discardableResult
    func rename(_ item: Item, to newName: String) async -> Bool {
        let newName = newName.trimmingCharacters(in: .whitespaces)
        guard newName != item.name else { return true }
        if let problem = VaultPath.problem(with: newName) {
            await Alerts.error(CofferError(code: "invalid", message: problem), title: "Can’t rename “\(item.name)”")
            return false
        }
        let to = VaultPath.join(VaultPath.parent(item.path), newName)
        do {
            let _: MovedResult = try await core.call(["op": "rename", "id": vaultID, "from": item.path, "to": to])
            await reload()
            selection = [to]
            return true
        } catch {
            await Alerts.error(error, title: "Can’t rename “\(item.name)”")
            return false
        }
    }

    func move(_ paths: [String], to dir: String) async {
        var moved: [String] = []
        for p in paths {
            let to = VaultPath.join(dir, VaultPath.name(p))
            guard to != p, !(dir == p || dir.hasPrefix(p + "/")) else { continue }
            do {
                let _: MovedResult = try await core.call(["op": "rename", "id": vaultID, "from": p, "to": to])
                moved.append(to)
            } catch {
                report(error)
                break
            }
        }
        await reload()
        if !moved.isEmpty {
            show(Banner(style: .success, text: "Moved \(Fmt.count(UInt64(moved.count), "item")) to “\(dir.isEmpty ? name : VaultPath.name(dir))”"))
        }
    }

    func delete(_ paths: [String]) async {
        guard !paths.isEmpty else { return }
        let what = paths.count == 1 ? "“\(VaultPath.name(paths[0]))”" : "\(paths.count) items"
        let ok = await Alerts.confirm(
            "Delete \(what)?",
            "Deleted files go to this vault’s Trash" + (synced ? " on all your devices" : "") + ". You can restore them from the Trash or from version history.",
            action: "Delete")
        guard ok else { return }
        do {
            let r: DeletedResult = try await core.call(["op": "delete", "id": vaultID, "paths": paths])
            setSelection([])
            await reload()
            show(Banner(style: .info, text: "Moved \(Fmt.count(UInt64(r.deleted), "item")) to the vault’s Trash", actionTitle: "Show Trash") { [weak self] in
                guard let self else { return }
                AppModel.shared.selection = .trash(self.vaultID)
            })
        } catch {
            report(error)
        }
    }

    // MARK: Export

    func export(_ paths: [String], remove: Bool) async {
        guard !paths.isEmpty else { return }
        let what = paths.count == 1 ? "“\(VaultPath.name(paths[0]))”" : "\(paths.count) items"
        if remove {
            let ok = await Alerts.confirm(
                "Move \(what) out of “\(name)”?",
                "They will be decrypted into the folder you choose and removed from the vault. The copies on disk are NOT encrypted. Until the vault’s Trash history is gone, they can still be restored here.",
                action: "Choose Destination…")
            guard ok else { return }
        }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = remove ? "Move Out" : "Export"
        panel.message = "Decrypted copies of \(what) will be saved here, unencrypted."
        let r: NSApplication.ModalResponse
        if let w = NSApp.keyWindow {
            r = await withCheckedContinuation { cont in panel.beginSheetModal(for: w) { cont.resume(returning: $0) } }
        } else {
            r = panel.runModal()
        }
        guard r == .OK, let dest = panel.url else { return }
        busy += 1
        defer { busy -= 1 }
        do {
            let res: WrittenResult = try await core.call(["op": "export", "id": vaultID, "paths": paths, "dest": dest.path(percentEncoded: false), "remove": remove])
            if remove {
                setSelection([])
                await reload()
            }
            let urls = res.written.map { URL(fileURLWithPath: $0) }
            show(Banner(style: .success, text: "\(remove ? "Moved" : "Exported") \(what) to “\(dest.lastPathComponent)”", actionTitle: "Reveal in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting(urls)
            })
        } catch {
            report(error)
        }
    }

    // MARK: Versions & trash

    func restore(entry: String, rev: UInt64?) async -> String? {
        var req: [String: Any] = ["op": "restore", "id": vaultID, "entry": entry]
        if let rev { req["rev"] = rev }
        do {
            let r: PathResult = try await core.call(req)
            await reload()
            return r.path
        } catch {
            report(error)
            return nil
        }
    }

    /// Where a permanent erase takes effect, for confirmations.
    var eraseScope: String {
        synced
            ? "on this Mac, on the sync server and on all your other devices"
            : "on this Mac. This vault isn’t synced, so no other copy exists"
    }

    /// Permanently erase trashed entries (all versions). Confirms first.
    @discardableResult
    func purge(_ items: [TrashItem]) async -> Bool {
        guard !items.isEmpty else { return false }
        let size = items.reduce(UInt64(0)) { $0 + $1.size }
        let what = items.count == 1 ? "“\(VaultPath.name(items[0].path))”" : Fmt.count(UInt64(items.count), "item")
        let ok = await Alerts.confirm(
            "Delete \(what) permanently?",
            "\(items.count == 1 ? "It" : "They") (\(Fmt.bytes(size)), with every saved version) will be erased \(eraseScope)." + (synced ? " If another device changed a file in the meantime, that change wins and the file is kept." : "") + "\n\nThis can’t be undone.",
            action: "Delete Permanently")
        guard ok else { return false }
        do {
            let r: PurgedResult = try await core.call(["op": "purge", "id": vaultID, "entries": items.map(\.id)])
            await loadTrash()
            await poll()
            show(Banner(style: .success, text: "Permanently deleted \(Fmt.count(UInt64(r.purged), "item"))"))
            return true
        } catch {
            report(error)
            return false
        }
    }

    func emptyTrash() async {
        await loadTrash()
        guard !trash.isEmpty else { return }
        let size = trash.reduce(UInt64(0)) { $0 + $1.size }
        let ok = await Alerts.confirm(
            "Empty the Trash of “\(name)”?",
            "\(Fmt.count(UInt64(trash.count), "item")) (\(Fmt.bytes(size))), with every saved version, will be erased \(eraseScope)." + (synced ? " If another device changed a file in the meantime, that change wins and the file is kept." : "") + "\n\nThis can’t be undone.",
            action: "Empty Trash")
        guard ok else { return }
        do {
            let r: PurgedResult = try await core.call(["op": "empty_trash", "id": vaultID])
            await loadTrash()
            await poll()
            show(Banner(style: .success, text: r.purged == 0 ? "Nothing was erased" : "Permanently deleted \(Fmt.count(UInt64(r.purged), "item"))"))
        } catch {
            report(error)
        }
    }

    /// Keep only the current version of a file. Confirms first.
    func pruneVersions(entry: String, name fileName: String, older: Int) async -> Bool {
        let ok = await Alerts.confirm(
            "Delete \(Fmt.count(UInt64(older), "older version")) of “\(fileName)”?",
            "Only the current version is kept. The older versions are erased \(eraseScope).\n\nThis can’t be undone.",
            action: "Delete Older Versions")
        guard ok else { return false }
        do {
            try await core.perform(["op": "prune_versions", "id": vaultID, "entry": entry])
            await reload()
            return true
        } catch {
            report(error)
            return false
        }
    }

    func refreshUsage() async {
        guard synced else { usage = nil; return }
        if let u: UsageInfo = try? await core.call(["op": "usage", "id": vaultID]) { usage = u }
    }

    func loadTrash() async {
        if let t: [TrashItem] = try? await core.call(["op": "trash", "id": vaultID]) {
            trash = t
        }
    }

    func dismissConflicts() async {
        try? await core.perform(["op": "dismiss_conflicts", "id": vaultID])
        await poll()
    }

    func syncNow() {
        Task { try? await core.perform(["op": "sync", "id": vaultID]) }
    }
}
