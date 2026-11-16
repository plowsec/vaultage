import AppKit
import CofferKit
import Darwin
import Observation

/// "Open in External App": a decrypted temporary copy, watched and re-imported on change.
/// Copies live in temp/Coffer-<pid>-<uuid>/<entry>/<name> (0700) and are removed when the vault
/// locks or the app quits.
@MainActor
@Observable
final class ExternalEditor {
    static let shared = ExternalEditor()

    struct Session {
        let vaultID: String
        let entry: String
        let url: URL
        /// Vault folder the file is re-imported into (import keys on file name).
        let parentDir: String
        var mtime: Date
        var size: UInt64
        var saving = false
    }

    private(set) var sessions: [String: Session] = [:]   // key: vaultID/entry
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private lazy var root: URL = {
        FileManager.default.temporaryDirectory.appendingPathComponent("Coffer-\(getpid())-\(UUID().uuidString)", isDirectory: true)
    }()

    private func key(_ vault: String, _ entry: String) -> String { vault + "/" + entry }

    func isEditing(vault: String, entry: String?) -> Bool {
        guard let entry else { return false }
        return sessions[key(vault, entry)] != nil
    }

    func entries(in vault: String) -> Set<String> {
        Set(sessions.values.filter { $0.vaultID == vault }.map(\.entry))
    }

    // MARK: Open

    /// `app`: open with this application instead of the default one.
    func open(_ item: Item, in session: VaultSession, with app: URL? = nil) async {
        guard let entry = item.id else { return }
        if let s = sessions[key(session.vaultID, entry)] {
            launch(s.url, with: app, session: session)
            return
        }
        if !UserDefaults.standard.bool(forKey: Pref.externalEditWarned) {
            let ok = await Alerts.confirm(
                "Open “\(item.name)” in another app?",
                "To let another app edit it, Vaultage writes a decrypted copy to a private temporary folder. It stays on disk, unencrypted, until you stop editing, lock the vault or quit Vaultage. Saved changes are encrypted back into the vault as a new version.",
                action: "Open", destructive: false)
            guard ok else { return }
            UserDefaults.standard.set(true, forKey: Pref.externalEditWarned)
        }
        do {
            let data = try await CofferCore.shared.read(vault: session.vaultID, entry: entry)
            let dir = root.appendingPathComponent(entry, isDirectory: true)
            let fm = FileManager.default
            try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let url = dir.appendingPathComponent(item.name)
            guard fm.createFile(atPath: url.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
                throw CofferError(code: "io", message: "could not write the temporary copy")
            }
            let (m, s) = stat(url)
            sessions[key(session.vaultID, entry)] = Session(vaultID: session.vaultID, entry: entry, url: url, parentDir: VaultPath.parent(item.path), mtime: m, size: s)
            startTimer()
            launch(url, with: app, session: session)
        } catch {
            session.report(error)
        }
    }

    private func launch(_ url: URL, with app: URL?, session: VaultSession) {
        guard let app else {
            NSWorkspace.shared.open(url)
            return
        }
        let cfg = NSWorkspace.OpenConfiguration()
        cfg.activates = true
        NSWorkspace.shared.open([url], withApplicationAt: app, configuration: cfg) { _, error in
            guard let error else { return }
            Task { @MainActor in session.report(error) }
        }
    }

    // MARK: Watch

    private func stat(_ url: URL) -> (Date, UInt64) {
        let a = try? FileManager.default.attributesOfItem(atPath: url.path)
        return ((a?[.modificationDate] as? Date) ?? .distantPast, (a?[.size] as? NSNumber)?.uint64Value ?? 0)
    }

    private func startTimer() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in
            MainActor.assumeIsolated { ExternalEditor.shared.checkAll() }
        }
    }

    private func checkAll() {
        for (k, s) in sessions where !s.saving {
            let (m, size) = stat(s.url)
            if m != s.mtime || size != s.size {
                Task { await save(k, mtime: m, size: size) }
            }
        }
    }

    /// Re-import a changed copy as a new revision.
    private func save(_ k: String, mtime: Date, size: UInt64) async {
        guard var s = sessions[k], FileManager.default.fileExists(atPath: s.url.path) else { return }
        s.saving = true
        sessions[k] = s
        defer { if sessions[k] != nil { sessions[k]?.saving = false } }
        do {
            let _: ImportReport = try await CofferCore.shared.call(["op": "import", "id": s.vaultID, "sources": [s.url.path], "dest": s.parentDir])
            sessions[k]?.mtime = mtime
            sessions[k]?.size = size
            await AppModel.shared.sessions[s.vaultID]?.reload()
        } catch {
            AppModel.shared.sessions[s.vaultID]?.report(error)
        }
    }

    private func finish(_ k: String) async {
        guard let s = sessions[k] else { return }
        let (m, size) = stat(s.url)
        if FileManager.default.fileExists(atPath: s.url.path), m != s.mtime || size != s.size {
            await save(k, mtime: m, size: size)
        }
        try? FileManager.default.removeItem(at: s.url.deletingLastPathComponent())
        sessions[k] = nil
        if sessions.isEmpty {
            timer?.invalidate()
            timer = nil
        }
    }

    // MARK: Stop

    func stop(vault: String, entry: String) async {
        await finish(key(vault, entry))
    }

    func stopAll(vaultID: String? = nil) async {
        for k in sessions.keys where vaultID == nil || sessions[k]?.vaultID == vaultID {
            await finish(k)
        }
    }

    func removeSessionRoot() {
        try? FileManager.default.removeItem(at: root)
    }

    /// Remove copies left by an earlier Coffer process that didn't exit cleanly.
    func cleanStale() {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory
        guard let names = try? fm.contentsOfDirectory(atPath: tmp.path) else { return }
        for n in names where n.hasPrefix("Coffer-") {
            let parts = n.split(separator: "-")
            guard parts.count >= 3, let pid = Int32(parts[1]) else { continue }
            if pid != getpid(), kill(pid, 0) != 0, errno == ESRCH {
                try? fm.removeItem(at: tmp.appendingPathComponent(n))
            }
        }
    }
}

/// Applications that can open a file type, for "Open With ▸". Default app first.
@MainActor
enum OpenWith {
    struct App: Identifiable {
        let url: URL
        let name: String
        let icon: NSImage
        let isDefault: Bool
        var id: URL { url }
    }

    private static var cache: [String: [App]] = [:]

    static func apps(for name: String) -> [App] {
        let type = FileIcon.type(for: name, isDir: false)
        if let hit = cache[type.identifier] { return hit }
        let ws = NSWorkspace.shared
        let def = ws.urlForApplication(toOpen: type)
        var seen = Set<String>()
        var out: [App] = []
        for url in ([def].compactMap { $0 } + ws.urlsForApplications(toOpen: type)) {
            let bundleID = Bundle(url: url)?.bundleIdentifier ?? url.path
            // Skip duplicates (several copies of one app) and Coffer itself.
            guard seen.insert(bundleID).inserted, bundleID != Bundle.main.bundleIdentifier else { continue }
            let icon = ws.icon(forFile: url.path)
            icon.size = NSSize(width: 16, height: 16)
            var name = FileManager.default.displayName(atPath: url.path)
            if name.hasSuffix(".app") { name = String(name.dropLast(4)) }
            out.append(App(url: url, name: name, icon: icon, isDefault: url == def))
        }
        let rest = out.dropFirst().sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        out = Array(out.prefix(1)) + rest
        cache[type.identifier] = out
        return out
    }

    /// NSOpenPanel on /Applications.
    static func chooseOther(_ item: Item, in session: VaultSession) {
        let panel = NSOpenPanel()
        panel.directoryURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
        panel.allowedContentTypes = [.application]
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Open"
        panel.message = "Choose an application to open “\(item.name)”."
        let handle: (NSApplication.ModalResponse) -> Void = { r in
            guard r == .OK, let app = panel.url else { return }
            Task { await ExternalEditor.shared.open(item, in: session, with: app) }
        }
        if let w = NSApp.keyWindow { panel.beginSheetModal(for: w, completionHandler: handle) } else { handle(panel.runModal()) }
    }
}
