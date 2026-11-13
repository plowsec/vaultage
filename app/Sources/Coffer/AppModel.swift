import AppKit
import CofferKit
import LocalAuthentication
import Observation
import SwiftUI

enum SidebarItem: Hashable {
    case vault(String)
    case trash(String)

    var vaultID: String {
        switch self {
        case .vault(let id), .trash(let id): return id
        }
    }
}

enum AppSheet: Identifiable {
    case newVault
    case joinVault
    case vaultSettings(String)
    case versions(String, Item)
    case rename(String, Item)
    case newFolder(String)
    case moveTo(String, [String])
    case importReport(String, ImportReport, moved: Bool)
    case enableTouchID(String)
    case vaultTask(String, VaultTask)

    var id: String {
        switch self {
        case .newVault: return "new"
        case .joinVault: return "join"
        case .vaultSettings(let v): return "settings-\(v)"
        case .versions(let v, let i): return "versions-\(v)-\(i.path)"
        case .rename(let v, let i): return "rename-\(v)-\(i.path)"
        case .newFolder(let v): return "mkdir-\(v)"
        case .moveTo(let v, let p): return "move-\(v)-\(p.joined(separator: "|"))"
        case .importReport(let v, _, _): return "report-\(v)"
        case .enableTouchID(let v): return "touchid-\(v)"
        case .vaultTask(let v, let t): return "task-\(t.rawValue)-\(v)"
        }
    }
}

@MainActor
@Observable
final class AppModel {
    static let shared = AppModel()

    let core = CofferCore.shared
    var posture = Posture()
    var device: DeviceInfo?
    var vaults: [VaultInfo] = []
    var sessions: [String: VaultSession] = [:]
    var selection: SidebarItem?
    var sheet: AppSheet?
    var loaded = false
    /// Vault whose Touch ID prompt should fire once (set only by a user selection).
    var pendingTouchIDPrompt: String?
    let seAvailable = SecureEnclaveSlot.isAvailable
    let biometry = SecureEnclaveSlot.biometryAvailable
    /// Bumped to ask the toolbar search field to take focus (⌘F).
    var focusSearchToken = 0
    /// Vault whose key-rotation sheet is open (hides the "unfinished rotation" banner meanwhile).
    var rotationSheetVault: String?

    @ObservationIgnored private var lastActivity = Date()
    @ObservationIgnored private var pollTask: Task<Void, Never>?
    @ObservationIgnored private var monitors: [Any] = []
    @ObservationIgnored private var observers: [NSObjectProtocol] = []
    @ObservationIgnored private var tick = 0
    @ObservationIgnored private var seLoadable: [String: Bool] = [:]
    @ObservationIgnored private(set) var terminating = false

    // MARK: Startup

    func start(posture: Posture) {
        self.posture = posture
        ExternalEditor.shared.cleanStale()
        Task {
            device = try? await core.call(["op": "device"])
            await refreshVaults()
            if selection == nil, let first = sortedVaults.first {
                selection = .vault(first.id)
            }
            loaded = true
        }
        startPolling()
        startIdleMonitor()
        startSleepObservers()
        WindowProtector.shared.start()
    }

    var sortedVaults: [VaultInfo] {
        vaults.filter(\.synced).sortedByName() + vaults.filter { !$0.synced }.sortedByName()
    }

    func vault(_ id: String) -> VaultInfo? { vaults.first { $0.id == id } }

    var selectedVault: VaultInfo? { selection.flatMap { vault($0.vaultID) } }

    /// Session of the vault shown in the browser (not the trash view).
    var currentSession: VaultSession? {
        guard case .vault(let id) = selection else { return nil }
        return sessions[id]
    }

    var anySessionForSelection: VaultSession? {
        selection.flatMap { sessions[$0.vaultID] }
    }

    func userSelect(_ item: SidebarItem?) {
        let old = selection
        selection = item
        guard let item, old?.vaultID != item.vaultID else { return }
        if let v = vault(item.vaultID), !v.unlocked, touchIDSlot(for: v) != nil {
            pendingTouchIDPrompt = v.id
        }
    }

    // MARK: Vault list

    func refreshVaults() async {
        guard let list: [VaultInfo] = try? await core.call(["op": "vaults"]) else { return }
        vaults = list
        for v in list where v.unlocked && sessions[v.id] == nil {
            let s = VaultSession(vaultID: v.id, app: self)
            sessions[v.id] = s
            s.start()
        }
        for (id, s) in sessions where !(list.first { $0.id == id }?.unlocked ?? false) {
            s.tearDown()
            sessions[id] = nil
        }
        if let sel = selection, vault(sel.vaultID) == nil {
            selection = sortedVaults.first.map { .vault($0.id) }
        }
        if case .trash(let id) = selection, sessions[id] == nil {
            selection = .vault(id)
        }
    }

    /// After create/join: show the new vault.
    func didAddVault(_ id: String) async {
        await refreshVaults()
        selection = .vault(id)
    }

    // MARK: Touch ID

    /// The Secure Enclave slot usable on this Mac, if any.
    func touchIDSlot(for v: VaultInfo) -> SlotInfo? {
        guard seAvailable else { return nil }
        let seSlots = v.slots.filter { $0.kind == .secureEnclave }
        if let remembered = UserDefaults.standard.string(forKey: Pref.seSlotKey(v.id)) {
            return seSlots.first { $0.id == remembered }
        }
        // No record (e.g. preferences reset): a blob made by another Mac fails to load; loading doesn't prompt.
        return seSlots.first { slot in
            if let known = seLoadable[slot.id] { return known }
            let ok = SecureEnclaveSlot.canLoad(publicInfo: slot.publicInfo ?? [:])
            seLoadable[slot.id] = ok
            return ok
        }
    }

    var touchIDName: String { biometry ? "Touch ID" : "Mac Password" }

    func enableTouchID(_ vaultID: String) async throws {
        let created = try await Task.detached { try SecureEnclaveSlot.create() }.value
        defer { created.secret.wipe() }
        let r: SlotResult = try await core.call(
            ["op": "slot_add", "id": vaultID, "kind": "secure-enclave", "label": created.label, "public": created.publicInfo],
            secret: created.secret)
        // Replace an older slot this Mac made, so only one stays usable here.
        if let old = UserDefaults.standard.string(forKey: Pref.seSlotKey(vaultID)), old != r.slot,
           vault(vaultID)?.slots.contains(where: { $0.id == old }) == true {
            try? await core.perform(["op": "slot_remove", "id": vaultID, "slot": old])
        }
        UserDefaults.standard.set(r.slot, forKey: Pref.seSlotKey(vaultID))
        await refreshVaults()
    }

    /// After a key rotation (here or adopted from another device) this Mac's Touch ID slot is
    /// gone. Forget it and, if asked, set up a new one (creating a slot doesn't prompt).
    /// Returns a warning if Touch ID couldn't be re-created.
    func keysReplaced(_ id: String, recreateTouchID: Bool) async -> String? {
        UserDefaults.standard.removeObject(forKey: Pref.seSlotKey(id))
        seLoadable.removeAll()
        await refreshVaults()
        await sessions[id]?.poll()
        guard recreateTouchID, seAvailable else { return nil }
        do {
            try await enableTouchID(id)
            return nil
        } catch {
            return "\(touchIDName) couldn’t be set up again (\(error.localizedDescription)). Enable it in Vault Settings."
        }
    }

    func cancelRotation(_ id: String) async {
        let ok = await Alerts.confirm(
            "Cancel the key rotation?",
            "The prepared keys and their recovery key are discarded. The vault keeps its current keys, passphrases and devices.",
            action: "Cancel Rotation", destructive: false)
        guard ok else { return }
        do {
            try await core.perform(["op": "rotate_cancel", "id": id])
            await sessions[id]?.poll()
        } catch {
            await Alerts.error(error, title: "The rotation can’t be cancelled")
        }
    }

    // MARK: Lock / unlock

    func unlock(_ id: String, kind: SlotKind, secret: SecretBytes, slot: String? = nil) async throws {
        defer { secret.wipe() }
        var req: [String: Any] = ["op": "unlock", "id": id, "kind": kind.rawValue]
        if let slot { req["slot"] = slot }
        try await core.perform(req, secret: secret)
        await refreshVaults()
        lastActivity = Date()
    }

    func unlockWithTouchID(_ id: String) async throws {
        guard let v = vault(id), let slot = touchIDSlot(for: v), let info = slot.publicInfo else { return }
        let reason = "unlock the vault “\(v.name)”"
        let secret = try await Task.detached {
            try SecureEnclaveSlot.unlockSecret(publicInfo: info, reason: reason)
        }.value
        try await unlock(id, kind: .secureEnclave, secret: secret, slot: slot.id)
    }

    func lock(_ id: String) async {
        await ExternalEditor.shared.stopAll(vaultID: id)
        sessions[id]?.tearDown()
        try? await core.perform(["op": "lock", "id": id])
        await refreshVaults()
    }

    func lockAll() async {
        guard !sessions.isEmpty else { return }
        await ExternalEditor.shared.stopAll()
        for s in sessions.values { s.tearDown() }
        try? await core.perform(["op": "lock_all"])
        await refreshVaults()
    }

    /// Quit path: save edits back, remove plaintext temp copies, drop all keys.
    func shutdown() async {
        terminating = true
        pollTask?.cancel()
        await ExternalEditor.shared.stopAll()
        ExternalEditor.shared.removeSessionRoot()
        for s in sessions.values { s.tearDown() }
        try? await core.perform(["op": "lock_all"])
    }

    // MARK: Remove from this Mac

    func forget(_ id: String) async {
        guard let v = vault(id) else { return }
        let ok = await Alerts.confirm(
            "Remove “\(v.name)” from this Mac?",
            "The vault is locked and removed from Coffer’s list. Its encrypted folder stays on disk until you move it to the Trash." + (v.synced ? " The copy on the sync server is not affected." : " This is a local vault: without its folder, the files are gone."),
            action: "Remove")
        guard ok else { return }
        await ExternalEditor.shared.stopAll(vaultID: id)
        sessions[id]?.tearDown()
        do {
            let r: PathResult = try await core.call(["op": "forget", "id": id])
            UserDefaults.standard.removeObject(forKey: Pref.seSlotKey(id))
            await refreshVaults()
            let url = URL(fileURLWithPath: r.path)
            guard FileManager.default.fileExists(atPath: r.path) else { return }
            let choice = await Alerts.info(
                "“\(v.name)” was removed",
                "Its encrypted folder is still at \(url.path(percentEncoded: false)).",
                buttons: ["Keep Folder", "Move Folder to Trash", "Show in Finder"])
            switch choice {
            case 1:
                var go = v.synced
                if !go {
                    go = await Alerts.confirm("Move the vault folder to the Trash?", "This is the only copy of a local vault. Once the Trash is emptied, its files can’t be recovered.", action: "Move to Trash")
                }
                if go {
                    let err: Error? = await withCheckedContinuation { cont in
                        NSWorkspace.shared.recycle([url]) { _, e in cont.resume(returning: e) }
                    }
                    if let err { await Alerts.error(err) }
                }
            case 2:
                NSWorkspace.shared.activateFileViewerSelecting([url])
            default:
                break
            }
        } catch {
            await Alerts.error(error)
        }
    }

    // MARK: Polling

    private func startPolling() {
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollOnce()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func pollOnce() async {
        tick += 1
        await withTaskGroup(of: Void.self) { group in
            for s in sessions.values {
                group.addTask { await s.poll() }
            }
        }
        if tick % 10 == 0 { await refreshVaults() }
        checkIdle()
    }

    // MARK: Idle / sleep

    func noteActivity() { lastActivity = Date() }

    private func startIdleMonitor() {
        let mask: NSEvent.EventTypeMask = [.keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .scrollWheel, .mouseMoved, .leftMouseDragged]
        if let m = NSEvent.addLocalMonitorForEvents(matching: mask, handler: { event in
            MainActor.assumeIsolated { AppModel.shared.noteActivity() }
            return event
        }) {
            monitors.append(m)
        }
    }

    private func checkIdle() {
        let minutes = Pref.autoLock
        guard minutes > 0, !sessions.isEmpty else { return }
        // Don't pull keys out from under a running import/export.
        guard !sessions.values.contains(where: { $0.busy > 0 }) else { lastActivity = Date(); return }
        if Date().timeIntervalSince(lastActivity) > TimeInterval(minutes * 60) {
            Task { await lockAll() }
        }
    }

    private func startSleepObservers() {
        let ws = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification] {
            observers.append(ws.addObserver(forName: name, object: nil, queue: .main) { _ in
                MainActor.assumeIsolated { AppModel.shared.lockForSleep() }
            })
        }
        observers.append(DistributedNotificationCenter.default().addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { AppModel.shared.lockForSleep() }
        })
    }

    private func lockForSleep() {
        guard UserDefaults.standard.bool(forKey: Pref.lockOnSleep) else { return }
        Task { await lockAll() }
    }
}

extension Array where Element == VaultInfo {
    func sortedByName() -> [VaultInfo] {
        sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
}
