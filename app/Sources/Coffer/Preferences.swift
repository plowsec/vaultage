import AppKit
import Foundation

enum Pref {
    static let autoLockMinutes = "autoLockMinutes"        // Int, 0 = never
    static let lockOnSleep = "lockOnSleep"                // Bool
    static let screenCaptureProtection = "screenCaptureProtection" // Bool
    static let importMode = "importMode"                  // ImportMode raw value
    static let viewMode = "viewMode"                      // ViewMode raw value
    static let skipMoveInConfirm = "skipMoveIntoVaultConfirm"
    static let externalEditWarned = "externalEditWarned"
    static let showThumbnails = "showThumbnails"          // Bool

    static func register() {
        UserDefaults.standard.register(defaults: [
            autoLockMinutes: 10,
            lockOnSleep: true,
            screenCaptureProtection: true,
            importMode: ImportMode.copy.rawValue,
            viewMode: ViewMode.list.rawValue,
            showThumbnails: true,
        ])
    }

    /// Slot id of the Secure Enclave slot this Mac created for a vault. Not a secret.
    static func seSlotKey(_ vaultID: String) -> String { "seSlot.\(vaultID)" }

    static var autoLock: Int { UserDefaults.standard.integer(forKey: autoLockMinutes) }
    static var defaultImportMode: ImportMode {
        ImportMode(rawValue: UserDefaults.standard.string(forKey: importMode) ?? "") ?? .copy
    }
}

enum ImportMode: String, CaseIterable, Identifiable {
    case copy, move
    var id: String { rawValue }
}

enum ViewMode: String, CaseIterable, Identifiable {
    case list, grid
    var id: String { rawValue }
}

/// Best-effort exclusion of app windows from screenshots and screen sharing.
@MainActor
final class WindowProtector {
    static let shared = WindowProtector()
    private var observers: [NSObjectProtocol] = []

    var enabled: Bool { UserDefaults.standard.bool(forKey: Pref.screenCaptureProtection) }

    func start() {
        let nc = NotificationCenter.default
        for name in [NSWindow.didBecomeKeyNotification, NSWindow.didBecomeMainNotification, NSWindow.didChangeOcclusionStateNotification] {
            observers.append(nc.addObserver(forName: name, object: nil, queue: .main) { note in
                MainActor.assumeIsolated {
                    if let w = note.object as? NSWindow { WindowProtector.shared.apply(to: w) }
                }
            })
        }
        applyAll()
    }

    func apply(to window: NSWindow) {
        let wanted: NSWindow.SharingType = enabled ? .none : .readOnly
        if window.sharingType != wanted { window.sharingType = wanted }
    }

    func applyAll() {
        NSApp.windows.forEach(apply(to:))
    }
}
