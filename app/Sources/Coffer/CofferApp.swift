import AppKit
import CofferKit
import SwiftUI

struct CofferApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var app = AppModel.shared

    var body: some Scene {
        Window("Vaultage", id: "main") {
            RootView()
                .environment(app)
                .frame(minWidth: 900, minHeight: 560)
        }
        .defaultSize(width: 1180, height: 760)
        .windowToolbarStyle(.unified)
        .commands { CofferCommands(app: app) }

        Settings {
            AppSettingsView()
                .environment(app)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var cleaned = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        MainActor.assumeIsolated {
            AppModel.shared.start(posture: initialPosture)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if cleaned { return .terminateNow }
        Task { @MainActor in
            // Don't let a stuck network call hold up quitting forever.
            let fallback = Task { @MainActor in
                try? await Task.sleep(for: .seconds(8))
                guard !Task.isCancelled else { return }
                ExternalEditor.shared.removeSessionRoot()
                self.cleaned = true
                NSApp.reply(toApplicationShouldTerminate: true)
            }
            await AppModel.shared.shutdown()
            fallback.cancel()
            guard !self.cleaned else { return }
            self.cleaned = true
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}

/// Menu bar. Actions forward to the selected vault's session.
struct CofferCommands: Commands {
    let app: AppModel

    private var session: VaultSession? { app.currentSession }
    private var selected: [Item] { session?.selectedItems ?? [] }
    private var file: Item? { session?.singleSelectedFile }
    /// Unlocked session of the vault selected in the sidebar (browser or trash view).
    private var vaultSession: VaultSession? { app.anySessionForSelection }

    /// While a text field is being edited, ⌘⌫ belongs to it.
    private func textEditing() -> Bool {
        NSApp.keyWindow?.firstResponder is NSTextView
    }

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Vault…") { app.sheet = .newVault }
                .keyboardShortcut("n", modifiers: [.command, .option])
            Button("Join Existing Vault…") { app.sheet = .joinVault }
                .keyboardShortcut("j", modifiers: [.command, .option])
            Divider()
            Button("Add Files…") { session?.addFiles() }
                .keyboardShortcut("o")
                .disabled(session == nil)
            Button("New Folder") { if let s = session { Task { await s.newFolder() } } }
                .keyboardShortcut("n", modifiers: [.command, .shift])
                .disabled(session == nil || session?.isSearching == true)
        }

        CommandGroup(after: .newItem) {
            Divider()
            Button("Open") { if let s = session, let i = selected.first { s.open(i) } }
                .keyboardShortcut(.downArrow)
                .disabled(selected.count != 1)
            Button("Open in External App…") {
                if let s = session, let f = file { Task { await ExternalEditor.shared.open(f, in: s) } }
            }
            .keyboardShortcut("o", modifiers: [.command, .shift])
            .disabled(file == nil)
            Menu("Open With") {
                if let s = session, let f = file {
                    ForEach(OpenWith.apps(for: f.name)) { a in
                        Button {
                            Task { await ExternalEditor.shared.open(f, in: s, with: a.url) }
                        } label: {
                            Label { Text(a.isDefault ? "\(a.name) (default)" : a.name) } icon: { Image(nsImage: a.icon) }
                        }
                    }
                    Divider()
                    Button("Other…") { OpenWith.chooseOther(f, in: s) }
                }
            }
            .disabled(file == nil)
            Button("Versions…") { if let s = session, let f = file { app.sheet = .versions(s.vaultID, f) } }
                .keyboardShortcut("y", modifiers: [.command, .option])
                .disabled(file == nil)
            Divider()
            Button("Export…") { if let s = session { Task { await s.export(selected.map(\.path), remove: false) } } }
                .keyboardShortcut("e")
                .disabled(selected.isEmpty)
            Button("Move Out of Vault…") { if let s = session { Task { await s.export(selected.map(\.path), remove: true) } } }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(selected.isEmpty)
            Button("Move To…") { if let s = session { app.sheet = .moveTo(s.vaultID, selected.map(\.path)) } }
                .keyboardShortcut("m", modifiers: [.command, .shift])
                .disabled(selected.isEmpty)
            Divider()
            Button("Lock Vault") { if let id = app.selection?.vaultID { Task { await app.lock(id) } } }
                .keyboardShortcut("l")
                .disabled(app.anySessionForSelection == nil)
            Button("Lock All Vaults") { Task { await app.lockAll() } }
                .keyboardShortcut("l", modifiers: [.command, .shift])
                .disabled(app.sessions.isEmpty)
        }

        CommandGroup(after: .pasteboard) {
            Divider()
            Button("Rename…") {
                if let s = session, let i = selected.first { app.sheet = .rename(s.vaultID, i) }
            }
            .disabled(selected.count != 1)
            Button("Delete") {
                if textEditing() {
                    NSApp.sendAction(#selector(NSResponder.deleteToBeginningOfLine(_:)), to: nil, from: nil)
                } else if let s = session {
                    Task { await s.delete(selected.map(\.path)) }
                }
            }
            .keyboardShortcut(.delete)
            .disabled(selected.isEmpty)
            Divider()
            Button("Find") { app.focusSearchToken += 1 }
                .keyboardShortcut("f")
                .disabled(session == nil)
        }

        CommandGroup(before: .sidebar) {
            Button("as List") { UserDefaults.standard.set(ViewMode.list.rawValue, forKey: Pref.viewMode) }
                .keyboardShortcut("1")
            Button("as Grid") { UserDefaults.standard.set(ViewMode.grid.rawValue, forKey: Pref.viewMode) }
                .keyboardShortcut("2")
            Divider()
            Button(session?.showPreview == true ? "Hide Preview" : "Show Preview") { session?.togglePreview() }
                .keyboardShortcut("i", modifiers: [.command, .option])
                .disabled(session == nil)
            Button("Show Trash") { if let id = app.selection?.vaultID { app.selection = .trash(id) } }
                .keyboardShortcut("t", modifiers: [.command, .shift])
                .disabled(app.anySessionForSelection == nil)
            Divider()
        }

        CommandMenu("Go") {
            Button("Back") { session?.goBack() }
                .keyboardShortcut("[")
                .disabled(session?.canGoBack != true)
            Button("Forward") { session?.goForward() }
                .keyboardShortcut("]")
                .disabled(session?.canGoForward != true)
            Button("Enclosing Folder") { session?.goUp() }
                .keyboardShortcut(.upArrow)
                .disabled(session?.canGoUp != true)
            Divider()
            Button("Vault Root") { session?.navigate(to: "") }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(session?.canGoUp != true)
        }

        CommandMenu("Vault") {
            Button("Vault Settings…") { if let id = app.selection?.vaultID { app.sheet = .vaultSettings(id) } }
                .keyboardShortcut(",", modifiers: [.command, .option])
                .disabled(app.selection == nil)
            Button("Sync Now") { app.anySessionForSelection?.syncNow() }
                .keyboardShortcut("s", modifiers: [.command, .option])
                .disabled(app.anySessionForSelection?.synced != true)
            Button("Sync with a Server…") { if let id = vaultSession?.vaultID { app.sheet = .vaultTask(id, .attach) } }
                .disabled(vaultSession == nil || vaultSession?.synced == true)
            Button("Invite Someone…") { if let id = vaultSession?.vaultID { app.sheet = .vaultTask(id, .invite) } }
                .disabled(vaultSession?.synced != true || vaultSession?.status?.isRekeyed == true)
            Divider()
            Button(vaultSession?.status?.isRotationPending == true ? "Finish Key Rotation…" : "Rotate Keys…") {
                if let s = vaultSession {
                    app.sheet = .vaultTask(s.vaultID, s.status?.isRotationPending == true ? .finishRotation : .rotate)
                }
            }
            .disabled(vaultSession == nil || vaultSession?.status?.isRekeyed == true)
            Button("Empty Trash…") { if let s = vaultSession { Task { await s.emptyTrash() } } }
                .keyboardShortcut(.delete, modifiers: [.command, .shift])
                .disabled(vaultSession?.trash.isEmpty ?? true)
            Divider()
            Button("Lock Vault") { if let id = app.selection?.vaultID { Task { await app.lock(id) } } }
                .disabled(app.anySessionForSelection == nil)
            Button("Lock All Vaults") { Task { await app.lockAll() } }
                .disabled(app.sessions.isEmpty)
            Divider()
            Button("Remove from This Mac…") { if let id = app.selection?.vaultID { Task { await app.forget(id) } } }
                .disabled(app.selection == nil)
        }
    }
}
