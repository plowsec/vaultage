import CofferKit
import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var app
    @State private var columns = NavigationSplitViewVisibility.all

    var body: some View {
        @Bindable var app = app
        NavigationSplitView(columnVisibility: $columns) {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 200, ideal: 240, max: 360)
                .background(SplitViewAutosave(name: "CofferSidebar"))
        } detail: {
            DetailView()
        }
        .sheet(item: $app.sheet) { sheet in
            SheetHost(sheet: sheet)
                .environment(app)
        }
    }
}

/// Picks the detail pane for the sidebar selection.
struct DetailView: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        Group {
            if let sel = app.selection, let vault = app.vault(sel.vaultID) {
                if let session = app.sessions[vault.id] {
                    switch sel {
                    case .vault:
                        BrowserView(session: session)
                            .id(vault.id)
                    case .trash:
                        TrashView(session: session)
                            .id("trash-" + vault.id)
                    }
                } else if vault.missing {
                    MissingVaultView(vault: vault)
                } else {
                    LockedVaultView(vault: vault)
                        .id("locked-" + vault.id)
                }
            } else if app.loaded {
                WelcomeView()
            } else {
                Color.clear
            }
        }
        .transition(.opacity)
        .animation(.smooth(duration: 0.25), value: detailKey)
    }

    private var detailKey: String {
        guard let sel = app.selection else { return "none" }
        let unlocked = app.sessions[sel.vaultID] != nil
        switch sel {
        case .vault(let id): return "v-\(id)-\(unlocked)"
        case .trash(let id): return "t-\(id)-\(unlocked)"
        }
    }
}

struct SheetHost: View {
    let sheet: AppSheet
    @Environment(AppModel.self) private var app

    var body: some View {
        switch sheet {
        case .newVault:
            NewVaultSheet()
        case .joinVault:
            JoinVaultSheet()
        case .vaultSettings(let id):
            VaultSettingsSheet(vaultID: id)
        case .versions(let id, let item):
            if let s = app.sessions[id] { VersionsSheet(session: s, item: item) } else { LockedSheetNotice() }
        case .rename(let id, let item):
            if let s = app.sessions[id] { RenameSheet(session: s, item: item) } else { LockedSheetNotice() }
        case .newFolder(let id):
            if let s = app.sessions[id] { NewFolderSheet(session: s) } else { LockedSheetNotice() }
        case .moveTo(let id, let paths):
            if let s = app.sessions[id] { MoveToSheet(session: s, paths: paths) } else { LockedSheetNotice() }
        case .importReport(_, let rep, let moved):
            ImportReportSheet(report: rep, moved: moved)
        case .enableTouchID(let id):
            EnableTouchIDSheet(vaultID: id)
        case .vaultTask(let id, let task):
            VaultTaskSheet(vaultID: id, task: task)
        }
    }
}

struct LockedSheetNotice: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
            Text("This vault is locked.").font(.headline)
            Button("Close") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .padding(32)
    }
}

struct WelcomeView: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield")
                .font(.system(size: 64, weight: .light))
                .foregroundStyle(.tint)
                .symbolRenderingMode(.hierarchical)
            VStack(spacing: 6) {
                Text("Welcome to Vaultage").font(.largeTitle.weight(.semibold))
                Text("Files you put in a vault are encrypted on this Mac before they’re stored or synced.")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 440)
            }
            HStack(spacing: 12) {
                Button {
                    app.sheet = .newVault
                } label: {
                    Label("New Vault…", systemImage: "plus")
                        .frame(minWidth: 150)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                Button {
                    app.sheet = .joinVault
                } label: {
                    Label("Join Existing Vault…", systemImage: "link")
                        .frame(minWidth: 150)
                }
                .controlSize(.large)
            }
            .padding(.top, 8)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct MissingVaultView: View {
    let vault: VaultInfo
    @Environment(AppModel.self) private var app

    var body: some View {
        ContentUnavailableView {
            Label("Vault Folder Not Found", systemImage: "questionmark.folder")
        } description: {
            Text("Vaultage can’t find the encrypted folder for “\(vault.name)”. It may have been moved, renamed or deleted, or its disk isn’t connected.")
            Text(vault.path)
                .font(.callout.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .padding(.top, 4)
        } actions: {
            HStack {
                Button("Show Enclosing Folder") {
                    let parent = URL(fileURLWithPath: vault.path).deletingLastPathComponent()
                    NSWorkspace.shared.open(parent)
                }
                Button("Remove from This Mac…", role: .destructive) {
                    Task { await app.forget(vault.id) }
                }
            }
        }
    }
}
