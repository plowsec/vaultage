import AppKit
import CofferKit
import SwiftUI
import UniformTypeIdentifiers

struct BrowserView: View {
    @Bindable var session: VaultSession
    @Environment(AppModel.self) private var app
    @AppStorage(Pref.viewMode) private var viewModeRaw = ViewMode.list.rawValue
    private var editor: ExternalEditor { ExternalEditor.shared }

    private var viewMode: ViewMode { ViewMode(rawValue: viewModeRaw) ?? .list }

    var body: some View {
        VStack(spacing: 0) {
            BannerStack(session: session)
            PathBar(session: session)
            Divider()
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            StatusBarView(session: session)
        }
        .inspector(isPresented: Binding(get: { session.showPreview }, set: { v in
            session.showPreview = v
            session.refreshPreview()
        })) {
            PreviewPane(session: session)
                .inspectorColumnWidth(min: 260, ideal: 340, max: 600)
        }
        .navigationTitle(session.name)
        .navigationSubtitle(session.isSearching ? "Search results" : (session.path.isEmpty ? "" : VaultPath.name(session.path)))
        .toolbar { toolbar }
        .task { await session.poll() }
    }

    @ViewBuilder
    private var content: some View {
        let items = session.displayed
        if !session.loadedOnce {
            ProgressView().controlSize(.small)
        } else if session.isSearching && items.isEmpty {
            ContentUnavailableView.search(text: session.searchText)
        } else if items.isEmpty {
            EmptyFolderView(session: session)
        } else {
            switch viewMode {
            case .list:
                FileTableView(
                    session: session,
                    items: items,
                    selection: session.selection,
                    sort: session.sort,
                    showStatus: session.synced || !editor.entries(in: session.vaultID).isEmpty,
                    synced: session.synced,
                    editing: editor.entries(in: session.vaultID),
                    renameRequest: session.renameRequest)
            case .grid:
                FileGridView(session: session, items: items, editing: editor.entries(in: session.vaultID))
            }
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .navigation) {
            ControlGroup {
                Button { session.goBack() } label: { Label("Back", systemImage: "chevron.left") }
                    .disabled(!session.canGoBack)
                    .help("Back (⌘[)")
                Button { session.goForward() } label: { Label("Forward", systemImage: "chevron.right") }
                    .disabled(!session.canGoForward)
                    .help("Forward (⌘])")
            }
            .controlGroupStyle(.navigation)
        }
        ToolbarItem(placement: .primaryAction) {
            Picker("View", selection: $viewModeRaw) {
                Label("List", systemImage: "list.bullet").tag(ViewMode.list.rawValue)
                Label("Grid", systemImage: "square.grid.2x2").tag(ViewMode.grid.rawValue)
            }
            .pickerStyle(.segmented)
            .labelStyle(.iconOnly)
            .help("View as list or grid (⌘1, ⌘2)")
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Button { session.addFiles() } label: { Label("Add Files", systemImage: "plus.rectangle.on.folder") }
                .help("Add files or folders (⌘O)")
            Button { Task { await session.newFolder() } } label: { Label("New Folder", systemImage: "folder.badge.plus") }
                .disabled(session.isSearching)
                .help("New folder (⇧⌘N)")
            Button { Task { await session.export(session.selectedItems.map(\.path), remove: false) } } label: {
                Label("Export", systemImage: "square.and.arrow.up")
            }
            .disabled(session.selection.isEmpty)
            .help("Export decrypted copies (⌘E)")
            Button { Task { await session.delete(session.selectedItems.map(\.path)) } } label: { Label("Delete", systemImage: "trash") }
                .disabled(session.selection.isEmpty)
                .help("Delete (⌘⌫)")
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Button { Task { await app.lock(session.vaultID) } } label: { Label("Lock", systemImage: "lock") }
                .help("Lock this vault (⌘L)")
            SearchField(text: $session.searchText, prompt: "Search \(session.name)", focusToken: app.focusSearchToken) {
                session.searchChanged()
            }
            .frame(width: 200)
            Button { session.togglePreview() } label: { Label("Preview", systemImage: "sidebar.trailing") }
                .help("Show or hide the preview (Space, ⌥⌘I)")
        }
    }
}

// MARK: - Item actions (shared by list context menu, grid context menu)

struct ItemAction {
    let title: String
    var destructive = false
    var icon: NSImage? = nil
    /// Non-nil: a submenu.
    var children: [ItemAction?]? = nil
    var run: @MainActor () -> Void = {}
}

@MainActor
func openWithMenu(_ session: VaultSession, _ item: Item) -> ItemAction {
    var kids: [ItemAction?] = OpenWith.apps(for: item.name).map { a in
        ItemAction(title: a.isDefault ? "\(a.name) (default)" : a.name, icon: a.icon) {
            Task { await ExternalEditor.shared.open(item, in: session, with: a.url) }
        }
    }
    if !kids.isEmpty { kids.append(nil) }
    kids.append(ItemAction(title: "Other…") { OpenWith.chooseOther(item, in: session) })
    return ItemAction(title: "Open With", children: kids)
}

@MainActor
func itemActions(_ session: VaultSession, _ items: [Item]) -> [ItemAction?] {
    let app = AppModel.shared
    let editor = ExternalEditor.shared
    let paths = items.map(\.path)
    var out: [ItemAction?] = []
    if items.count == 1 {
        let it = items[0]
        if it.isDir {
            out.append(ItemAction(title: "Open") { session.open(it) })
        } else {
            out.append(ItemAction(title: "Preview") { session.open(it) })
            if editor.isEditing(vault: session.vaultID, entry: it.id) {
                out.append(ItemAction(title: "Show Editing Copy") { Task { await editor.open(it, in: session) } })
                out.append(ItemAction(title: "Stop Editing") { Task { await editor.stop(vault: session.vaultID, entry: it.id!) } })
            } else {
                out.append(ItemAction(title: "Open in External App…") { Task { await editor.open(it, in: session) } })
            }
            out.append(openWithMenu(session, it))
        }
        out.append(nil)
    }
    if !items.isEmpty {
        out.append(ItemAction(title: "Export…") { Task { await session.export(paths, remove: false) } })
        out.append(ItemAction(title: "Move Out of Vault…") { Task { await session.export(paths, remove: true) } })
        out.append(nil)
    }
    if items.count == 1 {
        let it = items[0]
        out.append(ItemAction(title: "Rename…") { app.sheet = .rename(session.vaultID, it) })
    }
    if !items.isEmpty {
        out.append(ItemAction(title: "Move to…") { app.sheet = .moveTo(session.vaultID, paths) })
    }
    if items.count == 1, !items[0].isDir {
        let it = items[0]
        out.append(ItemAction(title: "Versions…") { app.sheet = .versions(session.vaultID, it) })
    }
    if !items.isEmpty {
        out.append(nil)
        out.append(ItemAction(title: "Delete", destructive: true) { Task { await session.delete(paths) } })
    } else {
        if !session.isSearching {
            out.append(ItemAction(title: "New Folder") { Task { await session.newFolder() } })
        }
        out.append(ItemAction(title: "Add Files…") { session.addFiles() })
    }
    return out
}

struct ItemActionsMenu: View {
    let actions: [ItemAction?]
    var body: some View {
        ForEach(Array(actions.enumerated()), id: \.offset) { _, a in
            if let a, let kids = a.children {
                Menu(a.title) { ItemActionsMenu(actions: kids) }
            } else if let a {
                Button(role: a.destructive ? .destructive : nil) { a.run() } label: {
                    if let icon = a.icon {
                        Label { Text(a.title) } icon: { Image(nsImage: icon) }
                    } else {
                        Text(a.title)
                    }
                }
            } else {
                Divider()
            }
        }
    }
}

// MARK: - Path bar

struct PathBar: View {
    let session: VaultSession

    var body: some View {
        HStack(spacing: 2) {
            if session.isSearching {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                Text("Searching all of “\(session.name)”").foregroundStyle(.secondary)
                Spacer()
            } else {
                crumb(title: session.name, icon: session.synced ? "cloud" : "internaldrive", path: "")
                ForEach(Array(prefixes.enumerated()), id: \.offset) { _, p in
                    Image(systemName: "chevron.compact.right")
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                    crumb(title: VaultPath.name(p), icon: "folder", path: p)
                }
                Spacer(minLength: 0)
            }
        }
        .font(.callout)
        .lineLimit(1)
        .padding(.horizontal, 10)
        .frame(height: 30)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Path")
    }

    private var prefixes: [String] {
        var out: [String] = []
        var cur = ""
        for c in VaultPath.components(session.path) {
            cur = VaultPath.join(cur, c)
            out.append(cur)
        }
        return out
    }

    private func crumb(title: String, icon: String, path: String) -> some View {
        let current = path == session.path
        return Button {
            session.navigate(to: path)
        } label: {
            Label(title, systemImage: icon)
                .labelStyle(.titleAndIcon)
                .fontWeight(current ? .semibold : .regular)
                .foregroundStyle(current ? .primary : .secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .hoverHighlight(cornerRadius: 5)
        .disabled(current)
        .onDrop(of: [.fileURL], isTargeted: nil) { providers in
            FileDrop.urls(from: providers) { session.handleDrop($0, into: path) }
            return true
        }
    }
}

// MARK: - Empty state

struct EmptyFolderView: View {
    let session: VaultSession
    @State private var targeted = false

    var body: some View {
        VStack(spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [7, 6]))
                    .foregroundStyle(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.quaternary))
                    .frame(width: 168, height: 128)
                    .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(targeted ? Color.accentColor.opacity(0.08) : .clear))
                Image(systemName: targeted ? "lock.doc.fill" : "arrow.down.doc")
                    .font(.system(size: 42, weight: .light))
                    .foregroundStyle(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                    .contentTransition(.symbolEffect(.replace))
            }
            .scaleEffect(targeted ? 1.04 : 1)
            VStack(spacing: 4) {
                Text(session.path.isEmpty ? "Drop files here to encrypt them" : "This folder is empty")
                    .font(.title3.weight(.semibold))
                Text("Files are encrypted on this Mac before they’re stored\(session.synced ? " or synced" : ""). Hold ⌥ while dropping to move instead of copy.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
            }
            Button("Add Files…") { session.addFiles() }
                .controlSize(.large)
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .contentShape(Rectangle())
        .animation(.snappy(duration: 0.2), value: targeted)
        .onDrop(of: [.fileURL], isTargeted: $targeted) { providers in
            FileDrop.urls(from: providers) { session.handleDrop($0) }
            return true
        }
        .contextMenu { ItemActionsMenu(actions: itemActions(session, [])) }
    }
}

// MARK: - Banners

struct BannerStack: View {
    let session: VaultSession
    @Environment(AppModel.self) private var app

    var body: some View {
        VStack(spacing: 0) {
            if session.status?.isRekeyed == true {
                BannerView(icon: "key.horizontal.fill", tint: .orange,
                           title: "This vault’s keys were rotated on another device",
                           message: "Syncing is paused until you enter the new recovery key or passphrase. Files on this Mac stay readable.",
                           actions: [("Enter New Key…", { app.sheet = .vaultTask(session.vaultID, .adoptRekey) })])
            }
            if session.status?.isRotationPending == true, app.rotationSheetVault != session.vaultID {
                BannerView(icon: "arrow.triangle.2.circlepath", tint: .orange,
                           title: "Key rotation was started but not finished",
                           message: "New keys were prepared but aren’t in effect yet. Finish to switch to them, or cancel to keep the current keys.",
                           actions: [
                               ("Cancel Rotation…", { Task { await app.cancelRotation(session.vaultID) } }),
                               ("Finish…", { app.sheet = .vaultTask(session.vaultID, .finishRotation) }),
                           ])
            }
            if let issue = session.integrityIssue {
                BannerView(icon: "exclamationmark.octagon.fill", tint: .red,
                           title: "Integrity check failed",
                           message: issue + " Data was modified or damaged and was not used. Keep a copy of the vault folder before changing anything.",
                           closeLabel: "I Understand") {
                    session.integrityIssue = nil
                }
            }
            if let conflicts = session.status?.conflicts, !conflicts.isEmpty {
                BannerView(icon: "arrow.triangle.branch", tint: .orange,
                           title: conflicts.count == 1 ? "A conflict was resolved" : "\(conflicts.count) conflicts were resolved",
                           message: conflicts.prefix(4).joined(separator: "\n") + (conflicts.count > 4 ? "\n…and \(conflicts.count - 4) more" : ""),
                           closeLabel: "Dismiss") {
                    Task { await session.dismissConflicts() }
                }
            }
        }
        .animation(.snappy, value: session.integrityIssue)
        .animation(.snappy, value: session.status?.conflicts)
        .animation(.snappy, value: session.status?.isRekeyed)
        .animation(.snappy, value: session.status?.isRotationPending)
    }
}

struct BannerView: View {
    let icon: String
    let tint: Color
    let title: String
    let message: String
    /// Buttons; the last one is the prominent one. No close button: these need a decision.
    var actions: [(String, () -> Void)] = []

    init(icon: String, tint: Color, title: String, message: String, closeLabel: String, close: @escaping () -> Void) {
        self.init(icon: icon, tint: tint, title: title, message: message, actions: [(closeLabel, close)])
    }

    init(icon: String, tint: Color, title: String, message: String, actions: [(String, () -> Void)]) {
        self.icon = icon
        self.tint = tint
        self.title = title
        self.message = message
        self.actions = actions
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout.weight(.semibold))
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            ForEach(Array(actions.enumerated()), id: \.offset) { i, a in
                if i == actions.count - 1 && actions.count > 1 {
                    Button(a.0, action: a.1).controlSize(.small).buttonStyle(.borderedProminent)
                } else {
                    Button(a.0, action: a.1).controlSize(.small)
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(tint.opacity(0.10))
        .overlay(alignment: .bottom) { Divider() }
        .transition(.move(edge: .top).combined(with: .opacity))
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Search field (AppKit, so ⌘F can focus it)

struct SearchField: NSViewRepresentable {
    @Binding var text: String
    let prompt: String
    let focusToken: Int
    let onChange: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSSearchField {
        let f = NSSearchField()
        f.placeholderString = prompt
        f.delegate = context.coordinator
        f.sendsSearchStringImmediately = false
        f.sendsWholeSearchString = false
        f.controlSize = .regular
        context.coordinator.lastToken = focusToken
        return f
    }

    func updateNSView(_ f: NSSearchField, context: Context) {
        context.coordinator.parent = self
        if f.stringValue != text { f.stringValue = text }
        f.placeholderString = prompt
        if focusToken != context.coordinator.lastToken {
            context.coordinator.lastToken = focusToken
            DispatchQueue.main.async { f.window?.makeFirstResponder(f) }
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var parent: SearchField
        var lastToken = 0
        init(_ p: SearchField) { parent = p }

        func controlTextDidChange(_ obj: Notification) {
            guard let f = obj.object as? NSSearchField else { return }
            parent.text = f.stringValue
            parent.onChange()
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy sel: Selector) -> Bool {
            if sel == #selector(NSResponder.cancelOperation(_:)) {
                parent.text = ""
                parent.onChange()
                (control as? NSSearchField)?.stringValue = ""
                control.window?.makeFirstResponder(nil)
                return true
            }
            return false
        }
    }
}
