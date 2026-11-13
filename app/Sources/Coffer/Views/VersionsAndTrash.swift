import CofferKit
import SwiftUI

struct VersionsSheet: View {
    let session: VaultSession
    let item: Item
    @Environment(\.dismiss) private var dismiss
    @State private var versions: [Version] = []
    @State private var selected: Version.ID?
    @State private var preview: PreviewDoc?
    @State private var previewNote: String?
    @State private var loadingPreview = false
    @State private var loadError: String?
    @State private var pruning = false

    private var selectedVersion: Version? { versions.first { $0.id == selected } }
    private var olderCount: Int { versions.count > 1 ? versions.filter { !$0.current }.count : 0 }

    private func prune() async {
        guard let entry = item.id, olderCount > 0 else { return }
        pruning = true
        defer { pruning = false }
        if await session.pruneVersions(entry: entry, name: item.name, older: olderCount) {
            preview = nil
            await load()
            session.show(Banner(style: .success, text: "Deleted older versions of “\(item.name)”"))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(nsImage: FileIcon.image(for: item.name, isDir: false)).resizable().frame(width: 32, height: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Versions of “\(item.name)”").font(.headline)
                    Text("Every saved change is kept. Restoring makes an old version current again; nothing is lost.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(16)
            Divider()
            HSplitView {
                list.frame(minWidth: 470, idealWidth: 500, maxWidth: .infinity)
                previewPane.frame(minWidth: 260, idealWidth: 320, maxWidth: .infinity, maxHeight: .infinity)
            }
            Divider()
            HStack {
                if let e = loadError { Text(e).foregroundStyle(.red).font(.callout) }
                Spacer()
                Button("Delete Older Versions…", role: .destructive) { Task { await prune() } }
                    .disabled(olderCount == 0 || pruning)
                    .help("Keep only the current version")
                Button("Preview This Version") { Task { await loadPreview() } }
                    .disabled(selectedVersion == nil || selectedVersion?.deleted == true || loadingPreview)
                Button("Restore") { Task { await restore() } }
                    .disabled(selectedVersion == nil || selectedVersion?.current == true || selectedVersion?.deleted == true || selectedVersion?.pending == true)
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(12)
        }
        .frame(width: 860, height: 520)
        .task { await load() }
        .onChange(of: selected) { _, _ in
            preview = nil
            previewNote = nil
        }
    }

    private var list: some View {
        Table(versions, selection: $selected) {
            TableColumn("Version") { v in
                HStack(spacing: 6) {
                    Text("#\(v.rev)").monospacedDigit()
                    if v.current { badge("Current", .accentColor) }
                    if v.pending { badge("Pending", .orange) }
                    if v.deleted { badge("Deleted", .red) }
                }
            }
            .width(min: 110, ideal: 130)
            TableColumn("Date") { v in Text(Fmt.date(v.ts)) }
                .width(min: 110, ideal: 150)
            TableColumn("Device") { v in Text(v.device).lineLimit(1).truncationMode(.middle) }
                .width(min: 60, ideal: 110)
            TableColumn("Size") { v in Text(v.deleted ? "—" : Fmt.bytes(v.size)).monospacedDigit() }
                .width(min: 50, ideal: 64)
        }
        .contextMenu(forSelectionType: Version.ID.self) { ids in
            if let id = ids.first, let v = versions.first(where: { $0.id == id }), !v.deleted {
                Button("Preview This Version") { selected = id; Task { await loadPreview() } }
                if !v.current && !v.pending {
                    Button("Restore This Version") { selected = id; Task { await restore() } }
                }
            }
        } primaryAction: { ids in
            selected = ids.first
            Task { await loadPreview() }
        }
    }

    @ViewBuilder
    private var previewPane: some View {
        if loadingPreview {
            ProgressView("Decrypting…").controlSize(.small)
        } else if let preview {
            PreviewContentView(doc: preview)
        } else if let v = selectedVersion {
            VStack(spacing: 6) {
                Text(previewNote ?? (v.deleted ? "This version marks the file as deleted." : "Select “Preview This Version” to decrypt it in memory."))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding()
        } else {
            Text("Select a version").foregroundStyle(.secondary)
        }
    }

    private func badge(_ t: String, _ c: Color) -> some View {
        Text(t)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Capsule().fill(c))
            .foregroundStyle(.white)
    }

    private func load() async {
        guard let entry = item.id else { return }
        do {
            versions = try await session.core.call(["op": "versions", "id": session.vaultID, "entry": entry])
            selected = versions.first?.id
        } catch {
            loadError = error.localizedDescription
        }
    }

    private func loadPreview() async {
        guard let v = selectedVersion, let entry = item.id, !v.deleted else { return }
        guard v.size <= PreviewDoc.maxBytes else { previewNote = "Too large to preview."; return }
        guard PreviewDoc.canPreview(name: VaultPath.name(v.path)) else { previewNote = "No preview for this kind of file."; return }
        loadingPreview = true
        defer { loadingPreview = false }
        do {
            let data = try await session.core.read(vault: session.vaultID, entry: entry, rev: v.pending ? nil : v.rev)
            let doc = PreviewDoc.make(name: VaultPath.name(v.path), data: data)
            if case .unsupported = doc.kind { previewNote = "No preview for this kind of file." } else { preview = doc }
        } catch {
            if let ce = error as? CofferError, ce.isIntegrity { session.integrityIssue = ce.errorDescription }
            previewNote = error.localizedDescription
        }
    }

    private func restore() async {
        guard let v = selectedVersion, let entry = item.id else { return }
        let ok = await Alerts.confirm("Restore version #\(v.rev)?", "It becomes the current version of “\(item.name)”. The current contents stay available in this list.", action: "Restore", destructive: false)
        guard ok else { return }
        if await session.restore(entry: entry, rev: v.rev) != nil {
            await load()
        }
    }
}

struct TrashView: View {
    let session: VaultSession
    @Environment(AppModel.self) private var app
    @State private var selection = Set<TrashItem.ID>()

    var body: some View {
        VStack(spacing: 0) {
            if session.trash.isEmpty {
                ContentUnavailableView("Trash Is Empty", systemImage: "trash", description: Text("Files you delete from “\(session.name)” appear here, and can be restored."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(session.trash, selection: $selection) {
                    TableColumn("Name") { t in
                        HStack(spacing: 6) {
                            Image(nsImage: FileIcon.image(for: VaultPath.name(t.path), isDir: false)).resizable().frame(width: 16, height: 16)
                            Text(VaultPath.name(t.path))
                        }
                    }
                    .width(min: 160, ideal: 260)
                    TableColumn("Original Location") { t in
                        Text(VaultPath.parent(t.path).isEmpty ? session.name : VaultPath.parent(t.path)).foregroundStyle(.secondary)
                    }
                    TableColumn("Deleted") { t in Text(Fmt.date(t.deletedTs)).foregroundStyle(.secondary) }
                        .width(min: 120, ideal: 160)
                    TableColumn("Device") { t in Text(t.device).foregroundStyle(.secondary) }
                        .width(min: 60, ideal: 100)
                    TableColumn("Size") { t in Text(Fmt.bytes(t.size)).monospacedDigit().foregroundStyle(.secondary) }
                        .width(min: 60, ideal: 80)
                }
                .contextMenu(forSelectionType: TrashItem.ID.self) { ids in
                    Button("Restore") { Task { await restore(ids) } }
                    Divider()
                    Button("Delete Permanently…", role: .destructive) { Task { await purge(ids) } }
                } primaryAction: { ids in
                    Task { await restore(ids) }
                }
            }
            Divider()
            HStack {
                Text(footerText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(footerText)
                Spacer()
                Button("Delete Permanently…", role: .destructive) { Task { await purge(selection) } }
                    .disabled(selection.isEmpty)
                    .help("Erase the selected items and all their versions")
                Button("Restore") { Task { await restore(selection) } }
                    .disabled(selection.isEmpty)
            }
            .padding(.horizontal, 12)
            .frame(height: 36)
            .background(.bar)
        }
        .navigationTitle("Trash")
        .navigationSubtitle(session.name)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { app.selection = .vault(session.vaultID) } label: { Label("Back to Vault", systemImage: "arrow.uturn.backward") }
                    .help("Back to the vault")
            }
            ToolbarItem(placement: .primaryAction) {
                Button("Empty Trash…") { Task { await session.emptyTrash() } }
                    .disabled(session.trash.isEmpty)
                    .help("Permanently erase everything in this vault’s Trash")
            }
        }
        .task {
            session.trashVisible = true
            await session.loadTrash()
        }
        .onDisappear { session.trashVisible = false }
    }

    private var footerText: String {
        let t = session.trash
        guard !t.isEmpty else { return "Restored files go back to their original folder." }
        let total = t.reduce(UInt64(0)) { $0 + $1.size }
        return "\(Fmt.count(UInt64(t.count), "item")) · \(Fmt.bytes(total)). Restored files go back to their original folder (renamed if something else is there now)."
    }

    private func purge(_ ids: Set<String>) async {
        let items = session.trash.filter { ids.contains($0.id) }
        if await session.purge(items) { selection.subtract(ids) }
    }

    private func restore(_ ids: Set<String>) async {
        var restored = 0
        for id in ids {
            if await session.restore(entry: id, rev: nil) != nil { restored += 1 }
        }
        selection.removeAll()
        await session.loadTrash()
        if restored > 0 {
            session.show(Banner(style: .success, text: "Restored \(Fmt.count(UInt64(restored), "file"))"))
        }
    }
}
