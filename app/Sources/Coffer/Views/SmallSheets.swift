import CofferKit
import SwiftUI

struct RenameSheet: View {
    let session: VaultSession
    let item: Item
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Rename “\(item.name)”").font(.headline)
            TextField("Name", text: $name)
                .textFieldStyle(.roundedBorder)
                .onSubmit { Task { await commit() } }
            if let p = VaultPath.problem(with: name), !name.isEmpty {
                Text(p).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Rename") { Task { await commit() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(VaultPath.problem(with: name) != nil || working)
            }
        }
        .padding(20)
        .frame(width: 380)
        .onAppear { name = item.name }
    }

    private func commit() async {
        guard VaultPath.problem(with: name) == nil else { return }
        working = true
        defer { working = false }
        if await session.rename(item, to: name) { dismiss() }
    }
}

struct NewFolderSheet: View {
    let session: VaultSession
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        Color.clear.frame(width: 1, height: 1).task {
            await session.newFolder()
            dismiss()
        }
    }
}

/// Folder picker inside the vault for "Move to…".
struct MoveToSheet: View {
    let session: VaultSession
    let paths: [String]
    @Environment(\.dismiss) private var dismiss
    @State private var dir = ""
    @State private var folders: [Item] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Move \(paths.count == 1 ? "“\(VaultPath.name(paths[0]))”" : "\(paths.count) items") to…").font(.headline)
                HStack(spacing: 4) {
                    Button {
                        dir = VaultPath.parent(dir)
                    } label: {
                        Image(systemName: "chevron.left")
                    }
                    .buttonStyle(.borderless)
                    .disabled(dir.isEmpty)
                    .accessibilityLabel("Up one folder")
                    Image(systemName: "folder").foregroundStyle(.secondary)
                    Text(dir.isEmpty ? session.name : dir).foregroundStyle(.secondary).lineLimit(1).truncationMode(.head)
                }
                .font(.callout)
            }
            .padding(16)
            Divider()
            List {
                ForEach(folders, id: \.path) { f in
                    let blocked = paths.contains { f.path == $0 || f.path.hasPrefix($0 + "/") }
                    Button {
                        dir = f.path
                    } label: {
                        HStack {
                            Image(nsImage: FileIcon.image(for: f.name, isDir: true)).resizable().frame(width: 18, height: 18)
                            Text(f.name)
                            Spacer()
                            Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(blocked)
                    .opacity(blocked ? 0.4 : 1)
                }
            }
            .overlay {
                if folders.isEmpty { Text("No subfolders").foregroundStyle(.secondary) }
            }
            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Move Here") {
                    let target = dir
                    dismiss()
                    Task { await session.move(paths, to: target) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(paths.allSatisfy { VaultPath.parent($0) == dir })
            }
            .padding(12)
        }
        .frame(width: 440, height: 420)
        .task(id: dir) {
            let r: ListResult? = try? await session.core.call(["op": "list", "id": session.vaultID, "path": dir])
            folders = (r?.items ?? []).filter(\.isDir).sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        }
        .onAppear { dir = session.isSearching ? "" : session.path }
    }
}

struct ImportReportSheet: View {
    let report: ImportReport
    let moved: Bool
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(moved ? "Move into vault finished" : "Import finished", systemImage: "checkmark.circle.fill")
                .font(.headline)
                .foregroundStyle(.primary)
            Text("\(Fmt.count(report.files, "file")) encrypted (\(Fmt.bytes(report.bytes)))" + (moved ? ", \(report.sourcesDeleted) originals removed." : "."))
            if !report.skipped.isEmpty {
                Text("Skipped (\(report.skipped.count))").font(.subheadline.weight(.semibold))
                List(report.skipped, id: \.self) { s in
                    Text(s).font(.callout).textSelection(.enabled)
                }
                .frame(minHeight: 140)
                Text(moved ? "Skipped items were left where they were." : "Skipped items weren’t added.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("OK") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520, height: report.skipped.isEmpty ? 150 : 400)
    }
}

// MARK: - App settings

struct AppSettingsView: View {
    @AppStorage(Pref.autoLockMinutes) private var autoLock = 10
    @AppStorage(Pref.lockOnSleep) private var lockOnSleep = true
    @AppStorage(Pref.screenCaptureProtection) private var captureProtection = true
    @AppStorage(Pref.importMode) private var importMode = ImportMode.copy.rawValue
    @AppStorage(Pref.skipMoveInConfirm) private var skipMoveConfirm = false
    @AppStorage(Pref.showThumbnails) private var showThumbnails = true

    var body: some View {
        Form {
            Section("Locking") {
                Picker("Lock vaults after", selection: $autoLock) {
                    Text("1 minute idle").tag(1)
                    Text("5 minutes idle").tag(5)
                    Text("10 minutes idle").tag(10)
                    Text("30 minutes idle").tag(30)
                    Text("Never").tag(0)
                }
                Toggle(isOn: $lockOnSleep) {
                    Text("Lock when the Mac sleeps or the screen locks")
                }
            }
            Section {
                Toggle(isOn: $captureProtection) {
                    Text("Hide Coffer windows from screenshots and screen sharing")
                    Text("Best-effort: some capture tools and newer macOS versions may ignore it.")
                }
                .onChange(of: captureProtection) { _, _ in WindowProtector.shared.applyAll() }
            } header: {
                Text("Privacy")
            }
            Section {
                Toggle(isOn: $showThumbnails) {
                    Text("Show image thumbnails")
                    Text("Decrypted in memory for the grid view; never written to disk.")
                }
                .onChange(of: showThumbnails) { _, on in if !on { ThumbnailStore.shared.purge() } }
            } header: {
                Text("Browsing")
            }
            Section {
                Picker("When adding files", selection: $importMode) {
                    Text("Copy into the vault").tag(ImportMode.copy.rawValue)
                    Text("Move into the vault").tag(ImportMode.move.rawValue)
                }
                Toggle("Ask before moving files into a vault", isOn: Binding(get: { !skipMoveConfirm }, set: { skipMoveConfirm = !$0 }))
            } header: {
                Text("Adding Files")
            } footer: {
                Text("Moving deletes each original after its encrypted copy has been verified. Hold ⌥ while dropping to use the other option.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 500)
        .fixedSize(horizontal: false, vertical: true)
        .navigationTitle("Coffer Settings")
    }
}
