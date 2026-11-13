import CofferKit
import SwiftUI

struct SidebarView: View {
    @Environment(AppModel.self) private var app

    var body: some View {
        let selection = Binding<SidebarItem?>(get: { app.selection }, set: { app.userSelect($0) })
        let synced = app.vaults.filter(\.synced).sortedByName()
        let local = app.vaults.filter { !$0.synced }.sortedByName()
        List(selection: selection) {
            if !synced.isEmpty {
                Section("Synced") {
                    ForEach(synced) { v in rows(for: v) }
                }
            }
            if !local.isEmpty {
                Section("On this Mac") {
                    ForEach(local) { v in rows(for: v) }
                }
            }
        }
        .listStyle(.sidebar)
        .overlay {
            if app.loaded && app.vaults.isEmpty {
                VStack(spacing: 6) {
                    Text("No Vaults").font(.headline).foregroundStyle(.secondary)
                    Text("Use + below to create one.").font(.callout).foregroundStyle(.tertiary)
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            SidebarFooter()
        }
    }

    @ViewBuilder
    private func rows(for v: VaultInfo) -> some View {
        VaultRow(vault: v, session: app.sessions[v.id])
            .tag(SidebarItem.vault(v.id))
            .contextMenu { VaultContextMenu(vault: v) }
        if let s = app.sessions[v.id] {
            Label {
                Text("Trash")
            } icon: {
                Image(systemName: "trash")
            }
            .badge(s.trash.count)
            .padding(.leading, 22)
            .tag(SidebarItem.trash(v.id))
            .accessibilityLabel("Trash of \(v.name)")
        }
    }
}

struct VaultContextMenu: View {
    let vault: VaultInfo
    @Environment(AppModel.self) private var app

    var body: some View {
        if vault.unlocked {
            Button("Lock") { Task { await app.lock(vault.id) } }
        }
        Button("Vault Settings…") { app.sheet = .vaultSettings(vault.id) }
        if vault.unlocked, vault.synced {
            Button("Sync Now") { app.sessions[vault.id]?.syncNow() }
            Button("Invite Someone…") { app.sheet = .vaultTask(vault.id, .invite) }
        }
        if vault.unlocked, !vault.synced {
            Button("Sync with a Server…") { app.sheet = .vaultTask(vault.id, .attach) }
        }
        Divider()
        Button("Remove from This Mac…", role: .destructive) { Task { await app.forget(vault.id) } }
    }
}

struct VaultRow: View {
    let vault: VaultInfo
    let session: VaultSession?

    var body: some View {
        HStack(spacing: 6) {
            Label {
                Text(vault.name).lineLimit(1)
            } icon: {
                Image(systemName: vault.synced ? "cloud.fill" : "internaldrive.fill")
                    .foregroundStyle(.tint)
            }
            Spacer(minLength: 4)
            SyncGlyph(vault: vault, status: session?.status)
            Image(systemName: vault.unlocked ? "lock.open.fill" : "lock.fill")
                .font(.caption)
                .foregroundStyle(vault.unlocked ? AnyShapeStyle(.secondary) : AnyShapeStyle(.tertiary))
                .contentTransition(.symbolEffect(.replace))
                .help(vault.unlocked ? "Unlocked" : "Locked")
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(vault.name), \(vault.unlocked ? "unlocked" : "locked")\(vault.missing ? ", folder missing" : "")")
    }
}

/// Small sync indicator for synced, unlocked vaults.
struct SyncGlyph: View {
    let vault: VaultInfo
    let status: VaultStatus?

    var body: some View {
        if vault.missing {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(.orange)
                .help("Vault folder not found")
        } else if vault.synced, let st = status {
            let pending = st.summary.pending
            switch st.sync.state {
            case "syncing":
                ProgressView().controlSize(.mini).help("Syncing")
            case "offline":
                HStack(spacing: 2) {
                    if pending > 0 { Text("\(pending)").font(.caption2.monospacedDigit()) }
                    Image(systemName: "icloud.slash")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .help(pending > 0 ? "Offline — \(pending) changes waiting" : "Offline")
            case "error":
                Image(systemName: "exclamationmark.icloud.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .help(st.sync.error.map(CofferError.readableSync) ?? "Sync error")
            case "rekeyed":
                Image(systemName: "key.horizontal.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .help("Keys rotated on another device — enter the new key to sync")
            default:
                if pending > 0 {
                    HStack(spacing: 2) {
                        Text("\(pending)").font(.caption2.monospacedDigit())
                        Image(systemName: "arrow.up.circle")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .help("\(pending) changes waiting to upload")
                } else {
                    Image(systemName: "checkmark.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .help("Up to date")
                }
            }
        }
    }
}

struct SidebarFooter: View {
    @Environment(AppModel.self) private var app
    @State private var showPosture = false

    var body: some View {
        HStack(spacing: 4) {
            Menu {
                Button("New Vault…") { app.sheet = .newVault }
                Button("Join Existing Vault…") { app.sheet = .joinVault }
            } label: {
                Image(systemName: "plus")
                    .frame(width: 24, height: 22)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .hoverHighlight()
            .help("Add a vault")
            .accessibilityLabel("Add a vault")

            Spacer()

            Button {
                showPosture.toggle()
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: app.posture.needsAttention ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                        .foregroundStyle(app.posture.needsAttention ? .orange : .green)
                    Text(app.posture.needsAttention ? "Check" : "Protected")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 6)
                .frame(height: 22)
            }
            .buttonStyle(.plain)
            .hoverHighlight()
            .help("Security status")
            .accessibilityLabel(app.posture.needsAttention ? "Security status: needs attention" : "Security status: protected")
            .popover(isPresented: $showPosture, arrowEdge: .top) {
                PostureView()
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }
}

struct PostureView: View {
    @Environment(AppModel.self) private var app
    @AppStorage(Pref.screenCaptureProtection) private var captureProtection = true

    private struct Row: Identifiable {
        let id: String
        let ok: Bool?
        let explanation: String
    }

    private var rows: [Row] {
        let p = app.posture
        return [
            Row(id: "Hardened runtime", ok: p.hardenedRuntime,
                explanation: p.hardenedRuntime == true ? "Other processes can’t inject code into Coffer." : "Not signed with the hardened runtime; code injection isn’t blocked."),
            Row(id: "Not debuggable", ok: p.debuggable.map { !$0 },
                explanation: p.debuggable == false ? "The signature doesn’t allow debuggers to attach." : "The signature allows debugging (development build)."),
            Row(id: "Debugger attach denied", ok: p.attachDenied,
                explanation: p.attachDenied ? "Coffer refuses debugger attachment at runtime." : "Runtime attach denial is off (debug build)."),
            Row(id: "Core dumps off", ok: p.coreDumpsOff,
                explanation: p.coreDumpsOff ? "A crash can’t write memory, including keys, to disk." : "A crash could write memory to disk."),
            Row(id: "System Integrity Protection", ok: p.sip,
                explanation: p.sip == true ? "macOS enforces the protections above, even against root." : (p.sip == false ? "SIP is off: the protections above can be bypassed." : "Couldn’t determine SIP status.")),
            Row(id: "Memory locking", ok: p.memoryLocked,
                explanation: p.memoryLocked ? "Key memory is kept out of swap." : "Keys could be swapped to disk (swap is encrypted on modern Macs)."),
            Row(id: "Secure Enclave", ok: app.seAvailable,
                explanation: app.seAvailable ? "Touch ID unlock keys never leave the Secure Enclave." : "Not available: Touch ID unlock is off."),
            Row(id: "Screen-capture protection", ok: captureProtection,
                explanation: captureProtection ? "Windows are hidden from screenshots and sharing (best-effort)." : "Off in Settings: windows can be captured."),
        ]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: app.posture.needsAttention ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                    .font(.title)
                    .foregroundStyle(app.posture.needsAttention ? .orange : .green)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Security Status").font(.headline)
                    Text(app.posture.needsAttention ? "Some protections are missing in this build." : "Coffer’s memory is protected from other apps.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            Divider()
            ForEach(rows) { r in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: r.ok == true ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundStyle(r.ok == true ? .green : .orange)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(r.id).font(.callout.weight(.medium))
                        Text(r.explanation).font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .accessibilityElement(children: .combine)
            }
        }
        .padding(16)
        .frame(width: 340)
    }
}
