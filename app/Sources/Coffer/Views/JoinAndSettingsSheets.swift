import AppKit
import CofferKit
import SwiftUI

struct JoinVaultSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss

    private enum Mode { case server, invite }

    @State private var mode = Mode.server
    @State private var url = ""
    @State private var vaultID = ""
    @State private var name = ""
    @State private var kind = SlotKind.recovery
    @State private var secret = ""
    @State private var invite = ""
    @State private var working = false
    @State private var error: String?
    @State private var joinedID: String?
    @State private var viaInvite = false
    /// One-time invite: this member's own recovery key, shown before anything else.
    @State private var joinedKey: String?

    /// Shape check only: "<server>#<32 hex vault id>#<key>".
    private var inviteProblem: String? {
        let parts = invite.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "#", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, !parts[2].isEmpty else { return "An invite is one line of three parts separated by “#”. Paste it exactly as you received it." }
        if serverURLProblem(parts[0]) != nil { return "The invite’s server address isn’t valid." }
        if !(parts[1].count == 32 && parts[1].allSatisfy(\.isHexDigit)) { return "The invite’s vault ID isn’t valid." }
        return nil
    }

    private var idProblem: String? {
        let t = vaultID.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return "Enter the vault ID." }
        return t.count == 32 && t.allSatisfy(\.isHexDigit) ? nil : "A vault ID is 32 hexadecimal characters (shown in Vault Settings on the other Mac)."
    }

    private var canJoin: Bool {
        guard !working else { return false }
        if mode == .invite { return !invite.isEmpty && inviteProblem == nil }
        return serverURLProblem(url) == nil && idProblem == nil && !secret.isEmpty
    }

    var body: some View {
        if let joinedID, let key = joinedKey {
            RecoveryKeyView(vaultName: name.isEmpty ? "Vault" : name, recoveryKey: key, hasOtherUnlock: false, note: nil,
                            subtitle: "You joined “\(name.isEmpty ? "Vault" : name)”.",
                            message: "The invite is used up and opens nothing now. This recovery key is your own way into the vault, on this Mac or another device. Coffer doesn’t keep a copy.",
                            doneTitle: "Continue") {
                withAnimation(.snappy) { joinedKey = nil }
            }
        } else if let joinedID {
            EnableTouchIDPrompt(vaultID: joinedID, title: "Vault Added", subtitle: "“\(name.isEmpty ? "Vault" : name)” is now on this Mac and syncing.",
                                note: viaInvite ? "Add a passphrase in Vault Settings → Unlock Methods if you’d rather not type the recovery key." : nil) {
                dismiss()
                Task { await app.didAddVault(joinedID) }
            }
        } else {
            form
        }
    }

    private var form: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "link.badge.plus", title: "Join Existing Vault", subtitle: "Add a synced vault from another device, or one you were invited to.")
            Picker("Join with", selection: $mode.animation(.snappy)) {
                Text("Server & Vault ID").tag(Mode.server)
                Text("I have an invite").tag(Mode.invite)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 20)
            .padding(.top, 10)
            if mode == .invite { inviteForm } else { serverForm }
            SheetFooter(error: error) {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button {
                    Task { await join() }
                } label: {
                    if working { ProgressView().controlSize(.small).padding(.horizontal, 6) } else { Text("Join") }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canJoin)
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var inviteForm: some View {
        Form {
            Section {
                SecureField("Invite", text: $invite, prompt: Text("Paste the invite"))
                    .font(.body.monospaced())
                    .onSubmit { if canJoin { Task { await join() } } }
                if !invite.isEmpty, let p = inviteProblem { Text(p).font(.caption).foregroundStyle(.red) }
                TextField("Name on this Mac", text: $name, prompt: Text("e.g. Family"))
            } footer: {
                Text("The one-line code the vault’s owner sent you. It works once and gives this Mac full access to the vault.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .disabled(working)
    }

    private var serverForm: some View {
            Form {
                Section {
                    TextField("Server", text: $url, prompt: Text("https://sync.example.com"))
                        .autocorrectionDisabled()
                    if !url.isEmpty, let p = serverURLProblem(url) { Text(p).font(.caption).foregroundStyle(.red) }
                    TextField("Vault ID", text: $vaultID, prompt: Text("32 characters"))
                        .font(.body.monospaced())
                        .autocorrectionDisabled()
                    if !vaultID.isEmpty, let p = idProblem { Text(p).font(.caption).foregroundStyle(.red) }
                    TextField("Name on this Mac", text: $name, prompt: Text("e.g. Personal"))
                } footer: {
                    Text("Find the server and vault ID in Vault Settings on the other device.").font(.caption).foregroundStyle(.secondary)
                }
                Section("Unlock With") {
                    Picker("Method", selection: $kind) {
                        Text("Recovery Key").tag(SlotKind.recovery)
                        Text("Passphrase").tag(SlotKind.passphrase)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    SecureField(kind == .recovery ? "Recovery key" : "Passphrase", text: $secret)
                        .font(kind == .recovery ? .body.monospaced() : .body)
                        .onSubmit { if canJoin { Task { await join() } } }
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .disabled(working)
    }

    private func join() async {
        working = true
        error = nil
        defer { working = false }
        if mode == .invite {
            let s = SecretBytes(utf8: invite.trimmingCharacters(in: .whitespacesAndNewlines))
            invite = ""
            defer { s.wipe() }
            do {
                let r: JoinInviteResult = try await app.core.call(["op": "join_invite", "name": name.trimmingCharacters(in: .whitespaces)], secret: s)
                await app.refreshVaults()
                viaInvite = true
                withAnimation(.snappy) {
                    joinedKey = r.recoveryKey
                    joinedID = r.id
                }
            } catch let e as CofferError where e.isWrongSecret {
                error = "That invite doesn’t open the vault. It may have been removed, or the keys were rotated."
            } catch let e as CofferError where e.inviteProblem != nil {
                error = e.inviteProblem
            } catch {
                self.error = error.localizedDescription
            }
            return
        }
        let text = kind == .recovery ? secret.trimmingCharacters(in: .whitespacesAndNewlines) : secret
        let s = SecretBytes(utf8: text)
        secret = ""
        defer { s.wipe() }
        do {
            let r: IDResult = try await app.core.call([
                "op": "join", "name": name.trimmingCharacters(in: .whitespaces), "url": url.trimmingCharacters(in: .whitespaces),
                "vault_id": vaultID.trimmingCharacters(in: .whitespaces), "kind": kind.rawValue,
            ], secret: s)
            await app.refreshVaults()
            withAnimation(.snappy) { joinedID = r.id }
        } catch let e as CofferError where e.isWrongSecret {
            error = kind == .recovery ? "That recovery key doesn’t open this vault." : "That passphrase doesn’t open this vault."
        } catch {
            self.error = error.localizedDescription
        }
    }
}

/// After join (or from settings): offer Touch ID.
struct EnableTouchIDPrompt: View {
    let vaultID: String
    let title: String
    let subtitle: String
    var note: String? = nil
    let done: () -> Void
    @Environment(AppModel.self) private var app
    @State private var working = false
    @State private var error: String?
    @State private var enabled = false

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "checkmark.circle", title: title, subtitle: subtitle)
            if app.seAvailable {
                HStack(spacing: 14) {
                    Image(systemName: app.biometry ? "touchid" : "lock.open")
                        .font(.system(size: 36))
                        .foregroundStyle(.tint)
                        .symbolRenderingMode(.hierarchical)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Unlock with \(app.touchIDName)?").font(.headline)
                        Text("A key in this Mac’s Secure Enclave unlocks the vault. It never leaves this Mac.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if enabled {
                        Label("Enabled", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    } else {
                        Button("Enable") {
                            Task {
                                working = true
                                defer { working = false }
                                do {
                                    try await app.enableTouchID(vaultID)
                                    enabled = true
                                } catch {
                                    self.error = error.localizedDescription
                                }
                            }
                        }
                        .disabled(working)
                    }
                }
                .padding(20)
            }
            if let note {
                Label(note, systemImage: "info.circle")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 16)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            SheetFooter(error: error) {
                Button("Done", action: done).keyboardShortcut(.defaultAction)
            }
        }
        .frame(width: 500)
        .fixedSize(horizontal: false, vertical: true)
    }
}

struct EnableTouchIDSheet: View {
    let vaultID: String
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        EnableTouchIDPrompt(vaultID: vaultID, title: "Touch ID", subtitle: "Unlock this vault without typing.") { dismiss() }
    }
}

// MARK: - Vault settings

struct VaultSettingsSheet: View {
    let vaultID: String
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var addingPassphrase = false
    @State private var newPass = ""
    @State private var confirmPass = ""
    @State private var working = false
    @State private var error: String?
    @State private var task: VaultTask?
    @State private var invites: [InviteStatus] = []

    private var vault: VaultInfo? { app.vault(vaultID) }
    private var session: VaultSession? { app.sessions[vaultID] }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "gearshape", title: "Vault Settings", subtitle: vault?.name ?? "")
            if let v = vault {
                Form {
                    general(v)
                    sync(v)
                    slots(v)
                    if v.synced { sharing(v) }
                    security(v)
                    Section {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Remove from This Mac")
                                Text("Locks the vault and removes it from Coffer. The encrypted folder stays until you trash it.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Remove…", role: .destructive) {
                                dismiss()
                                Task {
                                    try? await Task.sleep(for: .milliseconds(300))
                                    await app.forget(vaultID)
                                }
                            }
                        }
                    }
                }
                .formStyle(.grouped)
                .scrollContentBackground(.hidden)
                .disabled(working)
            }
            SheetFooter(error: error) {
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .frame(width: 580, height: 660)
        .onAppear { name = vault?.name ?? "" }
        .task(id: vault?.synced) {
            await session?.refreshUsage()
            await loadInvites()
        }
        .onChange(of: task) { _, t in if t == nil { Task { await loadInvites() } } }
        .sheet(item: $task) { t in
            VaultTaskSheet(vaultID: vaultID, task: t)
                .environment(app)
        }
    }

    @ViewBuilder
    private func general(_ v: VaultInfo) -> some View {
        Section("General") {
            HStack {
                TextField("Name", text: $name)
                    .onSubmit { Task { await rename() } }
                if name.trimmingCharacters(in: .whitespaces) != v.name {
                    Button("Rename") { Task { await rename() } }
                        .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            CopyRow(label: "Vault ID", value: v.id, mono: true)
            LabeledContent("Location") {
                Button(URL(fileURLWithPath: v.path).lastPathComponent) {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: v.path)])
                }
                .buttonStyle(.link)
                .help("Show the encrypted folder in Finder")
            }
        }
    }

    @ViewBuilder
    private func sync(_ v: VaultInfo) -> some View {
        Section {
            if let remote = v.remote {
                CopyRow(label: "Sync server", value: remote, mono: false)
                if v.unlocked { usageRow }
            } else {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Local only — not synced")
                        Text(v.unlocked ? "Upload this vault, encrypted, to a sync server to use it on other devices." : "Unlock the vault to connect it to a server.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Sync This Vault with a Server…") { task = .attach }
                        .disabled(!v.unlocked)
                }
            }
        } header: {
            Text("Sync")
        } footer: {
            if v.remote != nil {
                Text("To use this vault on another Mac, choose Join Existing Vault there and enter the server, vault ID and your recovery key or passphrase, or send an invite.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var usageRow: some View {
        if let u = session?.usage {
            VStack(alignment: .leading, spacing: 5) {
                LabeledContent("Storage") {
                    Text(u.quota.map { "\(Fmt.bytes(u.bytes)) on server (of \(Fmt.bytes($0)))" } ?? "\(Fmt.bytes(u.bytes)) on server")
                        .monospacedDigit()
                }
                if let q = u.quota, q > 0 {
                    let frac = min(Double(u.bytes) / Double(q), 1)
                    ProgressView(value: frac)
                        .progressViewStyle(.linear)
                        .controlSize(.small)
                        .tint(frac > 0.9 ? .red : (frac > 0.75 ? .orange : .accentColor))
                        .accessibilityLabel("Server storage used")
                        .accessibilityValue("\(Int(frac * 100)) percent")
                }
            }
        } else {
            LabeledContent("Storage", value: "—")
        }
    }

    @ViewBuilder
    private func sharing(_ v: VaultInfo) -> some View {
        Section {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Invite someone")
                    Text("Creates a one-line invite with full read and write access.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Invite Someone…") { task = .invite }
                    .disabled(!v.unlocked || session?.status?.isRekeyed == true)
            }
            ForEach(invites) { i in
                HStack {
                    Image(systemName: inviteSymbol(i))
                        .foregroundStyle(i.state == "used" ? AnyShapeStyle(.green) : (i.isWaiting ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary)))
                        .frame(width: 20)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(i.label.isEmpty ? "Invite" : i.label)
                        Text(inviteLine(i)).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if i.isWaiting {
                        Button("Revoke") { Task { await revoke(i) } }
                    }
                }
            }
        } header: {
            Text("Sharing")
        } footer: {
            Text("An invite works once, within 24 hours. A used, expired or revoked invite opens nothing. To cut off someone who already joined, rotate keys.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func inviteSymbol(_ i: InviteStatus) -> String {
        switch i.state {
        case "waiting": return "clock"
        case "used": return "checkmark.circle"
        default: return "xmark.circle"
        }
    }

    private func inviteLine(_ i: InviteStatus) -> String {
        switch i.state {
        case "waiting": return "Not used yet · expires \(Fmt.date(i.expires))"
        case "used": return "Used \(Fmt.date(i.claimed ?? i.created))"
        case "revoked": return "Revoked \(Fmt.date(i.revoked ?? i.created))"
        default: return "Expired unused \(Fmt.date(i.expires))"
        }
    }

    private func loadInvites() async {
        guard let v = vault, v.synced, v.unlocked else { invites = []; return }
        invites = (try? await app.core.call(["op": "invites", "id": vaultID]) as [InviteStatus]) ?? []
    }

    private func revoke(_ i: InviteStatus) async {
        let ok = await Alerts.confirm("Revoke the invite “\(i.label.isEmpty ? "Invite" : i.label)”?", "Nobody can join with it any more.", action: "Revoke")
        guard ok else { return }
        do {
            let _: Nothing = try await app.core.call(["op": "revoke_invite", "id": vaultID, "invite": i.id])
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        await loadInvites()
    }

    @ViewBuilder
    private func security(_ v: VaultInfo) -> some View {
        Section {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(session?.status?.isRotationPending == true ? "Key rotation not finished" : "Rotate keys")
                    Text("New keys; revokes every passphrase, the recovery key\(v.synced ? ", every invite and every other device" : "") and \(app.touchIDName) on this Mac (set up again automatically).")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button(session?.status?.isRotationPending == true ? "Finish…" : "Rotate Keys…") {
                    task = session?.status?.isRotationPending == true ? .finishRotation : .rotate
                }
                .disabled(!v.unlocked || session?.status?.isRekeyed == true)
            }
        } header: {
            Text("Security")
        } footer: {
            if !v.unlocked {
                Text("Unlock the vault to rotate its keys.").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private func slots(_ v: VaultInfo) -> some View {
        Section {
            ForEach(v.slots) { slot in
                HStack(spacing: 10) {
                    Image(systemName: icon(slot))
                        .foregroundStyle(isInvite(slot) ? AnyShapeStyle(.orange) : AnyShapeStyle(.tint))
                        .frame(width: 20)
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 6) {
                            Text(slot.label)
                            if slot.kind == .secureEnclave, app.touchIDSlot(for: v)?.id == slot.id {
                                Text("This Mac").font(.caption2.weight(.semibold)).padding(.horizontal, 5).background(Capsule().fill(Color.accentColor.opacity(0.15))).foregroundStyle(.tint)
                            }
                        }
                        Text(isInvite(slot) ? "Invite · full access · created \(Fmt.date(slot.created))" : "Added \(Fmt.date(slot.created))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if v.unlocked {
                        Button("Remove…") { Task { await remove(slot, in: v) } }
                            .controlSize(.small)
                    }
                }
            }
            if v.unlocked {
                if addingPassphrase {
                    SecureField("New passphrase", text: $newPass)
                    SecureField("Confirm", text: $confirmPass)
                    HStack {
                        let s = Strength.of(newPass)
                        Text(s.label).font(.caption).foregroundStyle(s.color)
                        if !confirmPass.isEmpty && confirmPass != newPass {
                            Text("Passphrases don’t match").font(.caption).foregroundStyle(.red)
                        }
                        Spacer()
                        Button("Cancel") { addingPassphrase = false; newPass = ""; confirmPass = "" }
                        Button("Add Passphrase") { Task { await addPassphrase() } }
                            .disabled(newPass.isEmpty || newPass != confirmPass)
                    }
                } else {
                    HStack {
                        Button("Add Passphrase…") { addingPassphrase = true }
                        if app.seAvailable && app.touchIDSlot(for: v) == nil {
                            Button("Enable \(app.touchIDName)") {
                                Task {
                                    working = true
                                    defer { working = false }
                                    do { try await app.enableTouchID(vaultID) } catch { self.error = error.localizedDescription }
                                }
                            }
                        }
                    }
                }
            }
        } header: {
            Text("Unlock Methods")
        } footer: {
            Text(v.unlocked
                 ? "Passphrase and recovery key work on any device. \(app.touchIDName) works only on the Mac that set it up. At least one passphrase or recovery key must remain."
                 : "Unlock the vault to change its unlock methods.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    /// Invites are recovery-type slots the core labels "Invite" / "Invite: <name>".
    private func isInvite(_ s: SlotInfo) -> Bool { s.kind == .recovery && s.label.hasPrefix("Invite") }

    private func icon(_ s: SlotInfo) -> String {
        if isInvite(s) { return "person.badge.key" }
        switch s.kind {
        case .passphrase: return "character.cursor.ibeam"
        case .recovery: return "key.horizontal"
        case .secureEnclave: return "touchid"
        case .unknown: return "questionmark.circle"
        }
    }

    private func rename() async {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty, n != vault?.name else { return }
        do {
            try await app.core.perform(["op": "rename_vault", "id": vaultID, "name": n])
            await app.refreshVaults()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func addPassphrase() async {
        guard !newPass.isEmpty, newPass == confirmPass else { return }
        working = true
        defer { working = false }
        let s = SecretBytes(utf8: newPass)
        newPass = ""
        confirmPass = ""
        defer { s.wipe() }
        do {
            let _: SlotResult = try await app.core.call(["op": "slot_add", "id": vaultID, "kind": "passphrase", "label": "Passphrase"], secret: s)
            addingPassphrase = false
            error = nil
            await app.refreshVaults()
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func remove(_ slot: SlotInfo, in v: VaultInfo) async {
        let title: String
        let consequence: String
        if isInvite(slot) {
            title = "Remove the invite “\(slot.label)”?"
            consequence = "The invite can no longer be used to join this vault.\n\nThis does not revoke anyone who already joined with it: their device keeps full access. To cut them off, rotate the vault’s keys (Vault Settings → Security)."
        } else {
            title = "Remove “\(slot.label)”?"
            switch slot.kind {
            case .recovery: consequence = "The recovery key you saved will no longer open this vault."
            case .passphrase: consequence = "This passphrase will no longer open this vault on any device."
            case .secureEnclave: consequence = "\(app.touchIDName) on that Mac will no longer open this vault."
            case .unknown: consequence = "It will no longer open this vault."
            }
        }
        let ok = await Alerts.confirm(title, consequence, action: isInvite(slot) ? "Remove Invite" : "Remove")
        guard ok else { return }
        do {
            try await app.core.perform(["op": "slot_remove", "id": vaultID, "slot": slot.id])
            if UserDefaults.standard.string(forKey: Pref.seSlotKey(vaultID)) == slot.id {
                UserDefaults.standard.removeObject(forKey: Pref.seSlotKey(vaultID))
            }
            error = nil
            await app.refreshVaults()
        } catch {
            // e.g. the core refuses to remove the last portable slot.
            self.error = error.localizedDescription
        }
    }
}

struct CopyRow: View {
    let label: String
    let value: String
    let mono: Bool
    @State private var copied = false

    var body: some View {
        LabeledContent(label) {
            HStack(spacing: 6) {
                Text(value)
                    .font(mono ? .callout.monospaced() : .callout)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy \(label.lowercased())")
                .accessibilityLabel("Copy \(label)")
            }
        }
    }
}
