import AppKit
import CofferKit
import CoreImage.CIFilterBuiltins
import SwiftUI

/// Vault-level flows opened from Vault Settings, the menu bar or a banner.
enum VaultTask: String, Identifiable {
    case attach, rotate, finishRotation, invite, adoptRekey
    var id: String { rawValue }
}

struct VaultTaskSheet: View {
    let vaultID: String
    let task: VaultTask
    @Environment(AppModel.self) private var app

    var body: some View {
        if app.sessions[vaultID] == nil {
            LockedSheetNotice()
        } else {
            switch task {
            case .attach: AttachSheet(vaultID: vaultID)
            case .rotate: RotateKeysSheet(vaultID: vaultID, resume: false)
            case .finishRotation: RotateKeysSheet(vaultID: vaultID, resume: true)
            case .invite: InviteSheet(vaultID: vaultID)
            case .adoptRekey: AdoptRekeySheet(vaultID: vaultID)
            }
        }
    }
}

// MARK: - Sync a local vault with a server

struct AttachSheet: View {
    let vaultID: String
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var url = ""
    @State private var token = ""
    @State private var working = false
    @State private var error: String?
    @State private var done = false

    private var session: VaultSession? { app.sessions[vaultID] }
    private var name: String { app.vault(vaultID)?.name ?? "Vault" }

    var body: some View {
        if done {
            VStack(spacing: 0) {
                SheetHeader(icon: "checkmark.icloud", title: "Vault Is Now Synced", subtitle: "“\(name)” is on \(URL(string: url)?.host ?? "the server").")
                Text("Changes now sync automatically. To use the vault on another device, choose Join Existing Vault there, or send an invite from Vault Settings → Sharing.")
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                SheetFooter(error: nil) {
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            }
            .frame(width: 520)
            .fixedSize(horizontal: false, vertical: true)
        } else {
            form
        }
    }

    private var form: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "icloud.and.arrow.up", title: "Sync This Vault with a Server", subtitle: "Uploads “\(name)”, encrypted, with its kept history.")
            Form {
                Section {
                    TextField("Server", text: $url, prompt: Text("https://sync.example.com"))
                        .textContentType(.URL)
                        .autocorrectionDisabled()
                    if !url.isEmpty, let p = serverURLProblem(url) {
                        Text(p).font(.caption).foregroundStyle(.red)
                    }
                    SecureField("Enrollment token", text: $token, prompt: Text("From your server administrator"))
                } footer: {
                    Text("The server only ever sees encrypted data. While the upload runs, the vault is read-only; if it’s interrupted, choose Retry to continue where it stopped.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if working {
                    Section {
                        progress
                    }
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .disabled(working)
            SheetFooter(error: error) {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(working)
                Button {
                    Task { await attach() }
                } label: {
                    Text(error == nil ? "Start Syncing" : "Retry")
                }
                .keyboardShortcut(.defaultAction)
                .disabled(serverURLProblem(url) != nil || working)
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
        .interactiveDismissDisabled(working)
    }

    @ViewBuilder
    private var progress: some View {
        if let a = session?.status?.activity, a.total > 0 {
            VStack(alignment: .leading, spacing: 6) {
                ProgressView(value: Double(a.done), total: Double(a.total))
                HStack {
                    Text(a.label).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text("\(a.done) of \(a.total)").monospacedDigit()
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        } else {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Connecting to the server…").foregroundStyle(.secondary)
            }
        }
    }

    private func attach() async {
        guard serverURLProblem(url) == nil else { return }
        working = true
        error = nil
        session?.busy += 1
        defer {
            working = false
            session?.busy -= 1
        }
        do {
            try await app.core.perform(["op": "attach", "id": vaultID, "url": url.trimmingCharacters(in: .whitespaces), "token": token])
            token = ""
            await app.refreshVaults()
            await session?.poll()
            withAnimation(.snappy) { done = true }
        } catch {
            self.error = error.localizedDescription
        }
    }
}

// MARK: - Key rotation

struct RotateKeysSheet: View {
    let vaultID: String
    /// Pick up a rotation that was prepared earlier (the staged key is shown again).
    let resume: Bool
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss

    private enum Step { case intro, preparing, key, done }

    @State private var step = Step.intro
    @State private var usePass = false
    @State private var pass = ""
    @State private var confirm = ""
    @State private var recoveryKey: String?
    @State private var committing = false
    @State private var error: String?
    @State private var resumed = false
    @State private var hadTouchID = false
    @State private var touchIDNote: String?
    @State private var newPassphrase = false
    /// The server holds a newer header than this Mac has seen (core only re-reads it on unlock).
    @State private var staleHeader = false

    private var vault: VaultInfo? { app.vault(vaultID) }
    private var name: String { vault?.name ?? "Vault" }
    private var synced: Bool { vault?.synced ?? false }
    private var passOK: Bool { !usePass || (!pass.isEmpty && pass == confirm) }

    var body: some View {
        Group {
            switch step {
            case .intro: intro
            case .preparing: preparing
            case .key: keyStep
            case .done: finished
            }
        }
        .onAppear {
            app.rotationSheetVault = vaultID
            if let v = vault { hadTouchID = app.touchIDSlot(for: v) != nil }
            if resume || app.sessions[vaultID]?.status?.isRotationPending == true {
                resumed = true
                Task { await prepare() }
            }
        }
        .onDisappear {
            if app.rotationSheetVault == vaultID { app.rotationSheetVault = nil }
            pass = ""
            confirm = ""
        }
    }

    private var intro: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "arrow.triangle.2.circlepath", title: "Rotate Keys", subtitle: "Give “\(name)” new keys and cut off old ones.")
            Form {
                Section {
                    bullet("xmark.circle", "Every passphrase, the current recovery key\(synced ? ", every invite and every other device" : "") stop working.")
                    if synced {
                        bullet("laptopcomputer.and.iphone", "Your other devices pause syncing until the new recovery key or passphrase is entered on each of them.")
                    }
                    if hadTouchID {
                        bullet("touchid", "\(app.touchIDName) on this Mac is set up again automatically.")
                    }
                    bullet("exclamationmark.triangle", "Files already on a revoked device stay readable there. Rotation protects changes made from now on.")
                } header: {
                    Text("What Happens")
                }
                Section {
                    Toggle(isOn: $usePass.animation(.snappy)) {
                        Text("Set a new passphrase")
                        Text("Without one, only the new recovery key\(hadTouchID ? " and \(app.touchIDName)" : "") open the vault.")
                    }
                    if usePass {
                        SecureField("New passphrase", text: $pass)
                        SecureField("Confirm", text: $confirm)
                        let s = Strength.of(pass)
                        if s != .empty || (!confirm.isEmpty && confirm != pass) {
                            HStack {
                                if s != .empty { Text(s.label).foregroundStyle(s.color) }
                                Spacer()
                                if !confirm.isEmpty && confirm != pass {
                                    Text("Passphrases don’t match").foregroundStyle(.red)
                                }
                            }
                            .font(.caption)
                        }
                    }
                } header: {
                    Text("New Passphrase")
                } footer: {
                    Text("Next you’ll see the new recovery key. Nothing changes until you confirm you stored it.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            SheetFooter(error: error) {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Continue") { Task { await prepare() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!passOK)
            }
        }
        .frame(width: 540)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func bullet(_ icon: String, _ text: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: icon).foregroundStyle(.secondary)
        }
    }

    private var preparing: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "arrow.triangle.2.circlepath", title: "Rotate Keys", subtitle: name)
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text(resumed ? "Loading the prepared keys…" : "Preparing new keys…").foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 120)
            SheetFooter(error: error) {
                if error != nil {
                    Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Try Again") { Task { await prepare() } }.keyboardShortcut(.defaultAction)
                }
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private var keyStep: some View {
        if let key = recoveryKey {
            RecoveryKeyView(
                vaultName: name,
                recoveryKey: key,
                hasOtherUnlock: newPassphrase || hadTouchID,
                note: resumed ? "A rotation was already prepared; this is its recovery key. A passphrase set then still applies." : nil,
                title: "Save the New Recovery Key",
                subtitle: "Nothing has changed yet.",
                message: "When you rotate, this key replaces the current recovery key of “\(name)”. Vaultage doesn’t keep a copy.",
                doneTitle: committing ? "Rotating…" : "Rotate Keys",
                working: committing,
                error: error,
                secondaryTitle: staleHeader ? "Cancel and Lock Vault" : "Cancel Rotation",
                secondary: { Task { await cancelRotation(lock: staleHeader) } },
                done: { Task { await commit() } })
        }
    }

    private var finished: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "checkmark.shield", title: "Keys Rotated", subtitle: "“\(name)” now uses new keys.")
            VStack(alignment: .leading, spacing: 10) {
                if synced {
                    bullet("laptopcomputer.and.iphone", "On each of your other devices, open Vaultage and enter the new recovery key\(newPassphrase ? " or the new passphrase" : "") when asked. They don’t sync until then.")
                    bullet("person.badge.key", "Anyone you invited before needs a new invite.")
                } else {
                    bullet("key.horizontal", "Use the new recovery key\(newPassphrase ? " or the new passphrase" : "") to unlock from now on.")
                }
                if hadTouchID && touchIDNote == nil {
                    bullet("touchid", "\(app.touchIDName) on this Mac was set up again.")
                }
                if let touchIDNote {
                    Label(touchIDNote, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            SheetFooter(error: nil) {
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func prepare() async {
        error = nil
        step = .preparing
        let secret = usePass && !resumed ? SecretBytes(utf8: pass) : SecretBytes(count: 0)
        defer { secret.wipe() }
        do {
            let r: RecoveryKeyResult = try await app.core.call(["op": "rotate_prepare", "id": vaultID], secret: secret)
            if !resumed { newPassphrase = usePass }
            pass = ""
            confirm = ""
            recoveryKey = r.recoveryKey
            await app.sessions[vaultID]?.poll()
            withAnimation(.snappy) { step = .key }
        } catch {
            self.error = error.localizedDescription
            if !resumed { step = .intro }
        }
    }

    private func commit() async {
        committing = true
        error = nil
        let session = app.sessions[vaultID]
        session?.busy += 1
        defer {
            committing = false
            session?.busy -= 1
        }
        do {
            try await app.core.perform(["op": "rotate_commit", "id": vaultID])
        } catch let e as CofferError where e.code == "server" && e.message.contains("stale header") {
            staleHeader = true
            error = "Another device changed this vault’s unlock methods since you unlocked it here. Cancel, lock and unlock the vault, then rotate again."
            return
        } catch {
            // The staged key stays on disk and on screen; the user can retry.
            self.error = error.localizedDescription
            return
        }
        recoveryKey = nil
        touchIDNote = await app.keysReplaced(vaultID, recreateTouchID: hadTouchID)
        withAnimation(.snappy) { step = .done }
    }

    private func cancelRotation(lock: Bool = false) async {
        do {
            try await app.core.perform(["op": "rotate_cancel", "id": vaultID])
            recoveryKey = nil
            await app.sessions[vaultID]?.poll()
            dismiss()
            if lock { await app.lock(vaultID) }
        } catch {
            self.error = error.localizedDescription
        }
    }
}

// MARK: - Invite

struct InviteSheet: View {
    let vaultID: String
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var label = ""
    @State private var working = false
    @State private var error: String?
    @State private var code: String?
    @State private var copied = false

    private var name: String { app.vault(vaultID)?.name ?? "Vault" }

    var body: some View {
        if let code {
            ready(code)
        } else {
            form
        }
    }

    private var form: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "person.badge.plus", title: "Invite Someone", subtitle: "Let another person or device join “\(name)”.")
            Form {
                Section {
                    TextField("For", text: $label, prompt: Text("e.g. Alex, or Work MacBook"))
                        .onSubmit { if !working { Task { await create() } } }
                } footer: {
                    Text("The name appears under Sharing, where you can see whether the invite was used and revoke it. The invite works once, for 24 hours, and gives full read and write access.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if working {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Creating the invite on the server…").foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .disabled(working)
            SheetFooter(error: error) {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).disabled(working)
                Button("Create Invite") { Task { await create() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(working)
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
        .interactiveDismissDisabled(working)
    }

    private func ready(_ code: String) -> some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "person.badge.key", title: "Invite Ready", subtitle: label.isEmpty ? "For “\(name)”" : "For \(label.trimmingCharacters(in: .whitespaces))")
            VStack(alignment: .leading, spacing: 14) {
                if let qr = InviteQRCode.image(for: code) {
                    Image(nsImage: qr)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 220, height: 220)
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(.white))
                        .frame(maxWidth: .infinity)
                        .accessibilityLabel("Invite QR code")
                    Text("On the iPhone: Join Existing Vault → Invite → Scan QR Code.")
                        .font(.caption).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                }
                Text(code)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .lineLimit(nil)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(.quaternary.opacity(0.5)))
                    .accessibilityLabel("Invite code")
                HStack {
                    Button {
                        SecretPasteboard.copy(code) { copied = $0 }
                    } label: {
                        Label(copied ? "Copied — clears in 60 s" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                    }
                    Spacer()
                }
                Label {
                    Text("Works once, within 24 hours. Whoever uses it first can open “\(name)” and read, change or delete every file. Scanning the code keeps it off chats and clipboards; otherwise send it over a channel you trust. On their device: Join Existing Vault → I have an invite.\n\nOnce used, the line opens nothing. If your recipient is told it was already used, someone else got it first: rotate the vault’s keys. Revoke an unused invite in Vault Settings → Sharing.")
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                .font(.callout)
            }
            .padding(20)
            SheetFooter(error: nil) {
                Button("Done") {
                    self.code = nil
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .frame(width: 540)
        .fixedSize(horizontal: false, vertical: true)
        .interactiveDismissDisabled()
    }

    private func create() async {
        working = true
        error = nil
        defer { working = false }
        do {
            let r: CodeResult = try await app.core.call(["op": "invite", "id": vaultID, "label": label.trimmingCharacters(in: .whitespaces)])
            await app.refreshVaults()
            withAnimation(.snappy) { code = r.code }
        } catch {
            self.error = error.localizedDescription
        }
    }
}

/// Crisp QR code: generated at module size 1, scaled by an integer factor, drawn without smoothing.
enum InviteQRCode {
    static func image(for text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cg = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: scaled.extent.width, height: scaled.extent.height))
    }
}

// MARK: - Keys rotated on another device

struct AdoptRekeySheet: View {
    let vaultID: String
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @State private var kind = SlotKind.recovery
    @State private var secret = ""
    @State private var working = false
    @State private var error: String?
    @State private var adopted = false
    @State private var note: String?

    private var name: String { app.vault(vaultID)?.name ?? "Vault" }

    var body: some View {
        if adopted {
            EnableTouchIDPrompt(vaultID: vaultID, title: "Syncing Again", subtitle: "“\(name)” uses the new keys on this Mac.", note: note) { dismiss() }
        } else {
            form
        }
    }

    private var form: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "key.horizontal", title: "Enter the New Key", subtitle: "This vault’s keys were rotated on another device.")
            Form {
                Section {
                    Text("Until you enter the new recovery key or passphrase, this Mac can’t sync “\(name)”. Files already here stay readable. Ask whoever rotated the keys if you don’t have them.")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Section("Unlock With") {
                    Picker("Method", selection: $kind) {
                        Text("New Recovery Key").tag(SlotKind.recovery)
                        Text("New Passphrase").tag(SlotKind.passphrase)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    SecureField(kind == .recovery ? "Recovery key" : "Passphrase", text: $secret)
                        .font(kind == .recovery ? .body.monospaced() : .body)
                        .onSubmit { if !secret.isEmpty { Task { await adopt() } } }
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .disabled(working)
            SheetFooter(error: error) {
                Button("Later") { dismiss() }.keyboardShortcut(.cancelAction)
                Button {
                    Task { await adopt() }
                } label: {
                    if working { ProgressView().controlSize(.small).padding(.horizontal, 8) } else { Text("Continue") }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(secret.isEmpty || working)
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func adopt() async {
        working = true
        error = nil
        defer { working = false }
        let text = kind == .recovery ? secret.trimmingCharacters(in: .whitespacesAndNewlines) : secret
        let s = SecretBytes(utf8: text)
        secret = ""
        defer { s.wipe() }
        let hadTouchID = app.vault(vaultID).map { app.touchIDSlot(for: $0) != nil } ?? false
        do {
            try await app.core.perform(["op": "adopt_rekey", "id": vaultID, "kind": kind.rawValue], secret: s)
        } catch let e as CofferError where e.isWrongSecret {
            error = kind == .recovery ? "That recovery key doesn’t open the rotated vault." : "That passphrase doesn’t open the rotated vault."
            return
        } catch {
            self.error = error.localizedDescription
            return
        }
        _ = await app.keysReplaced(vaultID, recreateTouchID: false)
        note = hadTouchID ? "The rotation removed this Mac’s \(app.touchIDName) unlock. Enable it again below." : nil
        withAnimation(.snappy) { adopted = true }
    }
}
