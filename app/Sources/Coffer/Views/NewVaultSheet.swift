import AppKit
import CofferKit
import SwiftUI

/// Client-side check mirroring the core's rules: https://host[:port], http only for loopback.
func serverURLProblem(_ raw: String) -> String? {
    let s = raw.trimmingCharacters(in: .whitespaces)
    if s.isEmpty { return "Enter the sync server’s address." }
    guard let comps = URLComponents(string: s), let scheme = comps.scheme?.lowercased(), let host = comps.host, !host.isEmpty else {
        return "Use the form https://host or https://host:port."
    }
    if !(comps.path.isEmpty || comps.path == "/") || comps.query != nil || comps.fragment != nil || comps.user != nil {
        return "Enter just the server address, without a path."
    }
    let loopback = ["localhost", "127.0.0.1", "::1"].contains(host)
    switch scheme {
    case "https": return nil
    case "http": return loopback ? nil : "Use https:// — unencrypted http:// is only allowed for localhost."
    default: return "The address must start with https://."
    }
}

struct NewVaultSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss

    private enum Kind: String { case local, synced }

    @State private var name = ""
    @State private var kind = Kind.local
    @State private var url = ""
    @State private var token = ""
    @State private var useTouchID = SecureEnclaveSlot.isAvailable
    @State private var usePassphrase = false
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var working = false
    @State private var error: String?
    @State private var created: (id: String, key: String)?
    @State private var touchIDWarning: String?

    private var nameOK: Bool { !name.trimmingCharacters(in: .whitespaces).isEmpty }
    private var urlProblem: String? { kind == .synced ? serverURLProblem(url) : nil }
    private var passOK: Bool { !usePassphrase || (!passphrase.isEmpty && passphrase == confirm) }
    private var canCreate: Bool { nameOK && urlProblem == nil && passOK && !working }

    var body: some View {
        if let created {
            RecoveryKeyView(vaultName: name.trimmingCharacters(in: .whitespaces), recoveryKey: created.key, hasOtherUnlock: usePassphrase, note: touchIDWarning) {
                let id = created.id
                self.created = nil
                dismiss()
                Task { await app.didAddVault(id) }
            }
        } else {
            form
        }
    }

    private var form: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "lock.rectangle.stack", title: "New Vault", subtitle: "Files in a vault are encrypted on this Mac with a key only you hold.")
            Form {
                Section {
                    TextField("Name", text: $name, prompt: Text("e.g. Personal"))
                    Picker("Stored", selection: $kind) {
                        Text("On this Mac only").tag(Kind.local)
                        Text("Synced").tag(Kind.synced)
                    }
                    .pickerStyle(.segmented)
                }
                if kind == .synced {
                    Section {
                        TextField("Server", text: $url, prompt: Text("https://sync.example.com"))
                            .textContentType(.URL)
                            .autocorrectionDisabled()
                        if !url.isEmpty, let p = urlProblem {
                            Text(p).font(.caption).foregroundStyle(.red)
                        }
                        SecureField("Enrollment token", text: $token, prompt: Text("From your server administrator"))
                    } header: {
                        Text("Sync Server")
                    } footer: {
                        Text("The server only ever sees encrypted data.").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section("Unlocking") {
                    if app.seAvailable {
                        Toggle(isOn: $useTouchID) {
                            Text("Unlock with \(app.touchIDName)")
                            Text("Uses this Mac’s Secure Enclave. Works only on this Mac.")
                        }
                    }
                    Toggle(isOn: $usePassphrase.animation(.snappy)) {
                        Text("Passphrase")
                        Text("Works on any device. Needed to join from another Mac without the recovery key.")
                    }
                    if usePassphrase {
                        SecureField("Passphrase", text: $passphrase)
                        SecureField("Confirm", text: $confirm)
                        let s = Strength.of(passphrase)
                        if s != .empty || (!confirm.isEmpty && confirm != passphrase) {
                            HStack {
                                if s != .empty {
                                    Text(s.label).foregroundStyle(s.color)
                                }
                                Spacer()
                                if !confirm.isEmpty && confirm != passphrase {
                                    Text("Passphrases don’t match").foregroundStyle(.red)
                                }
                            }
                            .font(.caption)
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .disabled(working)
            SheetFooter(error: error) {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button {
                    Task { await create() }
                } label: {
                    if working { ProgressView().controlSize(.small).padding(.horizontal, 12) } else { Text("Create Vault") }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canCreate)
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func create() async {
        working = true
        error = nil
        defer { working = false }
        var req: [String: Any] = ["op": "create", "name": name.trimmingCharacters(in: .whitespaces)]
        if kind == .synced {
            req["url"] = url.trimmingCharacters(in: .whitespaces)
            req["token"] = token
        }
        do {
            let r: CreateResult = try await app.core.call(req)
            token = ""
            // The vault exists now: whatever happens next, the recovery key must be shown.
            var warnings: [String] = []
            if usePassphrase {
                let secret = SecretBytes(utf8: passphrase)
                passphrase = ""
                confirm = ""
                do {
                    let _: SlotResult = try await app.core.call(["op": "slot_add", "id": r.id, "kind": "passphrase", "label": "Passphrase"], secret: secret)
                } catch {
                    usePassphrase = false
                    warnings.append("The passphrase couldn’t be added (\(error.localizedDescription)). Add one later in Vault Settings.")
                }
                secret.wipe()
            }
            if useTouchID && app.seAvailable {
                do {
                    try await app.enableTouchID(r.id)
                } catch {
                    warnings.append("\(app.touchIDName) couldn’t be set up (\(error.localizedDescription)). Enable it later in Vault Settings.")
                }
            }
            touchIDWarning = warnings.isEmpty ? nil : warnings.joined(separator: " ")
            created = (r.id, r.recoveryKey)
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct RecoveryKeyView: View {
    let vaultName: String
    let recoveryKey: String
    let hasOtherUnlock: Bool
    let note: String?
    var title = "Save Your Recovery Key"
    var subtitle: String? = nil
    /// Replaces the default explanation.
    var message: String? = nil
    var doneTitle = "Done"
    var working = false
    var error: String? = nil
    var secondaryTitle: String? = nil
    var secondary: (() -> Void)? = nil
    let done: () -> Void

    @State private var stored = false
    @State private var copied = false

    private var groups: [String] { recoveryKey.split(separator: "-").map(String.init) }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(icon: "key.horizontal", title: title, subtitle: subtitle ?? "“\(vaultName)” was created.")
            VStack(alignment: .leading, spacing: 16) {
                Text(message ?? (hasOtherUnlock
                     ? "This key opens the vault if you forget your passphrase or lose this Mac. Vaultage doesn’t keep a copy."
                     : "This key is the only way into the vault if this Mac is lost or replaced. Vaultage doesn’t keep a copy."))
                    .fixedSize(horizontal: false, vertical: true)
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 8), count: 4), spacing: 10) {
                    ForEach(Array(groups.enumerated()), id: \.offset) { _, g in
                        Text(g)
                            .font(.system(size: 17, weight: .medium, design: .monospaced))
                            .tracking(1.5)
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(.quaternary.opacity(0.5)))
                .textSelection(.enabled)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Recovery key: " + groups.joined(separator: ", "))

                HStack {
                    Button {
                        SecretPasteboard.copy(recoveryKey) { copied = $0 }
                    } label: {
                        Label(copied ? "Copied — clears in 60 s" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                    }
                    Button {
                        printKey()
                    } label: {
                        Label("Print or Save as PDF…", systemImage: "printer")
                    }
                }
                if let note {
                    Label(note, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
                Toggle("I stored it somewhere safe (a password manager or on paper)", isOn: $stored)
                    .toggleStyle(.checkbox)
            }
            .padding(20)
            .disabled(working)
            SheetFooter(error: error) {
                if let secondaryTitle, let secondary {
                    Button(secondaryTitle, action: secondary)
                        .disabled(working)
                }
                Button(action: done) {
                    if working { ProgressView().controlSize(.small).padding(.horizontal, 12) } else { Text(doneTitle) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!stored || working)
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
        .interactiveDismissDisabled()
    }

    private func printKey() {
        let text = "Vaultage recovery key\n\nVault: \(vaultName)\n\n\(recoveryKey)\n\nKeep this somewhere safe. Anyone with this key can open the vault."
        let tv = NSTextView(frame: NSRect(x: 0, y: 0, width: 468, height: 300))
        tv.string = text
        tv.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        let info = NSPrintInfo.shared.copy() as! NSPrintInfo
        info.jobDisposition = .spool
        let op = NSPrintOperation(view: tv, printInfo: info)
        op.jobTitle = "Vaultage Recovery Key"
        op.showsPrintPanel = true
        if let w = NSApp.keyWindow {
            op.runModal(for: w, delegate: nil, didRun: nil, contextInfo: nil)
        } else {
            op.run()
        }
    }
}

/// The only places Coffer puts a secret on the pasteboard (recovery key, invite): marked
/// concealed and cleared after 60 s if still unchanged.
@MainActor
enum SecretPasteboard {
    static func copy(_ text: String, copied: @escaping @MainActor (Bool) -> Void) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        // Ask clipboard managers not to keep it.
        pb.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        let count = pb.changeCount
        copied(true)
        DispatchQueue.main.asyncAfter(deadline: .now() + 60) {
            MainActor.assumeIsolated {
                if NSPasteboard.general.changeCount == count { NSPasteboard.general.clearContents() }
                copied(false)
            }
        }
    }
}

struct SheetHeader: View {
    let icon: String
    let title: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 26, weight: .regular))
                .foregroundStyle(.tint)
                .symbolRenderingMode(.hierarchical)
                .frame(width: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title3.weight(.semibold))
                Text(subtitle).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 20)
        .padding(.top, 18)
        .padding(.bottom, 6)
    }
}

struct SheetFooter<Buttons: View>: View {
    let error: String?
    @ViewBuilder let buttons: Buttons

    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack {
                if let error {
                    Label(error, systemImage: "exclamationmark.circle.fill")
                        .foregroundStyle(.red)
                        .font(.callout)
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                buttons
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
    }
}
