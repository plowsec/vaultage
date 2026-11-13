import CofferKit
import LocalAuthentication
import SwiftUI

struct LockedVaultView: View {
    let vault: VaultInfo
    @Environment(AppModel.self) private var app

    @State private var passphrase = ""
    @State private var recoveryKey = ""
    @State private var showRecovery = false
    @State private var working = false
    @State private var error: String?
    @State private var shake: CGFloat = 0
    @FocusState private var focus: Field?

    private enum Field { case passphrase, recovery }

    private var touchIDSlot: SlotInfo? { app.touchIDSlot(for: vault) }

    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                header
                if let _ = touchIDSlot {
                    touchIDButton
                }
                if vault.hasPassphrase {
                    if touchIDSlot != nil { orDivider }
                    passphraseField
                }
                recoverySection
                if let error {
                    Label(error, systemImage: "exclamationmark.circle.fill")
                        .foregroundStyle(.red)
                        .font(.callout)
                        .multilineTextAlignment(.center)
                        .transition(.opacity.combined(with: .move(edge: .top)))
                        .accessibilityAddTraits(.isStaticText)
                }
            }
            .frame(width: 340)
            .modifier(ShakeEffect(animatableData: shake))
            .padding(.vertical, 60)
            .frame(maxWidth: .infinity, minHeight: 480)
        }
        .scrollBounceBehavior(.basedOnSize)
        .navigationTitle(vault.name)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    app.sheet = .vaultSettings(vault.id)
                } label: {
                    Label("Vault Settings", systemImage: "gearshape")
                }
                .help("Vault Settings")
            }
        }
        .task(id: vault.id) {
            // Touch ID once per user selection, never in a loop.
            if app.pendingTouchIDPrompt == vault.id {
                app.pendingTouchIDPrompt = nil
                try? await Task.sleep(for: .milliseconds(250))
                await unlockTouchID()
            } else if touchIDSlot == nil, vault.hasPassphrase {
                focus = .passphrase
            } else if touchIDSlot == nil {
                // Recovery key is the only way in.
                showRecovery = true
                focus = .recovery
            }
        }
        .animation(.snappy, value: error)
        .animation(.snappy, value: showRecovery)
    }

    private var header: some View {
        VStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(.quaternary.opacity(0.6))
                    .frame(width: 88, height: 88)
                Image(systemName: "lock.fill")
                    .font(.system(size: 38, weight: .medium))
                    .foregroundStyle(.tint)
            }
            .accessibilityHidden(true)
            Text(vault.name)
                .font(.title.weight(.semibold))
                .multilineTextAlignment(.center)
            Text(vault.synced ? "Synced vault · locked" : "Vault on this Mac · locked")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var touchIDButton: some View {
        Button {
            Task { await unlockTouchID() }
        } label: {
            VStack(spacing: 8) {
                Image(systemName: app.biometry ? "touchid" : "lock.open")
                    .font(.system(size: 34, weight: .regular))
                    .symbolRenderingMode(.hierarchical)
                Text("Unlock with \(app.touchIDName)")
                    .font(.callout.weight(.medium))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .disabled(working)
        .keyboardShortcut(touchIDSlot != nil && passphrase.isEmpty ? .defaultAction : nil)
        .accessibilityLabel("Unlock with \(app.touchIDName)")
    }

    private var orDivider: some View {
        HStack {
            VStack { Divider() }
            Text("or").font(.caption).foregroundStyle(.secondary)
            VStack { Divider() }
        }
    }

    private var passphraseField: some View {
        HStack(spacing: 8) {
            SecureField("Passphrase", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .controlSize(.large)
                .focused($focus, equals: .passphrase)
                .onSubmit { Task { await unlockPassphrase() } }
                .disabled(working)
                .accessibilityLabel("Passphrase for \(vault.name)")
            Button {
                Task { await unlockPassphrase() }
            } label: {
                if working {
                    ProgressView().controlSize(.small).frame(width: 18, height: 18)
                } else {
                    Image(systemName: "arrow.right.circle.fill").font(.title2)
                }
            }
            .buttonStyle(.borderless)
            .disabled(passphrase.isEmpty || working)
            .help("Unlock")
            .accessibilityLabel("Unlock")
        }
    }

    @ViewBuilder
    private var recoverySection: some View {
        VStack(spacing: 10) {
            Button {
                showRecovery.toggle()
                if showRecovery { focus = .recovery }
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .rotationEffect(.degrees(showRecovery ? 90 : 0))
                    Text("Use recovery key…")
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(showRecovery ? "Hide recovery key field" : "Use recovery key")

            if showRecovery {
                VStack(alignment: .leading, spacing: 6) {
                    SecureField("XXXXX-XXXXX-…", text: $recoveryKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                        .focused($focus, equals: .recovery)
                        .onSubmit { Task { await unlockRecovery() } }
                        .disabled(working)
                        .accessibilityLabel("Recovery key")
                    HStack {
                        Text("The key you saved when the vault was created.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Unlock") { Task { await unlockRecovery() } }
                            .disabled(recoveryKey.trimmingCharacters(in: .whitespaces).isEmpty || working)
                    }
                }
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .padding(.top, vault.hasPassphrase || touchIDSlot != nil ? 4 : 0)
    }

    // MARK: Actions

    private func fail(_ message: String) {
        error = message
        shake = 0
        withAnimation(.linear(duration: 0.4)) { shake = 1 }
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [.announcement: message, .priority: NSAccessibilityPriorityLevel.high.rawValue])
    }

    private func unlockPassphrase() async {
        guard !passphrase.isEmpty, !working else { return }
        let secret = SecretBytes(utf8: passphrase)
        passphrase = ""
        await attempt { try await app.unlock(vault.id, kind: .passphrase, secret: secret) }
        if error != nil { focus = .passphrase }
    }

    private func unlockRecovery() async {
        let key = recoveryKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty, !working else { return }
        let secret = SecretBytes(utf8: key)
        recoveryKey = ""
        await attempt { try await app.unlock(vault.id, kind: .recovery, secret: secret) }
    }

    private func unlockTouchID() async {
        guard !working else { return }
        await attempt { try await app.unlockWithTouchID(vault.id) }
    }

    private func attempt(_ body: () async throws -> Void) async {
        working = true
        error = nil
        defer { working = false }
        do {
            try await body()
        } catch let e where SecureEnclaveSlot.isUserCancel(e) {
            // User backed out of Touch ID: no error.
        } catch let e as CofferError {
            if e.isIntegrity { await Alerts.error(e) }
            fail(e.isWrongSecret ? "That didn’t work. Check it and try again." : (e.errorDescription ?? "Couldn’t unlock."))
        } catch {
            fail(error.localizedDescription)
        }
    }
}
