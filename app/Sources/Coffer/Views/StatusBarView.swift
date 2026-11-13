import CofferKit
import SwiftUI

struct StatusBarView: View {
    let session: VaultSession

    var body: some View {
        VStack(spacing: 0) {
            if let b = session.banner {
                transientBanner(b)
            }
            Divider()
            HStack(spacing: 12) {
                syncLabel
                    .frame(maxWidth: .infinity, alignment: .leading)
                if let a = session.status?.activity {
                    activity(a)
                } else if session.busy > 0 {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Working…").foregroundStyle(.secondary)
                    }
                }
                Text(summaryText)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .font(.callout)
            .lineLimit(1)
            .padding(.horizontal, 12)
            .frame(height: 28)
            .background(.bar)
        }
        .animation(.snappy, value: session.banner?.id)
        .animation(.snappy, value: session.status?.activity)
    }

    private var summaryText: String {
        guard let s = session.status?.summary else { return "" }
        var t = "\(Fmt.count(s.files, "file")) · \(Fmt.bytes(s.bytes))"
        if !session.trash.isEmpty { t += " · \(session.trash.count) in Trash" }
        return t
    }

    private func activity(_ a: Activity) -> some View {
        HStack(spacing: 8) {
            Text(a.label)
                .foregroundStyle(.secondary)
                .truncationMode(.middle)
                .frame(maxWidth: 220, alignment: .trailing)
            ProgressView(value: Double(a.done), total: Double(max(a.total, 1)))
                .progressViewStyle(.linear)
                .frame(width: 120)
            Text("\(a.done) of \(a.total)")
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var syncLabel: some View {
        let (icon, text, color) = describe()
        HStack(spacing: 6) {
            if session.status?.sync.state == "syncing" {
                ProgressView().controlSize(.mini)
            } else {
                Image(systemName: icon).foregroundStyle(color == .primary ? .secondary : color)
            }
            Text(text)
                .foregroundStyle(color == .primary ? .secondary : color)
                .truncationMode(.tail)
                .help(text)
            if session.synced, let st = session.status?.sync.state, st == "offline" || st == "error" {
                Button("Retry") { session.syncNow() }
                    .buttonStyle(.link)
                    .controlSize(.small)
            }
            if session.status?.isRekeyed == true {
                Button("Enter New Key…") { AppModel.shared.sheet = .vaultTask(session.vaultID, .adoptRekey) }
                    .buttonStyle(.link)
                    .controlSize(.small)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func describe() -> (String, String, Color) {
        guard let st = session.status else { return ("ellipsis", "", .primary) }
        let pending = st.summary.pending
        let waiting = Fmt.count(pending, "change") + " waiting"
        switch st.sync.state {
        case "local":
            return ("internaldrive", "Local vault — not synced", .primary)
        case "syncing":
            return ("arrow.triangle.2.circlepath", pending > 0 ? "Syncing · \(waiting)" : "Syncing…", .primary)
        case "offline":
            return ("icloud.slash", pending > 0 ? "\(waiting) — server unreachable, will retry" : "Offline — server unreachable, will retry", .orange)
        case "error":
            return ("exclamationmark.icloud.fill", "Sync error: " + CofferError.readableSync(st.sync.error ?? "unknown"), .red)
        case "rekeyed":
            return ("key.horizontal.fill", "Keys rotated on another device — enter the new key to sync", .orange)
        default:
            if st.sync.lastOkMs == 0 { return ("icloud", "Waiting for first sync…", .primary) }
            if let e = st.sync.error {
                return ("exclamationmark.triangle.fill", "Synced \(Fmt.shortTime(st.sync.lastOkMs)) with problems: " + CofferError.readableSync(e), .orange)
            }
            if pending > 0 { return ("arrow.up.circle", "\(waiting) to upload", .primary) }
            return ("checkmark.icloud", "Up to date · synced \(Fmt.shortTime(st.sync.lastOkMs))", .primary)
        }
    }

    private func transientBanner(_ b: Banner) -> some View {
        HStack(spacing: 8) {
            Image(systemName: b.style == .warning ? "exclamationmark.triangle.fill" : (b.style == .success ? "checkmark.circle.fill" : "info.circle.fill"))
                .foregroundStyle(b.style == .warning ? .orange : (b.style == .success ? .green : .accentColor))
            Text(b.text).lineLimit(1).truncationMode(.middle)
            Spacer()
            if let title = b.actionTitle, let action = b.action {
                Button(title) { action() }
                    .controlSize(.small)
            }
            Button {
                session.banner = nil
            } label: {
                Image(systemName: "xmark").font(.caption.weight(.semibold))
            }
            .buttonStyle(.borderless)
            .help("Close")
            .accessibilityLabel("Close message")
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.thinMaterial)
        .overlay(alignment: .top) { Divider() }
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }
}
