import AppKit
import CofferKit
import SwiftUI
import UniformTypeIdentifiers

enum Fmt {
    static func bytes(_ n: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: n), countStyle: .file)
    }

    private static let relative: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        f.doesRelativeDateFormatting = true
        return f
    }()

    private static let timeOnly: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .short
        return f
    }()

    static func date(_ ms: Int64) -> String {
        ms > 0 ? relative.string(from: Date(ms: ms)) : "—"
    }

    /// "12:04" today, otherwise a relative date and time.
    static func shortTime(_ ms: Int64) -> String {
        let d = Date(ms: ms)
        return Calendar.current.isDateInToday(d) ? timeOnly.string(from: d) : relative.string(from: d)
    }

    static func count(_ n: UInt64, _ singular: String, _ plural: String? = nil) -> String {
        "\(n.formatted()) \(n == 1 ? singular : (plural ?? singular + "s"))"
    }
}

extension Date {
    init(ms: Int64) { self.init(timeIntervalSince1970: TimeInterval(ms) / 1000) }
}

enum VaultPath {
    static func parent(_ p: String) -> String {
        guard let i = p.lastIndex(of: "/") else { return "" }
        return String(p[..<i])
    }

    static func name(_ p: String) -> String {
        guard let i = p.lastIndex(of: "/") else { return p }
        return String(p[p.index(after: i)...])
    }

    static func join(_ dir: String, _ name: String) -> String {
        dir.isEmpty ? name : dir + "/" + name
    }

    static func components(_ p: String) -> [String] {
        p.split(separator: "/").map(String.init)
    }

    /// Validation message for a new file/folder name, or nil if fine.
    static func problem(with name: String) -> String? {
        let t = name.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return "Enter a name." }
        if t.contains("/") { return "Names can’t contain “/”." }
        if t == "." || t == ".." { return "That name is reserved." }
        return nil
    }
}

/// File-type icons from the extension only (never touches files on disk).
@MainActor
enum FileIcon {
    private static var cache: [String: NSImage] = [:]

    nonisolated static func type(for name: String, isDir: Bool) -> UTType {
        if isDir { return .folder }
        let ext = (name as NSString).pathExtension.lowercased()
        return ext.isEmpty ? .data : (UTType(filenameExtension: ext) ?? .data)
    }

    static func image(for name: String, isDir: Bool) -> NSImage {
        let key = isDir ? "/dir" : (name as NSString).pathExtension.lowercased()
        if let img = cache[key] { return img }
        let img = NSWorkspace.shared.icon(for: type(for: name, isDir: isDir))
        cache[key] = img
        return img
    }

    static func kindDescription(for name: String, isDir: Bool) -> String {
        if isDir { return "Folder" }
        return type(for: name, isDir: false).localizedDescription ?? "Document"
    }
}

/// AppKit alerts as async functions, attached to the key window as sheets when possible.
@MainActor
enum Alerts {
    static func run(_ alert: NSAlert) async -> NSApplication.ModalResponse {
        if let w = NSApp.keyWindow ?? NSApp.mainWindow, w.isVisible, w.attachedSheet == nil {
            return await withCheckedContinuation { cont in
                alert.beginSheetModal(for: w) { cont.resume(returning: $0) }
            }
        }
        return alert.runModal()
    }

    /// Confirmation with a destructive (or default) primary button. Returns true to proceed.
    static func confirm(_ title: String, _ message: String, action: String, destructive: Bool = true, suppressionKey: String? = nil) async -> Bool {
        if let key = suppressionKey, UserDefaults.standard.bool(forKey: key) { return true }
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = title
        a.informativeText = message
        let ok = a.addButton(withTitle: action)
        ok.hasDestructiveAction = destructive
        a.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        if destructive {
            // Destructive actions are never the default button.
            ok.keyEquivalent = ""
        }
        if suppressionKey != nil {
            a.showsSuppressionButton = true
            a.suppressionButton?.title = "Don’t ask again"
        }
        let r = await run(a)
        let yes = r == .alertFirstButtonReturn
        if yes, let key = suppressionKey, a.suppressionButton?.state == .on {
            UserDefaults.standard.set(true, forKey: key)
        }
        return yes
    }

    static func error(_ error: Error, title: String? = nil) async {
        let a = NSAlert()
        let ce = error as? CofferError
        if ce?.isIntegrity == true {
            a.alertStyle = .critical
            a.messageText = "Vault data failed an integrity check"
            a.informativeText = (ce?.errorDescription ?? "") + "\n\nThis means the encrypted data was modified or damaged on disk or on the server. Coffer refused to use it. Don’t delete anything yet; keep a copy of the vault folder."
        } else {
            a.alertStyle = .warning
            a.messageText = title ?? "The operation couldn’t be completed"
            a.informativeText = error.localizedDescription
        }
        a.addButton(withTitle: "OK")
        _ = await run(a)
    }

    static func info(_ title: String, _ message: String, buttons: [String]) async -> Int {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = message
        for b in buttons { a.addButton(withTitle: b) }
        let r = await run(a)
        return r.rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
    }
}

/// Horizontal shake for wrong-passphrase feedback.
struct ShakeEffect: GeometryEffect {
    var travel: CGFloat = 7
    var animatableData: CGFloat

    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: travel * sin(animatableData * .pi * 4), y: 0))
    }
}

/// Persists the sidebar width by giving the enclosing NSSplitView an autosave name.
struct SplitViewAutosave: NSViewRepresentable {
    let name: String

    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        DispatchQueue.main.async {
            var s: NSView? = v.superview
            while let cur = s, !(cur is NSSplitView) { s = cur.superview }
            if let split = s as? NSSplitView, split.autosaveName == nil || split.autosaveName?.isEmpty == true {
                split.autosaveName = name
            }
        }
        return v
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

/// Rough passphrase strength for a hint (not a policy).
enum Strength: Int {
    case empty, weak, fair, good, strong

    static func of(_ s: String) -> Strength {
        if s.isEmpty { return .empty }
        var classes = 0
        if s.rangeOfCharacter(from: .lowercaseLetters) != nil { classes += 1 }
        if s.rangeOfCharacter(from: .uppercaseLetters) != nil { classes += 1 }
        if s.rangeOfCharacter(from: .decimalDigits) != nil { classes += 1 }
        if s.rangeOfCharacter(from: CharacterSet.alphanumerics.union(.whitespaces).inverted) != nil { classes += 1 }
        let words = s.split(whereSeparator: { $0 == " " || $0 == "-" }).count
        let score = Double(s.count) * (1 + Double(classes) * 0.25) + Double(max(0, words - 1)) * 6
        switch score {
        case ..<14: return .weak
        case ..<22: return .fair
        case ..<32: return .good
        default: return .strong
        }
    }

    var label: String {
        switch self {
        case .empty: return ""
        case .weak: return "Weak — easy to guess"
        case .fair: return "Fair — consider a longer passphrase"
        case .good: return "Good"
        case .strong: return "Strong"
        }
    }

    var color: Color {
        switch self {
        case .empty: return .clear
        case .weak: return .red
        case .fair: return .orange
        case .good, .strong: return .green
        }
    }
}

extension View {
    /// Hover highlight for borderless controls.
    func hoverHighlight(cornerRadius: CGFloat = 6) -> some View { modifier(HoverHighlight(cornerRadius: cornerRadius)) }
}

struct HoverHighlight: ViewModifier {
    let cornerRadius: CGFloat
    @State private var hovering = false

    func body(content: Content) -> some View {
        content
            .background(RoundedRectangle(cornerRadius: cornerRadius).fill(Color.primary.opacity(hovering ? 0.08 : 0)))
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
    }
}

/// Loads file URLs dropped from Finder.
enum FileDrop {
    static func urls(from providers: [NSItemProvider], completion: @escaping @MainActor ([URL]) -> Void) {
        let group = DispatchGroup()
        let lock = NSLock()
        var urls: [URL] = []
        for p in providers where p.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            group.enter()
            _ = p.loadDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier) { data, _ in
                if let data, let url = URL(dataRepresentation: data, relativeTo: nil), url.isFileURL {
                    lock.lock(); urls.append(url); lock.unlock()
                }
                group.leave()
            }
        }
        group.notify(queue: .main) {
            MainActor.assumeIsolated { completion(urls) }
        }
    }
}
