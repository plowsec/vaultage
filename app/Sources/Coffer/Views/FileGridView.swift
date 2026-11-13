import AppKit
import CofferKit
import SwiftUI

struct FileGridView: View {
    let session: VaultSession
    let items: [Item]
    let editing: Set<String>
    @State private var anchor: String?
    @State private var targeted = false
    @FocusState private var focused: Bool

    private let columns = [GridItem(.adaptive(minimum: 112, maximum: 140), spacing: 12)]

    var body: some View {
        ScrollView {
            LazyVGrid(columns: columns, spacing: 14) {
                ForEach(items, id: \.path) { item in
                    GridTile(
                        item: item,
                        selected: session.selection.contains(item.path),
                        editing: item.id.map { editing.contains($0) } ?? false,
                        synced: session.synced,
                        session: session
                    )
                    .onTapGesture(count: 2) { session.open(item) }
                    .simultaneousGesture(TapGesture().onEnded { select(item) })
                    .contextMenu {
                        ItemActionsMenu(actions: itemActions(session, contextItems(for: item)))
                    }
                }
            }
            .padding(16)
        }
        .background(
            Color.clear
                .contentShape(Rectangle())
                .onTapGesture { session.setSelection([]) }
        )
        .overlay {
            if targeted {
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(Color.accentColor, lineWidth: 3)
                    .padding(3)
                    .allowsHitTesting(false)
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $targeted) { providers in
            FileDrop.urls(from: providers) { session.handleDrop($0) }
            return true
        }
        .focusable()
        .focusEffectDisabled()
        .focused($focused)
        .onAppear { focused = true }
        .onKeyPress(.space) {
            session.togglePreview()
            return .handled
        }
        .onKeyPress(.return) {
            if let it = session.selectedItems.first, session.selection.count == 1 {
                AppModel.shared.sheet = .rename(session.vaultID, it)
            }
            return .handled
        }
        .onKeyPress(keys: [.leftArrow, .rightArrow, .upArrow, .downArrow]) { press in
            move(press.key)
            return .handled
        }
    }

    /// Context menus are built during rendering: never mutate state here.
    private func contextItems(for item: Item) -> [Item] {
        session.selection.contains(item.path) ? session.selectedItems : [item]
    }

    private func select(_ item: Item) {
        focused = true
        let flags = NSEvent.modifierFlags
        if flags.contains(.command) {
            var s = session.selection
            if s.contains(item.path) { s.remove(item.path) } else { s.insert(item.path) }
            session.setSelection(s)
            anchor = item.path
        } else if flags.contains(.shift), let a = anchor, let i = items.firstIndex(where: { $0.path == a }), let j = items.firstIndex(of: item) {
            session.setSelection(Set(items[min(i, j)...max(i, j)].map(\.path)))
        } else {
            session.setSelection([item.path])
            anchor = item.path
        }
    }

    /// Arrow keys: left/right step; up/down step by a row estimate.
    private func move(_ key: KeyEquivalent) {
        guard !items.isEmpty else { return }
        let cur = items.firstIndex { session.selection.contains($0.path) } ?? -1
        let perRow = 6
        var next = cur
        switch key {
        case .leftArrow: next = max(cur - 1, 0)
        case .rightArrow: next = min(cur + 1, items.count - 1)
        case .upArrow: next = max(cur - perRow, 0)
        case .downArrow: next = min(cur < 0 ? 0 : cur + perRow, items.count - 1)
        default: break
        }
        session.setSelection([items[next].path])
        anchor = items[next].path
    }
}

private struct GridTile: View {
    let item: Item
    let selected: Bool
    let editing: Bool
    let synced: Bool
    let session: VaultSession
    @State private var hovering = false
    @State private var dropTarget = false
    @State private var thumb: NSImage?
    @AppStorage(Pref.showThumbnails) private var showThumbnails = true

    private var thumbKey: String? {
        guard showThumbnails, ThumbnailStore.eligible(item) else { return nil }
        return "\(item.id ?? "")/\(item.rev)"
    }

    var body: some View {
        VStack(spacing: 6) {
            ZStack(alignment: .bottomTrailing) {
                if let thumb, thumbKey != nil {
                    Image(nsImage: thumb)
                        .resizable()
                        .interpolation(.high)
                        .aspectRatio(contentMode: .fit)
                        .frame(maxWidth: 64, maxHeight: 64)
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .shadow(color: .black.opacity(0.18), radius: 1, y: 0.5)
                        .frame(width: 64, height: 64)
                } else {
                    Image(nsImage: FileIcon.image(for: item.name, isDir: item.isDir))
                        .resizable()
                        .interpolation(.high)
                        .frame(width: 64, height: 64)
                }
                if editing {
                    badge("pencil.circle.fill", .accentColor)
                } else if synced && item.pending {
                    badge("arrow.up.circle.fill", .secondary)
                }
            }
            .padding(6)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(selected ? 0.10 : (hovering || dropTarget ? 0.05 : 0))))
            Text(item.name)
                .font(.callout)
                .lineLimit(2)
                .truncationMode(.middle)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .foregroundStyle(selected ? Color.white : Color.primary)
                .background(RoundedRectangle(cornerRadius: 4).fill(selected ? Color.accentColor : .clear))
            Text(item.isDir ? Fmt.count(item.count, "item") : Fmt.bytes(item.size))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(width: 112)
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .overlay {
            if dropTarget {
                RoundedRectangle(cornerRadius: 10).strokeBorder(Color.accentColor, lineWidth: 2)
            }
        }
        .onHover { hovering = $0 }
        .task(id: thumbKey) {
            guard thumbKey != nil else { thumb = nil; return }
            thumb = ThumbnailStore.shared.cached(vault: session.vaultID, item: item)
            if thumb == nil { thumb = await ThumbnailStore.shared.thumbnail(vault: session.vaultID, item: item) }
        }
        .modifier(FolderDrop(item: item, session: session, targeted: $dropTarget))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(item.isDir ? "\(item.name), folder" : item.name)
        .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
    }

    private func badge(_ symbol: String, _ color: Color) -> some View {
        Image(systemName: symbol)
            .font(.system(size: 16))
            .foregroundStyle(color)
            .background(Circle().fill(.background).padding(1))
            .offset(x: 4, y: 4)
    }
}

private struct FolderDrop: ViewModifier {
    let item: Item
    let session: VaultSession
    @Binding var targeted: Bool

    func body(content: Content) -> some View {
        if item.isDir {
            content.onDrop(of: [.fileURL], isTargeted: $targeted) { providers in
                FileDrop.urls(from: providers) { session.handleDrop($0, into: item.path) }
                return true
            }
        } else {
            content
        }
    }
}
