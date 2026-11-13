import AppKit
import CofferKit
import SwiftUI

/// Finder-style list: NSTableView for native sorting, type-select, inline rename (Return),
/// drop-on-folder highlighting and internal drag-to-move.
struct FileTableView: NSViewRepresentable {
    let session: VaultSession
    let items: [Item]
    let selection: Set<String>
    let sort: SortSpec
    let showStatus: Bool
    let synced: Bool
    let editing: Set<String>
    let renameRequest: String?

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSScrollView {
        let c = context.coordinator
        c.parent = self
        c.applying = true
        let table = FileNSTableView()
        table.coordinator = c
        c.table = table

        func column(_ id: String, _ title: String, width: CGFloat, min: CGFloat, sortKey: SortKey, ascending: Bool = true, align: NSTextAlignment = .left) {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id))
            col.title = title
            col.width = width
            col.minWidth = min
            col.headerCell.alignment = align
            col.sortDescriptorPrototype = NSSortDescriptor(key: sortKey.rawValue, ascending: ascending)
            table.addTableColumn(col)
        }
        column("name", "Name", width: 360, min: 160, sortKey: .name)
        column("size", "Size", width: 90, min: 60, sortKey: .size, ascending: false, align: .right)
        column("modified", "Date Modified", width: 180, min: 110, sortKey: .modified, ascending: false)
        column("status", "Status", width: 60, min: 44, sortKey: .status, align: .center)
        table.tableColumns[0].resizingMask = .autoresizingMask

        table.style = .inset
        table.rowHeight = 24
        table.intercellSpacing = NSSize(width: 8, height: 0)
        table.columnAutoresizingStyle = .firstColumnOnlyAutoresizingStyle
        table.allowsMultipleSelection = true
        table.allowsEmptySelection = true
        table.allowsColumnReordering = false
        table.usesAlternatingRowBackgroundColors = false
        table.dataSource = c
        table.delegate = c
        table.target = c
        table.doubleAction = #selector(Coordinator.doubleClicked(_:))
        table.registerForDraggedTypes([.fileURL, Coordinator.internalType])
        table.setDraggingSourceOperationMask(.move, forLocal: true)
        table.setDraggingSourceOperationMask([], forLocal: false)
        table.draggingDestinationFeedbackStyle = .regular
        let menu = NSMenu()
        menu.delegate = c
        table.menu = menu
        table.autosaveName = "CofferFileTable"
        table.autosaveTableColumns = true
        table.setAccessibilityLabel("Files")

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        table.backgroundColor = .clear

        c.applying = false
        c.apply(self, initial: true)
        DispatchQueue.main.async { table.window?.makeFirstResponder(table) }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.apply(self, initial: false)
    }

    // MARK: - Coordinator

    @MainActor
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate, NSTextFieldDelegate {
        static let internalType = NSPasteboard.PasteboardType("local.coffer.internal-drag")

        var parent: FileTableView!
        weak var table: FileNSTableView?
        private var items: [Item] = []
        private var editing: Set<String> = []
        var applying = false
        private var renaming: (row: Int, item: Item)?
        /// Opaque drag token → dragged vault paths (names never go on a pasteboard).
        private var drags: [String: [String]] = [:]

        var session: VaultSession { parent.session }

        func apply(_ p: FileTableView, initial: Bool) {
            parent = p
            guard let table else { return }
            applying = true
            defer { applying = false }

            if let status = table.tableColumn(withIdentifier: .init("status")), status.isHidden == p.showStatus {
                status.isHidden = !p.showStatus
            }
            let wantSort = [NSSortDescriptor(key: p.sort.key.rawValue, ascending: p.sort.ascending)]
            if table.sortDescriptors != wantSort { table.sortDescriptors = wantSort }

            if p.items != items || p.editing != editing {
                let sameRows = p.items.map(\.path) == items.map(\.path)
                items = p.items
                editing = p.editing
                if renaming == nil {
                    if sameRows {
                        table.reloadData(forRowIndexes: IndexSet(integersIn: 0..<items.count), columnIndexes: IndexSet(integersIn: 0..<table.numberOfColumns))
                    } else {
                        table.reloadData()
                    }
                }
            }
            let want = IndexSet(items.indices.filter { p.selection.contains(items[$0].path) })
            if table.selectedRowIndexes != want {
                table.selectRowIndexes(want, byExtendingSelection: false)
                if let first = want.first { table.scrollRowToVisible(first) }
            }
            if let req = p.renameRequest, let row = items.firstIndex(where: { $0.path == req }) {
                DispatchQueue.main.async { [weak self] in
                    self?.session.renameRequest = nil
                    self?.beginRename(row: row)
                }
            }
        }

        // MARK: Data

        func numberOfRows(in tableView: NSTableView) -> Int { items.count }

        func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? {
            guard let column, row < items.count else { return nil }
            let item = items[row]
            switch column.identifier.rawValue {
            case "name":
                let cell = (tableView.makeView(withIdentifier: .init("nameCell"), owner: nil) as? NameCell) ?? NameCell()
                cell.configure(item)
                cell.textField?.delegate = self
                return cell
            case "size":
                let text = item.isDir ? (item.count == 0 ? "—" : Fmt.bytes(item.size)) : Fmt.bytes(item.size)
                return TextCell.make(tableView, id: "sizeCell", text: text, align: .right)
            case "modified":
                return TextCell.make(tableView, id: "dateCell", text: Fmt.date(item.mtime), align: .left)
            case "status":
                let cell = (tableView.makeView(withIdentifier: .init("statusCell"), owner: nil) as? StatusCell) ?? StatusCell()
                cell.configure(item, synced: parent.synced, editing: item.id.map { editing.contains($0) } ?? false)
                return cell
            default:
                return nil
            }
        }

        func tableView(_ tableView: NSTableView, typeSelectStringFor tableColumn: NSTableColumn?, row: Int) -> String? {
            tableColumn?.identifier.rawValue == "name" ? items[row].name : nil
        }

        func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
            guard !applying, let d = tableView.sortDescriptors.first, let key = d.key.flatMap(SortKey.init(rawValue:)) else { return }
            session.sort = SortSpec(key: key, ascending: d.ascending)
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !applying, let table else { return }
            let paths = Set(table.selectedRowIndexes.compactMap { $0 < items.count ? items[$0].path : nil })
            session.setSelection(paths)
        }

        // MARK: Actions

        @objc func doubleClicked(_ sender: Any?) {
            guard let table, table.clickedRow >= 0, table.clickedRow < items.count else { return }
            session.open(items[table.clickedRow])
        }

        func openSelection() {
            guard let table, table.selectedRowIndexes.count == 1, let row = table.selectedRowIndexes.first else { return }
            session.open(items[row])
        }

        func beginRename(row: Int) {
            guard let table, row < items.count,
                  let cell = table.view(atColumn: 0, row: row, makeIfNecessary: true) as? NameCell,
                  let tf = cell.textField else { return }
            renaming = (row, items[row])
            table.scrollRowToVisible(row)
            tf.isEditable = true
            tf.isSelectable = true
            table.window?.makeFirstResponder(tf)
            // Select the name without its extension, like Finder.
            let name = items[row].name as NSString
            let ext = items[row].isDir ? "" : name.pathExtension
            let len = ext.isEmpty ? name.length : name.length - ext.count - 1
            tf.currentEditor()?.selectedRange = NSRange(location: 0, length: max(len, 0))
        }

        func beginRenameSelected() {
            guard let table, table.selectedRowIndexes.count == 1, let row = table.selectedRowIndexes.first else { return }
            beginRename(row: row)
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy sel: Selector) -> Bool {
            if sel == #selector(NSResponder.cancelOperation(_:)), let r = renaming {
                (control as? NSTextField)?.stringValue = r.item.name
                renaming = nil
                endEditing(control as? NSTextField)
                return true
            }
            return false
        }

        func controlTextDidEndEditing(_ obj: Notification) {
            guard let tf = obj.object as? NSTextField, let r = renaming else { return }
            renaming = nil
            let newName = tf.stringValue
            endEditing(tf)
            guard newName != r.item.name else { return }
            Task {
                let ok = await session.rename(r.item, to: newName)
                if !ok { tf.stringValue = r.item.name }
                table?.reloadData()
            }
        }

        private func endEditing(_ tf: NSTextField?) {
            tf?.isEditable = false
            tf?.isSelectable = false
            table?.window?.makeFirstResponder(table)
        }

        // MARK: Context menu

        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            guard let table else { return }
            let row = table.clickedRow
            if row >= 0, !table.selectedRowIndexes.contains(row) {
                table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            }
            let selected = row >= 0 ? table.selectedRowIndexes.compactMap { $0 < items.count ? items[$0] : nil } : []
            Self.fill(menu, with: itemActions(session, selected))
        }

        static func fill(_ menu: NSMenu, with actions: [ItemAction?]) {
            for a in actions {
                if let a {
                    let mi = ClosureMenuItem(title: a.title, run: a.run)
                    mi.image = a.icon
                    if let kids = a.children {
                        let sub = NSMenu(title: a.title)
                        fill(sub, with: kids)
                        mi.submenu = sub
                    }
                    menu.addItem(mi)
                } else if menu.items.last?.isSeparatorItem == false {
                    menu.addItem(.separator())
                }
            }
        }

        // MARK: Drag & drop

        func tableView(_ tableView: NSTableView, pasteboardWriterForRow row: Int) -> NSPasteboardWriting? {
            guard renaming == nil else { return nil }
            let token = UUID().uuidString
            let selected = tableView.selectedRowIndexes.contains(row) ? tableView.selectedRowIndexes.map { items[$0].path } : [items[row].path]
            drags = [token: selected]
            let pb = NSPasteboardItem()
            pb.setString(token, forType: Self.internalType)
            return pb
        }

        func tableView(_ tableView: NSTableView, validateDrop info: NSDraggingInfo, proposedRow row: Int, proposedDropOperation op: NSTableView.DropOperation) -> NSDragOperation {
            let internalDrag = info.draggingPasteboard.availableType(from: [Self.internalType]) != nil
            let onFolder = op == .on && row >= 0 && row < items.count && items[row].isDir
            if internalDrag {
                guard onFolder, let token = info.draggingPasteboard.string(forType: Self.internalType),
                      let paths = drags[token], !paths.contains(items[row].path) else { return [] }
                return .move
            }
            guard info.draggingPasteboard.canReadObject(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) else { return [] }
            if !onFolder { tableView.setDropRow(-1, dropOperation: .on) }
            return .copy
        }

        func tableView(_ tableView: NSTableView, acceptDrop info: NSDraggingInfo, row: Int, dropOperation op: NSTableView.DropOperation) -> Bool {
            let dest: String? = (row >= 0 && row < items.count && items[row].isDir) ? items[row].path : nil
            if let token = info.draggingPasteboard.string(forType: Self.internalType) {
                guard let dest, let paths = drags.removeValue(forKey: token) else { return false }
                Task { await session.move(paths, to: dest) }
                return true
            }
            let urls = (info.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL]) ?? []
            guard !urls.isEmpty else { return false }
            session.handleDrop(urls, into: dest)
            return true
        }

        func tableView(_ tableView: NSTableView, draggingSession: NSDraggingSession, endedAt screenPoint: NSPoint, operation: NSDragOperation) {
            drags.removeAll()
        }
    }
}

/// Keyboard: Return renames, Space previews, ⌘↓ opens.
final class FileNSTableView: NSTableView {
    weak var coordinator: FileTableView.Coordinator?

    override func keyDown(with event: NSEvent) {
        let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        switch event.keyCode {
        case 36 where flags.isEmpty, 76 where flags.isEmpty: // Return, Enter
            coordinator?.beginRenameSelected()
        case 49 where flags.isEmpty: // Space
            coordinator?.session.togglePreview()
        default:
            super.keyDown(with: event)
        }
    }
}

final class ClosureMenuItem: NSMenuItem {
    private let run: @MainActor () -> Void

    init(title: String, run: @escaping @MainActor () -> Void) {
        self.run = run
        super.init(title: title, action: #selector(fire), keyEquivalent: "")
        target = self
    }

    required init(coder: NSCoder) { fatalError() }

    @objc private func fire() { MainActor.assumeIsolated { run() } }
}

// MARK: - Cells

final class NameCell: NSTableCellView {
    init() {
        super.init(frame: .zero)
        identifier = .init("nameCell")
        let iv = NSImageView()
        iv.translatesAutoresizingMaskIntoConstraints = false
        iv.imageScaling = .scaleProportionallyUpOrDown
        let tf = NSTextField(labelWithString: "")
        tf.translatesAutoresizingMaskIntoConstraints = false
        tf.lineBreakMode = .byTruncatingMiddle
        tf.isEditable = false
        tf.isSelectable = false
        tf.drawsBackground = false
        tf.focusRingType = .none
        tf.cell?.usesSingleLineMode = true
        addSubview(iv)
        addSubview(tf)
        imageView = iv
        textField = tf
        NSLayoutConstraint.activate([
            iv.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 2),
            iv.centerYAnchor.constraint(equalTo: centerYAnchor),
            iv.widthAnchor.constraint(equalToConstant: 18),
            iv.heightAnchor.constraint(equalToConstant: 18),
            tf.leadingAnchor.constraint(equalTo: iv.trailingAnchor, constant: 6),
            tf.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -2),
            tf.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError() }

    @MainActor
    func configure(_ item: Item) {
        imageView?.image = FileIcon.image(for: item.name, isDir: item.isDir)
        textField?.stringValue = item.name
        textField?.isEditable = false
        textField?.isSelectable = false
        setAccessibilityLabel(item.isDir ? "\(item.name), folder" : item.name)
    }
}

enum TextCell {
    @MainActor
    static func make(_ table: NSTableView, id: String, text: String, align: NSTextAlignment) -> NSView {
        let cell: NSTableCellView
        if let c = table.makeView(withIdentifier: .init(id), owner: nil) as? NSTableCellView {
            cell = c
        } else {
            cell = NSTableCellView()
            cell.identifier = .init(id)
            let tf = NSTextField(labelWithString: "")
            tf.translatesAutoresizingMaskIntoConstraints = false
            tf.textColor = .secondaryLabelColor
            tf.alignment = align
            tf.lineBreakMode = .byTruncatingTail
            tf.font = .monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
            cell.addSubview(tf)
            cell.textField = tf
            NSLayoutConstraint.activate([
                tf.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
                tf.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -2),
                tf.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
            ])
        }
        cell.textField?.stringValue = text
        return cell
    }
}

final class StatusCell: NSTableCellView {
    private let icon = NSImageView()

    init() {
        super.init(frame: .zero)
        identifier = .init("statusCell")
        icon.translatesAutoresizingMaskIntoConstraints = false
        addSubview(icon)
        NSLayoutConstraint.activate([
            icon.centerXAnchor.constraint(equalTo: centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError() }

    @MainActor
    func configure(_ item: Item, synced: Bool, editing: Bool) {
        let (symbol, tint, tip): (String?, NSColor, String)
        if editing {
            (symbol, tint, tip) = ("pencil.circle.fill", .controlAccentColor, "Open in another app — saved changes are encrypted back")
        } else if !synced {
            (symbol, tint, tip) = (nil, .clear, "")
        } else if item.pending {
            (symbol, tint, tip) = ("arrow.up.circle", .secondaryLabelColor, "Waiting to upload")
        } else {
            (symbol, tint, tip) = ("checkmark.circle", .tertiaryLabelColor, "Synced")
        }
        icon.image = symbol.flatMap { NSImage(systemSymbolName: $0, accessibilityDescription: tip) }
        icon.contentTintColor = tint
        toolTip = tip.isEmpty ? nil : tip
        setAccessibilityLabel(tip)
    }
}
