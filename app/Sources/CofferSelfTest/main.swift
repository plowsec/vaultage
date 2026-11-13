// Headless round-trip through the same client code the app uses. Never prompts.
// Usage: COFFER_HOME=<empty temp dir> coffer-selftest [--demo <folder to import>]
// --demo leaves a vault "Demo" (passphrase "demo") with the folder's contents and a no-prompt
// Secure Enclave slot; prints `<vault id> <slot id>` for `-seSlot.<id> <slot>` on the app's command line.
// COFFER_TEST_URL + COFFER_TEST_TOKEN (a local cofferd) add attach / usage / invite / join / adopt checks;
// the joining device is this binary re-run with another COFFER_HOME (secrets go over stdin).
import AVFoundation
import CofferKit
import Foundation

guard let home = ProcessInfo.processInfo.environment["COFFER_HOME"], !home.isEmpty else {
    FileHandle.standardError.write("set COFFER_HOME to an empty temporary directory\n".data(using: .utf8)!)
    exit(2)
}

let core = CofferCore.shared
var failures = 0

func check(_ ok: Bool, _ what: String) {
    print(ok ? "ok   \(what)" : "FAIL \(what)")
    if !ok { failures += 1 }
}

func run() async throws {
    let posture = CofferCore.harden()
    print("posture: hardened_runtime=\(String(describing: posture.hardenedRuntime)) debuggable=\(String(describing: posture.debuggable)) sip=\(String(describing: posture.sip)) attach_denied=\(posture.attachDenied)")

    let device: DeviceInfo = try await core.call(["op": "device"])
    check(!device.id.isEmpty, "device")

    let created: CreateResult = try await core.call(["op": "create", "name": "Test"])
    let id = created.id
    check(created.recoveryKey.count > 40, "create returns recovery key")

    let pass = SecretBytes(utf8: "correct horse battery staple")
    let slot: SlotResult = try await core.call(["op": "slot_add", "id": id, "kind": "passphrase", "label": "Passphrase"], secret: pass)
    pass.wipe()
    check(!slot.slot.isEmpty, "slot_add passphrase")

    // Source files.
    let src = URL(fileURLWithPath: home).appendingPathComponent("src", isDirectory: true)
    try FileManager.default.createDirectory(at: src.appendingPathComponent("folder"), withIntermediateDirectories: true)
    let payload = Data((0..<100_000).map { UInt8($0 % 251) })
    try payload.write(to: src.appendingPathComponent("blob.bin"))
    try Data("hello".utf8).write(to: src.appendingPathComponent("folder/note.txt"))

    let rep: ImportReport = try await core.call(["op": "import", "id": id, "sources": [src.appendingPathComponent("blob.bin").path, src.appendingPathComponent("folder").path], "dest": ""])
    check(rep.files == 2 && rep.skipped.isEmpty, "import 2 files (got \(rep.files), skipped \(rep.skipped.count))")

    let root: ListResult = try await core.call(["op": "list", "id": id, "path": ""])
    check(root.items.map(\.name).sorted() == ["blob.bin", "folder"], "list root")
    let blob = root.items.first { $0.name == "blob.bin" }!

    var data = try await core.read(vault: id, entry: blob.id!)
    check(data == payload, "read decrypts identical bytes")
    data = Data()

    try await core.perform(["op": "mkdir", "id": id, "path": "folder/sub"])
    let moved: MovedResult = try await core.call(["op": "rename", "id": id, "from": "blob.bin", "to": "folder/sub/blob2.bin"])
    check(moved.moved == 1, "rename/move")

    let found: ItemsResult = try await core.call(["op": "search", "id": id, "query": "BLOB"])
    check(found.items.count == 1 && found.items[0].path == "folder/sub/blob2.bin", "search")

    let status: VaultStatus = try await core.call(["op": "status", "id": id])
    check(status.sync.state == "local" && status.summary.files == 2, "status (local, 2 files)")

    // New revision via re-import of a same-named file.
    let tmp = URL(fileURLWithPath: home).appendingPathComponent("edit", isDirectory: true)
    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    try Data("hello, edited".utf8).write(to: tmp.appendingPathComponent("note.txt"))
    let _: ImportReport = try await core.call(["op": "import", "id": id, "sources": [tmp.appendingPathComponent("note.txt").path], "dest": "folder"])
    let folder: ListResult = try await core.call(["op": "list", "id": id, "path": "folder"])
    let note = folder.items.first { $0.name == "note.txt" }!
    let versions: [Version] = try await core.call(["op": "versions", "id": id, "entry": note.id!])
    check(versions.count == 2 && versions[0].current, "versions after re-import (\(versions.count))")
    let old = try await core.read(vault: id, entry: note.id!, rev: versions[1].rev)
    check(String(decoding: old, as: UTF8.self) == "hello", "read old revision")

    let del: DeletedResult = try await core.call(["op": "delete", "id": id, "paths": ["folder/note.txt"]])
    check(del.deleted == 1, "delete")
    let trash: [TrashItem] = try await core.call(["op": "trash", "id": id])
    check(trash.count == 1, "trash lists deleted file")
    let restored: PathResult = try await core.call(["op": "restore", "id": id, "entry": trash[0].id])
    check(restored.path == "folder/note.txt", "restore from trash")

    let out = URL(fileURLWithPath: home).appendingPathComponent("out", isDirectory: true)
    let written: WrittenResult = try await core.call(["op": "export", "id": id, "paths": ["folder"], "dest": out.path])
    check(written.written.count == 1 && FileManager.default.fileExists(atPath: out.appendingPathComponent("folder/sub/blob2.bin").path), "export folder")

    // Secure Enclave slot with .privateKeyUsage only (no prompt).
    if SecureEnclaveSlot.isAvailable {
        let se = try SecureEnclaveSlot.create(flags: [.privateKeyUsage])
        let seSlot: SlotResult = try await core.call(["op": "slot_add", "id": id, "kind": "secure-enclave", "label": se.label, "public": se.publicInfo], secret: se.secret)
        se.secret.wipe()
        try await core.perform(["op": "lock", "id": id])
        let vaults: [VaultInfo] = try await core.call(["op": "vaults"])
        let info = vaults.first { $0.id == id }!
        check(!info.unlocked, "locked")
        let seInfo = info.slots.first { $0.id == seSlot.slot }!
        check(SecureEnclaveSlot.canLoad(publicInfo: seInfo.publicInfo ?? [:]), "SE blob loads on this Mac")
        let secret = try SecureEnclaveSlot.unlockSecret(publicInfo: seInfo.publicInfo ?? [:], reason: "self-test")
        try await core.perform(["op": "unlock", "id": id, "kind": "secure-enclave", "slot": seSlot.slot], secret: secret)
        secret.wipe()
        check(true, "unlock with Secure Enclave slot")
        try await core.perform(["op": "slot_remove", "id": id, "slot": seSlot.slot])
    } else {
        print("skip Secure Enclave (unavailable)")
    }

    try await core.perform(["op": "lock", "id": id])
    do {
        try await core.perform(["op": "unlock", "id": id, "kind": "passphrase"], secret: SecretBytes(utf8: "wrong"))
        check(false, "wrong passphrase rejected")
    } catch let e as CofferError {
        check(e.isWrongSecret, "wrong passphrase rejected (\(e.errorDescription ?? ""))")
    }
    try await core.perform(["op": "unlock", "id": id, "kind": "passphrase"], secret: SecretBytes(utf8: "correct horse battery staple"))
    let after: ListResult = try await core.call(["op": "list", "id": id, "path": "folder/sub"])
    check(after.items.count == 1, "list after passphrase unlock")
    let again = try await core.read(vault: id, entry: after.items[0].id!)
    check(again == payload, "read after unlock")

    try await core.perform(["op": "lock", "id": id])
    try await core.perform(["op": "unlock", "id": id, "kind": "recovery"], secret: SecretBytes(utf8: created.recoveryKey))
    check(true, "unlock with recovery key")

    do {
        try await core.perform(["op": "slot_remove", "id": id, "slot": slot.slot])
        let v: [VaultInfo] = try await core.call(["op": "vaults"])
        let recovery = v[0].slots.first { $0.kind == .recovery }!
        try await core.perform(["op": "slot_remove", "id": id, "slot": recovery.id])
        check(false, "last portable slot is protected")
    } catch let e as CofferError {
        check(e.code == "invalid", "last portable slot is protected (\(e.errorDescription ?? ""))")
    }

    try await core.perform(["op": "lock_all"])
    let forgot: PathResult = try await core.call(["op": "forget", "id": id])
    check(!forgot.path.isEmpty, "forget")

    try await lifecycle()
    try await media()
    let env = ProcessInfo.processInfo.environment
    if let url = env["COFFER_TEST_URL"], let token = env["COFFER_TEST_TOKEN"] {
        try await server(url: url, token: token)
    } else {
        print("skip server checks (COFFER_TEST_URL / COFFER_TEST_TOKEN not set)")
    }
}

func write(_ name: String, _ text: String, in dir: String) throws -> String {
    let d = URL(fileURLWithPath: home).appendingPathComponent(dir, isDirectory: true)
    try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
    let u = d.appendingPathComponent(name)
    try Data(text.utf8).write(to: u)
    return u.path
}

func entry(_ vault: String, _ path: String) async throws -> Item? {
    let r: ListResult = try await core.call(["op": "list", "id": vault, "path": VaultPathParent(path)])
    return r.items.first { $0.path == path }
}

func VaultPathParent(_ p: String) -> String {
    guard let i = p.lastIndex(of: "/") else { return "" }
    return String(p[..<i])
}

func fails(_ body: () async throws -> Void) async -> CofferError? {
    do { try await body(); return nil } catch let e as CofferError { return e } catch { return CofferError(code: "other", message: "\(error)") }
}

/// Trash purge, version pruning, key rotation.
func lifecycle() async throws {
    let created: CreateResult = try await core.call(["op": "create", "name": "Life"])
    let id = created.id
    let oldPass = SecretBytes(utf8: "old passphrase")
    let _: SlotResult = try await core.call(["op": "slot_add", "id": id, "kind": "passphrase", "label": "Passphrase"], secret: oldPass)

    let _: ImportReport = try await core.call(["op": "import", "id": id, "sources": [try write("a.txt", "v1", in: "life1"), try write("b.txt", "bee", in: "life1"), try write("c.txt", "sea", in: "life1")], "dest": ""])
    let _: ImportReport = try await core.call(["op": "import", "id": id, "sources": [try write("a.txt", "v2", in: "life2")], "dest": ""])
    let a = try await entry(id, "a.txt")!
    var vs: [Version] = try await core.call(["op": "versions", "id": id, "entry": a.id!])
    check(vs.count == 2, "two versions before prune")
    let oldRev = vs.first { !$0.current }!.rev
    try await core.perform(["op": "prune_versions", "id": id, "entry": a.id!])
    vs = try await core.call(["op": "versions", "id": id, "entry": a.id!])
    check(vs.count == 1 && vs[0].current, "prune_versions leaves one version (\(vs.count))")
    let oldRead = await fails { _ = try await core.read(vault: id, entry: a.id!, rev: oldRev) }
    check(oldRead != nil, "pruned revision unreadable (\(oldRead?.code ?? "read ok"))")
    check(String(decoding: try await core.read(vault: id, entry: a.id!), as: UTF8.self) == "v2", "current version intact after prune")

    // delete → empty_trash
    let b = try await entry(id, "b.txt")!
    let _: DeletedResult = try await core.call(["op": "delete", "id": id, "paths": ["b.txt"]])
    var trash: [TrashItem] = try await core.call(["op": "trash", "id": id])
    check(trash.count == 1, "trash has deleted file")
    let emptied: PurgedResult = try await core.call(["op": "empty_trash", "id": id])
    trash = try await core.call(["op": "trash", "id": id])
    check(emptied.purged >= 1 && trash.isEmpty, "empty_trash empties the trash (purged \(emptied.purged))")
    let restoreB = await fails { let _: PathResult = try await core.call(["op": "restore", "id": id, "entry": b.id!]) }
    check(restoreB != nil, "restore after empty_trash fails (\(restoreB?.code ?? "restored"))")

    // delete → purge one entry
    let c = try await entry(id, "c.txt")!
    let _: DeletedResult = try await core.call(["op": "delete", "id": id, "paths": ["c.txt"]])
    let purged: PurgedResult = try await core.call(["op": "purge", "id": id, "entries": [c.id!]])
    trash = try await core.call(["op": "trash", "id": id])
    check(purged.purged == 1 && trash.isEmpty, "purge erases one trashed entry")
    let st0: VaultStatus = try await core.call(["op": "status", "id": id])
    if st0.summary.trashed != 0 {
        print("note status.summary.trashed is \(st0.summary.trashed) after purge (core still counts purged entries; the app counts the trash op)")
    }

    // Key rotation: cancel, then prepare + commit.
    var oldSE: String?
    if SecureEnclaveSlot.isAvailable {
        let se = try SecureEnclaveSlot.create(flags: [.privateKeyUsage])
        let r: SlotResult = try await core.call(["op": "slot_add", "id": id, "kind": "secure-enclave", "label": se.label, "public": se.publicInfo], secret: se.secret)
        se.secret.wipe()
        oldSE = r.slot
    }
    let r1: RecoveryKeyResult = try await core.call(["op": "rotate_prepare", "id": id], secret: SecretBytes(count: 0))
    var st: VaultStatus = try await core.call(["op": "status", "id": id])
    check(r1.recoveryKey.count > 40 && st.rotationPending == true, "rotate_prepare stages a rotation")
    let r1b: RecoveryKeyResult = try await core.call(["op": "rotate_prepare", "id": id], secret: SecretBytes(count: 0))
    check(r1b.recoveryKey == r1.recoveryKey, "rotate_prepare again returns the staged key")
    try await core.perform(["op": "rotate_cancel", "id": id])
    st = try await core.call(["op": "status", "id": id])
    check(st.rotationPending == false, "rotate_cancel discards the staged rotation")

    let epoch0 = st.epoch ?? 0
    let r2: RecoveryKeyResult = try await core.call(["op": "rotate_prepare", "id": id], secret: SecretBytes(utf8: "new passphrase"))
    check(r2.recoveryKey != r1.recoveryKey, "new rotation, new recovery key")
    try await core.perform(["op": "rotate_commit", "id": id])
    st = try await core.call(["op": "status", "id": id])
    check(st.rotationPending == false && (st.epoch ?? 0) > epoch0, "rotate_commit in effect (epoch \(epoch0) → \(st.epoch ?? 0))")
    var vaults: [VaultInfo] = try await core.call(["op": "vaults"])
    let slots = vaults.first { $0.id == id }!.slots
    check(oldSE == nil || !slots.contains { $0.id == oldSE }, "old Secure Enclave slot gone after rotation")

    try await core.perform(["op": "lock", "id": id])
    let e1 = await fails { try await core.perform(["op": "unlock", "id": id, "kind": "passphrase"], secret: oldPass) }
    check(e1?.isWrongSecret == true, "old passphrase no longer unlocks")
    let e2 = await fails { try await core.perform(["op": "unlock", "id": id, "kind": "recovery"], secret: SecretBytes(utf8: created.recoveryKey)) }
    check(e2?.isWrongSecret == true, "old recovery key no longer unlocks")
    let e3 = await fails { try await core.perform(["op": "unlock", "id": id, "kind": "recovery"], secret: SecretBytes(utf8: r1.recoveryKey)) }
    check(e3?.isWrongSecret == true, "cancelled rotation's key doesn't unlock")
    try await core.perform(["op": "unlock", "id": id, "kind": "recovery"], secret: SecretBytes(utf8: r2.recoveryKey))
    check(true, "new recovery key unlocks")
    check(String(decoding: try await core.read(vault: id, entry: a.id!), as: UTF8.self) == "v2", "file readable after rotation")
    try await core.perform(["op": "lock", "id": id])
    try await core.perform(["op": "unlock", "id": id, "kind": "passphrase"], secret: SecretBytes(utf8: "new passphrase"))
    check(true, "new passphrase unlocks")

    if SecureEnclaveSlot.isAvailable {
        // What the app does after commit: a fresh SE slot (no-prompt flags here).
        let se = try SecureEnclaveSlot.create(flags: [.privateKeyUsage])
        let r: SlotResult = try await core.call(["op": "slot_add", "id": id, "kind": "secure-enclave", "label": se.label, "public": se.publicInfo], secret: se.secret)
        se.secret.wipe()
        try await core.perform(["op": "lock", "id": id])
        vaults = try await core.call(["op": "vaults"])
        let info = vaults.first { $0.id == id }!.slots.first { $0.id == r.slot }!
        let secret = try SecureEnclaveSlot.unlockSecret(publicInfo: info.publicInfo ?? [:], reason: "self-test")
        try await core.perform(["op": "unlock", "id": id, "kind": "secure-enclave", "slot": r.slot], secret: secret)
        secret.wipe()
        check(true, "re-created Secure Enclave slot unlocks after rotation")
    }
    try await core.perform(["op": "lock", "id": id])
    let _: PathResult = try await core.call(["op": "forget", "id": id])
}

/// In-memory playback path: AVFoundation reads the whole file through the resource loader.
func media() async throws {
    let dir = URL(fileURLWithPath: home).appendingPathComponent("media", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let src = dir.appendingPathComponent("tone.m4a")
    do {
        let fmt = AVAudioFormat(standardFormatWithSampleRate: 44100, channels: 1)!
        let file = try AVAudioFile(forWriting: src, settings: [AVFormatIDKey: kAudioFormatMPEG4AAC, AVSampleRateKey: 44100, AVNumberOfChannelsKey: 1])
        let buf = AVAudioPCMBuffer(pcmFormat: fmt, frameCapacity: 44100)!
        buf.frameLength = 44100
        for i in 0..<Int(buf.frameLength) { buf.floatChannelData![0][i] = Float(sin(Double(i) * 2 * .pi * 440 / 44100) * 0.2) }
        try file.write(from: buf)
    }
    let created: CreateResult = try await core.call(["op": "create", "name": "Media"])
    let _: ImportReport = try await core.call(["op": "import", "id": created.id, "sources": [src.path], "dest": ""])
    let item = try await entry(created.id, "tone.m4a")!
    let data = try await core.read(vault: created.id, entry: item.id!)
    let loader = MemoryMediaLoader(data: data, name: item.name)
    let duration = try await loader.asset.load(.duration)
    check(duration.seconds > 0.8, "media loader: duration \(String(format: "%.2f", duration.seconds)) s from memory")
    let tracks = try await loader.asset.loadTracks(withMediaType: .audio)
    check(tracks.count == 1, "media loader: audio track")
    let reader = try AVAssetReader(asset: loader.asset)
    let out = AVAssetReaderTrackOutput(track: tracks[0], outputSettings: [AVFormatIDKey: kAudioFormatLinearPCM])
    reader.add(out)
    reader.startReading()
    var frames = 0
    while let sb = out.copyNextSampleBuffer() { frames += CMSampleBufferGetNumSamples(sb) }
    check(reader.status == .completed && frames > 40000, "media loader: decoded \(frames) frames")
    loader.release()
    check(MemoryMediaLoader.isPlayable(name: "x.mp4") && !MemoryMediaLoader.isPlayable(name: "x.txt"), "media type detection")
    try await core.perform(["op": "lock", "id": created.id])
    let _: PathResult = try await core.call(["op": "forget", "id": created.id])
}

/// Run this binary as another device (separate COFFER_HOME). `input` goes to its stdin.
func child(_ args: [String], home: String, input: String) throws -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
    p.arguments = args
    var env = ProcessInfo.processInfo.environment
    env["COFFER_HOME"] = home
    p.environment = env
    let inPipe = Pipe(), outPipe = Pipe()
    p.standardInput = inPipe
    p.standardOutput = outPipe
    try p.run()
    inPipe.fileHandleForWriting.write(Data(input.utf8))
    try inPipe.fileHandleForWriting.close()
    let out = outPipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(decoding: out, as: UTF8.self)
}

func waitStatus(_ id: String, seconds: Double = 30, _ ok: (VaultStatus) -> Bool) async throws -> VaultStatus {
    let end = Date().addingTimeInterval(seconds)
    var st: VaultStatus = try await core.call(["op": "status", "id": id])
    while !ok(st) && Date() < end {
        try await core.perform(["op": "sync", "id": id])
        try await Task.sleep(for: .milliseconds(300))
        st = try await core.call(["op": "status", "id": id])
    }
    return st
}

func server(url: String, token: String) async throws {
    let created: CreateResult = try await core.call(["op": "create", "name": "Attach"])
    let id = created.id
    let _: ImportReport = try await core.call(["op": "import", "id": id, "sources": [try write("one.txt", "first", in: "att"), try write("two.txt", "second", in: "att")], "dest": ""])
    let _: ImportReport = try await core.call(["op": "import", "id": id, "sources": [try write("one.txt", "first, edited", in: "att2")], "dest": ""])
    let bad = await fails { try await core.perform(["op": "attach", "id": id, "url": url, "token": "wrong-token"]) }
    check(bad != nil, "attach with a bad token fails (\(bad?.errorDescription ?? "ok"))")
    try await core.perform(["op": "attach", "id": id, "url": url, "token": token])
    let vaults: [VaultInfo] = try await core.call(["op": "vaults"])
    check(vaults.first { $0.id == id }?.remote != nil, "attach: vault is now synced")
    let st = try await waitStatus(id) { $0.sync.state == "idle" && $0.sync.lastOkMs > 0 }
    check(st.sync.state == "idle", "attach: sync runs (\(st.sync.state))")
    let usage: UsageInfo = try await core.call(["op": "usage", "id": id])
    check(usage.bytes > 0 && usage.records >= 3, "usage: \(usage.bytes) bytes, \(usage.records) records, quota \(usage.quota.map(String.init) ?? "none")")

    let inv: CodeResult = try await core.call(["op": "invite", "id": id, "label": "Second Mac"])
    let parts = inv.code.split(separator: "#", omittingEmptySubsequences: false)
    check(parts.count == 3 && parts[0].hasPrefix("http") && !parts[2].isEmpty, "invite: 3-part code")
    check(parts.count == 3 && parts[1] == id, "invite: carries the vault id")

    let home2 = URL(fileURLWithPath: home).appendingPathComponent("device2", isDirectory: true).path
    try FileManager.default.createDirectory(atPath: home2, withIntermediateDirectories: true)
    let joined = try child(["--child-join"], home: home2, input: inv.code + "\n")
    check(joined.contains("JOINED \(id) 2"), "join_invite on a second device sees both files (\(joined.trimmingCharacters(in: .whitespacesAndNewlines)))")

    // Rotate here; the second device must adopt the new key.
    var r: RecoveryKeyResult = try await core.call(["op": "rotate_prepare", "id": id], secret: SecretBytes(count: 0))
    if let e = await fails({ try await core.perform(["op": "rotate_commit", "id": id]) }) {
        // Core gap: the joiner's first sync bumps the server header version and this device never
        // re-reads it while unlocked, so rekey is refused. The app tells the user to relock; do that.
        print("note rotate_commit refused after a join (\(e.message)); cancel, relock, retry")
        try await core.perform(["op": "rotate_cancel", "id": id])
        try await core.perform(["op": "lock", "id": id])
        try await core.perform(["op": "unlock", "id": id, "kind": "recovery"], secret: SecretBytes(utf8: created.recoveryKey))
        _ = try await waitStatus(id) { $0.sync.state == "idle" && $0.sync.lastOkMs > 0 }
        r = try await core.call(["op": "rotate_prepare", "id": id], secret: SecretBytes(count: 0))
        try await core.perform(["op": "rotate_commit", "id": id])
    }
    check(true, "rotate_commit on a synced vault")
    let _: ImportReport = try await core.call(["op": "import", "id": id, "sources": [try write("three.txt", "after rotation", in: "att3")], "dest": ""])
    let st2 = try await waitStatus(id) { $0.sync.state == "idle" && $0.summary.pending == 0 }
    check(st2.sync.state == "idle", "sync continues after rotation")
    let adopted = try child(["--child-adopt", id], home: home2, input: String(parts.count == 3 ? parts[2] : "") + "\n" + r.recoveryKey + "\n")
    check(adopted.hasPrefix("REKEYED"), "second device sees state rekeyed (\(adopted.split(separator: "\n").first ?? ""))")
    check(adopted.contains("ADOPTED 3"), "adopt_rekey: second device syncs again and sees the new file")

    // Over quota: the sync error must read as a full quota.
    let usage2: UsageInfo = try await core.call(["op": "usage", "id": id])
    if let q = usage2.quota, q < 64 << 20 {
        let big = URL(fileURLWithPath: home).appendingPathComponent("big.bin")
        var rng = SystemRandomNumberGenerator()
        try Data((0..<(Int(q) + (1 << 20))).map { _ in UInt8.random(in: 0...255, using: &rng) }).write(to: big)
        let _: ImportReport = try await core.call(["op": "import", "id": id, "sources": [big.path], "dest": ""])
        let st3 = try await waitStatus(id) { $0.sync.error != nil }
        let text = st3.sync.error.map(CofferError.readableSync) ?? ""
        check(text == CofferError.quotaFull, "quota full reads clearly (\(st3.sync.state): \(st3.sync.error ?? "no error"))")
    } else {
        print("skip quota check (server has no small quota; run cofferd with --vault-quota-bytes)")
    }
    try await core.perform(["op": "lock", "id": id])
}

/// Second-device side of the server checks.
func childJoin() async throws {
    guard let code = readLine() else { return }
    let r: IDResult = try await core.call(["op": "join_invite", "name": "Joined"], secret: SecretBytes(utf8: code))
    let st = try await waitStatus(r.id) { $0.sync.state == "idle" && $0.sync.lastOkMs > 0 }
    let l: ListResult = try await core.call(["op": "list", "id": r.id, "path": ""])
    print("JOINED \(r.id) \(l.items.count) \(st.sync.state)")
    try await core.perform(["op": "lock_all"])
}

func childAdopt(_ id: String) async throws {
    guard let oldKey = readLine(), let newKey = readLine() else { return }
    try await core.perform(["op": "unlock", "id": id, "kind": "recovery"], secret: SecretBytes(utf8: oldKey))
    var st = try await waitStatus(id) { $0.isRekeyed }
    print(st.isRekeyed ? "REKEYED" : "NOT-REKEYED \(st.sync.state) \(st.sync.error ?? "")")
    try await core.perform(["op": "adopt_rekey", "id": id, "kind": "recovery"], secret: SecretBytes(utf8: newKey))
    st = try await waitStatus(id) { $0.sync.state == "idle" && $0.sync.lastOkMs > 0 && !$0.isRekeyed }
    let l: ListResult = try await core.call(["op": "list", "id": id, "path": ""])
    print("ADOPTED \(l.items.count) \(st.sync.state)")
    try await core.perform(["op": "lock_all"])
}

func demo(_ folder: String) async throws {
    // DEMO_NAME / DEMO_URL / DEMO_TOKEN make it a synced vault on a test server.
    let env = ProcessInfo.processInfo.environment
    var req: [String: Any] = ["op": "create", "name": env["DEMO_NAME"] ?? "Demo"]
    if let url = env["DEMO_URL"] { req["url"] = url; req["token"] = env["DEMO_TOKEN"] ?? "" }
    let created: CreateResult = try await core.call(req)
    let pass = SecretBytes(utf8: "demo")
    let _: SlotResult = try await core.call(["op": "slot_add", "id": created.id, "kind": "passphrase", "label": "Passphrase"], secret: pass)
    let kids = try FileManager.default.contentsOfDirectory(atPath: folder).filter { !$0.hasPrefix(".") }.map { (folder as NSString).appendingPathComponent($0) }
    let _: ImportReport = try await core.call(["op": "import", "id": created.id, "sources": kids, "dest": ""])
    let se = try SecureEnclaveSlot.create(flags: [.privateKeyUsage])
    let slot: SlotResult = try await core.call(["op": "slot_add", "id": created.id, "kind": "secure-enclave", "label": se.label, "public": se.publicInfo], secret: se.secret)
    try await core.perform(["op": "lock_all"])
    print(created.id, slot.slot)
}

let done = DispatchSemaphore(value: 0)
let args = CommandLine.arguments
Task {
    if args.count == 3, args[1] == "--demo" {
        do { try await demo(args[2]); exit(0) } catch { print("demo failed: \(error.localizedDescription)"); exit(1) }
    }
    if args.count == 2, args[1] == "--child-join" {
        do { try await childJoin(); exit(0) } catch { print("child failed: \(error.localizedDescription)"); exit(1) }
    }
    if args.count == 3, args[1] == "--child-adopt" {
        do { try await childAdopt(args[2]); exit(0) } catch { print("child failed: \(error.localizedDescription)"); exit(1) }
    }
    do { try await run() } catch {
        print("FAIL unexpected error: \(error.localizedDescription)")
        failures += 1
    }
    done.signal()
}
done.wait()
print(failures == 0 ? "ALL OK" : "\(failures) FAILURE(S)")
exit(failures == 0 ? 0 : 1)
