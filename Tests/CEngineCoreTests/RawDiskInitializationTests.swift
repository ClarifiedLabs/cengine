#if os(macOS)
import Darwin
import Foundation
import Synchronization
import Testing
import XCTest
@testable import CEngineRuntime

@Suite struct RawDiskInitializationTests {
    @Test(arguments: [UInt64(4096), 64 << 30, 512 << 30])
    func createsOnlyNewSparseDisks(size: UInt64) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        guard case .created(let disk) = try f.create(size: size) else { Issue.record("not created"); return }
        let record = disk.record
        #expect(record.state == .created)
        #expect(record.expectedSize == size)
        #expect(record.binding == nil)
        #expect(record.ext4UUID != record.operationUUID)
        #expect(UUID(uuidString: record.ext4UUID)?.uuidString.lowercased() == record.ext4UUID)
        let identity = try f.directory.regularFileIdentity(named: f.name, expectedSize: size)
        #expect(record.schemaVersion == 2)
        #expect(record.diskIdentity.inode == identity.inode)
        #expect(record.diskIdentity.volumeUUID == identity.volumeUUID?.uuidString.lowercased())
        var info = stat()
        try #require(lstat(f.disk.path, &info) == 0)
        #expect(info.st_blocks < 1024) // Sparse: never read or write GiBs in this test.
        #expect(info.st_mode & 0o777 == 0o600)
        let bytes = try Data(contentsOf: f.record(.created))
        guard case .alreadyExists = try f.create(size: size) else { Issue.record("adopted existing disk"); return }
        #expect(try Data(contentsOf: f.record(.created)) == bytes)
        #expect(try f.inspect(size: size) == .journal(record))
    }

    @Test func durableRecordAcceptsNewBootDevicesButLiveObservationsDoNot() throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        guard case .created(let disk) = try f.create() else { Issue.record("not created"); return }
        let record = disk.record
        let identities = [record.diskIdentity, record.parentIdentity, record.lockIdentity]
        func observations(device: UInt64) throws -> [RawDiskInitialization.LiveObservation] {
            try identities.map {
                try .init(PersistentFileIdentity(device: device, inode: $0.inode,
                                                volumeUUID: UUID(uuidString: $0.volumeUUID)))
            }
        }
        let before = try observations(device: 11)
        let after = try observations(device: 99)
        #expect(record.matches(disk: before[0], parent: before[1], lock: before[2]))
        #expect(record.matches(disk: after[0], parent: after[1], lock: after[2]))
        for index in identities.indices {
            try before[index].requireSame(as: before[index])
            #expect(throws: RawDiskInitialization.Failure.unsafePath) {
                try before[index].requireSame(as: after[index])
            }
            for changedVolume in [false, true] {
                var replaced = after
                replaced[index] = try .init(PersistentFileIdentity(device: 99,
                    inode: changedVolume ? identities[index].inode : identities[index].inode + 1,
                    volumeUUID: changedVolume ? UUID() : UUID(uuidString: identities[index].volumeUUID)))
                #expect(!record.matches(disk: replaced[0], parent: replaced[1], lock: replaced[2]))
            }
        }
        let json = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: f.record(.created))) as? [String: Any])
        for key in ["diskIdentity", "parentIdentity", "lockIdentity"] {
            let identity = try #require(json[key] as? [String: Any])
            #expect(Set(identity.keys) == Set(["inode", "volumeUUID"]))
        }
    }

    @Test(arguments: [false, true])
    func oldSchemaRefusesWithoutChangingArtifacts(legacyDeviceFields: Bool) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        _ = try f.create()
        var json = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: f.record(.created))) as? [String: Any])
        json["schemaVersion"] = 1
        if legacyDeviceFields {
            for key in ["diskIdentity", "parentIdentity", "lockIdentity"] {
                var identity = try #require(json[key] as? [String: Any])
                identity["device"] = 11
                json[key] = identity
            }
        }
        try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
            .write(to: f.record(.created))
        let names = try f.directory.entryNames().sorted()
        let bytes = try names.map { try Data(contentsOf: f.directory.url.appending(path: $0)) }
        let identities = try names.map { try f.directory.regularFileIdentity(named: $0) }
        let held = try f.directory.openRegularFile(named: f.name, access: .readWrite).handle
        defer { try? held.close() }
        #expect(try RawDiskInitialization.inspectReadOnly(in: f.directory, named: f.name,
            expectedSize: f.size, heldDiskDescriptor: held.fileDescriptor) == .quarantined)
        #expect(try f.inspect() == .quarantined)
        #expect(throws: RawDiskInitialization.Failure.quarantined) { try f.begin() }
        #expect(try f.directory.entryNames().sorted() == names)
        #expect(try names.map { try Data(contentsOf: f.directory.url.appending(path: $0)) } == bytes)
        #expect(try names.map { try f.directory.regularFileIdentity(named: $0) } == identities)
    }

    @Test(arguments: ["diskIdentity", "parentIdentity", "lockIdentity"],
          ["missing-volume", "zero-volume", "missing-inode", "zero-inode", "device"])
    func durableIdentityRequiresOnlyNonzeroVolumeAndInode(key: String, mutation: String) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        _ = try f.create()
        var json = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: f.record(.created))) as? [String: Any])
        var identity = try #require(json[key] as? [String: Any])
        switch mutation {
        case "missing-volume": identity.removeValue(forKey: "volumeUUID")
        case "zero-volume": identity["volumeUUID"] = "00000000-0000-0000-0000-000000000000"
        case "missing-inode": identity.removeValue(forKey: "inode")
        case "zero-inode": identity["inode"] = 0
        default: identity["device"] = 11
        }
        json[key] = identity
        let bytes = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
        try bytes.write(to: f.record(.created))
        #expect(try f.inspect() == .quarantined)
        #expect(throws: RawDiskInitialization.Failure.quarantined) { try f.begin() }
        #expect(try Data(contentsOf: f.record(.created)) == bytes)
    }

    @Test func readOnlyInspectionNeverCreatesMissingLockOrArtifacts() throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        let before = try f.directory.entryNames()
        #expect(throws: (any Error).self) {
            try RawDiskInitialization.inspectExisting(in: f.directory, named: f.name, expectedSize: 4096, createLock: false)
        }
        #expect(try f.directory.entryNames() == before)
        guard case .created(let disk) = try f.create(size: 4096) else { Issue.record("not created"); return }
        #expect(try RawDiskInitialization.inspectExisting(in: f.directory, named: f.name,
            expectedSize: 4096, createLock: false) == .journal(disk.record))
    }
    @Test func mountOnlyInspectionRejectsAReplacedHeldDisk() throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        try Data(repeating: 0, count: Int(f.size)).write(to: f.disk)
        let held = try f.directory.openRegularFile(named: f.name, access: .readWrite).handle
        defer { try? held.close() }
        #expect(try RawDiskInitialization.inspectExisting(in: f.directory, named: f.name,
            expectedSize: f.size, heldDiskDescriptor: held.fileDescriptor) == .mountOnly)
        try FileManager.default.moveItem(at: f.disk, to: f.root.appending(path: "saved"))
        try Data(repeating: 0, count: Int(f.size)).write(to: f.disk)
        #expect(try RawDiskInitialization.inspectExisting(in: f.directory, named: f.name,
            expectedSize: f.size, heldDiskDescriptor: held.fileDescriptor) == .quarantined)
        #expect(!FileManager.default.fileExists(atPath: f.record(.created).path))
    }

    @Test func heldDescriptorMustMatchBeforeBeginAndCompletion() throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        _ = try f.create()
        let held = try f.directory.openRegularFile(named: f.name, access: .readWrite).handle
        let other = f.directory.url.appending(path: "other.ext4")
        try Data(repeating: 0, count: Int(f.size)).write(to: other)
        let wrong = try FileHandle(forUpdating: other)
        defer { try? held.close(); try? wrong.close() }
        #expect(throws: (any Error).self) {
            try RawDiskInitialization.begin(in: f.directory, named: f.name, expectedSize: f.size,
                                            binding: f.binding, heldDiskDescriptor: wrong.fileDescriptor)
        }
        #expect(!FileManager.default.fileExists(atPath: f.record(.spent).path))
        let spent = try #require(try RawDiskInitialization.begin(
            in: f.directory, named: f.name, expectedSize: f.size,
            binding: f.binding, heldDiskDescriptor: held.fileDescriptor
        )).record
        #expect(throws: (any Error).self) {
            try RawDiskInitialization.completeAfterVerifiedGuestSync(
                in: f.directory, named: f.name, expectedSize: f.size,
                operationUUID: UUID(uuidString: spent.operationUUID)!, ext4UUID: UUID(uuidString: spent.ext4UUID)!,
                binding: f.binding, heldDiskDescriptor: wrong.fileDescriptor
            )
        }
        #expect(!FileManager.default.fileExists(atPath: f.record(.initialized).path))
        #expect(try f.inspect() == .journal(spent))
    }

    @Test func oneShotAndExactIdempotentCompletion() throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        _ = try f.create()
        let createdBytes = try Data(contentsOf: f.record(.created))
        let authorization = try #require(try f.begin())
        let spent = authorization.record
        #expect(spent.state == .spent)
        #expect(spent.binding == f.binding)
        #expect(try f.reopen().inspect() == .journal(spent))
        #expect(throws: RawDiskInitialization.Failure.alreadySpent) { try f.begin() }
        #expect(throws: RawDiskInitialization.Failure.alreadySpent) {
            try RawDiskInitialization.begin(in: f.directory, named: f.name, expectedSize: f.size,
                                            binding: .init(shimLaunchUUID: UUID(), guestBootNonce: UUID()))
        }
        for mismatch in 0..<4 {
            #expect(throws: RawDiskInitialization.Failure.acknowledgementMismatch) {
                try f.complete(spent, mismatch: mismatch)
            }
        }
        try f.complete(spent)
        let initializedBytes = try Data(contentsOf: f.record(.initialized))
        try f.reopen().complete(spent)
        #expect(try Data(contentsOf: f.record(.initialized)) == initializedBytes)
        #expect(try Data(contentsOf: f.record(.created)) == createdBytes)
        #expect(try f.begin() == nil)
        guard case .journal(let initialized) = try f.inspect() else { Issue.record("missing journal"); return }
        #expect(initialized.state == .initialized)
        #expect(initialized.operationUUID == spent.operationUUID)
    }

    @Test(arguments: [0, 17, 4096, 8192])
    func existingBytesNeverBecomeFresh(size: Int) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        let bytes = Data(repeating: size == 4096 ? 0 : 0xA5, count: size)
        try bytes.write(to: f.disk)
        let identity = try f.directory.regularFileIdentity(named: f.name)
        guard case .alreadyExists = try f.create() else { Issue.record("existing became fresh"); return }
        #expect(try f.inspect() == (size == 4096 ? .mountOnly : .quarantined))
        if size == 4096 { #expect(try f.begin() == nil) }
        else { #expect(throws: (any Error).self) { try f.begin() } }
        #expect(try Data(contentsOf: f.disk) == bytes)
        #expect(try f.directory.regularFileIdentity(named: f.name) == identity)
        #expect(!FileManager.default.fileExists(atPath: f.record(.created).path))
    }

    @Test func concurrentCreatorsAndBeginsHaveExactlyOneWinner() throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        let creations = Mutex<[Result<RawDiskInitialization.Creation, any Error>]>([])
        DispatchQueue.concurrentPerform(iterations: 12) { _ in
            let result = Result { try f.create() }
            creations.withLock { $0.append(result) }
        }
        let values = try creations.withLock { try $0.map { try $0.get() } }
        #expect(values.filter { if case .created = $0 { true } else { false } }.count == 1)
        #expect(values.filter { if case .alreadyExists = $0 { true } else { false } }.count == 11)
        let begins = Mutex<[Result<RawDiskInitialization.Authorization?, any Error>]>([])
        DispatchQueue.concurrentPerform(iterations: 12) { _ in
            let result = Result { try f.begin() }
            begins.withLock { $0.append(result) }
        }
        begins.withLock { results in
            #expect(results.filter { if case .success(.some) = $0 { true } else { false } }.count == 1)
            #expect(results.filter {
                if case .failure(let error) = $0 { return error as? RawDiskInitialization.Failure == .alreadySpent }
                return false
            }.count == 11)
        }
    }

    @Test(arguments: ["regular", "symlink", "directory", "nonempty", "hardlink"])
    func preexistingLockMustBeSafeAndRetainsIdentity(kind: String) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        switch kind {
        case "symlink":
            let target = f.root.appending(path: "target")
            try Data().write(to: target)
            try #require(symlink(target.path, f.lock.path) == 0)
        case "directory":
            try FileManager.default.createDirectory(at: f.lock, withIntermediateDirectories: false)
        default:
            try (kind == "nonempty" ? Data([1]) : Data()).write(to: f.lock)
            if kind == "hardlink" {
                try #require(link(f.lock.path, f.root.appending(path: "alias").path) == 0)
            }
        }
        guard kind == "regular" else {
            #expect(throws: (any Error).self) { try f.create() }
            #expect(!FileManager.default.fileExists(atPath: f.disk.path))
            #expect(!FileManager.default.fileExists(atPath: f.record(.created).path))
            return
        }
        let identity = try f.directory.regularFileIdentity(named: f.lock.lastPathComponent)
        guard case .created(let disk) = try f.create() else {
            Issue.record("safe preexisting lock prevented creation")
            return
        }
        #expect(disk.record.lockIdentity.inode == identity.inode)
        #expect(disk.record.lockIdentity.volumeUUID == identity.volumeUUID?.uuidString.lowercased())
        #expect(try f.directory.regularFileIdentity(named: f.lock.lastPathComponent) == identity)
    }

    @Test(arguments: ["disk", "lock", "parent", "size", "hardlink", "symlink", "record-symlink", "record-hardlink"])
    func replacedOrAliasedIdentitiesFailClosed(kind: String) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        _ = try f.create()
        let sentinel = Data(repeating: 0xA5, count: Int(f.size))
        switch kind {
        case "parent":
            try FileManager.default.moveItem(at: f.directory.url, to: f.root.appending(path: "displaced"))
            try FileManager.default.createDirectory(at: f.directory.url, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            try sentinel.write(to: f.disk)
        case "size":
            let handle = try FileHandle(forWritingTo: f.disk)
            try handle.truncate(atOffset: 17)
            try handle.close()
        case "hardlink", "record-hardlink":
            let source = kind == "hardlink" ? f.disk : f.record(.created)
            try #require(link(source.path, f.root.appending(path: "alias").path) == 0)
        default:
            let victim = kind == "lock" ? f.lock : (kind == "record-symlink" ? f.record(.created) : f.disk)
            try FileManager.default.moveItem(at: victim, to: f.root.appending(path: "saved"))
            if kind == "symlink" || kind == "record-symlink" {
                try #require(symlink(f.root.appending(path: "saved").path, victim.path) == 0)
            } else { try (kind == "lock" ? Data() : sentinel).write(to: victim) }
        }
        #expect(throws: (any Error).self) { try f.begin() }
        #expect(!FileManager.default.fileExists(atPath: f.record(.spent).path))
        if kind == "disk" || kind == "parent" { #expect(try Data(contentsOf: f.disk) == sentinel) }
    }

    @Test(arguments: ["../disk", "/disk", ".", "..", "a/b", "a\u{0}b", ".raw-init-disk", "a%2fb"])
    func invalidDiskComponentsAreRejected(name: String) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        #expect(throws: RawDiskInitialization.Failure.unsafePath) {
            try RawDiskInitialization.createNewDisk(in: f.directory, named: name, size: 4096)
        }
        #expect(try f.directory.entryNames().isEmpty)
    }

    @Test func directorySymlinkAndNonPrivateParentAreRejected() throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        let alias = f.root.appending(path: "alias")
        try #require(symlink(f.directory.url.path, alias.path) == 0)
        #expect(throws: (any Error).self) { try PersistentStateDirectory.open(alias) }
        try #require(chmod(f.directory.url.path, 0o755) == 0)
        #expect(throws: RawDiskInitialization.Failure.unsafePath) { try f.create() }
        #expect(!FileManager.default.fileExists(atPath: f.disk.path))
    }

    @Test(arguments: [false, true])
    func extendedACLIsNotOwnerPrivate(onDisk: Bool) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        _ = try f.create()
        let command = Process()
        command.executableURL = URL(filePath: "/bin/chmod")
        command.arguments = ["+a", "everyone allow read,write,delete", (onDisk ? f.disk : f.directory.url).path]
        try command.run()
        command.waitUntilExit()
        try #require(command.terminationStatus == 0)
        #expect(throws: (any Error).self) { try f.begin() }
        #expect(!FileManager.default.fileExists(atPath: f.record(.spent).path))
    }

    @Test(arguments: ["truncated", "oversized", "unknown", "duplicate", "schema", "uppercase", "missing-identity", "device", "missing-created", "binding", "preexisting"])
    func malformedOrInconsistentRecordsNeverAuthorize(kind: String) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        if kind == "preexisting" {
            try Data("old".utf8).write(to: f.record(.created))
            #expect(throws: RawDiskInitialization.Failure.quarantined) { try f.create() }
            #expect(try Data(contentsOf: f.record(.created)) == Data("old".utf8))
            #expect(!FileManager.default.fileExists(atPath: f.disk.path))
            return
        }
        _ = try f.create()
        let original = try Data(contentsOf: f.record(.created))
        var json = try #require(JSONSerialization.jsonObject(with: original) as? [String: Any])
        var bytes: Data
        switch kind {
        case "truncated": bytes = Data(original.prefix(17))
        case "oversized": bytes = Data(repeating: 32, count: RawDiskInitialization.maximumRecordBytes + 1)
        case "duplicate": bytes = Data(("{\"schemaVersion\":2," + String(decoding: original.dropFirst(), as: UTF8.self)).utf8)
        case "missing-created":
            _ = try f.begin()
            try FileManager.default.removeItem(at: f.record(.created))
            #expect(try f.inspect() == .quarantined)
            #expect(throws: (any Error).self) { try f.begin() }
            return
        default:
            if kind == "unknown" { json["extra"] = true }
            if kind == "schema" { json["schemaVersion"] = 3 }
            if kind == "uppercase" { json["ext4UUID"] = (json["ext4UUID"] as? String)?.uppercased() }
            if kind == "binding" { json["binding"] = ["shimLaunchUUID": UUID().uuidString.lowercased(), "guestBootNonce": UUID().uuidString.lowercased()] }
            if kind == "device" || kind == "missing-identity" {
                var identity = try #require(json["diskIdentity"] as? [String: Any])
                if kind == "device" { identity["device"] = 11 }
                else { identity.removeValue(forKey: "volumeUUID") }
                json["diskIdentity"] = identity
            }
            bytes = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
        }
        try bytes.write(to: f.record(.created))
        #expect(try f.inspect() == .quarantined)
        #expect(throws: (any Error).self) { try f.begin() }
        #expect(try Data(contentsOf: f.record(.created)) == bytes)
        #expect(try Data(contentsOf: f.disk) == Data(repeating: 0, count: Int(f.size)))
    }

    @Test(arguments: [RawDiskInitialization.Boundary.diskCreated, .diskSynchronized, .recordPrepared, .recordPublished, .recordSynchronized])
    func creationFaultsPreserveEvidenceAndNeverReturnAuthority(boundary: RawDiskInitialization.Boundary) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        #expect(throws: POSIXError.self) {
            try f.create { point, _ in if point == boundary { throw POSIXError(.EIO) } }
        }
        #expect(FileManager.default.fileExists(atPath: f.disk.path))
        #expect(try f.reopen().inspect() == .quarantined)
        guard case .alreadyExists = try f.create() else { Issue.record("reconstituted freshness"); return }
        #expect(throws: (any Error).self) { try f.begin() }
    }

    @Test(arguments: [RawDiskInitialization.Boundary.recordPrepared, .recordPublished, .recordSynchronized, .beforeFullSync])
    func transitionPersistenceFaultIsQuarantined(boundary: RawDiskInitialization.Boundary) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        _ = try f.create()
        #expect(throws: POSIXError.self) {
            try f.begin { point, _ in if point == boundary { throw POSIXError(.EIO) } }
        }
        #expect(try f.reopen().inspect() == .quarantined)
        #expect(throws: RawDiskInitialization.Failure.quarantined) { try f.begin() }
    }

    @Test(arguments: [RawDiskInitialization.Boundary.recordPrepared, .recordPublished, .beforeFullSync, .recordSynchronized])
    func completionFaultsNeverRestoreFormatAuthority(boundary: RawDiskInitialization.Boundary) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        _ = try f.create()
        let spent = try #require(try f.begin()).record
        #expect(throws: POSIXError.self) {
            try f.complete(spent) { point, _ in if point == boundary { throw POSIXError(.EIO) } }
        }
        #expect(try f.reopen().inspect() == .quarantined)
        #expect(throws: (any Error).self) { try f.begin() }
    }

    @Test(arguments: ["beforeCreatedRecord", "createdPrepared", "spentPrepared", "spentPublished", "spentDurable", "lostBeginReply", "lostCompletionReply", "completionPublished"])
    func processDeathNeverReissuesFormat(scenario: String) throws {
        let f = try InitializationFixture()
        defer { f.remove() }
        if scenario != "beforeCreatedRecord" && scenario != "createdPrepared" { _ = try f.create() }
        let child = Process()
        child.executableURL = URL(filePath: "/usr/bin/xcrun")
        child.arguments = ["xctest", "-XCTest", "CEngineCoreTests.RawDiskInitializationProcessTests/testWorker",
                           Bundle(for: RawDiskInitializationProcessTests.self).bundleURL.path]
        // An independent xctest must not inherit its parent's IDE session.
        var environment = ProcessInfo.processInfo.environment.filter {
            !$0.key.hasPrefix("XCTest") && !$0.key.hasPrefix("XCInject")
                && $0.key != "DYLD_INSERT_LIBRARIES"
        }
        environment["CENGINE_RAW_INIT_TEST_ROOT"] = f.root.path
        environment["CENGINE_RAW_INIT_TEST_SCENARIO"] = scenario
        child.environment = environment
        let output = Pipe()
        child.standardOutput = output
        child.standardError = output
        let ended = DispatchSemaphore(value: 0)
        child.terminationHandler = { _ in ended.signal() }
        try child.run()
        if ended.wait(timeout: .now() + 30) != .success {
            kill(child.processIdentifier, SIGKILL)
            child.waitUntilExit()
            throw POSIXError(.ETIMEDOUT)
        }
        let log = try output.fileHandleForReading.readToEnd() ?? Data()
        child.waitUntilExit()
        try #require(child.terminationStatus == 86, "child did not reach crash boundary: \(String(decoding: log, as: UTF8.self))")
        let inspection = try f.reopen().inspect()
        switch scenario {
        case "beforeCreatedRecord":
            #expect(inspection == .mountOnly)
            #expect(try f.begin() == nil)
            guard case .alreadyExists = try f.create() else { Issue.record("crashed disk became fresh"); return }
        case "createdPrepared", "spentPrepared":
            #expect(inspection == .quarantined)
            #expect(throws: RawDiskInitialization.Failure.quarantined) { try f.begin() }
        case "lostCompletionReply", "completionPublished":
            guard case .journal(let record) = inspection else { Issue.record("missing completion"); return }
            #expect(record.state == .initialized)
            var synchronized = false
            try f.complete(record) { point, _ in
                if point == .recordSynchronized { synchronized = true }
            }
            #expect(synchronized)
            #expect(try f.begin() == nil)
        default:
            guard case .journal(let record) = inspection else { Issue.record("missing spent record"); return }
            #expect(record.state == .spent)
            #expect(throws: RawDiskInitialization.Failure.alreadySpent) { try f.begin() }
        }
    }
}

// XCTest supplies a reliably selectable subprocess entry point. All assertions
// are Swift Testing above; no Swift/Foundation code runs between fork and exec.
final class RawDiskInitializationProcessTests: XCTestCase {
    func testWorker() throws {
        guard let root = ProcessInfo.processInfo.environment["CENGINE_RAW_INIT_TEST_ROOT"],
              let scenario = ProcessInfo.processInfo.environment["CENGINE_RAW_INIT_TEST_SCENARIO"] else { return }
        let f = try InitializationFixture(root: URL(filePath: root))
        if scenario == "beforeCreatedRecord" || scenario == "createdPrepared" {
            _ = try f.create { point, _ in
                if (scenario == "beforeCreatedRecord" && point == .diskSynchronized)
                    || (scenario == "createdPrepared" && point == .recordPrepared) { _exit(86) }
            }
        } else {
            let authorization = try f.begin { point, _ in
                if (scenario == "spentPrepared" && point == .recordPrepared)
                    || (scenario == "spentPublished" && point == .recordPublished)
                    || (scenario == "spentDurable" && point == .recordSynchronized) { _exit(86) }
            }
            if scenario == "lostCompletionReply" || scenario == "completionPublished", let authorization {
                try f.complete(authorization.record) { point, _ in
                    if scenario == "completionPublished" && point == .recordPublished { _exit(86) }
                }
            }
            _exit(86)
        }
        XCTFail("crash boundary not reached")
    }
}

private struct InitializationFixture: Sendable {
    let root: URL
    let directory: PersistentStateDirectory
    let name = "root.ext4"
    let size: UInt64 = 4096
    // Fixed only in the test fixture so a fresh child can supply the same binding.
    let binding = RawDiskInitialization.Binding(shimLaunchUUID: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
                                                guestBootNonce: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!)
    var disk: URL { directory.url.appending(path: name) }
    var lock: URL { directory.url.appending(path: ".raw-init-\(name).lock") }
    func record(_ state: RawDiskInitialization.State) -> URL { directory.url.appending(path: ".raw-init-\(name).\(state.rawValue).json") }

    init(root existing: URL? = nil) throws {
        root = existing ?? FileManager.default.temporaryDirectory.appending(path: "cengine-raw-initialization-\(UUID())")
        if existing == nil {
            try FileManager.default.createDirectory(at: root.appending(path: "private"), withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        directory = try PersistentStateDirectory.open(root.appending(path: "private"))
    }
    func reopen() throws -> InitializationFixture { try InitializationFixture(root: root) }
    func remove() { try? FileManager.default.removeItem(at: root) }
    func create(size: UInt64 = 4096, hook: RawDiskInitialization.Hook? = nil) throws -> RawDiskInitialization.Creation {
        try RawDiskInitialization.createNewDisk(in: directory, named: name, size: size, hook: hook)
    }
    func inspect(size: UInt64 = 4096) throws -> RawDiskInitialization.Inspection {
        try RawDiskInitialization.inspectExisting(in: directory, named: name, expectedSize: size)
    }
    func begin(hook: RawDiskInitialization.Hook? = nil) throws -> RawDiskInitialization.Authorization? {
        try RawDiskInitialization.begin(in: directory, named: name, expectedSize: size, binding: binding, hook: hook)
    }
    func complete(_ record: RawDiskInitialization.Record, mismatch: Int? = nil, hook: RawDiskInitialization.Hook? = nil) throws {
        try RawDiskInitialization.completeAfterVerifiedGuestSync(
            in: directory, named: name, expectedSize: size,
            operationUUID: mismatch == 0 ? UUID() : UUID(uuidString: record.operationUUID)!,
            ext4UUID: mismatch == 1 ? UUID() : UUID(uuidString: record.ext4UUID)!,
            binding: .init(shimLaunchUUID: mismatch == 2 ? UUID() : UUID(uuidString: binding.shimLaunchUUID)!,
                           guestBootNonce: mismatch == 3 ? UUID() : UUID(uuidString: binding.guestBootNonce)!), hook: hook)
    }
}
#endif
