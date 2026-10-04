#if os(macOS) && CENGINE_STORAGE_LIFECYCLE_INTEGRATION
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

/// Descriptor-pinned, bounded local evidence reader; never follows symlinks or
/// blocks opening a FIFO. Source files are readable, but trace/manifest are 0600.
private enum LifecycleTraceInput {
    static let maximumBytes = 32 * 1024 * 1024
    enum Failure: Error { case invalidFile, invalidFraming }

    static func read(_ url: URL, privateFile: Bool = true, afterRead: (() throws -> Void)? = nil) throws -> Data {
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw Failure.invalidFile }
        defer { Darwin.close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == geteuid(), before.st_nlink == 1,
              !privateFile || before.st_mode & 0o7777 == 0o600,
              before.st_size >= 0, before.st_size <= maximumBytes else { throw Failure.invalidFile }
        var bytes = Data(count: Int(before.st_size)), offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes {
                Darwin.pread(fd, $0.baseAddress!.advanced(by: offset), min(64 * 1024, $0.count - offset), off_t(offset))
            }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw Failure.invalidFile }
            offset += count
        }
        try afterRead?()
        var after = stat(), named = stat()
        guard fstat(fd, &after) == 0, lstat(url.path, &named) == 0,
              same(before, after), same(after, named) else { throw Failure.invalidFile }
        return bytes
    }

    private static func same(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_size == rhs.st_size &&
            lhs.st_uid == rhs.st_uid && lhs.st_mode == rhs.st_mode && lhs.st_nlink == rhs.st_nlink &&
            lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec &&
            lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    static func records(_ bytes: Data) throws -> [Data.SubSequence] {
        guard bytes.last == 10 else { throw Failure.invalidFraming }
        let records = bytes.dropLast().split(separator: 10, maxSplits: 4_500, omittingEmptySubsequences: false)
        guard records.count <= 4_500,
              records.allSatisfy({ !$0.isEmpty && $0.count <= StorageLifecycleProtocol.maximumPayloadBytes }) else {
            throw Failure.invalidFraming
        }
        return records
    }

    static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
}

private struct LifecycleTraceHeader: Codable {
    let rootKey: Data
    let manifestSHA256: String
    let workerSHA256: String
    let goVersion: String
    let sourceCount: Int
    let takeovers: Int
    let stores: Int
}
private struct LifecycleTraceRow: Codable {
    let signed: StorageLifecycleProtocol.SignedGrant
    let receipt: StorageLifecycleProtocol.Receipt
    let publicKey: Data
    let incarnation: String
    let daemonUniqueID: UInt64
    let childUniqueID: UInt64
    let childPID: Int32
    let guestBytes: Int
    let guestEpoch: UInt64
    let reclaimed: Bool
}

/// Sequential composition of source-pinned PUBLIC metadata from the ROOT -> Go
/// producer, not a transport/authentication/recovery capability. Compiled only by
/// the focused integration runner, so normal make test gains no skipped test.
@Suite @MainActor struct StorageLifecycleIntegratedTraceTests {
    private typealias Owner = ManagedStorageLifecycleCheckpoint
    private typealias Wire = StorageLifecycleProtocol
    @Test func replaySameRootGrantsAndActualGuestResults() throws {
        let path = try #require(ProcessInfo.processInfo.environment["CENGINE_LIFECYCLE_TRACE"], "focused runner must supply trace")
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let url = URL(fileURLWithPath: path)
        let lines = try LifecycleTraceInput.records(LifecycleTraceInput.read(url))
        #expect(lines.count == 4488)
        let header = try Wire.decode(LifecycleTraceHeader.self, from: Data(try #require(lines.first)))
        #expect(header.stores == 130 && header.takeovers == 4098)
        _ = try StorageIdentity.SPKISHA256(header.workerSHA256)
        #expect(header.goVersion.hasSuffix("darwin/arm64"))
        let manifest = try LifecycleTraceInput.read(url.deletingLastPathComponent().appending(path: "source-hashes.json"))
        guard LifecycleTraceInput.hash(manifest) == header.manifestSHA256 else { throw Owner.Failure.invalid }
        let hashes = try JSONDecoder().decode([String: String].self, from: manifest)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard try encoder.encode(hashes) == manifest else { throw Owner.Failure.invalid }
        #expect(hashes.count == header.sourceCount)
        #expect(hashes["Sources/CEngineRuntime/ManagedStorageLifecycleCheckpoint.swift"] != nil)
        #expect(hashes["Sources/CEngineNetworkHelper/StorageBootstrapLifecycleAuthority.swift"] != nil)
        #expect(hashes["Guest/internal/storageauthority/lifecycle.go"] != nil)
        #expect(hashes["Guest/vendor/modules.txt"] != nil)
        for (path, expected) in hashes {
            guard !path.hasPrefix("/"), !path.split(separator: "/").contains("..") else { throw Owner.Failure.invalid }
            let bytes = try LifecycleTraceInput.read(root.appending(path: path), privateFile: false)
            #expect(LifecycleTraceInput.hash(bytes) == expected, "source changed: \(path)")
        }
        let provenance = String(repeating: "a", count: 64)
        var state: Owner.Metadata?, initialization: Owner.GrantContext?
        var count = 0, takeovers = 0, terminals = 0, peak = 0, aggregate = 0
        var firstEpoch: UInt64 = 0, latestSerial: UInt64 = 0
        for line in lines.dropFirst() {
            guard line.count <= Wire.maximumPayloadBytes else { throw Owner.Failure.capacity }
            let row = try Wire.decode(LifecycleTraceRow.self, from: Data(line))
            let grant = row.signed.grant
            #expect(grant.serial == latestSerial + 1); latestSerial = grant.serial
            #expect(row.receipt.grant == grant)
            #expect(row.guestBytes < 6000)
            let recipient = Owner.Recipient(publicKey: row.publicKey, incarnation: row.incarnation,
                daemonUniqueID: row.daemonUniqueID, childUniqueID: row.childUniqueID, childPID: row.childPID)
            let context = Owner.GrantContext(signed: row.signed, recipient: recipient, requestID: grant.id,
                serviceEpoch: grant.operation == .initialize ? nil : row.receipt.serviceEpoch)
            let intents = HostStorageIntents.State(schema: 2, store: grant.identity.store, revision: 1,
                volumes: [:], intents: [:], operations: [:], operationDigests: [:], reconciliationRequired: true)
            if grant.operation == .initialize {
                if let prior = state { #expect(prior.terminal != nil); aggregate += try Owner.encode(prior).count }
                count += 1; #expect(grant.identity.generation == UInt64(count))
                state = try Owner.baseline(identity: grant.identity, rootPublicKey: header.rootKey, provenanceReference: provenance, initialize: context)
                initialization = context
            } else {
                state = try Owner.applying(.stage(context), to: #require(state), intents: intents)
                #expect(try Owner.decode(Owner.encode(state!)).pending == context)
            }
            if grant.operation == .retire {
                #expect(row.reclaimed)
                #expect(throws: (any Error).self) { _ = try Owner.applying(.retire(row.receipt), to: state!, intents: intents) }
                state = try Owner.applying(.seal(row.receipt), to: state!, intents: intents)
                state = try Owner.applying(.retire(row.receipt), to: state!, intents: intents)
                let terminal = state!
                state = try Owner.applying(.retire(row.receipt), to: terminal, intents: intents)
                #expect(state == terminal) // Same actual receipt: terminal retry is read-only.
                var changedIntents = intents; changedIntents.revision += 1
                #expect(throws: (any Error).self) { _ = try Owner.applying(.retire(row.receipt), to: terminal, intents: changedIntents) }
                terminals += 1
            } else {
                #expect(!row.reclaimed)
                state = try Owner.applying(.complete(row.receipt), to: state!, intents: intents)
                #expect(state!.currentContext?.controllerEpoch == row.guestEpoch)
                if grant.operation == .takeover {
                    takeovers += 1
                    #expect(throws: (any Error).self) { _ = try Owner.applying(.stage(initialization!), to: state!, intents: intents) }
                    if count == 1 { firstEpoch = row.guestEpoch }
                }
            }
            let bytes = try Owner.encode(state!)
            peak = max(peak, bytes.count)
            #expect(try Owner.decode(bytes) == state)
            #expect(state!.contexts.count == 1)
        }
        aggregate += try Owner.encode(#require(state)).count
        #expect(firstEpoch == 4099 && takeovers == 4227 && terminals == 130 && count == 130)
        #expect(latestSerial == 4487 && peak < 16000)
        print("INTEGRATED HOST: firstEpoch=\(firstEpoch) stores=\(count) takeovers=\(takeovers) terminals=\(terminals) peakCheckpointBytes=\(peak) retainedAggregateBytes=\(aggregate)")
    }
}

/// Small input-boundary regressions: never run the 4,098-takeover replay.
@Suite struct StorageLifecycleTraceBoundaryTests {
    private typealias Wire = StorageLifecycleProtocol
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "cengine-trace-boundary-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return url
    }
    private func create(_ url: URL, _ bytes: Data = Data("{}\n".utf8)) throws {
        let fd = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw LifecycleTraceInput.Failure.invalidFile }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try file.write(contentsOf: bytes); try file.close()
    }

    @Test func refusesUnsafeFileTypesPermissionsAndLinks() throws {
        let dir = try directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let regular = dir.appending(path: "regular"), fifo = dir.appending(path: "fifo"), link = dir.appending(path: "link")
        try create(regular)
        #expect(try LifecycleTraceInput.read(regular) == Data("{}\n".utf8))
        #expect(chmod(regular.path, 0o644) == 0)
        #expect(throws: (any Error).self) { try LifecycleTraceInput.read(regular) }
        #expect(chmod(regular.path, 0o600) == 0)
        #expect(symlink(regular.path, link.path) == 0)
        #expect(mkfifo(fifo.path, 0o600) == 0)
        for url in [link, fifo, dir] {
            #expect(throws: (any Error).self) { try LifecycleTraceInput.read(url) }
        }
        let hard = dir.appending(path: "hard")
        #expect(Darwin.link(regular.path, hard.path) == 0)
        #expect(throws: (any Error).self) { try LifecycleTraceInput.read(regular) }
    }

    @Test func refusesOversizeAndConcurrentReplacementOrGrowth() throws {
        let dir = try directory(); defer { try? FileManager.default.removeItem(at: dir) }
        let oversized = dir.appending(path: "oversized")
        try create(oversized)
        let fd = Darwin.open(oversized.path, O_WRONLY | O_CLOEXEC); defer { Darwin.close(fd) }
        #expect(fd >= 0)
        #expect(ftruncate(fd, off_t(LifecycleTraceInput.maximumBytes + 1)) == 0)
        #expect(throws: (any Error).self) { try LifecycleTraceInput.read(oversized) }
        let growing = dir.appending(path: "growing"); try create(growing)
        #expect(throws: (any Error).self) {
            try LifecycleTraceInput.read(growing, afterRead: {
                let writer = try FileHandle(forWritingTo: growing); defer { try? writer.close() }
                try writer.seekToEnd(); try writer.write(contentsOf: Data([10]))
            })
        }
        let replaced = dir.appending(path: "replaced"); try create(replaced)
        #expect(throws: (any Error).self) {
            try LifecycleTraceInput.read(replaced, afterRead: {
                try FileManager.default.moveItem(at: replaced, to: dir.appending(path: "old"))
                try create(replaced)
            })
        }
    }

    @Test func requiresTerminalNewlineAndNonemptyBoundedRecords() throws {
        #expect(try LifecycleTraceInput.records(Data("{}\n{}\n".utf8)).count == 2)
        for bytes in [Data(), Data("{}".utf8), Data("\n".utf8), Data("{}\n\n".utf8),
                      Data("{}\n\n{}\n".utf8), Data(repeating: 10, count: 4_502),
                      Data(repeating: 32, count: Wire.maximumPayloadBytes + 1) + Data([10])] {
            #expect(throws: (any Error).self) { try LifecycleTraceInput.records(bytes) }
        }
    }

    private func checkCanonical<T: Codable>(_ value: T, duplicate: String) throws {
        let canonical = try Wire.encode(value)
        _ = try Wire.decode(T.self, from: canonical)
        let unknown = canonical.dropLast() + Data(",\"unknown\":0}".utf8)
        let duplicated = Data(("{\"" + duplicate + "\":0,").utf8) + canonical.dropFirst()
        for bytes in [Data([32]) + canonical, canonical + Data([32]), unknown, duplicated] {
            #expect(throws: (any Error).self) { try Wire.decode(T.self, from: bytes) }
        }
    }

    @Test func requiresClosedCanonicalHeaderAndRows() throws {
        let digest = String(repeating: "a", count: 64), uuid = "11111111-1111-4111-8111-111111111111"
        let header = LifecycleTraceHeader(rootKey: Data(repeating: 1, count: 32), manifestSHA256: digest,
            workerSHA256: digest, goVersion: "go version test darwin/arm64", sourceCount: 1, takeovers: 4098, stores: 130)
        try checkCanonical(header, duplicate: "stores")
        let grant = try Wire.Grant(operation: .initialize, id: uuid, identity: .init(store: uuid, generation: 1, binding: digest),
            serial: 1, expectedEpoch: 0, newKey: digest)
        let row = LifecycleTraceRow(signed: try .init(grant: grant, signature: Data(repeating: 2, count: 64)),
            receipt: try .init(grant: grant, nonce: Data(repeating: 3, count: 32), serviceEpoch: uuid, revision: 1),
            publicKey: Data(repeating: 4, count: 32), incarnation: uuid, daemonUniqueID: 1, childUniqueID: 2, childPID: 2,
            guestBytes: 1, guestEpoch: 1, reclaimed: false)
        try checkCanonical(row, duplicate: "guestBytes")
        let canonical = String(decoding: try Wire.encode(row), as: UTF8.self)
        for altered in [canonical.replacingOccurrences(of: "\"serial\":1", with: "\"serial\":1.0"),
                        canonical.replacingOccurrences(of: "\"expected_epoch\":0", with: "\"unknown\":0,\"expected_epoch\":0")] {
            #expect(throws: (any Error).self) { try Wire.decode(LifecycleTraceRow.self, from: Data(altered.utf8)) }
        }
    }
}
#endif
