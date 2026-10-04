#if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

private final class QualificationDirectory {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let fd: Int32
    init() throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(.EIO) }
    }
    deinit { close(fd); try? FileManager.default.removeItem(at: url) }
}

private final class QualificationTickets: @unchecked Sendable {
    typealias Admission = StorageLifecycleQualificationAdmission<Int>
    private let lock = NSLock()
    private var tickets: [Admission.Ticket] = []
    private var completions = 0
    func append(_ ticket: Admission.Ticket) { lock.withLock { tickets.append(ticket) } }
    func completed() { lock.withLock { completions += 1 } }
    var values: [Admission.Ticket] { lock.withLock { tickets } }
    var completionCount: Int { lock.withLock { completions } }
}

@Suite struct StorageBootstrapLifecycleQualificationTests {
    private func binding(_ root: QualificationDirectory, store: String = "11111111-1111-4111-8111-111111111111") throws -> StorageLifecycleQualificationBinding {
        try .verified(store: store, rootFD: root.fd, owner: geteuid())
    }
    private func process(_ unique: UInt64, version: UInt32 = 1) -> BootstrapProcess {
        .init(pid: 42, startSeconds: 1, startMicroseconds: 2, boot: "boot", signingIdentity: "unsigned-test-only",
            uniqueID: unique, pidVersion: version, auditToken: Data())
    }
    private func fullBinding(_ value: StorageLifecycleQualificationBinding, inode: UInt64 = 90) throws -> StorageIdentity.StoreBinding {
        try .init(storeID: value.store, root: value.root,
            backing: .init(identity: .init(volumeUUID: value.root.volumeUUID, inode: inode), size: 4096),
            expectedExt4UUID: .init("22222222-2222-4222-8222-222222222222"))
    }
    @Test func stableScopeReopensAcrossDeviceRenumberingWithPendingState() throws {
        let base = try QualificationDirectory(), root = try QualificationDirectory()
        let value = try binding(root), full = try fullBinding(value)
        let old = StorageIdentity.DescriptorIdentity(stableIdentity: value.root, device: 23)
        let rebooted = StorageIdentity.DescriptorIdentity(stableIdentity: value.root, device: 0)
        let reopenedBinding = StorageLifecycleQualificationBinding(store: value.store, root: rebooted.stableIdentity, ownerUID: value.ownerUID)
        #expect(old != rebooted)
        #expect(value.rootHash == reopenedBinding.rootHash)
        #expect(value.metadata == reopenedBinding.metadata)
        #expect(String(decoding: value.metadata, as: UTF8.self).split(separator: "\n").count == 5)
        var scope: StorageLifecycleQualificationDirectory? = try .init(baseFD: base.fd, binding: value, owner: geteuid())
        try scope!.requireBinding(full, establish: true)
        let key = try scope!.journal.readRootPublicKey()
        let identity = try StorageLifecycleProtocol.Identity(binding: full, generation: 9)
        let pending = Data("opaque pending authority snapshot".utf8)
        try scope!.journal.checkpoint(pending)
        scope = nil
        scope = try .init(baseFD: base.fd, binding: reopenedBinding, owner: geteuid())
        #expect(try scope!.journal.readRootPublicKey() == key)
        #expect(try scope!.journal.load() == pending)
        #expect(try scope!.recordedBinding() == full)
        try scope!.requireIdentity(identity)
        // A restart can re-pin; reuse in the SAME running helper cannot.
        try StorageLifecycleQualificationBinding.requireSameObservation(rebooted, rebooted)
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationBinding.requireSameObservation(old, rebooted) }
        for foreign in [try StorageIdentity.RootIdentity(volumeUUID: .init(UUID().uuidString.lowercased()), inode: value.root.inode),
                        try .init(volumeUUID: value.root.volumeUUID, inode: value.root.inode + 1)] {
            let altered = StorageLifecycleQualificationBinding(store: value.store, root: foreign, ownerUID: value.ownerUID)
            #expect(altered.rootHash != value.rootHash)
            #expect(throws: (any Error).self) {
                try StorageLifecycleQualificationBinding.requireSameObservation(old, .init(stableIdentity: foreign, device: old.device))
            }
        }
        let wrongOwner = StorageLifecycleQualificationBinding(store: value.store, root: value.root, ownerUID: value.ownerUID + 1)
        #expect(wrongOwner.rootHash == value.rootHash)
        scope = nil
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationDirectory(baseFD: base.fd, binding: wrongOwner, owner: geteuid()) }
    }

    @Test func verifiedRootIdentityRejectsWrongOwnerModeAndNonDirectory() throws {
        let root = try QualificationDirectory()
        let original = try binding(root)
        #expect(original.root.inode > 0)
        #expect(original.rootHash.count == 64)
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationBinding.verified(store: original.store.rawValue, rootFD: root.fd, owner: geteuid() + 1) }
        #expect(fchmod(root.fd, 0o750) == 0)
        #expect(throws: (any Error).self) { try binding(root) }
        #expect(fchmod(root.fd, 0o700) == 0)
        let file = openat(root.fd, "file", O_CREAT | O_EXCL | O_RDWR, 0o600)
        defer { close(file) }
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationBinding.verified(store: original.store.rawValue, rootFD: file, owner: geteuid()) }
        #expect(throws: (any Error).self) { try binding(root, store: "../escape") }
    }
    @Test func hashUsesVerifiedIdentityNotPathOrStoreUUID() throws {
        let root = try QualificationDirectory(), other = try QualificationDirectory()
        let first = try binding(root)
        #expect(first.rootHash == (try binding(root, store: "33333333-3333-4333-8333-333333333333")).rootHash)
        #expect(first.rootHash != (try binding(other)).rootHash)
        let moved = root.url.appendingPathExtension("moved")
        try FileManager.default.moveItem(at: root.url, to: moved)
        defer { try? FileManager.default.moveItem(at: moved, to: root.url) }
        #expect(try binding(root) == first)
    }
    @Test func immutableProcessBindingsAndCapacityNeverEvict() throws {
        let root = try QualificationDirectory(), other = try QualificationDirectory()
        let value = try binding(root)
        var registry = StorageLifecycleQualificationRegistry()
        for id in 1...128 { try registry.bind(process(UInt64(id)), to: value) }
        try registry.bind(process(1), to: value)
        #expect(try registry.binding(process(1)) == value)
        #expect(throws: (any Error).self) { try registry.bind(process(129), to: value) }
        #expect(throws: (any Error).self) { try registry.bind(process(1, version: 2), to: value) }
        #expect(throws: (any Error).self) { try registry.bind(process(1), to: binding(other)) }
        #expect(throws: (any Error).self) { try registry.binding(process(1, version: 2)) }
        #expect(throws: (any Error).self) { try registry.route(999) }
    }
    @Test func exactReopenPreservesKeyAndBindingOutsideJournalLeaf() throws {
        let base = try QualificationDirectory(), root = try QualificationDirectory()
        let value = try binding(root), full = try fullBinding(value)
        var scope: StorageLifecycleQualificationDirectory? = try .init(baseFD: base.fd, binding: value, owner: geteuid())
        let key = try scope!.journal.readRootPublicKey()
        try scope!.requireBinding(full, establish: true)
        let identity = try StorageLifecycleProtocol.Identity(binding: full, generation: 1)
        try scope!.requireIdentity(identity)
        let leaf = base.url.appendingPathComponent(value.rootHash).appendingPathComponent("journal")
        #expect(Set(try FileManager.default.contentsOfDirectory(atPath: leaf.path)) == ["authority.lock", "authority.journal"])
        scope = nil
        scope = try .init(baseFD: base.fd, binding: value, owner: geteuid())
        #expect(try scope!.journal.readRootPublicKey() == key)
        #expect(try scope!.recordedBinding() == full)
        #expect(throws: (any Error).self) { try scope!.requireBinding(fullBinding(value, inode: 91), establish: true) }
        #expect(throws: (any Error).self) { try scope!.requireIdentity(.init(store: value.store.rawValue, generation: 1, binding: String(repeating: "a", count: 64))) }
        scope = nil
        let wrong = try binding(root, store: "33333333-3333-4333-8333-333333333333")
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationDirectory(baseFD: base.fd, binding: wrong, owner: geteuid()) }
    }
    @Test func initialDescriptorFreeProbeAllowsExactlyTheFreshAttachPath() throws {
        let base = try QualificationDirectory(), root = try QualificationDirectory()
        let value = try binding(root), full = try fullBinding(value)
        let scope = try StorageLifecycleQualificationDirectory(baseFD: base.fd, binding: value, owner: geteuid())
        do {
            try scope.requireBinding(full, establish: false)
            Issue.record("fresh probe unexpectedly accepted")
        } catch let failure as BootstrapFailure {
            #expect(failure.code == .invalidRequest)
        }
        #expect(try scope.recordedBinding() == nil)
        try scope.requireBinding(full, establish: true)
        try scope.requireBinding(full, establish: false)
        #expect(try scope.recordedBinding() == full)
        #expect(throws: (any Error).self) { try scope.requireBinding(fullBinding(value, inode: 91), establish: false) }
    }
    @Test func existingEmptyOrIncompleteScopeAndJournalMarkerNeverReset() throws {
        let base = try QualificationDirectory(), root = try QualificationDirectory()
        let value = try binding(root)
        #expect(mkdirat(base.fd, value.rootHash, 0o700) == 0)
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationDirectory(baseFD: base.fd, binding: value, owner: geteuid()) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: base.url.appendingPathComponent(value.rootHash).path).isEmpty)
        let clean = try QualificationDirectory()
        var scope: StorageLifecycleQualificationDirectory? = try .init(baseFD: clean.fd, binding: value, owner: geteuid())
        let before = try scope!.journal.readRootPublicKey(); #expect(before.count == 32)
        scope = nil
        let marker = clean.url.appendingPathComponent(value.rootHash).appendingPathComponent("journal/authority.checkpoint-in-progress")
        try Data("incomplete".utf8).write(to: marker)
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationDirectory(baseFD: clean.fd, binding: value, owner: geteuid()) }
        #expect(try Data(contentsOf: marker) == Data("incomplete".utf8))
    }
    @Test func refusesSymlinkComponentsAndCorruptMetadata() throws {
        let base = try QualificationDirectory(), root = try QualificationDirectory(), target = try QualificationDirectory()
        let value = try binding(root)
        #expect(symlinkat(target.url.path, base.fd, value.rootHash) == 0)
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationDirectory(baseFD: base.fd, binding: value, owner: geteuid()) }
        let clean = try QualificationDirectory()
        var scope: StorageLifecycleQualificationDirectory? = try .init(baseFD: clean.fd, binding: value, owner: geteuid())
        #expect(try scope!.recordedBinding() == nil); scope = nil
        let metadata = clean.url.appendingPathComponent(value.rootHash).appendingPathComponent("scope")
        try Data("corrupt".utf8).write(to: metadata)
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationDirectory(baseFD: clean.fd, binding: value, owner: geteuid()) }
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationFiles.directory(clean.fd, "../escape", owner: geteuid(), create: true) }
    }
    @Test func installer0755AncestorsAreProtectedButLeafMustBePrivate() throws {
        let base = try QualificationDirectory()
        #expect(mkdirat(base.fd, "ancestor", 0o755) == 0)
        let (ancestor, fresh) = try StorageLifecycleQualificationFiles.directory(base.fd, "ancestor", owner: geteuid(), create: true, privateMode: false)
        defer { close(ancestor) }
        #expect(!fresh)
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationFiles.directory(base.fd, "ancestor", owner: geteuid(), create: true) }
        #expect(fchmod(ancestor, 0o775) == 0)
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationFiles.directory(base.fd, "ancestor", owner: geteuid(), create: true, privateMode: false) }
    }
    @Test func threadedAdmissionStrictlyBoundsGlobalAndPerPeerWork() throws {
        let admission = QualificationTickets.Admission(), accepted = QualificationTickets()
        DispatchQueue.concurrentPerform(iterations: 512) { peer in
            if let ticket = try? admission.admit(peer) { accepted.append(ticket) }
        }
        #expect(accepted.values.count == 16)
        #expect(admission.counts.inFlight == 16)
        #expect(admission.counts.peers == 16) // Rejections retain nothing.
        let tickets = accepted.values
        DispatchQueue.concurrentPerform(iterations: 512) { index in
            admission.finish(tickets[index % tickets.count]) { accepted.completed() }
        }
        #expect(accepted.completionCount == 16)
        #expect(admission.counts.inFlight == 0)
        admission.wait()

        let single = QualificationTickets.Admission(), samePeer = QualificationTickets()
        DispatchQueue.concurrentPerform(iterations: 256) { _ in
            if let ticket = try? single.admit(1) { samePeer.append(ticket) }
        }
        #expect(samePeer.values.count == 1)
        let first = try #require(samePeer.values.first)
        single.finish(first)
        let second = try single.admit(1)
        single.finish(first) // A stale completion cannot release the next request.
        #expect(single.counts.inFlight == 1)
        single.finish(second)
        single.wait()
    }
    @Test func peerBudgetRejectsBeforeRetainingAndDisconnectReleasesIdlePeer() throws {
        let admission = QualificationTickets.Admission()
        for peer in 0..<128 { admission.finish(try admission.admit(peer)) }
        #expect(admission.counts.peers == 128)
        #expect(throws: (any Error).self) { try admission.admit(128) }
        #expect(admission.counts.inFlight == 0)
        admission.finish(try admission.admit(0)) // Existing peers still work at capacity.
        admission.disconnected(0)
        admission.finish(try admission.admit(128))
        #expect(admission.counts.peers == 128)
        admission.invalidate(); admission.wait()
        #expect(admission.counts.peers == 0)
    }
    @Test func disconnectAndQuiesceDoNotFreeBlockedWorkUntilExactlyOnceFinish() throws {
        let admission = QualificationTickets.Admission(), accepted = QualificationTickets()
        let tickets = try (0..<16).map { try admission.admit($0) }
        DispatchQueue.concurrentPerform(iterations: 16) { admission.disconnected($0) }
        #expect(admission.counts.inFlight == 16)
        #expect(admission.counts.peers == 16)
        #expect(throws: (any Error).self) { try admission.admit(100) }
        #expect(throws: (any Error).self) { try admission.admit(0) }
        admission.finish(tickets[0]) { accepted.completed() }
        let replacement = try admission.admit(100)
        admission.invalidate()
        #expect(throws: (any Error).self) { try admission.admit(101) }
        let drained = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { admission.wait(); drained.signal() }
        #expect(drained.wait(timeout: .now() + 0.05) == .timedOut)
        DispatchQueue.concurrentPerform(iterations: 256) { index in
            admission.finish(tickets[index % tickets.count]) { accepted.completed() }
        }
        #expect(admission.counts.inFlight == 1)
        admission.finish(replacement) { accepted.completed() }
        #expect(drained.wait(timeout: .now() + 2) == .success)
        #expect(accepted.completionCount == 17)
        #expect(admission.counts.inFlight == 0)
        #expect(admission.counts.peers == 0)
    }
    @Test func mismatchingStoreBindCannotPoisonHealthyPhysicalRoot() throws {
        let base = try QualificationDirectory(), root = try QualificationDirectory()
        let value = try binding(root), full = try fullBinding(value)
        let mismatch = try binding(root, store: "33333333-3333-4333-8333-333333333333")
        #expect(mismatch.rootHash == value.rootHash)
        var scopes = StorageLifecycleQualificationScopes<StorageLifecycleQualificationDirectory>()
        let healthy = try scopes.resolve(value) { try .init(baseFD: base.fd, binding: value, owner: geteuid()) }
        try healthy.requireBinding(full, establish: true)
        let key = try healthy.journal.readRootPublicKey()
        var attemptedConstruction = false
        #expect(throws: (any Error).self) {
            try scopes.resolve(mismatch) {
                attemptedConstruction = true
                return try .init(baseFD: base.fd, binding: mismatch, owner: geteuid())
            }
        }
        #expect(!attemptedConstruction)
        #expect(try scopes.existing(value) === healthy)
        #expect(try scopes.resolve(value) { throw BootstrapFailure(.repairRequired) } === healthy)
        #expect(try healthy.journal.readRootPublicKey() == key)
        #expect(try healthy.recordedBinding() == full)
    }
    @Test func partialConstructionFailureAlwaysRefusesPhysicalRootEvenIfTransient() throws {
        let base = try QualificationDirectory(), root = try QualificationDirectory(), other = try QualificationDirectory()
        let value = try binding(root)
        var scopes = StorageLifecycleQualificationScopes<Int>()
        #expect(throws: (any Error).self) {
            try scopes.resolve(value) {
                #expect(mkdirat(base.fd, value.rootHash, 0o700) == 0)
                throw BootstrapFailure(.unavailable) // Transient error after a partial durable write.
            }
        }
        var retried = false
        for candidate in [value, try binding(root, store: "33333333-3333-4333-8333-333333333333")] {
            #expect(throws: (any Error).self) { try scopes.resolve(candidate) { retried = true; return 2 } }
        }
        #expect(!retried)
        #expect(try scopes.resolve(binding(other)) { 3 } == 3)
        #expect(try FileManager.default.contentsOfDirectory(atPath: base.url.path) == [value.rootHash])
    }
    @Test func transientPreWriteScopeFailureStaysRetryable() throws {
        let root = try QualificationDirectory(), value = try binding(root)
        var scopes = StorageLifecycleQualificationScopes<Int>()
        #expect(throws: (any Error).self) {
            try scopes.resolve(value) { throw StorageLifecycleTransientScopeFailure(failure: BootstrapFailure(.unavailable)) }
        }
        #expect(try scopes.existing(value) == nil) // Not poisoned.
        #expect(try scopes.resolve(value) { 7 } == 7)
    }
    @Test func preAdmissionValidationClosesEveryEnvelopeBeforeQueueing() throws {
        let root = try QualificationDirectory(), value = try binding(root), full = try fullBinding(value)
        let uuid = "44444444-4444-4444-8444-444444444444", hash = String(repeating: "a", count: 64)
        let key = try StorageIdentity.RootPublicKey(publicData: Data(repeating: 7, count: 32))
        let fresh = try StorageLifecycleFreshProtocol.Greeting(channelID: uuid, daemonUniqueID: 1, rootPublicKey: key.publicData,
            store: value.store.rawValue, shimLaunchUUID: uuid, guestBootNonce: uuid, operationUUID: uuid,
            ext4UUID: full.expectedExt4UUID.rawValue, bytes: 4096, initramfsSHA256: hash,
            device: 1, inode: full.backing.identity.inode, volumeUUID: full.backing.identity.volumeUUID.rawValue)
        let child = try StorageLifecycleChildProtocol.Greeting(channelID: uuid, incarnationID: uuid, daemonUniqueID: 1,
            controllerSPKI: StorageIdentity.Ed25519SPKI(rawPublicKey: Data(repeating: 8, count: 32)).publicData, rootPublicKey: key.publicData,
            store: value.store.rawValue, binding: StorageLifecycleProtocol.bindingDigest(full), expectedEpoch: 0)
        let service = try StorageLifecycleServiceProofProtocol.Greeting(channelID: uuid, daemonUniqueID: 1, rootPublicKey: key.publicData,
            binding: .init(full), bootBinding: .init(shimLaunchUUID: uuid, guestBootNonce: uuid, ext4UUID: full.expectedExt4UUID.rawValue, bytes: 4096),
            initramfsSHA256: hash, boot: .init(identity: .init(binding: full, generation: 1), serviceEpoch: uuid,
                tlsRootSHA256: hash, serverSPKI: hash, bootstrapKey: key.fingerprint.rawValue))
        let rootRequest = try StorageLifecycleRootProtocol.Request(requestID: .init(uuid), body: .rootPublicKey)
        let envelopes: [(String, String?, Data)] = [
            (StorageLifecycleScopeProtocol.xpcOperation, nil, try StorageLifecycleScopeProtocol.encode(.init(store: value.store))),
            (StorageLifecycleRootProtocol.xpcOperation, nil, try StorageLifecycleRootProtocol.encode(rootRequest)),
            ("storage-lifecycle-child", "controller-child", try StorageLifecycleProtocol.encode(child)),
            ("storage-lifecycle-fresh-shim", "storage-shim", try StorageLifecycleProtocol.encode(fresh)),
            ("storage-lifecycle-service-shim", "storage-shim", try StorageLifecycleProtocol.encode(service))
        ]
        for (operation, role, data) in envelopes {
            func message(_ payload: Data) -> xpc_object_t {
                let result = xpc_dictionary_create(nil, nil, 0)
                xpc_dictionary_set_string(result, "operation", operation)
                if let role {
                    // Match the live FreshShim/ServiceShim and native Go child
                    // envelopes, not just their inner canonical greeting DTOs.
                    xpc_dictionary_set_int64(result, "version", PrivilegedPortProtocol.version)
                    xpc_dictionary_set_string(result, "role", role)
                }
                if operation == StorageLifecycleScopeProtocol.xpcOperation { xpc_dictionary_set_fd(result, "store-root", root.fd) }
                payload.withUnsafeBytes { xpc_dictionary_set_data(result, "request", $0.baseAddress, $0.count) }
                return result
            }
            #expect(try StorageBootstrapLifecycleQualification.validateAdmission(message(data)) == operation)
            for payload in [Data(), Data(count: StorageLifecycleProtocol.maximumPayloadBytes + 1), data + Data([10]),
                            Data(String(decoding: data, as: UTF8.self).replacingOccurrences(of: "{", with: "{\"extra\":true,").utf8)] {
                #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.validateAdmission(message(payload)) }
            }
            let extra = message(data)
            xpc_dictionary_set_data(extra, "unknown", nil, 0)
            #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.validateAdmission(extra) }
            let wrongType = message(data)
            xpc_dictionary_set_string(wrongType, "request", "not-data")
            #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.validateAdmission(wrongType) }
            if role != nil {
                let missingVersion = message(data)
                xpc_dictionary_set_value(missingVersion, "version", nil)
                #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.validateAdmission(missingVersion) }
                for version in [Int64(0), PrivilegedPortProtocol.version - 1, PrivilegedPortProtocol.version + 1] {
                    let wrongVersion = message(data)
                    xpc_dictionary_set_int64(wrongVersion, "version", version)
                    #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.validateAdmission(wrongVersion) }
                }
                for version in [xpc_string_create("5"), xpc_uint64_create(UInt64(PrivilegedPortProtocol.version)), xpc_bool_create(true)] {
                    let wrongType = message(data)
                    xpc_dictionary_set_value(wrongType, "version", version)
                    #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.validateAdmission(wrongType) }
                }
                let wrongRole = message(data)
                xpc_dictionary_set_string(wrongRole, "role", "daemon")
                #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.validateAdmission(wrongRole) }
            } else {
                // The ROOT and scope protocols deliberately remain versionless.
                let extraVersion = message(data)
                xpc_dictionary_set_int64(extraVersion, "version", PrivilegedPortProtocol.version)
                #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.validateAdmission(extraVersion) }
            }
        }
        // Local dictionaries exercise parsing only, never dispatch/audit authentication.
    }
    @Test func strictScopeEnvelopeAndVersionlessRootDispatchClassification() throws {
        let root = try QualificationDirectory()
        let request = StorageLifecycleScopeProtocol.Request(store: try .init("11111111-1111-4111-8111-111111111111"))
        let data = try StorageLifecycleScopeProtocol.encode(request)
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", StorageLifecycleScopeProtocol.xpcOperation)
        data.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        xpc_dictionary_set_fd(message, "store-root", root.fd)
        #expect(try StorageBootstrapLifecycleQualification.decodeBind(message) == request)
        xpc_dictionary_set_string(message, "path", "/tmp/attacker")
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleQualification.decodeBind(message) }
        let unknown = Data(String(decoding: data, as: UTF8.self).replacingOccurrences(of: "{", with: "{\"policy\":\"qualification\",").utf8)
        #expect(throws: (any Error).self) { try StorageLifecycleScopeProtocol.decode(unknown) }
        #expect(StorageBootstrapLifecycleQualification.recognizes(StorageLifecycleRootProtocol.xpcOperation))
        #expect(StorageBootstrapLifecycleQualification.recognizes("storage-lifecycle-child"))
        #expect(!StorageBootstrapLifecycleQualification.recognizes("storage-bootstrap"))
        #expect(!StorageBootstrapLifecycleQualification.recognizes("restart"))
    }
}
#endif
