import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

private typealias L = StorageLifecycleProtocol
private func id() -> String { UUID().uuidString.lowercased() }
private func process(_ pid: Int32) -> BootstrapProcess {
    .init(pid: pid, startSeconds: 1, startMicroseconds: 2, boot: "unsigned-integration-test", signingIdentity: "unsigned-test-only",
          uniqueID: UInt64(pid), pidVersion: 1, auditToken: Data(repeating: UInt8(truncatingIfNeeded: pid), count: 32))
}
private struct Directive: Encodable {
    var command: String
    var signed: L.SignedGrant? = nil
    var grant: L.Grant? = nil
    var nonce: Data? = nil
    var rootKey: Data? = nil
}
private struct MetadataScope: Decodable {
    let identity: L.Identity
    let serviceEpoch: String
    let bootstrapKey: String
    let openRevision: UInt64

    // Deterministic native-free pins only. The identity/E/bootstrap key come from
    // the actual Go authority, but no certificates or TLS exist in this lane.
    func testBootTrust() throws -> StorageLifecycleBootTrust {
        let context = try L.encode(identity) + Data((serviceEpoch + bootstrapKey).utf8)
        func pin(_ role: String) -> String {
            SHA256.hash(data: Data("unsigned-lifecycle-integration-\(role)\0".utf8) + context)
                .map { String(format: "%02x", $0) }.joined()
        }
        return try .init(identity: identity, serviceEpoch: serviceEpoch,
                         tlsRootSHA256: pin("test-ca"), serverSPKI: pin("test-server"), bootstrapKey: bootstrapKey)
    }
}
private struct Reply: Decodable {
    var error: String?
    var receipt: L.Receipt?
    var serviceResult: L.ServiceResult?
    var metadataScope: MetadataScope?
    var epoch: UInt64
    var revision: UInt64
    var bytes: Int
    var files: Int
    var fence: Bool
    var aggregateBytes: Int
}
private final class Bridge {
    let child = Process(), input = Pipe(), output = Pipe()
    var buffer = Data()
    init() throws {
        child.executableURL = URL(fileURLWithPath: try #require(ProcessInfo.processInfo.environment["CENGINE_LIFECYCLE_WORKER"]))
        child.arguments = ["-test.run=^TestLifecycleIntegrationBridge$", "-test.timeout=12m"]
        child.environment = ProcessInfo.processInfo.environment.merging(["CENGINE_LIFECYCLE_BRIDGE": "unsigned-test-only-v1"]) { _, new in new }
        child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.standardError
        let fd = input.fileHandleForWriting.fileDescriptor
        guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0,
              fcntl(fd, F_SETNOSIGPIPE, 1) == 0 else { throw BootstrapFailure(.unavailable) }
        try child.run()
    }
    func call(_ directive: Directive) throws -> Reply {
        let bytes = try L.encode(directive) + Data([10])
        try send(bytes)
        let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
        while !buffer.contains(10) {
            var pollFD = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw BootstrapFailure(.unavailable) }
            let status = poll(&pollFD, 1, Int32(min((deadline - now) / 1_000_000 + 1, 30_000)))
            if status < 0 && errno == EINTR { continue }
            guard status > 0 else { throw BootstrapFailure(.unavailable) }
            let data = output.fileHandleForReading.availableData
            guard !data.isEmpty, buffer.count + data.count <= 65_536 else { throw BootstrapFailure(.unavailable) }
            buffer.append(data)
        }
        let end = buffer.firstIndex(of: 10)!, line = buffer.prefix(upTo: end)
        buffer.removeSubrange(...end)
        return try JSONDecoder().decode(Reply.self, from: line)
    }
    private func send(_ bytes: Data) throws {
        guard bytes.count <= 65_536 else { throw BootstrapFailure(.invalidRequest) }
        let fd = input.fileHandleForWriting.fileDescriptor
        let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
        var offset = 0
        while offset < bytes.count {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw BootstrapFailure(.unavailable) }
            var ready = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let status = poll(&ready, 1, Int32(min((deadline - now) / 1_000_000 + 1, 30_000)))
            if status < 0 && errno == EINTR { continue }
            guard status > 0, ready.revents & Int16(POLLOUT) != 0,
                  ready.revents & Int16(POLLERR | POLLHUP | POLLNVAL) == 0 else { throw BootstrapFailure(.unavailable) }
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
            if count < 0 && (errno == EAGAIN || errno == EINTR) { continue }
            guard count > 0 else { throw BootstrapFailure(.unavailable) }
            offset += count
        }
    }
    func finish() throws {
        try send(Data("{\"command\":\"quit\"}\n".utf8))
        try input.fileHandleForWriting.close()
        child.waitUntilExit()
        #expect(child.terminationStatus == 0)
    }
    deinit {
        if child.isRunning { kill(child.processIdentifier, SIGKILL) }
        child.waitUntilExit()
    }
}
private final class Journal: StorageLifecycleJournal {
    let physical: StorageBootstrapCheckpointJournal
    var peak = 0
    var failProofAfterWrite: (() -> Void)?
    init(_ fd: Int32) throws {
        // Real fsync/rename, explicitly NOT qualification of macOS power-loss barriers.
        physical = try .init(directoryFD: fd, fresh: true, ownerUID: geteuid(), configuredOwnerUID: geteuid(), sync: {
            guard fsync($0) == 0 else { throw BootstrapFailure(.repairRequired) }
        })
    }
    func load() throws -> Data? { try physical.load() }
    func checkpoint(_ data: Data) throws { try physical.checkpoint(data); peak = max(peak, data.count); failProofAfterWrite?() }
    func lifecycleRootPublicKey() throws -> StorageIdentity.RootPublicKey { try .init(publicData: physical.readRootPublicKey()) }
    func signLifecycle(_ grant: L.Grant) throws -> L.SignedGrant { try physical.signLifecycle(grant) }
    func signServiceChange(_ request: L.ServiceChangeRequest) throws -> L.SignedServiceChange { try physical.signServiceChange(request) }
}
// Counter fault injection over a captured real ROOT snapshot; never changes the
// campaign journal. Any attempt to write/sign fails the test, rather than hiding
// a counter overflow behind a synthetic persistence error.
private final class CounterProbe: StorageLifecycleJournal {
    let data: Data
    let root: StorageIdentity.RootPublicKey
    init(_ data: Data, _ root: StorageIdentity.RootPublicKey) { self.data = data; self.root = root }
    func load() throws -> Data? { data }
    func lifecycleRootPublicKey() throws -> StorageIdentity.RootPublicKey { root }
    func checkpoint(_ state: Data) throws { Issue.record("overflow attempted checkpoint"); throw BootstrapFailure(.repairRequired) }
    func signLifecycle(_ grant: L.Grant) throws -> L.SignedGrant { Issue.record("overflow attempted signing"); throw BootstrapFailure(.repairRequired) }
    func signServiceChange(_ request: L.ServiceChangeRequest) throws -> L.SignedServiceChange { Issue.record("overflow attempted signing"); throw BootstrapFailure(.repairRequired) }
}
private final class Processes: StorageLifecycleProcessChecking {
    let bridge: Bridge
    var dead = Set<Int32>(), deny = false, corrupt = false
    var denyServiceResult = false, corruptServiceNonce = false, corruptBoot = false
    var lastReceiptNonce: Data?, lastServiceNonce: Data?
    var serviceResultCalls = 0
    init(_ bridge: Bridge) { self.bridge = bridge }
    func candidate(_ candidate: StorageIdentity.Candidate, daemon: BootstrapProcess, grant: L.Grant) throws -> BootstrapPrincipal {
        let p = BootstrapPrincipal(daemon: daemon, child: process(candidate.childPIDHint), incarnation: candidate.incarnationID.rawValue, controllerSPKI: candidate.publicKey.publicData)
        try validateRecipient(p, daemon: daemon, grant: grant); return p
    }
    func liveness(_ p: BootstrapProcess) -> BootstrapLiveness { dead.contains(p.pid) ? .exited : .unknown }
    func validateRecipient(_ p: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant) throws {
        guard p.daemon == daemon, !dead.contains(daemon.pid), !dead.contains(p.child.pid),
              try StorageIdentity.Ed25519SPKI(publicData: p.controllerSPKI).fingerprint.rawValue == grant.newKey else { throw BootstrapFailure(.unauthorized) }
    }
    func serviceBootTrust(_ p: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant) throws -> StorageLifecycleBootTrust {
        try validateRecipient(p, daemon: daemon, grant: grant)
        guard !deny else { throw BootstrapFailure(.unavailable) }
        let reply = try bridge.call(.init(command: "metadataScope", grant: grant))
        guard reply.error == nil, let scope = reply.metadataScope, scope.identity == grant.identity else {
            throw BootstrapFailure(.unavailable)
        }
        let boot = try scope.testBootTrust()
        if corruptBoot {
            return try .init(identity: boot.identity, serviceEpoch: "00000000-0000-4000-8000-000000000001",
                             tlsRootSHA256: boot.tlsRootSHA256, serverSPKI: boot.serverSPKI, bootstrapKey: boot.bootstrapKey)
        }
        return boot
    }
    func serviceResult(_ p: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant, nonce: Data,
                       boot: StorageLifecycleBootTrust, changeRequest: L.ServiceChangeRequest?,
                       confirmation: L.ServiceChangeConfirmation?) throws -> L.ServiceResult {
        try validateRecipient(p, daemon: daemon, grant: grant)
        // This lane has no reopen/staged-client promotion. Never invent success.
        guard changeRequest == nil, confirmation == nil else { throw BootstrapFailure(.unavailable) }
        guard !deny, !denyServiceResult else { throw BootstrapFailure(.unavailable) }
        #expect(nonce != lastReceiptNonce && nonce != lastServiceNonce)
        lastServiceNonce = nonce
        let reply = try bridge.call(.init(command: "serviceResult", grant: grant,
                                          nonce: corruptServiceNonce ? Data(repeating: 0, count: 32) : nonce))
        guard reply.error == nil, let result = reply.serviceResult, let scope = reply.metadataScope,
              try scope.testBootTrust() == boot, scope.identity == result.identity,
              scope.serviceEpoch == result.serviceEpoch, scope.openRevision == result.openRevision else {
            throw BootstrapFailure(.unavailable)
        }
        serviceResultCalls += 1
        // Return the actual Guest result unchanged; ROOT checks its fresh nonce.
        return result
    }
    func receipt(_ p: BootstrapPrincipal, daemon: BootstrapProcess, grant: L.Grant, nonce: Data) throws -> L.Receipt {
        try validateRecipient(p, daemon: daemon, grant: grant)
        guard !deny else { throw BootstrapFailure(.unavailable) }
        lastReceiptNonce = nonce
        let reply = try bridge.call(.init(command: "receipt", grant: grant, nonce: nonce))
        guard reply.error == nil, let receipt = reply.receipt else { throw BootstrapFailure(.unavailable) }
        if corrupt { return try .init(grant: receipt.grant, nonce: Data(repeating: 0, count: 32), serviceEpoch: receipt.serviceEpoch, revision: receipt.revision) }
        return receipt
    }
}
private struct Bindings: StorageLifecycleFreshBindingChecking {
    let rootPublicKey: Data
    // Explicit deterministic unsigned seam; not ext4/native provisioning evidence.
    func verifyFresh(_ binding: StorageIdentity.StoreBinding, grant: L.Grant, daemon: BootstrapProcess,
                     principal: BootstrapPrincipal, rootFD: Int32, backingFD: Int32) throws -> StorageLifecycleFreshOrigin {
        let greeting = try StorageLifecycleFreshProtocol.Greeting(channelID: grant.id,
            daemonUniqueID: daemon.uniqueID, rootPublicKey: rootPublicKey, store: binding.storeID.rawValue,
            shimLaunchUUID: grant.id, guestBootNonce: grant.id, operationUUID: grant.id,
            ext4UUID: binding.expectedExt4UUID.rawValue, bytes: binding.backing.size,
            initramfsSHA256: String(repeating: "a", count: 64), device: 1,
            inode: binding.backing.identity.inode, volumeUUID: binding.backing.identity.volumeUUID.rawValue)
        return StorageLifecycleFreshOrigin(greeting: greeting, shim: process(daemon.pid + 2),
            daemon: daemon, grant: grant, principal: principal)
    }
}
private struct Trace: Encodable {
    let signed: L.SignedGrant
    let receipt: L.Receipt
    let publicKey: Data
    let incarnation: String
    let daemonUniqueID: UInt64
    let childUniqueID: UInt64
    let childPID: Int32
    let guestBytes: Int
    let guestEpoch: UInt64
    let reclaimed: Bool
}
@Suite struct StorageLifecycleIntegrationProducerTests {
    @Test func sameSignedGrantsCrossActualRootAndGuest() throws {
        let env = ProcessInfo.processInfo.environment
        let traceURL = URL(fileURLWithPath: try #require(env["CENGINE_LIFECYCLE_TRACE"]))
        let dir = FileManager.default.temporaryDirectory.appending(path: "cengine-lifecycle-root-\(id())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let fd = open(dir.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw BootstrapFailure(.unavailable) }; defer { close(fd) }
        let bridge = try Bridge(), journal = try Journal(fd), processes = Processes(bridge)
        var authority = try StorageBootstrapLifecycleAuthority(journal: journal, processes: processes, bindings: Bindings(rootPublicKey: try journal.lifecycleRootPublicKey().publicData))
        let root = try journal.lifecycleRootPublicKey()
        // Never replace, truncate, follow, or remove a pre-existing trace pathname.
        let traceFD = open(traceURL.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard traceFD >= 0 else { throw BootstrapFailure(.unavailable) }
        let trace = FileHandle(fileDescriptor: traceFD, closeOnDealloc: true); defer { try? trace.close() }
        struct Header: Encodable {
            let rootKey: Data; let manifestSHA256: String; let workerSHA256: String; let goVersion: String
            let sourceCount: Int; let takeovers: Int; let stores: Int
        }
        let sourceCountText = try #require(env["CENGINE_LIFECYCLE_SOURCE_COUNT"])
        let sourceCount = try #require(Int(sourceCountText))
        let header = Header(rootKey: root.publicData, manifestSHA256: try #require(env["CENGINE_LIFECYCLE_MANIFEST_SHA256"]),
            workerSHA256: try #require(env["CENGINE_LIFECYCLE_WORKER_SHA256"]), goVersion: try #require(env["CENGINE_LIFECYCLE_GO_VERSION"]),
            sourceCount: sourceCount, takeovers: 4098, stores: 130)
        try trace.write(contentsOf: L.encode(header) + Data([10]))
        var guestPeak = 0, guestAggregate = 0, previousIdentity: L.Identity?
        var finalFirstEpoch: UInt64 = 0
        // Reusing store UUID exercises generation fencing rather than historical UUID blacklists.
        let storeID = id()
        for number in UInt64(1)...130 {
            var owner = process(Int32(number * 10000)), candidate = try makeCandidate(owner.pid + 1)
            let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
            let binding = try StorageIdentity.StoreBinding(storeID: .init(storeID), root: .init(volumeUUID: volume, inode: number * 2 + 1),
                backing: .init(identity: .init(volumeUUID: volume, inode: number * 2 + 2), size: 4096), expectedExt4UUID: volume)
            let initial = try authority.provision(id: id(), binding: binding, candidate: candidate, daemon: owner, rootFD: fd, backingFD: fd)
            let identity = initial.grant.identity
            #expect(identity.generation == number)
            if let previousIdentity { #expect(throws: (any Error).self) { try authority.status(identity: previousIdentity) } }
            func record(_ signed: L.SignedGrant, _ reply: Reply, _ receipt: L.Receipt, reclaimed: Bool = false) throws {
                #expect(reply.error == nil)
                #expect(receipt.grant == signed.grant)
                guestPeak = max(guestPeak, reply.bytes); guestAggregate = reply.aggregateBytes
                try trace.write(contentsOf: L.encode(Trace(signed: signed, receipt: receipt,
                    publicKey: candidate.publicKey.publicData.suffix(32), incarnation: candidate.incarnationID.rawValue,
                    daemonUniqueID: owner.uniqueID, childUniqueID: UInt64(candidate.childPIDHint), childPID: candidate.childPIDHint,
                    guestBytes: reply.bytes, guestEpoch: reply.epoch, reclaimed: reclaimed)) + Data([10]))
            }
            let initialized = try bridge.call(.init(command: "apply", signed: initial, rootKey: root.publicData))
            if number == 1 {
                let pending = try journal.load()
                // A real stable receipt cannot replace independently fresh live proof.
                processes.denyServiceResult = true
                #expect(throws: (any Error).self) { try authority.complete(identity: identity, id: initial.grant.id, daemon: owner) }
                processes.denyServiceResult = false; processes.corruptServiceNonce = true
                #expect(throws: (any Error).self) { try authority.complete(identity: identity, id: initial.grant.id, daemon: owner) }
                processes.corruptServiceNonce = false; processes.corruptBoot = true
                #expect(throws: (any Error).self) { try authority.complete(identity: identity, id: initial.grant.id, daemon: owner) }
                processes.corruptBoot = false
                #expect(try journal.load() == pending)
            }
            let initialReceipt = try authority.complete(identity: identity, id: initial.grant.id, daemon: owner)
            #expect(initialReceipt.serviceEpoch == initialized.metadataScope?.serviceEpoch)
            if number == 1 {
                let live = try authority.serviceResult(identity: identity, grantID: initial.grant.id, daemon: owner)
                let principal = try processes.candidate(candidate, daemon: owner, grant: initial.grant)
                let boot = try processes.serviceBootTrust(principal, daemon: owner, grant: initial.grant)
                let change = try L.ServiceChangeRequest(operationID: id(), predecessor: live.state(boot: boot))
                #expect(throws: (any Error).self) {
                    try processes.serviceResult(principal, daemon: owner, grant: initial.grant, nonce: live.nonce,
                                                boot: boot, changeRequest: change, confirmation: nil)
                }
            }
            try record(initial, initialized, initialReceipt)
            var previous = initial
            for epoch in UInt64(1)...UInt64(number == 1 ? 4098 : 1) {
                processes.dead.insert(owner.pid); processes.dead.insert(candidate.childPIDHint)
                owner = process(owner.pid + 2); candidate = try makeCandidate(owner.pid + 1)
                #expect(throws: (any Error).self) { try authority.issue(operation: .takeover, id: id(), identity: identity, expectedEpoch: epoch + 1, candidate: candidate, daemon: owner) }
                let next = try authority.issue(operation: .takeover, id: id(), identity: identity, expectedEpoch: epoch, candidate: candidate, daemon: owner)
                #expect(next.grant.serial == previous.grant.serial + 1)
                let applied = try bridge.call(.init(command: "apply", signed: next))
                let receipt = try authority.complete(identity: identity, id: next.grant.id, daemon: owner)
                #expect(receipt.serviceEpoch == initialReceipt.serviceEpoch)
                #expect(applied.metadataScope?.openRevision == initialized.metadataScope?.openRevision)
                #expect(try authority.status(identity: identity).epoch.rawValue == epoch + 1)
                #expect(throws: (any Error).self) { try authority.read(identity: identity, id: previous.grant.id, daemon: owner) }
                if epoch > 1 {
                    let stale = try bridge.call(.init(command: "apply", signed: previous))
                    #expect(stale.error != nil); #expect(stale.epoch == applied.epoch)
                }
                if number == 1 && epoch == 1 {
                    // ROOT refuses an ID collision with a changed epoch/recipient.
                    #expect(throws: (any Error).self) { try authority.issue(operation: .takeover, id: next.grant.id, identity: identity, expectedEpoch: epoch + 1, candidate: candidate, daemon: owner) }
                    for kind in 0..<3 {
                        let g = next.grant
                        let altered = try L.Grant(operation: .takeover, id: kind == 1 ? g.id : id(),
                            identity: kind == 0 ? .init(store: identity.store, generation: identity.generation + 1, binding: identity.binding) : identity,
                            serial: kind == 2 ? g.serial : g.serial + 1, expectedEpoch: epoch + 1, newKey: makeCandidate(owner.pid + 100).publicKey.fingerprint.rawValue)
                        let rejected = try bridge.call(.init(command: "apply", signed: journal.signLifecycle(altered)))
                        #expect(rejected.error != nil); #expect(rejected.epoch == applied.epoch)
                    }
                    let badSignature = try L.SignedGrant(grant: next.grant, signature: Data(repeating: 0, count: 64))
                    #expect(try bridge.call(.init(command: "apply", signed: badSignature)).error != nil)
                }
                try record(next, applied, receipt)
                previous = next
                if epoch % 257 == 0 { authority = try .init(journal: journal, processes: processes, bindings: Bindings(rootPublicKey: try journal.lifecycleRootPublicKey().publicData)) }
            }
            let epoch: UInt64 = number == 1 ? 4099 : 2
            if number == 1 { finalFirstEpoch = epoch }
            let retirement = try authority.issue(operation: .retire, id: id(), identity: identity, expectedEpoch: epoch, candidate: candidate, daemon: owner)
            #expect(throws: (any Error).self) { try authority.reclaim(identity: identity, id: retirement.grant.id, daemon: owner) }
            let sealed = try bridge.call(.init(command: "apply", signed: retirement))
            #expect(sealed.error == nil)
            // Guest has durably sealed, but ROOT cannot release its reservation on lost/private proof.
            processes.deny = true
            #expect(throws: (any Error).self) { try authority.complete(identity: identity, id: retirement.grant.id, daemon: owner) }
            #expect(throws: (any Error).self) { try authority.reclaim(identity: identity, id: retirement.grant.id, daemon: owner) }
            processes.deny = false; processes.corrupt = true
            #expect(throws: (any Error).self) { try authority.complete(identity: identity, id: retirement.grant.id, daemon: owner) }
            processes.corrupt = false
            journal.failProofAfterWrite = { processes.deny = true }
            #expect(throws: (any Error).self) { try authority.complete(identity: identity, id: retirement.grant.id, daemon: owner) }
            journal.failProofAfterWrite = nil
            #expect(throws: (any Error).self) { try authority.reclaim(identity: identity, id: retirement.grant.id, daemon: owner) }
            processes.deny = false
            authority = try .init(journal: journal, processes: processes, bindings: Bindings(rootPublicKey: try journal.lifecycleRootPublicKey().publicData))
            let receipt = try authority.complete(identity: identity, id: retirement.grant.id, daemon: owner)
            #expect(try bridge.call(.init(command: "fence")).fence)
            try authority.reclaim(identity: identity, id: retirement.grant.id, daemon: owner)
            try authority.reclaim(identity: identity, id: retirement.grant.id, daemon: owner)
            try record(retirement, sealed, receipt, reclaimed: true)
            previousIdentity = identity
        }
        let bytes = try #require(try journal.load())
        let state = try #require(try JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect((state["stores"] as? [String: Any])?.isEmpty == true)
        #expect((state["generation"] as? NSNumber)?.uint64Value == 130)
        #expect((state["serial"] as? NSNumber)?.uint64Value == 4487)
        #expect(journal.peak < 16000); #expect(guestPeak < 6000)
        let rootBytes = try Data(contentsOf: dir.appending(path: "authority.journal")).count + Data(contentsOf: dir.appending(path: "authority.lock")).count
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted() == ["authority.journal", "authority.lock"])
        print("INTEGRATED ROOT/GUEST: firstEpoch=\(finalFirstEpoch) stores=130 serial=4487 rootAggregateBytes=\(rootBytes) rootPeakPayload=\(journal.peak) guestPeakBytes=\(guestPeak) guestRetainedAggregateBytes=\(guestAggregate) freshServiceResults=\(processes.serviceResultCalls)")
        for counter in ["serial", "generation"] {
            var exhausted = state
            exhausted["serial"] = NSNumber(value: UInt64.max)
            exhausted[counter] = NSNumber(value: UInt64.max)
            let data = try JSONSerialization.data(withJSONObject: exhausted, options: [.sortedKeys, .withoutEscapingSlashes])
            let probe = CounterProbe(data, root)
            let exhaustedAuthority = try StorageBootstrapLifecycleAuthority(journal: probe, processes: processes, bindings: Bindings(rootPublicKey: try journal.lifecycleRootPublicKey().publicData))
            let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
            let binding = try StorageIdentity.StoreBinding(storeID: .init(id()), root: .init(volumeUUID: volume, inode: 9001),
                backing: .init(identity: .init(volumeUUID: volume, inode: 9002), size: 4096), expectedExt4UUID: volume)
            #expect(throws: (any Error).self) {
                _ = try exhaustedAuthority.provision(id: id(), binding: binding, candidate: makeCandidate(9001), daemon: process(9000), rootFD: fd, backingFD: fd)
            }
        }
        try trace.synchronize(); try bridge.finish()
    }
    private func makeCandidate(_ pid: Int32) throws -> StorageIdentity.Candidate {
        try .init(publicKey: .init(rawPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation), childPIDHint: pid, incarnationID: .init(id()))
    }
}
