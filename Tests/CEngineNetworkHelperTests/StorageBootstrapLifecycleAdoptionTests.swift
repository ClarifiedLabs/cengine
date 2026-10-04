import CEngineCore
import Darwin
import Foundation
import Testing
import Synchronization
@preconcurrency import XPC
@testable import StorageBootstrapHelper

private typealias Wire = StorageLifecycleAdoptionProtocol
private func process(_ pid: Int32) -> BootstrapProcess {
    var token = audit_token_t(); token.val = (501, 501, 20, 501, 20, UInt32(pid), 1, 2)
    return .init(pid: pid, startSeconds: 1, startMicroseconds: 0, boot: "test-boot",
                 signingIdentity: "unsigned-test-seam", uniqueID: UInt64(pid), pidVersion: 2,
                 auditToken: BootstrapAuditIdentity(token: token).data)
}
private let adoptionSPKI = try! StorageIdentity.Ed25519SPKI(rawPublicKey: Data(repeating: 4, count: 32)).publicData
private func principal(_ pid: Int32) -> BootstrapPrincipal {
    .init(daemon: process(pid), child: process(pid + 1),
          incarnation: UUID().uuidString.lowercased(), controllerSPKI: adoptionSPKI)
}
private final class AdoptionJournal: StorageLifecycleAdoptionJournal {
    var bytes: Data?
    var root = Data(repeating: 7, count: 32)
    var fail = false
    var writes = 0
    func load() throws -> Data? { bytes }
    func rootPublicKey() throws -> Data { root }
    func checkpoint(_ bytes: Data) throws {
        writes += 1
        if fail { throw BootstrapFailure(.unavailable) }
        self.bytes = bytes
    }
}
/// State-machine seam only. Never fabricates a native authorization object.
private final class AdoptionProcesses: StorageLifecycleAdoptionChecking {
    var principal = BootstrapPrincipal(daemon: process(20), child: process(21),
                                      incarnation: UUID().uuidString.lowercased(), controllerSPKI: adoptionSPKI)
    var daemonLife = BootstrapLiveness.exited, controllerLife = BootstrapLiveness.exited
    var shimAlive = true, fresh = true, candidateValid = true, acknowledge = true
    var shimRegistered = true
    var challenges: [Wire.Challenge] = []
    var beforeFence: () throws -> Void = {}
    var beforeCommit: () throws -> Void = {}
    var commitAcknowledged = true
    var commits: [Wire.Request] = []
    var lives: [Int32: BootstrapLiveness] = [:]
    var shimFence: Wire.FenceIdentity?
    var shimEpoch: UInt64 = 1
    func freshOrigin(_ origin: StorageLifecycleShimOrigin, rootFD: Int32, backingFD: Int32) throws {
        guard fresh else { throw BootstrapFailure(.unauthorized) }
    }
    func candidate(_ request: Wire.Request, peer: BootstrapAuditIdentity) throws -> BootstrapPrincipal {
        guard candidateValid else { throw BootstrapFailure(.unauthorized) }; return principal
    }
    func liveness(_ p: BootstrapProcess) -> BootstrapLiveness {
        lives[p.pid] ?? (p.pid == 10 ? daemonLife : controllerLife)
    }
    func registeredShim(_ origin: StorageLifecycleShimOrigin) throws {
        guard shimAlive else { throw BootstrapFailure(.unauthorized) }
        guard shimRegistered else { throw BootstrapFailure(.unavailable) }
    }
    func commit(_ request: Wire.Request, origin: StorageLifecycleShimOrigin) throws {
        try beforeCommit(); commits.append(request)
        guard commitAcknowledged else { throw BootstrapFailure(.unavailable) }
    }
    func fence(_ challenge: Wire.Challenge, origin: StorageLifecycleShimOrigin) throws {
        try beforeFence(); challenges.append(challenge)
        // Model the required native high-water contract, NOT native authorization.
        let fence = try challenge.request.fenceIdentity
        guard challenge.request.origin == origin.wire,
              fence.epoch > shimEpoch || fence == shimFence else { throw BootstrapFailure(.conflict) }
        shimEpoch = fence.epoch; shimFence = fence
        guard acknowledge else { throw BootstrapFailure(.unavailable) }
    }
}
private struct Fixture {
    let journal = AdoptionJournal(), processes = AdoptionProcesses()
    let origin: StorageLifecycleShimOrigin
    init() throws {
        let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(UUID().uuidString.lowercased()),
            root: .init(volumeUUID: volume, inode: 2),
            backing: .init(identity: .init(volumeUUID: volume, inode: 3), size: 4096), expectedExt4UUID: volume)
        origin = try .init(wire: .init(binding: .init(binding), rootPublicKey: journal.root,
            shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: String(repeating: "a", count: 64)),
            shim: process(12), originalDaemon: process(10), originalController: process(11))
    }
    func authority() throws -> StorageBootstrapLifecycleAdoptionAuthority {
        try .init(journal: journal, processes: processes)
    }
    func request(id: String = UUID().uuidString.lowercased(), epoch: UInt64 = 1,
                 origin override: Wire.Origin? = nil, superseded: Wire.FenceIdentity? = nil) throws -> Wire.Request {
        try .init(id: id, origin: override ?? origin.wire, expectedEpoch: epoch,
            daemonAudit: processes.principal.daemon.auditToken, daemonUniqueID: processes.principal.daemon.uniqueID,
            controllerAudit: processes.principal.child.auditToken, controllerUniqueID: processes.principal.child.uniqueID,
            superseded: superseded)
    }
    var peer: BootstrapAuditIdentity {
        .init(token: processes.principal.daemon.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
    }
    func registered() throws -> StorageBootstrapLifecycleAdoptionAuthority {
        let value = try authority(); try value.recordOrigin(origin, rootFD: -1, backingFD: -1); return value
    }
}

@Suite struct StorageBootstrapLifecycleAdoptionTests {
    private func coldOrigin(_ f: Fixture, pid: Int32 = 40) throws -> StorageLifecycleShimOrigin {
        try .init(wire: .init(binding: f.origin.wire.binding, rootPublicKey: f.journal.root,
            shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: f.origin.wire.specSHA256),
            shim: process(pid + 2), originalDaemon: process(pid), originalController: process(pid + 1))
    }
    private let coldDigest = String(repeating: "b", count: 64)

    @Test func coldRotationReloadAndLiveAdoptionUseNewBaseAndRejectStaleBridge() throws {
        let f = try Fixture(), a = try f.registered(), first = try f.request()
        try a.prepare(first, peer: f.peer); _ = try a.complete(first, peer: f.peer)
        let snapshot = try a.coldSnapshot(store: f.origin.wire.binding.store)
        #expect(snapshot.committedEpoch == 2 && snapshot.allocatedEpoch == 2)
        #expect(try JSONDecoder().decode(StorageLifecycleColdAdoptionSnapshot.self,
            from: JSONEncoder().encode(snapshot)) == snapshot)
        let origin = try coldOrigin(f), operation = UUID().uuidString.lowercased()
        try a.verifyColdPredecessor(snapshot: snapshot)
        try a.rotateCold(from: snapshot, to: origin, operationID: operation, signedOpenSHA256: coldDigest, baseEpoch: 3)
        let reloaded = try f.authority(), writes = f.journal.writes
        #expect(try reloaded.matchesColdRotation(from: snapshot, to: origin, operationID: operation,
            signedOpenSHA256: coldDigest, baseEpoch: 3))
        try reloaded.rotateCold(from: snapshot, to: origin, operationID: operation, signedOpenSHA256: coldDigest, baseEpoch: 3)
        #expect(f.journal.writes == writes)
        let status = try reloaded.status(store: origin.wire.binding.store)
        #expect(status.baseEpoch == 3 && status.committedEpoch == 3 && status.allocatedEpoch == 3)
        #expect(status.latest == nil && status.pending == nil)
        #expect(throws: (any Error).self) { try reloaded.prepare(f.request(epoch: 3), peer: f.peer) }
        #expect(throws: (any Error).self) { try reloaded.verifyColdPredecessor(snapshot: snapshot) }
        #expect(try !reloaded.matchesColdRotation(from: snapshot, to: origin, operationID: UUID().uuidString.lowercased(),
            signedOpenSHA256: coldDigest, baseEpoch: 3))
        #expect(try !reloaded.matchesColdRotation(from: snapshot, to: origin, operationID: operation,
            signedOpenSHA256: String(repeating: "c", count: 64), baseEpoch: 3))
        let next = try f.request(epoch: 3, origin: origin.wire)
        try reloaded.prepare(next, peer: f.peer)
        #expect(try !reloaded.matchesColdRotation(from: snapshot, to: origin, operationID: operation,
            signedOpenSHA256: coldDigest, baseEpoch: 3))
        #expect(try reloaded.complete(next, peer: f.peer) == 4)
        let after = try f.authority()
        #expect(try after.status(store: origin.wire.binding.store).baseEpoch == 3)
        #expect(try !after.matchesColdRotation(from: snapshot, to: origin, operationID: operation,
            signedOpenSHA256: coldDigest, baseEpoch: 3))
        #expect(throws: (any Error).self) {
            try after.rotateCold(from: snapshot, to: origin, operationID: operation, signedOpenSHA256: coldDigest, baseEpoch: 3)
        }
        #expect(String(decoding: try #require(f.journal.bytes), as: UTF8.self).contains("\"coldBridge\""))
    }

    @Test func coldRequiresPositiveDeathOfOriginalAndCommittedProcesses() throws {
        for pid: Int32 in [10, 11, 12, 20, 21] {
            for life in [BootstrapLiveness.alive, .unknown] {
                let f = try Fixture(), a = try f.registered(), request = try f.request()
                try a.prepare(request, peer: f.peer); _ = try a.complete(request, peer: f.peer)
                let snapshot = try a.coldSnapshot(store: f.origin.wire.binding.store), origin = try coldOrigin(f)
                let before = f.journal.bytes
                f.processes.lives[pid] = life
                #expect(throws: (any Error).self) { try a.verifyColdPredecessor(snapshot: snapshot) }
                #expect(throws: (any Error).self) {
                    try a.rotateCold(from: snapshot, to: origin, operationID: UUID().uuidString.lowercased(),
                                     signedOpenSHA256: coldDigest, baseEpoch: 3)
                }
                #expect(f.journal.bytes == before)
            }
        }
    }

    @Test func coldRejectsPendingAndAbandonedWithoutAutomaticAbandonment() throws {
        let f = try Fixture(), a = try f.registered(), first = try f.request()
        let clean = try a.coldSnapshot(store: f.origin.wire.binding.store)
        try a.prepare(first, peer: f.peer)
        #expect(throws: (any Error).self) { try a.coldSnapshot(store: f.origin.wire.binding.store) }
        #expect(throws: (any Error).self) { try a.verifyColdPredecessor(snapshot: clean) }
        f.processes.principal = principal(30)
        let second = try f.request(epoch: 2, superseded: first.fenceIdentity)
        try a.prepare(second, peer: f.peer)
        #expect(throws: (any Error).self) { try a.coldSnapshot(store: f.origin.wire.binding.store) }
        _ = try a.complete(second, peer: f.peer)
        let before = f.journal.bytes
        #expect(throws: (any Error).self) { try a.coldSnapshot(store: f.origin.wire.binding.store) }
        #expect(f.journal.bytes == before) // Abandoned evidence remains even after commit.
    }

    @Test func coldSnapshotFingerprintsLatestPrincipalAndRotationFailurePoisons() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        try a.prepare(request, peer: f.peer); _ = try a.complete(request, peer: f.peer)
        let snapshot = try a.coldSnapshot(store: f.origin.wire.binding.store)
        let changedBytes = Data(String(decoding: snapshot.protectedStore, as: UTF8.self)
            .replacingOccurrences(of: f.processes.principal.incarnation, with: UUID().uuidString.lowercased()).utf8)
        let changed = StorageLifecycleColdAdoptionSnapshot(origin: snapshot.origin, committedEpoch: snapshot.committedEpoch,
            allocatedEpoch: snapshot.allocatedEpoch, daemon: snapshot.daemon, controller: snapshot.controller,
            protectedStore: changedBytes)
        #expect(changed != snapshot)
        #expect(throws: (any Error).self) { try a.verifyColdPredecessor(snapshot: changed) }
        let origin = try coldOrigin(f), operation = UUID().uuidString.lowercased()
        f.journal.fail = true
        #expect(throws: (any Error).self) {
            try a.rotateCold(from: snapshot, to: origin, operationID: operation, signedOpenSHA256: coldDigest, baseEpoch: 3)
        }
        f.journal.fail = false
        #expect(throws: (any Error).self) { try a.coldSnapshot(store: f.origin.wire.binding.store) }
        let reloaded = try f.authority()
        #expect(try reloaded.coldSnapshot(store: f.origin.wire.binding.store) == snapshot)
        try reloaded.rotateCold(from: snapshot, to: origin, operationID: operation, signedOpenSHA256: coldDigest, baseEpoch: 3)
    }

    @Test func coldBridgeRejectsTamperingReusedShimWrongBaseAndOverflow() throws {
        let f = try Fixture(), a = try f.registered(), snapshot = try a.coldSnapshot(store: f.origin.wire.binding.store)
        let origin = try coldOrigin(f), operation = UUID().uuidString.lowercased()
        for base: UInt64 in [0, 1, 3, UInt64.max] {
            #expect(throws: (any Error).self) {
                try a.rotateCold(from: snapshot, to: origin, operationID: operation, signedOpenSHA256: coldDigest, baseEpoch: base)
            }
        }
        for reused in [f.origin, StorageLifecycleShimOrigin(wire: origin.wire, shim: f.origin.shim,
            originalDaemon: origin.originalDaemon, originalController: origin.originalController)] {
            #expect(throws: (any Error).self) {
                try a.rotateCold(from: snapshot, to: reused, operationID: operation, signedOpenSHA256: coldDigest, baseEpoch: 2)
            }
        }
        try a.rotateCold(from: snapshot, to: origin, operationID: operation, signedOpenSHA256: coldDigest, baseEpoch: 2)
        let valid = try #require(f.journal.bytes)
        for (old, new) in [("\"oldAllocatedEpoch\":1", "\"oldAllocatedEpoch\":2"),
                           ("\"baseEpoch\":2", "\"baseEpoch\":1"),
                           ("\"signedOpenSHA256\":\"" + coldDigest, "\"signedOpenSHA256\":\"bad"),
                           ("\"baseEpoch\":2,", "")] {
            f.journal.bytes = Data(String(decoding: valid, as: UTF8.self).replacingOccurrences(of: old, with: new).utf8)
            #expect(throws: (any Error).self) { try f.authority() }
        }
        // A valid protected latest commit can reach max; cold must not wrap to zero.
        let g = try Fixture(), b = try g.registered(), last = try g.request()
        try b.prepare(last, peer: g.peer); _ = try b.complete(last, peer: g.peer)
        g.journal.bytes = Data(String(decoding: try #require(g.journal.bytes), as: UTF8.self)
            .replacingOccurrences(of: "\"expectedEpoch\":1", with: "\"expectedEpoch\":18446744073709551614")
            .replacingOccurrences(of: "\"allocatedEpoch\":2", with: "\"allocatedEpoch\":18446744073709551615")
            .replacingOccurrences(of: "\"epoch\":2", with: "\"epoch\":18446744073709551615").utf8)
        let maximum = try g.authority(), maxSnapshot = try maximum.coldSnapshot(store: g.origin.wire.binding.store)
        #expect(maxSnapshot.allocatedEpoch == UInt64.max)
        #expect(throws: (any Error).self) {
            try maximum.rotateCold(from: maxSnapshot, to: coldOrigin(g), operationID: operation,
                                   signedOpenSHA256: coldDigest, baseEpoch: 0)
        }
    }

    @Test func helperReloadWaitsForRegisteredShimWithoutChangingPendingFence() throws {
        let f = try Fixture(), initial = try f.registered(), request = try f.request()
        try initial.prepare(request, peer: f.peer)
        let before = try #require(f.journal.bytes), writes = f.journal.writes
        let reloaded = try f.authority()
        f.processes.shimRegistered = false
        for _ in 0..<3 {
            do { _ = try reloaded.complete(request, peer: f.peer); Issue.record("missing registration accepted") }
            catch let failure as BootstrapFailure { #expect(failure.code == .unavailable) }
            #expect(f.journal.bytes == before && f.journal.writes == writes)
            #expect(try reloaded.status(store: request.origin.binding.store).pending == request)
        }
        #expect(f.processes.challenges.isEmpty)
        f.processes.shimAlive = false
        do { _ = try reloaded.complete(request, peer: f.peer); Issue.record("dead shim accepted") }
        catch let failure as BootstrapFailure { #expect(failure.code == .unauthorized) }
        f.processes.shimAlive = true; f.processes.shimRegistered = true
        #expect(try reloaded.complete(request, peer: f.peer) == 2)
        #expect(f.processes.challenges.count == 1)
        #expect(try reloaded.status(store: request.origin.binding.store).pending == nil)
    }

    @Test func serviceAdmissionRequiresExactCommitAndRejectsSupersedingPending() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        #expect(throws: (any Error).self) { try a.committed(request, peer: f.peer) }
        try a.prepare(request, peer: f.peer)
        #expect(throws: (any Error).self) { try a.committed(request, peer: f.peer) }
        _ = try a.complete(request, peer: f.peer)
        #expect(try a.committed(request, peer: f.peer).1 == f.processes.principal)
        let status = try a.status(store: f.origin.wire.binding.store)
        #expect(status.shimAudit == f.origin.shim.auditToken && status.shimUniqueID == f.origin.shim.uniqueID)
        f.processes.principal = principal(30)
        let next = try f.request(epoch: 2)
        try a.prepare(next, peer: f.peer)
        #expect(throws: (any Error).self) { try a.committed(request, peer: f.peer) }
        #expect(throws: (any Error).self) { try a.committed(next, peer: f.peer) }
    }
    @Test func rootDispatchIsScopedReadOnlyAndExactRetryRemainsNecessary() throws {
        typealias Root = StorageLifecycleAdoptionRootProtocol
        let f = try Fixture(), a = try f.registered(), adoption = try f.request()
        func call(_ body: Root.Body, origin: Wire.Origin? = nil) throws -> Root.ResultBody {
            let request = try Root.Request(requestID: .init(UUID().uuidString.lowercased()), body: body)
            let result = try StorageBootstrapLifecycleAdoptionRootXPC.dispatch(request, authority: a,
                origin: origin ?? f.origin.wire, peer: f.peer)
            return try Root.decodeReply(Root.encode(.init(for: request, body: result)), for: request).body
        }
        let other = try Fixture()
        #expect(throws: (any Error).self) { try call(.prepare(adoption), origin: other.origin.wire) }
        #expect(throws: (any Error).self) { try call(.complete(adoption), origin: other.origin.wire) }
        #expect(f.journal.writes == 1)
        _ = try call(.prepare(adoption))
        f.processes.commitAcknowledged = false
        #expect(throws: (any Error).self) { try call(.complete(adoption)) }
        let writes = f.journal.writes, commits = f.processes.commits.count, fences = f.processes.challenges.count
        f.processes.candidateValid = false; f.processes.shimAlive = false
        guard case .status(let status) = try call(.status) else { Issue.record("status missing"); return }
        #expect(status.latest == adoption && status.pending == nil)
        #expect(f.journal.writes == writes && f.processes.commits.count == commits && f.processes.challenges.count == fences)
        f.processes.candidateValid = true; f.processes.shimAlive = true; f.processes.commitAcknowledged = true
        #expect(try call(.complete(adoption)) == .completed(adoption.fenceIdentity))
        #expect(f.processes.commits.count == commits + 1)
        #expect(throws: (any Error).self) { try call(.complete(f.request())) }
    }

    @Test func checkpointPostflightFailurePreservesExactIntent() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        var checks = 0
        #expect(throws: (any Error).self) {
            try a.withIOChecks({
                checks += 1
                if checks == 2 { throw BootstrapFailure(.unauthorized) }
            }) { try a.prepare(request, peer: f.peer) }
        }
        #expect(checks == 2)
        #expect(try f.authority().status(store: f.origin.wire.binding.store).pending == request)
        try a.prepare(request, peer: f.peer)
        #expect(f.journal.writes == 2)
    }

    @Test func statusIsReadOnlyAndDoesNotAcknowledgeNativeCommit() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        let initial = try a.status(store: f.origin.wire.binding.store)
        #expect(initial.committedEpoch == 1 && initial.allocatedEpoch == 1)
        #expect(initial.pending == nil && initial.latest == nil)
        #expect(f.journal.writes == 1)
        try a.prepare(request, peer: f.peer)
        let pending = try a.status(store: f.origin.wire.binding.store)
        #expect(pending.committedEpoch == 1 && pending.allocatedEpoch == 2)
        #expect(pending.pending == request && pending.latest == nil)
        #expect(f.journal.writes == 2)
        f.processes.commitAcknowledged = false
        #expect(throws: (any Error).self) { try a.complete(request, peer: f.peer) }
        let writes = f.journal.writes, fences = f.processes.challenges.count, commits = f.processes.commits.count
        let uncertain = try f.authority().status(store: f.origin.wire.binding.store)
        #expect(uncertain.committedEpoch == 2 && uncertain.allocatedEpoch == 2)
        #expect(uncertain.pending == nil && uncertain.latest == request)
        #expect(f.journal.writes == writes && f.processes.challenges.count == fences && f.processes.commits.count == commits)
        #expect(throws: (any Error).self) { try a.status(store: UUID().uuidString.lowercased()) }
        #expect(f.journal.writes == writes)
    }

    @Test func enrollmentEnvelopeRequiresBackingDescriptorAndExactShimRole() throws {
        let f = try Fixture(), message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", StorageBootstrapLifecycleAdoptionXPC.enrollmentOperation)
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        xpc_dictionary_set_string(message, "role", "storage-shim")
        let bytes = try Wire.encode(f.origin.wire)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        #expect(StorageBootstrapLifecycleRouter.recognizes(StorageBootstrapLifecycleAdoptionXPC.greetingOperation))
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.validateAdmission(message) }
        let fd = open("/dev/null", O_RDONLY | O_CLOEXEC); defer { close(fd) }
        #expect(fd >= 0)
        xpc_dictionary_set_fd(message, "backing-fd", fd)
        #expect(try StorageBootstrapLifecycleRouter.validateAdmission(message) == StorageBootstrapLifecycleAdoptionXPC.enrollmentOperation)
        xpc_dictionary_set_string(message, "role", "daemon")
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.validateAdmission(message) }
        xpc_dictionary_set_string(message, "role", "storage-shim")
        xpc_dictionary_set_string(message, "extra", "not-allowed")
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.validateAdmission(message) }
    }

    @Test func actualAnonymousMachGreetingCannotReplaceJournalShim() async throws {
        try await Task.detached {
            let f = try Fixture(), worker = StorageBootstrapLifecycleChildWorker()
            let transport = StorageBootstrapLifecycleAdoptionXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
                expectedRootPublicKey: try .init(publicData: f.journal.root), worker: worker,
                lookupOrigin: { _ in f.origin },
                verifyFreshOrigin: { _, _, _ in throw BootstrapFailure(.unauthorized) },
                verifyCandidate: { _, _, _ in throw BootstrapFailure(.unauthorized) })
            let queue = DispatchQueue(label: "dev.cengine.test.adoption-native")
            let listener = xpc_connection_create(nil, queue), peers = Mutex<[xpc_connection_t]>([])
            let done = DispatchSemaphore(value: 0)
            xpc_connection_set_event_handler(listener) { peer in
                guard xpc_get_type(peer) == XPC_TYPE_CONNECTION else { return }
                peers.withLock { $0.append(peer) }
                xpc_connection_set_event_handler(peer) { message in
                    guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
                          let reply = xpc_dictionary_create_reply(message) else { return }
                    defer { done.signal() }
                    #expect(throws: (any Error).self) {
                        try worker.perform { try transport.greet(message, reply: reply, peer: peer) }
                    }
                    transport.disconnected(peer)
                }
                xpc_connection_resume(peer)
            }
            xpc_connection_resume(listener)
            let client = xpc_connection_create_from_endpoint(xpc_endpoint_create(listener))
            xpc_connection_set_event_handler(client) { _ in }
            xpc_connection_resume(client)
            defer {
                xpc_connection_cancel(client); xpc_connection_cancel(listener)
                for peer in peers.withLock({ $0 }) { xpc_connection_cancel(peer) }
            }
            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(message, "operation", "storage-lifecycle-adoption-shim")
            xpc_dictionary_set_string(message, "role", "storage-shim")
            let bytes = try Wire.encode(f.origin.wire)
            bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
            xpc_connection_send_message_with_reply(client, message, queue) { _ in }
            func waitForGreeting() -> Bool { done.wait(timeout: .now() + 5) == .success }
            #expect(waitForGreeting())
        }.value
    }

    @Test func commitNotificationFollowsDurableCommitAndLostReceiptRetriesExactly() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        try a.prepare(request, peer: f.peer)
        f.processes.beforeCommit = {
            #expect(f.journal.writes == 3)
            let text = String(decoding: try #require(f.journal.bytes), as: UTF8.self)
            #expect(text.contains("\"epoch\":2"))
            #expect(!text.contains("\"pending\":"))
        }
        f.processes.commitAcknowledged = false
        #expect(throws: (any Error).self) { try a.complete(request, peer: f.peer) }
        f.processes.commitAcknowledged = true
        #expect(try f.authority().complete(request, peer: f.peer) == 2)
        #expect(f.processes.commits == [request, request])
        #expect(f.journal.writes == 3)
    }

    @Test func protectedCheckpointRecordsOriginPreparesAndReloads() throws {
        let disk = try AdoptionDiskFixture(), processes = AdoptionProcesses()
        var scope: StorageLifecycleQualificationDirectory? = try disk.scope()
        var adapter: StorageBootstrapLifecycleAdoptionJournal? = try scope!.adoptionJournalForTesting(enrollIfNoState: true)
        let root = try adapter!.rootPublicKey(), binding = disk.binding
        let full = try StorageIdentity.StoreBinding(storeID: binding.store, root: binding.root,
            backing: .init(identity: .init(volumeUUID: binding.root.volumeUUID, inode: binding.root.inode + 1), size: 4096),
            expectedExt4UUID: binding.root.volumeUUID)
        let origin = try StorageLifecycleShimOrigin(wire: .init(binding: .init(full), rootPublicKey: root,
            shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: String(repeating: "a", count: 64)),
            shim: process(12), originalDaemon: process(10), originalController: process(11))
        let request = try Wire.Request(id: UUID().uuidString.lowercased(), origin: origin.wire, expectedEpoch: 1,
            daemonAudit: processes.principal.daemon.auditToken, daemonUniqueID: processes.principal.daemon.uniqueID,
            controllerAudit: processes.principal.child.auditToken, controllerUniqueID: processes.principal.child.uniqueID)
        let peer = BootstrapAuditIdentity(token: processes.principal.daemon.auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
        var authority: StorageBootstrapLifecycleAdoptionAuthority? = try .init(journal: adapter!, processes: processes)
        try authority!.recordOrigin(origin, rootFD: disk.fd, backingFD: -1)
        try authority!.prepare(request, peer: peer)
        #expect(processes.challenges.isEmpty)
        authority = nil; adapter = nil; scope = nil
        let reopened = try disk.scope().adoptionJournalForTesting()
        #expect(try reopened.rootPublicKey() == root)
        let loaded = try StorageBootstrapLifecycleAdoptionAuthority(journal: reopened, processes: processes)
        try loaded.prepare(request, peer: peer)
        #expect(try loaded.complete(request, peer: peer) == 2)
    }

    @Test func prepareIsDurableBeforeFenceAndExactRetriesAreBounded() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        try a.prepare(request, peer: f.peer)
        #expect(f.processes.challenges.isEmpty && f.journal.writes == 2)
        let durable = f.journal.bytes
        f.processes.beforeFence = { #expect(f.journal.bytes == durable) }
        #expect(try a.complete(request, peer: f.peer) == 2)
        f.processes.beforeFence = {}
        for _ in 0..<20 {
            try a.prepare(request, peer: f.peer)
            #expect(try a.complete(request, peer: f.peer) == 2)
        }
        #expect(f.journal.writes == 3)
        #expect(Set(f.processes.challenges.map(\.nonce)).count == 21)
        #expect(try f.authority().complete(request, peer: f.peer) == 2)
    }
    @Test func lostShimReplyKeepsPendingAcrossReloadAndRejectsConflicts() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        try a.prepare(request, peer: f.peer); f.processes.acknowledge = false
        #expect(throws: (any Error).self) { try a.complete(request, peer: f.peer) }
        let reloaded = try f.authority()
        #expect(throws: (any Error).self) { try reloaded.prepare(f.request(), peer: f.peer) }
        f.processes.acknowledge = true
        #expect(try reloaded.complete(request, peer: f.peer) == 2)
    }
    @Test func bothOldProcessesMustPositivelyExit() throws {
        for daemon in [true, false] {
            for life in [BootstrapLiveness.alive, .unknown] {
                let f = try Fixture(), a = try f.registered()
                if daemon { f.processes.daemonLife = life } else { f.processes.controllerLife = life }
                #expect(throws: (any Error).self) { try a.prepare(f.request(), peer: f.peer) }
                #expect(f.journal.writes == 1 && f.processes.challenges.isEmpty)
            }
        }
    }
    @Test func failedFreshNativeEvidenceCannotRecordOrigin() throws {
        let f = try Fixture(), a = try f.authority(); f.processes.fresh = false
        #expect(throws: (any Error).self) { try a.recordOrigin(f.origin, rootFD: -1, backingFD: -1) }
        #expect(f.journal.bytes == nil)
    }
    @Test func shimDeathAndWrongConnectedPeerRefuse() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        f.processes.shimAlive = false
        #expect(throws: (any Error).self) { try a.prepare(request, peer: f.peer) }
        f.processes.shimAlive = true
        #expect(throws: (any Error).self) { try a.prepare(request, peer: .init(token: audit_token_t())) }
        f.processes.candidateValid = false
        #expect(throws: (any Error).self) { try a.prepare(request, peer: f.peer) }
        #expect(f.journal.writes == 1)
    }
    @Test func failuresPoisonUntilReloadIncludingCommitAfterAck() throws {
        for commit in [false, true] {
            let f = try Fixture(), a = try f.registered(), request = try f.request()
            if commit { try a.prepare(request, peer: f.peer) }
            f.journal.fail = true
            #expect(throws: (any Error).self) {
                if commit { _ = try a.complete(request, peer: f.peer) }
                else { try a.prepare(request, peer: f.peer) }
            }
            f.journal.fail = false
            #expect(throws: (any Error).self) { try a.prepare(request, peer: f.peer) }
            let reloaded = try f.authority(); try reloaded.prepare(request, peer: f.peer)
            #expect(try reloaded.complete(request, peer: f.peer) == 2)
        }
    }
    @Test func rootEpochAndOriginConflictsRefuse() throws {
        let f = try Fixture(), a = try f.registered()
        #expect(throws: (any Error).self) { try a.prepare(f.request(epoch: 2), peer: f.peer) }
        let changed = try Wire.Origin(binding: f.origin.wire.binding, rootPublicKey: f.journal.root,
            shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: f.origin.wire.specSHA256)
        #expect(throws: (any Error).self) { try a.prepare(f.request(origin: changed), peer: f.peer) }
        f.journal.root = Data(repeating: 8, count: 32)
        #expect(throws: (any Error).self) { try f.authority() }
        #expect(throws: (any Error).self) { try a.prepare(f.request(), peer: f.peer) }
    }
    @Test func closedWireRejectsUnknownDuplicateWhitespaceAndInvalidValues() throws {
        let f = try Fixture(), request = try f.request()
        let bytes = try Wire.encode(request)
        #expect(try Wire.decodeRequest(bytes) == request)
        let text = String(decoding: bytes, as: UTF8.self)
        for bad in [" " + text, String(text.dropLast()) + ",\"extra\":1}",
                    String(text.dropLast()) + ",\"expectedEpoch\":1}",
                    text.replacingOccurrences(of: "\"expectedEpoch\":1", with: "\"expectedEpoch\":0")] {
            #expect(throws: (any Error).self) { try Wire.decodeRequest(Data(bad.utf8)) }
        }
        #expect(throws: (any Error).self) { try f.request(epoch: UInt64.max) }
        let challenge = try Wire.Challenge(request: request, nonce: Data(repeating: 1, count: 32))
        #expect(try Wire.decodeChallenge(Wire.encode(challenge)) == challenge)
        let reply = try Wire.Reply(challengeSHA256: challenge.digest)
        #expect(try Wire.decodeReply(Wire.encode(reply)) == reply)
        #expect(throws: (any Error).self) { try Wire.decodeReply(Data("{\"challengeSHA256\":\"\"}".utf8)) }
    }
    @Test func cannotCommitBeforePrepareOrAfterShimChangesDuringChallenge() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        #expect(throws: (any Error).self) { try a.complete(request, peer: f.peer) }
        #expect(f.processes.challenges.isEmpty)
        try a.prepare(request, peer: f.peer)
        f.processes.beforeFence = { f.processes.shimAlive = false }
        #expect(throws: (any Error).self) { try a.complete(request, peer: f.peer) }
        #expect(f.journal.writes == 2)
    }
    @Test func repeatedAdoptionReplacesLatestAndRejectsHistoricalReplay() throws {
        let f = try Fixture(), a = try f.registered(), first = try f.request()
        try a.prepare(first, peer: f.peer); _ = try a.complete(first, peer: f.peer)
        for epoch in UInt64(2)...40 {
            f.processes.principal = .init(daemon: process(Int32(epoch * 2 + 30)),
                child: process(Int32(epoch * 2 + 31)), incarnation: UUID().uuidString.lowercased(), controllerSPKI: adoptionSPKI)
            let request = try f.request(epoch: epoch)
            try a.prepare(request, peer: f.peer)
            #expect(try a.complete(request, peer: f.peer) == epoch + 1)
        }
        #expect(try #require(f.journal.bytes).count < 10_000)
        _ = try f.authority()
        #expect(throws: (any Error).self) { try a.prepare(first, peer: f.peer) }
    }
    @Test func physicalAliasesAndMalformedCheckpointRefuse() throws {
        let f = try Fixture(), a = try f.registered()
        let bound = try f.origin.wire.binding.value()
        let alias = StorageIdentity.StoreBinding(storeID: try .init(UUID().uuidString.lowercased()),
            root: bound.root, backing: bound.backing, expectedExt4UUID: bound.expectedExt4UUID)
        let origin = try StorageLifecycleShimOrigin(wire: .init(binding: .init(alias), rootPublicKey: f.journal.root,
            shimLaunchUUID: f.origin.wire.shimLaunchUUID, specSHA256: f.origin.wire.specSHA256),
            shim: f.origin.shim, originalDaemon: f.origin.originalDaemon, originalController: f.origin.originalController)
        #expect(throws: (any Error).self) { try a.recordOrigin(origin, rootFD: -1, backingFD: -1) }
        #expect(f.journal.writes == 1)
        f.journal.bytes?.append(32)
        #expect(throws: (any Error).self) { try f.authority() }
    }
    @Test func pendingSupersessionSurvivesRepeatedCrashesAndReloadWithoutEpochReuse() throws {
        for lostReply in [false, true] {
            let f = try Fixture()
            var a = try f.registered(), old = try f.request()
            try a.prepare(old, peer: f.peer)
            for epoch in UInt64(2)...12 {
                if lostReply && epoch.isMultiple(of: 2) {
                    f.processes.acknowledge = false
                    #expect(throws: (any Error).self) { try a.complete(old, peer: f.peer) }
                }
                let oldPrincipal = f.processes.principal, oldPeer = f.peer
                f.processes.lives[oldPrincipal.daemon.pid] = .exited
                f.processes.lives[oldPrincipal.child.pid] = .exited
                let successor = principal(Int32(epoch * 2 + 30))
                f.processes.principal = successor
                a = try f.authority()
                let next = try f.request(epoch: epoch, superseded: old.fenceIdentity)
                try a.prepare(next, peer: f.peer)
                let bytes = try #require(f.journal.bytes)
                let state = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
                let stores = try #require(state["stores"] as? [String: [String: Any]])
                let store = try #require(stores[f.origin.wire.binding.store])
                #expect(store["epoch"] as? Int == 1) // Abandoned adoption was never committed.
                #expect(store["allocatedEpoch"] as? UInt64 == epoch + 1)
                #expect(store["latest"] == nil)
                #expect(bytes.count < 13_000) // One predecessor, not recursive history.
                f.processes.principal = oldPrincipal
                #expect(throws: (any Error).self) { try a.complete(old, peer: oldPeer) }
                f.processes.principal = successor
                old = next
            }
            f.processes.acknowledge = true
            a = try f.authority()
            #expect(try a.complete(old, peer: f.peer) == 13)
            #expect(f.processes.shimEpoch == 13)
            #expect(f.processes.challenges.last?.request.superseded == old.superseded)
            #expect(try f.authority().complete(old, peer: f.peer) == 13)
        }
    }
    @Test func supersessionRequiresExactFenceAndPositiveDeathOfBothOwners() throws {
        for pid: Int32 in [10, 11, 20, 21] {
            for life in [BootstrapLiveness.alive, .unknown] {
                let f = try Fixture(), a = try f.registered(), old = try f.request()
                try a.prepare(old, peer: f.peer)
                f.processes.principal = principal(30); f.processes.lives[pid] = life
                #expect(throws: (any Error).self) {
                    try a.prepare(f.request(epoch: 2, superseded: old.fenceIdentity), peer: f.peer)
                }
                #expect(f.journal.writes == 2 && f.processes.challenges.isEmpty)
            }
        }
        let f = try Fixture(), a = try f.registered(), old = try f.request()
        try a.prepare(old, peer: f.peer); f.processes.principal = principal(30)
        let wrong = try Wire.FenceIdentity(id: UUID().uuidString.lowercased(), epoch: 2,
                                         nativeIdentitySHA256: old.nativeIdentitySHA256)
        for fence in [nil, wrong] {
            #expect(throws: (any Error).self) { try a.prepare(f.request(epoch: 2, superseded: fence), peer: f.peer) }
        }
        for epoch: UInt64 in [1, 3, 100] {
            #expect(throws: (any Error).self) { try a.prepare(f.request(epoch: epoch), peer: f.peer) }
        }
        let wrongDigest = try Wire.FenceIdentity(id: old.id, epoch: 2, nativeIdentitySHA256: Data(repeating: 9, count: 32))
        #expect(throws: (any Error).self) { try a.prepare(f.request(epoch: 2, superseded: wrongDigest), peer: f.peer) }
        #expect(f.journal.writes == 2)
    }
    @Test func supersessionCheckpointFailurePoisonsWithoutReissuingAbandonedEpoch() throws {
        let f = try Fixture(), a = try f.registered(), old = try f.request()
        try a.prepare(old, peer: f.peer)
        f.processes.acknowledge = false
        #expect(throws: (any Error).self) { try a.complete(old, peer: f.peer) }
        f.processes.principal = principal(30)
        let next = try f.request(epoch: 2, superseded: old.fenceIdentity)
        f.journal.fail = true
        #expect(throws: (any Error).self) { try a.prepare(next, peer: f.peer) }
        f.journal.fail = false
        #expect(throws: (any Error).self) { try a.prepare(next, peer: f.peer) }
        #expect(throws: (any Error).self) { try a.complete(next, peer: f.peer) }
        let reloaded = try f.authority()
        try reloaded.prepare(next, peer: f.peer)
        f.processes.acknowledge = true
        #expect(try reloaded.complete(next, peer: f.peer) == 3)
    }
    @Test func principalValidationRejectsMalformedLaunchAndNativeProcessFields() throws {
        for bad in ["incarnation", "key", "start", "pid", "unique", "audit", "boot"] {
            let f = try Fixture(), a = try f.registered(), valid = f.processes.principal
            let child = valid.child
            let altered = BootstrapProcess(pid: bad == "pid" ? valid.daemon.pid : child.pid,
                startSeconds: bad == "start" ? 0 : child.startSeconds, startMicroseconds: child.startMicroseconds,
                boot: bad == "boot" ? "other-boot" : child.boot, signingIdentity: child.signingIdentity,
                uniqueID: bad == "unique" ? valid.daemon.uniqueID : child.uniqueID,
                pidVersion: child.pidVersion, auditToken: bad == "audit" ? valid.daemon.auditToken : child.auditToken)
            f.processes.principal = .init(daemon: valid.daemon, child: altered,
                incarnation: bad == "incarnation" ? "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" : valid.incarnation,
                controllerSPKI: bad == "key" ? Data() : valid.controllerSPKI)
            #expect(throws: (any Error).self) { try a.prepare(f.request(), peer: f.peer) }
            #expect(f.journal.writes == 1)
        }
    }
    @Test func malformedCheckpointPrincipalAndHighWaterRefuseReload() throws {
        for committed in [false, true] {
            let f = try Fixture(), a = try f.registered(), request = try f.request()
            try a.prepare(request, peer: f.peer)
            if committed { _ = try a.complete(request, peer: f.peer) }
            let bytes = try #require(f.journal.bytes)
            for (key, bad): (String, Any) in [("incarnation", "not-a-uuid"), ("controllerSPKI", ""),
                                             ("incarnation", NSNull()), ("controllerSPKI", NSNull()),
                                             ("incarnation", "missing"), ("controllerSPKI", "missing")] {
                var root = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
                var stores = try #require(root["stores"] as? [String: [String: Any]])
                var store = try #require(stores[f.origin.wire.binding.store])
                let slot = committed ? "latest" : "pending"
                var intent = try #require(store[slot] as? [String: Any])
                var principal = try #require(intent["principal"] as? [String: Any])
                if bad as? String == "missing" { principal.removeValue(forKey: key) }
                else { principal[key] = bad }
                intent["principal"] = principal; store[slot] = intent
                stores[f.origin.wire.binding.store] = store; root["stores"] = stores
                f.journal.bytes = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys, .withoutEscapingSlashes])
                #expect(throws: (any Error).self) { try f.authority() }
            }
            f.journal.bytes = Data(String(decoding: bytes, as: UTF8.self)
                .replacingOccurrences(of: "\"allocatedEpoch\":2", with: "\"allocatedEpoch\":1").utf8)
            #expect(throws: (any Error).self) { try f.authority() }
        }
    }
    @Test func supersessionRechecksAbandonedAndCommittedOwnersAfterFence() throws {
        for pid: Int32 in [10, 11, 20, 21] {
            let f = try Fixture(), a = try f.registered(), first = try f.request()
            try a.prepare(first, peer: f.peer); f.processes.principal = principal(30)
            let next = try f.request(epoch: 2, superseded: first.fenceIdentity)
            try a.prepare(next, peer: f.peer)
            f.processes.beforeFence = { f.processes.lives[pid] = .unknown }
            #expect(throws: (any Error).self) { try a.complete(next, peer: f.peer) }
            #expect(f.journal.writes == 3 && f.processes.shimEpoch == 3)
            f.processes.beforeFence = {}; f.processes.lives[pid] = .exited
            let reloaded = try f.authority()
            #expect(try reloaded.complete(next, peer: f.peer) == 3)
            f.processes.principal = principal(40)
            let following = try f.request(epoch: 3)
            try reloaded.prepare(following, peer: f.peer)
            #expect(try reloaded.complete(following, peer: f.peer) == 4)
        }
    }
    @Test func sameBackingWithDifferentSizeAndDistinctRootStillAliases() throws {
        let f = try Fixture(), a = try f.registered(), b = try f.origin.wire.binding.value()
        let alias = try StorageIdentity.StoreBinding(storeID: .init(UUID().uuidString.lowercased()),
            root: .init(volumeUUID: b.root.volumeUUID, inode: 500),
            backing: .init(identity: b.backing.identity, size: 8192), expectedExt4UUID: b.expectedExt4UUID)
        let origin = try StorageLifecycleShimOrigin(wire: .init(binding: .init(alias), rootPublicKey: f.journal.root,
            shimLaunchUUID: f.origin.wire.shimLaunchUUID, specSHA256: f.origin.wire.specSHA256),
            shim: f.origin.shim, originalDaemon: f.origin.originalDaemon, originalController: f.origin.originalController)
        do {
            try a.recordOrigin(origin, rootFD: -1, backingFD: -1)
            Issue.record("physical backing alias accepted")
        } catch let failure as BootstrapFailure { #expect(failure.code == .conflict) }
        #expect(f.journal.writes == 1)
        let request = try f.request()
        try a.prepare(request, peer: f.peer)
        #expect(try a.complete(request, peer: f.peer) == 2) // Alias conflict did not poison state.
    }
    @Test func committedRetryStillRequiresLiveShimAndFreshChallenge() throws {
        let f = try Fixture(), a = try f.registered(), request = try f.request()
        try a.prepare(request, peer: f.peer); _ = try a.complete(request, peer: f.peer)
        f.processes.acknowledge = false
        #expect(throws: (any Error).self) { try a.complete(request, peer: f.peer) }
        #expect(f.processes.challenges.count == 2)
        #expect(f.processes.challenges[0].nonce != f.processes.challenges[1].nonce)
        f.processes.shimAlive = false
        #expect(throws: (any Error).self) { try a.complete(request, peer: f.peer) }
    }
    @Test func nativeRegisteredPinRejectsUnsignedClaimsWithoutRelaxingFreshPin() throws {
        let f = try Fixture()
        let verifier = StorageBootstrapProcesses(ownerUID: geteuid(), team: "ABCDEFGHIJ", policy: .production)
        #expect(throws: (any Error).self) {
            try verifier.registeredStorageShim(audit: f.peer, origin: f.origin.shim)
        }
    }
}
