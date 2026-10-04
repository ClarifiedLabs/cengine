#if os(macOS) && DEBUG
import CEngineCore
import CryptoKit
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

/// HOST v2 with real journals and pinned compatibility files, isolated child/ROOT
/// peers. This does not qualify native authentication or manufacture live permits.
@Suite(.serialized) @MainActor struct ManagedStorageLifecyclePublicReplayTests {
    typealias Base = ManagedStorageLifecycleOwnerTests
    typealias Owner = ManagedStorageLifecycleOwner
    typealias L = StorageLifecycleProtocol
    typealias C = ManagedStorageLifecycleCheckpoint
    typealias Q = ManagedPrepareCompatibilityQueue
    typealias Boot = StorageLifecycleServiceBootProtocol
    typealias Replay = StorageLifecycleChildProcess.PublicTakeoverReplayObservation

    @Test func c2ReplayRunsOnceBeforeLegitimateTakeoverAndRootCompletion() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        try await f.takeover()
        let state = try f.owner.snapshot()
        let begun = try f.read(Owner.PublicTakeoverBegun.self, "begun")
        let denied = try f.read(Replay.self, "denied")
        let confirmed = try f.read(Owner.PublicTakeoverConfirmed.self, "confirmed")
        #expect(begun.version == 2 && begun.requestID == f.capture.requestID)
        #expect(begun.old == f.old && begun.old.grant.operation == .takeover)
        #expect(begun.old.grant.expectedEpoch == 1 && begun.pending.grant.expectedEpoch == 2)
        #expect(begun.pending == f.recorder.state.withLock { $0.bound })
        #expect(begun.incarnationID == f.incarnation)
        #expect(denied.version == 1 && denied.error == "UNAUTHORIZED")
        #expect(denied.requestID == begun.requestID && denied.old == begun.old)
        #expect(denied.pending == begun.pending && denied.incarnationID == begun.incarnationID)
        #expect(try Data(contentsOf: f.artifact("denied")) == f.recorder.state.withLock { $0.reply })
        #expect(confirmed.version == 2 && confirmed.completion == state.current)
        #expect(confirmed.completion.original.signed == begun.pending)
        #expect(state.currentContext?.controllerEpoch == 3)
        #expect(state.pending == nil && state.pendingTakeover == nil)
        #expect(f.recorder.state.withLock { $0.requests.count } == 1)
        let events = f.peer.state.withLock { $0.workloadEvents }
        let replay = try #require(events.firstIndex(of: "public-replay"))
        let takeover = try #require(events.firstIndex(of: "child-takeover"))
        let root = try #require(events.firstIndex(of: "root"))
        #expect(replay < takeover && takeover < root)
        #expect(f.peer.state.withLock { $0.childTakeovers == 1 && $0.completions == 1 })
        #expect(!f.exists("attestation") && !f.exists("positive"))
        #expect(!FileManager.default.fileExists(atPath: f.captureURL.path))
        #expect(try Data(contentsOf: f.claimURL) == Self.canonical(f.capture))
        #expect(try f.queue.publicTakeoverCapture(store: f.capture.store, epoch: 2, serviceEpoch: f.capture.serviceEpoch) == nil)
        await #expect(throws: (any Error).self) { try await f.takeover() }
        #expect(f.recorder.state.withLock { $0.requests.count } == 1)
        await f.owner.close()
    }

    @Test(arguments: ["pending", "incarnation", "request", "old", "error", "io-loss", "changed-physical", "changed-capture", "timeout", "after-state"])
    func rejectsReplayBeforeLegitimateTakeover(_ fault: String) async throws {
        let f = try await Fixture(original: fault == "timeout" || fault == "after-state", fault: fault)
        defer { f.disk.remove() }
        await #expect(throws: (any Error).self) { try await f.takeover() }
        #expect(f.exists("begun") && !f.exists("confirmed"))
        #expect(!f.exists("resumed") && !f.exists("positive") && !f.exists("registry"))
        #expect(f.peer.state.withLock { $0.childTakeovers == 0 && $0.completions == 0 })
        #expect(!f.transport.base.commands.contains(.reconcileController))
        #expect(f.recorder.state.withLock { $0.requests.count } == (fault == "timeout" ? 0 : 1))
        if fault != "changed-physical" {
            let state = try C.decode(Data(contentsOf: f.stateURL))
            #expect(state.current?.original.signed == f.old && state.pending != nil)
        }
        if fault != "after-state" { #expect(!f.exists("denied")) }
        await f.owner.close()
    }

    @Test func rootCompletionLossNeverPublishesConfirmed() async throws {
        let f = try await Fixture(); defer { f.disk.remove() }
        f.peer.state.withLock { $0.failComplete = true }
        await #expect(throws: (any Error).self) { try await f.takeover() }
        #expect(f.exists("denied") && !f.exists("confirmed"))
        #expect(f.peer.state.withLock { $0.childTakeovers == 1 && $0.completions == 1 })
        let state = try C.decode(Data(contentsOf: f.stateURL))
        #expect(state.current?.original.signed == f.old && state.pending != nil)
        await f.owner.close()
    }

    @Test(arguments: ["complete", "trust", "live"])
    func changedCensusDuringRootCompletionCannotPublishConfirmed(_ phase: String) async throws {
        let f = try await Fixture(rootPause: phase); defer { f.disk.remove(); f.completionGate.release.signal() }
        let takeover = Task { try await f.takeover() }
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        while !f.completionGate.started.withLock({ $0 }) && ProcessInfo.processInfo.systemUptime < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        #expect(f.completionGate.started.withLock { $0 })
        // Mutate through the real journal so this is a valid new physical census,
        // not merely corrupt bytes rejected by the journal's existing health check.
        try #require(f.owner.isolatedTestIntents).requireReconciliation()
        f.completionGate.release.signal()
        await #expect(throws: (any Error).self) { try await takeover.value }
        #expect(f.exists("denied") && !f.exists("confirmed"))
        await f.owner.close()
    }

    @Test func c1CannotSelectPublicReplay() async throws {
        let f = try await Fixture(c2: false); defer { f.disk.remove() }
        #expect(f.old.grant.operation == .initialize)
        await #expect(throws: (any Error).self) { try await f.takeover() }
        #expect(f.recorder.state.withLock { $0.requests.isEmpty })
        #expect(f.peer.state.withLock { $0.takeoverIssues == 0 && $0.childTakeovers == 0 && $0.completions == 0 })
        #expect(!f.exists("begun") && !f.exists("confirmed"))
        #expect(try f.owner.snapshot().current?.original.signed == f.old)
        await f.owner.close()
    }

    @Test(arguments: [false, true])
    func ordinaryTakeoverWithoutCaptureIsUnchanged(_ queueEnabled: Bool) async throws {
        let f = try await Fixture(captureEnabled: false, queueEnabled: queueEnabled); defer { f.disk.remove() }
        try await f.takeover()
        #expect(try f.owner.snapshot().currentContext?.controllerEpoch == 3)
        #expect(f.recorder.state.withLock { $0.requests.isEmpty })
        #expect(f.peer.state.withLock { $0.childTakeovers == 1 && $0.completions == 1 })
        #expect(!f.exists("begun") && !f.exists("denied") && !f.exists("confirmed"))
        await f.owner.close()
    }

    @Test(arguments: [false, true])
    func originalAttestationDoesNotMintResumeAuthority(_ recoverFirst: Bool) async throws {
        let f = try await Fixture(original: true); defer { f.disk.remove() }
        try await f.takeover()
        let pair = try f.read(StorageServiceTypes.IsolationStatePair.self, "attestation")
        #expect(pair.before == pair.after)
        #expect(pair.before.request.requestID == f.capture.requestID)
        #expect(pair.before.request.operationUUID == f.capture.original?.operationUUID)
        #expect(pair.before.request.armDigest == f.capture.original?.armDigest)
        #expect(f.transport.isolation.frames.compactMap(\.command) == [.isolationState, .isolationState])
        #expect(Set(f.transport.isolation.deadlines).count == 1)
        #expect(f.exists("confirmed"))
        if recoverFirst {
            try await f.owner.recoverWorkload()
            let lifecycle = try f.owner.makeWorkloadCoordinator(names: SharedVolumeInitializationCoordinator())
            try await lifecycle.reconcileStartup()
            #expect(f.owner.hasRecoveryPermission)
            // Empty reconciliation is real but cannot mint an original's live-runtime permit.
        } else { #expect(!f.owner.hasRecoveryPermission) }
        await #expect(throws: (any Error).self) { try await f.owner.resumePublicTakeoverOriginal() }
        #expect(!f.exists("resumed") && !f.exists("positive") && !f.exists("registry"))
        #expect(f.recorder.state.withLock { $0.requests.count } == 1)
        await f.owner.close()
    }

    nonisolated static func canonical<T: Encodable>(_ value: T) throws -> Data {
        try ManagedPrepareCompatibilityProtocol.canonicalData(value)
    }

    nonisolated final class CompletionGate: @unchecked Sendable {
        let started = Mutex(false)
        let release = DispatchSemaphore(value: 0)
        func hold() throws {
            started.withLock { $0 = true }
            guard release.wait(timeout: .now() + 10) == .success else { throw URLError(.timedOut) }
        }
    }
    nonisolated final class Recorder: @unchecked Sendable {
        let state = Mutex(Recorded())
    }
    struct Recorded: Sendable {
        var bound: L.SignedGrant?
        var requests: [StorageLifecycleChildProcess.PublicTakeoverReplayRequest] = []
        var reply: Data?
    }
    struct Reply: Encodable {
        let version: UInt32 = 1
        let requestID: String
        let old: L.SignedGrant
        let pending: L.SignedGrant
        let incarnationID: String
        let error: String
    }

    @MainActor final class Fixture {
        let disk: Base.Disk
        let peer: Base.Peer
        let queue: Q
        let owner: Owner
        let old: L.SignedGrant
        let incarnation: String
        let capture: Q.PublicTakeoverCapture
        let transport: Transport
        let recorder: Recorder
        let completionGate = CompletionGate()
        var directory: URL { disk.url.appending(path: Q.directoryName) }
        var stateURL: URL { disk.url.appending(path: "managed-storage-owner/state.json") }
        var captureURL: URL { directory.appending(path: "public-takeover.capture.json") }
        var claimURL: URL { directory.appending(path: capture.requestID + ".public-takeover.capture.json") }
        func artifact(_ phase: String) -> URL { directory.appending(path: capture.requestID + ".public-takeover." + phase + ".json") }
        func exists(_ phase: String) -> Bool { FileManager.default.fileExists(atPath: artifact(phase).path) }
        func read<T: Decodable>(_ type: T.Type, _ phase: String) throws -> T {
            try JSONDecoder().decode(type, from: Data(contentsOf: artifact(phase)))
        }
        func takeover() async throws {
            try await owner.takeover(using: transport, current: ManagedStorageLifecycleRestartTests().current(peer, old.grant))
        }
        /// Returning from this scope drops C2 as well as explicitly closing it;
        /// C3 must not contend with C2's retained checkpoint/intents leases.
        static func baseline(_ disk: Base.Disk, _ peer: Base.Peer, c2: Bool) async throws -> L.SignedGrant {
            let restart = ManagedStorageLifecycleRestartTests()
            let fresh = try await restart.freshStore(disk, peer)
            if !c2 { return try peer.state.withLock { try #require($0.grants[fresh.id]) } }
            let owner = try restart.existing(disk, peer)
            try await owner.takeover(using: Base.Transport(peer: peer, root: disk.root), current: restart.current(peer, fresh))
            let old = try #require(owner.snapshot().current?.original.signed)
            await owner.close()
            return old
        }
        init(c2: Bool = true, original: Bool = false, fault: String = "", captureEnabled: Bool = true,
             queueEnabled: Bool = true, rootPause: String? = nil) async throws {
            let disk = try Base.Disk(), peer = try Base.Peer(disk.binding)
            self.disk = disk; self.peer = peer
            let old = try await Self.baseline(disk, peer, c2: c2)
            self.old = old
            peer.state.withLock { $0.workloadEvents = []; $0.childTakeovers = 0; $0.completions = 0; $0.takeoverIssues = 0 }
            queue = try Q(storeLock: CanonicalDataStoreLock(root: disk.url))
            let requestID = Base.id(), epoch: UInt64 = c2 ? 2 : 1, launch = Base.id()
            var capture = Q.PublicTakeoverCapture(version: "original-takeover-public.v1", requestID: requestID,
                store: disk.binding.storeID.rawValue, epoch: epoch, serviceEpoch: peer.serviceEpoch)
            if original {
                capture.original = .init(requestID: requestID, armDigest: String(repeating: "b", count: 64),
                    operationUUID: Base.id(), caseName: .sameEExistingData, generation: 1,
                    boot: .init(shimLaunchUUID: launch, guestBootNonce: Base.id()),
                    scope: .init(intent: Base.id(), store: capture.store, serviceEpoch: capture.serviceEpoch,
                        controllerEpoch: epoch, controllerKey: old.grant.newKey, container: String(repeating: "a", count: 64),
                        containerInstance: Base.id(), launch: launch, prepare: Base.id(), specificationDigest: String(repeating: "c", count: 64)),
                    targetAttachment: Base.id(), key: String(repeating: "d", count: 64), certificateSHA256: String(repeating: "e", count: 64))
            }
            self.capture = capture
            let directory = disk.url.appending(path: Q.directoryName)
            let captureURL = directory.appending(path: "public-takeover.capture.json")
            if captureEnabled {
                try ManagedStorageLifecyclePublicReplayTests.canonical(capture).write(to: captureURL)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: captureURL.path)
            }
            let incarnation = Base.id(); self.incarnation = incarnation
            let base = try peer.seam(child: Curve25519.Signing.PrivateKey(), childIncarnation: incarnation, expectedEpoch: epoch, daemon: 19)
            let recorder = Recorder(); self.recorder = recorder
            let stateURL = disk.url.appending(path: "managed-storage-owner/state.json")
            let claimURL = directory.appending(path: requestID + ".public-takeover.capture.json")
            let begunURL = directory.appending(path: requestID + ".public-takeover.begun.json")
            let deniedURL = directory.appending(path: requestID + ".public-takeover.denied.json")
            let gate = completionGate
            var seam = Owner.IsolatedTestSeam(preparation: base.preparation, recipient: base.recipient,
                rootRequest: { request, rootFD, backingFD in
                    let reply = try base.rootRequest(request, rootFD, backingFD)
                    if recorder.state.withLock({ !$0.requests.isEmpty }) {
                        let phase: String?
                        switch request.body {
                        case .complete: phase = "complete"
                        case .serviceBootTrust: phase = "trust"
                        case .serviceResult: phase = "live"
                        default: phase = nil
                        }
                        if let rootPause, phase == rootPause { try gate.hold() }
                    }
                    return reply
                }, childAction: { action in
                    if case .bind(let signed) = action { recorder.state.withLock { $0.bound = signed } }
                    if case .takeover = action, captureEnabled {
                        #expect(FileManager.default.fileExists(atPath: deniedURL.path))
                    }
                    guard case .publicTakeoverReplay(let request) = action else { return try base.childAction(action) }
                    #expect(!Thread.isMainThread)
                    recorder.state.withLock { $0.requests.append(request) }
                    peer.state.withLock { $0.workloadEvents.append("public-replay") }
                    let pending = try recorder.state.withLock { try #require($0.bound) }
                    let begun = try JSONDecoder().decode(Owner.PublicTakeoverBegun.self, from: Data(contentsOf: begunURL))
                    #expect(request.old == old && request.requestID == requestID)
                    #expect(begun.pending == pending && begun.incarnationID == incarnation)
                    #expect(peer.state.withLock { $0.childTakeovers == 0 && $0.completions == 0 })
                    if fault == "io-loss" { throw CocoaError(.fileReadUnknown) }
                    var returnedPending = pending
                    if fault == "pending" {
                        let g = pending.grant
                        let other = try L.Grant(operation: g.operation, id: Base.id(), identity: g.identity,
                            serial: g.serial, expectedEpoch: g.expectedEpoch, newKey: g.newKey)
                        returnedPending = try L.SignedGrant(grant: other, signature: peer.rootPrivate.signature(for: other.signingBytes))
                    }
                    let data = try L.encode(Reply(
                        requestID: fault == "request" ? Base.id() : request.requestID,
                        old: fault == "old" ? pending : request.old, pending: returnedPending,
                        incarnationID: fault == "incarnation" ? Base.id() : incarnation,
                        error: fault == "error" ? "BLOCKED" : "UNAUTHORIZED"))
                    recorder.state.withLock { $0.reply = data }
                    if fault == "changed-physical" { try Data("invalid".utf8).write(to: stateURL) }
                    if fault == "changed-capture" { try Data("{}".utf8).write(to: claimURL) }
                    return data
                })
            seam.publicTakeoverQueue = queueEnabled ? queue : nil
            seam.isolationCompatibilityIdentity = {}
            owner = try Owner(isolatedTestExisting: seam, root: disk.root, backingDescriptor: disk.backing, binding: disk.binding)
            transport = Transport(peer: peer, root: disk.root, fault: fault)
        }
    }

    @MainActor final class Transport: ManagedStorageLifecycleServiceTransport {
        let base: Base.Transport
        let isolation: ManagedStorageLifecycleIsolationTests.Transport
        let fault: String
        init(peer: Base.Peer, root: PersistentStateDirectory, fault: String) {
            base = Base.Transport(peer: peer, root: root)
            isolation = ManagedStorageLifecycleIsolationTests.Transport(base: base)
            self.fault = fault
        }
        nonisolated func cancel() { base.cancel() }
        func configure(_ value: Boot.Configuration) async throws -> ManagedStorageLifecycleServiceReady { try await base.configure(value) }
        func command(_ frame: Boot.Frame) async throws -> Boot.Frame { try await base.command(frame) }
        func command(_ frame: Boot.Frame, deadlineNanoseconds: UInt64?) async throws -> Boot.Frame {
            // Model transport timeout, not an elapsed 30-second native watchdog.
            if fault == "timeout" { throw URLError(.timedOut) }
            let reply = try await isolation.command(frame, deadlineNanoseconds: deadlineNanoseconds)
            if fault == "after-state" && isolation.frames.count == 2 {
                let proof = try #require(reply.isolationProof)
                var fields = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(proof)) as? [String: Any])
                fields["registrySHA256"] = String(repeating: "c", count: 64)
                let changed = try JSONDecoder().decode(Boot.IsolationProof.self, from: JSONSerialization.data(withJSONObject: fields))
                return .init(operation: .reply, binding: reply.binding, sequence: reply.sequence,
                    serviceEpoch: reply.serviceEpoch, workerUUID: reply.workerUUID, isolationProof: changed)
            }
            return reply
        }
        func connectLifecycle() async throws -> FileHandle { try await base.connectLifecycle() }
        func connectWorkload() async throws -> FileHandle { try await base.connectWorkload() }
        func connectAttachmentCSR() async throws -> FileHandle { try await base.connectAttachmentCSR() }
    }
}
#endif
