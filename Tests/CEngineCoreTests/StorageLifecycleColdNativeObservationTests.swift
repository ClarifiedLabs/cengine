#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing
@preconcurrency import XPC
@testable import CEngineRuntime

@Suite("Native cold observer retains one private boot session")
struct StorageLifecycleColdNativeObservationTests {
    private typealias O = StorageLifecycleColdObservationProtocol
    private typealias C = StorageLifecycleColdProtocol
    private typealias L = StorageLifecycleProtocol
    private typealias W = StorageLifecycleServiceBootProtocol
    private typealias S = StorageLifecycleColdShimProtocol

    private func observationChallenge(counter: UInt64 = 1, nonce: UInt8 = 3) throws -> S.ObservationChallenge {
        let f = try ColdContractFixture(), g = f.prepare.mountedGreeting, old = g.launch
        let launch = try C.Launch(shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: old.specSHA256,
            initramfsSHA256: old.initramfsSHA256, ext4UUID: old.ext4UUID, bytes: old.bytes)
        let greeting = try S.Greeting(channelID: g.channelID, daemonUniqueID: g.daemonUniqueID,
            rootPublicKey: g.rootPublicKey, binding: g.binding,
            bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID, guestBootNonce: g.bootBinding.guestBootNonce,
                ext4UUID: launch.ext4UUID, bytes: launch.bytes), launch: launch, heldBackingIdentity: g.heldBackingIdentity)
        let request = try O.Request(observationID: UUID().uuidString.lowercased(), subject: L.encode(f.prepared.signedOpen), observer: launch)
        return try S.ObservationChallenge(authorization: .init(request: request, signature: f.key.signature(for: request.signingBytes)),
            greeting: greeting, shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 20,
            daemonAudit: Data(repeating: 2, count: 32), daemonUniqueID: 10,
            counter: counter, nonce: Data(repeating: nonce, count: 32), expiresUnixMS: 40_000)
    }
    private func changed(_ c: S.ObservationChallenge, counter: UInt64, nonce: UInt8) throws -> S.ObservationChallenge {
        try .init(authorization: c.authorization, greeting: c.greeting, shimAudit: c.shimAudit,
            shimUniqueID: c.shimUniqueID, daemonAudit: c.daemonAudit, daemonUniqueID: c.daemonUniqueID,
            counter: counter, nonce: Data(repeating: nonce, count: 32), expiresUnixMS: c.expiresUnixMS)
    }

    @Test func observationReplayDoesNotClaimTakeoverAndNeverEvictsEvidence() throws {
        let first = try observationChallenge()
        var state = StorageLifecycleColdObservationClaimState()
        let takeover = StorageLifecycleColdClaimState()
        try state.accept(first, now: 10_000)
        try state.accept(first, now: 10_001)
        #expect(takeover.first == nil)
        #expect(throws: (any Error).self) { try state.accept(first, now: 40_000) }
        #expect(throws: (any Error).self) { try state.accept(changed(first, counter: 2, nonce: 3), now: 10_000) }
        #expect(throws: (any Error).self) { try state.accept(changed(first, counter: 1, nonce: 4), now: 10_000) }
        #expect(StorageLifecycleColdObservationClaimState.maximumChallenges == 128)
        var latest = first
        for n in 2...StorageLifecycleColdObservationClaimState.maximumChallenges {
            latest = try changed(first, counter: UInt64(n), nonce: UInt8(n + 3))
            try state.accept(latest, now: 10_000)
            try state.accept(latest, now: 10_001) // Lost replies never consume fresh-claim capacity.
        }
        try state.accept(latest, now: 10_002) // Exact retry still works at the bound.
        #expect(throws: (any Error).self) { try state.accept(first, now: 10_000) }
        #expect(throws: (any Error).self) { try state.accept(changed(first, counter: 129, nonce: 255), now: 10_000) }
        #expect(throws: (any Error).self) { try state.accept(observationChallenge(counter: 6, nonce: 10), now: 10_000) }
    }

    @Test func sevenObservationProofsAndLostReplyDoNotFreezeTheLaterMountedGrant() throws {
        let first = try observationChallenge(), subject = try first.authorization.request.subjectOpen().request
        var observations = StorageLifecycleColdObservationClaimState()
        var mounted = StorageLifecycleColdClaimState()
        // O1/O2 consume four proofs; prepare consumes another three.
        for counter in 1...7 {
            let challenge = try changed(first, counter: UInt64(counter), nonce: UInt8(counter + 2))
            try observations.accept(challenge, now: 10_000)
            if counter == 4 { try observations.accept(challenge, now: 10_001) } // Lost reply.
            #expect(mounted.first == nil)
        }
        let freshGrant = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(),
            identity: subject.takeover.grant.identity, serial: subject.takeover.grant.serial + 1,
            expectedEpoch: subject.predecessor.controllerEpoch, newKey: String(repeating: "9", count: 64))
        let challenge = try S.Challenge(greeting: first.greeting, prepareSHA256: String(repeating: "a", count: 64),
            unsignedGrant: freshGrant, signedOpenSHA256: String(repeating: "b", count: 64), baseEpoch: 3,
            shimAudit: first.shimAudit, shimUniqueID: first.shimUniqueID,
            daemonAudit: first.daemonAudit, daemonUniqueID: first.daemonUniqueID,
            counter: 1, nonce: first.nonce, expiresUnixMS: first.expiresUnixMS)
        try mounted.accept(challenge, now: 10_000) // Independent counter and nonce domain.
        #expect(mounted.first?.unsignedGrant == freshGrant)
        #expect(mounted.first?.unsignedGrant != subject.takeover.grant)
    }

    @Test func plausibleObservationDictionaryIsNotNativeROOTAuthority() throws {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-cold-observation-challenge")
        let bytes = try S.encode(observationChallenge())
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        #expect(throws: (any Error).self) { try StorageLifecycleColdShim.authenticateRoot(message, team: "TEAM") }
    }

    private struct Mounted: Sendable {
        let disk: ObservationDiskFixture
        let proof: RawDiskBootTransaction.VerifiedStorageDiskBoot
        let pair: BootSocketPair
        static func make() async throws -> Self {
            let disk = try ObservationDiskFixture(kind: .storage)
            do {
                let initialized = try await disk.storageProof()
                var superblock = [UInt8](repeating: 0, count: 120)
                superblock[56] = 0x53; superblock[57] = 0xef
                var uuid = try #require(UUID(uuidString: initialized.binding.ext4UUID)).uuid
                superblock.replaceSubrange(104..<120, with: withUnsafeBytes(of: &uuid) { Array($0) })
                try #require(pwrite(disk.disks[0].handle.fileDescriptor, superblock, superblock.count, 1024) == superblock.count)
                var specification = disk.specification
                specification.expectedInitramfsSHA256 = String(repeating: "a1", count: 32)
                let transaction = try RawDiskBootTransaction(specification: specification, disks: disk.disks, policy: .requireInitializedStorage)
                let port = try BootSocketPair()
                defer { port.close() }
                let cancelled = Mutex(false)
                let worker = StorageBootWorker(cancel: { cancelled.withLock { $0 = true } }) {
                    try transaction.run(descriptor: port.host.fileDescriptor, isCancelled: { cancelled.withLock { $0 } })
                }
                defer { worker.settle() }
                try port.send(disk.hello())
                let manifest = try port.manifest()
                try port.send(disk.synced(manifest)); _ = try port.commit()
                try await worker.result()
                return Self(disk: disk, proof: try transaction.verifiedStorageDiskBoot(), pair: try BootSocketPair())
            } catch { disk.remove(); throw error }
        }
        func close() { pair.close(); disk.remove() }
    }

    private func authorization(_ proof: RawDiskBootTransaction.VerifiedStorageDiskBoot,
                               material: ObservationCertificateFixture, wrongObserver: Bool = false) throws -> O.SignedRequest {
        let initial = material.configuration, old = material.ready, binding = proof.binding
        let predecessor = try C.Predecessor(currentGrant: initial.signed.grant, serviceEpoch: old.serviceEpoch,
            controllerEpoch: old.controllerEpoch, controllerKey: old.controllerKey, openRevision: old.openRevision,
            bootstrapKey: old.bootstrapKey)
        let grant = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: old.identity,
            serial: 2, expectedEpoch: predecessor.controllerEpoch, newKey: String(repeating: "8", count: 64))
        let signed = try L.SignedGrant(grant: grant, signature: material.bootstrap.signature(for: grant.signingBytes))
        let abandoned = try C.Launch(shimLaunchUUID: UUID().uuidString.lowercased(), specSHA256: proof.specificationSHA256,
            initramfsSHA256: proof.initramfsSHA256, ext4UUID: binding.ext4UUID, bytes: binding.bytes)
        let failed = try C.Request(operationID: grant.id, predecessor: predecessor, takeover: signed, launch: abandoned,
            nowUnixSeconds: initial.nowUnixSeconds, lifetimeSeconds: initial.lifetimeSeconds)
        let subject = try C.SignedOpen(request: failed, signature: material.bootstrap.signature(for: failed.signingBytes))
        let observer = try C.Launch(shimLaunchUUID: wrongObserver ? UUID().uuidString.lowercased() : binding.shimLaunchUUID,
            specSHA256: proof.specificationSHA256, initramfsSHA256: proof.initramfsSHA256, ext4UUID: binding.ext4UUID, bytes: binding.bytes)
        let request = try O.Request(observationID: UUID().uuidString.lowercased(), subject: L.encode(subject), observer: observer)
        return try .init(request: request, signature: material.bootstrap.signature(for: request.signingBytes))
    }

    @Test func oneHelloObservationThenFreshConfigureUsesExactStreamAndReleasesOnce() async throws {
        let f = try await Mounted.make(), material = try ObservationCertificateFixture()
        defer { f.close() }
        let auth = try authorization(f.proof, material: material), initial = material.configuration
        let root = try StorageIdentity.RootPublicKey(publicData: initial.rootPublicKey)
        let released = Mutex(0)
        let session = try PrivateStorageLifecycleBootCoordinator.ColdObservationSession(verified: f.proof, root: root,
            descriptor: f.pair.host.fileDescriptor, closeConnection: { released.withLock { $0 += 1 } })
        defer { session.close() }
        let readOnly = try O.Observation(requestSHA256: auth.request.digest, outcome: .unchanged,
            predecessor: auth.request.subjectOpen().request.predecessor)
        let worker = StorageBootWorker(cancel: { session.cancel() }) {
            try session.observe(auth, deadline: ProcessInfo.processInfo.systemUptime + 5)
        }
        defer { worker.settle() }
        try f.pair.guest.write(contentsOf: W.encode(.init(operation: .hello, binding: f.proof.binding)))
        let observedRequest = try read(f.pair.guest)
        #expect(observedRequest.operation == .observeCold)
        #expect(observedRequest.observationAuthorization == auth)
        #expect(observedRequest.observationRootPublicKey == root.publicData)
        var reply = W.Frame(operation: .coldObserved, binding: f.proof.binding)
        reply.coldObservation = readOnly
        try f.pair.guest.write(contentsOf: W.encode(reply))
        #expect(try await worker.result() == readOnly)
        // Four O1/O2 proofs plus three prepare proofs must all perform real
        // read-only exchanges. A lost native reply repeats the exchange too.
        for _ in 2...8 {
            let repeated = StorageBootWorker(cancel: { session.cancel() }) {
                try session.observe(auth, deadline: ProcessInfo.processInfo.systemUptime + 5)
            }
            defer { repeated.settle() }
            let freshRequest = try read(f.pair.guest)
            #expect(freshRequest.operation == .observeCold) // No reconnect/second hello.
            #expect(freshRequest.observationAuthorization == auth)
            #expect(freshRequest.observationRootPublicKey == root.publicData)
            try f.pair.guest.write(contentsOf: W.encode(reply))
            #expect(try await repeated.result() == readOnly)
        }

        let grant = try L.Grant(operation: .takeover, id: UUID().uuidString.lowercased(), identity: material.ready.identity,
            serial: 3, expectedEpoch: readOnly.predecessor.controllerEpoch,
            newKey: ObservationCertificateFixture.fingerprint(material.successor))
        let signed = try L.SignedGrant(grant: grant, signature: material.bootstrap.signature(for: grant.signingBytes))
        let request = try C.Request(operationID: grant.id, predecessor: readOnly.predecessor, takeover: signed,
            launch: auth.request.observer, nowUnixSeconds: initial.nowUnixSeconds, lifetimeSeconds: initial.lifetimeSeconds, observation: auth)
        let cold = try C.SignedOpen(request: request, signature: material.bootstrap.signature(for: request.signingBytes))
        let cfg = W.Configuration(action: .coldOpenTakeover, rootPublicKey: root.publicData, signed: signed,
            nowUnixSeconds: initial.nowUnixSeconds, lifetimeSeconds: initial.lifetimeSeconds, cold: cold)
        let coordinator = try PrivateStorageLifecycleBootCoordinator(verified: f.proof, configuration: cfg,
            descriptor: -1, observedSession: session)
        defer { coordinator.close() }
        session.close() // Transferred lease cannot close the coordinator's descriptor.
        #expect(released.withLock { $0 } == 0)
        let boot = StorageBootWorker(cancel: { coordinator.cancel() }) { try coordinator.bootstrap() }
        defer { boot.settle() }
        // No second hello is sent. Configure must arrive directly on this same pair.
        #expect(try read(f.pair.guest).configuration == cfg)
        let ready = try material.readyLike(material.ready, serviceEpoch: UUID().uuidString.lowercased(), root: .init(), server: .init(),
            controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey, revision: 2,
            openRevision: readOnly.predecessor.openRevision + 1)
        try f.pair.guest.write(contentsOf: W.encode(.init(operation: .ready, binding: f.proof.binding, ready: ready)))
        #expect(try await boot.result().ready == ready)
        coordinator.close(); coordinator.close(); session.close()
        #expect(released.withLock { $0 } == 1)
        #expect(throws: (any Error).self) {
            try PrivateStorageLifecycleBootCoordinator(verified: f.proof, configuration: cfg, descriptor: -1, observedSession: session)
        }
    }

    @Test(arguments: ["eof", "changed-result", "expired-deadline", "late-reply", "changed-authorization"])
    func repeatedObservationMustRemainLiveAndEqual(fault: String) async throws {
        let f = try await Mounted.make(), material = try ObservationCertificateFixture()
        defer { f.close() }
        let auth = try authorization(f.proof, material: material)
        let root = try StorageIdentity.RootPublicKey(publicData: material.configuration.rootPublicKey)
        let released = Mutex(0)
        let session = try PrivateStorageLifecycleBootCoordinator.ColdObservationSession(verified: f.proof, root: root,
            descriptor: f.pair.host.fileDescriptor, closeConnection: { released.withLock { $0 += 1 } })
        defer { session.close() }
        let unchanged = try O.Observation(requestSHA256: auth.request.digest, outcome: .unchanged,
            predecessor: auth.request.subjectOpen().request.predecessor)
        let first = StorageBootWorker(cancel: { session.cancel() }) {
            try session.observe(auth, deadline: ProcessInfo.processInfo.systemUptime + 5)
        }
        defer { first.settle() }
        try f.pair.guest.write(contentsOf: W.encode(.init(operation: .hello, binding: f.proof.binding)))
        #expect(try read(f.pair.guest).operation == .observeCold)
        var reply = W.Frame(operation: .coldObserved, binding: f.proof.binding)
        reply.coldObservation = unchanged
        try f.pair.guest.write(contentsOf: W.encode(reply))
        #expect(try await first.result() == unchanged)

        if fault == "expired-deadline" || fault == "changed-authorization" {
            let next = fault == "changed-authorization" ? try authorization(f.proof, material: material) : auth
            #expect(throws: (any Error).self) {
                try session.observe(next, deadline: ProcessInfo.processInfo.systemUptime + (fault == "expired-deadline" ? -1 : 5))
            }
        } else {
            let deadline = ProcessInfo.processInfo.systemUptime + (fault == "late-reply" ? 0.5 : 5)
            let repeated = StorageBootWorker(cancel: { session.cancel() }) { try session.observe(auth, deadline: deadline) }
            defer { repeated.settle() }
            #expect(try read(f.pair.guest).operation == .observeCold)
            if fault == "eof" {
                _ = Darwin.shutdown(f.pair.guest.fileDescriptor, SHUT_RDWR)
            } else if fault == "late-reply" {
                // Guest stays open but cannot reuse the earlier successful reply.
                try await Task.sleep(for: .milliseconds(600))
            } else {
                // A separately valid result for this authorization must still be
                // rejected when it differs from the retained authenticated proof.
                let subject = try auth.request.subjectOpen(), grant = subject.request.takeover.grant
                let changed = try C.Predecessor(currentGrant: grant, serviceEpoch: UUID().uuidString.lowercased(),
                    controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey,
                    openRevision: unchanged.predecessor.openRevision + 1, bootstrapKey: unchanged.predecessor.bootstrapKey)
                reply.coldObservation = try O.Observation(requestSHA256: auth.request.digest, outcome: .applied, predecessor: changed)
                try reply.coldObservation?.validate(for: auth.request)
                try f.pair.guest.write(contentsOf: W.encode(reply))
            }
            await #expect(throws: (any Error).self) { try await repeated.result() }
        }
        session.close(); session.close()
        #expect(released.withLock { $0 } == 1)
        #expect(throws: (any Error).self) { try session.observe(auth, deadline: ProcessInfo.processInfo.systemUptime + 5) }
    }

    @Test(arguments: ["root", "observer", "cancel", "timeout"])
    func observerFailureClosesOwnedStreamExactlyOnce(fault: String) async throws {
        let f = try await Mounted.make(), material = try ObservationCertificateFixture()
        defer { f.close() }
        let auth = try authorization(f.proof, material: material, wrongObserver: fault == "observer")
        let root = try StorageIdentity.RootPublicKey(publicData: fault == "root"
            ? Curve25519.Signing.PrivateKey().publicKey.rawRepresentation : material.configuration.rootPublicKey)
        let released = Mutex(0)
        let session = try PrivateStorageLifecycleBootCoordinator.ColdObservationSession(verified: f.proof, root: root,
            descriptor: f.pair.host.fileDescriptor, closeConnection: { released.withLock { $0 += 1 } })
        if fault == "cancel" { session.cancel() }
        #expect(throws: (any Error).self) {
            try session.observe(auth, deadline: ProcessInfo.processInfo.systemUptime + (fault == "timeout" ? -1 : 5))
        }
        session.close(); session.close()
        #expect(released.withLock { $0 } == 1)
    }

    @Test func bridgeRevocationCancelsPendingTaskAndUnblocksNativeWorker() async throws {
        let bridge = StorageLifecycleColdObservationBridge(), started = DispatchSemaphore(value: 0)
        let worker = StorageBootWorker<O.Observation>(cancel: { bridge.close() }) {
            try bridge.read {
                started.signal()
                try await Task.sleep(for: .seconds(30))
                throw CancellationError()
            }
        }
        defer { worker.settle() }
        let didStart = await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                continuation.resume(returning: started.wait(timeout: .now() + 2) == .success)
            }
        }
        #expect(didStart)
        bridge.close(); bridge.close()
        await #expect(throws: (any Error).self) { try await worker.result() }
        #expect(throws: (any Error).self) {
            try bridge.read { throw CancellationError() }
        }
    }

    private func read(_ handle: FileHandle) throws -> W.Frame {
        func exact(_ count: Int) throws -> Data {
            var bytes = Data()
            while bytes.count < count {
                var item = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
                guard Darwin.poll(&item, 1, 5_000) > 0 else { throw W.ValidationError.invalidFrame }
                guard let part = try handle.read(upToCount: count - bytes.count), !part.isEmpty else { throw W.ValidationError.invalidFrame }
                bytes.append(part)
            }
            return bytes
        }
        let count = try exact(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= W.maxFrame else { throw W.ValidationError.invalidFrame }
        return try W.decode(exact(Int(count)))
    }
}

/// A real 4105 mount capability; no test-only initializer mints native authority.
private struct ObservationDiskFixture: Sendable {
    let root: URL
    let disks: [VMShimHeldDisk]
    let specification: VMShimProtocol.Specification
    let nonce = UUID().uuidString.lowercased()
    init(kind: VMShimProtocol.Specification.Kind) throws {
        root = FileManager.default.temporaryDirectory.appending(path: "cengine-cold-observer-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let directory = try PersistentStateDirectory.open(root), name = "store.ext4"
        _ = try RawDiskInitialization.createNewDisk(in: directory, named: name, size: 32 << 20)
        let opened = try directory.openRegularFile(named: name, access: .readWrite)
        guard flock(opened.handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw POSIXError(.EIO) }
        disks = [.init(ordinal: 0, role: "storage-root", volumeName: nil, parent: directory, name: name,
            handle: opened.handle, identity: opened.identity, bytes: 32 << 20)]
        specification = .init(kind: kind, containerID: "test", generation: 1, token: "unused", kernelPath: "/unused",
            initialRamdiskPath: "/unused", rootDiskPath: root.appending(path: name).path,
            rootDiskIdentity: .init(device: opened.identity.device, inode: opened.identity.inode, volumeUUID: opened.identity.volumeUUID),
            rootDiskSize: 32 << 20, volumeDisks: [], cpus: 1, memoryBytes: 1 << 30,
            macAddress: "02:00:00:00:00:01", socketPath: "/unused", logPath: "/unused",
            shimLaunchUUID: UUID().uuidString.lowercased(), diskBootstrapVersion: 1,
            expectedInitramfsSHA256: String(repeating: "a1", count: 32))
    }
    func hello() -> DiskInitializationProtocol.Hello {
        .init(kind: "storage", guestBootNonce: nonce,
            disks: disks.map { .init(ordinal: $0.ordinal, blockIdentifier: $0.blockIdentifier, bytes: $0.bytes) })
    }
    func synced(_ manifest: DiskInitializationProtocol.Manifest) -> DiskInitializationProtocol.Synced {
        .init(shimLaunchUUID: manifest.shimLaunchUUID, guestBootNonce: manifest.guestBootNonce,
            disks: manifest.disks.map { .init(ordinal: $0.ordinal, bytes: $0.expectedBytes, ext4UUID: $0.ext4UUID!, operationUUID: $0.operationUUID) })
    }
    func storageProof() async throws -> RawDiskBootTransaction.VerifiedStorageDiskBoot {
        let pair = try BootSocketPair()
        defer { pair.close() }
        let transaction = try RawDiskBootTransaction(specification: specification, disks: disks)
        let cancelled = Mutex(false)
        let worker = StorageBootWorker(cancel: { cancelled.withLock { $0 = true } }) {
            try transaction.run(descriptor: pair.host.fileDescriptor, isCancelled: { cancelled.withLock { $0 } })
        }
        defer { worker.settle() }
        try pair.send(hello()); let manifest = try pair.manifest()
        try pair.send(synced(manifest)); _ = try pair.commit()
        try await worker.result()
        return try transaction.verifiedStorageDiskBoot()
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
}

/// Minimal Ed25519 certificates for the coordinator's real signature/pin checks.
private struct ObservationCertificateFixture {
    typealias Key = Curve25519.Signing.PrivateKey
    typealias W = StorageLifecycleServiceBootProtocol
    let bootstrap = Key(), root = Key(), server = Key(), controller = Key(), successor = Key()
    let configuration: W.Configuration
    let ready: W.Ready
    private static let algorithm = Data([0x30, 5, 6, 3, 0x2b, 0x65, 0x70])
    private static func der(_ tag: UInt8, _ body: Data) -> Data {
        let n = body.count
        let length: [UInt8] = n < 128 ? [UInt8(n)] : n < 256 ? [0x81, UInt8(n)] : [0x82, UInt8(n >> 8), UInt8(n & 255)]
        return Data([tag] + length) + body
    }
    static func fingerprint(_ key: Key) throws -> String {
        try StorageIdentity.Ed25519SPKI(rawPublicKey: key.publicKey.rawRepresentation).fingerprint.rawValue
    }
    private static func certificate(key: Key, issuer: Key) throws -> Data {
        let name = der(0x30, der(0x31, der(0x30, Data([6, 3, 0x55, 4, 3]) + der(0x0c, Data("test TLS CA".utf8)))))
        let validity = der(0x30, der(0x17, Data("270115080000Z".utf8)) + der(0x17, Data("270115090000Z".utf8)))
        let spki = try StorageIdentity.Ed25519SPKI(rawPublicKey: key.publicKey.rawRepresentation).publicData
        let constraints = der(0x30, Data([6, 3, 0x55, 0x1d, 0x13, 1, 1, 0xff])
            + der(4, der(0x30, Data([1, 1, 0xff, 2, 1, 0]))))
        let extensions = der(0xa3, der(0x30, constraints))
        let tbs = der(0x30, Data([0xa0, 3, 2, 1, 2, 2, 1, 1]) + algorithm + name + validity + name + spki + extensions)
        return try der(0x30, tbs + algorithm + der(3, Data([0]) + issuer.signature(for: tbs)))
    }
    func readyLike(_ r: W.Ready, serviceEpoch: String, root newRoot: Key, server newServer: Key,
                   controllerEpoch: UInt64, controllerKey: String, revision: UInt64, openRevision: UInt64) throws -> W.Ready {
        try .init(identity: r.identity, serviceEpoch: serviceEpoch, workerUUID: r.workerUUID,
            controllerEpoch: controllerEpoch, controllerKey: controllerKey, revision: revision, openRevision: openRevision,
            bootstrapKey: r.bootstrapKey, tlsRootDER: Self.certificate(key: newRoot, issuer: newRoot),
            serverDER: Self.certificate(key: newServer, issuer: newRoot), serverSPKI: Self.fingerprint(newServer))
    }
    init() throws {
        let identity = try StorageLifecycleProtocol.Identity(store: UUID().uuidString.lowercased(), generation: 1, binding: String(repeating: "a", count: 64))
        let grant = try StorageLifecycleProtocol.Grant(operation: .initialize, id: UUID().uuidString.lowercased(), identity: identity,
            serial: 1, expectedEpoch: 0, newKey: Self.fingerprint(controller))
        configuration = try .init(action: .initialize, rootPublicKey: bootstrap.publicKey.rawRepresentation,
            signed: .init(grant: grant, signature: bootstrap.signature(for: grant.signingBytes)), nowUnixSeconds: 1_800_000_000, lifetimeSeconds: 3600)
        ready = try .init(identity: identity, serviceEpoch: UUID().uuidString.lowercased(), workerUUID: UUID().uuidString.lowercased(),
            controllerEpoch: 1, controllerKey: Self.fingerprint(controller), revision: 1, openRevision: 1,
            bootstrapKey: Self.fingerprint(bootstrap), tlsRootDER: Self.certificate(key: root, issuer: root),
            serverDER: Self.certificate(key: server, issuer: root), serverSPKI: Self.fingerprint(server))
    }
}
#endif
