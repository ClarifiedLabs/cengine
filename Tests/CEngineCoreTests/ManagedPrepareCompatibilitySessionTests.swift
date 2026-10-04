#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

@Suite(.serialized) struct ManagedPrepareCompatibilitySessionTests {
    typealias Carrier = ManagedPrepareCompatibilityProtocol
    typealias Wire = WorkloadStorageProtocol

    private func prepared(_ session: WorkloadSession) throws -> Carrier.Arm {
        try session.start()
        let attachment = session.configuration.slots[0].attachment
        let key = String(repeating: "e", count: 64)
        try session.exchange(.offerKeys, data: .init(role: .prepare), reply: .init(offers: [.init(attachment: attachment, key: key, csrDER: Data([1]))]))
        try session.exchange(.installCertificate, data: .init(attachment: attachment, certificateDER: Data([2])), reply: .init(attachment: attachment))
        return .init(version: 1, profile: Carrier.profile, requestID: workloadUUID(), caseName: "first-child-published",
            targetAttachment: attachment, binding: session.binding, scope: session.configuration.scope,
            mounts: session.configuration.mounts, slots: session.configuration.slots.sorted { $0.attachment < $1.attachment },
            credentials: [.init(attachment: attachment, key: key, certificateSHA256: Wire.specificationDigest(Data([2])))])
    }
    @Test func checkpointDoesNotWaitForSerialPrepareOrCancelOwner() throws {
        let session = try WorkloadSession(); defer { session.close() }
        let arm = try prepared(session)
        try session.exchange(.prepareCompatibilityArm, data: .init(compatibilityArm: arm), reply: .init(compatibilityDigest: Carrier.digest(arm)))
        try session.exchange(.mountPhase, data: .init(role: .prepare), reply: .init(attachmentIDs: [arm.targetAttachment]))
        var requested = session.command(); requested.kind = .prepare; requested.data = .init(workloadJSON: Data("{}".utf8), ioClaim: "")
        let command = requested, coordinator = session.coordinator
        let pending = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(command) }
        defer { pending.settle() }
        let sent = try session.pair.receive()
        #expect(sent.kind == .prepare)
        var wrong = arm; wrong.requestID = workloadUUID()
        #expect(throws: (any Error).self) { try coordinator.prepareObservation(wrong) }
        #expect(!coordinator.isTerminal)
        let observer = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.prepareObservation(arm) }
        defer { observer.settle() }
        func identity(_ inode: UInt64, _ type: UInt32) -> Carrier.ObjectIdentity {
            .init(inode: inode, generation: 1, fileType: type, handle: String(format: "%02x00000001000000", inode))
        }
        let observation = Carrier.Observation(version: 1, profile: Carrier.profile, requestID: arm.requestID,
            armDigest: try Carrier.digest(arm), stage: "first-child-published", count: 1, targetAttachment: arm.targetAttachment,
            copyIntent: workloadUUID(), filesystemUUID: String(repeating: "ab", count: 16), manifestDigest: String(repeating: "cd", count: 32),
            manifestSize: 512, sourceAtimes: .init(root: 0, a: 1, z: UInt64(Int64.max)), root: identity(2, 16384), transaction: identity(3, 16384), published: identity(4, 32768), staged: identity(5, 32768))
        let event = Wire.Frame(operation: .prepareCheckpoint, binding: arm.binding, scope: arm.scope,
            data: .init(compatibilityObservation: observation))
        try session.pair.send(event)
        #expect(try observer.result() == event)
        #expect(!pending.finishedWithin(0))
        #expect(!coordinator.isTerminal)
        #expect(throws: (any Error).self) { try coordinator.prepareObservation(arm) }
        // Only explicit owner teardown settles the pending PREPARE.
        coordinator.cancel()
        #expect(throws: (any Error).self) { try pending.result() }
    }
    private func checkpoint(_ arm: Carrier.Arm) throws -> Wire.Frame {
        func identity(_ inode: UInt64, _ kind: UInt32) -> Carrier.ObjectIdentity {
            .init(inode: inode, generation: 1, fileType: kind, handle: String(format: "%02x00000001000000", inode))
        }
        let observation = Carrier.Observation(version: 1, profile: Carrier.profile, requestID: arm.requestID,
            armDigest: try Carrier.digest(arm), stage: "first-child-published", count: 1, targetAttachment: arm.targetAttachment,
            copyIntent: workloadUUID(), filesystemUUID: String(repeating: "ab", count: 16), manifestDigest: String(repeating: "cd", count: 32),
            manifestSize: 512, sourceAtimes: .init(root: 0, a: 1, z: UInt64(Int64.max)),
            root: identity(2, 16384), transaction: identity(3, 16384), published: identity(4, 32768), staged: identity(5, 32768))
        return .init(operation: .prepareCheckpoint, binding: arm.binding, scope: arm.scope, data: .init(compatibilityObservation: observation))
    }
    private func normalArm(_ session: WorkloadSession) throws -> Carrier.Arm {
        var arm = try prepared(session); arm.caseName = "normal"
        try session.exchange(.prepareCompatibilityArm, data: .init(compatibilityArm: arm), reply: .init(compatibilityDigest: Carrier.digest(arm)))
        try session.exchange(.mountPhase, data: .init(role: .prepare), reply: .init(attachmentIDs: [arm.targetAttachment]))
        return arm
    }
    private func successfulPrepare(_ sent: Wire.Frame) -> Wire.Frame {
        let scope = sent.scope!
        return .init(operation: .reply, binding: sent.binding, scope: scope, sequence: sent.sequence, kind: .prepare,
            data: .init(prepare: scope.prepare, containerInstance: scope.containerInstance, launch: scope.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "f", count: 64)))
    }
    @Test(arguments: ["pending", "prepared"])
    func normalCheckpointHasNoHoldAndSurvivesPrepareReply(observerPhase: String) throws {
        let session = try WorkloadSession(); defer { session.close() }
        let arm = try normalArm(session), coordinator = session.coordinator, event = try checkpoint(arm)
        var requested = session.command(); requested.kind = .prepare; requested.data = .init(workloadJSON: Data("{}".utf8), ioClaim: "")
        let command = requested
        let pending = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(command) }
        defer { pending.settle() }
        let sent = try session.pair.receive(), reply = successfulPrepare(sent)
        if observerPhase == "pending" {
            let observer = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.prepareObservation(arm) }
            defer { observer.settle() }
            try session.pair.send(event)
            #expect(try observer.result() == event)
            #expect(!pending.finishedWithin(0))
            try session.pair.send(reply)
            #expect(try pending.result() == reply)
        } else {
            // One coalesced write deterministically orders event before reply,
            // without scheduling the observer until PREPARE is already complete.
            try session.pair.sendBytes(Wire.encode(event) + Wire.encode(reply))
            #expect(try pending.result() == reply)
            let observer = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.prepareObservation(arm) }
            defer { observer.settle() }
            #expect(try observer.result() == event)
        }
        #expect(!coordinator.isTerminal)
        #expect(throws: (any Error).self) { try coordinator.prepareObservation(arm) }
        #expect(!coordinator.isTerminal)
        try session.exchange(.closePhase, data: .init(role: .prepare),
            reply: .init(role: .prepare, attachmentIDs: [arm.targetAttachment], clean: true))
        let runtime = session.configuration.slots[1].attachment
        try session.exchange(.offerKeys, data: .init(role: .runtime),
            reply: .init(offers: [.init(attachment: runtime, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        #expect(!coordinator.isTerminal)
    }
    @Test(arguments: ["missing-event", "missing-atimes", "malformed-atimes", "overflow", "unknown", "replay", "unsolicited"])
    func normalCheckpointCannotArriveLateOrReplayOrSkipAtimes(fault: String) throws {
        let session = try WorkloadSession(); defer { session.close() }
        let arm = try normalArm(session), coordinator = session.coordinator, event = try checkpoint(arm)
        if fault == "unsolicited" {
            try session.pair.send(event)
            #expect(session.terminalSignal.wait(timeout: .now() + 5) == .success)
            #expect(coordinator.isTerminal)
            return
        }
        var requested = session.command(); requested.kind = .prepare; requested.data = .init(workloadJSON: Data("{}".utf8), ioClaim: "")
        let command = requested
        let pending = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(command) }
        defer { pending.settle() }
        let sent = try session.pair.receive()
        if fault == "missing-event" {
            // A late first event cannot repair success published ahead of it.
            try session.pair.sendBytes(Wire.encode(successfulPrepare(sent)) + Wire.encode(event))
        } else if fault == "replay" {
            let observer = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.prepareObservation(arm) }
            defer { observer.settle() }
            try session.pair.send(event)
            #expect(try observer.result() == event)
            try session.pair.send(event)
        } else {
            var text = String(decoding: try Data(Wire.encode(event).dropFirst(4)), as: UTF8.self)
            let atimes = #"{"a":1,"root":0,"z":9223372036854775807}"#
            switch fault {
            case "missing-atimes": text = text.replacingOccurrences(of: "\"sourceAtimes\":" + atimes + ",", with: "")
            case "malformed-atimes": text = text.replacingOccurrences(of: atimes, with: "null")
            case "overflow": text = text.replacingOccurrences(of: atimes, with: #"{"a":1,"root":9223372036854775808,"z":1}"#)
            default: text = text.replacingOccurrences(of: atimes, with: #"{"a":1,"extra":1,"root":0,"z":1}"#)
            }
            let data = Data(text.utf8); var length = UInt32(data.count).bigEndian
            try session.pair.sendBytes(Data(bytes: &length, count: 4) + data)
        }
        #expect(throws: (any Error).self) { try pending.result() }
        #expect(session.terminalSignal.wait(timeout: .now() + 5) == .success)
        #expect(coordinator.isTerminal)
    }
    @Test(arguments: ["profile", "leaf", "key", "runtime", "scope", "mount", "boot", "rearm"])
    func invalidArmIsTerminalWithoutGuestSideEffects(fault: String) throws {
        let session = try WorkloadSession(profile: fault == "profile" ? nil : Carrier.profile)
        defer { session.close() }
        var arm = try prepared(session)
        switch fault {
        case "leaf": arm.credentials[0].certificateSHA256 = String(repeating: "f", count: 64)
        case "key": arm.credentials[0].key = String(repeating: "f", count: 64)
        case "runtime": arm.credentials[0].attachment = session.configuration.slots[1].attachment
        case "scope": arm.scope.controllerEpoch += 1
        case "mount": arm.mounts[0].destination = "/other"
        case "boot": arm.binding.guestBootNonce = workloadUUID()
        case "rearm": try session.exchange(.prepareCompatibilityArm, data: .init(compatibilityArm: arm), reply: .init(compatibilityDigest: Carrier.digest(arm)))
        default: break
        }
        var command = session.command(); command.kind = .prepareCompatibilityArm; command.data = .init(compatibilityArm: arm)
        #expect(throws: (any Error).self) { try session.coordinator.command(command) }
        #expect(session.coordinator.isTerminal)
        session.pair.expectNoBytes()
    }
}
private func workloadUUID() -> String { UUID().uuidString.lowercased() }
private enum WorkloadTestFailure: Error { case timeout, transport, fixture }

/// Dedicated OS threads, not shared-dispatch work or blocking cooperative Tasks.
/// Every owner defers settle before closing FDs; a watchdog is only a safety net.
private final class WorkloadWorker<Value: Sendable>: @unchecked Sendable {
    private struct State {
        var result: Result<Value, any Error>?
        var expired = false
    }
    private final class SharedState: Sendable {
        let value = Mutex(State())
    }
    private let state: SharedState
    private let finished: DispatchGroup
    private let watchdogFinished: DispatchGroup
    private let cancel: @Sendable () -> Void

    init(cancel: @escaping @Sendable () -> Void, operation: @escaping @Sendable () throws -> Value) {
        self.cancel = cancel
        let state = SharedState(), finished = DispatchGroup(), watchdogFinished = DispatchGroup()
        self.state = state; self.finished = finished; self.watchdogFinished = watchdogFinished
        finished.enter()
        watchdogFinished.enter()
        Thread.detachNewThread {
            defer { watchdogFinished.leave() }
            guard finished.wait(timeout: .now() + 15) == .timedOut else { return }
            let shouldCancel = state.value.withLock {
                guard $0.result == nil else { return false }
                $0.expired = true
                return true
            }
            if shouldCancel { cancel() }
        }
        Thread.detachNewThread {
            let result = Result { try operation() }
            state.value.withLock { $0.result = result }
            finished.leave()
        }
    }

    func finishedWithin(_ seconds: Double) -> Bool { finished.wait(timeout: .now() + seconds) == .success }

    func outcome() throws -> Result<Value, any Error> {
        guard finishedWithin(15) else { cancel(); throw WorkloadTestFailure.timeout }
        #expect(!state.value.withLock { $0.expired }, "watchdog cancellation is not evidence of transport rejection")
        return try #require(state.value.withLock { $0.result })
    }

    func result() throws -> Value { try outcome().get() }

    func settle() {
        if !finishedWithin(0) { cancel() }
        // Join the watchdog too: an already-running cancellation closure must
        // never touch descriptor numbers after test cleanup has reused them.
        precondition(finishedWithin(15), "private workload worker did not settle before descriptor cleanup")
        precondition(watchdogFinished.wait(timeout: .now() + 15) == .success,
            "private workload watchdog did not settle before descriptor cleanup")
    }
}

private final class WorkloadSocketPair: @unchecked Sendable {
    let host: FileHandle
    let guest: FileHandle

    init() throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw WorkloadTestFailure.transport }
        host = FileHandle(fileDescriptor: pair[0], closeOnDealloc: true)
        guest = FileHandle(fileDescriptor: pair[1], closeOnDealloc: true)
        var enabled: Int32 = 1
        for descriptor in pair {
            guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw WorkloadTestFailure.transport }
        }
    }

    func close() { try? host.close(); try? guest.close() }
    func interrupt() { _ = shutdown(guest.fileDescriptor, SHUT_RDWR) }
    func endWrites() throws {
        guard shutdown(guest.fileDescriptor, SHUT_WR) == 0 else { throw WorkloadTestFailure.transport }
    }
    func send(_ frame: WorkloadStorageProtocol.Frame) throws { try sendBytes(WorkloadStorageProtocol.encode(frame)) }
    func sendUnchecked<T: Encodable>(_ value: T) throws { try sendBody(JSONEncoder().encode(value)) }
    func sendBody(_ body: Data) throws {
        var count = UInt32(body.count).bigEndian
        try sendBytes(Data(bytes: &count, count: 4) + body)
    }
    func sendBytes(_ data: Data) throws {
        let deadline = ContinuousClock.now + .seconds(10)
        var offset = 0
        while offset < data.count {
            try wait(Int16(POLLOUT), deadline: deadline)
            let count = data.withUnsafeBytes {
                Darwin.send(guest.fileDescriptor, $0.baseAddress!.advanced(by: offset), data.count - offset, MSG_DONTWAIT)
            }
            if count < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard count > 0 else { throw WorkloadTestFailure.transport }
            offset += count
        }
    }
    func readExactly(_ count: Int) throws -> Data {
        let deadline = ContinuousClock.now + .seconds(10)
        var data = Data(count: count), offset = 0
        while offset < count {
            try wait(Int16(POLLIN), deadline: deadline)
            let amount = data.withUnsafeMutableBytes {
                recv(guest.fileDescriptor, $0.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT)
            }
            if amount < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            if amount == 0 && offset == 0 { return Data() }
            guard amount > 0 else { throw WorkloadTestFailure.transport }
            offset += amount
        }
        return data
    }
    func readBody() throws -> Data {
        let prefix = try readExactly(4)
        guard prefix.count == 4 else { throw WorkloadTestFailure.transport }
        let count = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= UInt32(WorkloadStorageProtocol.maxFrame) else { throw WorkloadTestFailure.transport }
        let body = try readExactly(Int(count))
        guard body.count == Int(count) else { throw WorkloadTestFailure.transport }
        return body
    }
    func receive() throws -> WorkloadStorageProtocol.Frame { try WorkloadStorageProtocol.decode(from: readBody()) }
    func expectNoBytes() {
        var byte: UInt8 = 0
        let amount = recv(guest.fileDescriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        #expect(amount == -1 && errno == EAGAIN)
    }
    private func wait(_ events: Int16, deadline: ContinuousClock.Instant) throws {
        while ContinuousClock.now < deadline {
            var item = pollfd(fd: guest.fileDescriptor, events: events, revents: 0)
            let result = poll(&item, 1, 100)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw WorkloadTestFailure.transport }
            if result == 0 { continue }
            guard item.revents & events != 0 else { throw WorkloadTestFailure.transport }
            return
        }
        throw WorkloadTestFailure.timeout
    }
}

private struct WorkloadBootFixture: Sendable {
    let root: URL
    let disk: VMShimHeldDisk
    let specification: VMShimProtocol.Specification
    let rootUUID: String
    let nonce = workloadUUID()

    init() throws {
        root = FileManager.default.temporaryDirectory.appending(path: "cengine-private-workload-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let directory = try PersistentStateDirectory.open(root)
        guard case .created(let created) = try RawDiskInitialization.createNewDisk(in: directory, named: "root.ext4", size: 16 << 20) else {
            throw WorkloadTestFailure.fixture
        }
        rootUUID = created.record.ext4UUID
        let opened = try directory.openRegularFile(named: "root.ext4", access: .readWrite)
        guard flock(opened.handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw WorkloadTestFailure.fixture }
        disk = .init(ordinal: 0, role: "container-root", volumeName: nil, parent: directory, name: "root.ext4",
            handle: opened.handle, identity: opened.identity, bytes: 16 << 20)
        specification = .init(containerID: String(repeating: "a", count: 64), generation: 1, token: "unused",
            kernelPath: "/unused", initialRamdiskPath: "/unused", rootDiskPath: root.appending(path: "root.ext4").path,
            rootDiskIdentity: .init(device: opened.identity.device, inode: opened.identity.inode, volumeUUID: opened.identity.volumeUUID),
            rootDiskSize: disk.bytes, cpus: 1, memoryBytes: 1 << 30, macAddress: "02:00:00:00:00:01",
            socketPath: "/unused", logPath: "/unused", shimLaunchUUID: workloadUUID(), diskBootstrapVersion: 1,
            expectedInitramfsSHA256: String(repeating: "b", count: 64), workloadStorageMode: .managed)
    }

    var binding: WorkloadStorageProtocol.BootBinding {
        .init(shimLaunchUUID: specification.shimLaunchUUID!, guestBootNonce: nonce)
    }

    func committedProof(beforeCommit: (@Sendable (RawDiskBootTransaction) throws -> Void)? = nil) throws -> RawDiskBootTransaction.VerifiedContainerBoot {
        let pair = try WorkloadSocketPair()
        defer { pair.close() }
        let owner = Mutex<RawDiskBootTransaction?>(nil)
        let transaction = try RawDiskBootTransaction(specification: specification, disks: [disk], hook: { boundary in
            if boundary == .beforeCommit {
                let current = try #require(owner.withLock { $0 })
                #expect(throws: (any Error).self) { _ = try current.verifiedContainerBoot() }
                try beforeCommit?(current)
            }
        })
        owner.withLock { $0 = transaction }
        defer { owner.withLock { $0 = nil } }
        #expect(throws: (any Error).self) { _ = try transaction.verifiedContainerBoot() }
        let cancelled = Mutex(false)
        let worker = WorkloadWorker(cancel: { cancelled.withLock { $0 = true }; pair.interrupt() }) {
            try transaction.run(descriptor: pair.host.fileDescriptor, isCancelled: { cancelled.withLock { $0 } })
        }
        defer { worker.settle() }
        let hello = DiskInitializationProtocol.Hello(kind: "container", guestBootNonce: nonce,
            disks: [.init(ordinal: 0, blockIdentifier: disk.blockIdentifier, bytes: disk.bytes)])
        try pair.sendBytes(DiskInitializationProtocol.encode(hello))
        let manifest = try DiskInitializationProtocol.decode(DiskInitializationProtocol.Manifest.self, from: pair.readBody())
        #expect(manifest.shimLaunchUUID == specification.shimLaunchUUID)
        #expect(manifest.guestBootNonce == nonce)
        let synced = DiskInitializationProtocol.Synced(shimLaunchUUID: manifest.shimLaunchUUID, guestBootNonce: manifest.guestBootNonce,
            disks: manifest.disks.map { .init(ordinal: $0.ordinal, bytes: $0.expectedBytes, ext4UUID: $0.ext4UUID!, operationUUID: $0.operationUUID) })
        try pair.sendBytes(DiskInitializationProtocol.encode(synced))
        let commit = try DiskInitializationProtocol.decode(DiskInitializationProtocol.Commit.self, from: pair.readBody())
        #expect(commit.shimLaunchUUID == manifest.shimLaunchUUID)
        #expect(commit.guestBootNonce == nonce)
        try worker.result()
        return try transaction.verifiedContainerBoot()
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
}

private final class WorkloadCallbackState: Sendable {
    let counts = Mutex((terminal: 0, closed: 0))
}

private final class WorkloadSession: @unchecked Sendable {
    let fixture: WorkloadBootFixture
    let profile: String?
    let pair: WorkloadSocketPair
    let coordinator: PrivateWorkloadStorageCoordinator
    let configuration: WorkloadStorageConfiguration
    let terminalSignal: DispatchSemaphore
    let callbacks: WorkloadCallbackState
    var binding: WorkloadStorageProtocol.BootBinding { fixture.binding }

    init(profile: String? = ManagedPrepareCompatibilityProtocol.profile, sendBuffer: Int32? = nil,
         diagnosticHook: @escaping @Sendable (PrivateWorkloadStorageCoordinator.DiagnosticBoundary) -> Void = { _ in }) throws {
        let fixture = try WorkloadBootFixture()
        var initialized = false
        defer { if !initialized { fixture.remove() } }
        let pair = try WorkloadSocketPair()
        defer { if !initialized { pair.close() } }
        if var sendBuffer {
            try #require(setsockopt(pair.host.fileDescriptor, SOL_SOCKET, SO_SNDBUF, &sendBuffer,
                socklen_t(MemoryLayout<Int32>.size)) == 0)
        }
        let proof = try fixture.committedProof()
        let signal = DispatchSemaphore(value: 0), counts = WorkloadCallbackState()
        let coordinator = try PrivateWorkloadStorageCoordinator(verified: proof, descriptor: pair.host.fileDescriptor, compatibilityProfile: profile,
            closeConnection: { counts.counts.withLock { $0.closed += 1 } },
            onTerminal: { counts.counts.withLock { $0.terminal += 1 }; signal.signal() }, diagnosticHook: diagnosticHook)
        defer { if !initialized { coordinator.close() } }
        // The real coordinator must retain an independent owned descriptor.
        try pair.host.close()
        let volume = workloadUUID()
        let configuration = WorkloadStorageConfiguration(scope: .init(intent: workloadUUID(), store: workloadUUID(), serviceEpoch: workloadUUID(),
            controllerEpoch: 1, controllerKey: String(repeating: "c", count: 64), container: proof.containerID,
            containerInstance: workloadUUID(), launch: proof.shimLaunchUUID, prepare: workloadUUID(),
            specificationDigest: WorkloadStorageProtocol.specificationDigest(Data("{}".utf8))),
            peer: .init(tlsRootDER: Data([1]), serverDER: Data([2]), serverKey: String(repeating: "d", count: 64), dataAddress: "192.0.2.1"),
            mounts: [.init(index: 0, volume: volume, destination: "/data", subpath: "", mode: .readWrite, noCopy: false)],
            slots: [.init(volume: volume, attachment: workloadUUID(), role: .prepare, mode: .readWrite),
                    .init(volume: volume, attachment: workloadUUID(), role: .runtime, mode: .readWrite)])
        self.profile = profile
        self.fixture = fixture; self.pair = pair; self.coordinator = coordinator
        self.configuration = configuration; self.terminalSignal = signal; self.callbacks = counts
        initialized = true
    }

    func hello() throws {
        let coordinator = coordinator
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.hello() }
        defer { worker.settle() }
        try pair.send(.init(operation: .hello, binding: binding, data: .init(compatibilityProfile: profile)))
        _ = try worker.result()
    }
    func start() throws {
        try hello()
        let coordinator = coordinator, configuration = configuration
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.configure(configuration) }
        defer { worker.settle() }
        let request = try pair.receive()
        #expect(request.operation == .configure)
        #expect(request.scope == configuration.scope)
        try pair.send(configured())
        _ = try worker.result()
    }
    func startRunning() throws {
        try start()
        let prepareID = configuration.slots[0].attachment, runtimeID = configuration.slots[1].attachment
        try exchange(.offerKeys, data: .init(role: .prepare),
            reply: .init(offers: [.init(attachment: prepareID, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        try exchange(.installCertificate, data: .init(attachment: prepareID, certificateDER: Data([2])),
            reply: .init(attachment: prepareID))
        try exchange(.mountPhase, data: .init(role: .prepare), reply: .init(attachmentIDs: [prepareID]))
        let scope = configuration.scope
        try exchange(.prepare, data: .init(workloadJSON: Data("{}".utf8), ioClaim: "separate-private-claim"),
            reply: .init(prepare: scope.prepare, containerInstance: scope.containerInstance, launch: scope.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "f", count: 64)))
        try exchange(.closePhase, data: .init(role: .prepare), reply: .init(role: .prepare, attachmentIDs: [prepareID], clean: true))
        try exchange(.offerKeys, data: .init(role: .runtime),
            reply: .init(offers: [.init(attachment: runtimeID, key: String(repeating: "e", count: 64), csrDER: Data([1]))]))
        try exchange(.installCertificate, data: .init(attachment: runtimeID, certificateDER: Data([2])),
            reply: .init(attachment: runtimeID))
        try exchange(.mountPhase, data: .init(role: .runtime), reply: .init(attachmentIDs: [runtimeID]))
        try exchange(.start, data: .init(), reply: .init(status: "running", pid: 42))
    }
    func runningReply(to command: WorkloadStorageProtocol.Frame) -> WorkloadStorageProtocol.Frame {
        .init(operation: .reply, binding: binding, scope: configuration.scope, sequence: command.sequence, kind: .status,
            data: .init(phase: .running, mountedIDs: [configuration.slots[1].attachment], terminalIDs: []))
    }
    func configured() -> WorkloadStorageProtocol.Frame {
        .init(operation: .configured, binding: binding, scope: configuration.scope)
    }
    func command() -> WorkloadStorageProtocol.Frame {
        .init(operation: .command, binding: binding, scope: configuration.scope, sequence: 1, kind: .status)
    }
    func reply(to command: WorkloadStorageProtocol.Frame) -> WorkloadStorageProtocol.Frame {
        .init(operation: .reply, binding: binding, scope: configuration.scope, sequence: command.sequence, kind: .status,
            data: .init(phase: .configured, mountedIDs: [], terminalIDs: []))
    }
    func exchange(_ kind: WorkloadStorageProtocol.Kind, data: WorkloadStorageProtocol.Payload,
                  reply: WorkloadStorageProtocol.Payload) throws {
        let coordinator = coordinator
        var command = command()
        command.kind = kind
        command.data = data
        let requested = command
        let worker = WorkloadWorker(cancel: { coordinator.cancel() }) { try coordinator.command(requested) }
        defer { worker.settle() }
        let received = try pair.receive()
        #expect(received.kind == kind)
        #expect(received.data == data)
        try pair.send(.init(operation: .reply, binding: binding, scope: configuration.scope,
            sequence: received.sequence, kind: kind, data: reply))
        #expect(try worker.result().data == reply)
    }
    func close() { coordinator.close(); pair.close(); fixture.remove() }
}
#endif
