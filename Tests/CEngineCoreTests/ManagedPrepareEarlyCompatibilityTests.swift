#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

@Suite(.serialized) struct ManagedPrepareEarlyCompatibilityTests {
    typealias Carrier = ManagedPrepareCompatibilityProtocol
    typealias Wire = WorkloadStorageProtocol

    private func ready(_ session: EarlySession, caseName: String, mount: Bool = true) throws -> Carrier.Arm {
        try session.start()
        let attachment = session.configuration.slots[0].attachment
        let key = String(repeating: "e", count: 64)
        try session.exchange(.offerKeys, data: .init(role: .prepare), reply: .init(offers: [.init(attachment: attachment, key: key, csrDER: Data([1]))]))
        try session.exchange(.installCertificate, data: .init(attachment: attachment, certificateDER: Data([2])), reply: .init(attachment: attachment))
        let arm = Carrier.Arm(version: 2, profile: Carrier.earlyProfile, requestID: earlyUUID(), caseName: caseName,
            targetAttachment: attachment, binding: session.binding, scope: session.configuration.scope,
            mounts: session.configuration.mounts, slots: session.configuration.slots,
            credentials: [.init(attachment: attachment, key: key, certificateSHA256: Wire.specificationDigest(Data([2])))])
        try session.exchange(.prepareCompatibilityArm, data: .init(compatibilityArm: arm), reply: .init(compatibilityDigest: Carrier.digest(arm)))
        if mount { try session.exchange(.mountPhase, data: .init(role: .prepare), reply: .init(attachmentIDs: [attachment])) }
        return arm
    }
    private func prepare(_ session: EarlySession) -> Wire.Frame {
        var frame = session.command(); frame.kind = .prepare; frame.sequence = 9876
        frame.data = .init(workloadJSON: Data("{}".utf8), ioClaim: "current-private-claim")
        return frame
    }
    private func event(_ arm: Carrier.Arm, sequence: UInt64) throws -> Wire.Frame {
        let sent: UInt32 = arm.caseName == "before-prepare-send" ? 0 : 1
        let observation = Carrier.EarlyObservation(version: 2, profile: Carrier.earlyProfile, requestID: arm.requestID,
            armDigest: try Carrier.digest(arm), stage: arm.caseName, count: 1, targetAttachment: arm.targetAttachment,
            requestSequence: sequence, prepareCommandsSent: sent, prepareCommandsAccepted: sent,
            dataBytesWritten: arm.caseName == "data-partial-frame" ? 5 : 0)
        return .init(operation: .prepareEarlyCheckpoint, binding: arm.binding, scope: arm.scope,
            data: .init(compatibilityEarlyObservation: observation))
    }
    private func success(_ sent: Wire.Frame) -> Wire.Frame {
        let scope = sent.scope!
        return .init(operation: .reply, binding: sent.binding, scope: scope, sequence: sent.sequence, kind: .prepare,
            data: .init(prepare: scope.prepare, containerInstance: scope.containerInstance, launch: scope.launch,
                succeeded: true, cleanCopyUp: true, evidenceDigest: String(repeating: "f", count: 64)))
    }

    @Test(arguments: [false, true])
    func actualA1PublishesBeforeOwnCloseWithoutSendingAnyPrepareByte(observerFirst: Bool) throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: "before-prepare-send"), coordinator = session.coordinator
        let observer = observerFirst ? EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.prepareObservation(arm) } : nil
        defer { observer?.settle() }
        #expect(throws: (any Error).self) { try coordinator.command(prepare(session)) }
        #expect(session.terminalSignal.wait(timeout: .now() + 5) == .success)
        // EOF, not merely an empty nonblocking peek: A1 really closed its channel.
        #expect(try session.pair.readExactly(1).isEmpty)
        coordinator.close()
        let observed = try observer?.result() ?? coordinator.prepareObservation(arm)
        #expect(observed == (try event(arm, sequence: 5)))
        #expect(observed.data.compatibilityObservation == nil)
        #expect(coordinator.isTerminal)
        #expect(throws: (any Error).self) { try coordinator.prepareObservation(arm) }
        #expect(throws: (any Error).self) { try coordinator.command(prepare(session)) }
        #expect(session.callbacks.counts.withLock { $0.terminal == 1 && $0.closed == 1 })
    }

    @Test(arguments: ["mount", "digest", "missing-credentials"])
    func a1CannotCutBeforeRealValidation(fault: String) throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: "before-prepare-send", mount: fault != "mount")
        var requested = prepare(session)
        if fault == "digest" { requested.data.workloadJSON = Data("changed".utf8) }
        if fault == "missing-credentials" {
            var changed = arm; changed.credentials = []
            requested.kind = .prepareCompatibilityArm; requested.data = .init(compatibilityArm: changed)
        }
        #expect(throws: (any Error).self) { try session.coordinator.command(requested) }
        session.pair.expectNoBytes()
        session.coordinator.cancel()
        #expect(throws: (any Error).self) { try session.coordinator.prepareObservation(arm) }
    }

    @Test(arguments: ["guest-accepted-before-prepare", "data-partial-frame"])
    func guestEarlyEventSurvivesCoalescedTerminalAndLateObserver(caseName: String) throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: caseName), coordinator = session.coordinator
        let command = prepare(session)
        let pending = EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.command(command) }
        defer { pending.settle() }
        let sent = try session.pair.receive()
        #expect(sent.sequence == 5)
        let checkpoint = try event(arm, sequence: caseName == "data-partial-frame" ? 71 : sent.sequence!)
        let terminal = Wire.Frame(operation: .terminal, binding: arm.binding, scope: arm.scope,
            data: .init(attachmentIDs: [arm.targetAttachment], code: .prepare))
        try session.pair.sendBytes(Wire.encode(checkpoint) + Wire.encode(terminal))
        #expect(throws: (any Error).self) { try pending.result() }
        #expect(session.terminalSignal.wait(timeout: .now() + 5) == .success)
        coordinator.close()
        var wrong = arm; wrong.requestID = earlyUUID()
        #expect(throws: (any Error).self) { try coordinator.prepareObservation(wrong) }
        #expect(try coordinator.prepareObservation(arm) == checkpoint)
        #expect(coordinator.events() == [terminal])
        #expect(throws: (any Error).self) { try coordinator.prepareObservation(arm) }
    }

    @Test(arguments: ["guest-accepted-before-prepare", "data-partial-frame"])
    func independentGuestEarlyObserverNeverReleasesOrPromotesPrepare(caseName: String) throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: caseName), coordinator = session.coordinator
        let command = prepare(session)
        let pending = EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.command(command) }
        defer { pending.settle() }
        let sent = try session.pair.receive(), checkpoint = try event(arm, sequence: sent.sequence!)
        let observer = EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.prepareObservation(arm) }
        defer { observer.settle() }
        try session.pair.send(checkpoint)
        #expect(try observer.result() == checkpoint)
        #expect(!pending.finishedWithin(0))
        #expect(!coordinator.isTerminal)
        // A valid fault checkpoint never makes a PREPARE success reply legitimate.
        try session.pair.send(success(sent))
        #expect(throws: (any Error).self) { try pending.result() }
        #expect(coordinator.isTerminal)
    }

    @Test(arguments: ["sequence", "wrong-case", "wrong-arm", "scope", "boot", "unsolicited", "replay", "guest-a1"])
    func earlyGuestDemuxIsBoundToPendingPrepare(fault: String) throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: "guest-accepted-before-prepare"), coordinator = session.coordinator
        var checkpoint = try event(arm, sequence: 5)
        if fault == "sequence" { checkpoint.data.compatibilityEarlyObservation!.requestSequence = 4 }
        if fault == "wrong-case" { checkpoint.data.compatibilityEarlyObservation!.stage = "data-partial-frame"; checkpoint.data.compatibilityEarlyObservation!.dataBytesWritten = 5 }
        if fault == "wrong-arm" { checkpoint.data.compatibilityEarlyObservation!.armDigest = String(repeating: "f", count: 64) }
        if fault == "scope" { checkpoint.scope!.controllerEpoch += 1 }
        if fault == "boot" { checkpoint.binding.guestBootNonce = earlyUUID() }
        if fault == "guest-a1" {
            checkpoint.data.compatibilityEarlyObservation!.stage = "before-prepare-send"
            checkpoint.data.compatibilityEarlyObservation!.prepareCommandsSent = 0
            checkpoint.data.compatibilityEarlyObservation!.prepareCommandsAccepted = 0
        }
        var pending: EarlyWorker<Wire.Frame>?
        defer { pending?.settle() }
        if fault != "unsolicited" {
            let command = prepare(session)
            pending = EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.command(command) }
            _ = try session.pair.receive()
        }
        try session.pair.send(checkpoint)
        if fault == "replay" { try session.pair.send(checkpoint) }
        #expect(session.terminalSignal.wait(timeout: .now() + 5) == .success)
        if let pending { #expect(throws: (any Error).self) { try pending.result() } }
        if fault == "replay" { #expect(try coordinator.prepareObservation(arm) == checkpoint) }
        else { #expect(throws: (any Error).self) { try coordinator.prepareObservation(arm) } }
    }

    @Test func strictEarlySchemaAndClosedProfiles() throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: "data-partial-frame")
        let checkpoint = try event(arm, sequence: UInt64.max)
        let observation = try #require(checkpoint.data.compatibilityEarlyObservation)
        try Carrier.validateProfile(Carrier.earlyProfile, sourceSHA256: String(repeating: "a", count: 64))
        try Carrier.validate(observation, arm: arm)
        #expect(try Wire.decode(from: Data(Wire.encode(checkpoint).dropFirst(4))) == checkpoint)
        let original = String(decoding: try Carrier.canonicalData(observation), as: UTF8.self)
        for (field, value) in [("count", "0"), ("version", "1"), ("prepareCommandsSent", "0"),
                              ("prepareCommandsAccepted", "0"), ("dataBytesWritten", "4"), ("requestSequence", "0"),
                              ("count", "null"), ("count", "1e0"), ("count", "4294967296")] {
            var object = try JSONSerialization.jsonObject(with: Data(original.utf8)) as! [String: Any]
            object.removeValue(forKey: field)
            let stripped = String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
            let body = String(stripped.dropLast()) + ",\"" + field + "\":" + value + "}"
            // Wire does not require key order; it must still reject malformed semantics.
            let frameText = String(decoding: try Data(Wire.encode(checkpoint).dropFirst(4)), as: UTF8.self)
            let changed = frameText.replacingOccurrences(of: original, with: body)
            #expect(changed != frameText)
            #expect(throws: (any Error).self) { try Wire.decode(from: Data(changed.utf8)) }
        }
        for field in ["version", "profile", "requestID", "armDigest", "stage", "count", "targetAttachment", "requestSequence", "prepareCommandsSent", "prepareCommandsAccepted", "dataBytesWritten"] {
            var object = try JSONSerialization.jsonObject(with: Data(original.utf8)) as! [String: Any]
            object.removeValue(forKey: field)
            let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try Carrier.decode(Carrier.EarlyObservation.self, from: bytes) }
        }
        for extra in [",\"unknown\":0}", ",\"count\":1}", ",\"root\":null}"] {
            #expect(throws: (any Error).self) { try Carrier.decode(Carrier.EarlyObservation.self, from: Data((String(original.dropLast()) + extra).utf8)) }
        }
        for name in ["normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame", "first-child-published", "unknown"] {
            var changed = arm; changed.caseName = name
            if name == "first-child-published" || name == "unknown" { #expect(throws: (any Error).self) { try Carrier.validate(changed) } }
            else { try Carrier.validate(changed) }
            changed.version = 1; changed.profile = Carrier.profile
            if name == "normal" || name == "first-child-published" { try Carrier.validate(changed) }
            else { #expect(throws: (any Error).self) { try Carrier.validate(changed) } }
        }
    }

    @Test @MainActor func failedBeforeMountContainsBeforeJoiningObserver() async throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: "before-prepare-send", mount: false)
        let source = session.coordinator.prepareObserver
        let observation = Task<Void, Error> { _ = try await source.observation(arm) }
        try await RawManagedStorageBackend.joinFailedPrepareObservation(observation) {
            session.coordinator.close()
        }
        if case .success = await observation.result { Issue.record("pre-mount containment fabricated evidence") }
        #expect(session.coordinator.isTerminal)
    }

    @Test @MainActor func failedContainmentDoesNotWaitForLiveObserver() async throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: "before-prepare-send", mount: false)
        let source = session.coordinator.prepareObserver
        let observation = Task<Void, Error> { _ = try await source.observation(arm) }
        do {
            try await RawManagedStorageBackend.joinFailedPrepareObservation(observation) { throw EarlyTestFailure.fixture }
            Issue.record("containment failure was accepted")
        } catch EarlyTestFailure.fixture { }
        #expect(!session.coordinator.isTerminal)
        session.coordinator.close()
        _ = await observation.result
    }

    @Test func v2NormalStillRequiresSealedPhysicalEventBeforeSuccess() throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: "normal"), coordinator = session.coordinator
        func identity(_ inode: UInt64, _ kind: UInt32) -> Carrier.ObjectIdentity {
            .init(inode: inode, generation: 1, fileType: kind, handle: String(format: "%02x00000001000000", inode))
        }
        let observation = Carrier.Observation(version: 2, profile: Carrier.earlyProfile, requestID: arm.requestID,
            armDigest: try Carrier.digest(arm), stage: "first-child-published", count: 1, targetAttachment: arm.targetAttachment,
            copyIntent: earlyUUID(), filesystemUUID: String(repeating: "ab", count: 16), manifestDigest: String(repeating: "cd", count: 32),
            manifestSize: 512, sourceAtimes: .init(root: 0, a: 1, z: UInt64(Int64.max)),
            root: identity(2, 16384), transaction: identity(3, 16384), published: identity(4, 32768), staged: identity(5, 32768))
        let checkpoint = Wire.Frame(operation: .prepareCheckpoint, binding: arm.binding, scope: arm.scope,
            data: .init(compatibilityObservation: observation))
        let command = prepare(session)
        let pending = EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.command(command) }
        defer { pending.settle() }
        let sent = try session.pair.receive(), reply = success(sent)
        try session.pair.sendBytes(Wire.encode(checkpoint) + Wire.encode(reply))
        #expect(try pending.result() == reply)
        #expect(try coordinator.prepareObservation(arm) == checkpoint)
        #expect(!coordinator.isTerminal)
        var earlyArm = arm; earlyArm.caseName = "data-partial-frame"
        #expect(throws: (any Error).self) { try Carrier.validate(observation, arm: earlyArm) }
    }

    @Test func earlyQueuePublicationIsImmutableAndUsesExistingSuffix() throws {
        let session = try EarlySession(); defer { session.close() }
        let arm = try ready(session, caseName: "before-prepare-send")
        let root = FileManager.default.temporaryDirectory.appending(path: "early-queue-" + earlyUUID())
        defer { try? FileManager.default.removeItem(at: root) }
        let lock = try CanonicalDataStoreLock(root: root), queue = try ManagedPrepareCompatibilityQueue(storeLock: lock)
        let directory = lock.root.appending(path: ManagedPrepareCompatibilityQueue.directoryName)
        func put(_ bytes: Data, _ name: String) throws { let path = directory.appending(path: name); try bytes.write(to: path); #expect(chmod(path.path, 0o600) == 0) }
        let capture = Carrier.Capture(version: 1, requestID: arm.requestID, container: arm.scope.container,
            containerInstance: arm.scope.containerInstance, specificationDigest: arm.scope.specificationDigest, mounts: arm.mounts)
        try put(Carrier.canonicalData(capture), "capture.json")
        let claim = try #require(try queue.capture(container: capture.container, instance: capture.containerInstance, digest: capture.specificationDigest, mounts: capture.mounts))
        let candidate = Carrier.Candidate(version: 2, profile: arm.profile, requestID: arm.requestID, binding: arm.binding,
            scope: arm.scope, mounts: arm.mounts, slots: arm.slots, credentials: arm.credentials)
        try queue.candidate(candidate, claim: claim)
        try put(Carrier.armData(arm), arm.requestID + ".arm.json")
        #expect(try queue.arm(claim, candidate: candidate) == Carrier.normalized(arm))
        let accepted = Carrier.normalized(arm)
        try queue.armed(accepted, claim: claim)
        let observation = try #require(try event(arm, sequence: 5).data.compatibilityEarlyObservation)
        try queue.checkpoint(observation, arm: accepted, claim: claim)
        let path = directory.appending(path: arm.requestID + ".checkpoint.json")
        #expect(try Data(contentsOf: path) == Carrier.canonicalData(observation))
        #expect(throws: (any Error).self) { try queue.checkpoint(observation, arm: accepted, claim: claim) }
        #expect(try Data(contentsOf: path) == Carrier.canonicalData(observation))
        let armed = try Carrier.decode(Carrier.Armed.self, from: Data(contentsOf: directory.appending(path: arm.requestID + ".armed.json")))
        #expect(armed.version == 2)
    }
}
private func earlyUUID() -> String { UUID().uuidString.lowercased() }
private enum EarlyTestFailure: Error { case timeout, transport, fixture }

/// Dedicated OS threads, not shared-dispatch work or blocking cooperative Tasks.
/// Every owner defers settle before closing FDs; a watchdog is only a safety net.
private final class EarlyWorker<Value: Sendable>: @unchecked Sendable {
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
        guard finishedWithin(15) else { cancel(); throw EarlyTestFailure.timeout }
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

private final class EarlySocketPair: @unchecked Sendable {
    let host: FileHandle
    let guest: FileHandle

    init() throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw EarlyTestFailure.transport }
        host = FileHandle(fileDescriptor: pair[0], closeOnDealloc: true)
        guest = FileHandle(fileDescriptor: pair[1], closeOnDealloc: true)
        var enabled: Int32 = 1
        for descriptor in pair {
            guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw EarlyTestFailure.transport }
        }
    }

    func close() { try? host.close(); try? guest.close() }
    func interrupt() { _ = shutdown(guest.fileDescriptor, SHUT_RDWR) }
    func endWrites() throws {
        guard shutdown(guest.fileDescriptor, SHUT_WR) == 0 else { throw EarlyTestFailure.transport }
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
            guard count > 0 else { throw EarlyTestFailure.transport }
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
            guard amount > 0 else { throw EarlyTestFailure.transport }
            offset += amount
        }
        return data
    }
    func readBody() throws -> Data {
        let prefix = try readExactly(4)
        guard prefix.count == 4 else { throw EarlyTestFailure.transport }
        let count = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= UInt32(WorkloadStorageProtocol.maxFrame) else { throw EarlyTestFailure.transport }
        let body = try readExactly(Int(count))
        guard body.count == Int(count) else { throw EarlyTestFailure.transport }
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
            guard result >= 0 else { throw EarlyTestFailure.transport }
            if result == 0 { continue }
            guard item.revents & events != 0 else { throw EarlyTestFailure.transport }
            return
        }
        throw EarlyTestFailure.timeout
    }
}

private struct EarlyBootFixture: Sendable {
    let root: URL
    let disk: VMShimHeldDisk
    let specification: VMShimProtocol.Specification
    let rootUUID: String
    let nonce = earlyUUID()

    init() throws {
        root = FileManager.default.temporaryDirectory.appending(path: "cengine-private-workload-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let directory = try PersistentStateDirectory.open(root)
        guard case .created(let created) = try RawDiskInitialization.createNewDisk(in: directory, named: "root.ext4", size: 16 << 20) else {
            throw EarlyTestFailure.fixture
        }
        rootUUID = created.record.ext4UUID
        let opened = try directory.openRegularFile(named: "root.ext4", access: .readWrite)
        guard flock(opened.handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw EarlyTestFailure.fixture }
        disk = .init(ordinal: 0, role: "container-root", volumeName: nil, parent: directory, name: "root.ext4",
            handle: opened.handle, identity: opened.identity, bytes: 16 << 20)
        specification = .init(containerID: String(repeating: "a", count: 64), generation: 1, token: "unused",
            kernelPath: "/unused", initialRamdiskPath: "/unused", rootDiskPath: root.appending(path: "root.ext4").path,
            rootDiskIdentity: .init(device: opened.identity.device, inode: opened.identity.inode, volumeUUID: opened.identity.volumeUUID),
            rootDiskSize: disk.bytes, cpus: 1, memoryBytes: 1 << 30, macAddress: "02:00:00:00:00:01",
            socketPath: "/unused", logPath: "/unused", shimLaunchUUID: earlyUUID(), diskBootstrapVersion: 1,
            expectedInitramfsSHA256: String(repeating: "b", count: 64), workloadStorageMode: .managed)
    }

    var binding: WorkloadStorageProtocol.BootBinding {
        .init(shimLaunchUUID: specification.shimLaunchUUID!, guestBootNonce: nonce)
    }

    func committedProof(beforeCommit: (@Sendable (RawDiskBootTransaction) throws -> Void)? = nil) throws -> RawDiskBootTransaction.VerifiedContainerBoot {
        let pair = try EarlySocketPair()
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
        let worker = EarlyWorker(cancel: { cancelled.withLock { $0 = true }; pair.interrupt() }) {
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

private final class EarlyCallbackState: Sendable {
    let counts = Mutex((terminal: 0, closed: 0))
}

private final class EarlySession: @unchecked Sendable {
    let fixture: EarlyBootFixture
    let profile: String?
    let pair: EarlySocketPair
    let coordinator: PrivateWorkloadStorageCoordinator
    let configuration: WorkloadStorageConfiguration
    let terminalSignal: DispatchSemaphore
    let callbacks: EarlyCallbackState
    var binding: WorkloadStorageProtocol.BootBinding { fixture.binding }

    init(profile: String? = ManagedPrepareCompatibilityProtocol.earlyProfile, sendBuffer: Int32? = nil,
         diagnosticHook: @escaping @Sendable (PrivateWorkloadStorageCoordinator.DiagnosticBoundary) -> Void = { _ in }) throws {
        let fixture = try EarlyBootFixture()
        var initialized = false
        defer { if !initialized { fixture.remove() } }
        let pair = try EarlySocketPair()
        defer { if !initialized { pair.close() } }
        if var sendBuffer {
            try #require(setsockopt(pair.host.fileDescriptor, SOL_SOCKET, SO_SNDBUF, &sendBuffer,
                socklen_t(MemoryLayout<Int32>.size)) == 0)
        }
        let proof = try fixture.committedProof()
        let signal = DispatchSemaphore(value: 0), counts = EarlyCallbackState()
        let coordinator = try PrivateWorkloadStorageCoordinator(verified: proof, descriptor: pair.host.fileDescriptor, compatibilityProfile: profile,
            closeConnection: { counts.counts.withLock { $0.closed += 1 } },
            onTerminal: { counts.counts.withLock { $0.terminal += 1 }; signal.signal() }, diagnosticHook: diagnosticHook)
        defer { if !initialized { coordinator.close() } }
        // The real coordinator must retain an independent owned descriptor.
        try pair.host.close()
        let volume = earlyUUID()
        let configuration = WorkloadStorageConfiguration(scope: .init(intent: earlyUUID(), store: earlyUUID(), serviceEpoch: earlyUUID(),
            controllerEpoch: 1, controllerKey: String(repeating: "c", count: 64), container: proof.containerID,
            containerInstance: earlyUUID(), launch: proof.shimLaunchUUID, prepare: earlyUUID(),
            specificationDigest: WorkloadStorageProtocol.specificationDigest(Data("{}".utf8))),
            peer: .init(tlsRootDER: Data([1]), serverDER: Data([2]), serverKey: String(repeating: "d", count: 64), dataAddress: "192.0.2.1"),
            mounts: [.init(index: 0, volume: volume, destination: "/data", subpath: "", mode: .readWrite, noCopy: false)],
            slots: [.init(volume: volume, attachment: earlyUUID(), role: .prepare, mode: .readWrite),
                    .init(volume: volume, attachment: earlyUUID(), role: .runtime, mode: .readWrite)])
        self.profile = profile
        self.fixture = fixture; self.pair = pair; self.coordinator = coordinator
        self.configuration = configuration; self.terminalSignal = signal; self.callbacks = counts
        initialized = true
    }

    func hello() throws {
        let coordinator = coordinator
        let worker = EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.hello() }
        defer { worker.settle() }
        try pair.send(.init(operation: .hello, binding: binding, data: .init(compatibilityProfile: profile)))
        _ = try worker.result()
    }
    func start() throws {
        try hello()
        let coordinator = coordinator, configuration = configuration
        let worker = EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.configure(configuration) }
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
        let worker = EarlyWorker(cancel: { coordinator.cancel() }) { try coordinator.command(requested) }
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
