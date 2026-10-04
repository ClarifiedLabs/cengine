#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

@Suite struct ManagedStoragePeerTests {
    private typealias Recovery = RawStorageShimRecovery

    @Test func exactPublishedNativePeerReceivesAuthenticatedStatusRequest() async throws {
        let fixture = try ManagedPeerFixture()
        defer { fixture.remove() }
        let generation = try #require(try Recovery.publishedGeneration(for: fixture.specification))
        #expect(generation.specification == fixture.specification)
        #expect(generation.record.process.pid == getpid())
        #expect(Recovery.observe(getpid()) == .process(generation.record.process))

        let exchange = try await managedPeerExchange(fixture.specification)
        #expect(try exchange.result.get() == managedPeerStatus(fixture.specification))
        #expect(exchange.capture.peerPID == getpid())
        let request = try #require(exchange.capture.request)
        #expect(request.operation == .status)
        #expect(request.token == fixture.specification.token)
        #expect(request.payload == nil)
        #expect(!exchange.capture.bytes.isEmpty)
    }

    @Test(arguments: [false, true])
    func productionReplyRetainsExactNativePeerUntilAuthenticatedAcknowledgement(changedIdentity: Bool) async throws {
        let observation = try await peerFixtureOnThread {
            try Self.checkProductionReply(changedIdentity: changedIdentity)
        }
        #expect(observation.requestMatched)
        #expect(observation.replyMatched)
        #expect(!observation.writerFinishedBeforeAcknowledgement)
        if changedIdentity {
            if case .success = observation.proof { Issue.record("post-reply changed native identity was accepted") }
            if case .success = observation.writerResult { Issue.record("server accepted EOF as acknowledgement") }
        } else {
            try observation.writerResult.get()
            try observation.proof.get()
        }
    }

    private struct ProductionReplyObservation: Sendable {
        let requestMatched: Bool
        let replyMatched: Bool
        let writerFinishedBeforeAcknowledgement: Bool
        let proof: Result<Void, any Error>
        let writerResult: Result<Void, any Error>
    }

    private static func checkProductionReply(changedIdentity: Bool) throws -> ProductionReplyObservation {
        let fixture = try ManagedPeerFixture()
        defer { fixture.remove() }
        let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
        defer { Darwin.close(listener) }
        let clientScope = VMShimManagedTransport()
        defer { clientScope.close() }
        try clientScope.connect(path: fixture.specification.socketPath)
        let peer = try UnixSocket.accept(listener)
        let serverScope = VMShimManagedTransport()
        defer { serverScope.close() }
        do { try serverScope.adopt(peer) } catch { Darwin.close(peer); throw error }
        let client = VMShimClient(specification: fixture.specification)
        let descriptor = try clientScope.ownedDescriptor()
        try client.validateManagedStoragePeer(descriptor)
        let request = VMShimProtocol.Envelope(token: fixture.specification.token, operation: .status)
        try clientScope.write(VMShimProtocol.encode(request))
        let received = try VMShimProtocol.decode(serverScope.readFrame())
        let reply = VMShimProtocol.Envelope(id: request.id, token: request.token, operation: request.operation,
            payload: try JSONEncoder().encode(managedPeerStatus(fixture.specification)))
        let frame = try VMShimProtocol.encode(reply)
        let writer = PeerFixtureWorker {
            defer { serverScope.close() }
            try VMShimServer.writeManagedReply(frame, using: serverScope)
        }
        defer {
            serverScope.cancel()
            precondition(writer.wait(milliseconds: 15_000), "reply worker did not join before fixture cleanup")
        }
        let receivedReply = try VMShimProtocol.decode(clientScope.readFrame())
        // Deterministically give the old one-shot writer time to close. The
        // production writer must instead remain blocked on the explicit ack.
        let writerFinishedBeforeAcknowledgement = writer.wait(milliseconds: 100)
        if changedIdentity {
            guard let generation = try Recovery.publishedGeneration(for: fixture.specification) else {
                throw PeerFixtureFailure.prerequisite("missing published storage generation")
            }
            let old = generation.record.process
            let changed = Recovery.ProcessIdentity(pid: old.pid, startSeconds: old.startSeconds,
                startMicroseconds: old.startMicroseconds, bootUUID: old.bootUUID, uniqueID: old.uniqueID + 1)
            let record = Recovery.LaunchRecord(intent: generation.record.intent, process: changed)
            guard let launch = fixture.launch else {
                throw PeerFixtureFailure.prerequisite("missing prepared storage launch")
            }
            try JSONEncoder().encode(record).write(to: launch.specificationURL.deletingLastPathComponent().appending(path: "launch.json"))
        }
        let proof = Result { try client.validateManagedStoragePeer(descriptor) }
        if changedIdentity {
            clientScope.close() // No acknowledgement on failed proof.
        } else if case .success = proof {
            try clientScope.write(Data([VMShimServer.managedReplyAcknowledgement]))
        } else {
            clientScope.close()
        }
        return try .init(requestMatched: received == request, replyMatched: receivedReply == reply,
            writerFinishedBeforeAcknowledgement: writerFinishedBeforeAcknowledgement,
            proof: proof, writerResult: writer.result())
    }

    @Test(arguments: ["invalid", "eof", "timeout", "cancel"], [false, true])
    func managedReplyAcknowledgementFailuresAreBounded(fault: String, completedShutdown: Bool) async throws {
        // Both peers perform blocking I/O. Neither may occupy the cooperative
        // executor needed to start the other; the async caller joins this worker.
        let observation = try await peerFixtureOnThread {
            try managedReplyAcknowledgementFailure(fault: fault, completedShutdown: completedShutdown)
        }
        #expect(observation.replyMatched)
        #expect(observation.joinedWithinBound, "reply worker escaped its bound")
        if fault == "timeout" { #expect(observation.completedAt >= observation.deadline) }
        if completedShutdown {
            // Only an already-completed shutdown permits cleanup after lost ack.
            try observation.result.get()
            return
        }
        guard case .failure(let error) = observation.result else {
            Issue.record("invalid acknowledgement succeeded"); return
        }
        switch fault {
        case "timeout": #expect(error is AsyncTimeout.TimeoutError)
        case "cancel": #expect(error is CancellationError)
        case "invalid": #expect(error is EngineError)
        case "eof": #expect((error as? POSIXError)?.code == .ECONNRESET)
        default: Issue.record("unknown acknowledgement fault")
        }
    }

    @Test func managedErrorReplyIsAcknowledgedBeforeClosedFailureReturns() async throws {
        let fixture = try ManagedPeerFixture()
        defer { fixture.remove() }
        let exchange = try await managedPeerExchange(fixture.specification, replyFailure: true)
        if case .success = exchange.result { Issue.record("error reply succeeded") }
        #expect(exchange.capture.request?.operation == .status)
    }

    @Test func closedPeerBeforeAcceptStillProvidesZeroByteEOF() throws {
        let fixture = try ManagedPeerFixture(publication: .none)
        defer { fixture.remove() }
        let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
        defer { Darwin.close(listener) }
        let client = try UnixSocket.connect(path: fixture.specification.socketPath)
        Darwin.close(client) // Deterministically close before the fixture accepts.
        let capture = try serveManagedPeer(listener, specification: fixture.specification)
        #expect(capture.bytes.isEmpty)
        #expect(capture.request == nil)
        #expect(capture.peerPID == nil)
    }

    @Test func delayedStartupStillRequiresAcceptedZeroByteEOF() async throws {
        let fixture = try ManagedPeerFixture(publication: .none)
        defer { fixture.remove() }
        let exchange = try await managedPeerExchange(fixture.specification, delayedStartup: true)
        if case .success = exchange.result { Issue.record("unpublished peer succeeded") }
        #expect(exchange.capture.bytes.isEmpty)
        #expect(exchange.capture.request == nil)
    }

    @Test func acceptedSilentPeerStillExpiresItsIOBudget() async throws {
        let error = try await peerFixtureOnThread {
            let fixture = try ManagedPeerFixture(publication: .none)
            defer { fixture.remove() }
            let listener = try UnixSocket.listen(path: fixture.specification.socketPath)
            defer { Darwin.close(listener) }
            let connection = try UnixSocket.connect(path: fixture.specification.socketPath)
            defer { Darwin.close(connection) } // Keep the accepted peer live and silent.
            do {
                _ = try serveManagedPeer(listener, specification: fixture.specification)
                throw PeerFixtureFailure.prerequisite("silent peer unexpectedly completed")
            } catch { return error }
        }
        guard case PeerFixtureFailure.phase("storage request/EOF", let underlying) = error else {
            Issue.record("silent accepted peer did not expire in request/EOF: \(error)")
            return
        }
        #expect((underlying as? POSIXError)?.code == .ETIMEDOUT)
    }

    @Test(arguments: ["none", "intentOnly"])
    func missingPublicationClosesBeforeSendingAnyToken(publication: String) async throws {
        let fixture = try ManagedPeerFixture(publication: publication == "none" ? .none : .intentOnly)
        defer { fixture.remove() }
        try await expectManagedPeerRejection(fixture.specification)
    }

    @Test(arguments: ["token", "launchUUID", "generation", "cpus"])
    func sameStoreAndPIDDoNotAuthorizeAnotherSpecification(field: String) async throws {
        let fixture = try ManagedPeerFixture()
        defer { fixture.remove() }
        var proposed = fixture.specification
        switch field {
        case "token": proposed.token = "another-private-shim-token"
        case "launchUUID": proposed.shimLaunchUUID = UUID().uuidString.lowercased()
        case "generation": proposed.generation += 1
        default: proposed.cpus += 1
        }
        // Recovery deliberately matches a store, not an exact launch. The
        // socket gate must additionally compare the entire published spec.
        let generation = try #require(try Recovery.publishedGeneration(for: proposed))
        #expect(generation.specification == fixture.specification)
        #expect(generation.specification != proposed)
        #expect(Recovery.observe(getpid()) == .process(generation.record.process))
        try await expectManagedPeerRejection(proposed)
    }

    @Test func anotherLivePublishedProcessCannotAuthenticateThisSocket() async throws {
        let fixture = try ManagedPeerFixture()
        defer { fixture.remove() }
        let generation = try #require(try Recovery.publishedGeneration(for: fixture.specification))
        guard case let .process(other) = Recovery.observe(getppid()) else {
            Issue.record("native parent process identity unavailable")
            return
        }
        try #require(other.pid != getpid())
        let record = Recovery.LaunchRecord(intent: generation.record.intent, process: other)
        let launch = try #require(fixture.launch)
        try JSONEncoder().encode(record).write(to:
            launch.specificationURL.deletingLastPathComponent().appending(path: "launch.json"))
        let reopened = try #require(try Recovery.publishedGeneration(for: fixture.specification))
        #expect(reopened.record == record)
        #expect(Recovery.liveness(other, observation: Recovery.observe(other.pid)) == .alive)
        // Checking only the recorded process would now succeed. The listener
        // still belongs to self, so LOCAL_PEERPID must bind proof to this socket.
        try await expectManagedPeerRejection(fixture.specification)
    }

    @Test(arguments: ["start", "uniqueID", "bothBirthFields"])
    func publishedPIDRequiresCompleteNativeBirthEvidence(field: String) async throws {
        let fixture = try ManagedPeerFixture()
        defer { fixture.remove() }
        let generation = try #require(try Recovery.publishedGeneration(for: fixture.specification))
        let actual = generation.record.process
        let changedStart = field == "start" || field == "bothBirthFields"
        let changedUniqueID = field == "uniqueID" || field == "bothBirthFields"
        let recorded = Recovery.ProcessIdentity(
            pid: actual.pid,
            startSeconds: actual.startSeconds + (changedStart ? 1 : 0),
            startMicroseconds: actual.startMicroseconds,
            bootUUID: actual.bootUUID,
            uniqueID: actual.uniqueID + (changedUniqueID ? 1 : 0)
        )
        #expect(recorded.valid)
        let liveness = Recovery.liveness(recorded, observation: Recovery.observe(getpid()))
        #expect(liveness == (field == "bothBirthFields" ? .dead : .unknown))
        let record = Recovery.LaunchRecord(intent: generation.record.intent, process: recorded)
        let launch = try #require(fixture.launch)
        try JSONEncoder().encode(record).write(to:
            launch.specificationURL.deletingLastPathComponent().appending(path: "launch.json"))
        // This remains a structurally valid publication: rejection must come
        // from the connected PID / native birth proof, not malformed JSON.
        let reopened = try #require(try Recovery.publishedGeneration(for: fixture.specification))
        #expect(reopened.record == record)
        try await expectManagedPeerRejection(fixture.specification)
    }
}

private struct ManagedReplyFailureObservation: Sendable {
    let replyMatched: Bool
    let joinedWithinBound: Bool
    let completedAt: UInt64
    let deadline: UInt64
    let result: Result<Void, any Error>
}

private func managedReplyAcknowledgementFailure(
    fault: String, completedShutdown: Bool
) throws -> ManagedReplyFailureObservation {
    var pair: [CInt] = [-1, -1]
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    let client = VMShimManagedTransport()
    do { try client.adopt(pair[1]) } catch { Darwin.close(pair[0]); Darwin.close(pair[1]); throw error }
    defer { client.close() }
    let frame = try VMShimProtocol.encode(.init(token: "test-only", operation: .status, payload: Data("{}".utf8)))
    let descriptor = pair[0]
    let server = Mutex<VMShimManagedTransport?>(nil)
    let outcome = Mutex<Result<Void, any Error>?>(nil)
    let finished = DispatchGroup()
    finished.enter()
    Thread.detachNewThread {
        // This fault's 250 ms budget starts on the actual writer, not before a
        // queued Task gets a thread. Other faults must not be masked by timeout.
        let scope = VMShimManagedTransport(deadlineNanoseconds: fault == "timeout"
            ? DispatchTime.now().uptimeNanoseconds + 250_000_000 : nil)
        server.withLock { $0 = scope }
        let result = Result {
            do { try scope.adopt(descriptor) } catch { Darwin.close(descriptor); throw error }
            try VMShimServer.writeManagedReply(frame, using: scope, completedShutdown: completedShutdown)
        }
        scope.close()
        outcome.withLock { $0 = result }
        finished.leave()
    }
    defer {
        server.withLock { $0?.cancel() }
        // Never release/reuse either peer's descriptor while its worker lives.
        precondition(finished.wait(timeout: .now() + 15) == .success)
    }
    let received = try client.readFrame()
    guard let scope = server.withLock({ $0 }) else {
        throw PeerFixtureFailure.prerequisite("missing reply worker transport")
    }
    switch fault {
    case "invalid": try client.write(Data([VMShimServer.managedReplyAcknowledgement + 1]))
    case "eof": client.close()
    case "cancel": scope.cancel()
    default: break // Keep a live peer silent: no EOF/cancel can prove timeout.
    }
    let joinedWithinBound = finished.wait(timeout: .now() + 3) == .success
    if !joinedWithinBound {
        scope.cancel()
        precondition(finished.wait(timeout: .now() + 15) == .success, "reply worker did not join before fixture cleanup")
    }
    guard let result = outcome.withLock({ $0 }) else {
        throw PeerFixtureFailure.prerequisite("missing reply worker result")
    }
    return .init(replyMatched: received == frame, joinedWithinBound: joinedWithinBound,
        completedAt: DispatchTime.now().uptimeNanoseconds, deadline: scope.deadlineNanoseconds, result: result)
}

private struct ManagedPeerFixture {
    enum Publication: Sendable { case none, intentOnly, published }

    let directory: URL
    let specification: VMShimProtocol.Specification
    let launch: RawStorageShimRecovery.PreparedLaunch?

    init(publication: Publication = .published) throws {
        directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        do {
            let disk = directory.appending(path: "volumes.ext4")
            try Data(repeating: 0x5a, count: 4_096).write(to: disk)
            let parent = try PersistentStateDirectory.open(directory)
            let proposed = try VMShimProtocol.Specification(
                kind: .storage, containerID: "cengine-storage", generation: 1,
                token: "private-managed-peer-test-token", kernelPath: "/unused",
                initialRamdiskPath: "/unused", rootDiskPath: disk.path,
                rootDiskIdentity: parent.regularFileIdentity(named: "volumes.ext4").shimIdentity,
                rootDiskSize: 4_096, cpus: 1, memoryBytes: 512 * 1_024 * 1_024,
                macAddress: "02:ce:00:00:00:01",
                socketPath: directory.appending(path: "shim.sock").path,
                logPath: directory.appending(path: "shim.log").path,
                shimLaunchUUID: UUID().uuidString.lowercased(), diskBootstrapVersion: 1,
                expectedInitramfsSHA256: String(repeating: "a", count: 64)
            )
            switch publication {
            case .none:
                specification = proposed
                launch = nil
            case .intentOnly, .published:
                let prepared = try RawStorageShimRecovery.prepareLaunch(proposed)
                launch = prepared
                specification = prepared.specification
                if publication == .published {
                    // No injected process observation: publish the actual test
                    // process with the real, exclusively held disk description.
                    _ = try RawStorageShimRecovery.publishLaunch(
                        specificationURL: prepared.specificationURL,
                        data: prepared.data, diskHandle: prepared.diskHandle
                    )
                }
            }
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    func remove() {
        try? launch?.diskHandle.close()
        try? FileManager.default.removeItem(at: directory)
    }
}

private struct ManagedPeerCapture: Sendable {
    let peerPID: pid_t?
    let bytes: Data
    let request: VMShimProtocol.Envelope?
}

private struct ManagedPeerExchange: Sendable {
    let result: Result<VMShimProtocol.Status, any Error>
    let capture: ManagedPeerCapture
}

private func managedPeerStatus(_ specification: VMShimProtocol.Specification) -> VMShimProtocol.Status {
    .init(containerID: specification.containerID, generation: specification.generation,
        state: .created, processIdentifier: getpid(), shimLaunchUUID: specification.shimLaunchUUID)
}

private func expectManagedPeerRejection(_ specification: VMShimProtocol.Specification) async throws {
    let exchange = try await managedPeerExchange(specification)
    switch exchange.result {
    case .success:
        Issue.record("unproven managed storage peer was accepted")
    case let .failure(error):
        #expect(!EngineError.message(for: error).contains(specification.token))
    }
    // A timeout is not proof: the server must have accepted our connection and
    // observed EOF, with no frame prefix or token bytes sent before rejection.
    // A closed-before-accept peer has no queryable LOCAL_PEERPID on Darwin.
    // This fixture owns the private listener and its only connecting client;
    // rejection evidence is actual zero-byte EOF, never an inferred peer ID.
    #expect(exchange.capture.peerPID == nil || exchange.capture.peerPID == getpid())
    #expect(exchange.capture.bytes.isEmpty)
    #expect(exchange.capture.request == nil)
}

private func managedPeerExchange(
    _ specification: VMShimProtocol.Specification, replyFailure: Bool = false, delayedStartup: Bool = false
) async throws -> ManagedPeerExchange {
    // Rejection closes the production transport in an async defer after its
    // native worker returns. Keep that continuation off the shared cooperative
    // pool: unrelated blocking tests must not consume this peer's EOF budget.
    try await withTaskExecutorPreference(ManagedPeerFixtureExecutor()) {
        try await managedPeerExchangeOnExecutor(specification, replyFailure: replyFailure, delayedStartup: delayedStartup)
    }
}

final class ManagedPeerFixtureExecutor: TaskExecutor {
    func enqueue(_ job: consuming ExecutorJob) {
        let job = UnownedJob(job)
        Thread.detachNewThread { job.runSynchronously(on: self.asUnownedTaskExecutor()) }
    }
}

private func managedPeerExchangeOnExecutor(
    _ specification: VMShimProtocol.Specification, replyFailure: Bool, delayedStartup: Bool
) async throws -> ManagedPeerExchange {
    let listener = try UnixSocket.listen(path: specification.socketPath)
    let flags = fcntl(listener, F_GETFL)
    guard flags >= 0, fcntl(listener, F_SETFL, flags | O_NONBLOCK) == 0 else {
        Darwin.close(listener)
        throw POSIXError(.EIO)
    }
    let client = VMShimClient(specification: specification)
    let budget = PeerFixtureBudget()
    let ready = DispatchSemaphore(value: 0)
    let server = PeerFixtureWorker {
        defer { Darwin.close(listener) }
        return try serveManagedPeer(listener, specification: specification, replyFailure: replyFailure,
            budget: budget, accepting: { ready.signal() })
    }
    let watchdog = PeerFixtureWatchdog { client.invalidateRequests() }
    defer { watchdog.finish() }
    let result: Result<VMShimProtocol.Status, any Error>
    do {
        if delayedStartup { try await delayPeerFixtureClient(until: ready) }
        result = .success(try await client.status())
    }
    catch { result = .failure(error) }
    return try await ManagedPeerExchange(result: result, capture: server.value(preserving: result))
}

private func serveManagedPeer(
    _ listener: CInt, specification: VMShimProtocol.Specification, replyFailure: Bool = false,
    budget: PeerFixtureBudget = .init(), accepting: @Sendable () -> Void = {}
) throws -> ManagedPeerCapture {
    let acceptDeadline = budget.deadline(after: PeerFixtureBudget.startupNanoseconds)
    accepting()
    try waitForManagedPeerIO(listener, events: Int16(POLLIN), deadline: acceptDeadline, phase: "storage accept")
    // Production accept configures SO_NOSIGPIPE again, which Darwin rejects
    // with EINVAL if the client already closed. The listener already set it;
    // assert that inherited protection rather than mutating a disconnected peer.
    let peer = Darwin.accept(listener, nil, nil)
    guard peer >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    defer { Darwin.close(peer) }
    let deadline = budget.deadline(after: PeerFixtureBudget.ioNanoseconds)
    var protected: CInt = 0
    var optionSize = socklen_t(MemoryLayout<CInt>.size)
    guard getsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &protected, &optionSize) == 0,
          protected == 1 else { throw POSIXError(.EIO) }
    var pid: pid_t = 0
    var size = socklen_t(MemoryLayout<pid_t>.size)
    let identityResult = getsockopt(peer, SOL_LOCAL, LOCAL_PEERPID, &pid, &size)
    let identityError = errno
    let peerPID: pid_t?
    if identityResult == 0, size == MemoryLayout<pid_t>.size {
        peerPID = pid
    } else if identityResult < 0, identityError == ENOTCONN {
        peerPID = nil
    } else { throw POSIXError(.EIO) }

    var bytes = Data()
    var request: VMShimProtocol.Envelope?
    var frameSize: Int?
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while true {
        try waitForManagedPeerIO(peer, events: Int16(POLLIN), deadline: deadline)
        let count = buffer.withUnsafeMutableBytes {
            Darwin.recv(peer, $0.baseAddress, $0.count, MSG_DONTWAIT)
        }
        if count == 0 { return ManagedPeerCapture(peerPID: peerPID, bytes: bytes, request: request) }
        if count < 0 {
            if errno == EINTR || errno == EAGAIN { continue }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        bytes.append(contentsOf: buffer.prefix(count))
        guard bytes.count <= 64 * 1_024 else { throw POSIXError(.EMSGSIZE) }
        if frameSize == nil, bytes.count >= 4 {
            let length = bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard length > 0, length <= 64 * 1_024 - 4 else { throw POSIXError(.EMSGSIZE) }
            frameSize = 4 + Int(length)
        }
        if request == nil, let frameSize, bytes.count >= frameSize {
            let decoded = try VMShimProtocol.decode(Data(bytes.prefix(frameSize)))
            request = decoded
            // Even negative cases receive a valid reply if the gate regresses;
            // a protocol failure must not mask the unauthorized token write.
            let reply = VMShimProtocol.Envelope(id: decoded.id, token: decoded.token,
                operation: decoded.operation,
                payload: replyFailure ? nil : try JSONEncoder().encode(managedPeerStatus(specification)),
                error: replyFailure ? .init(code: "shim_error", message: "secret-canary") : nil)
            // Use the production response lifetime, not a fake EOF wait that
            // silently hides a server reply-then-close authentication race.
            let scope = VMShimManagedTransport(deadlineNanoseconds: deadline)
            let duplicate = fcntl(peer, F_DUPFD_CLOEXEC, 0)
            guard duplicate >= 0 else { throw POSIXError(.EIO) }
            do { try scope.adopt(duplicate) } catch { Darwin.close(duplicate); throw error }
            defer { scope.close() }
            try peerFixturePhase("storage reply/ack") {
                try VMShimServer.writeManagedReply(VMShimProtocol.encode(reply), using: scope)
            }
            return ManagedPeerCapture(peerPID: peerPID, bytes: bytes, request: request)
        }
    }
}

// Native fixture prerequisites throw ordinary errors, so the awaiting test task
// reports them with its Swift Testing context rather than from an OS thread.
enum PeerFixtureFailure: Error {
    case prerequisite(String)
    case phase(String, any Error)
    case exchange(client: any Error, fixture: any Error)
}

// Harness allowances, not production transport deadlines. Startup and each
// archive resumption get their own window; all phases share an absolute cap.
struct PeerFixtureBudget: Sendable {
    static let startupNanoseconds: UInt64 = 15_000_000_000
    static let ioNanoseconds: UInt64 = 3_000_000_000
    static let functionalNanoseconds: UInt64 = 15_000_000_000
    static let overallSeconds = 60
    let overall = DispatchTime.now().uptimeNanoseconds + UInt64(overallSeconds) * 1_000_000_000

    func deadline(after allowance: UInt64) -> UInt64 {
        min(overall, DispatchTime.now().uptimeNanoseconds + allowance)
    }
}

func peerFixturePhase<Value>(_ phase: String, _ body: () throws -> Value) throws -> Value {
    do { return try body() }
    catch { throw PeerFixtureFailure.phase(phase, error) }
}

// Independent of Swift executor availability. Join before fixture cleanup;
// cancellation only touches the client's owned requests, never a borrowed FD.
final class PeerFixtureWatchdog: Sendable {
    private let stopped = DispatchSemaphore(value: 0)
    private let worker: PeerFixtureWorker<Void>

    init(_ cancel: @escaping @Sendable () -> Void) {
        let stopped = self.stopped
        worker = PeerFixtureWorker {
            if stopped.wait(timeout: .now() + .seconds(PeerFixtureBudget.overallSeconds)) == .timedOut { cancel() }
        }
    }

    func finish() {
        stopped.signal()
        precondition(worker.wait(milliseconds: 15_000), "fixture watchdog did not join")
    }
}

// Wait until the server has actually started its accept clock, then spend more
// than the accepted-I/O allowance before dispatching any client request.
func delayPeerFixtureClient(until ready: DispatchSemaphore) async throws {
    try await peerFixtureOnThread {
        guard ready.wait(timeout: .now() + 15) == .success else {
            throw PeerFixtureFailure.prerequisite("server never entered accept")
        }
        Thread.sleep(forTimeInterval: 3.2)
    }
}

// Blocking fixture work starts directly on OS threads, never queued behind the
// cooperative tasks whose socket traffic or cancellation it needs to observe.
func peerFixtureOnThread<Value: Sendable>(
    _ operation: @escaping @Sendable () throws -> Value
) async throws -> Value {
    try await withCheckedThrowingContinuation { continuation in
        Thread.detachNewThread { continuation.resume(with: Result(catching: operation)) }
    }
}

final class PeerFixtureWorker<Value: Sendable>: Sendable {
    private let outcome = Mutex<Result<Value, any Error>?>(nil)
    private let finished = DispatchGroup()

    init(_ operation: @escaping @Sendable () throws -> Value) {
        finished.enter()
        Thread.detachNewThread { [self] in
            let result = Result(catching: operation)
            outcome.withLock { $0 = result }
            finished.leave() // The operation's descriptor cleanup has completed.
        }
    }

    func wait(milliseconds: Int) -> Bool {
        wait(until: .now() + .milliseconds(milliseconds))
    }

    func wait(until deadline: DispatchTime) -> Bool {
        finished.wait(timeout: deadline) == .success
    }

    func result() throws -> Result<Value, any Error> {
        // Do not unwind a fixture while a stuck callback can still access its
        // files/FDs. A failed hard join bound must stop rather than reuse them.
        precondition(wait(milliseconds: (PeerFixtureBudget.overallSeconds + 5) * 1_000), "fixture worker did not join before fixture cleanup")
        guard let result = outcome.withLock({ $0 }) else {
            throw PeerFixtureFailure.prerequisite("joined fixture worker has no result")
        }
        return result
    }

    func value() async throws -> Value {
        try await peerFixtureOnThread { try self.result().get() }
    }

    func value<Client: Sendable>(preserving client: Result<Client, any Error>) async throws -> Value {
        do { return try await value() }
        catch {
            if case .failure(let clientError) = client {
                throw PeerFixtureFailure.exchange(client: clientError, fixture: error)
            }
            throw error
        }
    }
}

private func waitForManagedPeerIO(_ descriptor: CInt, events: Int16, deadline: UInt64, phase: String = "storage request/EOF") throws {
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { throw PeerFixtureFailure.phase(phase, POSIXError(.ETIMEDOUT)) }
        let remaining = CInt(max(1, (deadline - now) / 1_000_000))
        var event = pollfd(fd: descriptor, events: events, revents: 0)
        let result = Darwin.poll(&event, 1, remaining)
        if result > 0 {
            guard event.revents & Int16(POLLNVAL) == 0 else { throw POSIXError(.EBADF) }
            return
        }
        if result < 0, errno != EINTR { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
}

private func writeManagedPeerFrame(_ frame: Data, to descriptor: CInt, deadline: UInt64) throws {
    var offset = 0
    while offset < frame.count {
        try waitForManagedPeerIO(descriptor, events: Int16(POLLOUT), deadline: deadline)
        let count = frame.withUnsafeBytes {
            Darwin.send(descriptor, $0.baseAddress!.advanced(by: offset), $0.count - offset, MSG_DONTWAIT)
        }
        if count > 0 { offset += count; continue }
        if count < 0, errno == EINTR || errno == EAGAIN { continue }
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
#endif
