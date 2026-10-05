#if os(macOS) && DEBUG
import CEngineCore
@testable import CEngineRuntime
import Darwin
import Foundation
import Synchronization
import Testing

@Suite("Dormant lifecycle shim private IPC (unsigned unit seams)")
struct StorageLifecycleShimIPCTests {
    private typealias W = StorageLifecycleShimProtocol
    private typealias C = StorageLifecycleShimChannel
    private func pair() throws -> (FileHandle, FileHandle) {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw W.Failure.closed }
        return (FileHandle(fileDescriptor: fds[0], closeOnDealloc: true), FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    }
    @Test(arguments: [false, true])
    func adoptionAdmissionDependsOnProfileNotNamespace(isQualification: Bool) throws {
        // A pure admission seam cannot mint either a signed policy or a peer.
        // Both ordinary namespaces supply false; qualification supplies true.
        if isQualification {
            #expect(throws: W.Failure.unauthorized) {
                try StorageLifecycleShimServer.validateProfile(for: .enrollAdoption, isQualification: true)
            }
        } else {
            try StorageLifecycleShimServer.validateProfile(for: .enrollAdoption, isQualification: false)
        }
        try StorageLifecycleShimServer.validateProfile(for: .stop, isQualification: isQualification)
    }
    #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
    @Test func qualificationOperationsRequireExplicitProfileEvenInQualificationBuild() throws {
        for operation: W.Operation in [.qualificationRevokeServiceProof, .qualificationCheckLiveVM] {
            #expect(throws: W.Failure.unauthorized) {
                try StorageLifecycleShimServer.validateProfile(for: operation, isQualification: false)
            }
            try StorageLifecycleShimServer.validateProfile(for: operation, isQualification: true)
        }
    }
    @Test func ordinaryClientRejectsQualificationMethodsBeforeIOWithoutClosingChannel() async throws {
        let (a, b) = try pair()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor)
        defer { client.cancel() }
        for _ in 0..<2 {
            await #expect(throws: W.Failure.unauthorized) { try await client.qualificationRevokeServiceProof() }
            await #expect(throws: W.Failure.unauthorized) { try await client.qualificationCheckLiveVM() }
        }
        var byte: UInt8 = 0
        let count = Darwin.recv(b.fileDescriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        let error = errno
        #expect(count == -1 && (error == EAGAIN || error == EWOULDBLOCK))
    }
    #endif
    @Test func closedCanonicalSchemaAndUInt64() throws {
        let frame = W.Frame(sequence: UInt64.max, operation: .stop, reply: false)
        let body = try W.encode(frame)
        #expect(try W.decode(body).sequence == UInt64.max)
        let text = String(decoding: body, as: UTF8.self)
        for bad in [body + Data([10]), Data(("{\"unknown\":true," + text.dropFirst()).utf8),
                    Data(text.replacingOccurrences(of: "\"stop\"", with: "\"delete\"").utf8),
                    Data(text.replacingOccurrences(of: "18446744073709551615", with: "0").utf8),
                    Data(text.replacingOccurrences(of: "\"reply\":false", with: "\"reply\":false,\"reply\":false").utf8),
                    Data(text.replacingOccurrences(of: "\"reply\":false", with: "\"configuration\":null,\"reply\":false").utf8)] {
            #expect(throws: (any Error).self) { try W.decode(bad) }
        }
        #expect(throws: (any Error).self) { try W.encode(.init(sequence: 1, operation: .configure, reply: false)) }
        #expect(throws: (any Error).self) { try W.encode(.init(sequence: 1, operation: .command, reply: false)) }
    }
    private func checkpointExitCommand() throws -> W.Boot.Frame {
        typealias P = ManagedPrepareWorkerCheckpointProtocol
        typealias Prepare = ManagedPrepareCompatibilityProtocol
        struct Vector: Decodable {
            let name: String
            let arm: Prepare.Arm
            let observationCanonical: String
        }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let rows = try JSONDecoder().decode([Vector].self, from: Data(contentsOf:
            root.appendingPathComponent("Guest/internal/preparecompat/testdata/full-vectors.json")))
        let row = try #require(rows.first { $0.name == "normal" })
        let checkpoint = try Prepare.decode(Prepare.Observation.self, from: Data(row.observationCanonical.utf8))
        let claim = P.WorkerCheckpointExit(arm: row.arm, checkpoint: checkpoint, workerUUID: row.arm.requestID)
        try P.validate(claim)
        let binding = try #require(StorageLifecycleServiceBootProtocolTests.vectors().first?.binding)
        return .init(operation: .command, binding: binding, sequence: UInt64.max,
            serviceEpoch: row.arm.scope.serviceEpoch, command: .prepareCompatibilityCheckpointExit,
            workerUUID: claim.workerUUID, prepareCompatibilityCheckpointExit: claim)
    }
    @Test func nestedCheckpointExitCommandAndRepliesRoundTrip() throws {
        let command = try checkpointExitCommand()
        let claim = try #require(command.prepareCompatibilityCheckpointExit)
        var ack = command
        ack.operation = .reply; ack.command = nil; ack.prepareCompatibilityCheckpointExit = nil
        ack.prepareCompatibilityCheckpointAck = claim
        var wait = ack
        wait.prepareCompatibilityCheckpointAck = nil
        wait.prepareCompatibilityCheckpointWait = .init(arm: claim.arm, checkpoint: claim.checkpoint,
            workerUUID: claim.workerUUID, workerPID: 42, exitCode: 74, reaped: true)
        for nested in [command, ack, wait] {
            // RTM098 crosses TWO envelopes, unlike the standalone boot vectors.
            // The shared fixture also retains UInt64.max and Int64.max exactly.
            let frame = W.Frame(sequence: 7, operation: .command, reply: nested.operation == .reply, command: nested)
            let bytes = try W.encode(frame)
            let decoded = try W.decode(bytes)
            #expect(decoded.sequence == 7 && decoded.reply == frame.reply)
            #expect(decoded.command == nested)
            #expect(try W.encode(decoded) == bytes)
            let text = String(decoding: bytes, as: UTF8.self)
            for changed in [
                text.replacingOccurrences(of: "\"sourceAtimes\":{", with: "\"sourceAtimes\":{\"unknown\":0,"),
                text.replacingOccurrences(of: "\"sourceAtimes\":{", with: "\"sourceAtimes\":{\"a\":17,"),
                text.replacingOccurrences(of: "\"checkpoint\":{", with: "\"earlyCheckpoint\":null,\"checkpoint\":{")
            ] {
                #expect(throws: (any Error).self) { try W.decode(Data(changed.utf8)) }
            }
        }
    }
    @Test func nestedCheckpointExitReachesSocketOwnerAndPreservesChannel() async throws {
        let command = try checkpointExitCommand()
        let claim = try #require(command.prepareCompatibilityCheckpointExit)
        let (a, b) = try pair()
        let sequences = Mutex<[UInt64]>([])
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, operation: { request in
            try #require(request.operation == .command && request.command == command)
            sequences.withLock { $0.append(request.sequence) }
            var reply = command
            reply.operation = .reply; reply.command = nil; reply.prepareCompatibilityCheckpointExit = nil
            if request.sequence == 2 {
                reply.prepareCompatibilityCheckpointWait = .init(arm: claim.arm, checkpoint: claim.checkpoint,
                    workerUUID: claim.workerUUID, workerPID: 42, exitCode: 74, reaped: true)
            } else { reply.prepareCompatibilityCheckpointAck = claim }
            return (.init(sequence: request.sequence, operation: .command, reply: true, command: reply), nil)
        })
        defer { server.close() }
        try server.start()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: C.budget)
        defer { client.cancel() }
        for sequence in 1...3 {
            let reply = try await client.command(command)
            if sequence == 2 {
                let wait = try #require(reply.prepareCompatibilityCheckpointWait)
                try ManagedPrepareWorkerCheckpointProtocol.validate(wait, for: claim)
                #expect(wait.workerPID == 42 && wait.exitCode == 74 && wait.reaped)
            } else { #expect(reply.prepareCompatibilityCheckpointAck == claim) }
        }
        #expect(sequences.withLock { $0 } == [1, 2, 3])
    }
    @Test func resumePrepareIsSeparateAndPurposeChecked() throws {
        let resume = try ResumeContractFixture().probeGreeting
        let cold = try ColdContractFixture().prepare.mountedGreeting
        let request = W.Frame(sequence: 1, operation: .prepareResume, reply: false)
        #expect(try W.decode(W.encode(request)).operation == .prepareResume)
        let reply = W.Frame(sequence: 1, operation: .prepareResume, reply: true, resumeGreeting: resume)
        #expect(try W.decode(W.encode(reply)).resumeGreeting == resume)
        #expect(throws: (any Error).self) { try W.encode(.init(sequence: 1, operation: .prepareResume, reply: true, resumeGreeting: cold)) }
        #expect(throws: (any Error).self) { try W.encode(.init(sequence: 1, operation: .prepareCold, reply: true, coldGreeting: resume)) }
        #expect(throws: (any Error).self) { try W.encode(.init(sequence: 1, operation: .prepareResume, reply: true, coldGreeting: resume)) }
        #expect(W.HostBootstrap.DiskMode.resumeReadOnly.policy == .resumeReadOnly)
        #expect(RawContainerVirtualMachine.StorageLifecycleDiskMode.resumeReadOnly.bootstrapPolicy == .resumeReadOnly)
        #expect(RawStorageLifecycleShim.diskMode(for: .resumeOpenTakeover) == .resumeReadOnly)
    }

    @Test func exactOneRightOnlyOnConnectAndNoDescriptorLeaks() throws {
        let (a, b) = try pair(), (stream, _) = try pair()
        let channel = try C(borrowedFD: b.fileDescriptor)
        defer { channel.close() }
        let body = try W.encode(.init(sequence: 1, operation: .connectLifecycle, reply: true))
        try C.send(body, fd: a.fileDescriptor, passing: stream.fileDescriptor, deadline: C.deadline(1))
        let packet = try C.receive(fd: b.fileDescriptor, permitsDescriptor: true, deadline: C.deadline(1))
        #expect(packet.descriptor != nil)
        #expect(fcntl(packet.descriptor!.fileDescriptor, F_GETFD) & FD_CLOEXEC != 0)
        try C.send(body, fd: a.fileDescriptor, passing: stream.fileDescriptor, deadline: C.deadline(1))
        #expect(throws: (any Error).self) { try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(1)) }
        try C.send(body, fd: a.fileDescriptor, deadline: C.deadline(1))
        #expect(throws: (any Error).self) { try C.receive(fd: b.fileDescriptor, permitsDescriptor: true, deadline: C.deadline(1)) }
    }
    @Test func extraAndLateRightsAreClosedOnRejection() throws {
        for late in [false, true] {
            let (a, b) = try pair(), (stream, peer) = try pair()
            let channel = try C(borrowedFD: b.fileDescriptor)
            defer { channel.close() }
            let body = try W.encode(.init(sequence: 1, operation: .stop, reply: true))
            var header = UInt32(body.count).bigEndian
            let prefix = withUnsafeBytes(of: &header) { Data($0) }
            if late { _ = prefix.withUnsafeBytes { Darwin.send(a.fileDescriptor, $0.baseAddress, 4, 0) } }
            let bytes = late ? body : prefix + body
            let rightsCount = late ? 1 : 2
            let sent = bytes.withUnsafeBytes { raw in
                var vector = iovec(iov_base: UnsafeMutableRawPointer(mutating: raw.baseAddress), iov_len: raw.count)
                return withUnsafeMutablePointer(to: &vector) { pointer in
                    var ancillary = [UInt32](repeating: 0, count: 3 + rightsCount)
                    return ancillary.withUnsafeMutableBytes { control in
                        control.storeBytes(of: cmsghdr(cmsg_len: socklen_t(control.count), cmsg_level: SOL_SOCKET, cmsg_type: SCM_RIGHTS), as: cmsghdr.self)
                        for i in 0..<rightsCount { control.storeBytes(of: stream.fileDescriptor, toByteOffset: 12 + 4 * i, as: Int32.self) }
                        var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                        message.msg_control = control.baseAddress; message.msg_controllen = socklen_t(control.count)
                        return Darwin.sendmsg(a.fileDescriptor, &message, 0)
                    }
                }
            }
            #expect(sent == bytes.count)
            try stream.close()
            #expect(throws: (any Error).self) { try C.receive(fd: b.fileDescriptor, permitsDescriptor: !late, deadline: C.deadline(1)) }
            // EOF proves all delivered aliases were closed, not merely rejected.
            var byte: UInt8 = 0
            #expect(Darwin.recv(peer.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
        }
    }
    @Test func invalidLengthsAndPartialBodyAreBounded() throws {
        for size: UInt32 in [0, 65_537] {
            let (a, b) = try pair()
            var header = size.bigEndian
            _ = withUnsafeBytes(of: &header) { Darwin.send(a.fileDescriptor, $0.baseAddress, 4, 0) }
            #expect(throws: (any Error).self) { try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(0.1)) }
        }
        let (a, b) = try pair()
        var header = UInt32(100).bigEndian
        _ = withUnsafeBytes(of: &header) { Darwin.send(a.fileDescriptor, $0.baseAddress, 4, 0) }
        #expect(throws: (any Error).self) { try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(0.02)) }
    }
    @Test func anonymousUnsignedProductionConstructorFailsBeforeIO() async throws {
        let (a, b) = try pair()
        await Task.detached {
            #expect(throws: (any Error).self) {
                try StorageLifecycleShimConnection(parentBorrowedFD: a.fileDescriptor, expectedChildPID: getpid())
            }
        }.value
        var byte: UInt8 = 0
        #expect(Darwin.recv(b.fileDescriptor, &byte, 1, MSG_DONTWAIT) <= 0)
    }
    @Test func cancellationShutsBorrowedAliasesAndClosesFutureGate() async throws {
        let (a, b) = try pair()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 1)
        let pending = Task { try await client.prepareFreshDisk() }
        try await Task.sleep(for: .milliseconds(10))
        client.cancel()
        do { _ = try await pending.value; Issue.record("cancellation admitted a greeting") } catch {}
        await #expect(throws: (any Error).self) { try await client.stop() }
        var byte: UInt8 = 0
        #expect(Darwin.recv(a.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
        _ = b
    }
    @Test func deadlineIncludesQueueWaitAndUncertainDeliveryIsTerminal() async throws {
        let (a, b) = try pair()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 0.05)
        defer { client.cancel() }
        let submitted = Mutex<ContinuousClock.Instant?>(nil), ready = DispatchSemaphore(value: 0)
        let observed = AsyncStream<Bool>.makeStream()
        let begin: @Sendable () -> Void = {
            submitted.withLock {
                if $0 == nil { $0 = .now; ready.signal() }
            }
        }
        // Observe real transport EOF on an independent thread. Resuming the test
        // executor is not part of the protocol's deadline. Keep the same <1s
        // bound, starting before the first call (including its queue admission).
        Thread.detachNewThread {
            ready.wait()
            let start = submitted.withLock { $0! }
            var closedInTime = false
            while start.duration(to: .now) < .seconds(1) {
                let remaining = .seconds(1) - start.duration(to: .now)
                let parts = remaining.components
                let milliseconds = max(1, Int32(parts.seconds * 1000 + parts.attoseconds / 1_000_000_000_000_000))
                var descriptor = pollfd(fd: b.fileDescriptor, events: Int16(POLLIN), revents: 0)
                let polled = Darwin.poll(&descriptor, 1, milliseconds)
                if polled < 0 && errno == EINTR { continue }
                guard polled > 0 else { break }
                var bytes = [UInt8](repeating: 0, count: 4096)
                let count = Darwin.recv(b.fileDescriptor, &bytes, bytes.count, MSG_DONTWAIT)
                if count == 0 { closedInTime = start.duration(to: .now) < .seconds(1); break }
                if count < 0 && errno != EINTR && errno != EAGAIN { break }
                // Drain the unanswered request, never reply: the second request
                // remains behind the first on the client's serial worker.
            }
            observed.continuation.yield(closedInTime)
            observed.continuation.finish()
        }
        async let first: (any Error)? = #expect(throws: (any Error).self) {
            begin(); _ = try await client.prepareFreshDisk()
        }
        async let second: (any Error)? = #expect(throws: (any Error).self) {
            begin(); _ = try await client.connectWorkload()
        }
        _ = await (first, second)
        var closedInTime = false
        for await value in observed.stream { closedInTime = value }
        #expect(closedInTime)
        await #expect(throws: (any Error).self) { try await client.prepareFreshDisk() }
    }
    @Test(arguments: [UInt64(0), UInt64(1)])
    func expiredCommandDeadlineSendsNoBytes(deadline: UInt64) async throws {
        let (a, b) = try pair()
        let peer = try C(borrowedFD: b.fileDescriptor)
        defer { peer.close() }
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 5)
        defer { client.cancel() }
        // Exercise the protocol witness, not its default Task cancellation race.
        let transport: any ManagedStorageLifecycleServiceTransport = client
        let frames = try StorageLifecycleServiceBootProtocolTests.vectors()
        await #expect(throws: W.Failure.timeout) {
            try await transport.command(frames[3], deadlineNanoseconds: deadline)
        }
        var byte: UInt8 = 0
        let count = Darwin.recv(b.fileDescriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
        let error = errno
        // Pre-admission expiry has neither delivered bytes nor revoked the channel.
        #expect(count == -1 && (error == EAGAIN || error == EWOULDBLOCK))
        let observed = AsyncStream<Result<Void, any Error>>.makeStream()
        Thread.detachNewThread {
            let result = Result<Void, any Error> {
                let packet = try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(5))
                let request = try W.decode(packet.body)
                try #require(request.sequence == 1 && request.operation == .command && request.command == frames[3])
                let reply = W.Frame(sequence: request.sequence, operation: .command, reply: true, command: frames[4])
                try C.send(W.encode(reply), fd: b.fileDescriptor, deadline: C.deadline(5))
            }
            observed.continuation.yield(result); observed.continuation.finish()
        }
        let reply = try await transport.command(frames[3], deadlineNanoseconds: nil)
        #expect(reply == frames[4])
        for await result in observed.stream { try result.get() }
    }
    @Test func commandDeadlineIsRecheckedAtomicallyAtPublication() async throws {
        let (a, b) = try pair()
        let peer = try C(borrowedFD: b.fileDescriptor)
        defer { peer.close() }
        let releaseDeadline = DispatchSemaphore(value: 0)
        let crossedDeadline = Mutex(false)
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 5,
            beforePublication: { deadline in
                // This seam is AFTER the last unlocked check. Simulate a worker
                // scheduling pause while the independent timer is also delayed.
                _ = DispatchSemaphore(value: 0).wait(timeout: deadline + .milliseconds(20))
                crossedDeadline.withLock { $0 = DispatchTime.now() >= deadline }
            }, beforeDeadline: {
                #expect(releaseDeadline.wait(timeout: C.deadline(5)) == .success)
            })
        defer { releaseDeadline.signal(); client.cancel() }
        let transport: any ManagedStorageLifecycleServiceTransport = client
        let frames = try StorageLifecycleServiceBootProtocolTests.vectors()
        let deadline = C.deadline(1)
        let observed = AsyncStream<Result<Void, any Error>>.makeStream()
        Thread.detachNewThread {
            let result = Result<Void, any Error> {
                let packet = try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(5))
                let request = try W.decode(packet.body)
                try #require(request.operation == .command && request.command == frames[3])
                let reply = W.Frame(sequence: request.sequence, operation: .command, reply: true, command: frames[4])
                try C.send(W.encode(reply), fd: b.fileDescriptor, deadline: C.deadline(5))
                try #require(Self.eof(on: b.fileDescriptor, before: deadline + .seconds(2)) != nil)
            }
            observed.continuation.yield(result); observed.continuation.finish()
        }
        // The catch path terminally cancels all pending requests, so closed can
        // win over timeout. No timer callback can make this assertion pass.
        await #expect(throws: W.Failure.closed) {
            try await transport.command(frames[3], deadlineNanoseconds: deadline.uptimeNanoseconds)
        }
        try #require(crossedDeadline.withLock { $0 })
        for await result in observed.stream { try result.get() }
        await #expect(throws: W.Failure.closed) { try await client.command(frames[3]) }
    }
    @Test func commandDeadlineIncludesExistingWorkerQueueAndRevokesGeneration() async throws {
        let (a, b) = try pair()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 5)
        defer { client.cancel() }
        let transport: any ManagedStorageLifecycleServiceTransport = client
        let command = try StorageLifecycleServiceBootProtocolTests.vectors()[3]
        let received = AsyncStream<Void>.makeStream()
        let observed = AsyncStream<Result<Void, any Error>>.makeStream()
        let submitted = DispatchSemaphore(value: 0)
        let deadline = Mutex<DispatchTime?>(nil)
        Thread.detachNewThread {
            let result = Result<Void, any Error> {
                defer { received.continuation.finish() }
                let packet = try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(5))
                let request = try W.decode(packet.body)
                try #require(request.operation == .command)
                received.continuation.yield(); received.continuation.finish()
                try #require(submitted.wait(timeout: C.deadline(5)) == .success)
                let limit = try #require(deadline.withLock { $0 }) + .milliseconds(700)
                // The first request remains unanswered. Any byte here would be
                // the queued command escaping its expired generation.
                try #require(Self.eof(on: b.fileDescriptor, before: limit) != nil)
            }
            observed.continuation.yield(result); observed.continuation.finish()
        }
        let first = Task { try await client.command(command) }
        defer { first.cancel() }
        var didReceive = false
        for await _ in received.stream { didReceive = true }
        try #require(didReceive)
        let bound = C.deadline(0.3)
        deadline.withLock { $0 = bound }; submitted.signal()
        await #expect(throws: (any Error).self) {
            try await transport.command(command, deadlineNanoseconds: bound.uptimeNanoseconds)
        }
        await #expect(throws: (any Error).self) { try await first.value }
        for await result in observed.stream { try result.get() }
        await #expect(throws: W.Failure.closed) { try await client.command(command) }
    }
    @Test(arguments: [0, 1, 4, 5])
    func commandAbsoluteDeadlineBoundsPartialReply(byteCount: Int) async throws {
        let (a, b) = try pair()
        let peer = try C(borrowedFD: b.fileDescriptor)
        defer { peer.close() }
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 5)
        defer { client.cancel() }
        let transport: any ManagedStorageLifecycleServiceTransport = client
        let frames = try StorageLifecycleServiceBootProtocolTests.vectors()
        let deadline = C.deadline(0.8)
        let observed = AsyncStream<Result<Void, any Error>>.makeStream()
        Thread.detachNewThread {
            let result = Result<Void, any Error> {
                let packet = try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(5))
                let request = try W.decode(packet.body)
                try #require(request.operation == .command && request.command == frames[3])
                let body = try W.encode(.init(sequence: request.sequence, operation: .command, reply: true, command: frames[4]))
                var header = UInt32(body.count).bigEndian
                let bytes = (withUnsafeBytes(of: &header) { Data($0) } + body).prefix(byteCount)
                // Spend most of the caller's budget before supplying an incomplete
                // header/body. Progress must not start a fresh relative IO budget.
                _ = DispatchSemaphore(value: 0).wait(timeout: deadline - .milliseconds(300))
                if !bytes.isEmpty {
                    try #require(bytes.withUnsafeBytes { Darwin.send(b.fileDescriptor, $0.baseAddress, $0.count, 0) } == byteCount)
                }
                try #require(Self.eof(on: b.fileDescriptor, before: deadline + .milliseconds(200)) != nil)
            }
            observed.continuation.yield(result); observed.continuation.finish()
        }
        await #expect(throws: (any Error).self) {
            try await transport.command(frames[3], deadlineNanoseconds: deadline.uptimeNanoseconds)
        }
        for await result in observed.stream { try result.get() }
        await #expect(throws: W.Failure.closed) { try await client.command(frames[3]) }
    }
    @Test func commandCallerDeadlineCannotExtendLocalBudget() async throws {
        let (a, b) = try pair()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 0.3)
        defer { client.cancel() }
        let transport: any ManagedStorageLifecycleServiceTransport = client
        let command = try StorageLifecycleServiceBootProtocolTests.vectors()[3]
        let observed = AsyncStream<Result<Void, any Error>>.makeStream()
        let limit = C.deadline(1)
        Thread.detachNewThread {
            let result = Result<Void, any Error> {
                let packet = try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(5))
                let request = try W.decode(packet.body)
                try #require(request.operation == .command)
                try #require(Self.eof(on: b.fileDescriptor, before: limit) != nil)
            }
            observed.continuation.yield(result); observed.continuation.finish()
        }
        await #expect(throws: (any Error).self) {
            try await transport.command(command, deadlineNanoseconds: C.deadline(5).uptimeNanoseconds)
        }
        for await result in observed.stream { try result.get() }
    }
    @Test func completedCommandDeadlineCannotRevokeNextCommand() async throws {
        let (a, b) = try pair()
        let peer = try C(borrowedFD: b.fileDescriptor)
        defer { peer.close() }
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 5)
        defer { client.cancel() }
        let transport: any ManagedStorageLifecycleServiceTransport = client
        let frames = try StorageLifecycleServiceBootProtocolTests.vectors()
        let deadline = C.deadline(1)
        let observed = AsyncStream<Result<Void, any Error>>.makeStream()
        Thread.detachNewThread {
            let result = Result<Void, any Error> {
                for sequence: UInt64 in [1, 2] {
                    let packet = try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline(5))
                    let request = try W.decode(packet.body)
                    try #require(request.sequence == sequence && request.command == frames[3])
                    if sequence == 2 {
                        // Keep a later request pending across the completed one's
                        // absolute deadline: its stale callback must not revoke it.
                        _ = DispatchSemaphore(value: 0).wait(timeout: deadline + .milliseconds(200))
                    }
                    let reply = W.Frame(sequence: sequence, operation: .command, reply: true, command: frames[4])
                    try C.send(W.encode(reply), fd: b.fileDescriptor, deadline: C.deadline(5))
                }
            }
            observed.continuation.yield(result); observed.continuation.finish()
        }
        let first = try await transport.command(frames[3], deadlineNanoseconds: deadline.uptimeNanoseconds)
        let second = try await transport.command(frames[3], deadlineNanoseconds: nil)
        #expect(first == frames[4] && second == frames[4])
        for await result in observed.stream { try result.get() }
    }
    @MainActor private final class Calls {
        var operations = 0
        var terminated = false
        var cancelled = false
    }
    /// Only the observing thread's recv timestamp counts, never executor resumption.
    private static func eof(on fd: Int32, before limit: DispatchTime) -> DispatchTime? {
        while true {
            let now = DispatchTime.now()
            guard now < limit else { return nil }
            let remaining = limit.uptimeNanoseconds - now.uptimeNanoseconds
            var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let result = Darwin.poll(&item, 1, Int32(max(1, remaining / 1_000_000)))
            if result < 0 && errno == EINTR { continue }
            guard result > 0 else { return nil }
            var byte: UInt8 = 0
            let count = Darwin.recv(fd, &byte, 1, MSG_DONTWAIT)
            if count == 0 { return .now() }
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            return nil // A reply is not EOF.
        }
    }
    @Test @MainActor func serverIdleBeyondRequestBudgetStillAdmitsRequests() throws {
        let (a, b) = try pair(), calls = Calls()
        let idle = DispatchSemaphore(value: 0), admitted = DispatchSemaphore(value: 0)
        let done = DispatchSemaphore(value: 0)
        let firstDeadline = Mutex<DispatchTime?>(nil)
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, timeout: 0.15, observe: { event in
            switch event {
            case .idle: idle.signal()
            case .firstByte(let deadline): firstDeadline.withLock { $0 = deadline }
            case .admitted: admitted.signal()
            default: break
            }
        }, operation: { request in
            calls.operations += 1
            return (.init(sequence: request.sequence, operation: request.operation, reply: true), nil)
        })
        defer { server.close() }
        try server.start()
        let body = try W.encode(.init(sequence: 1, operation: .stop, reply: false))
        Thread.detachNewThread {
            defer { done.signal() }
            guard idle.wait(timeout: C.deadline()) == .success else { Issue.record("reader never became idle"); return }
            // Actual idle transport observation, not an assumption that a Task ran.
            var item = pollfd(fd: a.fileDescriptor, events: Int16(POLLIN), revents: 0)
            #expect(Darwin.poll(&item, 1, 350) == 0)
            let sent = DispatchTime.now()
            do { try C.send(body, fd: a.fileDescriptor, deadline: C.deadline()) }
            catch { Issue.record(error); return }
            #expect(admitted.wait(timeout: C.deadline()) == .success)
            #expect(firstDeadline.withLock { $0.map { $0 > sent } ?? false })
        }
        // Deliberately withhold MainActor: admission after >2 idle budgets must
        // work without relying on a VM-owner scheduling opportunity within 150ms.
        #expect(done.wait(timeout: C.deadline()) == .success)
        #expect(calls.operations == 0)
    }
    @Test(arguments: [1, 4, 5])
    func serverPartialHeaderAndBodyExpireAfterFirstByte(byteCount: Int) async throws {
        let (a, b) = try pair(), calls = await Calls()
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, timeout: 0.1, operation: { request in
            calls.operations += 1
            return (.init(sequence: request.sequence, operation: request.operation, reply: true), nil)
        })
        defer { server.close() }
        try server.start()
        let body = try W.encode(.init(sequence: 1, operation: .stop, reply: false))
        var header = UInt32(body.count).bigEndian
        let bytes = (withUnsafeBytes(of: &header) { Data($0) } + body).prefix(byteCount)
        #expect(bytes.withUnsafeBytes { Darwin.send(a.fileDescriptor, $0.baseAddress, $0.count, 0) } == byteCount)
        #expect(await Task.detached { server.waitForReaderForTesting(deadline: C.deadline(1)) }.value)
        #expect(await calls.operations == 0)
        var byte: UInt8 = 0
        #expect(Darwin.recv(a.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
    }
    @Test @MainActor func serverFirstByteDeadlineAlsoBoundsOwnerOperation() throws {
        let (a, b) = try pair(), calls = Calls()
        let firstByte = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
        let done = DispatchSemaphore(value: 0)
        let deadlines = Mutex<(first: DispatchTime?, admitted: DispatchTime?)>((nil, nil))
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, timeout: 3, observe: { event in
            switch event {
            case .firstByte(let deadline):
                deadlines.withLock { $0.first = deadline }; firstByte.signal()
            case .admitted(let sequence, let deadline):
                #expect(sequence == 1); deadlines.withLock { $0.admitted = deadline }
            case .cancelled(let sequence, let isCancelled):
                #expect(sequence == 1 && isCancelled); cancelled.signal()
            default: break
            }
        }, operation: { request in
            calls.operations += 1
            return (.init(sequence: request.sequence, operation: request.operation, reply: true), nil)
        })
        defer { server.close() }
        try server.start()
        let body = try W.encode(.init(sequence: 1, operation: .stop, reply: false))
        var header = UInt32(body.count).bigEndian
        let bytes = withUnsafeBytes(of: &header) { Data($0) } + body
        Thread.detachNewThread {
            defer { done.signal() }
            let start = DispatchTime.now()
            #expect(bytes.prefix(1).withUnsafeBytes { Darwin.send(a.fileDescriptor, $0.baseAddress, $0.count, 0) } == 1)
            guard firstByte.wait(timeout: C.deadline()) == .success,
                  let deadline = deadlines.withLock({ $0.first }) else {
                Issue.record("first byte never observed"); return
            }
            // The observer supplies the actual first-byte deadline. Hold framing
            // for two seconds on this thread, without a Task/actor scheduling
            // assumption. Leave a full second for framing/admission on CI.
            _ = DispatchSemaphore(value: 0).wait(timeout: deadline - .seconds(1))
            #expect(DispatchTime.now() >= deadline - .seconds(1))
            #expect(bytes.dropFirst().withUnsafeBytes { Darwin.send(a.fileDescriptor, $0.baseAddress, $0.count, 0) } == bytes.count - 1)
            let limit = start + .milliseconds(4750)
            let eof = Self.eof(on: a.fileDescriptor, before: limit)
            #expect(eof != nil && eof! < limit)
            #expect(server.waitForReaderForTesting(deadline: limit))
            #expect(cancelled.wait(timeout: limit) == .success)
        }
        // Intentionally starve MainActor until the off-actor observation finishes:
        // the SAME deadline must bound framing AND queued owner work. Resetting it
        // after framing would expire >=5s, outside the 4.75s bound.
        #expect(done.wait(timeout: C.deadline(6)) == .success)
        #expect(deadlines.withLock { $0.first != nil && $0.first == $0.admitted })
        #expect(calls.operations == 0)
        // Cancellation of an owner that has actually entered is checked separately
        // below, after an explicit entry gate rather than a 20ms scheduling guess.
    }
    @Test(arguments: [false, true])
    func idleServerEOFAndCancellationJoinReader(cancel: Bool) async throws {
        let (a, b) = try pair(), calls = await Calls()
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, operation: { _ in
            calls.operations += 1
            throw W.Failure.invalid
        }, terminate: { calls.terminated = true })
        defer { server.close() }
        try server.start()
        try await Task.sleep(for: .milliseconds(20))
        if cancel { server.close() } else { try a.close() }
        #expect(await Task.detached { server.waitForReaderForTesting(deadline: C.deadline(1)) }.value)
        try await Task.sleep(for: .milliseconds(20))
        #expect(await calls.terminated)
        #expect(await calls.operations == 0)
    }
    @Test(arguments: [1, 2, 4])
    func serverRejectsFirstReadRightsWithoutLeakingDescriptors(byteCount: Int) async throws {
        let (a, b) = try pair(), (stream, peer) = try pair(), calls = await Calls()
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, operation: { _ in
            calls.operations += 1
            throw W.Failure.invalid
        })
        defer { server.close() }
        try server.start()
        var header = UInt32(100).bigEndian
        let sent = withUnsafeBytes(of: &header) { raw in
            var vector = iovec(iov_base: UnsafeMutableRawPointer(mutating: raw.baseAddress), iov_len: byteCount)
            return withUnsafeMutablePointer(to: &vector) { pointer in
                var ancillary = [UInt32](repeating: 0, count: 4)
                return ancillary.withUnsafeMutableBytes { control in
                    control.storeBytes(of: cmsghdr(cmsg_len: 16, cmsg_level: SOL_SOCKET, cmsg_type: SCM_RIGHTS), as: cmsghdr.self)
                    control.storeBytes(of: stream.fileDescriptor, toByteOffset: 12, as: Int32.self)
                    var message = msghdr(); message.msg_iov = pointer; message.msg_iovlen = 1
                    message.msg_control = control.baseAddress; message.msg_controllen = 16
                    return Darwin.sendmsg(a.fileDescriptor, &message, 0)
                }
            }
        }
        #expect(sent == byteCount)
        try stream.close()
        // No complete request arrives: rejection must occur on that first recvmsg.
        #expect(await Task.detached { server.waitForReaderForTesting(deadline: C.deadline(1)) }.value)
        #expect(await calls.operations == 0)
        var byte: UInt8 = 0
        #expect(Darwin.recv(peer.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
    }
    @Test func serverUnknownOperationNeverInvokesOwner() async throws {
        let (a, b) = try pair(), calls = await Calls()
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, operation: { request in
            calls.operations += 1
            return (.init(sequence: request.sequence, operation: request.operation, reply: true), nil)
        }, terminate: { calls.terminated = true })
        try server.start()
        let valid = try W.encode(.init(sequence: 1, operation: .stop, reply: false))
        let unknown = Data(String(decoding: valid, as: UTF8.self).replacingOccurrences(of: "stop", with: "delete").utf8)
        try C.send(unknown, fd: a.fileDescriptor, deadline: C.deadline(1))
        try await Task.sleep(for: .milliseconds(50))
        #expect(await calls.operations == 0)
        #expect(await calls.terminated)
        server.close()
    }
    @Test func stopReplyRequiresActualCompletionAndEOFInterruptsInflightStop() async throws {
        let (a, b) = try pair(), calls = await Calls()
        let entered = AsyncStream<Void>.makeStream(), suspended = AsyncStream<Void>.makeStream()
        let cancelled = AsyncStream<Void>.makeStream(), terminated = AsyncStream<Void>.makeStream()
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, operation: { request in
            calls.operations += 1
            defer { cancelled.continuation.finish() }
            DispatchQueue.global().asyncAfter(deadline: C.deadline()) {
                suspended.continuation.finish() // Bounded failure if cancellation regresses.
            }
            entered.continuation.yield(); entered.continuation.finish()
            // This gate never completes normally. AsyncStream iteration wakes on
            // task cancellation, independent of when MainActor is scheduled again.
            do {
                for await _ in suspended.stream {}
                try Task.checkCancellation()
            } catch {
                calls.cancelled = true
                cancelled.continuation.yield(); cancelled.continuation.finish()
                throw error
            }
            return (.init(sequence: request.sequence, operation: request.operation, reply: true), nil)
        }, terminate: {
            calls.terminated = true
            entered.continuation.finish()
            terminated.continuation.yield(); terminated.continuation.finish()
        })
        defer { server.close() }
        try server.start()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: C.budget)
        defer { client.cancel() }
        let pending = Task { try await client.stop() }
        var didEnter = false
        for await _ in entered.stream { didEnter = true }
        #expect(didEnter)
        client.cancel()
        do { try await pending.value; Issue.record("stop success before owner completed") } catch {}
        if didEnter { for await _ in cancelled.stream {} }
        for await _ in terminated.stream {}
        #expect(await calls.operations == 1)
        #expect(await calls.terminated)
        #expect(await calls.cancelled)
    }
    @Test func mismatchedReplyCorrelationClosesChannel() async throws {
        for wrongOperation in [false, true] {
            let (a, b) = try pair()
            // Correlation, not a one-second scheduling test. Blocking peer IO
            // must not occupy Swift's cooperative pool during the full suite.
            let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: C.budget)
            defer { client.cancel() }
            let replies = AsyncStream<Result<Void, any Error>>.makeStream()
            Thread.detachNewThread {
                let result = Result<Void, any Error> {
                    let packet = try C.receive(fd: b.fileDescriptor, permitsDescriptor: false, deadline: C.deadline())
                    let request = try W.decode(packet.body)
                    let reply = W.Frame(sequence: wrongOperation ? request.sequence : request.sequence + 1,
                        operation: wrongOperation ? .connectWorkload : .stop, reply: true)
                    try C.send(W.encode(reply), fd: b.fileDescriptor, deadline: C.deadline())
                }
                replies.continuation.yield(result)
                replies.continuation.finish()
            }
            do { try await client.stop(); Issue.record("mismatched reply accepted") }
            catch {
                // Revocation may win the pending completion race; a timeout
                // is not evidence that correlation was actually rejected.
                #expect((error as? W.Failure) == .invalid || (error as? W.Failure) == .closed)
            }
            for await result in replies.stream { try result.get() }
            await #expect(throws: (any Error).self) { try await client.prepareFreshDisk() }
        }
    }
    @Test func failedOwnerStopCannotProduceSuccess() async throws {
        let (a, b) = try pair()
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, operation: { _ in throw W.Failure.closed })
        try server.start()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: 1)
        await #expect(throws: (any Error).self) { try await client.stop() }
        server.close()
    }
    @Test @MainActor func completedRequestDeadlineCannotCloseIdleOrLaterRequest() async throws {
        let (a, b) = try pair(), (stream, peer) = try pair(), calls = Calls()
        let completed = DispatchSemaphore(value: 0), entered = DispatchSemaphore(value: 0)
        let released = AsyncStream<Void>.makeStream()
        let cancellations = Mutex<[UInt64]>([])
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, observe: { event in
            switch event {
            case .completed(1): completed.signal()
            case .cancelled(let sequence, _): cancellations.withLock { $0.append(sequence) }
            default: break
            }
        }, operation: { request in
            calls.operations += 1
            if request.sequence == 2 {
                entered.signal()
                for await _ in released.stream {}
                calls.cancelled = Task.isCancelled
                try Task.checkCancellation()
            }
            return (.init(sequence: request.sequence, operation: request.operation, reply: true), stream)
        }, terminate: { calls.terminated = true })
        defer { released.continuation.finish(); server.close() }
        try server.start()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: C.budget)
        defer { client.cancel() }
        let lifecycle = try await client.connectLifecycle()
        #expect(lifecycle.fileDescriptor >= 0)
        // Receiving a reply can race writer bookkeeping. Observe the actual
        // completed state before expiring its timer while the server is idle.
        let didComplete = await withCheckedContinuation { continuation in
            Thread.detachNewThread {
                continuation.resume(returning: completed.wait(timeout: C.deadline()) == .success)
            }
        }
        try #require(didComplete)
        func expectOpenTransport() {
            var byte: UInt8 = 0
            let count = Darwin.recv(a.fileDescriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
            let error = errno
            #expect(count == -1 && (error == EAGAIN || error == EWOULDBLOCK))
            #expect(cancellations.withLock { $0.isEmpty })
        }
        server.testingExpire(sequence: 1)
        expectOpenTransport()

        let pending = Task { try await client.connectWorkload() }
        defer { pending.cancel() }
        let didEnter = await withCheckedContinuation { continuation in
            Thread.detachNewThread {
                continuation.resume(returning: entered.wait(timeout: C.deadline()) == .success)
            }
        }
        try #require(didEnter)
        // A later owner has actually entered but cannot reply until released.
        // Exercise the same stale callback again: neither EOF nor cancellation
        // may occur, and the real request must subsequently complete normally.
        server.testingExpire(sequence: 1)
        expectOpenTransport()
        released.continuation.finish()
        let workload = try await pending.value
        #expect(workload.fileDescriptor >= 0)
        #expect(calls.operations == 2)
        #expect(!calls.cancelled && !calls.terminated)
        _ = peer
    }
    @Test(arguments: ["peer-close", "deadline", "late-request"])
    func stopReplyKeepsPeerAliveUntilAuthenticatedConsumerCloses(ending: String) async throws {
        let (a, b) = try pair()
        let calls = Mutex<[W.Operation]>([])
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, operation: { request in
            calls.withLock { $0.append(request.operation) }
            return (.init(sequence: request.sequence, operation: request.operation, reply: true), nil)
        })
        defer { server.close() }
        try server.start()
        // A raw consumer deliberately withholds EOF after reading the reply. Native
        // clients must still authenticate the live shim before closing this channel.
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            Thread.detachNewThread {
                do {
                    let peer = try C(borrowedFD: a.fileDescriptor)
                    defer { peer.close() }
                    try C.send(W.encode(.init(sequence: 1, operation: .stop, reply: false)),
                               fd: a.fileDescriptor, deadline: C.deadline(C.budget))
                    let packet = try C.receive(fd: a.fileDescriptor, permitsDescriptor: false,
                                               deadline: C.deadline(C.budget))
                    let reply = try W.decode(packet.body)
                    try #require(reply.reply && reply.sequence == 1 && reply.operation == .stop)
                    // The writer barrier makes the old send-then-close failure
                    // deterministic, independent of executor or socket scheduling.
                    try #require(server.waitForWriterForTesting(deadline: .now() + 5))
                    var byte: UInt8 = 0
                    let count = Darwin.recv(a.fileDescriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
                    let error = errno
                    try #require(count == -1 && error == EAGAIN)
                    switch ending {
                    case "peer-close": peer.close()
                    case "deadline": server.testingExpire(sequence: 1)
                    default:
                        try C.send(W.encode(.init(sequence: 2, operation: .connectWorkload, reply: false)),
                                   fd: a.fileDescriptor, deadline: C.deadline(5))
                    }
                    if ending != "peer-close" {
                        try #require(Self.eof(on: a.fileDescriptor, before: .now() + 5) != nil)
                    }
                    try #require(server.waitForReaderForTesting(deadline: .now() + 5))
                    continuation.resume()
                } catch { continuation.resume(throwing: error) }
            }
        }
        #expect(calls.withLock { $0 } == [.stop])
        _ = b
    }
    @MainActor @Test func openAndInitializeConfigureFramesValidate() throws {
        let vectors = try StorageLifecycleServiceBootProtocolTests.vectors()
        for index in [1, 5] {
            let cfg = try #require(vectors[index].configuration)
            let body = try W.encode(.init(sequence: 1, operation: .configure, reply: false, configuration: cfg))
            #expect(try W.decode(body).configuration == cfg)
        }
        #expect(try #require(vectors[5].configuration).action == .open)
    }
    @Test func streamOwnershipBoundsLifecycleGenerationsAndReplacesOthers() throws {
        var owner = StorageLifecycleStreamOwnership<Int>()
        #expect(StorageLifecycleStreamOwnership<Int>.Stream.attachmentCSR.rawValue == 4_108)
        try owner.admit(.lifecycle)
        #expect(owner.install(1, for: .lifecycle) == nil)
        #expect(throws: (any Error).self) { try owner.admit(.lifecycle) }
        owner.serviceChanged(); owner.serviceChanged() // One per admitted change, never stacked.
        try owner.admit(.lifecycle)
        #expect(owner.install(2, for: .lifecycle) == 1)
        #expect(throws: (any Error).self) { try owner.admit(.lifecycle) }
        for n in 0..<3 {
            try owner.admit(.workload); try owner.admit(.attachmentCSR)
            #expect(owner.install(10 + n, for: .workload) == (n == 0 ? nil : 9 + n))
            #expect(owner.install(20 + n, for: .attachmentCSR) == (n == 0 ? nil : 19 + n))
        }
        #expect(Set(owner.removeAll()) == [2, 12, 22])
        #expect(owner.connections.isEmpty)
        #expect(throws: (any Error).self) { try owner.admit(.lifecycle) }
    }
    @Test func attachmentCSRStreamIsRepeatableAndDescriptorsAreReleased() async throws {
        let (a, b) = try pair()
        let peers = Mutex<[FileHandle]>([])
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, operation: { request in
            var fds: [Int32] = [-1, -1]
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw W.Failure.closed }
            peers.withLock { $0.append(FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)) }
            return (.init(sequence: request.sequence, operation: request.operation, reply: true),
                    FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
        })
        defer { server.close() }
        try server.start()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: C.budget)
        defer { client.cancel() }
        var received: [FileHandle] = [try await client.connectAttachmentCSR(), try await client.connectAttachmentCSR(),
                                      try await client.connectLifecycle(), try await client.connectLifecycle()]
        #expect(received.allSatisfy { fcntl($0.fileDescriptor, F_GETFD) & FD_CLOEXEC != 0 })
        #expect(server.waitForWriterForTesting(deadline: .now() + 2))
        received.removeAll()
        let limit = Date() + 2
        var eof = false
        while !eof && Date() < limit {
            eof = peers.withLock { $0.count == 4 && $0.allSatisfy { peer in
                var byte: UInt8 = 0
                return recv(peer.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0
            } }
            if !eof { usleep(10_000) }
        }
        #expect(eof, "shim or client leaked a transferred stream descriptor")
    }
    @Test(arguments: [false, true])
    func enrollmentWireEOFSeparatesControlFromOwner(enrollmentSucceeds: Bool) async throws {
        let (a, b) = try pair(), (control, oldPeer) = try pair(), (data, dataPeer) = try pair()
        let lifetime = StorageLifecycleControlLifetime()
        let ended = AsyncStream<Void>.makeStream()
        let terminated = Mutex(false)
        try lifetime.hold(.stream(4_107)) {
            StorageLifecycleShimRevocation.revokeStream(control.fileDescriptor)
        }
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, controlLifetime: lifetime,
            operation: { request in
                #expect(request.operation == .enrollAdoption)
                guard enrollmentSucceeds else { throw W.Failure.unauthorized }
                try lifetime.beginEnrollment()
                try lifetime.enroll() // Unit seam models successful native ROOT start, not authentication.
                return (.init(sequence: request.sequence, operation: request.operation, reply: true), nil)
            }, terminate: { terminated.withLock { $0 = true }; ended.continuation.finish() })
        defer { server.close() }
        try server.start()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: C.budget)
        if enrollmentSucceeds { try await client.enrollAdoption() }
        else { await #expect(throws: (any Error).self) { try await client.enrollAdoption() } }
        client.cancel()
        #expect(await Task.detached { server.waitForReaderForTesting(deadline: C.deadline(2)) }.value)
        if !enrollmentSucceeds { for await _ in ended.stream {} }
        // Even MainActor cleanup is unnecessary for synchronous stream revocation.
        var byte: UInt8 = 0
        #expect(recv(oldPeer.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
        #expect(terminated.withLock { $0 } == !enrollmentSucceeds)
        #expect(lifetime.preservesOwner == enrollmentSucceeds)
        #expect(throws: (any Error).self) { try lifetime.withAdmission {} }
        // DATA was never registered as control and is still the SAME live socket.
        byte = 42
        #expect(send(data.fileDescriptor, &byte, 1, 0) == 1)
        #expect(recv(dataPeer.fileDescriptor, &byte, 1, 0) == 1 && byte == 42)
    }

    @Test @MainActor func fenceSynchronouslyRevokesIPCWhileMainActorIsBlocked() throws {
        let (a, b) = try pair(), (control, peer) = try pair()
        let lifetime = StorageLifecycleControlLifetime()
        try lifetime.beginEnrollment()
        try lifetime.enroll()
        try lifetime.hold(.stream(4_108)) { StorageLifecycleShimRevocation.revokeStream(control.fileDescriptor) }
        let terminated = Mutex(false)
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, controlLifetime: lifetime,
            operation: { _ in Issue.record("fenced request reached owner"); throw W.Failure.closed },
            terminate: { terminated.withLock { $0 = true } })
        defer { server.close() }
        try server.start()
        let fenced = DispatchSemaphore(value: 0)
        // Independent native thread, not a shared dispatch pool competing with
        // the suite's blocking fixtures. Keep the same two-second fence bound.
        Thread.detachNewThread { lifetime.detach(); fenced.signal() }
        // Deliberately do not yield MainActor. ROOT's callback must finish anyway.
        #expect(fenced.wait(timeout: C.deadline(2)) == .success)
        var byte: UInt8 = 0
        #expect(recv(a.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
        #expect(recv(peer.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
        #expect(!terminated.withLock { $0 })
        #expect(throws: (any Error).self) { try lifetime.enroll() }
        let (late, latePeer) = try pair()
        #expect(throws: (any Error).self) {
            try lifetime.hold(.stream(4_107)) { StorageLifecycleShimRevocation.revokeStream(late.fileDescriptor) }
        }
        #expect(recv(latePeer.fileDescriptor, &byte, 1, MSG_DONTWAIT) == 0)
    }

    @Test func EOFDuringEnrollmentCannotResurrectLifetime() async throws {
        let (a, b) = try pair(), lifetime = StorageLifecycleControlLifetime()
        let entered = AsyncStream<Void>.makeStream(), finished = AsyncStream<Void>.makeStream()
        let release = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let lateSuccess = Mutex(false)
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, controlLifetime: lifetime,
            operation: { request in
                try lifetime.beginEnrollment()
                await withCheckedContinuation { continuation in
                    release.withLock { $0 = continuation }
                    entered.continuation.finish()
                }
                defer { finished.continuation.finish() }
                // Models a noncooperative native completion arriving after EOF.
                try lifetime.enroll()
                lateSuccess.withLock { $0 = true }
                return (.init(sequence: request.sequence, operation: request.operation, reply: true), nil)
            })
        defer { server.close() }
        try server.start()
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: C.budget)
        let pending = Task { try await client.enrollAdoption() }
        for await _ in entered.stream {}
        client.cancel()
        #expect(await Task.detached { server.waitForReaderForTesting(deadline: C.deadline(2)) }.value)
        release.withLock { $0?.resume(); $0 = nil }
        for await _ in finished.stream {}
        await #expect(throws: (any Error).self) { try await pending.value }
        #expect(!lateSuccess.withLock { $0 } && !lifetime.isEnrolled && !lifetime.preservesOwner)
    }

    @Test func correlatedStopAndConnectReplies() async throws {
        let (a, b) = try pair(), (stream, peer) = try pair()
        let deadlines = Mutex<(first: [DispatchTime], admitted: [DispatchTime], responding: [DispatchTime])>(([], [], []))
        let server = try StorageLifecycleShimServer(testFD: b.fileDescriptor, observe: { event in
            deadlines.withLock {
                switch event {
                case .firstByte(let deadline): $0.first.append(deadline)
                case .admitted(_, let deadline): $0.admitted.append(deadline)
                case .responding(_, let deadline): $0.responding.append(deadline)
                default: break
                }
            }
        }, operation: { request in
            (.init(sequence: request.sequence, operation: request.operation, reply: true), request.operation.transfersDescriptor ? stream : nil)
        })
        defer { server.close() }
        try server.start()
        // This checks correlation/descriptor delivery, not a one-second deadline.
        let client = try StorageLifecycleShimConnection.testing(borrowedFD: a.fileDescriptor, timeout: C.budget)
        defer { client.cancel() }
        let lifecycle = try await client.connectLifecycle()
        let workload = try await client.connectWorkload()
        #expect(lifecycle.fileDescriptor >= 0 && workload.fileDescriptor >= 0)
        try await client.stop()
        await #expect(throws: (any Error).self) { try await client.connectWorkload() }
        #expect(deadlines.withLock {
            $0.admitted.count == 3 && $0.admitted == $0.responding && Array($0.first.prefix(3)) == $0.admitted
        })
        _ = peer
    }
}
#endif
