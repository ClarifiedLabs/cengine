#if os(macOS)
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

// These are transport/lifetime tests using real local sockets, not authenticated
// storage-authority fixtures. No VM, daemon, or privileged helper is involved.
@Suite(.serialized) struct VMShimManagedTransportTests {
    @Test func defaultAndCallerDeadlinesAreCappedAtFifteenSeconds() {
        let before = DispatchTime.now().uptimeNanoseconds
        let defaultScope = VMShimManagedTransport()
        let cappedScope = VMShimManagedTransport(deadlineNanoseconds: .max)
        let after = DispatchTime.now().uptimeNanoseconds
        for scope in [defaultScope, cappedScope] {
            #expect(scope.deadlineNanoseconds >= before + 15_000_000_000)
            #expect(scope.deadlineNanoseconds <= after + 15_000_000_000)
        }
        let requested = after + 100_000_000
        #expect(VMShimManagedTransport(deadlineNanoseconds: requested).deadlineNanoseconds == requested)
        #expect(VMShimManagedTransport(deadlineNanoseconds: 0).deadlineNanoseconds == 0)
    }

    @Test(arguments: [Data(), Data([0, 0]), Data([0, 0, 0, 4, 7, 8])])
    func frameStallsBeforeHeaderInPrefixAndInBodyAreBounded(available: Data) async throws {
        let pair = try TransportTestPair(milliseconds: 150)
        try transportTestSend(available, to: pair.peer)
        let attempt = TransportTestAttempt(pair) { try $0.readFrame() }
        try await attempt.expectTimeout()
    }

    @Test func expiredDeadlineBeforeWorkerEntryDoesNotInvokeOperation() async throws {
        let pair = try TransportTestPair(deadlineNanoseconds: 0)
        let attempt = TransportTestAttempt(pair) { _ in Data() }
        try await attempt.expectTimeout()
        #expect(!(await transportTestWait(attempt.entered, milliseconds: 0)))
        #expect(!(await transportTestWait(attempt.exited, milliseconds: 0)))
    }

    @Test func readExactlyStallIsBounded() async throws {
        let pair = try TransportTestPair(milliseconds: 150)
        try transportTestSend(Data([1, 2]), to: pair.peer)
        let attempt = TransportTestAttempt(pair) { try $0.readExactly(3) }
        try await attempt.expectTimeout()
    }

    @Test func writeBackpressureIsBounded() async throws {
        let pair = try TransportTestPair(milliseconds: 200)
        try #require(fcntl(pair.descriptor, F_GETFL) & O_NONBLOCK != 0)
        var capacity: CInt = 4_096
        try #require(setsockopt(pair.descriptor, SOL_SOCKET, SO_SNDBUF, &capacity,
                               socklen_t(MemoryLayout<CInt>.size)) == 0)
        let chunk = Data(repeating: 0x5a, count: 4_096)
        var saturated = false
        // Fill without blocking and without relying on the kernel's exact buffer size.
        for _ in 0..<2_048 {
            let count = chunk.withUnsafeBytes {
                Darwin.send(pair.descriptor, $0.baseAddress, $0.count, MSG_DONTWAIT)
            }
            if count < 0 {
                try #require(errno == EAGAIN || errno == EWOULDBLOCK)
                saturated = true
                break
            }
            try #require(count > 0)
        }
        try #require(saturated)
        let attempt = TransportTestAttempt(pair) { scope in
            try scope.write(Data(repeating: 0x7b, count: 65_536))
            return Data()
        }
        try await attempt.expectTimeout()
    }

    @Test func adoptedAcceptedSocketPartialWriteHonorsDeadline() async throws {
        let listener = try TransportTestListener()
        let peer = FileHandle(fileDescriptor: try UnixSocket.connect(path: listener.path), closeOnDealloc: true)
        let accepted = try UnixSocket.accept(listener.descriptor)
        let acceptedFlags = fcntl(accepted, F_GETFL)
        try #require(acceptedFlags >= 0 && acceptedFlags & O_NONBLOCK == 0)
        try #require(fcntl(accepted, F_SETFL, acceptedFlags | O_APPEND) == 0)
        let originalFlags = fcntl(accepted, F_GETFL)
        try #require(originalFlags == acceptedFlags | O_APPEND)
        var capacity: CInt = 4_096
        try #require(setsockopt(accepted, SOL_SOCKET, SO_SNDBUF, &capacity,
                               socklen_t(MemoryLayout<CInt>.size)) == 0)
        let scope = VMShimManagedTransport(deadlineNanoseconds: transportTestDeadline(200))
        do { try scope.adopt(accepted) }
        catch { Darwin.close(accepted); throw error }
        #expect(fcntl(accepted, F_GETFL) == originalFlags | O_NONBLOCK)
        let attempt = TransportTestAttempt(scope, retaining: peer) {
            // Start with an empty send buffer, not a pre-saturated socket. poll
            // must allow send to make partial progress before backpressure.
            try $0.write(Data(repeating: 0x7b, count: 65_536))
            return Data()
        }
        let prefix = await withCheckedContinuation { continuation in
            Thread.detachNewThread {
                var ready = pollfd(fd: peer.fileDescriptor, events: Int16(POLLIN), revents: 0)
                var bytes = [UInt8](repeating: 0, count: 4)
                let count = Darwin.poll(&ready, 1, 3_000) > 0
                    ? Darwin.recv(peer.fileDescriptor, &bytes, bytes.count, MSG_DONTWAIT) : -1
                continuation.resume(returning: count == 4 && bytes == [0x7b, 0x7b, 0x7b, 0x7b])
            }
        }
        #expect(prefix) // Real bytes prove this did not expire before send.
        try await attempt.expectTimeout()
        let transferred = try scope.takeDescriptor()
        defer { Darwin.close(transferred) }
        #expect(fcntl(transferred, F_GETFL) == originalFlags)
        #expect(fcntl(transferred, F_GETFD) & FD_CLOEXEC != 0)
    }

    @Test func managedServerReadRestoresBlockingBeforeStreamHandoff() async throws {
        let listener = try TransportTestListener()
        let peer = try UnixSocket.connect(path: listener.path)
        defer { Darwin.close(peer) }
        let accepted = try UnixSocket.accept(listener.descriptor)
        defer { Darwin.close(accepted) }
        let originalFlags = fcntl(accepted, F_GETFL)
        try #require(originalFlags >= 0 && originalFlags & O_NONBLOCK == 0)
        try transportTestSend(Data([0x42]), to: peer)
        let received = try await VMShimServer.managedSocketIO(accepted, deadline: transportTestDeadline(200)) {
            guard fcntl(try $0.ownedDescriptor(), F_GETFL) & O_NONBLOCK != 0 else {
                throw TransportTestFailure.blockingManagedSocket
            }
            return try $0.readExactly(1)
        }
        #expect(received == Data([0x42]))
        // The owned duplicate shares status flags with the original used by a
        // subsequent blocking stream relay; close alone does not restore them.
        #expect(fcntl(accepted, F_GETFL) == originalFlags)
        try transportTestAssertDuplex(accepted, peer)
    }

    @Test func fragmentProgressDoesNotResetTheAbsoluteFrameDeadline() async throws {
        let observation = try await peerFixtureOnThread { try Self.checkFragmentProgress() }
        #expect(observation.sent > 4)
        #expect(observation.sent < 8)
        guard case .failure(let error) = observation.result else {
            Issue.record("fragment progress renewed the absolute frame deadline")
            return
        }
        #expect(error is AsyncTimeout.TimeoutError)
        let completion = try #require(observation.completedAt)
        #expect(completion >= observation.deadline)
        // A delayed fixture thread must not mistake a later renewed-budget
        // timeout for completion at the original deadline.
        #expect(completion <= observation.deadline + 50_000_000)
    }

    private struct FragmentProgressObservation: Sendable {
        let sent: Int
        let result: Result<Data, any Error>
        let completedAt: UInt64?
        let deadline: UInt64
    }

    private static func checkFragmentProgress() throws -> FragmentProgressObservation {
        let pair = try TransportTestPair(milliseconds: 250)
        let entered = DispatchSemaphore(value: 0)
        let completedAt = Mutex<UInt64?>(nil)
        let reader = PeerFixtureWorker {
            entered.signal()
            defer { completedAt.withLock { $0 = DispatchTime.now().uptimeNanoseconds } }
            return try pair.scope.readFrame()
        }
        defer {
            pair.scope.cancel()
            precondition(reader.wait(milliseconds: 15_000), "frame reader did not join before descriptor cleanup")
        }
        guard entered.wait(timeout: .now() + 3) == .success else {
            throw PeerFixtureFailure.prerequisite("frame reader did not enter")
        }
        let deadline = pair.scope.deadlineNanoseconds
        // Reserve half the original budget before progress. This clock wait is
        // failure-aware: premature reader completion cannot look like progress.
        guard !reader.wait(until: DispatchTime(uptimeNanoseconds: deadline - 125_000_000)) else {
            throw PeerFixtureFailure.prerequisite("frame reader exited before fragment progress")
        }
        var sent = 0
        for fragment in [Data([0, 0, 0, 4]), Data([0x61])] {
            try transportTestSend(fragment, to: pair.peer)
            sent += fragment.count
            // The receive queue draining proves readFrame consumed this exact
            // fragment. No number of sleeps/writes stands in for body progress.
            while true {
                var pending: CInt = 0
                // Darwin sys/filio.h: FIONREAD = _IOR('f', 127, int).
                // Swift cannot import this sizeof-based macro (sys/ioccom.h).
                let fionread = UInt(0x40000000 | (MemoryLayout<CInt>.size << 16) | (0x66 << 8) | 127)
                guard ioctl(pair.descriptor, fionread, &pending) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                guard DispatchTime.now().uptimeNanoseconds < deadline else {
                    throw PeerFixtureFailure.prerequisite("fragment was not consumed within the original budget")
                }
                if pending == 0 { break }
                guard !reader.wait(milliseconds: 0) else {
                    throw PeerFixtureFailure.prerequisite("frame reader exited before consuming the fragment")
                }
                sched_yield()
            }
        }
        // A renewed prefix/body budget would still be live here and accept the
        // remaining body. The correct reader expires at the original deadline.
        if !reader.wait(until: DispatchTime(uptimeNanoseconds: deadline + 50_000_000)) {
            try transportTestSend(Data([0x62, 0x63, 0x64]), to: pair.peer)
        }
        let result = try reader.result()
        return .init(sent: sent, result: result, completedAt: completedAt.withLock { $0 }, deadline: deadline)
    }

    @Test func expiredDeadlineRejectsReadyReadsAndWrites() throws {
        let pair = try TransportTestPair(deadlineNanoseconds: 0)
        try transportTestSend(Data([1, 2, 3, 4]), to: pair.peer)
        #expect(throws: AsyncTimeout.TimeoutError.self) { try pair.scope.readExactly(1) }
        #expect(throws: AsyncTimeout.TimeoutError.self) { try pair.scope.readFrame() }
        #expect(throws: AsyncTimeout.TimeoutError.self) { try pair.scope.write(Data([9])) }
        #expect(try transportTestReceive(4, from: pair.descriptor) == Data([1, 2, 3, 4]))
        var byte: UInt8 = 0
        #expect(Darwin.recv(pair.peer, &byte, 1, MSG_DONTWAIT) == -1)
        #expect(errno == EAGAIN || errno == EWOULDBLOCK)
    }

    @Test func cancellationShutsDownOnlyOwnedSocketAndJoinsWorkerCleanup() async throws {
        let pair = try TransportTestPair(milliseconds: 250)
        let unrelated = try TransportTestPair(milliseconds: 250)
        let readUnwound = DispatchSemaphore(value: 0)
        let releaseCleanup = DispatchSemaphore(value: 0)
        let readResult = Mutex<Result<Data, any Error>?>(nil)
        defer { releaseCleanup.signal() }
        let attempt = TransportTestAttempt(pair) { scope in
            let result = Result { try scope.readExactly(1) }
            readResult.withLock { $0 = result }
            readUnwound.signal()
            // Deliberately keep the synchronous worker alive after shutdown. The
            // async caller must not complete until this cleanup has been released.
            guard releaseCleanup.wait(timeout: .now() + .seconds(3)) == .success else {
                throw TransportTestFailure.watchdog
            }
            return Data()
        }
        try #require(await transportTestWait(attempt.entered))
        attempt.task.cancel()
        try #require(await transportTestWait(readUnwound))
        try #require(!(await transportTestWait(attempt.completed, milliseconds: 50)))
        #expect(!(await transportTestWait(attempt.exited, milliseconds: 0)))
        // Cancellation is shutdown, not close; close belongs to the joined owner.
        #expect(fcntl(pair.descriptor, F_GETFD) >= 0)
        var byte: UInt8 = 0
        #expect(Darwin.recv(pair.peer, &byte, 1, MSG_DONTWAIT) == 0)
        try transportTestAssertDuplex(unrelated.descriptor, unrelated.peer)
        releaseCleanup.signal()
        let result = try await attempt.result()
        let observedRead = try #require(readResult.withLock { $0 })
        if case .failure(let error) = observedRead {
            #expect(!(error is AsyncTimeout.TimeoutError))
        } else {
            Issue.record("stalled read unexpectedly succeeded")
        }
        guard case .failure(let error) = result else {
            Issue.record("cancelled run returned success")
            return
        }
        #expect(error is CancellationError)
    }

    @Test func lateCancellationDoesNotShutdownAReusedDescriptorNumber() throws {
        let original = try TransportTestPair(milliseconds: 250)
        let unrelated = try TransportTestPair(milliseconds: 250)
        var number = original.descriptor
        original.scope.close()
        // F_DUPFD never overwrites another suite's descriptor, unlike dup2.
        // If a concurrent allocator wins the freed number, retry using only the
        // fresh descriptor we actually own; never close the competing descriptor.
        for _ in 0..<32 {
            let replacement = fcntl(unrelated.descriptor, F_DUPFD, number)
            try #require(replacement >= 0)
            if replacement != number {
                do { try original.scope.adopt(replacement) }
                catch { Darwin.close(replacement); throw error }
                number = replacement
                original.scope.close()
                continue
            }
            defer { Darwin.close(replacement) }
            original.scope.cancel()
            original.scope.cancel()
            original.scope.close()
            #expect(fcntl(replacement, F_GETFD) >= 0)
            try transportTestAssertDuplex(replacement, unrelated.peer)
            return
        }
        Issue.record("could not exercise exact descriptor reuse after 32 allocation races")
    }

    @Test func descriptorTransferRestoresBlockingAndDetachesCancellation() throws {
        let pair = try TransportTestPair(milliseconds: 250)
        let flags = fcntl(pair.descriptor, F_GETFL)
        try #require(flags >= 0 && flags & O_NONBLOCK != 0)
        let transferred = try pair.scope.takeDescriptor()
        defer { Darwin.close(transferred) }
        #expect(transferred == pair.descriptor)
        #expect(fcntl(transferred, F_GETFD) & FD_CLOEXEC != 0)
        #expect(fcntl(transferred, F_GETFL) & O_NONBLOCK == 0)
        #expect(throws: CancellationError.self) { try pair.scope.takeDescriptor() }
        pair.scope.cancel()
        pair.scope.close()
        try transportTestAssertDuplex(transferred, pair.peer)
    }

    @Test func successfulFrameAndWriteUseTheOwnedSocket() async throws {
        let pair = try TransportTestPair(milliseconds: 250)
        let frame = Data([0, 0, 0, 3, 10, 11, 12])
        try transportTestSend(frame, to: pair.peer)
        let attempt = TransportTestAttempt(pair) { scope in
            let received = try scope.readFrame()
            try scope.write(Data([42]))
            return received
        }
        #expect(try await attempt.result().get() == frame)
        #expect(try transportTestReceive(1, from: pair.peer) == Data([42]))
    }

    @Test func connectCanTransferAWorkingBlockingSocket() async throws {
        let listener = try TransportTestListener()
        let scope = VMShimManagedTransport(deadlineNanoseconds: transportTestDeadline(250))
        let attempt = TransportTestAttempt(scope, retaining: listener) { scope in
            try scope.connect(path: listener.path)
            return Data()
        }
        _ = try await attempt.result().get()
        var ready = pollfd(fd: listener.descriptor, events: Int16(POLLIN), revents: 0)
        try #require(Darwin.poll(&ready, 1, 0) == 1)
        let peer = Darwin.accept(listener.descriptor, nil, nil)
        try #require(peer >= 0)
        defer { Darwin.close(peer) }
        try transportTestSuppressSIGPIPE(peer)
        let transferred = try scope.takeDescriptor()
        defer { Darwin.close(transferred) }
        #expect(fcntl(transferred, F_GETFL) & O_NONBLOCK == 0)
        #expect(fcntl(transferred, F_GETFD) & FD_CLOEXEC != 0)
        scope.cancel()
        scope.close()
        try transportTestAssertDuplex(transferred, peer)
    }

    @Test func queuedAdmissionExpiresWithoutReleasingItsSlotBeforeActorSettlement() async throws {
        let admission = VMShimManagedAdmission()
        let pair = try TransportTestPair(milliseconds: 2_000)
        let duplicate = fcntl(pair.descriptor, F_DUPFD_CLOEXEC, 0)
        try #require(duplicate >= 0)
        var permits: [VMShimManagedAdmission.Permit] = []
        permits.append(try #require(admission.reserve(duplicate, deadline: transportTestDeadline(50))))
        #expect(fcntl(duplicate, F_GETFD) & FD_CLOEXEC != 0)
        for _ in 1..<64 {
            let owned = fcntl(pair.descriptor, F_DUPFD_CLOEXEC, 0)
            try #require(owned >= 0)
            permits.append(try #require(admission.reserve(owned, deadline: transportTestDeadline(50))))
        }
        let extra = fcntl(pair.descriptor, F_DUPFD_CLOEXEC, 0)
        try #require(extra >= 0)
        defer { Darwin.close(extra) }
        #expect(admission.reserve(extra, deadline: transportTestDeadline(500)) == nil)
        // No actor task has taken a permit. The timer must close all accepted FDs,
        // but cannot make space for another queued actor task until settlement.
        try await Task.sleep(for: .milliseconds(100))
        for permit in permits { #expect(permit.take() == nil) }
        #expect(admission.reserve(extra, deadline: transportTestDeadline(500)) == nil)
        try transportTestAssertDuplex(pair.descriptor, pair.peer)
        permits.removeAll()
        let reclaimed = fcntl(pair.descriptor, F_DUPFD_CLOEXEC, 0)
        try #require(reclaimed >= 0)
        let permit = try #require(admission.reserve(reclaimed, deadline: transportTestDeadline(500)))
        let taken = try #require(permit.take())
        defer { Darwin.close(taken) }
        #expect(permit.take() == nil)
        try transportTestAssertDuplex(taken, pair.peer)
    }

    @Test func queuedAdmissionTimerClosesSocketBeforeAnyActorTake() async throws {
        let admission = VMShimManagedAdmission()
        var descriptors: [CInt] = [-1, -1]
        try #require(Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0)
        let peer = descriptors[1]
        defer { Darwin.close(peer) }
        let permit = try #require(admission.reserve(descriptors[0], deadline: transportTestDeadline(50)))
        // No duplicate of the accepted endpoint survives. EOF on its exact peer
        // proves timer closure without inspecting an FD number another test could reuse.
        let closed = await withCheckedContinuation { continuation in
            Thread.detachNewThread {
                var item = pollfd(fd: peer, events: Int16(POLLIN), revents: 0)
                let ready = Darwin.poll(&item, 1, 2_000)
                var byte: UInt8 = 0
                continuation.resume(returning: ready > 0 && Darwin.recv(peer, &byte, 1, MSG_DONTWAIT) == 0)
            }
        }
        #expect(closed)
        #expect(permit.take() == nil)
    }

    @Test func acceptedUnixSocketIsProtectedBeforeActorAdmission() throws {
        let listener = try TransportTestListener()
        let client = try UnixSocket.connect(path: listener.path)
        defer { Darwin.close(client) }
        let accepted = try UnixSocket.accept(listener.descriptor)
        defer { Darwin.close(accepted) }
        for descriptor in [listener.descriptor, client, accepted] {
            #expect(fcntl(descriptor, F_GETFD) & FD_CLOEXEC != 0)
        }
        try transportTestAssertDuplex(client, accepted)
    }

    @Test func expiredAdmissionDoesNotTransferOrCloseAnUnrelatedDescriptor() throws {
        let admission = VMShimManagedAdmission()
        let pair = try TransportTestPair(milliseconds: 500)
        let owned = fcntl(pair.descriptor, F_DUPFD_CLOEXEC, 0)
        try #require(owned >= 0)
        let permit = try #require(admission.reserve(owned, deadline: 0))
        #expect(permit.take() == nil)
        #expect(permit.take() == nil)
        try transportTestAssertDuplex(pair.descriptor, pair.peer)
    }

    @Test func saturatedUnixListenerFailsWithinABoundedAttempt() async throws {
        let listener = try TransportTestListener()
        try #require(Darwin.listen(listener.descriptor, 1) == 0)
        var fillers: [CInt] = []
        defer { for descriptor in fillers { Darwin.close(descriptor) } }
        var saturated = false
        for _ in 0..<16 {
            let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            try #require(descriptor >= 0)
            fillers.append(descriptor)
            try #require(fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0)
            let result = try UnixSocket.withAddress(listener.path) {
                Darwin.connect(descriptor, $0, $1)
            }
            if result != 0 {
                try #require(errno == ECONNREFUSED || errno == EINPROGRESS || errno == EAGAIN)
                saturated = true
                break
            }
        }
        try #require(saturated)
        let scope = VMShimManagedTransport(deadlineNanoseconds: transportTestDeadline(150))
        let attempt = TransportTestAttempt(scope, retaining: listener) { scope in
            try scope.connect(path: listener.path)
            return Data()
        }
        guard case .failure(let error) = try await attempt.result() else {
            Issue.record("connect unexpectedly succeeded against a saturated listener")
            return
        }
        // Darwin commonly refuses immediately rather than leaving connect pending.
        // This covers bounded saturation failure, not a claimed pending-connect stall.
        #expect(error is POSIXError || error is AsyncTimeout.TimeoutError)
    }
}

private enum TransportTestFailure: Error { case watchdog, blockingManagedSocket }

private func transportTestDeadline(_ milliseconds: UInt64) -> UInt64 {
    DispatchTime.now().uptimeNanoseconds + milliseconds * 1_000_000
}

private func transportTestSuppressSIGPIPE(_ descriptor: CInt) throws {
    var enabled: CInt = 1
    guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                     socklen_t(MemoryLayout<CInt>.size)) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}

private final class TransportTestPair: @unchecked Sendable {
    let scope: VMShimManagedTransport
    let descriptor: CInt
    let peer: CInt

    convenience init(milliseconds: UInt64) throws {
        try self.init(deadlineNanoseconds: transportTestDeadline(milliseconds))
    }

    init(deadlineNanoseconds: UInt64) throws {
        var descriptors: [CInt] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let scope = VMShimManagedTransport(deadlineNanoseconds: deadlineNanoseconds)
        do {
            try transportTestSuppressSIGPIPE(descriptors[1])
            try scope.adopt(descriptors[0])
        } catch {
            Darwin.close(descriptors[0])
            Darwin.close(descriptors[1])
            throw error
        }
        self.scope = scope
        descriptor = descriptors[0]
        peer = descriptors[1]
    }

    deinit {
        scope.close()
        Darwin.close(peer)
    }
}

private final class TransportTestListener: @unchecked Sendable {
    let path = "/tmp/cengine-transport-\(UUID().uuidString).sock"
    let descriptor: CInt

    init() throws {
        descriptor = try UnixSocket.listen(path: path)
    }

    deinit {
        Darwin.close(descriptor)
        unlink(path)
    }
}

private func transportTestSend(_ data: Data, to descriptor: CInt) throws {
    if data.isEmpty { return }
    let sent = data.withUnsafeBytes {
        Darwin.send(descriptor, $0.baseAddress, $0.count, MSG_DONTWAIT)
    }
    guard sent == data.count else {
        throw PeerFixtureFailure.prerequisite("fixture send did not write all bytes")
    }
}

private func transportTestReceive(_ count: Int, from descriptor: CInt) throws -> Data {
    var data = Data(count: count)
    let received = data.withUnsafeMutableBytes {
        Darwin.recv(descriptor, $0.baseAddress, $0.count, MSG_DONTWAIT)
    }
    guard received == count else {
        throw PeerFixtureFailure.prerequisite("fixture receive did not read all bytes")
    }
    return data
}

private func transportTestAssertDuplex(_ first: CInt, _ second: CInt) throws {
    try transportTestSend(Data([0x41]), to: first)
    #expect(try transportTestReceive(1, from: second) == Data([0x41]))
    try transportTestSend(Data([0x42]), to: second)
    #expect(try transportTestReceive(1, from: first) == Data([0x42]))
}

// Wait off the cooperative executor. Every event has an independent three-second
// watchdog; a broken worker cannot make the test await its Task.value forever.
private func transportTestWait(_ event: DispatchSemaphore, milliseconds: Int = 3_000) async -> Bool {
    await withCheckedContinuation { continuation in
        Thread.detachNewThread {
            continuation.resume(returning: event.wait(timeout: .now() + .milliseconds(milliseconds)) == .success)
        }
    }
}

private final class TransportTestOperationLifecycle: @unchecked Sendable {
    enum State { case notEntered, running, exited }
    private let lock = NSLock()
    private var state = State.notEntered

    func enter() { lock.withLock { state = .running } }
    func exit() { lock.withLock { state = .exited } }
    var snapshot: State { lock.withLock { state } }
}

private final class TransportTestAttempt: @unchecked Sendable {
    let entered: DispatchSemaphore
    let exited: DispatchSemaphore
    let completed: DispatchSemaphore
    let task: Task<Result<Data, any Error>, Never>
    private let scope: VMShimManagedTransport
    private let lifecycle: TransportTestOperationLifecycle

    convenience init(_ pair: TransportTestPair,
                     operation: @escaping @Sendable (VMShimManagedTransport) throws -> Data) {
        self.init(pair.scope, retaining: pair, operation: operation)
    }

    init(_ scope: VMShimManagedTransport, retaining resource: (any Sendable)? = nil,
         operation: @escaping @Sendable (VMShimManagedTransport) throws -> Data) {
        self.scope = scope
        let entered = DispatchSemaphore(value: 0)
        let exited = DispatchSemaphore(value: 0)
        let completed = DispatchSemaphore(value: 0)
        let lifecycle = TransportTestOperationLifecycle()
        self.lifecycle = lifecycle
        self.entered = entered
        self.exited = exited
        self.completed = completed
        task = Task.detached {
            // A watchdog failure must not close/reuse descriptors underneath a
            // stuck worker. The task retains its fixture until run actually joins;
            // an irreparably broken worker leaks its fixture rather than doing I/O
            // on an unrelated test's subsequently reused descriptor number.
            defer { withExtendedLifetime(resource) {} }
            let result: Result<Data, any Error>
            do {
                result = .success(try await scope.run { scope in
                    lifecycle.enter()
                    entered.signal()
                    defer { lifecycle.exit(); exited.signal() }
                    return try operation(scope)
                })
            } catch {
                result = .failure(error)
            }
            completed.signal()
            return result
        }
    }

    func result() async throws -> Result<Data, any Error> {
        guard await transportTestWait(completed) else {
            task.cancel()
            scope.cancel()
            Issue.record("managed transport exceeded the independent three-second watchdog")
            throw TransportTestFailure.watchdog
        }
        let result = await task.value
        switch lifecycle.snapshot {
        case .notEntered:
            // run checks its absolute deadline before invoking the operation. A
            // queued worker may expire there without any operation to join.
            guard case .failure(let error) = result else {
                Issue.record("managed transport succeeded without entering its operation")
                return result
            }
            #expect(error is AsyncTimeout.TimeoutError || error is CancellationError)
        case .running:
            Issue.record("managed transport completed before its operation exited")
        case .exited:
            #expect(await transportTestWait(exited, milliseconds: 0))
        }
        return result
    }

    func expectTimeout() async throws {
        let result = try await result()
        guard case .failure(let error) = result else {
            Issue.record("stalled transport unexpectedly succeeded")
            return
        }
        #expect(error is AsyncTimeout.TimeoutError)
        #expect(DispatchTime.now().uptimeNanoseconds >= scope.deadlineNanoseconds)
    }
}
#endif
