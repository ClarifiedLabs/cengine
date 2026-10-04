#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

// Each socket test owns its MainActor process: unrelated suites' blocking work
// must not consume this fixture's unchanged ten-second liveness watchdog.
@Suite @MainActor struct RootFSContentStreamerTests {
    @Test func successfulTransferPreservesRequestAndLayerBytesAfterCallerClosesFD() async throws {
        await #expect(processExitsWith: .success) {
            try await RootFSContentStreamerTests().checkSuccessfulTransferPreservesRequestAndLayerBytesAfterCallerClosesFD()
        }
    }

    private func checkSuccessfulTransferPreservesRequestAndLayerBytesAfterCallerClosesFD() async throws {
        try await withRootFSTransfer { fixture in
            let contents = [Data((0..<131_071).map { UInt8($0 % 251) }), Data("second\0layer\n".utf8)]
            var layers: [OCIDescriptor] = []
            for bytes in contents {
                layers.append(try await fixture.store.put(bytes, mediaType: "application/vnd.oci.image.layer.v1.tar"))
            }
            fixture.expectEOFAtClose = true
            let transfer = fixture.start(layers: layers, rootDevice: "/dev/vdb")
            let envelope = try await fixture.sockets.request()
            #expect(envelope.version == GuestProtocol.version)
            #expect(envelope.operation == "prepare-rootfs")
            #expect(envelope.error == nil)
            #expect(!envelope.id.isEmpty)
            let request = try JSONDecoder().decode(GuestProtocol.RootFSRequest.self, from: #require(envelope.payload))
            #expect(request == GuestProtocol.RootFSRequest(rootDevice: "/dev/vdb", layers: layers.map {
                .init(mediaType: $0.mediaType, digest: $0.digest, size: $0.size)
            }))

            // No test-owned duplicate remains. Both subsequent blob reads and the
            // reply must use the descriptor retained by the production worker.
            fixture.sockets.closeCaller()
            for expected in contents {
                let actual = try await fixture.sockets.onPeer { try rootFSReadExactly($0, count: expected.count) }
                #expect(actual == expected)
            }
            #expect(fixture.registry.activeCount == 1)
            #expect(fixture.closeCount == 0)
            try await fixture.sockets.reply(to: envelope)
            try await transfer.value
            #expect(fixture.closeCount == 1)
            #expect(fixture.registry.activeCount == 0)
            // The callback's EOF assertion occurs before fixture cleanup and with
            // no shutdown: it proves the worker closed its duplicate before closeConnection.
        }
    }

    @Test(arguments: [false, true])
    func truncatedReplyAllowsMainActorStatusAndBootGateStopJoinsTransfer(duringBoot: Bool) async throws {
        // Isolate this MainActor liveness assertion from other suites' blocking
        // work. The child creates its own fixture and retains the ten-second watchdog.
        if duringBoot {
            await #expect(processExitsWith: .success) {
                try await RootFSContentStreamerTests().checkTruncatedReplyAllowsMainActorStatusAndBootGateStopJoinsTransfer(duringBoot: true)
            }
        } else {
            await #expect(processExitsWith: .success) {
                try await RootFSContentStreamerTests().checkTruncatedReplyAllowsMainActorStatusAndBootGateStopJoinsTransfer(duringBoot: false)
            }
        }
    }

    private func checkTruncatedReplyAllowsMainActorStatusAndBootGateStopJoinsTransfer(duringBoot: Bool) async throws {
        try await withRootFSTransfer { fixture in
            let gate = VMShimBootGate()
            let transfer = fixture.start(gate: duringBoot ? gate : nil)
            let envelope = try await fixture.sockets.request()
            let request = try JSONDecoder().decode(GuestProtocol.RootFSRequest.self, from: #require(envelope.payload))
            #expect(request.rootDevice == "/dev/vda")
            #expect(request.layers.isEmpty)
            fixture.sockets.closeCaller()
            try await fixture.sockets.reply(to: envelope, truncated: true)

            // A completed peer write, not a delay, establishes the deliberately
            // incomplete frame. This actor hop must run while prepare is pending.
            let heartbeat = Task { @MainActor in
                #expect(fixture.registry.activeCount == 1)
                #expect(fixture.closeCount == 0)
                #expect(!gate.isStopping)
            }
            await heartbeat.value
            try await gate.stop {
                await fixture.registry.cancelAndJoin()
                #expect(fixture.closeCount == 1)
                #expect(fixture.registry.activeCount == 0)
                fixture.stopCompleted = true
            }
            await #expect(throws: (any Error).self) { try await transfer.value }
            #expect(fixture.stopCompleted)
            #expect(fixture.closeCount == 1)
            #expect(!gate.isStopping)
            await fixture.registry.cancelAndJoin()
            #expect(fixture.closeCount == 1)

            // Give even an accidentally admitted future transfer its own owned
            // socket watchdog, so an admission regression cannot hang the suite.
            try await withRootFSTransfer { refused in
                var refusalCloses = 0
                await #expect(throws: CancellationError.self) {
                    try await fixture.registry.prepare(store: fixture.store, layers: [], descriptor: refused.sockets.callerFD) {
                        refusalCloses += 1
                        refused.sockets.closeCaller()
                    }
                }
                #expect(refusalCloses == 1)
                #expect(refused.sockets.peerHasEOF()) // No request bytes escaped the admission fence.
                #expect(fixture.registry.activeCount == 0)
            }
        }
    }

    @Test func stopJoinsBackpressuredBlobWriterWithoutPeerReadingLayer() async throws {
        // Match the truncated-reply liveness test: do not share the MainActor
        // with other suites' blocking work. Keep the child's ten-second watchdog.
        await #expect(processExitsWith: .success) {
            try await RootFSContentStreamerTests().checkStopJoinsBackpressuredBlobWriterWithoutPeerReadingLayer()
        }
    }

    private func checkStopJoinsBackpressuredBlobWriterWithoutPeerReadingLayer() async throws {
        try await withRootFSTransfer { fixture in
            var capacity: Int32 = 4_096
            #expect(setsockopt(fixture.sockets.callerFD, SOL_SOCKET, SO_SNDBUF, &capacity,
                socklen_t(MemoryLayout<Int32>.size)) == 0)
            let bytes = Data(repeating: 91, count: 2 * 1_024 * 1_024)
            let layer = try await fixture.store.put(bytes, mediaType: "application/vnd.oci.image.layer.v1.tar")
            let transfer = fixture.start(layers: [layer])
            _ = try await fixture.sockets.request()
            // Observe the first blob byte without consuming it. A two-MiB write
            // cannot complete in the explicitly bounded send buffer, and this
            // peer never reads any layer bytes or provides a rootfs reply.
            let first = try await fixture.sockets.onPeer { descriptor in
                var byte: UInt8 = 0
                guard recv(descriptor, &byte, 1, MSG_PEEK) == 1 else { throw POSIXError(.EIO) }
                return byte
            }
            #expect(first == 91)
            #expect(fixture.registry.activeCount == 1)
            #expect(fixture.closeCount == 0)
            fixture.sockets.closeCaller()
            let gate = VMShimBootGate()
            try await gate.stop { await fixture.registry.cancelAndJoin() }
            await #expect(throws: (any Error).self) { try await transfer.value }
            #expect(fixture.closeCount == 1)
            #expect(fixture.registry.activeCount == 0)
            // Also proves the OCI store actor's blocking copy call has returned.
            #expect(try await fixture.store.data(for: layer.digest) == bytes)
        }
    }

    @Test func callerCancellationJoinsTruncatedReplyAndClosesConnectionExactlyOnce() async throws {
        await #expect(processExitsWith: .success) {
            try await RootFSContentStreamerTests().checkCallerCancellationJoinsTruncatedReplyAndClosesConnectionExactlyOnce()
        }
    }

    private func checkCallerCancellationJoinsTruncatedReplyAndClosesConnectionExactlyOnce() async throws {
        try await withRootFSTransfer { fixture in
            let transfer = fixture.start()
            let envelope = try await fixture.sockets.request()
            fixture.sockets.closeCaller()
            try await fixture.sockets.reply(to: envelope, truncated: true)
            #expect(fixture.registry.activeCount == 1)
            #expect(fixture.closeCount == 0)
            transfer.cancel()
            await #expect(throws: (any Error).self) { try await transfer.value }
            #expect(fixture.closeCount == 1)
            #expect(fixture.registry.activeCount == 0)
            #expect(fixture.sockets.peerHasEOF())
            await fixture.registry.cancelAndJoin()
            #expect(fixture.closeCount == 1)
        }
    }

    @Test(arguments: [false, true])
    func invalidReplyFailsAndJoinsWorker(guestFailure: Bool) async throws {
        if guestFailure {
            await #expect(processExitsWith: .success) {
                try await RootFSContentStreamerTests().checkInvalidReplyFailsAndJoinsWorker(guestFailure: true)
            }
        } else {
            await #expect(processExitsWith: .success) {
                try await RootFSContentStreamerTests().checkInvalidReplyFailsAndJoinsWorker(guestFailure: false)
            }
        }
    }

    private func checkInvalidReplyFailsAndJoinsWorker(guestFailure: Bool) async throws {
        try await withRootFSTransfer { fixture in
            let transfer = fixture.start()
            let envelope = try await fixture.sockets.request()
            fixture.sockets.closeCaller()
            fixture.expectEOFAtClose = true
            let reply = GuestProtocol.Envelope(
                id: guestFailure ? envelope.id : "wrong-request-id",
                operation: envelope.operation,
                error: guestFailure ? .init(code: "unpack_failed", message: "layer rejected") : nil
            )
            let bytes = try GuestProtocol.encode(reply)
            try await fixture.sockets.onPeer { try rootFSWriteAll($0, bytes: bytes) }
            await #expect(throws: EngineError.self) { try await transfer.value }
            #expect(fixture.closeCount == 1)
            #expect(fixture.registry.activeCount == 0)
        }
    }
}

// All blocking peer I/O runs on dedicated threads. Every operation is awaited;
// there is no semaphore, polling deadline, or abandoned task on the MainActor.
@MainActor private func withRootFSTransfer(
    _ operation: @MainActor (RootFSTestFixture) async throws -> Void
) async throws {
    let fixture = try RootFSTestFixture()
    do {
        try await operation(fixture)
        await fixture.finish()
    } catch {
        await fixture.finish()
        throw error
    }
}

@MainActor private final class RootFSTestFixture {
    let root: URL
    let store: OCIContentStore
    let sockets: RootFSTestSocketPair
    let registry = RootFSContentTransfers()
    var closeCount = 0
    var expectEOFAtClose = false
    var stopCompleted = false
    private var transfer: Task<Void, Error>?
    private let watchdog: Task<Void, Never>
    private let watchdogFired = RootFSTestWatchdogState()

    init() throws {
        root = FileManager.default.temporaryDirectory.appending(path: "rootfs-stream-test-\(UUID())")
        store = try OCIContentStore(root: root)
        sockets = try RootFSTestSocketPair()
        let sockets = sockets, fired = watchdogFired
        watchdog = Task.detached {
            do { try await Task.sleep(for: .seconds(10)) } catch { return }
            fired.value.withLock { $0 = true }
            // Only owned FDs are shut down, never closed from the watchdog. This
            // unblocks an accidental MainActor read too; finish still joins all I/O.
            sockets.shutdown()
        }
    }

    func start(layers: [OCIDescriptor] = [], rootDevice: String = "/dev/vda",
               gate: VMShimBootGate? = nil) -> Task<Void, Error> {
        precondition(transfer == nil)
        let task = Task { @MainActor in
            let prepare: @MainActor @Sendable () async throws -> Void = {
                try await self.registry.prepare(store: self.store, layers: layers,
                    rootDevice: rootDevice, descriptor: self.sockets.callerFD) {
                    #expect(!self.stopCompleted)
                    if self.expectEOFAtClose { #expect(self.sockets.peerHasEOF()) }
                    self.closeCount += 1
                    self.sockets.closeCaller()
                }
            }
            if let gate { try await gate.boot(prepare) } else { try await prepare() }
        }
        transfer = task
        return task
    }

    func finish() async {
        sockets.shutdown()
        transfer?.cancel()
        if let transfer { _ = await transfer.result }
        await registry.cancelAndJoin()
        watchdog.cancel()
        await watchdog.value
        // A deadline is failure plus cleanup, NEVER evidence of cancellation or join.
        #expect(!watchdogFired.value.withLock { $0 }, "socket test watchdog fired")
        transfer = nil
        try? FileManager.default.removeItem(at: root)
    }
}

private final class RootFSTestWatchdogState: Sendable {
    let value = Mutex(false)
}

private final class RootFSTestSocketPair: @unchecked Sendable {
    private let caller: Mutex<Int32>
    private let peer: Int32

    init() throws {
        var descriptors: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { throw POSIXError(.EIO) }
        for descriptor in descriptors {
            var enabled: Int32 = 1
            guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                             socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                descriptors.forEach { _ = Darwin.close($0) }
                throw POSIXError(.EIO)
            }
        }
        caller = Mutex(descriptors[0])
        peer = descriptors[1]
    }

    deinit {
        closeCaller()
        _ = Darwin.close(peer)
    }

    var callerFD: Int32 { caller.withLock { $0 } }

    func closeCaller() {
        caller.withLock {
            if $0 >= 0 { _ = Darwin.close($0); $0 = -1 }
        }
    }

    func shutdown() {
        caller.withLock { if $0 >= 0 { _ = Darwin.shutdown($0, SHUT_RDWR) } }
        _ = Darwin.shutdown(peer, SHUT_RDWR)
    }

    func peerHasEOF() -> Bool {
        var byte: UInt8 = 0
        return recv(peer, &byte, 1, MSG_PEEK | MSG_DONTWAIT) == 0
    }

    func onPeer<T: Sendable>(_ operation: @escaping @Sendable (Int32) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread { [self] in
                do { continuation.resume(returning: try operation(peer)) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    func request() async throws -> GuestProtocol.Envelope {
        try await onPeer { descriptor in
            let prefix = try rootFSReadExactly(descriptor, count: 4)
            let count = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard count > 0, count <= GuestProtocol.maximumControlFrameSize else { throw POSIXError(.EINVAL) }
            return try GuestProtocol.decode(prefix + rootFSReadExactly(descriptor, count: Int(count)))
        }
    }

    func reply(to request: GuestProtocol.Envelope, truncated: Bool = false) async throws {
        let frame = try GuestProtocol.encode(.init(id: request.id, operation: request.operation))
        // Include the full length prefix and one body byte, but keep the peer open.
        let bytes = truncated ? Data(frame.prefix(5)) : frame
        try await onPeer { try rootFSWriteAll($0, bytes: bytes) }
    }
}

private func rootFSReadExactly(_ descriptor: Int32, count: Int) throws -> Data {
    var bytes = Data(count: count)
    var offset = 0
    while offset < count {
        let readCount = bytes.withUnsafeMutableBytes {
            recv(descriptor, $0.baseAddress!.advanced(by: offset), count - offset, 0)
        }
        if readCount < 0, errno == EINTR { continue }
        guard readCount > 0 else { throw POSIXError(.EIO) }
        offset += readCount
    }
    return bytes
}

private func rootFSWriteAll(_ descriptor: Int32, bytes: Data) throws {
    var offset = 0
    while offset < bytes.count {
        let written = bytes.withUnsafeBytes {
            send(descriptor, $0.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
        }
        if written < 0, errno == EINTR { continue }
        guard written > 0 else { throw POSIXError(.EIO) }
        offset += written
    }
}
#endif
