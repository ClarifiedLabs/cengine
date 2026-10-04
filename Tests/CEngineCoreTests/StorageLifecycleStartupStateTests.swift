#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct StorageLifecycleStartupStateTests {
    @Test func strictTwoPhaseStartupNeverAdoptsReadyMetadata() throws {
        var state = StorageLifecycleStartupState()
        #expect(throws: (any Error).self) { try state.requireReady() }
        #expect(throws: (any Error).self) { try state.beginService() }
        #expect(throws: (any Error).self) { try state.diskReady() }
        try state.beginDisk()
        #expect(throws: (any Error).self) { try state.beginDisk() }
        #expect(throws: (any Error).self) { try state.serviceReady() }
        try state.diskReady()
        #expect(throws: (any Error).self) { try state.diskReady() }
        try state.beginService()
        #expect(throws: (any Error).self) { try state.beginService() }
        try state.serviceReady()
        try state.requireReady()
        #expect(throws: (any Error).self) { try state.serviceReady() }
    }
    @Test(arguments: 0...4)
    func cancellationIsTerminalAtEveryAwaitBoundary(completedSteps: Int) throws {
        var state = StorageLifecycleStartupState()
        if completedSteps >= 1 { try state.beginDisk() }
        if completedSteps >= 2 { try state.diskReady() }
        if completedSteps >= 3 { try state.beginService() }
        if completedSteps >= 4 { try state.serviceReady() }
        state.terminate(); state.terminate()
        #expect(state.phase == .terminal)
        #expect(throws: (any Error).self) { try state.beginDisk() }
        #expect(throws: (any Error).self) { try state.diskReady() }
        #expect(throws: (any Error).self) { try state.beginService() }
        #expect(throws: (any Error).self) { try state.serviceReady() }
        #expect(throws: (any Error).self) { try state.requireReady() }
    }
    @Test func terminationDuringResponderStartupRevokesBeforePublication() async throws {
        let gate = StorageLifecycleShimRevocation(), installed = AsyncStream<Void>.makeStream()
        let release = DispatchSemaphore(value: 0), closed = Mutex(false), published = Mutex(false)
        let worker = Task.detached {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                // A blocked responder owns a real thread, not a cooperative
                // executor slot needed by the test's cancellation driver.
                Thread.detachNewThread {
                    let result = Result {
                        try gate.hold(.fresh) { closed.withLock { $0 = true } }
                        installed.continuation.yield(())
                        installed.continuation.finish()
                        release.wait()
                        // Models responder.start's own-gate check after registration.
                        if !closed.withLock({ $0 }) { published.withLock { $0 = true } }
                    }
                    installed.continuation.finish()
                    continuation.resume(with: result)
                }
            }
        }
        defer { release.signal() }
        var didInstall = false
        for await _ in installed.stream { didInstall = true; break }
        #expect(didInstall)
        gate.close()
        release.signal()
        try await worker.value
        #expect(closed.withLock { $0 })
        #expect(!published.withLock { $0 })
        let lateClosed = Mutex(false)
        #expect(throws: (any Error).self) { try gate.hold(.service) { lateClosed.withLock { $0 = true } } }
        #expect(lateClosed.withLock { $0 })
    }
    @Test func streamRevocationShutsDownTransferredDuplicates() throws {
        var pair: [Int32] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        defer { for fd in pair where fd >= 0 { Darwin.close(fd) } }
        let alias = fcntl(pair[0], F_DUPFD_CLOEXEC, 0)
        #expect(alias >= 0)
        defer { if alias >= 0 { Darwin.close(alias) } }
        var byte: UInt8 = 1
        #expect(send(pair[1], &byte, 1, 0) == 1)
        #expect(recv(alias, &byte, 1, 0) == 1)
        StorageLifecycleShimRevocation.revokeStream(pair[0])
        #expect(recv(alias, &byte, 1, MSG_DONTWAIT) == 0)
        #expect(recv(pair[1], &byte, 1, MSG_DONTWAIT) == 0)
    }
    @Test func unsignedShimCannotAuthenticateBeforeStartingVZ() async throws {
        // This runs the real native preflight, without creating or starting a VM.
        let result = await Task.detached {
            Result { _ = try StorageLifecycleFreshShim.authenticatedParent(parentFD: -1) }
        }.value
        if case .success = result { Issue.record("unsigned shim or invalid inherited parent accepted") }
    }
}
#endif
