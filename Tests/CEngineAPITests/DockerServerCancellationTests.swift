import CEngineAPI
import CEngineRuntime
import Darwin
import Foundation
import Testing

@Suite struct DockerServerCancellationTests {
    @Test func alreadyCancelledWaitClosesListener() async throws {
        try await checkCancellation(cancelBeforeWaiting: true)
    }

    @Test func cancellationDuringWaitClosesListener() async throws {
        try await checkCancellation(cancelBeforeWaiting: false)
    }

    @Test func normalStopAndRepeatedWaitsComplete() async throws {
        try await withServer { server, socketPath in
            // Waiting before start retains its existing no-op semantics.
            try await server.wait()
            try await server.start()
            #expect(try connectionError(socketPath) == 0)
            let probe = WaitProbe()
            let waiter = Task { try await probe.wait(server) }
            await waitUntil { await probe.started }
            #expect(await probe.started)
            #expect(await probe.completed == false)
            try await server.stop()
            await waitUntil { await probe.completed }
            #expect(await probe.completed)
            try await waiter.value
            let closedError = try connectionError(socketPath)
            #expect(closedError == ECONNREFUSED || closedError == ENOENT)
            try await server.wait()
            try await server.wait()
            try await server.stop()
        }
    }

    private func checkCancellation(cancelBeforeWaiting: Bool) async throws {
        try await withServer { server, socketPath in
            try await server.start()
            #expect(try connectionError(socketPath) == 0)
            let probe = WaitProbe()
            let waiter = Task {
                try await probe.wait(server, cancelBeforeWaiting: cancelBeforeWaiting)
            }
            if !cancelBeforeWaiting {
                await waitUntil { await probe.started }
                #expect(await probe.started)
                // Give wait() time to suspend on the live listener's close future.
                try await Task.sleep(for: .milliseconds(100))
                #expect(await probe.completed == false)
                waiter.cancel()
            }
            await waitUntil { await probe.completed }
            // Record both failures before rescue: the old implementation must fail,
            // not hang, and returning without closing the socket must also fail.
            #expect(await probe.completed, "Cancellation must finish wait before rescue stop")
            let closedError = try connectionError(socketPath)
            #expect(closedError == ECONNREFUSED || closedError == ENOENT,
                    "Cancellation must close the listener before rescue stop")
            try await server.stop()
            try await waiter.value // Cancellation must not throw and skip caller cleanup.
            try await server.wait()
        }
    }

    private func withServer(
        operation: (DockerServer, String) async throws -> Void
    ) async throws {
        try await withDockerServerTestIsolation {
            let root = URL(filePath: "/tmp/cengine-wait-\(UUID().uuidString)", directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let socketPath = root.appending(path: "api.sock").path
            let runtime = try await EngineRuntime(root: root)
            let server = DockerServer(socketPath: socketPath, router: DockerRouter(runtime: runtime, root: root))
            do {
                try await operation(server, socketPath)
            } catch {
                try? await server.shutdown()
                throw error
            }
            try await server.shutdown()
        }
    }

    private func waitUntil(_ condition: () async -> Bool) async {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while await !condition(), ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
    }

    // Nonblocking connect proves the listening socket is closed, independently of
    // task state or whether the socket pathname has been unlinked by shutdown().
    private func connectionError(_ path: String) throws -> Int32 {
        let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { Darwin.close(descriptor) }
        guard Darwin.fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8) + [0]
        precondition(bytes.count <= MemoryLayout.size(ofValue: address.sun_path))
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: bytes)
        }
        return withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                let result = Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                return result == 0 ? 0 : errno
            }
        }
    }
}

private actor WaitProbe {
    private(set) var started = false
    private(set) var completed = false

    func wait(_ server: DockerServer, cancelBeforeWaiting: Bool = false) async throws {
        if cancelBeforeWaiting {
            withUnsafeCurrentTask { $0?.cancel() }
        }
        started = true
        defer { completed = true }
        try await server.wait()
    }
}
