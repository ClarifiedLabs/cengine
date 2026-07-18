import Foundation
import Testing
@testable import CEngineCore
#if os(macOS)
import Darwin
@testable import CEngineRuntime

private final class ShimDescriptorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: CInt?

    func store(_ descriptor: CInt) { lock.withLock { value = descriptor } }
    func load() -> CInt? { lock.withLock { value } }
}

private func blockingSemaphoreWait(_ semaphore: DispatchSemaphore) -> Bool {
    semaphore.wait(timeout: .now() + 2) == .success
}

private func semaphoreArrives(_ semaphore: DispatchSemaphore) async -> Bool {
    await Task.detached { blockingSemaphoreWait(semaphore) }.value
}
#endif

@Suite struct VMShimProtocolTests {
    @Test func envelopeRoundTrips() throws {
        let envelope = VMShimProtocol.Envelope(token: "secret", operation: .status)

        #expect(try VMShimProtocol.decode(VMShimProtocol.encode(envelope)) == envelope)
    }

    @Test func envelopeRequiresAuthenticationToken() throws {
        let frame = try VMShimProtocol.encode(.init(token: "", operation: .status))

        #expect(throws: EngineError.self) { try VMShimProtocol.decode(frame) }
    }

    @Test func shimSpecificationPersistsVolumeDisks() throws {
        let specification = VMShimProtocol.Specification(
            containerID: "volume-container",
            generation: 1,
            token: "secret",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            volumeDisks: [.init(name: "data", path: "/data.ext4")],
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:04",
            socketRelays: [.init(path: "/tmp/docker.sock", port: GuestProtocol.socketProxyPortBase)],
            socketPath: "/tmp/control.sock",
            logPath: "/tmp/shim.log"
        )

        let data = try JSONEncoder().encode(specification)
        #expect(try JSONDecoder().decode(VMShimProtocol.Specification.self, from: data) == specification)
    }

    @Test func managementVLANIsReservedFromDockerNetworks() {
        #expect(VMShimProtocol.managementVLAN == 4_094)
        #if os(macOS)
        #expect(RawVirtualizationBackend.nextAvailableVLAN(used: Set(1..<VMShimProtocol.managementVLAN)) == nil)
        #expect(RawVirtualizationBackend.nextAvailableVLAN(used: []) == 1)
        #endif
    }

    #if os(macOS)
    @Test func execContextInheritsImageThenContainerDefaults() {
        let context = RawVirtualizationBackend.resolveExecContext(
            configuration: .init(arguments: ["env"]),
            containerEnvironment: ["SHARED=container", "CONTAINER=1"],
            containerWorkingDirectory: "",
            containerUser: "",
            containerPrivileged: false,
            imageEnvironment: ["IMAGE=1", "SHARED=image"],
            imageWorkingDirectory: "/image-work",
            imageUser: "image-user"
        )

        #expect(context.environment == ["IMAGE=1", "SHARED=container", "CONTAINER=1"])
        #expect(context.workingDirectory == "/image-work")
        #expect(context.user == .init(username: "image-user"))
        #expect(context.noNewPrivileges)
        #expect(!context.privileged)
    }

    @Test func execContextExplicitValuesOverrideContainerAndImage() {
        let context = RawVirtualizationBackend.resolveExecContext(
            configuration: .init(
                arguments: ["env"], environment: ["SHARED=exec", "EXEC=1"],
                workingDirectory: "/exec-work", user: "2000:3000", privileged: true
            ),
            containerEnvironment: ["SHARED=container", "CONTAINER=1"],
            containerWorkingDirectory: "/container-work",
            containerUser: "1000:1000",
            containerPrivileged: false,
            imageEnvironment: ["IMAGE=1", "SHARED=image"],
            imageWorkingDirectory: "/image-work",
            imageUser: "image-user"
        )

        #expect(context.environment == [
            "IMAGE=1", "SHARED=exec", "CONTAINER=1", "EXEC=1",
        ])
        #expect(context.workingDirectory == "/exec-work")
        #expect(context.user == .init(uid: 2_000, gid: 3_000))
        #expect(!context.noNewPrivileges)
        #expect(context.privileged)
    }

    @Test func defaultExecInheritsContainerPrivilege() {
        let context = RawVirtualizationBackend.resolveExecContext(
            configuration: .init(arguments: ["id"]),
            containerEnvironment: [],
            containerWorkingDirectory: "",
            containerUser: "",
            containerPrivileged: true,
            imageEnvironment: [],
            imageWorkingDirectory: nil,
            imageUser: nil
        )

        #expect(context.privileged)
        #expect(!context.noNewPrivileges)
    }

    @Test func blockVolumesUseTheReportedSparseCapacity() {
        #expect(VolumeRecord.defaultSizeBytes == 512 * 1_024 * 1_024 * 1_024)
        #expect(RawVirtualizationBackend.defaultVolumeDiskBytes == VolumeRecord.defaultSizeBytes)
        #expect(RawVirtualizationBackend.defaultStorageDiskBytes == VolumeRecord.defaultSizeBytes)
    }

    @Test func multiContainerVolumesUseSharedStorageBeforeVMsStart() throws {
        let modes = try RawVirtualizationBackend.resolveVolumeStorageModes(
            names: ["compose-data", "buildkit-state"],
            referenceCounts: ["compose-data": 2, "buildkit-state": 1],
            existing: [:]
        )

        #expect(modes["compose-data"] == .shared)
        #expect(modes["buildkit-state"] == .block)
        #expect(throws: EngineError.self) {
            try RawVirtualizationBackend.resolveVolumeStorageModes(
                names: ["buildkit-state"],
                referenceCounts: ["buildkit-state": 2],
                existing: ["buildkit-state": .block]
            )
        }
    }
    #endif

    #if os(macOS)
    @Test func managementAddressesStayInsideIsolatedSubnetAndAvoidServer() {
        let address = RawVirtualizationBackend.managementAddress(for: "container-id")
        #expect(address.hasPrefix("100."))
        #expect(address.hasSuffix("/10"))
        #expect(address != "100.64.0.1/10")
    }
    #endif

    #if os(macOS)
    @Test func runtimeSocketsRemainBelowDarwinPathLimitForLongDataRoots() throws {
        let socket = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let longRoot = "/tmp/" + String(repeating: "nested-data-root/", count: 20)
        let specification = VMShimProtocol.Specification(
            containerID: "long-root",
            generation: 1,
            token: "secret",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "\(longRoot)/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:02",
            socketPath: socket,
            logPath: "\(longRoot)/shim.log"
        )

        #expect(socket.utf8.count < 104)
        #expect(socket.hasPrefix("/tmp/cengine-\(getuid())/"))
        #expect(
            VMShimClient.specificationURL(for: specification).path
                == URL(filePath: longRoot).appending(path: "shim.json").path
        )
    }

    @Test func rawKernelCommandLineKeepsVirtioPCIEnabled() {
        let commandLine = RawVirtualMachineConfiguration.kernelCommandLine(
            id: "test-container",
            kernelArguments: []
        )
        let arguments = commandLine.split(separator: " ")

        #expect(arguments.contains("console=hvc0"))
        #expect(arguments.contains("cengine.id=test-container"))
        #expect(!arguments.contains("pci=off"))
    }

    @Test func dockerVolumesMapAfterTheRootVirtioBlockDevice() throws {
        #expect(try RawVirtualizationBackend.volumeDevicePath(index: 0) == "/dev/vdb")
        #expect(try RawVirtualizationBackend.volumeDevicePath(index: 24) == "/dev/vdz")
        #expect(throws: EngineError.self) { try RawVirtualizationBackend.volumeDevicePath(index: 25) }
    }

    @MainActor @Test func containerShutdownDoesNotOwnInfrastructureTransportSockets() {
        func specification(kind: VMShimProtocol.Specification.Kind) -> VMShimProtocol.Specification {
            VMShimProtocol.Specification(
                kind: kind,
                containerID: "socket-owner",
                generation: 1,
                token: "secret",
                kernelPath: "/kernel",
                initialRamdiskPath: "/initramfs",
                rootDiskPath: "/root.ext4",
                cpus: 1,
                memoryBytes: 268_435_456,
                macAddress: "02:ce:00:00:00:03",
                socketPath: "/tmp/control.sock",
                logPath: "/tmp/shim.log",
                fileSystemSocketPath: "/tmp/filesystem.sock",
                networkSocketPath: "/tmp/network.sock"
            )
        }

        #expect(VMShimServer.ownedSocketPaths(specification(kind: .container)) == ["/tmp/control.sock"])
        #expect(Set(VMShimServer.ownedSocketPaths(specification(kind: .storage))) == [
            "/tmp/control.sock", "/tmp/filesystem.sock", "/tmp/network.sock",
        ])
    }

    @MainActor @Test func virtioSocketAttemptsHaveABoundedDeadline() async {
        await #expect(throws: EngineError.self) {
            try await RawContainerVirtualMachine.awaitConnection(timeout: .milliseconds(1)) { _ in }
        }
    }

    @Test func timeoutCancelsTheLosingOperation() async {
        let (cancellations, continuation) = AsyncStream<Void>.makeStream()
        await #expect(throws: AsyncTimeout.TimeoutError.self) {
            try await AsyncTimeout.run(for: .milliseconds(10)) {
                do {
                    try await Task.sleep(for: .seconds(30))
                    return true
                } catch {
                    continuation.yield()
                    continuation.finish()
                    throw error
                }
            }
        }
        var iterator = cancellations.makeAsyncIterator()
        #expect(await iterator.next() != nil)
    }

    @Test func callerCancellationPromptlyEscapesANoncooperativeTimedOperation() async {
        let (startStream, startContinuation) = AsyncStream<Void>.makeStream()
        let (releaseStream, releaseContinuation) = AsyncStream<Void>.makeStream()
        let (observationStream, observationContinuation) = AsyncStream<Bool>.makeStream()
        let task = Task {
            try await AsyncTimeout.run(for: .seconds(30)) {
                startContinuation.yield()
                var releaseIterator = releaseStream.makeAsyncIterator()
                _ = await releaseIterator.next() // Deliberately ignores cancellation.
                observationContinuation.yield(Task.isCancelled)
                observationContinuation.finish()
                return true
            }
        }
        var startIterator = startStream.makeAsyncIterator()
        _ = await startIterator.next()

        let clock = ContinuousClock()
        let cancelledAt = clock.now
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("cancelled timeout unexpectedly returned a value")
        } catch is CancellationError {
            // Expected: caller cancellation wins independently of the child.
        } catch {
            Issue.record("cancelled timeout threw \(error) instead of CancellationError")
        }
        #expect(clock.now - cancelledAt < .seconds(1))

        releaseContinuation.yield()
        releaseContinuation.finish()
        var observationIterator = observationStream.makeAsyncIterator()
        #expect(await observationIterator.next() == true)
    }

    @Test func descriptorInvalidationCannotShutdownAReusedUnrelatedSocket() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let socketPath = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let listener = try UnixSocket.listen(path: socketPath)
        defer { Darwin.close(listener) }
        let requestReceived = DispatchSemaphore(value: 0)
        let sendResponse = DispatchSemaphore(value: 0)
        let invalidationEntered = DispatchSemaphore(value: 0)
        let releaseInvalidation = DispatchSemaphore(value: 0)
        let descriptorReleaseAttempted = DispatchSemaphore(value: 0)
        let invalidationFinished = DispatchSemaphore(value: 0)
        let invalidatedDescriptor = ShimDescriptorBox()
        let specification = VMShimProtocol.Specification(
            containerID: "descriptor-owner",
            generation: 11,
            token: "test-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:11",
            socketPath: socketPath,
            logPath: root.appending(path: "shim.log").path
        )

        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            let file = FileHandle(fileDescriptor: peer, closeOnDealloc: false)
            let prefix = file.readData(ofLength: 4)
            guard prefix.count == 4 else { return }
            let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let body = file.readData(ofLength: Int(size))
            guard let request = try? VMShimProtocol.decode(prefix + body) else { return }
            requestReceived.signal()
            sendResponse.wait()
            let payload = try! JSONEncoder().encode(true)
            let response = VMShimProtocol.Envelope(
                id: request.id,
                token: specification.token,
                operation: request.operation,
                payload: payload
            )
            try? file.write(contentsOf: VMShimProtocol.encode(response))
        }

        let client = VMShimClient(
            specification: specification,
            descriptorInvalidationHook: { descriptor in
                invalidatedDescriptor.store(descriptor)
                invalidationEntered.signal()
                releaseInvalidation.wait()
            },
            descriptorReleaseHook: { _ in descriptorReleaseAttempted.signal() }
        )
        let request = Task {
            try await client.guest(operation: "descriptor-test", payload: false, response: Bool.self)
        }
        #expect(await semaphoreArrives(requestReceived))
        DispatchQueue.global().async {
            client.invalidateRequests()
            invalidationFinished.signal()
        }
        #expect(await semaphoreArrives(invalidationEntered))
        sendResponse.signal()
        #expect(await semaphoreArrives(descriptorReleaseAttempted))

        var unrelated = [CInt](repeating: -1, count: 2)
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &unrelated) == 0)
        defer { unrelated.forEach { Darwin.close($0) } }
        let original = try #require(invalidatedDescriptor.load())
        #expect(!unrelated.contains(original))

        releaseInvalidation.signal()
        #expect(await semaphoreArrives(invalidationFinished))
        #expect(try await request.value)
        var sent: UInt8 = 0x5a
        var received: UInt8 = 0
        #expect(Darwin.write(unrelated[0], &sent, 1) == 1)
        #expect(Darwin.read(unrelated[1], &received, 1) == 1)
        #expect(received == sent)
    }

    @Test func unresponsiveShimTerminationAbortsItsSocketAndMeetsTheDeadline() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let socketPath = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let listener = try UnixSocket.listen(path: socketPath)
        defer { Darwin.close(listener) }

        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            var buffer = [UInt8](repeating: 0, count: 4_096)
            while Darwin.read(peer, &buffer, buffer.count) > 0 {}
        }

        let process = Process()
        process.executableURL = URL(filePath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        defer { if process.isRunning { process.terminate() } }
        Thread.detachNewThread {
            process.waitUntilExit()
        }

        let specification = VMShimProtocol.Specification(
            containerID: "wedged-shim",
            generation: 7,
            token: "test-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:07",
            socketPath: socketPath,
            logPath: root.appending(path: "shim.log").path
        )
        let status = VMShimProtocol.Status(
            containerID: specification.containerID,
            generation: specification.generation,
            state: .paused,
            processIdentifier: process.processIdentifier,
            processStartTime: try #require(
                VMShimClient.processStartTime(for: process.processIdentifier)
            )
        )
        try JSONEncoder().encode(status).write(
            to: URL(filePath: socketPath + ".status"), options: .atomic
        )

        let client = VMShimClient(specification: specification)
        let clock = ContinuousClock()
        let started = clock.now
        try await client.terminate(gracePeriodMilliseconds: 100, forceWaitMilliseconds: 1_000)

        #expect(clock.now - started < .seconds(2))
        #expect(!process.isRunning)
    }

    @Test func staleShimStatusCannotKillAReusedProcessIdentifier() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let socketPath = try RawVirtualizationBackend.makeRuntimeSocketPath()
        let listener = try UnixSocket.listen(path: socketPath)
        defer { Darwin.close(listener) }
        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            var buffer = [UInt8](repeating: 0, count: 4_096)
            while Darwin.read(peer, &buffer, buffer.count) > 0 {}
        }

        let unrelated = Process()
        unrelated.executableURL = URL(filePath: "/bin/sleep")
        unrelated.arguments = ["30"]
        try unrelated.run()
        defer { if unrelated.isRunning { unrelated.terminate() } }
        Thread.detachNewThread { unrelated.waitUntilExit() }
        let actualStart = try #require(
            VMShimClient.processStartTime(for: unrelated.processIdentifier)
        )
        let specification = VMShimProtocol.Specification(
            containerID: "stale-shim",
            generation: 17,
            token: "test-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: "/root.ext4",
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:17",
            socketPath: socketPath,
            logPath: root.appending(path: "shim.log").path
        )
        let stale = VMShimProtocol.Status(
            containerID: specification.containerID,
            generation: specification.generation,
            state: .paused,
            processIdentifier: unrelated.processIdentifier,
            processStartTime: actualStart &+ 1
        )
        try JSONEncoder().encode(stale).write(
            to: URL(filePath: socketPath + ".status"), options: .atomic
        )

        let client = VMShimClient(specification: specification)
        await #expect(throws: EngineError.self) {
            try await client.terminate(gracePeriodMilliseconds: 50, forceWaitMilliseconds: 50)
        }
        #expect(unrelated.isRunning)
        #expect(VMShimClient.processStartTime(for: unrelated.processIdentifier) == actualStart)
    }
    #endif
}
