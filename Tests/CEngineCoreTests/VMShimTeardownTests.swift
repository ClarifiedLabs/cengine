import Foundation
import Testing
@testable import CEngineCore
#if os(macOS)
import Darwin
@testable import CEngineRuntime

@Suite struct VMShimTeardownTests {
    @Test func uninstallTerminatesContainerAndInfrastructureShimsBeforeZap() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/owned-container")
        let infrastructureDirectory = root.appending(path: "infrastructure")
        try FileManager.default.createDirectory(
            at: containerDirectory, withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: infrastructureDirectory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let executable = try buildIdleShimExecutable(in: root)
        let rootDisk = containerDirectory.appending(path: "root.ext4")
        let rootDiskContents = Data("preserved container data".utf8)
        try rootDiskContents.write(to: rootDisk)
        let container = ContainerRecord(
            id: "owned-container", name: "owned-container", image: "alpine"
        )
        let containerSpecification = VMShimProtocol.Specification(
            containerID: container.id,
            generation: 3,
            token: "container-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs",
            rootDiskPath: rootDisk.path,
            cpus: 1,
            memoryBytes: 268_435_456,
            macAddress: "02:ce:00:00:00:03",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: containerDirectory.appending(path: "shim.log").path
        )
        let spawn = try VMShimClient.preparePersistentSpawn(
            specification: containerSpecification,
            container: container,
            generationsDirectory: RawVirtualizationBackend.generationsDirectory(
                for: containerDirectory
            ),
            executable: executable
        )
        let containerProcess = Process()
        containerProcess.executableURL = executable
        containerProcess.arguments = [
            "vm-shim", "--spec", spawn.specificationURL.path,
            "--launch-intent", spawn.intentURL.path,
        ]
        try containerProcess.run()
        Thread.detachNewThread { containerProcess.waitUntilExit() }
        defer { if containerProcess.isRunning { containerProcess.terminate() } }

        let infrastructureSpecification = VMShimProtocol.Specification(
            kind: .storage,
            containerID: "cengine-storage",
            generation: 1,
            token: "infrastructure-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/storage-initramfs",
            rootDiskPath: infrastructureDirectory.appending(path: "volumes.ext4").path,
            cpus: 2,
            memoryBytes: 1_073_741_824,
            macAddress: "02:ce:00:00:00:01",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: infrastructureDirectory.appending(path: "shim.log").path
        )
        try JSONEncoder().encode(infrastructureSpecification).write(
            to: infrastructureDirectory.appending(path: "shim.json")
        )
        defer {
            try? FileManager.default.removeItem(
                atPath: infrastructureSpecification.socketPath
            )
            try? FileManager.default.removeItem(
                atPath: infrastructureSpecification.socketPath + ".status"
            )
        }
        let listener = try UnixSocket.listen(path: infrastructureSpecification.socketPath)
        defer { Darwin.close(listener) }
        Thread.detachNewThread {
            guard let peer = try? UnixSocket.accept(listener) else { return }
            defer { Darwin.close(peer) }
            let file = FileHandle(fileDescriptor: peer, closeOnDealloc: false)
            let prefix = file.readData(ofLength: 4)
            guard prefix.count == 4 else { return }
            let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let body = file.readData(ofLength: Int(size))
            guard let request = try? VMShimProtocol.decode(prefix + body),
                  request.token == infrastructureSpecification.token,
                  request.operation == .shutdown else { return }
            let status = VMShimProtocol.Status(
                containerID: infrastructureSpecification.containerID,
                generation: infrastructureSpecification.generation,
                state: .stopped,
                processIdentifier: getpid()
            )
            let response = VMShimProtocol.Envelope(
                id: request.id,
                token: infrastructureSpecification.token,
                operation: request.operation,
                payload: try! JSONEncoder().encode(status)
            )
            try? file.write(contentsOf: VMShimProtocol.encode(response))
        }

        let stopped = try await VMShimTeardown.terminateAll(
            in: root,
            expectedExecutable: executable,
            gracePeriodMilliseconds: 1_000,
            forceWaitMilliseconds: 1_000
        )

        #expect(stopped == 2)
        #expect(VMShimClient.processStartTime(for: containerProcess.processIdentifier) == nil)
        #expect(try Data(contentsOf: rootDisk) == rootDiskContents)
        #expect(FileManager.default.fileExists(atPath: spawn.intentURL.path))
    }

    @Test func infrastructureStatusCannotCauseForeignProcessTermination() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let infrastructureDirectory = root.appending(path: "infrastructure")
        try FileManager.default.createDirectory(
            at: infrastructureDirectory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let foreignProcess = Process()
        foreignProcess.executableURL = URL(filePath: "/bin/sleep")
        foreignProcess.arguments = ["30"]
        try foreignProcess.run()
        Thread.detachNewThread { foreignProcess.waitUntilExit() }
        defer { if foreignProcess.isRunning { foreignProcess.terminate() } }
        let startTime = try #require(
            VMShimClient.processStartTime(for: foreignProcess.processIdentifier)
        )
        let specification = VMShimProtocol.Specification(
            kind: .storage,
            containerID: "cengine-storage",
            generation: 1,
            token: "infrastructure-token",
            kernelPath: "/kernel",
            initialRamdiskPath: "/storage-initramfs",
            rootDiskPath: infrastructureDirectory.appending(path: "volumes.ext4").path,
            cpus: 2,
            memoryBytes: 1_073_741_824,
            macAddress: "02:ce:00:00:00:01",
            socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
            logPath: infrastructureDirectory.appending(path: "shim.log").path
        )
        try JSONEncoder().encode(specification).write(
            to: infrastructureDirectory.appending(path: "shim.json")
        )
        defer {
            try? FileManager.default.removeItem(atPath: specification.socketPath)
            try? FileManager.default.removeItem(atPath: specification.socketPath + ".status")
        }
        try JSONEncoder().encode(VMShimProtocol.Status(
            containerID: specification.containerID,
            generation: specification.generation,
            state: .running,
            processIdentifier: foreignProcess.processIdentifier,
            processStartTime: startTime
        )).write(to: URL(filePath: specification.socketPath + ".status"))

        do {
            _ = try await VMShimTeardown.terminateAll(
                in: root,
                gracePeriodMilliseconds: 10,
                forceWaitMilliseconds: 10
            )
            Issue.record("teardown unexpectedly accepted an unreachable infrastructure shim")
        } catch {
            // The warning is expected; the untrusted PID must remain untouched.
        }
        #expect(VMShimClient.processStartTime(for: foreignProcess.processIdentifier) == startTime)
    }

    @Test func quarantinedGenerationDoesNotBlockOwnedShimTermination() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let containerDirectory = root.appending(path: "containers/owned-container")
        try FileManager.default.createDirectory(
            at: containerDirectory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let executable = try buildIdleShimExecutable(in: root)
        let container = ContainerRecord(
            id: "owned-container", name: "owned-container", image: "alpine"
        )
        func specification(generation: UInt64) throws -> VMShimProtocol.Specification {
            VMShimProtocol.Specification(
                containerID: container.id,
                generation: generation,
                token: "container-token-\(generation)",
                kernelPath: "/kernel",
                initialRamdiskPath: "/initramfs",
                rootDiskPath: containerDirectory.appending(path: "root.ext4").path,
                cpus: 1,
                memoryBytes: 268_435_456,
                macAddress: "02:ce:00:00:00:03",
                socketPath: try RawVirtualizationBackend.makeRuntimeSocketPath(),
                logPath: containerDirectory.appending(path: "shim.log").path
            )
        }
        let generations = RawVirtualizationBackend.generationsDirectory(
            for: containerDirectory
        )
        let live = try VMShimClient.preparePersistentSpawn(
            specification: specification(generation: 3),
            container: container,
            generationsDirectory: generations,
            executable: executable
        )
        let process = Process()
        process.executableURL = executable
        process.arguments = [
            "vm-shim", "--spec", live.specificationURL.path,
            "--launch-intent", live.intentURL.path,
        ]
        try process.run()
        Thread.detachNewThread { process.waitUntilExit() }
        defer { if process.isRunning { process.terminate() } }

        let malformed = try VMShimClient.preparePersistentSpawn(
            specification: specification(generation: 4),
            container: container,
            generationsDirectory: generations,
            executable: executable
        )
        try Data("not-json".utf8).write(to: malformed.recordURL)

        await #expect(throws: EngineError.self) {
            _ = try await VMShimTeardown.terminateAll(
                in: root,
                expectedExecutable: executable,
                gracePeriodMilliseconds: 0,
                forceWaitMilliseconds: 1_000
            )
        }
        #expect(VMShimClient.processStartTime(for: process.processIdentifier) == nil)
        #expect(FileManager.default.fileExists(atPath: malformed.directory.path))
    }
}

private func buildIdleShimExecutable(in directory: URL) throws -> URL {
    let source = directory.appending(path: "uninstall-idle-shim.c")
    let executable = directory.appending(path: "uninstall-idle-shim")
    try Data("#include <unistd.h>\nint main(void) { for (;;) pause(); }\n".utf8)
        .write(to: source)
    let compiler = Process()
    compiler.executableURL = URL(filePath: "/usr/bin/clang")
    compiler.arguments = [source.path, "-o", executable.path]
    compiler.standardInput = FileHandle.nullDevice
    compiler.standardOutput = FileHandle.nullDevice
    compiler.standardError = FileHandle.nullDevice
    try compiler.run()
    compiler.waitUntilExit()
    guard compiler.terminationStatus == 0 else {
        throw EngineError(.internalError, "could not build uninstall shim test helper")
    }
    return executable
}
#endif
