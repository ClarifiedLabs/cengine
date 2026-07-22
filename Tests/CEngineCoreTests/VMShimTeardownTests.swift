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

        let infrastructureProcess = Process()
        infrastructureProcess.executableURL = URL(filePath: "/bin/sleep")
        infrastructureProcess.arguments = ["30"]
        try infrastructureProcess.run()
        Thread.detachNewThread { infrastructureProcess.waitUntilExit() }
        defer { if infrastructureProcess.isRunning { infrastructureProcess.terminate() } }

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
        let infrastructureStartTime = try #require(
            VMShimClient.processStartTime(for: infrastructureProcess.processIdentifier)
        )
        try JSONEncoder().encode(VMShimProtocol.Status(
            containerID: infrastructureSpecification.containerID,
            generation: infrastructureSpecification.generation,
            state: .running,
            processIdentifier: infrastructureProcess.processIdentifier,
            processStartTime: infrastructureStartTime
        )).write(to: URL(filePath: infrastructureSpecification.socketPath + ".status"))

        let stopped = try await VMShimTeardown.terminateAll(
            in: root,
            expectedExecutable: executable,
            gracePeriodMilliseconds: 0,
            forceWaitMilliseconds: 1_000
        )

        #expect(stopped == 2)
        #expect(VMShimClient.processStartTime(for: containerProcess.processIdentifier) == nil)
        #expect(VMShimClient.processStartTime(for: infrastructureProcess.processIdentifier) == nil)
        #expect(try Data(contentsOf: rootDisk) == rootDiskContents)
        #expect(FileManager.default.fileExists(atPath: spawn.intentURL.path))
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
