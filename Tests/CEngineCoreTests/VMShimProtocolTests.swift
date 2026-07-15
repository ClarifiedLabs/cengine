import Foundation
import Testing
@testable import CEngineCore
#if os(macOS)
@testable import CEngineRuntime
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
    #endif
}
