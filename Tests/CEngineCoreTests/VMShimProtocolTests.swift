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

    @MainActor @Test func virtioSocketAttemptsHaveABoundedDeadline() async {
        await #expect(throws: EngineError.self) {
            try await RawContainerVirtualMachine.awaitConnection(timeout: .milliseconds(1)) { _ in }
        }
    }
    #endif
}
