#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import MachO
import Testing
@testable import CEngineRuntime

@Suite struct InfrastructureRecoveryTests {
    private func specification(in root: URL) -> VMShimProtocol.Specification {
        .init(
            kind: .storage, containerID: "cengine-storage", generation: 1,
            token: "test-token", kernelPath: "/kernel", initialRamdiskPath: "/initramfs",
            rootDiskPath: root.appending(path: "volumes.ext4").path,
            cpus: 1, memoryBytes: 268_435_456, macAddress: "02:ce:00:00:00:01",
            socketPath: root.appending(path: "control.sock").path,
            logPath: root.appending(path: "shim.log").path
        )
    }

    private func status(uuid: UUID?) -> VMShimProtocol.Status {
        .init(
            containerID: "cengine-storage", generation: 1, state: .running,
            processIdentifier: getpid(), processStartTime: VMShimClient.processStartTime(for: getpid()),
            executableUUID: uuid
        )
    }

    @Test func legacyStatusDecodesWithoutExecutableIdentity() throws {
        let data = Data(#"{"containerID":"cengine-storage","generation":1,"state":"running","processIdentifier":123}"#.utf8)
        let value = try JSONDecoder().decode(VMShimProtocol.Status.self, from: data)
        #expect(value.executableUUID == nil)
        var current = value
        current.executableUUID = UUID()
        #expect(try JSONDecoder().decode(VMShimProtocol.Status.self, from: JSONEncoder().encode(current)) == current)
    }

    @Test func mappedExecutableHasStableUUID() throws {
        let uuid = try #require(RunningExecutableIdentity.uuid)
        #expect(RunningExecutableIdentity.uuid == uuid)
    }

    @Test func mappedLoadCommandsRejectTruncationAndInvalidSizes() {
        let expected = UUID()
        var command = uuid_command(
            cmd: UInt32(LC_UUID), cmdsize: UInt32(MemoryLayout<uuid_command>.size), uuid: expected.uuid
        )
        let data = withUnsafeBytes(of: &command) { Data($0) }
        #expect(data.withUnsafeBytes { RunningExecutableIdentity.uuid(in: $0, commandCount: 1) } == expected)
        for size in 0..<data.count {
            #expect(data.prefix(size).withUnsafeBytes { RunningExecutableIdentity.uuid(in: $0, commandCount: 1) } == nil)
        }
        command.cmdsize = 0
        #expect(withUnsafeBytes(of: &command) { RunningExecutableIdentity.uuid(in: $0, commandCount: 1) } == nil)
        command.cmdsize = UInt32.max
        #expect(withUnsafeBytes(of: &command) { RunningExecutableIdentity.uuid(in: $0, commandCount: 1) } == nil)
    }

    @Test(arguments: ["same", "different", "legacy", "unknown-engine"])
    func onlySameExecutableCanBeAdopted(_ mode: String) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let spec = specification(in: root)
        let original = try JSONEncoder().encode(spec)
        let path = VMShimClient.specificationURL(for: spec)
        try original.write(to: path)
        let uuid = UUID()
        let reply = status(uuid: mode == "legacy" ? nil : (mode == "different" ? UUID() : uuid))
        var launched = false
        do {
            let recovered = try await RawVirtualizationBackend.recoverOrLaunch(
                spec, executableUUID: mode == "unknown-engine" ? nil : uuid,
                probe: { _ in reply },
                launch: { candidate in launched = true; return VMShimClient(specification: candidate) }
            )
            #expect(mode == "same")
            #expect(recovered.specification == spec)
        } catch let error as EngineError {
            #expect(mode != "same")
            #expect(error.code == .conflict)
            #expect(error.message.contains("reopen the updated cengine app"))
        }
        #expect(!launched)
        #expect(try Data(contentsOf: path) == original)
    }

    @Test(arguments: ["live", "reused-pid", "no-runtime", "unverified-socket", "legacy-status"])
    func unreachableInfrastructureRequiresProofOfExit(_ mode: String) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let spec = specification(in: root)
        try JSONEncoder().encode(spec).write(to: VMShimClient.specificationURL(for: spec))
        if mode == "unverified-socket" {
            try Data().write(to: URL(filePath: spec.socketPath))
        } else if mode != "no-runtime" {
            var reply = status(uuid: UUID())
            if mode == "reused-pid" { reply.processStartTime = 1 }
            if mode == "legacy-status" { reply.processStartTime = nil }
            try JSONEncoder().encode(reply).write(to: URL(filePath: spec.socketPath + ".status"))
        }
        let mayLaunch = mode == "reused-pid" || mode == "no-runtime"
        var launched = false
        do {
            _ = try await RawVirtualizationBackend.recoverOrLaunch(
                spec,
                probe: { _ in throw EngineError(.internalError, "unresponsive test peer") },
                launch: { candidate in launched = true; return VMShimClient(specification: candidate) }
            )
            #expect(mayLaunch)
        } catch let error as EngineError {
            #expect(!mayLaunch)
            #expect(error.code == .conflict)
        }
        #expect(launched == mayLaunch)
    }

    @Test func mismatchedStatusAndDiskCannotBeAdopted() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let spec = specification(in: root)
        let uuid = UUID()
        var reply = status(uuid: uuid)
        reply.containerID = "another-root"
        #expect(throws: EngineError.self) {
            try InfrastructureRecovery.validate(reply, specification: spec, executableUUID: uuid)
        }
        var oldSpec = spec
        oldSpec.rootDiskIdentity = .init(device: 1, inode: 2, volumeUUID: UUID())
        try JSONEncoder().encode(oldSpec).write(to: VMShimClient.specificationURL(for: spec))
        let validStatus = status(uuid: uuid)
        await #expect(throws: EngineError.self) {
            _ = try await RawVirtualizationBackend.recoverOrLaunch(
                spec, executableUUID: uuid, probe: { _ in validStatus },
                launch: { candidate in Issue.record("must not launch"); return VMShimClient(specification: candidate) }
            )
        }
    }

    @Test func cancellationDoesNotReplaceInfrastructure() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let spec = specification(in: root)
        try JSONEncoder().encode(spec).write(to: VMShimClient.specificationURL(for: spec))
        await #expect(throws: CancellationError.self) {
            _ = try await RawVirtualizationBackend.recoverOrLaunch(
                spec, probe: { _ in throw CancellationError() },
                launch: { candidate in Issue.record("must not launch"); return VMShimClient(specification: candidate) }
            )
        }
    }
}
#endif
