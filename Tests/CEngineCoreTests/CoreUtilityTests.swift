import Foundation
import Testing
@testable import CEngineCore

@Suite struct DockerIntegrationTests {
    @Test func executableSearchesInjectedPath() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let name = "cengine-test-tool-\(UUID().uuidString)"
        let tool = root.appending(path: name)
        try Data("#!/bin/sh\n".utf8).write(to: tool)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool.path)

        #expect(DockerIntegration.executable(named: name, environment: ["PATH": root.path]) == tool.path)
        #expect(DockerIntegration.executable(named: name, environment: [:]) == nil)
    }

    @Test func executableIgnoresNonExecutableFiles() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let name = "cengine-test-tool-\(UUID().uuidString)"
        try Data().write(to: root.appending(path: name))

        #expect(DockerIntegration.executable(named: name, environment: ["PATH": root.path]) == nil)
    }

    @Test func builderArgumentsProvisionRecommendedResources() {
        let arguments = DockerIntegration.createBuilderArguments(.init(cpus: 4, memoryGiB: 4))

        #expect(arguments.contains("memory=4294967296"))
        #expect(arguments.contains("cpu-period=100000"))
        #expect(arguments.contains("cpu-quota=400000"))
        #expect(arguments.contains("--oci-worker-snapshotter=overlayfs"))
    }

    @Test func builderInspectionMustMatchEveryManagedResource() {
        let inspection = #"Driver Options: image="moby/buildkit:v0.27.1" memory="4294967296" cpu-period="100000" cpu-quota="400000" BuildKit daemon flags: --oci-worker-snapshotter=overlayfs"#

        #expect(DockerIntegration.builder(inspection, matches: .init(cpus: 4, memoryGiB: 4)))
        #expect(!DockerIntegration.builder(inspection, matches: .init(cpus: 6, memoryGiB: 4)))
        #expect(!DockerIntegration.builder(inspection, matches: .init(cpus: 4, memoryGiB: 8)))
        #expect(!DockerIntegration.builder(
            inspection.replacingOccurrences(of: "overlayfs", with: "native"),
            matches: .init(cpus: 4, memoryGiB: 4)
        ))
    }

    @Test func configuringMatchingBuilderSelectsIt() throws {
        let inspection = #"Driver Options: image="moby/buildkit:v0.27.1" memory="4294967296" cpu-period="100000" cpu-quota="400000" BuildKit daemon flags: --oci-worker-snapshotter=overlayfs"#
        var commands: [[String]] = []

        try DockerIntegration.configureBuilder(.init(cpus: 4, memoryGiB: 4)) { arguments in
            commands.append(arguments)
            return arguments == ["buildx", "inspect", DockerIntegration.builderName] ? inspection : ""
        }

        #expect(commands == [
            ["buildx", "version"],
            ["buildx", "inspect", DockerIntegration.builderName],
            [
                "--context", DockerIntegration.contextName,
                "buildx", "use", "--default", DockerIntegration.builderName,
            ],
        ])
    }

    @Test func configuringNativeBuilderReplacesItsState() throws {
        let inspection = #"Driver Options: image="moby/buildkit:v0.27.1" memory="4294967296" cpu-period="100000" cpu-quota="400000" BuildKit daemon flags: --oci-worker-snapshotter=native"#
        var commands: [[String]] = []

        try DockerIntegration.configureBuilder(.default) { arguments in
            commands.append(arguments)
            return arguments == ["buildx", "inspect", DockerIntegration.builderName] ? inspection : ""
        }

        #expect(commands == [
            ["buildx", "version"],
            ["buildx", "inspect", DockerIntegration.builderName],
            ["buildx", "rm", "--force", DockerIntegration.builderName],
            DockerIntegration.createBuilderArguments(.default),
            [
                "--context", DockerIntegration.contextName,
                "buildx", "use", "--default", DockerIntegration.builderName,
            ],
        ])
    }

    @Test func configuringNewResourcesPreservesOverlayState() throws {
        let inspection = #"Driver Options: image="moby/buildkit:v0.27.1" memory="4294967296" cpu-period="100000" cpu-quota="400000" BuildKit daemon flags: --oci-worker-snapshotter=overlayfs"#
        let settings = BuilderSettings(cpus: 2, memoryGiB: 4)
        var commands: [[String]] = []

        try DockerIntegration.configureBuilder(settings) { arguments in
            commands.append(arguments)
            return arguments == ["buildx", "inspect", DockerIntegration.builderName] ? inspection : ""
        }

        #expect(commands == [
            ["buildx", "version"],
            ["buildx", "inspect", DockerIntegration.builderName],
            ["buildx", "rm", "--force", "--keep-state", DockerIntegration.builderName],
            DockerIntegration.createBuilderArguments(settings),
            [
                "--context", DockerIntegration.contextName,
                "buildx", "use", "--default", DockerIntegration.builderName,
            ],
        ])
    }
}

@Suite struct BuilderSettingsTests {
    @Test func recommendationsScaleWithHostResources() {
        #expect(BuilderSettings.recommended(hostCPUs: 8, hostMemoryBytes: 15 * VirtualMachineMemory.gibibyte) == .init(cpus: 4, memoryGiB: 4))
        #expect(BuilderSettings.recommended(hostCPUs: 12, hostMemoryBytes: 16 * VirtualMachineMemory.gibibyte) == .init(cpus: 6, memoryGiB: 6))
        #expect(BuilderSettings.recommended(hostCPUs: 20, hostMemoryBytes: 24 * VirtualMachineMemory.gibibyte) == .init(cpus: 8, memoryGiB: 8))
        #expect(BuilderSettings.recommended(hostCPUs: 2, hostMemoryBytes: 8 * VirtualMachineMemory.gibibyte) == .init(cpus: 2, memoryGiB: 4))
    }

    @Test func settingsRoundTripThroughSharedFile() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appending(path: "builder-settings.json")
        let settings = BuilderSettings(cpus: 2, memoryGiB: 1)

        try settings.save(to: url)

        #expect(try BuilderSettings.load(from: url) == settings)
    }

    @Test func validationRejectsResourcesBeyondHostLimits() {
        #expect(throws: EngineError.self) {
            try BuilderSettings(cpus: 9, memoryGiB: 4).validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        }
        #expect(throws: EngineError.self) {
            try BuilderSettings(cpus: 4, memoryGiB: 17).validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        }
    }
}

@Suite struct VirtualMachineMemoryTests {
    @Test func capacityAddsGuestReserveWithoutChangingHardLimit() throws {
        #expect(try VirtualMachineMemory.capacity(forHardLimit: 64 * VirtualMachineMemory.mebibyte) == 256 * VirtualMachineMemory.mebibyte)
        #expect(try VirtualMachineMemory.capacity(forHardLimit: VirtualMachineMemory.gibibyte) == 1_140 * VirtualMachineMemory.mebibyte)
        #expect(try VirtualMachineMemory.capacity(forHardLimit: 4 * VirtualMachineMemory.gibibyte) == 4_365 * VirtualMachineMemory.mebibyte)
    }

    @Test func maximumHardLimitAccountsForGuestReserve() {
        #expect(VirtualMachineMemory.maximumHardLimitGiB(maximumCapacityBytes: 16 * VirtualMachineMemory.gibibyte) == 15)
        #expect(VirtualMachineMemory.maximumHardLimitGiB(maximumCapacityBytes: 64 * VirtualMachineMemory.gibibyte) == 60)
    }
}

@Suite struct MemoryBalloonPolicyTests {
    @Test func reclaimsOnlyAvailabilityAboveTheCushion() {
        #expect(MemoryBalloonPolicy.targetBytes(
            maximumBytes: 8 * VirtualMachineMemory.gibibyte,
            availableBytes: 4 * VirtualMachineMemory.gibibyte,
            minimumBytes: 4 * VirtualMachineMemory.mebibyte
        ) == 5 * VirtualMachineMemory.gibibyte)
        #expect(MemoryBalloonPolicy.targetBytes(
            maximumBytes: VirtualMachineMemory.gibibyte,
            availableBytes: 500 * VirtualMachineMemory.mebibyte,
            minimumBytes: 4 * VirtualMachineMemory.mebibyte
        ) == VirtualMachineMemory.gibibyte)
    }

    @Test func pressureTransitionsAreEdgeTriggeredAndGenerationChecked() {
        var state = MemoryBalloonPressureState()
        #expect(state.transition(toConstrained: true) == .reclaim(generation: 1))
        #expect(state.transition(toConstrained: true) == .none)
        #expect(state.isCurrent(generation: 1, constrained: true))
        #expect(state.transition(toConstrained: false) == .restore(generation: 2))
        #expect(!state.isCurrent(generation: 1, constrained: true))
        #expect(state.transition(toConstrained: false) == .none)
    }
}

@Suite struct ContainerSettingsTests {
    @Test func defaultsMatchExistingContainerAllocation() {
        #expect(ContainerSettings.default.cpus == 4)
        #expect(ContainerSettings.default.memoryGiB == 1)
        #expect(ContainerSettings.default.memoryBytes == 1_073_741_824)
    }

    @Test func settingsRoundTripThroughSharedFile() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appending(path: ContainerSettings.fileName)
        let settings = ContainerSettings(cpus: 2, memoryGiB: 1)

        try settings.save(to: url)

        #expect(try ContainerSettings.load(from: url) == settings)
    }

    @Test func validationRejectsResourcesBeyondHostLimits() {
        #expect(throws: EngineError.self) {
            try ContainerSettings(cpus: 9, memoryGiB: 1).validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        }
        #expect(throws: EngineError.self) {
            try ContainerSettings(cpus: 4, memoryGiB: 17).validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        }
    }

    @Test func resourceOverrideValidatesIndependentFields() throws {
        try ContainerResourceOverride(cpus: 2).validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        try ContainerResourceOverride(memoryGiB: 4).validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        #expect(ContainerResourceOverride(memoryGiB: 2).memoryBytes == 2_147_483_648)
        #expect(throws: EngineError.self) {
            try ContainerResourceOverride().validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        }
        #expect(throws: EngineError.self) {
            try ContainerResourceOverride(cpus: 9).validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        }
        #expect(throws: EngineError.self) {
            try ContainerResourceOverride(memoryGiB: 17).validate(maximumCPUs: 8, maximumMemoryGiB: 16)
        }
    }
}

@Suite struct EngineErrorMessageTests {
    private enum BareError: Error { case brokenPipe(code: Int) }

    @Test func prefersLocalizedErrorDescription() {
        let error = EngineError(.conflict, "container name already in use")
        #expect(EngineError.message(for: error) == "container name already in use")
    }

    @Test func fallsBackToSwiftRepresentationForBareErrors() {
        #expect(EngineError.message(for: BareError.brokenPipe(code: 32)) == "brokenPipe(code: 32)")
    }
}

@Suite struct DaemonLogTests {
    @Test func openCreatesDirectoryAndAppends() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let log = root.appending(path: "logs/daemon.log")

        let first = try DaemonLog.open(at: log)
        try first.write(contentsOf: Data("first\n".utf8))
        try first.close()
        let second = try DaemonLog.open(at: log)
        try second.write(contentsOf: Data("second\n".utf8))
        try second.close()

        let contents = try String(contentsOf: log, encoding: .utf8)
        #expect(contents == "first\nsecond\n")
    }

    @Test func timestampedLinesPreservePartialMessages() {
        var buffer = TimestampedLineBuffer()

        let partial = buffer.append(Data("first".utf8)) { "2026-07-16T12:00:00.000Z" }
        #expect(String(decoding: partial, as: UTF8.self) == "2026-07-16T12:00:00.000Z first")

        let complete = buffer.append(Data(" line\nsecond line\nthird".utf8)) { "2026-07-16T12:00:01.234Z" }
        #expect(String(decoding: complete, as: UTF8.self) == """
         line
        2026-07-16T12:00:01.234Z second line
        2026-07-16T12:00:01.234Z third
        """)
    }
}
