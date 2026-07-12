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
        let arguments = DockerIntegration.createBuilderArguments(.default)

        #expect(arguments.contains("memory=4294967296"))
        #expect(arguments.contains("cpu-period=100000"))
        #expect(arguments.contains("cpu-quota=400000"))
    }

    @Test func builderInspectionMustMatchEveryManagedResource() {
        let inspection = #"Driver Options: image="moby/buildkit:v0.27.1" memory="4294967296" cpu-period="100000" cpu-quota="400000""#

        #expect(DockerIntegration.builder(inspection, matches: .default))
        #expect(!DockerIntegration.builder(inspection, matches: .init(cpus: 6, memoryGiB: 4)))
        #expect(!DockerIntegration.builder(inspection, matches: .init(cpus: 4, memoryGiB: 8)))
    }
}

@Suite struct BuilderSettingsTests {
    @Test func defaultsAreFourCPUsAndFourGiB() {
        #expect(BuilderSettings.default.cpus == 4)
        #expect(BuilderSettings.default.memoryGiB == 4)
        #expect(BuilderSettings.default.memoryBytes == 4_294_967_296)
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
}
