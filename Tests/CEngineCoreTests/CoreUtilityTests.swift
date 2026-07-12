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
