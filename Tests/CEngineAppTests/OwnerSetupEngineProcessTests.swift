import Darwin
import Foundation
import Testing
@testable import CEngineApp

@Suite struct OwnerSetupEngineProcessTests {
    @Test func childRunsOnlyAfterAuthenticationAndIsReaped() throws {
        let marker = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: marker) }
        var child: Int32 = 0
        try OwnerSetupEngineProcess.run("/bin/sh", arguments: ["-c", "echo approved > \"$1\"", "test", marker.path]) { pid in
            child = pid
            #expect(!FileManager.default.fileExists(atPath: marker.path))
            let childGeneration = try OwnerSetupEngineProcess.generation(pid)
            let parentGeneration = try OwnerSetupEngineProcess.generation(getpid())
            #expect(childGeneration.parentID == parentGeneration.uniqueID)
        }
        #expect(try String(contentsOf: marker, encoding: .utf8) == "approved\n")
        var status: Int32 = 0
        #expect(waitpid(child, &status, WNOHANG) == -1)
        #expect(errno == ECHILD)
    }

    @Test func rejectedChildNeverExecutesAndIsReaped() throws {
        let marker = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: marker) }
        var child: Int32 = 0
        #expect(throws: CancellationError.self) {
            try OwnerSetupEngineProcess.run("/bin/sh", arguments: ["-c", "echo unsafe > \"$1\"", "test", marker.path]) { pid in
                child = pid
                throw CancellationError()
            }
        }
        #expect(child > 0)
        #expect(!FileManager.default.fileExists(atPath: marker.path))
        var status: Int32 = 0
        #expect(waitpid(child, &status, WNOHANG) == -1)
        #expect(errno == ECHILD)
    }

    @Test(arguments: [false, true])
    func wrongDynamicSignatureIsRejectedBeforeExecution(hashOnly: Bool) throws {
        let marker = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: marker) }
        let expected = OwnerSetupEngineProcess.ExpectedCode(team: "ABCDEFGHIJ", cdHash: Data(repeating: 0, count: 20),
            requirement: hashOnly ? "anchor apple" : "identifier \"dev.cengine.engine\"")
        #expect(throws: Error.self) {
            try OwnerSetupEngineProcess.run("/bin/sh", arguments: ["-c", "echo unsafe > \"$1\"", "test", marker.path]) {
                try OwnerSetupEngineProcess.authenticate(pid: $0, expected: expected)
            }
        }
        #expect(!FileManager.default.fileExists(atPath: marker.path))
    }
}
