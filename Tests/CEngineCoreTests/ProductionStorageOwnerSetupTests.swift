import CEngineCore
import Foundation
import Security
import Testing
@testable import CEngineRuntime

@Suite struct ProductionStorageOwnerSetupTests {
    private static var helper: ProductionStorageOwnerSetup.ValidatedHelper {
        try! .init(team: "ABCDEFGHIJ", cdHash: Data(repeating: 0xab, count: 20))
    }

    @Test(arguments: [StorageOwnerStatus.absent, .disabled, .enrolled(501), .enrolled(502)])
    func checkNeverAuthorizes(state: StorageOwnerStatus) async {
        let coordinator = ProductionStorageOwnerSetup.Coordinator(uid: 501, status: { state },
            validate: { Issue.record("check must not validate"); return Self.helper },
            authorize: { _ in Issue.record("check must never prompt") })
        do { try await coordinator.check(); #expect(state == .enrolled(501)) }
        catch { #expect(state != .enrolled(501)) }
    }

    @Test(arguments: [StorageOwnerStatus.absent, .disabled])
    func explicitSetupRequeriesAuthenticatedStatus(state: StorageOwnerStatus) async throws {
        let recorder = OwnerSetupRecorder(states: [state, .enrolled(501)])
        let coordinator = ProductionStorageOwnerSetup.Coordinator(uid: 501,
            status: { await recorder.status() }, validate: { Self.helper },
            authorize: { await recorder.authorize($0) })
        try await coordinator.setup()
        #expect(await recorder.queries == 2)
        #expect(await recorder.scripts == [ProductionStorageOwnerSetup.enrollmentScript(uid: 501, helper: Self.helper)])
    }

    @Test(arguments: [StorageOwnerStatus.enrolled(501), .enrolled(502)])
    func existingOwnerNeverPrompts(state: StorageOwnerStatus) async {
        let coordinator = ProductionStorageOwnerSetup.Coordinator(uid: 501, status: { state },
            validate: { Issue.record("existing owner must not authorize"); return Self.helper },
            authorize: { _ in Issue.record("existing owner must not prompt") })
        do { try await coordinator.setup(); #expect(state == .enrolled(501)) }
        catch { #expect(state == .enrolled(502)) }
    }

    @Test func rootFailsBeforeStatusOrAuthorization() async {
        let coordinator = ProductionStorageOwnerSetup.Coordinator(uid: 0,
            status: { Issue.record("root must not query"); return .absent },
            validate: { Issue.record("root must not validate"); return Self.helper },
            authorize: { _ in Issue.record("root must not prompt") })
        await #expect(throws: Error.self) { try await coordinator.check() }
        await #expect(throws: Error.self) { try await coordinator.setup() }
    }

    @Test(arguments: ["status", "validation", "authorization", "verification"])
    func failuresNeverReportSuccess(phase: String) async {
        let recorder = OwnerSetupRecorder(states: [.absent, .enrolled(502)])
        let coordinator = ProductionStorageOwnerSetup.Coordinator(uid: 501, status: {
            if phase == "status" { throw CancellationError() }
            return await recorder.status()
        }, validate: {
            if phase == "validation" { throw CancellationError() }
            return Self.helper
        }, authorize: { script in
            #expect(phase != "status" && phase != "validation")
            if phase == "authorization" { throw CancellationError() }
            await recorder.authorize(script)
        })
        await #expect(throws: Error.self) { try await coordinator.setup() }
        #expect(await recorder.queries == (phase == "status" ? 0 : phase == "verification" ? 2 : 1))
    }

    @Test func commandCopiesThenVerifiesThenExecutesOnlyPrivateCopy() throws {
        let shell = ProductionStorageOwnerSetup.enrollmentShell(uid: 501, helper: Self.helper)
        #expect(shell.contains("/usr/bin/mktemp -d /private/tmp/cengine-owner.XXXXXXXX"))
        #expect(shell.contains("trap '/bin/rm -rf \"$dir\"' EXIT"))
        #expect(shell.contains("[ -d /private/tmp ] && [ -k /private/tmp ]"))
        #expect(shell.contains("[ \"$(/usr/bin/stat -f '%u:%Lp' /private/tmp)\" = '0:777' ]"))
        let copy = try #require(shell.range(of: "/bin/cp -L -X '/Applications/cengine.app/Contents/MacOS/cengine-helper' \"$dir/helper\""))
        let verify = try #require(shell.range(of: "/usr/bin/codesign"))
        let execute = try #require(shell.range(of: "\"$dir/helper\" enroll-storage-owner --uid '501'"))
        #expect(copy.lowerBound < verify.lowerBound && verify.lowerBound < execute.lowerBound)
        #expect(shell.contains("/bin/chmod 500 \"$dir/helper\""))
        #expect(shell.contains("[ \"$actual\" = '" + String(repeating: "ab", count: 20) + "' ]"))
        // Writable source ancestry is no longer execution authority.
        #expect(!shell.contains("stat -f '%u:%Lp' /Applications"))
        #expect(ProductionStorageOwnerSetup.shellQuote("a'b") == "'a'\\''b'")
        let script = ProductionStorageOwnerSetup.enrollmentScript(uid: 501, helper: Self.helper)
        #expect(script.hasPrefix("do shell script \"set -eu\\n"))
        #expect(script.hasSuffix("\" with administrator privileges"))
    }

    @Test func copiedSignedBytesMatchAndReplacedBytesFailExactHash() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let original = URL(fileURLWithPath: "/usr/bin/true")
        var code: SecStaticCode?, information: CFDictionary?
        #expect(SecStaticCodeCreateWithPath(original as CFURL, [], &code) == errSecSuccess)
        let signed = try #require(code)
        #expect(SecCodeCopySigningInformation(signed, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess)
        let hash = try #require((information as? [String: Any])?[kSecCodeInfoUnique as String] as? Data)
        let hashText = hash.map { String(format: "%02x", $0) }.joined()
        let copy = directory.appending(path: "helper")
        func verifyCopy() throws -> Int32 {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", "set -eu\ndir=" + ProductionStorageOwnerSetup.shellQuote(directory.path) + "\n" +
                ProductionStorageOwnerSetup.copyVerificationShell(requirement: "anchor apple", cdHash: hashText)]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run(); process.waitUntilExit()
            return process.terminationStatus
        }
        try FileManager.default.copyItem(at: original, to: copy)
        #expect(try verifyCopy() == 0)
        // Even another legitimately signed binary must fail the captured hash.
        try FileManager.default.removeItem(at: copy)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/false"), to: copy)
        #expect(try verifyCopy() != 0)
        try FileManager.default.removeItem(at: copy)
        try Data("unsigned replacement".utf8).write(to: copy)
        #expect(try verifyCopy() != 0)
    }

    @Test func authorizationFailureHasOneActionablePrefix() async {
        let coordinator = ProductionStorageOwnerSetup.Coordinator(uid: 501, status: { .absent },
            validate: { Self.helper }, authorize: { _ in throw EngineError(.internalError, "cancelled (-128)") })
        do { try await coordinator.setup(); Issue.record("must fail") }
        catch {
            #expect(error.localizedDescription.components(separatedBy: "Storage setup was cancelled").count == 2)
            #expect(error.localizedDescription.contains("cancelled (-128)"))
        }
    }
}

private actor OwnerSetupRecorder {
    var states: [StorageOwnerStatus]
    private(set) var queries = 0
    private(set) var scripts: [String] = []
    init(states: [StorageOwnerStatus]) { self.states = states }
    func status() -> StorageOwnerStatus { defer { queries += 1 }; return states[min(queries, states.count - 1)] }
    func authorize(_ script: String) { scripts.append(script) }
}
