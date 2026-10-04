import CEngineCore
import Darwin
import Foundation
import Security
import Testing
@testable import StorageBootstrapHelper

@Suite struct StorageBootstrapRegisteredShimTests {
    private let identifier = PrivilegedPortProtocol.defaultEngineIdentifier
    private let team = "M6P3423NZS"
    private let hash = Data(repeating: 0x11, count: 20)

    @Test func codePinRejectsMalformedOrDifferentIdentity() throws {
        let canonical = "\(identifier):\(team):\(hash.base64EncodedString())"
        #expect(BootstrapRegisteredShimCodePin(signingIdentity: canonical, identifier: identifier, team: team)?.hash == hash)
        for invalid in [
            "", canonical + ":", ":" + canonical, "prefix" + canonical,
            canonical.replacingOccurrences(of: identifier, with: identifier + ".test-compat"),
            canonical.replacingOccurrences(of: identifier, with: "dev.cengine.storage-control"),
            canonical.replacingOccurrences(of: team, with: "AAAAAAAAAA"),
            "\(identifier):\(team):", "\(identifier):\(team):not-base64",
            "\(identifier):\(team):\(Data(repeating: 1, count: 19).base64EncodedString())",
            "\(identifier):\(team):\(Data(repeating: 1, count: 21).base64EncodedString())",
            canonical + "\n", String(canonical.dropLast()),
            // Same decoded bytes, noncanonical pad bits.
            String(canonical.dropLast(2)) + "F="
        ] {
            #expect(BootstrapRegisteredShimCodePin(signingIdentity: invalid, identifier: identifier, team: team) == nil)
        }
        for invalidTeam in ["", "m6P3423NZS", "M6P3423NZ", "M6P3423NZSS", "M6P3423NZ:"] {
            #expect(BootstrapRegisteredShimCodePin(signingIdentity: "\(identifier):\(invalidTeam):\(hash.base64EncodedString())",
                identifier: identifier, team: invalidTeam) == nil)
        }
        #expect(BootstrapRegisteredShimCodePin(signingIdentity: canonical, identifier: "prefix" + identifier, team: team) == nil)
    }

    @Test func codePinRequiresExactHashAndStableValidHardenedNondebuggedStatus() throws {
        let pin = try #require(BootstrapRegisteredShimCodePin(
            signingIdentity: "\(identifier):\(team):\(hash.base64EncodedString())", identifier: identifier, team: team))
        let valid: UInt32 = 0x0001_0001
        #expect(pin.accepts(hash: hash, beforeStatus: valid, afterStatus: valid))
        for bad in [UInt32(0), 1, 0x10000, valid | 2, valid | 0x1000_0000] {
            #expect(!pin.accepts(hash: hash, beforeStatus: bad, afterStatus: bad))
            #expect(!pin.accepts(hash: hash, beforeStatus: valid, afterStatus: bad))
            #expect(!pin.accepts(hash: hash, beforeStatus: bad, afterStatus: valid))
        }
        #expect(!pin.accepts(hash: hash, beforeStatus: valid, afterStatus: valid | 0x200))
        for changed in [Data(), Data(repeating: 0x11, count: 19), Data(repeating: 0x11, count: 21), Data(repeating: 0x22, count: 20)] {
            #expect(!pin.accepts(hash: changed, beforeStatus: valid, afterStatus: valid))
        }
    }

    /// Opt-in actual Developer ID fixture; no helper, VM, sudo or existing root.
    /// The initial origin is produced by the unchanged full native pin, not a DTO.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["CENGINE_REGISTERED_SHIM_SIGNING_IDENTITY"] != nil))
    func nativeAtomicUpgradeRetainsOnlyOriginalImmutablePin() throws {
        let identity = try #require(ProcessInfo.processInfo.environment["CENGINE_REGISTERED_SHIM_SIGNING_IDENTITY"])
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("cengine-registered-shim-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("fixture.c")
        let plist = directory.appendingPathComponent("Info.plist")
        let executable = directory.appendingPathComponent("engine")
        let replacement = directory.appendingPathComponent("replacement")
        try """
        #include <mach/mach.h>
        #include <unistd.h>
        int main(int argc, char **argv) {
            audit_token_t token = {0};
            mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
            if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count)) return 9;
            if (write(1, &token, sizeof(token)) != sizeof(token)) return 8;
            char command;
            if (read(0, &command, 1) == 1 && command == 'e') execl(argv[0], argv[0], NULL);
            return VERSION;
        }
        """.write(to: source, atomically: true, encoding: .utf8)
        let metadata: [String: Any] = [
            "CFBundleIdentifier": identifier, "CEngineTeamIdentifier": team,
            PrivilegedPortProtocol.serviceNameInfoKey: SignedStorageIdentity.Namespace.production.serviceName,
            PrivilegedPortProtocol.helperIdentifierInfoKey: SignedStorageIdentity.Namespace.production.helperIdentifier
        ]
        try PropertyListSerialization.data(fromPropertyList: metadata, format: .xml, options: 0).write(to: plist)
        func run(_ command: String, _ arguments: [String]) throws {
            let process = Process(); process.executableURL = URL(fileURLWithPath: command); process.arguments = arguments
            try process.run(); process.waitUntilExit()
            _ = try #require(process.terminationStatus == 0)
        }
        func build(_ target: URL, version: Int) throws {
            try run("/usr/bin/xcrun", ["clang", source.path, "-DVERSION=\(version)", "-Wl,-sectcreate,__TEXT,__info_plist,\(plist.path)", "-o", target.path])
            try run("/usr/bin/codesign", ["--force", "--sign", identity, "--identifier", identifier, "--options", "runtime", "--timestamp=none", target.path])
        }
        try build(executable, version: 1)
        let child = Process(), input = Pipe(), output = Pipe()
        child.executableURL = executable; child.standardInput = input; child.standardOutput = output
        try child.run()
        defer {
            try? input.fileHandleForWriting.close()
            if child.isRunning { child.terminate() }
            child.waitUntilExit()
        }
        func receiveAudit() throws -> BootstrapAuditIdentity {
            let bytes = output.fileHandleForReading.readData(ofLength: MemoryLayout<audit_token_t>.size)
            _ = try #require(bytes.count == MemoryLayout<audit_token_t>.size)
            return .init(token: bytes.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) })
        }
        let audit = try receiveAudit()
        let verifier = StorageBootstrapProcesses(ownerUID: geteuid(), team: team, policy: .production)
        let origin = try verifier.daemon(audit: audit)
        #expect(try verifier.registeredStorageShim(audit: audit, origin: origin).process == origin)
        try build(replacement, version: 2)
        #expect(rename(replacement.path, executable.path) == 0)
        // This is the real Security.framework path/CDHash mismatch, not a mock.
        #expect(throws: (any Error).self) { try verifier.daemon(audit: audit) }
        #expect(try verifier.registeredStorageShim(audit: audit, origin: origin).process == origin)
        let encoded = try JSONEncoder().encode(origin)
        let fields = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let mutations: [(String, Any)] = [
            ("pid", origin.pid + 1), ("startSeconds", origin.startSeconds + 1),
            ("startMicroseconds", origin.startMicroseconds + 1), ("uniqueID", origin.uniqueID + 1),
            ("pidVersion", origin.pidVersion + 1), ("boot", UUID().uuidString.lowercased()),
            ("auditToken", Data(repeating: 0, count: 32).base64EncodedString()),
            ("signingIdentity", "\(identifier):\(team):\(hash.base64EncodedString())")
        ]
        for (key, value) in mutations {
            var changed = fields; changed[key] = value
            let forged = try JSONDecoder().decode(BootstrapProcess.self, from: JSONSerialization.data(withJSONObject: changed))
            #expect(throws: (any Error).self) { try verifier.registeredStorageShim(audit: audit, origin: forged) }
        }
        let wrongOwner = StorageBootstrapProcesses(ownerUID: geteuid() + 1, team: team, policy: .production)
        #expect(throws: (any Error).self) { try wrongOwner.registeredStorageShim(audit: audit, origin: origin) }
        try input.fileHandleForWriting.write(contentsOf: Data("e".utf8))
        let execAudit = try receiveAudit()
        #expect(execAudit.pid == audit.pid)
        #expect(execAudit.pidVersion != audit.pidVersion)
        #expect(throws: (any Error).self) { try verifier.registeredStorageShim(audit: audit, origin: origin) }
        #expect(throws: (any Error).self) { try verifier.registeredStorageShim(audit: execAudit, origin: origin) }
        let newOrigin = try verifier.daemon(audit: execAudit)
        #expect(newOrigin.signingIdentity != origin.signingIdentity)
        #expect(try verifier.registeredStorageShim(audit: execAudit, origin: newOrigin).process == newOrigin)
    }
}
