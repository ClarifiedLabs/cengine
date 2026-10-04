import CEngineCore
import Darwin
import Foundation
import Security

/// A private spawn owner: pathname preflight is never permission to run a child.
/// The child remains suspended until its actual dynamic code and generation match.
enum OwnerSetupEngineProcess {
    struct ExpectedCode: Sendable {
        let team: String
        let cdHash: Data
        let requirement: String
    }

    static func preflight(_ executable: URL) throws -> ExpectedCode {
        var running: SecCode?, ownCode: SecStaticCode?, engineCode: SecStaticCode?
        var information: CFDictionary?, requirement: SecRequirement?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running,
              SecCodeCopyStaticCode(running, [], &ownCode) == errSecSuccess, let ownCode,
              SecCodeCopySigningInformation(ownCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String
        else { throw invalidCode() }
        // Derive the team from this app, not a command argument, environment, or plist preference.
        let policy = try SignedStorageIdentity.developerIDRequirement(
            identifiers: [SignedStorageIdentity.Namespace.production.engineIdentifier], team: team)
        // The app itself must also be the Developer-ID-signed production app.
        let appPolicy = policy.replacingOccurrences(of: "identifier \"dev.cengine.engine\"", with: "identifier \"dev.cengine.app\"")
        guard SecRequirementCreateWithString(appPolicy as CFString, [], &requirement) == errSecSuccess,
              let appRequirement = requirement,
              SecCodeCheckValidity(running, SecCSFlags(rawValue: kSecCSStrictValidate), appRequirement) == errSecSuccess,
              SecRequirementCreateWithString(policy as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCreateWithPath(executable as CFURL, [], &engineCode) == errSecSuccess, let engineCode,
              SecStaticCodeCheckValidity(engineCode, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess,
              SecCodeCopySigningInformation(engineCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let engineValues = information as? [String: Any],
              let hash = engineValues[kSecCodeInfoUnique as String] as? Data, hash.count == 20
        else { throw invalidCode() }
        return ExpectedCode(team: team, cdHash: hash, requirement: policy)
    }

    static func authenticate(pid: Int32, expected: ExpectedCode) throws {
        var running: SecCode?, code: SecStaticCode?, information: CFDictionary?, requirement: SecRequirement?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary,
                                            [], &running) == errSecSuccess, let running,
              SecRequirementCreateWithString(expected.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCheckValidity(running, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess,
              SecCodeCopyStaticCode(running, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              values[kSecCodeInfoUnique as String] as? Data == expected.cdHash
        else { throw invalidCode() }
        try SignedStorageIdentity.validatePeer(running, pid: pid, role: .engine,
            namespace: .production, expectedTeam: expected.team)
    }

    struct Generation: Equatable {
        let uniqueID: UInt64
        let parentID: UInt64
        let version: UInt32
    }

    static func generation(_ pid: Int32) throws -> Generation {
        // XNU PROC_PIDUNIQIDENTIFIERINFO, 56-byte proc_uniqidentifierinfo.
        var bytes = Data(count: 56)
        guard bytes.withUnsafeMutableBytes({ proc_pidinfo(pid, 17, 0, $0.baseAddress, 56) }) == 56 else { throw invalidCode() }
        let value = bytes.withUnsafeBytes {
            Generation(uniqueID: $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self),
                parentID: $0.loadUnaligned(fromByteOffset: 24, as: UInt64.self),
                version: $0.loadUnaligned(fromByteOffset: 32, as: UInt32.self))
        }
        guard value.uniqueID != 0 else { throw invalidCode() }
        return value
    }

    /// Internal seam permits harmless test children; production supplies only its
    /// bundled engine path and the actual-code authenticator above.
    static func run(_ executable: String, arguments: [String], authenticate: (Int32) throws -> Void) throws {
        var descriptors: [Int32] = [-1, -1]
        guard pipe(&descriptors) == 0 else { throw systemError() }
        defer { for fd in descriptors where fd >= 0 { Darwin.close(fd) } }
        let null = open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard null >= 0 else { throw systemError() }
        defer { Darwin.close(null) }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        try check(posix_spawn_file_actions_init(&actions))
        defer { posix_spawn_file_actions_destroy(&actions) }
        try check(posix_spawnattr_init(&attributes))
        defer { posix_spawnattr_destroy(&attributes) }
        for (source, target) in [(null, Int32(0)), (descriptors[1], Int32(1)), (descriptors[1], Int32(2))] {
            try check(posix_spawn_file_actions_adddup2(&actions, source, target))
        }
        try check(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED)))
        let pointers = ([executable] + arguments).map { strdup($0) }
        defer { pointers.forEach { free($0) } }
        guard pointers.allSatisfy({ $0 != nil }) else { throw POSIXError(.ENOMEM) }
        var argv = pointers + [nil]
        // No DYLD injection or caller-controlled executable search paths.
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        let parent = try generation(getpid())
        var pid: pid_t = 0
        try check(posix_spawn(&pid, executable, &actions, &attributes, &argv, &environment))
        Darwin.close(descriptors[1]); descriptors[1] = -1
        // This function is the sole reaper. A live/zombie owned child keeps its PID
        // reserved until waitpid; failure never signals a reaped/recycled PID.
        var reaped = false
        defer {
            if !reaped {
                var status: Int32 = 0
                var result: pid_t
                repeat { result = waitpid(pid, &status, WNOHANG) } while result < 0 && errno == EINTR
                if result == 0 {
                    _ = kill(pid, SIGKILL)
                    repeat { result = waitpid(pid, &status, 0) } while result < 0 && errno == EINTR
                }
            }
        }
        let before = try generation(pid)
        guard before.parentID == parent.uniqueID else { throw invalidCode() }
        try authenticate(pid)
        guard try generation(pid) == before else { throw invalidCode() }
        guard kill(pid, SIGCONT) == 0 else { throw systemError() }
        var output = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(descriptors[0], &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw systemError() }
            if count == 0 { break }
            // Drain fully without allowing an unbounded diagnostic allocation.
            output.append(contentsOf: buffer.prefix(min(count, max(0, 8192 - output.count))))
        }
        var status: Int32 = 0
        var result: pid_t
        repeat { result = waitpid(pid, &status, 0) } while result < 0 && errno == EINTR
        guard result == pid else { throw systemError() }
        reaped = true
        guard status == 0 else {
            throw EngineError(.internalError, "Storage owner command failed: " + String(decoding: output, as: UTF8.self))
        }
    }

    private static func invalidCode() -> EngineError {
        EngineError(.unsupported, "The production cengine app or bundled engine signature is invalid. Reinstall cengine.")
    }
    private static func check(_ result: Int32) throws {
        guard result == 0 else { throw POSIXError(POSIXErrorCode(rawValue: result) ?? .EIO) }
    }
    private static func systemError() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}
