#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Security

@_silgen_name("csops")
nonisolated private func compatibilityIsolationCodeStatus(_ pid: Int32, _ operation: UInt32,
    _ buffer: UnsafeMutableRawPointer, _ size: Int) -> Int32

/// Read-only census of a production process that cannot authenticate as a compatibility client.
/// This is not audit-token authentication and returns no reusable authorization or identity proof.
nonisolated public enum CompatibilityRuntimeIsolation {
    public static func verifyProductionClient(pid: Int32, uniqueID: UInt64, pidVersion: UInt32) throws {
        guard pid > 0, pid != getpid(), getuid() != 0, geteuid() == getuid() else { throw refused() }
        let before = try observe(pid: pid, uniqueID: uniqueID, pidVersion: pidVersion)
        // Only our own running compatibility signature supplies the trusted team.
        let identity = try SignedStorageIdentity.current(role: .engine, namespace: .compatibility)
        try verifyRunningCode(pid: pid, expectedTeam: identity.teamIdentifier)
        let after = try observe(pid: pid, uniqueID: uniqueID, pidVersion: pidVersion)
        try requireUnchanged(before: before, after: after)
    }

    struct Observation: Equatable {
        let generation: Data
        let uid: UInt32
        let realUID: UInt32
        let startSeconds: UInt64
        let startMicroseconds: UInt64
        let codeStatus: UInt32
    }

    private static func observe(pid: Int32, uniqueID: UInt64, pidVersion: UInt32) throws -> Observation {
        guard let generation = RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: pidVersion) else { throw refused() }
        try validateGeneration(generation, uniqueID: uniqueID, pidVersion: pidVersion)
        var bsd = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        var status: UInt32 = 0
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, size) == size,
              bsd.pbi_pid == UInt32(pid), bsd.pbi_uid == geteuid(), bsd.pbi_ruid == getuid(),
              bsd.pbi_uid != 0, bsd.pbi_ruid != 0,
              compatibilityIsolationCodeStatus(pid, 0, &status, MemoryLayout<UInt32>.size) == 0 else { throw refused() }
        try validateCodeStatus(status)
        guard RuntimeProcessIdentity.processIdentity(pid: pid, pidVersion: pidVersion) == generation else { throw refused() }
        return Observation(generation: generation, uid: bsd.pbi_uid, realUID: bsd.pbi_ruid,
            startSeconds: bsd.pbi_start_tvsec, startMicroseconds: bsd.pbi_start_tvusec, codeStatus: status)
    }

    // Pure rejection seams. Passing these checks never constructs native authority.
    static func validateGeneration(_ bytes: Data?, uniqueID: UInt64, pidVersion: UInt32) throws {
        guard let bytes, bytes.count == 56, uniqueID != 0,
              bytes.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) }) == uniqueID,
              bytes.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 32, as: UInt32.self) }) == pidVersion else { throw refused() }
    }

    static func requireUnchanged(before: Observation?, after: Observation?) throws {
        guard let before, let after, before == after else { throw refused() }
    }

    static func validateCodeStatus(_ status: UInt32) throws {
        // XNU cs_blobs.h: CS_VALID, CS_ADHOC, CS_RUNTIME, CS_DEBUGGED.
        guard status & 0x1 != 0, status & SignedStorageIdentity.controllerRuntimeFlag != 0,
              status & (0x2 | 0x1000_0000) == 0 else { throw refused() }
    }

    static func validateSigningFields(identifier: String, team: String, expectedTeam: String) throws {
        let production = SignedStorageIdentity.Namespace.production
        guard team == expectedTeam,
              identifier == production.engineIdentifier || identifier == production.controllerIdentifier else { throw refused() }
    }

    /// Always resolves actual running code. Internal visibility permits native negative tests,
    /// not supplied signing fields, alternate team authority, or a mock authorization path.
    static func verifyRunningCode(pid: Int32, expectedTeam: String) throws {
        var running: SecCode?, code: SecStaticCode?, information: CFDictionary?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary,
                [], &running) == errSecSuccess, let running,
              SecCodeCopyStaticCode(running, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String else { throw refused() }
        let targetTeam = (expectedTeam == SignedStorageIdentity.adHocCompatibilityTeam
            && team != SignedStorageIdentity.adHocCompatibilityTeam) ? team : expectedTeam
        try validateSigningFields(identifier: identifier, team: team, expectedTeam: targetTeam)
        let text = try SignedStorageIdentity.developerIDRequirement(identifiers: [identifier], team: targetTeam)
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecCodeCheckValidity(running, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw refused() }
        let policy = StorageLifecycleNativePolicy.production
        if identifier == policy.engineIdentifier {
            try policy.validatePeer(running, pid: pid, role: .engine, expectedTeam: targetTeam)
        } else {
            // Includes the shared signed flags/entitlements and ordinary-profile checks.
            try policy.validateControllerCode(code, expectedTeam: targetTeam)
        }
    }

    private static func refused() -> EngineError {
        EngineError(.unsupported, "compatibility isolation requires a stable same-user hardened Developer-ID production engine or storage controller")
    }
}
#endif
