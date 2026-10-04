import CEngineCore
import Darwin
import Foundation
import Security

/// Production-only owner admission. Check never authorizes; setup is an explicit user action.
public enum ProductionStorageOwnerSetup {
    public static func checkCurrentOwner() async throws {
        try await Coordinator.production().check()
    }

    public static func setupCurrentOwner() async throws {
        try await Coordinator.production().setup()
    }

    enum Failure: LocalizedError {
        case rootCaller, setupRequired, differentOwner(UInt32), unsafeInstallation, authorizationFailed(String), verificationFailed

        var errorDescription: String? {
            switch self {
            case .rootCaller: "Run cengine as your normal user, not root or sudo."
            case .setupRequired: "Storage owner setup is required. Choose Enable or Restart in cengine, or run cengine helper setup-storage-owner."
            case .differentOwner(let uid): "Storage belongs to user \(uid). Sign in as that user; cengine will not replace or reset the owner."
            case .unsafeInstallation: "Storage setup requires the official signed cengine helper in /Applications. Reinstall cengine using the supported installer."
            case .authorizationFailed(let detail): "Storage setup was cancelled or authorization failed. Retry Enable or setup when ready. \(detail)"
            case .verificationFailed: "Storage enrollment could not be verified with the privileged helper. Retry setup; no storage was reset."
            }
        }
    }

    struct Coordinator: Sendable {
        let uid: UInt32
        let status: @Sendable () async throws -> StorageOwnerStatus
        let validate: @Sendable () throws -> ValidatedHelper
        let authorize: @Sendable (String) async throws -> Void

        static func production() -> Self {
            Self(uid: getuid(), status: { try await NetworkHelperControl.storageOwnerStatus() },
                 validate: { try validateInstalledHelper() }, authorize: { script in
                try await Task.detached { try runAdministratorScript(script) }.value
            })
        }

        func check() async throws {
            guard uid != 0 else { throw Failure.rootCaller }
            try requireOwner(await status())
        }

        func setup() async throws {
            guard uid != 0 else { throw Failure.rootCaller }
            switch try await status() {
            case .enrolled(let owner):
                guard owner == uid else { throw Failure.differentOwner(owner) }
                return
            case .absent, .disabled: break
            }
            try Task.checkCancellation()
            let helper = try validate()
            do { try await authorize(ProductionStorageOwnerSetup.enrollmentScript(uid: uid, helper: helper)) }
            catch { throw Failure.authorizationFailed(error.localizedDescription) }
            // Neither command output nor a successful exit is proof of enrollment.
            guard try await status() == .enrolled(uid) else { throw Failure.verificationFailed }
        }

        private func requireOwner(_ state: StorageOwnerStatus) throws {
            switch state {
            case .enrolled(let owner):
                guard owner == uid else { throw Failure.differentOwner(owner) }
            case .absent, .disabled: throw Failure.setupRequired
            }
        }
    }

    static let installedHelper = "/Applications/cengine.app/Contents/MacOS/cengine-helper"

    struct ValidatedHelper: Sendable {
        let requirement: String
        let cdHash: String

        init(team: String, cdHash: Data) throws {
            guard cdHash.count == 20 else { throw Failure.unsafeInstallation }
            let policy = try SignedStorageIdentity.developerIDRequirement(
                identifiers: [SignedStorageIdentity.Namespace.production.helperIdentifier], team: team)
            requirement = policy
            self.cdHash = cdHash.map { String(format: "%02x", $0) }.joined()
        }
    }

    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func enrollmentScript(uid: UInt32, helper: ValidatedHelper) -> String {
        let command = enrollmentShell(uid: uid, helper: helper)
        let literal = command.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "do shell script \"\(literal)\" with administrator privileges"
    }

    /// Source paths are untrusted, including stock admin-writable /Applications.
    /// Only the root-private copy is verified and executed. The CDHash requirement
    /// is captured from validated production code before requesting authorization.
    static func enrollmentShell(uid: UInt32, helper: ValidatedHelper) -> String {
        """
        set -eu
        umask 077
        [ "$(/usr/bin/id -u)" = 0 ]
        [ ! -L /private ] && [ ! -L /private/tmp ]
        [ "$(/usr/bin/stat -f '%u:%Lp' /)" = '0:755' ]
        [ "$(/usr/bin/stat -f '%u:%Lp' /private)" = '0:755' ]
        [ -d /private/tmp ] && [ -k /private/tmp ]
        [ "$(/usr/bin/stat -f '%u:%Lp' /private/tmp)" = '0:777' ]
        dir=$(/usr/bin/mktemp -d /private/tmp/cengine-owner.XXXXXXXX)
        trap '/bin/rm -rf "$dir"' EXIT
        trap 'exit 1' HUP INT TERM
        /bin/chmod -N "$dir"
        /bin/chmod 700 "$dir"
        /usr/sbin/chown 0:0 "$dir"
        /bin/cp -L -X \(shellQuote(installedHelper)) "$dir/helper"
        [ -f "$dir/helper" ] && [ ! -L "$dir/helper" ]
        /bin/chmod -N "$dir/helper"
        /usr/sbin/chown 0:0 "$dir/helper"
        /bin/chmod 500 "$dir/helper"
        \(copyVerificationShell(requirement: helper.requirement, cdHash: helper.cdHash))
        "$dir/helper" enroll-storage-owner --uid \(shellQuote(String(uid)))
        """
    }

    /// Verify every slice's signature/policy, then pin the native slice selected
    /// by Security.framework (also the slice the kernel will execute). Hardcoding
    /// --architecture arm64 can select a different subtype on arm64e hosts.
    static func copyVerificationShell(requirement: String, cdHash: String) -> String {
        """
        /usr/bin/codesign --verify --strict \(shellQuote("-R=" + requirement)) "$dir/helper"
        /usr/bin/codesign --display --verbose=4 "$dir/helper" 2> "$dir/signature"
        actual=$(/usr/bin/awk -F= '$1 == "CDHash" { count++; value=$2 } END { if (count != 1) exit 1; print value }' "$dir/signature")
        [ "$actual" = \(shellQuote(cdHash)) ]
        """
    }

    static func validateInstalledHelper() throws -> ValidatedHelper {
        let identity = try SignedStorageIdentity.current(role: .engine, namespace: .production)
        var code: SecStaticCode?, requirement: SecRequirement?, information: CFDictionary?
        let policy = try SignedStorageIdentity.developerIDRequirement(
            identifiers: [SignedStorageIdentity.Namespace.production.helperIdentifier], team: identity.teamIdentifier)
        guard SecRequirementCreateWithString(policy as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCreateWithPath(URL(fileURLWithPath: installedHelper) as CFURL, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              let cdHash = values[kSecCodeInfoUnique as String] as? Data,
              let flags = values[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & 0x2 == 0,
              SignedStorageIdentity.acceptsControllerCodeSigning(flags: flags.uint32Value,
                entitlementKeys: Set((values[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]).keys))
        else { throw Failure.unsafeInstallation }
        return try ValidatedHelper(team: identity.teamIdentifier, cdHash: cdHash)
    }

    private static func runAdministratorScript(_ script: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw EngineError(.internalError, String(decoding: data.prefix(2048), as: UTF8.self))
        }
    }
}
