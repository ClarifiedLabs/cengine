#if os(macOS)
import CEngineCore
import Darwin
import Foundation

/// Infrastructure owns shared storage as well as networking. Replacing it is a
/// coordinated upgrade operation, never an optimistic fallback from a failed RPC.
enum InfrastructureRecovery {
    static func validate(
        _ status: VMShimProtocol.Status,
        specification: VMShimProtocol.Specification,
        executableUUID: UUID?
    ) throws {
        guard status.containerID == specification.containerID,
              status.generation == specification.generation,
              status.processIdentifier > 1 else {
            throw EngineError(.conflict, "infrastructure VM status does not match its specification")
        }
        guard let executableUUID, status.executableUUID == executableUUID else {
            throw EngineError(
                .conflict,
                "infrastructure VM belongs to a different or older cengine build; "
                    + "reopen the updated cengine app to finish the upgrade and restart its VMs"
            )
        }
    }

    static func requireExited(_ specification: VMShimProtocol.Specification) throws {
        let statusURL = URL(filePath: specification.socketPath + ".status")
        guard let directory = try PersistentStateDirectory.openIfPresent(statusURL.deletingLastPathComponent()) else {
            return
        }
        guard let data = try directory.readRegularFile(named: statusURL.lastPathComponent, required: false) else {
            guard try directory.entryMetadata(named: URL(filePath: specification.socketPath).lastPathComponent) == nil else {
                throw unavailable()
            }
            return
        }
        let status = try JSONDecoder().decode(VMShimProtocol.Status.self, from: data)
        guard status.containerID == specification.containerID,
              status.generation == specification.generation,
              status.processIdentifier > 1,
              let startTime = status.processStartTime else { throw unavailable() }
        if let current = VMShimClient.processStartTime(for: status.processIdentifier) {
            guard current != startTime else { throw unavailable() }
        } else {
            // proc_pidinfo can fail for a live but unreadable process. ESRCH is
            // the only signal-probe result that proves the recorded PID is gone.
            guard Darwin.kill(status.processIdentifier, 0) == -1, errno == ESRCH else {
                throw unavailable()
            }
        }
    }

    private static func unavailable() -> EngineError {
        EngineError(
            .conflict,
            "infrastructure VM is unresponsive and its exit is unverified; "
                + "refusing to start another shared-disk VM; reopen cengine to finish the upgrade"
        )
    }
}
#endif
