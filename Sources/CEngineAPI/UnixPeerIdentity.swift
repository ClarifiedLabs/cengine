import CEngineCore
import Darwin
import Foundation
import NIOCore

public struct ProcessIdentity: Hashable, Sendable {
    public let processIdentifier: pid_t
    public let parentProcessIdentifier: pid_t
    public let effectiveUserIdentifier: uid_t
    public let effectiveGroupIdentifier: gid_t
    public let startTimeMicroseconds: UInt64

    public static func read(
        processIdentifier: pid_t,
        effectiveUserIdentifier: uid_t? = nil,
        effectiveGroupIdentifier: gid_t? = nil
    ) throws -> Self {
        guard processIdentifier > 1 else {
            throw EngineError(.forbidden, "peer process identity is unavailable")
        }
        var information = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(
            processIdentifier,
            PROC_PIDTBSDINFO,
            0,
            &information,
            size
        ) == size,
        information.pbi_start_tvsec >= 0,
        information.pbi_start_tvusec >= 0 else {
            throw EngineError(.forbidden, "peer process identity is unavailable")
        }
        let seconds = UInt64(information.pbi_start_tvsec)
        let microseconds = UInt64(information.pbi_start_tvusec)
        let start: UInt64
        do {
            start = try CheckedArithmetic.add(
                try CheckedArithmetic.multiply(seconds, 1_000_000),
                microseconds
            )
        } catch {
            throw EngineError(.forbidden, "peer process start identity is invalid")
        }
        return .init(
            processIdentifier: processIdentifier,
            parentProcessIdentifier: pid_t(information.pbi_ppid),
            effectiveUserIdentifier: effectiveUserIdentifier ?? uid_t(information.pbi_uid),
            effectiveGroupIdentifier: effectiveGroupIdentifier ?? gid_t(information.pbi_gid),
            startTimeMicroseconds: start
        )
    }

    public func revalidate() throws {
        let current = try Self.read(processIdentifier: processIdentifier)
        guard current.processIdentifier == processIdentifier,
              current.startTimeMicroseconds == startTimeMicroseconds,
              current.effectiveUserIdentifier == effectiveUserIdentifier else {
            throw EngineError(.forbidden, "peer process identity changed")
        }
    }

    public static func current() throws -> Self {
        try read(
            processIdentifier: getpid(),
            effectiveUserIdentifier: geteuid(),
            effectiveGroupIdentifier: getegid()
        )
    }

    public func isOwnerOrDescendant(of owner: ProcessIdentity, maximumDepth: Int = 64) -> Bool {
        guard effectiveUserIdentifier == owner.effectiveUserIdentifier else { return false }
        var current = self
        var seen = Set<pid_t>()
        for _ in 0..<maximumDepth {
            guard seen.insert(current.processIdentifier).inserted else { return false }
            if current.processIdentifier == owner.processIdentifier {
                return current.startTimeMicroseconds == owner.startTimeMicroseconds
                    && current.effectiveUserIdentifier == owner.effectiveUserIdentifier
            }
            guard current.parentProcessIdentifier > 1,
                  let parent = try? Self.read(
                    processIdentifier: current.parentProcessIdentifier
                  ),
                  parent.effectiveUserIdentifier == owner.effectiveUserIdentifier else {
                return false
            }
            current = parent
        }
        return false
    }
}

public struct UnixPeerIdentity: Hashable, Sendable {
    public let process: ProcessIdentity

    static func capture(from channel: Channel) throws -> Self {
        let identity = try channel.pipeline.syncOperations
            .withUnsafeTransportIfAvailable(of: NIOBSDSocket.Handle.self) { descriptor in
                var user = uid_t()
                var group = gid_t()
                guard getpeereid(descriptor, &user, &group) == 0 else {
                    throw EngineError(.forbidden, "Unix peer credentials are unavailable")
                }
                var processIdentifier = pid_t()
                var length = socklen_t(MemoryLayout<pid_t>.size)
                guard withUnsafeMutablePointer(to: &processIdentifier, {
                    getsockopt(
                        descriptor,
                        SOL_LOCAL,
                        LOCAL_PEERPID,
                        $0,
                        &length
                    )
                }) == 0,
                length == MemoryLayout<pid_t>.size else {
                    throw EngineError(.forbidden, "Unix peer PID is unavailable")
                }
                let observed = try ProcessIdentity.read(
                    processIdentifier: processIdentifier
                )
                guard observed.effectiveUserIdentifier == user else {
                    throw EngineError(.forbidden, "Unix peer UID does not match its process identity")
                }
                return UnixPeerIdentity(process: .init(
                    processIdentifier: observed.processIdentifier,
                    parentProcessIdentifier: observed.parentProcessIdentifier,
                    effectiveUserIdentifier: user,
                    effectiveGroupIdentifier: group,
                    startTimeMicroseconds: observed.startTimeMicroseconds
                ))
            }
        guard let identity else {
            throw EngineError(.forbidden, "Unix peer transport credentials are unavailable")
        }
        return identity
    }

    public static func current() throws -> Self {
        .init(process: try .current())
    }
}
