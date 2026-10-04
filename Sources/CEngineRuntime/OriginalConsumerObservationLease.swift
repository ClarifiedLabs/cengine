import CEngineCore
import Foundation

/// Scheduling only, never a drain/retirement receipt. A machine owns this object
/// for its entire boot; a consumed arm cannot be reused even after release.
@MainActor final class OriginalConsumerObservationLease {
    static let budgetNanoseconds: UInt64 = 10_000_000_000
    enum Failure: Error { case closed, changed, expired }
    enum Stop: Sendable { case storageTerminal, forced }
    // Weak exact-object identity neither retains VZ/disk handles nor matches
    // a newly allocated object reusing the former object's address (ABA).
    private weak var machineReference: AnyObject?
    private var machineWasBound = false
    func bindMachine(_ machine: AnyObject) throws {
        guard armID != nil, !machineWasBound, !closed else { throw Failure.closed }
        machineReference = machine; machineWasBound = true
    }
    func matchesMachine(_ machine: AnyObject) -> Bool { machineReference === machine }
    func releaseMachineIdentity() { machineReference = nil }

    private(set) var exchangeID: UUID?
    func reserveExchange() throws -> UUID {
        guard exchangeID == nil else { throw Failure.closed }
        let id = UUID(); exchangeID = id; return id
    }
    @discardableResult func finishExchange(_ id: UUID) -> Bool {
        guard exchangeID == id else { return false }
        exchangeID = nil; return true
    }

    private(set) var armID: String?
    private(set) var deadline: UInt64?
    private(set) var closed = false
    private(set) var pendingStop = false

    func arm(_ id: String) throws {
        guard armID == nil, !closed, !id.isEmpty else { throw Failure.closed }
        armID = id
    }
    /// Called only after the original PID1 acknowledges Begin. Arm and the
    /// in-flight Begin exchange cannot reserve time against a storage failure.
    func begin(_ id: String, now: UInt64) throws {
        guard armID == id, !closed, deadline == nil, !pendingStop,
              now <= UInt64.max - Self.budgetNanoseconds else { throw Failure.closed }
        deadline = now + Self.budgetNanoseconds
    }
    /// Reattachment may inspect an unbegun observation only. It does not renew
    /// or start the finite Begin budget and cannot displace an in-flight owner.
    func requireResumable(_ id: String, machine: AnyObject) throws {
        guard armID == id, !closed, !pendingStop, deadline == nil,
              exchangeID == nil, matchesMachine(machine) else { throw Failure.closed }
    }
    func require(_ id: String, now: UInt64) throws -> UInt64 {
        guard armID == id, !closed else { throw Failure.changed }
        guard let deadline, now < deadline else { throw Failure.expired }
        return deadline
    }
    /// Returns a deadline only for storage-terminal with an acknowledged Begin.
    /// Every other stop closes admission before its caller cancels/joins IO.
    func stop(_ reason: Stop, now: UInt64) -> UInt64? {
        pendingStop = true
        if reason == .storageTerminal, !closed, let deadline, now < deadline { return deadline }
        closed = true
        return nil
    }
    func release(_ id: String) throws {
        guard armID == id else { throw Failure.changed }
        closed = true
    }
    func cancel() { closed = true }
}
