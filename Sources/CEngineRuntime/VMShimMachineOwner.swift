import CEngineCore

/// The server's single owning reference to VZ and its held attachment leases.
/// Neither failed VZ stop nor failed surrounding teardown may clear ownership.
@MainActor final class VMShimMachineOwner<Machine: AnyObject> {
    var machine: Machine?

    func isCurrent(_ candidate: Machine) -> Bool { machine === candidate }

    func requireCurrent(_ candidate: Machine, teardownInProgress: Bool = false) throws {
        guard isCurrent(candidate), !teardownInProgress else {
            throw EngineError(.conflict, "VM operation belongs to a stopped generation")
        }
    }

    func stopAndRelease(
        stop: @MainActor (Machine) async throws -> Void,
        afterStop: @MainActor () async throws -> Void = {}
    ) async throws {
        let stoppedMachine = machine
        if let stoppedMachine { try await stop(stoppedMachine) }
        try await afterStop()
        guard machine === stoppedMachine else {
            throw BackendResourceRollbackIncompleteError("VM changed during teardown; retaining ownership")
        }
        machine = nil
    }
}
