import CEngineCore

/// The successful unbegun Arm remains owned by the original shim across daemon
/// exit. A failed publication must join release before returning its failure.
/// Deliberately has no Begin/replacement/retirement callback.
@MainActor enum PublicTakeoverArmScheduling {
    static func run<Observation>(arm: () async throws -> Observation,
        publish: (Observation) async throws -> Void,
        release: (Observation) async throws -> Void) async throws {
        let observation = try await arm()
        do { try await publish(observation) }
        catch {
            let failure = error
            do { try await release(observation) }
            catch { throw OriginalConsumerContainmentFailure(observation: failure, containment: error) }
            throw failure
        }
    }
}
