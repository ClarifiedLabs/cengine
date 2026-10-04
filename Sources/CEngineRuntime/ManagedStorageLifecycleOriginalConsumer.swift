#if os(macOS)
import CEngineCore
import Foundation

/// Only an actual observation owner may supply adopted trust. Construction stays
/// file-sealed here.
struct OriginalConsumerReplacementProbe: Sendable {
    let binding: OriginalConsumerObservationProtocol.Binding
    let payload: Data
    fileprivate init(lifecycleBinding binding: OriginalConsumerObservationProtocol.Binding,
        scope: WorkloadStorageProtocol.Scope, peer: WorkloadStorageProtocol.Peer) throws {
        self.binding = binding
        payload = try JSONEncoder().encode(OriginalConsumerObservationProtocol.Probe(arm: .init(binding), scope: scope, peer: peer))
    }
}

/// Owner-correlated observations, not authority or a drain receipt. In particular
/// unknown-authority rejection is NOT server-verified possession of the old key.
struct OriginalConsumerReplacementEvidence: Sendable {
    let worker: ConsumerObservationProtocol.Status
    let original: OriginalConsumerObservationProtocol.Evidence
    let retirement: ManagedVolumeLifecycleCoordinator.OriginalRetirement?
    let positive: OriginalConsumerObservationProtocol.Evidence?
    let baseline: OriginalConsumerRuntimeCarrier.Baseline?
    let registration: OriginalConsumerRuntimeCarrier.Registration?
    fileprivate init(lifecycleWorker worker: ConsumerObservationProtocol.Status, original: OriginalConsumerObservationProtocol.Evidence,
        retirement: ManagedVolumeLifecycleCoordinator.OriginalRetirement? = nil,
        positive: OriginalConsumerObservationProtocol.Evidence? = nil,
        baseline: OriginalConsumerRuntimeCarrier.Baseline? = nil,
        registration: OriginalConsumerRuntimeCarrier.Registration? = nil) {
        self.worker = worker; self.original = original; self.retirement = retirement
        self.positive = positive; self.baseline = baseline; self.registration = registration
    }
}

/// Root observations correlated against the sealed service before publication.
struct OriginalRootEvidence: Sendable {
    let result: OriginalConsumerRuntimeCarrier.RootResult
    fileprivate init(_ result: OriginalConsumerRuntimeCarrier.RootResult, lifecycleWorker worker: ManagedStorageLifecycleServiceReady) throws {
        try result.validate(original: result.binding, service: .init(storeUUID: worker.ready.identity.store,
            serviceEpoch: worker.ready.serviceEpoch, workerUUID: worker.ready.workerUUID),
            lifecycleIdentity: worker.ready.identity)
        self.result = result
    }
}

extension ManagedStorageLifecycleOwner {
    func observeOriginalConsumerReplacement(_ observation: VMShimClient.OriginalConsumerObservation,
        session: ServiceReplacementMaintenance) async throws -> OriginalConsumerReplacementEvidence {
        let point = OriginalConsumerFailureDiagnostic.Cursor()
        do {
            return try await withOriginalConsumerSession(maintenance: session,
                deadlineNanoseconds: observation.remainingDeadline()) { current in
                try await observeOriginalConsumer(observation, session: current, crossE: true, diagnostic: point)
            }
        } catch { throw OriginalConsumerFailureDiagnostic.annotate(error, at: point.stage) }
    }
    func observeOriginalConsumerWrongHello(_ observation: VMShimClient.OriginalConsumerObservation,
        request: StorageServiceTypes.ReplacementRequest) async throws -> OriginalConsumerReplacementEvidence {
        guard observation.binding.caseName.isWrongHello else { throw Failure.invalid }
        return try await withOriginalConsumerSession(request: request, deadlineNanoseconds: observation.remainingDeadline()) { current in
            try await observeOriginalConsumer(observation, session: current, crossE: false)
        }
    }
    func observeOriginalConsumerSameE(_ observation: VMShimClient.OriginalConsumerObservation,
        request: StorageServiceTypes.ReplacementRequest,
        installed: ((ManagedVolumeLifecycleCoordinator.OriginalRetirement?) throws -> Void)? = nil) async throws -> OriginalConsumerReplacementEvidence {
        guard observation.binding.caseName.isSameE,
              !observation.binding.caseName.isRegistration || installed != nil else { throw Failure.invalid }
        let point = OriginalConsumerFailureDiagnostic.Cursor()
        do {
            return try await withOriginalConsumerSession(request: request, deadlineNanoseconds: observation.remainingDeadline()) { current in
                try await observeOriginalConsumer(observation, session: current, crossE: false, installed: installed, diagnostic: point)
            }
        } catch { throw OriginalConsumerFailureDiagnostic.annotate(error, at: point.stage) }
    }
    func observeOriginalConsumerRoots(_ observation: VMShimClient.OriginalConsumerObservation,
        request: StorageServiceTypes.ReplacementRequest,
        installed: @escaping (ManagedVolumeLifecycleCoordinator.OriginalRetirement?) throws -> Void) async throws -> OriginalRootEvidence {
        guard observation.binding.caseName.isRoot else { throw Failure.invalid }
        return try await withOriginalConsumerSession(request: request, deadlineNanoseconds: observation.remainingDeadline()) { current in
            try await observeOriginalConsumerRoots(observation, session: current, installed: installed)
        }
    }
    private func observeOriginalConsumerRoots(_ observation: VMShimClient.OriginalConsumerObservation,
        session: OriginalConsumerSession,
        installed: @escaping (ManagedVolumeLifecycleCoordinator.OriginalRetirement?) throws -> Void) async throws -> OriginalRootEvidence {
        typealias C = ConsumerObservationProtocol
        typealias O = OriginalConsumerObservationProtocol
        let point = OriginalConsumerFailureDiagnostic.Cursor()
        do {
            let binding = observation.binding, positive = observation.evidence
            let boot = session.service, request = session.request
            let retainedLifecycle = session
            guard binding.caseName.isRoot, let originalPeer = observation.boot.configuredPeer,
                  let roots = positive.roots, let baseline = observation.backingBaseline,
                  baseline.binding == binding else { throw Failure.blocked }
            try baseline.validateRootPositive(positive)
            let scope = try ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(binding, current: .init(boot.ready), request: request)
            let original = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding, intent: journalSnapshot().intents.first { $0.id == scope.intent })
            guard roots.source.read.authority == original else { throw Failure.invalid }
            let peer = WorkloadStorageProtocol.Peer(tlsRootDER: boot.ready.tlsRootDER, serverDER: boot.ready.serverDER,
                serverKey: boot.ready.serverSPKI, dataAddress: originalPeer.dataAddress)
            let workerScope = C.WorkerScope(storeUUID: boot.ready.identity.store, serviceEpoch: boot.ready.serviceEpoch,
                workerUUID: boot.ready.workerUUID)
            let probe = try OriginalConsumerReplacementProbe(lifecycleBinding: binding, scope: scope, peer: peer)
            let probeRequest = O.Request(binding: binding, command: .probe, payload: probe.payload)
            var retirement: ManagedVolumeLifecycleCoordinator.OriginalRetirement?
            func check() throws {
                try session.check(); try installed(retirement)
                guard originalPeer == peer,
                      try ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(binding,
                        current: .init(boot.ready), request: request) == scope,
                      try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding,
                        intent: journalSnapshot().intents.first { $0.id == scope.intent },
                        retiredReceipt: retirement?.receipt) == original else { throw Failure.blocked }
                _ = try observation.remainingDeadline()
            }
            try check()
            try observation.claimReplacement()
            let deadline = try observation.remainingDeadline()
            let arm = C.Arm(requestID: binding.requestID, armDigest: binding.armDigest, operationUUID: binding.operationUUID,
                caseName: .sameE, originalBootBinding: binding.boot, original: original,
                originalLeafSHA256: binding.certificateSHA256, workerScope: workerScope)
            func command(_ kind: Boot.Command) async throws -> C.Status {
                guard binding.caseName == .retiredRootGrantReplay else { throw Failure.invalid }
                try check()
                let status = try await session.command(kind, arm: arm, revalidate: check)
                try check()
                return status
            }
            if binding.caseName == .retiredRootGrantReplay {
                point.stage = .workerArm
                let armed = try await command(.consumerObservationArm)
                point.stage = .workerArmReply
                guard armed.state == .armed else { throw Failure.blocked }
            }
            point.stage = .originalRetire
            var observed: C.Status?, finalized: C.Status?
            let authority: ManagedVolumeLifecycleCoordinator.OriginalRootAuthority
            do { authority = try await retainedLifecycle.withOriginalRootAuthority(binding,
                target: roots.target.read.authority, revalidate: { receipt in
                    retirement = receipt
                    try check()
                }, probe: { receipt in
                    retirement = receipt
                    try check()
                    point.stage = .originalProbe
                    do { _ = try await observation.probe(probe) } catch { try check(); throw error }
                    point.stage = .sameECorrelation
                    try check()
                    if binding.caseName == .retiredRootGrantReplay {
                        point.stage = .workerQuery
                        var status = try await command(.consumerObservationQuery)
                        while status.state == .claimed || status.state == .armed {
                            try check()
                            let now = DispatchTime.now().uptimeNanoseconds
                            guard now < deadline else { throw Failure.blocked }
                            do { try await Task.sleep(nanoseconds: min(20_000_000, deadline - now)) }
                            catch { try check(); throw error }
                            try check()
                            status = try await command(.consumerObservationQuery)
                        }
                        point.stage = .observedValidation
                        try O.validateRetiredRootAdmission(observation.evidence, positive: positive,
                            request: probeRequest, observed: status, worker: workerScope)
                        observed = status
                        point.stage = .workerFinalize
                        let final = try await command(.consumerObservationFinalize)
                        point.stage = .workerFinalizeReply
                        try C.validateFinalization(final, observed: status)
                        finalized = final
                    }
                }) } catch { try check(); throw error }
            try check()
            point.stage = .finalValidation
            return try .init(.init(binding: binding, service: workerScope, peer: peer, baseline: baseline, positive: positive,
                original: observation.evidence, authority: authority, worker: observed, finalized: finalized), lifecycleWorker: boot)
        } catch { throw OriginalConsumerFailureDiagnostic.annotate(error, at: point.stage) }
    }

    private func observeOriginalConsumer(_ observation: VMShimClient.OriginalConsumerObservation,
        session: OriginalConsumerSession, crossE: Bool,
        installed: ((ManagedVolumeLifecycleCoordinator.OriginalRetirement?) throws -> Void)? = nil,
        diagnostic: OriginalConsumerFailureDiagnostic.Cursor? = nil) async throws -> OriginalConsumerReplacementEvidence {
        typealias C = ConsumerObservationProtocol
        typealias O = OriginalConsumerObservationProtocol
        typealias D = OriginalConsumerFailureDiagnostic
        let point = diagnostic ?? D.Cursor()
        let binding = observation.binding
        let boot = session.service
        let request = session.request
        point.stage = .observationSetup
        guard let originalPeer = observation.boot.configuredPeer else { throw Failure.blocked }
        point.stage = .originalTuple
        let original = try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding, intent: journalSnapshot().intents.first { $0.id == binding.scope.intent })
        point.stage = .successorScope
        let scope = try !crossE
            ? ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(binding, current: .init(boot.ready), request: request)
            : ManagedStorageOriginalConsumerComparison.originalConsumerSuccessorScope(binding, successor: .init(boot.ready), request: request)
        let peer = WorkloadStorageProtocol.Peer(tlsRootDER: boot.ready.tlsRootDER, serverDER: boot.ready.serverDER,
            serverKey: boot.ready.serverSPKI, dataAddress: originalPeer.dataAddress)
        let hello = try binding.caseName.isWrongHello ? ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding, snapshot: journalSnapshot()) : nil
        let positive = observation.evidence
        point.stage = .baselineValidation
        if binding.caseName.isWritableFD {
            guard let baseline = observation.backingBaseline, baseline.binding == binding else { throw Failure.blocked }
            try baseline.validate()
        }
        let retainedLifecycle = session
        var registration: ManagedVolumeLifecycleCoordinator.OriginalRegistrationAuthority?
        var retirement: ManagedVolumeLifecycleCoordinator.OriginalRetirement?
        point.stage = .probeConstruction
        let probe = try OriginalConsumerReplacementProbe(lifecycleBinding: binding, scope: scope, peer: peer)
        guard let caseName = !crossE ? (binding.caseName.isRegistration ? .sameE : C.Case(rawValue: binding.caseName.rawValue)) : .crossE else { throw Failure.invalid }
        let arm = C.Arm(requestID: binding.requestID, armDigest: binding.armDigest, operationUUID: binding.operationUUID,
            caseName: caseName,
            originalBootBinding: binding.boot, original: original,
            originalLeafSHA256: binding.certificateSHA256,
            workerScope: .init(storeUUID: boot.ready.identity.store, serviceEpoch: boot.ready.serviceEpoch, workerUUID: boot.ready.workerUUID))
        point.stage = .armValidation
        try C.validate(arm)
        let selectedArm = arm
        func check() throws {
            try session.check()
            try installed?(retirement)
            guard try ManagedStorageOriginalConsumerComparison.originalConsumerTuple(binding,
                intent: journalSnapshot().intents.first { $0.id == binding.scope.intent },
                retiredReceipt: retirement?.receipt) == original else { throw Failure.blocked }
            if !crossE {
                guard originalPeer == peer,
                      try ManagedStorageOriginalConsumerComparison.originalConsumerCurrentScope(binding,
                        current: .init(boot.ready), request: request) == scope,
                      try !binding.caseName.isWrongHello || ManagedStorageOriginalConsumerComparison.originalConsumerWrongHello(binding,
                        snapshot: journalSnapshot()) == hello else { throw Failure.blocked }
            } else {
                guard try ManagedStorageOriginalConsumerComparison.originalConsumerSuccessorScope(binding,
                    successor: .init(boot.ready), request: request) == scope else { throw Failure.blocked }
            }
            _ = try observation.remainingDeadline()
        }
        try check()
        point.stage = .observationClaim
        try observation.claimReplacement()
        let deadline = try observation.remainingDeadline()
        func command(_ kind: Boot.Command) async throws -> C.Status {
            try check()
            point.stage = kind == .consumerObservationArm ? .workerArm
                : kind == .consumerObservationQuery ? .workerQuery : .workerFinalize
            let status = try await session.command(kind, arm: selectedArm, revalidate: check)
            try check()
            point.stage = kind == .consumerObservationArm ? .workerArmReply
                : kind == .consumerObservationQuery ? .workerQueryReply : .workerFinalizeReply
            return status
        }
        // Exact sealed worker ACK precedes the original retained TLS attempt.
        let armed = try await command(.consumerObservationArm)
        try check()
        guard armed.state == .armed else { throw Failure.blocked }
        if binding.caseName.isSameE {
            point.stage = .originalRetire
            if binding.caseName.isRegistration {
                guard installed != nil else { throw Failure.blocked }
                do { registration = try await retainedLifecycle.observeOriginalRegistration(binding, revalidate: { receipt in
                    retirement = receipt; try check()
                }, probe: { receipt in
                    retirement = receipt; try check()
                    point.stage = .originalProbe
                    do { _ = try await observation.probe(probe) } catch { try check(); throw error }
                    try check()
                    point.stage = .originalRetire
                }) } catch { try check(); throw error }
            } else {
                do { retirement = try await retainedLifecycle.retireOriginalConsumer(binding, revalidate: check) }
                catch { try check(); throw error }
            }
            point.stage = .retireReturnValidation
        }
        try check()
        if !binding.caseName.isRegistration {
            point.stage = .originalProbe
            do { _ = try await observation.probe(probe) } catch { try check(); throw error }
        }
        try check()
        var status = try await command(.consumerObservationQuery)
        try check()
        while status.state == .claimed || status.state == .armed {
            try check()
            point.stage = .workerPollDeadline
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw Failure.blocked }
            point.stage = .workerPollSleep
            do { try await Task.sleep(nanoseconds: min(20_000_000, deadline - now)) }
            catch { try check(); throw error }
            try check()
            status = try await command(.consumerObservationQuery)
            try check()
        }
        if binding.caseName.isSameE {
            point.stage = .sameECorrelation
            guard let retirement else { throw Failure.blocked }
            try ManagedStorageOriginalConsumerComparison.correlateSameE(status, positive: positive, result: observation.evidence, scope: scope, peer: peer)
            let finalStatus = try await command(.consumerObservationFinalize)
            try check()
            point.stage = .finalValidation
            try C.validateFinalization(finalStatus, observed: status)
            let control = registration.map { OriginalConsumerRuntimeCarrier.Registration($0, service: arm.workerScope, peer: peer, observed: status) }
            let result = OriginalConsumerReplacementEvidence(lifecycleWorker: finalStatus, original: observation.evidence, retirement: retirement,
                positive: binding.caseName.isWritableFD || binding.caseName.isRegistration ? positive : nil,
                baseline: observation.backingBaseline, registration: control)
            if binding.caseName.isRegistration {
                try OriginalConsumerRuntimeCarrier.Result(result).validateRegistration(binding: binding, service: arm.workerScope,
                    lifecycleIdentity: boot.ready.identity)
            }
            return result
        }
        point.stage = .observedValidation
        guard status.state == .observed, let evidence = status.evidence,
              let count = evidence.byteCount, let hash = evidence.prefixSHA256,
              evidence.hello == hello, observation.evidence.hello == hello else { throw Failure.blocked }
        let prefix = O.Prefix(arm: .init(binding), serverPrefixBytes: count, serverPrefixSHA256: hash)
        try check()
        point.stage = .originalResult
        do { _ = try await observation.result(payload: JSONEncoder().encode(prefix)) }
        catch { try check(); throw error }
        try check()
        // Atomically seal after guest correlation. A duplicate that linearizes
        // first must fail; later connections cannot mutate this closed snapshot.
        let finalStatus = try await command(.consumerObservationFinalize)
        try check()
        point.stage = .finalValidation
        try C.validateFinalization(finalStatus, observed: status)
        let result = observation.evidence
        guard result.stage == "original-owner-prefix-correlated", result.scope == scope,
              result.serverDERSHA256 == WorkloadStorageProtocol.specificationDigest(peer.serverDER),
              result.clientPrefixBytes == count, result.clientPrefixSHA256 == hash,
              result.hello == hello else { throw Failure.invalid }
        return OriginalConsumerReplacementEvidence(lifecycleWorker: finalStatus, original: result,
            positive: binding.caseName.isWritableFD ? positive : nil, baseline: observation.backingBaseline)
    }

}
#endif
