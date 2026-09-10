#if os(macOS)
import CEngineCore
import Foundation
import Testing
@testable import CEngineRuntime

@Suite @MainActor struct VMShimFabricTests {
    private enum StartupFailure: Error { case rejected }

    private final class Signal: @unchecked Sendable {
        private let lock = NSLock()
        private var signalled = false
        private var continuation: CheckedContinuation<Void, Never>?

        func signal() {
            let continuation = lock.withLock { () -> CheckedContinuation<Void, Never>? in
                signalled = true
                let result = self.continuation
                self.continuation = nil
                return result
            }
            continuation?.resume()
        }

        func wait() async {
            await withCheckedContinuation { continuation in
                let ready = lock.withLock {
                    if signalled { return true }
                    self.continuation = continuation
                    return false
                }
                if ready { continuation.resume() }
            }
        }
    }

    private final class Uplink: VMShimUplink, @unchecked Sendable {
        let trunk: RawPacketTrunk
        private let lock = NSLock()
        private var handler: (@Sendable () -> Void)?
        private var stops = 0
        var fabricFileHandle: FileHandle { trunk.fabricFileHandle }
        var stopCount: Int { lock.withLock { stops } }

        init() throws { trunk = try RawPacketTrunk() }

        func setDisconnectHandler(_ handler: @escaping @Sendable () -> Void) {
            lock.withLock { self.handler = handler }
        }

        func disconnect() {
            let callback = lock.withLock { handler }
            callback?()
        }

        func stop() async {
            let shouldStop = lock.withLock {
                if stops != 0 { return false }
                stops += 1
                return true
            }
            if shouldStop {
                try? trunk.fabricFileHandle.close()
                try? trunk.virtualMachineFileHandle.close()
            }
        }
    }

    private enum Outcome {
        case fail
        case success(Uplink)
        case suspended(Uplink, started: Signal, release: Signal, cancelled: Signal? = nil)
    }

    @MainActor private final class Factory {
        var outcomes: [Outcome]
        var networks: [VMShimClient.FabricNetwork] = []
        var namespaces: [String] = []

        init(_ outcomes: [Outcome]) { self.outcomes = outcomes }

        func start(_ network: VMShimClient.FabricNetwork, namespace: String) async throws -> any VMShimUplink {
            networks.append(network)
            namespaces.append(namespace)
            guard !outcomes.isEmpty else {
                Issue.record("unexpected uplink creation for \(network.id)")
                throw StartupFailure.rejected
            }
            switch outcomes.removeFirst() {
            case .fail:
                throw StartupFailure.rejected
            case .success(let uplink):
                return uplink
            case .suspended(let uplink, let started, let release, let cancelled):
                started.signal()
                // Deliberately return success even after cancellation, as can
                // happen when a helper reply wins concurrent cancellation.
                await withTaskCancellationHandler {
                    await release.wait()
                } onCancel: {
                    cancelled?.signal()
                }
                return uplink
            }
        }
    }

    private func makeNetwork(
        _ id: String = "bridge", vlan: UInt16 = 42,
        internalNetwork: Bool = false, isolated: Bool = false
    ) -> VMShimClient.FabricNetwork {
        .init(
            id: id, vlan: vlan, subnet: "10.240.\(vlan).0/24",
            gateway: "10.240.\(vlan).1", ipv6Subnet: "",
            internalNetwork: internalNetwork, isolated: isolated, ports: []
        )
    }

    private func makeServer(_ factory: Factory, fabric: TrunkNetworkFabric) -> VMShimServer {
        VMShimServer(
            specification: .init(
                kind: .storage, containerID: "fabric-test", generation: 1,
                token: "unused", kernelPath: "", initialRamdiskPath: "",
                rootDiskPath: "", cpus: 1, memoryBytes: 1, macAddress: "",
                socketPath: "", logPath: "", networkNamespace: "test-root"
            ),
            fabric: fabric,
            startUplink: { try await factory.start($0, namespace: $1) }
        )
    }

    private func expectRejection(_ server: VMShimServer, _ values: [VMShimClient.FabricNetwork]) async {
        do {
            try await server.configureFabric(values)
            Issue.record("rejected helper startup was reported as successful")
        } catch is StartupFailure {
        } catch {
            Issue.record("unexpected fabric error: \(error)")
        }
    }

    @Test(arguments: [1, 3])
    func identicalRequestsRetryEveryFailureThenCacheSuccess(failures: Int) async throws {
        let uplink = try Uplink()
        let factory = Factory(Array(repeating: .fail, count: failures) + [.success(uplink)])
        let fabric = TrunkNetworkFabric()
        let server = makeServer(factory, fabric: fabric)
        let network = makeNetwork()

        for attempt in 1...failures {
            await expectRejection(server, [network])
            #expect(factory.networks.count == attempt)
            #expect(server.fabricNetworks.isEmpty)
            #expect(server.dockerHostGateways.isEmpty)
            #expect(await fabric.memberships(.init("uplink-bridge")).isEmpty)
        }

        try await server.configureFabric([network])
        try await server.configureFabric([network])
        #expect(factory.networks.count == failures + 1)
        #expect(factory.namespaces.allSatisfy { $0 == "test-root" })
        #expect(server.fabricNetworks == [network.id: network])
        #expect(server.dockerHostGateways == [network.vlan: network.gateway])
        #expect(await fabric.memberships(.init("uplink-bridge")) == [network.vlan])
        #expect(uplink.stopCount == 0)
        try await server.configureFabric([])
    }

    @Test func failedReplacementPreservesUnrelatedNetworkAndOnlyAppliedDNS() async throws {
        let stable = makeNetwork("a-stable", vlan: 41)
        let changing = makeNetwork("b-changing")
        var replacement = changing
        replacement.gateway = "10.240.42.254"
        let stableUplink = try Uplink()
        let oldUplink = try Uplink()
        let newUplink = try Uplink()
        let factory = Factory([.success(stableUplink), .success(oldUplink), .fail, .success(newUplink)])
        let fabric = TrunkNetworkFabric()
        let server = makeServer(factory, fabric: fabric)

        try await server.configureFabric([stable, changing])
        await expectRejection(server, [stable, replacement])
        #expect(oldUplink.stopCount == 1)
        #expect(stableUplink.stopCount == 0)
        #expect(server.fabricNetworks == [stable.id: stable])
        #expect(server.dockerHostGateways == [stable.vlan: stable.gateway])
        #expect(await fabric.memberships(.init("uplink-b-changing")).isEmpty)
        #expect(await fabric.memberships(.init("uplink-a-stable")) == [stable.vlan])

        try await server.configureFabric([stable, replacement])
        #expect(factory.networks == [stable, changing, replacement, replacement])
        #expect(server.dockerHostGateways[replacement.vlan] == replacement.gateway)
        try await server.configureFabric([])
    }

    @Test(arguments: [false, true])
    func failedEarlierStartupCannotPreventRemovalOrIsolation(isolate: Bool) async throws {
        let external = makeNetwork("z-sensitive")
        var isolated = external
        isolated.isolated = true
        let failing = makeNetwork("a-failing", vlan: 43)
        let uplink = try Uplink()
        let factory = Factory([.success(uplink), .fail])
        let fabric = TrunkNetworkFabric()
        let server = makeServer(factory, fabric: fabric)
        try await server.configureFabric([external])

        await expectRejection(server, isolate ? [failing, isolated] : [failing])
        #expect(uplink.stopCount == 1)
        #expect(await fabric.memberships(.init("uplink-z-sensitive")).isEmpty)
        #expect(server.fabricNetworks == (isolate ? [isolated.id: isolated] : [:]))
        #expect(server.dockerHostGateways.isEmpty)
        try await server.configureFabric([])
    }

    @Test func isolatedNeedsNoUplinkButInternalStillRetriesHelper() async throws {
        let isolated = makeNetwork("a-isolated", isolated: true)
        let internalNetwork = makeNetwork("b-internal", vlan: 43, internalNetwork: true)
        let uplink = try Uplink()
        let factory = Factory([.fail, .success(uplink)])
        let fabric = TrunkNetworkFabric()
        let server = makeServer(factory, fabric: fabric)

        try await server.configureFabric([isolated])
        try await server.configureFabric([isolated])
        #expect(factory.networks.isEmpty)
        #expect(server.fabricNetworks == [isolated.id: isolated])
        await expectRejection(server, [isolated, internalNetwork])
        try await server.configureFabric([isolated, internalNetwork])
        #expect(factory.networks == [internalNetwork, internalNetwork])
        #expect(server.dockerHostGateways.isEmpty)
        #expect(await fabric.memberships(.init("uplink-a-isolated")).isEmpty)
        #expect(await fabric.memberships(.init("uplink-b-internal")) == [internalNetwork.vlan])
        try await server.configureFabric([])
    }

    @Test(arguments: [false, true])
    func reentrantChangeOrRemovalCannotResurrectSuspendedStart(remove: Bool) async throws {
        let initial = makeNetwork()
        let changed = makeNetwork(vlan: 43)
        let oldUplink = try Uplink()
        let newUplink = try Uplink()
        let started = Signal()
        let release = Signal()
        let queued = Signal()
        let factory = Factory([
            .suspended(oldUplink, started: started, release: release), .success(newUplink),
        ])
        let fabric = TrunkNetworkFabric()
        let server = makeServer(factory, fabric: fabric)
        let first = Task { try await server.configureFabric([initial]) }
        await started.wait()
        let second = Task {
            queued.signal()
            try await server.configureFabric(remove ? [] : [changed])
        }
        await queued.wait()
        #expect(factory.networks == [initial])
        #expect(server.fabricNetworks.isEmpty)
        release.signal()
        try await first.value
        try await second.value

        #expect(oldUplink.stopCount == 1)
        #expect(factory.networks == (remove ? [initial] : [initial, changed]))
        #expect(server.fabricNetworks == (remove ? [:] : [changed.id: changed]))
        #expect(server.dockerHostGateways == (remove ? [:] : [changed.vlan: changed.gateway]))
        #expect(await fabric.memberships(.init("uplink-bridge")) == (remove ? [] : [changed.vlan]))
        try await server.configureFabric([])
        await newUplink.stop()
    }

    @Test(arguments: [false, true])
    func configureFencesSuspendedDisconnectRecovery(remove: Bool) async throws {
        let network = makeNetwork()
        let initial = try Uplink()
        let stale = try Uplink()
        let current = try Uplink()
        let started = Signal()
        let release = Signal()
        let queued = Signal()
        let cancelled = Signal()
        let factory = Factory([
            .success(initial),
            .suspended(stale, started: started, release: release, cancelled: cancelled),
            .success(current),
        ])
        let fabric = TrunkNetworkFabric()
        let server = makeServer(factory, fabric: fabric)
        try await server.configureFabric([network])
        initial.disconnect()
        await started.wait()
        #expect(initial.stopCount == 1)
        #expect(server.fabricNetworks.isEmpty)
        #expect(server.dockerHostGateways.isEmpty)

        let configure = Task {
            queued.signal()
            try await server.configureFabric(remove ? [] : [network])
        }
        await queued.wait()
        await cancelled.wait()
        release.signal()
        try await configure.value
        #expect(stale.stopCount == 1)
        #expect(factory.networks.count == (remove ? 2 : 3))
        #expect(server.fabricNetworks == (remove ? [:] : [network.id: network]))
        #expect(await fabric.memberships(.init("uplink-bridge")) == (remove ? [] : [network.vlan]))
        try await server.configureFabric([])
        await current.stop()
    }

    @Test func cancelledConfigurationDiscardsLateSuccessfulStartAndAllowsRetry() async throws {
        let network = makeNetwork()
        let stale = try Uplink()
        let current = try Uplink()
        let started = Signal()
        let release = Signal()
        let cancelled = Signal()
        let factory = Factory([
            .suspended(stale, started: started, release: release, cancelled: cancelled),
            .success(current),
        ])
        let fabric = TrunkNetworkFabric()
        let server = makeServer(factory, fabric: fabric)
        let configure = Task { try await server.configureFabric([network]) }
        await started.wait()
        configure.cancel()
        await cancelled.wait()
        release.signal()
        do {
            try await configure.value
            Issue.record("cancelled configuration unexpectedly succeeded")
        } catch is CancellationError {
        }
        #expect(stale.stopCount == 1)
        #expect(server.fabricNetworks.isEmpty)
        #expect(server.dockerHostGateways.isEmpty)
        #expect(await fabric.memberships(.init("uplink-bridge")).isEmpty)
        try await server.configureFabric([network])
        #expect(factory.networks.count == 2)
        #expect(server.fabricNetworks == [network.id: network])
        try await server.configureFabric([])
    }

    private final class StopState: @unchecked Sendable {
        private let lock = NSLock()
        private var cancellations = 0
        private var completion: (@Sendable () -> Void)?
        var count: Int { lock.withLock { cancellations } }
        func cancel() { lock.withLock { cancellations += 1 } }
        func sent(_ completion: @escaping @Sendable () -> Void) { lock.withLock { self.completion = completion } }
        func reply() { let callback = lock.withLock { completion }; callback?() }
    }

    @Test func missingStopReplyIsBoundedAndLateReplyIsHarmless() async {
        let state = StopState()
        let timeout = ManualVMNetTimeout()
        let sent = Signal()
        let task = Task {
            await VMNetUplink.awaitStopReply(
                timeout: .seconds(5), makeTimeoutTimer: timeout.makeTimer,
                cancel: { state.cancel() }
            ) {
                state.sent($0)
                sent.signal()
            }
        }
        await sent.wait()
        #expect(timeout.duration == .seconds(5))
        #expect(state.count == 0)
        #expect(!timeout.isCancelled)
        // Expire the installed deadline explicitly, independent of CI scheduling.
        timeout.fire()
        await task.value
        #expect(timeout.isCancelled)
        #expect(state.count == 1)
        state.reply()
        state.reply()
        timeout.fire()
        #expect(state.count == 1)
    }

    @Test(.timeLimit(.minutes(1))) func dispatchStopTimeoutCompletesWithoutHelperReply() async {
        let state = StopState()
        let cancelled = Signal()
        // Keep coverage of the production scheduler without a latency assertion.
        await VMNetUplink.awaitStopReply(timeout: .zero, cancel: {
            state.cancel()
            cancelled.signal()
        }) { _ in }
        // A zero deadline may finish before continuation installation; wait for
        // cancellation bookkeeping too, not just the resumed continuation.
        await cancelled.wait()
        #expect(state.count == 1)
    }

    @Test func successfulStopReplyCompletesExactlyOnce() async {
        let state = StopState()
        let timeout = ManualVMNetTimeout()
        await VMNetUplink.awaitStopReply(
            timeout: .seconds(5), makeTimeoutTimer: timeout.makeTimer,
            cancel: { state.cancel() }
        ) { complete in
            complete()
            complete()
        }
        #expect(timeout.isCancelled)
        timeout.fire()
        #expect(state.count == 1)
    }

    @Test func cancellationReleasesStopWaitWithoutHelperReply() async {
        let state = StopState()
        let timeout = ManualVMNetTimeout()
        let sent = Signal()
        let task = Task {
            await VMNetUplink.awaitStopReply(
                timeout: .seconds(5), makeTimeoutTimer: timeout.makeTimer,
                cancel: { state.cancel() }
            ) {
                state.sent($0)
                sent.signal()
            }
        }
        await sent.wait()
        task.cancel()
        await task.value
        #expect(timeout.isCancelled)
        state.reply()
        timeout.fire()
        #expect(state.count == 1)
    }

    @Test func cancellationBeforeStopInstallationDoesNotSend() async {
        let state = StopState()
        let timeout = ManualVMNetTimeout()
        let entered = Signal()
        let release = Signal()
        let task = Task {
            entered.signal()
            await release.wait()
            await VMNetUplink.awaitStopReply(
                timeout: .seconds(5), makeTimeoutTimer: timeout.makeTimer,
                cancel: { state.cancel() }
            ) { _ in
                Issue.record("pre-cancelled stop must not send a request")
            }
        }
        await entered.wait()
        task.cancel()
        release.signal()
        await task.value
        #expect(timeout.isCancelled)
        timeout.fire()
        #expect(state.count == 1)
    }
}
#endif
