import Foundation
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

@Suite struct EngineRuntimeIPAMTests {
    enum ConcurrentEndpointConflict: CaseIterable, Sendable {
        case ipv4Address
        case macAddress
    }

    private actor FailingPersistenceGate {
        struct Failure: Error {}

        private var didPause = false
        private var arrivalWaiter: CheckedContinuation<Void, Never>?
        private var releaseWaiter: CheckedContinuation<Void, Never>?

        func pauseOnceThenFail() async throws {
            guard !didPause else { return }
            didPause = true
            arrivalWaiter?.resume()
            arrivalWaiter = nil
            await withCheckedContinuation { releaseWaiter = $0 }
            throw Failure()
        }

        func waitUntilPaused() async {
            guard !didPause else { return }
            await withCheckedContinuation { arrivalWaiter = $0 }
        }

        func release() {
            releaseWaiter?.resume()
            releaseWaiter = nil
        }
    }

    private actor PersistenceGate {
        private var didPause = false
        private var arrivalWaiter: CheckedContinuation<Void, Never>?
        private var releaseWaiter: CheckedContinuation<Void, Never>?

        func pauseOnce() async {
            guard !didPause else { return }
            didPause = true
            arrivalWaiter?.resume()
            arrivalWaiter = nil
            await withCheckedContinuation { releaseWaiter = $0 }
        }

        func waitUntilPaused() async {
            guard !didPause else { return }
            await withCheckedContinuation { arrivalWaiter = $0 }
        }

        func release() {
            releaseWaiter?.resume()
            releaseWaiter = nil
        }
    }

    private actor ArmedPersistenceGate {
        enum Failure: Error { case requested }

        private var armed = false
        private var shouldFail = false
        private var arrived = false
        private var arrivalWaiter: CheckedContinuation<Void, Never>?
        private var releaseWaiter: CheckedContinuation<Void, Never>?

        func arm(failing: Bool = false) {
            armed = true
            shouldFail = failing
            arrived = false
        }

        func pauseWhenArmed() async throws {
            guard armed else { return }
            armed = false
            arrived = true
            arrivalWaiter?.resume()
            arrivalWaiter = nil
            await withCheckedContinuation { releaseWaiter = $0 }
            if shouldFail { throw Failure.requested }
        }

        func waitUntilPaused() async {
            guard !arrived else { return }
            await withCheckedContinuation { arrivalWaiter = $0 }
        }

        func release() {
            releaseWaiter?.resume()
            releaseWaiter = nil
        }
    }

    private actor EndpointAddressBackendState {
        private var recoveredContainer: ContainerRecord?

        func recordRecovery(_ container: ContainerRecord) { recoveredContainer = container }
        func recovered() -> ContainerRecord? { recoveredContainer }
    }

    private struct EmptyIPv4EndpointBackend: ContainerBackend {
        let state: EndpointAddressBackendState

        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws {}
        func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
        func wait(_: ContainerRecord) async throws -> Int32 { 0 }
        func delete(_: ContainerRecord) async throws {}
        func endpointAddresses(for container: ContainerRecord) async -> [String: BackendEndpointAddress] {
            Dictionary(uniqueKeysWithValues: container.networks.map {
                ($0.networkID, .init(ipv4Address: "", ipv6Address: $0.ipv6Address ?? ""))
            })
        }
        func recover(_ container: ContainerRecord) async throws -> BackendContainerRecovery {
            await state.recordRecovery(container)
            return .running
        }
    }

    @Test func defaultNetworkAllocatesUniquePersistentDualStackAddressesBeforeBackendPreparation() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())

        let first = try await runtime.createContainer(ContainerRecord(name: "first", image: "example"))
        let second = try await runtime.createContainer(ContainerRecord(name: "second", image: "example"))
        let firstEndpoint = try #require(first.networks.first)
        let secondEndpoint = try #require(second.networks.first)

        #expect(firstEndpoint.ipv4Address == "192.168.64.2")
        #expect(secondEndpoint.ipv4Address == "192.168.64.3")
        #expect(firstEndpoint.ipv6Address == "fd00:ce::2")
        #expect(secondEndpoint.ipv6Address == "fd00:ce::3")
    }

    @Test func removedEndpointAddressIsNotImmediatelyReusedAcrossRuntimeRestart() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let firstRuntime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let first = try await firstRuntime.createContainer(ContainerRecord(name: "first", image: "example"))
        try await firstRuntime.removeContainer(first.id, force: false)

        let restartedRuntime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let second = try await restartedRuntime.createContainer(ContainerRecord(name: "second", image: "example"))
        let endpoint = try #require(second.networks.first)

        #expect(endpoint.ipv4Address == "192.168.64.3")
        #expect(endpoint.ipv6Address == "fd00:ce::3")
    }

    @Test func metadataBackendDerivesSlash31GatewayFromCanonicalSubnet() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())

        let network = try await runtime.createNetwork(name: "slash31", subnet: "10.90.0.2/31")
        #expect(network.gateway == "10.90.0.3")

        var record = ContainerRecord(name: "slash31-client", image: "example")
        record.networks = [.init(networkID: network.id)]
        let container = try await runtime.createContainer(record)
        #expect(container.networks.first?.ipv4Address == "10.90.0.2")
    }

    @Test func metadataBackendDerivesCanonicalIPv6GatewayAndAllocatesAfterIt() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())

        let network = try await runtime.createNetwork(
            name: "implicit-v6-gateway", ipv6Subnet: "fd00:90::10/124",
            enableIPv4: false, enableIPv6: true
        )
        #expect(network.ipv6Gateway == "fd00:90::11")

        var record = ContainerRecord(name: "implicit-v6-client", image: "example")
        record.networks = [.init(networkID: network.id)]
        let container = try await runtime.createContainer(record)
        #expect(container.networks.first?.ipv6Address == "fd00:90::12")
    }

    @Test func explicitEndpointMacIsNormalizedStoredAndSurvivesRecovery() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let network = try await runtime.createNetwork(name: "macnet")
        let created = try await runtime.createContainer(makeRecord(
            name: "maccy", networkID: network.id, macAddress: "02:42:AC:11:00:02"
        ))
        // Uppercase and hyphenated input is canonicalized to lowercase colons.
        #expect(created.networks.first?.macAddress == "02:42:ac:11:00:02")

        let restarted = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let recovered = try await restarted.container("maccy")
        #expect(recovered.networks.first?.macAddress == "02:42:ac:11:00:02")
    }

    @Test func containerWithoutExplicitMacHasNilStoredMac() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let created = try await runtime.createContainer(ContainerRecord(name: "auto", image: "example"))
        #expect(created.networks.first?.macAddress == nil)
    }

    @Test func malformedBroadcastAndMulticastEndpointMacsAreRejected() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let network = try await runtime.createNetwork(name: "macnet")
        for invalid in ["not-a-mac", "02:42:ac:11:00", "ff:ff:ff:ff:ff:ff", "03:42:ac:11:00:02", "zz:42:ac:11:00:02"] {
            await #expect(throws: EngineError.self) {
                _ = try await runtime.createContainer(makeRecord(
                    name: "invalid-\(UUID().uuidString.prefix(8))", networkID: network.id, macAddress: invalid
                ))
            }
        }
    }

    @Test func duplicateExplicitMacOnSameNetworkIsRejected() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let network = try await runtime.createNetwork(name: "macnet")
        _ = try await runtime.createContainer(makeRecord(
            name: "first-mac", networkID: network.id, macAddress: "02:42:ac:11:00:02"
        ))
        // A different case for the same address still collides.
        await #expect(throws: EngineError.self) {
            _ = try await runtime.createContainer(makeRecord(
                name: "second-mac", networkID: network.id, macAddress: "02:42:AC:11:00:02"
            ))
        }
        // The same MAC on a different network is allowed.
        let other = try await runtime.createNetwork(name: "othernet")
        _ = try await runtime.createContainer(makeRecord(
            name: "third-mac", networkID: other.id, macAddress: "02:42:ac:11:00:02"
        ))
    }

    @Test func explicitAndGeneratedEffectiveMacsConflictInEitherCreationOrder() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())

        let automaticFirstNetwork = try await runtime.createNetwork(name: "automatic-first-mac")
        var automaticFirst = ContainerRecord(id: "automatic-first", name: "automatic-first", image: "example")
        automaticFirst.networks = [.init(networkID: automaticFirstNetwork.id)]
        _ = try await runtime.createContainer(automaticFirst)
        let generatedFirst = EndpointMacAddress.generated(seed: automaticFirst.id + automaticFirstNetwork.id)
        do {
            _ = try await runtime.createContainer(makeRecord(
                name: "explicit-second", networkID: automaticFirstNetwork.id, macAddress: generatedFirst
            ))
            Issue.record("an explicit MAC reused an existing endpoint's generated MAC")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        let explicitFirstNetwork = try await runtime.createNetwork(name: "explicit-first-mac")
        let automaticSecondID = "automatic-second"
        let generatedSecond = EndpointMacAddress.generated(seed: automaticSecondID + explicitFirstNetwork.id)
        _ = try await runtime.createContainer(makeRecord(
            name: "explicit-first", networkID: explicitFirstNetwork.id, macAddress: generatedSecond
        ))
        var automaticSecond = ContainerRecord(id: automaticSecondID, name: "automatic-second", image: "example")
        automaticSecond.networks = [.init(networkID: explicitFirstNetwork.id)]
        do {
            _ = try await runtime.createContainer(automaticSecond)
            Issue.record("a generated MAC reused an existing endpoint's explicit MAC")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
    }

    @Test func staticAddressesAreCanonicalAndEquivalentIPv6SpellingsConflict() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let network = try await runtime.createNetwork(
            name: "canonical-static", subnet: "10.81.0.0/29", gateway: "10.81.0.1",
            ipv6Subnet: "fd00:81::/124", enableIPv4: true, enableIPv6: true
        )
        let first = try await runtime.createContainer(ContainerRecord(name: "canonical-first", image: "example"))
        try await runtime.connectNetwork(
            network.id, container: first.id,
            ipv6Address: "fd00:0081:0000:0000:0000:0000:0000:0002"
        )
        let stored = try #require(
            try await runtime.container(first.id).networks.first(where: { $0.networkID == network.id })
        )
        #expect(stored.ipv6Address == "fd00:81::2")

        let second = try await runtime.createContainer(ContainerRecord(name: "canonical-second", image: "example"))
        do {
            try await runtime.connectNetwork(network.id, container: second.id, ipv6Address: "fd00:81::2")
            Issue.record("equivalent IPv6 spellings reused the same static address")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        let restarted = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let recovered = try #require(
            try await restarted.container(first.id).networks.first(where: { $0.networkID == network.id })
        )
        #expect(recovered.ipv6Address == "fd00:81::2")
    }

    @Test func invalidOutOfPoolGatewayAndProtocolReservedStaticAddressesAreRejected() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let network = try await runtime.createNetwork(
            name: "validated-static", subnet: "10.82.0.0/29", gateway: "10.82.0.1",
            ipv6Subnet: "fd00:82::/124", enableIPv4: true, enableIPv6: true
        )

        for (index, address) in [
            "invalid", "fd00:82::2", "10.82.1.2", "10.82.0.1", "10.82.0.0", "10.82.0.7",
        ].enumerated() {
            var record = ContainerRecord(name: "invalid-v4-\(index)", image: "example")
            record.networks = [.init(
                networkID: network.id, ipv4Address: address, ipv4AddressIsStatic: true
            )]
            do {
                _ = try await runtime.createContainer(record)
                Issue.record("invalid static IPv4 address \(address) was accepted")
            } catch let error as EngineError {
                #expect(error.code == .badRequest)
            }
        }

        for (index, address) in [
            "invalid", "10.82.0.2", "fd00:83::2", "fd00:82::1", "fd00:82::",
        ].enumerated() {
            var record = ContainerRecord(name: "invalid-v6-\(index)", image: "example")
            record.networks = [.init(
                networkID: network.id, ipv6Address: address, ipv6AddressIsStatic: true
            )]
            do {
                _ = try await runtime.createContainer(record)
                Issue.record("invalid static IPv6 address \(address) was accepted")
            } catch let error as EngineError {
                #expect(error.code == .badRequest)
            }
        }
    }

    @Test func connectReservationSurvivesUnrelatedRemovalAndExcludesRemoveAndStart() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = ArmedPersistenceGate()
        let runtime = try await EngineRuntime(
            root: root,
            backend: MetadataOnlyBackend(),
            beforeEndpointAllocationPersistence: { try await gate.pauseWhenArmed() }
        )
        let removed = try await runtime.createContainer(ContainerRecord(name: "removed-before-connect", image: "example"))
        let target = try await runtime.createContainer(ContainerRecord(name: "connect-target", image: "example"))
        let network = try await runtime.createNetwork(name: "connect-race")

        await gate.arm()
        let connect = Task { try await runtime.connectNetwork(network.id, container: target.id) }
        await gate.waitUntilPaused()

        try await runtime.removeContainer(removed.id, force: false)
        for operation in [
            { try await runtime.removeContainer(target.id, force: false) },
            { try await runtime.startContainer(target.id) },
        ] {
            do {
                try await operation()
                Issue.record("container lifecycle operation bypassed a network-connect reservation")
            } catch let error as EngineError {
                #expect(error.code == .conflict)
            }
        }

        await gate.release()
        try await connect.value
        #expect(try await runtime.container(target.id).networks.contains { $0.networkID == network.id })
    }

    @Test func failedConnectRollsBackByStableContainerIdentityAfterUnrelatedRemoval() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = ArmedPersistenceGate()
        let runtime = try await EngineRuntime(
            root: root,
            backend: MetadataOnlyBackend(),
            beforeEndpointAllocationPersistence: { try await gate.pauseWhenArmed() }
        )
        let removed = try await runtime.createContainer(ContainerRecord(name: "rollback-prefix", image: "example"))
        let target = try await runtime.createContainer(ContainerRecord(name: "rollback-target", image: "example"))
        let network = try await runtime.createNetwork(name: "rollback-race")

        await gate.arm(failing: true)
        let connect = Task { try await runtime.connectNetwork(network.id, container: target.id) }
        await gate.waitUntilPaused()
        try await runtime.removeContainer(removed.id, force: false)
        await gate.release()
        await #expect(throws: ArmedPersistenceGate.Failure.self) { try await connect.value }

        #expect(try await runtime.container(target.id).networks.allSatisfy { $0.networkID != network.id })
    }

    @Test(arguments: ConcurrentEndpointConflict.allCases)
    func concurrentCreatesReserveExplicitEndpointsBeforePersistence(
        _ conflict: ConcurrentEndpointConflict
    ) async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = FailingPersistenceGate()
        let runtime = try await EngineRuntime(
            root: root,
            backend: MetadataOnlyBackend(),
            beforeEndpointAllocationPersistence: { try await gate.pauseOnceThenFail() }
        )
        let network = try await runtime.createNetwork(
            name: "concurrent-endpoints", subnet: "10.80.0.0/24", gateway: "10.80.0.1"
        )

        func record(_ name: String) -> ContainerRecord {
            var value = ContainerRecord(name: name, image: "example")
            switch conflict {
            case .ipv4Address:
                value.networks = [.init(
                    networkID: network.id,
                    ipv4Address: "10.80.0.2",
                    ipv4AddressIsStatic: true
                )]
            case .macAddress:
                value.networks = [.init(
                    networkID: network.id,
                    macAddress: "02:42:ac:11:00:02"
                )]
            }
            return value
        }

        let first = Task { try await runtime.createContainer(record("first-reservation")) }
        await gate.waitUntilPaused()

        do {
            _ = try await runtime.createContainer(record("conflicting-reservation"))
            Issue.record("a concurrent create reused a pending explicit endpoint")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }

        await gate.release()
        await #expect(throws: FailingPersistenceGate.Failure.self) { _ = try await first.value }

        // A failed create must release its pending endpoint reservation.
        _ = try await runtime.createContainer(record("retried-reservation"))
    }

    @Test func pendingContainerEndpointPreventsNetworkRemovalDuringCreate() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = PersistenceGate()
        let runtime = try await EngineRuntime(
            root: root,
            backend: MetadataOnlyBackend(),
            beforeEndpointAllocationPersistence: { await gate.pauseOnce() }
        )
        let network = try await runtime.createNetwork(name: "pending-delete")
        var record = ContainerRecord(name: "pending-delete-client", image: "example")
        record.networks = [.init(networkID: network.id)]

        let creation = Task { try await runtime.createContainer(record) }
        await gate.waitUntilPaused()
        do {
            try await runtime.removeNetwork(network.id)
            Issue.record("network removal ignored a pending container endpoint")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
        await gate.release()

        let created = try await creation.value
        #expect(created.networks.first?.networkID == network.id)
        #expect(try await runtime.network(network.id).id == network.id)
    }

    @Test func pendingContainerEndpointPreventsNetworkPruneDuringCreate() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = PersistenceGate()
        let runtime = try await EngineRuntime(
            root: root,
            backend: MetadataOnlyBackend(),
            beforeEndpointAllocationPersistence: { await gate.pauseOnce() }
        )
        let network = try await runtime.createNetwork(name: "pending-prune")
        var record = ContainerRecord(name: "pending-prune-client", image: "example")
        record.networks = [.init(networkID: network.id)]

        let creation = Task { try await runtime.createContainer(record) }
        await gate.waitUntilPaused()
        let removed = try await runtime.pruneNetworks(identifiers: [network.id])
        #expect(removed.isEmpty)
        await gate.release()

        let created = try await creation.value
        #expect(created.networks.first?.networkID == network.id)
        #expect(try await runtime.network(network.id).id == network.id)
    }

    @Test func emptyBackendIPv4AddressStaysNilAcrossStartAndRecovery() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let state = EndpointAddressBackendState()
        let backend = EmptyIPv4EndpointBackend(state: state)
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let network = try await runtime.createNetwork(
            name: "empty-backend-v4", ipv6Subnet: "fd00:80::/120", enableIPv4: false, enableIPv6: true
        )
        var record = ContainerRecord(name: "v6-client", image: "example")
        record.networks = [.init(networkID: network.id)]
        let created = try await runtime.createContainer(record)
        try await runtime.startContainer(created.id)

        let started = try await runtime.container(created.id)
        #expect(started.networks.first?.ipv4Address == nil)
        #expect(started.networks.first?.ipv6Address?.hasPrefix("fd00:80::") == true)

        let restarted = try await EngineRuntime(root: root, backend: backend)
        let recovered = try await restarted.container(created.id)
        #expect(recovered.networks.first?.ipv4Address == nil)
        #expect(recovered.networks.first?.ipv6Address?.hasPrefix("fd00:80::") == true)
        let backendRecovery = await state.recovered()
        #expect(backendRecovery?.networks.first?.ipv4Address == nil)
        #expect(backendRecovery?.networks.first?.ipv6Address?.hasPrefix("fd00:80::") == true)
    }

    @Test func peerHostAddressFallsBackFromEmptyIPv4ToIPv6() {
        let endpoint = NetworkEndpointRecord(
            networkID: "v6-network", ipv4Address: "", ipv6Address: "fd00:80::2"
        )

        #expect(RawVirtualizationBackend.peerHostAddress(endpoint) == "fd00:80::2")
    }

    @Test func explicitGatewayPriorityIsStoredAndSurvivesRecovery() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let first = try await runtime.createNetwork(name: "first-net")
        let second = try await runtime.createNetwork(name: "second-net")
        var record = ContainerRecord(name: "multi", image: "example")
        record.networks = [
            .init(networkID: first.id, gatewayPriority: 10),
            .init(networkID: second.id, gatewayPriority: 100),
        ]
        let created = try await runtime.createContainer(record)
        #expect(created.networks.first(where: { $0.networkID == first.id })?.gatewayPriority == 10)
        #expect(created.networks.first(where: { $0.networkID == second.id })?.gatewayPriority == 100)

        let restarted = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let recovered = try await restarted.container("multi")
        #expect(recovered.networks.first(where: { $0.networkID == second.id })?.gatewayPriority == 100)
    }

    @Test func connectNetworkPreservesRequestedGatewayPriority() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let extra = try await runtime.createNetwork(name: "extra-net")
        let created = try await runtime.createContainer(ContainerRecord(name: "joiner", image: "example"))
        try await runtime.connectNetwork(extra.id, container: created.id, gatewayPriority: 42)
        let updated = try await runtime.container("joiner")
        #expect(updated.networks.first(where: { $0.networkID == extra.id })?.gatewayPriority == 42)
    }

    @Test func containerWithoutExplicitGatewayPriorityHasNilStoredValue() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let created = try await runtime.createContainer(ContainerRecord(name: "auto", image: "example"))
        #expect(created.networks.first?.gatewayPriority == nil)
    }

    @Test func disabledAddressFamilyDoesNotAllocateAndSurvivesRecovery() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let network = try await runtime.createNetwork(
            name: "v6only", ipv6Subnet: "fd00:abcd::/120", enableIPv4: false, enableIPv6: true
        )
        var record = ContainerRecord(name: "client", image: "example")
        record.networks = [.init(networkID: network.id)]
        let created = try await runtime.createContainer(record)
        #expect(created.networks.first?.ipv4Address == nil)
        #expect(created.networks.first?.ipv6Address?.hasPrefix("fd00:abcd::") == true)

        let restarted = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        #expect(try await restarted.network("v6only").enableIPv4 == false)
        #expect(try await restarted.container("client").networks.first?.ipv4Address == nil)
    }

    @Test func endpointDriverOptionsValidateBeforePersistence() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        let network = try await runtime.createNetwork(name: "sysctls")
        var accepted = ContainerRecord(name: "accepted", image: "example")
        accepted.networks = [.init(
            networkID: network.id,
            driverOptions: [NetworkEndpointRecord.sysctlsDriverOption: "net.ipv4.conf.IFNAME.forwarding=1"]
        )]
        let created = try await runtime.createContainer(accepted)
        #expect(created.networks.first?.interfaceSysctls == ["net.ipv4.conf.IFNAME.forwarding=1"])

        for (name, options) in [
            ("bad-placeholder", [NetworkEndpointRecord.sysctlsDriverOption: "net.ipv4.conf.eth0.forwarding=1"]),
            ("bad-family", [NetworkEndpointRecord.sysctlsDriverOption: "net.core.conf.IFNAME.forwarding=1"]),
            ("bad-driver-option", ["unsupported": "value"]),
        ] {
            var invalid = ContainerRecord(name: name, image: "example")
            invalid.networks = [.init(networkID: network.id, driverOptions: options)]
            await #expect(throws: EngineError.self) { _ = try await runtime.createContainer(invalid) }
        }
    }

    @Test func publishingSCTPPortIsRejectedAsAnIntentionalGap() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        var record = ContainerRecord(name: "sctp", image: "example")
        record.ports = [.init(hostPort: 8080, containerPort: 132, proto: "sctp")]
        do {
            _ = try await runtime.createContainer(record)
            Issue.record("publishing an SCTP port should be rejected")
        } catch let error as EngineError {
            #expect(error.code == .badRequest)
        }
        // TCP and UDP publishing remains accepted.
        var accepted = ContainerRecord(name: "tcp-udp", image: "example")
        accepted.ports = [
            .init(hostPort: 8080, containerPort: 80, proto: "tcp"),
            .init(hostPort: 9090, containerPort: 90, proto: "udp"),
        ]
        _ = try await runtime.createContainer(accepted)
    }

    @Test func duplicateContainerNameWithUnsupportedPortKeepsConflictPrecedence() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = try await EngineRuntime(root: root, backend: MetadataOnlyBackend())
        _ = try await runtime.createContainer(ContainerRecord(name: "duplicate", image: "example"))
        var duplicate = ContainerRecord(name: "duplicate", image: "example")
        duplicate.ports = [.init(hostPort: 8080, containerPort: 132, proto: "sctp")]
        do {
            _ = try await runtime.createContainer(duplicate)
            Issue.record("duplicate container name should be rejected")
        } catch let error as EngineError {
            #expect(error.code == .conflict)
        }
    }

    private func makeRecord(name: String, networkID: String, macAddress: String) -> ContainerRecord {
        var record = ContainerRecord(name: name, image: "example")
        record.networks = [.init(networkID: networkID, macAddress: macAddress)]
        return record
    }
}
