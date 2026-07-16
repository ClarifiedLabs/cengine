import Foundation
import Testing
@testable import CEngineCore
@testable import CEngineRuntime

@Suite struct EngineRuntimeIPAMTests {
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
