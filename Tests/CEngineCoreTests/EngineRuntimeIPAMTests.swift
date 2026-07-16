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

    private func makeRecord(name: String, networkID: String, macAddress: String) -> ContainerRecord {
        var record = ContainerRecord(name: name, image: "example")
        record.networks = [.init(networkID: networkID, macAddress: macAddress)]
        return record
    }
}
