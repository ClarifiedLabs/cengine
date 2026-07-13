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
}
