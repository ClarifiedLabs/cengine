#if os(macOS)
import CEngineCore
import Foundation

public actor TrunkNetworkFabric {
    public struct EndpointID: Hashable, Sendable {
        public let rawValue: String
        public init(_ rawValue: String) { self.rawValue = rawValue }
    }

    private struct Endpoint {
        let file: FileHandle
        var vlans: Set<UInt16>
    }

    private struct LearnedAddress: Hashable {
        let vlan: UInt16
        let address: MAC
    }

    struct MAC: Hashable {
        let bytes: [UInt8]
        var isMulticast: Bool { bytes.first.map { $0 & 1 == 1 } ?? false }
        var isBroadcast: Bool { bytes.allSatisfy { $0 == 0xff } }
    }

    private var endpoints: [EndpointID: Endpoint] = [:]
    private var learned: [LearnedAddress: EndpointID] = [:]

    public init() {}

    public func register(_ id: EndpointID, file: FileHandle, vlans: Set<UInt16> = []) {
        unregister(id)
        endpoints[id] = Endpoint(file: file, vlans: vlans)
        file.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                Task { await self?.unregister(id) }
                return
            }
            Task { await self?.receive(data, from: id) }
        }
    }

    public func unregister(_ id: EndpointID) {
        endpoints[id]?.file.readabilityHandler = nil
        endpoints.removeValue(forKey: id)
        learned = learned.filter { $0.value != id }
    }

    public func connect(_ id: EndpointID, vlan: UInt16) throws {
        guard (1...4094).contains(vlan) else { throw EngineError(.badRequest, "invalid network VLAN \(vlan)") }
        guard endpoints[id] != nil else { throw EngineError(.notFound, "network endpoint \(id.rawValue) not found") }
        endpoints[id]?.vlans.insert(vlan)
    }

    public func disconnect(_ id: EndpointID, vlan: UInt16) {
        endpoints[id]?.vlans.remove(vlan)
        learned = learned.filter { $0.key.vlan != vlan || $0.value != id }
    }

    public func memberships(_ id: EndpointID) -> Set<UInt16> { endpoints[id]?.vlans ?? [] }

    private func receive(_ data: Data, from sourceID: EndpointID) {
        guard let frame = VLANFrame(data), endpoints[sourceID]?.vlans.contains(frame.vlan) == true else { return }
        learned[.init(vlan: frame.vlan, address: frame.source)] = sourceID
        let recipients: [EndpointID]
        if !frame.destination.isBroadcast, !frame.destination.isMulticast,
           let destination = learned[.init(vlan: frame.vlan, address: frame.destination)], destination != sourceID {
            recipients = [destination]
        } else {
            recipients = endpoints.compactMap { id, endpoint in
                id != sourceID && endpoint.vlans.contains(frame.vlan) ? id : nil
            }
        }
        for recipient in recipients {
            guard let file = endpoints[recipient]?.file else { continue }
            do { try file.write(contentsOf: data) }
            catch { unregister(recipient) }
        }
    }

    struct VLANFrame {
        let vlan: UInt16
        let destination: MAC
        let source: MAC

        init?(_ data: Data) {
            guard data.count >= 18 else { return nil }
            let bytes = [UInt8](data.prefix(18))
            guard bytes[12] == 0x81, bytes[13] == 0x00 else { return nil }
            let tag = UInt16(bytes[14]) << 8 | UInt16(bytes[15])
            let vlan = tag & 0x0fff
            guard (1...4094).contains(vlan) else { return nil }
            self.vlan = vlan
            destination = MAC(bytes: Array(bytes[0..<6]))
            source = MAC(bytes: Array(bytes[6..<12]))
        }
    }
}
#endif
