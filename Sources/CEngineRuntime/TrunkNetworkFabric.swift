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
        let registration: UUID
        let onDisconnect: (@Sendable () -> Void)?
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
    private var dockerHostDNS = DockerHostDNSResponder()

    public init() {}

    func configureDockerHostDNS(gateways: [UInt16: String]) {
        dockerHostDNS.configure(gateways: gateways)
    }

    public func register(
        _ id: EndpointID,
        file: FileHandle,
        vlans: Set<UInt16> = [],
        onDisconnect: (@Sendable () -> Void)? = nil
    ) {
        register(id, file: file, vlans: vlans, registration: UUID(), onDisconnect: onDisconnect)
    }

    func register(
        _ id: EndpointID,
        file: FileHandle,
        vlans: Set<UInt16>,
        registration: UUID,
        onDisconnect: (@Sendable () -> Void)? = nil
    ) {
        unregister(id)
        endpoints[id] = Endpoint(
            file: file,
            vlans: vlans,
            registration: registration,
            onDisconnect: onDisconnect
        )
        file.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                Task { await self?.unregisterDisconnected(id, registration: registration) }
                return
            }
            Task { await self?.receive(data, from: id, registration: registration) }
        }
    }

    public func unregister(_ id: EndpointID) {
        unregister(id, registration: nil, notifyDisconnect: false)
    }

    func unregister(_ id: EndpointID, registration: UUID) {
        unregister(id, registration: registration, notifyDisconnect: false)
    }

    private func unregisterDisconnected(_ id: EndpointID, registration: UUID) {
        unregister(id, registration: registration, notifyDisconnect: true)
    }

    private func unregister(_ id: EndpointID, registration: UUID?, notifyDisconnect: Bool) {
        if let registration, endpoints[id]?.registration != registration { return }
        let onDisconnect = endpoints[id]?.onDisconnect
        endpoints[id]?.file.readabilityHandler = nil
        endpoints.removeValue(forKey: id)
        learned = learned.filter { $0.value != id }
        if notifyDisconnect { onDisconnect?() }
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

    private func receive(_ data: Data, from sourceID: EndpointID, registration: UUID) {
        guard endpoints[sourceID]?.registration == registration,
              let frame = VLANFrame(data), endpoints[sourceID]?.vlans.contains(frame.vlan) == true else { return }
        learned[.init(vlan: frame.vlan, address: frame.source)] = sourceID
        if let response = dockerHostDNS.response(to: data), let file = endpoints[sourceID]?.file {
            do { try file.write(contentsOf: response) }
            catch {
                if Self.isTransientPacketWriteError(error) { return }
                unregisterDisconnected(sourceID, registration: registration)
            }
            return
        }
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
            catch {
                if Self.isTransientPacketWriteError(error) { continue }
                FileHandle.standardError.write(Data("network fabric write to \(recipient.rawValue) failed (\(data.count) bytes): \(error)\n".utf8))
                guard let registration = endpoints[recipient]?.registration else { continue }
                unregisterDisconnected(recipient, registration: registration)
            }
        }
    }

    static func isTransientPacketWriteError(_ error: Error) -> Bool {
        var current = error as NSError
        while true {
            if current.domain == NSPOSIXErrorDomain,
               current.code == Int(ENOBUFS) || current.code == Int(EAGAIN) || current.code == Int(EWOULDBLOCK) {
                return true
            }
            guard let underlying = current.userInfo[NSUnderlyingErrorKey] as? NSError else { return false }
            current = underlying
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
