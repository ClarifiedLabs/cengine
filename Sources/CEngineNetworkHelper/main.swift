import CEngineCore
import Darwin
import Foundation
import vmnet
@preconcurrency import XPC

private final class SendableXPCObject: @unchecked Sendable {
    let value: xpc_object_t
    init(_ value: xpc_object_t) { self.value = value }
}

private final class HelperPeerSession: @unchecked Sendable {
    var isClosed = false
    var networkIDs: Set<String> = []
}

private struct OwnedHelperVMNetUplink {
    let owner: HelperPeerSession
    let uplink: HelperVMNetUplink
}

@main enum CEngineNetworkHelper {
    private static let uplinkLock = NSLock()
    nonisolated(unsafe) private static var uplinks: [String: OwnedHelperVMNetUplink] = [:]
    nonisolated(unsafe) private static var isTerminating = false
    private static let environment = ProcessInfo.processInfo.environment
    private static let expectedAuthenticationToken = PrivilegedPortProtocol.authenticationToken(
        environment: environment
    )
    private static let testControlEnabled = environment[
        PrivilegedPortProtocol.testControlEnvironmentKey
    ] == "1"

    static func main() {
        guard geteuid() == 0 else {
            FileHandle.standardError.write(Data("cengine-network-helper must run as root\n".utf8))
            exit(1)
        }
        if environment[PrivilegedPortProtocol.authenticationTokenFileEnvironmentKey] != nil,
           expectedAuthenticationToken == nil {
            FileHandle.standardError.write(Data(
                "cengine-network-helper could not load its authentication token\n".utf8
            ))
            exit(1)
        }
        let listener = xpc_connection_create_mach_service(
            PrivilegedPortProtocol.serviceName, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
        )
        xpc_connection_set_event_handler(listener) { event in
            guard xpc_get_type(event) == XPC_TYPE_CONNECTION else { return }
            let peer: xpc_connection_t = event
            let team = Bundle.main.object(forInfoDictionaryKey: "CEngineTeamIdentifier") as? String ?? ""
            let requirement = team.isEmpty
                ? "identifier \"\(PrivilegedPortProtocol.engineIdentifier)\""
                : "anchor apple generic and identifier \"\(PrivilegedPortProtocol.engineIdentifier)\" and certificate leaf[subject.OU] = \"\(team)\""
            let status = requirement.withCString { xpc_connection_set_peer_code_signing_requirement(peer, $0) }
            guard status == 0 else { xpc_connection_cancel(peer); return }
            let session = HelperPeerSession()
            xpc_connection_set_event_handler(peer) { message in
                if xpc_get_type(message) == XPC_TYPE_ERROR {
                    Task { await stopUplinks(for: session) }
                    return
                }
                handle(message, peer: peer, session: session)
            }
            xpc_connection_activate(peer)
        }
        signal(SIGTERM, SIG_IGN)
        let terminationSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        terminationSource.setEventHandler {
            guard beginTermination() else { return }
            Task {
                await stopAllUplinks()
                exit(0)
            }
        }
        terminationSource.resume()

        xpc_connection_activate(listener)
        withExtendedLifetime(terminationSource) { dispatchMain() }
    }

    private static func handle(
        _ message: xpc_object_t,
        peer: xpc_connection_t,
        session: HelperPeerSession
    ) {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
              let reply = xpc_dictionary_create_reply(message) else { return }
        do {
            guard xpc_dictionary_get_int64(message, "version") == PrivilegedPortProtocol.version else {
                throw EngineError(.unsupported, "incompatible privileged networking helper protocol")
            }
            try authenticate(message)
            guard let operationValue = xpc_dictionary_get_string(message, "operation") else {
                throw EngineError(.badRequest, "privileged networking helper request has no operation")
            }
            switch String(cString: operationValue) {
            case "status":
                xpc_dictionary_set_bool(reply, "ok", true)
                xpc_dictionary_set_int64(
                    reply, "protocol-version", PrivilegedPortProtocol.version
                )
                PrivilegedPortProtocol.buildFingerprint.withCString {
                    xpc_dictionary_set_string(reply, "build-fingerprint", $0)
                }
                PrivilegedPortProtocol.serviceName.withCString {
                    xpc_dictionary_set_string(reply, "service-name", $0)
                }
                xpc_dictionary_set_uint64(reply, "owner-uid", UInt64(ownerUID()))
                xpc_dictionary_set_int64(reply, "pid", Int64(getpid()))
            case "restart":
                guard testControlEnabled else {
                    throw EngineError(.unsupported, "networking helper restart control is disabled")
                }
                xpc_dictionary_set_bool(reply, "ok", true)
                xpc_connection_send_message(peer, reply)
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                    guard beginTermination() else { return }
                    Task {
                        await stopAllUplinks()
                        exit(0)
                    }
                }
                return
            case "bind":
                let descriptor = try boundSocket(for: try bindRequest(message))
                xpc_dictionary_set_bool(reply, "ok", true)
                xpc_dictionary_set_fd(reply, "socket", descriptor)
                close(descriptor)
            case "start-vmnet":
                var length = 0
                guard let bytes = xpc_dictionary_get_data(message, "request", &length), length > 0 else {
                    throw EngineError(.badRequest, "vmnet request has no payload")
                }
                let request = try JSONDecoder().decode(
                    PrivilegedVMNetRequest.self,
                    from: Data(bytes: bytes, count: length)
                )
                try validate(request)
                let resourceID = request.resourceID
                let replyBox = SendableXPCObject(reply)
                let peerBox = SendableXPCObject(peer)
                Task {
                    do {
                        let previous = uplinkLock.withLock { () -> HelperVMNetUplink? in
                            guard !isTerminating, !session.isClosed else { return nil }
                            guard let previous = uplinks.removeValue(forKey: resourceID) else { return nil }
                            previous.owner.networkIDs.remove(resourceID)
                            return previous.uplink
                        }
                        await previous?.stop()
                        guard !uplinkLock.withLock({ isTerminating || session.isClosed }) else {
                            throw EngineError(.internalError, "vmnet client disconnected")
                        }
                        let (uplink, clientDescriptor) = try await HelperVMNetUplink.start(request: request)
                        let registration = uplinkLock.withLock { () -> (Bool, HelperVMNetUplink?) in
                            guard !isTerminating, !session.isClosed else { return (false, nil) }
                            let displaced = uplinks.removeValue(forKey: resourceID)
                            displaced?.owner.networkIDs.remove(resourceID)
                            uplinks[resourceID] = OwnedHelperVMNetUplink(owner: session, uplink: uplink)
                            session.networkIDs.insert(resourceID)
                            return (true, displaced?.uplink)
                        }
                        guard registration.0 else {
                            await uplink.stop()
                            close(clientDescriptor)
                            throw EngineError(.internalError, "vmnet client disconnected")
                        }
                        await registration.1?.stop()
                        xpc_dictionary_set_bool(replyBox.value, "ok", true)
                        xpc_dictionary_set_fd(replyBox.value, "packet-socket", clientDescriptor)
                        close(clientDescriptor)
                    } catch {
                        setError(error, reply: replyBox.value)
                    }
                    xpc_connection_send_message(peerBox.value, replyBox.value)
                }
                return
            case "stop-vmnet":
                guard let value = xpc_dictionary_get_string(message, "network-id") else {
                    throw EngineError(.badRequest, "vmnet stop request has no network id")
                }
                let id = String(cString: value)
                let replyBox = SendableXPCObject(reply)
                let peerBox = SendableXPCObject(peer)
                Task {
                    let uplink = uplinkLock.withLock { () -> HelperVMNetUplink? in
                        guard let owned = uplinks[id], owned.owner === session else { return nil }
                        uplinks.removeValue(forKey: id)
                        session.networkIDs.remove(id)
                        return owned.uplink
                    }
                    await uplink?.stop()
                    xpc_dictionary_set_bool(replyBox.value, "ok", true)
                    xpc_connection_send_message(peerBox.value, replyBox.value)
                }
                return
            default:
                throw EngineError(.unsupported, "unsupported privileged networking helper operation")
            }
        } catch {
            setError(error, reply: reply)
        }
        xpc_connection_send_message(peer, reply)
    }

    private static func beginTermination() -> Bool {
        uplinkLock.withLock {
            guard !isTerminating else { return false }
            isTerminating = true
            return true
        }
    }

    private static func stopAllUplinks() async {
        let active = uplinkLock.withLock { () -> [HelperVMNetUplink] in
            let values = uplinks.values.map(\.uplink)
            let sessions = uplinks.values.map(\.owner)
            for session in sessions {
                session.isClosed = true
                session.networkIDs.removeAll()
            }
            uplinks.removeAll()
            return values
        }
        await withTaskGroup(of: Void.self) { group in
            for uplink in active {
                group.addTask { await uplink.stop() }
            }
        }
    }

    private static func stopUplinks(for session: HelperPeerSession) async {
        let owned = uplinkLock.withLock { () -> [(String, HelperVMNetUplink)] in
            guard !session.isClosed else { return [] }
            session.isClosed = true
            let values = session.networkIDs.compactMap { id -> (String, HelperVMNetUplink)? in
                guard let value = uplinks[id], value.owner === session else { return nil }
                return (id, value.uplink)
            }
            session.networkIDs.removeAll()
            return values
        }
        for (id, uplink) in owned {
            await uplink.stop()
            uplinkLock.withLock {
                guard let value = uplinks[id], value.owner === session, value.uplink === uplink else { return }
                uplinks.removeValue(forKey: id)
            }
        }
    }

    private static func bindRequest(_ message: xpc_object_t) throws -> PrivilegedPortRequest {
        guard let addressValue = xpc_dictionary_get_string(message, "address"),
              let transportValue = xpc_dictionary_get_string(message, "transport"),
              let port = UInt16(exactly: xpc_dictionary_get_uint64(message, "port")),
              let transport = PrivilegedPortRequest.Transport(rawValue: String(cString: transportValue)) else {
            throw EngineError(.badRequest, "malformed privileged bind request")
        }
        return try PrivilegedPortRequest(address: String(cString: addressValue), port: port, transport: transport)
    }

    private static func authenticate(_ message: xpc_object_t) throws {
        guard let expectedAuthenticationToken else { return }
        guard let value = xpc_dictionary_get_string(message, "authentication-token"),
              String(cString: value) == expectedAuthenticationToken else {
            throw EngineError(.unauthorized, "privileged networking helper authentication failed")
        }
    }

    private static func ownerUID() -> uid_t {
        guard let value = environment[PrivilegedPortProtocol.ownerUIDEnvironmentKey],
              let owner = uid_t(value) else { return 0 }
        return owner
    }

    private static func validate(_ request: PrivilegedVMNetRequest) throws {
        guard !request.namespace.isEmpty, request.namespace.utf8.count <= 128 else {
            throw EngineError(.badRequest, "invalid vmnet namespace")
        }
        guard !request.id.isEmpty, request.id.utf8.count <= 128 else {
            throw EngineError(.badRequest, "invalid vmnet network id")
        }
        guard (1...4094).contains(request.vlan) else { throw EngineError(.badRequest, "invalid vmnet VLAN") }
        guard !request.subnet.isEmpty || !request.ipv6Subnet.isEmpty else {
            throw EngineError(.badRequest, "vmnet network requires an IPv4 subnet or IPv6 prefix")
        }
        if request.subnet.isEmpty {
            guard request.gateway.isEmpty else {
                throw EngineError(.badRequest, "vmnet IPv4 gateway requires an IPv4 subnet")
            }
            guard request.ports.isEmpty else {
                throw EngineError(.badRequest, "vmnet port forwarding requires an IPv4 subnet")
            }
        } else {
            _ = try VMNetIPv4Configuration.gateway(request.gateway, in: request.subnet)
        }
        if !request.ipv6Subnet.isEmpty { _ = try HelperVMNetUplink.ipv6Prefix(request.ipv6Subnet) }
        for port in request.ports {
            var address = in_addr()
            guard inet_pton(AF_INET, port.internalAddress, &address) == 1,
                  port.externalPort > 0, port.internalPort > 0,
                  port.proto.lowercased() == "tcp" || port.proto.lowercased() == "udp" else {
                throw EngineError(.badRequest, "invalid vmnet port-forwarding rule")
            }
        }
    }

    private static func setError(_ error: Error, reply: xpc_object_t) {
        xpc_dictionary_set_bool(reply, "ok", false)
        let message = (error as? EngineError)?.message ?? String(describing: error)
        message.withCString { xpc_dictionary_set_string(reply, "error", $0) }
    }

    private static func boundSocket(for request: PrivilegedPortRequest) throws -> CInt {
        let family = request.address.contains(":") ? AF_INET6 : AF_INET
        let kind = request.transport == .tcp ? SOCK_STREAM : SOCK_DGRAM
        let descriptor = socket(family, kind, 0)
        guard descriptor >= 0 else { throw posixError("socket", address: request.address, port: request.port) }
        do {
            var one: CInt = 1
            guard setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
                throw posixError("setsockopt(SO_REUSEADDR)", address: request.address, port: request.port)
            }
            if family == AF_INET6 {
                guard setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
                    throw posixError("setsockopt(IPV6_V6ONLY)", address: request.address, port: request.port)
                }
            }
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
                throw posixError("fcntl", address: request.address, port: request.port)
            }
            if family == AF_INET6 {
                var value = sockaddr_in6()
                value.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                value.sin6_family = sa_family_t(AF_INET6)
                value.sin6_port = request.port.bigEndian
                guard request.address.withCString({ inet_pton(AF_INET6, $0, &value.sin6_addr) }) == 1 else {
                    throw EngineError(.badRequest, "invalid IPv6 bind address")
                }
                let status = withUnsafePointer(to: &value) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                    }
                }
                guard status == 0 else { throw posixError("bind", address: request.address, port: request.port) }
            } else {
                var value = sockaddr_in()
                value.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                value.sin_family = sa_family_t(AF_INET)
                value.sin_port = request.port.bigEndian
                guard request.address.withCString({ inet_pton(AF_INET, $0, &value.sin_addr) }) == 1 else {
                    throw EngineError(.badRequest, "invalid IPv4 bind address")
                }
                let status = withUnsafePointer(to: &value) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                guard status == 0 else { throw posixError("bind", address: request.address, port: request.port) }
            }
            if request.transport == .tcp, listen(descriptor, SOMAXCONN) != 0 {
                throw posixError("listen", address: request.address, port: request.port)
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private static func posixError(_ operation: String, address: String, port: UInt16) -> EngineError {
        let code = errno
        return EngineError(
            .internalError,
            "\(operation) \(address):\(port) failed: \(String(cString: strerror(code))) (errno \(code))"
        )
    }
}

private final class HelperVMNetUplink: @unchecked Sendable {
    private let network: RetainedOpaquePointer
    private let interface: interface_ref
    private let queue: DispatchQueue
    private let vlan: UInt16
    private let packets: FileHandle
    private let lock = NSLock()
    private var stopTask: Task<Void, Never>?

    static func start(request: PrivilegedVMNetRequest) async throws -> (HelperVMNetUplink, CInt) {
        let networkOwner = try createNetwork(request: request)
        let descriptor = xpc_dictionary_create(nil, nil, 0)
        // A cengine uplink is a VLAN trunk carrying many container MAC addresses,
        // not a single VM interface using a vmnet-assigned address.
        xpc_dictionary_set_bool(descriptor, vmnet_allocate_mac_address_key, false)
        // Frames arrive from a virtio device, so vmnet must complete transport
        // checksums before forwarding them onto the shared network.
        xpc_dictionary_set_bool(descriptor, vmnet_enable_checksum_offload_key, true)
        let queue = DispatchQueue(label: "dev.cengine.vmnet.\(request.id)")
        var reference: interface_ref?
        do {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                reference = vmnet_interface_start_with_network(networkOwner.value, descriptor, queue) { status, _ in
                    if status == .VMNET_SUCCESS { continuation.resume() }
                    else { continuation.resume(throwing: failure("start vmnet interface", status)) }
                }
                if reference == nil {
                    continuation.resume(throwing: EngineError(.internalError, "vmnet did not create an interface"))
                }
            }
        } catch {
            if let reference {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    let status = vmnet_stop_interface(reference, queue) { _ in continuation.resume() }
                    if status != .VMNET_SUCCESS { continuation.resume() }
                }
            }
            throw error
        }
        guard let reference else { throw EngineError(.internalError, "vmnet interface is unavailable") }
        var sockets: [CInt] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else {
            await stopInterface(reference, queue: queue)
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        do {
            for descriptor in sockets {
                var bufferSize: CInt = 4 * 1024 * 1024
                guard setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &bufferSize, socklen_t(MemoryLayout.size(ofValue: bufferSize))) == 0,
                      setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &bufferSize, socklen_t(MemoryLayout.size(ofValue: bufferSize))) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
            }
        } catch {
            sockets.forEach { close($0) }
            await stopInterface(reference, queue: queue)
            throw error
        }
        let value = HelperVMNetUplink(
            network: networkOwner,
            interface: reference,
            queue: queue,
            vlan: request.vlan,
            packets: FileHandle(fileDescriptor: sockets[0], closeOnDealloc: true)
        )
        value.startReading()
        return (value, sockets[1])
    }

    private static func createNetwork(request: PrivilegedVMNetRequest) throws -> RetainedOpaquePointer {
        var status = vmnet_return_t.VMNET_SUCCESS
        let mode = request.internalNetwork ? vmnet_mode_t.VMNET_HOST_MODE : vmnet_mode_t.VMNET_SHARED_MODE
        guard let configuration = vmnet_network_configuration_create(mode, &status), status == .VMNET_SUCCESS else {
            throw failure("create vmnet configuration", status)
        }
        let configurationOwner = RetainedOpaquePointer(configuration, release: releaseCFObject)
        defer { withExtendedLifetime(configurationOwner) {} }
        if !request.dhcpEnabled {
            vmnet_network_configuration_disable_dhcp(configuration)
        }
        if request.subnet.isEmpty {
            vmnet_network_configuration_disable_nat44(configuration)
        } else {
            let (_, mask) = try VMNetIPv4Configuration.subnet(request.subnet)
            var subnetValue = try VMNetIPv4Configuration.gateway(request.gateway, in: request.subnet)
            var maskValue = mask
            guard vmnet_network_configuration_set_ipv4_subnet(configuration, &subnetValue, &maskValue) == .VMNET_SUCCESS else {
                throw EngineError(.badRequest, "vmnet rejected subnet \(request.subnet)")
            }
        }
        if !request.ipv6Subnet.isEmpty {
            let (prefix, prefixLength) = try ipv6Prefix(request.ipv6Subnet)
            var prefixValue = prefix
            guard vmnet_network_configuration_set_ipv6_prefix(configuration, &prefixValue, prefixLength) == .VMNET_SUCCESS else {
                throw EngineError(.badRequest, "vmnet rejected IPv6 prefix \(request.ipv6Subnet)")
            }
        } else {
            vmnet_network_configuration_disable_nat66(configuration)
            vmnet_network_configuration_disable_router_advertisement(configuration)
        }
        for port in request.internalNetwork ? [] : request.ports {
            var address = in_addr()
            guard inet_pton(AF_INET, port.internalAddress, &address) == 1 else {
                throw EngineError(.badRequest, "invalid port-forward address \(port.internalAddress)")
            }
            let proto = port.proto.lowercased() == "udp" ? UInt8(IPPROTO_UDP) : UInt8(IPPROTO_TCP)
            let result = withUnsafePointer(to: &address) {
                vmnet_network_configuration_add_port_forwarding_rule(
                    configuration, proto, sa_family_t(AF_INET),
                    port.internalPort, port.externalPort, $0
                )
            }
            guard result == .VMNET_SUCCESS else { throw failure("configure vmnet port forwarding", result) }
        }
        guard let network = vmnet_network_create(configuration, &status), status == .VMNET_SUCCESS else {
            throw failure("reserve vmnet network", status)
        }
        return RetainedOpaquePointer(network, release: releaseCFObject)
    }

    private init(
        network: RetainedOpaquePointer,
        interface: interface_ref,
        queue: DispatchQueue,
        vlan: UInt16,
        packets: FileHandle
    ) {
        self.network = network
        self.interface = interface
        self.queue = queue
        self.vlan = vlan
        self.packets = packets
        packets.readabilityHandler = { [weak self] handle in self?.writeTagged(handle.availableData) }
    }

    func stop() async {
        let task = lock.withLock { () -> Task<Void, Never> in
            if let stopTask { return stopTask }
            let task = Task { [self] in await performStop() }
            stopTask = task
            return task
        }
        await task.value
    }

    private func performStop() async {
        packets.readabilityHandler = nil
        try? packets.close()
        _ = vmnet_interface_set_event_callback(interface, .VMNET_INTERFACE_PACKETS_AVAILABLE, nil, nil)
        await Self.stopInterface(interface, queue: queue)
        network.release()
    }

    private func startReading() {
        let result = vmnet_interface_set_event_callback(interface, .VMNET_INTERFACE_PACKETS_AVAILABLE, queue) {
            [weak self] _, _ in self?.readAvailable()
        }
        if result != .VMNET_SUCCESS { Task { await stop() } }
    }

    private static func stopInterface(_ interface: interface_ref, queue: DispatchQueue) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let status = vmnet_stop_interface(interface, queue) { _ in continuation.resume() }
            if status != .VMNET_SUCCESS { continuation.resume() }
        }
    }

    private static func releaseCFObject(_ pointer: OpaquePointer) {
        Unmanaged<AnyObject>.fromOpaque(UnsafeRawPointer(pointer)).release()
    }

    private func readAvailable() {
        while true {
            var storage = [UInt8](repeating: 0, count: 65_535)
            let received: Data? = storage.withUnsafeMutableBytes { bytes in
                var vector = iovec(iov_base: bytes.baseAddress, iov_len: bytes.count)
                return withUnsafeMutablePointer(to: &vector) { vectorPointer in
                    var packet = vmpktdesc(
                        vm_pkt_size: bytes.count, vm_pkt_iov: vectorPointer,
                        vm_pkt_iovcnt: 1, vm_flags: 0
                    )
                    var count: Int32 = 1
                    let result = vmnet_read(interface, &packet, &count)
                    guard result == .VMNET_SUCCESS, count == 1, packet.vm_pkt_size > 0 else { return nil }
                    return Data(bytes: bytes.baseAddress!, count: packet.vm_pkt_size)
                }
            }
            guard let received else { return }
            try? packets.write(contentsOf: Self.tag(received, vlan: vlan))
        }
    }

    private func writeTagged(_ packet: Data) {
        guard let untagged = Self.untag(packet, vlan: vlan) else { return }
        untagged.withUnsafeBytes { bytes in
            var vector = iovec(
                iov_base: UnsafeMutableRawPointer(mutating: bytes.baseAddress),
                iov_len: bytes.count
            )
            withUnsafeMutablePointer(to: &vector) { vectorPointer in
                var descriptor = vmpktdesc(
                    vm_pkt_size: bytes.count, vm_pkt_iov: vectorPointer,
                    vm_pkt_iovcnt: 1, vm_flags: 0
                )
                var count: Int32 = 1
                _ = vmnet_write(interface, &descriptor, &count)
            }
        }
    }

    private static func tag(_ frame: Data, vlan: UInt16) -> Data {
        guard frame.count >= 14 else { return frame }
        var output = Data(frame.prefix(12))
        output.append(contentsOf: [0x81, 0x00, UInt8((vlan >> 8) & 0x0f), UInt8(vlan & 0xff)])
        output.append(frame.dropFirst(12))
        return output
    }

    private static func untag(_ frame: Data, vlan: UInt16) -> Data? {
        guard frame.count >= 18, frame[12] == 0x81, frame[13] == 0x00 else { return nil }
        let value = (UInt16(frame[14] & 0x0f) << 8) | UInt16(frame[15])
        guard value == vlan else { return nil }
        var output = Data(frame.prefix(12))
        output.append(frame.dropFirst(16))
        return output
    }

    static func ipv6Prefix(_ value: String) throws -> (in6_addr, UInt8) {
        let parts = value.split(separator: "/")
        guard parts.count == 2, let length = UInt8(parts[1]), length <= 128 else {
            throw EngineError(.badRequest, "invalid IPv6 prefix \(value)")
        }
        var prefix = in6_addr()
        guard inet_pton(AF_INET6, String(parts[0]), &prefix) == 1 else {
            throw EngineError(.badRequest, "invalid IPv6 prefix \(value)")
        }
        return (prefix, length)
    }

    private static func failure(_ operation: String, _ status: vmnet_return_t) -> EngineError {
        EngineError(.internalError, "\(operation) failed with vmnet status \(status.rawValue)")
    }
}
