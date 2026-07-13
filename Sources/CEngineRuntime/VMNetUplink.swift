#if os(macOS)
import CEngineCore
import Darwin
import Foundation
@preconcurrency import XPC

final class VMNetUplink: @unchecked Sendable {
    let fabricFileHandle: FileHandle

    private let networkID: String
    private let serviceName: String
    private let teamIdentifier: String
    private let lock = NSLock()
    private var stopped = false

    static func start(network: VMShimClient.FabricNetwork) async throws -> VMNetUplink {
        let request = PrivilegedVMNetRequest(
            id: network.id,
            vlan: network.vlan,
            subnet: network.subnet,
            ipv6Subnet: network.ipv6Subnet,
            internalNetwork: network.internalNetwork,
            dhcpEnabled: false,
            ports: network.ports.map {
                .init(
                    proto: $0.proto,
                    externalPort: $0.externalPort,
                    internalAddress: $0.internalAddress,
                    internalPort: $0.internalPort
                )
            }
        )
        let serviceName = PrivilegedPortProtocol.serviceName
        let teamIdentifier = Bundle.main.object(forInfoDictionaryKey: "CEngineTeamIdentifier") as? String ?? ""
        let descriptor = try await requestUplink(request, serviceName: serviceName, teamIdentifier: teamIdentifier)
        return VMNetUplink(
            networkID: request.id,
            descriptor: descriptor,
            serviceName: serviceName,
            teamIdentifier: teamIdentifier
        )
    }

    private init(networkID: String, descriptor: CInt, serviceName: String, teamIdentifier: String) {
        self.networkID = networkID
        self.serviceName = serviceName
        self.teamIdentifier = teamIdentifier
        fabricFileHandle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    func stop() {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        stopped = true
        lock.unlock()
        try? fabricFileHandle.close()

        let connection = xpc_connection_create_mach_service(serviceName, nil, 0)
        let requirement = Self.signingRequirement(identifier: PrivilegedPortProtocol.helperIdentifier, teamIdentifier: teamIdentifier)
        guard requirement.withCString({ xpc_connection_set_peer_code_signing_requirement(connection, $0) }) == 0 else {
            xpc_connection_cancel(connection)
            return
        }
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_activate(connection)
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        xpc_dictionary_set_string(message, "operation", "stop-vmnet")
        networkID.withCString { xpc_dictionary_set_string(message, "network-id", $0) }
        xpc_connection_send_message_with_reply(connection, message, nil) { _ in
            xpc_connection_cancel(connection)
        }
    }

    private static func requestUplink(
        _ request: PrivilegedVMNetRequest,
        serviceName: String,
        teamIdentifier: String
    ) async throws -> CInt {
        let encoded = try JSONEncoder().encode(request)
        return try await awaitUplinkReply(timeout: .seconds(5)) { reply in
            let connection = xpc_connection_create_mach_service(serviceName, nil, 0)
            reply.attach(connection)
            let requirement = signingRequirement(identifier: PrivilegedPortProtocol.helperIdentifier, teamIdentifier: teamIdentifier)
            let status = requirement.withCString {
                xpc_connection_set_peer_code_signing_requirement(connection, $0)
            }
            guard status == 0 else {
                reply.finish(.failure(EngineError(
                    .internalError, "could not secure privileged networking helper connection (status \(status))"
                )))
                return
            }
            xpc_connection_set_event_handler(connection) { _ in }
            xpc_connection_activate(connection)
            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
            xpc_dictionary_set_string(message, "operation", "start-vmnet")
            encoded.withUnsafeBytes { bytes in
                xpc_dictionary_set_data(message, "request", bytes.baseAddress, bytes.count)
            }
            xpc_connection_send_message_with_reply(connection, message, nil) { response in
                guard xpc_get_type(response) == XPC_TYPE_DICTIONARY else {
                    reply.finish(.failure(EngineError(
                        .unsupported,
                        "privileged networking helper is unavailable; enable Networking in the cengine app"
                    )))
                    return
                }
                guard xpc_dictionary_get_bool(response, "ok") else {
                    let message = xpc_dictionary_get_string(response, "error").map(String.init(cString:))
                        ?? "privileged networking helper rejected vmnet startup"
                    reply.finish(.failure(EngineError(.internalError, message)))
                    return
                }
                let descriptor = xpc_dictionary_dup_fd(response, "packet-socket")
                guard descriptor >= 0 else {
                    reply.finish(.failure(EngineError(.internalError, "privileged networking helper returned no packet socket")))
                    return
                }
                var socketType: CInt = 0
                var length = socklen_t(MemoryLayout<CInt>.size)
                guard getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socketType, &length) == 0,
                      socketType == CInt(SOCK_DGRAM) else {
                    close(descriptor)
                    reply.finish(.failure(EngineError(.internalError, "privileged networking helper returned an invalid packet socket")))
                    return
                }
                reply.finish(.success(descriptor))
            }
        }
    }

    static func awaitUplinkReply(
        timeout: Duration,
        start: @escaping @Sendable (VMNetUplinkReply) -> Void
    ) async throws -> CInt {
        try await withCheckedThrowingContinuation { continuation in
            let reply = VMNetUplinkReply(continuation: continuation)
            Task {
                try? await Task.sleep(for: timeout)
                reply.finish(.failure(EngineError(
                    .unsupported,
                    "timed out waiting for privileged networking helper; enable Networking in the cengine app"
                )))
            }
            start(reply)
        }
    }

    private static func signingRequirement(identifier: String, teamIdentifier: String) -> String {
        guard !teamIdentifier.isEmpty else { return "identifier \"\(identifier)\"" }
        return "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
    }

    static func tag(_ frame: Data, vlan: UInt16) -> Data {
        guard frame.count >= 14 else { return frame }
        var output = Data(frame.prefix(12))
        output.append(contentsOf: [0x81, 0x00, UInt8((vlan >> 8) & 0x0f), UInt8(vlan & 0xff)])
        output.append(frame.dropFirst(12))
        return output
    }

    static func untag(_ frame: Data, vlan: UInt16) -> Data? {
        guard frame.count >= 18, frame[12] == 0x81, frame[13] == 0x00 else { return nil }
        let value = (UInt16(frame[14] & 0x0f) << 8) | UInt16(frame[15])
        guard value == vlan else { return nil }
        var output = Data(frame.prefix(12))
        output.append(frame.dropFirst(16))
        return output
    }
}

final class VMNetUplinkReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<CInt, Error>?
    private var connection: xpc_connection_t?

    init(continuation: CheckedContinuation<CInt, Error>) {
        self.continuation = continuation
    }

    func attach(_ connection: xpc_connection_t) {
        lock.lock()
        if continuation == nil {
            lock.unlock()
            xpc_connection_cancel(connection)
            return
        }
        self.connection = connection
        lock.unlock()
    }

    func finish(_ result: Result<CInt, Error>) {
        lock.lock()
        guard let continuation else {
            lock.unlock()
            if case let .success(descriptor) = result {
                close(descriptor)
            }
            return
        }
        self.continuation = nil
        let connection = self.connection
        self.connection = nil
        lock.unlock()

        if let connection {
            xpc_connection_cancel(connection)
        }
        continuation.resume(with: result)
    }
}
#endif
