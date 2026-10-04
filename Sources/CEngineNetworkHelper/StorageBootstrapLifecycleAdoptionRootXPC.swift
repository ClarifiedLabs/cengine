import CEngineHelperSupport
import Darwin
import Foundation
@preconcurrency import XPC

/// Closed, scope-bound adoption envelope. No wire field can select a new scope.
enum StorageBootstrapLifecycleAdoptionRootXPC {
    typealias Wire = StorageLifecycleAdoptionRootProtocol
    static let budget: TimeInterval = 30
    static let descriptorKeys = ["path-lock", "store-root", "daemon-lock"]

    static func decodeRequest(_ message: xpc_object_t) throws -> Wire.Request {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY, xpc_dictionary_get_count(message) == 5 else {
            throw BootstrapFailure(.invalidRequest)
        }
        let allowed = Set(["operation", "request"] + descriptorKeys)
        guard xpc_dictionary_apply(message, { key, value in
            guard strnlen(key, 32) < 32 else { return false }
            let name = String(cString: key)
            guard allowed.contains(name) else { return false }
            switch name {
            case "operation": return xpc_get_type(value) == XPC_TYPE_STRING &&
                xpc_string_get_length(value) == Wire.xpcOperation.utf8.count &&
                xpc_string_get_string_ptr(value).map { String(cString: $0) == Wire.xpcOperation } == true
            case "request": return xpc_get_type(value) == XPC_TYPE_DATA && xpc_data_get_length(value) > 0 &&
                xpc_data_get_length(value) <= Wire.maximumPayloadBytes
            default: return xpc_get_type(value) == XPC_TYPE_FD
            }
        }) else { throw BootstrapFailure(.invalidRequest) }
        var count = 0
        guard let bytes = xpc_dictionary_get_data(message, "request", &count) else { throw BootstrapFailure(.invalidRequest) }
        do { return try Wire.decodeRequest(Data(bytes: bytes, count: count)) }
        catch { throw BootstrapFailure(.invalidRequest) }
    }

    static func withDescriptors<T>(_ message: xpc_object_t, request: Wire.Request,
                                   _ body: (Int32, Int32, Int32) throws -> T) throws -> T {
        guard try decodeRequest(message) == request else { throw BootstrapFailure(.invalidRequest) }
        var descriptors: [Int32] = []
        defer { descriptors.forEach { close($0) } }
        for key in descriptorKeys {
            let fd = xpc_dictionary_dup_fd(message, key)
            guard fd >= 0 else { throw BootstrapFailure(.unavailable) }
            descriptors.append(fd)
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw BootstrapFailure(.unavailable) }
        }
        return try body(descriptors[0], descriptors[1], descriptors[2])
    }

    /// Caller supplies only protected scope evidence and the actual Mach identity.
    static func dispatch(_ request: Wire.Request, authority: StorageBootstrapLifecycleAdoptionAuthority,
                         origin: Adoption.Origin, peer: BootstrapAuditIdentity,
                         service: ((Adoption.Request, Lifecycle.Grant) throws -> Lifecycle.ServiceState)? = nil,
                         completeServiceChange: ((Adoption.Request, Lifecycle.ServiceChangeRequest) throws -> (Lifecycle.ServiceChangeConfirmation, Lifecycle.ServiceResult))? = nil,
                         handoffStatus: ((Lifecycle.Identity) throws -> StorageLifecycleHandoffRootProtocol.Status)? = nil,
                         recoverHandoff: ((Lifecycle.Identity, String) throws -> StorageLifecycleHandoffRootProtocol.Completed)? = nil) throws -> Wire.ResultBody {
        switch request.body {
        case .handoffStatus(let identity):
            guard try identity == Lifecycle.Identity(binding: origin.binding.value(), generation: identity.generation),
                  let handoffStatus else { throw BootstrapFailure(.unauthorized) }
            return try .handoffStatus(handoffStatus(identity))
        case .recoverHandoff(let identity, let id):
            guard try identity == Lifecycle.Identity(binding: origin.binding.value(), generation: identity.generation),
                  let recoverHandoff else { throw BootstrapFailure(.unauthorized) }
            return try .handoffRecovered(recoverHandoff(identity, id))
        case .completeServiceChange(let adoption, let change):
            guard adoption.origin == origin, let completeServiceChange else { throw BootstrapFailure(.unauthorized) }
            let (confirmation, result) = try completeServiceChange(adoption, change)
            return .serviceChanged(confirmation, result)
        case .service(let adoption, let grant):
            guard adoption.origin == origin, let service else { throw BootstrapFailure(.unauthorized) }
            return try .service(service(adoption, grant))
        case .status:
            let status = try authority.status(store: origin.binding.store)
            guard status.origin == origin else { throw BootstrapFailure(.conflict) }
            return .status(status)
        case .prepare(let adoption):
            guard adoption.origin == origin else { throw BootstrapFailure(.conflict) }
            try authority.prepare(adoption, peer: peer)
            return try .prepared(adoption.fenceIdentity)
        case .complete(let adoption):
            guard adoption.origin == origin else { throw BootstrapFailure(.conflict) }
            guard try authority.complete(adoption, peer: peer) == adoption.epoch else { throw BootstrapFailure(.conflict) }
            return try .completed(adoption.fenceIdentity)
        }
    }
}
