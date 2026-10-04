import CEngineHelperSupport
import Darwin
import Foundation
@preconcurrency import XPC

/// Closed, scope-bound cold envelope. No wire field can select a new scope.
enum StorageBootstrapLifecycleColdRootXPC {
    typealias Wire = StorageLifecycleColdRootProtocol
    // Cold completion includes multiple native proof rounds around L2/A1/L3.
    static let budget: TimeInterval = 120
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

}
