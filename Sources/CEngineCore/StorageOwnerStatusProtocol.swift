import Foundation
#if os(macOS)
@preconcurrency import XPC
#endif

/// Informational only: this snapshot neither enrolls an owner nor grants storage authority.
public enum StorageOwnerStatus: Equatable, Sendable {
    case absent
    case disabled
    case enrolled(UInt32)
}

#if os(macOS)
public enum StorageOwnerStatusProtocol {
    public static let operation = "storage-owner-status"
    public static let version: Int64 = 1

    public static func validateRequest(_ message: xpc_object_t) throws {
        guard keys(message) == ["operation", "version"],
              string(message, "operation") == operation,
              let value = xpc_dictionary_get_value(message, "version"), xpc_get_type(value) == XPC_TYPE_INT64,
              xpc_int64_get_value(value) == version else { throw malformed() }
    }

    public static func encode(_ status: StorageOwnerStatus, into reply: xpc_object_t) throws {
        xpc_dictionary_set_bool(reply, "ok", true)
        xpc_dictionary_set_int64(reply, "version", version)
        let state: String
        switch status {
        case .absent: state = "absent"
        case .disabled: state = "disabled"
        case .enrolled(let uid):
            guard uid != 0 else { throw malformed() }
            state = "enrolled"
            xpc_dictionary_set_uint64(reply, "owner-uid", UInt64(uid))
        }
        state.withCString { xpc_dictionary_set_string(reply, "state", $0) }
    }

    /// Shape validation only. The transport must authenticate the root helper first.
    public static func decode(_ reply: xpc_object_t) throws -> StorageOwnerStatus {
        guard let fields = keys(reply), let ok = xpc_dictionary_get_value(reply, "ok"),
              xpc_get_type(ok) == XPC_TYPE_BOOL else { throw malformed() }
        if !xpc_bool_get_value(ok) {
            guard fields == ["ok", "error"], let text = string(reply, "error"), text.utf8.count <= 1024 else { throw malformed() }
            throw EngineError(.serviceUnavailable, "Storage owner status is unavailable")
        }
        guard let value = xpc_dictionary_get_value(reply, "version"), xpc_get_type(value) == XPC_TYPE_INT64,
              xpc_int64_get_value(value) == version, let state = string(reply, "state") else { throw malformed() }
        if state == "enrolled" {
            guard fields == ["ok", "version", "state", "owner-uid"],
                  let uid = xpc_dictionary_get_value(reply, "owner-uid"), xpc_get_type(uid) == XPC_TYPE_UINT64,
                  let owner = UInt32(exactly: xpc_uint64_get_value(uid)), owner != 0 else { throw malformed() }
            return .enrolled(owner)
        }
        guard fields == ["ok", "version", "state"] else { throw malformed() }
        switch state {
        case "absent": return .absent
        case "disabled": return .disabled
        default: throw malformed()
        }
    }

    private static func keys(_ message: xpc_object_t) -> Set<String>? {
        guard xpc_get_type(message) == XPC_TYPE_DICTIONARY, xpc_dictionary_get_count(message) <= 4 else { return nil }
        var result = Set<String>()
        xpc_dictionary_apply(message) { key, _ in result.insert(String(cString: key)); return true }
        return result
    }
    private static func string(_ message: xpc_object_t, _ key: String) -> String? {
        guard let value = xpc_dictionary_get_value(message, key), xpc_get_type(value) == XPC_TYPE_STRING,
              xpc_string_get_length(value) <= 1024, let text = xpc_string_get_string_ptr(value) else { return nil }
        let result = String(cString: text)
        return result.utf8.count == xpc_string_get_length(value) ? result : nil
    }
    private static func malformed() -> EngineError {
        EngineError(.badRequest, "Malformed storage owner status message")
    }
}
#endif
