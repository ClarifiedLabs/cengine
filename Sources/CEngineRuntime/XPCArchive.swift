#if os(macOS)
import CEngineCore
import Foundation
import XPC

indirect enum XPCArchive: Codable {
    case dictionary([String: XPCArchive])
    case array([XPCArchive])
    case data(Data)
    case string(String)
    case signed(Int64)
    case unsigned(UInt64)
    case bool(Bool)
    case double(Double)
    case uuid(UUID)
    case null

    static func encode(_ object: xpc_object_t) throws -> Data {
        try PropertyListEncoder().encode(try capture(object))
    }

    static func decode(_ data: Data) throws -> xpc_object_t {
        try PropertyListDecoder().decode(Self.self, from: data).object()
    }

    private static func capture(_ object: xpc_object_t) throws -> Self {
        switch xpc_get_type(object) {
        case XPC_TYPE_DICTIONARY:
            var result: [String: Self] = [:]
            var failure: Error?
            xpc_dictionary_apply(object) { key, value in
                do { result[String(cString: key)] = try capture(value) }
                catch { failure = error }
                return failure == nil
            }
            if let failure { throw failure }
            return .dictionary(result)
        case XPC_TYPE_ARRAY:
            return .array(try (0..<xpc_array_get_count(object)).map { index in
                try capture(xpc_array_get_value(object, index))
            })
        case XPC_TYPE_DATA:
            let count = xpc_data_get_length(object)
            guard count == 0 || xpc_data_get_bytes_ptr(object) != nil else {
                throw EngineError(.internalError, "vmnet serialization contains invalid XPC data")
            }
            if count == 0 { return .data(Data()) }
            return .data(Data(bytes: xpc_data_get_bytes_ptr(object)!, count: count))
        case XPC_TYPE_STRING:
            guard let value = xpc_string_get_string_ptr(object) else {
                throw EngineError(.internalError, "vmnet serialization contains an invalid XPC string")
            }
            return .string(String(cString: value))
        case XPC_TYPE_INT64: return .signed(xpc_int64_get_value(object))
        case XPC_TYPE_UINT64: return .unsigned(xpc_uint64_get_value(object))
        case XPC_TYPE_BOOL: return .bool(xpc_bool_get_value(object))
        case XPC_TYPE_DOUBLE: return .double(xpc_double_get_value(object))
        case XPC_TYPE_UUID:
            guard let bytes = xpc_uuid_get_bytes(object) else {
                throw EngineError(.internalError, "vmnet serialization contains an invalid UUID")
            }
            var value: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            withUnsafeMutableBytes(of: &value) { $0.copyBytes(from: UnsafeRawBufferPointer(start: bytes, count: 16)) }
            return .uuid(UUID(uuid: value))
        case XPC_TYPE_NULL: return .null
        default:
            let pointer = xpc_copy_description(object)
            defer { free(pointer) }
            let description = String(cString: pointer)
            throw EngineError(.unsupported, "vmnet returned a non-persistable XPC object: \(description)")
        }
    }

    private func object() throws -> xpc_object_t {
        switch self {
        case .dictionary(let values):
            let result = xpc_dictionary_create_empty()
            for (key, value) in values { xpc_dictionary_set_value(result, key, try value.object()) }
            return result
        case .array(let values):
            let result = xpc_array_create_empty()
            for value in values { xpc_array_append_value(result, try value.object()) }
            return result
        case .data(let value): return value.withUnsafeBytes { xpc_data_create($0.baseAddress, $0.count) }
        case .string(let value): return xpc_string_create(value)
        case .signed(let value): return xpc_int64_create(value)
        case .unsigned(let value): return xpc_uint64_create(value)
        case .bool(let value): return xpc_bool_create(value)
        case .double(let value): return xpc_double_create(value)
        case .uuid(let value):
            var bytes = value.uuid
            return withUnsafeBytes(of: &bytes) { xpc_uuid_create($0.baseAddress!.assumingMemoryBound(to: UInt8.self)) }
        case .null: return xpc_null_create()
        }
    }
}
#endif
