#if os(macOS)
import CEngineCore
import Foundation
import Security

/// Value-only workload CONTROL wire contract. Transport ownership, keys and
/// lifecycle authority remain with the child and its owner, never these DTOs.
nonisolated public enum ManagedStorageControlProtocol {
    public enum Failure: Error, Equatable, Sendable { case invalidConfiguration, protocolViolation }
    public static let maximumPayloadBytes = 64 * 1024
    static let maximumReplyBytes = 64 * 1024 * 1024

    public struct AttachmentCertificateRequest: Sendable {
        public let binding: Binding
        public let serviceEpoch: String
        public let controllerEpoch: UInt64
        public let csr: Data
        public init(binding: Binding, serviceEpoch: String, controllerEpoch: UInt64, csr: Data) throws {
            _ = try StorageIdentity.RequestID(serviceEpoch)
            guard controllerEpoch > 0, !csr.isEmpty, csr.count <= 16 * 1024,
                  (binding.role == .prepare) == (binding.prepare != nil) else { throw Failure.invalidConfiguration }
            self.binding = binding; self.serviceEpoch = serviceEpoch
            self.controllerEpoch = controllerEpoch; self.csr = csr
        }
        func wire() throws -> ControllerJSON {
            .object(["attachment": .object(["binding": try ControllerJSON.from(binding), "epoch": .string(serviceEpoch)]),
                "controller_epoch": .number(controllerEpoch), "csr": .string(csr.base64EncodedString())])
        }
    }
    public struct AttachmentCertificate: Sendable {
        public let der: Data
        fileprivate init(_ der: Data) throws {
            guard !der.isEmpty, der.count <= 16 * 1024,
                  SecCertificateCreateWithData(nil, der as CFData) != nil else { throw Failure.protocolViolation }
            self.der = der
        }
    }
    public enum AttachmentCertificateFailure: String, Sendable { case rejected, unavailable }
    public enum AttachmentCertificateResult: Sendable {
        case certificate(AttachmentCertificate)
        case failure(AttachmentCertificateFailure)
        static func decode(_ data: Data) throws -> Self {
            guard case .object(let fields) = try ControllerJSON.parse(data, limit: maximumPayloadBytes) else { throw Failure.protocolViolation }
            if Set(fields.keys) == ["error"], case .string(let text) = fields["error"], let error = AttachmentCertificateFailure(rawValue: text) {
                return .failure(error)
            }
            guard Set(fields.keys) == ["certificate"], case .string(let text) = fields["certificate"],
                  let der = Data(base64Encoded: text), der.base64EncodedString() == text else { throw Failure.protocolViolation }
            // Exact URI/SPKI are checked inside the nonexporting child, not asserted
            // by the parent. This wrapper additionally fences size and DER syntax.
            return .certificate(try AttachmentCertificate(der))
        }
    }
    public enum Role: String, Codable, Sendable { case prepare, runtime }
    public enum Mode: String, Codable, Sendable { case readOnly = "read-only", readWrite = "read-write" }
    public struct Binding: Codable, Equatable, Sendable {
        public let store: String
        public let volume: String
        public let attachment: String
        public let prepare: String?
        public let container: String
        public let launch: String
        public let key: String
        public let role: Role
        public let mode: Mode
        public init(store: String, volume: String, attachment: String, prepare: String? = nil, container: String, launch: String, key: String, role: Role, mode: Mode) throws {
            _ = try StorageIdentity.RequestID(store)
            self.store = store
            _ = try StorageIdentity.RequestID(volume)
            self.volume = volume
            _ = try StorageIdentity.RequestID(attachment)
            self.attachment = attachment
            if let prepare { _ = try StorageIdentity.RequestID(prepare) }
            self.prepare = prepare
            _ = try StorageIdentity.SPKISHA256(container)
            self.container = container
            _ = try StorageIdentity.RequestID(launch)
            self.launch = launch
            _ = try StorageIdentity.SPKISHA256(key)
            self.key = key
            self.role = role
            self.mode = mode
        }
    }
    public struct Receipt: Codable, Equatable, Sendable {
        public let schema: UInt64
        public let store: String
        public let volume: String
        public let attachment: String
        public let prepare: String?
        public let launch: String
        public let revision: UInt64
        public init(schema: UInt64, store: String, volume: String, attachment: String, prepare: String? = nil, launch: String, revision: UInt64) throws {
            guard schema == 3 else { throw Failure.invalidConfiguration }
            self.schema = schema
            _ = try StorageIdentity.RequestID(store)
            self.store = store
            _ = try StorageIdentity.RequestID(volume)
            self.volume = volume
            _ = try StorageIdentity.RequestID(attachment)
            self.attachment = attachment
            if let prepare { _ = try StorageIdentity.RequestID(prepare) }
            self.prepare = prepare
            // A receipt always names the exact generation that produced it; a
            // receipt for any other launch can never satisfy this retirement.
            _ = try StorageIdentity.RequestID(launch)
            self.launch = launch
            guard revision > 0 else { throw Failure.invalidConfiguration }
            self.revision = revision
        }
    }
    public struct Attestation: Codable, Equatable, Sendable {
        public let prepare: String
        public let succeeded: Bool
        public let cleanCopyUp: Bool
        public init(prepare: String, succeeded: Bool, cleanCopyUp: Bool) throws {
            _ = try StorageIdentity.RequestID(prepare)
            self.prepare = prepare
            self.succeeded = succeeded
            self.cleanCopyUp = cleanCopyUp
        }
        enum CodingKeys: String, CodingKey { case prepare, succeeded, cleanCopyUp = "clean_copy_up" }
    }
    public struct ReserveRequest: Encodable, Sendable {
        public let operation: String
        public let prepare: String
        public let attachments: [Binding]
        public init(operation: String, prepare: String, attachments: [Binding]) throws {
            _ = try StorageIdentity.RequestID(operation)
            self.operation = operation
            _ = try StorageIdentity.RequestID(prepare)
            self.prepare = prepare
            self.attachments = attachments
        }
    }
    public struct RegisterRequest: Encodable, Sendable {
        public let operation: String
        public let binding: Binding
        public init(operation: String, binding: Binding) throws {
            _ = try StorageIdentity.RequestID(operation)
            self.operation = operation
            self.binding = binding
        }
    }
    public struct RetireRequest: Encodable, Sendable {
        public let operation: String
        public let store: String
        public let volume: String
        public let attachment: String
        public let launch: String
        public init(operation: String, store: String, volume: String, attachment: String, launch: String) throws {
            _ = try StorageIdentity.RequestID(operation)
            self.operation = operation
            _ = try StorageIdentity.RequestID(store)
            self.store = store
            _ = try StorageIdentity.RequestID(volume)
            self.volume = volume
            _ = try StorageIdentity.RequestID(attachment)
            self.attachment = attachment
            // Retire is generation-fenced: the controller must only retire the
            // exact launch named by the caller's immutable intent evidence.
            _ = try StorageIdentity.RequestID(launch)
            self.launch = launch
        }
    }
    public struct CompleteRequest: Encodable, Sendable {
        public let operation: String
        public let prepare: String
        public let receipts: [Receipt]
        public let attestation: Attestation
        public init(operation: String, prepare: String, receipts: [Receipt], attestation: Attestation) throws {
            _ = try StorageIdentity.RequestID(operation)
            self.operation = operation
            _ = try StorageIdentity.RequestID(prepare)
            self.prepare = prepare
            self.receipts = receipts
            self.attestation = attestation
        }
    }
    public struct ReplaceRequest: Encodable, Sendable {
        public let operation: String
        public let prepare: String
        public let receipts: [Receipt]
        public let successor: ReserveRequest
        public init(operation: String, prepare: String, receipts: [Receipt], successor: ReserveRequest) throws {
            _ = try StorageIdentity.RequestID(operation)
            self.operation = operation
            _ = try StorageIdentity.RequestID(prepare)
            self.prepare = prepare
            self.receipts = receipts
            self.successor = successor
        }
    }
    public struct CreateVolumeRequest: Encodable, Sendable {
        public let operation: String
        public let store: String
        public let volume: String
        public let name: String
        public init(operation: String, store: String, volume: String, name: String) throws {
            _ = try StorageIdentity.RequestID(operation)
            self.operation = operation
            _ = try StorageIdentity.RequestID(store)
            self.store = store
            _ = try StorageIdentity.RequestID(volume)
            self.volume = volume
            self.name = name
        }
    }
    public struct DeleteVolumeRequest: Encodable, Sendable {
        public let operation: String
        public let store: String
        public let volume: String
        public init(operation: String, store: String, volume: String) throws {
            _ = try StorageIdentity.RequestID(operation)
            self.operation = operation
            _ = try StorageIdentity.RequestID(store)
            self.store = store
            _ = try StorageIdentity.RequestID(volume)
            self.volume = volume
        }
    }
    public enum ControlRequest: Sendable {
        case query
        case reservePrepare(ReserveRequest), registerAttachment(RegisterRequest), retire(RetireRequest)
        case completePrepare(CompleteRequest), replacePrepare(ReplaceRequest)
        case createVolume(CreateVolumeRequest), deleteVolume(DeleteVolumeRequest)
        /// Exact replay material for the private host write-ahead journal. This
        /// exposes no new operation or raw transport capability.
        func durableBytes() throws -> Data { try wire().bytes() }
        func wire() throws -> ControllerJSON {
            let name: String, value: ControllerJSON
            switch self {
            case .query: name = "query"; value = .object([:])
            case .reservePrepare(let body): name = "reserve_prepare"; value = try ControllerJSON.from(body)
            case .registerAttachment(let body): name = "register_attachment"; value = try ControllerJSON.from(body)
            case .retire(let body): name = "retire"; value = try ControllerJSON.from(body)
            case .completePrepare(let body): name = "complete_prepare"; value = try ControllerJSON.from(body)
            case .replacePrepare(let body): name = "replace_prepare"; value = try ControllerJSON.from(body)
            case .createVolume(let body): name = "create_volume"; value = try ControllerJSON.from(body)
            case .deleteVolume(let body): name = "delete_volume"; value = try ControllerJSON.from(body)
            }
            // Go storagecontrol.Client.Call requires ID == 0, then assigns its
            // own 1-based sequence per TLS connection before sending to the guest.
            return .object(["id": .number(0), name: value])
        }
    }


}

/// Recursive bounded JSON matching Go encoding/json canonical bytes. Integers
/// never pass through NSNumber/Double. Parser rejects duplicate keys and depth
/// before allocating recursive decoder containers. No generic public operation API.
nonisolated indirect enum ControllerJSON: Equatable, Encodable, Sendable {
    case object([String: ControllerJSON]), array([ControllerJSON]), string(String), number(UInt64), bool(Bool), null
    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
    static func from<T: Encodable>(_ value: T) throws -> Self {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard data.count <= ManagedStorageControlProtocol.maximumPayloadBytes else { throw ManagedStorageControlProtocol.Failure.invalidConfiguration }
        var parser = Parser(bytes: Array(data))
        let result = try parser.value(depth: 0)
        guard parser.index == data.count else { throw ManagedStorageControlProtocol.Failure.protocolViolation }
        return result
    }
    static func canonical<T: Encodable>(_ value: T, limit: Int) throws -> Data {
        let bytes = try from(value).bytes()
        guard !bytes.isEmpty, bytes.count <= limit else { throw ManagedStorageControlProtocol.Failure.invalidConfiguration }
        return bytes
    }
    func bytes() throws -> Data {
        func quoted(_ text: String) throws -> String {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.withoutEscapingSlashes]
            return String(decoding: try encoder.encode(text), as: UTF8.self)
                .replacingOccurrences(of: "<", with: "\\u003c").replacingOccurrences(of: ">", with: "\\u003e")
                .replacingOccurrences(of: "&", with: "\\u0026").replacingOccurrences(of: "\u{2028}", with: "\\u2028")
                .replacingOccurrences(of: "\u{2029}", with: "\\u2029")
        }
        switch self {
        case .object(let fields):
            let keys = fields.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            var data = Data("{".utf8)
            for (index, key) in keys.enumerated() {
                if index > 0 { data.append(44) }
                data.append(Data((try quoted(key) + ":").utf8)); data.append(try fields[key]!.bytes())
            }
            data.append(125); return data
        case .array(let values):
            var data = Data("[".utf8)
            for (index, value) in values.enumerated() {
                if index > 0 { data.append(44) }; data.append(try value.bytes())
            }
            data.append(93); return data
        case .string(let text): return Data(try quoted(text).utf8)
        case .number(let number): return Data(String(number).utf8)
        case .bool(let flag): return Data((flag ? "true" : "false").utf8)
        case .null: return Data("null".utf8)
        }
    }
    static func parse(_ data: Data, limit: Int) throws -> Self {
        guard !data.isEmpty, data.count <= limit else { throw ManagedStorageControlProtocol.Failure.protocolViolation }
        var parser = Parser(bytes: Array(data))
        let tree = try parser.value(depth: 0)
        guard parser.index == data.count, try tree.bytes() == data else { throw ManagedStorageControlProtocol.Failure.protocolViolation }
        return tree
    }
    private struct Parser {
        let bytes: [UInt8]
        var index = 0
        mutating func take(_ byte: UInt8) -> Bool {
            if index < bytes.count, bytes[index] == byte { index += 1; return true }; return false
        }
        mutating func string() throws -> String {
            let start = index
            guard take(34) else { throw ManagedStorageControlProtocol.Failure.protocolViolation }
            while index < bytes.count {
                let byte = bytes[index]; index += 1
                if byte == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<index])) }
                if byte == 92 { index += 1 }
            }
            throw ManagedStorageControlProtocol.Failure.protocolViolation
        }
        mutating func value(depth: Int) throws -> ControllerJSON {
            guard depth <= 32, index < bytes.count else { throw ManagedStorageControlProtocol.Failure.protocolViolation }
            if take(123) {
                var fields: [String: ControllerJSON] = [:]
                if take(125) { return .object(fields) }
                repeat {
                    let key = try string()
                    guard fields[key] == nil, take(58) else { throw ManagedStorageControlProtocol.Failure.protocolViolation }
                    fields[key] = try value(depth: depth + 1)
                    if take(125) { return .object(fields) }
                } while take(44)
                throw ManagedStorageControlProtocol.Failure.protocolViolation
            }
            if take(91) {
                var values: [ControllerJSON] = []
                if take(93) { return .array(values) }
                repeat {
                    values.append(try value(depth: depth + 1))
                    if take(93) { return .array(values) }
                } while take(44)
                throw ManagedStorageControlProtocol.Failure.protocolViolation
            }
            if bytes[index] == 34 { return .string(try string()) }
            for (word, value) in [("true", ControllerJSON.bool(true)), ("false", .bool(false)), ("null", .null)] {
                let literal = Array(word.utf8)
                if bytes[index...].starts(with: literal) { index += literal.count; return value }
            }
            let start = index
            while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
            guard index > start, let number = UInt64(String(decoding: bytes[start..<index], as: UTF8.self)) else {
                throw ManagedStorageControlProtocol.Failure.protocolViolation
            }
            return .number(number)
        }
    }
}
#endif
