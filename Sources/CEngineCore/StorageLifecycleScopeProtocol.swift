import Foundation

/// Namespace-neutral v2 scope selection; neither a path nor an authentication DTO.
/// The helper derives the root identity from the transferred descriptor itself and
/// selects the journal root from its own compiled namespace policy. The closed
/// canonical decoder rejects any extra field (no policy, source pin, fault hook).
public enum StorageLifecycleScopeProtocol {
    public static let xpcOperation = "storage-lifecycle-scope-bind"
    public static let maximumPayloadBytes = 512
    public struct Request: Codable, Equatable, Sendable {
        public let version: String
        public let store: String
        public init(store: StorageIdentity.StoreID) {
            version = "storage-lifecycle-scope.v2"; self.store = store.rawValue
        }
    }
    public static func encode(_ request: Request) throws -> Data {
        try StorageLifecycleProtocol.encode(request)
    }
    public static func decode(_ data: Data) throws -> Request {
        guard data.count <= maximumPayloadBytes else { throw StorageLifecycleProtocol.ValidationError.invalidMessage }
        let value = try StorageLifecycleProtocol.decode(Request.self, from: data)
        let canonical = try Request(store: .init(value.store))
        guard value == canonical, try encode(canonical) == data else { throw StorageLifecycleProtocol.ValidationError.invalidMessage }
        return canonical
    }
}
