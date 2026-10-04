import Foundation

/// Stable host binding DTO only, never disk ownership or authenticated provenance.
/// Conversion preserves every field used by StorageLifecycleProtocol.bindingDigest.
public struct StorageLifecycleStoreBinding: Codable, Equatable, Sendable {
    public typealias Bootstrap = StorageIdentity
    public static let version = "storage-host-binding.v2"

    public struct FileIdentity: Codable, Equatable, Sendable {
        public let inode: UInt64
        public let volumeUUID: String

        public init(_ identity: StorageIdentity.RootIdentity) {
            inode = identity.inode
            volumeUUID = identity.volumeUUID.rawValue
        }
        public func value() throws -> StorageIdentity.RootIdentity {
            try .init(volumeUUID: .init(volumeUUID), inode: inode)
        }
        private enum CodingKeys: String, CodingKey, CaseIterable {
            case inode, volumeUUID = "volume_uuid"
        }
        public init(from decoder: any Decoder) throws {
            try StorageLifecycleStoreBinding.requireKeys(CodingKeys.allCases.map(\.rawValue), from: decoder)
            let c = try decoder.container(keyedBy: CodingKeys.self)
            inode = try c.decode(UInt64.self, forKey: .inode)
            volumeUUID = try c.decode(String.self, forKey: .volumeUUID)
            _ = try value()
        }
    }

    /// Wire evidence of a live held descriptor, not a durable store binding.
    public struct LiveFileIdentity: Codable, Equatable, Sendable {
        public let device: UInt64
        public let inode: UInt64
        public let volumeUUID: String

        public init(_ identity: StorageIdentity.DescriptorIdentity) {
            device = identity.device
            inode = identity.stableIdentity.inode
            volumeUUID = identity.stableIdentity.volumeUUID.rawValue
        }
        public var stableIdentity: FileIdentity {
            // All constructors and decoding validate the stable fields.
            FileIdentity(inode: inode, volumeUUID: volumeUUID)
        }
        public func value() throws -> StorageIdentity.DescriptorIdentity {
            try .init(volumeUUID: .init(volumeUUID), device: device, inode: inode)
        }
        private enum CodingKeys: String, CodingKey, CaseIterable {
            case device, inode, volumeUUID = "volume_uuid"
        }
        public init(from decoder: any Decoder) throws {
            try StorageLifecycleStoreBinding.requireKeys(CodingKeys.allCases.map(\.rawValue), from: decoder)
            let c = try decoder.container(keyedBy: CodingKeys.self)
            device = try c.decode(UInt64.self, forKey: .device)
            inode = try c.decode(UInt64.self, forKey: .inode)
            volumeUUID = try c.decode(String.self, forKey: .volumeUUID)
            _ = try value()
        }
    }

    public let version: String
    public let store: String
    public let root: FileIdentity
    public let backing: FileIdentity
    public let bytes: UInt64
    public let ext4UUID: String

    public init(_ binding: StorageIdentity.StoreBinding) {
        version = Self.version
        store = binding.storeID.rawValue; root = .init(binding.root)
        backing = .init(binding.backing.identity); bytes = binding.backing.size
        ext4UUID = binding.expectedExt4UUID.rawValue
    }

    /// Throwing conversion rejects obsolete versions; it never migrates stale bindings.
    public func value() throws -> StorageIdentity.StoreBinding {
        guard version == Self.version else { throw StorageIdentity.ValidationError.invalidBinding }
        return try .init(storeID: .init(store), root: root.value(),
                         backing: .init(identity: backing.value(), size: bytes),
                         expectedExt4UUID: .init(ext4UUID))
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, store, root, backing, bytes, ext4UUID = "ext4_uuid"
    }
    public init(from decoder: any Decoder) throws {
        try Self.requireKeys(CodingKeys.allCases.map(\.rawValue), from: decoder)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        store = try c.decode(String.self, forKey: .store)
        root = try c.decode(FileIdentity.self, forKey: .root)
        backing = try c.decode(FileIdentity.self, forKey: .backing)
        bytes = try c.decode(UInt64.self, forKey: .bytes)
        ext4UUID = try c.decode(String.self, forKey: .ext4UUID)
        _ = try value()
    }

    private struct AnyKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    private static func requireKeys(_ keys: [String], from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: AnyKey.self)
        guard Set(c.allKeys.map(\.stringValue)) == Set(keys) else {
            throw StorageIdentity.ValidationError.invalidBinding
        }
    }
}

extension StorageLifecycleStoreBinding.FileIdentity {
    fileprivate init(inode: UInt64, volumeUUID: String) {
        self.inode = inode; self.volumeUUID = volumeUUID
    }
}
