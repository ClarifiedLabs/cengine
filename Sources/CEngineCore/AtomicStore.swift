import Foundation

public actor AtomicStore<Value: Codable & Sendable> {
    public static var schemaVersion: Int { 1 }

    private struct Envelope: Codable {
        let schemaVersion: Int
        let value: Value
    }

    public let url: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(url: URL) {
        self.url = url
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.sortedKeys]
        self.encoder.dateEncodingStrategy = .iso8601
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }

    public func load(default defaultValue: @autoclosure () -> Value) throws -> Value {
        guard FileManager.default.fileExists(atPath: url.path) else { return defaultValue() }
        let envelope = try decoder.decode(Envelope.self, from: Data(contentsOf: url))
        guard envelope.schemaVersion == Self.schemaVersion else {
            throw EngineError(.conflict, "unsupported state schema \(envelope.schemaVersion); run cengine system reset")
        }
        return envelope.value
    }

    public func save(_ value: Value) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let temporary = directory.appending(path: ".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        let data = try encoder.encode(Envelope(schemaVersion: Self.schemaVersion, value: value))
        try data.write(to: temporary, options: .withoutOverwriting)
        let handle = try FileHandle(forWritingTo: temporary)
        try handle.synchronize()
        try handle.close()
        if FileManager.default.fileExists(atPath: url.path) {
            _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary)
        } else {
            try FileManager.default.moveItem(at: temporary, to: url)
        }
    }
}
