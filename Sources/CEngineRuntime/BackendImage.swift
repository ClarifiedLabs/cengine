import Foundation

public struct BackendImage: Sendable {
    public let id: String
    public let reference: String
    public let createdAt: Date
    public let size: Int64
    public let architecture: String
    public let os: String

    public init(id: String, reference: String, createdAt: Date = Date(), size: Int64, architecture: String, os: String) {
        self.id = id; self.reference = reference; self.createdAt = createdAt; self.size = size
        self.architecture = architecture; self.os = os
    }
}
