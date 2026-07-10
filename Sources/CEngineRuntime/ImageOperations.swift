import Foundation

public struct RegistryCredentials: Sendable {
    public let username: String
    public let password: String
    public let identityToken: String
    public init(username: String = "", password: String = "", identityToken: String = "") {
        self.username = username; self.password = password; self.identityToken = identityToken
    }
}

public struct ImagePullProgress: Sendable {
    public let completedItems: Int; public let totalItems: Int
    public let completedBytes: Int64; public let totalBytes: Int64
    public init(completedItems: Int = 0, totalItems: Int = 0, completedBytes: Int64 = 0, totalBytes: Int64 = 0) {
        self.completedItems = completedItems; self.totalItems = totalItems
        self.completedBytes = completedBytes; self.totalBytes = totalBytes
    }
}
public typealias ImagePullProgressHandler = @Sendable (ImagePullProgress) async -> Void

public struct ImageHistoryEntry: Sendable {
    public let created: Int64; public let createdBy: String; public let comment: String; public let emptyLayer: Bool
    public init(created: Int64, createdBy: String, comment: String, emptyLayer: Bool) {
        self.created = created; self.createdBy = createdBy; self.comment = comment; self.emptyLayer = emptyLayer
    }
}
