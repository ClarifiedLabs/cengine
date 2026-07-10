import Foundation

public struct RuntimeEvent: Sendable {
    public let type: String
    public let action: String
    public let id: String
    public let attributes: [String: String]
    public let date: Date

    public init(type: String, action: String, id: String, attributes: [String: String], date: Date = Date()) {
        self.type = type; self.action = action; self.id = id; self.attributes = attributes; self.date = date
    }
}
