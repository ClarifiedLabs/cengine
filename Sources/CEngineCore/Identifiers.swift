import Foundation

public enum Identifier {
    public static func random() -> String {
        UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }

    public static func validateName(_ name: String) -> Bool {
        guard !name.isEmpty, name.count <= 255 else { return false }
        return name.range(of: #"^[A-Za-z0-9][A-Za-z0-9_.-]*$"#, options: .regularExpression) != nil
    }
}

public extension String {
    var normalizedContainerName: String {
        hasPrefix("/") ? String(dropFirst()) : self
    }
}
