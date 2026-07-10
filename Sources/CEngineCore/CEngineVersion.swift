import Foundation

public enum CEngineVersion {
    public static func shortVersion(bundle: Bundle = .main) -> String {
        guard let value = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String else {
            return "0.0.1"
        }
        let version = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return version.isEmpty ? "0.0.1" : version
    }
}
