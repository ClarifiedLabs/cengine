import Foundation

public enum CEngineVersion {
    public static func shortVersion(bundle: Bundle = .main) -> String {
        guard let value = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String else {
            return "0.0.1"
        }
        let version = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return version.isEmpty ? "0.0.1" : version
    }

    public static func gitCommit(bundle: Bundle = .main) -> String {
        metadataValue(forKey: "CEngineGitCommit", bundle: bundle, fallback: "unknown")
    }

    public static func buildTime(bundle: Bundle = .main) -> String {
        metadataValue(forKey: "CEngineBuildTime", bundle: bundle, fallback: "")
    }

    private static func metadataValue(forKey key: String, bundle: Bundle, fallback: String) -> String {
        guard let value = bundle.object(forInfoDictionaryKey: key) as? String else { return fallback }
        let metadata = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return metadata.isEmpty ? fallback : metadata
    }
}
