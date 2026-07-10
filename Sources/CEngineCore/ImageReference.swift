public enum ImageReference {
    /// Expands Docker's familiar short-name rules into an OCI registry reference.
    public static func normalized(_ value: String) -> String {
        guard !value.isEmpty else { return value }
        var reference = value
        let components = reference.split(separator: "/", omittingEmptySubsequences: false)
        if components.count == 1 {
            reference = "docker.io/library/\(reference)"
        } else if let first = components.first,
                  !first.contains("."), !first.contains(":"), first != "localhost" {
            reference = "docker.io/\(reference)"
        }
        let leaf = reference.split(separator: "/").last.map(String.init) ?? reference
        if !leaf.contains(":") && !reference.contains("@") { reference += ":latest" }
        return reference
    }
}
