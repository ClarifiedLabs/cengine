import Foundation

/// Shared helper that selects which network endpoint provides a multi-homed
/// container's default gateway, so the API inspect surface and the guest route
/// configuration agree on the same winner.
public enum EndpointGatewayPriority {
    /// One endpoint's candidacy for the container default gateway.
    public struct Candidate: Sendable, Equatable {
        public var networkID: String
        /// The requested gateway priority; absent requests are treated as `0`.
        public var priority: Int
        /// The network name, used only to break priority ties.
        public var networkName: String

        public init(networkID: String, priority: Int, networkName: String) {
            self.networkID = networkID
            self.priority = priority
            self.networkName = networkName
        }
    }

    /// Returns the network ID of the endpoint that should provide the container's
    /// default gateway, or `nil` when there are no candidates.
    ///
    /// This matches Docker's documented `GwPriority` semantics: the endpoint with
    /// the highest priority wins, and equal priorities are broken by sorting the
    /// network names lexicographically and picking the first one. Selecting over
    /// every endpoint means a container attached to a single network always keeps
    /// that network's gateway regardless of the requested priority.
    public static func defaultGatewayNetworkID(among candidates: [Candidate]) -> String? {
        candidates.max { lhs, rhs in
            if lhs.priority != rhs.priority { return lhs.priority < rhs.priority }
            // Equal priority: the lexicographically-first network name wins, so
            // it must compare as the greater element for `max`.
            return lhs.networkName > rhs.networkName
        }?.networkID
    }
}
