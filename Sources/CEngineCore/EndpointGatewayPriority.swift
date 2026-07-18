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
        public var providesIPv4: Bool
        public var providesIPv6: Bool

        public init(
            networkID: String,
            priority: Int,
            networkName: String,
            providesIPv4: Bool = true,
            providesIPv6: Bool = true
        ) {
            self.networkID = networkID
            self.priority = priority
            self.networkName = networkName
            self.providesIPv4 = providesIPv4
            self.providesIPv6 = providesIPv6
        }
    }

    public struct Selection: Sendable, Equatable {
        public var ipv4NetworkID: String?
        public var ipv6NetworkID: String?

        public init(ipv4NetworkID: String?, ipv6NetworkID: String?) {
            self.ipv4NetworkID = ipv4NetworkID
            self.ipv6NetworkID = ipv6NetworkID
        }
    }

    /// Returns the network IDs of the endpoints that should provide the
    /// container's IPv4 and IPv6 default gateways. Each family is selected
    /// independently because an endpoint may provide only one address family.
    ///
    /// This matches Docker's documented `GwPriority` semantics: the endpoint with
    /// the highest priority wins, and equal priorities are broken by sorting the
    /// network names lexicographically and picking the first one. Selecting over
    /// every endpoint means a container attached to a single network always keeps
    /// that network's gateway regardless of the requested priority.
    public static func defaultGatewayNetworks(among candidates: [Candidate]) -> Selection {
        .init(
            ipv4NetworkID: winner(candidates.filter(\.providesIPv4)),
            ipv6NetworkID: winner(candidates.filter(\.providesIPv6))
        )
    }

    private static func winner(_ candidates: [Candidate]) -> String? {
        candidates.max { lhs, rhs in
            if lhs.priority != rhs.priority { return lhs.priority < rhs.priority }
            // Equal priority: the lexicographically-first network name wins, so
            // it must compare as the greater element for `max`.
            return lhs.networkName > rhs.networkName
        }?.networkID
    }
}
