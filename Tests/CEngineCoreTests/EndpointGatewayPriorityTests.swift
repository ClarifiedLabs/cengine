import Testing
@testable import CEngineCore

@Suite struct EndpointGatewayPriorityTests {
    private func candidate(_ id: String, _ priority: Int, _ name: String) -> EndpointGatewayPriority.Candidate {
        .init(networkID: id, priority: priority, networkName: name)
    }

    @Test func noCandidatesHaveNoDefaultGateway() {
        #expect(EndpointGatewayPriority.defaultGatewayNetworks(among: []) == .init(
            ipv4NetworkID: nil,
            ipv6NetworkID: nil
        ))
    }

    @Test func singleCandidateAlwaysWins() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworks(among: [candidate("only", 0, "solo")])
        #expect(winner == .init(ipv4NetworkID: "only", ipv6NetworkID: "only"))
    }

    @Test func highestPriorityWins() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworks(among: [
            candidate("low", 5, "aaa"),
            candidate("high", 50, "zzz"),
            candidate("mid", 10, "mmm"),
        ])
        #expect(winner == .init(ipv4NetworkID: "high", ipv6NetworkID: "high"))
    }

    @Test func negativePriorityStillParticipates() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworks(among: [
            candidate("negative", -10, "aaa"),
            candidate("zero", 0, "zzz"),
        ])
        #expect(winner == .init(ipv4NetworkID: "zero", ipv6NetworkID: "zero"))
    }

    @Test func equalPriorityBreaksTieByLexicographicNetworkName() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworks(among: [
            candidate("beta", 7, "beta-net"),
            candidate("alpha", 7, "alpha-net"),
            candidate("gamma", 7, "gamma-net"),
        ])
        // alpha-net sorts first lexicographically among equal priorities.
        #expect(winner == .init(ipv4NetworkID: "alpha", ipv6NetworkID: "alpha"))
    }

    @Test func priorityDominatesLexicographicOrder() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworks(among: [
            candidate("zeta", 1, "aaa-net"),
            candidate("early", 0, "aaa-earliest-net"),
        ])
        // The higher priority wins even though the other network name sorts first.
        #expect(winner == .init(ipv4NetworkID: "zeta", ipv6NetworkID: "zeta"))
    }

    @Test func addressFamiliesChooseDefaultsIndependently() {
        let selection = EndpointGatewayPriority.defaultGatewayNetworks(among: [
            .init(
                networkID: "ipv4", priority: 10, networkName: "ipv4-net",
                providesIPv4: true, providesIPv6: false
            ),
            .init(
                networkID: "ipv6", priority: 100, networkName: "ipv6-net",
                providesIPv4: false, providesIPv6: true
            ),
        ])

        #expect(selection == .init(ipv4NetworkID: "ipv4", ipv6NetworkID: "ipv6"))
    }
}
