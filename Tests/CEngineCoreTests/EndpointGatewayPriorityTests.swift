import Testing
@testable import CEngineCore

@Suite struct EndpointGatewayPriorityTests {
    private func candidate(_ id: String, _ priority: Int, _ name: String) -> EndpointGatewayPriority.Candidate {
        .init(networkID: id, priority: priority, networkName: name)
    }

    @Test func noCandidatesHaveNoDefaultGateway() {
        #expect(EndpointGatewayPriority.defaultGatewayNetworkID(among: []) == nil)
    }

    @Test func singleCandidateAlwaysWins() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworkID(among: [candidate("only", 0, "solo")])
        #expect(winner == "only")
    }

    @Test func highestPriorityWins() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworkID(among: [
            candidate("low", 5, "aaa"),
            candidate("high", 50, "zzz"),
            candidate("mid", 10, "mmm"),
        ])
        #expect(winner == "high")
    }

    @Test func negativePriorityStillParticipates() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworkID(among: [
            candidate("negative", -10, "aaa"),
            candidate("zero", 0, "zzz"),
        ])
        #expect(winner == "zero")
    }

    @Test func equalPriorityBreaksTieByLexicographicNetworkName() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworkID(among: [
            candidate("beta", 7, "beta-net"),
            candidate("alpha", 7, "alpha-net"),
            candidate("gamma", 7, "gamma-net"),
        ])
        // alpha-net sorts first lexicographically among equal priorities.
        #expect(winner == "alpha")
    }

    @Test func priorityDominatesLexicographicOrder() {
        let winner = EndpointGatewayPriority.defaultGatewayNetworkID(among: [
            candidate("zeta", 1, "aaa-net"),
            candidate("early", 0, "aaa-earliest-net"),
        ])
        // The higher priority wins even though the other network name sorts first.
        #expect(winner == "zeta")
    }
}
