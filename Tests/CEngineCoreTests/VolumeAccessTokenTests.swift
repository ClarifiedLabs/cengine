import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct VolumeAccessTokenTests {
    @Test func tokensAreStableAndVolumeScoped() throws {
        let issuer = try VolumeAccessToken(secret: Data(repeating: 7, count: 32))

        #expect(issuer.token(for: "first") == issuer.token(for: "first"))
        #expect(issuer.token(for: "first") != issuer.token(for: "second"))
        #expect(issuer.kernelArgument.hasPrefix("cengine.volume_secret="))
    }
}
