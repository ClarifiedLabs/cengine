import CEngineCore
import CryptoKit
import Foundation

public struct VolumeAccessToken: Sendable {
    public static let secretSize = 32
    public let secret: Data

    public init(secret: Data) throws {
        guard secret.count >= Self.secretSize else {
            throw EngineError(.badRequest, "volume token secret must be at least \(Self.secretSize) bytes")
        }
        self.secret = secret
    }

    public static func random() -> VolumeAccessToken {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<secretSize).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        return try! VolumeAccessToken(secret: Data(bytes))
    }

    public func token(for volumeID: String) -> String {
        let key = SymmetricKey(data: secret)
        return HMAC<SHA256>.authenticationCode(for: Data(volumeID.utf8), using: key)
            .map { String(format: "%02x", $0) }.joined()
    }

    public var kernelArgument: String {
        "cengine.volume_secret=" + secret.map { String(format: "%02x", $0) }.joined()
    }
}
