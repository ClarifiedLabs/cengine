import CEngineCore
import Foundation
import Testing

@Suite struct ManagedPrepareEarlyVectorTests {
    private typealias Carrier = ManagedPrepareCompatibilityProtocol
    private enum Observation: Decodable {
        case physical(Carrier.Observation), early(Carrier.EarlyObservation)
        init(from decoder: any Decoder) throws {
            let value = try decoder.singleValueContainer()
            if let physical = try? value.decode(Carrier.Observation.self) { self = .physical(physical) }
            else { self = .early(try value.decode(Carrier.EarlyObservation.self)) }
        }
    }
    private struct Vector: Decodable {
        let name: String
        let arm: Carrier.Arm
        let canonical: String
        let sha256: String
        let observation: Observation
        let observationCanonical: String
        let observationSHA256: String
    }
    @Test func sharedGuestEarlyVectorsMatchAllFourCases() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let bytes = try Data(contentsOf: root.appending(path: "Guest/internal/preparecompat/testdata/early-vectors.json"))
        let vectors = try JSONDecoder().decode([Vector].self, from: bytes)
        #expect(Set(vectors.map(\.name)) == Set(["normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame"]))
        #expect(vectors.count == 4)
        for vector in vectors {
            #expect(try Carrier.armData(vector.arm) == Data(vector.canonical.utf8))
            #expect(try Carrier.digest(vector.arm) == vector.sha256)
            let canonical: Data
            let frame: WorkloadStorageProtocol.Frame
            switch vector.observation {
            case .physical(let observation):
                try Carrier.validate(observation, arm: vector.arm)
                canonical = try Carrier.canonicalData(observation)
                #expect(try Carrier.decode(Carrier.Observation.self, from: canonical) == observation)
                frame = .init(operation: .prepareCheckpoint, binding: vector.arm.binding, scope: vector.arm.scope,
                    data: .init(compatibilityObservation: observation))
            case .early(let observation):
                try Carrier.validate(observation, arm: vector.arm)
                canonical = try Carrier.canonicalData(observation)
                #expect(try Carrier.decode(Carrier.EarlyObservation.self, from: canonical) == observation)
                frame = .init(operation: .prepareEarlyCheckpoint, binding: vector.arm.binding, scope: vector.arm.scope,
                    data: .init(compatibilityEarlyObservation: observation))
            }
            #expect(canonical == Data(vector.observationCanonical.utf8))
            #expect(WorkloadStorageProtocol.specificationDigest(canonical) == vector.observationSHA256)
            try Carrier.validateObservation(frame, arm: vector.arm)
            #expect(try WorkloadStorageProtocol.decode(from: Data(WorkloadStorageProtocol.encode(frame).dropFirst(4))) == frame)
        }
    }
}
