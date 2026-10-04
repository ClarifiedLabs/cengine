import Foundation

// Standalone host DTO regression: compile with Sources/CEngineCore/*.swift.
@main struct VMCarrierRegression {
    typealias C = ManagedPrepareCompatibilityProtocol
    struct Vector: Decodable { var name: String; var arm: C.Arm; var observationCanonical: String; var storageStatus: C.StorageStatus? }
    static func object(_ template: C.StorageObject, inode: UInt64, fileType: UInt32, generation: UInt32? = nil) -> C.StorageObject {
        var value = template
        value.inode = inode; value.fileType = fileType; value.generation = generation ?? template.generation
        value.handle = [UInt32(inode), value.generation].flatMap { word in
            (0..<4).map { String(format: "%02x", (word >> ($0 * 8)) & 255) }
        }.joined()
        return value
    }
    static func rejected(_ body: () throws -> Void) throws {
        do { try body() } catch { return }
        throw C.Failure.invalid
    }
    static func main() throws {
        let vectors = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
        precondition(vectors.count == 9)
        let baseline = vectors.first { $0.name == "normal" }!
        for stage in ["vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed"] {
            var arm = C.normalized(baseline.arm)
            arm.mounts = Array(arm.mounts.prefix(1)); arm.slots = Array(arm.slots.prefix(2)); arm.credentials = Array(arm.credentials.prefix(1))
            arm.caseName = stage
            try C.validate(arm)
            precondition(!C.allowsPrepareSuccess(arm))
            var multiple = baseline.arm; multiple.caseName = stage
            try rejected { try C.validate(multiple) }
            var wrong = arm; wrong.profile = C.profile
            try rejected { try C.validate(wrong) }
            if stage == "vm-root-synced-before-cleanup" {
                var observation = try C.decode(C.Observation.self, from: Data(baseline.observationCanonical.utf8))
                observation.armDigest = try C.digest(arm)
                try rejected { try C.validate(observation, arm: arm) }
                observation.stage = stage
                try C.validate(observation, arm: arm)
                observation.count = 2
                try rejected { try C.validate(observation, arm: arm) }
            } else {
                precondition(C.isStorageCase(stage))
                let wrapped = C.StorageArm(arm: arm, workerUUID: arm.binding.guestBootNonce)
                try C.validate(wrapped)
                var status = vectors.first { $0.name == "transaction-published-bind-reply-lost" }!.storageStatus!
                status.query = try C.query(wrapped); status.state = "observed"
                status.acceptedInFlight = 1; status.retirementStarted = false
                status.observation!.stage = stage
                status.observation!.armDigest = status.query.armDigest
                status.observation!.workerUUID = wrapped.workerUUID
                if stage == "vm-cleaning-transaction-removed" {
                    var intent = status.observation!.bound!.intent
                    intent.phase = "CLEANING"; intent.manifestSize = 100
                    intent.manifestDigest = String(repeating: "1", count: 64)
                    intent.cleanup = intent.initial
                    let next = max(intent.root.root.inode, intent.transaction.inode) + 1
                    intent.cleanup.manifest = object(intent.transaction, inode: next, fileType: 32768)
                    intent.cleanup.staging = object(intent.transaction, inode: next + 1, fileType: 16384)
                    status.observation!.bound!.intent = intent
                    let objects = [intent.root.root, intent.transaction, intent.cleanup.manifest, intent.cleanup.staging]
                    precondition(Set(objects.map(\.inode)).count == 4)
                    for source in 0..<4 { for target in (source + 1)..<4 { for changedGeneration in [false, true] {
                        var aliases = objects, bad = status
                        aliases[target] = object(objects[target], inode: objects[source].inode,
                            fileType: objects[target].fileType, generation: objects[source].generation + (changedGeneration ? 1 : 0))
                        bad.observation!.bound!.intent.root.root = aliases[0]
                        bad.observation!.bound!.intent.transaction = aliases[1]
                        bad.observation!.bound!.intent.cleanup.manifest = aliases[2]
                        bad.observation!.bound!.intent.cleanup.staging = aliases[3]
                        try rejected { try C.validate(bad, arm: wrapped) }
                    } } }
                }
                try C.validate(status, arm: wrapped)
                for count in [UInt32(0), 1] { for retired in [false, true] where count == 0 || retired {
                    var bad = status; bad.acceptedInFlight = count; bad.retirementStarted = retired
                    try rejected { try C.validate(bad, arm: wrapped) }
                } }
                status.acceptedInFlight = UInt32.max
                try C.validate(status, arm: wrapped)
            }
        }
        print("Swift VM carrier regressions passed (host DTO only)")
    }
}
