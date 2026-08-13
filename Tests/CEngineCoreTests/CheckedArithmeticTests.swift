import Testing
@testable import CEngineCore

@Suite struct CheckedArithmeticTests {
    @Test func exactIntegerConversionsRejectSignAndRangeLoss() throws {
        #expect(try CheckedArithmetic.exact(Int64.max, as: UInt64.self) == UInt64(Int64.max))
        #expect(try CheckedArithmetic.exact(UInt64(Int64.max), as: Int64.self) == Int64.max)
        #expect(throws: CheckedArithmeticError.self) {
            try CheckedArithmetic.exact(Int64.min, as: UInt64.self)
        }
        #expect(throws: CheckedArithmeticError.self) {
            try CheckedArithmetic.exact(UInt64.max, as: Int64.self)
        }
    }

    @Test func additionAndMultiplicationAcceptBoundaryAndRejectFirstExcess() throws {
        #expect(try CheckedArithmetic.add(Int64.max - 1, 1) == Int64.max)
        #expect(try CheckedArithmetic.multiply(Int64.max / 2, 2) == (Int64.max / 2) * 2)
        #expect(throws: CheckedArithmeticError.self) {
            try CheckedArithmetic.add(Int64.max, 1)
        }
        #expect(throws: CheckedArithmeticError.self) {
            try CheckedArithmetic.add(Int64.min, -1)
        }
        #expect(throws: CheckedArithmeticError.self) {
            try CheckedArithmetic.multiply(UInt64.max, 2)
        }
    }

    @Test func ceilingDivisionDoesNotAddToTheDividend() throws {
        #expect(try CheckedArithmetic.ceilingDivide(UInt64.max, by: UInt64.max) == 1)
        #expect(try CheckedArithmetic.ceilingDivide(UInt64.max - 1, by: UInt64.max) == 1)
        #expect(try CheckedArithmetic.ceilingDivide(0, by: 7) == 0)
        #expect(try CheckedArithmetic.ceilingDivide(14, by: 7) == 2)
        #expect(try CheckedArithmetic.ceilingDivide(15, by: 7) == 3)
        #expect(throws: CheckedArithmeticError.self) {
            try CheckedArithmetic.ceilingDivide(-1, by: 7)
        }
        #expect(throws: CheckedArithmeticError.self) {
            try CheckedArithmetic.ceilingDivide(1, by: 0)
        }
    }

    @Test func tarAlignmentAcceptsExactLimitAndRejectsOverflow() throws {
        #expect(try CheckedArithmetic.alignedToTarBlock(0) == 0)
        #expect(try CheckedArithmetic.alignedToTarBlock(512) == 512)
        #expect(try CheckedArithmetic.alignedToTarBlock(513) == 1_024)
        #expect(try CheckedArithmetic.alignedUp(UInt64.max - 511, to: 512) == UInt64.max - 511)
        #expect(throws: CheckedArithmeticError.self) {
            try CheckedArithmetic.alignedToTarBlock(UInt64.max)
        }
    }

    @Test func dockerCPUConversionsPreserveOrdinaryRoundingAndRejectExtremes() throws {
        #expect(try DockerCPUResources.resolvedNanoCPUs(
            nanoCPUs: 1_500_000_000, period: nil, quota: nil
        ) == 1_500_000_000)
        #expect(try DockerCPUResources.resolvedNanoCPUs(
            nanoCPUs: nil, period: 100_000, quota: 150_000
        ) == 1_500_000_000)
        #expect(try DockerCPUResources.cpuCount(
            nanoCPUs: 1_500_000_000, maximumCPUs: 8
        ) == 2)
        #expect(try DockerCPUResources.nanoCPUs(cpuCount: 4) == 4_000_000_000)
        #expect(try DockerCPUResources.quota(cpuCount: 4) == 400_000)
        #expect(throws: EngineError.self) {
            try DockerCPUResources.resolvedNanoCPUs(
                nanoCPUs: nil, period: 1_000, quota: Int64.max
            )
        }
        #expect(throws: EngineError.self) {
            try DockerCPUResources.cpuCount(
                nanoCPUs: Int64.max, maximumCPUs: 8
            )
        }
        #expect(throws: EngineError.self) {
            try DockerCPUResources.resolvedNanoCPUs(
                nanoCPUs: Int64.max, period: 100_000, quota: 100_000
            )
        }
    }

    @Test func securityPolicyDefaultsMatchApprovedBounds() {
        #expect(ContainerLogRetentionPolicy.default.retainedBytes == 64 * 1_024 * 1_024)
        #expect(ContainerLogRetentionPolicy.default.maximumRetainedRecords == 65_536)
        #expect(ContainerLogRetentionPolicy.default.maximumRecordBytes == 1 * 1_024 * 1_024)
        #expect(ContainerLogRetentionPolicy.default.followerQueueBytes == 4 * 1_024 * 1_024)
        #expect(OCITransferPolicy.default.metadataBytes == 8 * 1_024 * 1_024)
        #expect(OCITransferPolicy.default.tokenBytes == 1 * 1_024 * 1_024)
        #expect(OCITransferPolicy.default.errorBodyBytes == 64 * 1_024)
        #expect(ArchivePolicy.default.wireBytes == 512 * 1_024 * 1_024)
        #expect(ArchivePolicy.default.expandedBytes == 20 * 1_024 * 1_024 * 1_024)
        #expect(ArchivePolicy.default.fileBytes == 8 * 1_024 * 1_024 * 1_024)
        #expect(APIAdmissionPolicy.default.connections == 256)
        #expect(APIAdmissionPolicy.default.requests == 128)
        #expect(APIAdmissionPolicy.default.bufferedRequestBytes == 64 * 1_024 * 1_024)
        #expect(APIAdmissionPolicy.default.expensiveOperations == 8)
        #expect(APIAdmissionPolicy.default.longLivedStreams == 64)
    }
}
