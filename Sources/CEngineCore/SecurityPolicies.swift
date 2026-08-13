import Foundation

/// Bounded representations for one container's durable and live Docker output.
public struct ContainerLogRetentionPolicy: Equatable, Sendable {
    public static let `default` = Self(
        retainedBytes: 64 * 1_024 * 1_024,
        segmentBytes: 8 * 1_024 * 1_024,
        maximumSegments: 10,
        maximumRetainedRecords: 65_536,
        maximumRecordBytes: 1 * 1_024 * 1_024,
        followerQueueBytes: 4 * 1_024 * 1_024,
        followerQueueRecords: 1_024
    )

    public let retainedBytes: Int
    public let segmentBytes: Int
    public let maximumSegments: Int
    public let maximumRetainedRecords: Int
    public let maximumRecordBytes: Int
    public let followerQueueBytes: Int
    public let followerQueueRecords: Int

    public init(
        retainedBytes: Int,
        segmentBytes: Int,
        maximumSegments: Int,
        maximumRetainedRecords: Int,
        maximumRecordBytes: Int,
        followerQueueBytes: Int,
        followerQueueRecords: Int
    ) {
        precondition(retainedBytes > 0 && segmentBytes > 0 && segmentBytes <= retainedBytes)
        precondition(maximumSegments >= 2 && maximumRetainedRecords > 0)
        precondition(maximumRecordBytes > 0 && maximumRecordBytes <= segmentBytes)
        precondition(followerQueueBytes > 0 && followerQueueRecords > 0)
        self.retainedBytes = retainedBytes
        self.segmentBytes = segmentBytes
        self.maximumSegments = maximumSegments
        self.maximumRetainedRecords = maximumRetainedRecords
        self.maximumRecordBytes = maximumRecordBytes
        self.followerQueueBytes = followerQueueBytes
        self.followerQueueRecords = followerQueueRecords
    }
}

/// Limits for untrusted registry metadata and descriptor graphs. Blob bodies
/// are streamed and checked against both this policy and their descriptor.
public struct OCITransferPolicy: Equatable, Sendable {
    public static let `default` = Self(
        metadataBytes: 8 * 1_024 * 1_024,
        tokenBytes: 1 * 1_024 * 1_024,
        errorBodyBytes: 64 * 1_024,
        maximumBlobBytes: 20 * 1_024 * 1_024 * 1_024,
        maximumGraphBytes: 20 * 1_024 * 1_024 * 1_024,
        maximumGraphDescriptors: 100_000,
        maximumGraphDepth: 32
    )

    public let metadataBytes: Int
    public let tokenBytes: Int
    public let errorBodyBytes: Int
    public let maximumBlobBytes: UInt64
    public let maximumGraphBytes: UInt64
    public let maximumGraphDescriptors: Int
    public let maximumGraphDepth: Int

    public init(
        metadataBytes: Int,
        tokenBytes: Int,
        errorBodyBytes: Int,
        maximumBlobBytes: UInt64,
        maximumGraphBytes: UInt64,
        maximumGraphDescriptors: Int,
        maximumGraphDepth: Int
    ) {
        precondition(metadataBytes > 0 && tokenBytes > 0 && errorBodyBytes > 0)
        precondition(maximumBlobBytes > 0 && maximumGraphBytes > 0)
        precondition(maximumGraphDescriptors > 0 && maximumGraphDepth > 0)
        self.metadataBytes = metadataBytes
        self.tokenBytes = tokenBytes
        self.errorBodyBytes = errorBodyBytes
        self.maximumBlobBytes = maximumBlobBytes
        self.maximumGraphBytes = maximumGraphBytes
        self.maximumGraphDescriptors = maximumGraphDescriptors
        self.maximumGraphDepth = maximumGraphDepth
    }
}

/// Wire and expansion limits shared by Docker archive and OCI image-layout
/// operations. Exact-limit inputs are accepted; accounting rejects the first
/// byte or entry beyond a limit.
public struct ArchivePolicy: Equatable, Sendable {
    public static let `default` = Self(
        wireBytes: 512 * 1_024 * 1_024,
        expandedBytes: 20 * 1_024 * 1_024 * 1_024,
        outputBytes: 20 * 1_024 * 1_024 * 1_024,
        fileBytes: 8 * 1_024 * 1_024 * 1_024,
        entries: 100_000,
        metadataRecords: 100_000,
        pathBytes: 4_096,
        linkBytes: 4_096,
        depth: 256
    )

    public let wireBytes: UInt64
    public let expandedBytes: UInt64
    public let outputBytes: UInt64
    public let fileBytes: UInt64
    public let entries: Int
    public let metadataRecords: Int
    public let pathBytes: Int
    public let linkBytes: Int
    public let depth: Int

    public init(
        wireBytes: UInt64,
        expandedBytes: UInt64,
        outputBytes: UInt64,
        fileBytes: UInt64,
        entries: Int,
        metadataRecords: Int,
        pathBytes: Int,
        linkBytes: Int,
        depth: Int
    ) {
        precondition(wireBytes > 0 && expandedBytes > 0 && outputBytes > 0 && fileBytes > 0)
        precondition(fileBytes <= expandedBytes)
        precondition(entries > 0 && metadataRecords > 0)
        precondition(pathBytes > 0 && linkBytes > 0 && depth > 0)
        self.wireBytes = wireBytes
        self.expandedBytes = expandedBytes
        self.outputBytes = outputBytes
        self.fileBytes = fileBytes
        self.entries = entries
        self.metadataRecords = metadataRecords
        self.pathBytes = pathBytes
        self.linkBytes = linkBytes
        self.depth = depth
    }
}

/// Process-wide API admission limits shared by the primary and scoped Unix
/// listeners.
public struct APIAdmissionPolicy: Equatable, Sendable {
    public static let `default` = Self(
        connections: 256,
        requests: 128,
        bufferedRequestBytes: 64 * 1_024 * 1_024,
        uploads: 8,
        downloads: 8,
        expensiveOperations: 8,
        longLivedStreams: 64
    )

    public let connections: Int
    public let requests: Int
    public let bufferedRequestBytes: Int
    public let uploads: Int
    public let downloads: Int
    public let expensiveOperations: Int
    public let longLivedStreams: Int

    public init(
        connections: Int,
        requests: Int,
        bufferedRequestBytes: Int,
        uploads: Int,
        downloads: Int,
        expensiveOperations: Int,
        longLivedStreams: Int
    ) {
        precondition(connections > 0 && requests > 0 && bufferedRequestBytes > 0)
        precondition(uploads > 0 && downloads > 0 && expensiveOperations > 0)
        precondition(longLivedStreams > 0)
        self.connections = connections
        self.requests = requests
        self.bufferedRequestBytes = bufferedRequestBytes
        self.uploads = uploads
        self.downloads = downloads
        self.expensiveOperations = expensiveOperations
        self.longLivedStreams = longLivedStreams
    }
}
