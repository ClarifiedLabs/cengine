import Foundation
import Testing
@testable import CEngineAPI
@testable import CEngineCore

private final class UploadWriterTestState: @unchecked Sendable {
    private let lock = NSLock()
    private var errors: [EngineError] = []

    func record(_ error: EngineError?) {
        if let error { lock.withLock { errors.append(error) } }
    }

    var isEmpty: Bool { lock.withLock { errors.isEmpty } }
    var hasError: Bool { lock.withLock { !errors.isEmpty } }
}

@Suite struct APIAdmissionControllerTests {
    @Test func leasesEnforceExactLimitsAndReleaseIdempotently() throws {
        let controller = APIAdmissionController(policy: .init(
            connections: 1,
            requests: 1,
            bufferedRequestBytes: 4,
            uploads: 1,
            downloads: 1,
            expensiveOperations: 1,
            longLivedStreams: 1
        ))
        let connection = try controller.acquire(.connection)
        #expect(controller.snapshot().connections == 1)
        #expect(throws: EngineError.self) {
            try controller.acquire(.connection)
        }

        let bytes = try controller.acquire(.bufferedRequestBytes, amount: 4)
        #expect(controller.snapshot().bufferedRequestBytes == 4)
        #expect(throws: EngineError.self) { try bytes.increase(by: 1) }
        bytes.release()
        bytes.release()
        #expect(controller.snapshot().bufferedRequestBytes == 0)

        connection.release()
        connection.release()
        #expect(controller.snapshot().connections == 0)
        _ = try controller.acquire(.connection)
    }

    @Test func uploadWriterQueuesOrderedIOOffCallerAndClosesDurably() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appending(path: "upload")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let queue = DispatchQueue(label: "dev.cengine.api-upload-test")
        queue.suspend()
        let writer = DockerUploadFileWriter(
            handle: try FileHandle(forWritingTo: url), queue: queue
        )
        let writes = DispatchSemaphore(value: 0)
        let state = UploadWriterTestState()
        writer.write(Data("first-".utf8)) { error in
            state.record(error)
            writes.signal()
        }
        writer.write(Data("second".utf8)) { error in
            state.record(error)
            writes.signal()
        }

        #expect(writes.wait(timeout: .now() + 0.05) == .timedOut)
        queue.resume()
        #expect(writes.wait(timeout: .now() + 2) == .success)
        #expect(writes.wait(timeout: .now() + 2) == .success)
        let finished = DispatchSemaphore(value: 0)
        writer.finish { error in
            state.record(error)
            finished.signal()
        }
        #expect(finished.wait(timeout: .now() + 2) == .success)
        #expect(state.isEmpty)
        #expect(try Data(contentsOf: url) == Data("first-second".utf8))
    }

    @Test func cancelledUploadWriterRejectsQueuedWrites() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appending(path: "upload")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let queue = DispatchQueue(label: "dev.cengine.api-upload-cancel-test")
        queue.suspend()
        let writer = DockerUploadFileWriter(
            handle: try FileHandle(forWritingTo: url), queue: queue
        )
        let completed = DispatchSemaphore(value: 0)
        let state = UploadWriterTestState()
        writer.write(Data("must-not-be-written".utf8)) { error in
            state.record(error)
            completed.signal()
        }
        writer.cancel()
        queue.resume()
        #expect(completed.wait(timeout: .now() + 2) == .success)
        #expect(state.hasError)
        #expect(try Data(contentsOf: url).isEmpty)
    }

    @Test func allAdmissionClassesReturnToBaseline() throws {
        let controller = APIAdmissionController(policy: .init(
            connections: 2,
            requests: 2,
            bufferedRequestBytes: 8,
            uploads: 2,
            downloads: 2,
            expensiveOperations: 2,
            longLivedStreams: 2
        ))
        let leases = [
            try controller.acquire(.connection),
            try controller.acquire(.request),
            try controller.acquire(.bufferedRequestBytes, amount: 8),
            try controller.acquire(.upload),
            try controller.acquire(.download),
            try controller.acquire(.expensiveOperation),
            try controller.acquire(.longLivedStream),
        ]
        #expect(controller.snapshot() == .init(
            connections: 1,
            requests: 1,
            bufferedRequestBytes: 8,
            uploads: 1,
            downloads: 1,
            expensiveOperations: 1,
            longLivedStreams: 1
        ))
        leases.forEach { $0.release() }
        #expect(controller.snapshot() == .init(
            connections: 0,
            requests: 0,
            bufferedRequestBytes: 0,
            uploads: 0,
            downloads: 0,
            expensiveOperations: 0,
            longLivedStreams: 0
        ))
    }
}
