import Darwin
import Dispatch
import Foundation
import Testing
@testable import CEngineCore

@Suite struct DaemonLogStreamingTests {
    @Test func forwardsShortAndFragmentedLinesBeforeEOF() throws {
        let source = Pipe()
        let destination = Pipe()
        defer { try? destination.fileHandleForReading.close() }
        let writer = TimestampedLogWriter(
            input: source.fileHandleForReading,
            output: destination.fileHandleForWriting
        )
        let finished = DispatchGroup()
        finished.enter()
        Thread.detachNewThread {
            writer.run()
            finished.leave()
        }
        defer {
            try? source.fileHandleForWriting.close()
            #expect(finished.wait(timeout: .now() + 5) == .success)
        }

        // Each read is an acknowledgement before the next write. In particular,
        // the first short line must arrive with the source pipe still open.
        try source.fileHandleForWriting.write(contentsOf: Data("first\n".utf8))
        var received = try readAvailableOutput(destination.fileHandleForReading, through: "first\n")
        #expect(finished.wait(timeout: .now()) == .timedOut)

        try source.fileHandleForWriting.write(contentsOf: Data("frag".utf8))
        received += try readAvailableOutput(destination.fileHandleForReading, through: "frag")
        try source.fileHandleForWriting.write(contentsOf: Data("mented\nlast".utf8))
        received += try readAvailableOutput(destination.fileHandleForReading, through: "last")
        #expect(finished.wait(timeout: .now()) == .timedOut)

        try source.fileHandleForWriting.close()
        try #require(finished.wait(timeout: .now() + 5) == .success)
        // run() must close its output at EOF, without losing the final partial line.
        var eof = pollfd(fd: destination.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
        try #require(Darwin.poll(&eof, 1, 5_000) > 0, "Writer did not close its output at EOF")
        var byte: UInt8 = 0
        #expect(Darwin.read(destination.fileHandleForReading.fileDescriptor, &byte, 1) == 0)

        let lines = received.split(separator: "\n")
        try #require(lines.count == 3)
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        for (line, expected) in zip(lines, ["first", "fragmented", "last"]) {
            let fields = line.split(separator: " ", maxSplits: 1)
            try #require(fields.count == 2)
            #expect(formatter.date(from: String(fields[0])) != nil)
            #expect(fields[0].hasSuffix("Z"))
            #expect(fields[1] == expected)
        }
    }

    private func readAvailableOutput(_ handle: FileHandle, through suffix: String) throws -> String {
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        var received = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while !String(decoding: received, as: UTF8.self).hasSuffix(suffix) {
            let now = DispatchTime.now().uptimeNanoseconds
            try #require(now < deadline, "Timed out waiting for live log output")
            let milliseconds = Int32(max(1, (deadline - now) / 1_000_000))
            var descriptor = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&descriptor, 1, milliseconds)
            if ready < 0, errno == EINTR { continue }
            try #require(ready > 0, "Expected log output before closing the source pipe")
            let count = Darwin.read(handle.fileDescriptor, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            try #require(count > 0, "Unexpected log EOF or read failure")
            received.append(contentsOf: buffer.prefix(count))
        }
        return String(decoding: received, as: UTF8.self)
    }
}
