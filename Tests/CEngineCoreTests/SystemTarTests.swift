import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite("System tar")
struct SystemTarTests {
    @Test("archive creation excludes macOS AppleDouble metadata")
    func archiveCreationExcludesAppleDoubleMetadata() throws {
        let temporary = FileManager.default.temporaryDirectory
            .appending(path: "cengine-system-tar-\(UUID().uuidString)", directoryHint: .isDirectory)
        let contents = temporary.appending(path: "contents", directoryHint: .isDirectory)
        let payload = contents.appending(path: "payload.txt")
        let archive = temporary.appending(path: "payload.tar")
        defer { try? FileManager.default.removeItem(at: temporary) }

        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        try Data("archive-roundtrip".utf8).write(to: payload)
        let attribute = Data("metadata".utf8)
        let result = attribute.withUnsafeBytes { bytes in
            setxattr(payload.path, "com.apple.cengine-test", bytes.baseAddress, bytes.count, 0, 0)
        }
        #expect(result == 0)

        try SystemTar.create(from: contents, at: archive)
        let paths = try SystemTar.ownership(in: Data(contentsOf: archive)).map(\.path)

        #expect(paths.contains("./payload.txt"))
        #expect(!paths.contains(where: { $0.contains("/._") || $0.hasPrefix("._") }))
    }
}
