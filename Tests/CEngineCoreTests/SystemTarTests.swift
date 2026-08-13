import Darwin
import Foundation
import Testing
@testable import CEngineCore
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

    @Test("extraction never traverses an archive symlink")
    func extractionRejectsSymlinkThenChildWithoutOutsideWrite() throws {
        let temporary = FileManager.default.temporaryDirectory
            .appending(path: "cengine-tar-links-\(UUID().uuidString)")
        let archive = temporary.appending(path: "attack.tar")
        let destination = temporary.appending(path: "destination")
        let outside = temporary.appending(path: "outside")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        try Data("sentinel".utf8).write(to: outside)
        try testTar([
            .init(name: "link", type: 0x32, link: "../outside", data: Data()),
            .init(name: "link/escape", type: 0x30, data: Data("overwrite".utf8)),
        ]).write(to: archive)

        #expect(throws: (any Error).self) {
            try SystemTar.extract(archive, to: destination)
        }
        #expect(try Data(contentsOf: outside) == Data("sentinel".utf8))
    }

    @Test("hard links must reference an earlier regular file")
    func extractionRejectsForwardHardLink() throws {
        let temporary = FileManager.default.temporaryDirectory
            .appending(path: "cengine-tar-hardlink-\(UUID().uuidString)")
        let archive = temporary.appending(path: "attack.tar")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        try testTar([
            .init(name: "forward", type: 0x31, link: "later", data: Data()),
            .init(name: "later", type: 0x30, data: Data("content".utf8)),
        ]).write(to: archive)

        #expect(throws: EngineError.self) {
            try SystemTar.extract(archive, to: temporary.appending(path: "destination"))
        }
    }

    @Test("archive expansion accepts the exact limit and rejects one byte over")
    func archiveExpansionBoundaryIsExact() throws {
        let temporary = FileManager.default.temporaryDirectory
            .appending(path: "cengine-tar-quota-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        let policy = ArchivePolicy(
            wireBytes: 16 * 1_024,
            expandedBytes: 4,
            outputBytes: 16 * 1_024,
            fileBytes: 4,
            entries: 10,
            metadataRecords: 10,
            pathBytes: 128,
            linkBytes: 128,
            depth: 8
        )
        let exact = temporary.appending(path: "exact.tar")
        try testTar([
            .init(name: "exact", type: 0x30, data: Data("1234".utf8))
        ]).write(to: exact)
        _ = try SystemTar.extract(
            exact, to: temporary.appending(path: "exact"), policy: policy
        )

        let excess = temporary.appending(path: "excess.tar")
        try testTar([
            .init(name: "excess", type: 0x30, data: Data("12345".utf8))
        ]).write(to: excess)
        #expect(throws: EngineError.self) {
            try SystemTar.extract(
                excess, to: temporary.appending(path: "excess"), policy: policy
            )
        }
    }
}

private struct TestTarEntry {
    let name: String
    let type: UInt8
    var link = ""
    let data: Data
}

private func testTar(_ entries: [TestTarEntry]) -> Data {
    var result = Data()
    for entry in entries {
        var header = Data(repeating: 0, count: 512)
        testTarWrite(entry.name, to: &header, offset: 0, length: 100)
        testTarOctal(0o644, to: &header, offset: 100, length: 8)
        testTarOctal(0, to: &header, offset: 108, length: 8)
        testTarOctal(0, to: &header, offset: 116, length: 8)
        testTarOctal(entry.data.count, to: &header, offset: 124, length: 12)
        testTarOctal(0, to: &header, offset: 136, length: 12)
        for index in 148..<156 { header[index] = 0x20 }
        header[156] = entry.type
        testTarWrite(entry.link, to: &header, offset: 157, length: 100)
        testTarWrite("ustar", to: &header, offset: 257, length: 6)
        testTarWrite("00", to: &header, offset: 263, length: 2)
        let checksum = header.reduce(0) { $0 + Int($1) }
        let encoded = Data(String(format: "%06o\u{0} ", checksum).utf8)
        header.replaceSubrange(148..<156, with: encoded)
        result.append(header)
        result.append(entry.data)
        if entry.data.count % 512 != 0 {
            result.append(Data(repeating: 0, count: 512 - entry.data.count % 512))
        }
    }
    result.append(Data(repeating: 0, count: 1_024))
    return result
}

private func testTarWrite(
    _ value: String,
    to data: inout Data,
    offset: Int,
    length: Int
) {
    let bytes = Array(value.utf8.prefix(max(0, length - 1)))
    data.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
}

private func testTarOctal(
    _ value: Int,
    to data: inout Data,
    offset: Int,
    length: Int
) {
    testTarWrite(
        String(format: "%0*o", length - 1, value),
        to: &data,
        offset: offset,
        length: length
    )
}
