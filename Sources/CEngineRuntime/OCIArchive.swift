import Foundation

enum OCIArchive {
    static func tar(entries: [(String, Data)]) -> Data {
        var archive = Data()
        for (name, contents) in entries.sorted(by: { $0.0 < $1.0 }) {
            var header = Data(repeating: 0, count: 512)
            write(name, to: &header, offset: 0, length: 100)
            writeOctal(0o644, to: &header, offset: 100, length: 8)
            writeOctal(0, to: &header, offset: 108, length: 8)
            writeOctal(0, to: &header, offset: 116, length: 8)
            writeOctal(contents.count, to: &header, offset: 124, length: 12)
            writeOctal(0, to: &header, offset: 136, length: 12)
            for index in 148..<156 { header[index] = 0x20 }
            header[156] = Character("0").asciiValue!
            write("ustar", to: &header, offset: 257, length: 6)
            write("00", to: &header, offset: 263, length: 2)
            let checksum = header.reduce(0) { $0 + Int($1) }
            let value = String(format: "%06o\u{0} ", checksum).data(using: .ascii)!
            header.replaceSubrange(148..<156, with: value)
            archive.append(header); archive.append(contents)
            if contents.count % 512 != 0 { archive.append(Data(repeating: 0, count: 512 - contents.count % 512)) }
        }
        archive.append(Data(repeating: 0, count: 1024))
        return archive
    }

    private static func write(_ value: String, to data: inout Data, offset: Int, length: Int) {
        let bytes = Array(value.utf8.prefix(max(0, length - 1)))
        data.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
    }

    private static func writeOctal(_ value: Int, to data: inout Data, offset: Int, length: Int) {
        write(String(format: "%0*o", length - 1, value), to: &data, offset: offset, length: length)
    }
}
