import Foundation
import Testing
@testable import StorageControllerRuntime

@Suite struct CanonicalTests {
    @Test func exactUInt64AndGoEscapes() throws {
        let source = #"{"a":{"b":[18446744073709551615,true,null]},"z":"\u003c\u0026\u003e\u2028"}"#
        let bytes = Data(source.utf8)
        let tree = try ControllerJSON.parse(bytes, limit: 65536)
        #expect(try tree.bytes() == bytes)
    }
    @Test func goControlCharacterVector() throws {
        // Generated with Go encoding/json.Marshal("\\x00\\b\\t\\n\\f\\r\\x1f").
        let expected = Data(#""\u0000\b\t\n\f\r\u001f""#.utf8)
        #expect(try ControllerJSON.string("\u{0}\u{8}\t\n\u{c}\r\u{1f}").bytes() == expected)
        #expect(try ControllerJSON.parse(expected, limit: 4096).bytes() == expected)
    }
    @Test func malformedAndDepthFuzz() throws {
        let invalid = ["", "{} ", "{\"x\":1,\"x\":2}", "{\"z\":1,\"a\":2}", "01", "-1", "1.0", "1e0", "18446744073709551616", "\"\\u0061\"", "\"<\"", "[true,]", "{\"a\":}"]
        for text in invalid { #expect(throws: (any Error).self) { try ControllerJSON.parse(Data(text.utf8), limit: 65536) } }
        for depth in 33...256 {
            let bytes = Data((String(repeating: "[", count: depth) + "0" + String(repeating: "]", count: depth)).utf8)
            #expect(throws: (any Error).self) { try ControllerJSON.parse(bytes, limit: 65536) }
        }
        var state: UInt64 = 17
        for _ in 0..<2000 {
            state = state &* 6364136223846793005 &+ 1
            let bytes = Data(withUnsafeBytes(of: state) { Array($0) })
            if let value = try? ControllerJSON.parse(bytes, limit: 64) { #expect(try value.bytes() == bytes) }
        }
    }
}
