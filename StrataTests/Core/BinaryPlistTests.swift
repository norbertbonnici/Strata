//
//  BinaryPlistTests.swift
//  StrataTests
//
//  Covers the bplist00 decoder: primitive round-trips against
//  PropertyListSerialization, and CF$UID preservation on a real NSKeyedArchiver
//  archive (the thing PropertyListSerialization hides).
//

import Testing
import Foundation
@testable import Strata

struct BinaryPlistTests {

    @Test func decodesPrimitivesAndContainers() {
        let obj: [String: Any] = [
            "n": 42, "neg": -7, "flag": true, "off": false,
            "s": "hello", "arr": [1, 2, 3], "nested": ["k": "v"],
            "blob": Data([0x01, 0x02, 0x03]),
        ]
        let data = try! PropertyListSerialization.data(fromPropertyList: obj, format: .binary, options: 0)
        guard let root = BinaryPlist.parse(data)?.dictValue else { Issue.record("parse failed"); return }
        #expect(root["n"]?.intValue == 42)
        #expect(root["neg"]?.intValue == -7)
        #expect(root["flag"] == .bool(true))
        #expect(root["off"] == .bool(false))
        #expect(root["s"]?.stringValue == "hello")
        #expect(root["arr"]?.arrayValue?.compactMap(\.intValue) == [1, 2, 3])
        #expect(root["nested"]?.dictValue?["k"]?.stringValue == "v")
        if case .data(let d)? = root["blob"] { #expect(Array(d) == [1, 2, 3]) } else { Issue.record("no blob") }
    }

    @Test func handlesLargeStringWithExtendedLength() {
        // A >15-char string forces the 0xF extended-length path.
        let long = String(repeating: "A", count: 500)
        let data = try! PropertyListSerialization.data(fromPropertyList: ["s": long], format: .binary, options: 0)
        #expect(BinaryPlist.parse(data)?.dictValue?["s"]?.stringValue == long)
    }

    @Test func preservesKeyedArchiverUIDs() {
        let archived = try! NSKeyedArchiver.archivedData(
            withRootObject: ["x": "y"], requiringSecureCoding: false)
        guard let root = BinaryPlist.parse(archived)?.dictValue else { Issue.record("parse failed"); return }
        #expect(root["$archiver"]?.stringValue == "NSKeyedArchiver")
        #expect(root["$objects"]?.arrayValue != nil)
        // $top.root is a CF$UID — must come through as .uid, not an opaque object.
        #expect(root["$top"]?.dictValue?["root"]?.uidValue != nil)
    }

    @Test func rejectsNonBplist() {
        #expect(BinaryPlist.parse(Data("not a plist".utf8)) == nil)
        #expect(BinaryPlist.parse(Data()) == nil)
    }

    @Test func toleratesTruncatedArchiveWithoutCrashing() {
        // A long string forces the extended-length path; truncating the buffer
        // must not read past the end (the sizeAndStart bounds guard) or crash.
        let full = try! PropertyListSerialization.data(
            fromPropertyList: ["s": String(repeating: "x", count: 400)], format: .binary, options: 0)
        for cut in [8, 20, 40, full.count / 2] where cut < full.count {
            _ = BinaryPlist.parse(full.prefix(full.count - cut))   // must not trap
        }
        #expect(Bool(true))
    }

    @Test func rejectsTrailerValuesThatDoNotFitInt() {
        var bytes = [UInt8](repeating: 0, count: 41)
        bytes.replaceSubrange(0..<8, with: Array("bplist00".utf8))
        let trailer = bytes.count - 32
        bytes[trailer + 6] = 8
        bytes[trailer + 7] = 8
        for i in 0..<8 { bytes[trailer + 8 + i] = 0xff }
        #expect(BinaryPlist.parse(Data(bytes)) == nil)
    }

    @Test func sharedReferencesDecodeOncePerObject() throws {
        // Object k is the array [k+1, k+1]; the last object is the int 7. As a
        // tree that's 2^39 leaves — a re-decoding parser hangs on these ~200
        // bytes. Memoized, each object decodes once.
        let depth = 40
        var bytes = Array("bplist00".utf8)
        var offsets: [UInt8] = []
        for k in 0..<(depth - 1) {
            offsets.append(UInt8(bytes.count))
            bytes += [0xA2, UInt8(k + 1), UInt8(k + 1)]   // 2-element array, 1-byte refs
        }
        offsets.append(UInt8(bytes.count))
        bytes += [0x10, 0x07]                              // 1-byte int 7
        let tableOffset = bytes.count
        bytes += offsets
        func be64(_ v: Int) -> [UInt8] { (0..<8).reversed().map { UInt8((v >> ($0 * 8)) & 0xFF) } }
        bytes += [0, 0, 0, 0, 0, 0, 1, 1]                  // unused ×6, offsetSize, refSize
        bytes += be64(depth) + be64(0) + be64(tableOffset)

        var node = try #require(BinaryPlist.parse(Data(bytes)))
        for _ in 0..<(depth - 1) {
            let pair = try #require(node.arrayValue)
            #expect(pair.count == 2)
            node = pair[1]
        }
        #expect(node.intValue == 7)
    }

    @Test func rejectsExtendedObjectLengthThatDoesNotFitInt() throws {
        let encoded = try PropertyListSerialization.data(
            fromPropertyList: String(repeating: "x", count: 500), format: .binary, options: 0)
        var bytes = [UInt8](encoded)
        let marker = try #require(bytes.firstIndex(of: 0x5f))
        bytes[marker + 1] = 0x13 // eight-byte integer length
        for i in 0..<8 { bytes[marker + 2 + i] = 0xff }
        #expect(BinaryPlist.parse(Data(bytes)) == nil)
    }
}
