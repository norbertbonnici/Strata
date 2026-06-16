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
}
