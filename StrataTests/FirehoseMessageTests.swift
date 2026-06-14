//
//  FirehoseMessageTests.swift
//  StrataTests
//
//  Covers M5b of the unified-log decoder: firehose argument-item decoding
//  (FirehoseItemDecoder) and printf-style message rendering (LogFormatter).
//  The item-decoder fixtures mirror the real layout (item u8, number_items u8,
//  then per-item type/type_size + (offset u16, size u16) for string items, then
//  a value region), with a synthetic optional header prefixed to exercise the
//  anchor search. No evidence bytes.
//

import Testing
import Foundation
@testable import Strata

struct FirehoseMessageTests {

    private static func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8(v >> 8)] }

    /// Build a firehose data section: an arbitrary `header` (the flag-driven
    /// optional fields we anchor past), then `item`/`number_items`, string-item
    /// descriptors (type 0x42), and the concatenated NUL-terminated values.
    private static func stringArgsData(header: [UInt8], values: [String]) -> [UInt8] {
        var descriptors: [UInt8] = []
        var region: [UInt8] = []
        for v in values {
            let bytes = Array(v.utf8) + [0]
            let offset = UInt16(region.count)
            descriptors += [0x42, 0x01] + le16(offset) + le16(UInt16(bytes.count))
            region += bytes
        }
        return header + [0x22, UInt8(values.count)] + descriptors + region
    }

    // MARK: - item decoder

    @Test func decodesSingleStringArgPastHeader() {
        // 15-byte synthetic optional header (like the real flags=0x603 case).
        let header = Array(repeating: UInt8(0xEE), count: 15)
        let data = Self.stringArgsData(header: header, values: ["BA08DA59-3A00-4EA5"])
        let items = FirehoseItemDecoder.decode(data, expectedCount: 1)
        #expect(items.count == 1)
        #expect(items[0].value == "BA08DA59-3A00-4EA5")
        #expect(items[0].isNumber == false)
    }

    @Test func decodesMultipleStringArgs() {
        let data = Self.stringArgsData(header: [0, 0, 0, 0, 0, 0, 0, 0],
                                       values: ["PersonalPersona", "NoEncryption"])
        let items = FirehoseItemDecoder.decode(data, expectedCount: 2)
        #expect(items.count == 2)
        #expect(items[0].value == "PersonalPersona")
        #expect(items[1].value == "NoEncryption")
    }

    @Test func privateStringItemRedacts() {
        // A private string item (type 0x21) with size 0 → <private>.
        var data: [UInt8] = Array(repeating: 0, count: 8)
        data += [0x22, 0x01, 0x21, 0x01] + Self.le16(0) + Self.le16(0)   // private, empty
        let items = FirehoseItemDecoder.decode(data, expectedCount: 1)
        #expect(items.count == 1)
        #expect(items[0].isPrivate)
        #expect(items[0].value == nil)
    }

    // MARK: - formatter

    @Test func rendersObjectAndStringSpecifiers() {
        let items = [FirehoseItem(type: 0x42, value: "alice", isPrivate: false, isNumber: false),
                     FirehoseItem(type: 0x42, value: "/tmp/x", isPrivate: false, isNumber: false)]
        let out = LogFormatter.render(format: "user %@ wrote %s", items: items)
        #expect(out == "user alice wrote /tmp/x")
    }

    @Test func escapesDoublePercentAndKeepsLiterals() {
        #expect(LogFormatter.render(format: "100%% done", items: []) == "100% done")
    }

    @Test func stripsPublicAnnotationAndRenders() {
        let items = [FirehoseItem(type: 0x22, value: "ok", isPrivate: false, isNumber: false)]
        #expect(LogFormatter.render(format: "status=%{public}@", items: items) == "status=ok")
    }

    @Test func honoursPrivateAnnotation() {
        let items = [FirehoseItem(type: 0x22, value: "secret", isPrivate: false, isNumber: false)]
        #expect(LogFormatter.render(format: "tok=%{private}@", items: items) == "tok=<private>")
    }

    @Test func rendersIntegerHexAndBool() {
        let n = [FirehoseItem(type: 0x02, value: "255", isPrivate: false, isNumber: true)]
        #expect(LogFormatter.render(format: "n=%d", items: n) == "n=255")
        #expect(LogFormatter.render(format: "h=%x", items: n) == "h=ff")
        let b = [FirehoseItem(type: 0x02, value: "1", isPrivate: false, isNumber: true)]
        #expect(LogFormatter.render(format: "on=%{BOOL}d", items: b) == "on=true")
    }

    @Test func missingArgumentKeepsSpecifier() {
        // No items → the specifier text is preserved (message never lost).
        #expect(LogFormatter.render(format: "x=%@", items: []) == "x=%@")
    }

    @Test func specifierCountIgnoresEscapes() {
        #expect(LogFormatter.specifierCount("%@ and %d (100%%)") == 2)
        #expect(LogFormatter.specifierCount("no args") == 0)
    }

    // MARK: - end-to-end via the string catalog

    @Test func catalogRendersMessageFromMainExe() {
        // A uuidtext whose range [10,40) holds "hello %@" at offset 10.
        func le32(_ v: UInt32) -> [UInt8] { withUnsafeBytes(of: v.littleEndian) { Array($0) } }
        var ut: [UInt8] = le32(0x6677_8899) + le32(2) + le32(1) + le32(1)
        ut += le32(10) + le32(30)                       // one entry: rangeStart 10, size 30
        var block = Array("hello %@".utf8) + [0]; while block.count < 30 { block.append(0) }
        ut += block + Array("/usr/bin/greet".utf8) + [0]
        let file = UUIDTextParser.parse(Data(ut), uuid: "MAIN")!
        let cat = UnifiedLogStringCatalog(uuidTexts: ["MAIN": file])

        let data = Self.stringArgsData(header: Array(repeating: 0, count: 8), values: ["world"])
        let m = cat.render(flags: 0x0002, formatStringLocation: 10, data: data,
                           mainUUID: "MAIN", dscUUID: nil)
        #expect(m.message == "hello world")
        #expect(m.process == "greet")
    }
}
