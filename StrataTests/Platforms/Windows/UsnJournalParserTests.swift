//
//  UsnJournalParserTests.swift
//  StrataTests
//
//  Validates the USN journal byte-parser against synthetic V2/V3 records and the
//  critical sparse-zero-gap skip-forward behaviour (the $J stream's oldest region
//  is zeros, so a naive stop-on-zero would truncate the whole parse).
//

import Testing
import Foundation
@testable import Strata

struct UsnJournalParserTests {
    private static let knownDate = Date(timeIntervalSince1970: 1_700_000_000)
    private static var knownFiletime: UInt64 {
        UInt64((knownDate.timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
    }

    private func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff)] }
    private func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> (8 * $0)) & 0xff) } }
    private func le64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (UInt64(8 * $0))) & 0xff) } }
    private func utf16le(_ s: String) -> [UInt8] { s.utf16.flatMap { le16($0) } }

    /// Build a USN_RECORD_V2 (or V3 with 128-bit refs).
    private func record(name: String, frn: UInt64, parent: UInt64, usn: UInt64,
                        filetime: UInt64, reason: UInt32, attrs: UInt32, v3: Bool = false) -> [UInt8] {
        let n = utf16le(name)
        let headerSize: UInt16 = v3 ? 0x4C : 0x3C
        var r = le32(0)                                  // @0 RecordLength (patched below)
        r += le16(v3 ? 3 : 2) + le16(0)                  // @4 major, @6 minor
        r += le64(frn); if v3 { r += le64(0) }           // @8 FRN (128-bit on v3)
        r += le64(parent); if v3 { r += le64(0) }        // ParentFRN
        r += le64(usn)                                   // Usn
        r += le64(filetime)                              // TimeStamp
        r += le32(reason) + le32(0) + le32(0)            // Reason, SourceInfo, SecurityId
        r += le32(attrs)                                 // FileAttributes
        r += le16(UInt16(n.count)) + le16(headerSize)    // FileNameLength, FileNameOffset
        r += n
        while r.count % 8 != 0 { r.append(0) }           // 8-byte alignment
        let len = le32(UInt32(r.count)); for i in 0..<4 { r[i] = len[i] }
        return r
    }

    @Test func parsesV2CreateRecord() throws {
        let bytes = record(name: "evil.exe", frn: (7 << 48) | 1234, parent: 5678, usn: 0x1000,
                           filetime: Self.knownFiletime,
                           reason: UsnReason.fileCreate | UsnReason.close, attrs: 0x20)
        let recs = UsnJournalParser.parse(bytes: bytes, sourceFile: "$J")
        #expect(recs.count == 1)
        let r = try #require(recs.first)
        #expect(r.fileName == "evil.exe")
        #expect(r.isCreate)
        #expect(r.isDirectory == false)
        #expect(r.mftEntry == 1234)
        #expect(r.mftSequence == 7)            // high 16 bits of the file reference
        #expect(r.parentMftEntry == 5678)
        #expect(r.timestamp == Self.knownDate)
        #expect(r.reasonLabels.contains("File create"))
    }

    @Test func parsesV3RecordWith128BitRefs() throws {
        let bytes = record(name: "x.ps1", frn: 42, parent: 9, usn: 0x2000,
                           filetime: Self.knownFiletime, reason: UsnReason.fileDelete,
                           attrs: 0x80, v3: true)
        let r = try #require(UsnJournalParser.parse(bytes: bytes, sourceFile: "$J").first)
        #expect(r.fileName == "x.ps1")
        #expect(r.isDelete)
        #expect(r.mftEntry == 42)
    }

    @Test func directoryFlagDecoded() throws {
        let bytes = record(name: "Temp", frn: 1, parent: 2, usn: 1, filetime: 0,
                           reason: UsnReason.fileCreate, attrs: 0x10)   // 0x10 = DIRECTORY
        let r = try #require(UsnJournalParser.parse(bytes: bytes, sourceFile: "$J").first)
        #expect(r.isDirectory)
        #expect(r.timestamp == nil)            // FILETIME 0 -> nil
    }

    @Test func skipsLeadingSparseZeroGapAndParsesMultiple() {
        // The $J starts with a long zero run; the parser must skip it, not stop.
        var bytes = [UInt8](repeating: 0, count: 4096)
        bytes += record(name: "a.exe", frn: 1, parent: 2, usn: 1, filetime: Self.knownFiletime,
                        reason: UsnReason.fileCreate, attrs: 0x20)
        bytes += record(name: "b.dll", frn: 3, parent: 2, usn: 2, filetime: Self.knownFiletime,
                        reason: UsnReason.fileDelete, attrs: 0x20)
        let recs = UsnJournalParser.parse(bytes: bytes, sourceFile: "$J")
        #expect(recs.count == 2)
        #expect(recs[0].fileName == "a.exe")
        #expect(recs[1].fileName == "b.dll")
    }

    @Test func emptyAndAllZeroYieldNothing() {
        #expect(UsnJournalParser.parse(bytes: [], sourceFile: "$J").isEmpty)
        #expect(UsnJournalParser.parse(bytes: Array(repeating: 0, count: 8192), sourceFile: "$J").isEmpty)
    }
}
