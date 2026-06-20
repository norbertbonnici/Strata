//
//  RecycleBinTests.swift
//  StrataTests
//
//  Validates the Windows $Recycle.Bin $I index-file byte-parser (v1 pre-Win10 +
//  v2 Win10+ layouts) and the RecycleBinAnalyzer detection rules (deleted
//  executable from a suspicious path + mass-deletion burst), using byte-built
//  fixtures (no real $I files).
//

import Testing
import Foundation
@testable import Strata

struct RecycleBinTests {

    // MARK: - Byte builders

    private func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> (8 * $0)) & 0xff) } }
    private func le64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (UInt64(8 * $0))) & 0xff) } }
    private func utf16le(_ s: String) -> [UInt8] { s.utf16.flatMap { [UInt8($0 & 0xff), UInt8(($0 >> 8) & 0xff)] } }

    /// Known FILETIME for 2023-06-15 12:00:00 UTC.
    /// unix = 1686830400 s; FILETIME = (unix + 11644473600) * 10_000_000.
    private static let knownFiletime: UInt64 = (1_686_830_400 + 11_644_473_600) * 10_000_000
    private static let knownDate = Date(timeIntervalSince1970: 1_686_830_400)

    /// Build a v1 $I: u64(1) + u64(size) + u64(filetime) + 520-byte fixed path
    /// region (UTF-16LE + NUL, zero-padded to 520).
    private func makeV1(path: String, size: UInt64, filetime: UInt64) -> Data {
        var b: [UInt8] = []
        b += le64(1)
        b += le64(size)
        b += le64(filetime)
        var pathRegion = utf16le(path)
        pathRegion += [0, 0]                       // NUL terminator unit
        while pathRegion.count < 520 { pathRegion.append(0) }
        if pathRegion.count > 520 { pathRegion = Array(pathRegion.prefix(520)) }
        b += pathRegion
        return Data(b)
    }

    /// Build a v2 $I: u64(2) + u64(size) + u64(filetime) + u32(charCount incl.
    /// NUL) + UTF-16LE path + NUL unit.
    private func makeV2(path: String, size: UInt64, filetime: UInt64) -> Data {
        var b: [UInt8] = []
        b += le64(2)
        b += le64(size)
        b += le64(filetime)
        let units = path.utf16.count + 1           // include trailing NUL
        b += le32(UInt32(units))
        b += utf16le(path)
        b += [0, 0]                                // NUL unit
        return Data(b)
    }

    // MARK: - Parser: positive

    @Test func parseV1Decodes() {
        let data = makeV1(path: "C:\\Users\\bob\\Desktop\\evil.exe",
                          size: 123_456, filetime: Self.knownFiletime)
        let e = RecycleBinParser.parse(data: data, recycledName: "$IABCDE.exe",
                                       sourceFile: "/C/$Recycle.Bin/S-1-5-21/$IABCDE.exe",
                                       sid: "S-1-5-21-1")
        #expect(e != nil)
        #expect(e?.originalPath == "C:\\Users\\bob\\Desktop\\evil.exe")
        #expect(e?.sizeBytes == 123_456)
        #expect(e?.recycledName == "$IABCDE.exe")
        #expect(e?.sid == "S-1-5-21-1")
        #expect(e?.fileName == "evil.exe")
        #expect(e?.fileExtension == "exe")
        #expect(e?.deletedAt != nil)
        if let d = e?.deletedAt {
            #expect(abs(d.timeIntervalSince(Self.knownDate)) < 1.0)
        }
    }

    @Test func parseV2DecodesAndTrimsNUL() {
        let data = makeV2(path: "C:\\Windows\\Temp\\mimikatz.exe",
                          size: 999, filetime: Self.knownFiletime)
        let e = RecycleBinParser.parse(data: data, recycledName: "$IZZZZZ.exe",
                                       sourceFile: "src", sid: nil)
        #expect(e != nil)
        // Trailing NUL must be stripped — no embedded NUL char in the path.
        #expect(e?.originalPath == "C:\\Windows\\Temp\\mimikatz.exe")
        #expect(e?.originalPath.contains("\0") == false)
        #expect(e?.sizeBytes == 999)
        #expect(e?.sid == nil)
        #expect(e?.fileExtension == "exe")
        if let d = e?.deletedAt {
            var cal = Calendar(identifier: .gregorian)
            cal.timeZone = TimeZone(identifier: "UTC")!
            #expect(cal.component(.year, from: d) == 2023)
        }
    }

    // MARK: - Parser: negative / malformed

    @Test func parseRejectsMalformed() {
        // Empty data.
        #expect(RecycleBinParser.parse(data: Data(), recycledName: "x", sourceFile: "s", sid: nil) == nil)

        // Bad version (3).
        var bad = le64(3) + le64(0) + le64(0)
        bad += utf16le("C:\\x.exe") + [0, 0]
        #expect(RecycleBinParser.parse(data: Data(bad), recycledName: "x", sourceFile: "s", sid: nil) == nil)

        // Truncated (< 24 bytes).
        #expect(RecycleBinParser.parse(data: Data(le64(2) + le64(0)),
                                       recycledName: "x", sourceFile: "s", sid: nil) == nil)

        // v2 with absurd char-count.
        var absurd = le64(2) + le64(0) + le64(0)
        absurd += le32(0xFFFF_FFFF)
        #expect(RecycleBinParser.parse(data: Data(absurd), recycledName: "x", sourceFile: "s", sid: nil) == nil)
    }

    @Test func parseV2WithZeroDeletionTimeKeepsNilDate() {
        let data = makeV2(path: "C:\\Users\\bob\\notes.txt", size: 10, filetime: 0)
        let e = RecycleBinParser.parse(data: data, recycledName: "$I.txt", sourceFile: "s", sid: nil)
        #expect(e != nil)
        #expect(e?.deletedAt == nil)          // FileTime.date(0) → nil, entry still returned
        #expect(e?.originalPath == "C:\\Users\\bob\\notes.txt")
    }

    // MARK: - Analyzer: Rule 1

    @Test func analyzerFlagsDeletedExeFromSuspiciousPath() {
        let e = RecycleBinEntry(originalPath: "C:\\Users\\Public\\Downloads\\mimikatz.exe",
                                deletedAt: Self.knownDate, sizeBytes: 100,
                                recycledName: "$I1.exe", sid: "S-1-5-21-1",
                                sourceFile: "/C/$Recycle.Bin/S-1-5-21-1/$I1.exe")
        let findings = RecycleBinAnalyzer().analyze([e])
        let high = findings.filter { $0.severity == .high }
        #expect(high.count == 1)
        #expect(high.first?.technique?.attackID == "T1070.004")
        #expect(high.first?.phase == .actionsOnObjectives)
        #expect(high.first?.timestamp == Self.knownDate)
        #expect(high.first?.evidencePaths.contains("C:\\Users\\Public\\Downloads\\mimikatz.exe") == true)
    }

    @Test func analyzerExeFromCleanPathIsMediumNotHigh() {
        let e = RecycleBinEntry(originalPath: "C:\\Users\\bob\\Documents\\tool.exe",
                                deletedAt: Self.knownDate, sizeBytes: 100,
                                recycledName: "$I2.exe", sid: nil, sourceFile: "s")
        let findings = RecycleBinAnalyzer().analyze([e])
        #expect(findings.filter { $0.severity == .high }.isEmpty)
        #expect(findings.contains { $0.severity == .medium && $0.technique?.attackID == "T1070.004" })
    }

    @Test func analyzerIgnoresBenignTextFile() {
        let e = RecycleBinEntry(originalPath: "C:\\Users\\bob\\Documents\\notes.txt",
                                deletedAt: Self.knownDate, sizeBytes: 100,
                                recycledName: "$I3.txt", sid: nil, sourceFile: "s")
        let findings = RecycleBinAnalyzer().analyze([e])
        #expect(findings.isEmpty)             // .txt not in exe set, not suspicious
    }

    // MARK: - Analyzer: Rule 2 (burst)

    @Test func analyzerFlagsMassDeletionBurst() {
        let base = Self.knownDate
        // 30 deletions within a 2-minute window (well under 300s).
        let entries = (0..<30).map { i in
            RecycleBinEntry(originalPath: "C:\\Users\\bob\\Documents\\doc\(i).docx",
                            deletedAt: base.addingTimeInterval(Double(i) * 4),  // 0..116s
                            sizeBytes: 10, recycledName: "$I\(i).docx", sid: nil,
                            sourceFile: "/C/$Recycle.Bin/S-1-5-21-1/$I\(i)")
        }
        let findings = RecycleBinAnalyzer().analyze(entries)
        let burst = findings.filter { $0.title.contains("Mass file deletion") }
        #expect(burst.count == 1)
        #expect(burst.first?.technique?.attackID == "T1070.004")
        #expect(burst.first?.phase == .actionsOnObjectives)
    }

    @Test func analyzerNoBurstWhenSpreadOut() {
        let base = Self.knownDate
        // 30 deletions spread over 2 hours — no 300s window holds >= 25.
        let entries = (0..<30).map { i in
            RecycleBinEntry(originalPath: "C:\\Users\\bob\\Documents\\doc\(i).docx",
                            deletedAt: base.addingTimeInterval(Double(i) * 240),  // 4 min apart
                            sizeBytes: 10, recycledName: "$I\(i).docx", sid: nil, sourceFile: "s")
        }
        let findings = RecycleBinAnalyzer().analyze(entries)
        #expect(findings.allSatisfy { !$0.title.contains("Mass file deletion") })
    }

    // MARK: - Protocol entrypoint

    @Test func protocolEntrypointReturnsEmptyWithoutContextField() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [])
        #expect(RecycleBinAnalyzer().analyze(context: ctx).isEmpty)
    }
}
