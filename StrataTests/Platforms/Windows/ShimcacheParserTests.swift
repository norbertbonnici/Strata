//
//  ShimcacheParserTests.swift
//  StrataTests
//
//  Validates the AppCompatCache (Shimcache) byte-parser against synthetic
//  per-version blobs hand-built from the public spec. There is no real test
//  data, so these fixtures ARE the spec contract: path, last-modified FILETIME,
//  insertion order, version detection, hex round-trip, and graceful failure.
//

import Testing
import Foundation
@testable import Strata

struct ShimcacheParserTests {

    // Known timestamp: 2021-06-01 00:00:00 UTC.
    private static let knownDate = Date(timeIntervalSince1970: 1_622_505_600)
    private static var knownFiletime: UInt64 {
        UInt64((knownDate.timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
    }

    // MARK: - Little-endian builders

    private func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff)] }
    private func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> (8 * $0)) & 0xff) } }
    private func le64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (UInt64(8 * $0))) & 0xff) } }
    private func utf16le(_ s: String) -> [UInt8] { s.utf16.flatMap { le16($0) } }

    /// One Win10/Win8.1 "10ts" entry: head (sig, unknown, cacheEntrySize) + body
    /// (pathSize, path, FILETIME, dataSize, data).
    private func tsEntry(sig: [UInt8], path: String, filetime: UInt64, data: [UInt8] = []) -> [UInt8] {
        let p = utf16le(path)
        var body = le16(UInt16(p.count)) + p + le64(filetime) + le32(UInt32(data.count)) + data
        var entry = sig + [0, 0, 0, 0] + le32(UInt32(body.count))
        entry += body
        return entry
    }

    private func win10Blob(_ entries: [[UInt8]]) -> [UInt8] {
        var blob = le32(0x34)                                  // header size at offset 0
        blob += [UInt8](repeating: 0, count: 0x34 - blob.count)
        for e in entries { blob += e }
        return blob
    }

    // MARK: - Win10

    @Test func parsesWin10Entries() throws {
        let ts10: [UInt8] = [0x31, 0x30, 0x74, 0x73]
        let blob = win10Blob([
            tsEntry(sig: ts10, path: #"C:\Windows\Temp\evil.exe"#, filetime: Self.knownFiletime),
            tsEntry(sig: ts10, path: #"C:\Windows\System32\cmd.exe"#, filetime: 0, data: [1, 2, 3, 4]),
        ])
        let entries = ShimcacheParser.parse(bytes: blob, sourceFile: "/SYSTEM")
        #expect(entries.count == 2)
        #expect(entries[0].path == #"C:\Windows\Temp\evil.exe"#)
        #expect(entries[0].version == .windows10)
        #expect(entries[0].insertionOrder == 0)
        #expect(entries[0].lastModified == Self.knownDate)
        #expect(entries[1].path == #"C:\Windows\System32\cmd.exe"#)
        #expect(entries[1].insertionOrder == 1)
        #expect(entries[1].lastModified == nil)          // FILETIME 0 -> nil
        #expect(entries[1].name == "cmd.exe")
    }

    @Test func detectsWin81ByHeaderSize() {
        // Header size 0x80 + "10ts" entry signature == Win8.1.
        let ts10: [UInt8] = [0x31, 0x30, 0x74, 0x73]
        var blob = le32(0x80)
        blob += [UInt8](repeating: 0, count: 0x80 - blob.count)
        blob += tsEntry(sig: ts10, path: #"C:\a.exe"#, filetime: Self.knownFiletime)
        let entries = ShimcacheParser.parse(bytes: blob, sourceFile: "x")
        #expect(entries.first?.version == .windows81)
        #expect(entries.first?.path == #"C:\a.exe"#)
    }

    // MARK: - Win7 (x64, offset-referenced paths)

    @Test func parsesWin7x64() throws {
        let path = #"C:\Temp\a.exe"#
        let p = utf16le(path)
        let entriesStart = 0x80, stride = 48
        let pathOffset = entriesStart + stride

        var header = le32(0xBADC_0FEE) + le32(1)              // magic + entry count
        header += [UInt8](repeating: 0, count: 0x80 - header.count)

        var entry = le16(UInt16(p.count)) + le16(UInt16(p.count)) + le32(0)   // pathLen, maxLen, padding
        entry += le64(UInt64(pathOffset))                    // path offset
        entry += le64(Self.knownFiletime)                    // FILETIME
        entry += le32(0) + le32(0)                           // insertion + shim flags
        entry += le64(0) + le64(0)                           // data size + offset
        #expect(entry.count == stride)

        let blob = header + entry + p
        let entries = ShimcacheParser.parse(bytes: blob, sourceFile: "x")
        #expect(entries.count == 1)
        let e = try #require(entries.first)
        #expect(e.version == .windows7)
        #expect(e.path == path)
        #expect(e.lastModified == Self.knownDate)
    }

    // MARK: - Robustness

    @Test func returnsEmptyOnGarbageOrUnknownMagic() {
        #expect(ShimcacheParser.parse(bytes: [], sourceFile: "x").isEmpty)
        #expect(ShimcacheParser.parse(bytes: [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0], sourceFile: "x").isEmpty)
        #expect(ShimcacheParser.parse(bytes: Array(repeating: 0x41, count: 64), sourceFile: "x").isEmpty)
    }

    @Test func hexDecodeRoundTripsThroughParse() {
        let ts10: [UInt8] = [0x31, 0x30, 0x74, 0x73]
        let blob = win10Blob([tsEntry(sig: ts10, path: #"C:\x.exe"#, filetime: 0)])
        let hex = blob.map { String(format: "%02x", $0) }.joined()
        let entries = ShimcacheParser.parse(hex: hex, sourceFile: "x")
        #expect(entries.first?.path == #"C:\x.exe"#)
        #expect(ShimcacheParser.parse(hex: "abc", sourceFile: "x").isEmpty)   // odd length -> nil -> []
    }

    @Test func fromRegistryPicksAppCompatCacheValue() {
        let ts10: [UInt8] = [0x31, 0x30, 0x74, 0x73]
        let blob = win10Blob([tsEntry(sig: ts10, path: #"C:\evil.exe"#, filetime: 0)])
        let hex = blob.map { String(format: "%02x", $0) }.joined()
        let values = [
            RegistryValue(hive: "SYSTEM",
                          path: #"ControlSet001\Control\Session Manager\AppCompatCache"#,
                          name: "AppCompatCache", type: .binary, data: hex, sourceFile: "/SYSTEM"),
            RegistryValue(hive: "SYSTEM", path: #"ControlSet001\Control\Foo"#,
                          name: "Other", type: .sz, data: "noise", sourceFile: "/SYSTEM"),
        ]
        let entries = ShimcacheParser.fromRegistry(values)
        #expect(entries.count == 1)
        #expect(entries.first?.path == #"C:\evil.exe"#)
    }
}

struct ShimcacheAnalyzerTests {
    private func context(_ entries: [ShimcacheEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], shimcache: entries)
    }

    @Test func flagsSuspiciousPath() throws {
        let e = ShimcacheEntry(path: #"C:\Windows\Temp\evil.exe"#, lastModified: nil,
                               insertionOrder: 0, version: .windows10, sourceFile: "x")
        let f = try #require(ShimcacheAnalyzer().analyze(context: context([e])).first)
        #expect(f.severity == .high)
        #expect(f.phase == .installation)
        #expect(f.detail.localizedCaseInsensitiveContains("not that it executed"))   // presence wording
    }

    @Test func ignoresBenignSystemPath() {
        let e = ShimcacheEntry(path: #"C:\Windows\System32\cmd.exe"#, lastModified: nil,
                               insertionOrder: 0, version: .windows10, sourceFile: "x")
        #expect(ShimcacheAnalyzer().analyze(context: context([e])).isEmpty)
    }
}
