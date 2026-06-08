//
//  JumpListTests.swift
//  StrataTests
//
//  Covers the pure JumpList logic: the DestList byte-parser (synthetic v3
//  fixture), the CustomDestinations LNK carver, AppID resolution, and the
//  analyzer's RDP / suspicious-path rules.
//

import Testing
import Foundation
@testable import Strata

struct DestListParserTests {
    private static let knownDate = Date(timeIntervalSince1970: 1_700_000_000)
    private static var knownFiletime: UInt64 {
        UInt64((knownDate.timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
    }

    private func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff)] }
    private func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> (8 * $0)) & 0xff) } }
    private func le64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (UInt64(8 * $0))) & 0xff) } }
    private func utf16le(_ s: String) -> [UInt8] { s.utf16.flatMap { le16($0) } }

    private func header(version: UInt32, numEntries: UInt32) -> [UInt8] {
        var h = le32(version) + le32(numEntries) + le32(0) + le32(0)   // 0x00..0x10
        h += le32(numEntries) + le32(0) + le32(0) + le32(0)            // 0x10..0x20
        return h
    }

    /// A v3 DestList record: 0x70 fixed block, then StringSize + UTF-16 path + u32 tail.
    private func record(entryID: UInt32, hostname: String, filetime: UInt64,
                        pinStatus: Int32, accessCount: UInt32, path: String) -> [UInt8] {
        var r = le64(0)                            // @0x00 checksum
        r += [UInt8](repeating: 0, count: 16 * 4)  // @0x08 four droid GUIDs
        var host = Array(hostname.utf8); host = Array(host.prefix(16)); host += [UInt8](repeating: 0, count: 16 - host.count)
        r += host                                  // @0x48 hostname (16)
        r += le32(entryID)                         // @0x58
        r += le32(0)                               // @0x5C reserved
        r += le64(filetime)                        // @0x60
        r += le32(UInt32(bitPattern: pinStatus))   // @0x68
        r += le32(accessCount)                     // @0x6C
        // r.count == 0x70 here
        r += le16(UInt16(path.utf16.count))        // @0x70 StringSize (chars)
        r += utf16le(path)
        r += le32(0)                               // v3 trailing u32
        return r
    }

    @Test func parsesV3Record() throws {
        var bytes = header(version: 3, numEntries: 1)
        bytes += record(entryID: 1, hostname: "WORKSTATION01", filetime: Self.knownFiletime,
                        pinStatus: -1, accessCount: 5, path: #"C:\Users\a\evil.exe"#)
        let recs = DestListParser.parse(bytes: bytes)
        #expect(recs.count == 1)
        let r = try #require(recs.first)
        #expect(r.entryID == 1)
        #expect(r.hostname == "WORKSTATION01")
        #expect(r.lastAccessed == Self.knownDate)
        #expect(r.accessCount == 5)
        #expect(r.pinned == false)
        #expect(r.path == #"C:\Users\a\evil.exe"#)
    }

    @Test func parsesMultipleSequentialRecordsAndPin() throws {
        var bytes = header(version: 3, numEntries: 2)
        bytes += record(entryID: 1, hostname: "H1", filetime: Self.knownFiletime,
                        pinStatus: 0, accessCount: 1, path: #"C:\a.exe"#)   // pinned
        bytes += record(entryID: 0x1a, hostname: "H2", filetime: 0,
                        pinStatus: -1, accessCount: 2, path: #"\\srv\share\b.exe"#)
        let recs = DestListParser.parse(bytes: bytes)
        #expect(recs.count == 2)
        #expect(recs[0].pinned == true)
        #expect(recs[1].entryID == 0x1a)         // hex 1a == 26; matches its stream name
        #expect(recs[1].lastAccessed == nil)     // FILETIME 0 -> nil
        #expect(recs[1].path == #"\\srv\share\b.exe"#)
    }

    @Test func rejectsGarbageAndUnknownVersion() {
        #expect(DestListParser.parse(bytes: []).isEmpty)
        #expect(DestListParser.parse(bytes: header(version: 99, numEntries: 1)).isEmpty)
    }
}

struct ShellLinkCarverTests {
    @Test func carvesConcatenatedLnks() {
        let sig = ShellLinkCarver.signature
        // header junk + LNK1(sig + 40 bytes) + LNK2(sig + 24 bytes)
        var bytes: [UInt8] = [0x02, 0, 0, 0, 0x01, 0, 0, 0]   // customDestinations header-ish
        bytes += sig + Array(repeating: 0xAA, count: 40)
        bytes += sig + Array(repeating: 0xBB, count: 24)
        let blobs = ShellLinkCarver.carve(bytes)
        #expect(blobs.count == 2)
        #expect(Array(blobs[0].prefix(sig.count)) == sig)
        #expect(blobs[0].count == sig.count + 40)
        #expect(blobs[1].count == sig.count + 24)
    }

    @Test func emptyWhenNoSignature() {
        #expect(ShellLinkCarver.carve(Array(repeating: 0, count: 64)).isEmpty)
    }
}

struct JumpListAppIDTests {
    @Test func resolvesKnownAppIDs() {
        #expect(JumpListAppID.application(for: "ebbc7bd0eff5b9e8") == "Remote Desktop (mstsc)")
        #expect(JumpListAppID.application(for: "EBBC7BD0EFF5B9E8") == "Remote Desktop (mstsc)")   // case-insensitive
        #expect(JumpListAppID.application(for: "deadbeefdeadbeef") == nil)
    }

    @Test func extractsAppIDFromFilename() {
        #expect(JumpListAppID.appID(fromFilename: "5f7b5f1e01b83767.automaticDestinations-ms") == "5f7b5f1e01b83767")
        #expect(JumpListAppID.appID(fromFilename: "ABC.customDestinations-ms") == "abc")
    }
}

struct JumpListAnalyzerTests {
    private func context(_ entries: [JumpListEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], jumpList: entries)
    }

    @Test func flagsRDPDestinationAsLateralMovement() throws {
        let e = JumpListEntry(appID: JumpListAppID.remoteDesktop, application: "Remote Desktop (mstsc)",
                              listType: .automatic, entryID: 1, targetPath: "DC01",
                              lastAccessed: Date(), hostname: "WKS01", sourceFile: "x")
        let f = try #require(JumpListAnalyzer().analyze(context: context([e])).first)
        #expect(f.technique?.attackID == "T1021.001")
        #expect(f.phase == .actionsOnObjectives)
        #expect(f.title.contains("RDP destination"))
    }

    @Test func flagsSuspiciousTargetPath() throws {
        let e = JumpListEntry(appID: "1b4dd67f29cb1962", application: "Windows Explorer (Win7)",
                              listType: .automatic, targetPath: #"C:\Users\Public\evil.exe"#,
                              sourceFile: "x")
        let f = try #require(JumpListAnalyzer().analyze(context: context([e])).first)
        #expect(f.severity == .high)
        #expect(f.technique?.attackID == "T1204.002")
    }

    @Test func ignoresBenignEntry() {
        let e = JumpListEntry(appID: "adecfb853d77462a", application: "Microsoft Word 2010",
                              listType: .automatic, targetPath: #"C:\Users\a\Documents\report.docx"#,
                              sourceFile: "x")
        #expect(JumpListAnalyzer().analyze(context: context([e])).isEmpty)
    }
}
