//
//  SrumExportDecoderTests.swift
//  StrataTests
//
//  Validates the pure SRUM export decoder against synthetic esedbexport-format TSV
//  fixtures: headered tab-separated tables, hex-encoded IdBlob (UTF-16LE path vs
//  binary SID), libfdatetime CTIME timestamps, and the AppId/UserId -> IdMap join.
//

import Testing
import Foundation
@testable import Strata

struct SrumExportDecoderTests {
    // MARK: - fixture builders

    /// UTF-16LE hex of a string with a trailing NUL (how IdBlob path strings render).
    private func utf16Hex(_ s: String) -> String {
        var bytes: [UInt8] = []
        for u in s.utf16 { bytes.append(UInt8(u & 0xff)); bytes.append(UInt8(u >> 8)) }
        bytes += [0, 0]
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Binary-SID hex for an `S-1-5-...` string (6-byte big-endian authority,
    /// 4-byte little-endian sub-authorities) — how a type-3 IdBlob renders.
    private func sidHex(_ sid: String) -> String {
        let parts = sid.split(separator: "-").map(String.init)
        // parts[0] == "S"
        let revision = UInt8(parts[1])!
        let authority = UInt64(parts[2])!
        let subs = parts.dropFirst(3).map { UInt32($0)! }
        var bytes: [UInt8] = [revision, UInt8(subs.count)]
        for i in stride(from: 5, through: 0, by: -1) { bytes.append(UInt8((authority >> (8 * UInt64(i))) & 0xff)) }
        for sub in subs { for i in 0..<4 { bytes.append(UInt8((sub >> (8 * i)) & 0xff)) } }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func utc(_ y: Int, _ mo: Int, _ d: Int, _ h: Int, _ mi: Int, _ s: Int) -> Date {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal.date(from: DateComponents(year: y, month: mo, day: d, hour: h, minute: mi, second: s))!
    }

    private let evilPath = #"\Device\HarddiskVolume2\Users\Public\evil.exe"#
    private let userSID  = "S-1-5-21-1111-2222-3333-1001"

    private func idMapTSV() -> String {
        """
        IdType\tIdIndex\tIdBlob
        0\t101\t\(utf16Hex(evilPath))
        3\t202\t\(sidHex(userSID))
        """
    }

    // MARK: - low-level decoders

    @Test func decodesUTF16LEBlobAndDropsNul() {
        let hex = utf16Hex(#"C:\tools\p.exe"#)
        #expect(SrumExportDecoder.decodeUTF16LE(SrumExportDecoder.hexToBytes(hex)) == #"C:\tools\p.exe"#)
    }

    @Test func decodesBinarySID() {
        let hex = sidHex("S-1-5-21-1111-2222-3333-1001")
        #expect(SrumExportDecoder.decodeSID(SrumExportDecoder.hexToBytes(hex)) == "S-1-5-21-1111-2222-3333-1001")
    }

    @Test func parsesCTimeTimestamp() {
        let d = CTimeDecoder().parse("Jun 09, 2025 13:45:07.000000000")
        #expect(d == utc(2025, 6, 9, 13, 45, 7))
    }

    @Test func parsesCTimeWithSpacePaddedDay() {
        let d = CTimeDecoder().parse("Jun  9, 2025 00:00:00.000000000")
        #expect(d == utc(2025, 6, 9, 0, 0, 0))
    }

    @Test func ctimeRejectsEmpty() {
        #expect(CTimeDecoder().parse("") == nil)
        #expect(CTimeDecoder().parse(nil) == nil)
    }

    @Test func ctimeRawOLEFallbackPreservesTimeOfDay() throws {
        // If a build ever emits a raw OLE-automation-date double instead of a
        // CTIME string, the fractional day (time-of-day) must survive: .5 day = 12h.
        let dt = CTimeDecoder()
        let midnight = try #require(dt.parse("45678"))
        let noon = try #require(dt.parse("45678.5"))
        #expect(noon.timeIntervalSince(midnight) == 43_200)   // exactly 12 hours
    }

    @Test func idMapResolvesPathAndSID() {
        let map = SrumExportDecoder.decodeIdMap(idMapTSV())
        #expect(map[101] == evilPath)
        #expect(map[202] == userSID)
    }

    // MARK: - provider tables + join

    @Test func decodesNetworkDataWithResolvedKeys() throws {
        let net = """
        AutoIncId\tTimeStamp\tAppId\tUserId\tInterfaceLuid\tBytesSent\tBytesRecvd
        1\tJun 09, 2025 13:45:07.000000000\t101\t202\t1\t1048576\t2048
        """
        let entries = SrumExportDecoder.decode(idMapTSV: idMapTSV(), networkDataTSV: net,
                                               appResourceTSV: nil, networkConnectivityTSV: nil,
                                               sourceFile: "SRUDB.dat")
        let e = try #require(entries.first)
        #expect(e.kind == .networkData)
        #expect(e.application == evilPath)
        #expect(e.userSID == userSID)
        #expect(e.bytesSent == 1_048_576)
        #expect(e.bytesReceived == 2048)
        #expect(e.timestamp == utc(2025, 6, 9, 13, 45, 7))
        #expect(e.appShortName == "evil.exe")
    }

    @Test func decodesAppResourceSummingForegroundAndBackground() throws {
        let app = """
        AutoIncId\tTimeStamp\tAppId\tUserId\tForegroundBytesRead\tForegroundBytesWritten\tBackgroundBytesRead\tBackgroundBytesWritten
        1\tJun 09, 2025 14:00:00.000000000\t101\t202\t1000\t500\t10\t5
        """
        let entries = SrumExportDecoder.decode(idMapTSV: idMapTSV(), networkDataTSV: nil,
                                               appResourceTSV: app, networkConnectivityTSV: nil,
                                               sourceFile: "SRUDB.dat")
        let e = try #require(entries.first)
        #expect(e.kind == .appResourceUsage)
        #expect(e.bytesRead == 1010)     // 1000 fg + 10 bg
        #expect(e.bytesWritten == 505)   // 500 fg + 5 bg
        #expect(e.application == evilPath)
    }

    @Test func decodesNetworkConnectivity() throws {
        let conn = """
        AutoIncId\tTimeStamp\tAppId\tUserId\tInterfaceLuid\tConnectedTime\tConnectStartTime
        1\tJun 09, 2025 12:00:00.000000000\t101\t202\t1\t3600\tJun 09, 2025 11:00:00.000000000
        """
        let entries = SrumExportDecoder.decode(idMapTSV: idMapTSV(), networkDataTSV: nil,
                                               appResourceTSV: nil, networkConnectivityTSV: conn,
                                               sourceFile: "SRUDB.dat")
        let e = try #require(entries.first)
        #expect(e.kind == .networkConnectivity)
        #expect(e.connectedSeconds == 3600)
        #expect(e.connectStart == utc(2025, 6, 9, 11, 0, 0))
    }

    @Test func handlesEmptyAndHeaderOnly() {
        #expect(SrumExportDecoder.decode(idMapTSV: nil, networkDataTSV: nil,
                                         appResourceTSV: nil, networkConnectivityTSV: nil,
                                         sourceFile: "x").isEmpty)
        let headerOnly = "AutoIncId\tTimeStamp\tAppId\tUserId\tBytesSent\tBytesRecvd"
        #expect(SrumExportDecoder.decode(idMapTSV: idMapTSV(), networkDataTSV: headerOnly,
                                         appResourceTSV: nil, networkConnectivityTSV: nil,
                                         sourceFile: "x").isEmpty)
    }

    @Test func parsesCRLFLineEndings() throws {
        // Hardening: a CRLF-lined export must not leave "\r" on the last column.
        let net = "AutoIncId\tTimeStamp\tAppId\tUserId\tBytesSent\tBytesRecvd\r\n"
            + "1\tJun 09, 2025 13:45:07.000000000\t101\t202\t10\t2048\r\n"
        let e = try #require(SrumExportDecoder.decode(idMapTSV: idMapTSV(), networkDataTSV: net,
                                                      appResourceTSV: nil, networkConnectivityTSV: nil,
                                                      sourceFile: "x").first)
        #expect(e.bytesSent == 10)
        #expect(e.bytesReceived == 2048)   // the trailing CRLF column still parses
    }

    @Test func unresolvedForeignKeyLeavesNilApplication() throws {
        // AppId 999 is not in the id map -> application stays nil, row still emitted.
        let net = """
        AutoIncId\tTimeStamp\tAppId\tUserId\tBytesSent\tBytesRecvd
        1\tJun 09, 2025 13:45:07.000000000\t999\t202\t10\t20
        """
        let e = try #require(SrumExportDecoder.decode(idMapTSV: idMapTSV(), networkDataTSV: net,
                                                      appResourceTSV: nil, networkConnectivityTSV: nil,
                                                      sourceFile: "x").first)
        #expect(e.application == nil)
        #expect(e.userSID == userSID)
        #expect(e.appShortName == "—")
    }
}
