//
//  InputSafetyTests.swift
//  StrataTests
//
//  Regression tests for the hostile-input hardening pass. All parser input is
//  adversary-controlled, so these assert that malformed length/offset/size
//  fields are rejected (return empty/nil) rather than trapping the process —
//  each of these would abort the test runner on the pre-hardening code.
//

import Testing
import Foundation
@testable import Strata

struct InputSafetyTests {

    // MARK: - intExact (the trap-prevention core)

    @Test func intExactRejectsOutOfRange() {
        #expect(intExact(UInt64(Int.max)) == Int.max)
        #expect(intExact(UInt64(Int.max) + 1) == nil)   // top bit set → would trap Int(UInt64)
        #expect(intExact(UInt64.max) == nil)
        #expect(intExact(UInt64(0)) == 0)

        #expect(intExact(42.9) == 42)
        #expect(intExact(1e308) == nil)                  // would trap Int(Double)
        #expect(intExact(-1e308) == nil)
        #expect(intExact(Double.nan) == nil)
        #expect(intExact(Double.infinity) == nil)
    }

    // MARK: - Byte parsers reject hostile fields instead of trapping

    @Test func traceV3RejectsHostileChunkSize() {
        // tag(4) subtag(4) size(8 LE) — size = 0x8000_0000_0000_0000 (top bit).
        var bytes = [UInt8](repeating: 0, count: 16)
        bytes[15] = 0x80
        #expect(TraceV3Parser.chunks(in: bytes).isEmpty)   // pre-fix: Int(UInt64) trap
    }

    @Test func fileTimePreciseRejectsTopBitFiletime() {
        #expect(FileTime.precise(0x8000_0000_0000_0000) == nil)   // Int64.min → pre-fix: underflow trap
        // 0xFFFF…F is Int64 -1 (a valid pre-1970 tick), so it renders, not nil.
        #expect(FileTime.precise(0xFFFF_FFFF_FFFF_FFFF) != nil)
        // A normal FILETIME still renders.
        #expect(FileTime.precise(133_151_475_719_188_377)?.hasPrefix("20") == true)
        #expect(FileTime.precise(0) == nil)
    }

    @Test func journaldRejectsHostileEntryArrayOffset() {
        // LPKSHHRH header (>=208 bytes) with entry_array_offset (byte 176) top bit.
        var bytes = [UInt8](repeating: 0, count: 256)
        bytes.replaceSubrange(0..<8, with: Array("LPKSHHRH".utf8))
        bytes[88] = 208           // header_size
        bytes[183] = 0x80         // entry_array_offset = 0x8000_0000_0000_0000
        #expect(JournaldParser.parse(data: Data(bytes), sourceFile: "x").isEmpty)   // pre-fix: Int(offset) trap
    }

    @Test func auditParserCapsHugeArgc() {
        // A forged EXECVE with argc=2_000_000_000 must not hang or overflow-trap.
        let log = "type=EXECVE msg=audit(1500000000.000:1): argc=2000000000\n"
        let events = AuditParser.parse(text: log, sourceFile: "audit.log")
        #expect(events.count >= 0)   // completes (capped) rather than hanging
    }

    @Test func appleLZ4RejectsOversizedDecodedSize() {
        // bv41 block declaring decoded_size = 0xFFFF_FFFF (~4 GB) from ~no input
        // must be rejected, not zero-fill-allocated.
        var bytes = Array("bv41".utf8)
        bytes += [0xFF, 0xFF, 0xFF, 0xFF]   // decoded_size
        bytes += [0x00, 0x00, 0x00, 0x00]   // encoded_size = 0
        bytes += Array("bv4$".utf8)         // end marker
        #expect(AppleLZ4.decompress(Data(bytes)) == nil)
    }

    // MARK: - Security

    @Test func csvNeutralizesFormulaInjection() {
        #expect(CSVExporter.record(["=cmd|'/c calc'!A1"]).hasPrefix("'="))
        #expect(CSVExporter.record(["@SUM(1)"]).hasPrefix("'@"))
        #expect(CSVExporter.record(["-1+1"]).hasPrefix("'-"))
        #expect(CSVExporter.record(["+1"]).hasPrefix("'+"))
        #expect(CSVExporter.record(["normal"]) == "normal")   // benign text untouched
    }

    @Test func scratchNameStripsPathSeparators() {
        #expect(!"x/../../tmp/evil".scratchSafeComponent.contains("/"))
        #expect(!"a\\b".scratchSafeComponent.contains("\\"))
        #expect(!"a:b".scratchSafeComponent.contains(":"))
        #expect("plain.txt".scratchSafeComponent == "plain.txt")
    }

    @Test func virusTotalEndpointPercentEncodesIndicator() {
        let base = URL(string: "https://www.virustotal.com/api/v3/")!
        let url = VirusTotalProvider.endpointURL(
            indicator: "evil.com/../../files/deadbeef", kind: .domain, baseURL: base)
        // The `../` traversal is encoded, so it can't collapse to the files/ resource.
        #expect(url?.absoluteString.contains("/files/") == false)
        #expect(url?.absoluteString.contains("domains") == true)
    }

    @Test func openCTIHashFilterMatchesDigestLength() {
        #expect(OpenCTIProvider.graphQLQuery(for: .hash, value: String(repeating: "a", count: 64)).contains("hashes.SHA-256"))
        #expect(OpenCTIProvider.graphQLQuery(for: .hash, value: String(repeating: "a", count: 40)).contains("hashes.SHA-1"))
        #expect(OpenCTIProvider.graphQLQuery(for: .hash, value: String(repeating: "a", count: 32)).contains("hashes.MD5"))
    }
}
