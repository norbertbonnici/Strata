//
//  JournaldTests.swift
//  StrataTests
//
//  Validates the pure-Swift journald binary parser against journals built
//  byte-by-byte to the documented systemd format - legacy + COMPACT layouts and
//  LZ4-compressed data - plus the auth analyzer over journal messages.
//

import Testing
import Foundation
import Compression
@testable import Strata

/// Builds a minimal but format-correct `.journal` file in memory.
private struct JournalBuilder {
    var bytes: [UInt8]
    let compact: Bool
    private let headerSize = 256

    init(compact: Bool) {
        self.compact = compact
        bytes = [UInt8](repeating: 0, count: headerSize)   // reserve header
    }

    private mutating func align8() {
        while bytes.count % 8 != 0 { bytes.append(0) }
    }
    private mutating func putU32(_ v: UInt32, at o: Int) {
        for i in 0..<4 { bytes[o + i] = UInt8((v >> (8 * i)) & 0xFF) }
    }
    private mutating func putU64(_ v: UInt64, at o: Int) {
        for i in 0..<8 { bytes[o + i] = UInt8((v >> (8 * UInt64(i))) & 0xFF) }
    }
    private mutating func appendU32(_ v: UInt32) { for i in 0..<4 { bytes.append(UInt8((v >> (8 * i)) & 0xFF)) } }
    private mutating func appendU64(_ v: UInt64) { for i in 0..<8 { bytes.append(UInt8((v >> (8 * UInt64(i))) & 0xFF)) } }

    /// Append a DATA object holding `field` ("KEY=value"); returns its offset.
    mutating func addData(_ field: String, lz4: Bool = false) -> UInt64 {
        align8()
        let offset = UInt64(bytes.count)
        var payload = [UInt8](field.utf8)
        var flags: UInt8 = 0
        if lz4 {
            let src = [UInt8](field.utf8)
            var dst = [UInt8](repeating: 0, count: src.count * 2 + 64)
            let n = compression_encode_buffer(&dst, dst.count, src, src.count, nil, COMPRESSION_LZ4_RAW)
            var blob = [UInt8]()
            for i in 0..<8 { blob.append(UInt8((UInt64(src.count) >> (8 * UInt64(i))) & 0xFF)) }
            blob.append(contentsOf: dst[0..<n])
            payload = blob
            flags = 1 << 1   // OBJECT_COMPRESSED_LZ4
        }
        let dataHeaderLen = 16 + 48 + (compact ? 8 : 0)
        let size = UInt64(dataHeaderLen + payload.count)
        bytes.append(1)            // type = DATA
        bytes.append(flags)
        bytes.append(contentsOf: [0,0,0,0,0,0])   // reserved[6]
        appendU64(size)
        appendU64(0x1234)          // hash
        appendU64(0); appendU64(0); appendU64(0); appendU64(0); appendU64(0)  // next/next/entry/array/n
        if compact { appendU32(0); appendU32(0) }   // tail_entry_array_offset + n
        bytes.append(contentsOf: payload)
        return offset
    }

    /// Append an ENTRY object; returns its offset.
    mutating func addEntry(realtime: UInt64, dataOffsets: [UInt64]) -> UInt64 {
        align8()
        let offset = UInt64(bytes.count)
        let itemSize = compact ? 4 : 16
        let size = UInt64(64 + dataOffsets.count * itemSize)
        bytes.append(3)            // type = ENTRY
        bytes.append(0)
        bytes.append(contentsOf: [0,0,0,0,0,0])
        appendU64(size)
        appendU64(7)               // seqnum
        appendU64(realtime)        // realtime µs
        appendU64(0)               // monotonic
        for _ in 0..<16 { bytes.append(0xAB) }   // boot_id
        appendU64(0)               // xor_hash
        for d in dataOffsets {
            if compact { appendU32(UInt32(d)) }
            else { appendU64(d); appendU64(0) }   // object_offset + hash
        }
        return offset
    }

    /// Append an ENTRY_ARRAY; returns its offset.
    mutating func addEntryArray(entryOffsets: [UInt64]) -> UInt64 {
        align8()
        let offset = UInt64(bytes.count)
        let itemSize = compact ? 4 : 8
        let size = UInt64(24 + entryOffsets.count * itemSize)
        bytes.append(6)            // type = ENTRY_ARRAY
        bytes.append(0)
        bytes.append(contentsOf: [0,0,0,0,0,0])
        appendU64(size)
        appendU64(0)               // next_entry_array_offset
        for e in entryOffsets {
            if compact { appendU32(UInt32(e)) } else { appendU64(e) }
        }
        return offset
    }

    /// Finalize: write the header fields and return the bytes.
    mutating func finish(entryArrayOffset: UInt64) -> Data {
        for (i, b) in Array("LPKSHHRH".utf8).enumerated() { bytes[i] = b }
        putU32(compact ? (1 << 4) : 0, at: 12)   // incompatible_flags (COMPACT)
        putU64(UInt64(headerSize), at: 88)        // header_size
        putU64(entryArrayOffset, at: 176)         // entry_array_offset
        return Data(bytes)
    }
}

struct JournaldParserTests {

    /// Realtime in µs for 2026-06-10T12:00:00Z.
    private static let t0: UInt64 = 1_781_352_000_000_000

    private func buildTwoEntry(compact: Bool, lz4Message: Bool = false) -> Data {
        var b = JournalBuilder(compact: compact)
        let m1 = b.addData("MESSAGE=Accepted password for jane from 10.0.0.5 port 22 ssh2", lz4: lz4Message)
        let c1 = b.addData("_COMM=sshd")
        let s1 = b.addData("SYSLOG_IDENTIFIER=sshd")
        let p1 = b.addData("PRIORITY=6")
        let pid1 = b.addData("_PID=1234")
        let h1 = b.addData("_HOSTNAME=web01")
        let e1 = b.addEntry(realtime: Self.t0, dataOffsets: [m1, c1, s1, p1, pid1, h1])

        let m2 = b.addData("MESSAGE=Failed password for root from 203.0.113.9 port 40000 ssh2")
        let s2 = b.addData("SYSLOG_IDENTIFIER=sshd")
        let p2 = b.addData("PRIORITY=5")
        let e2 = b.addEntry(realtime: Self.t0 + 60_000_000, dataOffsets: [m2, s2, p2])

        let arr = b.addEntryArray(entryOffsets: [e1, e2])
        return b.finish(entryArrayOffset: arr)
    }

    @Test func parsesLegacyLayout() {
        let entries = JournaldParser.parse(data: buildTwoEntry(compact: false),
                                           sourceFile: "/var/log/journal/x/system.journal")
        #expect(entries.count == 2)
        let first = entries[0]
        #expect(first.message.hasPrefix("Accepted password for jane"))
        #expect(first.program == "sshd")
        #expect(first.priority == 6)
        #expect(first.pid == 1234)
        #expect(first.hostname == "web01")
        #expect(first.timestamp == Date(timeIntervalSince1970: 1_781_352_000))
        #expect(entries[1].message.contains("Failed password for root"))
    }

    @Test func parsesCompactLayout() {
        let entries = JournaldParser.parse(data: buildTwoEntry(compact: true),
                                           sourceFile: "/var/log/journal/x/system.journal")
        #expect(entries.count == 2)
        #expect(entries[0].program == "sshd")
        #expect(entries[0].message.hasPrefix("Accepted password"))
        #expect(entries[0].timestamp == Date(timeIntervalSince1970: 1_781_352_000))
    }

    @Test func decompressesLZ4Message() {
        let entries = JournaldParser.parse(data: buildTwoEntry(compact: false, lz4Message: true),
                                           sourceFile: "/x")
        #expect(entries.count == 2)
        // The first message was stored LZ4-compressed; it must round-trip.
        #expect(entries[0].message.hasPrefix("Accepted password for jane"))
    }

    @Test func rejectsNonJournalAndEmpty() {
        #expect(JournaldParser.parse(data: Data("not a journal".utf8), sourceFile: "/x").isEmpty)
        #expect(JournaldParser.parse(data: Data(), sourceFile: "/x").isEmpty)
    }

    @Test func toleratesTruncation() {
        var data = buildTwoEntry(compact: false)
        data = data.prefix(data.count - 20)   // chop the tail mid-object
        // Must not crash; returns whatever parsed before the truncation.
        let entries = JournaldParser.parse(data: data, sourceFile: "/x")
        #expect(entries.count <= 2)
    }
}

struct JournaldAnalyzerTests {

    private func entry(_ prog: String, _ message: String, t: TimeInterval = 1000) -> JournaldEntry {
        JournaldEntry(timestamp: Date(timeIntervalSince1970: t), message: message,
                      identifier: prog, sourceFile: "/var/log/journal/x/system.journal")
    }

    private func analyze(_ entries: [JournaldEntry]) -> [Finding] {
        JournaldAnalyzer().analyze(context: AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [], journald: entries))
    }

    @Test func detectsBruteForceInJournal() {
        let entries = (0..<12).map {
            entry("sshd", "Failed password for user\($0) from 203.0.113.9 port 2222 ssh2")
        }
        let f = analyze(entries)
        #expect(f.contains { $0.title.contains("brute force from 203.0.113.9") && $0.severity == .high })
    }

    @Test func escalatesOnAcceptedAfterFailures() {
        var entries = (0..<10).map {
            entry("sshd", "Failed password for root from 203.0.113.9 port 2222 ssh2", t: Double($0))
        }
        entries.append(entry("sshd", "Accepted password for root from 203.0.113.9 port 2222 ssh2", t: 100))
        let f = analyze(entries)
        #expect(f.contains { $0.severity == .critical && $0.title.contains("SUCCEEDED") })
        #expect(f.contains { $0.title.contains("root SSH login") })
    }

    @Test func detectsSudoFailures() {
        let entries = (0..<6).map { _ in
            entry("sudo", "pam_unix(sudo:auth): authentication failure; logname=eve uid=1001")
        }
        let f = analyze(entries)
        #expect(f.contains { $0.title.contains("sudo authentication failures") })
    }

    @Test func quietJournalYieldsNothing() {
        let f = analyze([entry("systemd", "Started Session 1 of user jane."),
                         entry("sshd", "Accepted password for jane from 10.0.0.5 port 22 ssh2")])
        #expect(f.isEmpty)
    }
}
