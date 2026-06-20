//
//  TraceV3CatalogTests.swift
//  StrataTests
//
//  Covers M3 of the unified-log decoder: the .tracev3 header (0x1000) and
//  catalog (0x600B) chunks. Fixtures are SYNTHETIC bytes built to the layout
//  confirmed against the real macOS-12 image (header sub-records 0x6100-0x6103;
//  catalog: 24-byte header, 16-byte UUIDs, NUL-string pool, variable
//  process-info entries with 16-byte uuid sub-entries + 6-byte subsystem
//  entries, 8-byte aligned). No evidence bytes are committed.
//

import Testing
import Foundation
@testable import Strata

private func le<T: FixedWidthInteger>(_ v: T) -> [UInt8] {
    withUnsafeBytes(of: v.littleEndian) { Array($0) }
}
private func pad8(_ b: inout [UInt8]) {
    while b.count % 8 != 0 { b.append(0) }
}

struct TraceV3CatalogTests {

    private static let uuidA: [UInt8] = Array(0..<16).map { UInt8($0) }
    private static let uuidB: [UInt8] = Array(0..<16).map { UInt8(0xF0 &+ UInt8($0)) }

    // MARK: - header

    @Test func parsesHeaderWithSubRecords() {
        var sub: [UInt8] = []
        // 0x6100 continuous-time (8 bytes)
        sub += le(UInt32(0x6100)) + le(UInt32(8)) + le(UInt64(0x0000_0001_9FDA_0E17))
        // 0x6101 system info: u32,u32 then "21H1320\0" + "MacBookAir7,2\0"
        var info: [UInt8] = le(UInt32(7)) + le(UInt32(8))
        info += Array("21H1320".utf8) + [0] + Array("MacBookAir7,2".utf8) + [0]
        pad8(&info)
        sub += le(UInt32(0x6101)) + le(UInt32(UInt32(info.count))) + info
        // 0x6102 generation: 16-byte boot UUID + u64
        sub += le(UInt32(0x6102)) + le(UInt32(24)) + Self.uuidA + le(UInt64(78))
        // 0x6103 timezone path
        var tz = Array("/var/db/timezone/zoneinfo/Europe/Tallinn".utf8) + [0]
        pad8(&tz)
        sub += le(UInt32(0x6103)) + le(UInt32(UInt32(tz.count))) + tz

        var d: [UInt8] = []
        d += le(UInt32(1)) + le(UInt32(1))               // timebase 1/1
        d += le(UInt64(0x0000_0001_9FDA_0E17))           // continuous time
        d += le(UInt64(1_742_845_609))                   // start walltime seconds
        d += le(UInt32(0))                               // unknown @0x18
        d += le(Int32(-120))                             // tz bias @0x1C
        d += le(UInt32(0)) + le(UInt32(3))               // @0x20, @0x24
        d += sub                                         // sub-records @0x28

        // Wrap in a header chunk preamble so header(of:) finds it too.
        var file = le(TraceV3Parser.tagHeader) + le(UInt32(0x11)) + le(UInt64(UInt64(d.count))) + d
        pad8(&file)

        let h = TraceV3Parser.header(of: Data(file))
        #expect(h != nil)
        #expect(h?.bootUUID == "00010203-0405-0607-0809-0A0B0C0D0E0F")
        #expect(h?.timebaseNumerator == 1 && h?.timebaseDenominator == 1)
        #expect(h?.continuousTime == 0x0000_0001_9FDA_0E17)
        #expect(h?.startWalltimeSeconds == 1_742_845_609)
        #expect(h?.timezoneBiasMinutes == -120)
        #expect(h?.osBuild == "21H1320")
        #expect(h?.hardwareModel == "MacBookAir7,2")
        #expect(h?.timezonePath == "/var/db/timezone/zoneinfo/Europe/Tallinn")
    }

    @Test func headerRejectsNonHeaderFirstChunk() {
        let file = le(TraceV3Parser.tagCatalog) + le(UInt32(0)) + le(UInt64(0))
        #expect(TraceV3Parser.header(of: Data(file)) == nil)
    }

    // MARK: - catalog

    /// Build one process-info entry. `uuidEntries` = [(size, uuidIndex)];
    /// `subsystems` = [(identifier, subsystemOffset, categoryOffset)].
    private static func procInfo(index: UInt16, main: UInt16, dsc: UInt16,
                                 first: UInt64, second: UInt32, pid: UInt32, euid: UInt32,
                                 uuidEntries: [(UInt32, UInt16)],
                                 subsystems: [(UInt16, UInt16, UInt16)]) -> [UInt8] {
        var b: [UInt8] = []
        b += le(index) + le(UInt16(0)) + le(main) + le(dsc)   // 0x00..0x08
        b += le(first) + le(second) + le(pid) + le(euid)       // 0x08..0x1C
        b += le(UInt32(0))                                     // unknown2 @0x1C
        b += le(UInt32(UInt32(uuidEntries.count)))             // nUUID @0x20
        b += le(UInt32(0))                                     // unknown3 @0x24
        for (size, idx) in uuidEntries {                       // 16 bytes each
            b += le(size) + le(UInt32(0)) + le(idx) + le(UInt16(0)) + le(UInt32(0))
        }
        b += le(UInt32(UInt32(subsystems.count)))              // nSubsystems
        b += le(UInt32(0))                                     // unknown4
        for (id, so, co) in subsystems { b += le(id) + le(so) + le(co) }  // 6 bytes each
        pad8(&b)
        return b
    }

    @Test func parsesCatalogWithUUIDsSubsystemsAndSubchunks() {
        // Subsystem string pool: "com.apple.test\0Default\0Misc\0"
        let s0 = "com.apple.test", s1 = "Default", s2 = "Misc"
        var pool: [UInt8] = []
        let offTest = pool.count; pool += Array(s0.utf8) + [0]
        let offDefault = pool.count; pool += Array(s1.utf8) + [0]
        let offMisc = pool.count; pool += Array(s2.utf8) + [0]
        pad8(&pool)

        let uuidArray = Self.uuidA + Self.uuidB        // 2 UUIDs
        let subStrOff = uuidArray.count                // offsets relative to end of 24B header

        // Two process-info entries: one with a uuid sub-entry, one without.
        let pi0 = Self.procInfo(index: 1, main: 1, dsc: 0, first: 378, second: 881,
                                pid: 378, euid: 501,
                                uuidEntries: [(0xC000, 1)],
                                subsystems: [(1, UInt16(offTest), UInt16(offMisc)),
                                             (2, UInt16(offTest), UInt16(offDefault))])
        let pi1 = Self.procInfo(index: 2, main: 0, dsc: 0, first: 100, second: 200,
                                pid: 100, euid: 0,
                                uuidEntries: [],
                                subsystems: [(5, UInt16(offTest), UInt16(offDefault))])
        let piBlock = pi0 + pi1
        let piOff = subStrOff + pool.count

        // Two subchunks (24-byte prefix + empty index/offset tails).
        func subchunk(_ start: UInt64, _ end: UInt64, _ uncomp: UInt32) -> [UInt8] {
            var b = le(start) + le(end) + le(uncomp) + le(UInt32(0x100))
            b += le(UInt16(0)) + le(UInt16(0))   // nIndexes=0, nOffsets=0
            pad8(&b)
            return b
        }
        let scBlock = subchunk(1000, 2000, 63624) + subchunk(2000, 3000, 4096)
        let scOff = piOff + piBlock.count

        var c: [UInt8] = []
        c += le(UInt16(subStrOff)) + le(UInt16(piOff))
        c += le(UInt16(2)) + le(UInt16(scOff)) + le(UInt16(2))  // nPI=2, nSC=2
        c += [0, 0, 0, 0, 0, 0]                                                // reserved
        c += le(UInt64(0x19FDA0E17))                                      // earliest ts
        c += uuidArray + pool + piBlock + scBlock

        let cat = TraceV3Parser.catalog(fromData: c)
        #expect(cat != nil)
        guard let cat else { return }
        #expect(cat.uuids.count == 2)
        #expect(cat.uuids[0] == "00010203-0405-0607-0809-0A0B0C0D0E0F")
        #expect(cat.earliestFirehoseTimestamp == 0x19FDA0E17)
        #expect(cat.processInfos.count == 2)

        let p0 = cat.processInfo(first: 378, second: 881)
        #expect(p0?.pid == 378)
        #expect(p0?.euid == 501)
        #expect(p0?.mainUUIDIndex == 1)
        #expect(p0?.uuidEntries.count == 1)
        #expect(p0?.uuidEntries.first?.size == 0xC000)
        #expect(p0?.uuidEntries.first?.uuidIndex == 1)
        #expect(p0?.subsystem(for: 1)?.subsystem == "com.apple.test")
        #expect(p0?.subsystem(for: 1)?.category == "Misc")
        #expect(p0?.subsystem(for: 2)?.category == "Default")

        // Second entry (no uuid entries) must still be located — proves the
        // variable-length walk reached it correctly.
        let p1 = cat.processInfo(first: 100, second: 200)
        #expect(p1?.pid == 100)
        #expect(p1?.subsystems.count == 1)
        #expect(p1?.subsystem(for: 5)?.subsystem == "com.apple.test")

        #expect(cat.subchunks.count == 2)
        #expect(cat.subchunks[0].startContinuousTime == 1000)
        #expect(cat.subchunks[0].endContinuousTime == 2000)
        #expect(cat.subchunks[0].uncompressedSize == 63624)
        #expect(cat.subchunks[0].compressionAlgorithm == 0x100)
        #expect(cat.subchunks[1].startContinuousTime == 2000)
    }

    @Test func catalogTooSmallReturnsNil() {
        #expect(TraceV3Parser.catalog(fromData: [0, 1, 2, 3]) == nil)
    }
}
