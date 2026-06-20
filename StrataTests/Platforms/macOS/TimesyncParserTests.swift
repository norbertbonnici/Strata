//
//  TimesyncParserTests.swift
//  StrataTests
//
//  Covers the unified-log timesync parser (continuous-time -> wall-clock
//  anchors). Fixtures are SYNTHETIC bytes built to the format confirmed against a
//  real macOS-12 .timesync file (boot record 0xBBB0 / 48B, sync record "Ts " /
//  32B) — no evidence content is committed.
//

import Testing
import Foundation
@testable import Strata

struct TimesyncParserTests {

    // MARK: - synthetic byte builders

    private static func le<T: FixedWidthInteger>(_ v: T) -> [UInt8] {
        withUnsafeBytes(of: v.littleEndian) { Array($0) }
    }

    /// 48-byte boot record. `uuid16` must be 16 bytes.
    private static func bootRecord(uuid16: [UInt8], num: UInt32, den: UInt32,
                                   bootNs: UInt64) -> [UInt8] {
        var b: [UInt8] = []
        b += le(UInt16(0xBBB0))          // 0x00 signature
        b += le(UInt16(0x0030))          // 0x02 header size
        b += le(UInt32(0))               // 0x04 padding
        b += uuid16                      // 0x08 boot UUID
        b += le(num)                     // 0x18 timebase numerator
        b += le(den)                     // 0x1C timebase denominator
        b += le(bootNs)                  // 0x20 boot walltime ns
        b += le(UInt32(0))               // 0x28 tz
        b += le(UInt32(0))               // 0x2C dst
        #expect(b.count == 48)
        return b
    }

    /// 32-byte sync record.
    private static func syncRecord(continuousTime ct: UInt64, wallNs: UInt64) -> [UInt8] {
        var b: [UInt8] = []
        b += le(UInt32(0x0020_7354))     // 0x00 "Ts "
        b += le(UInt32(0))               // 0x04 flags
        b += le(ct)                      // 0x08 continuous time
        b += le(wallNs)                  // 0x10 walltime ns
        b += le(UInt32(0))               // 0x18 tz
        b += le(UInt32(0))               // 0x1C dst
        #expect(b.count == 32)
        return b
    }

    private static let uuidA: [UInt8] = [0x08,0x98,0x9B,0x84,0x4C,0x07,0x41,0x42,
                                         0xB7,0xF6,0x86,0x35,0x86,0x80,0xB4,0x33]
    private static let uuidAStr = "08989B84-4C07-4142-B7F6-86358680B433"

    // MARK: - tests

    @Test func parsesSingleBootWithAnchors() {
        var data: [UInt8] = []
        data += Self.bootRecord(uuid16: Self.uuidA, num: 1, den: 1, bootNs: 1_000_000_000)
        data += Self.syncRecord(continuousTime: 100, wallNs: 1_000_000_100)
        data += Self.syncRecord(continuousTime: 200, wallNs: 1_000_000_205)  // +5ns clock drift

        let boots = TimesyncParser.parse(Data(data))
        #expect(boots.count == 1)
        let b = boots[0]
        #expect(b.bootUUID == Self.uuidAStr)
        #expect(b.timebaseNumerator == 1 && b.timebaseDenominator == 1)
        #expect(b.bootTimeNs == 1_000_000_000)
        // implicit boot anchor (ct 0) + two sync anchors
        #expect(b.anchors.count == 3)
        #expect(b.anchors.first?.continuousTime == 0)
    }

    @Test func convertsContinuousTimeUsingNearestAnchor() {
        var data: [UInt8] = []
        data += Self.bootRecord(uuid16: Self.uuidA, num: 1, den: 1, bootNs: 1_000_000_000)
        data += Self.syncRecord(continuousTime: 100, wallNs: 1_000_000_100)
        data += Self.syncRecord(continuousTime: 200, wallNs: 1_000_000_205)
        let b = TimesyncParser.parse(Data(data))[0]
        // ns-exact math, compared with a sub-microsecond tolerance (Date stores
        // seconds as a Double, so 1e9-ns values aren't bit-exact as Doubles).
        func near(_ ct: UInt64, _ wantNs: Double) -> Bool {
            abs(b.walltime(forContinuousTime: ct).timeIntervalSince1970 - wantNs / 1e9) < 1e-6
        }
        // Each anchor's ct converts back to its own wall (1/1 timebase).
        #expect(near(100, 1_000_000_100))
        #expect(near(200, 1_000_000_205))
        // ct between anchors 100 and 200: base is the 100-anchor -> 1_000_000_100 + 50.
        #expect(near(150, 1_000_000_150))
        // ct before the first sync uses the implicit boot anchor (ct0 -> bootNs).
        #expect(near(50, 1_000_000_050))
    }

    @Test func appliesMachTimebaseScaling() {
        // Apple-Silicon-style 125/3 timebase: 24 ticks -> 1000 ns.
        var data: [UInt8] = []
        data += Self.bootRecord(uuid16: Self.uuidA, num: 125, den: 3, bootNs: 2_000_000_000)
        let b = TimesyncParser.parse(Data(data))[0]
        // delta from boot anchor: 24 * 125 / 3 = 1000 ns.
        let got = b.walltime(forContinuousTime: 24).timeIntervalSince1970
        #expect(abs(got - 2.000001) < 1e-6)
    }

    @Test func parsesMultipleBootRecordsInOneFile() {
        let uuidB: [UInt8] = Array(repeating: 0xCD, count: 16)
        var data: [UInt8] = []
        data += Self.bootRecord(uuid16: Self.uuidA, num: 1, den: 1, bootNs: 1_000_000_000)
        data += Self.syncRecord(continuousTime: 100, wallNs: 1_000_000_100)
        data += Self.bootRecord(uuid16: uuidB, num: 1, den: 1, bootNs: 5_000_000_000)
        data += Self.syncRecord(continuousTime: 300, wallNs: 5_000_000_300)

        let boots = TimesyncParser.parse(Data(data))
        #expect(boots.count == 2)
        #expect(boots[0].bootUUID == Self.uuidAStr)
        #expect(boots[0].anchors.count == 2)        // boot + 1 sync
        #expect(boots[1].bootTimeNs == 5_000_000_000)
        #expect(boots[1].anchors.count == 2)
    }

    @Test func parseAllKeysByBootUUID() {
        let f1 = Data(Self.bootRecord(uuid16: Self.uuidA, num: 1, den: 1, bootNs: 1))
        let uuidB: [UInt8] = Array(repeating: 0xAB, count: 16)
        let f2 = Data(Self.bootRecord(uuid16: uuidB, num: 1, den: 1, bootNs: 2))
        let map = TimesyncParser.parseAll([f1, f2])
        #expect(map.count == 2)
        #expect(map[Self.uuidAStr]?.bootTimeNs == 1)
    }

    @Test func emptyAndGarbageDataYieldNoBoots() {
        #expect(TimesyncParser.parse(Data()).isEmpty)
        #expect(TimesyncParser.parse(Data([0, 1, 2, 3, 4, 5, 6, 7])).isEmpty)
    }
}
