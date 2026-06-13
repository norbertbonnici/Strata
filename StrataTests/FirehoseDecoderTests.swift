//
//  FirehoseDecoderTests.swift
//  StrataTests
//
//  Covers M4 of the unified-log decoder: firehose tracepoint decoding. Fixtures
//  are SYNTHETIC bytes built to the layout confirmed against the real macOS-12
//  image and Mandiant's macos-UnifiedLogs (firehose preamble: proc-id pair,
//  publicDataSize @16, base continuous time @24, tracepoints @32; each
//  tracepoint a 24-byte header + data_size bytes, 8-byte aligned;
//  continuousTime = base + ((deltaUpper<<32)|deltaLower)). No evidence bytes.
//

import Testing
import Foundation
@testable import Strata

struct FirehoseDecoderTests {

    private static func le<T: FixedWidthInteger>(_ v: T) -> [UInt8] {
        withUnsafeBytes(of: v.littleEndian) { Array($0) }
    }

    /// Build a 24-byte tracepoint header + data + 8-byte padding.
    private static func tracepoint(activity: UInt8, logType: UInt8, flags: UInt16,
                                   fmtLoc: UInt32, tid: UInt64,
                                   deltaLower: UInt32, deltaUpper: UInt16,
                                   data: [UInt8]) -> [UInt8] {
        var b: [UInt8] = [activity, logType]
        b += le(flags) + le(fmtLoc) + le(tid)
        b += le(deltaLower) + le(deltaUpper) + le(UInt16(data.count))
        b += data
        while b.count % 8 != 0 { b.append(0) }
        return b
    }

    /// Assemble a firehose chunk's *data* (proc pair, base time, tracepoints).
    private static func firehoseChunk(firstProc: UInt64, secondProc: UInt32,
                                      base: UInt64, tracepoints: [[UInt8]]) -> [UInt8] {
        let body = tracepoints.flatMap { $0 }
        // tracepoints occupy [32, 32+body); publicDataSize is measured from 16.
        let publicDataSize = UInt16(16 + body.count)
        var b: [UInt8] = []
        b += le(firstProc) + le(secondProc)          // @0, @8
        b += [0, 0, 0, 0]                            // ttl, collapsed, unknown @12..16
        b += le(publicDataSize)                      // @16
        b += le(UInt16(0x1000)) + le(UInt16(0)) + le(UInt16(0))  // @18,@20,@22
        b += le(base)                                // @24
        b += body                                    // @32
        return b
    }

    private static func catalogWith(first: UInt64, second: UInt32, pid: UInt32, euid: UInt32) -> TraceV3Catalog {
        let pi = CatalogProcessInfo(firstProcID: first, secondProcID: second, pid: pid,
                                    euid: euid, mainUUIDIndex: 0, dscUUIDIndex: 0,
                                    uuidEntries: [], subsystems: [])
        return TraceV3Catalog(uuids: [], processInfos: [pi], subchunks: [],
                              earliestFirehoseTimestamp: 0)
    }

    // MARK: - tests

    @Test func decodesTracepointsWithProcessAndTimes() {
        let tp0 = Self.tracepoint(activity: 0x04, logType: 0x00, flags: 0x0602,
                                  fmtLoc: 0xB6BE0, tid: 688, deltaLower: 1000, deltaUpper: 0,
                                  data: [1, 2, 3, 4, 5])              // dsize 5
        let tp1 = Self.tracepoint(activity: 0x04, logType: 0x10, flags: 0x0602,
                                  fmtLoc: 0xB4FB0, tid: 688, deltaLower: 2000, deltaUpper: 0,
                                  data: Array(repeating: 0xAB, count: 21))
        let chunk = Self.firehoseChunk(firstProc: 126, secondProc: 261, base: 11_780_770_648,
                                       tracepoints: [tp0, tp1])
        let cat = Self.catalogWith(first: 126, second: 261, pid: 126, euid: 501)

        let tps = FirehoseDecoder.tracepoints(chunkData: chunk, catalog: cat)
        #expect(tps.count == 2)
        #expect(tps[0].pid == 126 && tps[0].euid == 501)
        #expect(tps[0].activityType == 0x04 && tps[0].eventType == .log)
        #expect(tps[0].level == .default)
        #expect(tps[0].formatStringLocation == 0xB6BE0)
        #expect(tps[0].threadID == 688)
        #expect(tps[0].continuousTime == 11_780_770_648 + 1000)
        #expect(tps[0].data == [1, 2, 3, 4, 5])
        #expect(tps[1].level == .error)
        #expect(tps[1].continuousTime == 11_780_770_648 + 2000)
        #expect(tps[1].data.count == 21)
    }

    @Test func combinesUpperAndLowerDeltaBits() {
        // delta = (upper << 32) | lower
        let tp = Self.tracepoint(activity: 0x04, logType: 0x01, flags: 0,
                                 fmtLoc: 0, tid: 1, deltaLower: 0xE0B94A8D, deltaUpper: 1,
                                 data: [])
        let chunk = Self.firehoseChunk(firstProc: 1, secondProc: 2, base: 0, tracepoints: [tp])
        let tps = FirehoseDecoder.tracepoints(chunkData: chunk, catalog: nil)
        #expect(tps.count == 1)
        #expect(tps[0].continuousTime == (UInt64(1) << 32) | 0xE0B94A8D)  // 8_065_206_925
        #expect(tps[0].level == .info)
        #expect(tps[0].pid == 0)   // no catalog match
    }

    @Test func mapsActivityTypesAndLevels() {
        func one(_ act: UInt8, _ lt: UInt8) -> FirehoseTracepoint {
            let tp = Self.tracepoint(activity: act, logType: lt, flags: 0, fmtLoc: 0,
                                     tid: 0, deltaLower: 0, deltaUpper: 0, data: [])
            let chunk = Self.firehoseChunk(firstProc: 1, secondProc: 1, base: 0, tracepoints: [tp])
            return FirehoseDecoder.tracepoints(chunkData: chunk, catalog: nil)[0]
        }
        #expect(one(0x02, 0).eventType == .activity)
        #expect(one(0x03, 0).eventType == .trace)
        #expect(one(0x04, 0).eventType == .log)
        #expect(one(0x06, 0).eventType == .signpost)
        #expect(one(0x07, 0).eventType == .loss)
        #expect(one(0x04, 0x02).level == .debug)
        #expect(one(0x04, 0x11).level == .fault)
    }

    @Test func stopsAtZeroPaddingAndRegionEnd() {
        // One real tracepoint then trailing zero padding inside the region.
        var tp = Self.tracepoint(activity: 0x04, logType: 0, flags: 0, fmtLoc: 0,
                                 tid: 0, deltaLower: 0, deltaUpper: 0, data: [9, 9])
        tp += Array(repeating: 0, count: 24)   // zero run that must not parse as a TP
        let chunk = Self.firehoseChunk(firstProc: 1, secondProc: 1, base: 0, tracepoints: [tp])
        let tps = FirehoseDecoder.tracepoints(chunkData: chunk, catalog: nil)
        #expect(tps.count == 1)
        #expect(tps[0].data == [9, 9])
    }

    @Test func partialEntryProjectsTimestampAndFields() {
        let boot = TimesyncBoot(bootUUID: "B", timebaseNumerator: 1, timebaseDenominator: 1,
                                bootTimeNs: 0,
                                anchors: [.init(continuousTime: 0, wallTimeNs: 1_000_000_000)])
        let tp = FirehoseTracepoint(activityType: 0x04, logType: 0x10, flags: 0,
                                    formatStringLocation: 1, threadID: 2, continuousTime: 500,
                                    pid: 42, euid: 0, firstProcID: 1, secondProcID: 1, data: [])
        let e = tp.partialEntry(timesync: boot, sourceFile: "x.tracev3")
        #expect(e.pid == 42)
        #expect(e.eventType == .log)
        #expect(e.level == .error)
        #expect(e.message == "")          // unresolved until M5
        #expect(e.process == nil)
        #expect(e.timestamp == Date(timeIntervalSince1970: 1.0000005))  // 1e9ns + 500ns
        #expect(e.sourceFile == "x.tracev3")
    }

    @Test func tooSmallChunkYieldsNothing() {
        #expect(FirehoseDecoder.tracepoints(chunkData: [1, 2, 3], catalog: nil).isEmpty)
    }
}
