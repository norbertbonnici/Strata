//
//  UnifiedLogStringTests.swift
//  StrataTests
//
//  Covers M5a of the unified-log decoder: the .uuidtext + dsc format-string
//  catalogs and the flag-driven resolver. Fixtures are SYNTHETIC bytes built to
//  the layout confirmed against the real macOS-12 image (uuidtext magic
//  0x66778899: 16-byte header + (range_start,size) table + format-string blocks
//  then image path; dsc magic "hcsd"/0x64736368 v2: 16-byte header + 24-byte
//  ranges + 32-byte uuid entries + string/path data). No evidence bytes.
//

import Testing
import Foundation
@testable import Strata

struct UnifiedLogStringTests {

    private static func le<T: FixedWidthInteger>(_ v: T) -> [UInt8] {
        withUnsafeBytes(of: v.littleEndian) { Array($0) }
    }
    private static func cstr(_ s: String) -> [UInt8] { Array(s.utf8) + [0] }
    private static func padTo(_ b: inout [UInt8], _ n: Int) { while b.count < n { b.append(0) } }

    // MARK: - .uuidtext

    /// A 2-entry uuidtext: block0 covers [100,110) → "Hello %@", block1 covers
    /// [200,208) → "Bye %d", then the image path "/usr/bin/foo".
    private static func uuidTextBytes() -> [UInt8] {
        var b: [UInt8] = []
        b += le(UInt32(0x6677_8899))      // signature
        b += le(UInt32(2)) + le(UInt32(1)) // major.minor
        b += le(UInt32(2))                // entry count
        b += le(UInt32(100)) + le(UInt32(10))  // entry 0: rangeStart, size
        b += le(UInt32(200)) + le(UInt32(8))   // entry 1
        var block0 = cstr("Hello %@"); padTo(&block0, 10)   // 10 bytes
        var block1 = cstr("Bye %d");   padTo(&block1, 8)    // 8 bytes
        b += block0 + block1 + cstr("/usr/bin/foo")
        return b
    }

    @Test func parsesUUIDTextAndResolves() {
        let ut = UUIDTextParser.parse(Data(Self.uuidTextBytes()), uuid: "AABBCCDD-0000-0000-0000-000000000000")
        #expect(ut != nil)
        guard let ut else { return }
        #expect(ut.majorVersion == 2 && ut.minorVersion == 1)
        #expect(ut.entries.count == 2)
        #expect(ut.imagePath == "/usr/bin/foo")
        #expect(ut.processName == "foo")
        #expect(ut.formatString(at: 100) == "Hello %@")
        #expect(ut.formatString(at: 200) == "Bye %d")
        // An offset outside any range resolves to nil.
        #expect(ut.formatString(at: 50) == nil)
        #expect(ut.formatString(at: 1000) == nil)
    }

    @Test func uuidTextRejectsBadSignature() {
        var bytes = Self.uuidTextBytes(); bytes[0] = 0
        #expect(UUIDTextParser.parse(Data(bytes), uuid: "x") == nil)
    }

    // MARK: - dsc

    /// A v2 dsc with one range [1000,1020) → "Shared %@" and one uuid entry whose
    /// path is "/usr/lib/libfoo.dylib".
    private static func dscBytes() -> [UInt8] {
        let headerLen = 16, rangeLen = 24, uuidLen = 32
        let dataOffset = headerLen + rangeLen + uuidLen       // 72: format string
        let pathOffset = dataOffset + 10                      // 82: image path
        var b: [UInt8] = []
        b += le(UInt32(0x6473_6368))      // "hcsd" little-endian
        b += le(UInt16(2)) + le(UInt16(0)) // major.minor
        b += le(UInt32(1)) + le(UInt32(1)) // ranges, uuids
        // range: rangeOffset u64, dataOffset u32, rangeSize u32, uuidIndex u64
        b += le(UInt64(1000)) + le(UInt32(UInt32(dataOffset))) + le(UInt32(20)) + le(UInt64(0))
        // uuid entry: textOffset u64, textSize u32, uuid(16), pathOffset u32
        b += le(UInt64(0)) + le(UInt32(0)) + Array(repeating: 0xAB, count: 16) + le(UInt32(UInt32(pathOffset)))
        #expect(b.count == dataOffset)
        b += cstr("Shared %@")            // at dataOffset (10 bytes incl NUL)
        b += cstr("/usr/lib/libfoo.dylib")
        return b
    }

    @Test func parsesDscAndResolves() {
        let dsc = DscParser.parse(Data(Self.dscBytes()), uuid: "DSCUUID")
        #expect(dsc != nil)
        guard let dsc else { return }
        #expect(dsc.majorVersion == 2)
        #expect(dsc.ranges.count == 1)
        #expect(dsc.uuidEntries.count == 1)
        let r = dsc.resolve(offset: 1000)
        #expect(r?.formatString == "Shared %@")
        #expect(r?.imagePath == "/usr/lib/libfoo.dylib")
        // Mid-range offset reads from within the same block.
        #expect(dsc.resolve(offset: 1007)?.formatString == "%@")
        // Outside any range → nil.
        #expect(dsc.resolve(offset: 5) == nil)
        #expect(dsc.resolve(offset: 2000) == nil)
    }

    @Test func dscRejectsBadSignature() {
        var bytes = Self.dscBytes(); bytes[0] = 0
        #expect(DscParser.parse(Data(bytes), uuid: "x") == nil)
    }

    // MARK: - resolver dispatch

    @Test func resolverDispatchesByFlags() {
        let ut = UUIDTextParser.parse(Data(Self.uuidTextBytes()), uuid: "MAIN")!
        let dsc = DscParser.parse(Data(Self.dscBytes()), uuid: "DSC")!
        let cat = UnifiedLogStringCatalog(uuidTexts: ["MAIN": ut], dscs: ["DSC": dsc])

        // main_exe (0x02): format from the process's main uuidtext.
        let m = cat.resolve(flags: 0x0602, formatStringLocation: 100, mainUUID: "MAIN", dscUUID: "DSC")
        #expect(m.source == .mainExe)
        #expect(m.formatString == "Hello %@")
        #expect(m.process == "foo")

        // shared_cache (0x04): format from the dsc; library from the dsc path.
        let s = cat.resolve(flags: 0x0604, formatStringLocation: 1000, mainUUID: "MAIN", dscUUID: "DSC")
        #expect(s.source == .sharedCache)
        #expect(s.formatString == "Shared %@")
        #expect(s.process == "foo")           // still the emitting process
        #expect(s.library == "libfoo.dylib")  // the owning library

        // other (0x0c): no format yet, but the process name is still known.
        let o = cat.resolve(flags: 0x060c, formatStringLocation: 1, mainUUID: "MAIN", dscUUID: "DSC")
        #expect(o.source == .other)
        #expect(o.formatString == nil)
        #expect(o.process == "foo")
    }

    @Test func resolverHandlesMissingCatalogs() {
        let empty = UnifiedLogStringCatalog()
        let r = empty.resolve(flags: 0x0602, formatStringLocation: 100, mainUUID: "MAIN", dscUUID: "DSC")
        #expect(r.formatString == nil)
        #expect(r.process == nil)
        #expect(r.source == .mainExe)
    }
}
