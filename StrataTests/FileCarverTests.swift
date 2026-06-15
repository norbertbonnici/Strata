//
//  FileCarverTests.swift
//  StrataTests
//
//  Covers the pure-Swift signature carver: exact sizing for SQLite/PNG/JPEG/
//  PDF/ZIP, capped/inexact carves for bplist/gzip, false-positive resistance,
//  multi-signature buffers, and the memory-mapped file path.
//

import Testing
import Foundation
@testable import Strata

struct FileCarverTests {

    // MARK: - Fixture builders

    /// A valid-enough SQLite file: 100-byte header (magic + page size + page
    /// count) padded to `pageSize * pageCount`.
    private func sqliteDB(pageSize: Int, pageCount: Int) -> Data {
        var header = [UInt8](repeating: 0, count: 100)
        let magic = Array("SQLite format 3\u{0}".utf8)
        for k in 0..<magic.count { header[k] = magic[k] }
        let raw = pageSize == 65536 ? 1 : pageSize
        header[16] = UInt8((raw >> 8) & 0xFF); header[17] = UInt8(raw & 0xFF)
        header[28] = UInt8((pageCount >> 24) & 0xFF); header[29] = UInt8((pageCount >> 16) & 0xFF)
        header[30] = UInt8((pageCount >> 8) & 0xFF); header[31] = UInt8(pageCount & 0xFF)
        var d = Data(header)
        d.append(Data(repeating: 0x00, count: pageSize * pageCount - 100))
        return d
    }

    private let jpeg = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0xFF, 0xD9])
    private let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                            0x00, 0x00, 0x00, 0x00,                         // filler chunk
                            0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]) // IEND + CRC
    private let pdf = Data(Array("%PDF-1.4\n%%EOF".utf8))
    private let zip = Data([0x50, 0x4B, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44,    // local header
                            0x50, 0x4B, 0x05, 0x06] + [UInt8](repeating: 0, count: 18)) // EOCD, 0 comment
    private let pad = Data(repeating: 0x41, count: 64)                          // 'A' — no triggers

    // MARK: - Exact sizing

    @Test func carvesSQLiteWithExactSize() {
        let db = sqliteDB(pageSize: 4096, pageCount: 2)
        let buf = pad + db + pad
        let out = FileCarver.carve(buf)
        #expect(out.count == 1)
        #expect(out[0].kind == .sqlite)
        #expect(out[0].offset == 64)
        #expect(out[0].size == 8192)
        #expect(out[0].sizeExact)
    }

    @Test func carvesSQLite64KPageSize() {
        let db = sqliteDB(pageSize: 65536, pageCount: 1)     // raw page-size field == 1
        let out = FileCarver.carve(db)
        #expect(out.first?.size == 65536)
        #expect(out.first?.sizeExact == true)
    }

    @Test func carvesJPEGToFooter() {
        let out = FileCarver.carve(pad + jpeg + pad)
        #expect(out.count == 1)
        #expect(out[0].kind == .jpeg)
        #expect(out[0].offset == 64)
        #expect(out[0].size == 10)
        #expect(out[0].sizeExact)
    }

    @Test func carvesPNGToIEND() {
        let out = FileCarver.carve(pad + png)
        #expect(out.count == 1)
        #expect(out[0].kind == .png)
        #expect(out[0].size == 20)
        #expect(out[0].sizeExact)
    }

    @Test func carvesPDFToLastEOF() {
        let out = FileCarver.carve(pad + pdf + pad)
        #expect(out.count == 1)
        #expect(out[0].kind == .pdf)
        #expect(out[0].size == 14)
        #expect(out[0].sizeExact)
    }

    @Test func carvesZIPToEOCD() {
        let out = FileCarver.carve(pad + zip)
        #expect(out.count == 1)
        #expect(out[0].kind == .zip)
        #expect(out[0].size == 30)
        #expect(out[0].sizeExact)
    }

    // MARK: - Inexact / capped

    @Test func bplistIsCappedInexact() {
        let buf = Data(Array("bplist00".utf8)) + Data(repeating: 0x00, count: 100)
        let out = FileCarver.carve(buf)
        #expect(out.count == 1)
        #expect(out[0].kind == .bplist)
        #expect(out[0].sizeExact == false)
        #expect(out[0].size == 108)                          // capped to remaining bytes
    }

    @Test func gzipIsCappedInexact() {
        let buf = Data([0x1F, 0x8B, 0x08, 0x00]) + Data(repeating: 0xCD, count: 200)
        let out = FileCarver.carve(buf)
        #expect(out.first?.kind == .gzip)
        #expect(out.first?.sizeExact == false)
    }

    @Test func jpegWithoutFooterIsInexact() {
        let buf = Data([0xFF, 0xD8, 0xFF, 0xE0]) + Data(repeating: 0x7A, count: 500)
        let out = FileCarver.carve(buf)
        #expect(out.first?.kind == .jpeg)
        #expect(out.first?.sizeExact == false)
    }

    // MARK: - False-positive resistance + multiple signatures

    @Test func noFalsePositivesOnPlainData() {
        #expect(FileCarver.carve(Data(repeating: 0x41, count: 4096)).isEmpty)
        #expect(FileCarver.carve(Data(repeating: 0x00, count: 4096)).isEmpty)
    }

    @Test func partialMagicIsNotCarved() {
        // "SQLite" without the full 16-byte signature must not match.
        let out = FileCarver.carve(Data(Array("SQLite fmt".utf8)) + Data(repeating: 0, count: 64))
        #expect(out.isEmpty)
    }

    @Test func carvesMultipleSignaturesInOrder() {
        let db = sqliteDB(pageSize: 1024, pageCount: 1)
        let buf = db + pad + jpeg + pad + png
        let out = FileCarver.carve(buf)
        #expect(out.count == 3)
        #expect(out.map(\.kind) == [.sqlite, .jpeg, .png])
        #expect(out[0].offset == 0)
        #expect(out[1].offset == Int64(1024 + 64))
        #expect(out[2].offset == Int64(1024 + 64 + 10 + 64))
    }

    @Test func baseOffsetIsApplied() {
        let out = FileCarver.carve(jpeg, baseOffset: 0x1_0000)
        #expect(out.first?.offset == 0x1_0000)
    }

    // MARK: - File path

    @Test func carveFileMapsAndScans() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("carver-\(UUID().uuidString).bin")
        defer { try? FileManager.default.removeItem(at: url) }
        try (pad + png + pad + pdf).write(to: url)
        let out = try FileCarver.carveFile(at: url)
        #expect(out.map(\.kind) == [.png, .pdf])
        #expect(out.allSatisfy { $0.source == url.lastPathComponent })
    }
}
