//
//  TraceV3ParserTests.swift
//  StrataTests
//
//  Phase 1 of the unified-log decoder: the .tracev3 container framing + the
//  Apple-LZ4 (bv4x) chunkset decompression. Synthetic .tracev3 bytes are built
//  in-test (no real corpus bundled). Firehose-entry decoding + uuidtext/dsc
//  message resolution are later phases.
//

import Testing
import Foundation
import Compression
@testable import Strata

struct AppleLZ4Tests {
    private func leU32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> ($0 * 8)) & 0xff) } }

    /// Raw-LZ4 encode via the Compression framework (the inverse of the decoder).
    private func lz4Raw(_ src: [UInt8]) -> [UInt8] {
        let cap = src.count + 512
        var dst = [UInt8](repeating: 0, count: cap)
        let n = src.withUnsafeBufferPointer { s in
            dst.withUnsafeMutableBufferPointer { d in
                compression_encode_buffer(d.baseAddress!, cap, s.baseAddress!, src.count, nil, COMPRESSION_LZ4_RAW)
            }
        }
        return Array(dst[0..<n])
    }

    @Test func decodesUncompressedBlock() throws {
        let payload: [UInt8] = Array("hello tracev3".utf8)
        var stream = Array("bv4-".utf8) + leU32(UInt32(payload.count)) + payload
        stream += Array("bv4$".utf8)
        let out = try #require(AppleLZ4.decompress(Data(stream)))
        #expect(Array(out) == payload)
    }

    @Test func decodesCompressedBlock() throws {
        // Zeros + text compress well, so COMPRESSION_LZ4_RAW returns a real block.
        let payload = [UInt8](repeating: 0x41, count: 4096) + Array("tail".utf8)
        let encoded = lz4Raw(payload)
        try #require(!encoded.isEmpty)
        var stream = Array("bv41".utf8) + leU32(UInt32(payload.count)) + leU32(UInt32(encoded.count)) + encoded
        stream += Array("bv4$".utf8)
        let out = try #require(AppleLZ4.decompress(Data(stream)))
        #expect(Array(out) == payload)
    }

    @Test func concatenatesMultipleBlocks() throws {
        let a: [UInt8] = Array("AAAA".utf8), b: [UInt8] = Array("BBBB".utf8)
        var stream = Array("bv4-".utf8) + leU32(4) + a
        stream += Array("bv4-".utf8) + leU32(4) + b
        stream += Array("bv4$".utf8)
        let out = try #require(AppleLZ4.decompress(Data(stream)))
        #expect(Array(out) == a + b)
    }
}

struct TraceV3FramingTests {
    private func leU32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> ($0 * 8)) & 0xff) } }
    private func leU64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> ($0 * 8)) & 0xff) } }

    /// One chunk: 16-byte preamble + data, padded to the next 8-byte boundary.
    private func chunk(tag: UInt32, subtag: UInt32 = 0, data: [UInt8]) -> [UInt8] {
        var out = leU32(tag) + leU32(subtag) + leU64(UInt64(data.count)) + data
        while out.count % 8 != 0 { out.append(0) }
        return out
    }

    /// Wrap inner chunks into an uncompressed bv4x chunkset payload.
    private func bv4Uncompressed(_ inner: [UInt8]) -> [UInt8] {
        Array("bv4-".utf8) + leU32(UInt32(inner.count)) + inner + Array("bv4$".utf8)
    }

    @Test func parsesChunksWithAlignment() {
        // First chunk has a 13-byte payload → 3 bytes of padding before the next.
        var bytes = chunk(tag: TraceV3Parser.tagHeader, data: [UInt8](repeating: 0, count: 13))
        bytes += chunk(tag: TraceV3Parser.tagCatalog, data: [UInt8](repeating: 1, count: 8))
        let chunks = TraceV3Parser.chunks(in: bytes)
        #expect(chunks.count == 2)
        #expect(chunks[0].tag == TraceV3Parser.tagHeader)
        #expect(chunks[1].tag == TraceV3Parser.tagCatalog)
    }

    @Test func truncatedPreambleStopsCleanly() {
        let bytes: [UInt8] = [0x00, 0x10, 0x00, 0x00, 0x01]   // partial preamble
        #expect(TraceV3Parser.chunks(in: bytes).isEmpty)
    }

    @Test func structureTalliesInnerChunks() {
        // Inner chunkset stream: one firehose + one simpledump chunk.
        let inner = chunk(tag: TraceV3Parser.tagFirehose, data: [UInt8](repeating: 0, count: 32))
            + chunk(tag: TraceV3Parser.tagSimpledump, data: [UInt8](repeating: 0, count: 16))
        var file = chunk(tag: TraceV3Parser.tagHeader, data: [UInt8](repeating: 0, count: 16))
        file += chunk(tag: TraceV3Parser.tagCatalog, data: [UInt8](repeating: 0, count: 8))
        file += chunk(tag: TraceV3Parser.tagChunkset, data: bv4Uncompressed(inner))

        let s = TraceV3Parser.structure(of: Data(file), sourceFile: "0000.tracev3")
        #expect(s.headerPresent)
        #expect(s.catalogCount == 1)
        #expect(s.chunksetCount == 1)
        #expect(s.firehoseCount == 1)
        #expect(s.simpledumpCount == 1)
        #expect(s.undecodableChunksets == 0)
        #expect(s.sourceFile == "0000.tracev3")
    }

    @Test func compressedChunksetDecodes() {
        // A bv41-compressed chunkset (real LZ4) carrying one firehose chunk.
        let inner = chunk(tag: TraceV3Parser.tagFirehose, data: [UInt8](repeating: 0, count: 2048))
        let cap = inner.count + 512
        var enc = [UInt8](repeating: 0, count: cap)
        let n = inner.withUnsafeBufferPointer { s in
            enc.withUnsafeMutableBufferPointer { d in
                compression_encode_buffer(d.baseAddress!, cap, s.baseAddress!, inner.count, nil, COMPRESSION_LZ4_RAW)
            }
        }
        enc = Array(enc[0..<n])
        var payload = Array("bv41".utf8) + leU32(UInt32(inner.count)) + leU32(UInt32(enc.count)) + enc
        payload += Array("bv4$".utf8)
        let file = chunk(tag: TraceV3Parser.tagChunkset, data: payload)

        let s = TraceV3Parser.structure(of: Data(file), sourceFile: "x")
        #expect(s.chunksetCount == 1)
        #expect(s.firehoseCount == 1)
        #expect(s.undecodableChunksets == 0)
    }

    @Test func parseReturnsEmptyInPhase1() {
        #expect(TraceV3Parser.parse(Data([0x00, 0x10, 0x00, 0x00]), sourceFile: "x").isEmpty)
    }
}
