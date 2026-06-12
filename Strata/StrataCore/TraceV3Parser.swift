import Foundation

/// **Phase 1** of the macOS unified-log (`.tracev3`) decoder: the *container*
/// layer. A `.tracev3` file is a flat sequence of **chunks**, each a 16-byte
/// preamble — `tag(u32 LE) | subtag(u32 LE) | data_size(u64 LE)` — followed by
/// `data_size` bytes, the next chunk 8-byte aligned. The top level holds a
/// header (`0x1000`), one or more catalog chunks (`0x600B`), and **chunkset**
/// chunks (`0x600D`) whose payload is an Apple-LZ4 (`bv4x`) block stream; once
/// decompressed, a chunkset contains the inner log chunks — firehose
/// (`0x6001`), oversize (`0x6002`), statedump (`0x6003`), simpledump (`0x6004`).
///
/// This phase parses + enumerates that structure (and decompresses chunksets);
/// it does **not** yet decode firehose tracepoints into `UnifiedLogEntry`s — that
/// needs the catalog + timesync (Phase 2) and `.uuidtext`/`dsc` string
/// resolution (Phase 3). The framing is **size-driven** (each chunk advances by
/// its declared size), so an unrecognised inner tag is skipped rather than
/// derailing the parse.
public nonisolated enum TraceV3Parser {

    // Top-level chunk tags.
    public static let tagHeader: UInt32   = 0x1000
    public static let tagCatalog: UInt32  = 0x600B
    public static let tagChunkset: UInt32 = 0x600D
    // Inner (post-decompression) chunk tags.
    public static let tagFirehose: UInt32   = 0x6001
    public static let tagOversize: UInt32   = 0x6002
    public static let tagStatedump: UInt32  = 0x6003
    public static let tagSimpledump: UInt32 = 0x6004

    /// One parsed chunk: its tag/subtag and the byte range of its data payload
    /// within the buffer it was parsed from.
    public struct Chunk: Sendable, Hashable {
        public let tag: UInt32
        public let subtag: UInt32
        public let range: Range<Int>
    }

    /// A structural summary of a `.tracev3` file — the Phase-1 output. Confirms
    /// the container parsed and tallies the chunk types, so the pipeline + tests
    /// have something concrete before entry decoding lands.
    public struct Structure: Sendable, Hashable, Codable {
        public var headerPresent = false
        public var catalogCount = 0
        public var chunksetCount = 0
        public var firehoseCount = 0
        public var oversizeCount = 0
        public var statedumpCount = 0
        public var simpledumpCount = 0
        public var otherInnerCount = 0
        /// Chunksets whose `bv4x` payload failed to decompress.
        public var undecodableChunksets = 0
        public var sourceFile = ""
    }

    /// Parse the flat chunk sequence in `bytes` (one level — not recursing into
    /// chunkset payloads). Stops cleanly at the first truncated/garbage preamble.
    public static func chunks(in bytes: [UInt8]) -> [Chunk] {
        var result: [Chunk] = []
        var i = 0
        while i + 16 <= bytes.count {
            let tag = readU32(bytes, i)
            let size = Int(readU64(bytes, i + 8))
            let dataStart = i + 16
            let dataEnd = dataStart + size
            guard size >= 0, dataEnd <= bytes.count else { break }
            result.append(Chunk(tag: tag, subtag: readU32(bytes, i + 4), range: dataStart..<dataEnd))
            // Advance to the next 8-byte-aligned preamble.
            var next = dataEnd
            if next % 8 != 0 { next += 8 - (next % 8) }
            i = next
        }
        return result
    }

    /// Walk a whole `.tracev3` file: enumerate top-level chunks, decompress every
    /// chunkset, and tally the inner chunk types into a `Structure`.
    public static func structure(of data: Data, sourceFile: String) -> Structure {
        let bytes = [UInt8](data)
        var s = Structure()
        s.sourceFile = sourceFile

        let top = chunks(in: bytes)
        if top.first?.tag == tagHeader { s.headerPresent = true }

        for chunk in top {
            switch chunk.tag {
            case tagHeader:
                break
            case tagCatalog:
                s.catalogCount += 1
            case tagChunkset:
                s.chunksetCount += 1
                let payload = Data(bytes[chunk.range])
                guard let inflated = AppleLZ4.decompress(payload), !inflated.isEmpty else {
                    s.undecodableChunksets += 1
                    continue
                }
                for inner in chunks(in: [UInt8](inflated)) {
                    switch inner.tag {
                    case tagFirehose:   s.firehoseCount += 1
                    case tagOversize:   s.oversizeCount += 1
                    case tagStatedump:  s.statedumpCount += 1
                    case tagSimpledump: s.simpledumpCount += 1
                    default:            s.otherInnerCount += 1
                    }
                }
            default:
                break
            }
        }
        return s
    }

    /// Phase-1 stub: decoding firehose tracepoints into `UnifiedLogEntry`s needs
    /// the catalog + timesync + `.uuidtext`/`dsc` layers (Phases 2-3). Returns
    /// `[]` for now so the ingest pipeline can wire to a stable entry point.
    public static func parse(_ data: Data, sourceFile: String) -> [UnifiedLogEntry] {
        []
    }

    // MARK: - Little-endian readers

    private static func readU32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }

    private static func readU64(_ b: [UInt8], _ i: Int) -> UInt64 {
        var v: UInt64 = 0
        for k in 0..<8 { v |= UInt64(b[i + k]) << (8 * k) }
        return v
    }
}
