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

    /// Decode a `.tracev3` file into `UnifiedLogEntry`s (M4): walk the top-level
    /// chunks in order, tracking the current catalog, decompress each chunkset,
    /// and decode its firehose tracepoints. Timestamps are resolved through the
    /// timesync boot matching the file header's boot UUID — pass `timesyncByBoot`
    /// (boot UUID → `TimesyncBoot`); without it, entries have a nil timestamp.
    ///
    /// **M4 scope:** entries carry timestamp, pid, event type and level. The
    /// `process`/`subsystem`/`category`/`message` fields are resolved later (M5)
    /// from the `.uuidtext`/`dsc` strings.
    public static func parse(_ data: Data, sourceFile: String,
                             timesyncByBoot: [String: TimesyncBoot] = [:]) -> [UnifiedLogEntry] {
        let bytes = [UInt8](data)
        let top = chunks(in: bytes)
        guard top.first?.tag == tagHeader else { return [] }

        let boot = header(of: data).flatMap { timesyncByBoot[$0.bootUUID] }

        var entries: [UnifiedLogEntry] = []
        var currentCatalog: TraceV3Catalog?
        for chunk in top {
            switch chunk.tag {
            case tagCatalog:
                currentCatalog = catalog(fromData: Array(bytes[chunk.range]))
            case tagChunkset:
                guard let inflated = AppleLZ4.decompress(Data(bytes[chunk.range])),
                      !inflated.isEmpty else { continue }
                let ib = [UInt8](inflated)
                for inner in chunks(in: ib) where inner.tag == tagFirehose {
                    let tps = FirehoseDecoder.tracepoints(chunkData: Array(ib[inner.range]),
                                                          catalog: currentCatalog)
                    for tp in tps {
                        entries.append(tp.partialEntry(timesync: boot, sourceFile: sourceFile))
                    }
                }
            default:
                break
            }
        }
        return entries
    }

    // MARK: - Header (0x1000)

    // Header sub-record tags.
    private static let subContinuousTime: UInt32 = 0x6100
    private static let subSystemInfo: UInt32     = 0x6101
    private static let subGeneration: UInt32     = 0x6102   // boot UUID
    private static let subTimezone: UInt32       = 0x6103

    /// Parse the `.tracev3` header chunk (`0x1000`) into a `TraceV3Header`.
    /// Returns nil if the first chunk isn't a header.
    public static func header(of data: Data) -> TraceV3Header? {
        let bytes = [UInt8](data)
        guard let h = chunks(in: bytes).first, h.tag == tagHeader else { return nil }
        return header(fromData: Array(bytes[h.range]))
    }

    /// Decode a header chunk's *data* payload (the bytes after the 16-byte
    /// preamble). Exposed for testing.
    public static func header(fromData d: [UInt8]) -> TraceV3Header? {
        guard d.count >= 0x28 else { return nil }
        let num = readU32(d, 0x00)
        let den = readU32(d, 0x04)
        let continuousTime = readU64(d, 0x08)
        let startWall = readU64(d, 0x10)
        let bias = Int32(bitPattern: readU32(d, 0x1C))

        var bootUUID = ""
        var build = "", model = "", tzPath = ""
        // Tagged sub-records: tag u32 | size u32 | data[size].
        var i = 0x28
        while i + 8 <= d.count {
            let tag = readU32(d, i)
            let size = Int(readU32(d, i + 4))
            let start = i + 8
            guard size >= 0, start + size <= d.count else { break }
            let body = Array(d[start..<start + size])
            switch tag {
            case subGeneration where body.count >= 16:
                bootUUID = uuidString(body, 0)
            case subSystemInfo:
                // u32, u32, then two NUL-terminated strings: build then model.
                let strs = nulStrings(body, from: 8)
                if strs.count >= 1 { build = strs[0] }
                if strs.count >= 2 { model = strs[1] }
            case subTimezone:
                tzPath = nulStrings(body, from: 0).first ?? ""
            default:
                break
            }
            i = start + size
            if i % 8 != 0 { i += 8 - (i % 8) }
        }
        return TraceV3Header(bootUUID: bootUUID, timebaseNumerator: num,
                             timebaseDenominator: den, continuousTime: continuousTime,
                             startWalltimeSeconds: startWall, timezoneBiasMinutes: bias,
                             osBuild: build, hardwareModel: model, timezonePath: tzPath)
    }

    // MARK: - Catalog (0x600B)

    /// Fixed catalog-header size; all `*_offset` fields are relative to its end.
    private static let catalogHeaderSize = 24
    /// Each per-process loaded-image (uuid-info) entry is 16 bytes.
    private static let uuidEntrySize = 16
    /// Each subsystem entry is 6 bytes (identifier, subsystem off, category off).
    private static let subsystemEntrySize = 6

    /// Parse every catalog chunk (`0x600B`) in a `.tracev3` file.
    public static func catalogs(of data: Data) -> [TraceV3Catalog] {
        let bytes = [UInt8](data)
        return chunks(in: bytes)
            .filter { $0.tag == tagCatalog }
            .compactMap { catalog(fromData: Array(bytes[$0.range])) }
    }

    /// Decode a catalog chunk's *data* payload. Exposed for testing.
    public static func catalog(fromData c: [UInt8]) -> TraceV3Catalog? {
        let n = c.count
        guard n >= catalogHeaderSize else { return nil }
        func u16(_ o: Int) -> Int { (o + 1 < n) ? Int(c[o]) | (Int(c[o + 1]) << 8) : 0 }
        func u32(_ o: Int) -> UInt32 { (o + 3 < n) ? readU32(c, o) : 0 }
        func u64(_ o: Int) -> UInt64 { (o + 7 < n) ? readU64(c, o) : 0 }

        let subStrOff = u16(0)
        let piOff = u16(2)
        let nProcInfo = u16(4)
        let scOff = u16(6)
        let nSubchunks = u16(8)
        let earliest = u64(16)

        let H = catalogHeaderSize
        let uuidArrayEnd = H + subStrOff           // UUID array fills [H, H+subStrOff)
        let subStrBase = H + subStrOff             // subsystem string pool base
        let piBase = H + piOff
        let scBase = H + scOff
        guard uuidArrayEnd <= n, piBase <= n, scBase <= n else { return nil }

        // UUID array (16 bytes each).
        var uuids: [String] = []
        var u = H
        while u + 16 <= uuidArrayEnd { uuids.append(uuidString(c, u)); u += 16 }

        // A subsystem string is read from the pool at `subStrBase + offset`.
        func poolString(_ offset: Int) -> String {
            let start = subStrBase + offset
            guard start >= 0, start < n else { return "" }
            var out: [UInt8] = []
            var i = start
            while i < n, c[i] != 0 { out.append(c[i]); i += 1 }
            return String(decoding: out, as: UTF8.self)
        }

        // Process-info entries (variable length).
        var processInfos: [CatalogProcessInfo] = []
        var p = piBase
        for _ in 0..<nProcInfo {
            guard p + 40 <= n else { break }
            let mainIdx = u16(p + 4)
            let dscIdx = u16(p + 6)
            let first = u64(p + 8)
            let second = u32(p + 16)
            let pid = u32(p + 20)
            let euid = u32(p + 24)
            let nUUID = Int(u32(p + 32))
            guard nUUID >= 0, p + 40 + nUUID * uuidEntrySize + 8 <= n else { break }

            var uuidEntries: [CatalogProcessInfo.UUIDEntry] = []
            for k in 0..<nUUID {
                let b = p + 40 + k * uuidEntrySize
                // load_address is a 48-bit value: lo u32 @+10, hi u16 @+14.
                let lo = UInt64(u32(b + 10))
                let hi = UInt64(UInt16(truncatingIfNeeded: u16(b + 14)))
                uuidEntries.append(.init(size: u32(b), loadAddress: lo | (hi << 32),
                                         uuidIndex: u16(b + 8)))
            }
            var q = p + 40 + nUUID * uuidEntrySize
            let nSub = Int(u32(q))
            q += 8
            guard nSub >= 0, q + nSub * subsystemEntrySize <= n else { break }

            var subsystems: [CatalogProcessInfo.Subsystem] = []
            for _ in 0..<nSub {
                let ident = UInt16(truncatingIfNeeded: u16(q))
                subsystems.append(.init(identifier: ident,
                                        subsystem: poolString(u16(q + 2)),
                                        category: poolString(u16(q + 4))))
                q += subsystemEntrySize
            }
            processInfos.append(.init(firstProcID: first, secondProcID: second, pid: pid,
                                      euid: euid, mainUUIDIndex: mainIdx, dscUUIDIndex: dscIdx,
                                      uuidEntries: uuidEntries, subsystems: subsystems))
            // Next entry is 8-byte aligned.
            if q % 8 != 0 { q += 8 - (q % 8) }
            p = q
        }

        // Subchunk windows (only the fixed prefix is needed here).
        var subchunks: [CatalogSubchunk] = []
        var s = scBase
        for _ in 0..<nSubchunks {
            guard s + 24 <= n else { break }
            let start = u64(s)
            let end = u64(s + 8)
            let uncomp = u32(s + 16)
            let algo = u32(s + 20)
            subchunks.append(.init(startContinuousTime: start, endContinuousTime: end,
                                   uncompressedSize: uncomp, compressionAlgorithm: algo))
            // Variable tail: numberOfIndexes u32 + indexes(u16) + numberOfOffsets
            // u32 + offsets(u16), 8-byte aligned. Walk it to reach the next.
            var t = s + 24
            guard t + 2 <= n else { break }
            let nIdx = Int(u16(t)); t += 2 + nIdx * 2
            guard t + 2 <= n else { break }
            let nOff = Int(u16(t)); t += 2 + nOff * 2
            if t % 8 != 0 { t += 8 - (t % 8) }
            s = t
        }

        return TraceV3Catalog(uuids: uuids, processInfos: processInfos,
                              subchunks: subchunks, earliestFirehoseTimestamp: earliest)
    }

    // MARK: - Little-endian readers

    /// Canonical 8-4-4-4-12 UUID string from 16 bytes at `o`.
    private static func uuidString(_ b: [UInt8], _ o: Int) -> String {
        guard o + 16 <= b.count else { return "" }
        let h = (o..<o + 16).map { String(format: "%02X", b[$0]) }.joined()
        let parts = [h.prefix(8), h.dropFirst(8).prefix(4), h.dropFirst(12).prefix(4),
                     h.dropFirst(16).prefix(4), h.dropFirst(20).prefix(12)]
        return parts.map(String.init).joined(separator: "-")
    }

    /// NUL-terminated strings in `b` starting at `from`, skipping empty runs.
    private static func nulStrings(_ b: [UInt8], from: Int) -> [String] {
        var out: [String] = []
        var cur: [UInt8] = []
        var i = from
        while i < b.count {
            if b[i] == 0 {
                if !cur.isEmpty { out.append(String(decoding: cur, as: UTF8.self)); cur = [] }
            } else {
                cur.append(b[i])
            }
            i += 1
        }
        if !cur.isEmpty { out.append(String(decoding: cur, as: UTF8.self)) }
        return out
    }

    private static func readU32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }

    private static func readU64(_ b: [UInt8], _ i: Int) -> UInt64 {
        var v: UInt64 = 0
        for k in 0..<8 { v |= UInt64(b[i + k]) << (8 * k) }
        return v
    }
}
