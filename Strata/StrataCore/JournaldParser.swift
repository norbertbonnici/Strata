import Foundation
import Compression

/// Pure-Swift decoder for the systemd **journald** binary journal format (no
/// vendored tool - like the USN and `$MFT` parsers). Implements enough of the
/// documented format (https://systemd.io/JOURNAL_FILE_FORMAT/) to recover log
/// entries: the file header, the entry-array chain, entry objects (carrying the
/// realtime timestamp), and the data objects they reference (`FIELD=value`).
///
/// Both the legacy and **COMPACT** (systemd ≥ 252) layouts are handled - in
/// compact mode entry-array and entry items are 32-bit offsets and the data
/// object header is 8 bytes longer. **LZ4**-compressed data is inflated via
/// Apple's `Compression` framework; **XZ/ZSTD**-compressed values are skipped
/// (those codecs aren't in the framework), which in practice only loses *large*
/// MESSAGE bodies - short fields and most messages are stored uncompressed.
///
/// Every read is bounds-checked: a truncated or corrupt journal yields whatever
/// parsed cleanly rather than crashing.
public nonisolated enum JournaldParser {

    private static let signature: [UInt8] = Array("LPKSHHRH".utf8)

    // incompatible_flags bits
    private static let flagCompressedXZ: UInt32   = 1 << 0
    private static let flagCompressedLZ4: UInt32  = 1 << 1
    private static let flagKeyedHash: UInt32      = 1 << 2
    private static let flagCompressedZSTD: UInt32 = 1 << 3
    private static let flagCompact: UInt32        = 1 << 4

    // object header flags (per-object compression)
    private static let objXZ: UInt8   = 1 << 0
    private static let objLZ4: UInt8  = 1 << 1
    private static let objZSTD: UInt8 = 1 << 2

    private static let objectTypeData: UInt8  = 1
    private static let objectTypeEntry: UInt8 = 3

    /// Cap to bound time/memory on a pathological journal (a real one rarely
    /// exceeds a few hundred thousand entries per file).
    private static let maxEntries = 500_000

    public static func parse(data: Data, sourceFile: String) -> [JournaldEntry] {
        let bytes = [UInt8](data)
        guard bytes.count >= 208, Array(bytes[0..<8]) == signature else { return [] }

        let incompatible = u32(bytes, 12)
        let compact = (incompatible & flagCompact) != 0
        let headerSize = u64(bytes, 88)
        var entryArrayOffset = u64(bytes, 176)
        guard headerSize >= 208, UInt64(bytes.count) >= headerSize else { return [] }

        var entries: [JournaldEntry] = []
        var visitedArrays = Set<UInt64>()

        while entryArrayOffset != 0, entries.count < maxEntries {
            guard visitedArrays.insert(entryArrayOffset).inserted else { break } // cycle guard
            guard let array = readObject(bytes, at: entryArrayOffset) else { break }
            // EntryArray: ObjectHeader(16) next_entry_array_offset(8) items[]
            let itemSize = compact ? 4 : 8
            let itemsStart = Int(entryArrayOffset) + 24
            let itemsBytes = Int(array.size) - 24
            guard itemsBytes >= 0 else { break }
            let count = itemsBytes / itemSize
            for i in 0..<count {
                let p = itemsStart + i * itemSize
                guard p + itemSize <= bytes.count else { break }
                let entryOffset = compact ? UInt64(u32(bytes, p)) : u64(bytes, p)
                if entryOffset == 0 { continue }
                if let entry = readEntry(bytes, at: entryOffset, compact: compact,
                                         incompatible: incompatible, sourceFile: sourceFile) {
                    entries.append(entry)
                    if entries.count >= maxEntries { break }
                }
            }
            entryArrayOffset = u64(bytes, Int(entryArrayOffset) + 16)
        }
        return entries
    }

    // MARK: - Entry

    private static func readEntry(_ bytes: [UInt8], at offset: UInt64, compact: Bool,
                                  incompatible: UInt32, sourceFile: String) -> JournaldEntry? {
        guard let header = readObject(bytes, at: offset), header.type == objectTypeEntry else { return nil }
        let base = Int(offset)
        // EntryObject: ObjectHeader(16) seqnum(8) realtime(8) monotonic(8) boot_id(16) xor_hash(8) items[]
        guard base + 64 <= bytes.count else { return nil }
        let realtime = u64(bytes, base + 24)               // microseconds since epoch
        let bootID = hex(bytes, base + 40, 16)
        let itemSize = compact ? 4 : 16
        let itemsStart = base + 64
        let itemsBytes = Int(header.size) - 64
        guard itemsBytes >= 0 else { return nil }
        let count = itemsBytes / itemSize

        var fields = Fields()
        for i in 0..<count {
            let p = itemsStart + i * itemSize
            guard p + itemSize <= bytes.count else { break }
            // Compact item = le32 offset; regular item = le64 offset + le64 hash.
            let dataOffset = compact ? UInt64(u32(bytes, p)) : u64(bytes, p)
            if dataOffset == 0 { continue }
            if let datum = readData(bytes, at: dataOffset, compact: compact, incompatible: incompatible) {
                fields.absorb(datum)
            }
        }

        let timestamp = realtime == 0 ? nil
            : Date(timeIntervalSince1970: TimeInterval(realtime) / 1_000_000)
        // An entry with no recoverable fields at all isn't useful.
        guard fields.hasAny else {
            return JournaldEntry(timestamp: timestamp, message: "", bootID: bootID,
                                 sourceFile: sourceFile)
        }
        return JournaldEntry(timestamp: timestamp, message: fields.message ?? "",
                             priority: fields.priority, comm: fields.comm, pid: fields.pid,
                             unit: fields.unit, identifier: fields.identifier,
                             hostname: fields.hostname, uid: fields.uid, bootID: bootID,
                             sourceFile: sourceFile)
    }

    // MARK: - Data

    /// Returns the decoded `FIELD=value` string for a DATA object, or nil.
    private static func readData(_ bytes: [UInt8], at offset: UInt64, compact: Bool,
                                 incompatible: UInt32) -> String? {
        guard let header = readObject(bytes, at: offset), header.type == objectTypeData else { return nil }
        let base = Int(offset)
        // DataObject header after ObjectHeader(16): hash next_hash next_field
        // entry_offset entry_array_offset n_entries = 48 bytes; +8 in compact.
        let payloadStart = base + 16 + 48 + (compact ? 8 : 0)
        let payloadLen = Int(header.size) - (16 + 48 + (compact ? 8 : 0))
        guard payloadLen > 0, payloadStart + payloadLen <= bytes.count else { return nil }
        let payload = Array(bytes[payloadStart..<(payloadStart + payloadLen)])

        // The per-object compression flag drives decompression. (An earlier
        // file-level-LZ4 fallback for flags==0 objects was actively harmful: in a
        // real LZ4 journal the sub-512-byte fields are stored UNcompressed with
        // flags==0, and treating them as LZ4 by length silently dropped them —
        // broad evidence loss. LZ4-compressed objects always carry the per-object
        // OBJECT_COMPRESSED_LZ4 flag, set since LZ4 support landed.)
        let objFlags = header.flags
        if objFlags & objLZ4 != 0 {
            guard let raw = inflateLZ4(payload) else { return nil }
            return String(decoding: raw, as: UTF8.self)
        }
        if objFlags & (objXZ | objZSTD) != 0 { return nil }   // unsupported codec - skip
        return String(decoding: payload, as: UTF8.self)
    }

    /// journald LZ4 blobs are `le64 uncompressed_size` + a raw LZ4 block.
    private static func looksLZ4(_ payload: [UInt8]) -> Bool { payload.count > 8 }

    private static func inflateLZ4(_ payload: [UInt8]) -> [UInt8]? {
        guard payload.count > 8 else { return nil }
        // intExact first: a hostile uncompressed_size past Int.max would trap the
        // bare Int(UInt64) before the sanity cap could reject it.
        guard let dstSize = intExact(UInt64(littleEndian: payload[0..<8].withUnsafeBytes { $0.load(as: UInt64.self) })),
              dstSize > 0, dstSize < 64 << 20 else { return nil }   // sanity cap 64 MB
        var dst = [UInt8](repeating: 0, count: dstSize)
        let n = payload[8...].withUnsafeBufferPointer { src in
            dst.withUnsafeMutableBufferPointer { d in
                compression_decode_buffer(d.baseAddress!, dstSize,
                                          src.baseAddress!, src.count, nil, COMPRESSION_LZ4_RAW)
            }
        }
        guard n > 0 else { return nil }
        if n != dstSize { dst.removeSubrange(n...) }
        return dst
    }

    // MARK: - Object header

    private struct ObjectInfo { let type: UInt8; let flags: UInt8; let size: UInt64 }

    /// ObjectHeader: type(1) flags(1) reserved[6] size(8 - total incl. header).
    private static func readObject(_ bytes: [UInt8], at offset: UInt64) -> ObjectInfo? {
        // Hostile offset past Int.max would trap Int(UInt64); reject it (and any
        // offset within 16 bytes of the end) here — the gateway every read
        // funnels through — so Int(offset) at the call sites is then always safe,
        // as is Int(header.size) (size is bounded to bytes.count below).
        guard let base = intExact(offset), base <= bytes.count - 16 else { return nil }
        let size = u64(bytes, base + 8)
        guard size >= 16, size <= UInt64(bytes.count - base) else { return nil }
        return ObjectInfo(type: bytes[base], flags: bytes[base + 1], size: size)
    }

    // MARK: - Field collection

    private struct Fields {
        var message: String?, priority: Int?, comm: String?, pid: Int?
        var unit: String?, identifier: String?, hostname: String?, uid: Int?
        var hasAny: Bool { message != nil || comm != nil || identifier != nil || unit != nil }

        mutating func absorb(_ datum: String) {
            guard let eq = datum.firstIndex(of: "=") else { return }
            let key = String(datum[..<eq])
            let value = String(datum[datum.index(after: eq)...])
            switch key {
            case "MESSAGE":           if message == nil { message = value }
            case "PRIORITY":          priority = Int(value)
            case "_COMM":             comm = value
            case "_PID":              pid = Int(value)
            case "_SYSTEMD_UNIT":     unit = value
            case "SYSLOG_IDENTIFIER": identifier = value
            case "_HOSTNAME":         hostname = value
            case "_UID":              uid = Int(value)
            default: break
            }
        }
    }

    // MARK: - Little-endian readers

    private static func u32(_ b: [UInt8], _ o: Int) -> UInt32 {
        guard o + 4 <= b.count else { return 0 }
        return UInt32(b[o]) | (UInt32(b[o+1]) << 8) | (UInt32(b[o+2]) << 16) | (UInt32(b[o+3]) << 24)
    }
    private static func u64(_ b: [UInt8], _ o: Int) -> UInt64 {
        guard o + 8 <= b.count else { return 0 }
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(b[o + i]) << (8 * i) }
        return v
    }
    private static func hex(_ b: [UInt8], _ o: Int, _ len: Int) -> String? {
        guard o + len <= b.count else { return nil }
        let slice = b[o..<(o + len)]
        if slice.allSatisfy({ $0 == 0 }) { return nil }
        return slice.map { String(format: "%02x", $0) }.joined()
    }
}
