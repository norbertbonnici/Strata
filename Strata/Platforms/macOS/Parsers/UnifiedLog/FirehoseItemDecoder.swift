import Foundation

/// One decoded argument item from a firehose tracepoint's data section.
public nonisolated struct FirehoseItem: Sendable, Hashable {
    public let type: UInt8
    /// The argument's rendered value (string contents, or a number's decimal
    /// text). `nil` for a `<private>`/redacted item with no public value.
    public let value: String?
    public let isPrivate: Bool
    public let isNumber: Bool
}

/// Decodes the **argument items** in a firehose tracepoint's data section (the
/// `data` of a `FirehoseTracepoint`) — M5b. The layout after the flag-driven
/// optional header is: `item(u8), number_items(u8)`, then `number_items` item
/// **descriptors**, then a **value region**. Each descriptor is
/// `type(u8), type_size(u8)`, plus — for string/data/private-number items — a
/// `(offset u16, size u16)` into the value region. Plain numbers (`0x0`/`0x2`)
/// carry their bytes inline (sequentially) in the value region.
///
/// The optional header (between the 24-byte tracepoint header and the item
/// block) is parsed **deterministically** by flag (order confirmed against the
/// real macOS-12 image, per Mandiant `macos-UnifiedLogs`): `has_current_aid`
/// (0x0001 → 8B), `has_private_data` (0x0100 → 4B), the always-present `pc_id`
/// (4B), `has_large_offset` (0x0020 → 2B), `has_subsystem` (0x0200 → 2B
/// subsystem id), `has_rules` (0x0400 → 1B ttl), `has_oversize` (0x0800 → 4B).
/// That yields the **subsystem identifier** for free. If the deterministic
/// header doesn't land on a self-consistent item block (an unhandled flag combo),
/// we fall back to **anchoring**: scanning candidate start positions for the one
/// whose descriptors parse in-bounds and consume the value region exactly.
public nonisolated enum FirehoseItemDecoder {

    /// The decode result: the argument items plus the subsystem identifier
    /// (present only when the deterministic header parse succeeded and the
    /// `has_subsystem` flag was set).
    public struct Decoded: Sendable {
        public let items: [FirehoseItem]
        public let subsystemID: UInt16?
        /// Format-string reference fields parsed from the optional header, used to
        /// resolve absolute / shared-cache-with-large-offset strings.
        public let pcID: UInt32
        public let largeOffset: UInt16
        public let largeSharedCache: UInt16
        public let altIndex: UInt16
        /// The embedded 32-hex UUID for a `uuid_relative` (`0x0a`) tracepoint.
        public let uuidRelative: String?
        public init(items: [FirehoseItem], subsystemID: UInt16?,
                    pcID: UInt32 = 0, largeOffset: UInt16 = 0, largeSharedCache: UInt16 = 0,
                    altIndex: UInt16 = 0, uuidRelative: String? = nil) {
            self.items = items; self.subsystemID = subsystemID
            self.pcID = pcID; self.largeOffset = largeOffset; self.largeSharedCache = largeSharedCache
            self.altIndex = altIndex; self.uuidRelative = uuidRelative
        }
    }

    /// The format-string reference fields recovered from the optional header.
    struct HeaderInfo {
        var start: Int
        var subsystem: UInt16?
        var pcID: UInt32 = 0
        var largeOffset: UInt16 = 0
        var largeSharedCache: UInt16 = 0
        var altIndex: UInt16 = 0
        var uuidRelative: String?
    }

    /// Item types that carry a `(offset, size)` into the value region.
    static let stringTypes: Set<UInt8> = [0x20, 0x21, 0x22, 0x25, 0x40, 0x41, 0x42,
                                          0x30, 0x31, 0x32, 0xf2, 0x35, 0x81, 0xf1, 0x01]
    /// Of those, the ones whose value is private/redacted.
    static let privateTypes: Set<UInt8> = [0x21, 0x25, 0x35, 0x41, 0x81, 0xf1, 0x01]
    /// Inline-number types (value is `type_size` bytes in the value region).
    static let numberTypes: Set<UInt8> = [0x00, 0x02]
    /// Precision/width specifier items (consume `type_size` value bytes, no own output).
    static let precisionTypes: Set<UInt8> = [0x10, 0x12]
    /// Sensitive items rendered as `<private>` (no metadata).
    static let sensitiveTypes: Set<UInt8> = [0x05, 0x45, 0x85]

    /// Decode the items + subsystem id. `flags` drives the deterministic
    /// optional-header parse; `expectedCount` is the format string's specifier
    /// count (used to disambiguate the anchor fallback).
    public static func decode(_ data: [UInt8], flags: UInt16, expectedCount: Int) -> Decoded {
        // 1. Deterministic optional-header parse — also yields the subsystem id
        //    and the format-string reference fields.
        if let h = optionalHeaderEnd(data, flags: flags),
           let (items, exact, _) = tryParse(data, at: h.start), exact {
            return Decoded(items: items, subsystemID: h.subsystem, pcID: h.pcID,
                           largeOffset: h.largeOffset, largeSharedCache: h.largeSharedCache,
                           altIndex: h.altIndex, uuidRelative: h.uuidRelative)
        }
        // 2. Fallback: anchor on the descriptor block (no subsystem/refs).
        return Decoded(items: anchorDecode(data, expectedCount: expectedCount), subsystemID: nil)
    }

    /// Walk the flag-driven optional header, recovering the `item`-byte offset,
    /// the subsystem id, and the format-string reference fields (pc_id,
    /// large_offset / large_shared_cache, absolute alt-index, uuid_relative).
    /// Returns nil if it runs past the buffer. Field order + sizes confirmed
    /// against the real image (Mandiant `firehose_formatter_flags` / Khatri).
    static func optionalHeaderEnd(_ d: [UInt8], flags: UInt16) -> HeaderInfo? {
        let n = d.count
        func u16(_ o: Int) -> UInt16 { (o + 1 < n) ? UInt16(d[o]) | (UInt16(d[o + 1]) << 8) : 0 }
        func u32(_ o: Int) -> UInt32 {
            (o + 3 < n) ? UInt32(d[o]) | (UInt32(d[o + 1]) << 8) | (UInt32(d[o + 2]) << 16) | (UInt32(d[o + 3]) << 24) : 0
        }
        func uuid(_ o: Int) -> String {
            guard o + 16 <= n else { return "" }
            return (o..<o + 16).map { String(format: "%02X", d[$0]) }.joined()
        }
        var p = 0
        if flags & 0x0001 != 0 { p += 8 }     // has_current_aid: activity id + sentinel
        if flags & 0x0100 != 0 { p += 4 }     // has_private_data: offset + size
        var h = HeaderInfo(start: 0, subsystem: nil)
        h.pcID = u32(p); p += 4                // pc_id (always present)

        // Format-type extras (the formatter flags).
        let formatType = flags & 0x000e
        var largeOffsetRead = false
        switch formatType {
        case 0x0c:   // large_shared_cache: optional large_offset u16, then large_shared_cache u16
            if flags & 0x0020 != 0 { h.largeOffset = u16(p); p += 2 }
            h.largeSharedCache = u16(p); p += 2
            largeOffsetRead = true
        case 0x08:   // absolute: alt-uuid index (only when not also main_exe)
            if flags & 0x0002 == 0 { h.altIndex = u16(p); p += 2 }
        case 0x0a:   // uuid_relative: an explicit 16-byte UUID
            h.uuidRelative = uuid(p); p += 16
        default:
            break
        }
        // has_large_offset, unless the format-type handler already consumed it.
        if flags & 0x0020 != 0 && !largeOffsetRead { h.largeOffset = u16(p); p += 2 }

        if flags & 0x0200 != 0 { h.subsystem = u16(p); p += 2 }   // has_subsystem
        if flags & 0x0400 != 0 { p += 1 }     // has_rules: ttl
        if flags & 0x0800 != 0 { p += 2 }     // has_oversize: data ref (u16)
        h.start = p
        return p + 2 <= n ? h : nil
    }

    /// Anchor on the descriptor block: scan for the start whose descriptors parse
    /// in-bounds and consume the value region exactly (preferring `expectedCount`).
    private static func anchorDecode(_ data: [UInt8], expectedCount: Int) -> [FirehoseItem] {
        let n = data.count
        var best: [FirehoseItem]?
        var bestScore = Int.min
        var p = 0
        while p + 2 <= n {
            if let (items, consumedExactly, count) = tryParse(data, at: p) {
                var score = 0
                if consumedExactly { score += 1000 }
                if count == expectedCount { score += 500 }
                score -= p
                if score > bestScore { bestScore = score; best = items }
                if consumedExactly && count == expectedCount { break }
            }
            p += 1
        }
        return best ?? []
    }

    /// Try to parse the descriptor block + value region starting at `pos`
    /// (`pos` points at the `item` byte). Returns the items, whether the value
    /// region was consumed exactly, and the item count — or nil if inconsistent.
    private static func tryParse(_ d: [UInt8], at pos: Int) -> (items: [FirehoseItem], exact: Bool, count: Int)? {
        let n = d.count
        guard pos + 2 <= n else { return nil }
        let numberItems = Int(d[pos + 1])
        guard numberItems >= 1, numberItems <= 48 else { return nil }

        // Parse descriptors.
        struct Desc { let type: UInt8; let typeSize: UInt8; let offset: Int; let size: Int }
        var descs: [Desc] = []
        var q = pos + 2
        for _ in 0..<numberItems {
            guard q + 2 <= n else { return nil }
            let type = d[q], typeSize = d[q + 1]
            q += 2
            let known = stringTypes.contains(type) || numberTypes.contains(type)
                || precisionTypes.contains(type) || sensitiveTypes.contains(type)
            guard known else { return nil }
            if stringTypes.contains(type) {
                guard q + 4 <= n else { return nil }
                let off = Int(d[q]) | (Int(d[q + 1]) << 8)
                let size = Int(d[q + 2]) | (Int(d[q + 3]) << 8)
                q += 4
                descs.append(Desc(type: type, typeSize: typeSize, offset: off, size: size))
            } else {
                descs.append(Desc(type: type, typeSize: typeSize, offset: -1, size: Int(typeSize)))
            }
        }
        let valueStart = q
        guard valueStart <= n else { return nil }
        let regionLen = n - valueStart

        // Validate string-item ranges fall inside the value region.
        var maxEnd = 0
        for de in descs where de.offset >= 0 {
            guard de.offset + de.size <= regionLen else { return nil }
            maxEnd = max(maxEnd, de.offset + de.size)
        }
        // Inline numbers are read sequentially from after the string values.
        var inlineCursor = maxEnd
        var items: [FirehoseItem] = []
        for de in descs {
            if de.offset >= 0 {
                if privateTypes.contains(de.type) && de.size == 0 {
                    items.append(.init(type: de.type, value: nil, isPrivate: true, isNumber: false))
                } else {
                    let lo = valueStart + de.offset
                    let raw = Array(d[lo..<lo + de.size])
                    let s = string(from: raw)
                    items.append(.init(type: de.type, value: s,
                                       isPrivate: privateTypes.contains(de.type), isNumber: false))
                }
            } else if numberTypes.contains(de.type) {
                let sz = de.size
                guard valueStart + inlineCursor + sz <= n else { return nil }
                let raw = Array(d[valueStart + inlineCursor..<valueStart + inlineCursor + sz])
                inlineCursor += sz
                items.append(.init(type: de.type, value: String(littleEndianInt(raw)),
                                   isPrivate: false, isNumber: true))
            } else if sensitiveTypes.contains(de.type) {
                items.append(.init(type: de.type, value: nil, isPrivate: true, isNumber: false))
            } else {
                // precision: no output item
            }
        }
        let exact = inlineCursor == regionLen
        return (items, exact, numberItems)
    }

    private static func string(from raw: [UInt8]) -> String {
        var bytes = raw
        if bytes.last == 0 { bytes.removeLast() }   // strip trailing NUL
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func littleEndianInt(_ raw: [UInt8]) -> Int64 {
        var v: UInt64 = 0
        for (i, b) in raw.prefix(8).enumerated() { v |= UInt64(b) << (8 * i) }
        // Sign-extend common widths.
        switch raw.count {
        case 1: return Int64(Int8(bitPattern: UInt8(truncatingIfNeeded: v)))
        case 2: return Int64(Int16(bitPattern: UInt16(truncatingIfNeeded: v)))
        case 4: return Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: v)))
        default: return Int64(bitPattern: v)
        }
    }
}
