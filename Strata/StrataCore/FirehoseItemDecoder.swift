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
/// The optional header's size is flag-dependent and underdocumented, so rather
/// than parse it, we **anchor** on the descriptor block: scan candidate start
/// positions and accept the one whose descriptors parse in-bounds and whose
/// value region is consumed exactly to the end of the data (preferring a match
/// whose item count equals the format string's specifier count). This is
/// self-validating and robust to unknown header fields.
public nonisolated enum FirehoseItemDecoder {

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

    /// Decode the items, anchoring the descriptor block. `expectedCount` is the
    /// format string's specifier count (used to disambiguate the anchor).
    public static func decode(_ data: [UInt8], expectedCount: Int) -> [FirehoseItem] {
        let n = data.count
        var best: [FirehoseItem]? = nil
        var bestScore = Int.min

        // `item` + `number_items` need 2 bytes; descriptors then values follow.
        var p = 0
        while p + 2 <= n {
            if let (items, consumedExactly, count) = tryParse(data, at: p) {
                // Score: exact consumption strongly preferred; matching the
                // expected arg count next; earlier anchor as a tiebreak.
                var score = 0
                if consumedExactly { score += 1000 }
                if count == expectedCount { score += 500 }
                score -= p
                if score > bestScore { bestScore = score; best = items }
                // A clean exact+count match is as good as it gets.
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
