import Foundation

/// A decoded binary-property-list value. Unlike `PropertyListSerialization`, this
/// preserves `CF$UID` references as `.uid`, which is what makes an
/// **NSKeyedArchiver** object graph (`$objects` / `$top`, used by `.btm`, `.sfl2`,
/// …) walkable without the originating private classes.
public indirect enum PlistValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case date(Double)          // seconds since 2001-01-01 (CFAbsoluteTime)
    case data(Data)
    case string(String)
    case uid(Int)              // keyed-archive object-table index
    case array([PlistValue])
    case dict([String: PlistValue])

    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var intValue: Int? {
        switch self {
        case .int(let i): return Int(i)
        case .bool(let b): return b ? 1 : 0
        default: return nil
        }
    }
    public var uidValue: Int? { if case .uid(let u) = self { return u }; return nil }
    public var arrayValue: [PlistValue]? { if case .array(let a) = self { return a }; return nil }
    public var dictValue: [String: PlistValue]? { if case .dict(let d) = self { return d }; return nil }
}

/// Minimal `bplist00` decoder — enough to read NSKeyedArchiver archives. Pure +
/// deterministic (no reliance on the opaque CF UID type), so keyed-archive
/// artifacts decode identically on every OS and can be unit-tested.
public enum BinaryPlist {
    public static func parse(_ data: Data) -> PlistValue? {
        let b = [UInt8](data)
        guard b.count > 40, b.starts(with: Array("bplist00".utf8)) else { return nil }
        let trailer = b.count - 32
        let offsetSize = Int(b[trailer + 6])
        let refSize = Int(b[trailer + 7])
        guard let numObjects = intExact(readBE(b, trailer + 8, 8)),
              let topIndex = intExact(readBE(b, trailer + 16, 8)),
              let offTableOff = intExact(readBE(b, trailer + 24, 8)),
              let tableSize = multiplied(numObjects, offsetSize),
              let tableEnd = added(offTableOff, tableSize) else { return nil }
        guard offsetSize > 0, offsetSize <= 8, refSize > 0, refSize <= 8, numObjects > 0,
              topIndex >= 0, topIndex < numObjects,
              offTableOff >= 0, tableEnd <= b.count else { return nil }
        var offsets = [Int](); offsets.reserveCapacity(numObjects)
        for i in 0..<numObjects {
            guard let relative = multiplied(i, offsetSize),
                  let position = added(offTableOff, relative),
                  let value = intExact(readBE(b, position, offsetSize)) else { return nil }
            offsets.append(value)
        }
        var building = Set<Int>()
        return decode(topIndex, b, offsets, refSize, &building, depth: 0)
    }

    private static func readBE(_ b: [UInt8], _ off: Int, _ size: Int) -> UInt64 {
        var v: UInt64 = 0
        for k in 0..<size where off + k < b.count { v = (v << 8) | UInt64(b[off + k]) }
        return v
    }

    private static func decode(_ index: Int, _ b: [UInt8], _ offsets: [Int], _ refSize: Int,
                               _ building: inout Set<Int>, depth: Int) -> PlistValue? {
        guard depth < 512, index >= 0, index < offsets.count else { return nil }
        let off = offsets[index]
        guard off >= 0, off < b.count else { return nil }
        let marker = b[off]
        let hi = marker >> 4, lo = Int(marker & 0x0F)
        switch hi {
        case 0x0:
            switch marker {
            case 0x08: return .bool(false)
            case 0x09: return .bool(true)
            default: return .null
            }
        case 0x1:                                   // int, 2^lo bytes
            let n = 1 << lo
            guard let end = added(off + 1, n), end <= b.count else { return nil }
            return .int(Int64(bitPattern: readBE(b, off + 1, n)))
        case 0x2:                                   // real
            let n = 1 << lo
            guard (n == 4 || n == 8), let end = added(off + 1, n), end <= b.count else { return nil }
            let raw = readBE(b, off + 1, n)
            return .double(n == 4 ? Double(Float(bitPattern: UInt32(truncatingIfNeeded: raw)))
                                  : Double(bitPattern: raw))
        case 0x3:                                   // date
            guard off + 9 <= b.count else { return nil }
            return .date(Double(bitPattern: readBE(b, off + 1, 8)))
        case 0x4:                                   // data
            guard let (len, start) = sizeAndStart(b, off, lo) else { return nil }
            guard let end = added(start, len), end <= b.count else { return nil }
            return .data(Data(b[start..<end]))
        case 0x5:                                   // ASCII string
            guard let (len, start) = sizeAndStart(b, off, lo) else { return nil }
            guard let end = added(start, len), end <= b.count else { return nil }
            return .string(String(decoding: b[start..<end], as: UTF8.self))
        case 0x6:                                   // UTF-16BE string (len = code units)
            guard let (len, start) = sizeAndStart(b, off, lo) else { return nil }
            guard let byteCount = multiplied(len, 2),
                  let end = added(start, byteCount), end <= b.count else { return nil }
            var units = [UInt16](); units.reserveCapacity(len)
            for k in 0..<len { units.append(UInt16(readBE(b, start + k * 2, 2))) }
            return .string(String(decoding: units, as: UTF16.self))
        case 0x8:                                   // UID (lo+1 bytes)
            guard off + 2 + lo <= b.count else { return nil }
            guard let value = intExact(readBE(b, off + 1, lo + 1)) else { return nil }
            return .uid(value)
        case 0xA:                                   // array
            guard let (count, start) = sizeAndStart(b, off, lo) else { return nil }
            guard let byteCount = multiplied(count, refSize),
                  let end = added(start, byteCount), end <= b.count,
                  building.insert(index).inserted else { return .null }
            defer { building.remove(index) }
            var out = [PlistValue](); out.reserveCapacity(count)
            for k in 0..<count {
                guard let relative = multiplied(k, refSize),
                      let position = added(start, relative),
                      let ref = intExact(readBE(b, position, refSize)) else { return nil }
                out.append(decode(ref, b, offsets, refSize, &building, depth: depth + 1) ?? .null)
            }
            return .array(out)
        case 0xD:                                   // dict
            guard let (count, start) = sizeAndStart(b, off, lo) else { return nil }
            guard let byteCount = multiplied(count, refSize),
                  let valuesStart = added(start, byteCount),
                  let end = added(valuesStart, byteCount), end <= b.count,
                  building.insert(index).inserted else { return .null }
            defer { building.remove(index) }
            var out = [String: PlistValue](minimumCapacity: count)
            for k in 0..<count {
                guard let relative = multiplied(k, refSize),
                      let keyPosition = added(start, relative),
                      let valuePosition = added(valuesStart, relative),
                      let keyRef = intExact(readBE(b, keyPosition, refSize)),
                      let valRef = intExact(readBE(b, valuePosition, refSize)) else { return nil }
                guard let key = decode(keyRef, b, offsets, refSize, &building,
                                       depth: depth + 1)?.stringValue else { continue }
                out[key] = decode(valRef, b, offsets, refSize, &building,
                                  depth: depth + 1) ?? .null
            }
            return .dict(out)
        default:
            return nil
        }
    }

    /// For data/string/array/dict: the count is the low nibble unless it's 0xF, in
    /// which case an int object follows giving the real count.
    private static func sizeAndStart(_ b: [UInt8], _ off: Int, _ lo: Int) -> (count: Int, start: Int)? {
        guard lo == 0x0F else { return (lo, off + 1) }
        guard off + 1 < b.count else { return nil }
        let intMarker = b[off + 1]
        guard intMarker >> 4 == 0x1 else { return nil }
        let n = 1 << Int(intMarker & 0x0F)
        // The extended length spans n bytes at off+2; bail on a truncated buffer
        // rather than reading a partial (corrupted) count.
        guard off + 2 + n <= b.count else { return nil }
        guard let count = intExact(readBE(b, off + 2, n)) else { return nil }
        return (count, off + 2 + n)
    }

    private static func added(_ lhs: Int, _ rhs: Int) -> Int? {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? nil : value
    }

    private static func multiplied(_ lhs: Int, _ rhs: Int) -> Int? {
        let (value, overflow) = lhs.multipliedReportingOverflow(by: rhs)
        return overflow ? nil : value
    }
}
