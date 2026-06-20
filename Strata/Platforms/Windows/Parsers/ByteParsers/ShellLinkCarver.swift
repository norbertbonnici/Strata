import Foundation

/// Carves embedded Shell Link (LNK) blobs out of a flat byte buffer.
///
/// CustomDestinations JumpLists (`*.customDestinations-ms`) are NOT OLE - they're
/// a small header followed by a concatenation of raw LNK structures (optionally
/// grouped under category headers). The robust way to split them is to scan for
/// the 20-byte ShellLinkHeader signature (HeaderSize 0x0000004C + the LinkCLSID
/// `00021401-0000-0000-C000-000000000046`); each occurrence starts one LNK and
/// the next occurrence (or EOF) bounds it. Each carved blob is a standalone LNK
/// that `lnkinfo` parses unchanged (trailing bytes are ignored by the parser).
public nonisolated enum ShellLinkCarver {
    /// HeaderSize (4C 00 00 00) + LinkCLSID, little-endian as stored on disk.
    static let signature: [UInt8] = [
        0x4C, 0x00, 0x00, 0x00,
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ]

    /// Return each embedded LNK blob, in file order.
    public static func carve(_ bytes: [UInt8]) -> [[UInt8]] {
        let starts = signatureOffsets(in: bytes)
        guard !starts.isEmpty else { return [] }
        var blobs: [[UInt8]] = []
        for (idx, start) in starts.enumerated() {
            let end = idx + 1 < starts.count ? starts[idx + 1] : bytes.count
            if end > start { blobs.append(Array(bytes[start..<end])) }
        }
        return blobs
    }

    static func signatureOffsets(in bytes: [UInt8]) -> [Int] {
        let sig = signature
        guard bytes.count >= sig.count else { return [] }
        var offsets: [Int] = []
        var i = 0
        let last = bytes.count - sig.count
        while i <= last {
            if bytes[i] == sig[0], Array(bytes[i..<i + sig.count]) == sig {
                offsets.append(i)
                i += sig.count   // LNKs are far longer than the signature; skip past it
            } else {
                i += 1
            }
        }
        return offsets
    }
}
