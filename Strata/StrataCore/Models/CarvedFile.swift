import Foundation

/// A file recovered by **signature carving** — found by its magic header in raw
/// image bytes, independent of the filesystem. This recovers content that the
/// allocated-metadata walk misses: deleted files in unallocated space, and (on
/// macOS) files libfsapfs won't surface through the volume layer — sealed System
/// snapshot files and locked FileVault volumes — because carving reads the raw
/// bytes directly rather than going through the APFS parser.
///
/// A carved entry is a *descriptor* (type + byte offset + length). The bytes are
/// re-read on demand from the source image, so a case doesn't store a copy of
/// every recovered file.
public nonisolated struct CarvedFile: Identifiable, Hashable, Sendable, Codable {
    /// Recoverable file types, chosen for macOS triage value + low false-positive
    /// magic. `sqlite` covers the high-value stores (browser history, TCC,
    /// KnowledgeC, quarantine, Messages `chat.db`).
    public enum Kind: String, CaseIterable, Sendable, Codable {
        case sqlite, bplist, png, jpeg, pdf, zip, gzip

        public var label: String {
            switch self {
            case .sqlite: return "SQLite database"
            case .bplist: return "Binary property list"
            case .png:    return "PNG image"
            case .jpeg:   return "JPEG image"
            case .pdf:    return "PDF document"
            case .zip:    return "ZIP archive"
            case .gzip:   return "gzip stream"
            }
        }

        /// Default file extension for a recovered file.
        public var ext: String {
            switch self {
            case .sqlite: return "sqlite"
            case .bplist: return "plist"
            case .png:    return "png"
            case .jpeg:   return "jpg"
            case .pdf:    return "pdf"
            case .zip:    return "zip"
            case .gzip:   return "gz"
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    /// Byte offset of the magic header in the source image.
    public let offset: Int64
    /// Recovered length in bytes.
    public let size: Int64
    /// True when `size` came from a header field or footer (SQLite/PNG/JPEG/PDF/
    /// ZIP); false when it was capped because the format has no recoverable
    /// length (bplist/gzip) or the footer wasn't found before the cap.
    public let sizeExact: Bool
    /// The image the bytes were carved from (display label).
    public let source: String

    public init(id: UUID = UUID(), kind: Kind, offset: Int64, size: Int64,
                sizeExact: Bool, source: String) {
        self.id = id
        self.kind = kind
        self.offset = offset
        self.size = size
        self.sizeExact = sizeExact
        self.source = source
    }

    /// A stable display name, e.g. `sqlite@0x1a2b3c00.sqlite`.
    public var suggestedName: String {
        "carved_\(String(offset, radix: 16)).\(kind.ext)"
    }

    public var title: String {
        "\(kind.label) @ 0x\(String(offset, radix: 16))"
    }
}
