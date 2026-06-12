import Foundation

/// One row of a TSK-style **bodyfile** (the `mactime` format). Strata uses it as
/// the bridge for **APFS (macOS)** evidence: The Sleuth Kit crashes on real APFS,
/// so the macOS ingest path runs libyal's `fsapfsinfo -E all -B` to emit a
/// bodyfile, which this decodes into the file tree + MACB timeline.
///
/// The line layout (libfsapfs writes the canonical 11 pipe-delimited fields,
/// with **nanosecond** timestamps as `<seconds>.<9-digit ns>`):
///
/// ```
/// MD5 | name[ -> symlink] | inode | mode(drwxr-xr-x) | UID | GID | size | atime | mtime | ctime | crtime
/// ```
public nonisolated struct BodyfileEntry: Identifiable, Hashable, Sendable {
    public let id: UUID
    /// MD5 of the file content, or "0" when not computed (the default).
    public let md5: String
    /// Full path of the entry (symlink target stripped into `symlinkTarget`).
    public let path: String
    /// The symlink target, when the entry is a symlink (`name -> target`).
    public let symlinkTarget: String?
    /// Filesystem inode / object identifier.
    public let inode: UInt64
    /// The `ls -l`-style mode string, e.g. `drwxr-xr-x` (index 0 encodes type).
    public let mode: String
    public let uid: UInt32
    public let gid: UInt32
    public let size: Int64
    public let accessed: Date?
    public let modified: Date?
    public let changed: Date?     // inode-change time (ctime)
    public let created: Date?     // crtime / birth time

    public init(id: UUID = UUID(), md5: String, path: String, symlinkTarget: String?,
                inode: UInt64, mode: String, uid: UInt32, gid: UInt32, size: Int64,
                accessed: Date?, modified: Date?, changed: Date?, created: Date?) {
        self.id = id
        self.md5 = md5
        self.path = path
        self.symlinkTarget = symlinkTarget
        self.inode = inode
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.size = size
        self.accessed = accessed
        self.modified = modified
        self.changed = changed
        self.created = created
    }

    /// True when the mode string marks a directory (`d…`).
    public var isDirectory: Bool { mode.first == "d" }
    /// True for a symbolic link (`l…`).
    public var isSymlink: Bool { mode.first == "l" }
    /// Leaf name of the path.
    public var name: String { (path as NSString).lastPathComponent }
}

/// Pure parser for the TSK `mactime` bodyfile format (as emitted by
/// `fsapfsinfo -B`). No I/O; the caller supplies the text.
public nonisolated enum BodyfileParser {

    /// Parse a whole bodyfile. Blank lines and `#` comments are skipped; a
    /// malformed line is dropped rather than aborting the parse.
    public static func parse(_ text: String) -> [BodyfileEntry] {
        text.split(separator: "\n", omittingEmptySubsequences: true).compactMap {
            parseLine(String($0))
        }
    }

    /// Parse one bodyfile line. Returns nil for blank/comment/malformed lines.
    ///
    /// The name field can itself contain `|` (paths aren't pipe-escaped), so we
    /// anchor on the **9 fixed trailing fields** and treat everything between the
    /// MD5 and those as the name.
    public static func parseLine(_ line: String) -> BodyfileEntry? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }

        let parts = trimmed.components(separatedBy: "|")
        guard parts.count >= 11 else { return nil }

        let md5 = parts[0]
        let tailStart = parts.count - 9          // inode is the first trailing field
        let nameField = parts[1..<tailStart].joined(separator: "|")
        let tail = Array(parts[tailStart...])     // exactly 9 fields

        guard let inode = UInt64(tail[0]) else { return nil }
        let mode = tail[1]
        let uid = UInt32(tail[2]) ?? 0
        let gid = UInt32(tail[3]) ?? 0
        let size = Int64(tail[4]) ?? 0

        // Split a symlink "name -> target" into path + target.
        let path: String
        let symlinkTarget: String?
        if let range = nameField.range(of: " -> ") {
            path = String(nameField[..<range.lowerBound])
            symlinkTarget = String(nameField[range.upperBound...])
        } else {
            path = nameField
            symlinkTarget = nil
        }

        return BodyfileEntry(
            md5: md5, path: path, symlinkTarget: symlinkTarget,
            inode: inode, mode: mode, uid: uid, gid: gid, size: size,
            accessed: time(tail[5]), modified: time(tail[6]),
            changed: time(tail[7]), created: time(tail[8]))
    }

    /// Parse a bodyfile timestamp: integer seconds, or `<seconds>.<nanoseconds>`
    /// (libfsapfs' nanosecond precision). `0` / non-positive ⇒ nil ("not set").
    static func time(_ field: String) -> Date? {
        let dot = field.firstIndex(of: ".")
        let secPart = dot.map { String(field[..<$0]) } ?? field
        guard let seconds = Int64(secPart), seconds > 0 else { return nil }
        var fractional = 0.0
        if let dot {
            let nsPart = field[field.index(after: dot)...]
            // Right-pad/truncate to 9 digits, then scale to seconds.
            let digits = nsPart.prefix(9)
            if let ns = Double(digits) {
                fractional = ns / pow(10.0, Double(digits.count))
            }
        }
        return Date(timeIntervalSince1970: Double(seconds) + fractional)
    }
}
