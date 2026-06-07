import Foundation

/// Tree node built from the flat `RegistryValue` set, for the registry
/// explorer's OutlineGroup — the registry analogue of `FileNode`. Pure,
/// `nonisolated` + `Sendable` so the (deterministic) builder can run off the
/// main actor.
///
/// A node is a registry **key**: it owns child keys (`children`) and the
/// values that live directly in that key (`values`). The top level is one
/// node per hive (SYSTEM / SOFTWARE / NTUSER …), mirroring how
/// `FileNode.buildTree` makes one node per volume so same-named subkeys under
/// different hives never look like duplicates.
public nonisolated struct RegistryNode: Identifiable, Sendable {
    public let id: String                  // "hive:SYSTEM" or full key path incl. hive
    public let name: String                // hive name, or last key component
    public var children: [RegistryNode]?
    public var values: [RegistryValue]     // values directly in this key, sorted by name
    public var lastWritten: Date?          // key's last-written time (from its values)
    public var isHive: Bool

    public init(id: String, name: String, children: [RegistryNode]? = nil,
                values: [RegistryValue] = [], lastWritten: Date? = nil,
                isHive: Bool = false) {
        self.id = id; self.name = name; self.children = children
        self.values = values; self.lastWritten = lastWritten; self.isHive = isHive
    }

    /// Full key path for display, e.g. "SOFTWARE\Microsoft\Windows". The hive
    /// node's id is "hive:<name>", so strip that prefix; key nodes already
    /// carry the full path as their id.
    public var displayPath: String {
        isHive ? name : id
    }

    /// Conventional hive ordering so the tree reads the way an analyst expects
    /// (the machine hives first, then user hives); anything unlisted sorts
    /// after, alphabetically.
    private static let hiveOrder: [String: Int] = [
        "SYSTEM": 0, "SOFTWARE": 1, "SAM": 2, "SECURITY": 3,
        "NTUSER": 4, "USRCLASS": 5,
    ]

    /// Build the registry tree from the flat, already-parsed value set.
    /// One top-level node per hive; within a hive, the backslash-delimited key
    /// path becomes a merged subtree with values hung off their leaf key.
    public static func buildTree(from values: [RegistryValue]) -> [RegistryNode] {
        // Group by hive label, like FileNode groups by volume.
        // NOTE (v1 limitation): hives sharing a label — e.g. several users'
        // NTUSER — merge under one node here, because `hive` is a logical
        // label, not a per-file identity. Per-user disambiguation is future work.
        var byHive: [String: [RegistryValue]] = [:]
        for v in values { byHive[v.hive, default: []].append(v) }

        return byHive.keys
            .sorted {
                let a = hiveOrder[$0.uppercased()] ?? Int.max
                let b = hiveOrder[$1.uppercased()] ?? Int.max
                return (a, $0) < (b, $1)            // conventional order, then alpha
            }
            .map { hive in buildHive(hive, values: byHive[hive] ?? []) }
    }

    /// Mutable accumulator mirroring `FileNode.buildSubtree`'s `Box`: merge key
    /// components by name so a shared prefix yields a shared subtree.
    private final class Box {
        var node: RegistryNode
        var kids: [String: Box] = [:]
        var values: [RegistryValue] = []
        init(_ n: RegistryNode) { node = n }
    }

    private static func buildHive(_ hive: String, values: [RegistryValue]) -> RegistryNode {
        let root = Box(RegistryNode(id: "hive:\(hive)", name: hive, isHive: true))

        for value in values {
            // `path` is backslash-delimited with a leading "\"; drop the empty
            // components the same way FileNode drops "/" path components.
            let components = value.path
                .components(separatedBy: "\\")
                .filter { !$0.isEmpty }
            var cursor = root
            var path = hive
            for comp in components {
                path += "\\" + comp
                if let existing = cursor.kids[comp] {
                    cursor = existing
                } else {
                    let box = Box(RegistryNode(id: path, name: comp))
                    cursor.kids[comp] = box
                    cursor = box
                }
            }
            // Empty path → value lives at the hive root; it attaches to `root`.
            cursor.values.append(value)
        }

        func materialize(_ box: Box) -> RegistryNode {
            var node = box.node
            node.values = box.values
                .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            // Key's last-written: libregf stamps it per key, so every value in a
            // key carries the same time — take the first non-nil. Intermediate
            // path-only keys hold no value and so have no last-written (v1 limit).
            node.lastWritten = box.values.compactMap(\.lastWritten).first
            if !box.kids.isEmpty {
                node.children = box.kids.values.map(materialize)
                    .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            }
            return node
        }
        return materialize(root)
    }
}

// MARK: - Value display / decoding (pure, shared by macOS + iOS, unit-tested)

public extension RegistryValue {
    /// Short type label for a value-row badge, e.g. REG_SZ → "SZ".
    var typeBadge: String {
        switch type {
        case .sz:             return "SZ"
        case .expandSz:       return "EXPAND_SZ"
        case .binary:         return "BINARY"
        case .dword:          return "DWORD"
        case .dwordBigEndian: return "DWORD_BE"
        case .multiSz:        return "MULTI_SZ"
        case .qword:          return "QWORD"
        case .none:           return "NONE"
        case .other:          return "OTHER"
        }
    }

    /// Presentation-formatted value data. The parser already string-renders
    /// `data` (binary arrives as a hex string, see RegistryHiveParser), so
    /// this formats for readability rather than re-parsing raw bytes:
    /// - DWORD / QWORD  → "<decimal> (0x<HEX>)"
    /// - BINARY / NONE / OTHER → space-grouped hex bytes
    /// - SZ / EXPAND_SZ / MULTI_SZ → the raw string unchanged
    var decodedData: String {
        switch type {
        case .dword, .dwordBigEndian, .qword:
            return Self.formatInteger(data)
        case .binary, .none, .other:
            return Self.formatHex(data)
        default:
            return data
        }
    }

    /// Case-insensitive search predicate over the value's name, key path, and
    /// data — the registry explorer's filter. An empty/blank query matches all.
    func matches(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return true }
        return name.localizedCaseInsensitiveContains(q)
            || path.localizedCaseInsensitiveContains(q)
            || data.localizedCaseInsensitiveContains(q)
    }

    /// Render an integer value as "<decimal> (0x<HEX>)". libregf may print the
    /// DWORD/QWORD in decimal or (0x-prefixed) hex; accept either and fall back
    /// to the raw string when it doesn't parse as a number.
    private static func formatInteger(_ raw: String) -> String {
        let s = raw.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return raw }
        let parsed: UInt64?
        if s.lowercased().hasPrefix("0x") {
            parsed = UInt64(s.dropFirst(2), radix: 16)
        } else {
            // Prefer decimal; only treat as hex when decimal can't represent it
            // (i.e. it contains a–f digits).
            parsed = UInt64(s) ?? UInt64(s, radix: 16)
        }
        guard let v = parsed else { return raw }
        return "\(v) (0x\(String(v, radix: 16, uppercase: true)))"
    }

    /// Group a contiguous hex string ("123456789abc") into space-separated
    /// upper-case byte pairs ("12 34 56 78 9A BC") for a readable preview.
    private static func formatHex(_ raw: String) -> String {
        let hex = raw.filter(\.isHexDigit)
        guard !hex.isEmpty else { return raw }
        var bytes: [String] = []
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let end = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            bytes.append(String(hex[idx..<end]).uppercased())
            idx = end
        }
        return bytes.joined(separator: " ")
    }
}
