import Foundation

public extension String {
    /// A filesystem-safe **single** path component. Artifact names come straight
    /// from adversary-controlled evidence (raw `$FN` / directory-entry bytes), so
    /// a name containing `/` (or `\`, `:`, NUL) would let `appendingPathComponent`
    /// escape the per-host scratch directory — `x/../../tmp/evil` resolves outside
    /// scratch and the extracted bytes land at an attacker-chosen path (arbitrary
    /// write within the non-sandboxed app's Full Disk Access reach). Replacing the
    /// separators with `_` confines the write to one component.
    var scratchSafeComponent: String {
        String(map { ($0 == "/" || $0 == "\\" || $0 == ":" || $0 == "\0") ? "_" : $0 })
    }
}
