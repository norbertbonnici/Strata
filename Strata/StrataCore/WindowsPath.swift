import Foundation

/// Path helpers for Windows-style paths embedded in evidence (event-log
/// `Image`/`ParentImage`, registry values, prefetch, …). These arrive with
/// **backslash** separators (`C:\Windows\System32\cmd.exe`).
///
/// `NSString.lastPathComponent` splits on `/` **only** — on macOS/iOS a
/// backslash is an ordinary character — so calling it on a Windows path returns
/// the whole string unchanged, silently defeating any basename equality check
/// (e.g. parent/child process matching). Use `WindowsPath.basename` instead,
/// which honours both `\` and `/`.
public nonisolated enum WindowsPath {
    /// The final path component, splitting on both `\` and `/`. Trailing
    /// separators are ignored; a path with no separator returns unchanged.
    public static func basename(_ path: String) -> String {
        let parts = path.split(whereSeparator: { $0 == "\\" || $0 == "/" })
        return parts.last.map(String.init) ?? path
    }

    /// `basename(_:)` lowercased — the common form for case-insensitive
    /// executable-name comparison.
    public static func basenameLower(_ path: String) -> String {
        basename(path).lowercased()
    }
}
