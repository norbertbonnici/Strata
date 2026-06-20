import Foundation

/// A file's **download provenance** — recovered from the
/// `com.apple.metadata:kMDItemWhereFroms` extended attribute Spotlight writes on
/// downloaded files. The xattr is a binary-plist array of strings, conventionally
/// `[download URL, referrer URL]`. This survives even when the
/// `com.apple.quarantine` flag has been stripped, so it complements the
/// quarantine store as a record of *where a file came from*.
///
/// Pure / `Sendable` / `Codable`. `WhereFromsParser` decodes the xattr bytes;
/// the macOS-only ingest reads them via `fsapfscat -x` (libfsapfs).
public nonisolated struct MacWhereFrom: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// The file the attribute was read from.
    public let path: String
    /// The where-from list (download URL first, referrer next, when present).
    public let urls: [String]
    public let scope: String

    public init(id: UUID = UUID(), path: String, urls: [String], scope: String) {
        self.id = id
        self.path = path
        self.urls = urls
        self.scope = scope
    }

    public var downloadURL: String? { urls.first }
    public var referrerURL: String? { urls.count > 1 ? urls[1] : nil }

    public var fileName: String { (path as NSString).lastPathComponent }

    /// Host of the download URL, lowercased (for display / matching).
    public var downloadHost: String? { Self.host(of: downloadURL) }

    /// Extract the host component from a URL string without requiring a valid
    /// `URL` (where-from values are occasionally malformed). Cuts the authority
    /// first (so an `@`/`:` in the path or query can't mangle the host), strips
    /// userinfo at the *last* `@`, and unwraps an IPv6 `[…]` literal.
    public static func host(of urlString: String?) -> String? {
        guard var s = urlString?.lowercased() else { return nil }
        if let range = s.range(of: "://") { s = String(s[range.upperBound...]) }
        // Authority ends at the first path / query / fragment delimiter.
        var authority = s.prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        // Userinfo ends at the last '@' within the authority.
        if let at = authority.lastIndex(of: "@") {
            authority = authority[authority.index(after: at)...]
        }
        let host: Substring
        if authority.first == "[" {                       // IPv6 literal
            if let close = authority.firstIndex(of: "]") {
                host = authority[authority.index(after: authority.startIndex)..<close]
            } else {
                host = authority.dropFirst()
            }
        } else {
            host = authority.prefix { $0 != ":" }          // drop the port
        }
        return host.isEmpty ? nil : String(host)
    }
}
