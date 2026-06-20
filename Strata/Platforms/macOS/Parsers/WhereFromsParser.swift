import Foundation

/// Decodes the `com.apple.metadata:kMDItemWhereFroms` extended-attribute bytes —
/// a binary-plist array of URL strings — into a `MacWhereFrom`. Pure /
/// cross-platform (the bytes are supplied by the macOS-only `fsapfscat -x`
/// extraction path).
public nonisolated enum WhereFromsParser {

    public static func parse(_ data: Data, path: String, scope: String) -> MacWhereFrom? {
        guard let root = BinaryPlist.parse(data), let array = root.arrayValue else { return nil }
        let urls = array
            .compactMap { $0.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !urls.isEmpty else { return nil }
        return MacWhereFrom(path: path, urls: urls, scope: scope)
    }
}
