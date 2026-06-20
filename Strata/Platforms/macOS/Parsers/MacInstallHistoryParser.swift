import Foundation

#if os(macOS)

/// Parses macOS software-install records into `[MacInstallEntry]`:
/// - `/Library/Receipts/InstallHistory.plist` — an **array** of install events
///   (displayName / date / displayVersion / processName / packageIdentifiers /
///   contentType).
/// - PackageKit receipts `/private/var/db/receipts/<id>.plist` — one **dict**
///   per installed package (PackageIdentifier / InstallDate / InstallProcessName
///   / PackageFileName / InstallPrefixPath / PackageVersion).
///
/// Pure (the caller hands it already-read `Data`); `PropertyListSerialization`
/// decodes both the XML and binary encodings.
public nonisolated enum MacInstallHistoryParser {

    public static func parse(_ data: Data, sourceFile: String, scope: String) -> [MacInstallEntry] {
        let base = (sourceFile.lowercased() as NSString).lastPathComponent
        if base == "installhistory.plist" { return installHistory(data, sourceFile, scope) }
        return receipt(data, sourceFile, scope)
    }

    /// InstallHistory.plist — an array of event dicts.
    private static func installHistory(_ data: Data, _ src: String, _ scope: String) -> [MacInstallEntry] {
        guard let array = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil))
            as? [[String: Any]] else { return [] }
        return array.map { d in
            MacInstallEntry(
                displayName: d["displayName"] as? String,
                packageIdentifiers: (d["packageIdentifiers"] as? [String]) ?? [],
                version: d["displayVersion"] as? String,
                date: d["date"] as? Date,
                processName: d["processName"] as? String,
                contentType: d["contentType"] as? String,
                source: .installHistory, scope: scope, sourceFile: src)
        }
    }

    /// A single PackageKit receipt dict.
    private static func receipt(_ data: Data, _ src: String, _ scope: String) -> [MacInstallEntry] {
        guard let d = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil))
            as? [String: Any] else { return [] }
        let pkgID = d["PackageIdentifier"] as? String
        // A receipt with no identifier is almost certainly not a PackageKit receipt.
        guard pkgID != nil || d["PackageFileName"] != nil else { return [] }
        return [MacInstallEntry(
            packageIdentifiers: pkgID.map { [$0] } ?? [],
            version: d["PackageVersion"] as? String,
            date: d["InstallDate"] as? Date,
            processName: d["InstallProcessName"] as? String,
            packageFile: d["PackageFileName"] as? String,
            installPrefix: d["InstallPrefixPath"] as? String,
            source: .receipt, scope: scope, sourceFile: src)]
    }
}

#endif
