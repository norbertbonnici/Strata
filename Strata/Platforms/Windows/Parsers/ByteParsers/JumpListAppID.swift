import Foundation

/// Resolves a JumpList **AppID** (the 16-hex filename prefix) to a human
/// application name. The AppID is a non-reversible hash of the launching
/// application's path, so identification is by lookup table - best-effort, and
/// the raw AppID is always retained alongside the resolved name.
///
/// Curated to the highest-signal / most reliable entries; published tables
/// disagree on some values, so this errs toward well-attested ones (Explorer,
/// the interpreters, Office, browsers, and - forensically key - the Remote
/// Desktop / `mstsc` AppID, which makes the RDP jumplist a lateral-movement
/// goldmine).
public nonisolated enum JumpListAppID {
    /// The Remote Desktop Client AppID. Entries in this jumplist are the remote
    /// hosts a user connected to - prime lateral-movement evidence.
    public static let remoteDesktop = "ebbc7bd0eff5b9e8"

    public static let table: [String: String] = [
        "1b4dd67f29cb1962": "Windows Explorer (Win7)",
        "f01b4d95cf55d32a": "Windows Explorer (Win8.1)",
        "5f7b5f1e01b83767": "Quick Access / Explorer (Win10)",
        "9b9cdc69c1c24e2b": "Notepad",
        "918e0ecb43d17e23": "Notepad (Win10)",
        "ebbc7bd0eff5b9e8": "Remote Desktop (mstsc)",
        "969252ce11249fdd": "Command Prompt (cmd.exe)",
        "b91050d8b077a4e8": "WinRAR",
        "d4ed642e04dde62e": "7-Zip",
        "adecfb853d77462a": "Microsoft Word 2010",
        "a7bd71699cd38d1c": "Microsoft Word 2013",
        "6824f4a902c78fbd": "Microsoft Word 2016/365",
        "9839aec31243a928": "Microsoft Excel 2010",
        "ca2076cebfc8c1d6": "WordPad",
        "7e4dca80246863e3": "Control Panel",
        "5d696d521de238c3": "Google Chrome",
        "9d1f905ce5044aee": "Mozilla Firefox",
        "c69e2727067e10d0": "Microsoft Edge",
        "12dc1ea8e34b5a6":  "Internet Explorer 8",
        "28c8b86deab549a1": "Internet Explorer",
    ]

    /// Resolve the application name for an AppID (case-insensitive); nil if unknown.
    public static func application(for appID: String) -> String? {
        table[appID.lowercased()]
    }

    /// Extract the AppID from a jumplist filename like
    /// "5f7b5f1e01b83767.automaticDestinations-ms".
    public static func appID(fromFilename name: String) -> String {
        String(name.split(separator: ".").first ?? Substring(name)).lowercased()
    }
}
