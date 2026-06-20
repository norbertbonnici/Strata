import Foundation

/// One destination from a Windows **JumpList** - the recent/pinned items Windows
/// keeps per-application (right-click an app on the taskbar).
///
/// JumpLists are high value in DFIR: they record, per application, the files a
/// user opened with a **true last-access timestamp** and an access count, and -
/// for the Remote Desktop (`mstsc`) jumplist - the **remote hosts** a user
/// connected to, which directly attributes lateral movement. They live in
/// `%APPDATA%\Microsoft\Windows\Recent\`:
///  - `AutomaticDestinations\<AppID>.automaticDestinations-ms` - an OLE compound
///    file whose numbered streams are embedded shortcuts (LNK) and whose
///    `DestList` stream is an MRU index (access time / count / host / pin).
///  - `CustomDestinations\<AppID>.customDestinations-ms` - a flat sequence of
///    embedded LNKs (app-curated tasks/pinned items; no DestList).
///
/// The `<AppID>` filename prefix is a (non-reversible) hash of the launching
/// application; `application` is a best-effort lookup, with the raw `appID`
/// always retained.
public nonisolated struct JumpListEntry: Identifiable, Hashable, Sendable, Codable {
    public enum ListType: String, Sendable, Codable {
        case automatic   // *.automaticDestinations-ms (OLE; has DestList MRU)
        case custom      // *.customDestinations-ms (flat LNK sequence)
    }

    public let id: UUID
    /// 16-hex filename prefix identifying the source application.
    public let appID: String
    /// Resolved application name, when the AppID is known.
    public let application: String?
    public let listType: ListType
    /// DestList entry number (also the OLE stream's hex name); nil for custom lists.
    public let entryID: Int?
    /// Target path from the embedded LNK.
    public let targetPath: String?
    /// Command-line arguments from the embedded LNK.
    public let arguments: String?
    /// Last time this destination was opened (DestList FILETIME). The single
    /// highest-value field - a real per-target user-activity timestamp.
    public let lastAccessed: Date?
    /// DestList interaction/access count, when present.
    public let accessCount: Int?
    /// NetBIOS hostname of the machine that recorded the access (DestList).
    public let hostname: String?
    /// Whether the destination is pinned.
    public let pinned: Bool?
    /// Source `*.automaticDestinations-ms` / `*.customDestinations-ms` path.
    public let sourceFile: String

    public init(id: UUID = UUID(), appID: String, application: String? = nil,
                listType: ListType, entryID: Int? = nil, targetPath: String? = nil,
                arguments: String? = nil, lastAccessed: Date? = nil, accessCount: Int? = nil,
                hostname: String? = nil, pinned: Bool? = nil, sourceFile: String) {
        self.id = id
        self.appID = appID
        self.application = application
        self.listType = listType
        self.entryID = entryID
        self.targetPath = targetPath
        self.arguments = arguments
        self.lastAccessed = lastAccessed
        self.accessCount = accessCount
        self.hostname = hostname
        self.pinned = pinned
        self.sourceFile = sourceFile
    }

    /// Display name: the target's last path component, else the app, else AppID.
    public var name: String {
        if let t = targetPath, let last = t.split(whereSeparator: { $0 == "\\" || $0 == "/" }).last {
            return String(last)
        }
        return application ?? appID
    }
}
