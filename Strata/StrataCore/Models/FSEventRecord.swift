import Foundation

/// One record from the macOS **FSEvents** store (`/.fseventsd/`), the kernel's
/// coalesced log of filesystem changes - the macOS analogue of the NTFS USN
/// change journal. Each record names a path, the (monotonic) **event ID** that
/// orders it, and a bitmask of *coalesced* change reasons (a single record can
/// carry Created + Modified + Removed if all happened to that path between
/// flushes). DLS version 2 logs add the file-system **node ID** (inode).
///
/// **No per-record timestamp.** FSEvents stores only the monotonically
/// increasing event ID, not a wall-clock time, so these records are *not*
/// spliced onto the super-timeline (the same reason the WMI carve isn't) - they
/// answer "did this path change, and how" rather than "exactly when".
///
/// Produced by `FSEventsParser`; surfaced in the **FSEvents** tab and scored by
/// `FSEventsAnalyzer`.
public nonisolated struct FSEventRecord: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// The changed path, relative to the volume root (no leading slash in the
    /// store; rendered as recorded).
    public let path: String
    /// The monotonic event ID that orders this record within the volume's
    /// FSEvents history. Not a timestamp.
    public let eventID: UInt64
    /// The coalesced change-reason bitmask (see `FSEventFlag`).
    public let flags: UInt32
    /// The file-system node ID (inode), present only in DLS v2 logs.
    public let nodeID: UInt64?
    /// The source `/.fseventsd/` log file the record came from.
    public let sourceFile: String

    public init(id: UUID = UUID(), path: String, eventID: UInt64, flags: UInt32,
                nodeID: UInt64? = nil, sourceFile: String) {
        self.id = id
        self.path = path
        self.eventID = eventID
        self.flags = flags
        self.nodeID = nodeID
        self.sourceFile = sourceFile
    }

    // MARK: - Flag decoding

    /// The decoded change-reason names, in canonical order (e.g. ["Created",
    /// "Modified"]). Empty when no known bit is set.
    public var flagNames: [String] {
        FSEventFlag.names(in: flags)
    }

    /// A "Created; Modified" style summary for display.
    public var flagSummary: String {
        let names = flagNames
        return names.isEmpty ? "—" : names.joined(separator: "; ")
    }

    public var isFile: Bool { flags & FSEventFlag.fileEvent != 0 }
    public var isFolder: Bool { flags & FSEventFlag.folderEvent != 0 || flags & FSEventFlag.folderCreated != 0 }
    public var wasCreated: Bool { flags & FSEventFlag.created != 0 }
    public var wasRemoved: Bool { flags & FSEventFlag.removed != 0 }
    public var wasRenamed: Bool { flags & FSEventFlag.renamed != 0 }
    public var wasModified: Bool { flags & FSEventFlag.modified != 0 }

    /// The leaf name of the changed path.
    public var name: String { (path as NSString).lastPathComponent }
}

/// The FSEvents record-reason bitmask constants (the values stored in each
/// record's flags field, per the de-facto `FSEventsParser` reference). These
/// are the *fseventsd log* flags, distinct from the public CoreServices
/// `FSEventStreamEventFlags`.
public nonisolated enum FSEventFlag {
    public static let folderEvent:          UInt32 = 0x00000001
    public static let mount:                UInt32 = 0x00000002
    public static let unmount:              UInt32 = 0x00000004
    public static let endOfTransaction:     UInt32 = 0x00000020
    public static let lastHardLinkRemoved:  UInt32 = 0x00000800
    public static let hardLink:             UInt32 = 0x00001000
    public static let symbolicLink:         UInt32 = 0x00004000
    public static let fileEvent:            UInt32 = 0x00008000
    public static let permissionChange:     UInt32 = 0x00010000
    public static let extendedAttrModified: UInt32 = 0x00020000
    public static let extendedAttrRemoved:  UInt32 = 0x00040000
    public static let documentRevision:     UInt32 = 0x00100000
    public static let itemCloned:           UInt32 = 0x00400000
    public static let created:              UInt32 = 0x01000000
    public static let removed:              UInt32 = 0x02000000
    public static let inodeMetaMod:         UInt32 = 0x04000000
    public static let renamed:              UInt32 = 0x08000000
    public static let modified:             UInt32 = 0x10000000
    public static let exchange:             UInt32 = 0x20000000
    public static let finderInfoMod:        UInt32 = 0x40000000
    public static let folderCreated:        UInt32 = 0x80000000

    /// Ordered (mask, name) table - matched low-to-high so summaries read
    /// type-then-action.
    static let table: [(UInt32, String)] = [
        (folderEvent, "FolderEvent"), (mount, "Mount"), (unmount, "Unmount"),
        (endOfTransaction, "EndOfTransaction"), (lastHardLinkRemoved, "LastHardLinkRemoved"),
        (hardLink, "HardLink"), (symbolicLink, "SymbolicLink"), (fileEvent, "FileEvent"),
        (permissionChange, "PermissionChange"), (extendedAttrModified, "ExtendedAttrModified"),
        (extendedAttrRemoved, "ExtendedAttrRemoved"), (documentRevision, "DocumentRevision"),
        (itemCloned, "ItemCloned"), (created, "Created"), (removed, "Removed"),
        (inodeMetaMod, "InodeMetaMod"), (renamed, "Renamed"), (modified, "Modified"),
        (exchange, "Exchange"), (finderInfoMod, "FinderInfoMod"), (folderCreated, "FolderCreated"),
    ]

    public static func names(in flags: UInt32) -> [String] {
        table.compactMap { (mask, name) in flags & mask != 0 ? name : nil }
    }
}
