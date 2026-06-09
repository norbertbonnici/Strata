import Foundation

/// One NTFS `$MFT` record, reconstructed from raw bytes.
///
/// The MFT is the heart of an NTFS volume: one ~1 KB record per file/directory.
/// Strata's value-add over the TSK file tree (which only exposes the visible
/// `$STANDARD_INFORMATION` timestamps) is that the raw record also carries the
/// **`$FILE_NAME` timestamps** — a *separate*, second MACB set that the public
/// `SetFileTime`/timestomping APIs do **not** touch. Comparing `$SI` against
/// `$FN` is the canonical way to spot **timestomping** (T1070.006): a backdated
/// `$SI` creation time that predates its own `$FN` creation is physically
/// impossible on a clean system.
///
/// For loose (KAPE) collections — which otherwise fall back to collection-host
/// timestamps — a collected `$MFT` restores true on-disk NTFS times.
public nonisolated struct MftEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// MFT record (entry) number.
    public let recordNumber: UInt64
    /// Record sequence number (distinguishes a reused MFT slot).
    public let sequence: UInt16
    /// Allocated (in use) vs unallocated (deleted) — header flag 0x01.
    public let inUse: Bool
    /// Directory — header flag 0x02.
    public let isDirectory: Bool
    /// Best `$FILE_NAME` (Win32 namespace preferred over DOS 8.3), if present.
    public let fileName: String?
    /// Full path resolved by walking `$FN` parent references; nil if unresolved.
    public let fullPath: String?
    /// Parent directory's MFT record number (from `$FN`).
    public let parentRecord: UInt64?

    // $STANDARD_INFORMATION — the "visible" MACB (settable via the timestomp API).
    public let siCreated: Date?
    public let siModified: Date?
    public let siChanged: Date?    // MFT entry modified (C)
    public let siAccessed: Date?
    // $FILE_NAME — the "hidden" MACB (not touched by the timestomp API).
    public let fnCreated: Date?
    public let fnModified: Date?
    public let fnChanged: Date?
    public let fnAccessed: Date?

    /// Logical file size from `$FN` (`$DATA` real size isn't parsed here).
    public let size: Int64?
    /// Source `$MFT` path.
    public let sourceFile: String

    public init(id: UUID = UUID(), recordNumber: UInt64, sequence: UInt16,
                inUse: Bool, isDirectory: Bool, fileName: String?, fullPath: String?,
                parentRecord: UInt64?,
                siCreated: Date?, siModified: Date?, siChanged: Date?, siAccessed: Date?,
                fnCreated: Date?, fnModified: Date?, fnChanged: Date?, fnAccessed: Date?,
                size: Int64?, sourceFile: String) {
        self.id = id
        self.recordNumber = recordNumber
        self.sequence = sequence
        self.inUse = inUse
        self.isDirectory = isDirectory
        self.fileName = fileName
        self.fullPath = fullPath
        self.parentRecord = parentRecord
        self.siCreated = siCreated; self.siModified = siModified
        self.siChanged = siChanged; self.siAccessed = siAccessed
        self.fnCreated = fnCreated; self.fnModified = fnModified
        self.fnChanged = fnChanged; self.fnAccessed = fnAccessed
        self.size = size
        self.sourceFile = sourceFile
    }

    /// Leaf-name extension (lowercased), for analyzer gating.
    public var fileExtension: String {
        guard let fileName else { return "" }
        return (fileName as NSString).pathExtension.lowercased()
    }

    /// Display path, falling back to the leaf name then a record label.
    public var displayPath: String {
        fullPath ?? fileName ?? "MFT #\(recordNumber)"
    }

    // MARK: - Timestomping signals (pure; unit-tested)

    /// Tolerance (seconds) below which a `$SI`-before-`$FN` gap is treated as
    /// clock skew rather than a backdate.
    public static let timestompTolerance: TimeInterval = 1

    /// True when the `$SI` creation time meaningfully predates the `$FN`
    /// creation time — the high-confidence timestomping signal (the visible
    /// creation time was rolled back below the un-settable `$FN` time).
    public var siCreatedPredatesFn: Bool {
        guard let si = siCreated, let fn = fnCreated else { return false }
        return si < fn.addingTimeInterval(-Self.timestompTolerance)
    }

    /// True when both `$SI` created and modified are whole-second values (zero
    /// 100-ns sub-second) — a fingerprint of timestomp tools that write
    /// second-granularity times, where real NTFS times carry sub-second noise.
    public var siHasZeroedSubseconds: Bool {
        func wholeSecond(_ d: Date?) -> Bool {
            guard let d else { return false }
            return d.timeIntervalSince1970.truncatingRemainder(dividingBy: 1) == 0
        }
        return wholeSecond(siCreated) && wholeSecond(siModified)
    }
}
