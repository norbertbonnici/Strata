import Foundation

/// One NTFS `$MFT` record, reconstructed from raw bytes.
///
/// The MFT is the heart of an NTFS volume: one ~1 KB record per file/directory.
/// Strata's value-add over the TSK file tree (which only exposes the visible
/// `$STANDARD_INFORMATION` timestamps) is that the raw record also carries the
/// **`$FILE_NAME` timestamps** — a *separate*, second MACB set that the public
/// `SetFileTime`/timestomping APIs do **not** touch. Comparing `$SI` against
/// `$FN` is the canonical way to spot **timestomping** (T1070.006).
///
/// Timestamps are kept as raw FILETIME ticks (`UInt64`) so the full 100-ns
/// precision survives — see `FileTime`. For small files NTFS stores the file
/// content **resident** inside the record itself; `residentData` captures it, so
/// such files are recoverable straight from the `$MFT` with no volume access.
public nonisolated struct MftEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    public let recordNumber: UInt64
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
    /// Volume label this record's `$MFT` belongs to — top level of the tree view.
    public let volume: String

    // $STANDARD_INFORMATION — the "visible" MACB (raw FILETIME ticks; 0 = unset).
    public let siCreatedRaw: UInt64
    public let siModifiedRaw: UInt64
    public let siChangedRaw: UInt64       // MFT entry modified (C)
    public let siAccessedRaw: UInt64
    // $FILE_NAME — the "hidden" MACB (not touched by the timestomp API).
    public let fnCreatedRaw: UInt64
    public let fnModifiedRaw: UInt64
    public let fnChangedRaw: UInt64
    public let fnAccessedRaw: UInt64

    /// Logical file size from `$FN`.
    public let size: Int64?
    /// Resident `$DATA` bytes — the entire file content for a small (resident)
    /// file, recoverable without touching the volume. nil if non-resident.
    public let residentData: Data?
    /// Source `$MFT` path.
    public let sourceFile: String

    public init(id: UUID = UUID(), recordNumber: UInt64, sequence: UInt16,
                inUse: Bool, isDirectory: Bool, fileName: String?, fullPath: String?,
                parentRecord: UInt64?, volume: String = "$MFT",
                siCreatedRaw: UInt64 = 0, siModifiedRaw: UInt64 = 0,
                siChangedRaw: UInt64 = 0, siAccessedRaw: UInt64 = 0,
                fnCreatedRaw: UInt64 = 0, fnModifiedRaw: UInt64 = 0,
                fnChangedRaw: UInt64 = 0, fnAccessedRaw: UInt64 = 0,
                size: Int64?, residentData: Data? = nil, sourceFile: String) {
        self.id = id
        self.recordNumber = recordNumber
        self.sequence = sequence
        self.inUse = inUse
        self.isDirectory = isDirectory
        self.fileName = fileName
        self.fullPath = fullPath
        self.parentRecord = parentRecord
        self.volume = volume
        self.siCreatedRaw = siCreatedRaw; self.siModifiedRaw = siModifiedRaw
        self.siChangedRaw = siChangedRaw; self.siAccessedRaw = siAccessedRaw
        self.fnCreatedRaw = fnCreatedRaw; self.fnModifiedRaw = fnModifiedRaw
        self.fnChangedRaw = fnChangedRaw; self.fnAccessedRaw = fnAccessedRaw
        self.size = size
        self.residentData = residentData
        self.sourceFile = sourceFile
    }

    // MARK: - Lossy Date accessors (timeline / analyzer / sorting)

    public var siCreated: Date? { FileTime.date(siCreatedRaw) }
    public var siModified: Date? { FileTime.date(siModifiedRaw) }
    public var siChanged: Date? { FileTime.date(siChangedRaw) }
    public var siAccessed: Date? { FileTime.date(siAccessedRaw) }
    public var fnCreated: Date? { FileTime.date(fnCreatedRaw) }
    public var fnModified: Date? { FileTime.date(fnModifiedRaw) }
    public var fnChanged: Date? { FileTime.date(fnChangedRaw) }
    public var fnAccessed: Date? { FileTime.date(fnAccessedRaw) }

    // MARK: - Display

    public var fileExtension: String {
        guard let fileName else { return "" }
        return (fileName as NSString).pathExtension.lowercased()
    }
    public var displayPath: String { fullPath ?? fileName ?? "MFT #\(recordNumber)" }
    public var hasResidentData: Bool { (residentData?.isEmpty == false) }

    // MARK: - Timestomping signals (raw-exact; unit-tested)

    /// 100-ns ticks in one second — `$SI` must predate `$FN` by more than this
    /// to count (excludes clock skew).
    private static let toleranceTicks: UInt64 = 10_000_000

    /// True when `$SI` creation meaningfully predates `$FN` creation — the
    /// high-confidence timestomp signal (the visible creation time rolled back
    /// below the un-settable `$FN` time).
    public var siCreatedPredatesFn: Bool {
        guard siCreatedRaw != 0, fnCreatedRaw != 0 else { return false }
        // Subtraction (guarded by the `<` short-circuit) rather than
        // `siCreatedRaw + toleranceTicks`, whose addition would trap on a crafted
        // record with a near-`UInt64.max` $SI value.
        return siCreatedRaw < fnCreatedRaw && fnCreatedRaw - siCreatedRaw > Self.toleranceTicks
    }

    /// True when both `$SI` created and modified are whole-second (zero 100-ns
    /// sub-second) — the timestomp-tool fingerprint.
    public var siHasZeroedSubseconds: Bool {
        FileTime.isWholeSecond(siCreatedRaw) && FileTime.isWholeSecond(siModifiedRaw)
    }
}
