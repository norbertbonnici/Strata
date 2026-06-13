import Foundation

/// One filesystem inside an evidence image (a row of TSK's `tsk_fs_info`). A
/// disk image routinely holds several - e.g. a FAT EFI System Partition plus
/// the main NTFS volume and a smaller NTFS recovery volume - each with its own
/// copy of the NTFS metadata files (`$MFT`, `$LogFile`, ...). The evidence tree
/// groups files under these so same-named volume metadata doesn't look like
/// duplicates.
public nonisolated struct VolumeInfo: Identifiable, Hashable, Sendable, Codable {
    public let id: Int64          // tsk_fs_info.obj_id (== tsk_files.fs_obj_id)
    public let fsType: String     // "NTFS", "FAT32", ...
    public let offsetBytes: Int64
    public let sizeBytes: Int64

    public init(id: Int64, fsType: String, offsetBytes: Int64, sizeBytes: Int64) {
        self.id = id; self.fsType = fsType
        self.offsetBytes = offsetBytes; self.sizeBytes = sizeBytes
    }

    /// "NTFS · 63.1 GB" - the size disambiguates same-type volumes.
    public var label: String {
        let size = ByteCountFormatter.string(fromByteCount: sizeBytes, countStyle: .file)
        return "\(fsType) · \(size)"
    }

    /// Map TSK's `fs_type` code (the `TSK_FS_TYPE_ENUM` bitmask) to a readable
    /// name. NTFS=1, FAT12=2, FAT16=4, FAT32=8, exFAT=0x0a, FAT(detect)=0x0e,
    /// ext2=0x80, ext3=0x100, ext4=0x2000, HFS=0x1000, APFS=0x8000.
    public static func fsTypeName(_ code: Int) -> String {
        switch code {
        case 1:      return "NTFS"
        case 2:      return "FAT12"
        case 4:      return "FAT16"
        case 8:      return "FAT32"
        case 0x0a:   return "exFAT"
        case 0x0e:   return "FAT"
        case 0x80:   return "Ext2"
        case 0x100:  return "Ext3"
        case 0x2000: return "Ext4"
        case 0x2180: return "ExtX"   // EXT_DETECT (ext2|ext3|ext4)
        case 0x1000: return "HFS+"
        case 0x8000: return "APFS"
        case 0x800:  return "ISO9660"
        default:     return "FS(0x" + String(code, radix: 16) + ")"
        }
    }
}
