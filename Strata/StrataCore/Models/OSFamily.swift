import Foundation

/// The operating-system family an evidence item belongs to, used to hide
/// artifact tabs that are *definitionally impossible* on the other OS (a
/// registry hive can't exist on ext4; `/var/log/auth.log` can't exist on
/// NTFS). Deliberately a small set - we only distinguish the two families
/// whose artifacts Strata parses.
public nonisolated enum OSFamily: String, CaseIterable, Sendable, Hashable, Codable {
    case windows
    case linux
    case macos

    public var label: String {
        switch self {
        case .windows: return "Windows"
        case .linux:   return "Linux"
        case .macos:   return "macOS"
        }
    }

    /// Detect the OS families present in one evidence item. Returns a *set*
    /// because a single image can hold more than one (a dual-boot disk with
    /// both an NTFS and an ext4 volume). An empty result means "couldn't
    /// tell" - the caller should fall back to showing everything rather than
    /// hiding tabs on a guess.
    ///
    /// Filesystem type (from TSK's `tsk_fs_info`) is the authoritative,
    /// pre-parse signal for images: NTFS ⇒ Windows, ext ⇒ Linux. FAT/exFAT
    /// are intentionally ignored - both a Windows and a Linux disk carry a
    /// FAT EFI System Partition, so FAT says nothing about the OS. Loose
    /// collection folders (KAPE / UAC) have no volumes, so they fall back to
    /// a bounded scan of the file tree for telltale top-level directories.
    public static func detect(volumes: [VolumeInfo], files: [FileEntry]) -> Set<OSFamily> {
        var found: Set<OSFamily> = []
        for volume in volumes {
            switch family(forFSType: volume.fsType) {
            case .some(let f): found.insert(f)
            case .none:        break
            }
        }
        if !found.isEmpty { return found }

        // No decisive volume (loose folder, or FAT-only) - sniff the paths.
        // Early-exit as soon as both families are seen, or on the first hit
        // for a typically single-OS collection.
        for file in files {
            let path = file.fullPath.lowercased()
            if path.contains("/library/launchdaemons/") || path.contains("/library/launchagents/")
                || path.contains("/system/library/coreservices/") || path.contains("/private/var/") {
                found.insert(.macos)
            } else if path.contains("/windows/") || path.contains("/users/") {
                found.insert(.windows)
            } else if path.contains("/etc/") || path.contains("/var/log/")
                        || path.contains("/home/") || path.hasSuffix("/etc/passwd") {
                found.insert(.linux)
            }
            if found.count == OSFamily.allCases.count { break }
        }
        return found
    }

    /// Map a `VolumeInfo.fsType` label to its OS family, or nil when the type
    /// doesn't identify an OS (FAT/exFAT/unknown).
    private static func family(forFSType fsType: String) -> OSFamily? {
        let upper = fsType.uppercased()
        if upper == "NTFS" { return .windows }
        if upper.hasPrefix("EXT") { return .linux }   // Ext2 / Ext3 / Ext4 / ExtX
        if upper == "APFS" || upper.hasPrefix("HFS") { return .macos }
        return nil
    }
}
