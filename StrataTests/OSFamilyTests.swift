//
//  OSFamilyTests.swift
//  StrataTests
//
//  Covers per-evidence OS detection that drives per-OS tab hiding: filesystem
//  type for images, file-tree fallback for loose folders, and the SidebarItem
//  OS classification.
//

import Testing
import Foundation
@testable import Strata

struct OSFamilyDetectTests {

    private func volume(_ fsType: String, id: Int64 = 1) -> VolumeInfo {
        VolumeInfo(id: id, fsType: fsType, offsetBytes: 0, sizeBytes: 1 << 30)
    }

    private func file(_ path: String) -> FileEntry {
        let parts = path.split(separator: "/")
        let name = parts.last.map(String.init) ?? path
        let parent = "/" + parts.dropLast().joined(separator: "/") + (parts.count > 1 ? "/" : "")
        return FileEntry(id: 1, metaAddr: nil, name: name, parentPath: parent,
                         size: 10, isDirectory: false, isDeleted: false,
                         modified: nil, accessed: nil, changed: nil, created: nil)
    }

    @Test func ntfsVolumeIsWindows() {
        let fams = OSFamily.detect(volumes: [volume("FAT32"), volume("NTFS", id: 2)], files: [])
        #expect(fams == [.windows])
    }

    @Test func extVolumeIsLinux() {
        // The ext code maps through VolumeInfo.fsTypeName -> "Ext4".
        #expect(VolumeInfo.fsTypeName(0x2000) == "Ext4")
        let fams = OSFamily.detect(volumes: [volume("FAT32"), volume("Ext4", id: 2)], files: [])
        #expect(fams == [.linux])
    }

    @Test func dualBootImageIsBoth() {
        let fams = OSFamily.detect(volumes: [volume("NTFS"), volume("Ext4", id: 2)], files: [])
        #expect(fams == [.windows, .linux])
    }

    @Test func fatOnlyVolumeIsUndetermined() {
        // FAT alone (an EFI System Partition) doesn't identify an OS, and with
        // no files to sniff the result is empty = "show everything".
        let fams = OSFamily.detect(volumes: [volume("FAT32")], files: [])
        #expect(fams.isEmpty)
    }

    @Test func looseWindowsFolderSniffsFileTree() {
        let fams = OSFamily.detect(volumes: [],
                                   files: [file("/C/Windows/System32/winevt/Logs/Security.evtx"),
                                           file("/C/Users/jane/NTUSER.DAT")])
        #expect(fams == [.windows])
    }

    @Test func looseLinuxFolderSniffsFileTree() {
        let fams = OSFamily.detect(volumes: [],
                                   files: [file("/etc/passwd"),
                                           file("/var/log/auth.log"),
                                           file("/home/jane/.bash_history")])
        #expect(fams == [.linux])
    }

    @Test func unrecognizableLooseFolderIsUndetermined() {
        let fams = OSFamily.detect(volumes: [],
                                   files: [file("/data/collection/notes.txt")])
        #expect(fams.isEmpty)
    }
}

struct SidebarItemOSTests {

    @Test func windowsArtifactsAreTaggedWindows() {
        for item in [SidebarItem.events, .registry, .prefetch, .amcache, .shimcache,
                     .lnk, .jumpList, .usn, .srum, .mft, .wmi] {
            #expect(item.osFamily == .windows, "\(item) should be Windows")
        }
    }

    @Test func linuxArtifactsAreTaggedLinux() {
        for item in [SidebarItem.linuxLogs, .shellHistory, .linuxPersistence, .linuxAccess, .webLogs, .packages] {
            #expect(item.osFamily == .linux, "\(item) should be Linux")
        }
    }

    @Test func crossPlatformTabsHaveNoOS() {
        // These must never be hidden - including Browser History (Chrome/Firefox
        // exist on both) and every case-level view.
        for item in [SidebarItem.overview, .evidence, .timeline, .browser,
                     .lateral, .killChain, .iocs, .annotations, .custody] {
            #expect(item.osFamily == nil, "\(item) should be cross-platform")
        }
    }

    @Test func everySidebarItemPartitionsCleanly() {
        let windows = SidebarItem.allCases.filter { $0.osFamily == .windows }
        let linux = SidebarItem.allCases.filter { $0.osFamily == .linux }
        let cross = SidebarItem.allCases.filter { $0.osFamily == nil }
        #expect(windows.count + linux.count + cross.count == SidebarItem.allCases.count)
        #expect(windows.count == 11)
        #expect(linux.count == 6)
    }
}
