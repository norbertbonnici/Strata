//
//  ApfsEvidenceTests.swift
//  StrataTests
//
//  Covers the persistence additions for the macOS APFS ingest path: the
//  EvidenceKind.apfs case and Evidence.apfsRawURL round-trip through Codable
//  (hosts.json), plus FileEntry/VolumeInfo Codable (the APFS tree is persisted
//  as JSON since there's no tsk.db).
//

import Testing
import Foundation
@testable import Strata

struct ApfsEvidenceTests {

    @Test func evidenceWithApfsKindRoundTrips() throws {
        let raw = URL(fileURLWithPath: "/Volumes/T7/case/new_mb_raw.raw")
        let e = Evidence(displayName: "mac.E01",
                         sourceURL: URL(fileURLWithPath: "/Volumes/T7/case/mac.E01"),
                         kind: .apfs, apfsRawURL: raw)
        let data = try JSONEncoder().encode(e)
        let back = try JSONDecoder().decode(Evidence.self, from: data)
        #expect(back.kind == .apfs)
        #expect(back.apfsRawURL == raw)
        #expect(back.kind.label == "APFS image")
    }

    @Test func legacyEvidenceWithoutApfsRawDecodes() throws {
        // A hosts.json written before this feature has no apfsRawURL key.
        let json = """
        {"id":"\(UUID().uuidString)","displayName":"win.E01",
         "sourceURL":"file:///x/win.E01","kind":"e01"}
        """
        let e = try JSONDecoder().decode(Evidence.self, from: Data(json.utf8))
        #expect(e.kind == .e01)
        #expect(e.apfsRawURL == nil)
    }

    @Test func fileEntryAndVolumeInfoAreCodable() throws {
        let f = FileEntry(id: 1, metaAddr: 828, name: "History.db",
                          parentPath: "/Users/jane/Library/Safari/", size: 4096,
                          isDirectory: false, isDeleted: false,
                          modified: Date(timeIntervalSince1970: 1700000000),
                          accessed: nil, changed: nil, created: nil, fsID: 4)
        let f2 = try JSONDecoder().decode(FileEntry.self, from: JSONEncoder().encode(f))
        #expect(f2.fullPath == "/Users/jane/Library/Safari/History.db")
        #expect(f2.fsID == 4)
        #expect(f2.metaAddr == 828)

        let v = VolumeInfo(id: 4, fsType: "APFS", offsetBytes: 209735680, sizeBytes: 0)
        let v2 = try JSONDecoder().decode(VolumeInfo.self, from: JSONEncoder().encode(v))
        #expect(v2.offsetBytes == 209735680)
        #expect(v2.fsType == "APFS")
    }
}
