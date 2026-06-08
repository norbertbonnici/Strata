//
//  AmcacheTests.swift
//  StrataTests
//
//  Covers the pure AmcacheEntry.reconstruct mapping (regfexport [RegistryValue]
//  -> structured entries, incl. SHA-1 recovery and the legacy Root\File shape)
//  and the AmcacheAnalyzer's suspicious-path gating.
//

import Testing
import Foundation
@testable import Strata

struct AmcacheReconstructTests {
    private let sha = String(repeating: "a", count: 40)

    private func rv(_ path: String, _ name: String, _ data: String,
                    lastWritten: Date? = nil) -> RegistryValue {
        RegistryValue(hive: "AMCACHE", path: path, name: name, type: .sz,
                      data: data, lastWritten: lastWritten, sourceFile: "/x/Amcache.hve")
    }

    @Test func reconstructsInventoryApplicationFileEntry() throws {
        let when = Date(timeIntervalSince1970: 1_600_000_000)
        let values = [
            rv(#"Root\InventoryApplicationFile\evil.exe|abc"#, "LowerCaseLongPath", #"c:\users\public\evil.exe"#, lastWritten: when),
            rv(#"Root\InventoryApplicationFile\evil.exe|abc"#, "FileId", "0000" + String(repeating: "a", count: 40), lastWritten: when),
            rv(#"Root\InventoryApplicationFile\evil.exe|abc"#, "Size", "12345", lastWritten: when),
            rv(#"Root\InventoryApplicationFile\evil.exe|abc"#, "BinaryType", "pe64_amd64", lastWritten: when),
        ]
        let entries = AmcacheEntry.reconstruct(from: values)
        #expect(entries.count == 1)
        let e = try #require(entries.first)
        #expect(e.name == "evil.exe")
        #expect(e.fullPath == #"c:\users\public\evil.exe"#)
        #expect(e.sha1 == sha)                 // leading "0000" stripped
        #expect(e.size == 12345)
        #expect(e.binaryType == "pe64_amd64")
        #expect(e.registeredAt == when)
        #expect(e.source == .inventoryApplicationFile)
    }

    @Test func reconstructsLegacyRootFileEntry() throws {
        let values = [
            rv(#"Root\File\{1d-vol}\0001"#, "15", #"c:\windows\temp\x.exe"#),
            rv(#"Root\File\{1d-vol}\0001"#, "101", "0000" + String(repeating: "b", count: 40)),
            rv(#"Root\File\{1d-vol}\0001"#, "6", "999"),
        ]
        let entries = AmcacheEntry.reconstruct(from: values)
        let e = try #require(entries.first)
        #expect(e.source == .legacyFile)
        #expect(e.fullPath == #"c:\windows\temp\x.exe"#)
        #expect(e.sha1 == String(repeating: "b", count: 40))
        #expect(e.size == 999)
    }

    @Test func skipsContainerKeysAndNonAmcacheHives() {
        let values = [
            // Container key with no file values -> skipped.
            rv(#"Root\InventoryApplicationFile"#, "SomeFlag", "1"),
            // Different hive -> ignored entirely.
            RegistryValue(hive: "SYSTEM", path: #"Root\InventoryApplicationFile\a"#, name: "FileId",
                          type: .sz, data: "0000" + String(repeating: "c", count: 40), sourceFile: "x"),
        ]
        #expect(AmcacheEntry.reconstruct(from: values).isEmpty)
    }

    @Test func malformedFileIdYieldsNilSha1ButKeepsPath() throws {
        let values = [
            rv(#"Root\InventoryApplicationFile\p.exe|x"#, "LowerCaseLongPath", #"c:\tools\p.exe"#),
            rv(#"Root\InventoryApplicationFile\p.exe|x"#, "FileId", "notahash"),
        ]
        let e = try #require(AmcacheEntry.reconstruct(from: values).first)
        #expect(e.sha1 == nil)
        #expect(e.fullPath == #"c:\tools\p.exe"#)
    }
}

struct AmcacheAnalyzerTests {
    private func context(_ entries: [AmcacheEntry]) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [], amcache: entries)
    }

    @Test func flagsSuspiciousPath() throws {
        let e = AmcacheEntry(name: "evil.exe", fullPath: #"c:\users\public\evil.exe"#,
                             sha1: String(repeating: "a", count: 40), source: .inventoryApplicationFile,
                             sourceFile: "x")
        let findings = AmcacheAnalyzer().analyze(context: context([e]))
        let f = try #require(findings.first)
        #expect(f.severity == .high)
        #expect(f.phase == .installation)
        #expect(f.evidencePaths.contains(String(repeating: "a", count: 40)))   // SHA-1 carried for pivoting
    }

    @Test func ignoresBenignSystemPath() {
        let e = AmcacheEntry(name: "cmd.exe", fullPath: #"c:\windows\system32\cmd.exe"#,
                             source: .inventoryApplicationFile, sourceFile: "x")
        #expect(AmcacheAnalyzer().analyze(context: context([e])).isEmpty)
    }
}
