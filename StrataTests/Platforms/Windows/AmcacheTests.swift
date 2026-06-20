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

#if os(macOS)
/// Exercises the FULL text pipeline - `RegistryHiveParser.records` (the
/// regfexport text parser) feeding `AmcacheEntry.reconstruct` - against a
/// verbatim slice of REAL `regfexport` output from a real `Amcache.hve`. The
/// other reconstruct tests start from synthetic `RegistryValue`s and so never
/// cover the regfexport key-path / value-name format (GUID-prefixed
/// `{GUID}\Root\InventoryApplicationFile\...` keys, `Value: <n> <name>` lines).
struct AmcacheRealFormatTests {
    // Two real entries (one modern InventoryApplicationFile, one legacy
    // Root\File) captured verbatim from regfexport on a real Amcache.hve.
    private let realDump = #"""
    Key path: {11517B7C-E79D-4e20-961B-75A811715ADD}\Root\InventoryApplicationFile\000004495fb538f070efc58b28b096aecca267e28ead
    Name: 000004495fb538f070efc58b28b096aecca267e28ead
    Last written time: Aug 03, 2017 11:34:09.482559700 UTC

    Value: 1 FileId
    Type: string (REG_SZ)
    Data size: 90
    Data: 0000186fef64c415af7d11986c7254db81ef65549ebc

    Value: 2 LowerCaseLongPath
    Type: string (REG_SZ)
    Data size: 162
    Data: c:\users\user\appdata\local\jetbrains\installations\dotpeek08\jetlauncher64c.exe

    Value: 4 BinaryType
    Type: string (REG_SZ)
    Data size: 22
    Data: PE64_AMD64

    Value: 5 Size
    Type: string (REG_SZ)
    Data size: 16
    Data: 0x7fac0

    Key path: {11517B7C-E79D-4e20-961B-75A811715ADD}\Root\File\ccbe4c57-0000-0000-0000-100000000000\100000169dd
    Name: 100000169dd
    Last written time: Aug 03, 2017 11:34:04.654176500 UTC

    Value: 1 15
    Type: string (REG_SZ)
    Data size: 156
    Data: c:\users\user\appdata\local\microsoft\onedrive\17.3.6943.0625\FileSyncFAL.dll

    Value: 3 101
    Type: string (REG_SZ)
    Data size: 90
    Data: 0000818b581a471c1c6833839d35a9d6f3544f6a9c92
    """#

    @Test func parsesRealRegfexportAmcacheOutput() throws {
        let values = RegistryHiveParser.records(from: realDump, hiveLabel: "AMCACHE",
                                                sourceFile: "/x/Amcache.hve")
        let entries = AmcacheEntry.reconstruct(from: values)
        #expect(entries.count == 2)

        let inv = try #require(entries.first { $0.source == .inventoryApplicationFile })
        #expect(inv.name == "jetlauncher64c.exe")
        #expect(inv.fullPath == #"c:\users\user\appdata\local\jetbrains\installations\dotpeek08\jetlauncher64c.exe"#)
        #expect(inv.sha1 == "186fef64c415af7d11986c7254db81ef65549ebc")   // leading 0000 stripped
        #expect(inv.size == 522_944)                                       // "0x7fac0" hex-parsed
        #expect(inv.binaryType == "PE64_AMD64")

        let legacy = try #require(entries.first { $0.source == .legacyFile })
        #expect(legacy.name == "FileSyncFAL.dll")
        #expect(legacy.sha1 == "818b581a471c1c6833839d35a9d6f3544f6a9c92")
    }
}
#endif

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
