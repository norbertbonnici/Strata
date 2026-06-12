//
//  FsApfsIngestorTests.swift
//  StrataTests
//
//  Covers the pure BodyfileEntry → FileEntry mapping in the macOS APFS ingest
//  path, pinned to a REAL `fsapfsinfo -H -B` line from the macOS-27 image.
//

import Testing
import Foundation
@testable import Strata

#if os(macOS)

struct FsApfsIngestorMappingTests {

    /// A real `fsapfsinfo -f 3 -H -B` line (Recovery volume): a file at depth 2
    /// with the `/{volume-uuid}/…` path prefix libfsapfs emits.
    private static let realLine =
        "0|/{fbd5d3cc-f15e-4314-b7e3-e94832f7e75a}/8C9E271C-6C30-48DC-93BA-35454536DE97/BootKernelExtensions.kc.j680ap.im4m|828|-rw-r--r--|242|0|2800|1721217513.000000000|1721215231.000000000|1742574446.328318160|1721215231.000000000"

    @Test func stripsVolumeUUIDPrefix() {
        #expect(FsApfsIngestor.cleanPath("/{fbd5d3cc-f15e-4314-b7e3-e94832f7e75a}/8C9E271C/file")
                == "/8C9E271C/file")
        // A path without the prefix is returned unchanged.
        #expect(FsApfsIngestor.cleanPath("/usr/libexec") == "/usr/libexec")
        #expect(FsApfsIngestor.cleanPath("private-dir") == "private-dir")
    }

    @Test func mapsRealLineToFileEntry() throws {
        let e = try #require(BodyfileParser.parseLine(Self.realLine))
        let f = try #require(FsApfsIngestor.fileEntry(from: e, id: 42, fsID: 2))
        #expect(f.id == 42)
        #expect(f.fsID == 2)
        #expect(f.metaAddr == 828)
        #expect(f.name == "BootKernelExtensions.kc.j680ap.im4m")
        #expect(f.parentPath == "/8C9E271C-6C30-48DC-93BA-35454536DE97/")
        #expect(f.fullPath == "/8C9E271C-6C30-48DC-93BA-35454536DE97/BootKernelExtensions.kc.j680ap.im4m")
        #expect(!f.isDirectory)
        #expect(f.size == 2800)
        #expect(f.modified == Date(timeIntervalSince1970: 1721215231))
        #expect(f.diskURL == nil)   // content extraction is a later step
    }

    @Test func rootEntryIsSkipped() {
        // The empty-path root line maps to nil (the tree synthesises volume roots).
        let root = BodyfileParser.parseLine(
            "0||2|drwxr-xr-x|0|0|0|1700000000|1700000000|1700000000|1700000000")!
        #expect(FsApfsIngestor.fileEntry(from: root, id: 1, fsID: 0) == nil)
    }

    @Test func topLevelDirGetsRootParent() throws {
        let e = BodyfileParser.parseLine(
            "0|private-dir|3|drwxr-xr-x|0|0|0|1700000000|1700000000|1700000000|1700000000")!
        let f = try #require(FsApfsIngestor.fileEntry(from: e, id: 5, fsID: 0))
        #expect(f.name == "private-dir")
        #expect(f.parentPath == "/")
        #expect(f.isDirectory)
    }
}

#endif
