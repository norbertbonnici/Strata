import Testing
import Foundation
@testable import Strata

struct KapeFolderIngestorTests {

    /// Build a throwaway KAPE-style tree (drive-letter prefix and all) and
    /// return its root. The caller is responsible for deleting it.
    private static func makeTree() throws -> URL {
        let fm = FileManager.default
        let root = fm.temporaryDirectory
            .appendingPathComponent("kape-\(UUID().uuidString)", isDirectory: true)
        let layout = [
            "C/Windows/System32/config/SYSTEM",
            "C/Windows/System32/winevt/Logs/Security.evtx",
            "C/Users/jdoe/NTUSER.DAT",
        ]
        for rel in layout {
            let fileURL = root.appendingPathComponent(rel)
            try fm.createDirectory(at: fileURL.deletingLastPathComponent(),
                                   withIntermediateDirectories: true)
            try Data("x".utf8).write(to: fileURL)
        }
        return root
    }

    @Test func mirrorsSourceLayoutAndSetsDiskURL() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(at: root) }

        let files = KapeFolderIngestor().ingest(folderAt: root)

        // The SYSTEM hive is discoverable by the same path suffix the registry
        // stage keys off, regardless of the drive-letter prefix layer.
        let system = files.first {
            $0.fullPath.lowercased().hasSuffix("/windows/system32/config/system")
        }
        #expect(system != nil)
        #expect(system?.isDirectory == false)
        // diskURL must point at a real, readable file - that's what evtx /
        // registry parsing reads in place instead of extracting with icat.
        #expect(system?.diskURL != nil)
        #expect(FileManager.default.fileExists(atPath: system?.diskURL?.path ?? "/nope"))

        // .evtx detection still works through FileEntry.fileExtension.
        let evtx = files.filter { $0.fileExtension == "evtx" && !$0.isDirectory }
        #expect(evtx.count == 1)

        // Directories are surfaced too (the evidence tree view needs them).
        #expect(files.contains { $0.isDirectory && $0.name == "config" })

        // NTUSER.DAT keeps the owning user in its path so analyzers can
        // attribute per-user findings.
        #expect(files.contains { $0.fullPath.lowercased().hasSuffix("/users/jdoe/ntuser.dat") })
    }

    @Test func timestampsStayCollectionHonest() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(at: root) }

        let file = KapeFolderIngestor().ingest(folderAt: root).first { !$0.isDirectory }
        #expect(file?.modified != nil)   // host FS preserves the source mtime
        #expect(file?.accessed == nil)   // no trustworthy atime survives a copy
        #expect(file?.changed == nil)    // nor an MFT-change time
    }

    @Test func relativeComponentsSplitsUnderRoot() {
        let url = URL(fileURLWithPath: "/tmp/case/C/Windows/System32/config/SYSTEM")
        let (parent, name) = KapeFolderIngestor.relativeComponents(of: url, underRoot: "/tmp/case")
        #expect(parent == "/C/Windows/System32/config")
        #expect(name == "SYSTEM")
    }
}
