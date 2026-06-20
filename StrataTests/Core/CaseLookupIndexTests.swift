//
//  CaseLookupIndexTests.swift
//  StrataTests
//
//  Covers the pure artifact lookup index that backs the summarizer's
//  FoundationModels tools (lookupFile / lookupDownloadOrigin). The tools and
//  the model round-trip need an Apple-Intelligence host and are verified
//  manually; the index itself is pure and tested here.
//

import Testing
import Foundation
@testable import Strata

struct CaseLookupIndexTests {

    private func finding(paths: [String]) -> Finding {
        Finding(title: "t", detail: "d", severity: .high, phase: .installation, evidencePaths: paths)
    }

    private func file(_ path: String, size: Int64 = 2048, deleted: Bool = false) -> FileEntry {
        let ns = path as NSString
        return FileEntry(id: Int64(abs(path.hashValue % 1_000_000)), metaAddr: nil,
                         name: ns.lastPathComponent, parentPath: ns.deletingLastPathComponent,
                         size: size, isDirectory: false, isDeleted: deleted,
                         modified: Date(timeIntervalSinceReferenceDate: 200), accessed: nil,
                         changed: nil, created: Date(timeIntervalSinceReferenceDate: 100))
    }

    @Test func indexesOnlyFindingReferencedFiles() {
        let referenced = "/Users/v/Downloads/evil.dmg"
        let unreferenced = "/Users/v/Documents/notes.txt"
        let idx = CaseLookupIndex.build(findings: [finding(paths: [referenced])],
                                        files: [file(referenced), file(unreferenced)],
                                        whereFroms: [])
        #expect(idx.file(at: referenced) != nil)
        #expect(idx.file(at: unreferenced) == nil)   // not referenced → not indexed
        #expect(!idx.isEmpty)
    }

    @Test func fileLookupIsCaseAndWhitespaceInsensitive() {
        let p = "/Users/v/Downloads/Evil.dmg"
        let idx = CaseLookupIndex.build(findings: [finding(paths: [p])],
                                        files: [file(p, size: 4096, deleted: true)], whereFroms: [])
        let f = idx.file(at: "  /users/v/downloads/evil.dmg ")
        #expect(f?.size == 4096)
        #expect(f?.isDeleted == true)
    }

    @Test func downloadOriginComesFromWhereFroms() {
        let p = "/Users/v/Downloads/evil.dmg"
        let idx = CaseLookupIndex.build(
            findings: [], files: [],
            whereFroms: [MacWhereFrom(path: p,
                                      urls: ["https://evil.example/evil.dmg", "https://forum.example/thread"],
                                      scope: "Downloads")])
        let o = idx.downloadOrigin(at: p)
        #expect(o?.downloadURL == "https://evil.example/evil.dmg")
        #expect(o?.referrer == "https://forum.example/thread")
        #expect(idx.downloadOrigin(at: "/nope") == nil)
    }

    @Test func emptyIndexIsEmpty() {
        #expect(CaseLookupIndex.empty.isEmpty)
        #expect(CaseLookupIndex.build(findings: [], files: [], whereFroms: []).isEmpty)
    }

    @Test func collidingPathsAcrossVolumesAreFlaggedAmbiguous() {
        // Same path, distinct facts (e.g. two volumes / hosts) → ambiguous.
        let p = "/Users/v/Downloads/a.dmg"
        let idx = CaseLookupIndex.build(findings: [finding(paths: [p])],
                                        files: [file(p, size: 100), file(p, size: 999, deleted: true)],
                                        whereFroms: [])
        #expect(idx.isAmbiguousFile(at: p))
        #expect(idx.file(at: p) != nil)                 // still resolves one representative
        #expect(!idx.isAmbiguousFile(at: "/other"))
    }

    // MARK: - Tool call() behaviour (pure - no model)

    @Test func lookupFileMissIsNonAuthoritativeButPresenceAware() async throws {
        let idx = CaseLookupIndex.build(findings: [], files: [], whereFroms: [])
        let tool = LookupFileTool(index: idx, knownPaths: ["/Users/v/x.dmg"])
        // Present in the whole tree but not finding-indexed → "present" wording.
        let present = try await tool.call(arguments: .init(path: "/Users/v/x.dmg"))
        #expect(present.contains("present in the evidence"))
        // Truly unknown → non-authoritative, never "absent from the host" as fact.
        let absent = try await tool.call(arguments: .init(path: "/nope/y"))
        #expect(absent.contains("does not mean it is absent"))
    }

    @Test func lookupFileReportsFactsWithAmbiguityCaveat() async throws {
        let p = "/Users/v/Downloads/a.dmg"
        let idx = CaseLookupIndex.build(findings: [finding(paths: [p])],
                                        files: [file(p, size: 100), file(p, size: 999, deleted: true)],
                                        whereFroms: [])
        let out = try await LookupFileTool(index: idx, knownPaths: []).call(arguments: .init(path: p))
        #expect(out.contains("size:"))
        #expect(out.contains("more than one file"))      // ambiguity disclosed
    }

    @Test func lookupDownloadOriginToolReportsURL() async throws {
        let p = "/Users/v/Downloads/a.dmg"
        let idx = CaseLookupIndex.build(findings: [], files: [],
            whereFroms: [MacWhereFrom(path: p, urls: ["https://evil.example/a.dmg"], scope: "Downloads")])
        let out = try await LookupDownloadOriginTool(index: idx).call(arguments: .init(path: p))
        #expect(out.contains("https://evil.example/a.dmg"))
        let miss = try await LookupDownloadOriginTool(index: idx).call(arguments: .init(path: "/nope"))
        #expect(miss.contains("No recorded download origin"))
    }
}
