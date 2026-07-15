//
//  IngestReviewFixTests.swift
//  StrataTests
//
//  Covers a batch of ingest-review fixes: EWF-family classification (D1),
//  tightened FileVault-encryption heuristic (B3), and fractional-second date
//  persistence (F3).
//

import Testing
import Foundation
@testable import Strata

struct IngestReviewFixTests {

    /// D1: the whole EWF family — including `.l01` logical evidence — classifies
    /// as `.e01`, so `verifyEWF` (gated on `.e01`) can re-verify the embedded
    /// hashes that `imageType` already seeds for it.
    @Test func classifyMapsEwfFamilyToE01() {
        for ext in ["e01", "E01", "ex01", "s01", "l01", "L01"] {
            #expect(KapeImporter.classify(URL(fileURLWithPath: "/x/image.\(ext)")) == .e01)
        }
        #expect(KapeImporter.classify(URL(fileURLWithPath: "/x/d.vhdx")) == .kapeVHD)
        #expect(KapeImporter.classify(URL(fileURLWithPath: "/x/d.dd")) == .raw)
    }

    /// F3: a sub-second timestamp survives a CaseStore save/reload instead of
    /// being truncated to whole seconds by the old `.iso8601` strategy.
    @Test func fractionalSecondsSurviveRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-f3-\(UUID().uuidString).strata")
        defer { try? FileManager.default.removeItem(at: dir) }
        try CaseStore.createBundle(at: dir,
            case: ForensicCase(name: "t", examiner: "e", createdAt: Date()))

        let stamp = Date(timeIntervalSince1970: 1_700_000_000.123456)
        try CaseStore.writeCustody(
            [CustodyEvent(timestamp: stamp, action: .noteAdded, actor: "e", detail: "d")],
            in: dir)
        let back = try #require(try CaseStore.readCustody(in: dir).first)
        // Whole-second truncation would drift by ~0.123 s; fractional keeps < 1 ms.
        #expect(abs(back.timestamp.timeIntervalSince1970 - 1_700_000_000.123456) < 0.001)
    }

    /// E1: the load path can tell a corrupt artifact from an absent one — the
    /// reader returns nil when the file is missing (→ no fault, "never parsed")
    /// but THROWS when the file is present-but-undecodable (→ recorded as an
    /// ArtifactLoadFault and surfaced, not silently swallowed to empty).
    @Test func corruptArtifactThrowsWhileAbsentReturnsNil() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-e1-\(UUID().uuidString).strata")
        defer { try? FileManager.default.removeItem(at: dir) }
        try CaseStore.createBundle(at: dir,
            case: ForensicCase(name: "t", examiner: "e", createdAt: Date()))

        let host = UUID()
        // (1) absent → nil (loadArr records no fault; genuinely "never parsed")
        #expect(try CaseStore.readFindings(forHostID: host, in: dir) == nil)

        let hostDir = CaseStore.hostDirectory(forHostID: host, in: dir)
        try FileManager.default.createDirectory(at: hostDir, withIntermediateDirectories: true)
        let findingsURL = hostDir.appendingPathComponent("findings.json")

        // (2) present + valid → decodes non-nil, no throw
        try Data("[]".utf8).write(to: findingsURL)
        #expect(try CaseStore.readFindings(forHostID: host, in: dir)?.isEmpty == true)

        // (3) present + corrupt → THROWS (loadArr converts this into a surfaced fault)
        try Data("{ not valid json".utf8).write(to: findingsURL)
        #expect(throws: (any Error).self) {
            _ = try CaseStore.readFindings(forHostID: host, in: dir)
        }
    }

    #if os(macOS)
    /// B2: the FileVault secret is framed as `<password>\0<recovery>` for
    /// fsapfscat's `-s` stdin channel (never on argv). NUL-separated so either
    /// part may be empty and a secret containing a newline still round-trips.
    @Test func fileVaultSecretPayloadIsNulFramed() {
        #expect(FsApfsExtractor.secretPayload(password: "pw", recovery: nil) == Data("pw\u{0}".utf8))
        #expect(FsApfsExtractor.secretPayload(password: nil, recovery: "rk") == Data("\u{0}rk".utf8))
        #expect(FsApfsExtractor.secretPayload(password: "pw", recovery: "rk") == Data("pw\u{0}rk".utf8))
        // A newline in the secret is preserved (framing is NUL-based, not line-based).
        #expect(FsApfsExtractor.secretPayload(password: "a\nb", recovery: nil) == Data("a\nb\u{0}".utf8))
    }

    /// B3: `looksEncrypted` matches only encryption-specific tokens, so a plain
    /// I/O error is no longer misread as a FileVault-locked volume (which would
    /// pop a spurious unlock prompt on a merely-broken volume).
    @Test func looksEncryptedMatchesOnlyEncryptionErrors() {
        func err(_ s: String) -> Error { FsApfsIngestor.FsApfsError.toolFailed(s) }
        #expect(FsApfsIngestor.looksEncrypted(err("volume is encrypted")))
        #expect(FsApfsIngestor.looksEncrypted(err("invalid password supplied")))
        #expect(FsApfsIngestor.looksEncrypted(err("unable to unlock volume")))
        #expect(!FsApfsIngestor.looksEncrypted(err("unable to read block 42")))
        #expect(!FsApfsIngestor.looksEncrypted(err("no such file or directory")))
    }
    #endif
}
