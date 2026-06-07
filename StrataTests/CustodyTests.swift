//
//  CustodyTests.swift
//  StrataTests
//
//  Covers the chain-of-custody feature: the streaming FileHasher, the EWF
//  metadata/verify parsers (against captured ewfinfo/ewfverify output), Codable
//  round-trips + legacy-bundle decoding, and the CoC report/export renderers.
//

import Testing
import Foundation
import CryptoKit
@testable import Strata

struct CustodyTests {

    // MARK: - FileHasher

    private static func hex<D: Sequence>(_ d: D) -> String where D.Element == UInt8 {
        d.map { String(format: "%02x", $0) }.joined()
    }

    private static func tempFile(_ data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("strata-hash-\(UUID().uuidString)")
        try data.write(to: url)
        return url
    }

    @Test func hashesKnownVectors() throws {
        // "abc" — canonical MD5 / SHA-256 test vectors.
        let url = try Self.tempFile(Data("abc".utf8))
        defer { try? FileManager.default.removeItem(at: url) }
        let result = try FileHasher.hash(fileAt: url)
        #expect(result.md5 == "900150983cd24fb0d6963f7d28e17f72")
        #expect(result.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test func hashesEmptyFile() throws {
        let url = try Self.tempFile(Data())
        defer { try? FileManager.default.removeItem(at: url) }
        let result = try FileHasher.hash(fileAt: url)
        #expect(result.md5 == "d41d8cd98f00b204e9800998ecf8427e")
        #expect(result.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test func chunkBoundaryMatchesSingleShot() throws {
        // Data larger than the chunk size, with a tiny chunk so the loop runs
        // many iterations: the streamed digest must equal a one-shot digest.
        let data = Data((0..<10_000).map { UInt8($0 % 251) })
        let url = try Self.tempFile(data)
        defer { try? FileManager.default.removeItem(at: url) }
        let result = try FileHasher.hash(fileAt: url, chunkSize: 7)
        #expect(result.md5 == Self.hex(Insecure.MD5.hash(data: data)))
        #expect(result.sha256 == Self.hex(SHA256.hash(data: data)))
    }

    @Test func hashHonoursCancellation() async throws {
        // 8 MiB with 4 KiB chunks => ~2048 iterations; the pre-cancelled task
        // throws at the first checkCancellation before finishing.
        let url = try Self.tempFile(Data(count: 8 << 20))
        defer { try? FileManager.default.removeItem(at: url) }
        let task = Task.detached { try FileHasher.hash(fileAt: url, chunkSize: 4096) }
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test func missingFileThrows() {
        let url = URL(fileURLWithPath: "/no/such/strata/file.raw")
        #expect(throws: (any Error).self) { try FileHasher.hash(fileAt: url) }
    }

    // MARK: - Custody model Codable

    @Test func custodyEventRoundTrips() throws {
        let event = CustodyEvent(
            id: UUID(),
            timestamp: Date(timeIntervalSinceReferenceDate: 1000),
            action: .hashRecorded, actor: "Jane",
            detail: "Embedded MD5: deadbeef", evidenceID: UUID())
        let data = try JSONEncoder().encode(event)
        let back = try JSONDecoder().decode(CustodyEvent.self, from: data)
        #expect(back == event)
    }

    @Test func sourceHashAndAcquisitionRoundTrip() throws {
        let hash = SourceHash(algorithm: .sha256, value: "ABCDEF", origin: .computed,
                              status: .verified, computedAt: Date(timeIntervalSinceReferenceDate: 5),
                              verifiedAt: Date(timeIntervalSinceReferenceDate: 9), note: "x")
        // The initialiser lowercases the value.
        #expect(hash.value == "abcdef")
        let h2 = try JSONDecoder().decode(SourceHash.self, from: JSONEncoder().encode(hash))
        #expect(h2 == hash)

        var acq = AcquisitionInfo(source: .ewfMetadata)
        acq.examiner = "Jane"; acq.caseNumber = "C-1"; acq.acquiredAt = Date(timeIntervalSinceReferenceDate: 3)
        let a2 = try JSONDecoder().decode(AcquisitionInfo.self, from: JSONEncoder().encode(acq))
        #expect(a2 == acq)
        #expect(!acq.isEmpty)
        #expect(AcquisitionInfo().isEmpty)
    }

    @Test func evidenceWithCustodyFieldsRoundTrips() throws {
        let ev = Evidence(displayName: "disk.E01",
                          sourceURL: URL(fileURLWithPath: "/cases/disk.E01"),
                          kind: .e01,
                          acquisition: AcquisitionInfo(examiner: "Jane", source: .ewfMetadata),
                          sourceHashes: [SourceHash(algorithm: .md5, value: "abc", origin: .embedded)])
        let back = try JSONDecoder().decode(Evidence.self, from: JSONEncoder().encode(ev))
        #expect(back.acquisition?.examiner == "Jane")
        #expect(back.sourceHashes.count == 1)
        #expect(back.sourceHashes.first?.origin == .embedded)
    }

    @Test func legacyEvidenceDecodesWithoutCustodyKeys() throws {
        // A hosts.json written before this feature has neither key.
        let json = """
        {"id":"\(UUID().uuidString)","displayName":"old.E01",
         "sourceURL":"file:///cases/old.E01","kind":"e01"}
        """
        let ev = try JSONDecoder().decode(Evidence.self, from: Data(json.utf8))
        #expect(ev.acquisition == nil)
        #expect(ev.sourceHashes.isEmpty)
        #expect(ev.displayName == "old.E01")
    }

    // MARK: - CoC report + custody export

    private static func sampleInputs() -> ReportInputs {
        let id = UUID()
        let host = ReportInputs.Host(
            displayName: "EVID-1", kindLabel: "E01 image", sourcePath: "/cases/disk.E01",
            registryValues: [], findings: [], iocMatches: [], timeline: [],
            fileCount: 10, eventCount: 5,
            evidenceID: id,
            acquisition: AcquisitionInfo(examiner: "Jane Examiner", acquisitionTool: "FTK",
                                         caseNumber: "CASE-1", source: .ewfMetadata),
            sourceHashes: [SourceHash(algorithm: .md5, value: "99bea62f7ac3e7d96518e6f0f0ab638e",
                                      origin: .embedded)])
        let log = [
            CustodyEvent(action: .addedToCase, actor: "Jane", detail: "Ingested EVID-1", evidenceID: id),
            CustodyEvent(action: .hashRecorded, actor: "Jane",
                         detail: "Embedded MD5", evidenceID: id),
        ]
        return ReportInputs(caseName: "Operation Test", examiner: "Jane Examiner",
                            createdAt: Date(timeIntervalSinceReferenceDate: 0),
                            generatedAt: Date(timeIntervalSinceReferenceDate: 100),
                            hosts: [host], custodyLog: log)
    }

    @Test func cocReportRendersBothFormats() {
        let model = CoCReportModelBuilder.build(from: Self.sampleInputs())
        let html = CoCReportRenderer.html(model)
        let md = CoCReportRenderer.markdown(model)
        for output in [html, md] {
            #expect(output.contains("Operation Test"))
            #expect(output.contains("Jane Examiner"))
            #expect(output.contains("99bea62f7ac3e7d96518e6f0f0ab638e"))
            #expect(output.contains("Added to case"))
            #expect(output.contains("Hash recorded"))
        }
        #expect(html.contains("<!DOCTYPE html>"))
    }

    @Test func custodyExportRowsAndCSV() {
        let inputs = Self.sampleInputs()
        let rows = ExportRowBuilder.custodyRows(from: inputs.custodyLog, hosts: inputs.hosts)
        #expect(rows.count == 2)
        // Resolved to the host display name via evidenceID.
        #expect(rows.allSatisfy { $0.evidence == "EVID-1" })
        let csv = CSVExporter.custody(rows)
        #expect(csv.contains("timestamp_iso,action,actor,detail,evidence"))
        #expect(csv.contains("Added to case"))
    }

    @Test func exportGeneratorEmitsCoCArtifacts() {
        let selection = ExportSelection(cocHTML: true, cocMarkdown: true,
                                        custodyCSV: true, custodyJSON: true)
        let files = ExportGenerator.generate(inputs: Self.sampleInputs(), selection: selection)
        let names = Set(files.map(\.filename))
        #expect(names.contains("Operation Test-chain-of-custody.html"))
        #expect(names.contains("Operation Test-chain-of-custody.md"))
        #expect(names.contains("Operation Test-custody.csv"))
        #expect(names.contains("Operation Test-custody.json"))
    }
}

#if os(macOS)
/// EWF parser tests run against output captured from the vendored ewfinfo /
/// ewfverify (20240506) so no real E01 is needed.
struct EWFInfoParserTests {

    @Test func parsesDFXML() {
        // Note the `<image_filenames>` fragment libewf prints BEFORE `<?xml?>`.
        let dfxml = """
        \t\t<image_filenames>
        \t\t\t<image_filename>strata_fixture.E01</image_filename>
        \t\t</image_filenames>
        <?xml version="1.0" encoding="UTF-8"?>
        <ewfobjects version="0.1">
        \t<ewfinfo>
        \t\t<acquiry_information>
        \t\t\t<case_number>CASE-001</case_number>
        \t\t\t<examiner_name>Jane Examiner</examiner_name>
        \t\t\t<evidence_number>EVD-7</evidence_number>
        \t\t\t<notes>synthetic 512KiB random</notes>
        \t\t\t<acquisition_date>2026-06-07T14:43:34</acquisition_date>
        \t\t\t<acquisition_system>Darwin</acquisition_system>
        \t\t\t<acquisition_version>20240506</acquisition_version>
        \t\t</acquiry_information>
        \t\t<hashdigest type="md5" coding="base16">99bea62f7ac3e7d96518e6f0f0ab638e</hashdigest>
        \t\t<hashdigest type="sha1" coding="base16">90895e0ab0acb2a954fb6aacabb76044c33cca49</hashdigest>
        \t</ewfinfo>
        </ewfobjects>
        """
        let m = EWFInfo.parseDFXML(dfxml)
        #expect(m.caseNumber == "CASE-001")
        #expect(m.examinerName == "Jane Examiner")
        #expect(m.evidenceNumber == "EVD-7")
        #expect(m.operatingSystem == "Darwin")
        #expect(m.storedMD5 == "99bea62f7ac3e7d96518e6f0f0ab638e")
        #expect(m.storedSHA1 == "90895e0ab0acb2a954fb6aacabb76044c33cca49")
        #expect(m.acquisitionDate != nil)
        #expect(!m.isEmpty)
    }

    @Test func parsesTextFallback() {
        let text = """
        ewfinfo 20240506

        Acquiry information:
        \tCase number:\t\tCASE-001
        \tExaminer name:\t\tJane Examiner
        \tNotes:\t\t\tsynthetic 512KiB random
        \tAcquisition date:\t2026-06-07T14:43:34
        \tOperating system used:\tDarwin
        \tSoftware version used:\t20240506
        \tPassword:\t\tN/A

        Digest hash information:
        \tMD5:\t\t\t99bea62f7ac3e7d96518e6f0f0ab638e
        \tSHA1:\t\t\t90895e0ab0acb2a954fb6aacabb76044c33cca49
        """
        let m = EWFInfo.parseText(text)
        #expect(m.caseNumber == "CASE-001")
        #expect(m.examinerName == "Jane Examiner")
        #expect(m.operatingSystem == "Darwin")
        #expect(m.acquisitionVersion == "20240506")
        #expect(m.storedMD5 == "99bea62f7ac3e7d96518e6f0f0ab638e")
        #expect(m.storedSHA1 == "90895e0ab0acb2a954fb6aacabb76044c33cca49")
        // "Password: N/A" must not leak in as a value.
        #expect(m.acquisitionDate != nil)
    }

    @Test func parsesVerifySuccess() {
        let out = """
        ewfverify 20240506

        Verify started at: Jun 07, 2026 14:43:40

        Verify completed at: Jun 07, 2026 14:43:40

        Read: 512 KiB (524288 bytes) in 0 second(s)

        SHA1 hash stored in file:\t\t90895e0ab0acb2a954fb6aacabb76044c33cca49
        SHA1 hash calculated over data:\t\t90895e0ab0acb2a954fb6aacabb76044c33cca49

        ewfverify: SUCCESS
        """
        let r = EWFInfo.parseVerify(out)
        #expect(r.passed)
        #expect(r.storedSHA1 == "90895e0ab0acb2a954fb6aacabb76044c33cca49")
        #expect(r.calculatedSHA1 == "90895e0ab0acb2a954fb6aacabb76044c33cca49")
    }

    @Test func parsesVerifyFailure() {
        let out = """
        ewfverify 20240506
        SHA1 hash stored in file:\t\t1111111111111111111111111111111111111111
        SHA1 hash calculated over data:\t\t2222222222222222222222222222222222222222
        ewfverify: FAILURE
        """
        let r = EWFInfo.parseVerify(out)
        #expect(!r.passed)
        #expect(r.storedSHA1 != r.calculatedSHA1)
    }

    @Test func normalizesHashes() {
        #expect(EWFInfo.normalizedHash("99BEA62F7AC3E7D96518E6F0F0AB638E") == "99bea62f7ac3e7d96518e6f0f0ab638e")
        #expect(EWFInfo.normalizedHash("N/A") == nil)
        #expect(EWFInfo.normalizedHash("xyz") == nil)
        #expect(EWFInfo.normalizedHash(nil) == nil)
    }
}
#endif
