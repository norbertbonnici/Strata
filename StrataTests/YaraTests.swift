import Foundation
import Testing
@testable import Strata

@Suite("YARA")
struct YaraTests {
    @Test("CLI output preserves rule names when target paths contain spaces")
    func parsesOutput() {
        let path = "/tmp/evidence files/payload.bin"
        let output = "Malware_Family_A \(path)\nSecondRule \(path)\nnoise\n"
        #expect(YaraRunner.parseRules(stdout: output, targetPath: path)
                == ["Malware_Family_A", "SecondRule"])
    }

    @Test("Analyzer groups matches by rule without claiming execution")
    func analyzerFindings() {
        let evidenceID = UUID()
        let matches = [
            YaraMatch(rule: "Example", evidenceID: evidenceID, path: "/a", fileID: 1, fileSize: 10),
            YaraMatch(rule: "Example", evidenceID: evidenceID, path: "/b", fileID: 2, fileSize: 20),
        ]
        let context = AnalysisContext(files: [], events: [], timeline: [],
                                      registryValues: [], yaraMatches: matches)
        let findings = YaraAnalyzer().analyze(context: context)
        #expect(findings.count == 1)
        #expect(findings[0].severity == .high)
        #expect(findings[0].technique == nil)
        #expect(findings[0].evidencePaths == ["/a", "/b"])
    }
}
