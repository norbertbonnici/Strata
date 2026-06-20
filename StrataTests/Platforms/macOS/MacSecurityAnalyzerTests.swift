//
//  MacSecurityAnalyzerTests.swift
//  StrataTests
//
//  Covers the MacSecurityAnalyzer detection rules over durable macOS security
//  telemetry (Gatekeeper / syspolicyd, XProtect, XProtect Remediator, MRT). The
//  MacSecurityEvent shape is pinned by MacSecurityParser; these tests exercise
//  the analyzer logic with synthetic events.
//

import Testing
import Foundation
@testable import Strata

struct MacSecurityAnalyzerTests {

    private func event(_ kind: MacSecurityEvent.Kind, _ severity: MacSecurityEvent.Severity,
                       message: String = "", path: String? = nil, signature: String? = nil,
                       process: String? = nil, at seconds: TimeInterval? = nil,
                       source: String = "/var/db/diagnostics/xprotect.log") -> MacSecurityEvent {
        MacSecurityEvent(kind: kind, severity: severity,
                         timestamp: seconds.map { Date(timeIntervalSince1970: $0) },
                         process: process,
                         message: message.isEmpty ? "\(kind.label) \(severity.label)" : message,
                         path: path, signature: signature, scope: "system", sourceFile: source)
    }

    // MARK: - Rule 1: malware detected / remediated

    @Test func flagsMalwareDetectionAndRemediation() {
        let findings = MacSecurityAnalyzer().analyze([
            event(.xprotect, .detected, message: "XProtect detected malware", signature: "OSX.Bundlore"),
            event(.mrt, .remediated, message: "MRT removed threat", path: "/Users/x/Downloads/evil.app"),
        ])
        #expect(findings.count == 2)
        #expect(findings.allSatisfy { $0.severity == .high })
        #expect(findings.allSatisfy { $0.technique?.attackID == "T1204.002" })
        #expect(findings.allSatisfy { $0.phase == .installation })
        #expect(findings.contains { $0.title.contains("OSX.Bundlore") })
        #expect(findings.contains { $0.title.contains("remediation") })
    }

    @Test func aggregatesRepeatedDetectionsOfSameSubject() {
        let events = (0..<3).map { event(.xprotect, .detected, signature: "OSX.Pirrit", at: Double(100 + $0)) }
        let findings = MacSecurityAnalyzer().analyze(events)
        #expect(findings.count == 1)
        #expect(findings[0].detail.contains("Seen 3 times"))
    }

    // MARK: - Rule 2: trust override (allow-after-block)

    @Test func flagsAllowAfterBlockAsOverride() {
        let path = "/Users/x/Downloads/tool"
        let findings = MacSecurityAnalyzer().analyze([
            event(.gatekeeper, .blocked, message: "Gatekeeper blocked unsigned", path: path, at: 1000),
            event(.gatekeeper, .allowed, message: "Gatekeeper allowed", path: path, at: 2000),
        ])
        #expect(findings.contains {
            $0.technique?.attackID == "T1553.001" && $0.severity == .high && $0.title.contains("overridden")
        })
        // The overridden subject is consumed by Rule 2, not re-reported as a plain block.
        #expect(findings.allSatisfy { !$0.title.contains("policy blocked") })
    }

    @Test func doesNotFlagAllowBeforeBlock() {
        let path = "/Users/x/app"
        let findings = MacSecurityAnalyzer().analyze([
            event(.gatekeeper, .allowed, path: path, at: 1000),
            event(.gatekeeper, .blocked, path: path, at: 2000),
        ])
        #expect(findings.contains { $0.title.contains("overridden") } == false)
    }

    @Test func overrideRequiresStableIdentity() {
        // Message-only events (no path/signature) cannot be correlated → no override.
        let findings = MacSecurityAnalyzer().analyze([
            event(.gatekeeper, .blocked, message: "blocked something"),
            event(.gatekeeper, .allowed, message: "allowed something else"),
        ])
        #expect(findings.contains { $0.title.contains("overridden") } == false)
    }

    // MARK: - Rule 3: security control disabled

    @Test func flagsDisabledControl() {
        let findings = MacSecurityAnalyzer().analyze([
            event(.syspolicyd, .info, message: "spctl master-disable executed; assessments disabled", process: "spctl"),
        ])
        #expect(findings.contains { $0.technique?.attackID == "T1562.001" && $0.severity == .high })
    }

    // MARK: - Rule 4: policy block + repeated-failure escalation

    @Test func singleBlockIsMedium() {
        let findings = MacSecurityAnalyzer().analyze([event(.gatekeeper, .blocked, path: "/tmp/one", at: 1)])
        #expect(findings.count == 1)
        #expect(findings[0].severity == .medium)
        #expect(findings[0].technique?.attackID == "T1553.001")
        #expect(findings[0].phase == .exploitation)
    }

    @Test func escalatesRepeatedPolicyFailures() {
        let path = "/tmp/payload"
        let events = (0..<6).map { event(.gatekeeper, .blocked, path: path, at: Double(1000 + $0)) }
        let block = MacSecurityAnalyzer().analyze(events).first { $0.title.contains(path) }
        #expect(block?.severity == .high)
        #expect(block?.title.contains("Repeated") == true)
    }

    // MARK: - Wiring / edge cases

    @Test func emptyInputNoFindings() {
        #expect(MacSecurityAnalyzer().analyze([]).isEmpty)
    }

    @Test func benignInfoEventsProduceNothing() {
        let findings = MacSecurityAnalyzer().analyze([
            event(.gatekeeper, .allowed, path: "/Applications/Safari.app", at: 1),
            event(.syspolicyd, .info, message: "policy evaluation complete", at: 2),
        ])
        #expect(findings.isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [],
            macSecurityEvents: [event(.xprotectRemediator, .remediated, signature: "OSX.Genieo")])
        let findings = MacSecurityAnalyzer().analyze(context: ctx)
        #expect(findings.count == 1)
        #expect(findings[0].severity == .high)
        #expect(findings[0].technique?.attackID == "T1204.002")
    }
}
