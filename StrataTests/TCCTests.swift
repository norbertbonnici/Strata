//
//  TCCTests.swift
//  StrataTests
//
//  Covers the TCC privacy model + analyzer. The TCC.db schema (service, client,
//  client_type, auth_value, auth_reason, last_modified) is pinned against a REAL
//  TCC.db read from a macOS-12 image (e.g. skype→Accessibility, screensharing→
//  ScreenCapture); these tests exercise the value-type logic with synthetic rows.
//

import Testing
import Foundation
@testable import Strata

struct TCCTests {

    private func grant(_ service: String, client: String, type: Int = 0,
                       auth: TCCAccess.AuthValue = .allowed, scope: String = "system") -> TCCAccess {
        TCCAccess(service: service, client: client, clientType: type, authValue: auth,
                  authReason: 4, lastModified: Date(timeIntervalSince1970: 1_742_800_000),
                  scope: scope, sourceFile: "/Library/Application Support/com.apple.TCC/TCC.db")
    }

    @Test func serviceLabelAndSensitivity() {
        let acc = grant("kTCCServiceAccessibility", client: "com.evil.app")
        #expect(acc.serviceLabel == "Accessibility")
        #expect(acc.isSensitive)
        #expect(grant("kTCCServiceScreenCapture", client: "x").serviceLabel == "Screen Recording")
        #expect(grant("kTCCServiceSystemPolicyAllFiles", client: "x").serviceLabel == "Full Disk Access")
        // A non-sensitive service.
        let ub = grant("kTCCServiceUbiquity", client: "com.apple.weather")
        #expect(ub.isSensitive == false)
        // Unknown service falls back to the stripped key.
        #expect(grant("kTCCServiceFoo", client: "x").serviceLabel == "Foo")
    }

    @Test func clientLabelForPathVsBundle() {
        #expect(grant("kTCCServiceCamera", client: "com.zoom.xos").clientLabel == "com.zoom.xos")
        #expect(grant("kTCCServiceAccessibility", client: "/opt/evil/agent", type: 1).clientLabel == "agent")
    }

    @Test func appleClientDetection() {
        #expect(TCCAnalyzer.isAppleClient(grant("kTCCServiceAccessibility", client: "com.apple.Terminal")))
        #expect(TCCAnalyzer.isAppleClient(grant("kTCCServiceCamera", client: "/System/Library/x", type: 1)))
        #expect(TCCAnalyzer.isAppleClient(grant("kTCCServiceCamera", client: "com.evil.app")) == false)
        #expect(TCCAnalyzer.isAppleClient(grant("kTCCServiceCamera", client: "/opt/evil", type: 1)) == false)
    }

    @Test func analyzerFlagsSensitiveAllowedNonApple() {
        let ctx = AnalysisContext(
            files: [], events: [], timeline: [], registryValues: [],
            tcc: [
                grant("kTCCServiceAccessibility", client: "com.evil.stealer"),       // flag
                grant("kTCCServiceScreenCapture", client: "/opt/rat/agent", type: 1), // flag
                grant("kTCCServiceAccessibility", client: "com.apple.Terminal"),      // Apple → no
                grant("kTCCServiceCamera", client: "com.evil.app", auth: .denied),    // denied → no
                grant("kTCCServiceUbiquity", client: "com.evil.app"),                 // not sensitive → no
            ])
        let findings = TCCAnalyzer().analyze(context: ctx)
        #expect(findings.count == 2)
        #expect(findings.allSatisfy { $0.severity == .high })
        #expect(findings.contains { $0.technique?.attackID == "T1056.001" })  // accessibility → keylogging
        #expect(findings.contains { $0.technique?.attackID == "T1113" })      // screen capture
    }

    @Test func analyzerDedupesRepeatGrants() {
        let g = grant("kTCCServiceMicrophone", client: "com.evil.app")
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  tcc: [g, g, g])
        #expect(TCCAnalyzer().analyze(context: ctx).count == 1)
    }
}
