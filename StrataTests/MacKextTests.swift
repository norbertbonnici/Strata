//
//  MacKextTests.swift
//  StrataTests
//
//  Covers the kernel/System-extension parser (kext Info.plist + SystemExtensions
//  db.plist) and the analyzer's third-party detection.
//

import Testing
import Foundation
@testable import Strata

struct MacKextTests {

    private func plist(_ dict: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    // MARK: - Parser: kext Info.plist

    @Test func parsesKextInfoPlist() {
        let data = plist([
            "CFBundleIdentifier": "com.vendor.driver",
            "CFBundleName": "VendorDriver",
            "CFBundleShortVersionString": "2.1",
        ])
        let path = "/Library/Extensions/VendorDriver.kext/Contents/Info.plist"
        let k = MacKextParser.parseKextInfo(data: data, sourceFile: path, scope: "system")
        #expect(k != nil)
        #expect(k?.kind == .kext)
        #expect(k?.bundleID == "com.vendor.driver")
        #expect(k?.name == "VendorDriver")
        #expect(k?.version == "2.1")
        #expect(k?.path == "/Library/Extensions/VendorDriver.kext")
        #expect(k?.isApple == false)
    }

    @Test func appleKextIsFlaggedApple() {
        let data = plist(["CFBundleIdentifier": "com.apple.driver.AppleHIDKeyboard"])
        let k = MacKextParser.parseKextInfo(data: data,
            sourceFile: "/System/Library/Extensions/AppleHIDKeyboard.kext/Contents/Info.plist", scope: "system")
        #expect(k?.isApple == true)
        // Name falls back to the bundle leaf when CFBundleName is absent.
        #expect(k?.name == "AppleHIDKeyboard")
    }

    @Test func kextWithoutBundleIDIsRejected() {
        let data = plist(["CFBundleName": "Nameless"])
        #expect(MacKextParser.parseKextInfo(data: data, sourceFile: "/x/Y.kext/Contents/Info.plist", scope: "system") == nil)
    }

    // MARK: - Parser: System Extensions db

    @Test func parsesSystemExtensionsDB() {
        let data = plist([
            "extensions": [
                ["identifier": "com.crowdstrike.falcon.Agent", "teamID": "X9E956P446",
                 "bundlePath": "/Applications/Falcon.app/Contents/Library/SystemExtensions/falcon.systemextension",
                 "bundleVersion": ["CFBundleShortVersionString": "7.0"], "state": "activated_enabled"],
                ["identifier": "com.apple.fileprovider.something", "teamID": "", "state": "enabled"],
            ],
        ])
        let out = MacKextParser.parseSystemExtensionsDB(data: data,
            sourceFile: "/Library/SystemExtensions/db.plist", scope: "system")
        #expect(out.count == 2)
        let falcon = out.first { $0.bundleID == "com.crowdstrike.falcon.Agent" }
        #expect(falcon?.kind == .systemExtension)
        #expect(falcon?.teamID == "X9E956P446")
        #expect(falcon?.version == "7.0")
        #expect(falcon?.enabled == true)
        #expect(falcon?.isApple == false)
        #expect(out.contains { $0.isApple })   // the com.apple one
    }

    @Test func systemExtensionsDBDedupes() {
        let entry: [String: Any] = ["identifier": "com.x.ext", "bundlePath": "/p"]
        let data = plist(["extensions": [entry, entry]])
        let out = MacKextParser.parseSystemExtensionsDB(data: data, sourceFile: "/db.plist", scope: "system")
        #expect(out.count == 1)
    }

    // MARK: - Analyzer

    private func kext(_ kind: MacKextEntry.Kind, _ bundle: String, team: String? = nil,
                      path: String? = nil) -> MacKextEntry {
        MacKextEntry(kind: kind, bundleID: bundle, name: bundle, teamID: team, path: path,
                     scope: "system", sourceFile: "/src")
    }

    @Test func flagsThirdPartyKextHighAndSysextMedium() {
        let findings = MacKextAnalyzer().analyze([
            kext(.kext, "com.vendor.rootkit", path: "/Library/Extensions/rk.kext"),
            kext(.systemExtension, "com.vendor.netext", team: "ABCDE12345"),
        ])
        #expect(findings.count == 2)
        #expect(findings.allSatisfy { $0.technique?.attackID == "T1547.006" })
        let kextFinding = findings.first { $0.title.contains("kernel extension") }
        #expect(kextFinding?.severity == .high)
        let sysextFinding = findings.first { $0.title.contains("system extension") }
        #expect(sysextFinding?.severity == .medium)
    }

    @Test func ignoresAppleExtensions() {
        let findings = MacKextAnalyzer().analyze([
            kext(.kext, "com.apple.driver.AppleEthernet"),
            kext(.systemExtension, "com.apple.fileprovider.x"),
        ])
        #expect(findings.isEmpty)
    }

    @Test func emptyInputNoFindings() {
        #expect(MacKextAnalyzer().analyze([]).isEmpty)
    }

    @Test func threadedThroughContext() {
        let ctx = AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                                  kexts: [kext(.kext, "com.evil.kmod")])
        let findings = MacKextAnalyzer().analyze(context: ctx)
        #expect(findings.count == 1)
        #expect(findings[0].severity == .high)
    }
}
