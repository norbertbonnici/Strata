//
//  CorrelationEngineTests.swift
//  StrataTests
//
//  Validates case-wide multi-host correlation (roadmap #8): the three
//  cross-host signals (shared indicator, source-IP pivot, credential reuse)
//  fire only when a key spans ≥2 distinct hosts, and single-host data stays
//  quiet. Severity scales with the number of involved hosts.
//

import Testing
import Foundation
@testable import Strata

struct CorrelationEngineTests {
    private static let when = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: Fixture builders

    private func fileMatch(_ value: String, kind: IOCKind, path: String,
                           ts: Date? = Self.when) -> IOCMatch {
        IOCMatch(iocValue: value, iocKind: kind,
                 location: .file(path: path), context: path, timestamp: ts)
    }

    /// Three hosts. host A + host B share IOC `evil.example.com` and source IP
    /// `10.0.0.50` and the account `jsmith`; host C is an outlier with its own
    /// distinct IOC / IP / user that must NOT correlate.
    private func threeHosts() -> [HostSummary] {
        let a = UUID(); let b = UUID(); let c = UUID()
        let hostA = HostSummary(
            hostID: a, hostname: "WS01",
            iocMatches: [
                fileMatch("evil.example.com", kind: .domain, path: #"C:\a\dropper.txt"#),
                fileMatch("203.0.113.9", kind: .ip, path: #"C:\a\only-on-A.txt"#),
            ],
            users: ["CORP\\jsmith", "Administrator", "WS01$"],
            remoteLogonSourceIPs: ["10.0.0.50", "127.0.0.1"])
        let hostB = HostSummary(
            hostID: b, hostname: "WS02",
            iocMatches: [
                fileMatch("evil.example.com", kind: .domain, path: #"C:\b\beacon.txt"#,
                          ts: Self.when.addingTimeInterval(-3600)),       // earlier
            ],
            users: ["jsmith", "SYSTEM"],
            remoteLogonSourceIPs: ["10.0.0.50", "::1"])
        let hostC = HostSummary(
            hostID: c, hostname: "WS03",
            iocMatches: [
                fileMatch("benign-only.example", kind: .domain, path: #"C:\c\x.txt"#),
            ],
            users: ["alice", "root"],
            remoteLogonSourceIPs: ["192.168.9.9"])
        return [hostA, hostB, hostC]
    }

    // MARK: (a) Shared indicator

    @Test func sharedIndicatorFiresAcrossTwoHosts() throws {
        let findings = CorrelationEngine.correlate(threeHosts())
        let f = try #require(findings.first {
            $0.title.contains("Shared indicator") && $0.title.contains("evil.example.com")
        })
        #expect(f.title.contains("2 hosts"))
        #expect(f.severity == .medium)                 // exactly 2 hosts
        #expect(f.phase == .commandAndControl)
        #expect(f.technique?.attackID == "T1105")
        #expect(f.detail.contains("WS01"))
        #expect(f.detail.contains("WS02"))
        // Earliest of the two timestamps is surfaced.
        #expect(f.timestamp == Self.when.addingTimeInterval(-3600))
    }

    @Test func singleHostIndicatorDoesNotCorrelate() {
        let findings = CorrelationEngine.correlate(threeHosts())
        // 203.0.113.9 and benign-only.example each appear on one host only.
        #expect(findings.contains { $0.title.contains("203.0.113.9") } == false)
        #expect(findings.contains { $0.title.contains("benign-only.example") } == false)
    }

    // MARK: (b) Source-IP pivot

    @Test func sourceIPPivotFiresAcrossTwoHosts() throws {
        let findings = CorrelationEngine.correlate(threeHosts())
        let f = try #require(findings.first {
            $0.title.contains("10.0.0.50") && $0.title.contains("lateral pivot")
        })
        #expect(f.severity == .medium)
        #expect(f.phase == .exploitation)
        #expect(f.technique?.attackID == "T1021")
        #expect(f.detail.contains("WS01"))
        #expect(f.detail.contains("WS02"))
    }

    @Test func loopbackSourcesAreIgnored() {
        let findings = CorrelationEngine.correlate(threeHosts())
        // 127.0.0.1 / ::1 appear on hosts but must never produce a pivot finding.
        #expect(findings.contains { $0.title.contains("127.0.0.1") } == false)
        #expect(findings.contains { $0.title.contains("::1") } == false)
        // Single-host source (192.168.9.9 on C only) must not fire.
        #expect(findings.contains { $0.title.contains("192.168.9.9") } == false)
    }

    // MARK: (c) Credential reuse

    @Test func credentialReuseFiresForSharedAccount() throws {
        let findings = CorrelationEngine.correlate(threeHosts())
        let f = try #require(findings.first {
            $0.title.contains("credential reuse") && $0.title.localizedCaseInsensitiveContains("jsmith")
        })
        #expect(f.severity == .medium)
        #expect(f.phase == .exploitation)
        #expect(f.technique?.attackID == "T1078")
        #expect(f.detail.contains("WS01"))
        #expect(f.detail.contains("WS02"))
    }

    @Test func builtinAndSingleHostAccountsDoNotCorrelate() {
        let findings = CorrelationEngine.correlate(threeHosts())
        // Administrator/SYSTEM/root appear on multiple hosts but are built-in.
        #expect(findings.contains { $0.title.localizedCaseInsensitiveContains("administrator") } == false)
        #expect(findings.contains { $0.title.contains("SYSTEM") } == false)
        #expect(findings.contains { $0.title.contains("root") } == false)
        // The WS01$ machine account is built-in (trailing $).
        #expect(findings.contains { $0.title.contains("WS01$") } == false)
        // alice is on host C only.
        #expect(findings.contains { $0.title.localizedCaseInsensitiveContains("alice") } == false)
    }

    // MARK: Domain-prefix collapsing

    @Test func userKeyCollapsesDomainPrefix() {
        // CORP\jsmith (host A) and jsmith (host B) must be recognised as one
        // identity — proven by the single credential-reuse finding above, but
        // assert the key helper directly too.
        #expect(CorrelationEngine.userKey("CORP\\jsmith") == "jsmith")
        #expect(CorrelationEngine.userKey("  WS01\\JSmith ") == "jsmith")
        #expect(CorrelationEngine.isBuiltinUser("WS01$"))
        #expect(CorrelationEngine.isBuiltinUser("DOMAIN\\SYSTEM"))
        #expect(CorrelationEngine.isBuiltinUser("UMFD-1"))
        #expect(CorrelationEngine.isBuiltinUser("jsmith") == false)
    }

    // MARK: Severity scaling

    @Test func severityScalesWithHostCount() throws {
        let value = "shared.example.com"
        func host(_ name: String) -> HostSummary {
            HostSummary(hostID: UUID(), hostname: name,
                        iocMatches: [fileMatch(value, kind: .domain, path: "/p/\(name)")])
        }
        // 3 hosts ⇒ high.
        let three = CorrelationEngine.correlate([host("H1"), host("H2"), host("H3")])
        let f3 = try #require(three.first { $0.title.contains("Shared indicator") })
        #expect(f3.severity == .high)
        #expect(f3.title.contains("3 hosts"))

        // 4 hosts ⇒ critical.
        let four = CorrelationEngine.correlate([host("H1"), host("H2"), host("H3"), host("H4")])
        let f4 = try #require(four.first { $0.title.contains("Shared indicator") })
        #expect(f4.severity == .critical)
    }

    // MARK: Guards

    @Test func singleHostYieldsNothing() {
        let only = HostSummary(
            hostID: UUID(), hostname: "Solo",
            iocMatches: [fileMatch("evil.example.com", kind: .domain, path: "/p")],
            users: ["jsmith"], remoteLogonSourceIPs: ["10.0.0.50"])
        #expect(CorrelationEngine.correlate([only]).isEmpty)
    }

    @Test func emptyInputYieldsNothing() {
        #expect(CorrelationEngine.correlate([]).isEmpty)
    }

    @Test func sameIndicatorRepeatedOnOneHostIsNotSpread() {
        // 50 matches of one domain on a SINGLE host must not look like spread.
        let a = UUID()
        let many = (0..<50).map { fileMatch("evil.example.com", kind: .domain, path: "/p/\($0)") }
        let host = HostSummary(hostID: a, hostname: "WS01", iocMatches: many)
        let other = HostSummary(hostID: UUID(), hostname: "WS02",
                                iocMatches: [fileMatch("other.example", kind: .domain, path: "/q")])
        let findings = CorrelationEngine.correlate([host, other])
        #expect(findings.contains { $0.title.contains("evil.example.com") } == false)
    }
}
