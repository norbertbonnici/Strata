//
//  IOCMatcherTests.swift
//  StrataTests
//
//  IP indicators must match standalone addresses only (10.0.0.1 must not hit
//  10.0.0.15 / 110.0.0.1), and event payloads are entity-decoded first so an
//  IOC containing `&` matches evtxexport's `&amp;`-escaped text.
//

import Testing
import Foundation
@testable import Strata

struct IOCMatcherTests {

    private func event(_ payloadXML: String, id: UInt32 = 4688) -> EventLogRecord {
        EventLogRecord(recordNumber: 1, writtenAt: Date(timeIntervalSince1970: 1_700_000_000),
                       eventID: id, level: 4, channel: "Security",
                       provider: "Microsoft-Windows-Security-Auditing",
                       computer: "WS01", payloadXML: payloadXML, sourceFile: "Security.evtx")
    }

    private func payload(_ commandLine: String) -> String {
        "<EventData><Data Name=\"CommandLine\">\(commandLine)</Data></EventData>"
    }

    private func matches(_ iocs: [IOC], events: [EventLogRecord] = [],
                         files: [String] = []) -> [IOCMatch] {
        let entries = files.enumerated().map { index, path in
            FileEntry(id: Int64(index + 1), metaAddr: nil,
                      name: (path as NSString).lastPathComponent,
                      parentPath: (path as NSString).deletingLastPathComponent,
                      size: 1, isDirectory: false, isDeleted: false,
                      modified: nil, accessed: nil, changed: nil, created: nil)
        }
        return IOCMatcher(iocs: iocs).match(events: events, registry: [], files: entries)
    }

    @Test func ipDoesNotMatchLongerAddresses() {
        let ioc = IOC(kind: .ip, value: "10.0.0.1")
        for other in ["10.0.0.15", "10.0.0.123", "110.0.0.1", "1.10.0.0.1"] {
            #expect(matches([ioc], events: [event(payload("ping \(other)"))]).isEmpty,
                    "10.0.0.1 must not match \(other)")
        }
    }

    @Test func ipMatchesStandaloneAddress() {
        let ioc = IOC(kind: .ip, value: "10.0.0.1")
        for text in ["ping 10.0.0.1", "connect 10.0.0.1:445", "reached 10.0.0.1.", "::ffff:10.0.0.1"] {
            #expect(matches([ioc], events: [event(payload(text))]).count == 1, "\(text)")
        }
    }

    @Test func ipv6DoesNotMatchLongerAddress() {
        let ioc = IOC(kind: .ip, value: "fe80::1")
        #expect(matches([ioc], events: [event(payload("from fe80::1a2b"))]).isEmpty)
        #expect(matches([ioc], events: [event(payload("from fe80::1 port 22"))]).count == 1)
    }

    @Test func ipBoundaryAppliesToFilePaths() {
        let ioc = IOC(kind: .ip, value: "10.0.0.1")
        #expect(matches([ioc], files: ["/logs/10.0.0.15/access.log"]).isEmpty)
        #expect(matches([ioc], files: ["/logs/10.0.0.1/access.log"]).count == 1)
    }

    @Test func domainStillMatchesAsSubstring() {
        let ioc = IOC(kind: .domain, value: "evil.example")
        #expect(matches([ioc], events: [event(payload("curl https://cdn.evil.example/x"))]).count == 1)
    }

    @Test func urlWithAmpersandMatchesEscapedPayload() {
        let ioc = IOC(kind: .url, value: "http://evil.example/a.php?id=1&k=2")
        let found = matches([ioc], events: [event(payload("curl http://evil.example/a.php?id=1&amp;k=2"))])
        #expect(found.count == 1)
    }
}
