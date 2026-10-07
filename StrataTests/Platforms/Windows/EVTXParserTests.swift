//
//  EVTXParserTests.swift
//  StrataTests
//
//  The evtxexport record splitter + field extraction, and the allocation-free
//  SystemTime fast path, which must stay bit-identical to the
//  ISO8601DateFormatter it replaced on the hot path.
//

#if os(macOS)

import Testing
import Foundation
@testable import Strata

struct EVTXParserTests {

    // Built per use: ISO8601DateFormatter isn't Sendable, so no shared static.
    private static var formatter: ISO8601DateFormatter {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }

    @Test func fastSystemTimeMatchesTheFormatterExactly() throws {
        for value in ["2026-03-17T16:09:31.055125500Z", "2026-03-17T16:09:31.999999999Z",
                      "2024-02-29T23:59:59.000000100Z", "1999-12-31T00:00:00.5Z",
                      "2001-01-01T00:00:00.123Z", "2038-01-19T03:14:08.000000000Z"] {
            let fast = try #require(EVTXParser.parseSystemTime(value), "\(value)")
            #expect(fast == Self.formatter.date(from: value), "\(value)")
        }
    }

    @Test func fastSystemTimeHandlesWholeSeconds() throws {
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        let value = "2026-03-17T16:09:31Z"
        #expect(try #require(EVTXParser.parseSystemTime(value)) == plain.date(from: value))
    }

    @Test func unexpectedShapesFallBack() {
        // Not the evtxexport shape → nil from the fast path; parseTimestamp then
        // defers to the formatter (here: an offset it understands, or epoch 0).
        #expect(EVTXParser.parseSystemTime("2026-03-17T16:09:31+02:00") == nil)
        #expect(EVTXParser.parseSystemTime("2026-13-17T16:09:31Z") == nil)
        #expect(EVTXParser.parseSystemTime("garbage") == nil)
        #expect(EVTXParser.parseSystemTime(
            "2026-03-17T16:09:31.\(String(repeating: "9", count: 40))Z")?.timeIntervalSince1970
            == EVTXParser.parseSystemTime("2026-03-17T16:09:31.999Z")?.timeIntervalSince1970)
        #expect(EVTXParser.parseTimestamp("2026-03-17T18:09:31+02:00")
                == EVTXParser.parseSystemTime("2026-03-17T16:09:31Z"))
        #expect(EVTXParser.parseTimestamp("garbage") == Date(timeIntervalSince1970: 0))
    }

    @Test func extractsRecordFields() throws {
        let xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{x}"/>
            <EventID Qualifiers="0">4624</EventID>
            <Level>0</Level>
            <TimeCreated SystemTime="2026-03-17T16:09:31.055125500Z"/>
            <EventRecordID>42</EventRecordID>
            <Channel>Security</Channel>
            <Computer>WS01</Computer>
          </System>
          <EventData>
            <Data Name="IpAddress">10.0.0.5</Data>
          </EventData>
        </Event>
        """
        let record = try #require(EVTXParser.records(from: xml, sourceFile: "Security.evtx").first)
        #expect(record.eventID == 4624)
        #expect(record.recordNumber == 42)
        #expect(record.channel == "Security")
        #expect(record.computer == "WS01")
        #expect(record.provider == "Microsoft-Windows-Security-Auditing")
        #expect(record.writtenAt == Self.formatter.date(from: "2026-03-17T16:09:31.055125500Z"))
        #expect(record.data("IpAddress") == "10.0.0.5")
    }
}

#endif
