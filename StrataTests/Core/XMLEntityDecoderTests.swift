//
//  XMLEntityDecoderTests.swift
//  StrataTests
//
//  evtxexport XML-escapes `<`, `>`, `&` and quotes inside `<Data>` values, so
//  event fields must be entity-decoded before analyzers match them. Covers the
//  decoder itself, `EventLogRecord.data(_:)`, and the Impacket detections that
//  depend on the raw `2>&1` / `1> \\127.0.0.1\` text.
//

import Testing
import Foundation
@testable import Strata

struct XMLEntityDecoderTests {

    // MARK: - Decoder

    @Test func decodesPredefinedEntities() {
        #expect(XMLEntityDecoder.decode("a &lt;b&gt; &amp; &quot;c&quot; &apos;d&apos;")
                == "a <b> & \"c\" 'd'")
    }

    @Test func decodesNumericReferences() {
        #expect(XMLEntityDecoder.decode("&#38;&#x26;&#X3C;&#233;") == "&&<é")
    }

    @Test func decodesInOnePass() {
        // An escaped entity decodes once, to the literal entity text.
        #expect(XMLEntityDecoder.decode("&amp;lt;") == "&lt;")
    }

    @Test func leavesUnknownOrMalformedReferencesVerbatim() {
        #expect(XMLEntityDecoder.decode("a & b") == "a & b")
        #expect(XMLEntityDecoder.decode("&nbsp; &#; &#xZZ; &unterminated") == "&nbsp; &#; &#xZZ; &unterminated")
        #expect(XMLEntityDecoder.decode("no entities") == "no entities")
    }

    // MARK: - EventLogRecord.data

    private func proc4688(_ escapedCommandLine: String) -> EventLogRecord {
        let xml = """
        <EventData>\
        <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>\
        <Data Name="CommandLine">\(escapedCommandLine)</Data>\
        </EventData>
        """
        return EventLogRecord(recordNumber: 1, writtenAt: Date(timeIntervalSince1970: 1_700_000_000),
                              eventID: 4688, level: 4, channel: "Security",
                              provider: "Microsoft-Windows-Security-Auditing",
                              computer: "WS01", payloadXML: xml, sourceFile: "Security.evtx")
    }

    @Test func dataFieldIsEntityDecoded() {
        let event = proc4688("cmd.exe /Q /c whoami 2&gt;&amp;1")
        #expect(event.data("CommandLine") == "cmd.exe /Q /c whoami 2>&1")
    }

    @Test func dataKeepsTheRegexSemantics() {
        func record(_ xml: String) -> EventLogRecord {
            EventLogRecord(recordNumber: 1, writtenAt: Date(timeIntervalSince1970: 0), eventID: 1,
                           level: 4, channel: "c", provider: "p", computer: "h",
                           payloadXML: xml, sourceFile: "f")
        }
        // Absent, empty and self-closing fields are nil.
        #expect(record("<EventData></EventData>").data("X") == nil)
        #expect(record("<Data Name=\"X\"></Data>").data("X") == nil)
        #expect(record("<Data Name=\"X\"/>").data("X") == nil)
        // The name matches exactly — no prefix match on a longer field name.
        #expect(record("<Data Name=\"XY\">no</Data><Data Name=\"X\">yes</Data>").data("X") == "yes")
        // A value interrupted by markup is skipped in favour of a later clean one.
        #expect(record("<Data Name=\"X\">a<b/>c</Data><Data Name=\"X\">ok</Data>").data("X") == "ok")
        // Multi-line values come through intact.
        #expect(record("<Data Name=\"X\">line1\nline2</Data>").data("X") == "line1\nline2")
    }

    // MARK: - Detections that depend on the decoded text

    private func impacket(_ events: [EventLogRecord]) -> [Finding] {
        ImpacketRemoteExecAnalyzer().analyze(
            context: AnalysisContext(files: [], events: events, timeline: [], registryValues: []))
    }

    @Test func impacketWrapperConfirmedByEscapedStderrRedirect() {
        // The /Q /c wrapper only fires with `2>&1` nearby — which evtxexport
        // writes as `2&gt;&amp;1`.
        let findings = impacket([proc4688("cmd.exe /Q /c whoami 2&gt;&amp;1")])
        #expect(findings.count == 1)
        #expect(findings.first?.title.contains("cmd /Q /c wrapper") == true)
    }

    @Test func impacketLoopbackRedirectMatchesEscapedCommandLine() {
        let findings = impacket([proc4688("cmd.exe /c dir 1&gt; \\\\127.0.0.1\\D$\\out.txt")])
        #expect(findings.first?.title.contains("loopback redirect") == true)
    }

    @Test func impacketWrapperWithoutRedirectStaysQuiet() {
        #expect(impacket([proc4688("cmd.exe /Q /c whoami")]).isEmpty)
    }
}
