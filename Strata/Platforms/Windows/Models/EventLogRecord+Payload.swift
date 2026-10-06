import Foundation

public extension EventLogRecord {
    /// Pull the value of `<Data Name="<name>">value</Data>` out of the payload XML,
    /// with XML entities decoded (evtxexport writes `2>&1` as `2&gt;&amp;1`), so
    /// analyzers match the real text. Returns nil if the field is absent or empty.
    nonisolated func data(_ name: String) -> String? {
        let pattern = "<Data Name=\"\(NSRegularExpression.escapedPattern(for: name))\">([^<]*)</Data>"
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: payloadXML,
                                           range: NSRange(payloadXML.startIndex..., in: payloadXML)),
              match.numberOfRanges > 1,
              let range = Range(match.range(at: 1), in: payloadXML)
        else { return nil }
        let value = XMLEntityDecoder.decode(String(payloadXML[range]))
        return value.isEmpty ? nil : value
    }
}
