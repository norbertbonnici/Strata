import Foundation

public extension EventLogRecord {
    /// Pull the value of `<Data Name="<name>">value</Data>` out of the payload XML.
    /// Returns nil if the field is absent or empty. Lets analyzers stay readable.
    nonisolated func data(_ name: String) -> String? {
        let pattern = "<Data Name=\"\(NSRegularExpression.escapedPattern(for: name))\">([^<]*)</Data>"
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: payloadXML,
                                           range: NSRange(payloadXML.startIndex..., in: payloadXML)),
              match.numberOfRanges > 1,
              let range = Range(match.range(at: 1), in: payloadXML)
        else { return nil }
        let value = String(payloadXML[range])
        return value.isEmpty ? nil : value
    }
}
