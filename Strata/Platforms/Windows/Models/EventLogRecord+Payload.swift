import Foundation

public extension EventLogRecord {
    /// Pull the value of `<Data Name="<name>">value</Data>` out of the payload XML,
    /// with XML entities decoded (evtxexport writes `2>&1` as `2&gt;&amp;1`), so
    /// analyzers match the real text. Returns nil if the field is absent or empty.
    ///
    /// A plain substring scan, not a regex: analyzers, correlation and the
    /// lateral graph call this millions of times on a large case, and the old
    /// implementation compiled a fresh NSRegularExpression on every call. Same
    /// semantics as `<Data Name="NAME">([^<]*)</Data>`: the first occurrence
    /// whose text runs straight to `</Data>` wins.
    nonisolated func data(_ name: String) -> String? {
        let open = "<Data Name=\"\(name)\">"
        var from = payloadXML.startIndex
        while let tag = payloadXML.range(of: open, options: .literal, range: from..<payloadXML.endIndex) {
            let rest = payloadXML[tag.upperBound...]
            if let lt = rest.firstIndex(of: "<"), rest[lt...].hasPrefix("</Data>") {
                let value = XMLEntityDecoder.decode(String(rest[..<lt]))
                return value.isEmpty ? nil : value
            }
            from = tag.upperBound
        }
        return nil
    }
}
