import Foundation

/// Decodes XML character references in text pulled out of an XML document by
/// regex rather than a real parser — notably `evtxexport`'s event payloads,
/// which escape `<`, `>`, `&`, `"` and `'` inside `<Data>` values (a command
/// line `a 2>&1` arrives as `a 2&gt;&amp;1`). Matching or displaying the raw
/// text would compare analyzer patterns and IOCs against entity-encoded strings.
///
/// Handles the five predefined entities plus decimal (`&#38;`) and hex
/// (`&#x26;`) character references, in a single left-to-right pass so an
/// escaped entity (`&amp;lt;`) decodes once, to `&lt;`. Anything unrecognised
/// is left verbatim.
public nonisolated enum XMLEntityDecoder {
    /// Longest reference body considered (`#x10FFFF` is 8 characters).
    private static let maxReferenceLength = 10

    public static func decode(_ text: String) -> String {
        guard text.contains("&") else { return text }   // fast path: nothing to decode
        var out = ""
        out.reserveCapacity(text.utf8.count)
        var i = text.startIndex
        while i < text.endIndex {
            let ch = text[i]
            guard ch == "&",
                  let semicolon = text[text.index(after: i)...]
                      .prefix(maxReferenceLength + 1).firstIndex(of: ";"),
                  let decoded = reference(String(text[text.index(after: i)..<semicolon]))
            else {
                out.append(ch)
                i = text.index(after: i)
                continue
            }
            out.append(decoded)
            i = text.index(after: semicolon)
        }
        return out
    }

    private static func reference(_ body: String) -> Character? {
        switch body {
        case "lt":   return "<"
        case "gt":   return ">"
        case "amp":  return "&"
        case "quot": return "\""
        case "apos": return "'"
        default:
            guard body.hasPrefix("#") else { return nil }
            let digits = body.dropFirst()
            let value: UInt32?
            if digits.first == "x" || digits.first == "X" {
                value = UInt32(digits.dropFirst(), radix: 16)
            } else {
                value = UInt32(digits, radix: 10)
            }
            guard let value, let scalar = Unicode.Scalar(value) else { return nil }
            return Character(scalar)
        }
    }
}
