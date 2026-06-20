import Foundation

/// Renders a macOS unified-log **format string** against its decoded argument
/// items (M5b) — the printf-style substitution that turns
/// *"Adopted persona %@"* + `["BA08DA59-…"]` into the final message.
///
/// Supports the conversions seen in practice: `%@` (object), `%s`/`%S` (string),
/// the integer family (`%d %i %u %x %X %o`, with `l`/`ll`/`z`/`q` length
/// modifiers), `%f`/`%g`, `%c`, `%p`, and `%%`. Apple's `%{…}` annotations
/// (`%{public}@`, `%{private}d`, `%{errno}d`, `%{time_t}d`, `%{BOOL}d`, …) are
/// recognised: the visibility (`public`/`private`/`sensitive`) is honoured and a
/// few common type hints (`errno`, `BOOL`) are rendered specially. Anything
/// unparseable is left intact rather than dropped, so the message is never lost.
public nonisolated enum LogFormatter {

    /// A redacted private argument renders as this (matching `log show`).
    public static let privatePlaceholder = "<private>"

    /// Count the conversion specifiers in a format string (excluding `%%`) — the
    /// expected argument count, used to anchor the item decoder.
    public static func specifierCount(_ format: String) -> Int {
        let a = Array(format)
        var count = 0, i = 0
        while i < a.count {
            if a[i] == "%" {
                if i + 1 < a.count, a[i + 1] == "%" { i += 2; continue }
                count += 1
            }
            i += 1
        }
        return count
    }

    /// Render `format` with `items`. Extra items are ignored; missing items
    /// leave the specifier text in place.
    public static func render(format: String, items: [FirehoseItem]) -> String {
        let chars = Array(format)
        var out = ""
        var i = 0
        var arg = 0
        let n = chars.count

        while i < n {
            let c = chars[i]
            if c != "%" { out.append(c); i += 1; continue }
            // Look at what follows the '%'.
            if i + 1 < n, chars[i + 1] == "%" { out.append("%"); i += 2; continue }

            // Parse one conversion specifier: %[{annotation}][flags][width][.prec][length]<conv>
            var j = i + 1
            var annotation = ""
            if j < n, chars[j] == "{" {
                var k = j + 1
                while k < n, chars[k] != "}" { annotation.append(chars[k]); k += 1 }
                if k < n { j = k + 1 } else { out.append(c); i += 1; continue }  // unterminated
            }
            // flags, width, precision, length modifiers — consume but mostly ignore.
            let convStart = j
            while j < n, "-+ #0".contains(chars[j]) { j += 1 }
            while j < n, chars[j].isNumber { j += 1 }
            if j < n, chars[j] == "." { j += 1; while j < n, chars[j].isNumber { j += 1 } }
            while j < n, "lhqLzjt".contains(chars[j]) { j += 1 }
            guard j < n else { out.append(contentsOf: chars[i...]); break }
            let conv = chars[j]
            let nextIndex = j + 1

            // Resolve the argument.
            let annLower = annotation.lowercased()
            let item: FirehoseItem? = (arg < items.count) ? items[arg] : nil

            switch conv {
            case "@", "s", "S", "d", "i", "u", "x", "X", "o", "f", "F", "g", "G", "c", "p", "D", "U":
                let isPrivate = (item?.isPrivate ?? false)
                    || annLower.contains("private") || annLower.contains("sensitive")
                if let item, let v = item.value, !isPrivate {
                    out += formatValue(v, conv: conv, annotation: annLower)
                } else if item != nil {
                    out += privatePlaceholder
                } else {
                    // No argument available — keep the raw specifier text.
                    out += String(chars[i..<nextIndex])
                }
                arg += 1
            default:
                // Unknown conversion: keep it verbatim, don't consume an arg.
                out += String(chars[i..<nextIndex])
            }
            _ = convStart
            i = nextIndex
        }
        return out
    }

    /// Format a single resolved value for a conversion character + annotation.
    private static func formatValue(_ value: String, conv: Character, annotation: String) -> String {
        // errno hint: render the number as its symbolic-ish description. Guard
        // the Int32 conversion — a mis-decoded arg can be out of range.
        if annotation.contains("errno"), let code = Int(value), let c32 = Int32(exactly: code) {
            let msg = String(cString: strerror(c32))
            return "\(value) (\(msg))"
        }
        if annotation.contains("bool"), let code = Int(value) {
            return code == 0 ? "false" : "true"
        }
        switch conv {
        case "x", "X":
            if let iv = Int64(value) { return String(iv, radix: 16) }
            return value
        case "o":
            if let iv = Int64(value) { return String(iv, radix: 8) }
            return value
        default:
            return value
        }
    }
}
