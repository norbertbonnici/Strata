import Foundation

/// Parses nginx/apache **access logs** (Common Log Format and Combined Log
/// Format) into `WebAccessLogEntry` rows. Pure - text in, values out.
///
/// Combined Log Format (the apache/nginx default):
///
///     127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /p?a=1 HTTP/1.0" 200 2326 "ref" "UA"
///
/// Common Log Format drops the two trailing quoted fields (referer, UA). A
/// hand tokenizer (not a regex) keeps the bracketed date and the quoted
/// request/referer/UA fields intact even when they contain spaces.
public nonisolated enum WebLogParser {

    public static func parseAccess(text: String, sourceFile: String,
                                   server: WebAccessLogEntry.Server) -> [WebAccessLogEntry] {
        var entries: [WebAccessLogEntry] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if let entry = parseLine(String(rawLine), sourceFile: sourceFile, server: server) {
                entries.append(entry)
            }
        }
        return entries
    }

    static func parseLine(_ line: String, sourceFile: String,
                          server: WebAccessLogEntry.Server) -> WebAccessLogEntry? {
        let fields = tokenize(line)
        // host ident authuser [date] "request" status bytes ["ref" "ua"]
        guard fields.count >= 7 else { return nil }
        let clientIP = fields[0]
        guard clientIP != "-", !clientIP.isEmpty else { return nil }

        let date = parseDate(fields[3])
        let request = fields[4]
        let (method, path, query, version) = splitRequest(request)
        guard !method.isEmpty else { return nil }

        let status = Int(fields[5]) ?? 0
        let bytes = fields[6] == "-" ? 0 : (Int64(fields[6]) ?? 0)
        let referer = fields.count >= 8 && fields[7] != "-" ? fields[7] : nil
        let userAgent = fields.count >= 9 && fields[8] != "-" ? fields[8] : nil

        return WebAccessLogEntry(timestamp: date, clientIP: clientIP, method: method,
                                 path: path, query: query, httpVersion: version,
                                 status: status, bytes: bytes, referer: referer,
                                 userAgent: userAgent, server: server,
                                 sourceFile: sourceFile)
    }

    // MARK: - Tokenizer

    /// Split a log line into fields, treating `"..."` and `[...]` as single
    /// tokens (so the quoted request and the bracketed date stay whole). The
    /// surrounding quotes/brackets are stripped from the returned tokens.
    private static func tokenize(_ line: String) -> [String] {
        var fields: [String] = []
        var current = ""
        var enclosure: Character? = nil    // '"' or ']' (the expected closer)
        var inField = false

        for ch in line {
            if let closer = enclosure {
                if ch == closer { enclosure = nil }   // end of quoted/bracketed token
                else { current.append(ch) }
            } else if ch == "\"" {
                enclosure = "\""; inField = true
            } else if ch == "[" {
                enclosure = "]"; inField = true
            } else if ch == " " {
                if inField { fields.append(current); current = ""; inField = false }
            } else {
                current.append(ch); inField = true
            }
        }
        if inField { fields.append(current) }
        return fields
    }

    /// `"GET /path?q=1 HTTP/1.1"` → (GET, /path, "q=1", HTTP/1.1).
    private static func splitRequest(_ request: String) -> (String, String, String?, String?) {
        let parts = request.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard !parts.isEmpty else { return ("", "", nil, nil) }
        let method = parts[0]
        let target = parts.count >= 2 ? parts[1] : ""
        let version = parts.count >= 3 ? parts[2] : nil
        if let q = target.firstIndex(of: "?") {
            return (method, String(target[..<q]),
                    String(target[target.index(after: q)...]), version)
        }
        return (method, target, nil, version)
    }

    // MARK: - Date

    /// CLF date: `10/Oct/2000:13:55:36 -0700` (explicit timezone - accurate,
    /// unlike syslog). Parsed with a fixed POSIX formatter.
    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "dd/MMM/yyyy:HH:mm:ss Z"
        return f
    }()

    static func parseDate(_ field: String) -> Date? {
        dateFormatter.date(from: field)
    }
}
