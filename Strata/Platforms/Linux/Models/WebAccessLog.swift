import Foundation

/// One request from an nginx/apache **access log** (Common or Combined Log
/// Format). For a web-facing host this is the front line of the investigation:
/// exploitation attempts, webshell hits, and recon all land here, each with a
/// real timestamp (the bracketed date carries an explicit timezone, unlike
/// syslog). Persisted per host as `weblog.json`, spliced onto the timeline,
/// and mined by `WebLogAnalyzer`.
public nonisolated struct WebAccessLogEntry: Identifiable, Hashable, Sendable, Codable {
    public enum Server: String, Sendable, Codable {
        case nginx, apache, unknown
        public var label: String {
            switch self {
            case .nginx:   return "nginx"
            case .apache:  return "apache"
            case .unknown: return "web"
            }
        }
    }

    public let id: UUID
    public let timestamp: Date?
    public let clientIP: String
    public let method: String        // GET / POST / HEAD / …
    public let path: String          // request target up to '?'
    public let query: String?        // raw query string (after '?'), if any
    public let httpVersion: String?  // "HTTP/1.1"
    public let status: Int           // response code (0 if unparseable)
    public let bytes: Int64          // response size ('-' → 0)
    public let referer: String?      // Combined format only
    public let userAgent: String?    // Combined format only
    public let server: Server
    public let sourceFile: String

    public init(id: UUID = UUID(), timestamp: Date?, clientIP: String, method: String,
                path: String, query: String? = nil, httpVersion: String? = nil,
                status: Int, bytes: Int64, referer: String? = nil, userAgent: String? = nil,
                server: Server, sourceFile: String) {
        self.id = id
        self.timestamp = timestamp
        self.clientIP = clientIP
        self.method = method
        self.path = path
        self.query = query
        self.httpVersion = httpVersion
        self.status = status
        self.bytes = bytes
        self.referer = referer
        self.userAgent = userAgent
        self.server = server
        self.sourceFile = sourceFile
    }

    /// Full request target (path + query) for display/search.
    public var target: String {
        query.map { "\(path)?\($0)" } ?? path
    }
}
