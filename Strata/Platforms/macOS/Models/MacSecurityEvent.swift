import Foundation

/// File-backed macOS security telemetry recovered from Gatekeeper, XProtect,
/// XProtect Remediator, MRT, and related policy logs.
public nonisolated struct MacSecurityEvent: Identifiable, Hashable, Sendable, Codable {
    public enum Kind: String, CaseIterable, Sendable, Codable {
        case gatekeeper
        case xprotect
        case xprotectRemediator
        case mrt
        case syspolicyd
        case other

        public var label: String {
            switch self {
            case .gatekeeper: return "Gatekeeper"
            case .xprotect: return "XProtect"
            case .xprotectRemediator: return "XProtect Remediator"
            case .mrt: return "MRT"
            case .syspolicyd: return "syspolicyd"
            case .other: return "macOS Security"
            }
        }
    }

    public enum Severity: String, CaseIterable, Comparable, Sendable, Codable {
        case info
        case allowed
        case warning
        case blocked
        case detected
        case remediated

        public var label: String {
            switch self {
            case .info: return "Info"
            case .allowed: return "Allowed"
            case .warning: return "Warning"
            case .blocked: return "Blocked"
            case .detected: return "Detected"
            case .remediated: return "Remediated"
            }
        }

        public static func < (lhs: Severity, rhs: Severity) -> Bool {
            order(lhs) < order(rhs)
        }

        private static func order(_ severity: Severity) -> Int {
            switch severity {
            case .info: return 0
            case .allowed: return 1
            case .warning: return 2
            case .remediated: return 3
            case .blocked: return 4
            case .detected: return 5
            }
        }
    }

    public let id: UUID
    public let kind: Kind
    public let severity: Severity
    public let timestamp: Date?
    public let process: String?
    public let message: String
    public let path: String?
    public let signature: String?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), kind: Kind, severity: Severity, timestamp: Date?,
                process: String?, message: String, path: String?, signature: String?,
                scope: String, sourceFile: String) {
        self.id = id
        self.kind = kind
        self.severity = severity
        self.timestamp = timestamp
        self.process = process
        self.message = message
        self.path = path
        self.signature = signature
        self.scope = scope
        self.sourceFile = sourceFile
    }

    public var title: String {
        if let signature, !signature.isEmpty { return signature }
        if let path, !path.isEmpty { return (path as NSString).lastPathComponent }
        return message
    }

    public var timelineSummary: String {
        let subject = path ?? signature ?? message
        return "[\(kind.label) \(severity.label)] \(subject)"
    }
}
