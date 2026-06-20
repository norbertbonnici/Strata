import Foundation

/// One high-value record from the macOS **KnowledgeC** database
/// (`knowledgeC.db`) — Apple's on-device activity store (CoreDuet). It is the
/// richest *behavioral* timeline on a Mac: which app was in focus and for how
/// long, when the screen turned on/off, media playback, Safari visits. Forensic
/// gold for placing a user at the keyboard and reconstructing app activity
/// minute-by-minute.
///
/// Drawn from the `ZOBJECT` table; timestamps are Core Data "Mac absolute time"
/// (seconds since 2001-01-01), decoded straight into `Date` via
/// `timeIntervalSinceReferenceDate`.
public nonisolated struct KnowledgeEntry: Identifiable, Hashable, Sendable, Codable {
    public let id: UUID
    /// The raw stream name, e.g. `/app/inFocus`.
    public let stream: String
    /// The string value (a bundle id for app/media streams, a URL for Safari).
    public let value: String?
    /// The integer value (e.g. `/display/isBacklit` 1 = on, 0 = off).
    public let valueInt: Int?
    public let startDate: Date?
    public let endDate: Date?
    public let scope: String
    public let sourceFile: String

    public init(id: UUID = UUID(), stream: String, value: String?, valueInt: Int?,
                startDate: Date?, endDate: Date?, scope: String, sourceFile: String) {
        self.id = id
        self.stream = stream; self.value = value; self.valueInt = valueInt
        self.startDate = startDate; self.endDate = endDate
        self.scope = scope; self.sourceFile = sourceFile
    }

    /// Duration in seconds, when the record spans a window.
    public var duration: TimeInterval? {
        guard let s = startDate, let e = endDate, e > s else { return nil }
        return e.timeIntervalSince(s)
    }

    public enum Category: String, Sendable, Codable {
        case appFocus, appUsage, appActivity, display, deviceLock, devicePower
        case media, safari, notification, other
        public var label: String {
            switch self {
            case .appFocus:     return "App Focus"
            case .appUsage:     return "App Usage"
            case .appActivity:  return "App Activity"
            case .display:      return "Display"
            case .deviceLock:   return "Lock State"
            case .devicePower:  return "Power"
            case .media:        return "Media"
            case .safari:       return "Safari"
            case .notification: return "Notification"
            case .other:        return "Other"
            }
        }
    }

    public var category: Category {
        switch stream {
        case "/app/inFocus":        return .appFocus
        case "/app/usage":          return .appUsage
        case "/app/activity":       return .appActivity
        case "/display/isBacklit":  return .display
        case "/device/isLocked":    return .deviceLock
        case "/device/isPluggedIn": return .devicePower
        case "/media/nowPlaying":   return .media
        case "/safari/history":     return .safari
        case "/notification/usage": return .notification
        default:                    return .other
        }
    }

    /// A human-readable one-line summary for the row + timeline.
    public var summary: String {
        switch category {
        case .appFocus, .appUsage, .appActivity:
            let d = duration.map { " (\(Int($0))s)" } ?? ""
            return "\(value ?? "app")\(d)"
        case .display:
            return (valueInt ?? 0) == 1 ? "Screen on" : "Screen off"
        case .deviceLock:
            return (valueInt ?? 0) == 1 ? "Locked" : "Unlocked"
        case .devicePower:
            return (valueInt ?? 0) == 1 ? "Plugged in" : "On battery"
        case .media:
            return "Now playing: \(value ?? "?")"
        case .safari:
            return value ?? "Safari visit"
        case .notification:
            return "Notification: \(value ?? "?")"
        case .other:
            return value ?? stream
        }
    }
}
