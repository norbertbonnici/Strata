import Foundation

/// What the analyst picked in the Export sheet: which artifacts, in which
/// formats. All flags default off so callers opt in explicitly; the UI seeds
/// its own sensible defaults.
public nonisolated struct ExportSelection: Sendable, Equatable {
    public var reportMarkdown: Bool
    public var reportHTML: Bool
    public var timelineCSV: Bool
    public var timelineJSON: Bool
    public var findingsCSV: Bool
    public var findingsJSON: Bool
    public var iocMatchesCSV: Bool
    public var iocMatchesJSON: Bool
    /// Chain-of-custody report (acquisition provenance, source hashes, and the
    /// custody ledger). Separate from the examiner report. The PDF is the
    /// formal, paginated record; HTML/Markdown mirror it.
    public var cocPDF: Bool
    public var cocHTML: Bool
    public var cocMarkdown: Bool
    /// Raw custody-log data export.
    public var custodyCSV: Bool
    public var custodyJSON: Bool
    /// Severities to include in the examiner *report*. Defaults to all. This
    /// filters only the narrative report (findings list, severity rollups, and
    /// the findings timeline excerpt) - the raw findings CSV/JSON export stays
    /// complete so the data dump is always a faithful copy.
    public var reportSeverities: Set<Severity>

    public init(reportMarkdown: Bool = false, reportHTML: Bool = false,
                timelineCSV: Bool = false, timelineJSON: Bool = false,
                findingsCSV: Bool = false, findingsJSON: Bool = false,
                iocMatchesCSV: Bool = false, iocMatchesJSON: Bool = false,
                cocPDF: Bool = false, cocHTML: Bool = false, cocMarkdown: Bool = false,
                custodyCSV: Bool = false, custodyJSON: Bool = false,
                reportSeverities: Set<Severity> = Set(Severity.allCases)) {
        self.reportMarkdown = reportMarkdown
        self.reportHTML = reportHTML
        self.timelineCSV = timelineCSV
        self.timelineJSON = timelineJSON
        self.findingsCSV = findingsCSV
        self.findingsJSON = findingsJSON
        self.iocMatchesCSV = iocMatchesCSV
        self.iocMatchesJSON = iocMatchesJSON
        self.cocPDF = cocPDF
        self.cocHTML = cocHTML
        self.cocMarkdown = cocMarkdown
        self.custodyCSV = custodyCSV
        self.custodyJSON = custodyJSON
        self.reportSeverities = reportSeverities
    }

    /// True when nothing is selected - the Export button gates on this.
    public var isEmpty: Bool {
        !(reportMarkdown || reportHTML || timelineCSV || timelineJSON ||
          findingsCSV || findingsJSON || iocMatchesCSV || iocMatchesJSON ||
          cocPDF || cocHTML || cocMarkdown || custodyCSV || custodyJSON)
    }

    /// Whether any examiner-report format was picked.
    public var wantsReport: Bool { reportMarkdown || reportHTML }

    /// Whether any chain-of-custody report format was picked.
    public var wantsCoC: Bool { cocPDF || cocHTML || cocMarkdown }
}

/// One generated artifact: a bare filename (no path) and its bytes. The writer
/// places it inside the timestamped export folder.
public nonisolated struct ExportedFile: Sendable {
    public let filename: String
    public let data: Data

    public init(filename: String, data: Data) {
        self.filename = filename
        self.data = data
    }
}

/// Result of a write, surfaced back to the main actor. `Sendable` (carries no
/// bare `Error`) so it can cross the `Task.detached` boundary cleanly.
public nonisolated enum ExportOutcome: Sendable {
    case success(folderURL: URL, filenames: [String])
    case failure(message: String)
}
