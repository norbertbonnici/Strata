import Foundation

/// 30 commonly abused remote management & monitoring tools, identified by
/// executable basename. We scan both process-creation events (Security 4688
/// and Sysmon 1) and the filesystem listing so the rule still fires on KAPE
/// triage captures that don't include event logs.
///
/// Findings default to medium / low severity because many of these tools are
/// legitimate IT software. When the binary sits under a user-writable
/// location (AppData, Temp, Downloads, etc.) we promote to high - that's
/// the "dropped, not installed" tell.
///
/// ATT&CK T1219 Remote Access Software.
/// Kill-chain phase: Command & Control.
public nonisolated struct RMMToolAnalyzer: Analyzer {
    public let name = "Remote Access Software"
    public init() {}

    /// (vendor, executable basename - lowercased). 30 tools.
    private static let tools: [(vendor: String, exe: String)] = [
        ("AnyDesk",                     "anydesk.exe"),
        ("TeamViewer",                  "teamviewer.exe"),
        ("TeamViewer Service",          "teamviewer_service.exe"),
        ("Ammyy Admin",                 "aa_v3.exe"),
        ("Atera",                       "ateraagent.exe"),
        ("ScreenConnect / ConnectWise", "screenconnect.clientservice.exe"),
        ("ScreenConnect / ConnectWise", "screenconnect.windowsclient.exe"),
        ("LogMeIn",                     "logmein.exe"),
        ("LogMeIn Rescue",              "lmi_rescue.exe"),
        ("GoToAssist",                  "g2ax_comm_customer.exe"),
        ("Radmin",                      "radmin.exe"),
        ("Radmin Server",               "rserver3.exe"),
        ("DameWare Mini Remote",        "dwrcs.exe"),
        ("DameWare client agent",       "dwagsvc.exe"),
        ("mRemoteNG",                   "mremoteng.exe"),
        ("ngrok",                       "ngrok.exe"),
        ("TightVNC",                    "tvnserver.exe"),
        ("UltraVNC",                    "winvnc.exe"),
        ("RealVNC",                     "vncserver.exe"),
        ("Supremo",                     "supremo.exe"),
        ("Zoho Assist",                 "zaservice.exe"),
        ("Splashtop Streamer",          "splashtopstreamer.exe"),
        ("Splashtop client",            "strwinclt.exe"),
        ("Quick Assist",                "quickassist.exe"),
        ("N-able takecontrol",          "windowsagent.exe"),
        ("Kaseya agent",                "agentmon.exe"),
        ("SimpleHelp",                  "simplehelp.exe"),
        ("BeyondTrust / Bomgar",        "bomgar-scc.exe"),
        ("NetSupport Manager",          "client32.exe"),
        ("Remote Utilities",            "rutserv.exe"),
    ]

    private static let exeIndex: [String: String] = Dictionary(
        tools.map { ($0.exe, $0.vendor) }, uniquingKeysWith: { first, _ in first }
    )

    /// Paths where a legitimate RMM install would not live.
    private static let droppedRoots = [
        "\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\",
        "\\public\\", "\\windows\\temp\\", "\\downloads\\",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        findFromEvents(context.events) + findFromFiles(context.files)
    }

    private func findFromEvents(_ events: [EventLogRecord]) -> [Finding] {
        events.compactMap { event -> Finding? in
            let image: String
            if event.eventID == 4688 {
                image = event.data("NewProcessName") ?? ""
            } else if event.eventID == 1,
                      event.channel.localizedCaseInsensitiveContains("Sysmon") {
                image = event.data("Image") ?? ""
            } else { return nil }
            guard !image.isEmpty else { return nil }
            // Backslash-aware: Windows image paths use '\', which
            // NSString.lastPathComponent doesn't split on (see WindowsPath).
            let base = WindowsPath.basenameLower(image)
            guard let vendor = Self.exeIndex[base] else { return nil }
            let dropped = Self.droppedRoots.contains { image.lowercased().contains($0) }
            return Finding(
                title: "\(vendor) executed on \(event.computer)\(dropped ? " (dropped location)" : "")",
                detail: """
                Process: \(image)
                Observed on \(event.computer) at \(event.writtenAt.formatted()).\(dropped ? "\n\nBinary path is under a user-writable location, which is unusual for a real RMM install." : "")
                """,
                severity: dropped ? .high : .medium,
                phase: .commandAndControl,
                technique: AttackTechnique(attackID: "T1219",
                                            name: "Remote Access Software"),
                timestamp: event.writtenAt,
                evidencePaths: [image])
        }
    }

    private func findFromFiles(_ files: [FileEntry]) -> [Finding] {
        files.compactMap { file -> Finding? in
            guard let vendor = Self.exeIndex[file.name.lowercased()] else { return nil }
            let parentLower = file.parentPath.lowercased()
            let dropped = Self.droppedRoots.contains { parentLower.contains($0) }
            var detail = "File: \(file.fullPath)\nSize: \(file.size) bytes"
            if let c = file.created  { detail += "\nCreated: \(c.formatted())" }
            if let m = file.modified { detail += "\nModified: \(m.formatted())" }
            return Finding(
                title: "\(vendor) binary on disk: \(file.fullPath)\(dropped ? " (dropped location)" : "")",
                detail: detail,
                severity: dropped ? .high : .low,
                phase: .commandAndControl,
                technique: AttackTechnique(attackID: "T1219",
                                            name: "Remote Access Software"),
                timestamp: file.created ?? file.modified,
                evidencePaths: [file.fullPath])
        }
    }
}
