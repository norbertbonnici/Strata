import Foundation

/// System 7045 = a new service was installed. Attacker tradecraft routinely
/// drops services in writable user dirs, runs out of cmd/powershell, or uses
/// scripted/encoded image paths. Plain Microsoft services landing under
/// C:\Windows\System32 from SYSTEM are common and noisy, so we down-rank them.
///
/// ATT&CK T1543.003 Create or Modify System Process: Windows Service.
/// Kill-chain phase: Installation.
public nonisolated struct ServiceInstallAnalyzer: Analyzer {
    public let name = "Service Install"
    public init() {}

    /// Path roots that almost never host a legitimate Windows service.
    private static let suspiciousRoots = [
        "\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\",
        "\\public\\", "\\windows\\temp\\",
    ]

    /// Image-path tokens that strongly suggest scripted / lolbin-launched services.
    private static let suspiciousTokens = [
        "powershell", "-enc", "-encodedcommand", "-nop", "-noprofile",
        "frombase64string", "iex ", "invoke-expression",
        "cmd.exe /c", "cmd /c", "rundll32", "regsvr32", "mshta", "wmic",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.events
            .filter { $0.eventID == 7045 }
            .compactMap { makeFinding(from: $0) }
    }

    private func makeFinding(from event: EventLogRecord) -> Finding? {
        let serviceName = event.data("ServiceName") ?? "(unknown)"
        let imagePath   = event.data("ImagePath") ?? ""
        let startType   = event.data("StartType") ?? ""
        let serviceAcct = event.data("AccountName") ?? ""

        let pathLower = imagePath.lowercased()
        let suspiciousPath = Self.suspiciousRoots.contains { pathLower.contains($0) }
        let suspiciousImage = Self.suspiciousTokens.contains { pathLower.contains($0) }

        // Down-rank vanilla System32 services to info unless something else flags.
        let severity: Severity
        if suspiciousImage || suspiciousPath {
            severity = .high
        } else if pathLower.contains("\\system32\\") || pathLower.contains("\\syswow64\\") {
            severity = .info
        } else {
            severity = .medium
        }

        var bullets: [String] = []
        bullets.append("Service: \(serviceName)")
        if !imagePath.isEmpty { bullets.append("Image: \(imagePath)") }
        if !startType.isEmpty { bullets.append("Start: \(startType)") }
        if !serviceAcct.isEmpty { bullets.append("Account: \(serviceAcct)") }
        if suspiciousImage { bullets.append("Reason: image path uses lolbin / encoded command pattern") }
        if suspiciousPath  { bullets.append("Reason: image path is under a user-writable directory") }

        return Finding(
            title: "Service installed: \(serviceName)",
            detail: bullets.joined(separator: "\n"),
            severity: severity,
            phase: .installation,
            technique: AttackTechnique(attackID: "T1543.003",
                                        name: "Create or Modify System Process: Windows Service"),
            timestamp: event.writtenAt,
            evidencePaths: imagePath.isEmpty ? [event.sourceFile] : [imagePath])
    }
}
