import Foundation

/// HKLM\SYSTEM\CurrentControlSet\Services lists every Windows service - the
/// machine's current state, regardless of whether a 7045 event was logged at
/// install time (handy when the attacker disabled audit logging before
/// dropping the service). We look at each service's `ImagePath` and
/// `ServiceDll` and score with the same heuristics as `ServiceInstallAnalyzer`.
///
/// ATT&CK T1543.003. Kill-chain phase: Installation.
public nonisolated struct ServicesRegistryAnalyzer: Analyzer {
    public let name = "Services (Registry)"
    public init() {}

    /// We accept both the canonical ControlSet001 spelling and
    /// CurrentControlSet, since regfexport may surface either.
    private static let pathFragments = [
        "ControlSet001\\Services\\",
        "ControlSet002\\Services\\",
        "CurrentControlSet\\Services\\",
    ]

    private static let suspiciousRoots = [
        "\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\",
        "\\public\\", "\\windows\\temp\\",
    ]
    private static let suspiciousTokens = [
        "powershell", "-enc", "-encodedcommand", "frombase64string",
        "iex ", "invoke-expression",
        "cmd.exe /c", "cmd /c", "rundll32", "regsvr32", "mshta", "wmic",
    ]

    public func analyze(context: AnalysisContext) -> [Finding] {
        context.registryValues.compactMap { value -> Finding? in
            guard value.hive.uppercased().contains("SYSTEM"),
                  Self.pathFragments.contains(where: { value.path.contains($0) })
            else { return nil }
            guard value.name == "ImagePath" || value.name == "ServiceDll" else { return nil }

            let imagePath = value.data
            let pathLower = imagePath.lowercased()
            let suspiciousPath = Self.suspiciousRoots.contains { pathLower.contains($0) }
            let suspiciousImage = Self.suspiciousTokens.contains { pathLower.contains($0) }

            // Keep the noise floor low: vanilla Microsoft services from
            // System32 only show up at info severity unless something else
            // flags them.
            let severity: Severity
            if suspiciousImage || suspiciousPath {
                severity = .high
            } else if pathLower.contains("\\system32\\") || pathLower.contains("\\syswow64\\") {
                severity = .info
            } else {
                severity = .medium
            }

            let service = Self.serviceName(from: value.path) ?? "(unknown)"
            var bullets: [String] = ["Service: \(service)", "Image: \(imagePath)"]
            if suspiciousImage { bullets.append("Reason: lolbin / encoded command pattern") }
            if suspiciousPath  { bullets.append("Reason: image path under user-writable directory") }
            if let written = value.lastWritten {
                bullets.append("Last written: \(written.formatted())")
            }

            return Finding(
                title: "Service '\(service)' image path: \(imagePath)",
                detail: bullets.joined(separator: "\n"),
                severity: severity,
                phase: .installation,
                technique: AttackTechnique(attackID: "T1543.003",
                                            name: "Create or Modify System Process: Windows Service"),
                timestamp: value.lastWritten,
                evidencePaths: [value.fullPath, value.sourceFile])
        }
    }

    /// Pull the service name out of a path like "ControlSet001\Services\Foo\".
    private static func serviceName(from path: String) -> String? {
        for fragment in pathFragments {
            if let range = path.range(of: fragment) {
                let tail = path[range.upperBound...]
                let parts = tail.split(separator: "\\")
                return parts.first.map(String.init)
            }
        }
        return nil
    }
}
