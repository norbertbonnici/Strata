import Foundation
import SwiftUI

extension AppModel {
    // MARK: - IOC management

    /// Parse a free-form paste, classify each token, dedupe against the
    /// existing list, and persist. Tokens separated by any whitespace,
    /// comma, or semicolon; lines starting with # are dropped as comments.
    func addIOCs(from pasted: String) {
        let separators = CharacterSet(charactersIn: ",;\n\r\t ")
        let cleaned = pasted
            .components(separatedBy: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }
            .joined(separator: "\n")
        let tokens = cleaned
            .components(separatedBy: separators)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines)
                     .trimmingCharacters(in: CharacterSet(charactersIn: "\"'<>")) }
            .filter { !$0.isEmpty }

        var seen = Set(iocs.map { $0.value.lowercased() })
        var added: [IOC] = []
        for token in tokens {
            let key = token.lowercased()
            if seen.contains(key) { continue }
            seen.insert(key)
            added.append(IOC(kind: IOCKind.classify(token), value: token))
        }
        iocs.append(contentsOf: added)
        saveIOCs()
        statusMessage = "Added \(added.count) IOC\(added.count == 1 ? "" : "s") (\(iocs.count) total)."
    }

    func removeIOC(_ id: UUID) {
        iocs.removeAll { $0.id == id }
        saveIOCs()
    }

    private func saveIOCs() {
        guard let bundleURL = currentCaseBundleURL else { return }
        do {
            try CaseStore.writeIOCs(iocs, in: bundleURL)
        } catch {
            errorMessage = "Failed to save IOCs: \(error.localizedDescription)"
        }
    }
}
