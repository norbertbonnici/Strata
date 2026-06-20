import Testing
import Foundation
@testable import Strata

struct CaseLibraryTests {

    @Test func listsDownloadedCasesAndIcloudPlaceholders() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("lib-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }

        // A downloaded case (real .strata directory)...
        try fm.createDirectory(at: root.appendingPathComponent("Alpha.strata"),
                               withIntermediateDirectories: true)
        // ...a not-yet-downloaded iCloud placeholder...
        try Data().write(to: root.appendingPathComponent(".Bravo.strata.icloud"))
        // ...and noise that must be ignored.
        try Data().write(to: root.appendingPathComponent("notes.txt"))
        try fm.createDirectory(at: root.appendingPathComponent("Misc"),
                               withIntermediateDirectories: true)

        let cases = CaseLibrary.cases(in: root)
        #expect(cases.map(\.name) == ["Alpha", "Bravo"])   // sorted, noise excluded
        let alpha = cases.first { $0.name == "Alpha" }
        let bravo = cases.first { $0.name == "Bravo" }
        #expect(alpha?.isDownloaded == true)
        #expect(bravo?.isDownloaded == false)
        // The placeholder resolves to the real bundle path, not the dotfile.
        #expect(bravo?.url.lastPathComponent == "Bravo.strata")
    }

    @Test func placeholderNameParsing() {
        #expect(CaseLibrary.placeholderCaseName(".Case.strata.icloud") == "Case.strata")
        #expect(CaseLibrary.placeholderCaseName("Case.strata") == nil)        // not a placeholder
        #expect(CaseLibrary.placeholderCaseName(".other.txt.icloud") == nil)  // wrong extension
        #expect(CaseLibrary.placeholderCaseName(".strata.icloud") == nil)     // no name
    }
}
