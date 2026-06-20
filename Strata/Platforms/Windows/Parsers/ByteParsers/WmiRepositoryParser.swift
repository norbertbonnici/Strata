import Foundation

/// Carves the WMI CIM repository (`OBJECTS.DATA`) for **event-subscription
/// persistence** (T1546.003) into `[WmiPersistenceEntry]`.
///
/// `OBJECTS.DATA` is a proprietary CIM database (pages + an `INDEX.BTR` B-tree),
/// too involved to fully parse in Swift. Like FireEye's PyWMIPersistenceFinder,
/// this keyword-carves the high-signal strings instead — validated against a real
/// repository (flare-wmi's `wmikatz` sample):
///  - **Bindings**: a `__FilterToConsumerBinding` carries ASCII references
///    `<Type>EventConsumer.Name="<name>"` and `__EventFilter.Name="<name>"`.
///  - **Filter WQL**: stored as `<filterName>\0\0<query>\0\0`.
///  - **CommandLine command**: `CommandLineEventConsumer\0<command>\0…`.
///  - **Script payloads**: an `ActiveScriptEventConsumer`'s `ScriptText` is a
///    large printable block (e.g. an `Invoke-Mimikatz` PowerShell). Surfaced
///    independently of bindings, so a malicious consumer is caught even when its
///    binding sits in unallocated repository space.
///
/// Pure + cross-platform; every read is bounds-checked and capped.
public nonisolated enum WmiRepositoryParser {
    private static let maxBindings = 5000
    private static let maxScripts = 500
    private static let maxScriptChars = 4096
    private static let bindingWindow = 512
    private static let minScriptRun = 120

    /// Built-in Microsoft subscriptions; also the canonical PoC names — noted but
    /// not dropped.
    private static let commonBenign = ["BVTConsumer", "BVTFilter",
                                       "SCM Event Log Consumer", "SCM Event Log Filter"]

    /// **Attacker-grade** tokens that mark a printable run as a malicious script
    /// payload. Deliberately specific: bare words like "powershell" or
    /// "createobject(" appear in benign CIM class-definition prose (Description
    /// qualifiers), so the gate uses execution/offensive signatures that prose
    /// doesn't carry. (Engine labelling, below, may still consult broader words.)
    private static let scriptIndicators = [
        "invoke-mimikatz", "invoke-reflectivepeinjection", "frombase64string",
        "downloadstring", "downloadfile", "-encodedcommand", "-enc ", "iex(",
        "new-object net.webclient", "system.net.webclient", "reflection.assembly",
        "[scriptblock]", "invoke-expression", "invoke-webrequest", "invoke-command",
        "add-type", "shellexecute(", "wscript.shell\".run",
    ]

    public static func parse(bytes b: [UInt8], sourceFile: String) -> [WmiPersistenceEntry] {
        var out: [WmiPersistenceEntry] = []
        out += carveBindings(b, sourceFile: sourceFile)
        out += carveScriptConsumers(b, sourceFile: sourceFile)
        return out
    }

    // MARK: - Bindings

    private static func carveBindings(_ b: [UInt8], sourceFile: String) -> [WmiPersistenceEntry] {
        let consumerRe = /([A-Za-z_]*EventConsumer)\.Name="([^"]{1,200})"/
        let filterRe = /_EventFilter\.Name="([^"]{1,200})"/

        var seen = Set<String>()
        var out: [WmiPersistenceEntry] = []
        for idx in indices(of: ascii("__FilterToConsumerBinding"), in: b, cap: maxBindings) {
            let end = min(idx + bindingWindow, b.count)
            let window = String(decoding: b[idx..<end], as: UTF8.self)
            guard let cm = try? consumerRe.firstMatch(in: window),
                  let fm = try? filterRe.firstMatch(in: window) else { continue }
            let consumerType = String(cm.1)
            let consumerName = String(cm.2)
            let filterName = String(fm.1)
            let key = "\(consumerName)\u{0}\(filterName)"
            guard seen.insert(key).inserted else { continue }

            out.append(WmiPersistenceEntry(
                kind: .binding,
                consumerName: consumerName,
                consumerType: consumerType,
                filterName: filterName,
                query: findValue(afterToken: filterName, in: b),
                command: consumerType == "CommandLineEventConsumer"
                    ? findCommand(consumerName: consumerName, in: b) : nil,
                isCommonBenign: commonBenign.contains(consumerName) || commonBenign.contains(filterName),
                sourceFile: sourceFile))
        }
        return out
    }

    /// `<token>\0\0<value>\0` — the layout filters use for their WQL query.
    private static func findValue(afterToken token: String, in b: [UInt8]) -> String? {
        let needle = ascii(token) + [0, 0]
        guard let at = indices(of: needle, in: b, cap: 1).first else { return nil }
        let value = printableRun(in: b, from: at + needle.count, maxLen: 1024)
        return value.isEmpty ? nil : value
    }

    /// A `CommandLineEventConsumer` instance is `marker\0…\0<command>\0…`, with
    /// the consumer name nearby. (The `.Name=` reference is excluded by requiring
    /// a NUL right after the marker; the class definition by the name check.)
    private static func findCommand(consumerName: String, in b: [UInt8]) -> String? {
        let marker = ascii("CommandLineEventConsumer")
        // Cap the marker scan: this runs once per binding (up to maxBindings), so
        // an OBJECTS.DATA packed with a dense field of `CommandLineEventConsumer`
        // markers could otherwise blow up to O(bindings × markers). 256 is far
        // more than any real repository carries.
        let markers = indices(of: marker, in: b, cap: 256)
        for (k, at) in markers.enumerated() {
            var p = at + marker.count
            guard p < b.count, b[p] == 0 else { continue }   // instance, not ".Name=" ref
            while p < b.count, b[p] == 0 { p += 1 }           // skip NUL padding
            let cmd = printableRun(in: b, from: p, maxLen: 512)
            guard !cmd.isEmpty, cmd != "CommandLineTemplate" else { continue }
            // Confirm the name appears within THIS record only — bounded by the
            // next consumer marker — so an adjacent instance's name can't make us
            // attribute the wrong command.
            let nextMarker = k + 1 < markers.count ? markers[k + 1] : b.count
            let scanEnd = min(at + 2048, nextMarker, b.count)
            if contains(ascii(consumerName), in: b, range: at..<scanEnd) { return cmd }
        }
        return nil
    }

    // MARK: - Script consumers (independent of bindings)

    private static func carveScriptConsumers(_ b: [UInt8], sourceFile: String) -> [WmiPersistenceEntry] {
        var out: [WmiPersistenceEntry] = []
        var seenHeads = Set<String>()
        var i = 0
        let n = b.count
        while i < n, out.count < maxScripts {
            // Accumulate a string value: printable ASCII + intra-string whitespace
            // (tab/CR/LF), so a multi-line script stays one run. Runs break on NUL
            // / other control bytes — how CIM separates string values.
            guard isScriptByte(b[i]) else { i += 1; continue }
            var j = i
            while j < n, isScriptByte(b[j]) { j += 1 }
            let len = j - i
            if len >= minScriptRun {
                let run = String(decoding: b[i..<min(j, i + maxScriptChars * 2)], as: UTF8.self)
                let lower = run.lowercased()
                if let engine = scriptEngineIfSuspicious(lower) {
                    let head = String(run.prefix(200))
                    if seenHeads.insert(head).inserted {
                        out.append(WmiPersistenceEntry(
                            kind: .scriptConsumer,
                            consumerType: "ActiveScriptEventConsumer",
                            scriptEngine: engine,
                            scriptText: String(run.prefix(maxScriptChars)),
                            sourceFile: sourceFile))
                    }
                }
            }
            i = j + 1
        }
        return out
    }

    /// Returns a best-effort engine label if the run carries an attacker-grade
    /// script signature, else nil (so CIM class-definition prose is skipped).
    /// The *gate* is the tight `scriptIndicators`; the engine label may then read
    /// broader words since the run has already qualified.
    private static func scriptEngineIfSuspicious(_ lower: String) -> String? {
        guard scriptIndicators.contains(where: { lower.contains($0) }) else { return nil }
        if lower.contains("powershell") || lower.contains("invoke-") || lower.contains("-enc")
            || lower.contains("frombase64string") || lower.contains("[scriptblock]") {
            return "PowerShell"
        }
        if lower.contains("createobject(") || lower.contains("wscript.shell") || lower.contains("vbscript") {
            return "VBScript/JScript"
        }
        return "Script"
    }

    // MARK: - Byte primitives

    private static func ascii(_ s: String) -> [UInt8] { Array(s.utf8) }

    /// Printable ASCII plus intra-string whitespace (tab/LF/CR).
    private static func isScriptByte(_ x: UInt8) -> Bool {
        (x >= 0x20 && x <= 0x7e) || x == 0x09 || x == 0x0a || x == 0x0d
    }

    private static func indices(of needle: [UInt8], in b: [UInt8], cap: Int = .max) -> [Int] {
        guard !needle.isEmpty, needle.count <= b.count, cap > 0 else { return [] }
        var result: [Int] = []
        let first = needle[0]
        let last = b.count - needle.count
        var i = 0
        while i <= last {
            if b[i] == first {
                var j = 1
                while j < needle.count, b[i + j] == needle[j] { j += 1 }
                if j == needle.count {
                    result.append(i)
                    if result.count >= cap { break }
                    i += needle.count
                    continue
                }
            }
            i += 1
        }
        return result
    }

    private static func contains(_ needle: [UInt8], in b: [UInt8], range: Range<Int>) -> Bool {
        guard !needle.isEmpty, range.lowerBound >= 0, range.upperBound <= b.count else { return false }
        let last = range.upperBound - needle.count
        guard last >= range.lowerBound else { return false }
        var i = range.lowerBound
        while i <= last {
            var j = 0
            while j < needle.count, b[i + j] == needle[j] { j += 1 }
            if j == needle.count { return true }
            i += 1
        }
        return false
    }

    private static func printableRun(in b: [UInt8], from start: Int, maxLen: Int) -> String {
        guard start >= 0, start < b.count else { return "" }
        var bytes: [UInt8] = []
        var i = start
        let end = min(start + maxLen, b.count)
        while i < end, b[i] >= 0x20, b[i] <= 0x7e { bytes.append(b[i]); i += 1 }
        return String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespaces)
    }
}
