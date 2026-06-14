import Foundation

/// The loaded set of `.uuidtext` + `dsc` string catalogs for a host, and the
/// logic that resolves a firehose tracepoint's **format string** and **emitting
/// process name** from them. This is M5's resolution layer; rendering the format
/// string against the tracepoint's argument items (the `%@`/`%d` substitution)
/// is M5b.
///
/// Source dispatch is driven by the tracepoint flags' format-string-type bits
/// (`flags & 0x000e`), confirmed against the real macOS-12 image:
///   - `0x02` main-executable → the process's **main UUID** `.uuidtext`
///   - `0x04` shared-cache    → the **`dsc`** (100% of shared-cache tracepoints
///                              resolved on the test image)
///   - `0x08`/`0x0a`/`0x0c`   → absolute / uuid-relative / alternate; resolved
///                              via the process's loaded-image table where
///                              possible (refined in M5b).
public nonisolated struct UnifiedLogStringCatalog: Sendable {
    /// `.uuidtext` files keyed by UUID (canonical upper-case 8-4-4-4-12).
    public var uuidTexts: [String: UUIDTextFile]
    /// `dsc` shared-cache files keyed by UUID.
    public var dscs: [String: DscFile]

    public init(uuidTexts: [String: UUIDTextFile] = [:], dscs: [String: DscFile] = [:]) {
        self.uuidTexts = uuidTexts
        self.dscs = dscs
    }

    /// Format-string source as selected by the tracepoint flags.
    public enum Source: Sendable, Equatable {
        case mainExe, sharedCache, absolute, uuidRelative, other
        public init(flags: UInt16) {
            switch flags & 0x000e {
            case 0x02: self = .mainExe
            case 0x04: self = .sharedCache
            case 0x08: self = .absolute
            case 0x0a: self = .uuidRelative
            default:   self = .other
            }
        }
    }

    public struct Resolved: Sendable, Equatable {
        /// The raw format string (with `%@`/`%d`/… placeholders) — nil if the
        /// referenced catalog wasn't available.
        public var formatString: String?
        /// The emitting process's leaf name (from the main image path).
        public var process: String?
        /// The library that owns the format string (the `dsc`/uuidtext image
        /// path leaf) — may differ from `process` for shared-cache strings.
        public var library: String?
        public var source: Source
    }

    /// Resolve a tracepoint. `mainUUID` / `dscUUID` come from the catalog
    /// `ProcessInfo` (`catalog.uuid(at: mainUUIDIndex/dscUUIDIndex)`).
    public func resolve(flags: UInt16, formatStringLocation: UInt32,
                        mainUUID: String?, dscUUID: String?) -> Resolved {
        let source = Source(flags: flags)
        // The emitting process is always the main executable image.
        let process = mainUUID.flatMap { uuidTexts[$0]?.processName }

        switch source {
        case .mainExe:
            let ut = mainUUID.flatMap { uuidTexts[$0] }
            return Resolved(formatString: ut?.formatString(at: formatStringLocation),
                            process: process, library: process, source: source)
        case .sharedCache:
            if let dsc = dscUUID.flatMap({ dscs[$0] }),
               let r = dsc.resolve(offset: UInt64(formatStringLocation)) {
                let lib = (r.imagePath as NSString).lastPathComponent
                return Resolved(formatString: r.formatString, process: process,
                                library: lib.isEmpty ? nil : lib, source: source)
            }
            return Resolved(formatString: nil, process: process, library: nil, source: source)
        default:
            // absolute / uuid-relative / other: best-effort process name now;
            // loaded-image resolution lands in M5b.
            return Resolved(formatString: nil, process: process, library: process, source: source)
        }
    }
}
