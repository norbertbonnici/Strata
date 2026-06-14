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
            // loaded-image resolution is a known gap (~17% on the test image).
            return Resolved(formatString: nil, process: process, library: process, source: source)
        }
    }

    /// The fully resolved + rendered message for a firehose tracepoint.
    public struct Message: Sendable, Equatable {
        public var process: String?
        public var library: String?
        /// The rendered message (format string + substituted args), or nil if the
        /// format string couldn't be resolved.
        public var message: String?
        public var subsystemIdentifier: UInt16?
        public var source: Source
    }

    /// A loaded image of the emitting process: its virtual base + extent + UUID,
    /// used to resolve an **absolute** program counter to the owning `.uuidtext`.
    public struct ImageEntry: Sendable, Equatable {
        public let loadAddress: UInt64
        public let size: UInt32
        public let uuid: String
        public init(loadAddress: UInt64, size: UInt32, uuid: String) {
            self.loadAddress = loadAddress; self.size = size; self.uuid = uuid
        }
    }

    /// Resolve a tracepoint's format string and render the final message.
    /// Implements the full firehose resolution: main-exe / shared-cache
    /// (with the large-offset math) / absolute (loaded-image range lookup) /
    /// uuid-relative. `imageEntries` are the process's loaded images (from the
    /// catalog) — needed only for the absolute case.
    public func render(flags: UInt16, formatStringLocation fmtLoc: UInt32, data: [UInt8],
                       mainUUID: String?, dscUUID: String?,
                       imageEntries: [ImageEntry] = []) -> Message {
        let source = Source(flags: flags)
        let process = mainUUID.flatMap { uuidTexts[$0]?.processName }
        let decoded = FirehoseItemDecoder.decode(data, flags: flags, expectedCount: 0)

        var formatString: String?
        var library: String? = process
        if fmtLoc & 0x8000_0000 != 0 {
            // Dynamic format string — the message is a single runtime string.
            formatString = "%s"
        } else {
            switch flags & 0x000e {
            case 0x02:   // main_exe
                formatString = mainUUID.flatMap { uuidTexts[$0]?.formatString(at: fmtLoc) }
            case 0x04, 0x0c:   // shared_cache (+ large_shared_cache)
                let real = Self.largeOffset(decoded.largeOffset, decoded.largeSharedCache) &+ UInt64(fmtLoc)
                if let dsc = dscUUID.flatMap({ dscs[$0] }), let r = dsc.resolve(offset: real) {
                    formatString = r.formatString
                    let leaf = (r.imagePath as NSString).lastPathComponent
                    if !leaf.isEmpty { library = leaf }
                }
            case 0x08:   // absolute → loaded-image range lookup
                let addr = (0x1_0000_0000 &* UInt64(decoded.altIndex)) &+ UInt64(decoded.pcID)
                if let img = imageEntries.first(where: {
                    addr >= $0.loadAddress && addr <= $0.loadAddress &+ UInt64($0.size)
                }), let ut = uuidTexts[img.uuid] {
                    formatString = ut.formatString(at: fmtLoc)
                    library = ut.processName
                }
            case 0x0a:   // uuid_relative → the embedded UUID's .uuidtext
                if let u = decoded.uuidRelative, let ut = uuidTexts[u] {
                    formatString = ut.formatString(at: fmtLoc)
                    library = ut.processName
                }
            default:
                break
            }
        }

        let message = formatString.map { LogFormatter.render(format: $0, items: decoded.items) }
        return Message(process: process, library: library, message: message,
                       subsystemIdentifier: decoded.subsystemID, source: source)
    }

    /// The shared-cache large-offset extension (Mandiant `get_message`):
    /// combines the `large_offset` / `large_shared_cache` values into the high
    /// bits added to the format-string offset before the `dsc` lookup.
    static func largeOffset(_ largeOffset: UInt16, _ largeSharedCache: UInt16) -> UInt64 {
        let lo = UInt64(largeOffset), lsc = UInt64(largeSharedCache)
        if (lo == 1 || lo == 2) && lo > lsc { return 0x8000_0000 &* lo }
        if lsc != 0 { return 0x1_0000_0000 &* (lsc / 2) }
        return 0x1_0000_0000 &* lo
    }
}
