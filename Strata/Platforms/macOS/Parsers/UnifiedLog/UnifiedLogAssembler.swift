import Foundation

/// Ties the unified-log decode layers together (M6): walk each `.tracev3` file's
/// chunks, decode firehose tracepoints (M4), and render each into a full
/// `UnifiedLogEntry` — timestamp via the timesync boot (M2), process/level from
/// the catalog (M3), message via the `.uuidtext`/`dsc` string catalogs (M5).
///
/// Pure / `Sendable` so the (expensive) walk runs off the main actor.
public nonisolated enum UnifiedLogAssembler {

    /// Every catalog UUID referenced across the given `.tracev3` files — the set
    /// of `.uuidtext`/`dsc` files that must be extracted to resolve messages.
    /// Returned as canonical upper-case 8-4-4-4-12 strings.
    public static func referencedUUIDs(in tracev3Datas: [Data]) -> Set<String> {
        var uuids = Set<String>()
        for data in tracev3Datas {
            for cat in TraceV3Parser.catalogs(of: data) {
                for pi in cat.processInfos {
                    if let u = cat.uuid(at: pi.mainUUIDIndex) { uuids.insert(u) }
                    if let u = cat.uuid(at: pi.dscUUIDIndex) { uuids.insert(u) }
                    for e in pi.uuidEntries { if let u = cat.uuid(at: e.uuidIndex) { uuids.insert(u) } }
                }
            }
        }
        return uuids
    }

    /// Decode + render every firehose tracepoint in `tracev3` into entries.
    public static func assemble(tracev3: [(data: Data, sourceFile: String)],
                                timesyncByBoot: [String: TimesyncBoot],
                                strings: UnifiedLogStringCatalog) -> [UnifiedLogEntry] {
        var out: [UnifiedLogEntry] = []
        for (data, sourceFile) in tracev3 {
            let bytes = [UInt8](data)
            let top = TraceV3Parser.chunks(in: bytes)
            guard top.first?.tag == TraceV3Parser.tagHeader else { continue }
            let boot = TraceV3Parser.header(of: data).flatMap { timesyncByBoot[$0.bootUUID] }
            let leaf = (sourceFile as NSString).lastPathComponent

            var cat: TraceV3Catalog?
            for chunk in top {
                switch chunk.tag {
                case TraceV3Parser.tagCatalog:
                    cat = TraceV3Parser.catalog(fromData: Array(bytes[chunk.range]))
                case TraceV3Parser.tagChunkset:
                    guard let c = cat,
                          let inflated = AppleLZ4.decompress(Data(bytes[chunk.range])),
                          !inflated.isEmpty else { continue }
                    let ib = [UInt8](inflated)
                    for inner in TraceV3Parser.chunks(in: ib) where inner.tag == TraceV3Parser.tagFirehose {
                        let tps = FirehoseDecoder.tracepoints(chunkData: Array(ib[inner.range]), catalog: c)
                        for tp in tps {
                            let pi = c.processInfo(first: tp.firstProcID, second: tp.secondProcID)
                            let mainUUID = pi.flatMap { c.uuid(at: $0.mainUUIDIndex) }
                            let dscUUID = pi.flatMap { c.uuid(at: $0.dscUUIDIndex) }
                            // Loaded-image table for the absolute-address case.
                            let images: [UnifiedLogStringCatalog.ImageEntry] = (pi?.uuidEntries ?? []).compactMap {
                                guard let u = c.uuid(at: $0.uuidIndex) else { return nil }
                                return .init(loadAddress: $0.loadAddress, size: $0.size, uuid: u)
                            }
                            let m = strings.render(flags: tp.flags,
                                                   formatStringLocation: tp.formatStringLocation,
                                                   data: tp.data, mainUUID: mainUUID, dscUUID: dscUUID,
                                                   imageEntries: images)
                            // Resolve the subsystem id (from the tracepoint) to
                            // its subsystem/category strings via the process's
                            // catalog subsystem table.
                            let sub = m.subsystemIdentifier.flatMap { pi?.subsystem(for: $0) }
                            out.append(UnifiedLogEntry(
                                timestamp: boot?.walltime(forContinuousTime: tp.continuousTime),
                                eventType: tp.eventType, level: tp.level, pid: Int(tp.pid),
                                process: m.process, subsystem: sub?.subsystem, category: sub?.category,
                                message: m.message ?? "", sourceFile: leaf))
                        }
                    }
                default:
                    break
                }
            }
        }
        return out
    }
}
