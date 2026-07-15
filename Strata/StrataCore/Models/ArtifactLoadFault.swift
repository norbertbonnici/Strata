import Foundation

/// A cached artifact file that EXISTS in the `.strata` bundle but could not be
/// decoded when the case was opened (truncated write, partial iCloud sync,
/// bit-rot, or a schema change in an older build).
///
/// This is the forensic distinction the load path must preserve: an *absent*
/// file means "this host was never parsed for that artifact"; a *present but
/// undecodable* file means "there was data here and we failed to read it". The
/// two look identical once collapsed to an empty collection, yet they support
/// opposite conclusions — so a decode failure is surfaced as one of these rather
/// than silently swallowed to `[]`.
public nonisolated struct ArtifactLoadFault: Sendable, Hashable, Identifiable, Codable {
    /// Human-readable artifact name, e.g. "Event logs", "Findings".
    public let artifact: String
    /// The underlying decode error, for the examiner + logs.
    public let reason: String

    public var id: String { artifact }

    public init(artifact: String, reason: String) {
        self.artifact = artifact
        self.reason = reason
    }
}
