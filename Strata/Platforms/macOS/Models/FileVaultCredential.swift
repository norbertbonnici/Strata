import Foundation

/// A FileVault unlock secret for an encrypted APFS Data volume — a login/volume
/// **password** or a **personal recovery key**. Held in memory only and **never
/// persisted** to the case bundle (forensic confidentiality): it exists for the
/// lifetime of the session so on-demand content extraction (`fsapfscat`) and the
/// metadata pass (`fsapfsinfo`) can unlock the volume.
public nonisolated struct FileVaultCredential: Sendable, Hashable {
    public var password: String?
    public var recovery: String?

    public init(password: String? = nil, recovery: String? = nil) {
        self.password = password?.isEmpty == true ? nil : password
        self.recovery = recovery?.isEmpty == true ? nil : recovery
    }

    /// True when at least one secret is present.
    public var hasSecret: Bool { password != nil || recovery != nil }
}

/// An APFS volume that couldn't be read at ingest without a FileVault secret
/// (its metadata came back empty or `fsapfsinfo` reported an encryption error).
/// Cross-platform so the UI + `AppModel` can reference it on iOS, where the
/// macOS-only `FsApfsIngestor` is compiled out.
public nonisolated struct ApfsLockedVolume: Sendable, Hashable {
    public let index: Int        // 1-based fsapfsinfo volume index
    public let name: String
    public init(index: Int, name: String) { self.index = index; self.name = name }
}
