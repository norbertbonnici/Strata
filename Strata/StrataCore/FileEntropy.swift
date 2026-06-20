import Foundation

/// Shannon-entropy helpers for content-based checks. The motivating use is
/// verifying that a ransomware "mass encryption" burst actually contains
/// encrypted - i.e. high-entropy - data, rather than files merely *renamed* to
/// a scary extension. Pure + dependency-free so it lives in StrataCore and is
/// unit-testable without any I/O.
public enum FileEntropy {
    /// Shannon entropy of `data` in **bits per byte** (0...8). Empty data → 0.
    /// Encrypted or already-compressed content sits near 8.0; text/structured
    /// data is much lower (~4-6), and a long run of one byte is 0.
    public static func shannonEntropy(_ data: Data) -> Double {
        guard !data.isEmpty else { return 0 }
        var counts = [Int](repeating: 0, count: 256)
        data.withUnsafeBytes { raw in
            for byte in raw { counts[Int(byte)] += 1 }
        }
        let n = Double(data.count)
        var h = 0.0
        for c in counts where c > 0 {
            let p = Double(c) / n
            h -= p * log2(p)
        }
        return h
    }
}

/// Aggregated entropy verdict for the files of one extension caught in a
/// ransomware mass-encryption burst, computed by sampling their real bytes.
/// Carried into `AnalysisContext` so the (pure) analyzer can **corroborate** its
/// metadata-only burst finding.
///
/// Important: high entropy *corroborates* encryption but can never *refute* it.
/// Partial / intermittent / append-based encryptors (LockBit, BlackCat, Black
/// Basta, …) deliberately leave plaintext regions, so a low reading does not
/// mean "not encrypted". Each file is therefore measured as the **maximum**
/// entropy over several windows (head / middle / tail), and the verdict counts
/// how many files contain any high-entropy region - never used to downgrade a
/// detection below its metadata severity.
public nonisolated struct EncryptionEntropyStat: Sendable, Hashable, Codable {
    /// Files whose content was actually read + measured (not the burst size).
    public let sampledFiles: Int
    /// Of those, how many contain a high-entropy window (≥ `encryptedThreshold`)
    /// somewhere - regions consistent with encryption.
    public let highEntropyFiles: Int
    /// Mean of the per-file maximum-window entropy (bits/byte).
    public let meanEntropy: Double
    /// Highest single-window entropy seen across all sampled files.
    public let maxEntropy: Double

    public init(sampledFiles: Int, highEntropyFiles: Int, meanEntropy: Double, maxEntropy: Double) {
        self.sampledFiles = sampledFiles
        self.highEntropyFiles = highEntropyFiles
        self.meanEntropy = meanEntropy
        self.maxEntropy = maxEntropy
    }

    /// Entropy at/above which a window is treated as encrypted-or-compressed.
    /// AES output sits at ~7.99; text/structured data well below. 7.5 leaves
    /// head room for small windows + headers while excluding non-encrypted
    /// content. NOTE: byte entropy cannot distinguish **encryption** from
    /// **compression** - both read near 8.0 - and the burst's novelty gate only
    /// excludes the *allow-listed* compressed families (zip/jpg/…), so an
    /// off-list compressed container can still read high. High entropy therefore
    /// corroborates encryption; it does not prove it.
    public static let encryptedThreshold = 7.5

    /// Whether any sampled file contains content consistent with encryption.
    /// A `false` here means "not corroborated", NOT "not encrypted".
    public var looksEncrypted: Bool { highEntropyFiles > 0 }

    public var meanString: String { String(format: "%.2f", meanEntropy) }
    public var maxString: String { String(format: "%.2f", maxEntropy) }

    /// Build from each sampled file's maximum-window entropy; nil when nothing
    /// could be sampled.
    public static func from(fileMaxEntropies entropies: [Double]) -> EncryptionEntropyStat? {
        guard !entropies.isEmpty else { return nil }
        let high = entropies.filter { $0 >= encryptedThreshold }.count
        let mean = entropies.reduce(0, +) / Double(entropies.count)
        return EncryptionEntropyStat(sampledFiles: entropies.count, highEntropyFiles: high,
                                     meanEntropy: mean, maxEntropy: entropies.max() ?? mean)
    }
}
