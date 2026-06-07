import Foundation

/// Encodes export rows to JSON. Matches `CaseStore`'s on-disk convention
/// (ISO-8601 dates, pretty-printed, sorted keys) so exported JSON reads the
/// same as the bundle's own files; `.withoutEscapingSlashes` keeps Windows
/// paths legible.
public nonisolated enum JSONExporter {
    static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try makeEncoder().encode(value)
    }
}
