import Foundation

/// Bounds-checked integer conversions for the byte-parsers.
///
/// All parser input is **adversary-controlled** (Strata ingests artifacts from
/// compromised hosts), so a length/offset/size field can hold any 64-bit value.
/// Swift's `Int(someUInt64)` and `Int(someDouble)` initializers **trap** (an
/// uncatchable `fatalError`, fatal even off the main actor) when the value
/// exceeds `Int`'s range — turning a malformed field into an app crash. These
/// helpers return `nil`/clamp instead, so a parser can treat an out-of-range
/// field as malformed (skip the record / return `[]`) per its own contract.
@inlinable
public func intExact(_ value: UInt64) -> Int? {
    value <= UInt64(Int.max) ? Int(value) : nil
}

/// Bounds-checked `UInt32`→`Int` is always safe on 64-bit, but provided for
/// symmetry / 32-bit safety.
@inlinable
public func intExact(_ value: UInt32) -> Int { Int(value) }

/// Bounds-checked `Double`→`Int`: `nil` for NaN, ±infinity, or any magnitude
/// outside `Int`'s representable range (the `Int(Double)` initializer traps on
/// all of these). Truncates toward zero like `Int(Double)`.
@inlinable
public func intExact(_ value: Double) -> Int? {
    guard value.isFinite, value >= -9_223_372_036_854_775_808.0, value < 9_223_372_036_854_775_808.0
    else { return nil }
    return Int(value)
}
