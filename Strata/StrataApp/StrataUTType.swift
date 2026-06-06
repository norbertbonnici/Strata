import UniformTypeIdentifiers

extension UTType {
    /// The Strata case package (".strata") - a directory bundle declared as a
    /// package in Info.plist. Used by the open-case pickers so a case can be
    /// selected as one item (it's no longer a plain folder once registered).
    static let strataCase = UTType(exportedAs: "com.bonnicilabs.strata-case")
}
