import Testing
import Foundation
@testable import Strata

/// Unit tests for the pure registry-explorer logic: the `RegistryNode` tree
/// builder (the registry analogue of `FileNode.buildTree`) and the shared
/// `RegistryValue` display/decoding helpers that both the macOS view and the
/// iOS drill render with.
struct RegistryNodeTests {

    /// Build a `RegistryValue` with sensible defaults so each test only states
    /// the fields it cares about.
    private func reg(hive: String = "SOFTWARE", path: String = "\\K", name: String = "v",
                     type: RegistryValue.ValueType = .sz, data: String = "",
                     lastWritten: Date? = nil) -> RegistryValue {
        RegistryValue(hive: hive, path: path, name: name, type: type, data: data,
                      lastWritten: lastWritten, sourceFile: "/test")
    }

    private func child(_ node: RegistryNode?, _ name: String) -> RegistryNode? {
        node?.children?.first { $0.name == name }
    }

    // MARK: - Tree building

    /// Top level is one node per hive, in the conventional machine-then-user
    /// order (SYSTEM, SOFTWARE, …), mirroring how FileNode groups by volume.
    @Test func hivesGroupAndSortConventionally() {
        let values = [
            reg(hive: "NTUSER",   name: "a"),
            reg(hive: "SOFTWARE", name: "b"),
            reg(hive: "SYSTEM",   name: "c"),
        ]
        let tree = RegistryNode.buildTree(from: values)
        #expect(tree.map(\.name) == ["SYSTEM", "SOFTWARE", "NTUSER"])
        // Hoisted out of #expect: the macro otherwise reads `allSatisfy(\.key)`
        // as a throwing call and won't compile.
        let allHives = tree.allSatisfy(\.isHive)
        #expect(allHives)
    }

    /// A backslash key path nests into a merged subtree, with the value hung
    /// off its leaf key.
    @Test func keyPathNestsIntoSubtree() {
        let v = reg(hive: "SYSTEM", path: "\\ControlSet001\\Services\\Foo",
                    name: "Start", type: .dword, data: "2")
        let tree = RegistryNode.buildTree(from: [v])
        #expect(tree.count == 1)
        let system = tree[0]
        #expect(system.isHive && system.name == "SYSTEM")

        let foo = child(child(child(system, "ControlSet001"), "Services"), "Foo")
        #expect(foo != nil)
        #expect(foo?.values.count == 1)
        #expect(foo?.values.first?.name == "Start")
        // Intermediate path-only keys carry no value of their own.
        #expect(child(system, "ControlSet001")?.values.isEmpty == true)
    }

    /// Sibling keys sharing a prefix collapse onto one shared subtree.
    @Test func siblingKeysShareTheirPrefix() {
        let run    = reg(hive: "SOFTWARE", path: "\\Microsoft\\Windows\\CurrentVersion\\Run", name: "A")
        let policy = reg(hive: "SOFTWARE", path: "\\Microsoft\\Windows\\CurrentVersion\\Policies", name: "B")
        let tree = RegistryNode.buildTree(from: [run, policy])
        let cv = child(child(child(tree[0], "Microsoft"), "Windows"), "CurrentVersion")
        #expect(cv?.children?.map(\.name).sorted() == ["Policies", "Run"])
    }

    /// A value with an empty path (and the default, unnamed value) attaches at
    /// the hive root and survives.
    @Test func emptyPathAndDefaultValueAttachAtHiveRoot() {
        let v = reg(hive: "SOFTWARE", path: "", name: "", type: .sz, data: "x")
        let tree = RegistryNode.buildTree(from: [v])
        #expect(tree.count == 1)
        #expect(tree[0].children == nil)            // no subkeys
        #expect(tree[0].values.count == 1)
        #expect(tree[0].values.first?.name == "")   // default value preserved
    }

    /// A key's last-written time is lifted from one of its values (libregf
    /// stamps it per key).
    @Test func keyLastWrittenComesFromItsValues() {
        let when = Date(timeIntervalSince1970: 1_700_000_000)
        let v = reg(hive: "SOFTWARE", path: "\\Microsoft\\Windows",
                    name: "Foo", type: .sz, data: "x", lastWritten: when)
        let tree = RegistryNode.buildTree(from: [v])
        #expect(child(child(tree[0], "Microsoft"), "Windows")?.lastWritten == when)
    }

    // MARK: - Display / decoding helpers

    @Test func matchesIsCaseInsensitiveOverNamePathData() {
        let v = reg(hive: "SOFTWARE", path: "\\Microsoft\\Windows\\CurrentVersion\\Run",
                    name: "Sysmon", type: .sz, data: "C:\\Windows\\Sysmon.exe")
        #expect(v.matches("sysmon"))          // by name
        #expect(v.matches("currentversion"))  // by path
        #expect(v.matches("sysmon.exe"))      // by data
        #expect(v.matches("   "))             // blank query matches all
        #expect(!v.matches("notpresent"))
    }

    @Test func typeBadgeMapsRegTypes() {
        #expect(reg(type: .dword).typeBadge == "DWORD")
        #expect(reg(type: .sz).typeBadge == "SZ")
        #expect(reg(type: .multiSz).typeBadge == "MULTI_SZ")
        #expect(reg(type: .binary).typeBadge == "BINARY")
    }

    @Test func decodedDataFormatsByType() {
        #expect(reg(type: .dword, data: "26").decodedData == "26 (0x1A)")
        #expect(reg(type: .dword, data: "0x100").decodedData == "256 (0x100)")
        #expect(reg(type: .qword, data: "4294967296").decodedData == "4294967296 (0x100000000)")
        #expect(reg(type: .binary, data: "deadbeef").decodedData == "DE AD BE EF")
        #expect(reg(type: .sz, data: "C:\\Windows").decodedData == "C:\\Windows")
        // Non-numeric DWORD text falls back to the raw string unchanged.
        #expect(reg(type: .dword, data: "(unset)").decodedData == "(unset)")
    }
}
