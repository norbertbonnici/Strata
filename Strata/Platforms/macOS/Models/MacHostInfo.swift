import Foundation

/// One local macOS account, recovered from a dslocal user plist
/// (`/private/var/db/dslocal/nodes/Default/users/<name>.plist`). The macOS
/// counterpart of `LinuxUser`. dslocal stores every attribute as a
/// single-element array; `MacHostInfoParser` unwraps that before populating us.
public nonisolated struct MacUser: Hashable, Sendable, Codable {
    public let name: String
    public let uid: Int
    public let home: String
    public let shell: String

    public init(name: String, uid: Int, home: String, shell: String) {
        self.name = name
        self.uid = uid
        self.home = home
        self.shell = shell
    }

    /// A shell that lets the account actually log in (vs nologin/false).
    public var hasLoginShell: Bool {
        !(shell.hasSuffix("nologin") || shell.hasSuffix("/false") || shell.isEmpty)
    }
}

/// What the small macOS identity files - `SystemVersion.plist`, the
/// SystemConfiguration `preferences.plist`, the dslocal user plists, and the
/// timezone - tell us about a macOS host. The source for its `HostProfile`,
/// the macOS counterpart of `LinuxHostInfo` (Linux) and the registry
/// derivation (Windows).
public nonisolated struct MacHostInfo: Hashable, Sendable, Codable {
    public var productName: String?     // "macOS" / "Mac OS X"
    public var productVersion: String?  // "14.4.1"
    public var buildVersion: String?    // "23E224"
    public var computerName: String?    // user-facing "Jane's MacBook Pro"
    public var localHostName: String?   // Bonjour name "Janes-MacBook-Pro"
    public var timeZone: String?        // "Europe/Malta"
    public var users: [MacUser] = []
    /// IPv4 addresses of the host, in discovery order, deduped.
    public var ipAddresses: [String] = []

    public init() {}

    public var isEmpty: Bool {
        productName == nil && productVersion == nil && buildVersion == nil
            && computerName == nil && localHostName == nil && timeZone == nil
            && users.isEmpty && ipAddresses.isEmpty
    }
}
