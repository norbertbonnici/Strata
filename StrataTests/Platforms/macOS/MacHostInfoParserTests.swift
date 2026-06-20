//
//  MacHostInfoParserTests.swift
//  StrataTests
//
//  Covers the macOS host-identity parser (SystemVersion.plist, the
//  SystemConfiguration preferences, dslocal user plists) and the HostProfile
//  projection that drives the Overview host card.
//

import Testing
import Foundation
@testable import Strata

struct MacHostInfoParserTests {

    /// Serialize a dictionary to binary-plist Data, the way an on-disk macOS
    /// plist would be read.
    private func plist(_ object: [String: Any]) -> Data {
        try! PropertyListSerialization.data(fromPropertyList: object, format: .binary, options: 0)
    }

    @Test func systemVersionPopulatesOSFields() {
        var info = MacHostInfo()
        MacHostInfoParser.applySystemVersion(plist([
            "ProductName": "macOS",
            "ProductVersion": "14.4.1",
            "ProductBuildVersion": "23E224",
        ]), to: &info)
        #expect(info.productName == "macOS")
        #expect(info.productVersion == "14.4.1")
        #expect(info.buildVersion == "23E224")
    }

    @Test func userVisibleVersionWinsOverProductVersion() {
        var info = MacHostInfo()
        MacHostInfoParser.applySystemVersion(plist([
            "ProductVersion": "10.16",
            "ProductUserVisibleVersion": "11.7.10",
        ]), to: &info)
        #expect(info.productVersion == "11.7.10")
    }

    @Test func preferencesPopulateNamesAndIPs() {
        var info = MacHostInfo()
        MacHostInfoParser.applyPreferences(plist([
            "System": [
                "System": ["ComputerName": "Jane's MacBook Pro"],
                "Network": ["HostNames": ["LocalHostName": "Janes-MacBook-Pro"]],
            ],
            "NetworkServices": [
                "svc": ["IPv4": ["Addresses": ["192.168.5.42"], "ConfigMethod": "Manual"]],
            ],
        ]), to: &info)
        #expect(info.computerName == "Jane's MacBook Pro")
        #expect(info.localHostName == "Janes-MacBook-Pro")
        #expect(info.ipAddresses == ["192.168.5.42"])
    }

    @Test func dslocalUserPlistUnwrapsArrays() {
        var info = MacHostInfo()
        // dslocal stores every attribute as a single-element array.
        MacHostInfoParser.applyUserPlist(plist([
            "name": ["jane"],
            "uid": ["501"],
            "home": ["/Users/jane"],
            "shell": ["/bin/zsh"],
        ]), to: &info)
        #expect(info.users.count == 1)
        #expect(info.users.first?.name == "jane")
        #expect(info.users.first?.uid == 501)
        #expect(info.users.first?.hasLoginShell == true)
    }

    @Test func ipSweepFiltersNonRoutable() {
        #expect(MacHostInfoParser.isRoutableIPv4("10.0.0.5"))
        #expect(!MacHostInfoParser.isRoutableIPv4("127.0.0.1"))
        #expect(!MacHostInfoParser.isRoutableIPv4("169.254.1.1"))
        #expect(!MacHostInfoParser.isRoutableIPv4("0.0.0.0"))
        #expect(!MacHostInfoParser.isRoutableIPv4("not.an.ip.addr"))
    }

    @Test func timezoneFromZoneinfoPath() {
        var info = MacHostInfo()
        MacHostInfoParser.applyTimezone(fromZoneinfoPath: "/var/db/timezone/zoneinfo/Europe/Malta", to: &info)
        #expect(info.timeZone == "Europe/Malta")
    }

    @Test func hostProfileProjectsMacInfo() {
        var info = MacHostInfo()
        info.computerName = "Jane's MacBook Pro"
        info.productName = "macOS"
        info.productVersion = "14.4.1"
        info.buildVersion = "23E224"
        // A system account (uid < 501) must not become the primary user.
        info.users = [
            MacUser(name: "_spotlight", uid: 89, home: "/var/empty", shell: "/usr/bin/false"),
            MacUser(name: "jane", uid: 501, home: "/Users/jane", shell: "/bin/zsh"),
        ]
        let profile = HostProfile.derive(fromMac: info)
        #expect(profile.hostname == "Jane's MacBook Pro")
        #expect(profile.osProductName == "macOS")
        #expect(profile.osBuild == "23E224")
        #expect(profile.primaryUser == "jane")
        #expect(profile.hasAnyData)
    }
}
