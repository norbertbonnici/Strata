import Testing
import Foundation
@testable import Strata

/// Covers `LinuxNetworkParser` - static (netplan / ifupdown) and runtime
/// (journal DHCP-lease) IPv4 recovery, plus the host-address filter. The
/// NetworkManager lease line is copied verbatim from a real Ubuntu journal.
struct LinuxNetworkParserTests {

    // MARK: - Netplan

    @Test func netplanListStyleAddresses() {
        let yaml = """
        network:
          version: 2
          renderer: networkd
          ethernets:
            ens33:
              addresses:
                - 192.168.1.50/24
                - 10.0.0.5/16
              gateway4: 192.168.1.1
              nameservers:
                addresses: [8.8.8.8, 1.1.1.1]
        """
        // Only the CIDR-suffixed interface addresses - gateway/nameservers (no
        // CIDR) are excluded.
        #expect(LinuxNetworkParser.parseNetplan(yaml) == ["192.168.1.50", "10.0.0.5"])
    }

    @Test func netplanInlineArray() {
        let yaml = "      addresses: [172.16.0.9/24]"
        #expect(LinuxNetworkParser.parseNetplan(yaml) == ["172.16.0.9"])
    }

    // MARK: - ifupdown

    @Test func interfacesStaticAddress() {
        let text = """
        auto eth0
        iface eth0 inet static
            address 192.168.10.20
            netmask 255.255.255.0
            gateway 192.168.10.1
        """
        // The `address` line is taken; `netmask`/`gateway` are not address lines.
        #expect(LinuxNetworkParser.parseInterfaces(text) == ["192.168.10.20"])
    }

    @Test func interfacesAddressWithCIDR() {
        #expect(LinuxNetworkParser.parseInterfaces("    address 10.1.2.3/8") == ["10.1.2.3"])
    }

    // MARK: - Journal DHCP lease

    @Test func networkManagerNewLease() {
        let msg = "<info>  [1760083991.9035] dhcp4 (ens18): state changed new lease, address=192.168.5.160"
        #expect(LinuxNetworkParser.leaseAddresses(inMessage: msg) == ["192.168.5.160"])
    }

    @Test func systemdNetworkdDHCPv4() {
        let msg = "ens33: DHCPv4 address 10.0.0.15/24 via 10.0.0.1"
        // Both the leased address and the gateway sit on a DHCPv4 line; we accept
        // both as host-reachable v4 (the gateway is a real, non-loopback IP).
        #expect(LinuxNetworkParser.leaseAddresses(inMessage: msg).contains("10.0.0.15"))
    }

    @Test func avahiLoopbackIsFiltered() {
        let msg = "Registering new address record for 127.0.0.1 on lo.IPv4."
        #expect(LinuxNetworkParser.leaseAddresses(inMessage: msg).isEmpty)
    }

    @Test func avahiRealInterfaceIsKept() {
        let msg = "Registering new address record for 192.168.5.160 on ens18.IPv4."
        #expect(LinuxNetworkParser.leaseAddresses(inMessage: msg) == ["192.168.5.160"])
    }

    @Test func nonLeaseLineIgnored() {
        // A message that merely mentions an IP without a lease keyword is skipped.
        let msg = "connection to peer 8.8.8.8 established"
        #expect(LinuxNetworkParser.leaseAddresses(inMessage: msg).isEmpty)
    }

    // MARK: - Host-address filter

    @Test func filtersNonHostAddresses() {
        #expect(LinuxNetworkParser.isHostIPv4("192.168.1.10"))
        #expect(!LinuxNetworkParser.isHostIPv4("127.0.0.1"))      // loopback
        #expect(!LinuxNetworkParser.isHostIPv4("0.0.0.0"))        // unspecified
        #expect(!LinuxNetworkParser.isHostIPv4("169.254.5.5"))    // link-local
        #expect(!LinuxNetworkParser.isHostIPv4("224.0.0.251"))    // multicast
        #expect(!LinuxNetworkParser.isHostIPv4("255.255.255.0"))  // netmask-shaped
        #expect(!LinuxNetworkParser.isHostIPv4("999.1.1.1"))      // invalid octet
        #expect(!LinuxNetworkParser.isHostIPv4("10.0.0"))         // not a quad
    }

    // MARK: - HostInfo merge → profile

    @Test func mergeAndProfileExposesIPs() {
        var info = LinuxHostInfo()
        LinuxHostInfoParser.applyNetplan("addresses: [192.168.5.160/24]", to: &info)
        LinuxHostInfoParser.mergeIPs(["192.168.5.160", "10.9.9.9"], into: &info)   // dedup first
        #expect(info.ipAddresses == ["192.168.5.160", "10.9.9.9"])
        let profile = HostProfile.derive(fromLinux: info)
        #expect(profile.ipAddresses == ["192.168.5.160", "10.9.9.9"])
    }
}
