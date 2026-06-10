//
//  LinuxAccessTests.swift
//  StrataTests
//
//  Covers the Linux access bundle: SSH / sudoers / group / shadow parsers, the
//  gzip decoder for rotated logs, and the access & privilege analyzer.
//

import Testing
import Foundation
import Compression
@testable import Strata

struct LinuxAccessParserTests {

    @Test func parsesAuthorizedKeysWithOptions() {
        let text = """
        # a comment
        ssh-ed25519 AAAAC3NzaC1lZDI1 jane@laptop
        command="/usr/bin/backup",no-pty,from="10.0.0.0/8" ssh-rsa AAAAB3Nza backup@auto
        """
        let keys = LinuxAccessParser.parseAuthorizedKeys(text: text, user: "jane",
                                                         sourceFile: "/home/jane/.ssh/authorized_keys")
        #expect(keys.count == 2)
        #expect(keys[0].algorithm == "ssh-ed25519")
        #expect(keys[0].comment == "jane@laptop")
        #expect(keys[0].options.isEmpty)
        #expect(keys[0].user == "jane")
        // Options field (with a quoted comma inside from="10.0.0.0/8") split correctly.
        #expect(keys[1].algorithm == "ssh-rsa")
        #expect(keys[1].options.contains { $0.hasPrefix("command=") })
        #expect(keys[1].options.contains("no-pty"))
        #expect(keys[1].comment == "backup@auto")
    }

    @Test func parsesKnownHosts() {
        let text = """
        |1|hashedstuff= ssh-ed25519 AAAAC3Nza
        gitlab.example.com,10.0.0.9 ssh-rsa AAAAB3Nza
        @revoked badhost ssh-rsa AAAAB3Nza
        """
        let keys = LinuxAccessParser.parseKnownHosts(text: text, user: "jane",
                                                     sourceFile: "/home/jane/.ssh/known_hosts")
        #expect(keys.count == 3)
        #expect(keys.allSatisfy { $0.kind == .knownHost })
        #expect(keys[1].host == "gitlab.example.com,10.0.0.9")
        #expect(keys[2].host == "badhost")   // @revoked marker stripped
    }

    @Test func parsesSSHDConfig() {
        let text = """
        # comment
        Port 22
        PermitRootLogin yes
        PasswordAuthentication no
        PermitEmptyPasswords yes
        PermitRootLogin no
        """
        let s = LinuxAccessParser.parseSSHDConfig(text: text)
        // Last value wins for a repeated key.
        #expect(s["permitrootlogin"] == "no")
        #expect(s["passwordauthentication"] == "no")
        #expect(s["permitemptypasswords"] == "yes")
        #expect(s["port"] == "22")
    }

    @Test func parsesSudoersIncludingNOPASSWD() {
        let text = """
        Defaults env_reset
        root    ALL=(ALL:ALL) ALL
        %sudo   ALL=(ALL:ALL) ALL
        eve     ALL=(ALL) NOPASSWD: ALL
        deploy  ALL=(root) NOPASSWD: /usr/bin/systemctl restart app
        """
        let rules = LinuxAccessParser.parseSudoers(text: text, sourceFile: "/etc/sudoers")
        #expect(rules.count == 4)   // Defaults line skipped
        let eve = rules.first { $0.principal == "eve" }
        #expect(eve?.noPasswd == true)
        #expect(eve?.grantsAll == true)
        let deploy = rules.first { $0.principal == "deploy" }
        #expect(deploy?.noPasswd == true)
        #expect(deploy?.grantsAll == false)
        #expect(deploy?.command.contains("systemctl") == true)
    }

    @Test func parsesGroupMembership() {
        let groups = LinuxAccessParser.parseGroup(text: """
        root:x:0:
        sudo:x:27:jane,eve
        docker:x:998:eve
        """)
        #expect(groups.count == 3)
        #expect(groups.first { $0.name == "docker" }?.members == ["eve"])
        #expect(groups.first { $0.name == "sudo" }?.members == ["jane", "eve"])
    }

    @Test func classifiesShadowHashes() {
        let shadow = LinuxAccessParser.parseShadow(text: """
        root:$6$abc$def:19000:0:99999:7:::
        backdoor::19000:0:99999:7:::
        daemon:*:19000:0:99999:7:::
        jane:!$6$locked:19000:0:99999:7:::
        """)
        #expect(shadow["root"] == .usable)
        #expect(shadow["backdoor"] == .empty)
        #expect(shadow["daemon"] == .noLogin)
        #expect(shadow["jane"] == .locked)
    }
}

struct GzipDecoderTests {

    /// Compress with the same raw-DEFLATE backend and wrap in a minimal gzip
    /// container, so the test doesn't depend on an external gzip.
    private static func gzip(_ data: Data) -> Data {
        let src = [UInt8](data)
        var dst = [UInt8](repeating: 0, count: max(64, src.count * 2 + 64))
        let n = compression_encode_buffer(&dst, dst.count, src, src.count, nil, COMPRESSION_ZLIB)
        var out = Data([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff])   // 10-byte header
        out.append(contentsOf: dst[0..<n])
        var crc: UInt32 = 0   // CRC not validated by the decoder
        var isize = UInt32(truncatingIfNeeded: src.count)
        withUnsafeBytes(of: &crc) { out.append(contentsOf: $0) }
        withUnsafeBytes(of: &isize) { out.append(contentsOf: $0) }
        return out
    }

    @Test func roundTripsThroughGzipContainer() throws {
        let original = Data("""
        Mar 12 13:01:02 web01 sshd[1]: Accepted password for jane from 10.0.0.5 port 22 ssh2
        Mar 12 13:01:05 web01 sshd[2]: Failed password for root from 203.0.113.9 port 40000 ssh2
        """.utf8)
        let restored = try GzipDecoder.decompress(Self.gzip(original))
        #expect(restored == original)
    }

    @Test func rejectsNonGzip() {
        #expect(throws: (any Error).self) {
            try GzipDecoder.decompress(Data("not gzip at all, much longer than header".utf8))
        }
    }
}

struct LinuxAccessAnalyzerTests {

    private static func context(access: LinuxAccessInfo,
                                info: LinuxHostInfo? = nil) -> AnalysisContext {
        AnalysisContext(files: [], events: [], timeline: [], registryValues: [],
                        linuxInfo: info, linuxAccess: access)
    }

    @Test func flagsRootKeyAndForcedCommand() {
        var access = LinuxAccessInfo()
        access.sshKeys = [
            SSHKey(kind: .authorized, user: "root", algorithm: "ssh-ed25519",
                   comment: "attacker@vps", sourceFile: "/root/.ssh/authorized_keys"),
            SSHKey(kind: .authorized, user: "deploy", algorithm: "ssh-rsa",
                   options: ["command=\"/tmp/.x\""], sourceFile: "/home/deploy/.ssh/authorized_keys"),
        ]
        let f = LinuxAccessAnalyzer().analyze(context: Self.context(access: access))
        #expect(f.contains { $0.title.contains("authorized for root") && $0.severity == .high })
        #expect(f.contains { $0.title.contains("Forced-command") })
        #expect(f.allSatisfy { $0.technique?.attackID == "T1098.004" })
    }

    @Test func flagsDangerousSSHDSettings() {
        var access = LinuxAccessInfo()
        access.sshdSettings = ["permitrootlogin": "yes", "permitemptypasswords": "yes"]
        let f = LinuxAccessAnalyzer().analyze(context: Self.context(access: access))
        #expect(f.contains { $0.title.contains("empty passwords") && $0.severity == .critical })
        #expect(f.contains { $0.title.contains("root login") && $0.severity == .high })
    }

    @Test func flagsUID0AndPasswordlessAndSudoAndDocker() {
        var access = LinuxAccessInfo()
        access.shadow = ["backdoor": .empty, "root": .usable]
        access.sudoRules = [SudoRule(principal: "eve", runAs: "ALL", noPasswd: true,
                                     command: "ALL", sourceFile: "/etc/sudoers")]
        access.groups = [LinuxGroup(name: "docker", gid: 998, members: ["eve"])]
        var info = LinuxHostInfo()
        info.users = [LinuxUser(name: "toor", uid: 0, gid: 0, home: "/root", shell: "/bin/bash"),
                      LinuxUser(name: "root", uid: 0, gid: 0, home: "/root", shell: "/bin/bash")]
        let f = LinuxAccessAnalyzer().analyze(context: Self.context(access: access, info: info))
        #expect(f.contains { $0.title.contains("UID 0: toor") && $0.severity == .critical })
        #expect(f.contains { $0.title.contains("Passwordless account: backdoor") })
        #expect(f.contains { $0.title.contains("Passwordless full sudo for eve") })
        #expect(f.contains { $0.title.contains("Root-equivalent group 'docker'") })
        // root's own UID 0 is not flagged.
        #expect(!f.contains { $0.title.contains("UID 0: root") })
    }

    @Test func cleanHostYieldsNothing() {
        var access = LinuxAccessInfo()
        access.sshdSettings = ["permitrootlogin": "no", "passwordauthentication": "no"]
        access.shadow = ["root": .locked, "jane": .usable]
        access.sudoRules = [SudoRule(principal: "%sudo", runAs: "ALL", noPasswd: false,
                                     command: "ALL", sourceFile: "/etc/sudoers")]
        let f = LinuxAccessAnalyzer().analyze(context: Self.context(access: access))
        #expect(f.isEmpty)
    }
}
