import SwiftUI

/// Linux access & privilege: SSH trust (authorized_keys / known_hosts), the
/// notable sshd_config settings, sudo rules, privileged group membership, and
/// per-account password state from /etc/shadow. The analyzer flags the
/// dangerous ones; this view shows the full picture for audit.
struct LinuxAccessView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var selectedKeyID: SSHKey.ID?

    private var access: LinuxAccessInfo? { model.linuxAccess }

    var body: some View {
        Group {
            if access == nil {
                ContentUnavailableView {
                    Label("No Linux access artifacts parsed yet", systemImage: "key.horizontal")
                } description: {
                    Text(model.files.isEmpty
                         ? "Ingest evidence first, then come back here."
                         : "Click Parse to read authorized_keys, sshd_config, sudoers, group, and shadow.")
                } actions: {
                    #if os(macOS)
                    if !model.files.isEmpty {
                        Button { Task { await model.parseArtifacts() } } label: {
                            Label("Parse artifacts", systemImage: "play.fill")
                        }
                        .disabled(model.isWorking)
                    }
                    #endif
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let access {
                content(access)
            }
        }
        .navigationTitle("Accounts & SSH")
    }

    @ViewBuilder
    private func content(_ access: LinuxAccessInfo) -> some View {
        let keys = filteredKeys(access.sshKeys)
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // SSH keys.
                if !access.sshKeys.isEmpty {
                    sectionHeader("SSH keys", count: access.sshKeys.count)
                    keyTable(keys)
                        .frame(minHeight: 140, maxHeight: 320)
                }
                // sshd_config notable settings.
                if !access.sshdSettings.isEmpty {
                    sectionHeader("sshd_config", count: nil)
                    grid(Self.notableSSHD.compactMap { key, label in
                        access.sshdSettings[key].map { (label, $0) }
                    })
                }
                // sudo.
                if !access.sudoRules.isEmpty {
                    sectionHeader("sudo rules", count: access.sudoRules.count)
                    sudoTable(access.sudoRules)
                        .frame(minHeight: 100, maxHeight: 240)
                }
                // privileged groups.
                let priv = access.groups.filter {
                    ["sudo", "wheel", "admin", "docker", "lxd", "adm", "root"].contains($0.name.lowercased())
                        && !$0.members.isEmpty
                }
                if !priv.isEmpty {
                    sectionHeader("Privileged groups", count: priv.count)
                    grid(priv.map { ($0.name, $0.members.joined(separator: ", ")) })
                }
                // shadow password state.
                if !access.shadow.isEmpty {
                    let notable = access.shadow.filter { $0.value == .empty || $0.value == .usable }
                        .sorted { $0.key < $1.key }
                    sectionHeader("Password state", count: notable.count)
                    grid(notable.map { ($0.key, $0.value.label) })
                }
            }
            .padding(16)
        }
    }

    // MARK: - SSH key table

    private func keyTable(_ keys: [SSHKey]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Spacer()
                TextField("Filter key / user / host...", text: $query)
                    .textFieldStyle(.roundedBorder).frame(width: 260)
            }
            Table(keys, selection: $selectedKeyID) {
                TableColumn("Kind") { k in
                    Text(k.kind.label).font(.caption).foregroundStyle(.secondary)
                }
                .width(min: 90, ideal: 100, max: 120)
                TableColumn("User / Host") { k in
                    Text(k.user ?? k.host ?? "—").font(.caption)
                }
                .width(min: 90, ideal: 120, max: 180)
                TableColumn("Algorithm") { k in
                    Text(k.algorithm).font(.caption.monospaced())
                }
                .width(min: 110, ideal: 130, max: 170)
                TableColumn("Options / Comment") { k in
                    let opts = k.options.joined(separator: ", ")
                    Text(opts.isEmpty ? k.comment : "\(opts)  \(k.comment)")
                        .font(.caption).lineLimit(1).truncationMode(.middle)
                        .foregroundStyle(opts.isEmpty ? .secondary : .primary)
                }
            }
        }
    }

    private func sudoTable(_ rules: [SudoRule]) -> some View {
        Table(rules) {
            TableColumn("Principal") { r in Text(r.principal).font(.caption) }
                .width(min: 90, ideal: 120, max: 180)
            TableColumn("Run as") { r in
                Text(r.runAs ?? "—").font(.caption).foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 80, max: 120)
            TableColumn("NOPASSWD") { r in
                Text(r.noPasswd ? "yes" : "—")
                    .font(.caption.bold())
                    .foregroundStyle(r.noPasswd ? .orange : .secondary)
            }
            .width(min: 70, ideal: 80, max: 90)
            TableColumn("Command") { r in
                Text(r.command).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
            }
        }
    }

    // MARK: - Helpers

    private func filteredKeys(_ keys: [SSHKey]) -> [SSHKey] {
        guard !query.isEmpty else { return keys }
        return keys.filter {
            ($0.user?.localizedCaseInsensitiveContains(query) ?? false)
                || ($0.host?.localizedCaseInsensitiveContains(query) ?? false)
                || $0.algorithm.localizedCaseInsensitiveContains(query)
                || $0.comment.localizedCaseInsensitiveContains(query)
                || $0.options.joined().localizedCaseInsensitiveContains(query)
        }
    }

    private func sectionHeader(_ title: String, count: Int?) -> some View {
        HStack(spacing: 8) {
            Text(title).font(.headline)
            if let count { Text("\(count)").font(.caption).foregroundStyle(.secondary) }
            Spacer()
        }
    }

    private func grid(_ rows: [(String, String)]) -> some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 16, verticalSpacing: 4) {
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                GridRow {
                    Text(row.0).foregroundStyle(.secondary).font(.callout)
                    Text(row.1).font(.callout).textSelection(.enabled)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// sshd_config keys worth surfacing, with display labels.
    static let notableSSHD: [(String, String)] = [
        ("permitrootlogin", "PermitRootLogin"),
        ("passwordauthentication", "PasswordAuthentication"),
        ("permitemptypasswords", "PermitEmptyPasswords"),
        ("pubkeyauthentication", "PubkeyAuthentication"),
        ("port", "Port"),
        ("allowusers", "AllowUsers"),
        ("allowgroups", "AllowGroups"),
    ]
}
