#if !os(macOS)
import SwiftUI

// Read-only iOS drills for the Linux artifacts. Lists are capped to keep the
// phone responsive on a noisy host (full data lives in the macOS app and the
// exports); the cap is disclosed in the header.

private let drillCap = 500

/// Auth events + login records behind one segmented control - the same split
/// as the macOS LinuxLogsView.
struct LinuxLogsDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var section = 0
    @State private var query = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Auth & Logins",
                           subtitle: "\(model.authLogCount) auth event\(model.authLogCount == 1 ? "" : "s") · \(model.loginsCount) login record\(model.loginsCount == 1 ? "" : "s")")

                Picker("", selection: $section) {
                    Text("Auth events").tag(0)
                    Text("Login records").tag(1)
                }
                .pickerStyle(.segmented)
                .padding(.top, 10)

                TextField("Filter user / IP...", text: $query)
                    .textFieldStyle(.roundedBorder)
                    .padding(.top, 8)

                if section == 0 {
                    authList
                } else {
                    loginList
                }
                Spacer(minLength: 26)
            }
            .padding(.horizontal)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    private var filteredAuth: [AuthLogEntry] {
        let rows = model.authLog
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.message.localizedCaseInsensitiveContains(query)
                || ($0.user?.localizedCaseInsensitiveContains(query) ?? false)
                || ($0.sourceIP?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    private var filteredLogins: [UtmpRecord] {
        let rows = model.logins
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.user.localizedCaseInsensitiveContains(query)
                || $0.host.localizedCaseInsensitiveContains(query)
        }
    }

    @ViewBuilder
    private var authList: some View {
        let rows = filteredAuth
        if rows.isEmpty {
            ContentUnavailableView("No auth events", systemImage: "person.badge.key")
                .padding(.top, 40)
        } else {
            capNote(total: rows.count)
            Card {
                ForEach(Array(rows.prefix(drillCap).enumerated()), id: \.element.id) { index, entry in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(entry.kind.label)
                                .font(.caption.bold())
                                .foregroundStyle(authColor(entry.kind))
                            Spacer()
                            if let t = entry.timestamp {
                                Text(t.formatted(date: .numeric, time: .shortened))
                                    .font(.caption2.monospacedDigit())
                                    .foregroundStyle(Theme.text3)
                            }
                        }
                        Text("\(entry.process): \(entry.message)")
                            .font(.caption)
                            .foregroundStyle(Theme.text)
                            .lineLimit(3)
                    }
                    .padding(.vertical, 5)
                    if index < min(rows.count, drillCap) - 1 {
                        Divider().background(Theme.hair2)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var loginList: some View {
        let rows = filteredLogins
        if rows.isEmpty {
            ContentUnavailableView("No login records", systemImage: "person.badge.key")
                .padding(.top, 40)
        } else {
            capNote(total: rows.count)
            Card {
                ForEach(Array(rows.prefix(drillCap).enumerated()), id: \.element.id) { index, record in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(record.isFailedLogin ? "Failed login" : record.type.label)
                                .font(.caption.bold())
                                .foregroundStyle(record.isFailedLogin ? Theme.high : Theme.text2)
                            Spacer()
                            if let t = record.timestamp {
                                Text(t.formatted(date: .numeric, time: .shortened))
                                    .font(.caption2.monospacedDigit())
                                    .foregroundStyle(Theme.text3)
                            }
                        }
                        Text("\(record.user.isEmpty ? "—" : record.user) on \(record.line.isEmpty ? "—" : record.line)\(record.host.isEmpty ? "" : " from \(record.host)")")
                            .font(.caption)
                            .foregroundStyle(Theme.text)
                            .lineLimit(2)
                    }
                    .padding(.vertical, 5)
                    if index < min(rows.count, drillCap) - 1 {
                        Divider().background(Theme.hair2)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func capNote(total: Int) -> some View {
        if total > drillCap {
            Text("Showing first \(drillCap) of \(total) — filter to narrow, or use the macOS app.")
                .font(.caption2)
                .foregroundStyle(Theme.text3)
                .padding(.top, 6)
        }
    }

    private func authColor(_ kind: AuthLogEntry.Kind) -> Color {
        switch kind {
        case .sshFailed, .sshInvalidUser: return Theme.high
        case .sshAccepted:                return Theme.low
        case .userAdded, .userModified:   return Theme.med
        default:                          return Theme.text2
        }
    }
}

/// Per-user shell history, newest (or file order) first.
struct ShellHistoryDrillView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""

    private var filtered: [ShellHistoryEntry] {
        let rows = model.shellHistory
        guard !query.isEmpty else { return rows }
        return rows.filter {
            $0.command.localizedCaseInsensitiveContains(query)
                || $0.user.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Shell History",
                           subtitle: "\(model.shellHistoryCount) command\(model.shellHistoryCount == 1 ? "" : "s")")
                TextField("Filter command / user...", text: $query)
                    .textFieldStyle(.roundedBorder)
                    .padding(.top, 10)

                let rows = filtered
                if rows.isEmpty {
                    ContentUnavailableView("No shell history", systemImage: "terminal")
                        .padding(.top, 40)
                } else {
                    if rows.count > drillCap {
                        Text("Showing first \(drillCap) of \(rows.count).")
                            .font(.caption2).foregroundStyle(Theme.text3).padding(.top, 6)
                    }
                    Card {
                        ForEach(Array(rows.prefix(drillCap).enumerated()), id: \.element.id) { index, entry in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text("\(entry.user) · \(entry.shell.label)")
                                        .font(.caption.bold())
                                        .foregroundStyle(Theme.teal)
                                    Spacer()
                                    if let t = entry.timestamp {
                                        Text(t.formatted(date: .numeric, time: .shortened))
                                            .font(.caption2.monospacedDigit())
                                            .foregroundStyle(Theme.text3)
                                    }
                                }
                                Text(entry.command)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(Theme.text)
                                    .lineLimit(3)
                                    .textSelection(.enabled)
                            }
                            .padding(.vertical, 5)
                            if index < min(rows.count, drillCap) - 1 {
                                Divider().background(Theme.hair2)
                            }
                        }
                    }
                }
                Spacer(minLength: 26)
            }
            .padding(.horizontal)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }
}

/// SSH trust + privilege (read-only).
struct LinuxAccessDrillView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Accounts & SSH",
                           subtitle: "\(model.sshKeyCount) SSH key\(model.sshKeyCount == 1 ? "" : "s")")
                if let access = model.linuxAccess {
                    if !access.sshKeys.isEmpty {
                        SectionHeader(label: "SSH keys").padding(.top, 14)
                        Card {
                            ForEach(Array(access.sshKeys.enumerated()), id: \.element.id) { index, key in
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack {
                                        Text(key.kind.label)
                                            .font(.caption.bold()).foregroundStyle(Theme.teal)
                                        Spacer()
                                        Text(key.user ?? key.host ?? "—")
                                            .font(.caption2).foregroundStyle(Theme.text3)
                                    }
                                    Text(key.algorithm + (key.comment.isEmpty ? "" : "  \(key.comment)"))
                                        .font(.caption.monospaced()).foregroundStyle(Theme.text)
                                        .lineLimit(2).truncationMode(.middle)
                                    if !key.options.isEmpty {
                                        Text(key.options.joined(separator: ", "))
                                            .font(.caption2).foregroundStyle(Theme.high)
                                            .lineLimit(2)
                                    }
                                }
                                .padding(.vertical, 5)
                                if index < access.sshKeys.count - 1 {
                                    Divider().background(Theme.hair2)
                                }
                            }
                        }
                    }
                    if !access.sshdSettings.isEmpty {
                        SectionHeader(label: "sshd_config").padding(.top, 14)
                        Card {
                            ForEach(LinuxAccessView.notableSSHD, id: \.0) { key, label in
                                if let v = access.sshdSettings[key] {
                                    KVRow(key: label, value: v)
                                }
                            }
                        }
                    }
                    let priv = access.groups.filter {
                        ["sudo","wheel","admin","docker","lxd","adm"].contains($0.name.lowercased())
                            && !$0.members.isEmpty
                    }
                    if !priv.isEmpty {
                        SectionHeader(label: "Privileged groups").padding(.top, 14)
                        Card {
                            ForEach(Array(priv.enumerated()), id: \.offset) { _, g in
                                KVRow(key: g.name, value: g.members.joined(separator: ", "))
                            }
                        }
                    }
                } else {
                    ContentUnavailableView("No access artifacts", systemImage: "key.horizontal")
                        .padding(.top, 60)
                }
                Spacer(minLength: 26)
            }
            .padding(.horizontal)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }
}

/// Cron + systemd persistence entries.
struct LinuxPersistenceDrillView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                LargeTitle(title: "Linux Persistence",
                           subtitle: "\(model.linuxPersistenceCount) entr\(model.linuxPersistenceCount == 1 ? "y" : "ies")")
                let rows = model.linuxPersistence
                if rows.isEmpty {
                    ContentUnavailableView("No persistence entries", systemImage: "calendar.badge.clock")
                        .padding(.top, 40)
                } else {
                    Card {
                        ForEach(Array(rows.enumerated()), id: \.element.id) { index, entry in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text(entry.kind.label)
                                        .font(.caption.bold())
                                        .foregroundStyle(Theme.teal)
                                    if let schedule = entry.schedule {
                                        Text(schedule)
                                            .font(.caption2.monospaced())
                                            .foregroundStyle(Theme.text2)
                                    }
                                    Spacer()
                                    if let user = entry.user {
                                        Text(user).font(.caption2).foregroundStyle(Theme.text3)
                                    }
                                }
                                if let unit = entry.unitName {
                                    Text(unit).font(.caption).foregroundStyle(Theme.text)
                                }
                                Text(entry.command)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(Theme.text2)
                                    .lineLimit(3)
                                    .textSelection(.enabled)
                            }
                            .padding(.vertical, 5)
                            if index < rows.count - 1 {
                                Divider().background(Theme.hair2)
                            }
                        }
                    }
                }
                Spacer(minLength: 26)
            }
            .padding(.horizontal)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }
}
#endif
