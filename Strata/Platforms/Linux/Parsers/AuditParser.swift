import Foundation

/// Parses the Linux audit daemon log (`/var/log/audit/audit.log`) into folded
/// `AuditEvent` rows. Pure. Replicates the essential interpretation `ausearch
/// -i` does:
///
///  - Each line is `type=NAME msg=audit(EPOCH:SERIAL): key=value …`. A logical
///    event spans several consecutive records sharing the same SERIAL (e.g.
///    SYSCALL + EXECVE + PROCTITLE + CWD + PATH); they're grouped and folded.
///  - Field values are bareword, `"quoted"`, a single-`'`quoted nested blob
///    (USER_* records), or a bare even-length **hex string** (proctitle, EXECVE
///    args, and any name/comm with special chars) which is hex-decoded.
///  - The timestamp is `EPOCH` (`seconds.millis`, UTC); SERIAL is the group key.
///
/// Records are grouped by a streaming flush-on-serial-change (records of one
/// event are contiguous in practice), bounding memory on large logs.
public nonisolated enum AuditParser {

    public static func parse(text: String, sourceFile: String) -> [AuditEvent] {
        var events: [AuditEvent] = []
        var group: [Record] = []
        var groupSerial: Int? = nil

        func flush() {
            guard !group.isEmpty else { return }
            if let event = fold(group, sourceFile: sourceFile) { events.append(event) }
            group.removeAll(keepingCapacity: true)
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let record = parseLine(String(rawLine)) else { continue }
            if record.serial != groupSerial {
                flush()
                groupSerial = record.serial
            }
            group.append(record)
        }
        flush()
        return events
    }

    // MARK: - One record

    struct Record {
        let type: String
        let epoch: Double?
        let serial: Int
        let fields: [String: String]   // raw values (still quoted/hex)
    }

    static func parseLine(_ line: String) -> Record? {
        // Strip an optional leading "node=host " (audisp remote logging).
        var s = Substring(line)
        if s.hasPrefix("node=") {
            if let sp = s.firstIndex(of: " ") { s = s[s.index(after: sp)...] } else { return nil }
        }
        guard s.hasPrefix("type=") else { return nil }
        s = s.dropFirst(5)
        guard let sp = s.firstIndex(of: " ") else { return nil }
        let type = String(s[..<sp])
        s = s[s.index(after: sp)...]

        // msg=audit(EPOCH:SERIAL):
        guard s.hasPrefix("msg=audit(") else { return nil }
        s = s.dropFirst("msg=audit(".count)
        guard let close = s.firstIndex(of: ")") else { return nil }
        let idPart = s[..<close]            // EPOCH:SERIAL
        s = s[s.index(after: close)...]
        if s.hasPrefix(":") { s = s.dropFirst() }
        if s.hasPrefix(" ") { s = s.dropFirst() }

        let idTokens = idPart.split(separator: ":")
        guard idTokens.count == 2, let serial = Int(idTokens[1]) else { return nil }
        let epoch = Double(idTokens[0])     // seconds.millis

        let fields = tokenizeFields(s)
        return Record(type: type, epoch: epoch, serial: serial, fields: fields)
    }

    /// Quote-aware key=value splitter. Values may be `"…"`, `'…'` (USER_* nested
    /// blob, may contain spaces and parens), or a bareword run.
    private static func tokenizeFields(_ body: Substring) -> [String: String] {
        var fields: [String: String] = [:]
        let chars = Array(body)
        var i = 0
        let n = chars.count
        while i < n {
            while i < n, chars[i] == " " { i += 1 }
            guard i < n else { break }
            // key
            let keyStart = i
            while i < n, chars[i] != "=", chars[i] != " " { i += 1 }
            guard i < n, chars[i] == "=" else { break }   // malformed token
            let key = String(chars[keyStart..<i])
            i += 1   // skip '='
            // value
            var value = ""
            if i < n, chars[i] == "\"" {
                i += 1; let start = i
                while i < n, chars[i] != "\"" { i += 1 }
                value = "\"" + String(chars[start..<i]) + "\""
                if i < n { i += 1 }
            } else if i < n, chars[i] == "'" {
                i += 1; let start = i
                while i < n, chars[i] != "'" { i += 1 }
                value = "'" + String(chars[start..<i]) + "'"
                if i < n { i += 1 }
            } else {
                let start = i
                while i < n, chars[i] != " " { i += 1 }
                value = String(chars[start..<i])
            }
            if !key.isEmpty { fields[key] = value }
        }
        return fields
    }

    // MARK: - Fold a group into one event

    private static func fold(_ records: [Record], sourceFile: String) -> AuditEvent? {
        let serial = records[0].serial
        let epoch = records.compactMap(\.epoch).first
        let timestamp = epoch.map { Date(timeIntervalSince1970: $0) }

        let syscallRec = records.first { $0.type == "SYSCALL" }
        let execveRec = records.first { $0.type == "EXECVE" }
        let procRec = records.first { $0.type == "PROCTITLE" }
        let cwdRec = records.first { $0.type == "CWD" }
        let pathRec = records.first { $0.type == "PATH" }
        let userRec = records.first { $0.type.hasPrefix("USER_") || $0.type.hasPrefix("CRED_")
            || $0.type.hasPrefix("ADD_") || $0.type.hasPrefix("DEL_") || $0.type == "GRP_MGMT"
            || $0.type == "LOGIN" || $0.type == "ANOM_ABEND" }
        let avcRec = records.first { $0.type == "AVC" || $0.type == "USER_AVC" }

        // Representative record type.
        let recordType: String
        if execveRec != nil { recordType = "EXECVE" }
        else if syscallRec != nil { recordType = "SYSCALL" }
        else { recordType = records[0].type }

        // SYSCALL-derived scalars.
        let archHex = syscallRec?.fields["arch"]
        let syscallName = syscallRec.flatMap { rec -> String? in
            guard let num = rec.fields["syscall"].flatMap({ Int($0) }) else { return nil }
            return syscallTable(archHex)[num] ?? "syscall=\(num)"
        }
        let success = (syscallRec?.fields["success"]).map { $0 == "yes" }
        let exit = syscallRec?.fields["exit"].flatMap { Int($0) }
        let exe = decode(syscallRec?.fields["exe"]) ?? decode(avcRec?.fields["exe"])
        let comm = decode(syscallRec?.fields["comm"])
        let auid = intOrNil(syscallRec?.fields["auid"] ?? userRec?.fields["auid"])
        let uid = intOrNil(syscallRec?.fields["uid"] ?? userRec?.fields["uid"])
        let ses = intOrNil(syscallRec?.fields["ses"] ?? userRec?.fields["ses"])
        let tty = decode(syscallRec?.fields["tty"])
        let key = decode(syscallRec?.fields["key"]).flatMap { $0 == "(null)" ? nil : $0 }

        // Command line: EXECVE preferred, PROCTITLE fallback.
        var commandLine: String? = execveRec.flatMap { reconstructExecve($0) }
        if commandLine == nil, let proc = procRec?.fields["proctitle"] {
            commandLine = decode(proc)
        }

        // Touched path: CWD + PATH name.
        var path: String?
        if let name = decode(pathRec?.fields["name"]) {
            if name.hasPrefix("/") { path = name }
            else if let cwd = decode(cwdRec?.fields["cwd"]) { path = cwd + "/" + name }
            else { path = name }
        } else {
            path = decode(cwdRec?.fields["cwd"])
        }

        // USER_* account / result / source (top-level and nested msg='…').
        var account: String?, result: String?, sourceIP: String?
        if let user = userRec {
            let nested = user.fields["msg"].map { stripQuotes($0) } ?? ""
            account = decode(user.fields["acct"]) ?? subField(nested, "acct")
            result = (user.fields["res"] ?? subField(nested, "res")).map(normalizeResult)
            sourceIP = (user.fields["addr"] ?? subField(nested, "addr")).flatMap {
                ($0 == "?" || $0.isEmpty) ? nil : $0
            }
            account = account ?? decode(user.fields["id"])   // ADD_USER/etc carry id=
        }

        return AuditEvent(timestamp: timestamp, serial: serial, recordType: recordType,
                          syscall: syscallName, success: success, exit: exit, exe: exe,
                          comm: comm, commandLine: commandLine, path: path,
                          auid: auid, uid: uid, ses: ses, tty: tty, key: key,
                          account: account, result: result, sourceIP: sourceIP,
                          sourceFile: sourceFile)
    }

    /// Rebuild a command line from an EXECVE record: argc + a0..a(argc-1),
    /// each decoded (quoted literal or hex), joined with spaces.
    private static func reconstructExecve(_ rec: Record) -> String? {
        // `argc` is adversary-controlled: clamp it so a forged `argc=2000000000`
        // can't drive a multi-billion-iteration hang, and `argc=Int.max` can't
        // overflow-trap on `argc + 8`. Real EXECVE argc is small.
        let argc = min(max(rec.fields["argc"].flatMap { Int($0) } ?? 64, 0), 4096)
        var args: [String] = []
        var n = 0
        while n < argc + 8 {                  // small slack past argc
            if let v = rec.fields["a\(n)"] {
                args.append(decode(v) ?? "")
            } else if rec.fields["a\(n)_len"] != nil || rec.fields["a\(n)[0]"] != nil {
                // Continuation chunks: a<n>[0], a<n>[1], …
                var chunk = ""
                var c = 0
                while let part = rec.fields["a\(n)[\(c)]"] { chunk += decode(part) ?? ""; c += 1 }
                args.append(chunk)
            } else if n >= argc {
                break
            }
            n += 1
        }
        let joined = args.joined(separator: " ").trimmingCharacters(in: .whitespaces)
        return joined.isEmpty ? nil : joined
    }

    // MARK: - Value decoding

    /// Decode an audit field value: strip quotes; hex-decode a bare even-length
    /// hex run (replacing NUL with space, for proctitle's argv separators).
    static func decode(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        if value.hasPrefix("\"") { return String(value.dropFirst().dropLast(value.hasSuffix("\"") ? 1 : 0)) }
        if value.hasPrefix("'") { return stripQuotes(value) }
        // Hex string? (even length, all hex digits, not a path/number we want
        // literal). An unquoted value is hex-encoded when it isn't plain
        // printable - so a bare all-digit run like "30303030" decodes to "0000".
        if value.count >= 2, value.count % 2 == 0,
           value.allSatisfy({ $0.isHexDigit }),
           !value.hasPrefix("/"), !looksLiteralNumeric(value) {
            var bytes: [UInt8] = []
            var idx = value.startIndex
            while idx < value.endIndex {
                let next = value.index(idx, offsetBy: 2)
                if let b = UInt8(value[idx..<next], radix: 16) { bytes.append(b == 0 ? 0x20 : b) }
                idx = next
            }
            return String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespaces)
        }
        return value
    }

    /// Keep only *short* all-digit fields literal (a 1-2 byte value like "10" is
    /// far more likely the decimal it reads as than the 1 byte 0x10). A longer
    /// bare all-digit run in a string-context field is hex-encoded content
    /// (auditd quotes plain-printable values), so it must be decoded.
    private static func looksLiteralNumeric(_ value: String) -> Bool {
        value.count <= 3 && value.allSatisfy { $0.isNumber }
    }

    private static func stripQuotes(_ value: String) -> String {
        var v = Substring(value)
        if v.hasPrefix("'") { v = v.dropFirst() }
        if v.hasSuffix("'") { v = v.dropLast() }
        if v.hasPrefix("\"") { v = v.dropFirst() }
        if v.hasSuffix("\"") { v = v.dropLast() }
        return String(v)
    }

    private static func intOrNil(_ value: String?) -> Int? {
        guard let v = value, let i = Int(v) else { return nil }
        return i == 4_294_967_295 ? nil : i   // unset sentinel (-1)
    }

    private static func normalizeResult(_ value: String) -> String {
        switch value.lowercased() {
        case "1", "success": return "success"
        case "0", "failed":  return "failed"
        default:             return value
        }
    }

    /// Pull `key=value` (bareword or quoted) out of a nested blob.
    private static func subField(_ blob: String, _ key: String) -> String? {
        guard let r = blob.range(of: key + "=") else { return nil }
        let tail = blob[r.upperBound...]
        if tail.hasPrefix("\"") {
            let inner = tail.dropFirst()
            return inner.prefix { $0 != "\"" }.isEmpty ? nil : String(inner.prefix { $0 != "\"" })
        }
        let word = tail.prefix { $0 != " " && $0 != ")" && $0 != "," && $0 != "'" }
        return word.isEmpty ? nil : String(word)
    }

    // MARK: - Syscall tables (common DFIR syscalls)

    private static func syscallTable(_ archHex: String?) -> [Int: String] {
        // aarch64 (c00000b7) differs; default to x86_64 (c000003e).
        if archHex == "c00000b7" { return aarch64 }
        return x86_64
    }

    private static let x86_64: [Int: String] = [
        0: "read", 1: "write", 2: "open", 41: "socket", 42: "connect", 49: "bind",
        57: "fork", 58: "vfork", 59: "execve", 62: "kill", 82: "rename", 87: "unlink",
        90: "chmod", 91: "fchmod", 92: "chown", 101: "ptrace", 105: "setuid",
        106: "setgid", 165: "mount", 175: "init_module", 257: "openat", 260: "fchownat",
        263: "unlinkat", 268: "fchmodat", 280: "utimensat", 322: "execveat",
    ]
    private static let aarch64: [Int: String] = [
        56: "openat", 57: "close", 63: "read", 64: "write", 198: "socket", 203: "connect",
        129: "kill", 220: "clone", 221: "execve", 281: "execveat", 53: "fchmodat",
        35: "unlinkat", 105: "setuid", 144: "setgid", 117: "ptrace",
    ]
}
