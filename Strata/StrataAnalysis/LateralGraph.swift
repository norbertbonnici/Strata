import Foundation

/// A directed multigraph of who logged into whom, derived from Windows
/// Security 4624 (success) and 4625 (failure) events. Only *remote* logon
/// types are kept - interactive console logons (type 2) and service starts
/// (type 5) aren't lateral movement.
public nonisolated struct LateralGraph: Sendable {
    public struct Node: Identifiable, Hashable, Sendable {
        public let id: String        // canonical name, also the label
        public let kind: Kind
        public let degree: Int       // # of edges incident on this node

        public enum Kind: Sendable {
            case knownHost           // a machine we have evidence from
            case externalSource      // a workstation / IP we only see as an origin
        }
    }

    public struct Edge: Identifiable, Hashable, Sendable {
        public var id: String { "\(source)->\(target)" }
        public let source: String
        public let target: String
        public var count: Int
        public var failureCount: Int
        public var users: Set<String>
        public var logonTypes: Set<Int>     // 3, 10, 7, 8...
        public var firstSeen: Date
        public var lastSeen: Date
    }

    public let nodes: [Node]
    public let edges: [Edge]

    /// Build a graph from a flat list of events. Remote logon types only -
    /// 2 (interactive console) and 5 (service) aren't lateral movement.
    public static func build(from events: [EventLogRecord]) -> LateralGraph {
        let remoteTypes: Set<String> = ["3", "7", "8", "10"]
        let knownHosts = Set(events.map { $0.computer }.filter { !$0.isEmpty })

        // Aggregate edges as (source, target) pairs.
        var edgeMap: [String: Edge] = [:]

        for event in events {
            guard event.eventID == 4624 || event.eventID == 4625 else { continue }
            guard let logonType = event.data("LogonType"),
                  remoteTypes.contains(logonType) else { continue }

            let target = event.computer
            let source = canonicalSource(for: event)
            guard !target.isEmpty, !source.isEmpty, source != target else { continue }

            let key = "\(source)->\(target)"
            let isFailure = event.eventID == 4625
            let user = event.data("TargetUserName") ?? ""
            let type = Int(logonType) ?? 0

            if var existing = edgeMap[key] {
                existing.count += 1
                if isFailure { existing.failureCount += 1 }
                if !user.isEmpty { existing.users.insert(user) }
                existing.logonTypes.insert(type)
                if event.writtenAt < existing.firstSeen { existing.firstSeen = event.writtenAt }
                if event.writtenAt > existing.lastSeen  { existing.lastSeen  = event.writtenAt }
                edgeMap[key] = existing
            } else {
                edgeMap[key] = Edge(
                    source: source, target: target,
                    count: 1,
                    failureCount: isFailure ? 1 : 0,
                    users: user.isEmpty ? [] : [user],
                    logonTypes: [type],
                    firstSeen: event.writtenAt,
                    lastSeen: event.writtenAt)
            }
        }

        // Build nodes from the edge endpoints, classify each.
        let edges = Array(edgeMap.values)
        var degree: [String: Int] = [:]
        for edge in edges {
            degree[edge.source, default: 0] += 1
            degree[edge.target, default: 0] += 1
        }
        let nodes = degree.keys.sorted().map { id in
            Node(id: id,
                 kind: knownHosts.contains(id) ? .knownHost : .externalSource,
                 degree: degree[id] ?? 0)
        }
        return LateralGraph(nodes: nodes, edges: edges)
    }

    /// Prefer a named source (WorkstationName) over an IP - it's more readable
    /// and lets the user spot when one source is reused across hosts.
    private static func canonicalSource(for event: EventLogRecord) -> String {
        let workstation = (event.data("WorkstationName") ?? "")
            .trimmingCharacters(in: .whitespaces)
        if !workstation.isEmpty, workstation != "-" { return workstation }
        let ip = (event.data("IpAddress") ?? "").trimmingCharacters(in: .whitespaces)
        if !ip.isEmpty, ip != "-", ip != "::1", ip != "0.0.0.0", ip != "127.0.0.1" {
            return ip
        }
        return ""
    }
}
