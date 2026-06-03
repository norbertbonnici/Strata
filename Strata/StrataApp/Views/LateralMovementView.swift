import SwiftUI

struct LateralMovementView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selected: String?

    private var graph: LateralGraph { LateralGraph.build(from: model.events) }

    var body: some View {
        Group {
            if model.events.isEmpty {
                ContentUnavailableView("No events parsed yet",
                    systemImage: "point.3.connected.trianglepath.dotted",
                    description: Text("Parse event logs on the Events tab to populate this view."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if graph.edges.isEmpty {
                ContentUnavailableView("No lateral logons found",
                    systemImage: "point.3.connected.trianglepath.dotted",
                    description: Text("No 4624 / 4625 events with remote logon types (3, 7, 8, 10) were observed."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HSplitView {
                    LateralGraphCanvas(graph: graph, selection: $selected)
                        .frame(minWidth: 480)
                    NodeDetailPanel(graph: graph, selection: selected)
                        .frame(minWidth: 280)
                }
            }
        }
        .navigationTitle(graph.edges.isEmpty
                         ? "Lateral Movement"
                         : "Lateral Movement - \(graph.edges.count) edges, \(graph.nodes.count) nodes")
    }
}

// MARK: - Canvas

/// Circular layout: known hosts (the boxes we have logs from) are drawn
/// larger and in blue; external sources (workstations / IPs we only see as
/// origins) are smaller and orange. Edge thickness encodes logon count.
private struct LateralGraphCanvas: View {
    let graph: LateralGraph
    @Binding var selection: String?

    @State private var canvasSize: CGSize = .zero

    var body: some View {
        GeometryReader { geo in
            let layout = LayoutCache(graph: graph, size: geo.size)
            ZStack {
                Canvas { ctx, _ in
                    draw(into: &ctx, layout: layout)
                }
                // Invisible buttons positioned over each node give us hit
                // testing without re-implementing point-in-circle by hand.
                ForEach(graph.nodes) { node in
                    let pos = layout.position(of: node.id) ?? .zero
                    let radius = layout.radius(of: node)
                    Button {
                        selection = (selection == node.id) ? nil : node.id
                    } label: {
                        Circle().fill(Color.clear).frame(width: radius * 2,
                                                          height: radius * 2)
                    }
                    .buttonStyle(.plain)
                    .position(pos)
                }
            }
            .padding(40)
        }
        .background(Color(NSColor.controlBackgroundColor))
    }

    /// Two-segment arrowhead at the line's destination, offset by the target
    /// node's radius so the head sits just outside the circle.
    private func arrowPath(from control: CGPoint,
                           to dst: CGPoint,
                           endpointRadius: CGFloat) -> Path {
        let dx = dst.x - control.x
        let dy = dst.y - control.y
        let angle = atan2(dy, dx)
        let head = endpointRadius + 6
        let tip = CGPoint(x: dst.x - cos(angle) * head,
                          y: dst.y - sin(angle) * head)
        let leftAngle  = angle - .pi / 6
        let rightAngle = angle + .pi / 6
        let armLength: CGFloat = 10
        let leftEnd  = CGPoint(x: tip.x - cos(leftAngle)  * armLength,
                                y: tip.y - sin(leftAngle)  * armLength)
        let rightEnd = CGPoint(x: tip.x - cos(rightAngle) * armLength,
                                y: tip.y - sin(rightAngle) * armLength)
        var path = Path()
        path.move(to: tip);  path.addLine(to: leftEnd)
        path.move(to: tip);  path.addLine(to: rightEnd)
        return path
    }

    private func draw(into ctx: inout GraphicsContext, layout: LayoutCache) {
        // Edges first so node circles render on top of them.
        for edge in graph.edges {
            guard let src = layout.position(of: edge.source),
                  let dst = layout.position(of: edge.target) else { continue }
            let highlighted = (selection == edge.source || selection == edge.target)
            let baseColor: Color = edge.failureCount == edge.count
                ? .red    // every attempt failed
                : (edge.failureCount > 0 ? .orange : .accentColor)
            let color = highlighted ? baseColor : baseColor.opacity(0.35)
            let width = min(8.0, 1.0 + log(Double(edge.count) + 1) * 1.5)

            var path = Path()
            path.move(to: src)
            // Shallow curve via control point pulled toward the canvas centre
            // so multi-edge fans don't all overlap.
            let mid = CGPoint(x: (src.x + dst.x) / 2, y: (src.y + dst.y) / 2)
            let centre = layout.centre
            let control = CGPoint(x: (mid.x + centre.x) / 2,
                                  y: (mid.y + centre.y) / 2)
            path.addQuadCurve(to: dst, control: control)
            ctx.stroke(path, with: .color(color), lineWidth: width)

            // Arrowhead at the destination so direction is obvious.
            let arrow = arrowPath(from: control,
                                  to: dst,
                                  endpointRadius: layout.radius(ofID: edge.target))
            ctx.stroke(arrow, with: .color(color), lineWidth: width)
        }

        // Nodes
        for node in graph.nodes {
            guard let pos = layout.position(of: node.id) else { continue }
            let r = layout.radius(of: node)
            let rect = CGRect(x: pos.x - r, y: pos.y - r, width: 2 * r, height: 2 * r)
            let baseColor: Color = node.kind == .knownHost ? .accentColor : .orange
            let isSelected = selection == node.id
            let fill = isSelected ? baseColor : baseColor.opacity(0.85)
            ctx.fill(Path(ellipseIn: rect), with: .color(fill))
            if isSelected {
                ctx.stroke(Path(ellipseIn: rect.insetBy(dx: -3, dy: -3)),
                           with: .color(baseColor), lineWidth: 2)
            }

            // Label below the node.
            let text = Text(node.id).font(.caption).foregroundStyle(.primary)
            let resolved = ctx.resolve(text)
            ctx.draw(resolved, at: CGPoint(x: pos.x, y: pos.y + r + 10),
                      anchor: .top)
        }
    }
}

// MARK: - Layout

/// Lays nodes around a circle. Computes once per render and is cheap enough
/// to redo on every body call.
private struct LayoutCache {
    let graph: LateralGraph
    let size: CGSize

    var centre: CGPoint { CGPoint(x: size.width / 2, y: size.height / 2) }

    private var ringRadius: CGFloat {
        max(60, min(size.width, size.height) / 2 - 80)
    }

    func position(of id: String) -> CGPoint? {
        guard let index = graph.nodes.firstIndex(where: { $0.id == id }) else { return nil }
        let count = max(1, graph.nodes.count)
        let theta = (2 * .pi * Double(index)) / Double(count) - (.pi / 2)
        return CGPoint(x: centre.x + ringRadius * cos(theta),
                       y: centre.y + ringRadius * sin(theta))
    }

    func radius(of node: LateralGraph.Node) -> CGFloat {
        let base: CGFloat = node.kind == .knownHost ? 16 : 10
        return base + CGFloat(min(node.degree, 6)) * 1.5
    }

    func radius(ofID id: String) -> CGFloat {
        guard let node = graph.nodes.first(where: { $0.id == id }) else { return 12 }
        return radius(of: node)
    }
}

// MARK: - Detail panel

private struct NodeDetailPanel: View {
    let graph: LateralGraph
    let selection: String?

    private var inbound: [LateralGraph.Edge] {
        graph.edges.filter { $0.target == selection }.sorted { $0.count > $1.count }
    }
    private var outbound: [LateralGraph.Edge] {
        graph.edges.filter { $0.source == selection }.sorted { $0.count > $1.count }
    }

    var body: some View {
        if let selection {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text(selection).font(.headline)
                    if let node = graph.nodes.first(where: { $0.id == selection }) {
                        Text(node.kind == .knownHost
                             ? "Known host (we have logs from this machine)"
                             : "External source (only seen as a logon origin)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    section("Inbound logons (this host was logged into)", inbound)
                    section("Outbound logons (this host logged into others)", outbound)
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Select a host",
                systemImage: "cursorarrow.click.2",
                description: Text("Click a node to see its inbound and outbound logons."))
        }
    }

    @ViewBuilder
    private func section(_ title: String, _ edges: [LateralGraph.Edge]) -> some View {
        if !edges.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Text(title).font(.subheadline).bold()
                ForEach(edges) { edge in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(edge.source).font(.caption.monospaced())
                            Image(systemName: "arrow.right").foregroundStyle(.secondary)
                            Text(edge.target).font(.caption.monospaced())
                            Spacer()
                            Text("\(edge.count)x").font(.caption2).foregroundStyle(.secondary)
                            if edge.failureCount > 0 {
                                Text("(\(edge.failureCount) failed)")
                                    .font(.caption2).foregroundStyle(.red)
                            }
                        }
                        let types = edge.logonTypes.sorted().map { typeLabel($0) }
                            .joined(separator: ", ")
                        Text("Type: \(types), users: \(edge.users.sorted().joined(separator: ", "))")
                            .font(.caption2).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                        Text("\(edge.firstSeen.formatted()) -> \(edge.lastSeen.formatted())")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                    .padding(8)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                }
            }
        }
    }

    private func typeLabel(_ t: Int) -> String {
        switch t {
        case 2:  return "2 Console"
        case 3:  return "3 Network"
        case 4:  return "4 Batch"
        case 5:  return "5 Service"
        case 7:  return "7 Unlock"
        case 8:  return "8 NetworkCleartext"
        case 10: return "10 RDP"
        case 11: return "11 CachedInteractive"
        default: return "\(t)"
        }
    }
}
