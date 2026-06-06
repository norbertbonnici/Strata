import SwiftUI

/// Background behind the lateral-movement canvas. Uses Theme.bg2 - a touch
/// deeper than Theme.bg - so the graph sits in its own visual well rather
/// than blending into the surrounding pane.
private var canvasBackground: Color { Theme.bg2 }

struct LateralMovementView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selected: String?

    private var graph: LateralGraph { model.lateralGraph }   // cached on AppModel

    var body: some View {
        // Build the graph once per render. It was read 4-6x per body, and each
        // build re-sorts the event set and recompiles a regex per 4624/4625.
        let graph = self.graph
        return Group {
            if model.eventCount == 0 {
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
                #if os(macOS)
                HSplitView {
                    LateralGraphCanvas(graph: graph, selection: $selected)
                        .frame(minWidth: 480, maxHeight: .infinity)
                    NodeDetailPanel(graph: graph, selection: selected)
                        .frame(minWidth: 280, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                #else
                HStack(spacing: 0) {
                    LateralGraphCanvas(graph: graph, selection: $selected)
                        .frame(minWidth: 480, maxHeight: .infinity)
                    Divider()
                    NodeDetailPanel(graph: graph, selection: selected)
                        .frame(minWidth: 280, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                #endif
            }
        }
        .navigationTitle(graph.edges.isEmpty
                         ? "Lateral Movement"
                         : "Lateral Movement - \(graph.edges.count) edges, \(graph.nodes.count) nodes")
    }
}

// MARK: - Canvas

/// Interactive graph: known hosts (machines we have logs from) are larger and
/// blue; external sources (origins we only see logging in) are smaller and
/// orange. Edge thickness encodes logon count. The view is pannable and
/// zoomable, nodes are draggable, and a Force toggle turns on a force-directed
/// auto-layout where dragging a node makes its neighbours react.
private struct LateralGraphCanvas: View {
    let graph: LateralGraph
    @Binding var selection: String?

    // Simulation state (positions live here, in an unbounded "world" space).
    @State private var engine = GraphEngine()
    // Pan/zoom transform from world space to the canvas.
    @State private var viewport = Viewport()
    @State private var forceEnabled = false

    // Gesture bookkeeping.
    private enum DragMode: Equatable { case idle, panning, node(String) }
    @State private var dragMode: DragMode = .idle
    @State private var panBase: CGSize = .zero
    @State private var grabOffset: CGPoint = .zero   // cursor->node-centre delta at grab
    @State private var zoomBase: CGFloat = 1
    @State private var lastSize: CGSize = .zero
    @State private var needsFit = true
    // Bumped on every drag change so sticky-mode node drags (which mutate the
    // non-observed engine) still trigger a redraw.
    @State private var dragNonce = 0

    private let minZoom: CGFloat = 0.2
    private let maxZoom: CGFloat = 4.0
    private let tapSlop: CGFloat = 4   // movement under this = a tap, not a drag

    private var graphSignature: String {
        graph.nodes.map(\.id).sorted().joined(separator: "|")
    }

    var body: some View {
        GeometryReader { geo in
            let size = geo.size
            canvas(size: size)
                .onAppear {
                    lastSize = size
                    engine.seed(graph: graph, radii: currentRadii())
                    fit(in: size)
                }
                .onChange(of: size) { _, new in
                    lastSize = new
                    if needsFit { fit(in: new) }
                }
                .onChange(of: graphSignature) { _, _ in
                    // New node set: the engine reseeds itself on the next render;
                    // refit so the fresh layout lands inside the viewport.
                    needsFit = true
                    fit(in: lastSize)
                }
                .onChange(of: forceEnabled) { _, on in
                    if on { engine.reheat() }
                }
        }
    }

    private func canvas(size: CGSize) -> some View {
        engine.seed(graph: graph, radii: currentRadii())
        let _ = dragNonce   // redraw dependency for sticky-mode node drags
        return Group {
            if forceEnabled {
                // Continuous redraw drives the simulation; physics is stepped in
                // the draw pass so it never races SwiftUI's update cycle.
                // Qualified: the app defines its own `TimelineView` (the
                // forensic timeline tab), which would otherwise shadow this.
                SwiftUI.TimelineView(.animation) { _ in
                    Canvas { ctx, sz in
                        engine.step()
                        draw(into: &ctx, size: sz)
                    }
                }
            } else {
                // Sticky mode: no animation loop. The canvas redraws only when
                // state changes (pan / zoom / a node drag bumps dragNonce).
                Canvas { ctx, sz in
                    draw(into: &ctx, size: sz)
                }
            }
        }
        // A gutter so the graph never butts against the window edge or the
        // HSplitView divider. Symmetric, so it preserves the geometric centre
        // that both drawing and hit testing key off (no click/draw drift).
        .padding(40)
        .contentShape(Rectangle())
        .gesture(dragGesture)
        .simultaneousGesture(magnifyGesture)
        .background(canvasBackground)
        .overlay(alignment: .topTrailing) { controls.padding(10) }
    }

    // MARK: Controls overlay

    private var controls: some View {
        HStack(spacing: 6) {
            Toggle(isOn: $forceEnabled) {
                Label("Force", systemImage: "scribble.variable")
            }
            .toggleStyle(.button)
            .help("Auto-arrange with a force-directed layout. Drag a node and its neighbours react and re-settle.")

            Divider().frame(height: 14)

            Button { zoomBy(1 / 1.25) } label: { Image(systemName: "minus.magnifyingglass") }
                .help("Zoom out")
            Button { zoomBy(1.25) } label: { Image(systemName: "plus.magnifyingglass") }
                .help("Zoom in")
            Button { fit(in: lastSize) } label: { Image(systemName: "arrow.up.left.and.down.right.magnifyingglass") }
                .help("Fit the whole graph to the view")
            Button { resetLayout() } label: { Image(systemName: "arrow.counterclockwise") }
                .help("Reset to the ring layout")
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .padding(6)
        .background(.thinMaterial, in: Capsule())
    }

    // MARK: Gestures

    private var dragGesture: some Gesture {
        DragGesture(minimumDistance: 0)
            .onChanged { value in
                if dragMode == .idle {
                    let world = viewport.toWorld(value.startLocation, in: lastSize)
                    if let id = hitNode(at: world), let centre = engine.position(of: id) {
                        dragMode = .node(id)
                        // Remember where on the node we grabbed it, so dragging
                        // tracks the cursor instead of snapping the centre to it.
                        grabOffset = CGPoint(x: centre.x - world.x, y: centre.y - world.y)
                        if forceEnabled { engine.pinned = id; engine.reheat() }
                    } else {
                        dragMode = .panning
                        panBase = viewport.pan
                    }
                }
                let moved = hypot(value.translation.width, value.translation.height)
                switch dragMode {
                case .node(let id):
                    // Hold still until the press becomes a real drag, so a
                    // tap-to-select never nudges the node.
                    if moved >= tapSlop {
                        let w = viewport.toWorld(value.location, in: lastSize)
                        engine.setPosition(id, to: CGPoint(x: w.x + grabOffset.x, y: w.y + grabOffset.y))
                        if forceEnabled { engine.reheat() }
                    }
                case .panning:
                    // Screen translation -> world units (so pan speed is
                    // zoom-independent and tracks the cursor).
                    viewport.pan = CGSize(width: panBase.width + value.translation.width / viewport.zoom,
                                          height: panBase.height + value.translation.height / viewport.zoom)
                case .idle:
                    break
                }
                dragNonce &+= 1
            }
            .onEnded { value in
                if case .node(let id) = dragMode {
                    let moved = hypot(value.translation.width, value.translation.height)
                    if moved < tapSlop {
                        selection = (selection == id) ? nil : id   // it was a tap
                    }
                    engine.pinned = nil   // let it re-settle in Force mode
                }
                dragMode = .idle
                dragNonce &+= 1
            }
    }

    private var magnifyGesture: some Gesture {
        MagnifyGesture()
            .onChanged { value in
                viewport.zoom = clampZoom(zoomBase * value.magnification)
            }
            .onEnded { _ in zoomBase = viewport.zoom }
    }

    // MARK: Viewport helpers

    private func clampZoom(_ z: CGFloat) -> CGFloat { min(maxZoom, max(minZoom, z)) }

    private func zoomBy(_ factor: CGFloat) {
        viewport.zoom = clampZoom(viewport.zoom * factor)
        zoomBase = viewport.zoom
    }

    /// Frame the whole graph: scale so the node bounding box fits with padding
    /// and centre it. No-op until we know the canvas size and have positions.
    private func fit(in size: CGSize) {
        guard size.width > 1, size.height > 1,
              let box = engine.boundingBox(), box.width > 1, box.height > 1 else { return }
        // Reserve more than the 40pt gutter so node labels (which extend below
        // each circle, beyond the bounding box) stay inside the canvas.
        let pad: CGFloat = 120
        let z = min((size.width - pad) / box.width, (size.height - pad) / box.height)
        viewport.zoom = clampZoom(z)
        viewport.pan = CGSize(width: -box.midX, height: -box.midY)
        zoomBase = viewport.zoom
        needsFit = false
    }

    private func resetLayout() {
        engine.resetLayout()
        engine.seed(graph: graph, radii: currentRadii())
        fit(in: lastSize)
        dragNonce &+= 1
    }

    // MARK: Node geometry / hit testing

    private func nodeRadius(_ node: LateralGraph.Node) -> CGFloat {
        let base: CGFloat = node.kind == .knownHost ? 16 : 10
        return base + CGFloat(min(node.degree, 6)) * 1.5
    }

    private func nodeRadius(byID id: String) -> CGFloat {
        guard let node = graph.nodes.first(where: { $0.id == id }) else { return 12 }
        return nodeRadius(node)
    }

    private func currentRadii() -> [String: CGFloat] {
        Dictionary(uniqueKeysWithValues: graph.nodes.map { ($0.id, nodeRadius($0)) })
    }

    /// Nearest node whose (world-space) circle contains `world`, plus a little
    /// slack so small nodes are still easy to grab.
    private func hitNode(at world: CGPoint) -> String? {
        var best: (id: String, dist: CGFloat)?
        for node in graph.nodes {
            guard let p = engine.position(of: node.id) else { continue }
            let d = hypot(world.x - p.x, world.y - p.y)
            if d <= nodeRadius(node) + 6, best == nil || d < best!.dist {
                best = (node.id, d)
            }
        }
        return best?.id
    }

    // MARK: Drawing

    private func draw(into ctx: inout GraphicsContext, size: CGSize) {
        // Edges first so node circles render on top of them.
        for edge in graph.edges {
            guard let s = engine.position(of: edge.source),
                  let d = engine.position(of: edge.target) else { continue }
            let src = viewport.toScreen(s, in: size)
            let dst = viewport.toScreen(d, in: size)
            let highlighted = (selection == edge.source || selection == edge.target)
            let baseColor: Color = edge.failureCount == edge.count
                ? .red    // every attempt failed
                : (edge.failureCount > 0 ? .orange : .accentColor)
            let color = highlighted ? baseColor : baseColor.opacity(0.35)
            let width = max(0.75, min(12, (1.0 + log(Double(edge.count) + 1) * 1.5) * viewport.zoom))

            // Shallow curve via a control point pulled toward the world origin
            // so multi-edge fans don't all overlap.
            let midWorld = CGPoint(x: (s.x + d.x) / 2, y: (s.y + d.y) / 2)
            let control = viewport.toScreen(CGPoint(x: midWorld.x / 2, y: midWorld.y / 2), in: size)
            var path = Path()
            path.move(to: src)
            path.addQuadCurve(to: dst, control: control)
            ctx.stroke(path, with: .color(color), lineWidth: width)

            // Arrowhead at the destination so direction is obvious.
            let endpointRadius = nodeRadius(byID: edge.target) * viewport.zoom
            ctx.stroke(arrowPath(from: control, to: dst, endpointRadius: endpointRadius),
                       with: .color(color), lineWidth: width)
        }

        // Nodes
        for node in graph.nodes {
            guard let p = engine.position(of: node.id) else { continue }
            let pos = viewport.toScreen(p, in: size)
            let r = nodeRadius(node) * viewport.zoom
            let rect = CGRect(x: pos.x - r, y: pos.y - r, width: 2 * r, height: 2 * r)
            let baseColor: Color = node.kind == .knownHost ? .accentColor : .orange
            let isSelected = selection == node.id
            ctx.fill(Path(ellipseIn: rect), with: .color(isSelected ? baseColor : baseColor.opacity(0.85)))
            if isSelected {
                ctx.stroke(Path(ellipseIn: rect.insetBy(dx: -3, dy: -3)),
                           with: .color(baseColor), lineWidth: 2)
            }
            // Label below the node (kept in screen space so it stays legible
            // at any zoom).
            let text = Text(node.id).font(.caption).foregroundStyle(.primary)
            ctx.draw(ctx.resolve(text), at: CGPoint(x: pos.x, y: pos.y + r + 10), anchor: .top)
        }
    }

    /// Two-segment arrowhead at the line's destination, offset by the target
    /// node's radius so the head sits just outside the circle.
    private func arrowPath(from control: CGPoint, to dst: CGPoint,
                           endpointRadius: CGFloat) -> Path {
        let dx = dst.x - control.x
        let dy = dst.y - control.y
        let angle = atan2(dy, dx)
        let head = endpointRadius + 6
        let tip = CGPoint(x: dst.x - cos(angle) * head, y: dst.y - sin(angle) * head)
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
}

// MARK: - Transform

/// Maps the simulation's unbounded "world" space to canvas points. `pan` is a
/// world-space offset of the origin from the canvas centre; `zoom` scales about
/// that centre.
private struct Viewport {
    var zoom: CGFloat = 1
    var pan: CGSize = .zero

    func toScreen(_ p: CGPoint, in size: CGSize) -> CGPoint {
        CGPoint(x: size.width / 2 + (p.x + pan.width) * zoom,
                y: size.height / 2 + (p.y + pan.height) * zoom)
    }

    func toWorld(_ s: CGPoint, in size: CGSize) -> CGPoint {
        CGPoint(x: (s.x - size.width / 2) / zoom - pan.width,
                y: (s.y - size.height / 2) / zoom - pan.height)
    }
}

// MARK: - Force simulation

/// Holds node positions and runs an optional force-directed layout. A plain
/// reference type (not observed): the view drives redraws via TimelineView and
/// a drag nonce, and we step physics inside the Canvas draw pass so mutations
/// never collide with SwiftUI's view-update cycle.
private final class GraphEngine {
    private struct Body { var pos: CGPoint; var vel: CGPoint }

    private var bodies: [String: Body] = [:]
    private var order: [String] = []                                 // stable iteration order
    private var links: [(a: String, b: String, rest: CGFloat)] = []
    private var radius: [String: CGFloat] = [:]
    private var signature = ""
    private var alpha: CGFloat = 0                                    // d3-style cooling factor

    var pinned: String?                                              // node held under the cursor

    // Tunables (world units). Conservative + well-damped so the layout settles
    // rather than oscillating; Force is opt-in so these never affect the
    // default ring.
    private let repulsion: CGFloat = 9000
    private let springK: CGFloat = 0.02
    private let gravity: CGFloat = 0.015
    private let velocityDecay: CGFloat = 0.82
    private let maxSpeed: CGFloat = 40
    private let alphaDecay: CGFloat = 0.02
    private let alphaMin: CGFloat = 0.01

    func position(of id: String) -> CGPoint? { bodies[id]?.pos }

    /// Keep the engine in sync with the current graph. Radii and links refresh
    /// every call (cheap); positions are only reseeded when the node *set*
    /// changes, so a graph refresh or a re-render never teleports the layout.
    func seed(graph: LateralGraph, radii: [String: CGFloat]) {
        radius = radii
        let ids = Set(graph.nodes.map(\.id))
        links = graph.edges.compactMap { e in
            guard ids.contains(e.source), ids.contains(e.target) else { return nil }
            return (e.source, e.target, restLength(for: e))
        }

        let sig = graph.nodes.map(\.id).sorted().joined(separator: "|")
        guard sig != signature else { return }
        signature = sig
        order = graph.nodes.map(\.id)

        let n = max(1, order.count)
        let ring = max(140, CGFloat(n) * 22)
        var fresh: [String: Body] = [:]
        for (i, id) in order.enumerated() {
            if let existing = bodies[id] { fresh[id] = existing; continue }  // keep prior position
            let theta = (2 * .pi * CGFloat(i)) / CGFloat(n) - .pi / 2
            fresh[id] = Body(pos: CGPoint(x: cos(theta) * ring, y: sin(theta) * ring), vel: .zero)
        }
        bodies = fresh
        alpha = 1
    }

    func setPosition(_ id: String, to p: CGPoint) {
        guard bodies[id] != nil else { return }
        bodies[id]!.pos = p
        bodies[id]!.vel = .zero
    }

    func reheat() { alpha = max(alpha, 0.7) }

    /// Wipe positions so the next `seed` rebuilds the ring from scratch.
    func resetLayout() {
        bodies = [:]
        signature = ""
        alpha = 1
    }

    /// One physics tick (d3-force style: per-frame, dt-independent). Pinned
    /// node is held fixed so the cursor leads and neighbours follow.
    func step() {
        guard order.count > 1 else { return }
        guard alpha > alphaMin || pinned != nil else { return }

        // Repulsion: every pair pushes apart (~1/dist²). O(n²), but lateral
        // graphs are small (tens of nodes).
        for i in 0..<order.count {
            let a = order[i]
            guard var ba = bodies[a] else { continue }
            for j in (i + 1)..<order.count {
                let b = order[j]
                guard let bb = bodies[b] else { continue }
                var dx = ba.pos.x - bb.pos.x
                var dy = ba.pos.y - bb.pos.y
                var d2 = dx * dx + dy * dy
                if d2 < 0.01 {   // coincident: nudge apart deterministically
                    dx = 0.5; dy = CGFloat((i + j) % 5) - 2; d2 = dx * dx + dy * dy
                }
                let d = sqrt(d2)
                let f = repulsion * alpha / d2
                let fx = dx / d * f, fy = dy / d * f
                ba.vel.x += fx; ba.vel.y += fy
                bodies[b]?.vel.x -= fx; bodies[b]?.vel.y -= fy
            }
            bodies[a] = ba
        }

        // Springs along edges, pulling toward the rest length.
        for link in links {
            guard let ba = bodies[link.a], let bb = bodies[link.b] else { continue }
            let dx = bb.pos.x - ba.pos.x, dy = bb.pos.y - ba.pos.y
            let d = max(1, hypot(dx, dy))
            let f = (d - link.rest) * springK * alpha
            let fx = dx / d * f, fy = dy / d * f
            bodies[link.a]?.vel.x += fx; bodies[link.a]?.vel.y += fy
            bodies[link.b]?.vel.x -= fx; bodies[link.b]?.vel.y -= fy
        }

        // Gravity toward the origin keeps disconnected pieces on screen.
        for id in order {
            guard var b = bodies[id] else { continue }
            b.vel.x -= b.pos.x * gravity * alpha
            b.vel.y -= b.pos.y * gravity * alpha
            bodies[id] = b
        }

        // Integrate with damping + a speed clamp for stability.
        for id in order {
            guard var b = bodies[id] else { continue }
            if id == pinned { b.vel = .zero; bodies[id] = b; continue }
            b.vel.x *= velocityDecay; b.vel.y *= velocityDecay
            let speed = hypot(b.vel.x, b.vel.y)
            if speed > maxSpeed { b.vel.x *= maxSpeed / speed; b.vel.y *= maxSpeed / speed }
            b.pos.x += b.vel.x; b.pos.y += b.vel.y
            bodies[id] = b
        }

        alpha *= (1 - alphaDecay)
    }

    func boundingBox() -> CGRect? {
        guard !bodies.isEmpty else { return nil }
        var minX = CGFloat.greatestFiniteMagnitude, minY = CGFloat.greatestFiniteMagnitude
        var maxX = -CGFloat.greatestFiniteMagnitude, maxY = -CGFloat.greatestFiniteMagnitude
        for (id, b) in bodies {
            let r = radius[id] ?? 12
            minX = min(minX, b.pos.x - r); minY = min(minY, b.pos.y - r)
            maxX = max(maxX, b.pos.x + r); maxY = max(maxY, b.pos.y + r)
        }
        return CGRect(x: minX, y: minY, width: maxX - minX, height: maxY - minY)
    }

    private func restLength(for edge: LateralGraph.Edge) -> CGFloat {
        (radius[edge.source] ?? 12) + (radius[edge.target] ?? 12) + 70
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
                description: Text("Click a node to see its inbound and outbound logons. Drag to move it; pinch or use the toolbar to zoom."))
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
