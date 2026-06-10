import Foundation
import CoreGraphics
import CoreText

/// Renders a `CoCReportModel` to a paginated PDF — the formal, file-able
/// chain-of-custody record (the HTML/Markdown renderers mirror the same model
/// for convenience copies). Pure CoreText + `CGPDFContext`: no WebKit and no
/// AppKit/UIKit, so it runs headless, off the main actor, on both platforms,
/// and produces the same bytes for the same model.
///
/// Layout mirrors `CoCReportRenderer.html` section-for-section: case header →
/// per-evidence acquisition + source-hash blocks → custody-log table. Tables
/// repeat their header row after a page break and every page carries a
/// "Page N of M" footer.
public nonisolated enum CoCPDFRenderer {

    // MARK: - Geometry (A4, 18 mm margins — matches the HTML report's @page)

    private static let pageSize = CGSize(width: 595.28, height: 841.89)
    private static let margin: CGFloat = 51
    private static var contentWidth: CGFloat { pageSize.width - 2 * margin }
    private static var contentHeight: CGFloat { pageSize.height - 2 * margin }

    private static let cellPadX: CGFloat = 4
    private static let cellPadY: CGFloat = 3

    // MARK: - Styles
    //
    // CTFont/CGColor are not Sendable, so these live per-call (not in statics)
    // to stay clean under strict concurrency. Palette matches the HTML CSS.

    private struct Fonts {
        let title = CTFontCreateWithName("Helvetica-Bold" as CFString, 18, nil)
        let subtitle = CTFontCreateWithName("Helvetica-Bold" as CFString, 12.5, nil)
        let section = CTFontCreateWithName("Helvetica-Bold" as CFString, 13, nil)
        let evidence = CTFontCreateWithName("Helvetica-Bold" as CFString, 11, nil)
        let label = CTFontCreateWithName("Helvetica-Bold" as CFString, 8, nil)
        let body = CTFontCreateWithName("Helvetica" as CFString, 9, nil)
        let bodyBold = CTFontCreateWithName("Helvetica-Bold" as CFString, 9, nil)
        let note = CTFontCreateWithName("Helvetica-Oblique" as CFString, 8.5, nil)
        let mono = CTFontCreateWithName("Menlo-Regular" as CFString, 8, nil)
        let footer = CTFontCreateWithName("Helvetica" as CFString, 7.5, nil)
    }

    private struct Palette {
        let fg = CGColor(red: 0.106, green: 0.122, blue: 0.141, alpha: 1)         // #1b1f24
        let muted = CGColor(red: 0.357, green: 0.392, blue: 0.439, alpha: 1)      // #5b6470
        let line = CGColor(red: 0.847, green: 0.867, blue: 0.890, alpha: 1)       // #d8dde3
        let accent = CGColor(red: 0.122, green: 0.435, blue: 0.545, alpha: 1)     // #1f6f8b
        let headerFill = CGColor(red: 0.953, green: 0.961, blue: 0.969, alpha: 1) // #f3f5f7
    }

    // MARK: - Layout items

    /// One flow unit. Text blocks span the content width; rows carry resolved
    /// column widths plus the key of their table's header row so a page break
    /// can repeat it.
    private enum Item {
        case text(NSAttributedString, keepWithNext: Bool, rule: Bool)
        case row(cells: [NSAttributedString], widths: [CGFloat],
                 isHeader: Bool, headerKey: Int, fill: Bool, separator: Bool)
        case spacer(CGFloat)
    }

    private struct Placed {
        let item: Item
        let y: CGFloat        // offset from the content top
        let height: CGFloat
    }

    // MARK: - Entry point

    public static func pdf(_ model: CoCReportModel) -> Data {
        let fonts = Fonts()
        let palette = Palette()
        var headerRows: [Int: Item] = [:]
        let items = buildItems(model, fonts, palette, headerRows: &headerRows)
        var pages = paginate(items, headerRows: headerRows)
        if pages.isEmpty { pages = [[]] }

        let data = NSMutableData()
        guard let consumer = CGDataConsumer(data: data as CFMutableData) else { return Data() }
        var mediaBox = CGRect(origin: .zero, size: pageSize)
        let info: [CFString: Any] = [
            kCGPDFContextTitle: "Strata Chain-of-Custody Report — \(model.caseName)",
            kCGPDFContextCreator: "Strata",
            kCGPDFContextAuthor: model.examiner.isEmpty ? "Strata" : model.examiner,
        ]
        guard let ctx = CGContext(consumer: consumer, mediaBox: &mediaBox,
                                  info as CFDictionary) else { return Data() }

        for (index, page) in pages.enumerated() {
            ctx.beginPDFPage(nil)
            ctx.textMatrix = .identity
            for placed in page { draw(placed, in: ctx, palette: palette) }
            drawFooter(in: ctx, page: index + 1, of: pages.count,
                       model: model, fonts: fonts, palette: palette)
            ctx.endPDFPage()
        }
        ctx.closePDF()
        return data as Data
    }

    // MARK: - Content assembly (mirrors CoCReportRenderer.html)

    private static func buildItems(_ model: CoCReportModel, _ fonts: Fonts,
                                   _ palette: Palette,
                                   headerRows: inout [Int: Item]) -> [Item] {
        var items: [Item] = []
        var nextHeaderKey = 0
        let dash = "—"

        func text(_ string: String, _ font: CTFont, _ color: CGColor,
                  before: CGFloat = 0, after: CGFloat = 0,
                  keepWithNext: Bool = false, rule: Bool = false, mono: Bool = false) {
            if before > 0 { items.append(.spacer(before)) }
            items.append(.text(attr(string, font: font, color: color, charWrap: mono),
                               keepWithNext: keepWithNext, rule: rule))
            if after > 0 { items.append(.spacer(after)) }
        }

        func metaRow(_ label: String, _ value: String) {
            items.append(.row(
                cells: [attr(label, font: fonts.bodyBold, color: palette.muted),
                        attr(value, font: fonts.body, color: palette.fg)],
                widths: [110, contentWidth - 110],
                isHeader: false, headerKey: -1, fill: false, separator: false))
        }

        func tableHeader(_ titles: [String], _ widths: [CGFloat]) -> Int {
            let key = nextHeaderKey
            nextHeaderKey += 1
            let row = Item.row(
                cells: titles.map { attr($0, font: fonts.bodyBold, color: palette.fg) },
                widths: widths, isHeader: true, headerKey: key, fill: true, separator: true)
            headerRows[key] = row
            items.append(row)
            return key
        }

        // Case header.
        text("Strata Chain-of-Custody Report", fonts.title, palette.fg, after: 4)
        text(model.caseName, fonts.subtitle, palette.accent, after: 10)
        metaRow("Examiner", model.examiner.isEmpty ? dash : model.examiner)
        metaRow("Case created", ReportFormat.display(model.createdAt))
        metaRow("Report generated", ReportFormat.display(model.generatedAt))
        metaRow("Evidence items", String(model.evidence.count))
        metaRow("Custody log entries", String(model.log.count))
        text("All timestamps are ISO-8601 / UTC. This is an append-only custody record.",
             fonts.note, palette.muted, before: 6)

        // Evidence integrity.
        text("Evidence integrity", fonts.section, palette.fg,
             before: 18, after: 8, keepWithNext: true, rule: true)
        if model.evidence.isEmpty {
            text("No evidence.", fonts.note, palette.muted)
        }
        for ev in model.evidence {
            text(ev.displayName, fonts.evidence, palette.accent,
                 before: 10, after: 3, keepWithNext: true)
            text("Source: \(ev.kindLabel) — \(ev.sourcePath)", fonts.body, palette.fg,
                 after: 2, keepWithNext: true, mono: true)

            text("ACQUISITION", fonts.label, palette.muted,
                 before: 5, after: 3, keepWithNext: true)
            if let acq = ev.acquisition, !acq.isEmpty {
                func row(_ label: String, _ value: String) {
                    if !value.isEmpty { metaRow(label, value) }
                }
                row("Examiner", acq.examiner)
                row("Tool", acq.acquisitionTool)
                row("Method", acq.acquisitionMethod)
                if let d = acq.acquiredAt { metaRow("Acquired", ReportFormat.display(d)) }
                row("Case number", acq.caseNumber)
                row("Media serial", acq.mediaSerial)
                row("Notes", acq.notes)
                metaRow("Provenance", CoCReportRenderer.provenanceLabel(acq.source))
            } else {
                text("No acquisition metadata recorded.", fonts.note, palette.muted)
            }

            text("SOURCE HASHES", fonts.label, palette.muted,
                 before: 6, after: 3, keepWithNext: true)
            if ev.hashes.isEmpty {
                text("No source hashes recorded.", fonts.note, palette.muted)
            } else {
                let widths = columns([70, -1, 75, 75])
                let key = tableHeader(["Algorithm", "Value", "Origin", "Status"], widths)
                for h in ev.hashes {
                    items.append(.row(
                        cells: [attr(h.algorithm.label, font: fonts.body, color: palette.fg),
                                attr(h.value, font: fonts.mono, color: palette.fg, charWrap: true),
                                attr(h.origin.label, font: fonts.body, color: palette.fg),
                                attr(h.status.label, font: fonts.body, color: palette.fg)],
                        widths: widths, isHeader: false, headerKey: key,
                        fill: false, separator: true))
                }
            }
        }

        // Custody log.
        text("Custody log", fonts.section, palette.fg,
             before: 18, after: 8, keepWithNext: true, rule: true)
        if model.log.isEmpty {
            text("No recorded events.", fonts.note, palette.muted)
        } else {
            let widths = columns([105, 72, 82, 70, -1])
            let key = tableHeader(["Timestamp", "Action", "Evidence", "Actor", "Detail"], widths)
            for e in model.log {
                items.append(.row(
                    cells: [attr(ReportFormat.display(e.timestamp), font: fonts.mono,
                                 color: palette.fg, charWrap: true),
                            attr(e.action, font: fonts.body, color: palette.fg),
                            attr(e.evidenceName ?? dash, font: fonts.body, color: palette.fg),
                            attr(e.actor, font: fonts.body, color: palette.fg),
                            attr(e.detail, font: fonts.body, color: palette.fg)],
                    widths: widths, isHeader: false, headerKey: key,
                    fill: false, separator: true))
            }
        }

        return items
    }

    /// Resolve a column spec: fixed widths in points, one `-1` taking the rest.
    private static func columns(_ spec: [CGFloat]) -> [CGFloat] {
        let fixed = spec.filter { $0 >= 0 }.reduce(0, +)
        return spec.map { $0 >= 0 ? $0 : max(40, contentWidth - fixed) }
    }

    // MARK: - Pagination

    private static func paginate(_ items: [Item],
                                 headerRows: [Int: Item]) -> [[Placed]] {
        var pages: [[Placed]] = []
        var page: [Placed] = []
        var y: CGFloat = 0

        func closePage() {
            if !page.isEmpty { pages.append(page) }
            page = []
            y = 0
        }

        func place(_ item: Item) {
            let h = height(of: item)
            page.append(Placed(item: item, y: y, height: h))
            y += h
        }

        var index = 0
        while index < items.count {
            let item = items[index]

            // Spacers never lead a page and never force a break.
            if case .spacer(let h) = item {
                if !page.isEmpty { y = min(y + h, contentHeight) }
                index += 1
                continue
            }

            var needed = height(of: item)

            // Keep a heading attached to the block it introduces.
            if case .text(_, keepWithNext: true, _) = item {
                var look = index + 1
                var extra: CGFloat = 0
                while look < items.count {
                    if case .spacer(let s) = items[look] { extra += s; look += 1; continue }
                    extra += height(of: items[look])
                    break
                }
                needed += extra
            }

            if y + needed > contentHeight, !page.isEmpty, needed <= contentHeight {
                closePage()
                // A table continuing onto a fresh page repeats its header row.
                if case .row(_, _, isHeader: false, let key, _, _) = item,
                   let header = headerRows[key] {
                    place(header)
                }
            }
            place(item)
            index += 1
        }
        closePage()
        return pages
    }

    private static func height(of item: Item) -> CGFloat {
        switch item {
        case .spacer(let h):
            return h
        case .text(let text, _, let rule):
            return measure(text, width: contentWidth) + (rule ? 5 : 0)
        case .row(let cells, let widths, _, _, _, _):
            let tallest = zip(cells, widths)
                .map { measure($0, width: max(4, $1 - 2 * cellPadX)) }
                .max() ?? 0
            return max(tallest, 9) + 2 * cellPadY
        }
    }

    // MARK: - Drawing

    private static func draw(_ placed: Placed, in ctx: CGContext, palette: Palette) {
        let top = pageSize.height - margin - placed.y
        let rect = CGRect(x: margin, y: top - placed.height,
                          width: contentWidth, height: placed.height)

        switch placed.item {
        case .spacer:
            break

        case .text(let text, _, let rule):
            // +2 of slack keeps rounding from clipping the last line.
            drawText(text, in: CGRect(x: rect.minX, y: rect.minY - 2,
                                      width: rect.width, height: rect.height + 2), ctx)
            if rule {
                stroke(from: CGPoint(x: rect.minX, y: rect.minY + 2),
                       to: CGPoint(x: rect.maxX, y: rect.minY + 2),
                       width: 1, color: palette.line, in: ctx)
            }

        case .row(let cells, let widths, let isHeader, _, let fill, let separator):
            if fill {
                ctx.setFillColor(palette.headerFill)
                ctx.fill(rect)
            }
            var x = rect.minX
            for (cell, width) in zip(cells, widths) {
                let cellRect = CGRect(x: x + cellPadX,
                                      y: rect.minY,
                                      width: width - 2 * cellPadX,
                                      height: rect.height - cellPadY)
                drawText(cell, in: cellRect, ctx)
                x += width
            }
            if separator {
                stroke(from: CGPoint(x: rect.minX, y: rect.minY),
                       to: CGPoint(x: rect.maxX, y: rect.minY),
                       width: isHeader ? 1.2 : 0.5, color: palette.line, in: ctx)
            }
        }
    }

    private static func drawFooter(in ctx: CGContext, page: Int, of total: Int,
                                   model: CoCReportModel, fonts: Fonts, palette: Palette) {
        let ruleY = margin - 12
        stroke(from: CGPoint(x: margin, y: ruleY),
               to: CGPoint(x: pageSize.width - margin, y: ruleY),
               width: 0.5, color: palette.line, in: ctx)

        let left = attr("Strata Chain-of-Custody Report — generated \(ReportFormat.display(model.generatedAt))",
                        font: fonts.footer, color: palette.muted)
        drawLine(left, at: CGPoint(x: margin, y: ruleY - 11), in: ctx)

        let right = attr("Page \(page) of \(total)", font: fonts.footer, color: palette.muted)
        drawLine(right, at: CGPoint(x: pageSize.width - margin, y: ruleY - 11),
                 in: ctx, rightAligned: true)
    }

    // MARK: - CoreText primitives

    private static func attr(_ string: String, font: CTFont, color: CGColor,
                             charWrap: Bool = false) -> NSAttributedString {
        var attributes: [NSAttributedString.Key: Any] = [
            NSAttributedString.Key(kCTFontAttributeName as String): font,
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): color,
        ]
        if charWrap {
            // Hashes and paths have no spaces; wrap them anywhere rather than
            // letting CoreText overflow the column.
            var mode = CTLineBreakMode.byCharWrapping
            let style = withUnsafeMutablePointer(to: &mode) { ptr -> CTParagraphStyle in
                var setting = CTParagraphStyleSetting(
                    spec: .lineBreakMode,
                    valueSize: MemoryLayout<CTLineBreakMode>.size,
                    value: ptr)
                return CTParagraphStyleCreate(&setting, 1)
            }
            attributes[NSAttributedString.Key(kCTParagraphStyleAttributeName as String)] = style
        }
        return NSAttributedString(string: string, attributes: attributes)
    }

    private static func measure(_ text: NSAttributedString, width: CGFloat) -> CGFloat {
        guard text.length > 0 else { return 0 }
        let setter = CTFramesetterCreateWithAttributedString(text)
        let size = CTFramesetterSuggestFrameSizeWithConstraints(
            setter, CFRange(location: 0, length: text.length), nil,
            CGSize(width: width, height: .greatestFiniteMagnitude), nil)
        return ceil(size.height)
    }

    private static func drawText(_ text: NSAttributedString, in rect: CGRect, _ ctx: CGContext) {
        guard text.length > 0 else { return }
        let setter = CTFramesetterCreateWithAttributedString(text)
        let frame = CTFramesetterCreateFrame(
            setter, CFRange(location: 0, length: text.length),
            CGPath(rect: rect, transform: nil), nil)
        CTFrameDraw(frame, ctx)
    }

    private static func drawLine(_ text: NSAttributedString, at point: CGPoint,
                                 in ctx: CGContext, rightAligned: Bool = false) {
        let line = CTLineCreateWithAttributedString(text)
        var x = point.x
        if rightAligned {
            x -= CGFloat(CTLineGetTypographicBounds(line, nil, nil, nil))
        }
        ctx.textPosition = CGPoint(x: x, y: point.y)
        CTLineDraw(line, ctx)
    }

    private static func stroke(from: CGPoint, to: CGPoint, width: CGFloat,
                               color: CGColor, in ctx: CGContext) {
        ctx.setStrokeColor(color)
        ctx.setLineWidth(width)
        ctx.move(to: from)
        ctx.addLine(to: to)
        ctx.strokePath()
    }
}
