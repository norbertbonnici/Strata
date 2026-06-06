import SwiftUI

/// Visual language for the Strata viewer. Originally built for the iOS
/// mockup, now shared with macOS so both platforms render the same dark
/// teal/amber palette and severity ramp.
///
/// All colors here are literal RGB triplets - no AppKit/UIKit color
/// references - so the file is trivially cross-platform. (The file path
/// still lives under `iOS/` for historical reasons; the contents are not
/// iOS-specific.)
enum Theme {
    static let bg        = Color(red: 0x0B/255, green: 0x14/255, blue: 0x1B/255)
    static let bg2       = Color(red: 0x0E/255, green: 0x1A/255, blue: 0x22/255)
    static let card      = Color(red: 0x15/255, green: 0x24/255, blue: 0x2E/255)
    static let card2     = Color(red: 0x1B/255, green: 0x2F/255, blue: 0x3D/255)
    static let hair      = Color.white.opacity(0.08)
    static let hair2     = Color.white.opacity(0.05)

    static let text      = Color(red: 0xEA/255, green: 0xF1/255, blue: 0xF5/255)
    static let text2     = Color(red: 0x94/255, green: 0xA6/255, blue: 0xB1/255)
    static let text3     = Color(red: 0x5F/255, green: 0x72/255, blue: 0x7D/255)

    static let teal      = Color(red: 0x3F/255, green: 0xB5/255, blue: 0xAD/255)
    static let teal2     = Color(red: 0x56/255, green: 0xC7/255, blue: 0xBE/255)
    static let tealDim   = Color(red: 0x3F/255, green: 0xB5/255, blue: 0xAD/255).opacity(0.16)
    static let amber     = Color(red: 0xF2/255, green: 0xA2/255, blue: 0x3D/255)
    static let amberDim  = Color(red: 0xF2/255, green: 0xA2/255, blue: 0x3D/255).opacity(0.16)

    static let crit      = Color(red: 0xFF/255, green: 0x4D/255, blue: 0x6D/255)
    static let high      = Color(red: 0xFF/255, green: 0x8A/255, blue: 0x3D/255)
    static let med       = Color(red: 0xF4/255, green: 0xB7/255, blue: 0x40/255)
    static let low       = Color(red: 0x4F/255, green: 0xB0/255, blue: 0xC9/255)
    static let info      = Color(red: 0x7D/255, green: 0x8C/255, blue: 0x97/255)

    /// Pick a dot/badge color for a Finding severity.
    static func severityColor(_ s: Severity) -> Color {
        switch s {
        case .critical: return crit
        case .high:     return high
        case .medium:   return med
        case .low:      return low
        case .info:     return info
        }
    }

    /// Color the MACB letter badge to mirror the mockup's `m-M`, `m-A` etc.
    static func macbColor(_ kind: MACBKind) -> Color {
        switch kind {
        case .modified: return Color(red: 0x7C/255, green: 0xB8/255, blue: 0xEC/255)
        case .accessed: return Color(red: 0x5B/255, green: 0xCB/255, blue: 0x9C/255)
        case .changed:  return Color(red: 0xEA/255, green: 0xA4/255, blue: 0x56/255)
        case .born:     return Color(red: 0xBB/255, green: 0xA0/255, blue: 0xEC/255)
        }
    }

    static func macbLetter(_ kind: MACBKind) -> String {
        switch kind {
        case .modified: return "M"
        case .accessed: return "A"
        case .changed:  return "C"
        case .born:     return "B"
        }
    }
}

// MARK: - Primitives

/// Large title with optional subtitle, matching the mockup's `.largetitle .sub`.
struct LargeTitle: View {
    let title: String
    var subtitle: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.system(size: 32, weight: .heavy))
                .tracking(-0.6)
                .foregroundStyle(Theme.text)
            if let subtitle {
                Text(subtitle)
                    .font(.system(size: 13.5, weight: .medium))
                    .foregroundStyle(Theme.text2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 20)
        .padding(.top, 6)
        .padding(.bottom, 12)
    }
}

/// `.sec-h` style uppercase section header.
struct SectionHeader: View {
    let label: String
    var body: some View {
        Text(label.uppercased())
            .font(.system(size: 12.5, weight: .heavy))
            .tracking(0.9)
            .foregroundStyle(Theme.text3)
            .padding(.horizontal, 22)
            .padding(.bottom, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Rounded dark card that wraps a section of stacked rows. Uses LazyVStack so
/// large row sets (e.g. a directory listing) only instantiate visible rows -
/// every Card here lives inside a ScrollView, where lazy stacking applies.
struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        LazyVStack(spacing: 0) { content }
            .background(Theme.card)
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Theme.hair, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .padding(.horizontal, 16)
    }
}

/// Single key/value row inside a Card. `mono` switches the value to a
/// monospaced typeface for hashes, paths, IDs.
struct KVRow: View {
    let key: String
    let value: String
    var mono: Bool = false
    var showDivider: Bool = true

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Text(key)
                    .font(.system(size: 14.5))
                    .foregroundStyle(Theme.text2)
                Spacer()
                Text(value)
                    .font(mono
                          ? .system(size: 12.5, design: .monospaced)
                          : .system(size: 14.5))
                    .foregroundStyle(Theme.text)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .padding(.horizontal, 15)
            .padding(.vertical, 13)
            if showDivider { Divider().background(Theme.hair2) }
        }
    }
}

/// A horizontally scrolling row of chip buttons that act like a single-select
/// segmented filter. Generic over the case type so each tab can supply its
/// own enum (MACB letter, event source, etc.).
struct ChipRow<Value: Hashable>: View {
    let options: [(Value, String)]
    @Binding var selection: Value

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 7) {
                ForEach(options, id: \.0) { (value, label) in
                    let on = value == selection
                    Button { selection = value } label: {
                        Text(label)
                            .font(.system(size: 13, weight: .semibold))
                            .padding(.horizontal, 13)
                            .padding(.vertical, 6)
                            .foregroundStyle(on
                                ? Color(red: 0x04/255, green: 0x20/255, blue: 0x1E/255)
                                : Theme.text2)
                            .background(on ? Theme.teal : Theme.card)
                            .clipShape(Capsule())
                            .overlay(Capsule().stroke(on ? Theme.teal : Theme.hair, lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 4)
        }
    }
}

/// Small colored circle used in event rows / IOC rows / finding cards.
struct SeverityDot: View {
    let color: Color
    var size: CGFloat = 9
    var body: some View {
        Circle().fill(color).frame(width: size, height: size)
    }
}

/// Compact rounded pill used for event IDs and ATT&CK techniques.
struct Pill: View {
    let text: String
    var background: Color = Theme.card2
    var foreground: Color = Theme.text
    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .heavy, design: .monospaced))
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .background(background)
            .foregroundStyle(foreground)
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

/// "DEL" badge shown next to deleted file rows.
struct DeletedBadge: View {
    var body: some View {
        Text("DEL")
            .font(.system(size: 10, weight: .heavy))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Theme.crit.opacity(0.15))
            .foregroundStyle(Theme.crit)
            .clipShape(RoundedRectangle(cornerRadius: 5))
    }
}

/// Banner shown at the top of Overview when there are critical findings.
struct CriticalBanner: View {
    let title: String
    let message: String
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle().fill(Theme.crit.opacity(0.2)).frame(width: 30, height: 30)
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.crit)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 14.5, weight: .semibold)).foregroundStyle(Theme.text)
                Text(message).font(.system(size: 12.5)).foregroundStyle(Theme.text2).lineSpacing(2)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(
            LinearGradient(
                colors: [Theme.crit.opacity(0.16), Theme.high.opacity(0.10)],
                startPoint: .topLeading, endPoint: .topTrailing))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Theme.crit.opacity(0.32), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .padding(.horizontal, 16)
        .padding(.top, 6)
    }
}

/// 2-column stat tile grid used on the Overview tab.
struct StatTiles: View {
    struct Tile: Identifiable {
        let id = UUID()
        let value: String
        let label: String
        let color: Color
    }
    let tiles: [Tile]

    var body: some View {
        LazyVGrid(columns: [GridItem(.flexible(), spacing: 10),
                            GridItem(.flexible(), spacing: 10)],
                  spacing: 10) {
            ForEach(tiles) { t in
                VStack(alignment: .leading, spacing: 3) {
                    Text(t.value)
                        .font(.system(size: 24, weight: .heavy, design: .monospaced))
                        .foregroundStyle(t.color)
                    Text(t.label)
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.text2)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.card)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Theme.hair, lineWidth: 1))
                .clipShape(RoundedRectangle(cornerRadius: 16))
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
    }
}

