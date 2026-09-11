import SwiftUI
import TCShellCore

/// Three groups, never one column of mixed semantics.
///
/// Quarantine reads as held, not rejected, and never states a turnaround
/// time. Credit is a record: no currency symbol, no fiat estimate, no
/// projection, no date, no streaks, no leaderboards.
struct HistoryView: View {
    /// The public roster snapshot, when this contributor is on the roster and
    /// has "List my handle publicly" on. `nil` -- the shipping case today --
    /// renders no Community section at all, which is exactly what the design
    /// asks for off the roster.
    ///
    /// It is an input rather than a read off `AppModel` because the daemon
    /// contract has no roster call yet: there is no `rank`, no `accept rate`
    /// and no `public since` anywhere in `Models.swift`. Wiring one would be a
    /// feature, not a design pass, so the section is built and left waiting
    /// for its data instead of being drawn over invented numbers.
    var roster: RosterSnapshot?

    @EnvironmentObject private var model: AppModel
    @State private var quarantineExpanded = false
    /// Which level of the history list is showing, resolved against the
    /// live folders on every redraw exactly as the queue does it: a folder
    /// whose records leave -- a refresh that drops them -- returns to the
    /// list rather than rendering an empty detail view.
    @State private var location: QueueLocation = .root

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: TC.Space.xl) {
                if let rollup = model.rollup {
                    groups(rollup)
                    if rollup.quarantined > 0 {
                        quarantine(rollup)
                    }
                    credit(rollup)
                    // The public surface sits below the credit card, and the
                    // seam between the two is the design: everything above is
                    // the private tool, everything inside the black frame is
                    // what other people can see.
                    if let roster {
                        CommunitySection(roster: roster)
                    }
                } else {
                    Text("Nothing yet.")
                        .font(TC.Font_.meta)
                        .foregroundStyle(.secondary)
                }

                if !model.history.isEmpty {
                    contributions
                }
            }
            .padding(.horizontal, TC.Space.xxl)
            .padding(.vertical, TC.Space.xl)
            .tcColumn()
        }
        .tcScreen()
        // The shell that hosts this view never disappears when the sidebar
        // switches sections -- see `MainWindowView.shell`, a single `Group`
        // with a `switch` inside, not per-section views -- so `refreshAll()`
        // firing from the shell's own `.onAppear` at launch never fires
        // again on a tab switch. `AppModel.refreshHistory()` is a cheap
        // daemon-side read of state it already holds, so paying for it every
        // time a contributor opens this screen is the honest way to show
        // what the daemon actually has rather than what it had at launch.
        .onAppear { model.refreshHistory() }
    }

    /// Everything contributed, grouped by folder the way the queue is.
    ///
    /// Grouped on `project_id`, never on the label: two repositories can
    /// share a basename, and one row covering both would attribute one
    /// contributor's work to the wrong project. Records that predate the
    /// daemon carrying an id fall back to their label under a synthetic key
    /// -- see `HistoryFolders` for why that is the smaller loss.
    private var folders: [QueueGroup<HistoryRecord>] {
        HistoryFolders.folders(
            model.history,
            projectID: \.projectID,
            projectLabel: \.projectLabel
        )
    }

    @ViewBuilder
    private var contributions: some View {
        let folders = self.folders
        let here = QueueNavigation.resolve(location, in: folders)
        VStack(alignment: .leading, spacing: TC.Space.m) {
            switch here {
            case .root:
                TCSectionHeader(
                    title: "Everything you've contributed",
                    trailing: "\(model.history.count)"
                )
                copyDefects
                ForEach(folders) { group in
                    historyFolderRow(group)
                }
            case .project(let id):
                if let group = folders.first(where: { $0.id == id }) {
                    historyFolderDetail(group)
                }
            }
        }
        .onChange(of: folders.map(\.id)) { _, _ in
            location = QueueNavigation.resolve(location, in: folders)
        }
    }

    /// The folder's path, when it can be resolved.
    ///
    /// History records carry an opaque id and no path, so the path comes
    /// from matching that id against the live `list_projects` rows. A group
    /// keyed by label instead of by id, and a group whose project the daemon
    /// no longer lists, have no path to show and render their label alone --
    /// which is the honest answer rather than a guessed directory.
    private func folderPath(_ group: QueueGroup<HistoryRecord>) -> String? {
        guard !group.id.hasPrefix(HistoryFolders.unresolvedPrefix) else { return nil }
        let path = model.projects.first(where: { $0.projectId == group.id })?.projectPath
        guard let path, !path.isEmpty else { return nil }
        return path
    }

    private func historyFolderRow(_ group: QueueGroup<HistoryRecord>) -> some View {
        Button {
            location = .project(group.id)
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: TC.Space.s) {
                VStack(alignment: .leading, spacing: TC.Space.xxs) {
                    Text(group.label)
                        .font(TC.Font_.cardTitle)
                        .foregroundStyle(TC.inkPrimary)
                    if let path = folderPath(group) {
                        Text(path)
                            .font(TC.Font_.meta)
                            .foregroundStyle(TC.inkSecondary)
                    }
                }
                Spacer(minLength: TC.Space.m)
                Text("^[\(group.count) contribution](inflect: true)")
                    .font(TC.Font_.ledger)
                    .monospacedDigit()
                    .foregroundStyle(TC.inkSecondary)
                QueueGlyph(glyph: .chevronRight, size: 11, color: TC.inkTertiary)
            }
            .padding(TC.Space.l)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .tcCard()
        .accessibilityLabel("\(group.label), \(group.count) contributed. Open.")
    }

    private func historyFolderDetail(_ group: QueueGroup<HistoryRecord>) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.m) {
            Button {
                location = .root
            } label: {
                HStack(spacing: TC.Space.xs) {
                    QueueGlyph(glyph: .chevronLeft, size: 11, color: TC.inkSecondary)
                    Text("All folders")
                        .font(TC.Font_.meta)
                        .foregroundStyle(TC.inkSecondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            VStack(alignment: .leading, spacing: TC.Space.xxs) {
                Text(group.label)
                    .font(TC.Font_.sectionTitle)
                    .foregroundStyle(TC.inkPrimary)
                if let path = folderPath(group) {
                    Text(path)
                        .font(TC.Font_.meta)
                        .foregroundStyle(TC.inkSecondary)
                        .textSelection(.enabled)
                }
            }

            copyDefects
            ForEach(group.entries) { record in
                HistoryRow(record: record)
            }
        }
    }

    /// Three states, three tones, three glyphs, three words. The counts are
    /// the same shape as a queue card's manifest -- uppercase label over a
    /// monospaced figure -- so the two screens read as one system.
    private func groups(_ rollup: HistoryRollup) -> some View {
        HStack(alignment: .top, spacing: TC.Space.m) {
            tally("In the commons", rollup.allTime.accepted, .clear, "checkmark.circle")
            tally("Held for privacy review", rollup.quarantined, .held, "clock")
            tally("Waiting to be scored", rollup.allTime.submitted, .neutral, "circle.dotted")
        }
    }

    /// A stat card: an 11pt glyph and an eyebrow over a 20/700 figure, on a
    /// card face with a hairline. The glyph is what keeps the three states
    /// apart without colour -- a check, a clock, and a circle that is drawn
    /// dashed because it is waiting on something that has not started.
    private func tally(_ title: String, _ count: Int, _ tone: TC.Tone, _ symbol: String) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.xs) {
            HStack(spacing: TC.Space.xs) {
                Image(systemName: symbol)
                    .imageScale(.small)
                    .foregroundStyle(tone.textColor)
                    .accessibilityHidden(true)
                TCFieldLabel(title)
            }
            Text("\(count)")
                .font(TC.Font_.metricValue)
                .monospacedDigit()
        }
        .padding(TC.Space.m)
        .frame(maxWidth: .infinity, alignment: .leading)
        .tcCard()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(count)")
    }

    /// What holds a trace, and what happens to it while it is held.
    ///
    /// An AGENT inspects these. Not a person at Trace Commons -- that phrasing
    /// shipped here and was wrong in the direction that alarms: it invites a
    /// contributor to picture a staff member with their session open. Kept as
    /// named values so `QuarantineExplanationTests` can assert on them; the
    /// warm-sounding version is exactly the kind of thing a later copy pass
    /// reintroduces.
    static let heldReviewLede = """
        An agent inspects these before they enter the commons. \
        It happens when automated checks see something that might be personal \
        or sensitive and can't decide on its own.
        """

    static let heldReviewAssurance = """
        These have not been rejected, and they have not been shared with \
        anyone but the agent that inspects them. They are sitting still.
        """

    static var heldReviewBody: String { heldReviewLede + " " + heldReviewAssurance }

    /// The distinct, contributor-meaningful explanation lines across a set of
    /// records, in first-seen order.
    ///
    /// Two rules, both learned from what this section actually rendered:
    ///
    /// 1. **Distinct.** These lines come from the server per RECORD, and this
    ///    section spans every held record at once. The server writes the same
    ///    sentence for every trace held for the same reason, so the flat list
    ///    repeated two sentences once per trace. Order is preserved so the
    ///    first reason a contributor sees is the first one that occurred.
    /// 2. **No opaque digests.** Every receipt carries `Attributed to tenant
    ///    tenant_sha256:<64 hex>`. True, and unreadable: a digest the reader
    ///    cannot act on, above the sentence that says what happened. The rule
    ///    keys on the digest rather than the sentence so a future line
    ///    carrying a hash is caught without a list to maintain.
    ///
    /// A display filter, deliberately, not a server change: the receipt is an
    /// API surface other consumers read, and tenant attribution is real
    /// information there. It is only this screen that has no use for it.
    static func contributorFacingExplanations(in records: [HistoryRecord]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for record in records {
            for line in record.explanations where !line.contains("sha256:") {
                if seen.insert(line).inserted {
                    out.append(line)
                }
            }
        }
        return out
    }

    private func quarantine(_ rollup: HistoryRollup) -> some View {
        DisclosureGroup(isExpanded: $quarantineExpanded) {
            VStack(alignment: .leading, spacing: 8) {
                Text(Self.heldReviewLede)
                Text(Self.heldReviewAssurance)
                .fontWeight(.semibold)
                // Never state a turnaround time that cannot be honoured.
                Text("Typical wait: we don't have a reliable number yet.")
                    .foregroundStyle(.secondary)

                // Rendered verbatim: the server's own prose beats a status
                // word every time. But this is a SECTION over every held
                // trace, not one card, so the raw flatMap printed the same
                // two server sentences once per trace -- 210 traces gave 420
                // lines, of which two were distinct. Distinct lines only, and
                // no opaque digests: see `contributorFacingExplanations`.
                let explanations = Self.contributorFacingExplanations(
                    in: model.history.filter { $0.status == "quarantined" }
                )
                if !explanations.isEmpty {
                    ForEach(explanations, id: \.self) { text in
                        Text(text).font(.callout).foregroundStyle(.secondary)
                    }
                }

                // No bulk action, and the reason is stated rather than left
                // as an absence -- see WithdrawalCopy.noBulkAction.
                Text(WithdrawalCopy.noBulkAction)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .font(.callout)
            .frame(maxWidth: 560, alignment: .leading)
            .padding(.top, 8)
        } label: {
            // Held is a state, not a colour. It says "held", it carries a
            // clock, and it is tinted -- in that order of importance.
            HStack(spacing: TC.Space.s) {
                Image(systemName: TC.Tone.held.symbol)
                    .foregroundStyle(TC.Tone.held.textColor)
                    .accessibilityHidden(true)
                Text("Held for privacy review — ^[\(rollup.quarantined) trace](inflect: true)")
                    .font(TC.Font_.cardTitle)
            }
        }
    }

    /// The withdrawal copy's own assertions, rendered where a contributor
    /// and a developer both see them. There is no Swift test target here, so
    /// the alternative was assertions nobody runs; a screen that admits its
    /// withdrawal wording has stopped being trustworthy is better than a
    /// screen that quietly keeps showing it. Empty in every healthy build.
    @ViewBuilder
    private var copyDefects: some View {
        let problems = WithdrawalCopyCheck.failures()
        if !problems.isEmpty {
            VStack(alignment: .leading, spacing: TC.Space.xs) {
                Text("Do not trust the withdrawal wording on this screen.")
                    .font(TC.Font_.cardTitle)
                ForEach(problems, id: \.self) { problem in
                    Text(problem).font(TC.Font_.footnote)
                }
            }
            .foregroundStyle(TC.coralText)
            .padding(TC.Space.m)
            .frame(maxWidth: .infinity, alignment: .leading)
            .tcCard()
        }
    }

    private func credit(_ rollup: HistoryRollup) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.m) {
            TCSectionHeader(title: "Credit")
            CreditRecordView(
                creditFinal: rollup.creditFinal,
                creditPending: rollup.creditPending,
                lastRefreshedAt: rollup.lastRefreshedAt
            )
        }
    }
}

/// The three tier confirmations side by side, on fabricated records, for the
/// screenshot hook.
///
/// It exists because the demo state directory has no enrolment and therefore
/// no history at all, so a capture of the real History screen shows an empty
/// list and proves nothing about the copy -- which is the entire substance of
/// this feature. Everything here is invented; nothing reads the queue, the
/// history cache, or the daemon.
///
/// Built from plain `Text` and `Button` on purpose: `ImageRenderer` will not
/// rasterize NSView-backed controls (`Toggle`, `TextField`, `Menu`, segmented
/// `Picker`), which come out as yellow placeholders in a capture while being
/// perfectly fine in the running app.
struct WithdrawalConfirmationCapture: View {
    private static func record(_ label: String, _ status: String) -> HistoryRecord {
        HistoryRecord(
            submissionID: "capture-\(status)",
            submittedAt: Date(timeIntervalSince1970: 1_770_000_000),
            projectID: "project_capture_fixture",
            projectLabel: label,
            source: "claude-code",
            status: status,
            consentScopes: ["debugging_evaluation"],
            creditPointsPending: 0,
            creditPointsFinal: nil,
            explanations: [],
            lastRefreshedAt: nil
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: TC.Space.m) {
            TCSectionHeader(title: "Withdrawing, per tier")
            HistoryRow(
                record: Self.record("northwind-billing", "quarantined"),
                initiallyConfirming: true
            )
            HistoryRow(
                record: Self.record("dotfiles", "accepted"),
                initiallyConfirming: true
            )
            HistoryRow(record: Self.record("dotfiles", "withdrawn"))
        }
        .padding(TC.Space.xxl)
        .tcColumn()
        .tcScreen()
    }
}

struct HistoryRow: View {
    let record: HistoryRecord
    /// Screenshot hook only: opens the row with its confirmation already
    /// showing, since `ImageRenderer` never delivers a click.
    var initiallyConfirming: Bool = false

    @EnvironmentObject private var model: AppModel
    @State private var confirming = false

    var body: some View {
        VStack(alignment: .leading, spacing: TC.Space.s) {
            HStack(spacing: TC.Space.s) {
                Text(record.projectLabel).font(TC.Font_.body.weight(.semibold))
                Text(Format.when(record.submittedAt))
                    .font(TC.Font_.footnote)
                    .foregroundStyle(.tertiary)
                Spacer(minLength: TC.Space.m)
                TCTag(text: statusSentence, tone: statusTone, symbol: statusSymbol)
            }
            ForEach(Array(record.explanations.enumerated()), id: \.offset) { _, text in
                Text(text)
                    .font(TC.Font_.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if record.status == "quarantined" && record.explanations.isEmpty {
                // Only when the server said nothing of its own. Its prose is
                // about this trace; this sentence is about the state, and a
                // held row that explains itself twice is a row nobody reads.
                Text(HistoryCopy.heldExplanation)
                    .font(TC.Font_.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: TC.Measure.prose, alignment: .leading)
            }

            if let result = model.withdrawals[record.submissionID] {
                outcome(result)
            } else if confirming || initiallyConfirming {
                confirmation
            } else if isWithdrawable {
                // Plain, not filled. The filled action in this app is the
                // one a person is being invited to take; this one only
                // opens a question.
                Button("Withdraw") { confirming = true }
                    .buttonStyle(SmallSecondaryButtonStyle())
            }
        }
        .padding(.vertical, TC.Space.m)
        .padding(.horizontal, TC.Space.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .tcCard()
    }

    /// Whether there is anything to withdraw. A trace already withdrawn is
    /// not offered again -- the daemon would treat it as a no-op, and an
    /// enabled button on it would suggest the first one did not take.
    private var isWithdrawable: Bool {
        record.status != "withdrawn"
    }

    /// The confirmation, shown BEFORE anything is asked of the server and
    /// worded for this trace's stage. See `WithdrawalCopy` for why the
    /// wording is keyed on the local status and why the ambiguous case
    /// states the worse outcome.
    private var confirmation: some View {
        let copy = WithdrawalCopy.confirmation(for: .init(status: record.status))
        let inFlight = model.withdrawing.contains(record.submissionID)
        return VStack(alignment: .leading, spacing: TC.Space.s) {
            Text(copy.question).font(TC.Font_.cardTitle)
            if let ambiguity = copy.ambiguity {
                Text(ambiguity)
                    .font(TC.Font_.footnote)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(Array(copy.bodies.enumerated()), id: \.offset) { index, body in
                // The body carrying the cannot-be-recalled clause is the one
                // that must not be skimmed past, so it takes the coral text
                // token and a glyph. Coral is this app's "refused / cannot
                // proceed" role; it is on type here, never as a fill, and
                // `coralText` is the darkened light-mode twin measured to
                // clear 4.5:1 on a card face.
                let gravest = index == copy.gravest
                HStack(alignment: .firstTextBaseline, spacing: TC.Space.xs) {
                    Image(systemName: gravest ? "exclamationmark.triangle" : "info.circle")
                        .imageScale(.small)
                        .accessibilityHidden(true)
                    Text(body).fixedSize(horizontal: false, vertical: true)
                }
                .font(TC.Font_.footnote)
                .foregroundStyle(gravest ? AnyShapeStyle(TC.coralText) : AnyShapeStyle(.primary))
            }
            Text(copy.credit)
                .font(TC.Font_.footnote)
                .foregroundStyle(.secondary)
            HStack(spacing: TC.Space.s) {
                // Escape backs out. Nothing binds Return: withdrawal is
                // irreversible, and this app binds Return to nothing
                // irreversible anywhere.
                Button("Keep it") { confirming = false }
                    .keyboardShortcut(.cancelAction)
                Button(inFlight ? "Withdrawing..." : copy.confirmLabel) {
                    model.withdraw(record)
                }
                .tcPrimaryAction()
                .disabled(inFlight)
            }
            .font(TC.Font_.footnote)
        }
        .frame(maxWidth: TC.Measure.prose, alignment: .leading)
        .padding(TC.Space.m)
        .background(TC.surfaceInset, in: RoundedRectangle(cornerRadius: TC.Radius.inset))
    }

    /// What actually happened, on the row it happened to.
    @ViewBuilder
    private func outcome(_ result: AppModel.WithdrawalResult) -> some View {
        let (text, tone): (String, TC.Tone) = {
            switch result {
            case .withdrawn(let reach, let note):
                return ([WithdrawalCopy.resultSentence(reach), note].compactMap { $0 }.joined(separator: "\n"), .refused)
            case .noAccountSession:
                return (WithdrawalCopy.accountSessionRequired, .attention)
            case .failed(let label):
                return (WithdrawalCopy.failureSentence(label: label), .attention)
            }
        }()
        HStack(alignment: .firstTextBaseline, spacing: TC.Space.xs) {
            Image(systemName: tone.symbol)
                .imageScale(.small)
                .accessibilityHidden(true)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
        .font(TC.Font_.footnote)
        .foregroundStyle(tone.textColor)
        .frame(maxWidth: TC.Measure.prose, alignment: .leading)
    }

    private var statusSentence: String {
        switch record.status {
        case "accepted": return "In the commons"
        case "quarantined": return "Held for privacy review"
        case "submitted": return "Waiting to be scored"
        // Withdrawn is its own state, not the "something else happened"
        // bucket: a withdrawn trace stays on this list, reading as
        // withdrawn, rather than vanishing as though it had never been sent.
        case "withdrawn": return "Withdrawn by you"
        default: return "Not in the commons"
        }
    }

    private var statusTone: TC.Tone {
        switch record.status {
        case "accepted": return .clear
        case "quarantined": return .held
        case "submitted": return .neutral
        default: return .refused
        }
    }

    /// Overrides where the tone's default glyph is not the one the design
    /// draws. A trace waiting to be scored carries a DASHED circle -- the
    /// state is "nothing has happened to this yet", and a solid dot reads as
    /// a state of its own. A withdrawn trace carries the undo arrow, because
    /// the tone's cross would read as refused-by-us rather than taken back
    /// by the person whose trace it is.
    private var statusSymbol: String? {
        switch record.status {
        case "submitted": return "circle.dotted"
        case "withdrawn": return "arrow.uturn.backward"
        default: return nil
        }
    }
}

// MARK: - Copy

/// History's own sentences. Withdrawal's live in `WithdrawalCopy`; these are
/// the ones about a state rather than an act.
enum HistoryCopy {
    /// What "held for privacy review" means, on the row it applies to. Held,
    /// never rejected, and with no turnaround time stated -- there is no
    /// number this app could honour.
    static let heldExplanation =
        "Automated checks saw something that might be personal and couldn't decide on "
        + "their own. It has not been rejected, and it has not been shared with anyone "
        + "but the reviewer."
}

// MARK: - Small secondary action

/// The small outlined button the design gives "Withdraw": 11pt on a card
/// face, hairline bordered, sized to the row rather than to the screen.
///
/// It is a style rather than a bare `Button` because the point of the
/// treatment is that this action is NOT the filled one. `TCPrimaryButtonStyle`
/// is reserved for the action a person is being invited to take; this one only
/// opens a question, so it is drawn quiet and small and never fills.
private struct SmallSecondaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(TC.Font_.meta)
            .foregroundStyle(TC.inkPrimary)
            .padding(.horizontal, TC.Space.sm)
            .padding(.vertical, TC.Space.tiny)
            .background(TC.surface, in: RoundedRectangle(cornerRadius: TC.Radius.control))
            .overlay {
                RoundedRectangle(cornerRadius: TC.Radius.control)
                    .strokeBorder(TC.line, lineWidth: TC.Border.hairline)
            }
            .opacity(isEnabled ? (configuration.isPressed ? 0.7 : 1) : 0.45)
            .contentShape(Rectangle())
    }
}

// MARK: - Community

/// The public roster snapshot, as History renders it.
///
/// Every figure is optional and every optional omits its own cell. That is
/// not defensiveness: the panel is the exact boundary of what is public about
/// a person, and a placeholder inside it -- a dash, a zero, "--" -- would be a
/// claim about their standing that this app did not receive.
struct RosterSnapshot: Equatable {
    /// Position on the roster.
    var rank: Int?
    /// The same recorded credit the private card above shows, restated in the
    /// public panel's own terms.
    var noveltyCredit: Double?
    /// Accepted within `windowLabel`.
    var acceptedInWindow: Int?
    /// 0...1. Rendered as a whole percent.
    var acceptRate: Double?
    /// The rolling window the two figures above are measured over, in the
    /// server's own words ("7d").
    var windowLabel: String?
    /// When this contributor joined the public roster.
    var publicSince: Date?
    /// When the snapshot was taken. Its age is stated because a public figure
    /// that is quietly stale is worse than one that says how old it is.
    var snapshotTakenAt: Date?
    /// The public web profile. Omitted from the header when absent rather
    /// than rendered as a dead link.
    var profileURL: URL?
}

/// History's Community section, drawn in the community brand rather than in
/// this app's.
///
/// The foreignness is the feature. Everything else in this window is the
/// private tool -- warm ground, hairlines, SF, rounded corners. This panel is
/// 2px black frames, Helvetica, uppercase display type at landing scale, and
/// no corner radius anywhere inside it, because the black frame is the exact
/// boundary of what becomes public. A person scrolling History should be able
/// to see where their private record stops without reading a word.
private struct CommunitySection: View {
    let roster: RosterSnapshot

    var body: some View {
        VStack(alignment: .leading, spacing: TC.Space.md) {
            communityBrandPanel {
                header
                metricStrip
                metaRow
                withheldNotice
            }

            // Outside the frame, and therefore in the native voice again:
            // this sentence is about a setting in this app, not about the
            // public surface.
            Text(
                "Shown only while \u{201C}List my handle publicly\u{201D} is on. Turn it off in "
                + "Settings and this section disappears with it."
            )
            .tcType(TC.Font_.captionText)
            .foregroundStyle(TC.inkSecondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: TC.Measure.prose, alignment: .leading)
        }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("Community")
                .font(CommunityBrand.Font_.displayPanel)
                .textCase(.uppercase)
                .tracking(CommunityBrand.Font_.displayPanelTracking)
                .foregroundStyle(CommunityBrand.ink)
            Spacer(minLength: TC.Space.m)
            if let profileURL = roster.profileURL {
                Link(destination: profileURL) {
                    Text("View public profile \u{2197}")
                        .font(CommunityBrand.Font_.labelMono)
                        .textCase(.uppercase)
                        .underline()
                        .foregroundStyle(CommunityBrand.ink)
                }
                .buttonStyle(.plain)
            }
        }
    }

    /// One box divided into equal cells by 1px rules. Cells the snapshot did
    /// not carry are not drawn at all, so the strip stays a row of facts.
    @ViewBuilder
    private var metricStrip: some View {
        let cells: [(String, String)] = [
            roster.rank.map { ("Rank", "#" + Self.figure(Double($0))) },
            roster.noveltyCredit.map { ("Novelty credit", Self.figure($0)) },
            roster.acceptedInWindow.map { count in
                (roster.windowLabel.map { "Accepted \u{00B7} \($0)" } ?? "Accepted",
                 Self.figure(Double(count)))
            },
            roster.acceptRate.map { ("Accept rate", "\(Int(($0 * 100).rounded()))%") },
        ].compactMap { $0 }

        if !cells.isEmpty {
            HStack(spacing: 0) {
                ForEach(Array(cells.enumerated()), id: \.offset) { index, cell in
                    VStack(alignment: .leading, spacing: TC.Space.xs) {
                        Text(cell.0)
                            .font(CommunityBrand.Font_.labelMono)
                            .textCase(.uppercase)
                            .tracking(CommunityBrand.Font_.monoTracking)
                            .foregroundStyle(CommunityBrand.muted)
                        Text(cell.1)
                            .font(CommunityBrand.Font_.figure)
                            .monospacedDigit()
                            .tracking(CommunityBrand.Font_.figureTracking)
                            .foregroundStyle(CommunityBrand.ink)
                    }
                    .padding(.vertical, TC.Space.m)
                    .padding(.horizontal, TC.Space.md)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .overlay(alignment: .trailing) {
                        if index < cells.count - 1 {
                            Rectangle()
                                .fill(CommunityBrand.ink)
                                .frame(width: CommunityBrand.Metric.rule)
                        }
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(cell.0): \(cell.1)")
                }
            }
            .overlay {
                Rectangle().strokeBorder(
                    CommunityBrand.ink,
                    lineWidth: CommunityBrand.Metric.frame
                )
            }
        }
    }

    private var metaRow: some View {
        let items: [String] = [
            roster.windowLabel.map { "Window \($0)" },
            roster.publicSince.map { "Public since " + Self.day($0) },
            roster.snapshotTakenAt.map { "Snapshot " + Format.when($0) },
        ].compactMap { $0 }

        return ViewThatFits(in: .horizontal) {
            HStack(spacing: TC.Space.lg) { metaLabels(items) }
            VStack(alignment: .leading, spacing: TC.Space.xs) { metaLabels(items) }
        }
    }

    @ViewBuilder
    private func metaLabels(_ items: [String]) -> some View {
        ForEach(items, id: \.self) { item in
            Text(item)
                .font(CommunityBrand.Font_.labelMono)
                .textCase(.uppercase)
                .tracking(CommunityBrand.Font_.monoTracking)
                .foregroundStyle(CommunityBrand.muted)
        }
    }

    /// Withheld analytics are stated in words. An empty chart would imply the
    /// numbers exist and are merely unflattering; the truth is that the server
    /// will not publish aggregates without a noise mechanism it does not have.
    private var withheldNotice: some View {
        Text(
            "Corpus analytics are withheld. The server publishes the roster on consent, "
            + "but will not publish aggregates without an approved noise mechanism \u{2014} so "
            + "nothing is charted here either."
        )
        .font(CommunityBrand.Font_.body)
        .lineSpacing(CommunityBrand.Font_.bodyLineSpacing)
        .foregroundStyle(CommunityBrand.ink)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, TC.Space.m)
        .padding(.horizontal, TC.Space.md)
        .background(CommunityBrand.tint)
        .overlay {
            Rectangle().strokeBorder(
                CommunityBrand.ink,
                lineWidth: CommunityBrand.Metric.frame
            )
        }
    }

    /// Grouped, never abbreviated, and never carrying a currency symbol:
    /// credit is a record, and a `$` in front of it would be a claim this
    /// product does not make.
    private static func figure(_ value: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.maximumFractionDigits = 0
        return formatter.string(from: NSNumber(value: value)) ?? "\(Int(value))"
    }

    private static func day(_ date: Date) -> String {
        date.formatted(.dateTime.month(.abbreviated).day().year())
    }
}
