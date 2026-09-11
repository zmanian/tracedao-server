import AppKit
import SwiftUI
import TCBridge
import TCShellCore

/// "Look inside": the one surface in the product that deliberately shows
/// trace content, because consent to send something you cannot see is not
/// consent.
///
/// Four tabs, in the spec's order. **Search is first and focused** on
/// purpose: "does this mention my client's name?" is a question a
/// contributor can answer in five seconds. Judging redaction quality by eye
/// is not, and this interface never asks them to.
///
/// **One sheet, one session, one decision.** Both decisions close it and put
/// the contributor back on the queue. It used to load the next waiting
/// session into itself with `Contribute` under the same pixels, which made a
/// second click -- or a second Return, since the button was the default
/// action -- send a transcript nobody had looked at, with the recovery bar
/// stranded behind the sheet where it could not be seen.
///
/// `Contribute` waits only on a loaded preview (see `TCShellCore.ReadGate`)
/// and is bound to no keyboard shortcut at all.
///
/// The layout follows `design-import/DESIGN-SPEC.md` §5.2 (`1b` preview
/// sheet) and §5.10 (`4a` transcript renderer), which are the same shell:
/// header bar, tab strip, body, footer bar, with the header's second field
/// and the body swapping when the transcript tab is active.
struct PreviewSheet: View {
    /// Content already loaded elsewhere, so the sheet can be rendered
    /// without running its `task`. Used only by the screenshot hook, which
    /// has to rasterize the real view (`ImageRenderer` never runs `task` or
    /// `onAppear`) rather than photograph a window.
    struct Preloaded {
        let summary: PreviewSummary
        let transcript: String
        let needle: String
        let offsets: [Int]
    }

    let entry: QueueEntry
    let preloaded: Preloaded?

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var witnessSupported = false
    @State private var confirmingWitness = false
    @State private var witnessRequested = false
    @State private var witnessWorking = false
    @State private var preview: TCPreview?
    @State private var summary: PreviewSummary?
    @State private var transcriptText: String
    /// The transcript cut into chunks, built once when the body arrives.
    ///
    /// One document serves both tabs that need to walk the body: the
    /// transcript tab pages through its chunks, and the search tab cuts its
    /// context snippets out of its bytes. The search tab used to build
    /// `Array(transcript.utf8)` inside a computed property -- a full copy of
    /// the body per keystroke, 17.5 MB at a time on a real session.
    @State private var document: TranscriptDocument?
    @State private var failure: String?
    /// The daemon's sentence for a review it refused.
    ///
    /// Separate from `failure`, which also holds messages from the local
    /// preview build -- including raw error text. Only a refusal the daemon
    /// classified lands here, so the notice below can prefer it without
    /// risking an internal string reaching a screen.
    @State private var witnessRefusal: String?
    @State private var loading: Bool

    /// The contributor's answer to `VerdictCopy.question`, or `nil` for the
    /// answer they did not give.
    ///
    /// `nil` is the starting state and a perfectly good ending one: it never
    /// gates `Contribute`, and it is sent as an ABSENT `outcome`, not an
    /// empty one. One sheet is one session's decision, and the sheet is
    /// rebuilt per entry, so no verdict can carry into the next.
    @State private var verdict: ContributorVerdict?

    /// What the contributor wrote in the correction box.
    ///
    /// Shown only under `.partly` and `.failed` -- you cannot correct a run
    /// you have just called successful, and that gate is a guard as much as
    /// it is semantics: it halves the surface for correction-shaped credit
    /// farming and puts the field only where a correction means something.
    ///
    /// Optional throughout, and it never gates `Contribute`. Emptied when
    /// the answer moves off those two, because text left in a hidden box
    /// would ride along on an approval without ever being on screen again.
    @State private var correction: String = ""

    /// Set when the daemon refused this submission because the correction
    /// contains something credential-shaped. The sheet stays open with the
    /// text still in the box: the next thing the contributor has to do is
    /// edit it.
    @State private var correctionRefused = false

    // MARK: - The read gate
    //
    // There is no longer a read gate. `Contribute` used to wait on the
    // transcript tab having been on screen AND an acknowledgement checkbox
    // ticked by hand; both are gone, and `TCShellCore.ReadGate` records why
    // and holds the sentence that took their place. What survives here is
    // the one condition that was never friction: a preview has to have
    // loaded, because that is what an approval binds to.

    /// Search first, always: it is the question a contributor can actually
    /// answer in five seconds.
    @State private var tab: Tab = .search

    enum Tab: String, CaseIterable, Identifiable {
        case search, whatsInIt, transcript, permissions
        var id: String { rawValue }
        var title: String {
            switch self {
            case .search: return "Search"
            case .whatsInIt: return "What's in it"
            case .transcript: return "Exactly what would be sent"
            case .permissions: return "Permissions"
            }
        }

        var symbol: String {
            switch self {
            case .search: return "magnifyingglass"
            case .whatsInIt: return "list.bullet.rectangle"
            case .transcript: return "doc.plaintext"
            case .permissions: return "checklist"
            }
        }
    }

    init(entry: QueueEntry, preloaded: Preloaded? = nil) {
        self.entry = entry
        self.preloaded = preloaded
        _summary = State(initialValue: preloaded?.summary)
        _transcriptText = State(initialValue: preloaded?.transcript ?? "")
        _document = State(initialValue: preloaded.map { TranscriptDocument($0.transcript) })
        _loading = State(initialValue: preloaded == nil)
    }

    /// Bumped by Command-F. `SearchTab` watches it and takes focus, so the
    /// shortcut works from any tab and from anywhere on the search tab.
    @State private var searchFocusRequest = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            SheetHairline()
            content
            SheetHairline()
            footer
        }
        // The spec's canvas is the floor, not the fixed size: the transcript
        // and search tabs can use the additional reading space. Ideal
        // keeps the first presentation at
        // the spec measure and the screenshot hook renders at exactly it.
        .frame(
            minWidth: SheetMetric.width, idealWidth: SheetMetric.width, maxWidth: .infinity,
            minHeight: SheetMetric.height, idealHeight: SheetMetric.height, maxHeight: .infinity
        )
        .background {
            // A shortcut needs a control to hang from. This one is never
            // seen and never focused; it exists so Command-F does what it
            // does in every other macOS window: go to the search field.
            Button("") {
                tab = .search
                searchFocusRequest += 1
            }
            .keyboardShortcut("f", modifiers: .command)
            .buttonStyle(.plain)
            .opacity(0)
            .frame(width: 0, height: 0)
            .accessibilityHidden(true)
            .focusable(false)
        }
        .tcScreen()
        .task(id: entry.entryID) {
            guard preloaded == nil else { return }
            witnessSupported = await model.supportsWitnessReview()
            await load()
        }
        .onDisappear { closePreview() }
        .sheet(isPresented: $confirmingWitness) {
            if let copy = model.witnessCopy?.review {
                WitnessReviewConsent(copy: copy) { Task { await prepareWitness() } }
            }
        }
        // The credential refusal, as its own alert rather than a line in
        // the submit toast: it is the one submit failure the contributor
        // caused and the only one they can fix, and it asks them to do two
        // things -- edit the text, and rotate what they typed. Neither
        // string is derived from the response, so no correction text and no
        // detected value can reach the screen a second time.
        .alert(
            CorrectionCopy.credentialHeadline,
            isPresented: $correctionRefused
        ) {
            Button("Close", role: .cancel) {}
        } message: {
            Text(CorrectionCopy.credentialBody)
        }
    }

    // MARK: - Chrome

    /// The same identity line and the same labelled figures as a queue card,
    /// in the same order. Recognising the card you just clicked is one of
    /// the quieter things that makes a preview trustworthy.
    ///
    /// The second field is not fixed: §5.10 replaces the "nothing sent yet"
    /// lock with what scrubbing actually found while the transcript is on
    /// screen, because that is the number a person reads the body against.
    private var header: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            HStack(alignment: .firstTextBaseline, spacing: TC.Space.s) {
                Text(entry.projectLabel)
                    .font(TC.Font_.cardTitle)
                    .foregroundStyle(TC.inkPrimary)
                Text(entry.agentName)
                    .font(TC.Font_.caption)
                    .foregroundStyle(TC.inkSecondary)
                Spacer(minLength: TC.Space.m)
                Text(Format.when(entry.discoveredAt))
                    .font(TC.Font_.caption)
                    .foregroundStyle(TC.inkTertiary)
            }
            HStack(alignment: .firstTextBaseline, spacing: TC.Space.xxl) {
                if let summary {
                    VStack(alignment: .leading, spacing: TC.Space.micro) {
                        TCFieldLabel("Would send")
                        HStack(alignment: .firstTextBaseline, spacing: TC.Space.xs) {
                            Text(Format.bytes(summary.wouldSendBytes))
                                .font(TC.Font_.ledger)
                                .monospacedDigit()
                                .foregroundStyle(TC.inkPrimary)
                            if tab == .transcript {
                                Text("(the session file on disk is \(Format.bytes(summary.rawSessionBytes)))")
                                    .font(TC.Font_.caption)
                                    .foregroundStyle(TC.inkSecondary)
                            }
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
                if tab == .transcript, let summary {
                    VStack(alignment: .leading, spacing: TC.Space.micro) {
                        TCFieldLabel("Scrubbing found")
                        Text(Self.scrubbingFound(summary))
                            .font(TC.Font_.ledger)
                            .foregroundStyle(
                                summary.redactions.isEmpty
                                    ? TC.Tone.attention.textColor
                                    : TC.inkPrimary
                            )
                    }
                    .accessibilityElement(children: .combine)
                } else {
                    VStack(alignment: .leading, spacing: TC.Space.micro) {
                        TCFieldLabel("Status")
                        TCTag(text: "nothing sent yet", tone: .clear, symbol: "lock")
                    }
                    .accessibilityElement(children: .combine)
                }
                Spacer(minLength: 0)
            }
            Text("Nothing has been sent. This is what would be.")
                .font(TC.Font_.caption)
                .foregroundStyle(TC.inkSecondary)
        }
        .padding(.horizontal, TC.Space.lg)
        .padding(.vertical, TC.Space.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(TC.surface)
    }

    /// "12 secrets · 4 file paths · 2 email addresses" -- category labels and
    /// counts, in the daemon's own words, largest first. The contract
    /// guarantees this map never carries matched text.
    private static func scrubbingFound(_ summary: PreviewSummary) -> String {
        // Removals only. `redactions` also carries `residual_secret_at:*`,
        // which counts a secret that was DETECTED AND LEFT IN, and this line
        // sits under a heading that says the opposite. See
        // `RedactionLabels`; the survivor is stated separately, in the
        // attention tone, rather than dropped.
        let removals = RedactionLabels.removals(summary.redactions)
        guard !removals.isEmpty else { return "nothing matched" }
        return removals
            .sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
            .map { "\($0.value) \($0.key.replacingOccurrences(of: "_", with: " "))" }
            .joined(separator: " · ")
    }

    @ViewBuilder
    private var content: some View {
        if witnessWorking, let copy = model.witnessCopy?.review {
            CenteredNotice(title: copy.heading, detail: copy.working)
        } else if loading {
            CenteredNotice(
                title: "Scrubbing it locally…",
                detail: "Reading the session and running the redaction pass."
            )
        } else if let failure {
            VStack(spacing: TC.Space.md) {
                // A refusal the daemon classified wins; otherwise the one
                // fixed sentence, which is also what a failure that is not a
                // refusal gets -- `failure` can hold raw local error text and
                // must not reach a screen on this path.
                CenteredNotice(
                    title: "This one can't be shown.",
                    detail: witnessRequested
                        ? (witnessRefusal ?? model.witnessCopy?.review?.failed ?? failure)
                        : failure
                )
                if witnessSupported, model.witnessStateCode == 1, let copy = model.witnessCopy?.review {
                    Text(copy.disclosure).font(TC.Font_.caption)
                    Button(copy.action) { confirmingWitness = true }
                }
            }.padding(TC.Space.l)
        } else if let summary {
            // A segmented control rather than a TabView: inside a sheet this
            // is the standard macOS treatment, and Search has to be able to
            // start selected and focused.
            //
            // It is built from Buttons rather than `Picker(.segmented)`
            // because each segment needs to carry a glyph AND a count -- the
            // number of things scrubbing removed sits on "What's in it", so
            // a person can see there is something to look at before they
            // click the tab. A stock segmented picker takes labels only.
            VStack(alignment: .leading, spacing: TC.Space.m) {
                tabBar(summary)

                switch tab {
                case .search:
                    SearchTab(
                        document: document,
                        preview: preview,
                        searchOriginal: { needle in
                            model.searchOriginal(entryID: entry.entryID, needle: needle)
                        },
                        initialNeedle: preloaded?.needle ?? "",
                        initialOffsets: preloaded?.offsets,
                        focusRequest: searchFocusRequest
                    )
                case .whatsInIt:
                    WhatsInItTab(entry: entry, summary: summary)
                case .transcript:
                    // Fail closed rather than cutting a fresh document on
                    // every layout pass. Unreachable in practice -- the
                    // document is built in the same step that decodes the
                    // summary, and this branch only renders once the
                    // summary exists.
                    if let document {
                        TranscriptTab(document: document)
                    } else {
                        CenteredNotice(
                            title: "The transcript isn't ready.",
                            detail: """
                            Nothing has been sent, and nothing will be until it can be \
                            shown to you.
                            """
                        )
                    }
                case .permissions:
                    PermissionsTab(summary: summary, options: model.consentScopes)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, TC.Space.lg)
            .padding(.vertical, TC.Space.md)
        }
    }

    /// The four tabs, in the spec's order, each a plain button. The one that
    /// has something to report says so on its face.
    private func tabBar(_ summary: PreviewSummary) -> some View {
        HStack(spacing: TC.Space.xxs) {
            ForEach(Tab.allCases) { item in
                Button {
                    tab = item
                } label: {
                    HStack(spacing: TC.Space.xxs) {
                        Image(systemName: item.symbol)
                            .imageScale(.small)
                        Text(item.title)
                            .font(TC.Font_.caption.weight(tab == item ? .bold : .regular))
                        if let note = badge(for: item, summary: summary) {
                            Text(note)
                                .font(TC.Font_.monoBadge)
                        }
                    }
                    .foregroundStyle(tab == item ? TC.inkPrimary : TC.inkSecondary)
                    .padding(.horizontal, TC.Space.m)
                    .padding(.vertical, TC.Space.control)
                    .background {
                        RoundedRectangle(cornerRadius: TC.Radius.control)
                            .fill(tab == item ? TC.surface : Color.clear)
                    }
                    .overlay {
                        RoundedRectangle(cornerRadius: TC.Radius.control)
                            .strokeBorder(
                                tab == item
                                    ? TC.green.opacity(TC.Border.activeTabAlpha)
                                    : Color.clear,
                                lineWidth: TC.Border.hairline
                            )
                    }
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(tab == item ? [.isSelected, .isButton] : .isButton)
            }
            Spacer(minLength: 0)
        }
        .padding(TC.Space.xxs)
        .background(TC.surfaceInset, in: RoundedRectangle(cornerRadius: TC.Radius.card))
    }

    private func badge(for item: Tab, summary: PreviewSummary) -> String? {
        switch item {
        case .whatsInIt:
            let removed = summary.redactions.values.reduce(0, +)
            return removed == 0 ? nil : "\(removed)"
        case .permissions:
            return "\(summary.consentScopes.count)"
        default:
            return nil
        }
    }

    /// The one irreversible click in the product, and the one place the
    /// scrubbing caveat is repeated verbatim on purpose -- see
    /// `ScrubbingCaveat`.
    private var footer: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            // §5.10 drops this line from the transcript tab's footer. It is
            // kept on every tab here: it is the sentence everything else on
            // this sheet is qualified by, and the tab a person is standing
            // on when they reach for Contribute is not a reason to stop
            // saying it.
            ScrubbingCaveatAtCommit()
            admissibility
            gateStatement
            if model.witnessStateCode == 1 || witnessRequested || witnessWorking, let copy = model.witnessCopy?.review {
                Text(copy.immutable).font(TC.Font_.meta).foregroundStyle(TC.inkSecondary)
            }
            verdictQuestion.disabled(model.witnessStateCode == 1 || witnessRequested || witnessWorking)
            if correctionIsOffered {
                correctionField.disabled(model.witnessStateCode == 1 || witnessRequested || witnessWorking)
            }
            // Drawn on every preview, in the place GTK has always drawn it,
            // rather than only where one failed. It arms this session's NEXT
            // call -- "continue the agent task and return here to review" --
            // so it is something a contributor comes here to do, not a
            // remedy for the sheet in front of them. Reaching it used to
            // require a witness review that failed first.
            //
            // Still gated on the enrolment, and gated nowhere else: an
            // invited contributor has no evidence-bearing path, so the
            // control could only refuse them and is absent instead.
            if model.daemonSettings?.admissionEvidenceOffered == true {
                AdmissionPreparationView(entryID: entry.entryID)
            }
            HStack(spacing: TC.Space.s) {
                // Outlined like "Close", never filled: it must not read as a
                // second way to approve.
                Button("Not this one") {
                    model.dismiss(entry)
                    dismiss()
                }
                .buttonStyle(SheetSecondaryButtonStyle())
                Spacer(minLength: TC.Space.m)
                // Escape closes the sheet. The only other binding on this
                // sheet is Command-F below; Return stays unbound.
                Button("Close") { dismiss() }
                    .buttonStyle(SheetSecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
                // The ONLY approve control in the product. It is behind the
                // preview by design -- it cannot arm until one has loaded --
                // and it has NO keyboard shortcut: this used to be
                // `.defaultAction`, which put an irreversible send one
                // Return away from a hand resting on the keyboard.
                Button("Contribute") {
                    contribute()
                }
                .tcPrimaryAction()
                .disabled(!canContribute)
                .help(gateHelp)
            }
        }
        .padding(.horizontal, TC.Space.lg)
        .padding(.vertical, TC.Space.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(TC.surface)
    }

    // MARK: - What arms Contribute

    /// The consent surface's sentences, read once. Nil if the payload did
    /// not arrive or would not parse, in which case the sheet shows no claim
    /// rather than a blank one -- see `ConsentCopy.decode`.
    private var consent: ConsentCopy? {
        TCConsentCopy.copyJSON().flatMap(ConsentCopy.decode(fromJSON:))
    }

    /// This session's row AS THE QUEUE HOLDS IT NOW, not as it was when the
    /// sheet opened.
    ///
    /// `entry` is a `let` captured at open time, and this sheet can stay up
    /// across any number of snapshots -- including the one carrying a
    /// submit-time failure written back into the row. Reading the opening
    /// copy would apply the eligibility gate once and then never again,
    /// which is the same defect as never applying it.
    ///
    /// ONLY the eligibility gate and its sentence read this. Everything the
    /// sheet approves still goes through `entry`, whose id is the same
    /// either way -- what a preview pinned must not start moving under a
    /// contributor who is reading it.
    private var liveEntry: QueueEntry {
        EligibilitySurface.current(entry, in: model.awaitingDecision, id: \.entryID)
    }

    /// What the daemon said about contributing THIS session, or nothing at
    /// all for a contributor who has no eligibility question.
    private var eligibility: ContributionEligibility? { liveEntry.contributionEligibility }

    /// Whether the shared table offers a send control for this session.
    ///
    /// Answers `true` for an entry that carried no `eligibility` key: an
    /// invited contributor's queue is entirely contributable and the sheet is
    /// the sheet they always had. Nothing here branches on a state string.
    private var eligibilityOffersContribute: Bool {
        EligibilitySurface.offersContribute(eligibility, calls: model.eligibilityCalls)
    }

    private var canContribute: Bool {
        // `enrolled`, not `summary != nil`. An approval binds to the
        // envelope a preview pinned, and a preview built without an
        // enrollment pinned nothing -- which is the condition the shared
        // sentence names and the one the other two shells already test.
        //
        // And no claim, no approval: the statement above the button is the
        // whole of what a contributor is told before pressing it, so a
        // build that cannot read it must not arm the button either.
        //
        // And the daemon's own answer about this session. DISARMED HERE
        // RATHER THAN REMOVED, which is the opposite of the queue card: the
        // sheet's Contribute is already on screen and under a person's
        // cursor when the sentence above it is read, and a primary control
        // that vanished mid-read is its own confusion. On the card the
        // button is drawn fresh or not at all, so there is nothing to
        // vanish. Both routes go through the same shared table.
        consent != nil && ReadGate.canContribute(hasPinnedPreview: summary?.enrolled == true)
            && eligibilityOffersContribute
    }

    /// Whether this session can be contributed at all, above the statement
    /// the sheet already makes.
    ///
    /// Drawn WHEREVER Contribute is disarmed for this reason and never
    /// separated from it: a disarmed primary button with nothing beside it
    /// is a contributor hunting for a setting that would arm it. Absent
    /// entirely when the entry carried no `eligibility` key.
    @ViewBuilder
    private var admissibility: some View {
        if let copy = model.privateInferenceCopy,
           let line = EligibilitySurface.stateLine(
               eligibility, copy: copy, calls: model.eligibilityCalls)
        {
            let tone = PrivateInferenceIndicator.palette(
                EligibilitySurface.tone(eligibility, calls: model.eligibilityCalls)
                    ?? .neutral)
            VStack(alignment: .leading, spacing: TC.Space.xxs) {
                Label(line, systemImage: tone.symbol)
                    .font(TC.Font_.meta)
                    .foregroundStyle(tone.textColor)
                    .fixedSize(horizontal: false, vertical: true)
                if let reason = EligibilitySurface.reasonLine(
                    eligibility, calls: model.eligibilityCalls)
                {
                    Text(reason)
                        .font(TC.Font_.meta)
                        .foregroundStyle(TC.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
        }
    }

    /// The tooltip that explains the current answer, chosen by the ABI.
    ///
    /// Empty when the sentences are unavailable -- the same condition that
    /// disarms `canContribute`, so nothing is claimed and nothing is
    /// pressable. Without the guard a build whose bundle would not decode
    /// but whose `tc_consent_gate_help` still answered would paint a
    /// disarmed button with the not-connected sentence, which is a claim
    /// about the device rather than about the missing copy.
    private var gateHelp: String {
        guard consent != nil else { return "" }
        return TCConsentCopy.gateHelp(pinned: canContribute) ?? ""
    }

    /// The sentence the acknowledgement checkbox used to carry, printed
    /// where the tick used to be asked for.
    ///
    /// Plain text and no control: it is a statement the app makes, not a
    /// question it asks. The words come from `consent_copy.rs` across the
    /// ABI rather than being a literal here, because the Linux and Windows
    /// sheets print the same sentence and a copy in a view is a copy that
    /// drifts. Empty when the payload would not decode: the button is
    /// disarmed in that case, so nothing is claimed and nothing is
    /// pressable.
    /// The outcome question, its three answers, and the disclosure under
    /// them.
    ///
    /// Nothing here gates anything. There is no default selection, no
    /// fourth "didn't answer" option, and `Contribute` is armed by
    /// `ReadGate` alone -- a contributor who ignores this entire block
    /// contributes exactly as before, and the approval simply omits
    /// `outcome`. Tapping the selected answer again clears it, which is the
    /// only way back to unanswered once an answer is given.
    ///
    /// The caption is `VerdictCopy.caption` verbatim: it is where the sheet
    /// discloses that these fields sit outside its "exactly what would be
    /// sent" guarantee, which is the one thing on this sheet the preview
    /// cannot show.
    /// Whether the correction control is on screen: only under `Partly`
    /// and `Failed`.
    private var correctionIsOffered: Bool {
        verdict == .partly || verdict == .failed
    }

    /// What would actually be sent, or `nil` for a box that is hidden or
    /// holds nothing but whitespace.
    ///
    /// The visibility check is deliberate rather than redundant. The box is
    /// emptied when it is hidden, so this would answer `nil` anyway; the
    /// check states the rule -- a hidden control contributes nothing -- so
    /// it survives a future change that stops emptying on hide.
    private var correctionToSend: String? {
        guard correctionIsOffered else { return nil }
        return CorrectionCopy.toSend(correction)
    }

    /// Approve, and decide when the sheet goes away.
    ///
    /// With no correction, this is exactly what it was before the box
    /// existed: fire and dismiss. Back to the queue, never on to the next
    /// session -- the sheet used to load the next entry with the button
    /// under the same pixels, so a second keystroke or a second click sent
    /// a transcript nobody had looked at, with the recovery bar stranded
    /// behind the sheet. One sheet, one session, one decision.
    ///
    /// With a correction, the dismiss waits for the answer, because one of
    /// the answers is "that correction contains a credential" and the
    /// contributor needs the text still in front of them to act on it.
    private func contribute() {
        // THE PRESS DECIDES WHAT IS SENT. `canContribute` decided what was
        // offered, at the last render; a snapshot landing between that
        // render and this tap leaves the button acting on what was drawn.
        // Asking again here costs nothing and closes the window. Declining
        // leaves the sheet up, which repaints against the queue's current
        // answer and says why.
        guard EligibilitySurface.mayProceed(
            entry, in: model.awaitingDecision, id: \.entryID,
            eligibility: { $0.contributionEligibility }, calls: model.eligibilityCalls)
        else { return }
        guard let text = correctionToSend else {
            model.approve(entry, verdict: verdict)
            dismiss()
            return
        }
        model.approve(entry, verdict: verdict, correction: text) { refused in
            if refused {
                correctionRefused = true
            } else {
                dismiss()
            }
        }
    }

    /// The correction box and the disclosure under it.
    ///
    /// `CorrectionCopy.caption` is printed verbatim and in full. Until the
    /// published policy page carves a correction out of its "redacted
    /// locally, re-applied on the server" promise, that sentence is the
    /// only place a contributor is told their own words are stored as they
    /// typed them. It is not shortened for layout.
    private var correctionField: some View {
        VStack(alignment: .leading, spacing: TC.Space.xxs) {
            Text(CorrectionCopy.question)
                .font(TC.Font_.captionSmall)
                .foregroundStyle(TC.inkSecondary)
            TextEditor(text: $correction)
                .font(TC.Font_.caption)
                .frame(minHeight: 64, maxHeight: 140)
                .scrollContentBackground(.hidden)
                .padding(TC.Space.xxs)
                .background(TC.surfaceInset, in: RoundedRectangle(cornerRadius: TC.Radius.card))
                .accessibilityLabel(CorrectionCopy.question)
                .accessibilityHint(CorrectionCopy.placeholder)
                // Capped where the person can see it, so an over-long
                // correction is shortened at the keyboard rather than
                // refused as `correction-too-long` after the click.
                .onChange(of: correction) { _, latest in
                    if latest.count > CorrectionCopy.maxCharacters {
                        correction = String(latest.prefix(CorrectionCopy.maxCharacters))
                    }
                }
            Text(CorrectionCopy.caption)
                .font(TC.Font_.captionSmall)
                .foregroundStyle(TC.inkTertiary)
                .fixedSize(horizontal: false, vertical: true)
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var verdictQuestion: some View {
        VStack(alignment: .leading, spacing: TC.Space.xxs) {
            Text(VerdictCopy.question)
                .font(TC.Font_.captionSmall)
                .foregroundStyle(TC.inkSecondary)
            HStack(spacing: TC.Space.xxs) {
                ForEach(ContributorVerdict.allCases, id: \.rawValue) { option in
                    verdictOption(option)
                }
                Spacer(minLength: 0)
            }
            .padding(TC.Space.xxs)
            .background(TC.surfaceInset, in: RoundedRectangle(cornerRadius: TC.Radius.card))
            Text(VerdictCopy.caption)
                .font(TC.Font_.captionSmall)
                .foregroundStyle(TC.inkTertiary)
                .fixedSize(horizontal: false, vertical: true)
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// One answer, styled as the tab strip's chips are -- selected means a
    /// raised surface and the green hairline, the same vocabulary this sheet
    /// already uses for "this one is current".
    private func verdictOption(_ option: ContributorVerdict) -> some View {
        let selected = verdict == option
        return Button {
            verdict = selected ? nil : option
            // A contributor who wrote a correction under `Failed` and then
            // answered `Worked` has withdrawn it. Clearing it here is what
            // stops text nobody can see any more from riding along on the
            // approval.
            if !correctionIsOffered {
                correction = ""
            }
        } label: {
            Text(option.label)
                .font(TC.Font_.caption.weight(selected ? .bold : .regular))
                .foregroundStyle(selected ? TC.inkPrimary : TC.inkSecondary)
                .padding(.horizontal, TC.Space.m)
                .padding(.vertical, TC.Space.control)
                .background {
                    RoundedRectangle(cornerRadius: TC.Radius.control)
                        .fill(selected ? TC.surface : Color.clear)
                }
                .overlay {
                    RoundedRectangle(cornerRadius: TC.Radius.control)
                        .strokeBorder(
                            selected ? TC.green.opacity(TC.Border.activeTabAlpha) : Color.clear,
                            lineWidth: TC.Border.hairline
                        )
                }
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
    }

    private var gateStatement: some View {
        Text(consent?.gateStatement ?? "")
            .font(TC.Font_.captionSmall)
            .foregroundStyle(TC.inkTertiary)
            .fixedSize(horizontal: false, vertical: true)
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func prepareWitness() async {
        guard witnessSupported, !witnessWorking else { return }
        witnessRequested = true
        witnessWorking = true
        summary = nil
        closePreview()
        let outcome = await model.witnessReviewOutcome(entryID: entry.entryID)
        witnessWorking = false
        if outcome.succeeded { await load() }
        else {
            // The daemon classifies the refusal and chooses the words; this
            // used to render one sentence for all fourteen causes, so a
            // receipt the reviewer declined read exactly like a reviewer that
            // was down. `review.failed` remains the fallback for a response
            // carrying no sentence -- a transport failure, or a daemon older
            // than this shell.
            witnessRefusal = outcome.sentence
            failure = outcome.sentence ?? model.witnessCopy?.review?.failed
            loading = false
        }
    }

    private func load() async {
        loading = true
        failure = nil
        let outcome = await model.openPreview(entryID: entry.entryID)
        switch outcome {
        case .opened(let opened):
            preview = opened
            transcriptText = opened.body
            document = TranscriptDocument(opened.body)
            if let data = opened.summaryJSON.data(using: .utf8),
               let decoded = try? DaemonDecoding.decoder().decode(PreviewSummary.self, from: data)
            {
                summary = decoded
                witnessRequested = decoded.envelopeDigest?.hasPrefix("witness-sha256:") == true
            } else {
                failure = "the summary could not be read"
            }
        case .failed(let message):
            failure = message
        }
        loading = false
    }

    private func closePreview() {
        preview?.close()
        preview = nil
    }
}

// MARK: - Sheet parts
//
// These are private to this file on purpose. The sheet is the only surface
// that draws an outlined sheet button at this size. The read-gate box that
// used to live here was the same drawing three screens had each written out,
// and it is now `TCReadGateCheckbox` in the design system.

/// The one size the spec states that the shared scale has no step for: the
/// sheet canvas (§4.6), used as the sheet's minimum and its first-shown
/// size. The 5pt control padding and the 13pt read-gate box that used to
/// live here are now `TC.Space.control` and `TC.Control.checkbox`.
private enum SheetMetric {
    static let width: CGFloat = 760
    static let height: CGFloat = 620
}

/// True while the screenshot hook is rasterizing the shipping views.
///
/// `ImageRenderer` runs on the CPU with no window-server session, and two of
/// its limitations land squarely on this tab and are already documented
/// elsewhere in the shell: an NSView-backed `TextField` comes out as a solid
/// yellow bar with a "no entry" glyph (see `OnboardingConnectView`), and a
/// `ScrollView` comes out blank (see `ConsentScopesView`). Both are artifacts
/// of the renderer and neither is visible in the running app.
///
/// They still matter, because the captures are how this sheet is reviewed,
/// and a capture that shows a gold block where the search field is and an
/// empty space where the matched excerpt is says the opposite of what the
/// running app says -- the second one especially, since a match count with
/// no visible match is the one thing this tab must never do. So under the
/// hook, and only under the hook, the field is drawn rather than editable
/// and the scrolling regions lay out inline. Nothing about the shipping
/// behaviour changes: `TRACE_COMMONS_SCREENSHOT_DIR` is unset in a real run.
private enum CaptureMode {
    static let isRendering = DebugScreenshot.directory != nil
}

/// A scrolling region that lays its content out inline while the screenshot
/// hook is running, because `ImageRenderer` rasterizes a `ScrollView` as
/// blank. See `CaptureMode`.
private struct CaptureSafeScroll<Content: View>: View {
    @ViewBuilder let content: () -> Content

    init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    var body: some View {
        if CaptureMode.isRendering {
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
                .clipped()
        } else {
            ScrollView { content() }
        }
    }
}

/// The sheet's own hairline. `Divider()` picks up the system separator
/// colour, which is a different grey from the one every card edge in this
/// app is drawn in.
private struct SheetHairline: View {
    var body: some View {
        Rectangle()
            .fill(TC.line)
            .frame(height: TC.Border.hairline)
    }
}

/// The outlined button of §6.1: a card face, a hairline, and the label in
/// ink. Used for every control in the sheet that is not Contribute.
private struct SheetSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(TC.Font_.labelControl)
            .foregroundStyle(TC.inkPrimary)
            .padding(.horizontal, TC.Space.m)
            .padding(.vertical, TC.Space.control)
            .background(TC.surface, in: RoundedRectangle(cornerRadius: TC.Radius.control))
            .overlay {
                RoundedRectangle(cornerRadius: TC.Radius.control)
                    .strokeBorder(TC.line, lineWidth: TC.Border.hairline)
            }
            .opacity(configuration.isPressed ? 0.82 : 1)
            .contentShape(Rectangle())
    }
}

/// Wraps every occurrence of `term` in the gold highlight wash. SwiftUI can
/// carry a background colour on a run of an `AttributedString` but not the
/// 2pt radius and 2pt side padding the spec draws around it, so the wash is
/// flush against the glyphs.
private func highlighting(_ text: String, term: String) -> AttributedString {
    var attributed = AttributedString(text)
    guard !term.isEmpty else { return attributed }
    var searchRange = attributed.startIndex..<attributed.endIndex
    while let found = attributed[searchRange].range(of: term, options: .caseInsensitive) {
        attributed[found].backgroundColor = TC.goldHighlight
        attributed[found].foregroundColor = TC.inkPrimary
        searchRange = found.upperBound..<attributed.endIndex
    }
    return attributed
}

// MARK: - Tabs

/// The highest-value affordance in the product: type a client name, get
/// `0 matches` or jump-to-context, without reading 148 turns.
struct SearchTab: View {
    /// The body, already cut into chunks and holding its own bytes. Context
    /// snippets are cut from those bytes at the offsets the ABI reports.
    let document: TranscriptDocument?
    let preview: TCPreview?
    /// How many times a term appears in the PRE-redaction session, or nil
    /// when that could not be checked. A closure rather than a daemon
    /// reference because `AppModel` is the only thing in this app that talks
    /// to the daemon.
    let searchOriginal: (String) -> Int?
    /// Command-F, as a counter the sheet bumps. Any change puts the caret
    /// in the field; the value itself means nothing.
    let focusRequest: Int

    @State private var needle: String
    @State private var offsets: [Int]?
    @State private var outcome: OriginalSearchOutcome?
    @State private var searched: Bool
    @State private var recents: [String] = RecentSearches.load()
    @FocusState private var focused: Bool

    init(
        document: TranscriptDocument?,
        preview: TCPreview?,
        searchOriginal: @escaping (String) -> Int? = { _ in nil },
        initialNeedle: String = "",
        initialOffsets: [Int]? = nil,
        focusRequest: Int = 0
    ) {
        self.document = document
        self.preview = preview
        self.searchOriginal = searchOriginal
        self.focusRequest = focusRequest
        _needle = State(initialValue: initialNeedle)
        _offsets = State(initialValue: initialOffsets)
        _searched = State(initialValue: initialOffsets != nil)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: TC.Space.m) {
            Text("Search this trace for anything you need to be sure isn't in it.")
                .font(TC.Font_.body)
                .foregroundStyle(TC.inkPrimary)

            HStack(spacing: TC.Space.s) {
                searchField
                Button("Search", action: commit)
                    .buttonStyle(SheetSecondaryButtonStyle())
            }

            if !recents.isEmpty {
                // The contributor's own previous questions, one click away.
                HStack(spacing: TC.Space.s) {
                    Text("Recent:")
                        .font(TC.Font_.caption)
                        .foregroundStyle(TC.inkSecondary)
                    ForEach(recents, id: \.self) { term in
                        Button(term) { needle = term }
                            .buttonStyle(.plain)
                            .font(TC.Font_.caption)
                            .foregroundStyle(TC.greenText)
                    }
                }
            }

            resultSummary

            CaptureSafeScroll {
                VStack(alignment: .leading, spacing: TC.Space.sm) {
                    ForEach(Array(contexts.enumerated()), id: \.offset) { _, snippet in
                        Text(highlighting(snippet, term: needle))
                            .tcType(TC.Font_.monoCodeText)
                            .textSelection(.enabled)
                            .padding(.horizontal, TC.Space.sm)
                            .padding(.vertical, TC.Space.s)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                TC.surfaceScrim,
                                in: RoundedRectangle(cornerRadius: TC.Radius.control)
                            )
                    }
                }
            }
        }
        .onAppear { focused = true }
        .onChange(of: focusRequest) { _, _ in focused = true }
    }

    /// The spec's field: card face, hairline, radius 6, `5 x 10`.
    ///
    /// Under the screenshot hook it is drawn rather than editable -- see
    /// `CaptureMode`. The box, the type and the text are identical either
    /// way; what the capture loses is the caret and the ability to type,
    /// neither of which a still image was ever going to show.
    @ViewBuilder
    private var searchField: some View {
        Group {
            if CaptureMode.isRendering {
                Text(needle.isEmpty ? "Client name, hostname, anything" : needle)
                    .font(TC.Font_.body)
                    .foregroundStyle(needle.isEmpty ? TC.inkTertiary : TC.inkPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                TextField("Client name, hostname, anything", text: $needle)
                    .textFieldStyle(.plain)
                    .font(TC.Font_.body)
                    .foregroundStyle(TC.inkPrimary)
                    .focused($focused)
                    .onSubmit(commit)
                    .onChange(of: needle) { _, _ in run() }
            }
        }
        .padding(.horizontal, TC.Space.sm)
        .padding(.vertical, TC.Space.control)
        .background(TC.surface, in: RoundedRectangle(cornerRadius: TC.Radius.control))
        .overlay {
            RoundedRectangle(cornerRadius: TC.Radius.control)
                .strokeBorder(TC.line, lineWidth: TC.Border.hairline)
        }
    }

    @ViewBuilder
    private var resultSummary: some View {
        if !searched || needle.isEmpty {
            Text("Type to search. Nothing is sent while you look.")
                .font(TC.Font_.body)
                .foregroundStyle(TC.inkSecondary)
        } else if offsets == nil {
            Text("The search couldn't run on this trace.")
                .font(TC.Font_.body)
                .foregroundStyle(TC.inkSecondary)
        } else if let outcome {
            // The answer to the only question this tab exists for, in
            // the app's two loudest tones -- each with a glyph, because a
            // green word and an amber word are the same word in greyscale.
            //
            // Which tone is the outcome's to decide: a term that is still in
            // what would be sent is the one to slow down on, and a term that
            // was removed reads as clear even though the redacted body and
            // the original disagree about it.
            //
            // Three tones, not two. `.unknown` is a missing answer, and it
            // used to draw in the clear tone -- the app's all-clear glyph
            // beside the sentence that says the check did not run. See
            // `OriginalSearchOutcome.Emphasis`.
            Label(outcome.sentence, systemImage: tone(for: outcome).symbol)
                .font(TC.Font_.headingAlert)
                .foregroundStyle(tone(for: outcome).textColor)
        } else if offsets!.isEmpty {
            // No outcome: the preloaded screenshot path, which sets offsets
            // without running a search.
            Label("0 matches", systemImage: TC.Tone.clear.symbol)
                .font(TC.Font_.headingAlert)
                .foregroundStyle(TC.Tone.clear.textColor)
        } else {
            Label("^[\(offsets!.count) match](inflect: true)", systemImage: TC.Tone.attention.symbol)
                .font(TC.Font_.headingAlert)
                .foregroundStyle(TC.Tone.attention.textColor)
        }
    }

    /// The tone for an outcome. Three of them, because "could not check"
    /// is neither a clean answer nor an alarming one.
    private func tone(for outcome: OriginalSearchOutcome) -> TC.Tone {
        switch outcome.emphasis {
        case .attention: return .attention
        case .clear: return .clear
        case .unchecked: return .neutral
        }
    }

    /// The keystroke path. A local in-memory pass over the already-open
    /// redacted preview and nothing else.
    ///
    /// Runs on the main actor deliberately: the scan is a local in-memory
    /// pass, and keeping every touch of the `tc_preview*` on one thread is
    /// what the header's ownership rules ask for -- its pointer check narrows
    /// accidental misuse to an error, it does not make concurrent use safe.
    ///
    /// It deliberately does NOT ask about the original. `searchOriginal`
    /// bottoms out in `tc_search_original`, which spawns a thread, builds a
    /// runtime, and reads the whole raw unredacted session file off disk;
    /// on `.onChange(of: needle)` that ran once per character typed, on this
    /// actor. The outcome is cleared rather than left standing, so a verdict
    /// from the previous term is never shown against the new one.
    private func run() {
        searched = true
        outcome = nil
        guard !needle.isEmpty, let preview else {
            offsets = []
            return
        }
        offsets = preview.search(needle)
    }

    /// Runs the search, asks about the original, AND records the term.
    ///
    /// Separate from `run` for two reasons, and both are about the
    /// difference between passing through a prefix and asking a question.
    ///
    /// Remembering here because doing it in `run` filled the six-slot strip
    /// with the prefixes of one word: typing "xyz" recorded "x", "xy", and
    /// "xyz". Checking the original here because that check is the expensive
    /// one -- see `run` -- and a contributor asks it by pressing Return or
    /// the button.
    private func commit() {
        run()
        guard !needle.isEmpty, offsets != nil else { return }
        // The redacted-body count alone cannot tell "we took it out" from
        // "it was never here". See `OriginalSearchOutcome`.
        outcome = OriginalSearchOutcome.classify(
            remaining: offsets?.count ?? 0,
            original: searchOriginal(needle)
        )
        if let offsets, !offsets.isEmpty {
            recents = RecentSearches.remember(needle)
        }
    }

    /// The ABI reports UTF-8 BYTE offsets, so context is cut from the
    /// document's bytes at those offsets, never from Swift's character
    /// indices.
    ///
    /// Bounded on both sides: at most 20 snippets, each at most a match plus
    /// 240 bytes of surroundings, so what this tab lays out does not grow
    /// with the trace. The whole-body walk that used to be here -- a fresh
    /// `Array(transcript.utf8)` every time this property was read, which is
    /// every keystroke -- is gone; the copy is made once, when the sheet
    /// builds its `TranscriptDocument`.
    ///
    /// The search itself is not bounded here and does not need to be: it
    /// runs in the daemon over the raw body and returns offsets, so no part
    /// of finding a match is text layout.
    private var contexts: [String] {
        guard let offsets, !offsets.isEmpty, let document else { return [] }
        return offsets.prefix(20).map { offset in
            let snippet = document.snippet(
                around: offset, matchBytes: needle.utf8.count, window: 120)
            guard !snippet.text.isEmpty else { return "" }
            let text = snippet.text.replacingOccurrences(of: "\n", with: " ")
            return (snippet.elidedBefore ? "…" : "") + text + (snippet.elidedAfter ? "…" : "")
        }
    }
}

struct WhatsInItTab: View {
    let entry: QueueEntry
    let summary: PreviewSummary

    var body: some View {
        CaptureSafeScroll {
            VStack(alignment: .leading, spacing: TC.Space.sm) {
                LabeledContent("Agent", value: entry.agentName)
                LabeledContent("Project", value: entry.projectLabel)
                LabeledContent("Turns recorded", value: "\(summary.eventCount)")
                LabeledContent("Session on disk", value: Format.bytes(summary.rawSessionBytes))
                LabeledContent("Would send", value: Format.bytes(summary.wouldSendBytes))
                if let probabilities = summary.tokenDistributionSummary { Text(probabilities) }
                Text("""
                "Would send" is usually larger than the file on disk: a redacted \
                envelope also carries schema, consent and privacy metadata the raw \
                session file does not.
                """)
                .font(TC.Font_.caption)
                .foregroundStyle(TC.inkSecondary)

                removedPanel
                    .padding(.top, TC.Space.xs)

                if !summary.piiLabelsPresent.isEmpty {
                    TCSectionHeader(title: "Personal-information categories seen")
                        .padding(.top, TC.Space.xs)
                    Text(summary.piiLabelsPresent.joined(separator: ", "))
                        .font(TC.Font_.body)
                        .foregroundStyle(TC.inkPrimary)
                    Text("Categories only. The matched text is never reported here.")
                        .font(TC.Font_.caption)
                        .foregroundStyle(TC.inkSecondary)
                }

                TCSectionHeader(title: "Residual risk")
                    .padding(.top, TC.Space.xs)
                Text(summary.residualRisk.replacingOccurrences(of: "_", with: " "))
                    .font(TC.Font_.body)
                    .foregroundStyle(TC.inkPrimary)
                Text("""
                Files touched and tools invoked are not in this contract's preview \
                summary, so they are not shown rather than guessed at.
                """)
                .font(TC.Font_.caption)
                .foregroundStyle(TC.inkTertiary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// Grouped by family, described in words, and split into what left and
    /// what did not.
    ///
    /// This section used to print the daemon's count map one raw label per
    /// line -- which put `residual_secret_at:events.3.correction` under the
    /// heading "What scrubbing removed", stating the exact opposite of what
    /// happened about a secret that is still in the payload. See
    /// `RedactionSummary` and `RedactionLabels`.
    private var rows: (removed: [RedactionSummaryRow], stillPresent: [RedactionSummaryRow]) {
        RedactionSummary.rows(
            occurrences: summary.redactions,
            distinct: summary.redactionsDistinct
        )
    }

    @ViewBuilder
    private var removedPanel: some View {
        let rows = self.rows
        TCSectionHeader(title: "What scrubbing removed")
        if rows.removed.isEmpty {
            nothingMatchedCard
        } else {
            ForEach(rows.removed, id: \.family) { row in
                summaryRow(row)
            }
        }

        if !rows.stillPresent.isEmpty {
            TCSectionHeader(title: "Found, and still in what would be sent")
                .padding(.top, TC.Space.xs)
            ForEach(rows.stillPresent, id: \.family) { row in
                HStack(alignment: .top, spacing: TC.Space.s) {
                    Image(systemName: TC.Tone.attention.symbol)
                        .font(.system(size: 14))
                        .foregroundStyle(TC.Tone.attention.color)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: TC.Space.micro) {
                        Text(row.description)
                            .font(TC.Font_.body)
                            .foregroundStyle(TC.goldText)
                            .fixedSize(horizontal: false, vertical: true)
                        // Schema paths, never transcript text: the redactor
                        // guarantees the shape of these labels where it
                        // mints them.
                        if !row.detail.isEmpty {
                            Text(row.detail.joined(separator: ", "))
                                .font(TC.Font_.caption)
                                .foregroundStyle(TC.inkSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Spacer(minLength: 0)
                }
                .accessibilityElement(children: .combine)
            }
        }

        // A panel that enumerates categories makes the app look more
        // thorough than it is, which is exactly when this sentence earns its
        // place.
        ScrubbingCaveatNote()
            .padding(.top, TC.Space.xs)
    }

    private func summaryRow(_ row: RedactionSummaryRow) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.micro) {
            Text(row.countLine)
                .font(TC.Font_.body)
                .foregroundStyle(TC.inkPrimary)
            Text(row.description)
                .font(TC.Font_.caption)
                .foregroundStyle(TC.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if !row.detail.isEmpty {
                Text(row.detail.joined(separator: ", "))
                    .font(TC.Font_.caption)
                    .foregroundStyle(TC.inkTertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    /// The one card in this tab that is drawn to be found: a session where
    /// no pattern fired is the session most worth a second look, and it is
    /// the case a count of removals cannot state.
    private var nothingMatchedCard: some View {
        HStack(alignment: .top, spacing: TC.Space.m) {
            Image(systemName: TC.Tone.attention.symbol)
                .font(.system(size: 14))
                .foregroundStyle(TC.Tone.attention.color)
                .accessibilityHidden(true)
            Text("""
            Nothing matched. On a session that touched credentials, that is \
            itself worth a second look.
            """)
            .font(TC.Font_.body)
            .foregroundStyle(TC.inkPrimary)
            .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, TC.Space.md)
        .padding(.vertical, TC.Space.m)
        .frame(maxWidth: .infinity, alignment: .leading)
        .tcCard(emphasised: true)
        .accessibilityElement(children: .combine)
    }
}

/// The redacted transcript exactly as it would be sent, set as flat
/// monospace text and deliberately not as chat bubbles: these are the
/// literal bytes an approval covers, not a conversation to be enjoyed.
///
/// Redactions stay visible as inline chips rather than deletions, so a
/// contributor can see WHERE scrubbing fired -- which is the point. A hole
/// tells you nothing; a chip tells you the pipeline was standing there.
///
/// **All of the body is here.** It used to be the first 64 KB with a notice
/// saying the rest was not displayed, because one text run of a 17.5 MB
/// session pinned the main thread inside CoreText and took 2.97 GB to do
/// it. The body is now cut into chunks by `TranscriptDocument`; only the
/// chunks near the viewport are typeset, and chunks that scroll away are
/// dropped. What is bounded is glyph storage, not reach:
/// `TranscriptPaging.retainedLimitBytes` of text is laid out at any moment
/// whether the trace is 200 KB or 17.5 MB.
///
/// Two consequences a reader can see. Text selection is per block rather
/// than across the whole body -- a chunk that is not typeset has nothing to
/// select -- which is why "Copy everything" is here and copies all of it.
/// And the scrollbar settles by a row or two as chunks materialise, because
/// a chunk that is not laid out holds its place by an estimate.
struct TranscriptTab: View {
    let document: TranscriptDocument
    /// The chunks that are typeset right now, and the eviction that keeps
    /// that set under the ceiling. The policy lives in `TCShellCore` so it
    /// can be asserted against real byte counts without a running app.
    @State private var resident = TranscriptResidentChunks<ChippedChunk>()
    /// Where each chunk sits vertically, so a chunk that is not typeset
    /// still holds its place in the scroll.
    @State private var rows: TranscriptRowIndex?
    /// The last chunk to come into view; the window is centred on it, so
    /// overscan follows the reader in whichever direction they are going.
    @State private var anchor = 0
    @State private var columns = 0
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            Text(TranscriptMarkers.chipped(Self.caption, font: TC.Font_.caption))
                .tcType(TC.Font_.captionText)
                .foregroundStyle(TC.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: TC.Space.s) {
                Text("\(Format.bytes(document.totalBytes)), all of it.")
                    .font(TC.Font_.caption)
                    .foregroundStyle(TC.inkSecondary)
                Spacer(minLength: 0)
                Button(copied ? "Copied" : "Copy everything", action: copyAll)
                    .buttonStyle(SheetSecondaryButtonStyle())
                    .help(
                        "Puts the whole redacted body on the clipboard. "
                            + "Selection inside the transcript covers one block at a time."
                    )
                    .accessibilityIdentifier("transcript-copy-all")
            }

            GeometryReader { geometry in
                CaptureSafeScroll {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(laidOutIndices, id: \.self) { index in
                            chunkRow(index)
                        }
                    }
                    .padding(.horizontal, TC.Space.md)
                    .padding(.vertical, TC.Space.m)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .tcCard()
                .onAppear { measure(width: geometry.size.width) }
                .onChange(of: geometry.size.width) { _, width in measure(width: width) }
            }
        }
    }

    /// Which chunks exist as views at all.
    ///
    /// Every chunk, normally: a `LazyVStack` builds only the rows near the
    /// viewport, and the rest cost nothing until they are approached. Under
    /// the screenshot hook `CaptureSafeScroll` lays its content out inline
    /// with no viewport to be near, so there the list is cut to the resident
    /// window -- a capture of the first screen, which is what a capture
    /// shows anyway.
    private var laidOutIndices: Range<Int> {
        guard CaptureMode.isRendering else { return 0..<document.chunkCount }
        return TranscriptResidency.window(document, visible: 0..<1)
    }

    @ViewBuilder
    private func chunkRow(_ index: Int) -> some View {
        Group {
            if let chunk = resident.rendered[index] {
                Text(chunk.text)
                    .tcType(TC.Font_.monoTranscriptText)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    // The chips are named here and nowhere else: SwiftUI has
                    // no per-run accessibility label inside a `Text`, and a
                    // marker left unnamed is spelled out as punctuation and
                    // capitals in the middle of a sentence. See
                    // `RedactionMarks`.
                    .accessibilityLabel(chunk.spoken)
            } else {
                // Holds the chunk's place so the scroll extent is the whole
                // body's, not the resident window's.
                Color.clear
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .frame(height: placeholderHeight(index))
            }
        }
        .onAppear {
            anchor = index
            refresh()
        }
    }

    /// Moves the resident window to sit around `anchor`, typesetting what
    /// came into it and dropping what fell out of it.
    ///
    /// Only chunks that are new to the window are chipped and typeset, so a
    /// scroll of one chunk costs one chunk of layout -- measured at 6.4 ms
    /// for 4 KB with chips, inside a 16.7 ms frame.
    private func refresh() {
        let index = anchor
        resident.update(document: document, visible: index..<(index + 1)) { chunk in
            let text = document.text(of: chunk)
            return ChippedChunk(
                text: TranscriptMarkers.chipped(text, font: TC.Font_.monoTranscript),
                spoken: RedactionMarks.spoken(text)
            )
        }
    }

    private func measure(width: CGFloat) {
        let usable = max(1, width - 2 * TC.Space.md)
        let next = max(1, Int(usable / Self.columnWidth))
        guard next != columns else { return }
        columns = next
        rows = TranscriptRowIndex(document, columns: next)
        refresh()
    }

    private func placeholderHeight(_ index: Int) -> CGFloat {
        let count = rows?.rows(of: index) ?? max(1, document.chunks[index].lineCount)
        return CGFloat(count) * Self.rowHeight
    }

    private func copyAll() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(document.wholeText(), forType: .string)
        copied = true
    }

    // MARK: - Metrics
    //
    // Taken from the font rather than assumed, because the placeholder for a
    // chunk that is not laid out is only honest if it is the height that
    // chunk will have once it is.

    private static let font = NSFont.monospacedSystemFont(
        ofSize: NSFont.preferredFont(forTextStyle: .subheadline).pointSize,
        weight: .regular
    )
    private static let columnWidth = ("M" as NSString).size(withAttributes: [.font: font]).width
    private static let rowHeight =
        NSLayoutManager().defaultLineHeight(for: font)
        + TC.Font_.LineHeight.spacing(
            for: font.pointSize, TC.Font_.monoTranscriptText.lineHeight)

    /// Spec copy, with the sample marker rendered as a live chip so the
    /// sentence demonstrates the thing it describes.
    private static let caption = """
        These are the exact bytes an approval covers. Marks like <PRIVATE_SECRET_1> \
        show where scrubbing fired — legible as chips, not holes.
        """
}

/// One resident chunk: what it draws as, and what it reads as aloud.
///
/// The spoken form is built in the same pass as the chips, off the same
/// text, so naming costs one scan per chunk that was going to be scanned
/// anyway -- and a chunk that is evicted drops both together rather than
/// leaving a name behind for text nobody is holding.
private struct ChippedChunk {
    let text: AttributedString
    /// The chunk with each marker replaced by its name. See `RedactionMarks`.
    let spoken: String
}

/// Turns the redaction pipeline's `<PRIVATE_*>` and `[REDACTED*]` markers
/// into chips: bold, on the measured chip pair rather than the gold ramp,
/// so they read as objects placed in the text instead of damage done to it.
///
/// Runs per chunk now, never over the whole body. The scan itself is in
/// `TranscriptMarkerScan` and is shared with the chunker, which uses it to
/// avoid cutting through a marker -- half a marker rendered as body text in
/// one block and the other half in the next would read as content that was
/// never scrubbed.
///
/// The chip's colours are deliberate and are not the gold ramp; that is the
/// paragraph above and it stands. What the chip does NOT carry is a name:
/// every one of them draws the same whether it stands for a path, a
/// credential, or a name found in prose. `RedactionMarks` supplies that,
/// over this same scan, and `chunkRow` puts it on the chunk's accessibility
/// label -- SwiftUI has no per-run label inside a `Text`, so the chunk is
/// the finest grain available.
private enum TranscriptMarkers {
    static func chipped(_ text: String, font: Font) -> AttributedString {
        var out = AttributedString()
        var cursor = text.startIndex
        for range in TranscriptMarkerScan.spans(in: text) {
            out.append(AttributedString(String(text[cursor..<range.lowerBound])))
            var chip = AttributedString(String(text[range]))
            chip.font = font.weight(.bold)
            chip.backgroundColor = TC.redactionChipBackground
            chip.foregroundColor = TC.redactionChipForeground
            out.append(chip)
            cursor = range.upperBound
        }
        out.append(AttributedString(String(text[cursor...])))
        return out
    }
}

/// The consent scopes this upload will carry, restated at the moment of
/// consent rather than only at onboarding.
struct PermissionsTab: View {
    let summary: PreviewSummary
    let options: [ConsentScope]

    var body: some View {
        CaptureSafeScroll {
            VStack(alignment: .leading, spacing: TC.Space.m) {
                TCSectionHeader(title: "What this upload asks for")
                ForEach(summary.consentScopes, id: \.self) { scope in
                    VStack(alignment: .leading, spacing: TC.Space.micro) {
                        Text(ScopeCopy.title(for: scope, options: options))
                            .font(TC.Font_.cardTitle)
                            .foregroundStyle(TC.inkPrimary)
                        if let description = options.first(where: { $0.name == scope })?.description {
                            Text(description)
                                .font(TC.Font_.caption)
                                .foregroundStyle(TC.inkSecondary)
                        }
                    }
                }
                Text("""
                These are the permissions this device requests. Trace Commons can \
                narrow them, never widen them -- and if your permissions change \
                between now and sending, this approval stops applying and you are \
                asked again.
                """)
                .font(TC.Font_.caption)
                .foregroundStyle(TC.inkSecondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

enum ScopeCopy {
    /// The first words of each label carry the distinction, because that is
    /// all most people read.
    static func title(for wireName: String, options: [ConsentScope]) -> String {
        switch wireName {
        case "debugging_evaluation": return "Finding bugs and measuring agents"
        case "benchmark_only", "benchmark_creation": return "Turn my traces into test cases"
        case "ranking_training", "reward_model_training":
            return "Train models that judge agent output"
        case "model_training": return "Train coding models directly"
        case "public_attribution": return "List my handle publicly as a contributor"
        default:
            return options.first(where: { $0.name == wireName })?.name
                ?? wireName.replacingOccurrences(of: "_", with: " ")
        }
    }
}



/// The disclosure is scrollable and shared with the screenshot renderer.
struct WitnessReviewConsent: View {
    let copy: WitnessReviewCopy
    let onConfirm: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: TC.Space.l) {
            Text(copy.heading).font(TC.Font_.cardTitle)
            ViewThatFits(in: .vertical) {
                disclosure
                ScrollView { disclosure }
            }
            HStack {
                Spacer()
                Button(copy.cancel, role: .cancel) { dismiss() }
                Button(copy.confirm) { dismiss(); onConfirm() }
            }
        }
        .padding(TC.Space.xl)
        .frame(width: 560, height: 390)
        .tcScreen()
    }

    private var disclosure: some View {
        VStack(alignment: .leading, spacing: TC.Space.l) {
            Text(copy.disclosure).fixedSize(horizontal: false, vertical: true)
            Text(copy.immutable).foregroundStyle(TC.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
