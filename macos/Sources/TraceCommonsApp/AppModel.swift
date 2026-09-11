import Foundation
import SwiftUI
import TCBridge
import TCShellCore

/// Everything the UI reads, and the only thing that talks to the daemon.
///
/// `@MainActor` throughout: `tc_subscribe` callbacks arrive on a Rust
/// background thread, and `handle(event:)` is the single place that hops
/// back before touching any published property.
@MainActor
final class AppModel: ObservableObject {
    enum Startup: Equatable {
        case starting
        /// The daemon is running in-process.
        case running
        /// Refused to start, with a sentence a person can act on.
        case refused(String)
        /// Refused because nobody has said which session folders to watch.
        ///
        /// Separate from `.refused` because it is the one refusal with a way
        /// out: the roots screen collects two folders and starts the daemon
        /// with them. Before this case existed the refusal rendered as a
        /// static notice and every screen that could clear it lived behind
        /// the daemon it was blocking, so a fresh install could never
        /// finish onboarding.
        case needsRoots
    }

    /// The recovery hold that follows an approval.
    ///
    /// It deliberately carries no countdown. The real deadline is the
    /// daemon's next upload sweep -- `drain_approved` claims everything in
    /// `Approved` on a poll tick -- and this process cannot see when that
    /// tick lands: the socket's `status` and `get_settings` views expose the
    /// digest interval and the queue TTL but not the poll interval, and
    /// `list_pending` returns only `Pending` entries, so an approved entry
    /// disappears from everything the app can observe the moment it is
    /// approved.
    ///
    /// The old five-second counter was a number this app made up. Counting
    /// down to zero and vanishing told a contributor the window had closed
    /// when it usually had not, and told them nothing at all about the case
    /// that actually matters -- the sweep that fires one second after they
    /// clicked. So this counts UP, from a time that is real, and the
    /// affordance stays until the contributor puts it away or until the
    /// daemon refuses the cancel (`undoApproval` says so plainly when it
    /// does).
    ///
    /// One-click submit widened this from a single entry to a set: the row
    /// action approves one id, the project action can approve many, and
    /// `cancel` has no bulk form -- `undoApproval` below drives it once per
    /// id in `entryIDs`. `toastLine` and `offerUndo` are `SubmitToast`'s,
    /// carried here rather than re-derived: this is the one sentence the
    /// contributor sees for what just happened, whether or not Undo is
    /// offered alongside it (see `ApproveResponse.toast`).
    struct Undo: Equatable {
        let entryIDs: [String]
        let toastLine: String
        /// Whether the Undo control itself is shown. False for "Nothing
        /// approved" and fully-skipped responses -- the toast still needs to
        /// be seen, but there is nothing to undo. See `SubmitToast.offerUndo`.
        let offerUndo: Bool
        /// When the approval was made, on this machine's clock.
        let approvedAt: Date
        /// Seconds since `approvedAt`, ticked for display. Stops advancing
        /// after `Undo.tickCeiling`; the affordance does not.
        var heldSeconds: Int

        /// The display counter stops here. Past a couple of minutes the exact
        /// figure has stopped meaning anything, and a ticker that runs for the
        /// life of the process to redraw a number nobody is reading is waste.
        static let tickCeiling = 120
    }

    @Published private(set) var startup: Startup = .starting
    @Published private(set) var isStartingDaemon = false
    private let daemonStartup: DaemonStartup

    init(daemonStartup: DaemonStartup? = nil) {
        self.daemonStartup = daemonStartup ?? DaemonStartup()
    }
    @Published private(set) var status: DaemonStatus = .unknown
    @Published private(set) var pending: [QueueEntry] = [] {
        didSet { recomputeWaiting() }
    }
    @Published private(set) var summaries: [String: PreviewSummary] = [:]
    @Published private(set) var summaryErrors: [String: String] = [:]
    /// A session the daemon's preview scheduler refused to parse for being
    /// over the admission cap. Carries only what `PreviewTooLarge` carries
    /// -- a raw stat and the cap -- never a would-send estimate.
    @Published private(set) var tooLarge: [String: PreviewTooLarge] = [:]
    @Published private(set) var history: [HistoryRecord] = []
    @Published private(set) var rollup: HistoryRollup?
    @Published private(set) var projects: [ProjectRow] = []
    /// The one project the daemon suggests arming, or nil. Refreshed
    /// alongside `projects`, because every reason the project list changes
    /// is also a reason this answer might have.
    @Published private(set) var armingOffer: ArmingOffer?
    @Published private(set) var consentScopes: [ConsentScope] = []
    @Published private(set) var daemonSettings: DaemonSettingsView?

    // MARK: - The local proxy

    /// The routing surface's fixed words, decoded once from the Rust.
    ///
    /// Nil only if the export or the decode failed, and the card renders
    /// nothing at all in that case. A screen with blanks beside tool names
    /// would be worse, and a screen with Swift-authored words worse still.
    @Published private(set) var routingCopy: RoutingCopy? = RoutingCopy.decode(
        fromJSON: TCRoutingCopy.copyJSON() ?? ""
    )
    /// What IronWire last answered about which tools point at it, or nil
    /// for nothing held. Nil is not a fault; it is the absence of evidence,
    /// and every tool reads as not known while it stands.
    @Published private(set) var routingEvidence: RoutingEvidence?
    /// The sentence the last probe produced, shown under the Apply button.
    @Published private(set) var routingProbeLine: String?
    /// A probe is in flight. Drives the button's own label, which is a
    /// shared word like every other on this card.
    @Published private(set) var routingChecking = false

    /// What a running IronWire published about itself, as far as this app
    /// has asked.
    ///
    /// Starts as nothing found rather than as nil, because that is the
    /// state of a machine nobody has asked about yet AND the state of a
    /// machine without IronWire, and the card says the same thing about
    /// both: here are the fields, say which port. It becomes a found port
    /// only when `discover_routing` says so.
    @Published private(set) var routingDiscovery = RoutingDiscovery.none

    /// Everything on this surface that is decided in the Rust: the sentences
    /// that interpolate, and the two branch tables that pick a word and a
    /// state line. This shell fills in no holes and owns no `switch`; see
    /// `TCRoutingCopy`.
    let routingCalls = RoutingCalls(
        tokenLine: { TCRoutingCopy.tokenLine(path: $0) },
        unreachableLine: { TCRoutingCopy.unreachableLine(port: $0) },
        discoveryLine: { TCRoutingCopy.discoveryLine(port: $0) },
        toolWord: { TCRoutingCopy.toolWord(sourceMode: $0, wiring: $1) },
        toolTone: { TCRoutingCopy.toolTone(sourceMode: $0, wiring: $1) },
        stateLine: { TCRoutingCopy.stateLine(state: $0) },
        stateTone: { TCRoutingCopy.stateTone(state: $0) }
    )
    // MARK: - Answering model calls on this computer

    /// The offer's and the settings card's fixed words, decoded once from
    /// the Rust.
    ///
    /// Nil only if the export or the decode failed, and both surfaces render
    /// nothing at all in that case. An offer with a missing sentence would be
    /// an offer with the exposure paragraph missing, which is worse than no
    /// offer.
    @Published private(set) var privateInferenceCopy: PrivateInferenceCopy? =
        PrivateInferenceCopy.decode(fromJSON: TCPrivateInference.copyJSON() ?? "")

    /// The two branch tables and the interpolated sentence, all decided in
    /// the Rust. This shell owns no `switch` on this surface.
    let privateInferenceCalls = PrivateInferenceCalls(
        stateLine: { TCPrivateInference.stateLine(state: $0) },
        stateTone: { TCPrivateInference.stateTone(state: $0) },
        servingLine: { TCPrivateInference.servingLine(port: $0) },
        shouldOffer: { TCPrivateInference.shouldOffer(answered: $0, on: $1) },
        quitNeedsNotice: { TCPrivateInference.quitNeedsNotice(on: $0, state: $1) }
    )

    /// What the listener is doing, from the daemon's own report.
    ///
    /// Never nil: a daemon that has never heard of the field reads as the
    /// empty label, which the shared table answers as unreported.
    var privateInferenceState: PrivateInferenceState {
        daemonSettings?.privateInferenceState?.surfaceState
            ?? PrivateInferenceState(label: "", port: nil)
    }

    var privateInferenceQuitDetail: String? {
        PrivateInferenceSurface.quitDetail(on: daemonSettings?.privateInferenceOn ?? false,
            state: privateInferenceState, copy: privateInferenceCopy, calls: privateInferenceCalls)
    }

    /// Whether to put the offer in front of the contributor right now.
    ///
    /// Asked of the shared table on every settings read rather than latched
    /// at launch: the answer lives in the daemon, so a contributor who
    /// answered in another window has answered.
    var showsPrivateInferenceOffer: Bool {
        guard let settings = daemonSettings, privateInferenceCopy != nil else { return false }
        return PrivateInferenceSurface.shouldOffer(
            answered: settings.privateInferenceAnswered,
            on: settings.privateInferenceOn,
            calls: privateInferenceCalls
        )
    }

    @Published private(set) var privateInferenceBusy = false

    /// Both answers are written to the daemon and remembered across shells.
    func answerPrivateInferenceOffer(accepted: Bool) {
        submitPrivateInference { try $0.answerPrivateInferenceOffer(accepted: accepted) }
    }

    /// Keep the last confirmed switch while one write is in flight.
    func applyPrivateInference(_ on: Bool) {
        submitPrivateInference { try $0.setPrivateInference(on) }
    }

    private func submitPrivateInference(_ work: @escaping (DaemonClient) throws -> DaemonSettingsView) {
        guard !privateInferenceBusy else {
            objectWillChange.send()
            return
        }
        guard let client else {
            lastActionError = privateInferenceCopy?.writeUnconfirmed
            objectWillChange.send()
            return
        }
        privateInferenceBusy = true
        Task.detached(priority: .userInitiated) {
            let outcome = Result { try work(client) }
            await MainActor.run {
                self.privateInferenceBusy = false
                switch outcome {
                case .success(let settings):
                    if self.lastActionError == self.privateInferenceCopy?.writeUnconfirmed { self.lastActionError = nil }
                    self.publishIfChanged(\.daemonSettings, settings)
                case .failure:
                    self.lastActionError = self.privateInferenceCopy?.writeUnconfirmed
                }
                // Repaint the derived binding even when a failed write left
                // its confirmed value unchanged.
                self.objectWillChange.send()
            }
        }
    }

    // MARK: - The tools on this computer

    /// The branch tables and the sentences the harness list turns on, all
    /// decided in the Rust. This shell owns no `switch` over a state or an
    /// outcome, and picks none of the words either.
    let harnessCalls = HarnessCalls(
        stateCode: { TCHarness.stateCode(state: $0) },
        planOutcomeCode: { TCHarness.planOutcomeCode(outcome: $0) },
        actionAvailable: { TCHarness.actionAvailable(action: $0, installed: $1, connected: $2) },
        stateLine: { TCHarness.stateLine(state: $0) },
        lastCallLine: { TCHarness.lastCallLine(secondsAgo: $0) },
        outcomeLine: { TCHarness.outcomeLine(outcome: $0) },
        spendLine: { TCHarness.spendLine(micros: $0) }
    )

    /// The tools, as of the last read. `.none` is "nothing is known", which
    /// is what an unreadable payload and a daemon that has never heard of
    /// the call both honestly say.
    @Published private(set) var harnesses: HarnessList = .none

    /// One action at a time, and never a second while a write is in flight.
    @Published private(set) var harnessBusy = false

    /// The worked-out change, waiting to be shown. Nothing is written while
    /// this is nil, and nothing is written without it having been non-nil
    /// first: the preview is the only route to a commit.
    @Published private(set) var harnessPreview: HarnessPlan?

    /// One tool and one action, held while the exposure question is put.
    struct HarnessRequest: Equatable {
        let id: String
        let action: HarnessAction
    }

    /// The connect that is waiting on the exposure question, if any.
    @Published private(set) var harnessExposureRequest: HarnessRequest?

    /// Re-read, never cached. `connected` is a fact about a file this app
    /// does not own, and the state above it turns on a ledger that moves on
    /// its own.
    func refreshHarnesses() {
        perform("harness_list", work: { try $0.harnessList() }) {
            self.publishIfChanged(\.harnesses, $0)
        }
    }

    /// The contributor pressed the one button on a row.
    ///
    /// A connect made while nothing here answers model calls stops at the
    /// exposure question first: starting the listener opens it to everything
    /// on this machine, and that does not follow from connecting one tool.
    /// A disconnect never asks -- it only ever removes something.
    func beginHarnessAction(id: String, action: HarnessAction) {
        guard !harnessBusy, harnessPreview == nil, harnessExposureRequest == nil else { return }
        if action == .connect,
            HarnessSurface.connectNeedsExposure(
                listenerOn: daemonSettings?.privateInferenceOn ?? false)
        {
            harnessExposureRequest = HarnessRequest(id: id, action: action)
            return
        }
        planHarness(id: id, action: action)
    }

    /// The answer to that question.
    ///
    /// Declining writes the marker alone and connects nothing. Accepting
    /// turns the destination on and records the answer in one write, and
    /// only then works out the change -- which is still shown before it is
    /// made.
    func answerHarnessExposure(accepted: Bool) {
        guard let request = harnessExposureRequest else { return }
        harnessExposureRequest = nil
        guard accepted else {
            answerPrivateInferenceOffer(accepted: false)
            return
        }
        guard let client, !harnessBusy else { return }
        harnessBusy = true
        Task.detached(priority: .userInitiated) {
            let outcome = Result { () -> (DaemonSettingsView, HarnessPlan?) in
                let settings = try client.setPrivateInference(true)
                return (settings, try client.harnessPlan(id: request.id, action: request.action))
            }
            await MainActor.run {
                self.harnessBusy = false
                switch outcome {
                case .success(let (settings, plan)):
                    self.publishIfChanged(\.daemonSettings, settings)
                    self.harnessPreview = plan
                case .failure:
                    self.reportHarnessFailure()
                }
                self.refreshHarnesses()
            }
        }
    }

    /// Works the change out and shows it. Writes nothing.
    private func planHarness(id: String, action: HarnessAction) {
        guard let client else {
            reportHarnessFailure()
            return
        }
        harnessBusy = true
        Task.detached(priority: .userInitiated) {
            let outcome = Result { try client.harnessPlan(id: id, action: action) }
            await MainActor.run {
                self.harnessBusy = false
                switch outcome {
                case .success(let plan):
                    self.harnessPreview = plan
                case .failure(let error):
                    // A connect the daemon refused for want of somewhere to
                    // point the tool is the exposure question, not an error
                    // to show: the listener is off, and turning it on is a
                    // decision with words of its own.
                    if let failure = error as? DaemonClient.Failure,
                        HarnessSurface.isNoDestination(failure.message)
                    {
                        self.harnessExposureRequest = HarnessRequest(id: id, action: action)
                    } else {
                        self.reportHarnessFailure()
                    }
                }
            }
        }
    }

    /// The contributor said no to the change. The file keeps every value it
    /// has, and the plan is simply dropped -- it expires on the far side.
    func cancelHarnessPreview() {
        harnessPreview = nil
    }

    /// The contributor said yes.
    ///
    /// The only thing sent is the id the daemon minted, so what is written
    /// can only be what was shown. A plan the daemon no longer holds --
    /// expired, already committed, or a file that moved underneath it -- is
    /// reported as a change that did not happen and is NOT retried: the
    /// contributor is shown a fresh list, and a fresh preview if they ask
    /// again.
    func confirmHarnessPreview() {
        guard let plan = harnessPreview,
            HarnessSurface.canCommit(plan, calls: harnessCalls),
            let planID = plan.planID,
            let client, !harnessBusy
        else { return }
        harnessPreview = nil
        harnessBusy = true
        Task.detached(priority: .userInitiated) {
            let outcome = Result { try client.harnessCommit(planID: planID) }
            await MainActor.run {
                self.harnessBusy = false
                if case .failure = outcome { self.reportHarnessFailure() }
                self.refreshHarnesses()
            }
        }
    }

    /// One sentence for every way a change can fail to happen, and it is the
    /// payload's: the change was not confirmed, look and try again.
    private func reportHarnessFailure() {
        lastActionError = privateInferenceCopy?.writeUnconfirmed
    }

    // MARK: - The key this destination answers with

    /// The three branch tables the credential card turns on, all decided in
    /// the Rust. This shell owns no `switch` on this surface either.
    /// The four branch tables the queue's eligibility rows turn on, all
    /// decided in the Rust. This shell owns no `switch` on this surface
    /// either -- see `EligibilitySurface`.
    let eligibilityCalls = EligibilityCalls(
        stateLine: { TCContributionEligibility.stateLine(state: $0) },
        stateTone: { TCContributionEligibility.stateTone(state: $0) },
        control: { TCContributionEligibility.control(state: $0) },
        reasonLine: { TCContributionEligibility.reasonLine(reason: $0) },
        withheldLine: { TCContributionEligibility.withheldLine(withheld: $0) },
        groupControl: { TCContributionEligibility.groupControl(pending: $0, contributable: $1) }
    )

    /// The three branch tables the queue's attestation mark turns on, all
    /// decided in the Rust -- see `AttestationSurface`.
    ///
    /// Three and not four. There is no control table here, because the mark
    /// describes the trace and offers nothing to press; whether a session
    /// may be sent stays `eligibilityCalls.control`'s question.
    ///
    /// The reason closure is `TCAttestation`'s, never
    /// `TCContributionEligibility`'s. Both take the same thirteen labels and
    /// answer different sentences, so the wrong one here would compile,
    /// render, and tell a contributor their session had been refused.
    let attestationCalls = AttestationCalls(
        markLine: { TCAttestation.markLine(mark: $0) },
        markTone: { TCAttestation.markTone(mark: $0) },
        reasonLine: { TCAttestation.reasonLine(reason: $0) }
    )

    let credentialCalls = CredentialCalls(
        stateLine: { TCNearAiCredential.stateLine(state: $0) },
        stateTone: { TCNearAiCredential.stateTone(state: $0) },
        action: { TCNearAiCredential.action(state: $0) },
        harnessNotice: { TCNearAiCredential.harnessNotice(credentialed: $0) ?? "" }
    )

    let balanceCalls = BalanceCalls(
        stateLine: { TCNearAiBalance.stateLine(state: $0) },
        stateTone: { TCNearAiBalance.stateTone(state: $0) },
        action: { TCNearAiBalance.action(state: $0) },
        amount: { TCNearAiBalance.amount(present: $0, nanos: $1, scale: $2) },
        remainingLine: { TCNearAiBalance.remainingLine(present: $0, nanos: $1, scale: $2) },
        limitLine: { TCNearAiBalance.limitLine(present: $0, nanos: $1, scale: $2) },
        spentLine: { TCNearAiBalance.spentLine(present: $0, nanos: $1, scale: $2) },
        observedLine: { TCNearAiBalance.observedLine(secondsAgo: $0) }
    )

    /// What this machine holds, from the daemon's own report.
    ///
    /// Seeded as unreported rather than absent: before the first poll
    /// answers, this shell has read nothing, and "no key is kept here" is a
    /// claim about the machine that would invite a second sign-in.
    @Published private(set) var credentialStatus: CredentialStatus = .unreported

    /// What is left in the account, from the daemon's own report.
    ///
    /// Seeded as unreported for `credentialStatus`'s reason, and it matters
    /// more here: every other seed value would be a claim about somebody's
    /// money made before anything was read.
    @Published private(set) var balanceStatus: BalanceStatus = .unreported

    /// The ceremony this shell started, while it is still going.
    ///
    /// Kept because `browser_url` is served ONCE, by start, and no poll
    /// re-serves it -- and because cancel requires the attempt id, which is
    /// also only ever handed over here. Dropped when the ceremony leaves the
    /// state that has something to cancel.
    @Published private(set) var credentialAttempt: CredentialAttempt?

    @Published private(set) var credentialBusy = false

    /// Re-read on every settings refresh, and again while a ceremony is in
    /// flight: the ceremony finishes in a browser this app does not own, so
    /// nothing here is told when it does.
    func refreshNearAiCredential() {
        let attempt = credentialAttempt?.attemptID
        perform(
            CredentialSurface.statusMethod,
            work: { try $0.nearAiCredentialStatus(attemptID: attempt) }
        ) { status in
            self.publishIfChanged(\.credentialStatus, status)
            // The attempt is let go the moment the shared table stops
            // offering a cancel for it. Holding a finished attempt's id
            // would keep polling a ceremony nobody is waiting on.
            if CredentialSurface.action(status, calls: self.credentialCalls) != .cancel {
                self.credentialAttempt = nil
            }
        }
        refreshNearAiBalance()
    }

    /// Re-read whenever the key is, because it is the key the balance is
    /// read WITH: signing in, signing in again and forgetting all move this
    /// row, and a card whose two halves disagreed about whether a session
    /// exists would be worse than either half alone.
    func refreshNearAiBalance() {
        perform(
            BalanceSurface.statusMethod,
            work: { try $0.nearAiBalance() }
        ) { status in
            self.publishIfChanged(\.balanceStatus, status)
        }
    }

    func nearAiFunding(expected: FundingDestination?) async -> FundingStatus? {
        guard let client, !credentialBusy else { return nil }
        let result = await Task.detached(priority: .userInitiated) {
            try? client.nearAiFunding(expected: expected)
        }.value
        guard self.client === client, !Task.isCancelled, !credentialBusy else { return nil }
        return result
    }

    /// Begins the ceremony and hands back the one URL that was served.
    ///
    /// The URL is returned rather than opened here: opening a browser is the
    /// view's `openURL` environment, and this model has no window. A `nil`
    /// means the ceremony did not begin in a way this shell can carry
    /// through, and nothing is left half-started -- the daemon's own attempt
    /// times out on the browser.
    func startNearAiCredential(provider: String? = nil) async -> URL? {
        guard let client, !credentialBusy else { return nil }
        credentialBusy = true
        let outcome = await Task.detached(priority: .userInitiated) {
            Result { try client.nearAiCredentialStart(provider: provider) }
        }.value
        credentialBusy = false
        guard case .success(let attempt) = outcome, let attempt else {
            lastActionError = privateInferenceCopy?.writeUnconfirmed
            return nil
        }
        credentialAttempt = attempt
        refreshNearAiCredential()
        return URL(string: attempt.browserURL)
    }

    /// Stops waiting on the browser.
    ///
    /// Sent with no attempt id when this shell holds none: the daemon cancels
    /// whatever sign-in it is running, so an app restarted mid-ceremony can
    /// still stop the one it never started.
    func cancelNearAiCredential() {
        let attemptID = credentialAttempt?.attemptID
        submitNearAiCredential { try $0.nearAiCredentialCancel(attemptID: attemptID) }
    }

    /// Removes the stored key from this machine.
    func forgetNearAiCredential() {
        submitNearAiCredential { try $0.nearAiCredentialForget() }
    }

    /// One write, then a re-read of everything the key is behind.
    ///
    /// The listener and the tool list are re-read as well as the card: the
    /// key is what this destination answers with, so forgetting it moves the
    /// sentence under the switch and the connect controls too, and a card
    /// that updated alone would leave both claiming otherwise.
    ///
    /// The busy flag is cleared on BOTH outcomes. `perform` runs its
    /// continuation on success only, which would leave a failed cancel with
    /// the button disabled and no way back.
    private func submitNearAiCredential(_ work: @escaping (DaemonClient) throws -> Void) {
        guard !credentialBusy else { return }
        guard let client else {
            lastActionError = privateInferenceCopy?.writeUnconfirmed
            return
        }
        credentialBusy = true
        Task.detached(priority: .userInitiated) {
            let outcome = Result { try work(client) }
            await MainActor.run {
                self.credentialBusy = false
                if case .failure = outcome {
                    self.lastActionError = self.privateInferenceCopy?.writeUnconfirmed
                }
                self.refreshNearAiCredential()
                self.refreshSettings()
                self.refreshHarnesses()
            }
        }
    }

    // MARK: - The redaction witness

    /// The witness surface's fixed words, decoded once from the Rust.
    ///
    /// Nil only if the export or the decode failed, and the card renders
    /// nothing at all in that case, for the reason `routingCopy` gives.
    @Published private(set) var witnessCopy: WitnessCopy? = WitnessCopy.decode(
        fromJSON: TCWitness.copyJSON() ?? ""
    )

    /// What the witness is doing, as `TC_WITNESS_STATE_*`.
    ///
    /// **Nil is "nobody has asked yet", not "absent".** The config directory
    /// is not resolved until `start()` runs, and seeding this with a state
    /// would be this shell asserting something about a file it has not read.
    /// The card renders no witness sentence while it stands.
    @Published private(set) var witnessStateCode: Int32?

    /// The configuration behind that state, when it could be read.
    ///
    /// Nil is NOT "no witness" -- that is state `absent` on a successful
    /// read. It is an unenrolled device or a config that could not be read,
    /// and `witnessStateCode` is what says which.
    @Published private(set) var witnessStatus: WitnessStatus?

    /// The ABI's fixed label from the last witness read or write that
    /// refused, or nil.
    ///
    /// An operator string like `witness-pin-required`, never wording, and no
    /// sentence is built around it: that sentence would exist in this shell
    /// alone. It carries no path, no token and no trace content.
    @Published private(set) var witnessLabel: String?

    /// A witness read or write is in flight.
    @Published private(set) var witnessBusy = false

    /// The sentences and tones that are decided in Rust. This shell fills in
    /// no holes and owns no `switch`; see `TCWitness`.
    let witnessCalls = WitnessCalls(
        stateLine: { TCWitness.stateLine(state: $0) },
        stateTone: { TCWitness.stateTone(state: $0) },
        lastResultLine: { TCWitness.lastResultLine() },
        lastResultTone: { TCWitness.lastResultTone() }
    )

    /// The witness state as a case, or nil while nothing has been asked.
    ///
    /// Derived from the state code and from nothing else -- never from
    /// `witnessStatus?.url` being non-nil, which is the boolean this surface
    /// refuses to hand a shell, spelled differently.
    var witnessState: WitnessTrustState? {
        witnessStateCode.map(WitnessTrustState.fromABI)
    }

    /// Ask what the witness is doing and publish the answer.
    ///
    /// Two calls, deliberately: `tc_witness_trust_state` answers for every
    /// input, including the unenrolled and unreadable cases where the status
    /// JSON refuses. A card driven off the status alone would have nothing
    /// to say in exactly the states that matter most.
    func refreshWitness() {
        let dir = configDirectory
        guard !dir.isEmpty else { return }
        Task.detached(priority: .userInitiated) {
            let code = TCWitness.trustState(configDir: dir)
            let read = TCWitness.statusJSON(configDir: dir)
            await MainActor.run { self.publishWitness(code: code, read: read, wrote: nil) }
        }
    }

    /// Write the configuration, then re-read and publish what came back.
    ///
    /// `canConfigure` is checked here as well as in the card: an empty pin
    /// list produces a client that refuses every submission from the moment
    /// it is saved, and this shell does not make that call.
    func configureWitness(_ form: WitnessForm) {
        guard form.canConfigure, let pins = form.measurementsJSON else { return }
        let url = form.url.trimmingCharacters(in: .whitespacesAndNewlines)
        let address = form.signingAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        writeWitness { dir in
            TCWitness.configure(
                configDir: dir, url: url, signingAddress: address, measurementsJSON: pins)
        }
    }

    /// Stop using a witness, then re-read and publish what came back.
    ///
    /// This is the way out of a refusal, and it is a real change rather than
    /// a setting being switched off: later submissions carry this app's own
    /// judgement of what was left rather than a certificate. The card says
    /// so, in the Rust's words.
    func clearWitness() {
        writeWitness { TCWitness.clear(configDir: $0) }
    }

    /// Nothing is applied optimistically. The write's own answer decides
    /// only whether a refusal label is shown; what the card renders is the
    /// state and status read back afterwards.
    private func writeWitness(_ work: @escaping @Sendable (String) -> TCWitness.Outcome) {
        let dir = configDirectory
        guard !dir.isEmpty else { return }
        witnessBusy = true
        witnessLabel = nil
        Task.detached(priority: .userInitiated) {
            let wrote = work(dir)
            let code = TCWitness.trustState(configDir: dir)
            let read = TCWitness.statusJSON(configDir: dir)
            await MainActor.run {
                self.witnessBusy = false
                self.publishWitness(code: code, read: read, wrote: wrote)
            }
        }
    }

    private func publishWitness(
        code: Int32, read: TCWitness.StatusRead, wrote: TCWitness.Outcome?
    ) {
        publishIfChanged(\.witnessStateCode, code)
        var label: String?
        switch read {
        case .status(let json):
            publishIfChanged(\.witnessStatus, WitnessStatus.decode(fromJSON: json))
        case .refused(let refusalLabel):
            publishIfChanged(\.witnessStatus, nil)
            label = refusalLabel
        }
        // A refused write is the more specific answer, and the one somebody
        // just asked for, so it wins over a refused read.
        if case .refused(let writeLabel) = wrote { label = writeLabel }
        publishIfChanged(\.witnessLabel, label)
    }

    @Published private(set) var outcomeCounts: [String: Int] = [:]
    @Published private(set) var audit: [AuditEntry] = []
    @Published var undo: Undo?
    @Published var lastActionError: String?

    /// A one-line statement about something that DID happen, as opposed to
    /// `lastActionError`, which is about something that did not. Kept apart
    /// so the two never have to be told from each other by their wording.
    ///
    /// Nothing here clears it on the way to somewhere else -- only two
    /// actions ever assign it, so unlike `lastActionError` it is not
    /// overwritten by the next thing that goes wrong. Its dismiss control on
    /// the Waiting screen is therefore the only way out of it, which is why
    /// it has one: see `ActionMessageBanner`.
    @Published var lastActionNotice: String?

    private var daemon: TCDaemon?
    private var client: DaemonClient?
    private var subscription: TCSubscription?
    private var undoTask: Task<Void, Never>?

    /// Client-side bookkeeping for the daemon's bounded preview scheduler --
    /// see `PreviewRequestTracker`'s doc. Not published: nothing renders off
    /// it directly, `summaries`/`tooLarge`/`summaryErrors` are what views
    /// read.
    private var previewTracker = PreviewRequestTracker()
    /// Coalesces `preview_visible` sends against a scroll settling -- see
    /// `PreviewVisibilityCoalescer`'s doc. `visibleDebounce` is the real
    /// timer; the coalescer holds only the pure bookkeeping of what to send
    /// once it fires.
    private var visibilityCoalescer = PreviewVisibilityCoalescer()
    private var visibleDebounce: Task<Void, Never>?

    // MARK: - Derived state the shell renders

    /// What is waiting for a yes or no, and how that splits by project.
    ///
    /// Both are *stored*, recomputed only when `pending` actually changes
    /// (see `recomputeWaiting`), because both used to be computed
    /// properties that a SwiftUI body evaluated afresh every single time.
    /// `QueueContent` alone read `awaitingDecision` to test emptiness, read
    /// `decisionsOwed` for its headline, read `waitingByProject` for its
    /// group headers -- which walked `awaitingDecision` again -- and then
    /// filtered `awaitingDecision` once more *per group* to find that
    /// group's rows. At the 500-entry cap the queue runs at, that was tens
    /// of thousands of entry visits and a dozen freshly allocated arrays on
    /// the main thread for every redraw, however small the thing that
    /// prompted it. See #388.
    ///
    /// A fresh array every time also denied SwiftUI any chance of deciding
    /// a group had not changed; a stored one at least holds still.
    @Published private(set) var awaitingDecision: [QueueEntry] = []

    /// What is waiting, per project, with sizes, its own entries, and the
    /// id `submitProject` takes.
    ///
    /// Grouped by `projectID`, not `projectLabel`: a label is a display
    /// name only, not guaranteed unique across two different projects, and
    /// grouping by it here would silently merge them into one bucket with
    /// one Submit button that could approve the wrong project's entries.
    /// Order is first-seen, which is also `awaitingDecision`'s order, so
    /// this reshuffles nothing a contributor has already scanned.
    @Published private(set) var waitingByProject: [QueueGroup<QueueEntry>] = []

    /// Sessions waiting whose preview reported that no pattern fired.
    /// Drives `QueueShieldState` only, and never the badge: the count is
    /// what a contributor with 149 sessions is reading, and this is a state
    /// the count cannot carry.
    ///
    /// Stored rather than computed for the reason `awaitingDecision` is:
    /// a SwiftUI body would otherwise walk the whole waiting list on every
    /// redraw. It depends on `summaries`, which arrive asynchronously long
    /// after the queue settles, so it is recomputed from both sides --
    /// `recomputeWaiting` and `applyPreviewOutcome`.
    @Published private(set) var nothingMatchedCount: Int = 0

    /// The badge counts DECISIONS OWED -- entries actually waiting for a yes
    /// or no -- not sessions found and not queue total.
    var decisionsOwed: Int {
        awaitingDecision.count
    }

    /// The single place the two derived queue views are rebuilt. Called
    /// from `pending`'s `didSet`, so it runs when the queue moved and never
    /// when a view merely redrew.
    private func recomputeWaiting() {
        let waiting = pending.filter { $0.state == .pending }
        publishIfChanged(\.awaitingDecision, waiting)
        publishIfChanged(
            \.waitingByProject,
            QueueGrouping.groups(
                waiting,
                projectID: \.projectID,
                projectLabel: \.projectLabel,
                sizeBytes: \.sizeBytes
            )
        )
        recomputeNothingMatched()
    }

    /// How many waiting sessions have a preview that removed nothing.
    ///
    /// A session with no preview yet is NOT counted: nothing is known about
    /// it, and "nothing matched" is a report, not a default. It starts
    /// counting the moment its preview lands.
    private func recomputeNothingMatched() {
        let count = awaitingDecision.reduce(into: 0) { total, entry in
            guard let summary = summaries[entry.entryID] else { return }
            if RedactionLabels.removedTotal(summary.redactions) == 0 { total += 1 }
        }
        publishIfChanged(\.nothingMatchedCount, count)
    }

    var armedProjects: [ProjectRow] {
        projects.filter { $0.mode == .autoUpload }
    }

    var health: HealthCopy? {
        guard let label = status.health.lastErrorLabel else { return nil }
        // The budget banner says the same thing with real numbers, so the
        // bare label is suppressed when it is going to be drawn.
        if label == "daily-cap-reached" && status.dailyBudget.blocked { return nil }
        return HealthCopy.forLabel(label)
    }

    /// The spent-budget banner, when there is one.
    ///
    /// Deliberately independent of `health`. The daemon's health slot holds
    /// one label at a time and `daily-cap-reached` is last in its
    /// precedence order, so a full queue -- or any other condition -- hid
    /// the cap completely. Rendering both means the contributor sees the
    /// reason their approvals are not moving even while something else is
    /// also wrong.
    var budgetHealth: HealthCopy? {
        HealthCopy.forBudget(status.dailyBudget)
    }

    // MARK: - Lifecycle

    /// The resolved state directory, once `start()` has named one.
    ///
    /// Held so the roots screen starts the daemon against the same directory
    /// that refused, rather than re-resolving and possibly disagreeing with
    /// it.
    private(set) var configDirectory: String = ""

    var traceNavigationReady: Bool {
        guard case .running = startup else { return false }
        return status.loggedIn && isOnboardingComplete
    }

    func start() {
        guard case .starting = startup else { return }
        let resolved: DaemonHost.Resolution
        do {
            resolved = try DaemonHost.resolveConfigDirectory()
        } catch {
            startup = .refused("\(error)")
            return
        }
        start(configDirectory: resolved.path)
    }

    /// Explicit directory seam also exercises first-install startup without
    /// touching the developer's state or altering process-global environment.
    func start(configDirectory path: String) {
        guard case .starting = startup else { return }
        configDirectory = path
        startDaemon(at: path, settingsJSON: nil)
    }

    /// Start (or restart) the in-process daemon against an already-resolved
    /// state directory.
    ///
    /// `settingsJSON` is the roots screen's mechanism: the C ABI persists it
    /// and only then evaluates whether both session roots are declared, so
    /// one call both records the contributor's answer and starts the watcher.
    func startDaemon(
        at path: String,
        settingsJSON: String?,
        completion: (@MainActor @Sendable (Startup) -> Void)? = nil
    ) {
        guard daemon == nil, !daemonStartup.isStarting else { return }
        isStartingDaemon = true
        daemonStartup.start(configDirectory: path, settingsJSON: settingsJSON) { [weak self] result in
            guard let self else { return false }
            self.isStartingDaemon = false
            switch result {
            case .success(let daemon):
                self.daemon = daemon
                self.client = DaemonClient(daemon: daemon)
                self.startup = .running
                self.subscribe()
                self.refreshAll()
            case .failure(TCDaemon.TCError.rootsNotDeclared):
                self.startup = .needsRoots
            case .failure(let error):
                self.startup = .refused("\(error)")
            }
            completion?(self.startup)
            return true
        }
    }

    private func subscribe() {
        guard let daemon else { return }
        subscription = daemon.subscribe { [weak self] json in
            // Rust background thread. Nothing observable may be touched
            // here; hop first, always.
            let event = DaemonEventParser.parse(json)
            Task { @MainActor in
                self?.handle(event: event)
            }
        }
        // No `subscribe` call follows: the contract's `snapshot`-on-subscribe
        // is a property of the SOCKET connection loop, which sends it to the
        // client that just connected. `tc_subscribe` attaches to the event
        // bus directly and gets no such courtesy frame, so the first paint
        // comes from the explicit `list_pending` + `status` in refreshAll()
        // rather than from waiting on a snapshot that will never arrive.
    }

    private func handle(event: DaemonEvent) {
        switch event {
        case .snapshot(let pending, let status):
            applyPendingUpdate(pending)
            publishIfChanged(\.status, status)
        case .previewReady(let result):
            applyPreviewOutcome(result)
        case .queueChanged:
            refreshQueue()
            // `queue_depth` lives on `status`, and the daemon does not
            // publish `status_changed` for a queue change, so a status
            // fetched at launch would stay at 0 forever.
            refreshStatus()
            // A queue change is when a project can first become visible:
            // `list_projects` reports discovered projects from the queue, and
            // a session for a project nobody has ruled on is exactly what a
            // queue change delivers. Projects were fetched only by
            // `refreshAll()` at launch and after `setProjectMode`, so a
            // project discovered while the app was open stayed invisible in
            // both Settings and onboarding screen 5 until a relaunch.
            refreshProjects()
            // An entry leaving the queue -- accepted, quarantined, or
            // otherwise resolved -- is exactly the moment a new row appears
            // in history and the rollup tallies move. `refreshHistory()` was
            // reachable only from `refreshAll()` at launch, which is why the
            // History screen kept showing the counts from the moment the app
            // started no matter how many uploads finished after that: this
            // is the daemon's own signal that one just did. Both calls are
            // cheap daemon-side reads of state it already holds (no
            // recomputation, no network fan-out), so firing them on every
            // `queue_changed` costs the same as the queue/status/projects
            // refreshes right above, which already do this on every event
            // without a debounce.
            refreshHistory()
        case .statusChanged:
            refreshStatus()
            // The listener's own state moves under this, and with it whether
            // any tool has answered yet. Re-read rather than left to age.
            refreshHarnesses()
        case .digestDue(let count, let contributed, let contributedProjects, let credit, _):
            refreshQueue()
            // A digest can now be about what went out unasked, with nothing
            // waiting at all -- so this also refreshes history, which is the
            // screen those numbers came from and the one a contributor opens
            // next.
            if contributed > 0 {
                refreshHistory()
            }
            Notifier.shared.postDigest(
                pendingCount: count,
                projects: waitingByProject.map(\.label),
                contributedCount: contributed,
                contributedProjects: contributedProjects,
                creditPending: credit
            )
        case .resyncRequired, .lagged:
            refreshQueue()
            refreshStatus()
        case .unknown:
            break
        }
    }

    /// Teardown. Every user action here runs its daemon call on a detached
    /// task, so at the moment a contributor quits there can be a preview, an
    /// enrollment or a refresh sitting inside the C ABI with the raw handle.
    /// This method must not free that handle until those have left.
    ///
    /// It does not try to track those tasks itself. Tracking them here would
    /// mean tracking Swift Tasks, which can be cancelled and resumed at
    /// suspension points that have nothing to do with when the C call
    /// actually returns. The only place that knows a C call is in progress
    /// is the wrapper that makes it, so `TCDaemon.shutdown` owns the
    /// drain: it refuses new calls, waits for outstanding ones, and frees
    /// only if it can prove the handle is idle. If it cannot prove that, it
    /// leaks the handle on purpose -- see the note on `TCDaemon`.
    ///
    /// Called on the main thread (willTerminate), which is a plain thread
    /// with no tokio context, as the ABI requires. It blocks there for up to
    /// a few seconds in the bad case; that is the correct trade against
    /// freeing memory another thread is reading.
    func shutdown() {
        daemonStartup.cancel()
        isStartingDaemon = false
        undoTask?.cancel()
        let subscription = self.subscription
        let daemon = self.daemon
        // Dropped first so no new work can be started from this side while
        // teardown runs; `perform`, `enroll` and the rest all guard on
        // `client`.
        self.subscription = nil
        self.daemon = nil
        self.client = nil
        guard let daemon else { return }
        if case .leaked(let reason) = daemon.shutdown(unsubscribing: subscription) {
            // A fixed label, no path or token, per this repo's logging rule.
            // The handle stayed allocated on purpose; the process is exiting.
            lastActionError = "shutdown: handle-leaked-\(reason)"
        }
    }

    // MARK: - Publishing

    /// Assign to a `@Published` property only when the value actually
    /// differs.
    ///
    /// Every refresher below re-fetches from the daemon and writes the
    /// decoded answer straight back. A freshly decoded array is a *new*
    /// value even when it is byte-identical to the one already held, so a
    /// plain assignment fires `objectWillChange` regardless -- and one
    /// `objectWillChange` invalidates every view observing this model,
    /// which at 500 queue rows is a full view-graph rebuild on the main
    /// thread. A single `queue_changed` event runs four refreshers and so
    /// used to publish five or six of them back to back for a queue that
    /// had not moved.
    ///
    /// Comparing first turns "the daemon answered" into "the answer
    /// changed", which is the thing a view actually needs to redraw for.
    /// Every model written through here is `Equatable`, and the compare is
    /// over a few hundred small structs -- orders of magnitude cheaper than
    /// the rebuild it avoids.
    private func publishIfChanged<T: Equatable>(
        _ keyPath: ReferenceWritableKeyPath<AppModel, T>,
        _ value: T
    ) {
        guard self[keyPath: keyPath] != value else { return }
        self[keyPath: keyPath] = value
    }

    // MARK: - Refresh

    func refreshAll() {
        refreshStatus()
        refreshQueue()
        refreshHistory()
        refreshProjects()
        refreshSettings()
        refreshConsentOptions()
        refreshOutcomeCounts()
        refreshAudit()
        refreshPublicProfile()
        refreshHarnesses()
        refreshNearAiCredential()
    }

    /// The local change log. Refreshed alongside everything else at launch,
    /// and again after each call that APPENDS to it -- arming a project,
    /// changing consent scopes, acknowledging the NEAR AI notice -- because
    /// the daemon publishes no event for an audit append, so a list fetched
    /// once would show a contributor everything except the change they just
    /// made.
    func refreshAudit() {
        perform("list_audit", work: { try $0.listAudit() }) { self.publishIfChanged(\.audit, $0) }
    }

    func refreshStatus() {
        perform("status", work: { try $0.status() }) { self.publishIfChanged(\.status, $0) }
    }

    func refreshQueue() {
        perform("list_pending", work: { try $0.listPending() }) { entries in
            self.applyPendingUpdate(entries)
        }
    }

    func refreshHistory() {
        perform("list_history", work: { try $0.listHistory() }) {
            self.publishIfChanged(\.history, $0)
        }
        perform("history_rollup", work: { try $0.historyRollup() }) {
            self.publishIfChanged(\.rollup, $0)
        }
    }

    func refreshProjects() {
        perform("list_projects", work: { try $0.listProjects() }) { self.publishIfChanged(\.projects, $0) }
        refreshArmingOffer()
    }

    /// The daemon decides whether there is an offer and what it says; this
    /// only carries the answer. The rule -- how many contributions, which
    /// modes qualify, how long "Not now" lasts -- is
    /// `ProjectPolicy::arming_suggestion`, in one place, so the three shells
    /// cannot drift into offering different things.
    func refreshArmingOffer() {
        perform("arming_suggestion", work: { try $0.armingSuggestion() }) {
            self.publishIfChanged(\.armingOffer, $0)
        }
    }

    /// Arms the offered project. The offer clears because the daemon's next
    /// answer will not include an armed project, but it is cleared here too
    /// so the card does not linger for a round trip.
    func acceptArmingOffer(_ offer: ArmingOffer) {
        perform(
            "set_project_mode",
            work: { try $0.setProjectMode(projectID: offer.projectId, mode: .autoUpload) }
        ) { _ in
            self.armingOffer = nil
            self.refreshProjects()
            self.refreshAudit()
        }
    }

    /// "Not now". Silenced for thirty days by the daemon, not forgotten --
    /// and persisted there rather than here, so it survives a relaunch and
    /// applies to whichever shell asks next.
    func declineArmingOffer(_ offer: ArmingOffer) {
        perform("decline_arming", work: { try $0.declineArming(projectID: offer.projectId) }) { _ in
            self.armingOffer = nil
        }
    }

    /// Sets `project`'s mode via the daemon and refreshes `projects` from
    /// the daemon's own answer on success. Deliberately does not flip
    /// `project.mode` optimistically: the whole reason this method exists
    /// is that a UI that assumes a choice landed, when it did not, is worse
    /// than a UI that offers no choice at all. A failure lands in
    /// `lastActionError`, same as every other action here, and the caller
    /// must leave its own state alone until this succeeds.
    ///
    /// Named by `project.projectId`, the opaque id `list_projects` mints for
    /// every row. This used to send `projectLabel` as a `project_key`, which
    /// is a final path segment rather than a key and was refused with
    /// `project-key-unrecognized`.
    func setProjectMode(_ project: ProjectRow, mode: ProjectMode) {
        perform(
            "set_project_mode",
            work: { try $0.setProjectMode(projectID: project.projectId, mode: mode) }
        ) { _ in
            self.refreshProjects()
            // Arming or disarming a project is one of the changes the daemon
            // records; see `refreshAudit`.
            self.refreshAudit()
        }
    }

    /// Decline a whole project from the Waiting screen.
    ///
    /// The daemon clears what that project has waiting as part of setting the
    /// mode, so this refreshes the queue as well as the project list -- the
    /// cards are expected to disappear in the same round trip.
    ///
    /// `promised` is the count the confirmation named, which had to be read
    /// off this shell's own queue before the call. The daemon's `purged` is
    /// the authority: the queue is live, and a poll or an approval between
    /// the render and the click moves it. When the two disagree the
    /// contributor is told rather than left to notice -- see
    /// `ProjectIgnoreCopy.reconciliation`.
    func ignoreProject(id projectID: String, label: String, promised: Int) {
        perform(
            "set_project_mode",
            work: { try $0.setProjectMode(projectID: projectID, mode: .ignore) }
        ) { purged in
            self.lastActionNotice = ProjectIgnoreCopy.reconciliation(
                project: label,
                promised: promised,
                purged: purged
            )
            self.refreshQueue()
            self.refreshProjects()
            self.refreshAudit()
        }
    }

    func refreshSettings() {
        perform("get_settings", work: { try $0.settings() }) { self.publishIfChanged(\.daemonSettings, $0) }
    }

    /// The declaration the daemon is holding, as the card's three controls.
    ///
    /// The port shows the conventional number when nothing is declared.
    /// That is display only: `RoutingSurface.settingsParams` writes nothing
    /// while the switch is off, so a default nobody chose never becomes an
    /// announcement that a local service is in use.
    ///
    /// A discovered port fills the field only where nothing is declared.
    /// The contributor's own port always wins -- see
    /// `RoutingForm.fromDeclaration`.
    var routingForm: RoutingForm {
        RoutingForm.fromDeclaration(
            mode: daemonSettings?.ironwire?.mode,
            port: daemonSettings?.ironwire?.port,
            tokenDir: daemonSettings?.ironwire?.tokenDir,
            discoveredPort: routingDiscovery.port
        )
    }

    /// Ask what the machine already knows, and show it.
    ///
    /// **This writes nothing and reads nothing of the contributor's.** It
    /// reads one file IronWire left, learns a port from it, and puts that
    /// port in a field. Declaring is still the switch and the button; a
    /// discovery that declared on its own would be this window announcing a
    /// local service nobody mentioned, which is the whole thing the
    /// declaration exists to stop.
    ///
    /// A machine without IronWire is not a failure and produces no error
    /// state: the answer is `found: false`, and a call that did not run at
    /// all degrades to the same thing, because both mean there is nothing
    /// to offer.
    func discoverRouting() {
        guard let client else { return }
        Task.detached(priority: .userInitiated) {
            let discovery = (try? client.discoverRouting()) ?? .none
            await MainActor.run { self.routingDiscovery = discovery }
        }
    }

    /// Changes one source's declaration on the running daemon -- Settings'
    /// "Watched folders", the after-first-run counterpart of the roots
    /// screen's start-with-settings.
    ///
    /// Nothing is applied optimistically: the rows read the daemon's
    /// answer, which `set_settings` returns in full, and an undecided
    /// choice is never sent. A failed confirmation requests fresh settings.
    func setSourceRoot(_ kind: SourceKind, _ choice: SourceChoice) async -> Bool {
        guard let params = choice.settingsParams(for: kind), let client else { return false }
        let result = await Task.detached(priority: .userInitiated) {
            Result { try client.setSettings(params) }
        }.value
        switch result {
        case .success(let settings):
            daemonSettings = settings
            return true
        case .failure:
            // A lost response does not prove the write failed. Read back the
            // authoritative modes, and never retain the requested path.
            if let confirmed = await Task.detached(operation: { try? client.settings() }).value {
                daemonSettings = confirmed
            }
            return false
        }
    }

    /// Write the declaration, then -- when it is on -- ask what was found.
    ///
    /// The evidence is dropped before the write, not after the answer: the
    /// words have to stop asserting the moment the declaration changes, not
    /// once a replacement arrives. Nothing here asks anybody to restart the
    /// app; the daemon rebuilds its reader in the same call.
    ///
    /// The probes run only from here -- a contributor pressing the switch or
    /// the button. Nothing on the submission path calls them.
    func applyIronWire(_ form: RoutingForm) {
        routingEvidence = nil
        routingProbeLine = nil
        routingChecking = form.on
        perform("set_settings", work: { try $0.setIronWire(form) }) { view in
            self.publishIfChanged(\.daemonSettings, view)
            guard form.on else {
                self.routingChecking = false
                return
            }
            self.checkRouting(form)
        }
        if !form.on { routingChecking = false }
    }

    /// Ask whether the proxy answers, and say what it answered.
    private func checkRouting(_ form: RoutingForm) {
        guard let client else { return }
        Task.detached(priority: .userInitiated) {
            let outcome = try? client.probeRouting(form)
            let evidence = try? client.probeRoutedTools(form)
            await MainActor.run {
                self.routingChecking = false
                // A call that did not run is not a fact about the proxy.
                // `.unknown` is the outcome that claims nothing, and it is
                // what a refused call degrades to here.
                guard let copy = self.routingCopy else { return }
                self.routingProbeLine = RoutingSurface.probeLine(
                    outcome ?? .unknown, copy: copy, calls: self.routingCalls
                )
                self.routingEvidence = evidence
            }
        }
    }

    /// Refresh the per-tool words without touching the declaration, and say
    /// what the answer was.
    ///
    /// Called when the card appears, and only while something is declared:
    /// asking about a proxy nobody mentioned would be the probe of an
    /// undeclared local service that the declaration exists to prevent.
    ///
    /// The sentence is set from the same answer, which is what the Windows
    /// shell does when its settings card loads with a proxy declared.
    /// Without it, opening Settings against a declared proxy that is not
    /// running painted four "not known" rows and no sentence: the reason
    /// was in this answer's outcome and was thrown away, and only a button
    /// press could put it on screen. No second call is made for it -- the
    /// tool-list answer this already asks for carries the outcome.
    func refreshRoutedTools() {
        let form = routingForm
        guard form.on, let client else { return }
        Task.detached(priority: .userInitiated) {
            let evidence = try? client.probeRoutedTools(form)
            await MainActor.run {
                // Left as it was when the call did not run: a stale answer
                // is replaced by a new one, never by a blank -- and a
                // sentence about a call that did not happen is not a fact
                // about the proxy, so none is written either.
                guard let evidence else { return }
                self.routingEvidence = evidence
                guard let copy = self.routingCopy else { return }
                self.routingProbeLine = RoutingSurface.probeLine(
                    evidence.outcome, copy: copy, calls: self.routingCalls
                )
            }
        }
    }

    // MARK: - Enrollment

    enum EnrollOutcome {
        case succeeded(EnrollResult)
        /// Deliberately carries no message. The daemon's `enroll` only ever
        /// reports the generic `unavailable` / `enroll-failed` for this
        /// path -- see `DaemonClient.enroll` -- so there is nothing more
        /// specific a caller could show even if this case carried a string.
        case failed
    }

    /// Redeems `invite` for enrollment. Bypasses the `perform` helper (and
    /// its `lastActionError` label) on purpose: that helper renders
    /// `failure.message`, and `enroll`'s failure message must never reach a
    /// screen -- `OnboardingConnectView` renders one fixed sentence for
    /// every failure of this call instead.
    /// What a preparation did, and the words the daemon chose for it.
    ///
    /// This used to return `AdmissionPreparation?` through `try?`, which threw
    /// the refusal away: the bridge now carries the daemon's sentence on the
    /// `Failure` it raises, and `try?` discarded the whole error to get a
    /// `nil` the view could only answer with one generic line. Sixteen causes
    /// arrived here and left as the same sentence.
    ///
    /// The success sentence comes from the same `view`, so both outcomes are
    /// the daemon's words rather than this shell's.
    func prepareAdmissionSession(entryID: String, backend: String) async -> AdmissionOutcome {
        guard let client else { return AdmissionOutcome(succeeded: false, sentence: nil) }
        return await Task.detached(priority: .userInitiated) {
            AppModel.admissionOutcome(from: client, entryID: entryID, backend: backend)
        }.value
    }

    /// The whole decision, so the detached task above holds none of it.
    ///
    /// Split out because `client` is private and a test cannot reach this
    /// arm through the model: without it the only reachable path is the
    /// no-client guard, and dropping the daemon's sentence again would stay
    /// green. Takes the client so a test can hand it one over a recording
    /// transport and cross the real bridge and the real decode.
    nonisolated static func admissionOutcome(
        from client: DaemonClient,
        entryID: String,
        backend: String
    ) -> AdmissionOutcome {
        do {
            let prepared = try client.prepareAdmissionSession(entryID: entryID, backend: backend)
            return AdmissionOutcome(
                succeeded: prepared.view?.ready == true,
                sentence: prepared.view?.message
            )
        } catch {
            return AdmissionOutcome(
                succeeded: false,
                sentence: DaemonClient.refusalSentence(from: error)
            )
        }
    }

    func nativeWalletFlow(action: String, flowID: String, commons: String, account: String) async -> NativeWalletView? {
        guard let client else { return nil }
        return await Task.detached { try? client.nativeWalletFlow(action: action, flowID: flowID, commons: commons, account: account) }.value
    }
    /// Join with the NEAR AI login, reporting the daemon's own control name.
    ///
    /// The label is passed back untouched for `TCNearAiEnroll` to turn into a
    /// sentence. This model does not know which of the ten refusals it is and
    /// must not guess: a shell-side table would be an eleventh that agrees
    /// with the shared one until it does not.
    func nearAiAccountEnroll(commons: String) async -> NearAiEnrollOutcome {
        guard let client else { return .refused("near_ai_enroll_unavailable") }
        return await Task.detached(priority: .userInitiated) { () -> NearAiEnrollOutcome in
            do {
                return .joined(try client.nearAiAccountEnroll(commons: commons))
            } catch let failure as DaemonClient.Failure {
                // `message` is the daemon's control name -- the enrolment
                // handler answers a label and nothing else, because the
                // errors underneath can quote a remote body or a URL. Empty
                // falls back to the generic label rather than to a blank.
                return .refused(
                    failure.message.isEmpty ? "near_ai_enroll_unavailable" : failure.message)
            } catch {
                return .refused("near_ai_enroll_unavailable")
            }
        }.value
    }

    func enroll(invite: String, scopes: [String] = []) async -> EnrollOutcome {
        guard let client else { return .failed }
        return await Task.detached(priority: .userInitiated) { () -> EnrollOutcome in
            do {
                return .succeeded(try client.enroll(invite: invite, scopes: scopes))
            } catch {
                return .failed
            }
        }.value
    }

    /// Records that the NEAR AI first-use notice was shown, and clears the
    /// health label that otherwise keeps the daemon refusing that filter.
    /// Refreshes settings and status afterward so `nearAIConfigured` /
    /// `health` reflect the daemon's own post-acknowledgment state rather
    /// than an assumption made here.
    func acknowledgeNearAINotice() {
        perform(
            "acknowledge_near_ai_notice",
            work: { try $0.acknowledgeNearAINotice() }
        ) { _ in
            self.refreshSettings()
            self.refreshStatus()
            self.refreshAudit()
        }
    }

    func refreshConsentOptions() {
        perform("consent_options", work: { try $0.consentOptions() }) {
            self.publishIfChanged(\.consentScopes, $0)
        }
    }

    enum SetScopesOutcome: Equatable {
        case succeeded([String])
        /// Deliberately carries no message, matching `EnrollOutcome.failed`:
        /// `set_consent_scopes` only reports `not-logged-in` (this call
        /// only ever runs after `enroll` already succeeded, so that should
        /// not be reachable) or a local config-write failure, neither of
        /// which is more actionable to a contributor than a flat retry.
        case failed
    }

    /// Applies the consent scopes chosen on `ConsentScopesView`. Bypasses
    /// `perform` (like `enroll`) so the onboarding coordinator can await the
    /// outcome and only advance past the consent screen once the daemon has
    /// actually recorded the choice -- see the coordinator's ordering note
    /// on why this call, not `enroll`, is what applies scopes in this app's
    /// flow.
    func setConsentScopes(_ scopes: [String]) async -> SetScopesOutcome {
        guard let client else { return .failed }
        let outcome: SetScopesOutcome = await Task.detached(priority: .userInitiated) {
            do {
                return .succeeded(try client.setConsentScopes(scopes))
            } catch {
                return .failed
            }
        }.value
        if case .succeeded(let confirmed) = outcome {
            status.consentScopes = confirmed
            refreshStatus()
            refreshAudit()
        } else if let confirmed = await Task.detached(operation: { try? client.status() }).value {
            publishIfChanged(\.status, confirmed)
        }
        return outcome
    }

    @Published private(set) var inferenceEvidenceBusy = false
    @Published private(set) var inferenceEvidenceSaveFailed = false

    func setInferenceEvidence(_ enabled: Bool, disclosureConfirmed: Bool = false) async {
        guard !inferenceEvidenceBusy else { return }
        inferenceEvidenceSaveFailed = false
        guard let client else {
            daemonSettings?.ironwireAttestedBodies = nil
            inferenceEvidenceSaveFailed = true
            return
        }
        inferenceEvidenceBusy = true
        defer { inferenceEvidenceBusy = false }
        let result = await Task.detached(priority: .userInitiated) {
            Result { try client.setInferenceEvidence(enabled, disclosureConfirmed: disclosureConfirmed) }
        }.value
        switch result {
        case .success(let settings):
            daemonSettings = settings
            refreshAudit()
        case .failure:
            if let confirmed = await Task.detached(operation: { try? client.settings() }).value {
                daemonSettings = confirmed
            }
            inferenceEvidenceSaveFailed = true
        }
    }

    @Published private(set) var tokenStorageNotice = ""
    func setLocalTokenCapture(_ enabled: Bool) async {
        guard !tokenContributionBusy, let client else { return }
        tokenContributionBusy = true
        tokenStorageNotice = ""
        defer { tokenContributionBusy = false }
        let result = await Task.detached(priority: .userInitiated) {
            Result { try client.setSettings(["token_capture_enabled": enabled]) }
        }.value
        switch result {
        case .success(let settings): daemonSettings = settings
        case .failure: tokenStorageNotice = daemonSettings?.tokenStorage?.failureLine ?? ""
        }
    }
    func cleanTokenStorage(discard: Bool) async {
        guard !tokenContributionBusy, let client else { return }
        tokenContributionBusy = true
        tokenStorageNotice = ""
        defer { tokenContributionBusy = false }
        let result = await Task.detached(priority: .userInitiated) {
            Result { try client.tokenStorageAction(discard: discard) }
        }.value
        switch result {
        case .success(let status): daemonSettings?.tokenStorage = status
        case .failure: tokenStorageNotice = daemonSettings?.tokenStorage?.failureLine ?? ""
        }
    }

    @Published private(set) var tokenContributionBusy = false
    @Published private(set) var tokenContributionSaveFailed = false

    func setTokenContribution(_ enabled: Bool, disclosureConfirmed: Bool = false) async {
        guard !tokenContributionBusy else { return }
        tokenContributionSaveFailed = false
        guard let client else {
            daemonSettings?.tokenDistributionsContribution = nil
            tokenContributionSaveFailed = true
            return
        }
        tokenContributionBusy = true
        defer { tokenContributionBusy = false }
        let result = await Task.detached(priority: .userInitiated) {
            Result { try client.setTokenContribution(enabled, disclosureConfirmed: disclosureConfirmed) }
        }.value
        switch result {
        case .success(let settings):
            daemonSettings = settings
            refreshAudit()
        case .failure:
            if let confirmed = await Task.detached(operation: { try? client.settings() }).value {
                daemonSettings = confirmed
            }
            tokenContributionSaveFailed = true
        }
    }

    // MARK: - Onboarding resume

    /// Whether onboarding has been walked to the end (the Done screen) for
    /// the *currently enrolled* device. Keyed off `status.tenantID` rather
    /// than a single global flag: `enroll` alone flips `status.loggedIn` to
    /// true (it happens on screen 2, before consent is even chosen on
    /// screen 3), so `loggedIn` cannot by itself distinguish "fully
    /// onboarded" from "enrolled but consent was never confirmed." A
    /// contributor who quit mid-flow must come back to the rest of
    /// onboarding, not straight to the main window with whatever scopes
    /// `enroll`'s floor-only default happened to leave in place -- see the
    /// coordinator's atomicity note.
    var requiresOnboarding: Bool {
        startup == .needsRoots || !status.loggedIn || !isOnboardingComplete
    }

    var isOnboardingComplete: Bool {
        guard let tenantID = status.tenantID else { return false }
        return UserDefaults.standard.bool(forKey: Self.onboardingCompleteKey(tenantID))
    }

    /// `isOnboardingComplete` is computed from `UserDefaults`, not from a
    /// `@Published` property, so writing the key changes nothing SwiftUI is
    /// watching. Without the explicit `objectWillChange`, pressing Done
    /// updated the marker and left the contributor sitting on the Done
    /// screen until some *unrelated* published value happened to change --
    /// and `publishIfChanged` exists precisely to stop that from happening,
    /// so on a quiet daemon it never did. Do not remove this send without
    /// making the marker itself observable.
    func markOnboardingComplete() {
        guard let tenantID = status.tenantID else {
            // No tenant to key the marker to yet: the button must not be
            // inert. Re-ask the daemon so the next press has one.
            refreshStatus()
            return
        }
        objectWillChange.send()
        UserDefaults.standard.set(true, forKey: Self.onboardingCompleteKey(tenantID))
    }

    #if DEBUG
    /// Test seam: `status` is `private(set)` and otherwise only ever set
    /// from a live daemon reply, so there is no other way to exercise the
    /// tenant-keyed onboarding marker without a running daemon and a real
    /// enrolment. Debug-only, and deliberately routed through
    /// `publishIfChanged` so a test observes exactly what the app does.
    func setClientForTesting(_ client: DaemonClient) {
        self.client = client
    }
    func setDaemonSettingsForTesting(_ settings: DaemonSettingsView) { publishIfChanged(\.daemonSettings, settings) }
    func setStartupForTesting(_ startup: Startup) { self.startup = startup }

    func setStatusForTesting(_ status: DaemonStatus) {
        publishIfChanged(\.status, status)
    }
    #endif

    private static func onboardingCompleteKey(_ tenantID: String) -> String {
        "trace_commons.onboarding_complete.\(tenantID)"
    }

    func refreshOutcomeCounts() {
        perform("queue_outcome_counts", work: { try $0.queueOutcomeCounts() }) {
            self.publishIfChanged(\.outcomeCounts, $0)
        }
    }

    // MARK: - Preview scheduling

    /// Reconciles `pending` against a fresh list from the daemon (a
    /// `snapshot` event, `refreshQueue`, or any other refetch), and does the
    /// one thing a change in that list requires beyond updating `pending`
    /// itself: cancel the scheduled preview for anything that left it for
    /// good (approved, dismissed, expired, superseded -- `dismiss` also
    /// cancels its own preview server-side, but a cancel for an id the
    /// daemon already dropped is a defined no-op, not an error).
    ///
    /// Deliberately does **not** loop over the fresh list requesting a
    /// preview for everything newly waiting -- that was this method's shape
    /// before #353/#357 made the queue's row list a `LazyVStack`. Doing so
    /// here would mean asking the daemon about all 500 entries the instant
    /// a snapshot arrives, which defeats the point of realizing rows lazily
    /// in the first place: `QueueRow.onAppear` drives `requestPreview(for:)`
    /// for whatever the viewport actually realizes, so this stays
    /// proportional to what is on screen.
    ///
    /// Internal rather than private so a test can land a snapshot and watch
    /// what a view holding this model would see. `pending` is
    /// `@Published private(set)` and there is no other way in; the
    /// eligibility gate on an open preview sheet reads `awaitingDecision`,
    /// which only a snapshot moves, so a test that cannot deliver one
    /// cannot prove the sheet re-reads it.
    func applyPendingUpdate(_ entries: [QueueEntry]) {
        let previousIDs = Set(pending.map(\.entryID))
        publishIfChanged(\.pending, entries)
        let currentIDs = Set(entries.map(\.entryID))
        let vanished = previousIDs.subtracting(currentIDs)
        if !vanished.isEmpty {
            previewTracker.forget(vanished)
            for id in vanished {
                summaries[id] = nil
                summaryErrors[id] = nil
                tooLarge[id] = nil
                cancelPreview(id)
            }
        }
    }

    /// One `preview_request` per card, requirement 1 of the scheduler
    /// design: draw a pending card immediately ("Reading it locally...",
    /// see `QueueRow`) and never block waiting for the daemon's answer.
    ///
    /// Called from `QueueRow.onAppear` -- the same trigger #357 introduced
    /// as `requestSummary(for:)`, kept here under the scheduler's name
    /// because what changed is not when a row asks, only what happens once
    /// it does: this goes through the daemon's bounded preview scheduler
    /// (two workers, dedup, a cache, an admission cap) instead of the
    /// client-side `ConcurrencyLimiter` #357 added. Only one bound should
    /// own this work -- the daemon is the one that can see the total across
    /// all three shells (and, later, the approve and upload paths too), so
    /// `ConcurrencyLimiter` is not used here; see its own doc for whether it
    /// still has a reason to exist.
    ///
    /// `previewTracker` is #357's `requestingSummaries` in-flight set,
    /// generalized to the scheduler's five states rather than a plain
    /// "is a call running" flag -- it is what keeps a `LazyVStack` row
    /// recycled during a fast scroll from resending `preview_request` while
    /// the daemon still has the job `queued`/`running`.
    func requestPreview(for entry: QueueEntry) {
        guard let client else { return }
        let id = entry.entryID
        guard summaries[id] == nil,
            summaryErrors[id] == nil,
            tooLarge[id] == nil,
            previewTracker.shouldRequest(id)
        else { return }
        previewTracker.markRequested(id)
        Task.detached(priority: .utility) {
            let outcome = Result { try client.requestPreview(entryID: id) }
            await MainActor.run {
                switch outcome {
                case .success(let result):
                    self.applyPreviewOutcome(result)
                case .failure(let error):
                    self.previewTracker.apply(state: .failed, to: id)
                    self.summaryErrors[id] = (error as? DaemonClient.Failure)?.message
                        ?? "preview-request-failed"
                }
            }
        }
    }

    /// Applies one preview outcome, wherever it arrived from: the immediate
    /// response to `preview_request` (a cache hit, a refusal, or "it's
    /// queued/running now") or the later `preview_ready` event (requirement
    /// 2 of the scheduler design). `queued`/`running` leave every dictionary
    /// alone -- the card keeps reading "Reading it locally..." -- and only
    /// update `previewTracker` so a redundant request is not sent while one
    /// is already in flight.
    private func applyPreviewOutcome(_ result: PreviewRequestResult) {
        previewTracker.apply(state: result.state, to: result.entryID)
        switch result.state {
        case .queued, .running:
            break
        case .ready:
            if let summary = result.summary, summaries[result.entryID] != summary {
                summaries[result.entryID] = summary
                recomputeNothingMatched()
            }
        case .tooLarge:
            let refusal = PreviewTooLarge(
                rawSessionBytes: result.rawSessionBytes ?? 0,
                limitBytes: result.limitBytes ?? 0
            )
            if tooLarge[result.entryID] != refusal {
                tooLarge[result.entryID] = refusal
            }
        case .failed:
            let label = result.label ?? "preview-failed"
            if summaryErrors[result.entryID] != label {
                summaryErrors[result.entryID] = label
            }
        }
    }

    /// Drops a scheduled preview -- requirement 4: sent when a card is
    /// dismissed or leaves the list for good (`applyPendingUpdate` above),
    /// never on every scroll. Fire-and-forget: a `dropped: false` reply is a
    /// defined no-op by contract, and there is nothing actionable to do with
    /// a failure here either way.
    private func cancelPreview(_ entryID: String) {
        guard let client else { return }
        Task.detached(priority: .utility) {
            _ = try? client.cancelPreview(entryID: entryID)
        }
    }

    /// Called by a row's `onAppear`/`onDisappear` with what is currently on
    /// screen. Requirement 3: `preview_visible` decides preview *order*, is
    /// cheap and idempotent, but is meant to be sent once a scroll settles,
    /// not once per frame -- so this only records the change with
    /// `visibilityCoalescer` and (re)starts a debounce timer, cancelling
    /// whatever timer was already waiting. A fast scroll through many rows
    /// therefore produces one send, of whatever was on screen when it
    /// stopped, not one send per row that crossed the viewport.
    func setPreviewVisible(_ entryIDs: Set<String>) {
        visibilityCoalescer.setVisible(entryIDs)
        visibleDebounce?.cancel()
        visibleDebounce = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 250_000_000)
            guard !Task.isCancelled else { return }
            self?.flushVisiblePreviews()
        }
    }

    private func flushVisiblePreviews() {
        guard let client, let ids = visibilityCoalescer.takePendingSend() else { return }
        let idList = Array(ids)
        Task.detached(priority: .utility) {
            _ = try? client.setVisiblePreviews(entryIDs: idList)
        }
    }

    // MARK: - Decisions

    /// One click, one session. Builds and pins the envelope if it was never
    /// previewed, approves, then raises the toast -- see
    /// `docs/superpowers/specs/2026-08-20-one-click-submit-design.md`. This
    /// is also what the preview sheet's `Contribute` button calls: a preview
    /// only means the pin already exists, not a different daemon call.
    ///
    /// `verdict` is the contributor's optional answer to the outcome
    /// question. It defaults to none, and none is sent as an absent
    /// parameter rather than an empty one -- see
    /// `DaemonClient.approveParams`.
    /// `correction` is what the contributor wrote in the correction box.
    /// Blank or absent sends no key, and the call is then exactly the one
    /// this model made before the box existed.
    ///
    /// `completion` reports whether the daemon refused the submission
    /// because the correction contains something credential-shaped. That
    /// refusal gets no toast: the sheet is still on screen, still holding
    /// the text, and shows its own message instead -- see
    /// `CorrectionCopy.credentialHeadline`. Every other outcome toasts as
    /// before and reports `false`.
    func approve(
        _ entry: QueueEntry,
        verdict: ContributorVerdict? = nil,
        correction: String? = nil,
        completion: ((Bool) -> Void)? = nil
    ) {
        // THE PRESS DECIDES WHAT IS SENT. The queue card draws its Submit
        // only for a row the shared table offers one for, and its rows come
        // from `awaitingDecision` so they are never stale -- but the tap
        // still lands after the render that drew the button, and a snapshot
        // can arrive in between. Asked here rather than in the view so
        // every route to a single approval goes through it.
        //
        // A refusal is silent on purpose: the row is about to repaint
        // without its button and with the sentence saying why, which is the
        // answer. An error banner would name a failure that did not happen.
        guard EligibilitySurface.mayProceed(
            entry, in: awaitingDecision, id: \.entryID,
            eligibility: { $0.contributionEligibility }, calls: eligibilityCalls)
        else {
            completion?(false)
            return
        }
        perform("approve", work: {
            try $0.approve(entryID: entry.entryID, verdict: verdict, correction: correction)
        }) { response in
            self.refreshQueue()
            if response.wasRefusedForACorrectionCredential {
                completion?(true)
                return
            }
            self.showToast(for: response, attempted: [entry.entryID])
            completion?(false)
        }
    }

    /// One click, one project: approves every entry `waitingByProject` is
    /// currently showing for `projectID`, which must be the id `entry_value`
    /// publishes (`QueueEntry.projectID`) -- the daemon refuses a label
    /// here. An id naming no project the daemon knows throws a `Failure`
    /// (`bad_params` / `project-id-unrecognized`) that `perform` reports as
    /// `lastActionError`, never as a skip.
    ///
    /// `verdict` applies to every entry the approval covers. The plain
    /// `Submit all` passes none; `Submit all as...` is the opt-in path that
    /// passes one.
    ///
    /// **A GROUP-LEVEL SUBMIT MEANS "ALL ELIGIBLE", NEVER "ALL", AND THE
    /// DAEMON ENFORCES THAT.** Both group selectors act only on entries whose
    /// eligibility is `eligible`, and report how many they left out as
    /// `excluded_ineligible`. This shell used to fan the call out into one
    /// `entry_id` approval per eligible entry and merge the responses; it
    /// does not any more, because a per-project approve has no row to check
    /// and no shell can close that gap from outside. One call, one approval
    /// instant, one hold that covers every entry it took.
    func submitProject(id projectID: String, verdict: ContributorVerdict? = nil) {
        // The ids this shell believes the call covers, for the undo path
        // only. The daemon decides what it actually takes, and its
        // `excluded_ineligible` says how many it did not -- neither is
        // recovered by filtering here.
        let attempted = EligibilitySurface.contributable(
            awaitingDecision.filter { $0.projectID == projectID },
            eligibility: { $0.contributionEligibility }, calls: eligibilityCalls
        ).map(\.entryID)
        perform("approve", work: {
            try $0.approve(projectID: projectID, verdict: verdict)
        }) { response in
            self.refreshQueue()
            self.showToast(for: response, attempted: attempted)
            // What became of the rest, from the daemon's own count and the
            // shared sentence. NEVER BRANCHED ON HERE: the table answers the
            // empty string for zero and for the absence, so a filter that
            // ran and took everything, and one that never ran, both draw
            // nothing without this code knowing which it was.
            // `clamping`, not `Int64(...)`: the field is unsigned on the
            // wire and a plain conversion TRAPS above `Int64.max` rather
            // than wrapping. No honest daemon sends that, which is exactly
            // why it would be a crash nobody had thought about.
            let withheld = Int64(clamping: response.excludedIneligible ?? 0)
            let sentence = self.eligibilityCalls.withheldLine(withheld) ?? ""
            self.lastActionNotice = sentence.isEmpty ? nil : sentence
        }
    }

    /// Renders `response` as the toast and, when it offers one, starts the
    /// recovery affordance behind it.
    ///
    /// `attempted` is the set of ids the caller asked the daemon to approve
    /// -- `response.approved` is only a count, so `ApproveResponse
    /// .approvedEntryIDs` is what recovers which of `attempted` actually
    /// went through, and that recovered set is what Undo drives `cancel`
    /// with.
    private func showToast(for response: ApproveResponse, attempted: [String]) {
        undoTask?.cancel()
        let toast = response.toast
        let approvedIDs = response.approvedEntryIDs(attempted: attempted)
        let startedAt = Date()
        undo = Undo(
            entryIDs: approvedIDs,
            toastLine: toast.line,
            offerUndo: toast.offerUndo,
            approvedAt: startedAt,
            heldSeconds: 0
        )
        guard toast.offerUndo else {
            // Nothing to count up toward -- the toast still needs to be
            // seen, but there is no recovery window behind it.
            return
        }
        undoTask = Task { @MainActor in
            for second in 1...Undo.tickCeiling {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                if Task.isCancelled { return }
                guard var current = undo, current.approvedAt == startedAt else { return }
                current.heldSeconds = second
                undo = current
            }
            // The counter stops; the affordance stays. Only `undoApproval`
            // and `dismissUndo` clear it.
        }
    }

    /// Put the recovery affordance away without cancelling anything. The
    /// contributor is saying "yes, send it", which is the choice they already
    /// made -- so this touches the daemon not at all.
    func dismissUndo() {
        undoTask?.cancel()
        undo = nil
    }

    /// Undo, and be honest when it is too late.
    ///
    /// `cancel` takes one entry at a time and only works while that entry is
    /// still `approved` -- the daemon's uploader can pick an approved entry
    /// up immediately, observed in the self-test, where the entry had
    /// already moved to `failed` before the five seconds elapsed -- so any
    /// one of `undo.entryIDs` can lose the race independently of the rest.
    /// This drives `cancel` once per id and reports honestly if any of them
    /// were too late, rather than claiming a clean undo that some entries
    /// did not get.
    func undoApproval() {
        guard let undo, undo.offerUndo else { return }
        undoTask?.cancel()
        let ids = undo.entryIDs
        self.undo = nil
        guard let client else { return }
        Task.detached(priority: .userInitiated) {
            let tooLate = ids.reduce(into: 0) { count, id in
                let outcome = Result { try client.cancel(entryID: id) }
                if case .failure = outcome { count += 1 }
            }
            await MainActor.run {
                if tooLate == ids.count, ids.count == 1 {
                    self.lastActionError = "Too late to undo -- this one had already left "
                        + "the waiting list. History shows what happened to it."
                } else if tooLate > 0 {
                    self.lastActionError = "Too late to undo \(tooLate) of \(ids.count) -- "
                        + "they had already left the waiting list. History shows what "
                        + "happened to them."
                }
                self.refreshQueue()
                self.refreshHistory()
            }
        }
    }

    func dismiss(_ entry: QueueEntry) {
        perform("dismiss", work: { try $0.dismiss(entryID: entry.entryID) }) { _ in
            self.refreshQueue()
            self.refreshOutcomeCounts()
        }
    }

    // MARK: - Public profile

    /// What the last claim or withdrawal did.
    ///
    /// `published` and `left` both carry `cached`, which is the daemon's
    /// `handle_persisted` and is **not** whether the call worked. By the
    /// time that flag exists the server has already accepted the change, so
    /// both of those cases are successes; `cached == false` only means this
    /// device failed to write its local copy, and the sentence for it says
    /// so without retracting the public fact. Reporting that as `refused`
    /// would tell a contributor their handle is private when it is public.
    enum ProfileOutcome: Equatable {
        case published(cached: Bool)
        case left(cached: Bool)
        /// The daemon or the server refused. Carries the daemon's fixed
        /// label, which by contract is never a path, a token, or a response
        /// body.
        case refused(String)
        /// A refused withdrawal, which needs its own sentence: after one,
        /// the handle is still published.
        case leaveRefused(String)
    }

    /// The cached profile, or `nil` for "not on the roster". `nil` is also
    /// what an unenrolled device gets, which is correct: it has claimed
    /// nothing.
    @Published private(set) var publicProfile: DaemonClient.PublicProfile?
    @Published private(set) var profileOutcome: ProfileOutcome?
    @Published private(set) var profileBusy = false

    func refreshPublicProfile() {
        guard let client else { return }
        Task.detached(priority: .userInitiated) {
            let outcome = try? client.publicProfile()
            await MainActor.run {
                // A failure -- `not-logged-in` above all -- is the
                // off-the-roster state, not an error worth a banner.
                self.publicProfile = (outcome?.onRoster ?? false) ? outcome : nil
            }
        }
    }

    /// Claims or updates the public handle.
    ///
    /// Bypasses `perform` for the same reason `withdraw` does: that helper
    /// funnels every failure into `lastActionError` as a bare label, and a
    /// label is not a sentence a contributor can act on when the thing that
    /// was refused is the handle they just typed.
    ///
    /// The profile is taken from the daemon's own answer rather than from
    /// what was sent: the handle it stored is the validated display form,
    /// which is trimmed, and the roster date is the server's.
    func claimHandle(_ handle: String, bio: String) {
        guard let client, !profileBusy else { return }
        profileBusy = true
        profileOutcome = nil
        let trimmedBio = bio.trimmingCharacters(in: .whitespacesAndNewlines)
        // An empty box means "no bio", explicitly. The PUT replaces the
        // whole profile, so there is no "leave it alone" to express.
        let bioParam: String? = trimmedBio.isEmpty ? nil : trimmedBio
        Task.detached(priority: .userInitiated) {
            let result = Result { try client.setPublicProfile(handle: handle, bio: bioParam) }
            await MainActor.run {
                self.profileBusy = false
                switch result {
                case .success(let profile):
                    self.publicProfile = profile.onRoster ? profile : nil
                    // A build that did not report the flag is treated as
                    // having persisted: the alternative is warning about a
                    // cache miss that may not have happened, on a profile
                    // that is public either way.
                    self.profileOutcome = .published(cached: profile.handlePersisted ?? true)
                    self.refreshStatus()
                    self.refreshAudit()
                case .failure(let error):
                    let label = (error as? DaemonClient.Failure)?.message ?? "profile-update-failed"
                    self.profileOutcome = .refused(label)
                }
            }
        }
    }

    /// Withdraws the public handle from the roster.
    func leaveRoster() {
        guard let client, !profileBusy else { return }
        profileBusy = true
        profileOutcome = nil
        Task.detached(priority: .userInitiated) {
            let result = Result { try client.clearPublicProfile() }
            await MainActor.run {
                self.profileBusy = false
                switch result {
                case .success(let profile):
                    self.publicProfile = profile.onRoster ? profile : nil
                    self.profileOutcome = .left(cached: profile.handlePersisted ?? true)
                    self.refreshStatus()
                    self.refreshAudit()
                case .failure(let error):
                    let label = (error as? DaemonClient.Failure)?.message
                        ?? "profile-withdraw-failed"
                    self.profileOutcome = .leaveRefused(label)
                }
            }
        }
    }

    func clearProfileOutcome() {
        profileOutcome = nil
    }

    // MARK: - Withdrawal

    /// What a withdrawal attempt did, kept per submission so the row that
    /// was acted on can say it rather than a screen-level banner saying it
    /// about nothing in particular.
    enum WithdrawalResult: Equatable {
        /// The server withdrew it, and reported this tier. `nil` reach means
        /// the daemon sent a label this build does not know -- which is
        /// reported as not-knowable, never smoothed into the mild answer.
        case withdrawn(WithdrawalReach?, String? = nil)
        /// The daemon has no account session, so the request was never made.
        case noAccountSession
        /// Anything else. Carries the daemon's fixed label, which by
        /// contract is never a path, a token, or a response body.
        case failed(String)
    }

    @Published private(set) var withdrawals: [String: WithdrawalResult] = [:]
    @Published private(set) var withdrawing: Set<String> = []

    /// Withdraws one trace.
    ///
    /// Bypasses `perform` deliberately, like `enroll` does. That helper
    /// funnels every failure into `lastActionError` as `"withdraw:
    /// account-session-required"`, and the two things wrong with that here
    /// are that the label is not a sentence anybody can act on, and that a
    /// screen-level error next to a row that still says "In the commons"
    /// leaves it genuinely ambiguous whether the trace was withdrawn. Both
    /// outcomes are recorded against the submission instead, and the view
    /// states them in words on that row.
    ///
    /// On success the daemon has already updated its own history cache, so
    /// `refreshHistory` is what turns the row over to `withdrawn` -- the
    /// status is re-read rather than assumed here.
    func withdraw(_ record: HistoryRecord) {
        guard let client else { return }
        let id = record.submissionID
        guard !withdrawing.contains(id) else { return }
        withdrawing.insert(id)
        withdrawals[id] = nil
        Task.detached(priority: .userInitiated) {
            let outcome = Result { try client.withdraw(submissionID: id) }
            await MainActor.run {
                self.withdrawing.remove(id)
                switch outcome {
                case .success(let value):
                    self.withdrawals[id] = .withdrawn(value.distributionReach, value.tokenDeletionNote)
                    self.refreshHistory()
                case .failure(let error):
                    let label = (error as? DaemonClient.Failure)?.message ?? "withdraw-failed"
                    self.withdrawals[id] = label == "account-session-required"
                        ? .noAccountSession
                        : .failed(label)
                }
            }
        }
    }

    // MARK: - Pause

    func pause(until: Date?) {
        perform("pause", work: { try $0.pause(until: until) }) { _ in self.refreshStatus() }
    }

    func resume() {
        perform("resume", work: { try $0.resume() }) { _ in self.refreshStatus() }
    }

    // MARK: - Preview body

    /// How many times `needle` appears in an entry's pre-redaction session,
    /// or nil when that could not be checked.
    ///
    /// Synchronous: the ABI call scans an already-parsed session and returns
    /// a count, with no redaction pass to block on.
    func searchOriginal(entryID: String, needle: String) -> Int? {
        client?.searchOriginal(entryID: entryID, needle: needle)
    }

    /// Opens the in-process preview off the main actor -- the redaction pass
    /// blocks -- and hands the open handle back on the main actor.
    func supportsWitnessReview() async -> Bool {
        guard let client else { return false }
        return await Task.detached { (try? client.supportsWitnessReview()) == true }.value
    }

    func requestWitnessReview(entryID: String) async -> Bool {
        await witnessReviewOutcome(entryID: entryID).succeeded
    }

    /// A refused review and the sentence the daemon chose for it.
    ///
    /// The `Bool` above is kept for callers that only need to know whether to
    /// reload. This one is for the sheet, which has to say *why*: before it,
    /// every refusal -- a receipt the reviewer declined, a reviewer that was
    /// simply down, one that could not prove itself -- rendered the same
    /// single sentence.
    func witnessReviewOutcome(entryID: String) async -> WitnessReviewOutcome {
        guard let client else { return WitnessReviewOutcome(succeeded: false, sentence: nil) }
        return await Task.detached(priority: .userInitiated) {
            do {
                try client.requestWitnessReview(entryID: entryID)
                return WitnessReviewOutcome(succeeded: true, sentence: nil)
            } catch {
                return WitnessReviewOutcome(
                    succeeded: false,
                    sentence: DaemonClient.refusalSentence(from: error)
                )
            }
        }.value
    }

    func openPreview(entryID: String) async -> PreviewOutcome {
        guard let client else { return .failed("the watcher isn't running") }
        return await Task.detached(priority: .userInitiated) { () -> PreviewOutcome in
            do {
                return .opened(try client.openPreview(entryID: entryID))
            } catch {
                return .failed("\(error)")
            }
        }.value
    }

    /// Opens a real preview for the first waiting entry, runs a real search
    /// over the redacted body, and hands back everything the sheet needs to
    /// be rendered without its own async load. Used by the screenshot hook.
    /// A wholly synthetic preview for the screenshot hook.
    ///
    /// This used to open a REAL queued entry and hand its redacted body to
    /// `PreviewSheet`, which was then rasterized to a PNG in a directory the
    /// caller named. That put trace content in a durable file outside the
    /// protected state directory. The preview exemption covers showing
    /// redacted content to the contributor who owns the entry -- it does not
    /// cover writing it to an arbitrary path, and "we only ever point this at
    /// fixtures" is a property of how it is invoked, not of the code.
    ///
    /// The screenshots exist to show what the UI looks like, and a fabricated
    /// transcript does that just as well. Nothing here reads the queue.
    func loadCaptureSample(needle: String) async -> (QueueEntry, PreviewSheet.Preloaded)? {
        let transcript = """
            user: Add a retry to the Northwind billing sync -- it drops the \
            batch when the upstream 503s.

            assistant: I will wrap the call in a bounded retry. The credential \
            was scrubbed from this transcript: [REDACTED:aws_secret_key]

            tool: edit billing/sync.rs
            """
        let summary = PreviewSummary(
            wouldSendBytes: 4160,
            rawSessionBytes: 1615,
            eventCount: 3,
            openingPrompt: "Add a retry to the Northwind billing sync",
            redactions: ["aws_secret_key": 1, "local_path": 3],
            redactionsDistinct: ["aws_secret_key": 1, "local_path": 2],
            piiLabelsPresent: ["email"],
            consentScopes: ["debugging_evaluation"],
            residualRisk: "pattern-based"
        )
        let entry = QueueEntry(
            entryID: "entry_screenshot_fixture",
            sessionHash: "sha256:0000000000000000",
            source: "claude-code",
            declaredSource: nil,
            projectID: "project_screenshot_fixture",
            projectLabel: "northwind-billing",
            projectPath: "~/code/northwind-billing",
            sessionPath: nil,
            sizeBytes: 1615,
            discoveredAt: Date(timeIntervalSince1970: 1_770_000_000),
            state: .pending,
            reasonLabel: nil,
            attempts: 0,
            // A single-file conversation: no delegated transcripts, none
            // dropped, so the card's extent line is absent and the capture
            // shows exactly what it showed before these fields existed.
            subagentCount: 0,
            subagentsDropped: 0,
            // The screenshot fixture stands for an invited contributor: no
            // eligibility field, so the capture shows the card exactly as it
            // looked before this surface existed.
            eligibility: nil,
            eligibilityReason: nil,
            // The same invited contributor still gets a mark: an attested
            // session, which is the state the capture is meant to show.
            attestation: "attested",
            attestationReason: nil,
            // The capture shows a session a certificate is held for, which
            // is the state the certificate-held list is drawn from.
            holdsCertificateRaw: true
        )
        var offsets: [Int] = []
        if !needle.isEmpty {
            var searchRange = transcript.startIndex..<transcript.endIndex
            while let found = transcript.range(of: needle, range: searchRange) {
                offsets.append(transcript.distance(from: transcript.startIndex, to: found.lowerBound))
                searchRange = found.upperBound..<transcript.endIndex
            }
        }
        return (
            entry,
            PreviewSheet.Preloaded(
                summary: summary,
                transcript: transcript,
                needle: needle,
                offsets: offsets
            )
        )
    }

    /// What a preparation did, and the words for it either way.
    ///
    /// The mirror of [`WitnessReviewOutcome`], for the same reason: a `Bool`
    /// cannot carry why.
    struct AdmissionOutcome: Sendable {
        let succeeded: Bool
        /// The daemon's classified sentence, or `nil` when it sent none and
        /// the caller should keep its own fallback.
        let sentence: String?
    }

    /// What a witness review did, and the words for it when it refused.
    struct WitnessReviewOutcome: Sendable {
        let succeeded: Bool
        /// The daemon's classified sentence, or `nil` when it sent none and
        /// the caller should keep its own fallback.
        let sentence: String?
    }

    enum PreviewOutcome {
        case opened(TCPreview)
        /// A fixed label from the ABI, safe to show: it never carries a
        /// path, a token, or trace content.
        case failed(String)
    }

    // MARK: - Plumbing

    private func perform<T>(
        _ label: String,
        work: @escaping (DaemonClient) throws -> T,
        onSuccess: @escaping (T) -> Void
    ) {
        guard let client else { return }
        Task.detached(priority: .userInitiated) {
            let outcome = Result { try work(client) }
            await MainActor.run {
                switch outcome {
                case .success(let value):
                    onSuccess(value)
                case .failure(let error):
                    // `error.message` is a fixed label by contract, never a
                    // path, a token, or a server response body.
                    if let failure = error as? DaemonClient.Failure {
                        self.lastActionError = "\(label): \(failure.message)"
                    } else {
                        self.lastActionError = "\(label): failed"
                    }
                }
            }
        }
    }
}
