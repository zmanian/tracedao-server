import AppKit
import SwiftUI
import TCBridge
import TCShellCore
import TCUpdates
import UserNotifications

/// What this machine is doing, and what permissions traces carry.
///
/// The consent list comes from `consent_options`, never hardcoded, and
/// nothing optional is pre-checked. `public_attribution` is visually
/// separated because it grants no data use at all.
///
/// Layout follows `design-import/DESIGN-SPEC.md` §5.4 (`1d`): the standard
/// macOS content padding (`18 22 22`), an 18pt gap between sections, and a
/// prose column kept deliberately narrow. §5.4 is truncated in the imported
/// source -- it ends mid-attribute just after the Startup section -- so only
/// the Connection and Startup sections have drawn geometry to follow. The
/// consent list, "Watching" and "Projects" keep the treatment they already
/// had, expressed in tokens; nothing has been invented to fill the gap.
///
/// The public-profile block below (§5.6) and the go-public dialog (§5.7) are
/// rendered in the community brand rather than in `TC`. That seam is the
/// point: per §7.3 the black frame is the exact boundary of what becomes
/// public. See `CommunityBrand` for why those values are not `TC` tokens.
struct SettingsView: View {
    /// The window's selection, so the model-calls pointer below can hand the
    /// contributor to the destination that now owns that switch. Optional
    /// because `DebugScreenshot` renders this content outside the window and
    /// has no selection to hand it; the pointer draws either way and does
    /// nothing when there is nowhere to go.
    var navigation: MainWindowNavigation?

    var body: some View {
        ScrollView {
            SettingsContent(navigation: navigation)
        }
        .tcScreen()
    }
}

/// The screen's content, split out of its `ScrollView` for the same reason
/// `QueueContent` and `ConsentScopesContent` are: `ImageRenderer` renders a
/// `ScrollView` as blank, so the screenshot hook can only rasterize what
/// lives outside one -- and the local change log at the foot of this screen
/// is a surface that has to be looked at to be checked.
struct SettingsContent: View {
    /// See `SettingsView.navigation`.
    var navigation: MainWindowNavigation?

    @EnvironmentObject private var model: AppModel
    @ObservedObject private var updates = UpdateController.shared

    // Read fresh on appear rather than cached across the view's lifetime:
    // the user can flip this in System Settings -> General -> Login Items
    // while this window is open, and a value captured once at init would
    // then claim a state that is no longer true. See `LoginItemManager`.
    @State private var loginItemState: LoginItemManager.State = LoginItemManager.currentState
    @State private var loginItemActionError: String?
    /// Nil until the system has answered, and nil for good where there is
    /// no notification centre to ask; the section renders nothing then.
    @State private var notificationStatus: UNAuthorizationStatus?
    @State private var notificationRequestPending = false
    @State private var showingGoPublic = false
    @State private var showingTokenDisclosure = false
    @State private var showingTokenDiscard = false
    @State private var showingTokenCapture = false
    @State private var showingInferenceDisclosure = false
    /// The panel's two editable fields. Seeded from the daemon's answer --
    /// see `seedProfileDraft` -- rather than bound straight to it, so a
    /// background refresh cannot rewrite what is being typed.
    @State private var handleDraft = ""
    @State private var bioDraft = ""
    /// The routing card's three controls, held here rather than bound to
    /// the daemon's answer.
    ///
    /// Seeded from the declaration on appear and after a write, for the same
    /// reason the profile fields are: a background refresh landing mid-edit
    /// would otherwise replace a half-typed port with the declared one.
    /// `nil` means nothing has been edited, and the card reads the
    /// daemon's answer -- which is what lets a port discovery supplies
    /// after this view appeared reach the field at all. A draft seeded
    /// eagerly on appear would freeze the conventional number in place
    /// before `discover_routing` had answered.
    @State private var routingDraft: RoutingForm?

    /// Whether the port and folder are open, once the contributor has said.
    ///
    /// `nil` is "they have not said", and then the disclosure follows what
    /// discovery found: closed where the machine already supplied the port,
    /// open where the only way to answer is to type it. A contributor who
    /// opens or closes it is obeyed from then on.
    @State private var routingOverrideOpen: Bool?

    /// The witness card's three fields, held here rather than bound to what
    /// the ABI answered.
    ///
    /// Seeded from the status on first edit, for the reason `routingDraft`
    /// is: a refresh landing mid-edit would otherwise replace a half-typed
    /// address. `nil` means nothing has been edited, and the fields read
    /// what came back from the last write -- which is what lets a
    /// configuration written by the CLI reach these fields at all.
    @State private var witnessDraft: WitnessForm?

    /// The project a contributor has asked to arm, held while the
    /// confirmation is on screen. Nil means no sheet. It is the row and not
    /// a bool because the sheet names the project, and a bool would leave
    /// the name to be looked up from a selection that has already moved.
    @State private var armingCandidate: ProjectRow?

    /// The consent list's one failure line, and whether a write is in
    /// flight. The rows read the daemon's own answer, so there is no draft
    /// to hold here -- only the refusal, until the next press clears it.
    @State private var consentSaveError: String?
    @State private var consentBusy = false

    /// Discovery candidates are suggestions, never the configured path.
    /// The daemon reports modes only; Settings therefore displays modes.
    @State private var sourceCandidates: [SourceCandidate] = []
    @State private var sourceBusy = false
    @State private var sourceSaveFailed = false

    /// Spec §5.4: the Settings content column is `max-width:520px` ("prose
    /// column, kept narrow on purpose"), narrower than the 660 that
    /// `TC.Measure.prose` carries for onboarding. There is no token for it,
    /// so it is stated here rather than widening a shared one.
    private static let proseColumn: CGFloat = 520

    var body: some View {
        // Spec §5.4 gap: 18 between sections (`TC.Space.lg`), not the
        // 28 this screen used before.
        VStack(alignment: .leading, spacing: TC.Space.lg) {
            connection
            loginItem
            notifications
            updatesSection
            consent
            publicProfile
            watching
            watchedFolders
            routing
            privateInference
            witness
            projects
            audit
        }
        .padding(.top, TC.Space.Content.top)
        .padding(.horizontal, TC.Space.Content.horizontal)
        .padding(.bottom, TC.Space.Content.bottom)
        .tcColumn(Self.proseColumn)
        .onAppear {
            loginItemState = LoginItemManager.currentState
            // Same reason the login-item state is read fresh here: the log
            // can have grown since launch (the CLI writes to it too), and
            // the daemon publishes no event when it does.
            model.refreshAudit()
        }
        .task { notificationStatus = await Notifier.shared.authorizationStatus() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { notificationStatus = await Notifier.shared.authorizationStatus() }
        }
        .sheet(isPresented: $showingGoPublic) {
            // Handed the model explicitly rather than relying on the sheet
            // inheriting it: the dialog now makes a daemon call, and an
            // environment object it did not get would be a crash on the one
            // button that matters.
            GoPublicDialog(onDismiss: { showingGoPublic = false })
                .environmentObject(model)
        }
    }

    // MARK: - Connection (spec §5.4)

    private var connection: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            TCSectionHeader(title: "Connection")
            if model.status.loggedIn {
                TCTag(text: "Connected", tone: .clear, symbol: "link")
            } else {
                VStack(alignment: .leading, spacing: TC.Space.xs) {
                    TCTag(text: "Not connected", tone: .attention, symbol: "link.badge.plus")
                    Text("Sessions are being queued, but nothing can be sent.")
                        .font(TC.Font_.meta)
                        .foregroundStyle(.secondary)
                }
            }
            if let settings = model.daemonSettings {
                // No path and no credential: the contract keeps both off the
                // wire, and this view has nowhere to put one even if it were
                // sent it. The two session rows are driven by the MODE --
                // `*_root_configured` is `mode == "watch"` and cannot tell
                // "not declared" from "declared off".
                // All four sources the roots screen offers, not the two
                // the app started with: a Gemini CLI or Cline folder a
                // contributor declared was watched with no row here saying
                // so.
                sourceCheckRow(TCSourceChecks.claude, settings.routingSourceModes.claude)
                sourceCheckRow(TCSourceChecks.codex, settings.routingSourceModes.codex)
                sourceCheckRow(TCSourceChecks.gemini, settings.routingSourceModes.gemini)
                sourceCheckRow(TCSourceChecks.cline, settings.routingSourceModes.cline)
                checkRow("Extra privacy scan configured", settings.nearAIConfigured)
            }
        }
    }

    // MARK: - Startup (spec §5.4)

    /// Reflects the live `SMAppService.mainApp.status`, not a locally cached
    /// bool -- see `loginItemState`'s doc comment. `.requiresApproval` is
    /// rendered as guidance, not an error: it is the normal result of the
    /// user not yet approving the app in System Settings, or having denied
    /// it there, and retrying `register()` again would not change that.
    private var loginItem: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            TCSectionHeader(title: "Startup")
            switch loginItemState {
            case .enabled:
                startupToggle(isOn: Binding(
                    get: { true },
                    set: { newValue in if !newValue { setLoginItem(enabled: false) } }
                ))
            case .notRegistered, .notFound:
                startupToggle(isOn: Binding(
                    get: { false },
                    set: { newValue in if newValue { setLoginItem(enabled: true) } }
                ))
            case .requiresApproval:
                Text("Waiting on approval in System Settings.")
                    .font(TC.Font_.body)
                Text("""
                Turn it on in System Settings -> General -> Login Items to let \
                Trace Commons start automatically.
                """)
                .font(TC.Font_.caption)
                .foregroundStyle(.secondary)
            }
            if let loginItemActionError {
                Text(loginItemActionError)
                    .font(TC.Font_.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Spec §6.8 draws this as a hand-built 34x20 track with a 16x16 knob,
    /// filled `#178F70` when on. The system switch tinted with the same green
    /// is that drawing, at the platform's own metrics, and it keeps the
    /// keyboard and VoiceOver behaviour a hand-drawn track would have to
    /// re-earn -- which is the same rule `DesignSystem.swift` states for the
    /// rest of the window chrome.
    private func startupToggle(isOn: Binding<Bool>) -> some View {
        Toggle("Start Trace Commons when you log in", isOn: isOn)
            .toggleStyle(.switch)
            .tint(TC.green)
            .font(TC.Font_.body)
    }

    private func setLoginItem(enabled: Bool) {
        loginItemActionError = nil
        if enabled {
            switch LoginItemManager.register() {
            case .enabled, .requiresApproval:
                break
            case .failed(let message):
                loginItemActionError = "Couldn't turn this on: \(message)"
            }
        } else {
            if case .failed(let message) = LoginItemManager.unregister() {
                loginItemActionError = "Couldn't turn this off: \(message)"
            }
        }
        loginItemState = LoginItemManager.currentState
    }

    // MARK: - Notifications

    /// Where the system stands on this app's notifications, read fresh on
    /// appear for the same reason the login-item state is. Nothing is
    /// rendered where there is no notification centre (a bare `swift run`
    /// binary has no bundle identifier), and a denial is not an error: it
    /// says where to change the answer, because this app cannot re-ask
    /// once the system has been told no.
    @ViewBuilder
    private var notifications: some View {
        if let status = notificationStatus {
            VStack(alignment: .leading, spacing: TC.Space.sm) {
                TCSectionHeader(title: Notifier.copy?.notificationHeading ?? "")
                Text(Notifier.purpose)
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                switch status {
                case .authorized, .provisional, .ephemeral:
                    checkRow(Notifier.copy?.notificationAllowed ?? "", true)
                case .denied:
                    checkRow(Notifier.copy?.notificationDenied ?? "", false)
                    Link(Notifier.copy?.systemSettings ?? "", destination: Notifier.systemSettingsURL)
                        .font(TC.Font_.body)
                case .notDetermined:
                    checkRow(Notifier.copy?.notificationNotAsked ?? "", false)
                    Button(Notifier.copy?.notificationAllow ?? "") {
                        guard !notificationRequestPending else { return }
                        notificationRequestPending = true
                        Task {
                            defer { notificationRequestPending = false }
                            _ = await Notifier.shared.requestAuthorization()
                            notificationStatus = await Notifier.shared.authorizationStatus()
                        }
                    }
                    .buttonStyle(.bordered)
                    .disabled(notificationRequestPending)
                @unknown default:
                    Text(Notifier.copy?.notificationUnknown ?? "")
                    Link(Notifier.copy?.systemSettings ?? "", destination: Notifier.systemSettingsURL)
                }
            }
        }
    }

    // MARK: - Updates

    /// Version, update state, and -- when Homebrew owns this copy -- the one
    /// command that actually works.
    ///
    /// The Homebrew branch is not an apology for a missing feature. Homebrew
    /// placed these bytes and Homebrew replaces them; an app that offered a
    /// "Check Now" button here would be offering to fight the package
    /// manager over the same file.
    private var updatesSection: some View {
        VStack(alignment: .leading, spacing: TC.Space.m) {
            TCSectionHeader(title: "Updates")

            HStack(spacing: TC.Space.s) {
                TCFieldLabel("Version")
                Text(updates.currentVersion)
                    .font(TC.Font_.ledger)
                    .textSelection(.enabled)
            }

            switch updates.mode {
            case .selfUpdating:
                TCTag(text: "Checks daily", tone: .clear, symbol: "arrow.triangle.2.circlepath")
                Text(lastCheckSentence)
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
                // Deliberately does NOT claim the download already happened.
                // With SUAutomaticallyUpdate false, Sparkle's stock driver
                // finds the update in the background and then asks; the
                // download follows the yes. Copy that promised an
                // already-downloaded update would be describing a
                // configuration this app does not ship.
                Text("""
                    Trace Commons checks for updates automatically and asks before installing.
                    """)
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Check Now") { updates.checkNow() }
                    .buttonStyle(.bordered)
                    .disabled(!updates.canCheckNow)

            case .managedByHomebrew(let command):
                TCTag(text: "Updates managed by Homebrew", tone: .held, symbol: "shippingbox")
                Text("""
                    Homebrew installed this copy, so Homebrew replaces it. Run \
                    this in a terminal:
                    """)
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: TC.Space.s) {
                    Text(command)
                        .font(TC.Font_.ledger)
                        .textSelection(.enabled)
                        .padding(TC.Space.s)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .tcCard()
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(command, forType: .string)
                    }
                    .buttonStyle(.bordered)
                }

            case .disabled(let reason):
                TCTag(text: "Updates unavailable", tone: .refused, symbol: "arrow.down.circle")
                Text(disabledSentence(reason))
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var lastCheckSentence: String {
        guard let date = updates.lastCheckDate else {
            return "Not checked yet on this machine."
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return "Last checked \(formatter.localizedString(for: date, relativeTo: Date()))."
    }

    /// Turns the policy's stable label into a sentence. The label itself is
    /// what gets logged; this is what a person reads.
    private func disabledSentence(_ reason: String) -> String {
        switch reason {
        case UpdatePolicy.noFeedReason:
            return """
                This build has no update feed configured, so it will not look \
                for new versions. Development builds are like this. Install \
                from a release DMG to receive updates.
                """
        case UpdatePolicy.insecureFeedReason:
            return """
                This build's update feed is not HTTPS, so it has been refused. \
                Reinstall from a release DMG.
                """
        default:
            return "Updates are turned off for this build."
        }
    }

    // MARK: - Consent

    /// Scopes that grant no data use at all -- keyed off the daemon's
    /// `grants_data_use`, never off a scope name. This is the group the
    /// design calls "List my handle publicly": being on it is attribution
    /// and nothing more, which is why it is separated from the real
    /// data-use scopes and why the public-profile panel keys off it.
    private var creditScopes: [ConsentScope] {
        model.consentScopes.filter { !$0.alwaysOn && !$0.grantsDataUse }
    }

    // Whether this contributor is on the roster used to be inferred from
    // the granted scope list. It is now read from `get_public_profile`,
    // which is the only thing that knows: `public_attribution` is a
    // permission to be listed, and claiming a handle is the separate act
    // that actually puts a row on the roster.

    private var consent: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            TCSectionHeader(title: "How may your traces be used?")
            Text("Applies to traces you send from now on.")
                .font(TC.Font_.meta)
                .foregroundStyle(.secondary)

            let granted = Set(model.status.consentScopes)
            let alwaysOn = model.consentScopes.filter(\.alwaysOn)
            let optional = model.consentScopes.filter { !$0.alwaysOn && $0.grantsDataUse }

            if !alwaysOn.isEmpty {
                TCFieldLabel("Always included")
                ForEach(alwaysOn) { scope in
                    scopeRow(scope, checked: true, alwaysOn: true)
                }
            }
            if !optional.isEmpty {
                TCFieldLabel("Optional — each one lets your traces do more")
                ForEach(optional) { scope in
                    scopeRow(scope, checked: granted.contains(scope.name), alwaysOn: false)
                }
            }
            if !creditScopes.isEmpty {
                // Visually separated: it grants no data use at all, and
                // listing it beside four real scopes misleads both ways.
                TCFieldLabel("Credit")
                ForEach(creditScopes) { scope in
                    scopeRow(scope, checked: granted.contains(scope.name), alwaysOn: false)
                }
                // The door into the community-brand surface used to be
                // here, gated on this scope list. It has moved to the
                // public-profile section below, because the roster is not
                // what this list describes: the daemon deliberately does
                // not pre-check `consent_scopes` before a claim -- the
                // local list can be narrower than what the credential
                // carries, and refusing here would refuse contributors the
                // server would have allowed.
            }
            if let consentSaveError {
                Label(consentSaveError, systemImage: TC.Tone.refused.symbol)
                    .font(TC.Font_.caption)
                    .foregroundStyle(TC.coralText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Nothing here is pre-selected on your behalf.")
                .font(TC.Font_.caption)
                .foregroundStyle(.secondary)
        }
    }

    /// One scope, as a row that can be ticked.
    ///
    /// The tick reflects `status.consent_scopes` -- what the daemon reports
    /// is in force -- never a local copy of it, so nothing optional can
    /// show as granted that the daemon does not hold. A press writes the
    /// whole list back through `set_consent_scopes` and the row follows the
    /// daemon's answer; a refusal is one line above, with the tick
    /// unchanged. The footnote this replaced said changing permissions
    /// needed an account this build did not set up, which had stopped
    /// being true the day onboarding enrolled one.
    private func scopeRow(_ scope: ConsentScope, checked: Bool, alwaysOn: Bool) -> some View {
        Button {
            guard !alwaysOn else { return }
            setScope(scope, granted: !checked)
        } label: {
            HStack(alignment: .top, spacing: TC.Space.m) {
                TCReadGateCheckbox(checked: checked)
                VStack(alignment: .leading, spacing: TC.Space.xxs) {
                    HStack(spacing: TC.Space.s) {
                        Text(ScopeCopy.title(for: scope.name, options: model.consentScopes))
                            .font(TC.Font_.cardTitle)
                        if alwaysOn {
                            TCTag(text: "always on", tone: .clear, symbol: "lock")
                        }
                    }
                    Text(scope.description)
                        .font(TC.Font_.body)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(TC.Space.m)
            .frame(maxWidth: .infinity, alignment: .leading)
            .tcCard()
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(alwaysOn || consentBusy || !model.status.loggedIn)
        // `TCReadGateCheckbox` is drawn, and drawn shapes are hidden from
        // VoiceOver, so without this a scope announces its title and
        // description with no indication of whether it is granted. The row
        // becomes one element carrying that answer, which is the same shape
        // `ConsentScopesView` gives its own rows.
        .accessibilityElement(children: .combine)
        .accessibilityValue(checked ? "Granted" : "Not granted")
        .accessibilityAddTraits(checked ? [.isSelected] : [])
    }

    /// Adds or removes one optional scope. The list sent is the always-on
    /// scopes plus everything the daemon currently reports granted, with
    /// this one added or taken out -- built from the daemon's list, not
    /// from the ticks on screen, so two quick presses cannot race each
    /// other into dropping a scope neither touched.
    private func setScope(_ scope: ConsentScope, granted: Bool) {
        guard !consentBusy, model.status.loggedIn, !scope.alwaysOn else { return }
        var scopes = Set(model.status.consentScopes)
        scopes.formUnion(model.consentScopes.filter(\.alwaysOn).map(\.name))
        if granted {
            scopes.insert(scope.name)
        } else {
            scopes.remove(scope.name)
        }
        consentSaveError = nil
        consentBusy = true
        Task {
            switch await model.setConsentScopes(Array(scopes)) {
            case .succeeded:
                break
            case .failed:
                consentSaveError = TCSourceChecks.settingsCopy()?.consentSaveFailed
            }
            consentBusy = false
        }
    }

    // MARK: - Public profile (spec §5.6)

    /// The public surface: an opt-in row off the roster, the community-brand
    /// panel on it.
    ///
    /// Two surfaces rather than two states of one. Per §7.3 the black frame
    /// is the exact boundary of what becomes public, so the change of visual
    /// language is the statement and the two are built separately.
    ///
    /// Filled from `get_public_profile`, which reports the daemon's local
    /// cache of the last claim this device made. There is no
    /// `GET /v1/community/profile` for a contributor's own row, so a cache is
    /// what any shell has: it says what this machine last published, not what
    /// the roster holds this second.
    private var publicProfile: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            if let profile = model.publicProfile, let handle = profile.handle {
                profilePanel(profile, handle: handle)
            } else {
                TCSectionHeader(title: PublicProfileCopy.heading)
                optInRow
            }
            if let sentence = profileOutcomeSentence {
                Text(sentence)
                    .font(TC.Font_.body)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(PublicProfileCopy.footnote)
                .tcType(TC.Font_.captionText)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            profileCopyDefects
        }
        // Seeded from the daemon's answer whenever it changes, so the fields
        // show what is actually published -- including the trimmed display
        // form the server stored, which need not be the string that was
        // typed. Keyed on the published values rather than on every render,
        // so a refresh cannot overwrite an edit in progress.
        .onAppear { seedProfileDraft() }
        .onChange(of: publishedSignature) { _, _ in seedProfileDraft() }
    }

    /// The public-profile copy's own assertions, rendered where a
    /// contributor and a developer both see them -- the same arrangement
    /// `HistoryView` uses for the withdrawal wording, and for the same
    /// reason: there is no Swift test target here, so an assertion that is
    /// not rendered is an assertion nobody runs. Empty in every healthy
    /// build.
    @ViewBuilder
    private var profileCopyDefects: some View {
        let problems = PublicProfileCopyCheck.failures()
        if !problems.isEmpty {
            VStack(alignment: .leading, spacing: TC.Space.xs) {
                Text("Do not trust the public-profile wording on this screen.")
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

    /// Off the roster. The row §5.4 names, and a button that opens the
    /// consent dialog rather than doing anything itself: going public is a
    /// consent dialog, not a toggle flip (§5.7), and the foreign visual
    /// language starts at the sheet's edge.
    private var optInRow: some View {
        HStack(alignment: .center, spacing: TC.Space.m) {
            Text(PublicProfileCopy.listHandlePublicly)
                .font(TC.Font_.body)
            Spacer(minLength: 0)
            Button(PublicProfileCopy.goPublicConfirm) { showingGoPublic = true }
                .buttonStyle(.bordered)
                .font(TC.Font_.labelControl)
        }
        .padding(TC.Space.m)
        .frame(maxWidth: .infinity, alignment: .leading)
        .tcCard()
    }

    /// On the roster: §5.6's brand panel, editable.
    private func profilePanel(
        _ profile: DaemonClient.PublicProfile,
        handle: String
    ) -> some View {
        communityBrandPanel {
            HStack(alignment: .top, spacing: TC.Space.m) {
                Text(PublicProfileCopy.heading.uppercased())
                    .font(CommunityBrand.Font_.displayPanel)
                    .tracking(CommunityBrand.Font_.displayPanelTracking)
                    .foregroundStyle(CommunityBrand.ink)
                Spacer(minLength: 0)
                if let since = profile.publicSince {
                    Text(PublicProfileCopy.onRosterSince(Self.rosterDate.string(from: since)))
                        .font(CommunityBrand.Font_.labelMono)
                        .tracking(CommunityBrand.Font_.monoTracking)
                        .foregroundStyle(CommunityBrand.muted)
                        .multilineTextAlignment(.trailing)
                }
            }

            profileEditor(label: PublicProfileCopy.handleLabel, text: $handleDraft, mono: true)

            VStack(alignment: .leading, spacing: TC.Space.xs) {
                profileBioEditor(label: PublicProfileCopy.bioLabel, text: $bioDraft)
                // Counted off the value above, not the mockup's "74/280": a
                // counter that does not count is worse than no counter.
                // Bytes, because the limit is stated in bytes.
                Text("\(bioDraft.utf8.count)/280")
                    .font(CommunityBrand.Font_.labelMono)
                    .tracking(CommunityBrand.Font_.monoTracking)
                    .foregroundStyle(CommunityBrand.muted)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }

            HStack(spacing: TC.Space.sm) {
                // Save re-publishes the whole profile, because that is what
                // the PUT does: the handle and the bio as they stand, both
                // of them, every time. There is no partial update to offer.
                Button(PublicProfileCopy.saveProfile) {
                    model.claimHandle(handleDraft, bio: bioDraft)
                }
                .buttonStyle(CommunityBrandButtonStyle(fill: CommunityBrand.accent))
                .disabled(model.profileBusy || handleDraft.trimmingCharacters(
                    in: .whitespacesAndNewlines
                ).isEmpty)
                Button(PublicProfileCopy.leaveRoster) { model.leaveRoster() }
                    .buttonStyle(CommunityBrandButtonStyle(fill: CommunityBrand.paper))
                    .disabled(model.profileBusy)
            }
        }
        // The handle is what is published; the panel says so to VoiceOver
        // rather than leaving the fields to be read as unlabelled boxes.
        .accessibilityLabel("\(PublicProfileCopy.heading): \(handle)")
    }

    /// What the last claim or withdrawal did, in words.
    ///
    /// `published(cached: false)` is a **success**: the server has taken the
    /// handle, and only this device's copy of it is missing. It gets the
    /// sentence that says so rather than a refusal sentence -- a shell that
    /// reported it as a failure would tell a contributor their handle is
    /// private when it is public.
    private var profileOutcomeSentence: String? {
        switch model.profileOutcome {
        case .none: return nil
        case .published(let cached):
            return cached ? PublicProfileCopy.published : PublicProfileCopy.publishedNotCached
        case .left(let cached):
            return cached ? PublicProfileCopy.leftRoster : PublicProfileCopy.leftRosterNotCached
        case .refused(let label):
            return PublicProfileCopy.failureSentence(label)
        case .leaveRefused(let label):
            return PublicProfileCopy.leaveFailureSentence(label)
        }
    }

    /// The published values, as one string, so the drafts are re-seeded when
    /// and only when the daemon's answer actually changes.
    private var publishedSignature: String {
        "\(model.publicProfile?.handle ?? "")\u{1}\(model.publicProfile?.bio ?? "")"
    }

    private func seedProfileDraft() {
        handleDraft = model.publicProfile?.handle ?? ""
        bioDraft = model.publicProfile?.bio ?? ""
    }

    private static let rosterDate: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .long
        formatter.timeStyle = .none
        return formatter
    }()

    /// Spec §6.10: a brand field box is `border:1px solid #000`,
    /// `padding:8px 12px`, no radius, with its `label.mono` above it.
    private func profileEditor(
        label: String,
        text: Binding<String>,
        mono: Bool
    ) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.xs) {
            brandFieldLabel(label)
            TextField("", text: text)
                .textFieldStyle(.plain)
                .font(mono ? CommunityBrand.Font_.fieldValueMono : CommunityBrand.Font_.fieldValue)
                .tracking(CommunityBrand.Font_.fieldValueTracking)
                .foregroundStyle(CommunityBrand.ink)
                .padding(.vertical, TC.Space.s)
                .padding(.horizontal, TC.Space.m)
                .overlay(
                    Rectangle().strokeBorder(
                        CommunityBrand.ink,
                        lineWidth: CommunityBrand.Metric.rule
                    )
                )
                .accessibilityLabel(label)
        }
    }

    private func profileBioEditor(label: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.xs) {
            brandFieldLabel(label)
            TextEditor(text: text)
                .font(CommunityBrand.Font_.fieldValue)
                .foregroundStyle(CommunityBrand.ink)
                // The editor paints its own ground, which would be the
                // system's rather than the brand's paper inside a black
                // frame.
                .scrollContentBackground(.hidden)
                .background(CommunityBrand.paper)
                .frame(minHeight: 56)
                .padding(.vertical, TC.Space.s)
                .padding(.horizontal, TC.Space.m)
                .overlay(
                    Rectangle().strokeBorder(
                        CommunityBrand.ink,
                        lineWidth: CommunityBrand.Metric.rule
                    )
                )
                .accessibilityLabel(label)
        }
    }

    private func brandFieldLabel(_ text: String) -> some View {
        Text(text.uppercased())
            .font(CommunityBrand.Font_.labelMono)
            .tracking(CommunityBrand.Font_.monoTracking)
            .foregroundStyle(CommunityBrand.muted)
    }

    // MARK: - Watching and projects

    private var watching: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            TCSectionHeader(title: "Watching")
            if let settings = model.daemonSettings {
                Text("A session counts as finished after \(settings.quiescenceSecs) seconds of quiet.")
                    .font(TC.Font_.body)
                Text("At most one notification every \(settings.digestIntervalSecs / 3600) hours, and none when nothing is waiting.")
                    .font(TC.Font_.body)
                Text("Undecided sessions are dropped after \(settings.queueTtlDays) days. Dropped means never sent.")
                    .font(TC.Font_.body)
                checkRow("Notifications rendered by this app", !settings.localNotifications)
            }
            if model.status.paused {
                Text("Paused. Nothing is being queued or sent.").font(TC.Font_.body)
            }
        }
    }

    // MARK: - Watched folders

    /// The roots screen's rows, after first run.
    ///
    /// Each answer writes straight through `set_settings` -- there is no
    /// Save, because each row is one declaration and the daemon applies it
    /// in the same call. What a row shows is the MODE the daemon reports
    /// (`*_source_mode`), which is all `get_settings` says: it never
    /// reports the path, so a watched folder shows as "Watching" with no
    /// path, including after a write. The same explanation the roots screen gives
    /// applies, and is given, because a blank Claude Code or Codex row still
    /// means the standard location.
    @ViewBuilder
    private var watchedFolders: some View {
        if let copy = TCSourceChecks.settingsCopy() {
            VStack(alignment: .leading, spacing: TC.Space.sm) {
                TCSectionHeader(title: copy.heading)
                Text(copy.explanation).font(TC.Font_.meta).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if sourceSaveFailed {
                    Label(copy.saveFailed, systemImage: TC.Tone.refused.symbol)
                        .font(TC.Font_.caption).foregroundStyle(TC.coralText)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if model.daemonSettings != nil {
                    ForEach(OnboardingRootsView.offeredKinds, id: \.self) { kind in
                        SourceRootRow(
                            kind: kind,
                            candidate: sourceCandidates.first { $0.source == kind },
                            choice: sourceChoice(for: kind),
                            reportedMode: sourceMode(for: kind),
                            onWatchCandidate: { saveSource(kind, .watch(path: $0.path)) },
                            onChoose: { saveSource(kind, .watch(path: $0)) },
                            onDecline: { saveSource(kind, .off) }
                        )
                    }
                } else {
                    Text(copy.unavailable).font(TC.Font_.meta).foregroundStyle(.secondary)
                }
                if sourceSaveFailed || model.daemonSettings == nil {
                    Button(copy.retry) { model.refreshSettings() }
                }
            }
            .disabled(sourceBusy)
            .onAppear(perform: discoverSources)
        }
    }

    private func saveSource(_ kind: SourceKind, _ choice: SourceChoice) {
        guard !sourceBusy else { return }
        sourceBusy = true
        sourceSaveFailed = false
        Task {
            sourceSaveFailed = !(await model.setSourceRoot(kind, choice))
            sourceBusy = false
        }
    }

    /// The daemon's answer for one source, as the row shows it. The path
    /// is deliberately absent: the daemon only says that a folder is watched.
    private func sourceChoice(for kind: SourceKind) -> SourceChoice {
        switch sourceMode(for: kind) {
        case "watch": return .watch(path: "")
        case "off": return .off
        default: return .undecided
        }
    }

    private func sourceMode(for kind: SourceKind) -> String {
        guard let modes = model.daemonSettings?.routingSourceModes else { return "unset" }
        switch kind {
        case .claudeCode: return modes.claude
        case .codex: return modes.codex
        case .geminiCli: return modes.gemini
        case .cline: return modes.cline
        case .opencode: return model.daemonSettings?.opencodeSourceMode ?? ""
        }
    }

    /// Best-effort, exactly as on the roots screen: a row can always be
    /// answered by hand.
    private func discoverSources() {
        guard sourceCandidates.isEmpty, let json = TCDiscovery.sourcesJSON() else { return }
        sourceCandidates = (try? SourceCandidate.decodeList(from: json)) ?? []
    }

    // MARK: - Tools: the local proxy

    /// What each tool does with the first hop out of this machine, and the
    /// declaration that lets Trace Commons ask.
    ///
    /// Every string on this card comes from
    /// `trace_commons_contributor::routing_copy` through `RoutingCopy` --
    /// none is written here. Exactly one of those words claims privacy, and
    /// a hand-written copy of that claim would stop matching the day the
    /// claim changes with nothing to notice. The card renders nothing at all
    /// if the payload did not arrive, rather than falling back to wording of
    /// its own.
    @ViewBuilder
    private var routing: some View {
        if let copy = model.routingCopy {
            let form = routingDraft ?? model.routingForm
            VStack(alignment: .leading, spacing: TC.Space.sm) {
                TCSectionHeader(title: copy.toolsHeading)

                // The per-tool words come first, because they are what
                // somebody opened this card to read. Each is IronWire's own
                // answer about that tool, never this app's switch.
                ForEach(
                    RoutingSurface.toolRows(
                        sourceModes: model.daemonSettings?.routingSourceModes ?? .unset,
                        evidence: model.routingEvidence,
                        copy: copy,
                        calls: model.routingCalls
                    ),
                    id: \.name
                ) { row in
                    HStack {
                        Text(row.name).font(TC.Font_.body)
                        Spacer()
                        // The tone rides on the row, decided by the same
                        // shared table that chose the word. Nothing here
                        // reads the word to paint it.
                        TCTag(text: row.word, tone: tone(row.tone))
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(row.name): \(row.word)")
                }

                Text(copy.intro)
                    .font(TC.Font_.body)
                    .fixedSize(horizontal: false, vertical: true)

                Toggle(copy.toggle, isOn: Binding(
                    get: { form.on },
                    set: { on in
                        var next = form
                        next.on = on
                        routingDraft = next
                        model.applyIronWire(next)
                    }
                ))
                .toggleStyle(.switch)
                .tint(TC.green)
                .font(TC.Font_.body)

                routingState(copy: copy)

                // What the machine already knows, before anything it is
                // asked. The pointer IronWire writes when its daemon binds
                // carries the port, so on a machine running it there is
                // nothing here for a contributor to look up -- and on a
                // machine without it this sentence says so without saying
                // anything is wrong, because nothing is.
                Text(
                    RoutingSurface.discoveryLine(
                        model.routingDiscovery, copy: copy, calls: model.routingCalls
                    )
                )
                .font(TC.Font_.body)
                .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: TC.Space.xs) {
                    // Offered only where there is something to connect to,
                    // and only while nothing is declared: this is the
                    // shortcut past the two fields, not a second Apply.
                    if model.routingDiscovery.found, !form.on {
                        Button(copy.connect) {
                            let next = RoutingSurface.connecting(form)
                            routingDraft = next
                            model.applyIronWire(next)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.routingChecking)
                    }
                    // Offered rather than polled: this card does not go
                    // looking at a file on a timer, and somebody who
                    // started IronWire after opening this window needs a
                    // way to say so.
                    Button(copy.lookAgain) { model.discoverRouting() }
                        .buttonStyle(.borderless)
                }

                // The port and folder are the override, and they are live
                // only while the switch is on. They sit behind a disclosure
                // once discovery has supplied the port -- and stay open
                // where it has not, because then they are the only way to
                // answer. This inverts the default; it removes nothing.
                DisclosureGroup(
                    copy.overrideTitle,
                    isExpanded: Binding(
                        get: {
                            routingOverrideOpen
                                ?? !RoutingSurface.overrideIsCollapsed(model.routingDiscovery)
                        },
                        set: { routingOverrideOpen = $0 }
                    )
                ) {
                VStack(alignment: .leading, spacing: TC.Space.xs) {
                    TCFieldLabel(copy.portTitle)
                    TextField(
                        "",
                        value: Binding(
                            get: { Int(form.port) },
                            set: { value in
                                var next = form
                                // Out of range is left as it was rather than
                                // clamped to something nobody typed. Port 0
                                // in particular is the ask-the-kernel
                                // sentinel, which the daemon refuses.
                                if let port = UInt16(exactly: value), port > 0 { next.port = port }
                                routingDraft = next
                            }
                        ),
                        format: .number.grouping(.never)
                    )
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 120, alignment: .leading)
                    .accessibilityLabel(copy.portTitle)
                    Text(copy.portNote)
                        .font(TC.Font_.meta)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .disabled(!form.on)

                // A chooser, not a box to type a path into.
                //
                // On this platform the folder is a permission question
                // wearing a path's clothes: what makes a directory readable
                // is that the person at the keyboard pointed at it through
                // the system's own panel, not that the app was told a
                // string. This app is NOT sandboxed today -- there is no
                // entitlements file in the tree and `make-app-bundle.sh`
                // signs with `--options runtime` and no `--entitlements`
                // -- so a typed path would in fact work, and no
                // security-scoped bookmark is needed to keep this one. It
                // is a chooser anyway, because a panel is what a person can
                // answer without knowing the path, and because the day this
                // app is sandboxed the typed box stops working silently
                // while this does not.
                VStack(alignment: .leading, spacing: TC.Space.xs) {
                    TCFieldLabel(copy.folderTitle)
                    HStack(spacing: TC.Space.xs) {
                        Button(copy.chooseFolder) {
                            // `if let` rather than a `guard ... else`: a
                            // dismissed panel is nothing to do, and the
                            // card is asserted to carry no `else` branch
                            // at all, because the one that mattered was a
                            // fallback rendering wording of its own.
                            if let path = chooseIronWireFolder() {
                                var next = form
                                next.tokenDir = path
                                routingDraft = next
                            }
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(copy.folderTitle)
                        // The chosen folder, shown so the answer is
                        // visible. Empty until one is chosen, which is the
                        // ordinary case the note underneath describes.
                        Text(form.tokenDir)
                            .font(TC.Font_.meta)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.head)
                    }
                    Text(copy.folderNote)
                        .font(TC.Font_.meta)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .disabled(!form.on)
                }
                .font(TC.Font_.body)

                Button(model.routingChecking ? copy.checking : copy.apply) {
                    model.applyIronWire(form)
                }
                .buttonStyle(.bordered)
                .disabled(!form.on || model.routingChecking)

                if let probeLine = model.routingProbeLine {
                    Text(probeLine)
                        .font(TC.Font_.meta)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                // Said out loud because the obvious worry is that it is not
                // true. Nothing on this card waits on the app being started
                // again: a changed declaration is applied to the running
                // daemon and read on its next poll.
                Text(copy.appliesAtOnce)
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
            }
            .onAppear {
                // Asked before anything is offered, and asked every time
                // this card appears: IronWire may have started since. It
                // reads a file, opens no connection and declares nothing.
                model.discoverRouting()
                model.refreshRoutedTools()
            }
        }
    }

    /// The daemon's own three-state view of what it is seeing, and when it
    /// last got an answer.
    ///
    /// `awaiting_rows` is held, never a fault: a reader built a moment ago
    /// starts empty by construction, so this is what a contributor sees
    /// immediately after changing anything here.
    @ViewBuilder
    private func routingState(copy: RoutingCopy) -> some View {
        let state = model.status.routing.state
        // From the state, never from the sentence it produced. `tone` maps
        // only the three values this surface can take, so nothing here can
        // reach a fault colour whatever the daemon reports.
        let stateTone = tone(RoutingSurface.tone(forState: state, calls: model.routingCalls))
        VStack(alignment: .leading, spacing: TC.Space.xxs) {
            if model.status.routing.derived {
                Text(copy.derivedOrigin)
                    .font(TC.Font_.body)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(RoutingSurface.stateLine(state, copy: copy, calls: model.routingCalls))
                .font(TC.Font_.body)
                .foregroundStyle(stateTone.textColor)
                .fixedSize(horizontal: false, vertical: true)
            // "Last checked" is a stamp on the running daemon -- never an
            // install date, never a connected-since -- so it is only shown
            // on a state that has actually had an answer.
            if RoutingSurface.showsLastChecked(forState: state, calls: model.routingCalls),
               let at = model.status.routing.lastRefreshAt,
               let line = TCRoutingCopy.lastChecked(
                   when: Self.lastChecked.localizedString(for: at, relativeTo: Date())
               ) {
                Text(line)
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// The humanised time is the one part of this surface each shell renders
    /// for itself: it is a rendering of a timestamp, not wording about
    /// routing. The sentence around it comes from the Rust.
    private static let lastChecked: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter
    }()

    /// The system folder panel, or nil if it was dismissed.
    ///
    /// Directories only, no creating and no multiple selection: the answer
    /// is one directory that already exists, and every other affordance on
    /// this panel would be a way to give an answer that cannot be right.
    ///
    /// Returns the path rather than the URL because that is what the daemon
    /// takes and what `settingsParams` sends. There is no security-scoped
    /// bookmark kept: this app is not sandboxed -- no entitlements file
    /// exists in the tree, and the bundle is signed with `--options
    /// runtime` and no `--entitlements` -- so there is no scope to hold on
    /// to. If that changes, this is the one place that has to learn about
    /// bookmarks, which is why the panel lives here rather than inline.
    private func chooseIronWireFolder() -> String? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return url.path
    }

    // MARK: - The redaction witness

    /// Whether a sealed machine redacts a session before it is sent, and
    /// what happened to the last one.
    ///
    /// Every string on this card comes from
    /// `trace_commons_contributor::witness_copy` through `WitnessCopy` and
    /// the two sentence calls -- none is written here, and the same rule the
    /// routing card lives under applies with more force, because several of
    /// these sentences are privacy claims. The card renders nothing at all
    /// if the payload did not arrive.
    ///
    /// # Witness trust is not a switch
    ///
    /// A witness toggle would have to answer "is a witness configured?", and that
    /// question has two yes-answers that are opposites: a pinned witness
    /// certifies every submission, a configured-but-unpinned one refuses
    /// every submission before any network call. `WitnessTrustState` has one
    /// case per condition and this card renders the case, so `absent` --
    /// local redaction, a supported mode and not a warning -- and
    /// `refusing_unpinned` -- a total upload outage -- cannot come out
    /// looking alike.
    @ViewBuilder
    private var witness: some View {
        if let copy = model.witnessCopy {
            let state = model.witnessState
            VStack(alignment: .leading, spacing: TC.Space.sm) {
                TCSectionHeader(title: copy.heading)

                // What the witness is doing comes first, because it is what
                // somebody opened this card to read.
                if let code = model.witnessStateCode {
                    witnessState(code)
                }

                Text(copy.intro)
                    .font(TC.Font_.body)
                    .fixedSize(horizontal: false, vertical: true)
                Text(copy.certificateMeans)
                    .font(TC.Font_.body)
                    .fixedSize(horizontal: false, vertical: true)

                // What the last submission did, in the Rust's sentence. It
                // is process-local: a freshly started app says nothing has
                // been sent since it started, rather than guessing.
                if let line = WitnessSurface.lastResultLine(calls: model.witnessCalls) {
                    let resultTone = witnessTone(
                        WitnessSurface.lastResultTone(calls: model.witnessCalls))
                    HStack(alignment: .firstTextBaseline, spacing: TC.Space.xs) {
                        Image(systemName: resultTone.symbol).imageScale(.small)
                        Text(line).fixedSize(horizontal: false, vertical: true)
                    }
                    .font(TC.Font_.meta)
                    .foregroundStyle(resultTone.textColor)
                    .accessibilityElement(children: .combine)
                }

                if let state, WitnessSurface.offersConfigure(state) {
                    witnessFields(copy: copy)
                }

                // The way out. A refusal that offered nothing to do about
                // itself would be the trap `AppModel.Startup.needsRoots`
                // exists to avoid, so this is offered on EVERY refusing
                // state -- including one this build cannot name -- and not
                // only on the tidy ones.
                if let state, WitnessSurface.offersClear(state) {
                    Button(copy.clear) { model.clearWitness() }
                        .buttonStyle(.borderless)
                        .disabled(model.witnessBusy)
                    Text(copy.clearNote)
                        .font(TC.Font_.meta)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                inferenceEvidence(copy: copy)
                tokenContribution(copy: copy)

                Text(copy.appliesAtOnce)
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
            }
            .onAppear {
                // Asked every time the card appears: the config is a file,
                // and the CLI writes to it too.
                model.refreshWitness()
            }
        }
    }

    private func inferenceEvidence(copy: WitnessCopy) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            Text(copy.inferenceHeading).font(TC.Font_.body.weight(.semibold))
            Text(copy.inferenceDisclosure).fixedSize(horizontal: false, vertical: true)
            Text(copy.inferenceCaptureNote).fixedSize(horizontal: false, vertical: true)
            Text(copy.inferenceScopeNote).fixedSize(horizontal: false, vertical: true)
            if let enabled = model.daemonSettings?.ironwireAttestedBodies {
                Text(enabled ? copy.inferenceEnabled : copy.inferenceDisabled)
            }
            HStack {
                Button(copy.inferenceEnable) { showingInferenceDisclosure = true }
                    .disabled(model.inferenceEvidenceBusy || model.daemonSettings?.ironwireAttestedBodies == nil)
                Button(copy.inferenceDisable) {
                    Task { await model.setInferenceEvidence(false) }
                }
                .disabled(model.inferenceEvidenceBusy)
            }
            if model.inferenceEvidenceSaveFailed {
                NativeFlowNotice(message: copy.inferenceSaveFailed, glyph: copy.wallet?.refusedGlyph ?? "", tone: copy.wallet?.refusedTone ?? "refused")
            }
        }
        .font(TC.Font_.meta)
        .confirmationDialog(copy.inferenceHeading, isPresented: $showingInferenceDisclosure, titleVisibility: .visible) {
            Button(copy.inferenceConfirm) {
                Task { await model.setInferenceEvidence(true, disclosureConfirmed: true) }
            }
            Button(copy.inferenceCancel, role: .cancel) { }
        } message: {
            Text([copy.inferenceDisclosure, copy.inferenceCaptureNote, copy.inferenceScopeNote].joined(separator: "\n\n"))
        }
    }

    private func tokenContribution(copy: WitnessCopy) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            Text((copy.tokenHeading ?? "")).font(TC.Font_.body.weight(.semibold))
            Text((copy.tokenDisclosure ?? "")).fixedSize(horizontal: false, vertical: true)
            Text((copy.tokenCaptureNote ?? "")).fixedSize(horizontal: false, vertical: true)
            Text((copy.tokenScopeNote ?? "")).fixedSize(horizontal: false, vertical: true)
            if let enabled = model.daemonSettings?.tokenDistributionsContribution {
                Text(enabled ? (copy.tokenEnabled ?? "") : (copy.tokenDisabled ?? ""))
            }
            HStack {
                Button((copy.tokenEnable ?? "")) { showingTokenDisclosure = true }
                    .disabled(model.tokenContributionBusy || model.daemonSettings?.tokenDistributionsContribution == nil)
                Button((copy.tokenDisable ?? "")) {
                    Task { await model.setTokenContribution(false) }
                }
                .disabled(model.tokenContributionBusy)
            }
            if let storage = model.daemonSettings?.tokenStorage {
                if let label = storage.captureLabel {
                    Text(storage.captureNotice ?? "")
                    Button(label) {
                        if storage.captureEnabled == true { Task { await model.setLocalTokenCapture(false) } }
                        else { showingTokenCapture = true }
                    }
                    .disabled(model.tokenContributionBusy)
                    .confirmationDialog(label, isPresented: $showingTokenCapture, titleVisibility: .visible) {
                        Button(label) { Task { await model.setLocalTokenCapture(true) } }
                        Button(storage.cancelLabel, role: .cancel) { }
                    } message: { Text(storage.captureConfirmation ?? "") }
                }
                Text(storage.stateLine).fixedSize(horizontal: false, vertical: true)
                Text(storage.scopeNote).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button(storage.cleanupLabel) { Task { await model.cleanTokenStorage(discard: false) } }
                    Button(storage.discardLabel, role: .destructive) { showingTokenDiscard = true }
                }
                .disabled(model.tokenContributionBusy)
                .confirmationDialog(storage.discardLabel, isPresented: $showingTokenDiscard, titleVisibility: .visible) {
                    Button(storage.confirmLabel, role: .destructive) { Task { await model.cleanTokenStorage(discard: true) } }
                    Button(storage.cancelLabel, role: .cancel) { }
                } message: { Text(storage.discardConfirmation) }
                if !model.tokenStorageNotice.isEmpty { Text(model.tokenStorageNotice) }
            }
            if model.tokenContributionSaveFailed {
                NativeFlowNotice(message: (copy.tokenSaveFailed ?? ""), glyph: copy.wallet?.refusedGlyph ?? "", tone: copy.wallet?.refusedTone ?? "refused")
            }
        }
        .opacity(copy.tokenHeading == nil ? 0 : 1)
        .disabled(copy.tokenHeading == nil)
        .font(TC.Font_.meta)
        .confirmationDialog((copy.tokenHeading ?? ""), isPresented: $showingTokenDisclosure, titleVisibility: .visible) {
            Button((copy.tokenConfirm ?? "")) {
                Task { await model.setTokenContribution(true, disclosureConfirmed: true) }
            }
            Button((copy.tokenCancel ?? ""), role: .cancel) { }
        } message: {
            Text([(copy.tokenDisclosure ?? ""), (copy.tokenCaptureNote ?? ""), (copy.tokenScopeNote ?? "")].joined(separator: "\n\n"))
        }
    }

    /// What the witness is doing, in the Rust's sentence and the Rust's tone.
    ///
    /// The tone comes from the state code, never from the sentence it
    /// produced -- a text comparison here would be a comparison against a
    /// privacy claim. A state this build cannot name produces NO sentence
    /// (`stateLine` answers nil) and this renders none of its own; the tone
    /// still answers, and fails closed to refused.
    ///
    /// The glyph rides beside the words rather than inside a `TCTag`: a tag
    /// is a short state token, and the only short token this surface has is
    /// the ABI's fixed refusal label, which is rendered as one below. The
    /// state itself is a sentence, so it is set as one -- with the tone's
    /// symbol in front of it, which is what keeps a refusal legible in
    /// greyscale and in a black-and-white screenshot.
    @ViewBuilder
    private func witnessState(_ code: Int32) -> some View {
        let stateTone = witnessTone(WitnessSurface.tone(forState: code, calls: model.witnessCalls))
        VStack(alignment: .leading, spacing: TC.Space.xxs) {
            if let line = WitnessSurface.stateLine(code, calls: model.witnessCalls) {
                HStack(alignment: .firstTextBaseline, spacing: TC.Space.xs) {
                    Image(systemName: stateTone.symbol).imageScale(.small)
                    Text(line).fixedSize(horizontal: false, vertical: true)
                }
                .font(TC.Font_.body)
                .foregroundStyle(stateTone.textColor)
                .accessibilityElement(children: .combine)
            }
            // The ABI's fixed operator label, shown verbatim and with no
            // sentence built around it. It is not wording -- a sentence
            // written here would exist in this shell alone -- and it carries
            // no path, no token and no trace content. It is shown because a
            // refusal a contributor cannot name is a refusal they cannot get
            // help with.
            if let label = model.witnessStatus?.refusal ?? model.witnessLabel {
                TCTag(text: label, tone: stateTone)
            }
        }
    }

    /// The three things a contributor types, and the one button that writes
    /// them.
    ///
    /// The draft is held in the view for the reason the routing form and the
    /// profile fields are: a background refresh landing mid-edit would
    /// otherwise replace what is being typed. Nil means nothing has been
    /// edited, and the fields read what came back from the last write.
    @ViewBuilder
    private func witnessFields(copy: WitnessCopy) -> some View {
        let form = witnessDraft ?? WitnessForm.fromStatus(model.witnessStatus)
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            VStack(alignment: .leading, spacing: TC.Space.xs) {
                TCFieldLabel(copy.urlTitle)
                TextField("", text: Binding(
                    get: { form.url },
                    set: { value in
                        var next = form
                        next.url = value
                        witnessDraft = next
                    }
                ))
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel(copy.urlTitle)
            }

            VStack(alignment: .leading, spacing: TC.Space.xs) {
                TCFieldLabel(copy.signingAddressTitle)
                TextField("", text: Binding(
                    get: { form.signingAddress },
                    set: { value in
                        var next = form
                        next.signingAddress = value
                        witnessDraft = next
                    }
                ))
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel(copy.signingAddressTitle)
            }

            VStack(alignment: .leading, spacing: TC.Space.xs) {
                TCFieldLabel(copy.measurementsTitle)
                // The count as the Rust's sentence, never as a bare numeral:
                // a number with no words around it on a privacy surface is
                // this shell authoring wording by omission.
                //
                // Nil where there is no witness to count for -- absent, not
                // enrolled, unreadable -- and then NOTHING is rendered. A
                // count of the pins on a witness that does not exist is not
                // a shorter sentence, it is a wrong one, and there is no
                // `else` here for exactly that reason.
                if let line = model.witnessStatus?.pinnedMeasurementLine {
                    Text(line)
                        .font(TC.Font_.meta)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                // One measurement set per line, pre-filled from what the ABI
                // returned and handed straight back. A list, not a value: an
                // upgrade moves the witness's measurement and leaves its
                // signing address where it is, so the new one is added
                // before the fleet rolls.
                //
                // The box is the whole answer. Emptying it and saving is a
                // contributor clearing their pins, which the ABI refuses
                // with `witness-pin-required`; there is no keep-what-is-there
                // mode, because that would save a pin nobody looked at.
                TextEditor(text: Binding(
                    get: { form.measurements },
                    set: { value in
                        var next = form
                        next.measurements = value
                        witnessDraft = next
                    }
                ))
                .font(TC.Font_.monoChip)
                .scrollContentBackground(.hidden)
                .background(TC.surface)
                .frame(minHeight: 64)
                .overlay {
                    RoundedRectangle(cornerRadius: TC.Radius.card)
                        .strokeBorder(TC.Tone.neutral.color.opacity(0.35),
                                      lineWidth: TC.Space.hairline)
                }
                .accessibilityLabel(copy.measurementsTitle)
                Text(copy.measurementsNote)
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Disabled until there is something pinnable to write. The ABI
            // refuses an empty pin list, and it is right to: writing one
            // produces a client that refuses every submission from the
            // moment it is saved. This card does not offer the button that
            // would ask for that.
            Button(copy.configure) {
                model.configureWitness(form)
                witnessDraft = nil
            }
            .buttonStyle(.bordered)
            .disabled(!form.canConfigure || model.witnessBusy)
        }
    }

    /// `WitnessTone` -> the design system's tone.
    ///
    /// A refusal is `.refused` and NEVER `.attention`: attention is caution,
    /// not alarm -- the tone of a setup that is degraded but still working
    /// -- and a refusing witness is sending nothing at all.
    ///
    /// Deliberately not the routing bridge below. The two ABI tone ranges
    /// are disjoint so that a cross-wired mapper is wrong for every value
    /// rather than only for the dangerous one; two functions here is what
    /// keeps them from being cross-wired in the first place.
    private func witnessTone(_ tone: WitnessTone) -> TC.Tone {
        switch tone {
        case .neutral: return .neutral
        case .held: return .held
        case .clear: return .clear
        case .attention: return .attention
        case .refused: return .refused
        }
    }

    /// Where answering model calls went.
    ///
    /// The switch, the exposure sentence and the line that says what the
    /// listener actually did all live on the destination now
    /// (`PrivateInferenceView`), which is the one place that can show the
    /// state beside the control. What stays here is a pointer: somebody who
    /// learned where the switch was should find a sentence and a way there,
    /// not a hole.
    ///
    /// Nothing on it is painted as working, because nothing on it reports a
    /// state -- the indicator belongs beside the switch, and the rule that
    /// only a `Clear` tone may read as working is held where the tone is
    /// read. Renders nothing at all if the words did not arrive.
    @ViewBuilder
    private var privateInference: some View {
        if let copy = model.privateInferenceCopy {
            VStack(alignment: .leading, spacing: TC.Space.sm) {
                TCSectionHeader(title: copy.settingsTitle)
                Text(copy.settingsMoved)
                    .font(TC.Font_.body)
                    .fixedSize(horizontal: false, vertical: true)
                // The label is the destination's own, so the sidebar and
                // this pointer can never name it differently.
                Button(copy.destination) {
                    navigation?.section = .privateInference
                }
                .font(TC.Font_.body)
            }
        }
    }

    private func tone(_ tone: RoutingTone) -> TC.Tone {
        switch tone {
        case .clear: return .clear
        case .held: return .held
        case .attention: return .attention
        case .neutral: return .neutral
        }
    }

    // Every mode is offered here, arming included -- the Linux and Windows
    // shells have offered it from their settings for some time, and until
    // now a macOS contributor's only route to it was the CLI. Onboarding
    // still withholds it, deliberately: arming before anyone has seen a
    // single preview asks for trust they have no basis to give yet
    // (`OnboardingProjectsView`). By the time someone is in Settings they
    // have that basis, which is the difference between the two surfaces.
    //
    // The list comes from `ProjectRow.offerableModes` rather than from
    // `ProjectMode`'s cases, because the daemon refuses `auto_upload` for
    // the unresolvable bucket and a control offering it there would be a
    // choice that cannot be delivered.
    //
    // `setProjectMode` names the project by the opaque id `list_projects`
    // mints. It used to send `project_label` as a `project_key` and be
    // refused with `project-key-unrecognized` for every real project; that
    // is not expected any more.
    private var projects: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            TCSectionHeader(title: "Projects")
            if let error = model.lastActionError {
                ActionMessageBanner(text: error) { model.lastActionError = nil }
            }
            if model.projects.isEmpty {
                Text("No projects seen yet.").font(TC.Font_.body).foregroundStyle(.secondary)
            } else {
                ForEach(model.projects) { project in
                    VStack(alignment: .leading, spacing: TC.Space.xxs) {
                        HStack {
                            // `displayLabel`, not `projectLabel`: the bucket's
                            // own label is the slug `unknown-project`. The row
                            // is recognised by the daemon's
                            // `is_unresolved_bucket` flag, never by that
                            // string, which the IPC contract now forbids
                            // matching on because it is display text.
                            Text(project.displayLabel)
                            Spacer()
                            modePicker(project)
                        }
                        // Why this row is different, said on the row rather
                        // than in a footnote. Its picker is short one option
                        // and that absence would otherwise be unexplained --
                        // a contributor comparing two rows would be left to
                        // guess whether it was a bug.
                        if project.isUnresolvedBucket {
                            Text(ProjectCopy.unresolvedBucketNote)
                                .font(TC.Font_.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .font(TC.Font_.body)
                }
            }
        }
        // Presented from the section rather than from each row: one sheet
        // for the list, named by whichever row is being armed. A modifier
        // per row would build as many dialogs as there are projects, and
        // two of them can be presented at once.
        .confirmationDialog(
            armingCandidate.map { ProjectArmingCopy.confirmationTitle(project: $0.displayLabel) }
                ?? "",
            isPresented: Binding(
                get: { armingCandidate != nil },
                // Any dismissal -- the Escape key, a click outside, either
                // button -- clears the candidate. Leaving it set would show
                // the sheet again the next time anything else republished
                // this view.
                set: { if !$0 { armingCandidate = nil } }
            ),
            titleVisibility: .visible,
            presenting: armingCandidate
        ) { project in
            // `.destructive` is the wrong role: arming destroys nothing and
            // is reversible from this same picker. It is emphasised rather
            // than alarmed -- the Linux shell marks it destructive, which
            // this shell deliberately does not follow, because on macOS that
            // role means data is about to be lost and none is.
            Button(ProjectArmingCopy.confirm) {
                model.setProjectMode(project, mode: .autoUpload)
                armingCandidate = nil
            }
            Button(ProjectArmingCopy.cancel, role: .cancel) { armingCandidate = nil }
        } message: { _ in
            Text(ProjectArmingCopy.confirmationBody)
        }
    }

    /// The mode control for one project row.
    ///
    /// The binding reads through to `project.mode` -- the daemon's own
    /// answer, republished by `refreshProjects` -- and never to local state,
    /// so a mode the daemon refuses leaves the picker showing what is
    /// actually in force rather than what was clicked. That is also what
    /// makes cancelling the arming sheet need no revert: nothing moved.
    private func modePicker(_ project: ProjectRow) -> some View {
        Picker(
            "",
            selection: Binding(
                get: { project.mode },
                set: { wanted in
                    guard wanted != project.mode else { return }
                    // Arming is allowed from here, but never silently.
                    // Everything else is a direct call: changing a mind
                    // about "ignore" should not cost a sheet.
                    if wanted == .autoUpload {
                        armingCandidate = project
                    } else {
                        model.setProjectMode(project, mode: wanted)
                    }
                }
            )
        ) {
            ForEach(project.offerableModes, id: \.self) { mode in
                Text(ProjectCopy.modeChoiceLabel(mode)).tag(mode)
            }
        }
        .labelsHidden()
        .fixedSize()
    }

    // MARK: - The local change log

    /// What has been changed on this machine, from the daemon's `list_audit`.
    ///
    /// The shared design spec does not draw this surface -- the Linux shell
    /// is the only prior art -- so the section heading, the empty sentence
    /// and every action sentence below are the Linux shell's own words
    /// (`crates/trace-commons-contributor-gtk/src/ui/settings.rs`) rather
    /// than new copy. Two shells narrating the same log differently is a
    /// worse outcome than either wording on its own.
    ///
    /// Every value drawn here is a fixed label by contract: the instant, the
    /// action name mapped to a sentence, and the daemon-derived project
    /// label. Nothing on this screen may be enriched with a path, a token, a
    /// tenant, a session hash or a trace body -- see `AuditEntry`. And per
    /// the contract this is a record, not a guard: nothing in this app
    /// decides anything on the strength of what is listed here.
    private var audit: some View {
        VStack(alignment: .leading, spacing: TC.Space.sm) {
            TCSectionHeader(title: "What has been changed on this machine")
            if model.audit.isEmpty {
                Text("Nothing has been changed.")
                    .font(TC.Font_.meta)
                    .foregroundStyle(.secondary)
            }
            // The rows carry no id on the wire, and two entries can legally
            // agree on every field they do carry (the same action, on the
            // same project, within the same second), so the offset in a
            // newest-first list is the only stable identity available.
            ForEach(Array(model.audit.enumerated()), id: \.offset) { _, entry in
                auditRow(entry)
            }
        }
    }

    private func auditRow(_ entry: AuditEntry) -> some View {
        // The instant is a figure, so it is set as one, and the column of
        // them lines up down the section -- same reasoning as the Linux
        // shell's ledger treatment.
        HStack(alignment: .firstTextBaseline, spacing: TC.Space.m) {
            Text(Self.instant(entry.at))
                .font(TC.Font_.ledger)
                .foregroundStyle(.secondary)
            Text(Self.auditSentence(entry.action, project: entry.projectLabel))
                .font(TC.Font_.meta)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    /// The Linux shell prints the raw RFC 3339 instant because GTK has it as
    /// a string; this layer has already decoded it to a `Date`, so it is
    /// shown in the reader's own locale and time zone. Same fact, stated the
    /// way the platform states dates elsewhere in this app.
    private static func instant(_ date: Date) -> String {
        date.formatted(.dateTime.month(.abbreviated).day().hour().minute())
    }

    /// Fixed action labels to sentences. The wording is the Linux shell's
    /// `audit_sentence`, verbatim, including its catch-all: an action this
    /// build does not know still gets a row, because a change that happened
    /// and is not listed is exactly what this log exists to prevent.
    private static func auditSentence(_ action: String, project: String?) -> String {
        let sentence: String
        switch action {
        case "armed-auto-upload": sentence = "Automatic contributing turned on for"
        case "disarmed-auto-upload": sentence = "Automatic contributing turned off for"
        case "queue-bulk-approved": sentence = "The whole queue was approved"
        case "consent-scopes-changed": sentence = "Permissions changed"
        case "near-ai-notice-acknowledged": sentence = "The extra privacy scan was confirmed"
        default: sentence = "Changed"
        }
        guard let project, !project.isEmpty else { return sentence }
        return "\(sentence) \(project)"
    }

    /// One session-source row, worded by the Rust from the MODE.
    ///
    /// Not from `claudeRootConfigured`, which is `mode == "watch"` and so is
    /// false for `off` as well as for `unset`. The GTK and Windows shells
    /// branched on that boolean and printed "sessions read from the usual
    /// place" for a tool the contributor had declared off; this view printed
    /// an unticked "sessions folder set", which is not false but says
    /// nothing about what `off` means. All three now render one sentence per
    /// mode, from `trace_commons_contributor::source_copy`.
    ///
    /// Nothing is drawn if the ABI refused. A blank row is better than a
    /// sentence about somebody's session folder written in Swift.
    @ViewBuilder
    private func sourceCheckRow(_ tool: String, _ sourceMode: String) -> some View {
        if let line = TCSourceChecks.checkLine(tool: tool, sourceMode: sourceMode) {
            checkRow(line, sourceMode == "watch")
        }
    }

    /// Spec §5.4 / §6.9: a 12pt filled green disc carrying a white tick, then
    /// the label. Colour, glyph and words together -- the state survives
    /// greyscale.
    private func checkRow(_ title: String, _ value: Bool) -> some View {
        HStack(spacing: TC.Space.s) {
            Image(systemName: value ? "checkmark.circle.fill" : "circle")
                .font(.system(size: 12))
                .symbolRenderingMode(value ? .palette : .monochrome)
                .foregroundStyle(value ? TC.onAccent : Color.secondary, TC.green)
            Text(title).font(TC.Font_.body)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value ? "yes" : "no")")
    }
}

// MARK: - The go-public dialog (spec §5.7)

/// Going public is a deliberate consent dialog, not a toggle flip: what gets
/// published and what never does sit side by side, nothing is pre-checked,
/// and "Go public" stays disabled until the acknowledgement is checked.
///
/// The sheet is a pure brand surface, edge to edge -- the private tool ends
/// at the sheet's boundary. Per §7.3 that seam is the design.
private struct GoPublicDialog: View {
    var onDismiss: () -> Void

    @EnvironmentObject private var model: AppModel
    @State private var acknowledged = false
    @State private var handle = ""
    @State private var bio = ""

    /// Spec §4.6: the dialog is drawn at 560px.
    private static let width: CGFloat = 560

    /// The acknowledgement gate, plus the one thing the call cannot be made
    /// without. Both are the same rule stated twice: the primary does
    /// nothing until there is something to consent to and a consent to it.
    private var canGoPublic: Bool {
        acknowledged
            && !handle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !model.profileBusy
    }

    /// A refusal stays in the dialog, next to the field it is about: the one
    /// thing wanted after "that handle is reserved" is the box it was typed
    /// into. A success closes the sheet, and the Settings panel behind it
    /// reports what was published.
    private var refusal: String? {
        if case .refused(let label) = model.profileOutcome {
            return PublicProfileCopy.failureSentence(label)
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: TC.Space.l) {
            Text(PublicProfileCopy.goPublicHeadline.uppercased())
                .font(CommunityBrand.Font_.displayDialog)
                .tracking(CommunityBrand.Font_.displayDialogTracking)
                .foregroundStyle(CommunityBrand.ink)
                .fixedSize(horizontal: false, vertical: true)

            consentColumns

            // The handle itself, inside the consent dialog rather than
            // behind it: the thing being consented to is this exact string
            // becoming public, and nobody can meaningfully acknowledge "my
            // handle becomes public" and then be asked afterwards what the
            // handle is.
            fields

            acknowledgement

            if let refusal {
                Text(refusal)
                    .font(CommunityBrand.Font_.body)
                    .tracking(CommunityBrand.Font_.bodyTracking)
                    .foregroundStyle(CommunityBrand.ink)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: TC.Space.sm) {
                Spacer(minLength: 0)
                Button(PublicProfileCopy.notNow) { onDismiss() }
                    .buttonStyle(CommunityBrandButtonStyle(fill: CommunityBrand.paper))
                Button(PublicProfileCopy.goPublicConfirm) {
                    model.claimHandle(handle, bio: bio)
                }
                .buttonStyle(CommunityBrandButtonStyle(fill: CommunityBrand.accent))
                .disabled(!canGoPublic)
            }

            Text(PublicProfileCopy.goPublicFootnote)
                .font(CommunityBrand.Font_.footnote)
                .foregroundStyle(CommunityBrand.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(TC.Space.xl)
        .frame(width: Self.width, alignment: .leading)
        .background(CommunityBrand.paper)
        // Any outcome that is not a refusal is a claim the server accepted,
        // including one this device failed to cache: the handle is on the
        // roster either way, so the dialog's work is done and the sentence
        // for it belongs on the panel behind, not here.
        .onChange(of: outcomeIsSettled) { _, settled in
            if settled { onDismiss() }
        }
        // A stale refusal from an earlier attempt must not greet the next
        // opening of this sheet.
        .onAppear { model.clearProfileOutcome() }
    }

    private var outcomeIsSettled: Bool {
        switch model.profileOutcome {
        case .published, .left: return true
        case .none, .refused, .leaveRefused: return false
        }
    }

    /// Spec §6.10's brand field boxes, empty and waiting.
    private var fields: some View {
        VStack(alignment: .leading, spacing: TC.Space.m) {
            VStack(alignment: .leading, spacing: TC.Space.xs) {
                fieldLabel(PublicProfileCopy.goPublicHandleLabel)
                TextField("", text: $handle)
                    .textFieldStyle(.plain)
                    .font(CommunityBrand.Font_.fieldValueMono)
                    .tracking(CommunityBrand.Font_.fieldValueTracking)
                    .foregroundStyle(CommunityBrand.ink)
                    .padding(.vertical, TC.Space.s)
                    .padding(.horizontal, TC.Space.m)
                    .overlay(
                        Rectangle().strokeBorder(
                            CommunityBrand.ink,
                            lineWidth: CommunityBrand.Metric.rule
                        )
                    )
                    .accessibilityLabel(PublicProfileCopy.goPublicHandleLabel)
            }
            VStack(alignment: .leading, spacing: TC.Space.xs) {
                fieldLabel(PublicProfileCopy.goPublicBioLabel)
                TextEditor(text: $bio)
                    .font(CommunityBrand.Font_.fieldValue)
                    .foregroundStyle(CommunityBrand.ink)
                    .scrollContentBackground(.hidden)
                    .background(CommunityBrand.paper)
                    .frame(minHeight: 56)
                    .padding(.vertical, TC.Space.s)
                    .padding(.horizontal, TC.Space.m)
                    .overlay(
                        Rectangle().strokeBorder(
                            CommunityBrand.ink,
                            lineWidth: CommunityBrand.Metric.rule
                        )
                    )
                    .accessibilityLabel(PublicProfileCopy.goPublicBioLabel)
                // Bytes, because the limit is stated in bytes.
                Text("\(bio.utf8.count)/280")
                    .font(CommunityBrand.Font_.labelMono)
                    .tracking(CommunityBrand.Font_.monoTracking)
                    .foregroundStyle(CommunityBrand.muted)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
        }
    }

    private func fieldLabel(_ text: String) -> some View {
        Text(text.uppercased())
            .font(CommunityBrand.Font_.labelMono)
            .tracking(CommunityBrand.Font_.monoTracking)
            .foregroundStyle(CommunityBrand.muted)
    }

    /// A single 2px box split by one 1px rule, per §5.7. The two columns are
    /// deliberately the same weight: what is published and what never is are
    /// the same size of fact.
    private var consentColumns: some View {
        HStack(alignment: .top, spacing: 0) {
            column(
                title: PublicProfileCopy.publishedHeading,
                lines: [
                    "Your handle — real handles only, no pseudonyms.",
                    "Aggregate counts: accepted, novelty credit, accept rate.",
                    "The date you went public.",
                    "Your bio, if you write one."
                ]
            )
            Rectangle().fill(CommunityBrand.ink).frame(width: CommunityBrand.Metric.rule)
            column(
                title: PublicProfileCopy.neverHeading,
                lines: [
                    "Your traces or anything in them.",
                    "Per-trace data of any kind.",
                    "Anything about sessions you didn't send."
                ]
            )
        }
        .fixedSize(horizontal: false, vertical: true)
        .overlay(
            Rectangle().strokeBorder(
                CommunityBrand.ink,
                lineWidth: CommunityBrand.Metric.frame
            )
        )
    }

    private func column(title: String, lines: [String]) -> some View {
        VStack(alignment: .leading, spacing: TC.Space.s) {
            Text(title.uppercased())
                .font(CommunityBrand.Font_.labelMono)
                .tracking(CommunityBrand.Font_.monoTracking)
                .foregroundStyle(CommunityBrand.muted)
            ForEach(lines, id: \.self) { line in
                Text(line)
                    .font(CommunityBrand.Font_.body)
                    .tracking(CommunityBrand.Font_.bodyTracking)
                    .foregroundStyle(CommunityBrand.ink)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, TC.Space.m)
        .padding(.horizontal, TC.Space.md)
    }

    /// Spec §6.9's brand checkbox: a bare 14x14 square with a 2px border and
    /// no fill. Checked adds a tick inside the same square -- the shape
    /// changes, not only the colour.
    private var acknowledgement: some View {
        Button {
            acknowledged.toggle()
        } label: {
            HStack(alignment: .top, spacing: TC.Space.sm) {
                ZStack {
                    Rectangle().strokeBorder(
                        CommunityBrand.ink,
                        lineWidth: CommunityBrand.Metric.frame
                    )
                    if acknowledged {
                        Image(systemName: "checkmark")
                            .font(.system(size: 9, weight: .heavy))
                            .foregroundStyle(CommunityBrand.ink)
                    }
                }
                .frame(width: 14, height: 14)
                .padding(.top, 1)
                Text(PublicProfileCopy.goPublicAcknowledgement)
                .font(CommunityBrand.Font_.body)
                .tracking(CommunityBrand.Font_.bodyTracking)
                .foregroundStyle(CommunityBrand.ink)
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(.vertical, TC.Space.m)
            .padding(.horizontal, TC.Space.md)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(CommunityBrand.tint)
            .overlay(
            Rectangle().strokeBorder(
                CommunityBrand.ink,
                lineWidth: CommunityBrand.Metric.frame
            )
        )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(acknowledged ? [.isSelected] : [])
    }
}

