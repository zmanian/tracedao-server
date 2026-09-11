import Foundation
import TCShellCore

// Typed shapes for `trace_commons.daemon.v1_1`, as specified in
// docs/contributor-daemon-ipc-v1_1.md. The contract keeps `project_key` and
// raw paths off the wire on purpose. The one relaxation is
// `QueueEntry.projectPath` / `.sessionPath`: `~`-abbreviated display paths
// the daemon emits through `ipc::display_path` so a queue row can say which
// folder it is. They are for the screen only -- never logged, never in a
// notification, never in a history record.

// MARK: - Queue

enum QueueState: String, Codable {
    case pending, approved, uploading, uploaded, refused, failed, expired, superseded

    /// Every state except `uploaded`/`uploading` means nothing left this
    /// machine, and the queue view says so in words rather than in a colour.
    var nothingWasSent: Bool {
        switch self {
        case .uploaded, .uploading: return false
        default: return true
        }
    }
}

struct QueueEntry: Decodable, Identifiable, Hashable {
    let entryID: String
    let sessionHash: String
    /// Which ADAPTER produced this. Not always the tool the contributor
    /// used -- see `declaredSource`.
    let source: String
    /// What the transcript declares itself to be, when the daemon knew it.
    ///
    /// An imported Antigravity conversation is stored as a trajectory file,
    /// so `source` says `trajectory`: the storage format, and not the word
    /// the contributor typed to collect it. Optional because every native
    /// adapter declares nothing, and because a daemon predating the field
    /// sends none.
    let declaredSource: String?
    /// The opaque id `set_project_mode` and `approve`'s `project_id` filter
    /// both accept. Never a path, and never `projectLabel` -- the daemon
    /// refuses a label there (`project-key-unrecognized`), and a label is
    /// not guaranteed unique across two projects in the first place.
    let projectID: String
    let projectLabel: String
    /// The project's folder, `~`-abbreviated, for display only.
    ///
    /// The daemon relaxed its path rule in exactly one place to send this
    /// (see `ipc::display_path`), because `projectLabel` can keep two
    /// projects distinct but can never make them identifiable, and the
    /// queue's folder rows are where that difference is decided. Never
    /// logged, never in a notification, never in a history record.
    ///
    /// Empty against a daemon predating the field. A folder row with no
    /// path renders its label alone rather than an empty line.
    let projectPath: String
    /// Where this session actually ran, when that is not the project root.
    ///
    /// `nil` both when the daemon predates the field and when the session
    /// ran at the root -- the daemon sends null in the second case rather
    /// than repeating `projectPath`, so a row renders this line only when
    /// it says something.
    let sessionPath: String?
    let sizeBytes: Int
    let discoveredAt: Date
    let state: QueueState
    let reasonLabel: String?
    let attempts: Int
    /// How many delegated subagent transcripts this entry's session covers,
    /// and how many were left out because the conversation exceeded the
    /// source's raw byte budget.
    ///
    /// Optional because a daemon predating the fields sends neither, and a
    /// missing count is not a count of zero -- but both read as "nothing to
    /// say" through `subagentLine`, which is the only correct rendering of
    /// silence here. See `TCShellCore.SubagentCopy` for the words.
    let subagentCount: Int?
    let subagentsDropped: Int?
    /// Whether this session can actually be contributed, as the daemon
    /// answered it: `eligible`, `ineligible_permanent`,
    /// `ineligible_configuration`, `unknown`, or a label a later daemon
    /// grew.
    ///
    /// **`nil` MEANS THE DAEMON SENT NO FIELD, AND THAT IS NOT `unknown`.**
    /// An invited contributor has no eligibility question -- everything in
    /// their queue is contributable -- and a daemon predating this contract
    /// asks none either. Both render as the row always did. `unknown` is a
    /// real state that arrives on the wire, for a session this build never
    /// evaluated or one whose submission failed transiently, and it gets its
    /// own sentence. `Decodable` keeps the two apart for free: a missing key
    /// decodes to `nil`, a present `"unknown"` to the string.
    let eligibility: String?
    /// Which of the thirteen reason labels stands behind that state, or
    /// `nil`. Absent on every `eligible` row -- there is nothing to explain
    /// -- and on a state a daemon sent without one.
    let eligibilityReason: String?
    /// Whether this session carries a checkable copy of the model call that
    /// produced it, as the daemon answered it: `attested`,
    /// `unattested_permanent`, `unattested_configuration`, `unknown`, or a
    /// label a later daemon grew.
    ///
    /// **THE DAEMON SENDS THIS ON EVERY ENTRY, INCLUDING AN INVITED
    /// CONTRIBUTOR'S**, which is the opposite of `eligibility`'s rule.
    /// Eligibility is a permission question and is absent when nobody is
    /// asking; the mark is a fact about the trace and is owed to everyone.
    /// `nil` here therefore means only one thing -- a daemon predating the
    /// field -- and it still reaches a sentence, the unknown one, through
    /// `attestationMark`.
    let attestation: String?
    /// Which of the thirteen reason labels stands behind that mark, or
    /// `nil`.
    ///
    /// The thirteen are `eligibilityReason`'s thirteen and their SENTENCES
    /// are different; the two must never be rendered through each other's
    /// accessor. Absent on every `attested` row, present on both unattested
    /// marks, and present on `unknown` only when a send was retracted for a
    /// receipt the service could not supply.
    let attestationReason: String?
    /// Whether a witness certificate is held for the bytes this row was
    /// pinned to. True after either witness route.
    ///
    /// Optional on the wire and read through `holdsCertificate` below, for
    /// the reason every new daemon field is optional here: this app ships
    /// separately from the daemon and routinely runs against an older one.
    /// A non-optional property would throw on a daemon that sends no such
    /// key, and one row's missing field would fail the WHOLE list.
    ///
    /// Not `attestation` above. That says whether the session carries a copy
    /// of the model call that produced it; this says whether a certificate
    /// is held over the reviewed bytes. A session can have either without
    /// the other.
    let holdsCertificateRaw: Bool?

    var id: String { entryID }

    /// Whether this row belongs in the certificate-held list.
    ///
    /// Absent reads as no, never as yes: a row from a daemon that predates
    /// the field has established nothing, and putting it in a list that
    /// claims a certificate is held would assert something nobody checked.
    var holdsCertificate: Bool { holdsCertificateRaw == true }

    /// The eligibility question this row carries, or none at all.
    ///
    /// Built ONLY from a present `eligibility`, so an absent field can never
    /// reach a sentence. Everything the shell draws about it goes through
    /// `EligibilitySurface` from here; nothing in this file reads the state
    /// string.
    var contributionEligibility: ContributionEligibility? {
        guard let eligibility else { return nil }
        return ContributionEligibility(state: eligibility, reason: eligibilityReason)
    }

    /// The proof mark this row carries. Always one.
    ///
    /// Built from the fields whether or not they arrived: an entry from a
    /// daemon predating them carries the empty label, and the shared table
    /// answers that with the unknown sentence rather than with silence.
    /// Nothing in this file reads the mark string.
    var attestationMark: AttestationMark {
        AttestationMark(
            mark: attestation ?? "",
            reason: (attestationReason?.isEmpty ?? true) ? nil : attestationReason)
    }

    /// The card's extent line, or `nil` when there is nothing to report.
    /// The contract makes surfacing a non-zero `subagents_dropped`
    /// mandatory: a conversation trimmed to fit must say so rather than
    /// presenting as complete.
    var subagentLine: String? {
        SubagentCopy.line(count: subagentCount ?? 0, dropped: subagentsDropped ?? 0)
    }

    /// Whether this card is standing for a deliberately trimmed
    /// conversation. Drives tone only; the sentence says the rest.
    var wasTrimmed: Bool { (subagentsDropped ?? 0) > 0 }

    enum CodingKeys: String, CodingKey {
        case entryID = "entry_id"
        case sessionHash = "session_hash"
        case source
        case declaredSource = "declared_source"
        case projectID = "project_id"
        case projectLabel = "project_label"
        case projectPath = "project_path"
        case sessionPath = "session_path"
        case sizeBytes = "size_bytes"
        case discoveredAt = "discovered_at"
        case state
        case reasonLabel = "reason_label"
        case attempts
        case subagentCount = "subagent_count"
        case subagentsDropped = "subagents_dropped"
        case eligibility
        case eligibilityReason = "eligibility_reason"
        case attestation
        case attestationReason = "attestation_reason"
        case holdsCertificateRaw = "holds_certificate"
    }

    /// "Claude Code" / "Antigravity", never the raw source token.
    ///
    /// Prefers what the transcript declares over the adapter that stores
    /// it: an imported Antigravity conversation is a trajectory FILE, and
    /// calling it "Letta trajectory" names the format rather than the tool
    /// the contributor used.
    ///
    /// The `default` arm deliberately falls back to `source`, not to the
    /// coalesced value: an unrecognised declaration is untrusted text out
    /// of a file, and title-casing it onto the screen is a different
    /// decision from mapping a slug this build knows.
    var agentName: String {
        switch declaredSource ?? source {
        case "claude-code", "claude_code": return "Claude Code"
        case "codex": return "Codex"
        case "gemini-cli", "gemini_cli": return "Gemini CLI"
        case "cline": return "Cline"
        case "opencode": return "OpenCode"
        case "antigravity": return "Antigravity"
        case "trajectory", "letta_trajectory": return "Letta trajectory"
        default:
            return source
                .replacingOccurrences(of: "_", with: " ")
                .replacingOccurrences(of: "-", with: " ")
                .capitalized
        }
    }
}

private struct PendingList: Decodable {
    let pending: [QueueEntry]
}

// MARK: - Status

struct DaemonHealth: Decodable, Equatable {
    let lastErrorLabel: String?
    let since: Date?

    enum CodingKeys: String, CodingKey {
        case lastErrorLabel = "last_error_label"
        case since
    }
}

struct DaemonStatus: Decodable, Equatable {
    let schemaVersion: String
    let loggedIn: Bool
    let tenantID: String?
    var consentScopes: [String]
    let paused: Bool
    let queueDepth: Int
    let nextDigestAt: Date?
    let health: DaemonHealth
    /// The daily volume caps and what they are holding back.
    ///
    /// Decoded with a fallback rather than as an optional: a daemon that
    /// predates the field reports an unspent budget blocking nothing, which
    /// is the only safe reading of silence here.
    let dailyBudget: DailyBudget
    /// What the daemon is seeing from the declared local proxy, in three
    /// states. Not part of `health`: none of the three is a fault.
    let routing: RoutingStatus

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case loggedIn = "logged_in"
        case tenantID = "tenant_id"
        case consentScopes = "consent_scopes"
        case paused
        case queueDepth = "queue_depth"
        case nextDigestAt = "next_digest_at"
        case health
        case dailyBudget = "daily_budget"
        case routing
    }

    init(
        schemaVersion: String,
        loggedIn: Bool,
        tenantID: String?,
        consentScopes: [String],
        paused: Bool,
        queueDepth: Int,
        nextDigestAt: Date?,
        health: DaemonHealth,
        dailyBudget: DailyBudget = .unknown,
        routing: RoutingStatus = .notDeclared
    ) {
        self.schemaVersion = schemaVersion
        self.loggedIn = loggedIn
        self.tenantID = tenantID
        self.consentScopes = consentScopes
        self.paused = paused
        self.queueDepth = queueDepth
        self.nextDigestAt = nextDigestAt
        self.health = health
        self.dailyBudget = dailyBudget
        self.routing = routing
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decodeIfPresent(String.self, forKey: .schemaVersion) ?? ""
        loggedIn = try c.decodeIfPresent(Bool.self, forKey: .loggedIn) ?? false
        tenantID = try c.decodeIfPresent(String.self, forKey: .tenantID)
        consentScopes = try c.decodeIfPresent([String].self, forKey: .consentScopes) ?? []
        paused = try c.decodeIfPresent(Bool.self, forKey: .paused) ?? false
        queueDepth = try c.decodeIfPresent(Int.self, forKey: .queueDepth) ?? 0
        nextDigestAt = try c.decodeIfPresent(Date.self, forKey: .nextDigestAt)
        health = try c.decodeIfPresent(DaemonHealth.self, forKey: .health)
            ?? DaemonHealth(lastErrorLabel: nil, since: nil)
        dailyBudget = try c.decodeIfPresent(DailyBudget.self, forKey: .dailyBudget) ?? .unknown
        // A daemon that predates this field has declared no proxy, which is
        // exactly what the fallback says.
        routing = try c.decodeIfPresent(RoutingStatus.self, forKey: .routing) ?? .notDeclared
    }

    static let unknown = DaemonStatus(
        schemaVersion: "",
        loggedIn: false,
        tenantID: nil,
        consentScopes: [],
        paused: false,
        queueDepth: 0,
        nextDigestAt: nil,
        health: DaemonHealth(lastErrorLabel: nil, since: nil)
    )
}

/// `status`'s `routing` sub-object: what the daemon is seeing from the
/// declared proxy, and when it last got an answer.
///
/// `lastRefreshAt` is a per-process stamp on the running daemon. It is
/// never an install date and never a connected-since: it starts empty again
/// every time that process comes back up, which is why the surface only
/// shows it on a state that has actually had an answer.
struct RoutingStatus: Decodable, Equatable {
    let derived: Bool
    let state: String
    let lastRefreshAt: Date?

    enum CodingKeys: String, CodingKey {
        case state
        case derived
        case lastRefreshAt = "last_refresh_at"
    }

    init(state: String, lastRefreshAt: Date?, derived: Bool = false) {
        self.derived = derived
        self.state = state
        self.lastRefreshAt = lastRefreshAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        derived = try c.decodeIfPresent(Bool.self, forKey: .derived) ?? false
        state = try c.decodeIfPresent(String.self, forKey: .state) ?? RoutingStatus.notDeclaredState
        lastRefreshAt = try c.decodeIfPresent(Date.self, forKey: .lastRefreshAt)
    }

    /// The daemon's own spelling, from `daemon::ipc`'s
    /// `ROUTING_NOT_DECLARED`. Taken from `RoutingSurface` rather than
    /// respelled here: the surface maps this state to a line, and two
    /// spellings of it would be two readings of silence.
    static let notDeclaredState = RoutingSurface.State.notDeclared
    static let notDeclared = RoutingStatus(state: notDeclaredState, lastRefreshAt: nil)
}

// MARK: - Preview

/// The socket `preview` result: summary only, never the trace body.
struct PreviewSummary: Decodable, Equatable, Sendable {
    var tokenDistributionSummary: String? = nil
    let wouldSendBytes: Int
    let rawSessionBytes: Int
    let eventCount: Int
    let openingPrompt: String
    let redactions: [String: Int]
    /// Distinct values removed per label, beside `redactions`' occurrence
    /// counts. `185 local path` is occurrences; `(12 distinct)` is how much
    /// of the session's surface was really touched, which is the figure a
    /// person estimating risk is reaching for.
    ///
    /// Empty against a daemon predating the field; `RedactionLabels` renders
    /// occurrences alone in that case.
    let redactionsDistinct: [String: Int]
    let piiLabelsPresent: [String]
    let consentScopes: [String]
    let residualRisk: String
    var envelopeDigest: String? = nil
    /// Whether the preview pinned a real identity.
    ///
    /// False when the preview was built from the placeholder identity a
    /// device that has not enrolled carries, and false against a daemon
    /// predating the field. A hard gate on approving rather than a cosmetic
    /// flag: nothing was pinned, so there is no envelope for an approval to
    /// bind to. `PreviewSheet` keeps `Contribute` off and says why, which is
    /// what the Windows and Linux shells already do.
    var enrolled: Bool = false

    enum CodingKeys: String, CodingKey {
        case tokenDistributionSummary = "token_distribution_summary"
        case wouldSendBytes = "would_send_bytes"
        case rawSessionBytes = "raw_session_bytes"
        case eventCount = "event_count"
        case openingPrompt = "opening_prompt"
        case redactions
        case redactionsDistinct = "redactions_distinct"
        case piiLabelsPresent = "pii_labels_present"
        case consentScopes = "consent_scopes"
        case residualRisk = "residual_risk"
        case envelopeDigest = "envelope_digest"
        case enrolled
    }

    /// "12 secrets, 4 tokens, 31 paths" -- category labels and counts only;
    /// the contract guarantees neither map ever carries matched text.
    var redactionReceipt: String {
        // Delegated rather than a second copy of the wording: `redactions`
        // also carries `residual_secret_at:*`, which counts a secret that was
        // FOUND AND LEFT IN, and one place decides how that is worded. See
        // `RedactionLabels`.
        "scrubbed: " + RedactionLabels.line(
            occurrences: redactions,
            distinct: redactionsDistinct
        ).replacingOccurrences(of: "  ·  ", with: ", ")
    }
}

/// The wire shape `preview_request`'s immediate response and the
/// `preview_ready` event both carry, specialized to this app's own
/// `PreviewSummary` -- see `PreviewRequestResult`'s doc in `TCShellCore` for
/// why the generic lives there instead of a second copy of this decoder.
typealias PreviewRequestResult = TCShellCore.PreviewRequestResult<PreviewSummary>

/// A session refused by the daemon's preview scheduler's admission control,
/// before anything was parsed. `rawSessionBytes` is a `stat`; there is no
/// would-send figure, on purpose -- see the design spec's "Admission
/// control by size". A card renders exactly these two numbers and nothing
/// derived from them.
struct PreviewTooLarge: Equatable {
    let rawSessionBytes: Int
    let limitBytes: Int
}

// MARK: - Audit

/// One row of the daemon's local change log (`list_audit`).
///
/// Every field here is a fixed label by contract -- `action` and `detail`
/// are "never free text, a path, or a token", and `project_label` is the
/// daemon-derived display name, never a `project_key` or a path. That is
/// what makes this shape safe to render at all, and it is why nothing in
/// this app may enrich a row with anything more identifying.
///
/// The contract is equally explicit that this log is a VISIBILITY feature
/// for the contributor, not a security control: nothing in this app may
/// gate, permit or refuse anything on the strength of what is in here.
struct AuditEntry: Decodable, Equatable {
    let at: Date
    let action: String
    let projectLabel: String?
    /// Carried because the contract carries it, and deliberately not
    /// rendered: the Linux shell shows the action and the project only, and
    /// inventing a second line of copy for a label neither shell has ever
    /// displayed would put this app's audit surface out of step with it.
    let detail: String?

    enum CodingKeys: String, CodingKey {
        case at
        case action
        case projectLabel = "project_label"
        case detail
    }
}

// MARK: - History

struct HistoryRecord: Decodable, Identifiable, Equatable {
    let submissionID: String
    let submittedAt: Date
    /// The opaque project handle, so History can group by folder the way
    /// the queue does. Grouping on `projectLabel` instead would merge two
    /// different repositories that share a basename.
    ///
    /// Empty on records cached before the daemon carried it, and on records
    /// submitted before project keys were normalized -- those cannot be
    /// resolved to a folder and group under their label alone. Nothing
    /// retained the key they were minted from, so this is not backfillable.
    let projectID: String
    let projectLabel: String
    let source: String
    let status: String
    let consentScopes: [String]
    let creditPointsPending: Double
    let creditPointsFinal: Double?
    let explanations: [String]
    let lastRefreshedAt: Date?

    var id: String { submissionID }

    enum CodingKeys: String, CodingKey {
        case submissionID = "submission_id"
        case submittedAt = "submitted_at"
        case projectID = "project_id"
        case projectLabel = "project_label"
        case source
        case status
        case consentScopes = "consent_scopes"
        case creditPointsPending = "credit_points_pending"
        case creditPointsFinal = "credit_points_final"
        case explanations
        case lastRefreshedAt = "last_refreshed_at"
    }
}

// MARK: - Withdrawal

/// Which of the three withdrawal tiers the server applied.
///
/// The wire names are the SERVER's, pinned in
/// `crates/trace-commons-server/src/bin/trace-commons-ingest.rs`
/// (`TRACE_WITHDRAWAL_REACH_*`) and mirrored by `DistributionReach` in
/// `crates/trace-commons-contributor/src/withdraw.rs`. The two sides were
/// once written in parallel and did NOT agree -- the Rust client expected
/// `in_commons`/`distributed` while the server sends
/// `commons_not_distributed`/`commons_distributed` -- so the exact strings
/// below matter more than they look. `docs/contributor-daemon-ipc-v1_1.md`
/// still documents the old, wrong pair; the Rust is authoritative.
///
/// Deliberately decoded leniently (see `WithdrawalOutcome`): an unrecognized
/// label must leave this `nil` so the UI says it cannot tell which tier
/// applied, rather than throwing away a withdrawal that really happened.
enum WithdrawalReach: String, Decodable {
    /// Never entered the commons. Nothing was distributed.
    case notDistributed = "not_distributed"
    /// In the commons, never published in an export or benchmark.
    case commonsNotDistributed = "commons_not_distributed"
    /// In the commons AND already published. Copies cannot be recalled.
    case commonsDistributed = "commons_distributed"
}

/// The `withdraw` result: `withdrawn: true` plus the tier that applied.
struct WithdrawalOutcome: Decodable, Equatable {
    let tokenDeletionNote: String?
    let withdrawn: Bool
    /// `nil` when the daemon sent a label this build does not know. The
    /// withdrawal still happened; what cannot be stated is how far the trace
    /// had travelled, and the UI says so rather than guessing the gentler
    /// answer.
    let distributionReach: WithdrawalReach?

    enum CodingKeys: String, CodingKey {
        case withdrawn
        case distributionReach = "distribution_reach"
        case tokenDeletionNote = "token_deletion_note"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        tokenDeletionNote = try container.decodeIfPresent(String.self, forKey: .tokenDeletionNote)
        withdrawn = try container.decodeIfPresent(Bool.self, forKey: .withdrawn) ?? true
        let label = try container.decodeIfPresent(String.self, forKey: .distributionReach)
        distributionReach = label.flatMap(WithdrawalReach.init(rawValue:))
    }
}

struct HistoryCounts: Decodable, Equatable {
    let submitted: Int
    let accepted: Int
    let quarantined: Int
    let other: Int
}

struct HistoryRollup: Decodable, Equatable {
    let week: HistoryCounts
    let month: HistoryCounts
    let allTime: HistoryCounts
    let creditPending: Double
    let creditFinal: Double
    let quarantined: Int
    let lastRefreshedAt: Date?

    enum CodingKeys: String, CodingKey {
        case week, month
        case allTime = "all_time"
        case creditPending = "credit_pending"
        case creditFinal = "credit_final"
        case quarantined
        case lastRefreshedAt = "last_refreshed_at"
    }
}

// MARK: - Consent, projects, settings

struct ConsentScope: Decodable, Identifiable, Equatable {
    let name: String
    let description: String
    let alwaysOn: Bool
    let grantsDataUse: Bool

    var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, description
        case alwaysOn = "always_on"
        case grantsDataUse = "grants_data_use"
    }
}

// `ProjectMode` and `ProjectRow` live in TCShellCore, re-exported here by the
// file-level `import TCShellCore`. They moved because both had wire bugs no
// test could reach from an executable target: `ask` was spelled `"ask"` while
// the daemon sends `"notify_only"`, and `addedAt` was non-optional while a
// project the contributor has not decided about carries null. Either one
// fails the whole array, so `list_projects` never decoded and the projects
// screen rendered its empty state on every machine.

/// `get_settings`: the credential and both session roots are reported as
/// configured-or-not booleans, never as values. This type has nowhere to put
/// the values even if the daemon sent them.
struct DaemonSettingsView: Decodable, Equatable {
    let quiescenceSecs: Int
    let digestIntervalSecs: Int
    let localNotifications: Bool
    let queueTtlDays: Int
    let maxQueueEntries: Int
    let maxUploadsPerDay: Int
    let nearAIConfigured: Bool
    let claudeRootConfigured: Bool
    let codexRootConfigured: Bool
    /// What the contributor said about each agent's sessions: `watch`,
    /// `off`, or `unset`. Optional because a daemon that predates them
    /// answers neither, and the surface that reads them treats silence as
    /// `unset` -- a tool in use -- rather than as "not used".
    let claudeSourceMode: String?
    let codexSourceMode: String?
    let geminiSourceMode: String?
    let clineSourceMode: String?
    var opencodeSourceMode: String? = nil
    /// The local-proxy declaration this daemon is holding, or nil for none.
    /// Nil means off, with no fallback: connecting to a loopback port
    /// because nobody said otherwise would probe a service the contributor
    /// never mentioned.
    let ironwire: IronWireDeclarationView?
    /// Older daemons omit this independent, default-off consent.
    var admissionEvidenceRequired: Bool? = nil
    /// Whether to offer the admission-preparation control at all.
    ///
    /// Not a preference: the daemon answers true for a contributor who
    /// signed up through NEAR and false for one who came in on an invite,
    /// so the control can only refuse an invited contributor. It is also
    /// null when the daemon could not read its config, and absent from a
    /// daemon that predates the key -- neither of which is a yes.
    var admissionEvidenceOffered: Bool { admissionEvidenceRequired == true }
    var tokenDistributionsContribution: Bool? = nil
    var tokenStorage: TokenStorageView? = nil
    var ironwireAttestedBodies: Bool? = nil
    var inferenceEvidenceEnabled: Bool { ironwireAttestedBodies == true }
    /// Whether this daemon was asked to answer model calls itself. What was
    /// ASKED FOR; what happened is `privateInferenceState` beside it, and
    /// the two differ exactly when the listener refused to start.
    var privateInference: Bool? = nil
    var privateInferenceOn: Bool { privateInference == true }
    /// Whether the contributor has already been asked about that switch.
    /// Absent on a daemon that predates the key, which reads as unanswered
    /// -- and is what makes the offer appear once after an upgrade.
    var privateInferenceOfferSeen: Bool? = nil
    var privateInferenceAnswered: Bool { privateInferenceOfferSeen == true }
    /// What the listener is actually doing.
    var privateInferenceState: PrivateInferenceStateView? = nil

    /// The four source modes as the routing surface takes them. Absent
    /// means `unset`, which watches the conventional location and is
    /// therefore a tool in use -- never "not used".
    var routingSourceModes: RoutingSourceModes {
        RoutingSourceModes(
            claude: claudeSourceMode ?? "unset",
            codex: codexSourceMode ?? "unset",
            gemini: geminiSourceMode ?? "unset",
            cline: clineSourceMode ?? "unset"
        )
    }

    enum CodingKeys: String, CodingKey {
        case quiescenceSecs = "quiescence_secs"
        case digestIntervalSecs = "digest_interval_secs"
        case localNotifications = "local_notifications"
        case queueTtlDays = "queue_ttl_days"
        case maxQueueEntries = "max_queue_entries"
        case maxUploadsPerDay = "max_uploads_per_day"
        case nearAIConfigured = "near_ai_configured"
        case claudeRootConfigured = "claude_root_configured"
        case codexRootConfigured = "codex_root_configured"
        case claudeSourceMode = "claude_source_mode"
        case codexSourceMode = "codex_source_mode"
        case geminiSourceMode = "gemini_source_mode"
        case clineSourceMode = "cline_source_mode"
        case opencodeSourceMode = "opencode_source_mode"
        case ironwire
        case admissionEvidenceRequired = "admission_evidence_required"
        case tokenDistributionsContribution = "token_distributions_contribution"
        case tokenStorage = "token_storage"
        case ironwireAttestedBodies = "ironwire_attested_bodies"
        case privateInference = "private_inference"
        case privateInferenceOfferSeen = "private_inference_offer_seen"
        case privateInferenceState = "private_inference_state"
    }
}

/// `private_inference_state` as `get_settings`, `set_settings` and `status`
/// all report it.
///
/// The label is carried as the daemon's own string and handed to the shared
/// table, never parsed into a Swift enum: a state a later daemon grows would
/// otherwise have to be spelled here before it could be shown, and the shared
/// table already answers an unknown label with the sentence that claims
/// nothing.
struct PrivateInferenceStateView: Decodable, Equatable {
    let state: String
    let port: UInt16?

    var surfaceState: PrivateInferenceState {
        PrivateInferenceState(label: state, port: port)
    }
}

/// The `ironwire` declaration as `get_settings` reports it back.
///
/// Serialized by the daemon tagged on `mode`, so `off` can never be
/// mistaken for a port. `token_dir` is a directory the contributor named --
/// never the credential inside it, which is read at call time and never
/// enters the settings file.
struct IronWireDeclarationView: Decodable, Equatable {
    let mode: String
    let port: UInt16?
    let tokenDir: String?

    enum CodingKeys: String, CodingKey {
        case mode
        case port
        case tokenDir = "token_dir"
    }
}

/// `enroll`'s success shape. `tenant_id`/`device_key_id` are the same
/// already-public identifiers `whoami` prints -- never key material, never a
/// URL. See "### `enroll`" in the contract for what is deliberately absent
/// on failure.
struct EnrollResult: Decodable, Equatable {
    let enrolled: Bool
    let tenantID: String?
    let deviceKeyID: String?
    let consentScopes: [String]?

    enum CodingKeys: String, CodingKey {
        case enrolled
        case tenantID = "tenant_id"
        case deviceKeyID = "device_key_id"
        case consentScopes = "consent_scopes"
    }
}

// MARK: - Events

enum DaemonEvent: Equatable {
    case snapshot(pending: [QueueEntry], status: DaemonStatus)
    case queueChanged
    case statusChanged
    /// `contributed` and `creditPending` describe what went out unasked
    /// since the last digest. They are zero on a daemon that predates them,
    /// which degrades this to the waiting-only digest that shipped before
    /// rather than to a wrong number.
    case digestDue(
        pending: Int,
        contributed: Int,
        contributedProjects: [String],
        creditPending: Double,
        text: String
    )
    case resyncRequired
    /// The ABI's synthetic frame for a delivery gap. Treated exactly like
    /// `resync_required`: refetch rather than reason about what was missed.
    case lagged(skipped: Int)
    /// A previously `queued`/`running` scheduled preview finished. Never
    /// published for a `preview_request` that was itself answered from
    /// cache -- see the contract's note that a cache hit "no event
    /// follows".
    case previewReady(PreviewRequestResult)
    case unknown(String)
}

// MARK: - Decoding

enum DaemonDecoding {
    /// chrono serializes `DateTime<Utc>` as RFC 3339 with fractional
    /// seconds; `.iso8601` alone rejects those, so both spellings are tried.
    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        decoder.dateDecodingStrategy = .custom { decoder in
            let text = try decoder.singleValueContainer().decode(String.self)
            if let d = withFraction.date(from: text) { return d }
            if let d = plain.date(from: text) { return d }
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "unparseable timestamp")
            )
        }
        return decoder
    }

    static func pendingEntries(from data: Data) throws -> [QueueEntry] {
        try decoder().decode(PendingList.self, from: data).pending
    }
}

/// The decoder is an extension rather than a member so that `QueueEntry`
/// keeps its memberwise initializer, which the debug capture screens build
/// fixtures with.
///
/// Written out rather than synthesized because `projectPath` is
/// non-optional and must still tolerate absence: this app ships separately
/// from the daemon and routinely runs against an older one, where a required
/// key would fail the whole queue rather than one field.
extension QueueEntry {
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            entryID: try c.decode(String.self, forKey: .entryID),
            sessionHash: try c.decode(String.self, forKey: .sessionHash),
            source: try c.decode(String.self, forKey: .source),
            declaredSource: try c.decodeIfPresent(String.self, forKey: .declaredSource),
            projectID: try c.decode(String.self, forKey: .projectID),
            projectLabel: try c.decode(String.self, forKey: .projectLabel),
            projectPath: try c.decodeIfPresent(String.self, forKey: .projectPath) ?? "",
            sessionPath: try c.decodeIfPresent(String.self, forKey: .sessionPath),
            sizeBytes: try c.decode(Int.self, forKey: .sizeBytes),
            discoveredAt: try c.decode(Date.self, forKey: .discoveredAt),
            state: try c.decode(QueueState.self, forKey: .state),
            reasonLabel: try c.decodeIfPresent(String.self, forKey: .reasonLabel),
            attempts: try c.decode(Int.self, forKey: .attempts),
            subagentCount: try c.decodeIfPresent(Int.self, forKey: .subagentCount),
            subagentsDropped: try c.decodeIfPresent(Int.self, forKey: .subagentsDropped),
            // `decodeIfPresent` IS THE CONTRACT HERE, not a tolerance for an
            // older daemon. A missing key must stay `nil` and must never
            // become `"unknown"`: `unknown` is a state the daemon really
            // sends, and an absent field is a contributor who has no
            // eligibility question at all.
            eligibility: try c.decodeIfPresent(String.self, forKey: .eligibility),
            eligibilityReason: try c.decodeIfPresent(String.self, forKey: .eligibilityReason),
            // Optional at the decoder for ONE reason only -- a daemon
            // predating the field -- and not for the reason `eligibility` is.
            // Every daemon that knows the field sends it on every entry, and
            // an absent value here still draws a sentence: see
            // `attestationMark`.
            attestation: try c.decodeIfPresent(String.self, forKey: .attestation),
            attestationReason: try c.decodeIfPresent(String.self, forKey: .attestationReason),
            // Optional for the same one reason: a daemon predating the
            // field. Absent stays nil and reads as "no certificate" at
            // `holdsCertificate`, never as an error and never as held.
            holdsCertificateRaw: try c.decodeIfPresent(Bool.self, forKey: .holdsCertificateRaw)
        )
    }
}

/// How a join attempt ended.
///
/// The refusal carries the daemon's **control name**, not a sentence: the
/// words are `TCNearAiEnroll`'s, from the shared table, and a model that
/// carried prose would be a second place those ten sentences live.
enum NearAiEnrollOutcome: Sendable, Equatable {
    case joined(NearAiEnrollment)
    case refused(String)
}

/// What `near_ai_account_enroll` answers when it succeeds.
///
/// The account is whatever the commons resolved the daemon's NEAR AI token
/// to -- this shell never sends one and never asserts one. `enrolled` is
/// decoded rather than assumed from the absence of an error: a success
/// response that did not say so is not one this shell should celebrate.
struct NearAiEnrollment: Decodable, Sendable, Equatable {
    let enrolled: Bool
    let tenantID: String
    let accountID: String
    let deviceKeyID: String

    enum CodingKeys: String, CodingKey {
        case enrolled
        case tenantID = "tenant_id"
        case accountID = "account_id"
        case deviceKeyID = "device_key_id"
    }
}

/// An extension rather than a member so that `PreviewSummary` keeps its
/// memberwise initializer, which the debug capture screens build fixtures
/// with. Written out so `redactionsDistinct` can be absent without failing
/// the whole preview: a daemon predating the field sends no such key.
extension PreviewSummary {
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            tokenDistributionSummary: try c.decodeIfPresent(String.self, forKey: .tokenDistributionSummary),
            wouldSendBytes: try c.decode(Int.self, forKey: .wouldSendBytes),
            rawSessionBytes: try c.decode(Int.self, forKey: .rawSessionBytes),
            eventCount: try c.decode(Int.self, forKey: .eventCount),
            openingPrompt: try c.decode(String.self, forKey: .openingPrompt),
            redactions: try c.decode([String: Int].self, forKey: .redactions),
            redactionsDistinct:
                try c.decodeIfPresent([String: Int].self, forKey: .redactionsDistinct) ?? [:],
            piiLabelsPresent: try c.decode([String].self, forKey: .piiLabelsPresent),
            consentScopes: try c.decode([String].self, forKey: .consentScopes),
            residualRisk: try c.decode(String.self, forKey: .residualRisk),
            envelopeDigest: try c.decodeIfPresent(String.self, forKey: .envelopeDigest),
            enrolled: try c.decodeIfPresent(Bool.self, forKey: .enrolled) ?? false
        )
    }
}

/// An extension rather than a member so that `HistoryRecord` keeps its
/// memberwise initializer, which the debug capture screens and the
/// quarantine tests build fixtures with. Written out so `projectID` can be
/// absent -- records cached before the daemon carried it are still real
/// submissions, and failing them would empty the History screen rather than
/// degrade one row.
extension HistoryRecord {
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            submissionID: try c.decode(String.self, forKey: .submissionID),
            submittedAt: try c.decode(Date.self, forKey: .submittedAt),
            projectID: try c.decodeIfPresent(String.self, forKey: .projectID) ?? "",
            projectLabel: try c.decode(String.self, forKey: .projectLabel),
            source: try c.decode(String.self, forKey: .source),
            status: try c.decode(String.self, forKey: .status),
            consentScopes: try c.decode([String].self, forKey: .consentScopes),
            creditPointsPending: try c.decode(Double.self, forKey: .creditPointsPending),
            creditPointsFinal: try c.decodeIfPresent(Double.self, forKey: .creditPointsFinal),
            explanations: try c.decode([String].self, forKey: .explanations),
            lastRefreshedAt: try c.decodeIfPresent(Date.self, forKey: .lastRefreshedAt)
        )
    }
}

struct TokenStorageView: Decodable, Equatable {
    let captureEnabled: Bool?
    let captureLabel: String?
    let captureConfirmation: String?
    let captureNotice: String?
    let stateLine: String
    let scopeNote: String
    let cleanupLabel: String
    let discardLabel: String
    let discardConfirmation: String
    let cancelLabel: String
    let confirmLabel: String
    let failureLine: String
    enum CodingKeys: String, CodingKey {
        case captureEnabled = "capture_enabled", captureLabel = "capture_label", captureConfirmation = "capture_confirmation", captureNotice = "capture_notice"
        case stateLine = "state_line", scopeNote = "scope_note", cleanupLabel = "cleanup_label"
        case discardLabel = "discard_label", discardConfirmation = "discard_confirmation"
        case cancelLabel = "cancel_label", confirmLabel = "confirm_label", failureLine = "failure_line"
    }
}
