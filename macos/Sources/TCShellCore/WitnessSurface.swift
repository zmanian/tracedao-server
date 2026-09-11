import Foundation

/// The redaction witness surface's state machine: which answer each state
/// reaches for, and what the shell does with an answer it cannot name.
///
/// **Nothing in this file is a word.** Every sentence a contributor reads
/// arrives from `trace_commons_contributor::witness_copy` across the C ABI
/// -- as a `WitnessCopy` payload, or as a sentence that crate assembled.
/// What lives here is the mapping, because that is logic and not wording,
/// and because it can be tested in a target that does not link the dylib.
///
/// # There is no boolean on this surface
///
/// "Is a witness configured?" has two yes-answers that are opposites. A
/// PINNED witness certifies every submission. A CONFIGURED-BUT-UNPINNED one
/// REFUSES every submission, before any network call, because a client with
/// no pinned measurement cannot judge any quote it receives -- nothing
/// uploads at all. `WitnessTrustState` has one case per condition and
/// nothing here collapses them.
///
/// Having no witness at all is a legitimate, supported mode: local redaction
/// runs exactly as it does with this feature absent. It is not degraded and
/// is not rendered as a warning.

// MARK: - Tones

/// How a witness sentence is painted. Named rather than valued so this
/// target stays free of AppKit; the view maps these onto its own tokens.
///
/// Five cases, and the fifth is why this is not `RoutingTone`. A configured
/// witness with nothing pinned sends nothing at all, and neither of the two
/// tones that could otherwise carry it is honest: `attention` is the tone of
/// "something needs fixing before this can work", which reads as degraded
/// but functioning, and `neutral` reads as off. A refusal is neither.
public enum WitnessTone: Equatable, Sendable {
    /// Says nothing either way. No witness is configured, which is a
    /// supported mode and not a fault.
    case neutral
    /// Configured, and no answer has arrived yet.
    case held
    /// Configured, pinned, and working.
    case clear
    /// Something on this machine needs fixing, but sessions still go out.
    case attention
    /// Nothing is being sent at all until this is resolved.
    case refused

    /// A tone as the ABI answers it: `TC_WITNESS_TONE_*`, which is
    /// deliberately the disjoint range 10...14 and NOT `TC_ROUTING_TONE_*`.
    ///
    /// A value this build does not know is `.refused`, never `.neutral`.
    /// Every value added later is a condition this build has no words for,
    /// and on a surface about whether sessions leave the machine the safe
    /// reading of "I do not know" is "they are not". Spelled out rather than
    /// derived from this enum's declaration order, which is a Swift detail
    /// and not the contract.
    ///
    /// A routing tone fed in here (0...3) is unrecognised for every value
    /// rather than only for the dangerous one, which is what the disjoint
    /// numbering buys.
    public static func fromABI(_ value: Int32) -> WitnessTone {
        switch value {
        case 10: return .neutral
        case 11: return .held
        case 12: return .clear
        case 13: return .attention
        case 14: return .refused
        default: return .refused
        }
    }
}

// MARK: - States

/// What the witness is doing, as `tc_witness_trust_state` answers.
///
/// One case per condition. `absent` and `refusingUnpinned` are opposites and
/// must never render alike: the first says redaction is happening on this
/// machine, the second says nothing is being sent.
public enum WitnessTrustState: Equatable, Sendable {
    /// No witness configured. Local redaction runs. NOT a warning state.
    case absent
    /// Configured and pinned. Submissions go through the witness.
    case pinned
    /// Configured, nothing pinned. Every submission is refused.
    case refusingUnpinned
    /// Configured, pins unparsable. Also a total refusal, and a different
    /// mistake: somebody who mistyped a measurement must not be told they
    /// pinned none.
    case refusingPinMalformed
    /// Configured and pinned, refusing because a trace's inferences did not
    /// carry verified receipts. Reserved: no build returns it yet.
    case refusingInferenceReceiptsMissing
    /// No config exists to hold a witness. Not `absent` -- absent is a
    /// decision somebody made -- and not a refusal either.
    case notEnrolled
    /// The config could not be read. Not `absent`: a client whose behaviour
    /// is unknown is not a client redacting locally. A refusal.
    case unreadable
    /// A value this build cannot name, carried rather than discarded.
    ///
    /// This shell may run against a later library that has learned a new
    /// refusal. Folding one into `absent` would turn a future refusal into
    /// silence, so it is its own case and it reads as a refusal.
    case unnameable(Int32)

    /// The `TC_WITNESS_STATE_*` value this state travels as.
    public var abiCode: Int32 {
        switch self {
        case .absent: return 0
        case .pinned: return 1
        case .refusingUnpinned: return 2
        case .refusingPinMalformed: return 3
        case .refusingInferenceReceiptsMissing: return 4
        case .notEnrolled: return -1
        case .unreadable: return -2
        case .unnameable(let code): return code
        }
    }

    /// A state as the ABI answers it.
    public static func fromABI(_ code: Int32) -> WitnessTrustState {
        switch code {
        case 0: return .absent
        case 1: return .pinned
        case 2: return .refusingUnpinned
        case 3: return .refusingPinMalformed
        case 4: return .refusingInferenceReceiptsMissing
        case -1: return .notEnrolled
        case -2: return .unreadable
        default: return .unnameable(code)
        }
    }
}

// MARK: - The words

/// The witness surface's fixed words, decoded from what the Rust exported.
///
/// Every property is filled from the payload. None has a default and none is
/// written in Swift: a word this shell invented would be a word the Linux
/// and Windows shells do not print, and several of these are privacy claims,
/// so inventing one is inventing a claim.
///
/// Decoding is here rather than in `TCBridge` so it can be tested without
/// linking the dylib; `TCBridgeTests` checks the same properties against the
/// real export.
public struct WitnessCopy: Decodable, Equatable, Sendable {
    public let heading: String
    public let intro: String
    /// What a certificate proves -- and, explicitly, what it does not. Never
    /// summarised by a shell.
    public let certificateMeans: String
    public let measurementsNote: String
    public let urlTitle: String
    public let signingAddressTitle: String
    public let measurementsTitle: String
    public let configure: String
    public let clear: String
    /// What clearing actually does. Not "off": redaction still happens, on
    /// this machine.
    public let clearNote: String
    public let appliesAtOnce: String
    public let tokenHeading: String?
    public let tokenDisclosure: String?
    public let tokenCaptureNote: String?
    public let tokenScopeNote: String?
    public let tokenEnable: String?
    public let tokenDisable: String?
    public let tokenConfirm: String?
    public let tokenCancel: String?
    public let tokenEnabled: String?
    public let tokenDisabled: String?
    public let tokenSaveFailed: String?
    public let inferenceHeading: String
    public let inferenceDisclosure: String
    public let inferenceCaptureNote: String
    public let inferenceScopeNote: String
    public let inferenceEnable: String
    public let inferenceDisable: String
    public let inferenceConfirm: String
    public let inferenceCancel: String
    public let inferenceEnabled: String
    public let inferenceDisabled: String
    public let inferenceSaveFailed: String
    public let review: WitnessReviewCopy?
    public let onboarding: FirstContributionCopy?
    public let wallet: WalletCopy?
    public let admission: AdmissionCopy?


    enum CodingKeys: String, CodingKey {
        case review, onboarding, wallet, admission
        case heading
        case intro
        case certificateMeans = "certificate_means"
        case measurementsNote = "measurements_note"
        case urlTitle = "url_title"
        case signingAddressTitle = "signing_address_title"
        case measurementsTitle = "measurements_title"
        case configure
        case clear
        case clearNote = "clear_note"
        case appliesAtOnce = "applies_at_once"
        case tokenHeading = "token_heading"
        case tokenDisclosure = "token_disclosure"
        case tokenCaptureNote = "token_capture_note"
        case tokenScopeNote = "token_scope_note"
        case tokenEnable = "token_enable"
        case tokenDisable = "token_disable"
        case tokenConfirm = "token_confirm"
        case tokenCancel = "token_cancel"
        case tokenEnabled = "token_enabled"
        case tokenDisabled = "token_disabled"
        case tokenSaveFailed = "token_save_failed"
        case inferenceHeading = "inference_heading"
        case inferenceDisclosure = "inference_disclosure"
        case inferenceCaptureNote = "inference_capture_note"
        case inferenceScopeNote = "inference_scope_note"
        case inferenceEnable = "inference_enable"
        case inferenceDisable = "inference_disable"
        case inferenceConfirm = "inference_confirm"
        case inferenceCancel = "inference_cancel"
        case inferenceEnabled = "inference_enabled"
        case inferenceDisabled = "inference_disabled"
        case inferenceSaveFailed = "inference_save_failed"

    }

    /// Decode the payload, or nil if it will not parse.
    ///
    /// Nil, never a partly-filled value with placeholder words: a card that
    /// renders "" where a sentence belongs is worse than one that renders
    /// nothing, and a card that renders a Swift-authored word is worse than
    /// both.
    public static func decode(fromJSON json: String) -> WitnessCopy? {
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(WitnessCopy.self, from: data)
    }
}

// MARK: - What the ABI answers about the configuration

/// `tc_witness_status_json`, decoded.
///
/// The URL and signing address are the contributor's own configuration and
/// cross the ABI verbatim -- a screen that will not show what it is asking
/// somebody to trust with their raw session is not a settings screen.
///
/// The state is `stateCode` and nothing else. **Do not derive it from `url`
/// being non-nil**: that is the boolean this surface refuses to hand a
/// shell, spelled differently.
public struct WitnessStatus: Decodable, Equatable, Sendable {
    public let stateCode: Int32
    /// A fixed operator label, null unless the state is a refusing one. It
    /// is not wording and no sentence may be built around it.
    public let refusal: String?
    public let url: String?
    public let signingAddress: String?
    /// How many measurements are CONFIGURED, not how many parsed: a
    /// malformed pin reports the entries that were written. Always the
    /// length of `pinnedMeasurements`.
    public let pinnedMeasurementCount: Int
    /// That count as a sentence, or nil where there is no witness to count
    /// for -- `absent`, `not_enrolled` and `unreadable`.
    ///
    /// Nil is rendered as NOTHING. A count of the pins on a witness that
    /// does not exist is not a shorter sentence, it is a wrong one, and a
    /// bare numeral in its place would be this shell writing wording by
    /// omission.
    public let pinnedMeasurementLine: String?
    /// The pinned sets VERBATIM, in stored order.
    ///
    /// Exactly what `tc_witness_configure` takes as `measurements_json`:
    /// pre-fill the editor from it and hand it straight back. It is not
    /// parsed and must not be re-serialised from anything -- a shell that
    /// reformats a pin is a shell that can reformat it wrongly, and nothing
    /// on this card would show which entry had changed.
    ///
    /// An entry this build cannot parse is here AS IT IS STORED rather than
    /// omitted: the state already says `refusing_pin_malformed`, and the
    /// entry is present so the typo can be seen and repaired. Dropping it
    /// would delete a contributor's work the next time they saved.
    public let pinnedMeasurements: [String]

    enum CodingKeys: String, CodingKey {
        case stateCode = "state_code"
        case refusal
        case url
        case signingAddress = "signing_address"
        case pinnedMeasurementCount = "pinned_measurement_count"
        case pinnedMeasurementLine = "pinned_measurement_line"
        case pinnedMeasurements = "pinned_measurements"
    }

    public init(
        stateCode: Int32,
        refusal: String?,
        url: String?,
        signingAddress: String?,
        pinnedMeasurementCount: Int,
        pinnedMeasurementLine: String?,
        pinnedMeasurements: [String]
    ) {
        self.stateCode = stateCode
        self.refusal = refusal
        self.url = url
        self.signingAddress = signingAddress
        self.pinnedMeasurementCount = pinnedMeasurementCount
        self.pinnedMeasurementLine = pinnedMeasurementLine
        self.pinnedMeasurements = pinnedMeasurements
    }

    /// Decode, or nil. Nil rather than a half-filled value, for the reason
    /// `WitnessCopy.decode` gives.
    public static func decode(fromJSON json: String) -> WitnessStatus? {
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(WitnessStatus.self, from: data)
    }

    public var trustState: WitnessTrustState { WitnessTrustState.fromABI(stateCode) }
}

// MARK: - The card's controls

/// The three things a contributor types, held as a value so a background
/// refresh cannot rewrite what is being typed.
///
/// `measurements` is one measurement set per line, as typed. It is a list
/// because an image upgrade moves the measurement and leaves the signing
/// address where it is: the new one is added before the fleet rolls, and a
/// client holding only the old one refuses the upgraded deployment.
public struct WitnessForm: Equatable, Sendable {
    public var url: String
    public var signingAddress: String
    public var measurements: String

    public init(url: String, signingAddress: String, measurements: String) {
        self.url = url
        self.signingAddress = signingAddress
        self.measurements = measurements
    }

    /// Seed from what came back, and from nothing else.
    ///
    /// The editor is PRE-FILLED from `pinnedMeasurements`, one entry per
    /// line and each entry verbatim. It was write-only before the ABI
    /// returned them, which meant retyping every pin to change a URL.
    ///
    /// Nothing is added: a witness with nothing pinned seeds an EMPTY box.
    /// The box is the contributor's whole answer -- there is no "keep what
    /// is there" mode and there must not be one, because it would save a pin
    /// nobody looked at -- so a placeholder line here would be a pin this
    /// shell typed.
    ///
    /// A nil status -- not enrolled, or a config that could not be read --
    /// seeds an empty form rather than carrying a previous witness's address
    /// forward.
    public static func fromStatus(_ status: WitnessStatus?) -> WitnessForm {
        WitnessForm(
            url: status?.url ?? "",
            signingAddress: status?.signingAddress ?? "",
            measurements: (status?.pinnedMeasurements ?? []).joined(separator: "\n")
        )
    }

    /// The entries, one per line, in order.
    ///
    /// **Nothing is trimmed and nothing is rewritten.** These go straight
    /// back to `tc_witness_configure`, so this has to be the identity on
    /// everything `pinnedMeasurements` returned -- including an entry this
    /// build cannot parse, which comes back so a contributor can repair the
    /// typo and must not be repaired by this shell on the way past.
    ///
    /// The one thing dropped is a line with nothing but whitespace on it:
    /// that is what pressing return in the editor makes, and it is not an
    /// entry. A line that has any content at all is kept exactly as typed,
    /// leading and trailing spaces included -- no measurement is whitespace,
    /// so nothing storable is lost, and trimming a stored entry would be
    /// this shell rewriting a pin nobody touched.
    public var measurementLines: [String] {
        measurements
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    /// The measurement list as the JSON array `tc_witness_configure` takes,
    /// or nil when nothing is pinned.
    ///
    /// Encoded, never concatenated: a pasted value can carry a quote or a
    /// backslash, and a hand-built string would send something nobody typed.
    public var measurementsJSON: String? {
        let lines = measurementLines
        guard !lines.isEmpty else { return nil }
        guard let data = try? JSONEncoder().encode(lines) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Whether this shell will offer to write the configuration.
    ///
    /// An empty pin list is refused here as well as by the ABI, because
    /// writing one produces a client that refuses every submission from the
    /// moment it is saved -- a total upload outage. This shell does not
    /// offer the button that would do that.
    public var canConfigure: Bool {
        !url.trimmingCharacters(in: .whitespaces).isEmpty
            && !signingAddress.trimmingCharacters(in: .whitespaces).isEmpty
            && measurementsJSON != nil
    }
}

// MARK: - The sentences that come from Rust

/// The witness sentences and tones, injected rather than imported.
///
/// They are decided in Rust and cross the ABI already finished; `TCBridge`
/// supplies these closures in the app. This target does not link the dylib,
/// which is why they arrive as values.
///
/// `stateLine` returns nil for a state this build cannot name, and the shell
/// must then render NO sentence rather than one of its own. `stateTone`
/// never fails -- a styling call that could fail would leave this shell
/// choosing a tone for itself -- and fails closed to refused on the same
/// input.
public struct WitnessCalls: Sendable {
    public let stateLine: @Sendable (Int32) -> String?
    public let stateTone: @Sendable (Int32) -> Int32
    public let lastResultLine: @Sendable () -> String?
    public let lastResultTone: @Sendable () -> Int32

    public init(
        stateLine: @escaping @Sendable (Int32) -> String?,
        stateTone: @escaping @Sendable (Int32) -> Int32,
        lastResultLine: @escaping @Sendable () -> String?,
        lastResultTone: @escaping @Sendable () -> Int32
    ) {
        self.stateLine = stateLine
        self.stateTone = stateTone
        self.lastResultLine = lastResultLine
        self.lastResultTone = lastResultTone
    }
}

// MARK: - The mapping

public enum WitnessSurface {
    /// The sentence for a state, or nil where this build has none.
    ///
    /// Nil is not an error and not an empty string: the shell renders
    /// nothing at all, and pairs that with `tone(forState:)`, which still
    /// answers.
    public static func stateLine(_ code: Int32, calls: WitnessCalls) -> String? {
        calls.stateLine(code)
    }

    /// How that sentence is painted, taken from the STATE and never from the
    /// sentence it produced. One branch table, not two.
    public static func tone(forState code: Int32, calls: WitnessCalls) -> WitnessTone {
        WitnessTone.fromABI(calls.stateTone(code))
    }

    /// Whether nothing is going out. Every refusing state, plus every state
    /// this build cannot name.
    ///
    /// `absent` and `notEnrolled` are NOT refusals: the first is a supported
    /// mode, and the second is a setup that has simply not happened.
    public static func isRefusal(_ state: WitnessTrustState) -> Bool {
        switch state {
        case .absent, .pinned, .notEnrolled:
            return false
        case .refusingUnpinned, .refusingPinMalformed,
            .refusingInferenceReceiptsMissing, .unreadable, .unnameable:
            return true
        }
    }

    /// Whether the clear action is offered.
    ///
    /// **This is a refusal's way out.** A configured-but-unpinned witness
    /// stops every upload, and a card that showed that and offered nothing
    /// to do about it would be the trap `AppModel.Startup.needsRoots` exists
    /// to avoid: a refusal rendered behind the thing it was blocking.
    /// Offered on every refusal, including one this build cannot name.
    ///
    /// Not offered where there is nothing to clear: no witness configured,
    /// or no config at all yet.
    public static func offersClear(_ state: WitnessTrustState) -> Bool {
        switch state {
        case .absent, .notEnrolled:
            return false
        case .pinned, .refusingUnpinned, .refusingPinMalformed,
            .refusingInferenceReceiptsMissing, .unreadable, .unnameable:
            return true
        }
    }

    /// Whether the configure fields are offered.
    ///
    /// The other way out of the unpinned refusal: pinning a measurement is
    /// exactly what that state asks for. Withheld only before enrollment,
    /// where there is no config to write into and the call would be refused.
    public static func offersConfigure(_ state: WitnessTrustState) -> Bool {
        state != .notEnrolled
    }

    /// What the last submission this process made did about the witness.
    ///
    /// The only form a shell may print. The JSON behind it carries a fixed
    /// operator label and an `n_of_m` pair a shell must not phrase itself;
    /// this sentence already contains the count when one was carried.
    public static func lastResultLine(calls: WitnessCalls) -> String? {
        calls.lastResultLine()
    }

    /// How that sentence is painted. A refused send is refused and never
    /// attention: nothing was sent at all, which is not a
    /// degraded-but-working state.
    public static func lastResultTone(calls: WitnessCalls) -> WitnessTone {
        WitnessTone.fromABI(calls.lastResultTone())
    }
}

public struct WitnessReviewCopy: Decodable, Equatable, Sendable {
    public let heading, disclosure, action, confirm, cancel, working, failed, immutable: String
}

public struct FirstContributionCopy: Decodable, Equatable, Sendable {
    public let heading, start, review: String
    public let followUp, agentSetup: String
    enum CodingKeys: String, CodingKey {
        case heading, start, review
        case followUp = "follow_up", agentSetup = "agent_setup"
    }
}

public struct WalletCopy: Decodable, Equatable, Sendable {
    public let heading: String
    public let disclosure: String
    public let commons: String
    public let account: String
    public let check: String
    public let start: String
    public let cancel: String
    public let available: String
    public let unavailable: String
    public let addressRefused: String
    public let unreachable: String
    public let opening: String
    public let waiting: String
    public let failed: String
    public let cancelled: String
    public let refusedGlyph: String
    public let refusedTone: String
    enum CodingKeys: String, CodingKey {
        case heading = "heading"
        case disclosure = "disclosure"
        case commons = "commons"
        case account = "account"
        case check = "check"
        case start = "start"
        case cancel = "cancel"
        case available = "available"
        case unavailable = "unavailable"
        case addressRefused = "address_refused"
        case unreachable = "unreachable"
        case opening = "opening"
        case waiting = "waiting"
        case failed = "failed"
        case cancelled = "cancelled"
        case refusedGlyph = "refused_glyph"
        case refusedTone = "refused_tone"
    }
}
public struct AdmissionCopy: Decodable, Equatable, Sendable {
    public let heading: String
    public let disclosure: String
    public let prerequisite: String
    public let backend: String
    public let confirm: String
    public let cancel: String
    public let permission: String
    public let working: String
    public let ready: String
    public let failed: String
    public let failedReceiptEndpoint: String
    public let failedReceiptEndpointInvalid: String
    public let failedPermission: String
    public let failedNotEnrolled: String
    public let failedSessionUnreadable: String
    public let failedSourceUnsupported: String
    public let failedProxyMissing: String
    public let failedProxyUntrusted: String
    public let failedHostsUntrusted: String
    public let failedBackend: String
    public let failedTryAgain: String
    public let refusedGlyph: String
    public let refusedTone: String
    enum CodingKeys: String, CodingKey {
        case heading = "heading"
        case disclosure = "disclosure"
        case prerequisite = "prerequisite"
        case backend = "backend"
        case confirm = "confirm"
        case cancel = "cancel"
        case permission = "permission"
        case working = "working"
        case ready = "ready"
        case failed = "failed"
        case failedReceiptEndpoint = "failed_receipt_endpoint"
        case failedReceiptEndpointInvalid = "failed_receipt_endpoint_invalid"
        case failedPermission = "failed_permission"
        case failedNotEnrolled = "failed_not_enrolled"
        case failedSessionUnreadable = "failed_session_unreadable"
        case failedSourceUnsupported = "failed_source_unsupported"
        case failedProxyMissing = "failed_proxy_missing"
        case failedProxyUntrusted = "failed_proxy_untrusted"
        case failedHostsUntrusted = "failed_hosts_untrusted"
        case failedBackend = "failed_backend"
        case failedTryAgain = "failed_try_again"
        case refusedGlyph = "refused_glyph"
        case refusedTone = "refused_tone"
    }
}
