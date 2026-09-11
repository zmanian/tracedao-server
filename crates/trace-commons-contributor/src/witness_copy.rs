//! The witness surface's words and tones, in one place, for all three
//! shells.
//!
//! This module exists for the same reason [`crate::routing_copy`] does, and
//! for one more. The general reason: three shells render this surface, and a
//! word kept in three places is a privacy claim that silently stops matching
//! itself. The specific reason: the Windows shell's interop tests
//! (`NoWordingIsAuthoredInThisShell`,
//! `TheSettingsScreenAsksForTheRowRatherThanWritingIt`) fail on a hand
//! authored string literal, so on that shell there is nowhere else for these
//! words to live.
//!
//! GTK does not go through the C ABI -- it depends on
//! `trace-commons-contributor` directly -- so everything here is ordinary
//! public Rust, and `trace-commons-contributor-ffi` is a thin projection of
//! it. Nothing about this surface may exist only in the FFI crate; that is
//! how the three shells drift apart.
//!
//! # What a certificate says
//!
//! A witness certificate covers redaction mechanics and a residual-risk
//! verdict. **It does not say a trace is clean**, and no sentence in this
//! module may be read as saying so. The same rule governs the receipt count:
//! it is reported as `n of m`, never as the word "attested" and never as a
//! flag.

use serde::Serialize;

use crate::witness::status::{InferenceReceiptCount, WitnessLastResult, WitnessTrustState};

/// The card's heading.
pub const WITNESS_HEADING: &str = "Redaction witness";

/// What the card is for, in one sentence a contributor can act on.
pub const WITNESS_INTRO: &str = concat!(
    "A witness is a sealed machine that removes private material from a session for you, ",
    "instead of this app doing it here. Turning it on means sending the session to that ",
    "machine before anything is redacted, which is why it is checked against a measurement ",
    "you pin before a single byte leaves."
);

/// What the certificate proves, stated where a contributor reads it, so no
/// shell has to summarise it and no shell summarises it wrongly.
pub const WITNESS_CERTIFICATE_MEANS: &str = concat!(
    "A certificate records what the witness removed and the risk it judged was left. ",
    "It is not a statement that a session is clean."
);

/// Why the pin is a list and not a value.
pub const WITNESS_MEASUREMENTS_NOTE: &str = concat!(
    "More than one measurement can be pinned. An upgrade to the witness changes its ",
    "measurement, so the new one is added here before the change happens; a client that ",
    "holds only the old one will refuse the upgraded witness."
);

/// Field titles.
pub const WITNESS_URL_TITLE: &str = "Address";
pub const WITNESS_SIGNING_ADDRESS_TITLE: &str = "Signing key";
pub const WITNESS_MEASUREMENTS_TITLE: &str = "Pinned measurements";

/// Actions.
pub const WITNESS_CONFIGURE: &str = "Use this witness";
pub const WITNESS_CLEAR: &str = "Stop using a witness";

/// What clearing actually does. Not "off": the redaction still happens, on
/// this machine, and saying "off" would read as no redaction at all.
pub const WITNESS_CLEAR_NOTE: &str = concat!(
    "Sessions go back to being redacted on this machine, and are sent with this app's own ",
    "judgement of what was left rather than a certificate."
);

/// Changes take effect on the next upload, with no restart.
pub const WITNESS_APPLIES_AT_ONCE: &str = "Changes here apply to the next session sent.";

/// Consent to carry inference content is independent of observing a proxy's
/// ledger, configuring a witness, and acknowledging the extra privacy scan.
/// Metadata only: never render token bytes or alternative text in status UI.
pub fn token_review_summary(
    kept: usize,
    omitted: u64,
    alternatives: usize,
    omitted_alternatives: u64,
) -> String {
    format!(
        "Token probabilities: {kept} positions and {alternatives} alternatives included; {omitted} positions and {omitted_alternatives} alternatives removed. Restricted research data. Probabilities are not recalculated after filtering."
    )
}

pub const WITNESS_TOKEN_HEADING: &str = "Token probabilities";
pub const WITNESS_TOKEN_DISCLOSURE: &str = "Include token probabilities and alternative tokens in sessions you review with your witness. Alternatives can contain personal information even when the chosen text does not. The witness filters them before contribution; they remain restricted research data.";
pub const WITNESS_TOKEN_CAPTURE_NOTE: &str = "Capture is configured separately in Ironwire for supported models. This permission does not turn on capture.";
pub const WITNESS_TOKEN_SCOPE_NOTE: &str = "After the server confirms durable storage, this app removes its local bundle and releases its capture lease. Your agent session files stay on this device. Withdrawing a contribution is a separate action.";
pub const WITNESS_TOKEN_ENABLE: &str = "Include token probabilities";
pub const WITNESS_TOKEN_DISABLE: &str = "Stop including token probabilities";
pub const WITNESS_TOKEN_CONFIRM: &str = "Allow token review";
pub const WITNESS_TOKEN_CANCEL: &str = "Not now";
pub const WITNESS_TOKEN_ENABLED: &str = "Token probabilities will be included in explicit witness reviews when a matching capture is available.";
pub const WITNESS_TOKEN_DISABLED: &str = "Token probabilities are not included.";
pub const WITNESS_TOKEN_SAVE_FAILED: &str =
    "The change could not be confirmed. Check the saved setting before trying again.";

pub const WITNESS_INFERENCE_HEADING: &str = "Include captured inference evidence";
pub const WITNESS_INFERENCE_DISCLOSURE: &str = concat!(
    "When a contribution uses a witness, this allows the final model call's exact request ",
    "and response to be sent to that remote witness before redaction. These may include ",
    "prompts, conversation history, tool results, and secrets. The witness checks the ",
    "evidence and removes these attached bodies from the contribution it returns. ",
    "Looking up a receipt with NEAR AI can also reveal which call you are contributing."
);
pub const WITNESS_INFERENCE_CAPTURE_NOTE: &str = concat!(
    "IronWire capture must be configured separately. When capture is enabled, request ",
    "and response bodies are stored on this machine. Turning this permission off stops ",
    "including bodies in future contributions; it does not turn off IronWire capture ",
    "or delete bodies already stored. Work already in progress may still finish."
);
pub const WITNESS_INFERENCE_SCOPE_NOTE: &str = concat!(
    "This permission does not connect an agent to NEAR AI, fund inference, or prove a ",
    "receipt was verified. A supported desktop app asks separately before sending a ",
    "session for witness review. This permission alone does not make it ready to send."
);
pub const WITNESS_INFERENCE_ENABLE: &str = "Review permission";
pub const WITNESS_INFERENCE_DISABLE: &str = "Stop including inference bodies";
pub const WITNESS_INFERENCE_CONFIRM: &str = "Allow sending captured bodies";
pub const WITNESS_INFERENCE_CANCEL: &str = "Not now";
pub const WITNESS_INFERENCE_ENABLED: &str =
    "Permission saved. Captured bodies may be included when a contribution uses a witness.";
pub const WITNESS_INFERENCE_DISABLED: &str = "Captured inference bodies are not included.";
pub const WITNESS_INFERENCE_SAVE_FAILED: &str =
    "Couldn't confirm this permission was saved. Reload settings to check before continuing.";

/// How a witness sentence is painted.
///
/// Five values, and the fifth is the reason this is not
/// [`crate::routing_copy::StateTone`]. A configured witness with nothing
/// pinned sends **nothing at all**, and neither of the two tones that could
/// otherwise carry it is honest: `Attention` is the tone of "something here
/// needs fixing before this can work", which reads as a degraded but
/// functioning setup, and `Neutral` reads as off. A refusal is neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessTone {
    /// Says nothing either way. No witness is configured, which is a
    /// supported mode and not a fault.
    Neutral,
    /// Configured, and no answer has arrived yet.
    Held,
    /// Configured, pinned, and working.
    Clear,
    /// Something on this machine needs fixing, but sessions still go out.
    Attention,
    /// Nothing is being sent at all until this is resolved.
    Refused,
}

impl WitnessTone {
    /// The stable integer this tone travels as across the C ABI.
    ///
    /// # Why these are not the routing tone's numbers
    ///
    /// The obvious choice was to reuse `TC_ROUTING_TONE_NEUTRAL`..`ATTENTION`
    /// (0..=3) and give `Refused` the next value. That is the dangerous
    /// choice. The existing consumers of the routing tone spell out their
    /// arms and map anything else to *neutral* -- Windows'
    /// `RoutingSurface.FromAbiTone` does exactly this -- so a witness tone
    /// fed into a routing mapper would render a refusal as "nothing to say".
    /// Silently degrading a refusal to neutral is the precise failure this
    /// whole surface exists to prevent, and picking overlapping numbers
    /// makes it a one-line mistake.
    ///
    /// A disjoint range makes that mistake loud instead: a witness tone
    /// passed to a routing mapper is unrecognised for EVERY value, not just
    /// the new one, so the surface is visibly wrong the first time anyone
    /// looks at it rather than wrong only in the case nobody tested.
    ///
    /// Extending the routing enum was the other option and is rejected for
    /// the same reason in reverse: it would widen the domain of an ABI value
    /// every current consumer already switches on, and every one of them
    /// would keep compiling.
    pub fn abi_code(self) -> i32 {
        match self {
            Self::Neutral => 10,
            Self::Held => 11,
            Self::Clear => 12,
            Self::Attention => 13,
            Self::Refused => 14,
        }
    }
}

/// The sentence for a witness state.
///
/// One sentence per state, because the states are one per condition. In
/// particular [`WitnessTrustState::Absent`] and
/// [`WitnessTrustState::RefusingUnpinned`] get sentences that cannot be
/// mistaken for each other: the first says redaction is happening here, the
/// second says nothing is being sent.
#[must_use]
pub fn witness_state_line(state: WitnessTrustState) -> &'static str {
    match state {
        WitnessTrustState::Absent => concat!(
            "Not in use. Sessions are redacted on this machine before they are sent, ",
            "which is the normal arrangement."
        ),
        WitnessTrustState::Pinned => concat!(
            "In use. Each session is redacted by the pinned witness, which signs a record ",
            "of what it removed and the risk it judged was left."
        ),
        WitnessTrustState::RefusingUnpinned => concat!(
            "Nothing is being sent. A witness is set but no measurement is pinned, and this ",
            "app will not hand a session to a machine it cannot check. Pin the measurement ",
            "this witness reports."
        ),
        WitnessTrustState::RefusingPinMalformed => concat!(
            "Nothing is being sent. The pinned measurement could not be read, so this app ",
            "cannot check the witness. Check what was entered against what the witness ",
            "reports."
        ),
        WitnessTrustState::RefusingInferenceReceiptsMissing => concat!(
            "Nothing is being sent. The witness requires a receipt for each model call, and ",
            "these sessions carried none."
        ),
        WitnessTrustState::NotEnrolled => {
            "Not set up yet. Join an instance first, and a witness can be chosen after that."
        }
        WitnessTrustState::SettingsUnreadable => concat!(
            "Nothing is being sent. This app could not read its own settings, so it cannot ",
            "say what would happen to a session."
        ),
    }
}

/// The tone [`witness_state_line`]'s sentence is painted in.
///
/// ONE BRANCH TABLE, NOT TWO. This takes what the sentence takes, so the two
/// stay in step by construction, and no shell may recover the tone by
/// comparing the rendered sentence against anything.
#[must_use]
pub fn witness_state_tone(state: WitnessTrustState) -> WitnessTone {
    match state {
        WitnessTrustState::Absent => WitnessTone::Neutral,
        WitnessTrustState::Pinned => WitnessTone::Clear,
        // Nothing about a witness is being declined here; the device has no
        // account yet. Painting it as a refusal would accuse a setup that has
        // simply not happened.
        WitnessTrustState::NotEnrolled => WitnessTone::Neutral,
        WitnessTrustState::RefusingUnpinned
        | WitnessTrustState::RefusingPinMalformed
        | WitnessTrustState::RefusingInferenceReceiptsMissing
        | WitnessTrustState::SettingsUnreadable => WitnessTone::Refused,
    }
}

/// How many measurement sets are pinned, as a sentence.
///
/// Two shells rendered this as a bare numeral and both declined to write a
/// sentence for it, which is the right instinct and the reason this function
/// exists: a number with no words around it on a privacy surface is a shell
/// authoring wording by omission.
///
/// The zero case says only that nothing is pinned. It does NOT repeat the
/// outage -- [`witness_state_line`] already leads with "Nothing is being
/// sent." for that state, and a card that says it twice reads as two
/// separate faults.
#[must_use]
pub fn witness_pinned_count_line(count: usize) -> String {
    match count {
        0 => "No measurement is pinned.".to_string(),
        1 => "One measurement is pinned.".to_string(),
        n => format!("{n} measurements are pinned."),
    }
}

/// How many of a session's model calls carried a receipt, as a sentence.
///
/// ALWAYS THE PAIR. There is no sentence here that says "attested", and none
/// that reduces the count to a yes or a no: a flag would be false on nearly
/// every real session while reading as an accusation, and true on a session
/// with one model call in it while reading as a guarantee.
#[must_use]
pub fn witness_n_of_m_line(count: InferenceReceiptCount) -> String {
    if count.m == 1 {
        return format!("{} of 1 model call carried a receipt.", count.n);
    }
    format!("{} of {} model calls carried a receipt.", count.n, count.m)
}

/// The sentence for what the last submission did about the witness.
#[must_use]
pub fn witness_last_result_line(result: &WitnessLastResult) -> String {
    match result {
        WitnessLastResult::NotObserved => {
            "Nothing has been sent since this app started.".to_string()
        }
        WitnessLastResult::LocalRedaction => {
            "Last sent: redacted on this machine, with no certificate.".to_string()
        }
        WitnessLastResult::Certified { n_of_m } => {
            let mut line = concat!(
                "Last sent: redacted by the witness, which signed a record of what it ",
                "removed and the risk it judged was left."
            )
            .to_string();
            if let Some(count) = n_of_m {
                line.push(' ');
                line.push_str(&witness_n_of_m_line(*count));
            }
            line
        }
        // The label is deliberately absent from the sentence. It is a fixed
        // operator string, not wording, and a contributor reading "nothing
        // was sent" needs to know that before they need to know which check
        // said so. A shell that wants to show it has it separately, from
        // the status surface.
        WitnessLastResult::Refused {
            certificate_obtained,
            ..
        } => {
            if *certificate_obtained {
                concat!(
                    "Last send was refused. The witness answered, but its certificate did not ",
                    "match what it returned, so nothing was sent."
                )
                .to_string()
            } else {
                "Last send was refused. The witness could not be used, so nothing was sent."
                    .to_string()
            }
        }
    }
}

/// The tone [`witness_last_result_line`]'s sentence is painted in.
#[must_use]
pub fn witness_last_result_tone(result: &WitnessLastResult) -> WitnessTone {
    match result {
        WitnessLastResult::NotObserved => WitnessTone::Held,
        // Not `Clear`. Local redaction is the normal arrangement and claims
        // nothing beyond itself; painting it as reassuring would put the
        // same tone on it as on a certified send.
        WitnessLastResult::LocalRedaction => WitnessTone::Neutral,
        WitnessLastResult::Certified { .. } => WitnessTone::Clear,
        WitnessLastResult::Refused { .. } => WitnessTone::Refused,
    }
}

/// Explicit remote review disclosure, shared by every native shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WitnessReviewCopy {
    pub heading: &'static str,
    pub disclosure: &'static str,
    pub action: &'static str,
    pub confirm: &'static str,
    pub cancel: &'static str,
    pub working: &'static str,
    /// The sentence for a refusal this build has no words for. Every refusal
    /// the client actually raises is classified by
    /// [`witness_refusal_line`]; this is what an unknown label gets, and it
    /// is honest -- the build does not know what happened.
    pub failed: &'static str,
    /// The reviewer's address is not on this computer's allowed list.
    pub failed_host_not_allowed: &'static str,
    /// No measurement is pinned, or none matched what was reported.
    pub failed_measurement_unpinned: &'static str,
    /// The reviewer could not be reached, or answered something unreadable.
    /// Three causes, one move.
    pub failed_unreachable: &'static str,
    /// The reviewer could not prove it is what it claims -- an unverified or
    /// replayed quote, an unexpected signer, a certificate that does not
    /// cover or does not verify. Five causes and one move, because the
    /// difference between them is not something a contributor can act on.
    pub failed_unproven: &'static str,
    /// The reviewer returned the session still carrying the model text it
    /// was given.
    ///
    /// Kept apart from [`Self::failed_unproven`] even though the move is also
    /// "stop and ask": the data consequence is different, and a sentence on
    /// this surface has to state the data consequence.
    pub failed_bodies_returned: &'static str,
    /// Larger than this client will send. Refused here, before anything was
    /// offered.
    pub failed_too_large: &'static str,
    /// No usable enrollment, so there is nothing to review under.
    pub failed_not_connected: &'static str,
    /// The reviewer declined the receipt behind an evidence-bearing request:
    /// its signer, its model, or the size of the request it covers is outside
    /// what that deployment accepts.
    ///
    /// The common refusal during a rollout, and the reason this whole family
    /// exists: it used to arrive as the same word as a reviewer that was
    /// simply down.
    pub failed_receipt_declined: &'static str,
    pub immutable: &'static str,
}

/// Persistent next steps, without inferring acceptance or funding from local setup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FirstContributionCopy {
    pub heading: &'static str,
    pub start: &'static str,
    pub review: &'static str,
    pub follow_up: &'static str,
    pub agent_setup: &'static str,
}

/// Fixed wallet words used by the core state machine and all native adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WalletCopy {
    pub heading: &'static str,
    pub disclosure: &'static str,
    pub commons: &'static str,
    pub account: &'static str,
    pub check: &'static str,
    pub start: &'static str,
    pub cancel: &'static str,
    pub available: &'static str,
    pub unavailable: &'static str,
    /// The address was rejected before anything was sent.
    pub address_refused: &'static str,
    /// The address was dialled and did not answer.
    pub unreachable: &'static str,
    pub opening: &'static str,
    pub waiting: &'static str,
    pub failed: &'static str,
    pub cancelled: &'static str,
    pub refused_glyph: &'static str,
    pub refused_tone: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmissionCopy {
    pub heading: &'static str,
    pub disclosure: &'static str,
    pub prerequisite: &'static str,
    pub backend: &'static str,
    pub confirm: &'static str,
    pub cancel: &'static str,
    pub permission: &'static str,
    pub working: &'static str,
    pub ready: &'static str,
    pub failed: &'static str,
    /// Said instead of [`Self::failed`] when the commons has published no
    /// receipt service and nothing on this machine supplied one.
    ///
    /// Every other admission failure names something the contributor holds --
    /// an agent, a backend, a capture permission -- so "then try again" is
    /// real advice. This one names nothing they hold. Borrowing the generic
    /// sentence sends them round a loop of settings that were never wrong,
    /// and no wording of "check your settings" can end that loop.
    ///
    /// It names the commons rather than this app, because that is where the
    /// value comes from, and it does not ask for a URL: a contributor has no
    /// way to know which one is right, and this app would not take one from
    /// them anyway.
    pub failed_receipt_endpoint: &'static str,
    /// A receipt endpoint is configured that this client will not call.
    pub failed_receipt_endpoint_invalid: &'static str,
    /// The permission that lets captured inference bodies be used has not
    /// been given, or this session was not confirmed.
    pub failed_permission: &'static str,
    /// No enrolled account or device key on this computer.
    pub failed_not_enrolled: &'static str,
    /// The chosen session cannot be read back.
    pub failed_session_unreadable: &'static str,
    /// The session came from an agent this build cannot read.
    pub failed_source_unsupported: &'static str,
    /// IronWire is not running, or cannot capture request bodies.
    pub failed_proxy_missing: &'static str,
    /// IronWire is running but its control token failed a trust check.
    pub failed_proxy_untrusted: &'static str,
    /// The host allowlist refuses one of the addresses this step must call.
    pub failed_hosts_untrusted: &'static str,
    /// The named backend is not one this can prepare against.
    pub failed_backend: &'static str,
    /// The commons or the proxy declined this attempt, and another may work.
    pub failed_try_again: &'static str,
    pub refused_glyph: &'static str,
    pub refused_tone: &'static str,
}

/// Every fixed word on the witness surface, in one value.
///
/// ONE CALL, NOT ONE PER STRING, for the reason [`crate::routing_copy`]
/// gives: a shell handed the words one at a time takes some of them and
/// writes the rest, and a hand-written word here is a privacy claim that
/// stops matching what the other shells print.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WitnessCopy {
    pub heading: &'static str,
    pub intro: &'static str,
    pub certificate_means: &'static str,
    pub measurements_note: &'static str,
    pub url_title: &'static str,
    pub signing_address_title: &'static str,
    pub measurements_title: &'static str,
    pub configure: &'static str,
    pub clear: &'static str,
    pub clear_note: &'static str,
    pub applies_at_once: &'static str,
    pub token_heading: &'static str,
    pub token_disclosure: &'static str,
    pub token_capture_note: &'static str,
    pub token_scope_note: &'static str,
    pub token_enable: &'static str,
    pub token_disable: &'static str,
    pub token_confirm: &'static str,
    pub token_cancel: &'static str,
    pub token_enabled: &'static str,
    pub token_disabled: &'static str,
    pub token_save_failed: &'static str,
    pub inference_heading: &'static str,
    pub inference_disclosure: &'static str,
    pub inference_capture_note: &'static str,
    pub inference_scope_note: &'static str,
    pub inference_enable: &'static str,
    pub inference_disable: &'static str,
    pub inference_confirm: &'static str,
    pub inference_cancel: &'static str,
    pub inference_enabled: &'static str,
    pub inference_disabled: &'static str,
    pub inference_save_failed: &'static str,
    pub review: WitnessReviewCopy,
    pub onboarding: FirstContributionCopy,
    pub wallet: WalletCopy,
    pub admission: AdmissionCopy,
}

/// The one sentence for a wallet-signup refusal, chosen from the `reason` the
/// daemon reported.
///
/// One mapper for all three shells, for the reason this module exists: a shell
/// that picks the sentence itself picks a different one. `reason` is the wire
/// value of `daemon::account_onboarding::SignupRefusal`; anything else --
/// absent, or a class a newer daemon added -- falls back to the general
/// sentence rather than inventing a claim about why.
#[must_use]
pub fn wallet_refusal_line(reason: Option<&str>) -> &'static str {
    let wallet = witness_copy().wallet;
    match reason {
        Some("address_refused") => wallet.address_refused,
        Some("unreachable") => wallet.unreachable,
        _ => wallet.unavailable,
    }
}

/// A start failure is distinct from capability discovery. Native flow views
/// carry this sentence to all three shells without rendering wire labels.
pub fn wallet_start_refusal_line(reason: Option<&str>) -> &'static str {
    match reason {
        Some(crate::daemon::account_onboarding::CEREMONY_MISMATCH) => {
            "This commons and the app disagree about the signup details. No device proof was signed. Contact the commons operator."
        }
        _ => witness_copy().wallet.failed,
    }
}

/// The sentence for one refusal.
///
/// Grouped by **what the person must do differently**, which is the only
/// distinction a sentence earns. Nineteen labels reach here and several are the
/// same situation from the person's side -- a session that is missing, one that
/// will not parse and one whose id is unknown are all "this session cannot be
/// read", and there is nothing a person could do with the difference. Causes
/// with different remedies are kept apart even when they look alike in the
/// code: a proxy that is not running is a thing to start, while a proxy whose
/// control file failed its trust check is a thing to stop and ask about.
///
/// An unrecognised label is the generic sentence, which is honest -- this build
/// does not know what went wrong, so "try again" is all it can say. Every label
/// the daemon actually raises is classified, and
/// `daemon::admission_setup::every_admission_label_is_classified` fails if one
/// is not.
///
/// Shared rather than private to the daemon: the GTK shell reaches a refusal as
/// a bare label string and has no `view` to read, so it maps the same label
/// through the same function. Two mappings would drift.
#[must_use]
pub fn admission_refusal_line(label: Option<&str>) -> &'static str {
    let copy = witness_copy().admission;
    match label {
        Some("admission_receipt_endpoint_required") => copy.failed_receipt_endpoint,
        Some("admission_receipt_endpoint_invalid") => copy.failed_receipt_endpoint_invalid,
        Some("admission_setup_consent_required") => copy.failed_permission,
        Some("admission_setup_unenrolled") | Some("admission_setup_device_missing") => {
            copy.failed_not_enrolled
        }
        Some("admission_setup_session_missing")
        | Some("admission_setup_session_invalid")
        | Some("admission_setup_session_unknown") => copy.failed_session_unreadable,
        Some("admission_setup_source_unsupported") => copy.failed_source_unsupported,
        Some("admission_setup_proxy_missing") | Some("admission_setup_proxy_unsupported") => {
            copy.failed_proxy_missing
        }
        Some("admission_setup_proxy_untrusted") => copy.failed_proxy_untrusted,
        Some("admission_setup_endpoint_untrusted") => copy.failed_hosts_untrusted,
        Some("admission_setup_invalid") => copy.failed_backend,
        Some("admission_setup_claim_expired")
        | Some("admission_setup_state_changed")
        | Some("admission_setup_registration_refused")
        | Some("admission_setup_binding_invalid") => copy.failed_try_again,
        _ => copy.failed,
    }
}

/// The sentence for one witness-review refusal.
///
/// The mirror of [`admission_refusal_line`], and it exists for the same
/// reason: fourteen labels reach here and several are the same situation from
/// the person's side. A quote that did not verify, a quote bound to somebody
/// else's nonce and a certificate signed by the wrong key are all "this
/// reviewer could not prove it is the one you recorded", and there is nothing
/// a person could do with the difference. Causes with different remedies stay
/// apart even where the code makes them look alike -- a reviewer that did not
/// answer is a thing to retry, while one that answered with the session still
/// unredacted is a thing to stop and ask about.
///
/// An unrecognised label is [`WitnessReviewCopy::failed`], which is honest:
/// this build does not know what went wrong.
///
/// Shared rather than private to the daemon, exactly as
/// [`admission_refusal_line`] is: the GTK shell reaches a refusal as a bare
/// label and has no `view` to read, so it maps the same label through the
/// same function. Two mappings would drift.
#[must_use]
pub fn witness_refusal_line(label: Option<&str>) -> &'static str {
    let copy = witness_copy().review;
    match label {
        Some("witness_host_not_allowed") => copy.failed_host_not_allowed,
        Some(crate::witness::WITNESS_EXPECTED_MEASUREMENT_CONTROL) => {
            copy.failed_measurement_unpinned
        }
        Some("witness_attestation_unavailable")
        | Some("witness_collateral_unavailable")
        | Some("witness_response_malformed") => copy.failed_unreachable,
        Some("witness_quote_unverified")
        | Some("witness_quote_replayed")
        | Some("witness_signer_unexpected")
        | Some("witness_certificate_mismatched")
        | Some("witness_certificate_unverified") => copy.failed_unproven,
        Some("witness_body_not_stripped") => copy.failed_bodies_returned,
        Some("witness_payload_too_large") => copy.failed_too_large,
        Some("witness_claim_unavailable") => copy.failed_not_connected,
        Some("admission_evidence_refused") => copy.failed_receipt_declined,
        _ => copy.failed,
    }
}

/// The witness surface's fixed words.
#[must_use]
pub fn witness_copy() -> WitnessCopy {
    WitnessCopy {
        heading: WITNESS_HEADING,
        intro: WITNESS_INTRO,
        certificate_means: WITNESS_CERTIFICATE_MEANS,
        measurements_note: WITNESS_MEASUREMENTS_NOTE,
        url_title: WITNESS_URL_TITLE,
        signing_address_title: WITNESS_SIGNING_ADDRESS_TITLE,
        measurements_title: WITNESS_MEASUREMENTS_TITLE,
        configure: WITNESS_CONFIGURE,
        clear: WITNESS_CLEAR,
        clear_note: WITNESS_CLEAR_NOTE,
        applies_at_once: WITNESS_APPLIES_AT_ONCE,
        token_heading: WITNESS_TOKEN_HEADING,
        token_disclosure: WITNESS_TOKEN_DISCLOSURE,
        token_capture_note: WITNESS_TOKEN_CAPTURE_NOTE,
        token_scope_note: WITNESS_TOKEN_SCOPE_NOTE,
        token_enable: WITNESS_TOKEN_ENABLE,
        token_disable: WITNESS_TOKEN_DISABLE,
        token_confirm: WITNESS_TOKEN_CONFIRM,
        token_cancel: WITNESS_TOKEN_CANCEL,
        token_enabled: WITNESS_TOKEN_ENABLED,
        token_disabled: WITNESS_TOKEN_DISABLED,
        token_save_failed: WITNESS_TOKEN_SAVE_FAILED,
        inference_heading: WITNESS_INFERENCE_HEADING,
        inference_disclosure: WITNESS_INFERENCE_DISCLOSURE,
        inference_capture_note: WITNESS_INFERENCE_CAPTURE_NOTE,
        inference_scope_note: WITNESS_INFERENCE_SCOPE_NOTE,
        inference_enable: WITNESS_INFERENCE_ENABLE,
        inference_disable: WITNESS_INFERENCE_DISABLE,
        inference_confirm: WITNESS_INFERENCE_CONFIRM,
        inference_cancel: WITNESS_INFERENCE_CANCEL,
        inference_enabled: WITNESS_INFERENCE_ENABLED,
        inference_disabled: WITNESS_INFERENCE_DISABLED,
        inference_save_failed: WITNESS_INFERENCE_SAVE_FAILED,
        review: WitnessReviewCopy {
            heading: "Review with your configured witness",
            disclosure: "This sends this session, including its unredacted conversation and any correction you include, to your configured remote witness before you approve a contribution. It may contain prompts, tool results, personal data, or secrets. Captured inference bodies are included only with the separate saved permission. You can inspect the returned redacted contribution before deciding whether to send it. Cancelling afterwards cannot recall a session already sent to the witness.",
            action: "Prepare witness review",
            confirm: "Send this session for review",
            cancel: "Not now",
            working: "Preparing your witness review. The session may already have left this device.",
            failed: "The witness review could not be confirmed. The session may already have reached the witness. No contribution has been approved here. Try again only if you want to send another review request.",
            failed_host_not_allowed: "The review could not go ahead, because the reviewer's address is not on the allowed list for this computer. Nothing left the machine. Whoever set this computer up needs to allow it.",
            failed_measurement_unpinned: "The review could not go ahead, because this computer has nothing recorded to check the reviewer against, or what it reported did not match. Nothing was sent. Record the value your commons publishes for its reviewer, then try again.",
            failed_unreachable: "The review could not go ahead, because the reviewer did not answer, or answered something this app could not read. Nothing has been approved and nothing has been lost. Try again in a little while.",
            failed_unproven: "The review was refused, because the reviewer could not show it is the one you recorded. Nothing was sent onward and nothing has been approved. This is deliberate -- a reviewer that cannot prove itself does not get used. Ask whoever runs your commons before trying again.",
            failed_bodies_returned: "The review was refused, because what came back still held the model text it was given, which a finished review never does. That session has not been approved and will not be sent. Ask whoever runs your commons about it before reviewing anything else.",
            failed_too_large: "This session is larger than the review will carry, so nothing was offered and nothing left the machine. It cannot be contributed this way.",
            failed_not_connected: "The review could not go ahead, because this computer is not connected to a commons yet. Finish joining, then come back to this session.",
            failed_receipt_declined: "The review was refused, because the reviewer would not accept the signature covering this session's model call -- which one answered, which model, or how small the request was. Nothing has been approved. This is a setting where your commons runs, not here, so ask its operator. You can still contribute existing history without it.",
            immutable: "Witness review uses fixed contribution content. Outcome and correction edits are unavailable here.",
        },
        wallet: WalletCopy {
            heading: "Join with a NEAR account",
            disclosure: "Check whether your commons accepts new accounts. Connecting proves control of your account and this device; it does not fund inference or enable capture.",
            commons: "Commons HTTPS address",
            account: "Your NEAR account",
            check: "Check availability",
            start: "Continue in wallet",
            cancel: "Cancel connection",
            available: "This commons supports wallet signup.",
            unavailable: "This commons answered, and does not offer wallet signup. You can still use an invite.",
            address_refused: "That address was refused before anything was sent. A commons address must start with https, carry no user name, password or query, and be permitted by any host list this installation was set up with.",
            unreachable: "That address did not answer. Check the address and your network connection, then try again.",
            opening: "Opening a wallet connection…",
            waiting: "Finish signing in your wallet. Keep this window open.",
            failed: "The wallet connection could not be confirmed. Cancel and try again.",
            cancelled: "Connection cancelled.",
            refused_glyph: "⊘",
            refused_tone: "refused",
        },
        admission: AdmissionCopy {
            heading: "Prepare next NEAR inference",
            disclosure: "For new inference evidence, this adds an account-bound challenge to the next request in this session. Use your own funded NEAR AI backend, then continue the agent task and return here to review. You can separately choose witness review of eligible existing history, subject to server limits.",
            prerequisite: "IronWire must already route this agent to that backend and capture request bodies. Inference-body evidence also needs your separate permission in Settings.",
            backend: "NEAR AI backend name",
            confirm: "Prepare session",
            cancel: "Cancel",
            permission: "Review inference-body permission",
            working: "Preparing this session…",
            ready: "Ready. Continue this session in your agent, then review the updated session.",
            failed: "This session could not be prepared. Check your supported agent, backend, and capture settings, then try again.",
            failed_receipt_endpoint: "This session could not be prepared, and nothing in your settings will fix it. Your commons has not published a receipt service, so there is nowhere to collect the provider's signature for this inference. Ask the operator of your commons to publish one. You can still contribute existing history without it.",
            failed_receipt_endpoint_invalid: "This session could not be prepared. The receipt service configured for this computer is not an address this app will call, so the provider's signature cannot be collected. Whoever set it up needs to correct it. You can still contribute existing history without it.",
            failed_permission: "This session could not be prepared, because sending captured inference bodies has not been permitted. Open Settings and give that permission, then confirm this session again. Nothing is sent until you do.",
            failed_not_enrolled: "This session could not be prepared, because this computer is not connected to a commons yet. Finish joining, then come back to this session.",
            failed_session_unreadable: "This session could not be prepared, because its file could not be read back. It may have been moved, deleted, or still be in use by the agent. Pick another session, or close the agent and try again.",
            failed_source_unsupported: "This session could not be prepared, because it was produced by an agent this app cannot read yet. Use a supported agent for the task you want to contribute. Sessions from other agents are left alone.",
            failed_proxy_missing: "This session could not be prepared, because the local proxy that records model calls is not running or is not capturing them. Start it and turn on body capture, then confirm this session again.",
            failed_proxy_untrusted: "This session could not be prepared, because the local proxy's control file did not pass its safety check. Nothing was sent. Restart the proxy so it writes a fresh one, and if it keeps happening, ask for help before retrying.",
            failed_hosts_untrusted: "This session could not be prepared, because one of the addresses it must call is not on the allowed-hosts list for this computer. Whoever set this computer up needs to allow it. Nothing left the machine.",
            failed_backend: "This session could not be prepared, because the backend name given for it cannot be used. Choose a backend from the list and confirm again.",
            failed_try_again: "This session could not be prepared this time. Your commons or the local proxy declined the attempt, which is usually temporary. Confirm the session again in a moment.",
            refused_glyph: "⊘",
            refused_tone: "refused",
        },
        onboarding: FirstContributionCopy {
            heading: "Your first contribution",
            start: "Start with an existing session you can share, or complete a new task in a supported agent. Choose its session folder in Settings, then return here to review. Setup alone does not mean a contribution was accepted.",
            review: "Open a waiting session with Look inside. A configured witness asks separately before the session leaves this device for review. Check the returned contribution before sending it. The server may allow limited initial submissions from eligible existing history; this screen does not show a remaining allowance.",
            follow_up: "Open History to follow the server's recorded result. Upload, acceptance, and credit are separate steps. Points are not a spendable NEAR AI balance.",
            agent_setup: "To generate new NEAR AI inference evidence, configure your selected agent using your own funded provider account and model settings. IronWire capture and sending captured bodies each require separate setup. Existing-history review is a separate choice; this app does not create a funded provider account.",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_STATE: [WitnessTrustState; 7] = [
        WitnessTrustState::Absent,
        WitnessTrustState::Pinned,
        WitnessTrustState::RefusingUnpinned,
        WitnessTrustState::RefusingPinMalformed,
        WitnessTrustState::RefusingInferenceReceiptsMissing,
        WitnessTrustState::NotEnrolled,
        WitnessTrustState::SettingsUnreadable,
    ];

    #[test]
    fn every_state_has_its_own_sentence() {
        let mut seen: Vec<&str> = Vec::new();
        for state in EVERY_STATE {
            let line = witness_state_line(state);
            assert!(!line.is_empty());
            assert!(
                !seen.contains(&line),
                "{state:?} reuses another state's sentence"
            );
            seen.push(line);
        }
    }

    #[test]
    fn absent_and_unpinned_do_not_read_alike() {
        let absent = witness_state_line(WitnessTrustState::Absent);
        let unpinned = witness_state_line(WitnessTrustState::RefusingUnpinned);
        assert_ne!(absent, unpinned);
        // The one fact a contributor needs from the refusal is that nothing
        // is going out; the one fact they need from the absent state is that
        // redaction still happens here.
        assert!(
            unpinned.starts_with("Nothing is being sent."),
            "the unpinned sentence must lead with the outage: {unpinned}"
        );
        assert!(
            !absent.contains("Nothing is being sent"),
            "no witness is not an outage: {absent}"
        );
    }

    #[test]
    fn a_refusal_is_painted_as_a_refusal_and_never_as_attention() {
        for state in EVERY_STATE {
            let tone = witness_state_tone(state);
            if state.is_refusing() {
                assert_eq!(
                    tone,
                    WitnessTone::Refused,
                    "{state:?} sends nothing at all; Attention would read as degraded but \
                     working, and Neutral would read as off"
                );
            } else {
                assert_ne!(tone, WitnessTone::Refused, "{state:?} is not a refusal");
            }
        }
        assert_eq!(
            witness_state_tone(WitnessTrustState::Absent),
            WitnessTone::Neutral
        );
        assert_eq!(
            witness_state_tone(WitnessTrustState::Pinned),
            WitnessTone::Clear
        );
    }

    #[test]
    fn the_tone_numbering_shares_nothing_with_the_routing_one() {
        assert_eq!(WitnessTone::Neutral.abi_code(), 10);
        assert_eq!(WitnessTone::Held.abi_code(), 11);
        assert_eq!(WitnessTone::Clear.abi_code(), 12);
        assert_eq!(WitnessTone::Attention.abi_code(), 13);
        assert_eq!(WitnessTone::Refused.abi_code(), 14);

        // The routing tone's own numbers, restated rather than imported,
        // because the point is that the two sets must not meet. A shell
        // that cross-wires the two mappers must be wrong for every value
        // and not just for the refusal, which is the value a routing mapper
        // would quietly turn into "nothing to say".
        let routing = [0, 1, 2, 3];
        for tone in [
            WitnessTone::Neutral,
            WitnessTone::Held,
            WitnessTone::Clear,
            WitnessTone::Attention,
            WitnessTone::Refused,
        ] {
            assert!(
                !routing.contains(&tone.abi_code()),
                "{tone:?} collides with a routing tone value"
            );
        }
    }

    #[test]
    fn no_sentence_says_a_session_is_clean_or_attested() {
        let mut lines: Vec<String> = EVERY_STATE
            .iter()
            .map(|s| witness_state_line(*s).to_string())
            .collect();
        lines.push(WITNESS_INTRO.to_string());
        lines.push(WITNESS_CERTIFICATE_MEANS.to_string());
        lines.push(WITNESS_CLEAR_NOTE.to_string());
        lines.push(witness_n_of_m_line(InferenceReceiptCount { n: 3, m: 7 }));
        for count in [0usize, 1, 2] {
            lines.push(witness_pinned_count_line(count));
        }
        for result in [
            WitnessLastResult::NotObserved,
            WitnessLastResult::LocalRedaction,
            WitnessLastResult::Certified {
                n_of_m: Some(InferenceReceiptCount { n: 3, m: 7 }),
            },
            WitnessLastResult::Refused {
                label: "witness_quote_unverified".into(),
                certificate_obtained: false,
            },
        ] {
            lines.push(witness_last_result_line(&result));
        }

        for line in lines {
            let lowered = line.to_lowercase();
            assert!(
                !lowered.contains("attested") && !lowered.contains("attests"),
                "a surface must report n of m, never the word attested: {line}"
            );
            // "not a statement that a session is clean" is the one place the
            // word may appear, and only in that denial.
            if lowered.contains("clean") {
                assert!(
                    lowered.contains("not a statement that a session is clean"),
                    "a certificate never says a session is clean: {line}"
                );
            }
        }
    }

    #[test]
    fn the_pinned_count_is_a_sentence_and_never_a_bare_numeral() {
        assert_eq!(witness_pinned_count_line(0), "No measurement is pinned.");
        assert_eq!(witness_pinned_count_line(1), "One measurement is pinned.");
        assert_eq!(witness_pinned_count_line(2), "2 measurements are pinned.");
        assert_eq!(witness_pinned_count_line(11), "11 measurements are pinned.");
        for count in [0usize, 1, 2, 11] {
            let line = witness_pinned_count_line(count);
            assert!(line.ends_with('.'), "{line} is not a sentence");
            assert!(
                line.split_whitespace().count() > 1,
                "{line} is a bare numeral, which is a shell writing wording by omission"
            );
        }
        // The zero case must not repeat the outage: the state line already
        // leads with it, and a card saying it twice reads as two faults.
        assert!(
            !witness_pinned_count_line(0).contains("Nothing is being sent"),
            "the state line already says this"
        );
    }

    #[test]
    fn the_receipt_count_is_always_a_pair() {
        assert_eq!(
            witness_n_of_m_line(InferenceReceiptCount { n: 3, m: 7 }),
            "3 of 7 model calls carried a receipt."
        );
        assert_eq!(
            witness_n_of_m_line(InferenceReceiptCount { n: 0, m: 1 }),
            "0 of 1 model call carried a receipt."
        );
        assert_eq!(
            witness_n_of_m_line(InferenceReceiptCount { n: 0, m: 0 }),
            "0 of 0 model calls carried a receipt."
        );
    }

    #[test]
    fn a_certified_send_carries_the_count_into_its_sentence() {
        let with = witness_last_result_line(&WitnessLastResult::Certified {
            n_of_m: Some(InferenceReceiptCount { n: 3, m: 7 }),
        });
        let without = witness_last_result_line(&WitnessLastResult::Certified { n_of_m: None });
        assert!(with.contains("3 of 7 model calls carried a receipt."));
        assert!(!without.contains("receipt"));
        assert!(with.starts_with(&without));
    }

    #[test]
    fn local_redaction_and_no_send_yet_are_different_sentences_and_tones() {
        let local = witness_last_result_line(&WitnessLastResult::LocalRedaction);
        let never = witness_last_result_line(&WitnessLastResult::NotObserved);
        assert_ne!(local, never);
        assert_ne!(
            witness_last_result_tone(&WitnessLastResult::LocalRedaction),
            witness_last_result_tone(&WitnessLastResult::NotObserved)
        );
        assert_ne!(
            witness_last_result_tone(&WitnessLastResult::LocalRedaction),
            WitnessTone::Clear,
            "local redaction claims nothing beyond itself and must not wear the same tone \
             as a certified send"
        );
    }

    #[test]
    fn a_refused_send_reads_as_nothing_sent_in_both_shapes() {
        for obtained in [true, false] {
            let line = witness_last_result_line(&WitnessLastResult::Refused {
                label: "witness_certificate_mismatched".into(),
                certificate_obtained: obtained,
            });
            assert!(
                line.contains("nothing was sent"),
                "a refusal must say nothing was sent: {line}"
            );
            assert!(
                !line.contains("witness_certificate_mismatched"),
                "an operator label is not wording: {line}"
            );
            assert_eq!(
                witness_last_result_tone(&WitnessLastResult::Refused {
                    label: "witness_certificate_mismatched".into(),
                    certificate_obtained: obtained,
                }),
                WitnessTone::Refused
            );
        }
        let obtained = witness_last_result_line(&WitnessLastResult::Refused {
            label: "witness_certificate_mismatched".into(),
            certificate_obtained: true,
        });
        let never = witness_last_result_line(&WitnessLastResult::Refused {
            label: "witness_attestation_unavailable".into(),
            certificate_obtained: false,
        });
        assert_ne!(
            obtained, never,
            "a witness that answered with a certificate that does not hold is a different \
             fact from one that never answered"
        );
    }

    /// `AdmissionCopy` is nested, and the pin above counts only the top level,
    /// so until now a sentence could be added here that no test had seen. That
    /// mattered little while the struct held one failure sentence; it is about
    /// to hold eleven, and more are coming, so it gets its own count.
    ///
    /// Two sentences that are identical would also mean two causes a person
    /// must act on differently were given the same words, which is the defect
    /// this struct exists to remove -- so they are required to be distinct.
    #[test]
    fn every_admission_sentence_is_counted_and_distinct() {
        let json = serde_json::to_value(witness_copy().admission).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(
            object.len(),
            23,
            "a field added to AdmissionCopy must be counted here, or a shell is handed \
             a sentence no test has read"
        );

        let mut failures: Vec<&str> = object
            .iter()
            .filter(|(key, _)| key.starts_with("failed"))
            .map(|(_, value)| value.as_str().expect("a sentence"))
            .collect();
        assert_eq!(
            failures.len(),
            12,
            "every refusal sentence is a failed_* field"
        );
        for sentence in &failures {
            assert!(
                !sentence.is_empty(),
                "a shell renders a blank and writes its own"
            );
        }
        failures.sort_unstable();
        let before = failures.len();
        failures.dedup();
        assert_eq!(
            failures.len(),
            before,
            "two refusals share wording, so they are one sentence wearing two names"
        );
    }

    /// Every refusal this client can raise has a sentence, and no two share
    /// one.
    ///
    /// The counted half is #804's rule applied here: a `failed_*` field added
    /// without being counted is a sentence no test has read. The distinct
    /// half is the one that matters more -- two identical sentences would
    /// mean two causes a person must act on differently were given the same
    /// words, which is the collapse this family exists to undo.
    ///
    /// The label list is `WitnessTrustError::ALL_REFUSAL_LABELS` rather than
    /// literals, so a refusal added to the enum without a sentence here fails
    /// rather than quietly taking the generic one.
    #[test]
    fn every_witness_refusal_has_its_own_sentence() {
        let json = serde_json::to_value(witness_copy().review).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(
            object.len(),
            16,
            "a field added to WitnessReviewCopy must be counted here"
        );

        let mut sentences: Vec<&str> = object
            .iter()
            .filter(|(key, _)| key.starts_with("failed_"))
            .map(|(_, value)| value.as_str().expect("a sentence"))
            .collect();
        assert_eq!(
            sentences.len(),
            8,
            "every refusal sentence is a failed_* field"
        );
        for sentence in &sentences {
            assert!(!sentence.is_empty());
            // A run of spaces inside a sentence is invisible to a test that
            // checks only for empties and template markers, and one shipped
            // in this repo -- "carries      signed proof" -- unnoticed.
            //
            // It was authored that way, not produced by the formatter:
            // rustfmt does not rewrite literal contents, and `git log -S`
            // finds the spaces in the commit that added the constant. So this
            // guards a typo nobody would see in review, which is reason
            // enough; it is not a defence against tooling.
            assert!(
                !sentence.contains("  "),
                "a run of spaces inside a sentence: {sentence}"
            );
        }
        sentences.sort_unstable();
        let before = sentences.len();
        sentences.dedup();
        assert_eq!(
            sentences.len(),
            before,
            "two refusals share wording, so they are one sentence wearing two names"
        );

        let generic = witness_copy().review.failed;
        let mut selected: Vec<&str> = Vec::new();
        for label in crate::witness::WitnessTrustError::ALL_REFUSAL_LABELS {
            let line = witness_refusal_line(Some(label));
            assert_ne!(
                line, generic,
                "{label} falls through to the sentence for a refusal nobody classified"
            );
            assert!(
                !line.contains(label),
                "{label} is rendered to a contributor as its own internal name"
            );
            selected.push(line);
        }

        // The partition, not the mapping. Grouping several causes onto one
        // sentence is deliberate -- five ways of failing to prove itself are
        // one thing to do about it -- so this cannot require fourteen
        // distinct sentences. What it can require is that the eight written
        // sentences are the eight reached: a label quietly folded into a
        // neighbour's wording drops this to seven, and a sentence no label
        // selects is one nobody will ever read.
        //
        // Deliberately not a table of label to field. That would be this
        // function written twice, and the copy would agree with itself by
        // construction.
        selected.sort_unstable();
        selected.dedup();
        sentences.sort_unstable();
        assert_eq!(
            selected, sentences,
            "the refusal sentences written and the refusal sentences reached are not the \
             same set, so a cause was folded into a neighbour or a sentence is unreachable"
        );
        assert_eq!(witness_refusal_line(None), generic);
        assert_eq!(
            witness_refusal_line(Some("nothing-classifies-this")),
            generic
        );
    }

    #[test]
    fn the_copy_call_carries_every_fixed_word() {
        let copy = witness_copy();
        let json = serde_json::to_value(&copy).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(
            object.len(),
            37,
            "a field added to WitnessCopy must be counted here, or a shell can be handed \
             a word this test has never seen"
        );
        for (key, value) in object {
            assert!(
                value.as_str().is_some_and(|text| !text.is_empty())
                    || value.as_object().is_some_and(|fields| fields
                        .values()
                        .all(|text| text.as_str().is_some_and(|text| !text.is_empty()))),
                "{key} is empty, so a shell renders a blank and writes its own"
            );
        }
    }
}
