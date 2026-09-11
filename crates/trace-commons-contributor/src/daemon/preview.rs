//! Real preview: redact one session without uploading, and report exactly
//! what would leave the machine.
//!
//! Before this module existed, the IPC `"preview"` arm reported
//! `entry.size_bytes` -- the raw session file's size on disk. Redaction
//! shrinks (and reshapes) the payload, so that number overstated what
//! actually gets sent and was the one figure backing a contributor's consent
//! decision. `build_preview` runs the *same* redaction path `submit_one`
//! uses (`build_redactor_with` + `build_raw_contribution` +
//! `redact_to_envelope`).
//!
//! Running the same *code* is not the same as producing the same
//! *artifact*, and this module used to claim it was ("so preview and upload
//! can never disagree"). It could not have been: preview kept nothing of
//! the envelope it built, and the uploader's guard re-hashed the raw
//! transcript only. Redaction-service output, privacy-filter
//! configuration, daemon settings, contributor config, and timestamps can
//! all move between the preview and the send while the raw session hash is
//! unchanged, and the guard stayed silent through every one of them --
//! because it verified the input, not the artifact.
//!
//! Two things close that, and they close different halves of it.
//!
//! [`input_fingerprint`] covers the *inputs*: the whole contributor config,
//! the privacy-filter backend and model, and the redaction ruleset version.
//! It is recorded on every approval, including approvals given without a
//! preview (armed auto-upload), and re-derived immediately before every
//! upload. A mismatch revokes the approval and re-offers the entry, the
//! same way a changed session hash does.
//!
//! The *artifact* is not re-derived and compared at all. It is stored.
//! [`build_preview`] hands back the envelope it built, the caller persists
//! it (`daemon::approved_envelope`), and the upload sends exactly those
//! bytes. An earlier round compared a digest instead, and that comparison
//! made the whole feature unusable with `pii_filter = "near-ai"`: an
//! LLM-backed filter does not return identical spans for identical text,
//! so every previewed entry was refused and re-offered forever. See
//! `daemon::approved_envelope` for the full account.
//!
//! **Preview is the one interface in this crate that deliberately carries
//! trace content** (`PreviewSummary::opening_prompt` over the socket, the
//! redacted body over the C ABI, and now the stored envelope at rest under
//! the 0700 state directory). A contributor cannot consent to sending
//! something they cannot see, so the exemption exists -- bounded to
//! post-redaction content, only for an entry the caller already asked
//! about, deleted as soon as the entry is resolved, and never onward into a
//! log line, an audit entry, a history record, notification text, or a
//! receipt. Everywhere else in this crate the no-trace-content rule is
//! absolute.

use anyhow::Result;
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::config::{ConfigStore, ContributorConfig};
use crate::envelope::{
    NearAiSettings, build_raw_contribution_with_correction, build_redactor_with, envelope_size,
    redact_to_envelope, residual_secret_labels_fail_closed,
};
use crate::source::{SessionRef, TraceSource};
use trace_commons_protocol::canonical_json;
use trace_commons_protocol::trace_contribution::{
    TraceContributionEnvelope, TraceContributionEventType,
};

/// Envelope fields that differ between two builds of the same content and
/// therefore cannot participate in an approval digest: freshly generated
/// ids and wall-clock stamps. Everything else -- every redacted event body,
/// every redaction count, the PII labels, the consent scopes, the policy
/// version, the trace card, the contributor metadata -- is in.
///
/// `timestamp` is on the list because an event with no timestamp of its own
/// inherits `now`. Event *content* is already covered by both this digest
/// and the raw session hash, so nothing about what is being sent escapes
/// scrutiny by stripping it; leaving it in would just make the digest
/// non-deterministic for sources that omit per-event times, and a digest
/// that spuriously mismatches would re-offer entries forever.
///
/// `redaction_hash` is the protocol crate's own SHA-256 over the events and
/// the redaction counts -- including each event's freshly generated
/// `event_id` -- so it moves whenever those do, for reasons that have
/// nothing to do with what was redacted. Both of its real inputs are
/// already in this digest directly, so stripping it loses no coverage.
///
/// A field wrongly *left out* of this list weakens the guard silently, so
/// `every_stripped_field_is_actually_volatile` pins each entry: a field
/// that turns out to be stable across two builds does not belong here.
const VOLATILE_ENVELOPE_FIELDS: &[&str] = &[
    "trace_id",
    "event_id",
    // A reference to an `event_id`, so it is volatile for exactly the same
    // reason and has to come off with it. Left in, a transcript with a
    // paired tool call and result would digest differently on every build,
    // which the `fixture_session` transcript (one user message, no tool
    // calls) is not shaped to notice --
    // `a_paired_call_and_result_digests_identically` is.
    "parent_event_id",
    "revocation_handle",
    "created_at",
    "timestamp",
    "redaction_hash",
];

/// A content-addressed digest of the redacted envelope a contributor was
/// shown, stable across two builds of the same envelope from the same
/// inputs *when the redaction step is deterministic*.
///
/// Nothing compares this against a rebuild any more, and nothing may start
/// doing so: with an LLM-backed privacy filter a rebuild legitimately
/// differs, and a comparison makes previewed entries permanently
/// unuploadable. Its two remaining jobs are both local:
///
/// * it is the marker that says "this entry was previewed, and the bytes
///   that were shown are on disk" (`QueueEntry::previewed_envelope_digest`);
/// * it is a self-consistency check on this crate's own storage -- the
///   uploader re-digests the file it read back and refuses if it is not the
///   one that was pinned, which catches a corrupted or crossed-over file
///   rather than a jittery filter.
///
/// It is also returned over IPC so an app can confirm the entry it approves
/// is the one it displayed.
pub fn envelope_digest(envelope: &TraceContributionEnvelope) -> Result<String> {
    let mut value = serde_json::to_value(envelope)
        .map_err(|_| anyhow::anyhow!("envelope-digest-serialize-failed"))?;
    strip_volatile(&mut value);
    // Sort every object's keys before serializing. This is what makes the
    // digest stable: `serde_json::Value`'s map is key-ordered only while it
    // is a `BTreeMap`, and `serde_json/preserve_order` swaps it for an
    // insertion-ordered map. `dcap-qvl` enables that feature, and this
    // crate's cfg(not(windows)) dev-dependency on trace-commons-server pulls
    // it in, so `a_known_envelope_pins_a_known_digest` below runs against an
    // IndexMap and fails if this call is removed -- measured, not assumed.
    // Under a `BTreeMap` the call changes nothing, which is why it could be
    // adopted without moving that pinned digest. See
    // `trace_commons_protocol::canonical_json`.
    canonical_json::canonicalize(&mut value);
    //
    // The canonical bytes are hashed as the serializer produces them rather
    // than collected into a `Vec<u8>` first: `HashingWriter` feeds each
    // chunk straight into the running SHA-256 state, so this never holds a
    // second full copy of the envelope just to hash it. The digest is
    // byte-for-byte the same either way -- `serde_json::to_writer` and
    // `serde_json::to_vec` run the identical serializer, just over a
    // different `Write` sink -- and `two_builds_of_the_same_envelope_digest_identically`
    // plus `a_known_envelope_pins_a_known_digest` in this module's tests
    // guard that.
    let mut hasher = HashingWriter(Sha256::new());
    serde_json::to_writer(&mut hasher, &value)
        .map_err(|_| anyhow::anyhow!("envelope-digest-serialize-failed"))?;
    Ok(format!("sha256:{:x}", hasher.0.finalize()))
}

/// A `std::io::Write` sink that feeds every byte written into a running
/// SHA-256 state, so a canonical serialization can be hashed as it is
/// produced instead of collected into a buffer first.
struct HashingWriter(Sha256);

impl std::io::Write for HashingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn strip_volatile(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for k in VOLATILE_ENVELOPE_FIELDS {
                map.remove(*k);
            }
            for v in map.values_mut() {
                strip_volatile(v);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items.iter_mut() {
                strip_volatile(v);
            }
        }
        _ => {}
    }
}

/// The redaction ruleset this build implements.
///
/// The deterministic redactor's patterns, the categories it accepts from a
/// privacy-filter backend, and the shape of the envelope it produces are
/// all compiled in. An in-place upgrade of the daemon binary between an
/// approval and the upload therefore changes what gets redacted with no
/// config change to show for it, and a fingerprint built from config alone
/// cannot see that. Previewed entries are covered anyway (their bytes are
/// stored), but an **armed auto-upload entry is covered by nothing else**,
/// so the version goes into the fingerprint.
///
/// Bump this whenever the redaction rules, the accepted filter categories,
/// or the envelope layout change in a way that alters output for unchanged
/// input. The crate version is hashed in alongside it, so an ordinary
/// release bump moves the fingerprint even if nobody remembers to touch
/// this constant; this exists for the case where the rules move without a
/// version bump.
/// Moved to "2" for issue #298: the envelope layout changed for unchanged
/// input. A tool call's arguments are now named under an `arguments` key
/// rather than shipped as the payload itself, calls and results carry
/// `tool_call_id`, a result names its call in `parent_event_id`, and
/// `replay.replayable` / `required_tools` now describe the transcript
/// instead of being constants. An armed auto-upload entry approved before
/// that change would otherwise upload an envelope built to the new layout,
/// which is exactly the case this constant exists for.
pub const REDACTION_RULESET_VERSION: &str = "2";

/// Contributor-config fields that are deliberately **not** fingerprinted,
/// with the reason each one is out.
///
/// All three are this device's local cache of its public roster profile
/// (`config::ContributorConfig::display_handle` and the two fields beside
/// it). None of them reaches the envelope: `build_raw_contribution` never
/// reads them, the server derives the roster principal from the
/// authenticated request rather than from anything in a body, and a handle
/// is public by construction -- so no consent decision a contributor made
/// about a queued trace turns on any of them.
///
/// Fingerprinting them was actively harmful rather than merely redundant.
/// The cache is rewritten on every `set_public_profile` and every
/// `clear_public_profile`, and a moved fingerprint revokes **every** approved
/// entry in the queue (the `REASON_INPUTS_CHANGED` guard in `uploader`). So
/// claiming a handle silently re-asked the contributor to approve every
/// upload they had already approved -- a consent prompt raised by an action
/// with no consent content in it, which is how contributors learn to click
/// through the prompt that does matter.
///
/// A field left off this list is fingerprinted, and that is the safe
/// default: over-invalidating re-asks, under-invalidating sends something
/// the contributor did not approve. Adding a field to `ContributorConfig`
/// therefore needs no edit here to be *safe* -- but
/// `every_config_field_is_a_deliberate_fingerprint_decision` pins the whole
/// field set, so the addition fails that test until someone says which side
/// of this line the new field falls on.
const NON_ENVELOPE_CONFIG_FIELDS: &[&str] = &["display_handle", "public_bio", "public_since"];

/// The contributor config reduced to its envelope-determining fields, as
/// canonical bytes for [`input_fingerprint`].
///
/// Serialized whole and then narrowed by name rather than rebuilt field by
/// field: a field added to `ContributorConfig` later is covered without
/// anyone remembering to come back here, and dropping one out of the
/// fingerprint takes a deliberate entry in `NON_ENVELOPE_CONFIG_FIELDS`.
///
/// `serde_json::Value`'s map is a `BTreeMap` under this crate's feature set,
/// so the re-serialization is key-ordered and these bytes are stable for a
/// given config.
fn envelope_determining_config_bytes(cfg: &ContributorConfig) -> Vec<u8> {
    let Ok(mut value) = serde_json::to_value(cfg) else {
        return Vec::new();
    };
    if let Some(map) = value.as_object_mut() {
        for field in NON_ENVELOPE_CONFIG_FIELDS {
            map.remove(*field);
        }
    }
    serde_json::to_vec(&value).unwrap_or_default()
}

/// A fingerprint of everything outside the session file that determines the
/// envelope: the envelope-determining fields of the contributor config
/// (consent scopes, PII filter selection, tenant/instance/subject/device
/// identity, audience, endpoints, host allowlist -- that is, everything
/// except `NON_ENVELOPE_CONFIG_FIELDS`), the presence and identity of the
/// NEAR AI privacy-filter backend, and the redaction ruleset/build this
/// daemon is running.
///
/// Cheap -- no redaction pass, no network -- so it is recorded on every
/// approval and re-derived before every upload, including for entries that
/// were never previewed and for armed auto-upload.
///
/// The NEAR AI **API key is deliberately never hashed in**, and that is a
/// decision rather than an omission: rotating a credential does not change
/// what the filter does to a trace, so hashing it in would revoke every
/// standing approval on a routine rotation for no consent-relevant reason
/// -- and hashing a live secret into a value this crate writes to disk is
/// not something it does. The base URL and model *are* hashed in, because
/// both change what comes back.
///
/// One envelope-determining input is still outside this: `SubmitOptions`.
/// See the note at the daemon's construction site in `daemon::drain_approved`.
///
/// `attested_bodies` is the one term here that is NOT envelope-determining,
/// and it is hashed in for the reason the guard exists rather than for the
/// name it goes by: with it on, a submission carries the final inference
/// call's verbatim prompt to a witness, which is a change in what leaves the
/// machine that an earlier approval never covered.
pub fn input_fingerprint(
    cfg: &ContributorConfig,
    near_ai: Option<&NearAiSettings>,
    attested_bodies: bool,
) -> String {
    let mut h = Sha256::new();
    h.update(envelope_determining_config_bytes(cfg).as_slice());
    h.update(b"\x00redactor\x00");
    h.update(REDACTION_RULESET_VERSION.as_bytes());
    h.update(b"\x00");
    h.update(env!("CARGO_PKG_VERSION").as_bytes());
    h.update(b"\x00near_ai\x00");
    match near_ai {
        None => h.update(b"absent"),
        Some(s) => {
            h.update(b"present\x00");
            h.update(s.base_url.as_deref().unwrap_or("").as_bytes());
            h.update(b"\x00");
            h.update(s.model.as_deref().unwrap_or("").as_bytes());
        }
    }
    // The attested-bodies switch. It does not change the envelope, and it is
    // hashed in anyway: what it changes is what leaves the machine. With it
    // on, a submission carries the final inference call's verbatim request
    // and response to the witness -- the contributor's own prompt, in the
    // clear, to a remote process. An entry approved while it was off must
    // not be uploaded under it, which is exactly the "sends something the
    // contributor did not approve" failure this fingerprint exists to
    // prevent; the cost of being wrong the other way is one re-ask.
    //
    // The *directory* is deliberately not hashed in. It is derived from the
    // IronWire declaration rather than configured separately, it is a local
    // path, and a path in a value written to disk is what the hash-only rule
    // is about. The switch is the consent-relevant fact.
    h.update(b"\x00attested_bodies\x00");
    h.update(if attested_bodies { "on" } else { "off" }.as_bytes());
    format!("sha256:{:x}", h.finalize())
}

/// The fixed reason label an entry is re-offered under when it was pinned
/// to a previewed envelope but those bytes are missing or unusable at
/// upload time.
///
/// Fail-closed: the daemon does **not** quietly rebuild the envelope in
/// that case. Rebuilding is exactly what stored bytes exist to avoid, and a
/// silent rebuild would send something the contributor never saw.
pub const REASON_APPROVED_ENVELOPE_UNAVAILABLE: &str = "approved-envelope-unavailable";

/// The fixed reason label an entry is re-offered under when an
/// envelope-determining input changed between approval and upload.
pub const REASON_INPUTS_CHANGED: &str = "approval-inputs-changed";

/// What preview reports to the contributor before they consent to upload.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PreviewSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_distribution_summary: Option<String>,
    pub would_send_bytes: usize,
    pub raw_session_bytes: u64,
    pub event_count: usize,
    pub opening_prompt: String,
    pub redactions: std::collections::BTreeMap<String, u32>,
    /// Distinct values removed per label, beside the occurrence counts in
    /// `redactions`. A shell renders "185 local path (12 distinct)".
    pub redactions_distinct: std::collections::BTreeMap<String, u32>,
    pub pii_labels_present: Vec<String>,
    /// The consent scopes this device **requests**, taken from the local
    /// config, which is what `build_raw_contribution` stamps onto the
    /// envelope here.
    ///
    /// These are not necessarily the scopes an upload ends up carrying. An
    /// actual submission mints an upload claim first, and
    /// `submit::stamp_granted_scopes` then overwrites the envelope with the
    /// **granted** set the issuer echoed back -- falling back to the
    /// requested set only when the issuer is old enough not to echo one.
    /// Preview cannot show the granted set without minting a claim, which
    /// it deliberately does not do (preview is a local operation and must
    /// work offline).
    ///
    /// So this field is an upper bound on what an upload will claim, never
    /// an under-statement: the issuer can only narrow the request, never
    /// widen it. A consumer rendering this to a contributor should say
    /// "requested", not "will be sent as". Separately, an entry's approval
    /// is pinned to exactly this requested set
    /// (`QueueEntry::approved_scopes`), so a local widening between preview
    /// and upload revokes the approval rather than riding along with it.
    pub consent_scopes: Vec<String>,
    pub residual_risk: String,
    /// Digest of the redacted envelope this summary describes, and a
    /// fingerprint of the inputs that produced it. Hashes, never content.
    ///
    /// The digest is recorded on the queue entry alongside the envelope
    /// itself, and identifies the file the upload will send. It is not
    /// compared against a rebuild -- see [`envelope_digest`] and the module
    /// doc for why a comparison cannot work here.
    pub envelope_digest: String,
    pub input_fingerprint: String,
    /// Whether this preview was built from a real enrollment.
    ///
    /// `false` is the pre-enrollment preview: the daemon has no contributor
    /// config, so the envelope is built from the same placeholder identity
    /// the CLI's `--dry-run` uses (`commands::unenrolled_preview_config`)
    /// and through the deterministic-only redactor, with any configured
    /// external privacy filter ignored so that pre-enrollment trace text
    /// stays on the machine.
    ///
    /// Preview is a local operation -- no lock, no running loop, no network
    /// -- and requiring an enrollment for it was incidental rather than
    /// necessary: a contributor should be able to see what would be sent
    /// *before* deciding to enrol, which is exactly when the question
    /// matters most.
    ///
    /// When this is `false`, `envelope_digest` and `input_fingerprint`
    /// describe that placeholder build. Nothing is pinned and neither value
    /// is bindable to a later approval: enrolling changes the identity the
    /// envelope carries, so an approval given afterwards is fingerprinted
    /// against the real config and a fresh preview is what it covers.
    pub enrolled: bool,
    /// How many delegated subagent transcripts this envelope merges in, and
    /// how many the source left out to keep the conversation under its raw
    /// byte budget.
    ///
    /// The second number is the one that matters here. A group trimmed to
    /// fit is a conversation the contributor is being shown *less* of than
    /// exists on disk, and a preview that did not say so would describe a
    /// complete conversation while covering a partial one. The trim is
    /// decided in the adapter's `load`, so this describes both the bytes
    /// previewed and the bytes an upload sends -- they are the same bytes.
    pub subagent_count: u32,
    pub subagents_dropped: u32,
}

/// Every field a queue card needs, built without computing the envelope
/// digest. See [`build_preview_card`] for why that split exists and why it
/// is safe: nothing here is bindable to an approval, because nothing here
/// pins one.
///
/// Field-for-field identical to [`PreviewSummary`] except for
/// [`PreviewSummary::envelope_digest`], which this type has no equivalent
/// of by design.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PreviewCardSummary {
    pub would_send_bytes: usize,
    pub raw_session_bytes: u64,
    pub event_count: usize,
    pub opening_prompt: String,
    pub redactions: std::collections::BTreeMap<String, u32>,
    /// Distinct values removed per label, beside the occurrence counts in
    /// `redactions`. A shell renders "185 local path (12 distinct)".
    pub redactions_distinct: std::collections::BTreeMap<String, u32>,
    pub pii_labels_present: Vec<String>,
    pub consent_scopes: Vec<String>,
    pub residual_risk: String,
    pub input_fingerprint: String,
    pub enrolled: bool,
    pub subagent_count: u32,
    pub subagents_dropped: u32,
}

impl PreviewCardSummary {
    /// Complete this into a full [`PreviewSummary`] with a caller-supplied
    /// digest. The only field this adds; every other field carries over
    /// unchanged.
    fn into_summary(self, envelope_digest: String) -> PreviewSummary {
        PreviewSummary {
            token_distribution_summary: None,
            would_send_bytes: self.would_send_bytes,
            raw_session_bytes: self.raw_session_bytes,
            event_count: self.event_count,
            opening_prompt: self.opening_prompt,
            redactions: self.redactions,
            redactions_distinct: self.redactions_distinct,
            pii_labels_present: self.pii_labels_present,
            consent_scopes: self.consent_scopes,
            residual_risk: self.residual_risk,
            envelope_digest,
            input_fingerprint: self.input_fingerprint,
            enrolled: self.enrolled,
            subagent_count: self.subagent_count,
            subagents_dropped: self.subagents_dropped,
        }
    }
}

/// Redact one session without uploading and describe exactly what would be
/// sent. Same redaction path the uploader uses.
///
/// Returns the summary, the redacted body for display, **and the envelope
/// itself**. The envelope is the artifact the upload will send verbatim:
/// the caller persists it (`daemon::approved_envelope`) so nothing has to
/// rebuild it, which is what makes preview and upload agree under a
/// non-deterministic privacy filter.
///
/// `store` is accepted for signature parity with the other entry points that
/// build a redactor/envelope (`submit_one`); preview does not itself read or
/// write through it -- everything it needs comes from `cfg` and the already
/// -resolved `source`/`session_ref`.
///
/// `cfg` is `None` when this device is not enrolled. That is a supported
/// preview, not an error: preview performs no network I/O and needs neither
/// the daemon's lock nor its running loop, so the enrollment requirement it
/// used to carry was incidental -- and "show me what would be sent" is a
/// question a contributor most wants answered *before* enrolling. The
/// envelope is then built exactly the way the CLI's unenrolled `--dry-run`
/// builds it: the placeholder identity from
/// `commands::unenrolled_preview_config`, a preview submission id disjoint
/// from any real one, and the deterministic-only redactor, so no
/// pre-enrollment trace text is sent to an external privacy filter. The
/// summary says so (`PreviewSummary::enrolled`), and callers must not pin
/// an entry to an unenrolled build.
pub async fn build_preview(
    _store: &ConfigStore,
    cfg: Option<&ContributorConfig>,
    near_ai: Option<NearAiSettings>,
    source: &dyn TraceSource,
    session_ref: &SessionRef,
) -> Result<(PreviewSummary, String, TraceContributionEnvelope)> {
    // `false` for the attested-bodies term of the fingerprint: this
    // convenience entry point has no settings to read one from. The daemon's
    // own preview surfaces call `build_preview_with_correction` and
    // `build_preview_card` and pass the contributor's real answer -- a
    // summary built here reports the terms of a machine that carries no
    // bodies, which is what a caller with no daemon settings is.
    build_preview_with_correction(_store, cfg, near_ai, source, session_ref, None, false).await
}

/// [`build_preview`], with the contributor's written correction folded into
/// the envelope before redaction runs.
///
/// Only the approval path passes one, and only for an entry the contributor
/// is approving right now: a correction is typed at the moment of consent,
/// so there is no earlier build to have carried it. Building it in rather
/// than stamping it on afterwards is what puts it in front of credential
/// detection and what makes `consent.correction_included` describe the
/// envelope -- see `envelope::build_raw_contribution_with_correction`.
///
/// A credential in the correction surfaces here as an `Err`, which is the
/// refusal: nothing is pinned, so nothing can be approved.
pub async fn build_preview_with_correction(
    _store: &ConfigStore,
    cfg: Option<&ContributorConfig>,
    near_ai: Option<NearAiSettings>,
    source: &dyn TraceSource,
    session_ref: &SessionRef,
    correction: Option<&str>,
    attested_bodies: bool,
) -> Result<(PreviewSummary, String, TraceContributionEnvelope)> {
    let (core, envelope) = build_preview_core(
        cfg,
        near_ai,
        source,
        session_ref,
        correction,
        attested_bodies,
    )
    .await?;
    // Digested here, at exactly the point `submit_loaded` takes over the
    // envelope it is about to send: after redaction, before the granted
    // scopes the issuer echoes back are stamped on. This identifies the
    // stored artifact; it is not re-derived from a second build anywhere.
    //
    // This is the expensive half of a preview -- a full `serde_json::Value`
    // tree of the envelope, then a canonical re-serialization of it -- and
    // it exists only for a caller that is actually going to pin or submit
    // this build. A caller that only renders a queue card wants
    // [`build_preview_card`] instead, which shares every field below but
    // skips this call entirely.
    let digest = envelope_digest(&envelope)?;
    let body = body_of(&envelope)?;
    Ok((core.into_summary(digest), body, envelope))
}

/// Redact one session and describe exactly what would be sent, **without**
/// computing the envelope digest or the pretty-printed body.
///
/// This is the summary a queue card needs: would-send size, the opening
/// prompt, redaction counts, PII labels, consent scopes, residual risk, and
/// the enrollment/subagent bookkeeping -- every field [`PreviewSummary`]
/// carries except [`PreviewSummary::envelope_digest`] and
/// [`PreviewSummary::input_fingerprint`]'s sibling cost, the digest.
/// (`input_fingerprint` is cheap -- a hash of the config, not of the
/// envelope -- so it is still included.)
///
/// The digest is deliberately not computed here, and the envelope built for
/// this call is deliberately not returned: a caller that only wants to
/// *render* a card has no use for either, and a card is rendered for every
/// queued entry at once (this crate's daemon can be asked to summarize
/// several hundred of them in one pass). Computing the digest means
/// building a full `serde_json::Value` tree of the envelope and then
/// re-serializing that tree to canonical bytes -- two more full copies of a
/// structure that can already run to hundreds of megabytes for one session
/// -- purely to produce a hash nothing in the card path reads.
///
/// **This path must never pin an entry.** The digest is the value an
/// approval is checked against (`QueueEntry::previewed_envelope_digest`),
/// and a caller that skips computing it has nothing to pin an entry to.
/// Pinning stays exclusive to [`build_preview`], driven by the preview sheet
/// (`daemon::ipc::open_preview`) and by an on-demand rebuild inside
/// `handle_approve` for any entry a card never pinned -- so an entry a
/// contributor approves is always either the artifact the sheet showed them
/// or a fresh build made at the moment of approval, never a stale card
/// summary silently standing in for either.
pub async fn build_preview_card(
    cfg: Option<&ContributorConfig>,
    near_ai: Option<NearAiSettings>,
    attested_bodies: bool,
    source: &dyn TraceSource,
    session_ref: &SessionRef,
) -> Result<PreviewCardSummary> {
    let (core, _envelope) =
        build_preview_core(cfg, near_ai, source, session_ref, None, attested_bodies).await?;
    Ok(core)
}

/// Shared build behind [`build_preview`] and [`build_preview_card`]: load the
/// session, redact it, and assemble every summary field that does not
/// require a second full serialization pass. Neither the digest nor the
/// pretty-printed body is computed here; each caller adds the one it needs.
async fn build_preview_core(
    cfg: Option<&ContributorConfig>,
    near_ai: Option<NearAiSettings>,
    source: &dyn TraceSource,
    session_ref: &SessionRef,
    correction: Option<&str>,
    // `attested_bodies`: whether this machine carries the final call's
    // verbatim bodies to a witness. Reported, not applied -- the switch
    // changes nothing about the envelope built here, because an attested
    // body never enters a local envelope at all -- so it reaches this
    // function only to be fingerprinted.
    attested_bodies: bool,
) -> Result<(PreviewCardSummary, TraceContributionEnvelope)> {
    let transcript = source.load(session_ref)?;
    let raw_session_bytes = session_ref.size_bytes;

    let enrolled = cfg.is_some();
    let placeholder;
    let cfg = match cfg {
        Some(c) => c,
        None => {
            placeholder = crate::commands::unenrolled_preview_config();
            &placeholder
        }
    };
    // The fingerprint of an unenrolled build describes the placeholder, and
    // is reported only so the summary is self-describing. Nothing binds an
    // approval to it -- see `PreviewSummary::enrolled`.
    let fingerprint =
        input_fingerprint(cfg, near_ai.as_ref().filter(|_| enrolled), attested_bodies);
    let (redactor, raw) = if enrolled {
        (
            build_redactor_with(cfg, transcript.cwd.as_deref(), near_ai)
                .map_err(|_| anyhow::anyhow!("pii-filter-unavailable"))?,
            build_raw_contribution_with_correction(&transcript, cfg, Utc::now(), None, correction),
        )
    } else {
        // An unenrolled build is a placeholder-identity artifact that is
        // never pinned and never sent, and the only caller that supplies a
        // correction (`handle_approve`) refuses an unenrolled entry before
        // it gets here. So there is deliberately no correction on this
        // branch rather than one that would never be examined.
        (
            crate::envelope::build_deterministic_preview_redactor(transcript.cwd.as_deref()),
            crate::envelope::build_preview_raw_contribution(&transcript, cfg, Utc::now()),
        )
    };
    // A witnessed client cannot build a preview envelope here.
    //
    // This path has no claim -- it runs before the contributor has answered --
    // and a witnessed envelope must carry the granted scopes INSIDE the bytes
    // the certificate covers, which means minting first. There is no issuer
    // client on this path to mint with.
    //
    // Refusing rather than building one locally is the point. The preview
    // envelope is not merely displayed: `use_approved_envelope` uploads these
    // exact bytes later, so a locally-redacted preview under a configured
    // witness would be an unwitnessed submission from a contributor who
    // believes their submissions are certified. That is the downgrade this
    // design exists to make noisy, and silence about it is the failure mode.
    //
    // The consequence is real and is named here rather than discovered: with
    // a witness configured, the desktop shells' approve-then-upload flow does
    // not work. Direct submission does.
    if enrolled && cfg.witness.is_some() {
        return Err(anyhow::anyhow!("witness_claim_unavailable"));
    }
    let envelope = redact_to_envelope(&redactor, raw).await?;
    summarize_envelope(
        &envelope,
        raw_session_bytes,
        &transcript,
        fingerprint,
        enrolled,
        &redactor,
    )
    .map(|summary| (summary, envelope))
}

fn summarize_envelope(
    envelope: &TraceContributionEnvelope,
    raw_session_bytes: u64,
    transcript: &crate::source::SessionTranscript,
    fingerprint: String,
    enrolled: bool,
    redactor: &trace_commons_protocol::trace_contribution::DeterministicTraceRedactor,
) -> Result<PreviewCardSummary> {
    let would_send_bytes = envelope_size(envelope)?;
    let event_count = envelope.events.len();
    let opening_prompt = envelope
        .events
        .iter()
        .find(|e| e.event_type == TraceContributionEventType::UserMessage)
        .and_then(|e| e.redacted_content.clone())
        .unwrap_or_default();
    let opening_prompt = truncate_chars(&opening_prompt, 200);

    // The redaction pipeline's own counts describe what it TOOK OUT. Nothing
    // in them can describe what it left in: `redact_trace` never runs a
    // residual scan, and the server's two scans feed risk and a log line
    // without folding their findings back into `redaction_counts`. So until
    // this call existed, no shell had ever told a contributor that a secret
    // survived scrubbing -- the `residual_secret_at:*` handling in all three
    // of them read a label no producer minted.
    //
    // Merged into the summary's map only, never into
    // `envelope.privacy.redaction_counts`: those bytes are what
    // `use_approved_envelope` uploads and what `redaction_hash` covers, and a
    // detection-only finding must not change the artifact it describes.
    let mut redactions = envelope.privacy.redaction_counts.clone();
    for (label, count) in residual_secret_labels_fail_closed(redactor, envelope) {
        *redactions.entry(label).or_insert(0) += count;
    }
    let redactions_distinct = envelope.privacy.redaction_distinct_counts.clone();
    let pii_labels_present = envelope.privacy.pii_labels_present.clone();
    let consent_scopes = envelope.consent.scopes.iter().map(wire_name).collect();
    let residual_risk = serde_json::to_value(envelope.privacy.residual_pii_risk)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "pattern-based".to_string());

    Ok(PreviewCardSummary {
        would_send_bytes,
        raw_session_bytes,
        event_count,
        opening_prompt,
        redactions,
        redactions_distinct,
        pii_labels_present,
        consent_scopes,
        residual_risk,
        input_fingerprint: fingerprint,
        enrolled,
        subagent_count: transcript.subagent_count,
        subagents_dropped: transcript.subagents_dropped,
    })
}

/// Explicit user authorization for a single remote review. Not inferred from
/// enrollment, proxy configuration, optional scanner consent, or card visibility.
#[derive(Default)]
pub struct WitnessPreviewOptions<'a> {
    pub raw_session_confirmed: bool,
    pub token_capture: Option<&'a crate::token_capture_client::TokenCaptureClient>,
    pub expected_session_hash: &'a str,
    pub include_inference_bodies: bool,
    pub verdict: Option<crate::envelope::ContributorVerdict>,
    pub correction: Option<&'a str>,
}

pub struct WitnessPreview {
    pub summary: PreviewSummary,
    pub body: String,
    pub artifact: super::approved_envelope::WitnessReviewArtifact,
}

/// Only the explicit `witness_preview_request` handler may call this helper.
/// It does not persist or approve; the IPC handler atomically pins the returned
/// artifact under its queue lock after rechecking source/configuration state.
pub async fn build_witnessed_preview(
    store: &ConfigStore,
    cfg: &ContributorConfig,
    near_ai: Option<NearAiSettings>,
    source: &dyn TraceSource,
    session_ref: &SessionRef,
    options: WitnessPreviewOptions<'_>,
) -> Result<WitnessPreview> {
    if !options.raw_session_confirmed {
        anyhow::bail!("witness-review-consent-required");
    }
    let device = crate::identity::DeviceIdentity::load(store)
        .map_err(|_| anyhow::anyhow!("witness-review-not-enrolled"))?
        .ok_or_else(|| anyhow::anyhow!("witness-review-not-enrolled"))?;
    if device.device_key_id != cfg.device_key_id {
        anyhow::bail!("witness-review-not-enrolled");
    }
    let transcript = source
        .load(session_ref)
        .map_err(|_| anyhow::anyhow!("parse-failed"))?;
    if transcript.session_hash != options.expected_session_hash {
        anyhow::bail!("witness-review-source-changed");
    }
    let submit_options = crate::submit::SubmitOptions {
        dry_run: false,
        pii_filter: None,
        no_reasoning: false,
        machine_readable: true,
        unenrolled_preview: false,
        remediate_quarantined: false,
        verdict: options.verdict,
    };
    let mut context = super::run_blocking(|| {
        crate::submit::SubmitContext::new(store, cfg, &submit_options, near_ai.clone())
    })
    .map_err(|_| anyhow::anyhow!("witness-review-unavailable"))?;
    let (response, attested_inference, token_bundle) = if let Some(control) = options.token_capture
    {
        if !options.include_inference_bodies
            || options.verdict.is_some()
            || options.correction.is_some()
        {
            anyhow::bail!("token-review-input-unsupported");
        }
        let session = super::admission_setup::exact_session_id(source.name(), &session_ref.path)?;
        let (response, record, bundle) = context
            .prepare_token_review(&transcript, control, &session)
            .await?;
        (response, record, Some(bundle))
    } else {
        let (response, record) = context
            .prepare_witnessed_review(
                &transcript,
                options.correction,
                options.include_inference_bodies,
            )
            .await?;
        (response, record, None)
    };
    let mut pin_guard =
        crate::token_bundle::ReviewPinGuard::new(store.dir(), token_bundle.as_ref());
    let fingerprint = input_fingerprint(cfg, near_ai.as_ref(), options.include_inference_bodies);
    let verdict = options.verdict.map(|verdict| match verdict {
        crate::envelope::ContributorVerdict::Worked => "worked",
        crate::envelope::ContributorVerdict::Partly => "partly",
        crate::envelope::ContributorVerdict::Failed => "failed",
    });
    let mut artifact = super::approved_envelope::WitnessReviewArtifact::new(
        response,
        transcript.session_hash.clone(),
        fingerprint.clone(),
        verdict,
        options.correction,
        Some(attested_inference),
    );
    artifact.token_bundle = token_bundle;
    let envelope = artifact.validate(
        cfg,
        &transcript.session_hash,
        &fingerprint,
        verdict,
        options.correction,
    )?;
    let redactor = build_redactor_with(cfg, transcript.cwd.as_deref(), near_ai)
        .map_err(|_| anyhow::anyhow!("pii-filter-unavailable"))?;
    let mut summary = summarize_envelope(
        &envelope,
        session_ref.size_bytes,
        &transcript,
        fingerprint,
        true,
        &redactor,
    )?
    .into_summary(artifact.digest()?);
    if let Some(bundle) = &artifact.token_bundle {
        summary.token_distribution_summary = bundle.summary_line.clone();
        summary.would_send_bytes = summary
            .would_send_bytes
            .saturating_add(bundle.attachment_bytes as usize);
    }
    let preview = WitnessPreview {
        summary,
        body: body_of(&envelope)?,
        artifact,
    };
    pin_guard.disarm();
    Ok(preview)
}

/// Describe the certified envelope without invoking the remote redaction pipeline.
pub fn summarize_witnessed_preview(
    artifact: &super::approved_envelope::WitnessReviewArtifact,
    cfg: &ContributorConfig,
    near_ai: Option<NearAiSettings>,
    transcript: &crate::source::SessionTranscript,
    raw_session_bytes: u64,
    include_inference_bodies: bool,
) -> Result<(PreviewSummary, String, TraceContributionEnvelope)> {
    let fingerprint = input_fingerprint(cfg, near_ai.as_ref(), include_inference_bodies);
    let envelope = artifact.validate_stored(cfg, &transcript.session_hash, &fingerprint)?;
    let redactor = build_redactor_with(cfg, transcript.cwd.as_deref(), near_ai)?;
    let mut summary = summarize_envelope(
        &envelope,
        raw_session_bytes,
        transcript,
        fingerprint,
        true,
        &redactor,
    )?
    .into_summary(artifact.digest()?);
    if let Some(bundle) = &artifact.token_bundle {
        summary.token_distribution_summary = bundle.summary_line.clone();
        summary.would_send_bytes = summary
            .would_send_bytes
            .saturating_add(bundle.attachment_bytes as usize);
    }
    Ok((summary, body_of(&envelope)?, envelope))
}

/// The redacted body a contributor is shown for one envelope: the redacted
/// events, pretty-printed.
///
/// The single definition of "the preview body". [`build_preview`] returns
/// exactly this for the envelope it just built, and the socket's
/// `preview_body` returns exactly this for the *stored* envelope the entry
/// is pinned to -- which is why those two are byte-identical for the same
/// entry rather than merely equivalent. A second spelling of this
/// expression anywhere else is how they would stop being.
///
/// It is redacted trace content and carries the preview exemption with it:
/// post-redaction only, only for an entry the caller already holds, never
/// onward into a log line, an audit entry, a history record, notification
/// text, or a receipt.
pub fn body_of(envelope: &TraceContributionEnvelope) -> Result<String> {
    serde_json::to_string_pretty(&envelope.events)
        .map_err(|_| anyhow::anyhow!("preview-body-serialize-failed"))
}

/// One separator in the transcript view: a labelled span of the preview
/// body, never a re-rendering of it.
///
/// `byte_offset` and `byte_len` are a half-open range into the **exact**
/// string [`body_of`] returns for the same envelope. A client renders the
/// body verbatim and draws a separator at each `byte_offset`; nothing here
/// replaces a byte of it. That is the whole design: the transcript tab is
/// titled "exactly what would be sent", and a prose re-render would quietly
/// drop `structured_payload`, `token_counts`, `latency_ms`, `cost_usd` and
/// `failure_modes` -- showing a contributor *less* than what an approval
/// covers, under a heading promising the opposite.
///
/// `index` is 0-based, so it indexes this vector directly; a client
/// displaying "turn 1" for the first separator renders `index + 1`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PreviewTurn {
    pub index: usize,
    /// The wire name of the event type that opens this turn -- `user_message`,
    /// `assistant_message`, `tool_call`, and so on. Identical to the
    /// `event_type` string inside the bytes at `byte_offset`, so a client
    /// never has to reconcile two vocabularies.
    pub role: String,
    /// The tool this turn invoked, when the opening event names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub byte_offset: usize,
    pub byte_len: usize,
}

/// The fixed label reported when the body cannot be indexed. Fail-closed:
/// an index that is not certainly exact is worse than no index at all,
/// because it would draw a separator over the wrong text.
pub const REASON_TURN_INDEX_FAILED: &str = "preview-turn-index-failed";

/// The turn index for one envelope: where each turn starts and ends inside
/// [`body_of`]'s output, and what to label it.
///
/// Deliberately an *overlay*, computed from the body [`body_of`] actually
/// produced rather than from a second serialization of the events. The
/// offsets are found by scanning that string for its top-level array
/// elements, so there is no second spelling of the body to drift from the
/// first -- the same argument [`body_of`]'s own doc comment makes.
/// `turn_offsets_land_on_the_exact_event_bytes` re-parses every span and
/// requires it to be the event it claims to be, because an offset that has
/// drifted by one element silently labels the wrong turn.
///
/// # Grouping: a tool call and its result are one turn
///
/// A `tool_call` followed **immediately** by the `tool_result` carrying the
/// same `tool_call_id` is indexed as a single turn spanning both events.
/// One invocation of one tool is one thing that happened; splitting it puts
/// a separator between a command and its output, and doubles the separator
/// count on exactly the traces (long agentic runs) where the index is meant
/// to help someone navigate.
///
/// The pairing is required to be explicit and adjacent, and everything else
/// is one turn per event: an unmatched call, a result whose call is missing,
/// a call whose result was reordered or filtered out by redaction, and a
/// pair with no `tool_call_id` to correlate on all stay separate. Guessing a
/// pair would mean labelling a byte range that spans two unrelated events --
/// the one failure this index must not have. In practice this means the
/// claude-code source, whose records carry no call id to correlate on, is
/// indexed one turn per event, and a source that does carry one (a
/// trajectory export) gets the grouped form.
pub fn turns_of(envelope: &TraceContributionEnvelope) -> Result<Vec<PreviewTurn>> {
    let body = body_of(envelope)?;
    let spans = top_level_object_spans(&body)
        .ok_or_else(|| anyhow::anyhow!("{}", REASON_TURN_INDEX_FAILED))?;
    // The scan found a different number of elements than the envelope has
    // events, so one of the two is not what this function believes it is.
    // Refuse rather than index by position.
    if spans.len() != envelope.events.len() {
        return Err(anyhow::anyhow!("{}", REASON_TURN_INDEX_FAILED));
    }

    let events = &envelope.events;
    let mut turns = Vec::new();
    let mut i = 0usize;
    while i < events.len() {
        let event = &events[i];
        let (start, mut end) = spans[i];
        let mut consumed = 1usize;
        if event.event_type == TraceContributionEventType::ToolCall {
            if let (Some(call_id), Some(next)) = (event.tool_call_id.as_deref(), events.get(i + 1))
            {
                if next.event_type == TraceContributionEventType::ToolResult
                    && next.tool_call_id.as_deref() == Some(call_id)
                {
                    end = spans[i + 1].1;
                    consumed = 2;
                }
            }
        }
        turns.push(PreviewTurn {
            index: turns.len(),
            role: wire_name(event.event_type),
            tool_name: event.tool_name.clone(),
            byte_offset: start,
            byte_len: end - start,
        });
        i += consumed;
    }
    Ok(turns)
}

/// Byte spans of the top-level elements of a pretty-printed JSON array of
/// objects, as half-open `(start, end)` pairs into `body`.
///
/// A structural scan rather than a re-serialization, for the reason in
/// [`turns_of`]: the offsets have to describe the bytes that exist, not the
/// bytes a second pretty-printer would produce. Returns `None` for anything
/// that is not an array whose every element is an object -- which
/// [`body_of`] never produces, and which this refuses to index rather than
/// guess at.
fn top_level_object_spans(body: &str) -> Option<Vec<(usize, usize)>> {
    let bytes = body.as_bytes();
    let mut spans = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0usize;
    let mut opened_outer = false;
    for (i, &c) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'[' | b'{' => {
                if depth == 0 {
                    // The document itself must be the array of events.
                    if c != b'[' {
                        return None;
                    }
                    opened_outer = true;
                } else if depth == 1 {
                    // An element. Every event serializes as an object; an
                    // array here means this is not the document this
                    // function was written for.
                    if c != b'{' {
                        return None;
                    }
                    start = i;
                }
                depth += 1;
            }
            b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 1 {
                    spans.push((start, i + 1));
                }
            }
            _ => {}
        }
    }
    if depth != 0 || in_string || !opened_outer {
        return None;
    }
    Some(spans)
}

/// Serde's wire name for a `Serialize` value that serializes to a bare
/// string (every enum used here does, via `#[serde(rename_all =
/// "snake_case")]`).
fn wire_name<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Truncate to at most `max_chars` characters, always on a char boundary.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::build_raw_contribution;
    use crate::source::claude_code::ClaudeCodeSource;
    use trace_commons_protocol::trace_contribution::RESIDUAL_SECRET_AT_PREFIX;

    #[tokio::test]
    async fn witness_review_requires_explicit_confirmation_before_loading_or_minting() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (_session_dir, source, reference) = fixture_session();
        let error = build_witnessed_preview(
            &store,
            &cfg,
            None,
            &source,
            &reference,
            WitnessPreviewOptions::default(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "witness-review-consent-required");
    }

    #[tokio::test]
    async fn witness_review_refuses_a_changed_source_before_network_access() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (_session_dir, source, reference) = fixture_session();
        let options = WitnessPreviewOptions {
            raw_session_confirmed: true,
            expected_session_hash: "changed",
            ..Default::default()
        };
        let error = build_witnessed_preview(&store, &cfg, None, &source, &reference, options)
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "witness-review-source-changed");
    }

    #[tokio::test]
    async fn ordinary_witness_preview_and_cards_remain_fail_closed() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let mut cfg = sample_cfg(&store);
        cfg.witness = Some(crate::config::WitnessSettings {
            admission_evidence: false,
            url: "https://witness.invalid".into(),
            signing_address: "invalid".into(),
            expected_measurements: vec![],
        });
        let (_session_dir, source, reference) = fixture_session();
        assert_eq!(
            build_preview(&store, Some(&cfg), None, &source, &reference)
                .await
                .err()
                .unwrap()
                .to_string(),
            "witness_claim_unavailable"
        );
        assert_eq!(
            build_preview_card(Some(&cfg), None, true, &source, &reference)
                .await
                .err()
                .unwrap()
                .to_string(),
            "witness_claim_unavailable"
        );
    }

    fn sample_cfg(store: &ConfigStore) -> ContributorConfig {
        let device = crate::identity::DeviceIdentity::load_or_generate(store).unwrap();
        ContributorConfig {
            inference_receipt_endpoint: None,
            inference_receipt_check_attestation: false,
            schema_version: crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION.into(),
            issuer_url: "http://issuer.invalid".into(),
            ingest_url: "http://ingest.invalid".into(),
            audience: "trace-commons-upload".into(),
            tenant_id: "tenant-abc".into(),
            instance_id: "instance-1".into(),
            user_subject: "alice".into(),
            device_key_id: device.device_key_id.clone(),
            consent_scopes: vec!["debugging_evaluation".into()],
            pii_filter: None,
            allowed_hosts: None,
            display_handle: None,
            public_bio: None,
            public_since: None,
            witness: None,
        }
    }

    /// A session with a planted secret, so redaction has something to do.
    fn fixture_session() -> (tempfile::TempDir, ClaudeCodeSource, SessionRef) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        let project = root.join("-Users-testuser-code-myproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("11111111-1111-1111-1111-111111111111.jsonl"),
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\
             \"content\":\"deploy with key sk-fake-fixture-secret-1234\"},\
             \"cwd\":\"/Users/testuser/code/myproj\",\
             \"timestamp\":\"2026-08-08T10:00:00Z\",\"version\":\"2.0.1\",\
             \"sessionId\":\"11111111-1111-1111-1111-111111111111\",\
             \"uuid\":\"a1\"}\n",
        )
        .unwrap();
        let src = ClaudeCodeSource::new(root);
        let r = src.discover().unwrap().remove(0);
        (dir, src, r)
    }

    /// A session whose assistant `model` field is a recognized secret shape.
    ///
    /// `model` reaches `IronclawTraceMetadata::model_name` verbatim: the
    /// per-field redaction pass visits `content` and `structured_payload`
    /// and nothing else, so this is a real field the typed traversal never
    /// rewrites -- not a value planted into a finished envelope. That is
    /// what makes it a survivor rather than a fixture trick, and it is the
    /// same gap `submit_sessions_refuses_session_with_secret_in_unredacted_model_field`
    /// covers on the submit side.
    fn session_with_secret_in_unredacted_model_field()
    -> (tempfile::TempDir, ClaudeCodeSource, SessionRef) {
        let session = "33333333-3333-3333-3333-333333333333";
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        let project = root.join("-Users-testuser-code-myproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join(format!("{session}.jsonl")),
            format!(
                "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\
                 \"content\":\"what does this do\"}},\
                 \"cwd\":\"/Users/testuser/code/myproj\",\
                 \"timestamp\":\"2026-08-08T10:00:00Z\",\"version\":\"2.0.1\",\
                 \"sessionId\":\"{session}\",\"uuid\":\"a1\"}}\n\
                 {{\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\
                 \"model\":\"sk-ant-EXPOSEDsecret0123456789abcdefghij\",\
                 \"content\":[{{\"type\":\"text\",\"text\":\"it prints a greeting\"}}],\
                 \"usage\":{{\"input_tokens\":1,\"output_tokens\":1}}}},\
                 \"cwd\":\"/Users/testuser/code/myproj\",\
                 \"timestamp\":\"2026-08-08T10:00:05Z\",\"version\":\"2.0.1\",\
                 \"sessionId\":\"{session}\",\"uuid\":\"a2\"}}\n"
            ),
        )
        .unwrap();
        let src = ClaudeCodeSource::new(root);
        let r = src.discover().unwrap().remove(0);
        (dir, src, r)
    }

    /// A credential in a metadata field is now refused a pass earlier, by
    /// the metadata redaction pass, so no fixture on disk reaches the summary
    /// still carrying one. The property this test exists for is the *summary*
    /// one -- that `build_preview_core` merges residual-secret labels, so a
    /// survivor is reported rather than silent -- so the residual is injected
    /// into a finished envelope from a clean session instead. Deleting that
    /// merge still fails this.
    ///
    /// `a_preview_refuses_a_secret_in_a_metadata_field` is the fixture-driven
    /// half, and it covers the guard that made this one unreachable.
    #[tokio::test]
    async fn a_preview_reports_a_secret_that_survived_redaction_as_a_survivor() {
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (clean_summary, _body, mut envelope) =
            build_preview(&store, Some(&cfg), None, &src, &r)
                .await
                .unwrap();

        assert!(
            !serde_json::to_string(&envelope)
                .unwrap()
                .contains("sk-ant-EXPOSEDsecret0123456789abcdefghij")
        );
        envelope.ironclaw.model_name = Some("sk-ant-EXPOSEDsecret0123456789abcdefghij".into());
        let transcript = src.load(&r).unwrap();
        let redactor =
            trace_commons_protocol::trace_contribution::DeterministicTraceRedactor::try_default()
                .unwrap();
        let summary =
            summarize_envelope(&envelope, 0, &transcript, "fixture".into(), true, &redactor)
                .unwrap();

        // Non-vacuity: the secret really is still in what would be sent, and
        // the pipeline really did not count it as something it removed.
        assert!(
            serde_json::to_string(&envelope)
                .unwrap()
                .contains("sk-ant-EXPOSEDsecret0123456789abcdefghij"),
            "fixture must actually carry a surviving secret, else this test proves nothing"
        );
        assert!(
            !envelope
                .privacy
                .redaction_counts
                .keys()
                .any(|k| k.starts_with(RESIDUAL_SECRET_AT_PREFIX)),
            "the envelope's own counts must stay untouched; the survivor is a \
             summary-only finding and must not change the bytes that upload"
        );

        let survivors: Vec<(&String, &u32)> = summary
            .redactions
            .iter()
            .filter(|(k, _)| k.starts_with(RESIDUAL_SECRET_AT_PREFIX))
            .collect();
        assert!(
            !survivors.is_empty(),
            "preview reported no survivor for a session that still carries a \
             secret; got {:?}",
            summary.redactions
        );

        // ...and it is a survivor, not a removal: the shells split the map
        // on exactly this prefix.
        for (label, _) in &survivors {
            assert!(
                !label.contains("sk-ant-"),
                "a residual label must be a path, never the secret"
            );
        }

        // The queue card reads the same map through the same shared build.
        let card = build_preview_card(Some(&cfg), None, false, &src, &r)
            .await
            .unwrap();
        assert_eq!(
            card.redactions, clean_summary.redactions,
            "card and sheet must agree on what survived"
        );
    }

    /// Refused, not masked and previewed: a credential in `model` means the
    /// contributor has typed and transmitted a live one, and a preview that
    /// succeeds never tells them to rotate it.
    #[tokio::test]
    async fn a_preview_refuses_a_secret_in_a_metadata_field() {
        let (_d, src, r) = session_with_secret_in_unredacted_model_field();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let error = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .expect_err("a credential in metadata is a refusal");
        assert_eq!(
            error.to_string(),
            crate::envelope::REASON_METADATA_CREDENTIAL
        );
    }

    /// A clean session reports no survivor. Without this, the test above
    /// would pass against a wiring that labelled every preview.
    #[tokio::test]
    async fn a_preview_of_a_clean_session_reports_no_survivor() {
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, _body, _envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        assert!(
            !summary
                .redactions
                .keys()
                .any(|k| k.starts_with(RESIDUAL_SECRET_AT_PREFIX)),
            "a session whose secret was redacted has no survivor; got {:?}",
            summary.redactions
        );
    }

    /// A session with `members` delegated transcripts beside it, each
    /// carrying `body` repeated to `member_bytes`.
    fn grouped_session(
        members: usize,
        member_filler: usize,
    ) -> (tempfile::TempDir, ClaudeCodeSource, SessionRef) {
        let session = "11111111-1111-1111-1111-111111111111";
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        let project = root.join("-Users-testuser-code-myproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join(format!("{session}.jsonl")),
            format!(
                "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\
                 \"content\":\"the human's own opening question\"}},\
                 \"cwd\":\"/Users/testuser/code/myproj\",\
                 \"timestamp\":\"2026-08-08T10:00:00Z\",\"version\":\"2.0.1\",\
                 \"sessionId\":\"{session}\",\"uuid\":\"a1\"}}\n"
            ),
        )
        .unwrap();
        let subagents = project.join(session).join("subagents");
        std::fs::create_dir_all(&subagents).unwrap();
        for i in 0..members {
            let filler = "lorem ipsum ".repeat(member_filler);
            std::fs::write(
                subagents.join(format!("agent-{i:03}.jsonl")),
                format!(
                    "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\
                     \"content\":\"planted-in-subagent-{i} {filler}\"}},\
                     \"cwd\":\"/Users/testuser/code/myproj\",\
                     \"timestamp\":\"2026-08-08T10:00:00Z\",\"version\":\"2.0.1\",\
                     \"sessionId\":\"{session}\",\"uuid\":\"s{i}\"}}\n"
                ),
            )
            .unwrap();
        }
        let src = ClaudeCodeSource::new(root);
        let r = src.discover().unwrap().remove(0);
        (dir, src, r)
    }

    #[tokio::test]
    async fn a_previewed_group_shows_the_human_prompt_and_the_delegated_content() {
        // Both halves of the bug this fixes. The opening prompt must be the
        // contributor's own first message -- a subagent card used to render
        // an instruction written by the parent agent in that slot -- and the
        // body the contributor reads must actually contain the delegated
        // work, because that is what the upload sends.
        let (_d, src, r) = grouped_session(3, 1);
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, body, envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();

        assert_eq!(summary.subagent_count, 3);
        assert_eq!(summary.subagents_dropped, 0);
        assert!(
            summary.opening_prompt.contains("the human's own opening"),
            "got {:?}",
            summary.opening_prompt
        );
        for i in 0..3 {
            assert!(
                body.contains(&format!("planted-in-subagent-{i}")),
                "member {i} missing from the previewed body"
            );
        }
        assert_eq!(
            summary.event_count,
            envelope.events.len(),
            "the count shown must be the count sent"
        );
        // One turn per file plus a group header plus one marker per member.
        assert_eq!(summary.event_count, 1 + 1 + 3 + 3);
    }

    #[tokio::test]
    async fn a_114_member_group_still_fits_the_envelope_cap() {
        // The plan's ratio (42 MB raw to a 2.8 MB envelope) is one
        // observation, and `GROUP_RAW_BYTE_BUDGET` is set on the assumption
        // that it holds with room to spare. This is the measurement rather
        // than the assumption: the largest group on the probed machine had
        // 114 members, and a group that overruns the cap is refused whole.
        let (_d, src, r) = grouped_session(114, 200);
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, _body, _envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        assert_eq!(summary.subagent_count, 114);
        assert_eq!(summary.subagents_dropped, 0, "nothing should need dropping");
        assert!(
            summary.would_send_bytes < crate::envelope::MAX_ENVELOPE_BYTES,
            "114 members produced {} bytes against a {} cap",
            summary.would_send_bytes,
            crate::envelope::MAX_ENVELOPE_BYTES
        );
    }

    #[tokio::test]
    async fn preview_reports_the_redacted_size_not_the_raw_size() {
        // The defect this task exists to fix: the old code returned the raw
        // file size. Measured, the redacted envelope is substantially LARGER
        // than the session file it came from -- envelope metadata dominates --
        // so the old number understated what actually leaves the machine.
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, _body, _envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        assert!(summary.raw_session_bytes > 0);
        assert!(summary.would_send_bytes > 0);
        assert_ne!(
            summary.would_send_bytes as u64, summary.raw_session_bytes,
            "a redacted envelope is not the same size as the raw session file"
        );
    }

    #[tokio::test]
    async fn an_unenrolled_preview_redacts_locally_and_claims_no_identity() {
        // Preview needs no enrollment, but it must not borrow one either:
        // the envelope carries the placeholder identity, and a configured
        // external privacy filter is ignored so pre-enrollment trace text
        // never leaves the machine to be classified.
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let near_ai = NearAiSettings {
            api_key: "unused".into(),
            base_url: Some("http://filter.invalid".into()),
            model: None,
        };
        let (summary, _body, envelope) = build_preview(&store, None, Some(near_ai), &src, &r)
            .await
            .unwrap();

        assert!(!summary.enrolled);
        assert!(summary.would_send_bytes > 0);
        assert!(
            summary.redactions.values().sum::<u32>() > 0,
            "the deterministic redactor still runs: {:?}",
            summary.redactions
        );
        let placeholder = crate::commands::unenrolled_preview_config();
        let real = build_preview(&store, Some(&sample_cfg(&store)), None, &src, &r)
            .await
            .unwrap()
            .2;
        assert_ne!(
            envelope.contributor.tenant_scope_ref, real.contributor.tenant_scope_ref,
            "an unenrolled preview must not describe itself as the enrolled \
             contributor"
        );
        assert!(placeholder.tenant_id.starts_with("tenant-"));
    }

    #[tokio::test]
    async fn preview_reports_what_redaction_actually_removed() {
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, _body, _envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        let total: u32 = summary.redactions.values().sum();
        assert!(
            total > 0,
            "planted secret should appear in the counts: {:?}",
            summary.redactions
        );
    }

    /// A session naming its own working directory, which the redactor
    /// knows as a path prefix and therefore replaces with a NUMBERED
    /// placeholder.
    ///
    /// `fixture_session` plants a secret instead, and a secret is replaced
    /// with a fixed token rather than a numbered one -- so it produces
    /// occurrence counts and no distinct count at all. The distinct count
    /// comes from the placeholder index, which only the placeholder-minting
    /// labels populate, so a fixture that mints none cannot show this
    /// field working.
    fn fixture_session_naming_its_own_path() -> (tempfile::TempDir, ClaudeCodeSource, SessionRef) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        let project = root.join("-Users-testuser-code-myproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("11111111-1111-1111-1111-111111111111.jsonl"),
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\
             \"content\":\"open /Users/testuser/code/myproj/a.rs then \
             /Users/testuser/code/myproj/b.rs\"},\
             \"cwd\":\"/Users/testuser/code/myproj\",\
             \"timestamp\":\"2026-08-08T10:00:00Z\",\"version\":\"2.0.1\",\
             \"sessionId\":\"11111111-1111-1111-1111-111111111111\",\
             \"uuid\":\"a1\"}\n",
        )
        .unwrap();
        let src = ClaudeCodeSource::new(root);
        let r = src.discover().unwrap().remove(0);
        (dir, src, r)
    }

    /// The distinct-value counts reach the summary a shell reads.
    ///
    /// The distinct-per-value property itself is proved where it lives, in
    /// `trace_contribution`'s `one_value_gets_one_placeholder_however_often_it_appears`.
    /// What this covers is the plumbing between that map and
    /// `PreviewSummary`, which is the part a shell can actually reach, and
    /// the invariant that must hold on every session.
    #[tokio::test]
    async fn preview_reports_distinct_values_beside_occurrences() {
        let (_d, src, r) = fixture_session_naming_its_own_path();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, _body, envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        let occurrences: u32 = summary.redactions.values().sum();
        let distinct: u32 = summary.redactions_distinct.values().sum();
        assert!(occurrences > 0, "the fixture must have something to redact");
        assert!(distinct > 0, "distinct counts must be reported too");
        assert!(
            distinct <= occurrences,
            "distinct ({distinct}) can never exceed occurrences ({occurrences})"
        );
        assert_eq!(
            summary.redactions_distinct, envelope.privacy.redaction_distinct_counts,
            "the summary must report what the envelope recorded, unchanged"
        );
    }

    #[tokio::test]
    async fn preview_body_does_not_contain_the_planted_secret() {
        // The whole point of showing a body is that it is the redacted one.
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (_summary, body, _envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        assert!(
            !body.contains("sk-fake-fixture-secret-1234"),
            "secret survived into the preview body"
        );
    }

    #[tokio::test]
    async fn preview_carries_an_opening_prompt_and_an_event_count() {
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, _body, _envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        assert_eq!(summary.event_count, 1);
        assert!(!summary.opening_prompt.is_empty());
        assert!(
            !summary
                .opening_prompt
                .contains("sk-fake-fixture-secret-1234"),
            "the opening prompt must be the redacted one"
        );
    }

    #[tokio::test]
    async fn preview_opening_prompt_is_truncated() {
        // 200 chars, so a huge first message cannot dominate a queue row.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        let project = root.join("-Users-testuser-code-myproj");
        std::fs::create_dir_all(&project).unwrap();
        let long = "x".repeat(500);
        std::fs::write(
            project.join("22222222-2222-2222-2222-222222222222.jsonl"),
            format!(
                "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"{long}\"}},\
                 \"cwd\":\"/Users/testuser/code/myproj\",\
                 \"timestamp\":\"2026-08-08T10:00:00Z\",\"version\":\"2.0.1\",\
                 \"sessionId\":\"22222222-2222-2222-2222-222222222222\",\"uuid\":\"a1\"}}\n"
            ),
        )
        .unwrap();
        let src = ClaudeCodeSource::new(root);
        let r = src.discover().unwrap().remove(0);
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, _body, _envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        assert!(summary.opening_prompt.chars().count() <= 200);
    }

    #[tokio::test]
    async fn two_builds_of_the_same_envelope_digest_identically() {
        // The guard is only usable if the digest is stable: a
        // non-deterministic one would re-offer every entry forever.
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (a, _, _) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        let (b, _, _) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        assert_eq!(a.envelope_digest, b.envelope_digest);
        assert!(a.envelope_digest.starts_with("sha256:"));
    }

    #[tokio::test]
    async fn a_paired_call_and_result_digests_identically() {
        // `two_builds_of_the_same_envelope_digest_identically` above uses a
        // transcript of one user message, so it cannot see a field that is
        // only populated when a result is paired with its call.
        // `parent_event_id` is exactly that: it holds the call's `event_id`,
        // which is a fresh v4 UUID per build. Without it on the volatile
        // list this transcript digests differently every time -- and the
        // failure would land not here but in the field, as previewed
        // entries that never match their own stored bytes.
        let (_d, src, r) = tool_call_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let t = src.load(&r).unwrap();
        assert!(
            t.events
                .iter()
                .any(|e| e.kind == crate::source::SessionEventKind::ToolResult
                    && e.tool_call_id.is_some()),
            "this fixture has to carry a result that names its call, or the \
             test proves nothing"
        );
        let redactor = build_redactor_with(&cfg, t.cwd.as_deref(), None).unwrap();
        let a = redact_to_envelope(&redactor, build_raw_contribution(&t, &cfg, Utc::now()))
            .await
            .unwrap();
        let b = redact_to_envelope(&redactor, build_raw_contribution(&t, &cfg, Utc::now()))
            .await
            .unwrap();
        assert_eq!(
            envelope_digest(&a).unwrap(),
            envelope_digest(&b).unwrap(),
            "a paired call and result must not make the digest volatile"
        );
    }

    /// A session whose tool result names the call it answers, so
    /// `parent_event_id` is actually populated.
    fn tool_call_session() -> (tempfile::TempDir, ClaudeCodeSource, SessionRef) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("projects");
        let project = root.join("-Users-testuser-code-myproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("11111111-1111-1111-1111-111111111111.jsonl"),
            concat!(
                "{\"type\":\"user\",\"message\":{\"role\":\"user\",\
                 \"content\":\"read the config\"},\
                 \"cwd\":\"/Users/testuser/code/myproj\",\
                 \"timestamp\":\"2026-08-08T10:00:00Z\",\"version\":\"2.0.1\",\
                 \"sessionId\":\"11111111-1111-1111-1111-111111111111\",\
                 \"uuid\":\"a1\"}\n",
                "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\
                 \"content\":[{\"type\":\"tool_use\",\"id\":\"tu_1\",\
                 \"name\":\"Read\",\"input\":{\"file_path\":\"cfg.toml\"}}]},\
                 \"timestamp\":\"2026-08-08T10:00:01Z\",\"version\":\"2.0.1\",\
                 \"uuid\":\"a2\"}\n",
                "{\"type\":\"user\",\"message\":{\"role\":\"user\",\
                 \"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"tu_1\",\
                 \"content\":\"port = 8080\"}]},\
                 \"timestamp\":\"2026-08-08T10:00:02Z\",\"version\":\"2.0.1\",\
                 \"uuid\":\"a3\"}\n",
            ),
        )
        .unwrap();
        let src = ClaudeCodeSource::new(root);
        let r = src.discover().unwrap().remove(0);
        (dir, src, r)
    }

    #[tokio::test]
    async fn a_known_envelope_pins_a_known_digest() {
        // `envelope_digest` now hashes the canonical bytes as
        // `serde_json::to_writer` produces them, rather than collecting
        // them into a `Vec<u8>` first and hashing that. This pins the
        // output against a value computed before that change, so a
        // refactor that silently changed what gets hashed (a different
        // writer, a different key order, a dropped byte) fails here rather
        // than only showing up as entries mysteriously re-offered in the
        // field.
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (summary, _body, _envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        // The pin moved once, deliberately, for issue #373: this fixture
        // pastes an API key, and a scrubbed secret is now the Medium
        // found-and-removed floor rather than terminal High. That changes
        // `privacy.residual_pii_risk` and its warning string, which are
        // inside the hashed bytes. Asserting the tier here keeps the pin
        // honest -- if it moves again, this line says whether the risk
        // rule moved with it.
        assert_eq!(
            summary.residual_risk, "medium",
            "a fixture whose only finding is a successfully scrubbed secret \
             must be Medium, not High"
        );
        // Moved again, deliberately, for issue #298: `replay.replayable` is
        // no longer hardcoded `false` on this path, the replay note it ships
        // with changed, and `required_tools` is now derived from the events.
        // All three are inside the hashed bytes. The risk tier above is
        // unchanged, which is what says this was a shape change and not a
        // redaction change.
        //
        // Moved again, deliberately, for issue #298 S4a: the envelope now
        // carries `conversation_id`, populated from the fixture session's own
        // file stem (its `sessionId`, `11111111-1111-1111-1111-111111111111`).
        // Attribution only, inside the hashed bytes like every other field.
        //
        // Moved again, deliberately, for issue #298 S5: `ConsentMetadata`
        // gained `correction_included`, a third content-class declaration, and
        // it serialises unconditionally like the two flags beside it. This
        // fixture carries no correction, so the new key is `false` -- the move
        // is one added key, not a change to what the envelope declares. The
        // risk tier asserted above is unchanged, which is what says so.
        //
        // Moved again, deliberately, for #458: the residual-risk warning
        // strings were restored to #223's wording, which the #267 squash had
        // reverted. This fixture is the Medium case -- its only finding is a
        // successfully scrubbed secret -- so it carries the Medium string,
        // and that string now names successfully-redacted secrets and says
        // the trace stays reviewable. The warning text is inside the hashed
        // bytes.
        //
        // The `residual_risk == "medium"` assertion above is unchanged and
        // still passes, which is what says this was a wording change and not
        // a redaction or classification change. That ordering is the point of
        // asserting the tier before the digest.
        //
        // Moved again by `routing_metadata_included`: a new consent field
        // serializes into the envelope, so the digest changes while the
        // classification does not.
        assert_eq!(
            summary.envelope_digest,
            "sha256:8d9b9d0b2f1c78be8875d79435cc21397da4a1366139df38d59dff046930d27c",
            "the digest for this fixture moved -- if that is an intentional \
             change to the redaction or envelope pipeline, recompute and \
             update this pin; if not, something changed what gets hashed"
        );
    }

    #[tokio::test]
    async fn every_stripped_field_is_actually_volatile() {
        // A field on the strip list that is in fact stable is coverage
        // quietly given away: it would be excluded from the guard for no
        // reason. Build the same envelope twice and require that each
        // stripped field genuinely differs somewhere in the document (or,
        // for a field the schema does not currently emit, is absent from
        // both).
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let mut t = src.load(&r).unwrap();
        // A source that records no per-event time is what makes
        // `timestamp` volatile: those events inherit `now`. The claude-code
        // fixture does record times, so clear them here -- otherwise this
        // test would "prove" `timestamp` is stable and demand it be removed
        // from the list, which would make the digest non-deterministic for
        // every source that omits them.
        for e in t.events.iter_mut() {
            e.timestamp = None;
        }
        let redactor = build_redactor_with(&cfg, t.cwd.as_deref(), None).unwrap();
        let a = redact_to_envelope(&redactor, build_raw_contribution(&t, &cfg, Utc::now()))
            .await
            .unwrap();
        let b = redact_to_envelope(&redactor, build_raw_contribution(&t, &cfg, Utc::now()))
            .await
            .unwrap();
        let va = serde_json::to_value(&a).unwrap();
        let vb = serde_json::to_value(&b).unwrap();
        for field in VOLATILE_ENVELOPE_FIELDS {
            let ka = collect_field(&va, field);
            let kb = collect_field(&vb, field);
            assert!(
                ka.is_empty() || ka != kb,
                "{field} is stable across two builds and does not belong on \
                 the volatile list"
            );
        }
    }

    /// Every value stored under `field`, anywhere in the document.
    fn collect_field(value: &serde_json::Value, field: &str) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        fn walk(v: &serde_json::Value, field: &str, out: &mut Vec<serde_json::Value>) {
            match v {
                serde_json::Value::Object(map) => {
                    if let Some(found) = map.get(field) {
                        out.push(found.clone());
                    }
                    for child in map.values() {
                        walk(child, field, out);
                    }
                }
                serde_json::Value::Array(items) => {
                    for child in items {
                        walk(child, field, out);
                    }
                }
                _ => {}
            }
        }
        walk(value, field, &mut out);
        out
    }

    #[test]
    fn the_input_fingerprint_moves_with_every_envelope_determining_input() {
        let (_sd, store) = crate::config::tests_support::temp_store();
        let base = sample_cfg(&store);
        let baseline = input_fingerprint(&base, None, false);
        assert_eq!(
            baseline,
            input_fingerprint(&base, None, false),
            "must be stable"
        );

        for mutate in [
            (|c: &mut ContributorConfig| c.tenant_id = "other-tenant".into())
                as fn(&mut ContributorConfig),
            |c: &mut ContributorConfig| c.consent_scopes = vec!["model_training".into()],
            |c: &mut ContributorConfig| c.pii_filter = Some("near-ai".into()),
            |c: &mut ContributorConfig| c.user_subject = "bob".into(),
            |c: &mut ContributorConfig| c.ingest_url = "http://elsewhere.invalid".into(),
            |c: &mut ContributorConfig| c.device_key_id = "sha256:zz".into(),
        ] {
            let mut cfg = base.clone();
            mutate(&mut cfg);
            assert_ne!(
                baseline,
                input_fingerprint(&cfg, None, false),
                "an envelope-determining config change must move the fingerprint"
            );
        }

        // Attaching a privacy-filter backend changes it; so does pointing
        // that backend at a different service or model.
        let near = NearAiSettings {
            api_key: "secret-key".into(),
            base_url: Some("https://filter.invalid".into()),
            model: Some("m1".into()),
        };
        assert_ne!(baseline, input_fingerprint(&base, Some(&near), false));
        let other_model = NearAiSettings {
            model: Some("m2".into()),
            ..near.clone()
        };
        assert_ne!(
            input_fingerprint(&base, Some(&near), false),
            input_fingerprint(&base, Some(&other_model), false)
        );
        // But rotating the credential does not: it changes nothing about
        // what the filter does, and a secret is not hashed into a value
        // that lands on disk.
        let rotated = NearAiSettings {
            api_key: "a-different-secret".into(),
            ..near.clone()
        };
        assert_eq!(
            input_fingerprint(&base, Some(&near), false),
            input_fingerprint(&base, Some(&rotated), false)
        );
    }

    /// Turning the attested-bodies switch on starts sending the final
    /// call's verbatim prompt to a witness. Every approval taken before that
    /// was taken without it, so the fingerprint must move and the uploader
    /// must re-ask.
    #[test]
    fn switching_on_attested_bodies_re_asks_the_approved_backlog() {
        let (_sd, store) = crate::config::tests_support::temp_store();
        let base = sample_cfg(&store);
        assert_ne!(
            input_fingerprint(&base, None, false),
            input_fingerprint(&base, None, true),
            "an approval given before prompt bodies were carried must not \
             be honoured after"
        );
    }

    #[test]
    fn claiming_a_public_handle_does_not_invalidate_the_approved_backlog() {
        // The whole point of `NON_ENVELOPE_CONFIG_FIELDS`. A contributor who
        // claims, edits, or withdraws a public handle has said nothing about
        // any queued trace, so every approval they have already given must
        // survive it -- otherwise the uploader re-offers the entire backlog
        // under `approval-inputs-changed`.
        let (_sd, store) = crate::config::tests_support::temp_store();
        let base = sample_cfg(&store);
        let baseline = input_fingerprint(&base, None, false);

        let mut claimed = base.clone();
        claimed.display_handle = Some("quiet-otter".into());
        claimed.public_bio = Some("Ships billing systems by day.".into());
        claimed.public_since = Some(chrono::Utc::now());
        assert_eq!(
            baseline,
            input_fingerprint(&claimed, None, false),
            "claiming a handle must not move the fingerprint"
        );

        let mut renamed = claimed.clone();
        renamed.display_handle = Some("loud-otter".into());
        renamed.public_bio = None;
        assert_eq!(
            baseline,
            input_fingerprint(&renamed, None, false),
            "editing a published profile must not move the fingerprint"
        );
    }

    #[test]
    fn every_config_field_is_a_deliberate_fingerprint_decision() {
        // The blanket property `input_fingerprint` is built on is "hash the
        // config whole", which only stays trustworthy while every exception
        // to it is written down. This pins the full serialized field set so
        // that adding a field to `ContributorConfig` fails here until
        // whoever added it decides whether it determines the envelope. The
        // safe answer -- and the default if they simply drop it into the
        // list below -- is that it does.
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let value = serde_json::to_value(&cfg).unwrap();
        let mut all: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        all.sort_unstable();
        assert_eq!(
            all,
            vec![
                "allowed_hosts",
                "audience",
                "consent_scopes",
                "device_key_id",
                "display_handle",
                // Fingerprinted, deliberately, for the same reason as
                // `inference_receipt_endpoint` just below: turning it on
                // adds a second outbound request -- for a nonced attestation
                // report -- that tells the provider this exchange is being
                // checked for contribution, on top of the disclosure the
                // receipt fetch itself already makes. A consent-bearing
                // change, so an entry approved before it was set must be
                // re-asked.
                "inference_receipt_check_attestation",
                // Fingerprinted, deliberately. It does not change a byte of
                // the envelope -- the receipt goes to the witness, which
                // strips the bodies before certifying -- but turning it on
                // starts disclosing to the inference provider that a given
                // exchange is being contributed. That is a consent-bearing
                // change, and an entry approved before it was set should be
                // re-asked rather than uploaded under a rule the contributor
                // never saw.
                "inference_receipt_endpoint",
                "ingest_url",
                "instance_id",
                "issuer_url",
                "pii_filter",
                "public_bio",
                "public_since",
                "schema_version",
                "tenant_id",
                "user_subject",
                // Fingerprinted, deliberately, and NOT in
                // NON_ENVELOPE_CONFIG_FIELDS. Turning a witness on changes
                // who builds the envelope and therefore what the bytes are,
                // so an entry approved before the change must be re-approved
                // rather than uploaded under the new arrangement. Over-
                // invalidating re-asks; under-invalidating sends something
                // the contributor did not approve.
                "witness",
            ],
            "a new ContributorConfig field must be classified: leave it out of \
             NON_ENVELOPE_CONFIG_FIELDS to fingerprint it, or add it there with a reason"
        );

        // And the exclusions must name fields that actually exist -- a typo
        // would silently fingerprint the field it meant to drop.
        for field in NON_ENVELOPE_CONFIG_FIELDS {
            assert!(
                all.contains(field),
                "NON_ENVELOPE_CONFIG_FIELDS names {field}, which is not a config field"
            );
        }
    }

    #[tokio::test]
    async fn the_digest_moves_when_the_envelope_does() {
        // Same session bytes, different envelope-determining config: the
        // digest must not be blind to it.
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (a, _, _) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();

        let mut widened = cfg.clone();
        widened.consent_scopes = vec!["model_training".into()];
        let (b, _, _) = build_preview(&store, Some(&widened), None, &src, &r)
            .await
            .unwrap();
        assert_ne!(a.envelope_digest, b.envelope_digest);
        assert_ne!(a.input_fingerprint, b.input_fingerprint);
    }

    /// An envelope from the real pipeline, with synthetic tool events
    /// appended so the grouping rule has something to group. Cloning the
    /// redacted event keeps every required field real; only the fields the
    /// index reads are changed.
    async fn envelope_with_tool_events() -> TraceContributionEnvelope {
        let (_d, src, r) = fixture_session();
        let (_sd, store) = crate::config::tests_support::temp_store();
        let cfg = sample_cfg(&store);
        let (_summary, _body, mut envelope) = build_preview(&store, Some(&cfg), None, &src, &r)
            .await
            .unwrap();
        let template = envelope.events[0].clone();

        let mut call = template.clone();
        call.event_id = uuid::Uuid::new_v4();
        call.event_type = TraceContributionEventType::ToolCall;
        call.tool_name = Some("bash".into());
        call.tool_call_id = Some("call-1".into());
        call.redacted_content = Some("ls -la".into());

        let mut result = template.clone();
        result.event_id = uuid::Uuid::new_v4();
        result.event_type = TraceContributionEventType::ToolResult;
        result.tool_name = Some("bash".into());
        result.tool_call_id = Some("call-1".into());
        result.redacted_content = Some("total 0".into());

        let mut assistant = template.clone();
        assistant.event_id = uuid::Uuid::new_v4();
        assistant.event_type = TraceContributionEventType::AssistantMessage;
        assistant.tool_name = None;
        assistant.tool_call_id = None;

        envelope.events.push(call);
        envelope.events.push(result);
        envelope.events.push(assistant);
        envelope
    }

    #[tokio::test]
    async fn turn_offsets_land_on_the_exact_event_bytes() {
        // The property the whole index rests on. An offset that has drifted
        // -- by an element, or by the two bytes of a separator -- draws a
        // separator over the wrong text, and does it silently, under a tab
        // titled "exactly what would be sent". So every span is re-parsed
        // out of the body `body_of` actually returned and required to be
        // the events it claims.
        let envelope = envelope_with_tool_events().await;
        let body = body_of(&envelope).unwrap();
        let turns = turns_of(&envelope).unwrap();

        let mut covered = 0usize;
        let mut next_event = 0usize;
        for turn in &turns {
            assert!(
                turn.byte_offset >= covered,
                "turns must not overlap: {turn:?}"
            );
            let slice = &body[turn.byte_offset..turn.byte_offset + turn.byte_len];
            // A grouped turn spans two array elements and the separator
            // between them, so it is a fragment of an array rather than one
            // value. Re-wrapping is how a fragment is parsed; it asserts
            // that the span starts and ends exactly on element boundaries,
            // which is the thing being checked.
            let parsed: Vec<serde_json::Value> = serde_json::from_str(&format!("[{slice}]"))
                .unwrap_or_else(|e| {
                    panic!("span {turn:?} is not a run of whole elements: {e}");
                });
            for value in &parsed {
                assert_eq!(
                    value,
                    &serde_json::to_value(&envelope.events[next_event]).unwrap(),
                    "turn {} does not point at event {next_event}",
                    turn.index
                );
                next_event += 1;
            }
            covered = turn.byte_offset + turn.byte_len;
        }
        assert_eq!(
            next_event,
            envelope.events.len(),
            "every event must be covered by exactly one turn"
        );
        assert_eq!(
            turns.iter().map(|t| t.index).collect::<Vec<_>>(),
            (0..turns.len()).collect::<Vec<_>>(),
            "turn indices are dense and 0-based"
        );
    }

    #[tokio::test]
    async fn a_tool_call_and_its_result_are_one_turn() {
        // The grouping decision, pinned: one invocation of one tool is one
        // turn, spanning both events, labelled with the tool.
        let envelope = envelope_with_tool_events().await;
        let turns = turns_of(&envelope).unwrap();
        assert_eq!(
            turns.len(),
            envelope.events.len() - 1,
            "the call/result pair collapses into a single turn: {turns:?}"
        );
        let tool_turn = turns
            .iter()
            .find(|t| t.role == "tool_call")
            .expect("a tool turn");
        assert_eq!(tool_turn.tool_name.as_deref(), Some("bash"));
        let body = body_of(&envelope).unwrap();
        let slice = &body[tool_turn.byte_offset..tool_turn.byte_offset + tool_turn.byte_len];
        assert!(slice.contains("\"tool_call\""), "{slice}");
        assert!(
            slice.contains("\"tool_result\""),
            "the result belongs to the same turn: {slice}"
        );
        assert!(
            !turns.iter().any(|t| t.role == "tool_result"),
            "a grouped result must not also open a turn of its own: {turns:?}"
        );
    }

    #[tokio::test]
    async fn a_result_that_cannot_be_correlated_stays_its_own_turn() {
        // The other half of the rule. Pairing is only ever done on an
        // explicit, adjacent `tool_call_id`; a result that does not match
        // one is indexed separately rather than swept into the preceding
        // call, because a span covering two unrelated events labels bytes
        // that do not belong together.
        let mut envelope = envelope_with_tool_events().await;
        let grouped = turns_of(&envelope).unwrap().len();
        for event in envelope.events.iter_mut() {
            if event.event_type == TraceContributionEventType::ToolResult {
                event.tool_call_id = Some("some-other-call".into());
            }
        }
        let turns = turns_of(&envelope).unwrap();
        assert_eq!(turns.len(), grouped + 1);
        assert!(turns.iter().any(|t| t.role == "tool_result"));
    }

    #[tokio::test]
    async fn an_envelope_with_no_events_indexes_to_no_turns() {
        let mut envelope = envelope_with_tool_events().await;
        envelope.events.clear();
        assert_eq!(body_of(&envelope).unwrap(), "[]");
        assert!(turns_of(&envelope).unwrap().is_empty());
    }

    #[test]
    fn the_span_scan_refuses_a_document_it_was_not_written_for() {
        // Fail-closed: an index that is not certainly exact is worse than
        // none, so anything that is not an array of objects is refused
        // rather than approximated.
        assert!(top_level_object_spans("{\"a\": 1}").is_none());
        assert!(top_level_object_spans("[[1]]").is_none());
        assert!(top_level_object_spans("[{\"a\": 1}").is_none());
        assert_eq!(top_level_object_spans("[]"), Some(vec![]));
        // A brace inside a string is text, not structure.
        let body = "[\n  {\n    \"a\": \"} {\"\n  }\n]";
        assert_eq!(top_level_object_spans(body).unwrap().len(), 1);
        let (s, e) = top_level_object_spans(body).unwrap()[0];
        assert!(serde_json::from_str::<serde_json::Value>(&body[s..e]).is_ok());
    }
}
