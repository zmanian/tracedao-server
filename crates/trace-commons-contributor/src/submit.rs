//! Submit pipeline: redact-and-upload sessions, then read back submission
//! status. Every outcome reason is a fixed label -- never a response body,
//! trace content, or raw path.

use std::path::Path;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::BTreeMap;
use trace_commons_operator_client::{Client, Error as OcError};
use trace_commons_protocol::admission::AdmissionRefusal;
use trace_commons_protocol::trace_contribution::{
    ConsentMetadata, ConsentScope, RawTraceContribution, ResidualPiiRisk, TraceAllowedUse,
    TraceContributionEnvelope, TraceSubmissionReceipt, TraceSubmissionStatusRequest,
    TraceSubmissionStatusUpdate,
};

use crate::config::{ConfigStore, ContributorConfig, Receipt, WitnessSettings, config_allowlist};
use crate::envelope::{
    MAX_ENVELOPE_BYTES, NearAiSettings, apply_granted_scopes, build_deterministic_preview_redactor,
    build_preview_raw_contribution, build_raw_contribution_with_verdict, build_redactor_with,
    canary_self_test_async, envelope_has_residual_secret, envelope_size, envelope_size_ok,
    near_ai_settings_from_env, parse_scope_names, parse_use_names, raw_contribution_size,
    raw_contribution_size_ok, redact_to_envelope,
};
use crate::identity::{
    DeviceIdentity, build_signed_claim_request, build_signed_claim_request_with_scopes,
};
use crate::issuer_client::{ClaimToken, IssuerClient};
use crate::source::{SessionRef, TraceSource};
use crate::witness::inference_record::{self, InferenceAttestationRecord};
use crate::witness::status::{
    WitnessLastResult, certificate_obtained_for, n_of_m_from_certificate, record_last_result,
};
use crate::witness::transport::{
    GrantedConsent, HttpWitnessTransport, WITNESS_CERTIFICATE_HEADER, WITNESS_SIGNATURE_HEADER,
    WitnessedEnvelope, parse_witnessed_envelope,
};
use crate::witness::{WITNESS_EXPECTED_MEASUREMENT_CONTROL, witness_session};

/// Select the witness profile from source bytes before receipt lookup or HTTP.
/// The signup flag enables account-bound evidence, but existing unbound history
/// still uses ordinary signed review; the server independently requires invite
/// eligibility for that path. A present marker (even malformed/expired) must
/// never become an ordinary-profile retry.
/// What a witnessed review's attested-inference record says, decided from
/// what was actually offered to the witness.
///
/// Pure, and deliberately narrow: `attested` is the call whose bodies went
/// in the request, `receipt` is the receipt that went with them. A call
/// without a receipt is the failure this record exists to name -- the fetch
/// was attempted and nothing came back -- and a receipt without a call has
/// nothing to bind. Only both together is attested inference, and even then
/// the caller may say so only once the witness has certified the request.
pub(crate) fn inference_attestation_for(
    attested: Option<&crate::routing::attested::AttestedCall>,
    receipt: Option<&trace_commons_attestation::receipt::ReceiptPayload>,
) -> InferenceAttestationRecord {
    match (attested, receipt) {
        (Some(_), Some(_)) => InferenceAttestationRecord::certified(),
        (Some(_), None) => {
            InferenceAttestationRecord::uncertified(inference_record::REASON_RECEIPT_UNAVAILABLE)
        }
        (None, _) => {
            InferenceAttestationRecord::uncertified(inference_record::REASON_NO_ATTESTED_CALL)
        }
    }
}

pub(crate) fn admission_profile_for_request(
    enabled: bool,
    request_body: Option<&str>,
) -> std::result::Result<bool, &'static str> {
    if !enabled {
        return Ok(false);
    }
    let Some(body) = request_body else {
        return Ok(false);
    };
    let request: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "admission_request_malformed")?;
    let object = request.as_object().ok_or("admission_request_malformed")?;
    match object.get("metadata") {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Object(metadata)) => {
            Ok(metadata.contains_key(trace_commons_protocol::admission::REQUEST_METADATA_KEY))
        }
        Some(_) => Err("admission_request_malformed"),
    }
}

pub(crate) fn witness_input_for_profile(
    raw: RawTraceContribution,
    cfg: &ContributorConfig,
    admission: bool,
) -> RawTraceContribution {
    if admission {
        crate::envelope::final_call_witness_input(raw, cfg)
    } else {
        raw
    }
}

/// Statuses that mean a session has already been accepted by the server;
/// re-encountering a receipt with one of these statuses short-circuits the
/// per-session flow instead of re-uploading.
pub(crate) const ALREADY_SUBMITTED_STATUSES: [&str; 3] = ["submitted", "accepted", "quarantined"];

/// A fail-closed precondition that aborts the whole submit pass rather than
/// producing an outcome for one session.
///
/// `submit_one` returns `Ok(SubmitOutcome::…)` for everything that is a
/// decision *about a session* and `Err` only for these -- a privacy-filter
/// canary that did not catch its planted secret, a NEAR AI first-use notice
/// that could not be recorded, a missing device identity. It carries a
/// fixed label rather than free text so the daemon's health surface can
/// name the condition without parsing an error string: before this existed,
/// a canary failure propagated as an opaque `anyhow::Error`, the daemon
/// logged a warning and continued, `LABEL_CANARY_FAILED` was never set by
/// any production code path, and `expire` therefore ran the fourteen-day
/// clock straight through a filter outage -- discarding pending traces as
/// "expired-without-decision" when nobody had declined them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmitPreconditionFailure(pub &'static str);

/// The canary planted a known secret and the configured filter did not
/// remove it. Nothing may be sent through that filter.
pub const PRECONDITION_CANARY_FAILED: &str = "privacy-filter-canary-failed";
/// The NEAR AI first-use notice could not be recorded as shown.
pub const PRECONDITION_NEAR_AI_NOTICE_UNRECORDED: &str = "near-ai-notice-not-acknowledged";
/// No usable device identity, so nothing can be signed.
pub const PRECONDITION_NOT_LOGGED_IN: &str = "not-logged-in";

impl std::fmt::Display for SubmitPreconditionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for SubmitPreconditionFailure {}

#[derive(Debug)]
pub enum SubmitOutcome {
    Submitted {
        submission_id: Uuid,
        status: String,
    },
    AlreadySubmitted {
        submission_id: Uuid,
        /// The status this session already carries server-side, from the
        /// stored receipt. Without it, a re-run reports "already-submitted"
        /// and the contributor cannot tell whether the trace was accepted,
        /// quarantined, or merely delivered.
        prior_status: String,
    },
    SkippedParseFailure {
        reason_label: String,
    },
    Refused {
        reason_label: String,
        /// Opaque content hash identifying the local session without
        /// exposing its path or trace contents.
        session_ref: String,
        size_bytes: Option<usize>,
        limit_bytes: Option<usize>,
    }, // canary hit, fail-closed PII filter, too large
    Failed {
        reason_label: String,
    }, // network/auth after retries
}

/// What the inference-receipt fetch produced for a shipped submission.
///
/// The receipt fetch is best-effort on the ordinary witnessed path: a failure
/// does not block the upload, because an unattested submission is an honest
/// thing to send and the witness decides whether it is acceptable. But the
/// failure used to vanish into a debug log while the attestation mark went on
/// saying `attested`, so a person who ran a hosted model whose receipt 404'd
/// believed they had contributed attested work. This records what actually
/// happened so the mark can be corrected after the fact -- see
/// [`crate::daemon::attestation_mark::writeback_after_upload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptShipped {
    /// No attested call was carried, so no receipt was ever sought.
    NoCall,
    /// A receipt was fetched and accompanied the submission.
    Attached,
    /// An attested call was carried and its receipt could not be obtained.
    /// The submission shipped without it; the reason says whether that is
    /// permanent (a definite 404) or transient.
    Omitted(crate::routing::receipt::ReceiptFetchError),
}

/// Default options leave optional overrides absent and all switches off.
/// Enrollment and consent are still checked by the submission path; these
/// defaults do not establish either. Tests can override the flags they exercise.
#[derive(Default)]
pub struct SubmitOptions {
    pub dry_run: bool,
    pub pii_filter: Option<String>,
    /// Drop model reasoning from every session in this run before envelope
    /// construction. Reasoning is included by default.
    pub no_reasoning: bool,
    /// Suppress progress prose so stdout remains one machine-readable JSON
    /// document. Outcome data is still returned to the command renderer.
    pub machine_readable: bool,
    /// This run has no persisted contributor config. It must remain offline,
    /// use preview ids, and leave the contributor state directory untouched.
    pub unenrolled_preview: bool,
    /// Re-upload corrected envelopes for sessions whose local receipt is
    /// `quarantined`. Keeps the same content-addressed `submission_id` and
    /// asks the server to supersede the stored record (#214).
    pub remediate_quarantined: bool,
    /// How the contributor says these sessions went, applied to every
    /// envelope this run builds. `None` leaves `task_success` `Unknown`,
    /// which is what every envelope carried before this existed.
    ///
    /// Only reaches envelopes this run BUILDS. An entry uploading previously
    /// approved bytes sends exactly those bytes, so a verdict cannot be
    /// applied to it after the fact -- see the note on `SubmitOptions` in
    /// `daemon::drain_approved` about this struct sitting outside the
    /// approval fingerprint. Collecting a verdict at approval time is the
    /// daemon-side half and is deliberately not attempted here.
    pub verdict: Option<crate::envelope::ContributorVerdict>,
}

fn refused(reason_label: &str, session_ref: &str) -> SubmitOutcome {
    SubmitOutcome::Refused {
        reason_label: reason_label.to_string(),
        session_ref: session_ref.to_string(),
        size_bytes: None,
        limit_bytes: None,
    }
}

fn refused_for_size(session_ref: &str, size_bytes: usize) -> SubmitOutcome {
    SubmitOutcome::Refused {
        reason_label: "session-too-large".to_string(),
        session_ref: session_ref.to_string(),
        size_bytes: Some(size_bytes),
        limit_bytes: Some(MAX_ENVELOPE_BYTES),
    }
}

/// Whether a submit result must make the command exit non-zero. Only an
/// expected size finding is non-fatal during dry-run. Every known privacy or
/// pipeline refusal, and every future refusal label, fails closed.
/// Why an envelope carries the residual risk it does, in labels only.
///
/// The risk VALUE is never recomputed here -- it is read from
/// `envelope.privacy.residual_pii_risk`, which the protocol crate already
/// derived. Only the explanation is assembled, from the envelope's own counts,
/// labels and consent flags. A second implementation of the risk rule in this
/// crate would eventually disagree with the first, and an explanation that
/// contradicts the number it explains is worse than no explanation.
///
/// Labels and counts only. This runs over other people's private traces, so
/// no matched text, no path, no content ever reaches the output.
///
/// Takes the whole `ConsentMetadata` rather than a bool per flag, for the same
/// reason the ingest backstop-hold predicate does: passing them individually is
/// what lets a new content flag be forgotten, and an explanation that omits the
/// flag which raised the floor contradicts the number it explains.
fn residual_risk_explanation(
    consent: &ConsentMetadata,
    redaction_counts: &BTreeMap<String, u32>,
    pii_labels_present: &[String],
) -> String {
    let mut causes: Vec<String> = Vec::new();

    let mut consent_flags: Vec<&str> = Vec::new();
    if consent.message_text_included {
        consent_flags.push("message_text_included");
    }
    if consent.tool_payloads_included {
        consent_flags.push("tool_payloads_included");
    }
    if consent.correction_included {
        consent_flags.push("correction_included");
    }
    if !consent_flags.is_empty() {
        causes.push(format!("consent flags: {}", consent_flags.join(", ")));
    }

    if !redaction_counts.is_empty() {
        let mut parts: Vec<String> = redaction_counts
            .iter()
            .map(|(label, count)| format!("{count} {label}"))
            .collect();
        parts.sort();
        causes.push(format!("redaction found: {}", parts.join(", ")));
    }

    if !pii_labels_present.is_empty() {
        let mut labels = pii_labels_present.to_vec();
        labels.sort();
        causes.push(format!("pii labels: {}", labels.join(", ")));
    }

    if causes.is_empty() {
        "nothing in this envelope raised the floor".to_string()
    } else {
        causes.join("; ")
    }
}

/// What a given tier means for storage on the server.
///
/// Phrased conditionally on purpose: the client cannot see the operator's
/// configuration, so it says what the tier means rather than promising an
/// outcome it cannot know.
fn residual_risk_storage_note(risk: ResidualPiiRisk) -> &'static str {
    match risk {
        ResidualPiiRisk::Low => "Low is accepted.",
        ResidualPiiRisk::Medium => {
            "Medium accepts only if the operator enabled \
             TRACE_COMMONS_ACCEPT_MEDIUM_RISK_SUBMISSIONS; otherwise quarantines."
        }
        ResidualPiiRisk::High => "High quarantines for review.",
    }
}

pub fn outcomes_have_failure(outcomes: &[SubmitOutcome], dry_run: bool) -> bool {
    outcomes.iter().any(|outcome| match outcome {
        SubmitOutcome::Failed { .. } => true,
        SubmitOutcome::Refused { reason_label, .. } => match reason_label.as_str() {
            "session-too-large" => !dry_run,
            "pii-filter-unavailable"
            | "redaction-failed"
            | "secret-leak-detected"
            | "scopes-not-permitted" => true,
            _ => true,
        },
        _ => false,
    })
}

/// One entry in a `submit --manifest` file: an envelope id that reached the
/// server, for handing to an external collector (e.g. devfolio).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ManifestEntry {
    pub submission_id: Uuid,
    pub status: String,
}

/// Envelope ids that reached the server, for handing to an external
/// collector (e.g. devfolio). Includes freshly submitted and
/// already-submitted traces; skips refused/failed/skipped outcomes.
pub fn build_manifest(outcomes: &[SubmitOutcome]) -> Vec<ManifestEntry> {
    outcomes
        .iter()
        .filter_map(|o| match o {
            SubmitOutcome::Submitted {
                submission_id,
                status,
            } => Some(ManifestEntry {
                submission_id: *submission_id,
                status: status.clone(),
            }),
            SubmitOutcome::AlreadySubmitted {
                submission_id,
                prior_status,
            } => Some(ManifestEntry {
                submission_id: *submission_id,
                status: prior_status.clone(),
            }),
            SubmitOutcome::SkippedParseFailure { .. }
            | SubmitOutcome::Refused { .. }
            | SubmitOutcome::Failed { .. } => None,
        })
        .collect()
}

/// Redact-and-upload every selected session. Sessions are independent: one
/// session's failure never aborts the batch. The one exception is the
/// once-per-batch privacy-filter canary self-test, which is a fail-closed
/// precondition for the whole batch.
pub async fn submit_sessions(
    store: &ConfigStore,
    cfg: &ContributorConfig,
    sessions: Vec<(Box<dyn TraceSource>, SessionRef)>,
    opts: &SubmitOptions,
) -> Result<Vec<SubmitOutcome>> {
    if opts.unenrolled_preview && !opts.dry_run {
        anyhow::bail!("unenrolled preview requires dry-run");
    }
    let mut ctx = crate::daemon::run_blocking(|| {
        SubmitContext::new(store, cfg, opts, near_ai_settings_from_env())
    })?;
    let mut outcomes = Vec::with_capacity(sessions.len());
    for (source, session_ref) in sessions {
        outcomes.push(ctx.submit_one(source.as_ref(), &session_ref).await?);
    }
    Ok(outcomes)
}

/// A long-lived submit pipeline: everything `submit_sessions` used to hoist
/// across a batch -- device identity, issuer client, the minted claim, the
/// privacy-filter canary, and the receipts index -- held so it can be reused
/// across calls.
///
/// The CLI builds one per `submit` invocation and drops it. The daemon holds
/// one for the life of the process and feeds it a session at a time, so a
/// background upload takes byte-for-byte the same path as an interactive one
/// rather than a parallel reimplementation of it.
///
/// `near_ai` is supplied by the caller rather than read from the environment,
/// because a daemon started by a service manager inherits none of the user's
/// shell environment.
pub struct SubmitContext<'a> {
    store: &'a ConfigStore,
    cfg: &'a ContributorConfig,
    opts: &'a SubmitOptions,
    effective_cfg: ContributorConfig,
    device: Option<DeviceIdentity>,
    issuer: IssuerClient,
    claim: Option<ClaimToken>,
    canary_checked: bool,
    near_ai_notice_recorded: bool,
    near_ai: Option<NearAiSettings>,
    receipts: Vec<Receipt>,
    canary_runs: u32,
    approved_envelope: Option<TraceContributionEnvelope>,
    approved_witness: Option<WitnessedEnvelope>,
    approved_token_bundle: Option<crate::token_bundle::TokenBundleReview>,
    /// What the last `submit_one`'s receipt fetch produced, for the daemon to
    /// correct the attestation mark after an upload. Reset at the start of
    /// each `submit_one`, set by `witness_envelope` when it runs.
    last_receipt_shipped: ReceiptShipped,
    /// Stands in for a fetched provider receipt, tests only.
    ///
    /// `receipt_for_attested_call` refuses a plaintext endpoint before it
    /// refuses anything else, so a loopback mock cannot be fetched from, and
    /// a receipt is only verifiable against a signer no test holds. Without
    /// this seam the bound admission path is unreachable in-process: it
    /// refuses `admission_receipt_unavailable` before the projection below it
    /// ever runs, and the projection is the control this profile exists for.
    /// Compiled out of every shipped build.
    #[cfg(test)]
    receipt_override: Option<trace_commons_attestation::receipt::ReceiptPayload>,
}

impl<'a> SubmitContext<'a> {
    pub fn new(
        store: &'a ConfigStore,
        cfg: &'a ContributorConfig,
        opts: &'a SubmitOptions,
        near_ai: Option<NearAiSettings>,
    ) -> Result<Self> {
        let effective_cfg = effective_config(cfg, opts);
        let device = if opts.unenrolled_preview {
            None
        } else if opts.dry_run {
            DeviceIdentity::load(store).context("loading device identity")?
        } else {
            Some(DeviceIdentity::load_or_generate(store).context("loading device identity")?)
        };
        let issuer = IssuerClient::new(config_allowlist(cfg)).context("building issuer client")?;
        // An unenrolled preview has no enrollment and therefore no submission
        // history it can truthfully replay. Ignore stale receipts from torn
        // local state and run the preview pipeline for every selected session.
        let receipts = if opts.unenrolled_preview {
            Vec::new()
        } else {
            store.load_receipts().context("loading receipts")?
        };
        Ok(Self {
            store,
            cfg,
            opts,
            effective_cfg,
            device,
            issuer,
            claim: None,
            canary_checked: false,
            near_ai_notice_recorded: false,
            near_ai,
            receipts,
            canary_runs: 0,
            approved_envelope: None,
            approved_witness: None,
            approved_token_bundle: None,
            last_receipt_shipped: ReceiptShipped::NoCall,
            #[cfg(test)]
            receipt_override: None,
        })
    }

    /// Force the next `submit_one` to re-run the privacy-filter canary. A
    /// long-lived daemon must re-check the filter periodically rather than
    /// trusting a self-test from days ago.
    pub fn invalidate_canary(&mut self) {
        self.canary_checked = false;
    }

    /// Drop the cached claim, so the next upload mints a fresh one. Called
    /// when enrollment or consent may have changed underneath a running
    /// process.
    pub fn invalidate_claim(&mut self) {
        self.claim = None;
    }

    /// How many times the privacy-filter canary has actually run. Used to
    /// assert the canary is not re-run once per session.
    pub fn canary_runs(&self) -> u32 {
        self.canary_runs
    }

    /// Send *this* redacted envelope on the next `submit_loaded` instead of
    /// building one.
    ///
    /// This is the artifact half of the daemon's consent guard. The re-hash
    /// guard verifies the *input* -- the raw session bytes -- and cannot see
    /// a redaction service that returned different spans, a privacy-filter
    /// configuration that changed, or any other input to the envelope that
    /// is not the session file.
    ///
    /// An earlier version of this took a *digest* and refused when the
    /// rebuilt envelope did not match it. That is correct and unusable: the
    /// pilot runs `pii_filter = "near-ai"`, an LLM-backed filter does not
    /// return identical spans for identical text, and so every previewed
    /// entry was refused, re-offered, previewed again, and refused again --
    /// the primary consent path never completed. Handing the pipeline the
    /// approved bytes removes the divergence instead of detecting it: what
    /// the contributor saw is what goes out, by construction.
    ///
    /// `None` restores the ordinary build-from-transcript path, which is
    /// what armed auto-upload (never previewed, nothing shown to hold the
    /// send to) still uses.
    ///
    /// One-shot: consumed by the next `submit_loaded` so an approved
    /// envelope cannot leak onto an unrelated later session.
    pub fn use_approved_envelope(&mut self, envelope: Option<TraceContributionEnvelope>) {
        self.approved_envelope = envelope;
        self.approved_witness = None;
        self.approved_token_bundle = None;
    }

    /// One-shot witnessed artifact. Caller has checked the atomic record's pin
    /// and bindings; submit rechecks its certificate and fresh authorization.
    pub(crate) fn use_approved_witness(&mut self, response: WitnessedEnvelope) -> Result<()> {
        self.approved_envelope = None;
        self.approved_witness = None;
        self.approved_envelope = Some(parse_witnessed_envelope(&response)?);
        self.approved_witness = Some(response);
        self.invalidate_claim();
        Ok(())
    }

    pub(crate) fn use_approved_token_bundle(
        &mut self,
        bundle: Option<crate::token_bundle::TokenBundleReview>,
    ) {
        self.approved_token_bundle = bundle;
    }
    pub(crate) async fn prepare_token_review(
        &mut self,
        transcript: &crate::source::SessionTranscript,
        control: &crate::token_capture_client::TokenCaptureClient,
        session: &str,
    ) -> Result<(
        WitnessedEnvelope,
        InferenceAttestationRecord,
        crate::token_bundle::TokenBundleReview,
    )> {
        use crate::token_bundle::*;
        let settings = self
            .cfg
            .witness
            .clone()
            .ok_or_else(|| anyhow::anyhow!("witness-not-configured"))?;
        let trust = settings
            .trust()
            .map_err(|_| anyhow::anyhow!("witness_expected_measurement_malformed"))?;
        if !trust.is_pinned() {
            anyhow::bail!("witness_expected_measurement");
        }
        let call = transcript
            .attested_call
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("token-capture-source-unavailable"))?;
        let token = self
            .ensure_claim(Utc::now(), &transcript.session_hash)
            .await?
            .map_err(|_| anyhow::anyhow!("witness-claim-unavailable"))?;
        validate_review_grant(&self.effective_cfg, &token, Utc::now())?;
        let ingest = build_ingest_client(self.cfg, &token)?;
        let capability = ingest
            .call_bytes(reqwest::Method::GET, "/v1/token-bundles", &[], &[], &[])
            .await
            .map_err(|_| anyhow::anyhow!("token-bundles-unavailable"))?;
        let capability: serde_json::Value = serde_json::from_str(&capability)?;
        if capability["version"] != 1 || capability["policy"] != "token-distribution-restricted-v1"
        {
            anyhow::bail!("token-bundles-incompatible");
        }
        let destination: BundleDestination = serde_json::from_value(serde_json::json!({
            "server_id": capability["server_id"],
            "tenant_id": capability["tenant_id"],
            "account_id": capability["account_id"],
        }))?;
        let lease = crate::daemon::token_capture::acquire(control, session, call).await?;
        let lease_binding = lease.bundle_lease()?;
        let lease_guard = match crate::token_review_lease::ReviewLeaseGuard::new(
            &self.store.dir().join("token-bundles"),
            lease_binding.clone(),
        ) {
            Ok(guard) => guard,
            Err(error) => {
                let _ = control.release(&lease_binding).await;
                return Err(error);
            }
        };
        let source = lease
            .captures
            .first()
            .ok_or_else(|| anyhow::anyhow!("token-capture-source-unavailable"))?;
        let receipt = self
            .inference_receipt_for(call)
            .await
            .map_err(|_| anyhow::anyhow!("admission_receipt_unavailable"))?;
        let attested = crate::witness::transport::AttestedInference {
            call,
            receipt: Some(&receipt),
        };
        let raw = crate::envelope::build_raw_contribution_with_correction(
            transcript,
            &self.effective_cfg,
            Utc::now(),
            None,
            None,
        );
        let raw = witness_input_for_profile(raw, &self.effective_cfg, true);
        let (scopes, uses) = granted_consent_for(&self.effective_cfg, &token);
        let granted = GrantedConsent { scopes, uses };
        let transport = HttpWitnessTransport::new(
            settings.url.clone(),
            self.cfg.ingest_url.clone(),
            std::sync::Arc::new(config_allowlist(self.cfg)),
            std::time::Duration::from_secs(120),
        )?
        .with_admission_evidence(true);
        let payload = crate::witness::witness_token_session(
            &transport,
            crate::witness::TokenBundleSession {
                url: &settings.url,
                trust: &trust,
                now_unix: Utc::now().timestamp().max(0) as u64,
                raw,
                attested,
                granted: &granted,
                options: crate::witness::transport::TokenBundleRequest {
                    capture_store_id: source.store_id.clone(),
                    capture_id: source.capture_id.clone(),
                    bundle_revision: Uuid::new_v4().to_string(),
                    restricted_token_consent: true,
                },
            },
        )
        .await?;
        let envelope = parse_witnessed_envelope(&payload.envelope)?;
        ensure_certified_grant(&envelope, &token, Utc::now())?;
        if envelope.submission_id != crate::source::submission_id_for(&transcript.session_hash) {
            anyhow::bail!("witness-review-source-mismatch");
        }
        let redactor = build_redactor_with(
            &self.effective_cfg,
            transcript.cwd.as_deref(),
            self.near_ai.clone(),
        )
        .map_err(|_| anyhow::anyhow!("pii-filter-unavailable"))?;
        if residual_secret_refusal(&redactor, &envelope, &transcript.session_hash)?.is_some() {
            anyhow::bail!("secret-leak-detected");
        }
        let manifest =
            trace_commons_protocol::token_distribution::ContributionBundleManifest::decode(
                &payload.manifest.envelope_bytes,
            )?;
        let response = payload.envelope.clone();
        let record = inference_attestation_for(Some(call), Some(&receipt));
        let journal = BundleJournal::open(&self.store.dir().join("token-bundles"))?;
        let mut kept = 0usize;
        let mut omitted = 0u64;
        let mut alternatives = 0usize;
        let mut omitted_alternatives = 0u64;
        for bytes in payload.attachments.values() {
            let attachment: trace_commons_protocol::token_distribution::SanitizedTokenAttachment =
                serde_json::from_slice(bytes)?;
            kept += attachment.records.len();
            omitted += attachment.omitted_records;
            alternatives += attachment
                .records
                .iter()
                .map(|r| r.alternatives.len())
                .sum::<usize>();
            omitted_alternatives += attachment.omitted_alternatives;
        }
        let review = TokenBundleReview {
            summary_line: Some(crate::witness_copy::token_review_summary(
                kept,
                omitted,
                alternatives,
                omitted_alternatives,
            )),
            journal_id: journal.prepare(manifest.clone(), destination, lease.bundle_lease()?)?,
            manifest_digest: manifest.digest()?,
            attachment_bytes: manifest.attachments.iter().map(|a| a.size_bytes).sum(),
        };
        let mut pin_guard =
            crate::token_bundle::ReviewPinGuard::new(self.store.dir(), Some(&review));
        journal.record_renewal(&lease_binding, Some(u64::try_from(lease.expires_at)?))?;
        if let Err(error) = journal.approve_payload(review.journal_id, payload) {
            let _ = journal.abandon_review(review.journal_id);
            return Err(error);
        }
        lease_guard.adopted()?;
        pin_guard.disarm();
        self.last_receipt_shipped = ReceiptShipped::Attached;
        Ok((response, record, review))
    }

    /// Explicit review only. Ordinary preview/card paths never call this.
    pub(crate) async fn prepare_witnessed_review(
        &mut self,
        transcript: &crate::source::SessionTranscript,
        correction: Option<&str>,
        include_inference_bodies: bool,
    ) -> Result<(WitnessedEnvelope, InferenceAttestationRecord)> {
        let settings = self
            .cfg
            .witness
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("witness-not-configured"))?
            .clone();
        if !settings
            .trust()
            .map_err(|_| anyhow::anyhow!("witness_expected_measurement_malformed"))?
            .is_pinned()
        {
            anyhow::bail!("witness_expected_measurement");
        }
        if settings.admission_evidence && !include_inference_bodies {
            anyhow::bail!("admission_receipt_unavailable");
        }
        // A verdict and a correction have nowhere to go on this profile. The
        // projection in `witness_envelope` discards both, and the witness
        // cannot stamp them afterwards -- that would change bytes its
        // certificate already covers. Refused by name rather than dropped,
        // because the review-binding fields on `WitnessReviewArtifact` are
        // set from these arguments and validate against themselves, so a
        // silent drop leaves an entry that reads approved-with-correction
        // while the certified envelope carries neither.
        if settings.admission_evidence
            && (self.opts.verdict.is_some()
                || correction
                    .map(str::trim)
                    .is_some_and(|text| !text.is_empty()))
        {
            anyhow::bail!("admission_correction_unsupported");
        }
        let now = Utc::now();
        let token = self
            .ensure_claim(now, &transcript.session_hash)
            .await?
            .map_err(|_| anyhow::anyhow!("witness-claim-unavailable"))?;
        validate_review_grant(&self.effective_cfg, &token, now)?;
        let raw = crate::envelope::build_raw_contribution_with_correction(
            transcript,
            &self.effective_cfg,
            now,
            self.opts.verdict,
            correction,
        );
        let attested = if include_inference_bodies {
            transcript.attested_call.as_deref()
        } else {
            None
        };
        let (envelope, response, attested_inference, shipped) = self
            .witness_envelope(&settings, raw, attested, &token, now)
            .await
            .map_err(anyhow::Error::msg)?;
        // `witness_envelope` saw no call because this review withheld the
        // bodies, not because the session has none. Say which.
        let attested_inference = if !include_inference_bodies
            && transcript.attested_call.is_some()
            && !attested_inference.is_certified()
        {
            InferenceAttestationRecord::uncertified(inference_record::REASON_BODIES_WITHHELD)
        } else {
            attested_inference
        };
        self.last_receipt_shipped = shipped;
        ensure_certified_grant(&envelope, &token, Utc::now())?;
        if envelope.submission_id != crate::source::submission_id_for(&transcript.session_hash) {
            anyhow::bail!("witness-review-source-mismatch");
        }
        let redactor = build_redactor_with(
            &self.effective_cfg,
            transcript.cwd.as_deref(),
            self.near_ai.clone(),
        )
        .map_err(|_| anyhow::anyhow!("pii-filter-unavailable"))?;
        if residual_secret_refusal(&redactor, &envelope, &transcript.session_hash)?.is_some() {
            anyhow::bail!("secret-leak-detected");
        }
        Ok((response, attested_inference))
    }

    /// The effective contributor config this pipeline stamps onto
    /// envelopes -- `cfg` with any per-invocation option overrides applied.
    /// The daemon fingerprints this, not the raw config, so the fingerprint
    /// describes what actually determines the envelope.
    pub fn effective_cfg(&self) -> &ContributorConfig {
        &self.effective_cfg
    }

    /// The NEAR AI privacy-filter settings in force, if any.
    pub fn near_ai(&self) -> Option<&NearAiSettings> {
        self.near_ai.as_ref()
    }

    /// Redact and submit one session, loading it from `source` first.
    ///
    /// Independent of every other session: a refusal or failure here never
    /// affects a later call. The single exception is a fail-closed
    /// precondition (`SubmitPreconditionFailure`), which aborts the batch.
    /// Mint a claim if the current one is stale, and return it.
    ///
    /// Extracted so a witnessed submission can mint **before** it sends
    /// anything raw. On that path the order inverts: today the client redacts
    /// first and mints afterwards, then stamps the granted scopes into the
    /// finished envelope, and that stamp is a byte change a certificate does
    /// not cover.
    ///
    /// `Ok(Err(outcome))` is a refusal the caller returns as-is, kept distinct
    /// from `Err(..)` -- a precondition failure that aborts the whole pass --
    /// because the two mean different things and folding them would turn a
    /// contributor-visible refusal into a hard error.
    async fn ensure_claim(
        &mut self,
        now: DateTime<Utc>,
        session_hash: &str,
    ) -> std::result::Result<
        std::result::Result<ClaimToken, SubmitOutcome>,
        SubmitPreconditionFailure,
    > {
        if !self
            .claim
            .as_ref()
            .map(|c| c.is_fresh(now))
            .unwrap_or(false)
        {
            let device = self
                .device
                .as_ref()
                .ok_or(SubmitPreconditionFailure(PRECONDITION_NOT_LOGGED_IN))?;
            match mint_claim(&self.issuer, self.cfg, device, now).await {
                Ok(token) => self.claim = Some(token),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("consent scopes not permitted")
                        || msg.contains("allowed uses not permitted")
                    {
                        println!("hint: re-run login --scopes with a narrower selection");
                        return Ok(Err(refused("scopes-not-permitted", session_hash)));
                    }
                    return Ok(Err(SubmitOutcome::Failed {
                        reason_label: "claim-mint-failed".to_string(),
                    }));
                }
            }
        }
        Ok(Ok(self
            .claim
            .as_ref()
            .expect("a claim must be minted before applying granted scopes")
            .clone()))
    }

    /// Build the envelope through a witness.
    ///
    /// Returns the parsed envelope -- for the size and residual-secret checks
    /// downstream, which read fields -- alongside the response holding the
    /// bytes **as received**. Only those bytes are ever submitted; the parsed
    /// value is for reading.
    ///
    /// `Err(label)` is a refusal label. Never a fall back to local redaction:
    /// the operator would otherwise see an uncertified submission from someone
    /// enrolled as certified, which is the downgrade this design exists to
    /// make noisy.
    /// The provider's receipt for the attested call, or none.
    ///
    /// # Why an unfetchable receipt is not a refusal
    ///
    /// This is the one place on the submission path that calls a **third
    /// party this project does not run**, over a network the contributor does
    /// not control, for an artifact that is not a credential and not a
    /// secret. Every other fail-closed refusal in this client guards against
    /// sending something -- raw bytes to an unverified enclave, an
    /// uncertified envelope from someone enrolled as certified. Failing a
    /// submission here would guard against nothing: the bodies still travel,
    /// the witness still redacts and certifies, and the only difference is
    /// that a contribution the operator would have accepted is silently lost
    /// to somebody else's five-second outage.
    ///
    /// And the fail-closed property this path actually needs is enforced
    /// where it belongs -- on the witness. A deployment that requires attested
    /// inference refuses an absent receipt **by name** -- `403
    /// witness_inference_attestation_missing`, the label
    /// `witness_certificate_cross_implementation` pins -- inside the enclave,
    /// over the bodies it holds. A client-side refusal would be a second,
    /// weaker copy
    /// of a control that already exists on the party that can enforce it, and
    /// a contributor can patch this binary anyway, so a bound only the client
    /// applies is not a bound.
    ///
    /// So: no receipt means an unattested submission, which is an honest
    /// description of what happened, and the witness decides whether that is
    /// acceptable. Nothing here retries, and nothing here is logged -- the
    /// endpoint, the identifier, the model and the receipt are all caller
    /// data -- with one exception: an operator who turned on
    /// `inference_receipt_check_attestation` needs to be able to tell "the
    /// signer never matches" apart from an ordinary outage, since both look
    /// identical as an unattested submission otherwise. That case gets a
    /// fixed-label debug line and nothing else -- never the signer, the
    /// nonce, or the report.
    async fn inference_receipt_for(
        &self,
        call: &crate::routing::attested::AttestedCall,
    ) -> std::result::Result<
        trace_commons_attestation::receipt::ReceiptPayload,
        crate::routing::receipt::ReceiptFetchError,
    > {
        #[cfg(test)]
        if let Some(receipt) = self.receipt_override.clone() {
            return Ok(receipt);
        }
        let result = crate::routing::receipt::receipt_for_attested_call(
            // `effective_cfg`, which is `cfg` with the flag-level overrides
            // applied, so a future `--no-attest` lands in one place.
            self.effective_cfg.inference_receipt_endpoint.as_deref(),
            // The allowlist comes from the stored config, which is where
            // every other outbound call in this file reads it from.
            &config_allowlist(self.cfg),
            call,
            self.effective_cfg.inference_receipt_check_attestation,
        )
        .await;
        // Every failure still yields no receipt and still does not block the
        // submission -- an unattested submission is an honest description of
        // what happened, and the witness decides whether that is acceptable.
        // What changed is that the reason is now sayable. A brokered model
        // (a permanent 404), a provider outage, and a hosted call the
        // provider wrote no record for are three different facts about a
        // trace that used to arrive here as one value.
        //
        // `label()` is a fixed string per variant, so this line's vocabulary
        // is closed and cannot grow with the identifier, the URL, the status
        // or the body. The label for `SignerNotAttested` is the one this line
        // has always emitted.
        if let Err(err) = &result {
            tracing::debug!("inference receipt omitted: {}", err.label());
        }
        result
    }

    /// The witness's answer, and what it was handed to reach it.
    ///
    /// The third element is the only place
    /// [`InferenceAttestationRecord::certified`] is ever built, and it is
    /// built after `witness_session` returned a certificate for a request
    /// that carried a receipt -- the fact, not the intention. A receipt that
    /// could not be fetched leaves `receipt` as `None` below, and the record
    /// says so by name; nothing upstream of here may promote it.
    async fn witness_envelope(
        &self,
        settings: &WitnessSettings,
        raw: RawTraceContribution,
        attested: Option<&crate::routing::attested::AttestedCall>,
        token: &ClaimToken,
        now: DateTime<Utc>,
    ) -> std::result::Result<
        (
            TraceContributionEnvelope,
            WitnessedEnvelope,
            InferenceAttestationRecord,
            ReceiptShipped,
        ),
        &'static str,
    > {
        // A malformed pin and an absent one are different operator mistakes,
        // and a contributor who mistyped a measurement should not be told they
        // configured none.
        let trust = settings
            .trust()
            .map_err(|_| "witness_expected_measurement_malformed")?;

        let admission_profile = admission_profile_for_request(
            settings.admission_evidence,
            attested.map(|call| call.request_body()),
        )?;
        let transport = HttpWitnessTransport::new(
            settings.url.clone(),
            self.cfg.ingest_url.clone(),
            std::sync::Arc::new(config_allowlist(self.cfg)),
            std::time::Duration::from_secs(120),
        )
        .map_err(|e| e.refusal_label())?
        .with_admission_evidence(admission_profile);

        // The source-selected profile is already frozen. Optional legacy
        // receipt failures retain ordinary review; a bound admission call
        // must have its receipt and cannot switch to the window on failure.
        let (receipt, shipped) = match attested {
            Some(call) => match self.inference_receipt_for(call).await {
                Ok(receipt) => (Some(receipt), ReceiptShipped::Attached),
                Err(err) => (None, ReceiptShipped::Omitted(err)),
            },
            None => (None, ReceiptShipped::NoCall),
        };
        if admission_profile && receipt.is_none() {
            return Err("admission_receipt_unavailable");
        }
        let attested_inference = inference_attestation_for(attested, receipt.as_ref());
        let attested = attested.map(|call| crate::witness::transport::AttestedInference {
            call,
            receipt: receipt.as_ref(),
        });

        // The admission receipt covers one call, never unsigned companion
        // history or execution claims. Keep the ordinary invited profile intact.
        let raw = witness_input_for_profile(raw, &self.effective_cfg, admission_profile);
        let (scopes, uses) = granted_consent_for(&self.effective_cfg, token);
        let response = witness_session(
            &transport,
            &settings.url,
            &trust,
            now.timestamp().max(0) as u64,
            raw,
            attested,
            &GrantedConsent { scopes, uses },
        )
        .await
        .map_err(|e| e.refusal_label())?;

        let parsed = parse_witnessed_envelope(&response).map_err(|e| e.refusal_label())?;
        Ok((parsed, response, attested_inference, shipped))
    }

    /// What the most recent `submit_loaded` receipt fetch produced.
    ///
    /// Meaningful immediately after a submission returns `Submitted`: the
    /// daemon reads it to correct the attestation mark on a shipped row whose
    /// receipt did not arrive. `NoCall` on any path that carried no attested
    /// call or did not run the witness.
    #[must_use]
    pub fn last_receipt_shipped(&self) -> ReceiptShipped {
        self.last_receipt_shipped
    }

    pub async fn submit_one(
        &mut self,
        source: &dyn TraceSource,
        session_ref: &SessionRef,
    ) -> Result<SubmitOutcome> {
        let transcript = match source.load(session_ref) {
            Ok(t) => t,
            Err(_) => {
                return Ok(SubmitOutcome::SkippedParseFailure {
                    reason_label: "parse-failed".to_string(),
                });
            }
        };
        self.submit_loaded(transcript).await
    }

    /// Redact and submit a transcript the caller has already loaded.
    ///
    /// This is what closes the window between the daemon's re-hash guard
    /// and the bytes that actually go out. The uploader loads and hashes the
    /// session to check that its content still matches what the contributor
    /// approved; `submit_one` then loaded the file a second, independent
    /// time, and it was *that* read -- never hashed, never compared -- whose
    /// bytes were sent. A session appended to in between passed the guard
    /// and shipped content the guard had never seen, which is precisely the
    /// consent property the guard exists to enforce. The uploader calls this
    /// with the transcript it verified, so the verified bytes are the sent
    /// bytes.
    pub async fn submit_loaded(
        &mut self,
        mut transcript: crate::source::SessionTranscript,
    ) -> Result<SubmitOutcome> {
        // Reset before this submission, so a prior entry's fetch cannot be
        // read as this one's. Left at `NoCall` unless `witness_envelope` runs
        // and a call was carried.
        self.last_receipt_shipped = ReceiptShipped::NoCall;
        let opts = self.opts;
        // Taken up front, not at the point it is used below: several paths
        // return before that point (already-submitted, an unavailable
        // filter, an over-size refusal), and an approved envelope left
        // behind would apply to whatever session came next.
        let approved_envelope = self.approved_envelope.take();
        let approved_witness = self.approved_witness.take();

        if opts.no_reasoning {
            crate::commands::strip_reasoning(&mut transcript);
        }

        // Take the most recent matching receipt, so a session that was
        // delivered and later accepted reports "accepted" rather than the
        // first status it ever had.
        let prior = self
            .receipts
            .iter()
            .filter(|r| {
                r.session_hash == transcript.session_hash
                    && ALREADY_SUBMITTED_STATUSES.contains(&r.status.as_str())
            })
            .max_by_key(|r| r.submitted_at);
        if let Some(prior) = prior
            && self.approved_token_bundle.is_none()
        {
            let remediating_quarantined =
                opts.remediate_quarantined && prior.status == "quarantined";
            if !remediating_quarantined {
                return Ok(SubmitOutcome::AlreadySubmitted {
                    submission_id: prior.submission_id,
                    prior_status: prior.status.clone(),
                });
            }
        }

        let redactor = if opts.unenrolled_preview {
            build_deterministic_preview_redactor(transcript.cwd.as_deref())
        } else {
            match build_redactor_with(
                &self.effective_cfg,
                transcript.cwd.as_deref(),
                self.near_ai.clone(),
            ) {
                Ok(r) => r,
                Err(_) => {
                    return Ok(refused("pii-filter-unavailable", &transcript.session_hash));
                }
            }
        };

        if !self.canary_checked {
            canary_self_test_async(&redactor)
                .await
                .map_err(|_| SubmitPreconditionFailure(PRECONDITION_CANARY_FAILED))?;
            self.canary_checked = true;
            self.canary_runs += 1;
        }

        let now = Utc::now();
        // The approved envelope, when there is one, is used *as it is*. No
        // second redaction pass runs and nothing is compared: the bytes the
        // contributor was shown are the bytes that go out. Everything
        // downstream of here is unchanged and still applies to them -- the
        // size ceiling, the residual-secret sweep, the granted scopes the
        // issuer echoes back.
        //
        // The redactor above is still built and still canary-tested on this
        // path. It is what the residual-secret sweep runs with, and a
        // privacy filter that has gone bad must stop an upload whether or
        // not this particular envelope was built through it.
        // Resolved before the envelope is built. A configured witness that
        // cannot be used refuses the submission; it never falls back to local
        // redaction, because the envelope would then carry a self-reported
        // risk while the contributor believed it carried a certificate.
        let witness_settings = self.cfg.witness.clone();
        let mut witnessed: Option<WitnessedEnvelope> = None;

        let mut envelope = match approved_envelope {
            Some(approved) => {
                // Only the explicit witnessed-review path persists a certificate.
                // A local preview saved before witness configuration must still
                // refuse rather than upload an uncertified artifact.
                if let Some(response) = approved_witness {
                    let Some(settings) = witness_settings.as_ref() else {
                        return Ok(refused("witness-review-stale", &transcript.session_hash));
                    };
                    if settings
                        .trust()
                        .map(|trust| !trust.is_pinned())
                        .unwrap_or(true)
                        || crate::witness::transport::verify_certificate(
                            &response,
                            &settings.signing_address,
                        )
                        .is_err()
                        || approved.submission_id
                            != crate::source::submission_id_for(&transcript.session_hash)
                    {
                        return Ok(refused("witness-review-stale", &transcript.session_hash));
                    }
                    witnessed = Some(response);
                } else if witness_settings.is_some() {
                    record_last_result(WitnessLastResult::Refused {
                        label: "witness_certificate_missing".to_string(),
                        certificate_obtained: false,
                    });
                    return Ok(refused(
                        "witness_certificate_missing",
                        &transcript.session_hash,
                    ));
                }
                approved
            }
            None => {
                let raw = if opts.unenrolled_preview {
                    build_preview_raw_contribution(&transcript, &self.effective_cfg, now)
                } else {
                    build_raw_contribution_with_verdict(
                        &transcript,
                        &self.effective_cfg,
                        now,
                        opts.verdict,
                    )
                };
                // Skip sessions that already exceed the envelope limit before
                // the expensive redaction/privacy-filter pass; they would be
                // refused for size after redaction anyway (envelope_size_ok
                // below is the authoritative check).
                if raw_contribution_size_ok(&raw).is_err() {
                    let size = raw_contribution_size(&raw).unwrap_or(MAX_ENVELOPE_BYTES + 1);
                    return Ok(refused_for_size(&transcript.session_hash, size));
                }
                match witness_settings {
                    // Absent means the witness path is not entered at all, and
                    // this is byte for byte what it was before the feature
                    // existed.
                    None => {
                        match checked_local_redaction(&redactor, raw, self.canary_checked).await {
                            Ok(e) => {
                                // Recorded, rather than left at whatever the
                                // previous submission set: a shell asking "what
                                // happened last time" must be told that the last
                                // submission redacted locally, not handed a stale
                                // certificate from before the witness was cleared.
                                record_last_result(WitnessLastResult::LocalRedaction);
                                e
                            }
                            Err(label) => {
                                return Ok(refused(label, &transcript.session_hash));
                            }
                        }
                    }
                    Some(settings) => {
                        // The pin is judged BEFORE the mint, which is before
                        // anything reaches the network. An unpinned client
                        // cannot judge any quote it receives, so minting a
                        // claim for a submission that was always going to be
                        // refused would spend a round trip to learn nothing.
                        match settings.trust() {
                            Ok(trust) if trust.is_pinned() => {}
                            Ok(_) => {
                                record_last_result(WitnessLastResult::Refused {
                                    label: WITNESS_EXPECTED_MEASUREMENT_CONTROL.to_string(),
                                    certificate_obtained: false,
                                });
                                return Ok(refused(
                                    WITNESS_EXPECTED_MEASUREMENT_CONTROL,
                                    &transcript.session_hash,
                                ));
                            }
                            Err(_) => {
                                record_last_result(WitnessLastResult::Refused {
                                    label: "witness_expected_measurement_malformed".to_string(),
                                    certificate_obtained: false,
                                });
                                return Ok(refused(
                                    "witness_expected_measurement_malformed",
                                    &transcript.session_hash,
                                ));
                            }
                        }
                        // The claim is minted BEFORE anything raw is sent. The
                        // grants have to be inside the certified bytes, and a
                        // stamp afterwards is a byte change the certificate
                        // does not cover.
                        let token = match self.ensure_claim(now, &transcript.session_hash).await? {
                            Ok(token) => token,
                            Err(outcome) => return Ok(outcome),
                        };
                        match self
                            .witness_envelope(
                                &settings,
                                raw,
                                transcript.attested_call.as_deref(),
                                &token,
                                now,
                            )
                            .await
                        {
                            // The record is dropped on this path: the CLI keeps
                            // no per-entry store to write it to. The daemon's
                            // review path is where it is kept.
                            Ok((parsed, response, _attested_inference, shipped)) => {
                                // `parse_witnessed_envelope` inside
                                // `witness_envelope` is what verified this
                                // certificate against the bytes that came
                                // back, so reaching here IS "obtained and
                                // verified" -- there is no other way in.
                                record_last_result(WitnessLastResult::Certified {
                                    n_of_m: n_of_m_from_certificate(&response.certificate_json),
                                });
                                self.last_receipt_shipped = shipped;
                                witnessed = Some(response);
                                parsed
                            }
                            Err(label) => {
                                record_last_result(WitnessLastResult::Refused {
                                    label: label.to_string(),
                                    certificate_obtained: certificate_obtained_for(label),
                                });
                                return Ok(refused(label, &transcript.session_hash));
                            }
                        }
                    }
                }
            }
        };

        if !self.near_ai_notice_recorded
            && self.effective_cfg.pii_filter.as_deref() == Some("near-ai")
        {
            self.store
                .ensure_near_ai_notice_shown()
                .map_err(|_| SubmitPreconditionFailure(PRECONDITION_NEAR_AI_NOTICE_UNRECORDED))?;
            self.near_ai_notice_recorded = true;
        }

        let size = match envelope_size_ok(&envelope) {
            Ok(s) => s,
            Err(_) => {
                let size = envelope_size(&envelope).unwrap_or(MAX_ENVELOPE_BYTES + 1);
                return Ok(refused_for_size(&transcript.session_hash, size));
            }
        };

        if opts.dry_run {
            if let Some(outcome) =
                residual_secret_refusal(&redactor, &envelope, &transcript.session_hash)?
            {
                return Ok(outcome);
            }
            if !opts.machine_readable {
                if opts.unenrolled_preview {
                    println!(
                        "unenrolled-preview dry-run: preview_id={} bytes={size} \
                         deterministic-only",
                        envelope.submission_id
                    );
                } else {
                    // Unchanged first line: anything parsing it keeps working.
                    println!(
                        "dry-run: submission_id={} bytes={size}",
                        envelope.submission_id
                    );
                    let risk = envelope.privacy.residual_pii_risk;
                    println!("dry-run: risk={risk:?}");
                    println!(
                        "dry-run: why={}",
                        residual_risk_explanation(
                            &envelope.consent,
                            &envelope.privacy.redaction_counts,
                            &envelope.privacy.pii_labels_present,
                        )
                    );
                    println!("dry-run: storage={}", residual_risk_storage_note(risk));
                    println!(
                        "dry-run: the server re-scrubs and can RAISE this risk but never \
                         silently lower it; this client-side risk is a floor, not a promise."
                    );
                }
            }
            return Ok(SubmitOutcome::Submitted {
                submission_id: envelope.submission_id,
                status: "dry-run".to_string(),
            });
        }

        let token = match self.ensure_claim(now, &transcript.session_hash).await? {
            Ok(token) => token,
            Err(outcome) => return Ok(outcome),
        };
        // A witnessed envelope is NOT stamped. The grants are already inside
        // the bytes the certificate covers -- the witness applied them before
        // it serialised -- so writing them again here would change those bytes
        // and break the digest.
        if witnessed.is_none() {
            stamp_granted_scopes(&mut envelope, &self.effective_cfg, &token);
        } else if ensure_certified_grant(&envelope, &token, Utc::now()).is_err() {
            return Ok(refused("witness-grant-changed", &transcript.session_hash));
        }

        if let Some(outcome) =
            residual_secret_refusal(&redactor, &envelope, &transcript.session_hash)?
        {
            return Ok(outcome);
        }

        if envelope_size_ok(&envelope).is_err() {
            let size = envelope_size(&envelope).unwrap_or(MAX_ENVELOPE_BYTES + 1);
            return Ok(refused_for_size(&transcript.session_hash, size));
        }

        if let Some(bundle) = self.approved_token_bundle.take() {
            let journal =
                crate::token_bundle::BundleJournal::open(&self.store.dir().join("token-bundles"))?;
            let response = witnessed
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("bundle-review-stale"))?;
            journal.validate_review(&bundle, &response.envelope_bytes)?;
            let client = build_ingest_client(self.cfg, &token)?;
            match journal.upload_approved(bundle.journal_id, &client).await {
                Ok(_) => {
                    let receipt = Receipt {
                        submission_id: envelope.submission_id,
                        session_hash: transcript.session_hash.clone(),
                        source: transcript.source.into(),
                        submitted_at: Utc::now(),
                        status: "submitted".into(),
                    };
                    self.store.append_receipt(&receipt)?;
                    self.receipts.push(receipt);
                    return Ok(SubmitOutcome::Submitted {
                        submission_id: envelope.submission_id,
                        status: "submitted".into(),
                    });
                }
                Err(_) => {
                    return Ok(SubmitOutcome::Failed {
                        reason_label: "token-bundle-upload-pending".into(),
                    });
                }
            }
        }
        let device = self
            .device
            .as_ref()
            .ok_or(SubmitPreconditionFailure(PRECONDITION_NOT_LOGGED_IN))?;
        match upload_with_retry(
            self.cfg,
            &self.issuer,
            device,
            &mut self.claim,
            &mut envelope,
            &self.effective_cfg,
            witnessed.as_ref(),
        )
        .await
        {
            Ok(receipt) => {
                let r = Receipt {
                    submission_id: envelope.submission_id,
                    session_hash: transcript.session_hash.clone(),
                    source: transcript.source.to_string(),
                    submitted_at: Utc::now(),
                    status: receipt.status.clone(),
                };
                match self.store.append_receipt(&r) {
                    Ok(()) => {
                        self.receipts.push(r);
                        Ok(SubmitOutcome::Submitted {
                            submission_id: envelope.submission_id,
                            status: receipt.status,
                        })
                    }
                    Err(_) => Ok(SubmitOutcome::Failed {
                        reason_label: "receipt-write-failed".to_string(),
                    }),
                }
            }
            Err(reason_label) if reason_label == "session-too-large" => {
                let size = envelope_size(&envelope).unwrap_or(MAX_ENVELOPE_BYTES + 1);
                Ok(refused_for_size(&transcript.session_hash, size))
            }
            Err(reason_label) => Ok(SubmitOutcome::Failed { reason_label }),
        }
    }
}

/// Read back submission status for every locally recorded receipt. Returns
/// an empty vec (no network calls) when there are no receipts yet.
pub async fn status(
    store: &ConfigStore,
    cfg: &ContributorConfig,
) -> Result<Vec<TraceSubmissionStatusUpdate>> {
    let receipts = store.load_receipts().context("loading receipts")?;
    if receipts.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<Uuid> = receipts.iter().map(|r| r.submission_id).collect();

    let device = DeviceIdentity::load_or_generate_async(store)
        .await
        .context("loading device identity")?;
    let issuer = IssuerClient::new(config_allowlist(cfg)).context("building issuer client")?;
    // Mint with an empty scopes/uses request rather than the submit path's
    // consent_scopes: the issuer resolves an empty request to the caller's
    // full grant ceiling, so status read-back works regardless of what
    // scopes were narrowed for submission since the last login.
    let token = mint_status_claim(&issuer, cfg, &device, Utc::now())
        .await
        .context("minting upload claim for status lookup")?;
    let client = build_ingest_client(cfg, &token).context("building ingest client")?;

    let mut updates = Vec::new();
    for chunk in ids.chunks(500) {
        let req = TraceSubmissionStatusRequest {
            submission_ids: chunk.to_vec(),
        };
        let mut chunk_updates: Vec<TraceSubmissionStatusUpdate> = client
            .call_json(
                Method::POST,
                "/v1/contributors/me/submission-status",
                &[],
                Some(&req),
            )
            .await
            .context("fetching submission status")?;
        updates.append(&mut chunk_updates);
    }
    Ok(updates)
}

#[derive(Debug, Clone, Serialize)]
struct CommunityProfilePutRequest<'a> {
    display_handle: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bio: Option<&'a str>,
}

/// The public profile as the server stores it.
#[derive(Debug, Clone, Deserialize)]
pub struct CommunityProfile {
    pub display_handle: String,
    pub bio: Option<String>,
    pub public_since: DateTime<Utc>,
}

/// Claim or update this contributor's public handle.
///
/// `login` can grant `public_attribution`, but until this existed nothing in
/// this CLI could use it: claiming a handle meant the operator-facing
/// `/profile` page and a workload token from the *other* enrollment path.
/// Since the server derives the principal from the authenticated request
/// rather than from anything in the body, a handle claimed through a
/// different credential lands on a different principal and never appears
/// beside this device's traces.
pub async fn set_profile(
    store: &ConfigStore,
    cfg: &ContributorConfig,
    display_handle: &str,
    bio: Option<&str>,
) -> Result<CommunityProfile> {
    let device = DeviceIdentity::load_or_generate_async(store)
        .await
        .context("loading device identity")?;
    let issuer = IssuerClient::new(config_allowlist(cfg)).context("building issuer client")?;
    // Same empty-scope mint as `status`: the issuer resolves it to this
    // caller's full grant ceiling, so claiming a handle does not depend on
    // whichever scopes were narrowed for the last submission.
    let token = mint_status_claim(&issuer, cfg, &device, Utc::now())
        .await
        .context("minting upload claim for profile update")?;
    let client = build_ingest_client(cfg, &token).context("building ingest client")?;
    let req = CommunityProfilePutRequest {
        display_handle,
        bio,
    };
    client
        .call_json(Method::PUT, "/v1/community/profile", &[], Some(&req))
        .await
        .context("setting public profile")
}

/// Response of `POST /v1/account/login-links`. `url` is a ROOT-RELATIVE path
/// carrying a single-use code; it is a secret for the few minutes it lives.
/// `account_id` is returned by the server but not used here.
#[derive(Debug, Clone, Deserialize)]
struct MintLoginLinkResponse {
    url: String,
}

/// Mint a single-use account login link for this device's principal.
///
/// Used by `crate::account_auth::sign_in` to open the human's browser at the
/// EXISTING redeem flow. This is the same device-authenticated endpoint the
/// account slice has always exposed, called with the same empty-scope claim as
/// `status`: minting a login link is an authority the device key already has,
/// and the loopback flow adds none.
///
/// Returns the root-relative path only. The caller joins it onto the
/// configured ingest base URL; it is never logged.
pub async fn mint_account_login_link(
    store: &ConfigStore,
    cfg: &ContributorConfig,
) -> Result<String> {
    let device = DeviceIdentity::load_or_generate_async(store)
        .await
        .context("loading device identity")?;
    let issuer = IssuerClient::new(config_allowlist(cfg)).context("building issuer client")?;
    let token = mint_status_claim(&issuer, cfg, &device, Utc::now())
        .await
        .context("minting upload claim for account sign-in")?;
    let client = build_ingest_client(cfg, &token).context("building ingest client")?;
    let minted: MintLoginLinkResponse = client
        .call_json(Method::POST, "/v1/account/login-links", &[], None::<&()>)
        .await
        .context("minting an account login link")?;
    Ok(minted.url)
}

/// Withdraw this contributor's public attribution.
///
/// The row goes at the next snapshot. This is the action `/about/privacy`
/// promises, so it belongs in the tool the contributor already has rather
/// than only in a page they may never have been given access to.
pub async fn clear_profile(store: &ConfigStore, cfg: &ContributorConfig) -> Result<()> {
    let device = DeviceIdentity::load_or_generate_async(store)
        .await
        .context("loading device identity")?;
    let issuer = IssuerClient::new(config_allowlist(cfg)).context("building issuer client")?;
    let token = mint_status_claim(&issuer, cfg, &device, Utc::now())
        .await
        .context("minting upload claim for profile withdrawal")?;
    let client = build_ingest_client(cfg, &token).context("building ingest client")?;
    client
        .call_raw::<()>(Method::DELETE, "/v1/community/profile", &[], None)
        .await
        .context("withdrawing public profile")?;
    Ok(())
}

/// Record the profile the server just accepted in the local cache, and
/// persist it. Returns whether the write stuck.
///
/// There is no `GET /v1/community/profile`: the server derives the principal
/// from the authenticated request and offers no read-back, so this cache is
/// the only way anything on this machine can tell that a handle was ever
/// claimed. Both shells depend on it -- the daemon's `get_public_profile`
/// answers from it, and `daemon::refresh_community` polls the roster only
/// when it names a handle -- so a caller of `set_profile` that does not write
/// it leaves the contributor on the roster with no local sign of it, and
/// their community section never appears.
///
/// The write is here rather than in either shell so the CLI and the socket
/// cache identically. The reason this is a plain function taking `&mut
/// ContributorConfig` rather than part of `set_profile` is that the caller
/// already holds the config it loaded, and reloading it inside the network
/// call would race that copy.
///
/// A failed write is reported, not raised: the handle is published either
/// way -- the server already accepted it -- so a caller must not tell the
/// contributor their profile did not go up. The weaker true statement is
/// that the profile will not read back until the next successful call.
pub fn cache_public_profile(
    store: &ConfigStore,
    cfg: &mut ContributorConfig,
    profile: &CommunityProfile,
) -> bool {
    cfg.display_handle = Some(profile.display_handle.clone());
    cfg.public_bio = profile.bio.clone();
    cfg.public_since = Some(profile.public_since);
    store.save_config(cfg).is_ok()
}

/// Drop the cached public profile after a successful withdrawal, and
/// persist. Returns whether the write stuck.
///
/// The reverse of [`cache_public_profile`]'s reasoning: the row is gone from
/// the server regardless, and a cache that still names a withdrawn handle is
/// worse than one that is merely stale -- it keeps `refresh_community`
/// polling for a row that no longer exists and keeps a settings panel
/// claiming public attribution the contributor has withdrawn.
pub fn clear_cached_public_profile(store: &ConfigStore, cfg: &mut ContributorConfig) -> bool {
    cfg.display_handle = None;
    cfg.public_bio = None;
    cfg.public_since = None;
    store.save_config(cfg).is_ok()
}

/// Fetch a server-signed attestation of this contributor's own scores.
///
/// The returned value is a compact JWS the contributor hands to a collector
/// (a hackathon scorer, say). The collector verifies it against the ingest
/// attestation keyset rather than trusting a relayed list of submission ids,
/// which is forgeable by anyone who learns an id.
///
/// The endpoint takes no parameters: the principal comes from this call's
/// authentication, so there is nothing here that could request someone
/// else's scores.
pub async fn fetch_score_attestation(
    store: &ConfigStore,
    cfg: &ContributorConfig,
) -> Result<String> {
    let device = DeviceIdentity::load_or_generate_async(store)
        .await
        .context("loading device identity")?;
    let issuer = IssuerClient::new(config_allowlist(cfg)).context("building issuer client")?;
    // Same empty-scope mint as `status`: the attestation is a read of scores
    // the server already holds, so it must not depend on whatever scopes were
    // narrowed for submission since the last login.
    let token = mint_status_claim(&issuer, cfg, &device, Utc::now())
        .await
        .context("minting upload claim for score attestation")?;
    let client = build_ingest_client(cfg, &token).context("building ingest client")?;

    #[derive(serde::Deserialize)]
    struct AttestationBody {
        attestation: String,
    }

    let body: AttestationBody = client
        .call_json(
            Method::GET,
            "/v1/contributors/me/score-attestation",
            &[],
            None::<&()>,
        )
        .await
        .context("fetching score attestation")?;
    Ok(body.attestation)
}

/// Ids per scoped attestation request, matching the server's per-request cap
/// on `POST /v1/contributors/me/score-attestation`. A run that submitted
/// more traces than this is split across several requests -- and so across
/// several signed documents -- rather than truncated, because a document
/// that silently omits ids the contributor asked about is exactly the defect
/// the scoped form exists to remove.
pub const SCORE_ATTESTATION_REQUEST_CHUNK: usize = 500;

#[derive(Debug, Clone, Serialize)]
struct ScopedScoreAttestationRequest {
    submission_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
struct ScopedAttestationBody {
    attestation: String,
    scored: usize,
    pending: usize,
}

/// A scoped attestation over one submit run's ids.
///
/// `scored + pending` need not equal `requested`: an id the server does not
/// recognise as this principal's lands in the signed document's `unknown`
/// list and in neither count.
#[derive(Debug, Clone)]
pub struct ScopedAttestation {
    /// One compact JWS per request chunk, in request order. Usually one.
    pub attestations: Vec<String>,
    pub requested: usize,
    pub scored: usize,
    pub pending: usize,
}

impl ScopedAttestation {
    /// The line `submit` prints when the bounded wait ran out with traces
    /// still unscored. Counts only -- no ids, no paths.
    pub fn progress_line(&self) -> String {
        format!(
            "{} of {} traces scored, {} pending",
            self.scored, self.requested, self.pending
        )
    }

    /// The file body: one JWS per line. A single-chunk run -- every ordinary
    /// one -- is therefore just the JWS and a newline.
    pub fn document(&self) -> String {
        let mut body = self.attestations.join("\n");
        body.push('\n');
        body
    }
}

/// One round of scoped attestation requests over `submission_ids`, chunked
/// to the server's per-request cap.
async fn scoped_attestation_round(
    client: &Client,
    submission_ids: &[Uuid],
) -> Result<ScopedAttestation> {
    let mut collected = ScopedAttestation {
        attestations: Vec::new(),
        requested: submission_ids.len(),
        scored: 0,
        pending: 0,
    };
    for chunk in submission_ids.chunks(SCORE_ATTESTATION_REQUEST_CHUNK) {
        let request = ScopedScoreAttestationRequest {
            submission_ids: chunk.to_vec(),
        };
        let body: ScopedAttestationBody = client
            .call_json(
                Method::POST,
                "/v1/contributors/me/score-attestation",
                &[],
                Some(&request),
            )
            .await
            .context("fetching scoped score attestation")?;
        collected.attestations.push(body.attestation);
        collected.scored += body.scored;
        collected.pending += body.pending;
    }
    Ok(collected)
}

/// Ask for an attestation scoped to `submission_ids` and keep asking until
/// nothing is pending or `timeout` elapses, whichever comes first.
///
/// The wait has to be bounded and the bound has to be honest. Scoring is
/// asynchronous -- a 45-second tick over a small batch, and off entirely
/// unless the operator enabled the driver -- so "wait until scored" is not a
/// promise this side can keep. What it returns on timeout is a real signed
/// document that says which traces are still waiting, which a collector can
/// resolve later through the admin score read-back.
///
/// One upload claim is minted for the whole wait and reused across polls,
/// rather than re-minting per poll.
pub async fn await_scoped_score_attestation(
    store: &ConfigStore,
    cfg: &ContributorConfig,
    submission_ids: &[Uuid],
    timeout: StdDuration,
    poll_interval: StdDuration,
) -> Result<ScopedAttestation> {
    let device = DeviceIdentity::load_or_generate_async(store)
        .await
        .context("loading device identity")?;
    let issuer = IssuerClient::new(config_allowlist(cfg)).context("building issuer client")?;
    // Same empty-scope mint as `status` and the unscoped attestation: a read
    // of scores the server already holds must not depend on whatever scopes
    // were narrowed for submission since the last login.
    let token = mint_status_claim(&issuer, cfg, &device, Utc::now())
        .await
        .context("minting upload claim for score attestation")?;
    let client = build_ingest_client(cfg, &token).context("building ingest client")?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let attestation = scoped_attestation_round(&client, submission_ids).await?;
        if attestation.pending == 0 {
            return Ok(attestation);
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Ok(attestation);
        }
        tokio::time::sleep(poll_interval.min(deadline - now)).await;
    }
}

/// Fetch a scoped attestation for `submission_ids` and write it to `path`.
///
/// Returns `None` -- after a label-only warning -- when there was nothing to
/// attest to or the fetch failed. A submit run whose traces were accepted
/// and whose receipts were written has succeeded; failing it because a
/// follow-up read did not come back would throw away work the contributor
/// already did. The attestation is written on timeout too, because with the
/// scoped schema it is truthful about the part it does not cover.
/// The submission ids this run actually delivered, for a scoped attestation.
///
/// `Submitted` and `AlreadySubmitted` both count: a re-run that finds a trace
/// already on the server has still contributed it, and omitting it would make
/// the attestation shrink every time a contributor re-ran the command. Every
/// other outcome -- refused, quarantined, parse failure -- is something the
/// server cannot attest to and must not be asked about, or it comes back in
/// `unknown` and reads as a disclaimer.
pub fn submitted_ids(outcomes: &[SubmitOutcome]) -> Vec<Uuid> {
    outcomes
        .iter()
        .filter_map(|o| match o {
            SubmitOutcome::Submitted { submission_id, .. }
            | SubmitOutcome::AlreadySubmitted { submission_id, .. } => Some(*submission_id),
            _ => None,
        })
        .collect()
}

/// Add the attestation to a `--json` submit document.
///
/// `scored` and `pending` ride alongside it because a collector reading this
/// programmatically needs to know the document is partial without parsing the
/// JWS to find out.
pub fn attach_attestation_to_json(document: &mut serde_json::Value, attested: &ScopedAttestation) {
    if let Some(map) = document.as_object_mut() {
        map.insert(
            "attestation".to_string(),
            serde_json::json!(attested.attestations),
        );
        map.insert("scored".to_string(), serde_json::json!(attested.scored));
        map.insert("pending".to_string(), serde_json::json!(attested.pending));
    }
}

pub async fn emit_scoped_attestation(
    store: &ConfigStore,
    cfg: &ContributorConfig,
    submission_ids: &[Uuid],
    path: &Path,
    timeout: StdDuration,
    poll_interval: StdDuration,
) -> Option<ScopedAttestation> {
    if submission_ids.is_empty() {
        return None;
    }
    let attestation =
        match await_scoped_score_attestation(store, cfg, submission_ids, timeout, poll_interval)
            .await
        {
            Ok(attestation) => attestation,
            Err(_) => {
                // Label-only: the error can carry a URL or a token-bearing
                // request context, and this line reaches a terminal and any
                // log scraping it.
                tracing::warn!("score attestation unavailable: attestation-fetch-failed");
                return None;
            }
        };
    if std::fs::write(path, attestation.document()).is_err() {
        tracing::warn!("score attestation not written: attestation-write-failed");
    }
    Some(attestation)
}

/// Shared local preview/submit redaction, including post-redaction checks.
/// A submit batch may have already checked this same redactor; standalone
/// previews always pass false. No state, credentials, or network are opened.
pub(crate) async fn checked_local_redaction(
    redactor: &trace_commons_protocol::trace_contribution::DeterministicTraceRedactor,
    raw: RawTraceContribution,
    canary_checked: bool,
) -> std::result::Result<TraceContributionEnvelope, &'static str> {
    if !canary_checked {
        canary_self_test_async(redactor)
            .await
            .map_err(|_| PRECONDITION_CANARY_FAILED)?;
    }
    // A credential the contributor typed is the one pipeline refusal they can
    // act on, so it keeps its own label and the shells can say "rotate it".
    // Everything else is a condition of the machine and stays generic.
    //
    // Flattening this to "redaction-failed" is what the rescued admission work
    // was compensating for at its own call site; fixing it here means every
    // caller of this function gets the distinction rather than one of them.
    let envelope = redact_to_envelope(redactor, raw).await.map_err(|error| {
        // Named refusals survive; everything else is a condition of the
        // machine and stays generic. A credential the contributor typed and a
        // filter backend that collapsed two metadata keys are both things a
        // shell can say something useful about, and flattening them to
        // "redaction-failed" sends the reader looking at their own trace for
        // a fault that is not there.
        match error.to_string().as_str() {
            crate::envelope::REASON_METADATA_CREDENTIAL => {
                crate::envelope::REASON_METADATA_CREDENTIAL
            }
            crate::envelope::REASON_METADATA_KEY_COLLISION => {
                crate::envelope::REASON_METADATA_KEY_COLLISION
            }
            _ => "redaction-failed",
        }
    })?;
    validate_local_envelope(redactor, &envelope)?;
    Ok(envelope)
}

pub(crate) fn validate_local_envelope(
    redactor: &trace_commons_protocol::trace_contribution::DeterministicTraceRedactor,
    envelope: &TraceContributionEnvelope,
) -> std::result::Result<(), &'static str> {
    envelope_size_ok(envelope).map_err(|_| "session-too-large")?;
    if envelope_has_residual_secret(redactor, envelope).map_err(|_| "secret-scan-failed")? {
        return Err("secret-leak-detected");
    }
    Ok(())
}

/// Re-scan a finished envelope for a residual secret shape. Returns
/// `Ok(Some(Refused))` (emitting the same `refusing session` warn every
/// caller relies on) when the redactor's re-scan still finds a secret shape
/// in the serialized envelope, else `Ok(None)`. This is the single seam both
/// the dry-run and real submit paths route through, so deleting either call
/// site removes the fail-closed guard entirely -- callers must `continue` on
/// `Some(_)`.
fn residual_secret_refusal(
    redactor: &trace_commons_protocol::trace_contribution::DeterministicTraceRedactor,
    envelope: &TraceContributionEnvelope,
    session_ref: &str,
) -> Result<Option<SubmitOutcome>> {
    if envelope_has_residual_secret(redactor, envelope)? {
        tracing::warn!("refusing session: secret survived redaction");
        return Ok(Some(refused("secret-leak-detected", session_ref)));
    }
    Ok(None)
}

/// `cfg` with `opts.pii_filter` overriding `cfg.pii_filter` when set.
fn effective_config(cfg: &ContributorConfig, opts: &SubmitOptions) -> ContributorConfig {
    let mut c = cfg.clone();
    if opts.unenrolled_preview {
        c.pii_filter = None;
    } else if opts.pii_filter.is_some() {
        c.pii_filter = opts.pii_filter.clone();
    }
    c
}

async fn mint_claim(
    issuer: &IssuerClient,
    cfg: &ContributorConfig,
    device: &DeviceIdentity,
    now: DateTime<Utc>,
) -> Result<ClaimToken> {
    let signed =
        build_signed_claim_request(cfg, device, now).context("building signed claim request")?;
    issuer.mint_claim(&cfg.issuer_url, &signed).await
}

/// Mint a claim for a status read-back: an empty consent_scopes/allowed_uses
/// request, which the issuer resolves to the caller's full grant ceiling
/// regardless of what was requested for submission.
async fn mint_status_claim(
    issuer: &IssuerClient,
    cfg: &ContributorConfig,
    device: &DeviceIdentity,
    now: DateTime<Utc>,
) -> Result<ClaimToken> {
    let signed = build_signed_claim_request_with_scopes(cfg, device, now, &[], &[])
        .context("building signed status claim request")?;
    issuer.mint_claim(&cfg.issuer_url, &signed).await
}

/// Stamp `envelope` with the granted consent scopes/uses from `token`,
/// falling back to the requested (`effective_cfg`) scopes/uses when the
/// issuer is old enough not to echo them back (empty `consent_scopes`).
/// Shared between the initial stamp before the first upload attempt and the
/// restamp after a claim re-mint, so both paths derive the grant the same
/// way.
fn stamp_granted_scopes(
    envelope: &mut TraceContributionEnvelope,
    effective_cfg: &ContributorConfig,
    token: &ClaimToken,
) {
    let (granted_scopes, granted_uses) = granted_consent_for(effective_cfg, token);
    apply_granted_scopes(envelope, &granted_scopes, &granted_uses);
}

/// The grant a claim carried, or the requested one when the issuer is old
/// enough not to echo it back.
///
/// Split out of [`stamp_granted_scopes`] so a witnessed submission derives the
/// grant identically -- it passes these values into the witness request
/// instead of stamping them afterwards, and two derivations would eventually
/// disagree about what a contributor consented to.
fn granted_consent_for(
    effective_cfg: &ContributorConfig,
    token: &ClaimToken,
) -> (Vec<ConsentScope>, Vec<TraceAllowedUse>) {
    if token.consent_scopes.is_empty() {
        (
            parse_scope_names(&effective_cfg.consent_scopes),
            parse_use_names(&crate::consent::scopes_to_allowed_uses(
                &effective_cfg.consent_scopes,
            )),
        )
    } else {
        (
            parse_scope_names(&token.consent_scopes),
            parse_use_names(&token.allowed_uses),
        )
    }
}

fn validate_review_grant(
    cfg: &ContributorConfig,
    token: &ClaimToken,
    now: DateTime<Utc>,
) -> Result<()> {
    use std::collections::BTreeSet;
    let granted: BTreeSet<_> = token.consent_scopes.iter().collect();
    let requested: BTreeSet<_> = cfg.consent_scopes.iter().collect();
    if !token.is_fresh(now)
        || token.access_token.is_empty()
        || granted.is_empty()
        || !granted.is_subset(&requested)
        || parse_scope_names(&token.consent_scopes).len() != token.consent_scopes.len()
        || parse_use_names(&token.allowed_uses).len() != token.allowed_uses.len()
    {
        anyhow::bail!("witness-claim-invalid");
    }
    let permitted_uses = crate::consent::scopes_to_allowed_uses(&token.consent_scopes);
    if token
        .allowed_uses
        .iter()
        .any(|name| !permitted_uses.contains(name))
    {
        anyhow::bail!("witness-claim-invalid");
    }
    Ok(())
}

fn ensure_certified_grant(
    envelope: &TraceContributionEnvelope,
    token: &ClaimToken,
    now: DateTime<Utc>,
) -> Result<()> {
    if !token.is_fresh(now) || token.access_token.is_empty() || token.consent_scopes.is_empty() {
        anyhow::bail!("witness-grant-changed");
    }
    let mut expected = envelope.clone();
    apply_granted_scopes(
        &mut expected,
        &parse_scope_names(&token.consent_scopes),
        &parse_use_names(&token.allowed_uses),
    );
    if expected.consent != envelope.consent
        || expected.trace_card.allowed_uses != envelope.trace_card.allowed_uses
        || expected.trace_card.consent_scope != envelope.trace_card.consent_scope
        || parse_scope_names(&token.consent_scopes).len() != token.consent_scopes.len()
        || parse_use_names(&token.allowed_uses).len() != token.allowed_uses.len()
    {
        anyhow::bail!("witness-grant-changed");
    }
    Ok(())
}

fn build_ingest_client(
    cfg: &ContributorConfig,
    token: &ClaimToken,
) -> std::result::Result<Client, OcError> {
    Client::builder(
        &cfg.ingest_url,
        "TRACE_COMMONS_CONTRIBUTOR_UNUSED_BEARER_ENV",
    )
    .bearer_token(&token.access_token)
    .host_allowlist(config_allowlist(cfg))
    .build()
}

/// Upload `envelope`, retrying transient transport failures up to 3 attempts
/// total (1s then 4s backoff) and, on a 401/403, re-minting the claim once
/// and retrying once more before giving up.
///
/// A re-mint can return narrower (or otherwise different) granted scopes
/// than the claim that was active when `envelope` was first stamped. To
/// avoid resending an envelope stamped with a stale grant, the envelope is
/// restamped with the new token's granted scopes/uses (via
/// `stamp_granted_scopes`, the same helper used before the first attempt)
/// and re-checked for size before the retry.
///
/// # Witnessed submissions
///
/// `witnessed` carries the bytes the certificate covers. When it is `Some`,
/// those bytes go on the wire **verbatim** through `call_bytes`, with the
/// certificate and signature in headers, and `envelope` is not consulted for
/// the body at all. A re-mint retries only if all certified permissions match
/// the fresh grant exactly. Otherwise it refuses; it never restamps signed
/// bytes or sends the raw session to the witness a second time.
async fn upload_with_retry(
    cfg: &ContributorConfig,
    issuer: &IssuerClient,
    device: &DeviceIdentity,
    claim: &mut Option<ClaimToken>,
    envelope: &mut TraceContributionEnvelope,
    effective_cfg: &ContributorConfig,
    witnessed: Option<&WitnessedEnvelope>,
) -> std::result::Result<TraceSubmissionReceipt, String> {
    let mut transport_attempts: u32 = 0;
    let mut remint_attempted = false;

    loop {
        let token = claim
            .as_ref()
            .expect("a claim must be minted before uploading")
            .clone();
        let client = match build_ingest_client(cfg, &token) {
            Ok(c) => c,
            Err(e) => return Err(e.kind().to_string()),
        };

        let result = match witnessed {
            // The bytes as the witness emitted them. `call_bytes`, never
            // `call_json`: the certificate binds a SHA-256 over exactly these
            // bytes, and re-serialising would break the digest invisibly --
            // the re-encoded bytes still parse as the same envelope, so the
            // failure would only surface at the server's verification and
            // would look like tampering.
            Some(witnessed) => {
                let mut headers = vec![
                    (
                        WITNESS_CERTIFICATE_HEADER,
                        witnessed.certificate_json.as_str(),
                    ),
                    (WITNESS_SIGNATURE_HEADER, witnessed.signature_hex.as_str()),
                ];
                if let Some(admission) = &witnessed.admission {
                    headers.push((
                        trace_commons_protocol::admission::EVIDENCE_HEADER,
                        admission.evidence_json.as_str(),
                    ));
                    headers.push((
                        trace_commons_protocol::admission::SIGNATURE_HEADER,
                        admission.signature_hex.as_str(),
                    ));
                }
                client
                    .call_bytes(
                        Method::POST,
                        "/v1/traces",
                        &[],
                        &witnessed.envelope_bytes,
                        &headers,
                    )
                    .await
                    .and_then(|body| {
                        serde_json::from_str::<TraceSubmissionReceipt>(&body).map_err(|source| {
                            OcError::MalformedResponse {
                                url: cfg.ingest_url.clone(),
                                body,
                                source,
                            }
                        })
                    })
            }
            None => {
                client
                    .call_json::<TraceContributionEnvelope, TraceSubmissionReceipt>(
                        Method::POST,
                        "/v1/traces",
                        &[],
                        Some(&*envelope),
                    )
                    .await
            }
        };

        match result {
            Ok(receipt) => return Ok(receipt),
            Err(OcError::Transport { .. }) => {
                transport_attempts += 1;
                if transport_attempts >= 3 {
                    return Err("transport".to_string());
                }
                let delay_secs = if transport_attempts == 1 { 1 } else { 4 };
                tokio::time::sleep(StdDuration::from_secs(delay_secs)).await;
            }
            Err(e) => {
                // A refusal the gate sent deliberately, before anything reads
                // it as a credential problem. `label()` is this crate's own
                // constant for the variant that was recognised, never the
                // string the server sent.
                if let Some(refusal) = admission_refusal(&e) {
                    return Err(refusal.label().to_string());
                }
                if !is_auth_failure(&e) {
                    return Err(e.kind().to_string());
                }
                if remint_attempted {
                    return Err("auth-failed".to_string());
                }
                remint_attempted = true;
                match mint_claim(issuer, cfg, device, Utc::now()).await {
                    Ok(new_token) => {
                        if witnessed.is_some() {
                            ensure_certified_grant(envelope, &new_token, Utc::now())
                                .map_err(|_| "witness-grant-changed".to_string())?;
                        } else {
                            stamp_granted_scopes(envelope, effective_cfg, &new_token);
                        }
                        if envelope_size_ok(envelope).is_err() {
                            return Err("session-too-large".to_string());
                        }
                        *claim = Some(new_token);
                    }
                    Err(_) => return Err("auth-failed".to_string()),
                }
            }
        }
    }
}

/// The admission refusal this error carries, if the gate sent one.
///
/// Only a labelled body counts. [`OcError::HttpFailure`] is the shape a
/// non-success answer takes when its body carried no `error` field at all,
/// and something with no label is not a refusal this client can name.
fn admission_refusal(e: &OcError) -> Option<AdmissionRefusal> {
    match e {
        OcError::ServerLabel { status, label, .. } => {
            AdmissionRefusal::from_response(status.as_u16(), label)
        }
        _ => None,
    }
}

/// Whether this is the expired credential a remint answers.
///
/// **Fail closed.** A `403` stays an authentication failure unless the body
/// names a refusal this client recognises on that status. An unreadable body,
/// an unknown label, or a known label on the wrong status all leave the
/// remint in place: a genuinely expired claim must still be reminted, and a
/// response body does not get to talk this client out of it.
fn is_auth_failure(e: &OcError) -> bool {
    if admission_refusal(e).is_some() {
        return false;
    }
    match e {
        OcError::ServerLabel { status, .. } | OcError::HttpFailure { status, .. } => {
            status.as_u16() == 401 || status.as_u16() == 403
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WitnessSettings;
    use axum::{Json, Router, routing::post};
    use std::sync::{Arc, Mutex};

    #[test]
    fn admission_projection_omits_unsigned_history_but_preserves_submission_identity() {
        let cfg = crate::commands::unenrolled_preview_config();
        let (source, reference) = fixture_selection().remove(0);
        let transcript = source.load(&reference).unwrap();
        let mut raw = crate::envelope::build_raw_contribution_with_correction(
            &transcript,
            &cfg,
            Utc::now(),
            None,
            Some("unsigned correction sentinel"),
        );
        assert!(!raw.events.is_empty());
        raw.conversation_id = Some("unsigned conversation sentinel".into());
        raw.ironclaw.model_name = Some("unsigned model sentinel".into());
        raw.ironclaw
            .feature_flags
            .insert("unbound".into(), "unsigned flag sentinel".into());
        raw.ironclaw
            .feature_flags
            .insert("cwd_hash".into(), "unsigned cwd sentinel".into());
        raw.contributor.tenant_scope_ref = Some("unsigned tenant sentinel".into());
        raw.replay
            .expected_assertions
            .push("unsigned assertion sentinel".into());
        let ordinary = witness_input_for_profile(raw.clone(), &cfg, false);
        assert_eq!(
            ordinary, raw,
            "invited ordinary review retains its complete trace"
        );
        let isolated = witness_input_for_profile(raw.clone(), &cfg, true);
        assert_eq!(isolated.submission_id, raw.submission_id);
        assert_eq!(isolated.trace_id, raw.trace_id);
        assert_eq!(isolated.created_at, raw.created_at);
        assert_eq!(
            isolated.contributor.tenant_scope_ref.as_deref(),
            Some(cfg.tenant_id.as_str())
        );
        assert!(isolated.events.is_empty());
        assert!(!isolated.replay.replayable);
        assert!(isolated.replay.required_tools.is_empty());
        assert!(isolated.replay.expected_assertions.is_empty());
        assert!(isolated.outcome.human_correction.is_none());
        assert!(isolated.conversation_id.is_none());
        assert!(isolated.ironclaw.model_name.is_none());
        assert_eq!(isolated.value, Default::default());
        assert_eq!(
            isolated
                .ironclaw
                .feature_flags
                .get("cwd_hash")
                .map(String::as_str),
            Some("unknown"),
            "a projection that copied only this key would pass every other assertion here"
        );
        let agent = raw
            .ironclaw
            .feature_flags
            .get("agent")
            .map(String::as_str)
            .expect("the fixture transcript names its source");
        assert!(!agent.is_empty());
        assert_eq!(
            isolated
                .ironclaw
                .feature_flags
                .get("agent")
                .map(String::as_str),
            Some(agent),
            "the syntactic source label is the one carry-through, and it must survive"
        );
        assert!(
            !serde_json::to_string(&isolated)
                .unwrap()
                .contains("unsigned")
        );
    }

    fn review_options() -> SubmitOptions {
        SubmitOptions {
            dry_run: false,
            pii_filter: None,
            no_reasoning: false,
            machine_readable: true,
            unenrolled_preview: false,
            remediate_quarantined: false,
            verdict: None,
        }
    }

    async fn reviewed_fixture(
        cfg: &mut ContributorConfig,
    ) -> (
        crate::source::SessionTranscript,
        crate::daemon::approved_envelope::WitnessReviewArtifact,
    ) {
        let (source, reference) = fixture_selection().remove(0);
        let transcript = source.load(&reference).unwrap();
        let mut envelope = baseline_envelope(cfg).await;
        let token = ClaimToken {
            access_token: "review-only-not-stored".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            consent_scopes: cfg.consent_scopes.clone(),
            allowed_uses: vec![
                "debugging".into(),
                "evaluation".into(),
                "model_training".into(),
                "aggregate_analytics".into(),
            ],
        };
        stamp_granted_scopes(&mut envelope, cfg, &token);
        let (response, signer) = crate::witness::transport::signed_fixture(
            serde_json::to_vec_pretty(&envelope).unwrap(),
        );
        cfg.witness = Some(WitnessSettings {
            admission_evidence: false,
            url: "https://no-repeat-witness.invalid".into(),
            signing_address: signer,
            expected_measurements: vec![format!("mrtd={}", "aa".repeat(48))],
        });
        let fingerprint = crate::daemon::preview::input_fingerprint(cfg, None, false);
        let artifact = crate::daemon::approved_envelope::WitnessReviewArtifact::new(
            response,
            transcript.session_hash.clone(),
            fingerprint,
            None,
            None,
            None,
        );
        (transcript, artifact)
    }

    #[tokio::test]
    async fn admission_review_binds_exact_artifact_and_uploads_only_approved_bytes() {
        let capture = Arc::new(Mutex::new(CapturedUpload::default()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest_raw(capture.clone(), 200)).await;
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let anchor = "11".repeat(32);
        cfg.tenant_id = format!("near-{anchor}");
        let (transcript, original) = reviewed_fixture(&mut cfg).await;
        cfg.witness.as_mut().unwrap().admission_evidence = true;
        let response = crate::witness::transport::signed_admission_fixture(
            original.response().envelope_bytes.clone(),
            &anchor,
        );
        let fingerprint = crate::daemon::preview::input_fingerprint(&cfg, None, false);
        let artifact = crate::daemon::approved_envelope::WitnessReviewArtifact::new(
            response.clone(),
            transcript.session_hash.clone(),
            fingerprint.clone(),
            None,
            None,
            None,
        );
        artifact
            .validate(&cfg, &transcript.session_hash, &fingerprint, None, None)
            .unwrap();
        let mut changed = response;
        changed.envelope_bytes.push(b' '); // Same JSON value, different certified bytes.
        let changed = crate::daemon::approved_envelope::WitnessReviewArtifact::new(
            changed,
            transcript.session_hash.clone(),
            fingerprint.clone(),
            None,
            None,
            None,
        );
        assert_ne!(changed.digest().unwrap(), artifact.digest().unwrap());
        assert!(
            changed
                .validate(&cfg, &transcript.session_hash, &fingerprint, None, None)
                .is_err()
        );
        assert!(
            artifact
                .validate(
                    &cfg,
                    "sha256:another-contribution",
                    &fingerprint,
                    None,
                    None
                )
                .is_err()
        );
        let entry = crate::daemon::queue::entry_id_for(&transcript.session_hash);
        crate::daemon::approved_envelope::save_witnessed(&store, entry, &artifact).unwrap();
        let restored = crate::daemon::approved_envelope::load_witnessed(&store, entry)
            .unwrap()
            .unwrap();
        assert_eq!(restored.digest().unwrap(), artifact.digest().unwrap());
        // The order `uploader::approved_witness_for` runs in: the pin first,
        // against the bytes as stored, and only then the binding. Validating
        // the reloaded artifact rather than the pre-save one is the point --
        // a round trip that lost the admission headers would still satisfy
        // the digest and fail here.
        restored
            .validate(&cfg, &transcript.session_hash, &fingerprint, None, None)
            .unwrap();
        let opts = review_options();
        let mut context = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        context
            .use_approved_witness(restored.response().clone())
            .unwrap();
        assert!(matches!(
            context.submit_loaded(transcript).await.unwrap(),
            SubmitOutcome::Submitted { .. }
        ));
        let captured = capture.lock().unwrap();
        assert_eq!(
            captured.bodies.as_slice(),
            &[artifact.response().envelope_bytes.clone()]
        );
        let admission = artifact.response().admission.as_ref().unwrap();
        assert_eq!(
            captured.headers[0][trace_commons_protocol::admission::EVIDENCE_HEADER],
            admission.evidence_json
        );
        assert_eq!(
            captured.headers[0][trace_commons_protocol::admission::SIGNATURE_HEADER],
            admission.signature_hex
        );
    }

    #[tokio::test]
    async fn witness_review_survives_restart_and_uploads_exact_certified_bytes() {
        let capture = Arc::new(Mutex::new(CapturedUpload::default()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest_raw(capture.clone(), 200)).await;
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let (transcript, artifact) = reviewed_fixture(&mut cfg).await;
        let fingerprint = crate::daemon::preview::input_fingerprint(&cfg, None, false);
        artifact
            .validate(&cfg, &transcript.session_hash, &fingerprint, None, None)
            .unwrap();
        let entry_id = crate::daemon::queue::entry_id_for(&transcript.session_hash);
        crate::daemon::approved_envelope::save_witnessed(&store, entry_id, &artifact).unwrap();
        let restored = crate::daemon::approved_envelope::load_witnessed(&store, entry_id)
            .unwrap()
            .unwrap();
        assert_eq!(artifact.digest().unwrap(), restored.digest().unwrap());
        let opts = review_options();
        let mut context = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        context
            .use_approved_witness(restored.response().clone())
            .unwrap();
        assert!(matches!(
            context.submit_loaded(transcript).await.unwrap(),
            SubmitOutcome::Submitted { .. }
        ));
        let captured = capture.lock().unwrap();
        assert_eq!(
            captured.bodies.as_slice(),
            &[artifact.response().envelope_bytes.clone()]
        );
        assert_eq!(
            captured.headers[0][WITNESS_CERTIFICATE_HEADER]
                .to_str()
                .unwrap(),
            artifact.response().certificate_json
        );
        assert_eq!(
            captured.headers[0][WITNESS_SIGNATURE_HEADER]
                .to_str()
                .unwrap(),
            artifact.response().signature_hex
        );
    }

    #[tokio::test]
    async fn witness_review_re_mints_compatible_expired_authorization_without_rewitnessing() {
        let capture = Arc::new(Mutex::new(CapturedUpload::default()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest_raw(capture.clone(), 401)).await;
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let (transcript, artifact) = reviewed_fixture(&mut cfg).await;
        let opts = review_options();
        let mut context = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        context
            .use_approved_witness(artifact.response().clone())
            .unwrap();
        assert!(matches!(
            context.submit_loaded(transcript).await.unwrap(),
            SubmitOutcome::Submitted { .. }
        ));
        let captured = capture.lock().unwrap();
        assert_eq!(captured.bodies.len(), 2);
        assert_eq!(captured.bodies[0], artifact.response().envelope_bytes);
        assert_eq!(captured.bodies[0], captured.bodies[1]);
    }

    #[tokio::test]
    async fn witness_review_refuses_changed_grants_before_upload() {
        let capture = Arc::new(Mutex::new(CapturedUpload::default()));
        let issuer = spawn(Router::new().route("/v1/trace-upload-claim", post(|| async {
            Json(serde_json::json!({"access_token":"fresh-narrow-grant", "expires_at": Utc::now() + chrono::Duration::minutes(5),
                "consent_scopes":["debugging_evaluation"], "allowed_uses":["debugging"]}))
        }))).await;
        let ingest = spawn(stub_ingest_raw(capture.clone(), 200)).await;
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let (transcript, artifact) = reviewed_fixture(&mut cfg).await;
        let opts = review_options();
        let mut context = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        context
            .use_approved_witness(artifact.response().clone())
            .unwrap();
        assert!(
            matches!(context.submit_loaded(transcript).await.unwrap(), SubmitOutcome::Refused { reason_label, .. } if reason_label == "witness-grant-changed")
        );
        assert!(capture.lock().unwrap().bodies.is_empty());
    }

    #[tokio::test]
    async fn witness_review_binds_source_identity_settings_and_approval_answers() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(
            "https://issuer.invalid",
            "https://ingest.invalid",
            &device.device_key_id,
        );
        let (transcript, artifact) = reviewed_fixture(&mut cfg).await;
        let fingerprint = crate::daemon::preview::input_fingerprint(&cfg, None, false);
        assert!(
            artifact
                .validate(&cfg, &transcript.session_hash, &fingerprint, None, None)
                .is_ok()
        );
        assert!(
            artifact
                .validate(&cfg, "foreign-source", &fingerprint, None, None)
                .is_err()
        );
        assert!(
            artifact
                .validate(
                    &cfg,
                    &transcript.session_hash,
                    "changed-settings",
                    None,
                    None
                )
                .is_err()
        );
        assert!(
            artifact
                .validate(
                    &cfg,
                    &transcript.session_hash,
                    &fingerprint,
                    Some("worked"),
                    None
                )
                .is_err()
        );
        assert!(
            artifact
                .validate(
                    &cfg,
                    &transcript.session_hash,
                    &fingerprint,
                    None,
                    Some("new correction")
                )
                .is_err()
        );
        cfg.tenant_id.push_str("-foreign");
        assert!(
            artifact
                .validate(&cfg, &transcript.session_hash, &fingerprint, None, None)
                .is_err()
        );
    }

    #[tokio::test]
    async fn witness_review_grants_require_explicit_known_fresh_scopes() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(
            "https://issuer.invalid",
            "https://ingest.invalid",
            &device.device_key_id,
        );
        let now = Utc::now();
        let valid = stub_claim(now);
        assert!(validate_review_grant(&cfg, &valid, now).is_ok());
        let mut token = valid.clone();
        token.expires_at = now;
        assert!(validate_review_grant(&cfg, &token, now).is_err());
        token = valid.clone();
        token.consent_scopes.clear();
        assert!(validate_review_grant(&cfg, &token, now).is_err());
        token = valid.clone();
        token.consent_scopes.push("foreign-scope".into());
        assert!(validate_review_grant(&cfg, &token, now).is_err());
        token = valid.clone();
        token.allowed_uses.push("foreign-use".into());
        assert!(validate_review_grant(&cfg, &token, now).is_err());
        token = valid;
        token.consent_scopes.push("ranking_training".into());
        assert!(validate_review_grant(&cfg, &token, now).is_err());
    }

    /// Body limit every stub endpoint is mounted with. axum defaults to
    /// 2 MiB, which is BELOW the envelope cap -- a stub left on the default
    /// would 413 a legitimately-sized envelope and surface as a generic
    /// `http-failure`, hiding whatever the test was actually asserting.
    /// Mirrors real ingest: the envelope cap plus framing headroom.
    const STUB_BODY_LIMIT_BYTES: usize = MAX_ENVELOPE_BYTES + 4 * 1024 * 1024;

    async fn spawn(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = router.layer(axum::extract::DefaultBodyLimit::max(STUB_BODY_LIMIT_BYTES));
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    /// Same as `spawn`, but returns a URL addressed via `localhost` instead
    /// of the literal `127.0.0.1`, so tests can put the issuer and ingest
    /// endpoints on distinct allowlist-checkable host strings while both
    /// still resolve to the same loopback listener.
    async fn spawn_as_localhost(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = router.layer(axum::extract::DefaultBodyLimit::max(STUB_BODY_LIMIT_BYTES));
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://localhost:{port}")
    }

    fn stub_issuer() -> Router {
        Router::new().route(
            "/v1/trace-upload-claim",
            post(|| async {
                Json(serde_json::json!({
                    "access_token": "stub-claim-jwt",
                    "token_type": "Bearer",
                    "expires_at": chrono::Utc::now() + chrono::Duration::seconds(300),
                    "expires_in": 300,
                    "consent_scopes": ["debugging_evaluation", "model_training"],
                    "allowed_uses": ["debugging", "evaluation", "model_training", "aggregate_analytics"],
                }))
            }),
        )
    }

    fn stub_issuer_refuses_scopes() -> Router {
        Router::new().route(
            "/v1/trace-upload-claim",
            post(|| async {
                (
                    axum::http::StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "consent scopes not permitted"})),
                )
            }),
        )
    }

    fn stub_issuer_refuses_uses() -> Router {
        Router::new().route(
            "/v1/trace-upload-claim",
            post(|| async {
                (
                    axum::http::StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "allowed uses not permitted"})),
                )
            }),
        )
    }

    fn stub_ingest(received: Arc<Mutex<Vec<serde_json::Value>>>) -> Router {
        stub_ingest_status(received, "accepted")
    }

    fn stub_ingest_status(
        received: Arc<Mutex<Vec<serde_json::Value>>>,
        status: &'static str,
    ) -> Router {
        Router::new().route(
            "/v1/traces",
            post(
                move |headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| {
                    let received = received.clone();
                    async move {
                        assert_eq!(
                            headers.get("authorization").unwrap(),
                            "Bearer stub-claim-jwt"
                        );
                        received.lock().unwrap().push(body);
                        Json(serde_json::json!({
                            "status": status,
                            "credit_points_pending": 0.0,
                            "explanation": []
                        }))
                    }
                },
            ),
        )
    }

    /// The hosted admission gate's refusal shape: a status, an
    /// `{"error": ...}` label, and no receipt.
    fn stub_ingest_refuses(status: u16, label: &'static str) -> Router {
        Router::new().route(
            "/v1/traces",
            post(move || async move {
                (
                    axum::http::StatusCode::from_u16(status).expect("a legal status"),
                    Json(serde_json::json!({ "error": label })),
                )
            }),
        )
    }

    async fn refusal_from_ingest(status: u16, label: &'static str) -> String {
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest_refuses(status, label)).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let outcomes =
            submit_sessions(&store, &cfg, fixture_selection(), &SubmitOptions::default())
                .await
                .unwrap();
        refusal_label_of(&outcomes[0])
    }

    /// A refusal from the hosted admission gate is not an authentication
    /// failure, and the label it carries is the one that reaches the queue.
    ///
    /// Before this, `403 admission_refused` was read as an expired claim: it
    /// burned a remint and reported `auth-failed`, and the 409 and 429
    /// refusals reported the transport's own `server-label`. The daemon then
    /// rendered every one of them as an unreachable commons, so a contributor
    /// who had spent their budget, or whose evidence was declined, was told
    /// the service was down.
    #[tokio::test]
    async fn an_admission_refusal_is_reported_by_its_server_label() {
        for refusal in trace_commons_protocol::admission::AdmissionRefusal::ALL {
            // The witness gate sends this one, on a path that never reaches
            // `/v1/traces`.
            if refusal == trace_commons_protocol::admission::AdmissionRefusal::EvidenceRefused {
                continue;
            }
            assert_eq!(
                refusal_from_ingest(refusal.status(), refusal.label()).await,
                refusal.label(),
                "{} did not reach the queue as itself",
                refusal.label()
            );
        }
    }

    /// The fail-closed half. A 403 this client cannot read as an admission
    /// refusal is still treated as an expired claim, because it still is one
    /// on every other path -- and a body is not permission to stop reminting.
    #[tokio::test]
    async fn an_unrecognised_refusal_still_reads_as_an_expired_claim() {
        for (status, label) in [
            (403, "not_a_label_this_client_knows"),
            // The right label on a status it is never sent with.
            (403, "admission_limit_reached"),
        ] {
            assert_eq!(
                refusal_from_ingest(status, label).await,
                "auth-failed",
                "{status} {label}"
            );
        }
    }

    fn fixture_selection() -> Vec<(
        Box<dyn crate::source::TraceSource>,
        crate::source::SessionRef,
    )> {
        let root =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/claude-code");
        let src = crate::source::claude_code::ClaudeCodeSource::new(root.clone());
        let r = src.discover().unwrap().remove(0);
        vec![(
            Box::new(crate::source::claude_code::ClaudeCodeSource::new(root))
                as Box<dyn crate::source::TraceSource>,
            r,
        )]
    }

    fn write_test_trajectory(path: &std::path::Path, content: &str) {
        let body = serde_json::json!([
            {"role": "meta", "source": "submit-test"},
            {
                "role": "user",
                "content": content,
                "timestamp": "2026-07-31T12:00:00Z"
            }
        ]);
        std::fs::write(path, serde_json::to_vec(&body).unwrap()).unwrap();
    }

    fn trajectory_selection(
        root: &std::path::Path,
    ) -> Vec<(
        Box<dyn crate::source::TraceSource>,
        crate::source::SessionRef,
    )> {
        let mut refs = crate::source::trajectory::TrajectorySource::new(root.to_path_buf())
            .discover()
            .unwrap();
        refs.sort_by(|a, b| a.path.cmp(&b.path));
        refs.into_iter()
            .map(|session_ref| {
                (
                    Box::new(crate::source::trajectory::TrajectorySource::new(
                        root.to_path_buf(),
                    )) as Box<dyn crate::source::TraceSource>,
                    session_ref,
                )
            })
            .collect()
    }

    async fn narrow_boundary_envelope(
        trajectory_path: &std::path::Path,
        content_len: usize,
        cfg: &ContributorConfig,
        narrow_token: &ClaimToken,
    ) -> TraceContributionEnvelope {
        write_test_trajectory(trajectory_path, &"x".repeat(content_len));
        let source =
            crate::source::trajectory::TrajectorySource::new(trajectory_path.to_path_buf());
        let session_ref = source.discover().unwrap().remove(0);
        let transcript = source.load(&session_ref).unwrap();
        let redactor = build_redactor_with(cfg, transcript.cwd.as_deref(), None).unwrap();
        let now = DateTime::parse_from_rfc3339("2026-07-31T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let raw = build_raw_contribution_with_verdict(&transcript, cfg, now, None);
        assert!(raw_contribution_size_ok(&raw).is_ok());
        let mut envelope = redact_to_envelope(&redactor, raw).await.unwrap();
        stamp_granted_scopes(&mut envelope, cfg, narrow_token);
        envelope
    }

    fn cfg_for(
        issuer: &str,
        ingest: &str,
        device_key_id: &str,
    ) -> crate::config::ContributorConfig {
        crate::config::ContributorConfig {
            inference_receipt_endpoint: None,
            inference_receipt_check_attestation: false,
            schema_version: crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION.into(),
            issuer_url: issuer.into(),
            ingest_url: ingest.into(),
            audience: "trace-commons-upload".into(),
            tenant_id: "tenant-abc".into(),
            instance_id: "instance-1".into(),
            user_subject: "alice".into(),
            device_key_id: device_key_id.into(),
            consent_scopes: vec!["debugging_evaluation".into(), "model_training".into()],
            pii_filter: None,
            allowed_hosts: None,
            display_handle: None,
            public_bio: None,
            public_since: None,
            witness: None,
        }
    }

    async fn outcome_for_fixture(
        cfg: &crate::config::ContributorConfig,
        unenrolled_preview: bool,
    ) -> trace_commons_protocol::trace_contribution::TraceContributionEnvelope {
        let root =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/claude-code");
        let source = crate::source::claude_code::ClaudeCodeSource::new(root);
        let session_ref = source.discover().unwrap().remove(0);
        let transcript = source.load(&session_ref).unwrap();
        let redactor = if unenrolled_preview {
            build_deterministic_preview_redactor(transcript.cwd.as_deref())
        } else {
            build_redactor_with(cfg, transcript.cwd.as_deref(), None).unwrap()
        };
        let now = DateTime::parse_from_rfc3339("2026-07-31T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let raw = if unenrolled_preview {
            build_preview_raw_contribution(&transcript, cfg, now)
        } else {
            build_raw_contribution_with_verdict(&transcript, cfg, now, None)
        };
        redact_to_envelope(&redactor, raw).await.unwrap()
    }

    #[tokio::test]
    async fn unenrolled_and_enrolled_previews_have_full_outcome_parity() {
        let preview_cfg = crate::commands::unenrolled_preview_config();
        let enrolled_cfg = crate::config::ContributorConfig {
            inference_receipt_endpoint: None,
            inference_receipt_check_attestation: false,
            schema_version: crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION.into(),
            issuer_url: "https://issuer.example".into(),
            ingest_url: "https://ingest.example".into(),
            audience: "trace-commons-upload".into(),
            tenant_id: trace_commons_protocol::onboarding::derive_user_tenant_id(
                "instance-1",
                "alice",
            ),
            instance_id: "instance-1".into(),
            user_subject: "alice".into(),
            device_key_id: "sha256:enrolled".into(),
            consent_scopes: vec!["debugging_evaluation".into()],
            pii_filter: None,
            allowed_hosts: None,
            display_handle: None,
            public_bio: None,
            public_since: None,
            witness: None,
        };
        assert_eq!(preview_cfg.tenant_id.len(), enrolled_cfg.tenant_id.len());
        assert_eq!(preview_cfg.tenant_id.len(), 71);

        let preview = outcome_for_fixture(&preview_cfg, true).await;
        let enrolled = outcome_for_fixture(&enrolled_cfg, false).await;

        assert_eq!(
            envelope_size(&preview).unwrap(),
            envelope_size(&enrolled).unwrap(),
            "canonical-width placeholder identity must preserve serialized size"
        );
        assert_eq!(
            envelope_size_ok(&preview).is_ok(),
            envelope_size_ok(&enrolled).is_ok(),
            "placeholder identity must not change the size decision"
        );
        assert_eq!(
            preview.consent, enrolled.consent,
            "consent must agree without rewriting either fixture"
        );
        assert_eq!(
            preview.privacy.redaction_pipeline_version,
            enrolled.privacy.redaction_pipeline_version
        );
        assert_eq!(
            preview.privacy.redaction_counts,
            enrolled.privacy.redaction_counts
        );
        assert_eq!(
            preview.privacy.privacy_filter_summary,
            enrolled.privacy.privacy_filter_summary
        );
        assert_eq!(
            preview.privacy.pii_labels_present,
            enrolled.privacy.pii_labels_present
        );
        assert_eq!(
            preview.privacy.residual_pii_risk,
            enrolled.privacy.residual_pii_risk
        );
        assert_eq!(preview.privacy.warnings, enrolled.privacy.warnings);
        // The redaction hash commits to each envelope's deliberately disjoint
        // preview/submission id, so equality would erase the namespace fix.
        for hash in [
            &preview.privacy.redaction_hash,
            &enrolled.privacy.redaction_hash,
        ] {
            assert!(hash.starts_with("sha256:"));
            assert_eq!(hash.len(), 71);
        }
        assert_eq!(
            preview.trace_card.consent_scope,
            enrolled.trace_card.consent_scope
        );
        assert_eq!(
            preview.trace_card.redaction_pipeline_version,
            enrolled.trace_card.redaction_pipeline_version
        );
        assert_eq!(
            preview.trace_card.source_channel,
            enrolled.trace_card.source_channel
        );
        assert_eq!(
            preview.trace_card.tool_categories,
            enrolled.trace_card.tool_categories
        );
        assert_eq!(
            preview.trace_card.allowed_uses,
            enrolled.trace_card.allowed_uses
        );
        assert_eq!(
            preview.trace_card.retention_policy,
            enrolled.trace_card.retention_policy
        );
        assert!(Uuid::parse_str(&preview.trace_card.revocation_handle).is_ok());
        assert!(Uuid::parse_str(&enrolled.trace_card.revocation_handle).is_ok());
        let residual_scanner =
            trace_commons_protocol::trace_contribution::DeterministicTraceRedactor::deterministic_only(
                Vec::new(),
            );
        assert_eq!(
            envelope_has_residual_secret(&residual_scanner, &preview).unwrap(),
            envelope_has_residual_secret(&residual_scanner, &enrolled).unwrap(),
            "placeholder identity must not change the residual-secret result"
        );
        assert_eq!(preview.submission_id.get_version_num(), 8);
        assert_eq!(enrolled.submission_id.get_version_num(), 5);
        assert_ne!(preview.submission_id, enrolled.submission_id);
    }

    #[test]
    fn the_explanation_names_causes_in_labels_only() {
        // The point of the dry-run explanation is that a contributor can see
        // WHY a trace will quarantine. The point of this test is that seeing
        // why never costs them the content: this runs over other people's
        // private traces, so counts and labels only.
        let counts = BTreeMap::from([("secret:aws_access_key".to_string(), 2u32)]);
        let labels = vec!["email".to_string()];

        let why =
            residual_risk_explanation(&explanation_consent(true, false, false), &counts, &labels);

        assert!(why.contains("message_text_included"));
        assert!(why.contains("2 secret:aws_access_key"));
        assert!(why.contains("email"));
        // The matched text itself must never appear.
        assert!(!why.contains("AKIA"), "no matched secret may appear: {why}");
        assert!(!why.contains('/'), "no path may appear: {why}");
    }

    #[test]
    fn a_clean_envelope_says_so_rather_than_listing_nothing() {
        let why = residual_risk_explanation(
            &explanation_consent(false, false, false),
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(why, "nothing in this envelope raised the floor");
    }

    /// Consent declaring exactly the content flags named.
    fn explanation_consent(
        message_text: bool,
        tool_payloads: bool,
        correction: bool,
    ) -> ConsentMetadata {
        use trace_commons_protocol::trace_contribution::{
            ConsentScope, TRACE_CONTRIBUTION_POLICY_VERSION,
        };
        ConsentMetadata {
            policy_version: TRACE_CONTRIBUTION_POLICY_VERSION.to_string(),
            scopes: vec![ConsentScope::DebuggingEvaluation],
            message_text_included: message_text,
            tool_payloads_included: tool_payloads,
            correction_included: correction,
            routing_metadata_included: false,
            revocable: true,
        }
    }

    // A correction raises the floor to Medium, so the explanation of that
    // number has to name it. Before the flag existed, a correction-bearing
    // envelope explained its own Medium as "nothing raised the floor".
    #[test]
    fn the_explanation_names_a_correction_as_a_cause() {
        let why = residual_risk_explanation(
            &explanation_consent(false, false, true),
            &BTreeMap::new(),
            &[],
        );

        assert!(
            why.contains("correction_included"),
            "the flag that raised the floor must appear: {why}"
        );
    }

    #[test]
    fn the_storage_note_is_conditional_for_medium() {
        // The client cannot see the operator's configuration, so Medium must
        // describe the tier rather than promise an outcome.
        let note = residual_risk_storage_note(ResidualPiiRisk::Medium);
        assert!(note.contains("only if the operator enabled"));
        assert!(note.contains("TRACE_COMMONS_ACCEPT_MEDIUM_RISK_SUBMISSIONS"));
        assert!(residual_risk_storage_note(ResidualPiiRisk::Low).contains("accepted"));
        assert!(residual_risk_storage_note(ResidualPiiRisk::High).contains("quarantines"));
    }

    #[test]
    fn only_size_refusal_is_non_fatal_in_dry_run() {
        assert!(!outcomes_have_failure(
            &[refused("session-too-large", "sha256:test")],
            true
        ));
        assert!(outcomes_have_failure(
            &[refused("session-too-large", "sha256:test")],
            false
        ));
        for reason in [
            "pii-filter-unavailable",
            "redaction-failed",
            "secret-leak-detected",
            "scopes-not-permitted",
            "future-refusal",
        ] {
            assert!(
                outcomes_have_failure(&[refused(reason, "sha256:test")], true),
                "dry-run suppressed {reason}"
            );
            assert!(
                outcomes_have_failure(&[refused(reason, "sha256:test")], false),
                "real submit suppressed {reason}"
            );
        }
        assert!(outcomes_have_failure(
            &[SubmitOutcome::Failed {
                reason_label: "transport".into(),
            }],
            true
        ));
    }

    /// Drives the real submit path twice and inspects what actually reached
    /// the wire.
    ///
    /// The unit test on `strip_reasoning` alone is not enough: deleting the
    /// call site in `submit_sessions` would leave it green while every
    /// submission silently carried reasoning. `--no-reasoning` is a privacy
    /// control, so its failure mode has to be caught at the boundary it
    /// actually protects.
    #[test]
    fn already_submitted_preserves_the_prior_status() {
        // A re-run reports already-submitted for every session it has seen.
        // Reporting only that is what made three re-submitted traces look
        // like three failures to a contributor and to the collector reading
        // the manifest: nothing told them the traces had been ACCEPTED the
        // first time. The prior status is in the receipt; carry it through.
        let id = Uuid::new_v4();
        let outcomes = vec![SubmitOutcome::AlreadySubmitted {
            submission_id: id,
            prior_status: "accepted".to_string(),
        }];
        let manifest = build_manifest(&outcomes);
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].submission_id, id);
        assert_eq!(
            manifest[0].status, "accepted",
            "the manifest must carry the real server status, not the literal \"already-submitted\""
        );
    }

    #[tokio::test]
    async fn no_reasoning_controls_what_reaches_the_wire() {
        async fn run(no_reasoning: bool) -> serde_json::Value {
            let received = Arc::new(Mutex::new(Vec::new()));
            let issuer = spawn(stub_issuer()).await;
            let ingest = spawn(stub_ingest(received.clone())).await;
            let dir = tempfile::tempdir().unwrap();
            let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
            let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
            let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
            let opts = SubmitOptions {
                no_reasoning,
                ..Default::default()
            };
            submit_sessions(&store, &cfg, fixture_selection(), &opts)
                .await
                .unwrap();
            let guard = received.lock().unwrap();
            guard[0].clone()
        }

        fn reasoning_events(envelope: &serde_json::Value) -> usize {
            envelope["events"]
                .as_array()
                .map(|events| {
                    events
                        .iter()
                        .filter(|e| e["event_type"] == "reasoning")
                        .count()
                })
                .unwrap_or(0)
        }

        // The committed fixture contains a thinking block, so the default
        // path must carry reasoning. If this ever reaches zero the fixture
        // stopped exercising the feature and the opt-out assertion below
        // would pass vacuously.
        let with = run(false).await;
        assert!(
            reasoning_events(&with) > 0,
            "reasoning must reach the wire by default"
        );

        let without = run(true).await;
        assert_eq!(
            reasoning_events(&without),
            0,
            "--no-reasoning must strip reasoning before upload"
        );
    }

    #[tokio::test]
    async fn submit_context_reuses_the_canary_across_sessions() {
        // The canary is a per-batch precondition, not a per-session one. A
        // daemon holding one context for weeks must not pay for -- or fail
        // on -- a fresh self-test per trace.
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        let opts = SubmitOptions {
            dry_run: true,
            machine_readable: true,
            ..Default::default()
        };
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let selection = fixture_selection();
        let (source, session_ref) = &selection[0];

        let first = ctx.submit_one(source.as_ref(), session_ref).await.unwrap();
        let second = ctx.submit_one(source.as_ref(), session_ref).await.unwrap();

        assert!(
            matches!(first, SubmitOutcome::Submitted { .. }),
            "got {first:?}"
        );
        assert!(
            matches!(second, SubmitOutcome::Submitted { .. }),
            "got {second:?}"
        );
        assert_eq!(ctx.canary_runs(), 1, "canary must not re-run per session");
    }

    #[tokio::test]
    async fn submit_loaded_sends_the_transcript_it_was_given_not_a_fresh_read() {
        // The TOCTOU the daemon's re-hash guard could not close. The
        // uploader loads and hashes the session to check it still matches
        // what the contributor approved; `submit_one` then loaded the file
        // a second, independent time, and it was *that* read -- never
        // hashed, never compared -- whose bytes went out. A session
        // appended to between the two reads passed the guard and shipped
        // content the guard had never seen.
        //
        // Here the on-disk file is rewritten after the load, so the two
        // reads would disagree. What arrives at ingest must be what was
        // handed in.
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            machine_readable: true,
            ..Default::default()
        };

        // A private copy of the fixture: this test rewrites the session
        // file, and the checked-in fixture is shared by the whole module.
        let session_root = dir.path().join("claude-root");
        let project_dir = session_root.join("-Users-testuser-code-myproj");
        std::fs::create_dir_all(&project_dir).unwrap();
        let session_path = project_dir.join("11111111-1111-1111-1111-111111111111.jsonl");
        std::fs::copy(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
                "fixtures/claude-code/-Users-testuser-code-myproj/\
                 11111111-1111-1111-1111-111111111111.jsonl",
            ),
            &session_path,
        )
        .unwrap();
        let source = crate::source::claude_code::ClaudeCodeSource::new(session_root);
        let session_ref = source.discover().unwrap().remove(0);
        let verified = source.load(&session_ref).unwrap();
        let verified_hash = verified.session_hash.clone();

        // Whatever is on disk now, it is not what was verified.
        std::fs::write(
            &session_ref.path,
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"APPENDED \
             AFTER THE GUARD RAN\"},\"cwd\":\"/Users/testuser/code/myproj\",\
             \"timestamp\":\"2026-08-08T23:00:00Z\",\"version\":\"2.0.1\",\
             \"sessionId\":\"11111111-1111-1111-1111-111111111111\",\"uuid\":\"z9\"}\n",
        )
        .unwrap();
        assert_ne!(
            source.load(&session_ref).unwrap().session_hash,
            verified_hash,
            "the fixture must actually differ, or this test proves nothing"
        );

        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let outcome = ctx.submit_loaded(verified).await.unwrap();
        assert!(
            matches!(outcome, SubmitOutcome::Submitted { .. }),
            "got {outcome:?}"
        );

        let sent = received.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let body = serde_json::to_string(&sent[0]).unwrap();
        assert!(
            !body.contains("APPENDED AFTER THE GUARD RAN"),
            "the verified bytes must be the sent bytes: {body}"
        );

        // And the receipt records the hash that was actually verified, so a
        // later dedup check is against the right content.
        let receipts = store.load_receipts().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].session_hash, verified_hash);
    }

    #[tokio::test]
    async fn submit_context_reruns_the_canary_after_invalidation() {
        // A long-lived daemon re-checks the privacy filter periodically.
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        let opts = SubmitOptions {
            dry_run: true,
            machine_readable: true,
            ..Default::default()
        };
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let selection = fixture_selection();
        let (source, session_ref) = &selection[0];

        ctx.submit_one(source.as_ref(), session_ref).await.unwrap();
        ctx.invalidate_canary();
        ctx.submit_one(source.as_ref(), session_ref).await.unwrap();

        assert_eq!(ctx.canary_runs(), 2);
    }

    #[tokio::test]
    async fn submits_fixture_session_and_is_idempotent_on_rerun() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(outcomes[0], SubmitOutcome::Submitted { .. }));
        {
            // Scope the guard: `let sent = &received.lock().unwrap()[0]` would
            // extend the MutexGuard to the end of the test and self-deadlock
            // on the re-lock after the second run.
            let received_guard = received.lock().unwrap();
            assert_eq!(received_guard.len(), 1);
            let sent = &received_guard[0];
            assert_eq!(sent["schema_version"], "ironclaw.trace_contribution.v1");
            assert!(
                !serde_json::to_string(sent)
                    .unwrap()
                    .contains("sk-fake-fixture-secret-1234")
            );
            assert_eq!(
                sent["consent"]["scopes"],
                serde_json::json!(["debugging_evaluation", "model_training"])
            );
        }

        // Second run: receipt short-circuits, no second upload.
        let outcomes2 = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(
            outcomes2[0],
            SubmitOutcome::AlreadySubmitted { .. }
        ));
        assert_eq!(received.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn remediate_quarantined_reuploads_under_same_submission_id() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest_status(received.clone(), "quarantined")).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(
            &outcomes[0],
            SubmitOutcome::Submitted { status, .. } if status == "quarantined"
        ));
        assert_eq!(received.lock().unwrap().len(), 1);

        // Default re-run still short-circuits on the quarantined receipt.
        let blocked = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(
            &blocked[0],
            SubmitOutcome::AlreadySubmitted {
                prior_status,
                ..
            } if prior_status == "quarantined"
        ));
        assert_eq!(received.lock().unwrap().len(), 1);

        // Opt-in remediation rebuilds and re-uploads the same submission_id.
        let remediate = SubmitOptions {
            remediate_quarantined: true,
            ..Default::default()
        };
        let outcomes2 = submit_sessions(&store, &cfg, fixture_selection(), &remediate)
            .await
            .unwrap();
        assert!(matches!(
            &outcomes2[0],
            SubmitOutcome::Submitted { status, .. } if status == "quarantined"
        ));
        let received_guard = received.lock().unwrap();
        assert_eq!(received_guard.len(), 2);
        assert_eq!(
            received_guard[0]["submission_id"], received_guard[1]["submission_id"],
            "remediation must keep the content-addressed submission_id"
        );
    }

    /// The residual-secret guard is a re-scan of the finished envelope with
    /// the secret detector. A survivor (a detect-then-redact bug, or a
    /// non-string payload value the string-leaf pass never visited) leaves a
    /// recognizable secret shape in the serialized envelope and trips the
    /// guard; a clean envelope does not. This exercises the helper directly:
    /// forcing a real survivor through the (now-strong) redaction pipeline is
    /// impractical, so we plant a detector-recognized secret shape
    /// (`sk-ant-...`) into a finished envelope and assert the guard catches
    /// it, plus that an unmodified redacted envelope is clean. The full
    /// submit path's clean-session Submitted behavior is covered by
    /// `submits_fixture_session_and_is_idempotent_on_rerun` against the
    /// original fixture (whose Opaque record-type markers and normal prose
    /// are not secret-shaped and never trip the guard).
    #[tokio::test]
    async fn residual_secret_guard_flags_survivor_and_passes_clean_envelope() {
        use crate::envelope::{envelope_has_residual_secret, redact_to_envelope};
        let root =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/claude-code");
        let src = crate::source::claude_code::ClaudeCodeSource::new(root);
        let r = src.discover().unwrap().remove(0);
        let transcript = src.load(&r).unwrap();

        let cfg = cfg_for(
            "https://issuer.example",
            "https://ingest.example",
            "sha256:00",
        );
        let redactor =
            trace_commons_protocol::trace_contribution::DeterministicTraceRedactor::try_default()
                .unwrap();
        let raw = build_raw_contribution_with_verdict(&transcript, &cfg, Utc::now(), None);
        let mut envelope = redact_to_envelope(&redactor, raw).await.unwrap();

        // A properly-redacted envelope has no residual secret shape.
        assert!(!envelope_has_residual_secret(&redactor, &envelope).unwrap());

        // Plant a detector-recognized secret shape into the finished
        // envelope, simulating a value that survived redaction. The re-scan
        // must catch it and the session must fail closed.
        if let Some(first) = envelope.events.first_mut() {
            first.redacted_content =
                Some("leftover sk-ant-EXPOSEDsecret0123456789abcdefghij here".to_string());
        }
        assert!(envelope_has_residual_secret(&redactor, &envelope).unwrap());
    }

    /// A credential in the `model` field (`IronclawTraceMetadata::model_name`)
    /// is refused, not masked and uploaded. Two guards now stand behind that,
    /// and this drives the *real* `submit_sessions` entrypoint end to end
    /// from a fixture on disk, so it fails if either is deleted: the metadata
    /// redaction pass refuses at `METADATA_CREDENTIAL_REFUSAL`, and the
    /// whole-envelope residual rescan (`residual_secret_refusal`, called from
    /// both submit-path call sites) catches anything that reaches the
    /// finished envelope. Both report the same wire label, because the
    /// contributor's situation is the same either way: remove it and rotate
    /// it. Without them this session would upload (`Submitted`, 1 delivery).
    #[tokio::test]
    async fn submit_sessions_refuses_session_with_secret_in_unredacted_model_field() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        // A minimal transcript whose assistant message carries a
        // detector-recognized secret shape in `model`, a field the per-field
        // redaction pass never scans.
        let fixture_root = tempfile::tempdir().unwrap();
        let project_dir = fixture_root.path().join("-tmp-secret-model-proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        let jsonl = concat!(
            r#"{"type":"user","message":{"role":"user","content":"hello"},"cwd":"/tmp/secret-model-proj","timestamp":"2026-07-01T10:00:00Z","version":"2.0.1","sessionId":"22222222-2222-2222-2222-222222222222","uuid":"a1"}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","model":"sk-ant-EXPOSEDsecret0123456789abcdefghij","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}},"cwd":"/tmp/secret-model-proj","timestamp":"2026-07-01T10:00:05Z","version":"2.0.1","uuid":"a2"}"#,
            "\n",
        );
        std::fs::write(
            project_dir.join("22222222-2222-2222-2222-222222222222.jsonl"),
            jsonl,
        )
        .unwrap();

        let src =
            crate::source::claude_code::ClaudeCodeSource::new(fixture_root.path().to_path_buf());
        let session_ref = src.discover().unwrap().remove(0);
        let selection: Vec<(
            Box<dyn crate::source::TraceSource>,
            crate::source::SessionRef,
        )> = vec![(
            Box::new(crate::source::claude_code::ClaudeCodeSource::new(
                fixture_root.path().to_path_buf(),
            )) as Box<dyn crate::source::TraceSource>,
            session_ref,
        )];

        let outcomes = submit_sessions(&store, &cfg, selection, &opts)
            .await
            .unwrap();
        match &outcomes[0] {
            SubmitOutcome::Refused { reason_label, .. } => {
                assert_eq!(reason_label, "secret-leak-detected");
            }
            other => panic!("expected Refused(secret-leak-detected), got {other:?}"),
        }
        assert_eq!(
            received.lock().unwrap().len(),
            0,
            "a session with a residual secret must never reach ingest"
        );
        assert!(store.load_receipts().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dry_run_uploads_nothing_and_writes_no_receipt() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            dry_run: true,
            ..Default::default()
        };
        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(outcomes[0], SubmitOutcome::Submitted { .. }));
        assert_eq!(received.lock().unwrap().len(), 0);
        assert!(store.load_receipts().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_filter_construction_does_not_write_notice_marker() {
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest(Arc::new(Mutex::new(Vec::new())))).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        assert!(!store.dir().join("near-ai-notice-shown").exists());

        let opts = SubmitOptions {
            dry_run: true,
            pii_filter: Some("near-ai".to_string()),
            ..Default::default()
        };
        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(
            &outcomes[0],
            SubmitOutcome::Refused { reason_label, .. }
                if reason_label == "pii-filter-unavailable"
        ));
        assert!(!store.dir().join("near-ai-notice-shown").exists());
    }

    #[tokio::test]
    async fn receipt_append_failure_preserves_prior_outcomes_and_finishes_batch() {
        let trajectory_dir = tempfile::tempdir().unwrap();
        write_test_trajectory(&trajectory_dir.path().join("a.json"), "first session");
        write_test_trajectory(&trajectory_dir.path().join("b.json"), "second session");

        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let receipt_path = store.dir().join("receipts.jsonl");
        let post_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let ingest = spawn(Router::new().route(
            "/v1/traces",
            post({
                let post_calls = post_calls.clone();
                let received = received.clone();
                move |Json(body): Json<serde_json::Value>| {
                    let post_calls = post_calls.clone();
                    let received = received.clone();
                    let receipt_path = receipt_path.clone();
                    async move {
                        received.lock().unwrap().push(body);
                        let call = post_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if call == 1 {
                            std::fs::remove_file(&receipt_path).unwrap();
                            std::fs::create_dir(&receipt_path).unwrap();
                        }
                        Json(serde_json::json!({
                            "status": "accepted",
                            "credit_points_pending": 0.0,
                            "explanation": []
                        }))
                    }
                }
            }),
        ))
        .await;
        let issuer = spawn(stub_issuer()).await;
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(
            &store,
            &cfg,
            trajectory_selection(trajectory_dir.path()),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(outcomes.len(), 2);
        assert!(matches!(outcomes[0], SubmitOutcome::Submitted { .. }));
        assert!(matches!(
            &outcomes[1],
            SubmitOutcome::Failed { reason_label } if reason_label == "receipt-write-failed"
        ));
        assert_eq!(received.lock().unwrap().len(), 2);
    }

    /// Grants strictly less than requested: config asks for
    /// debugging_evaluation + model_training, issuer grants only
    /// debugging_evaluation.
    fn stub_issuer_narrows_grant() -> Router {
        Router::new().route(
            "/v1/trace-upload-claim",
            post(|| async {
                Json(serde_json::json!({
                    "access_token": "stub-claim-jwt",
                    "token_type": "Bearer",
                    "expires_at": chrono::Utc::now() + chrono::Duration::seconds(300),
                    "expires_in": 300,
                    "consent_scopes": ["debugging_evaluation"],
                    "allowed_uses": ["debugging", "evaluation", "aggregate_analytics"],
                }))
            }),
        )
    }

    #[tokio::test]
    async fn envelope_is_stamped_with_narrowed_grant_when_server_grants_less() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_narrows_grant()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        // cfg_for requests debugging_evaluation + model_training; the stub
        // issuer grants only debugging_evaluation. The envelope must carry
        // the granted (narrower) set, never the requested one.
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(outcomes[0], SubmitOutcome::Submitted { .. }));
        let received_guard = received.lock().unwrap();
        assert_eq!(received_guard.len(), 1);
        let sent = &received_guard[0];
        assert_eq!(
            sent["consent"]["scopes"],
            serde_json::json!(["debugging_evaluation"])
        );
        let allowed_uses = sent["trace_card"]["allowed_uses"].as_array().unwrap();
        assert!(
            !allowed_uses
                .iter()
                .any(|u| u == &serde_json::json!("model_training"))
        );
    }

    /// An issuer that predates the consent_scopes/allowed_uses echo: the
    /// claim response omits both fields entirely.
    fn stub_issuer_omits_scope_echo() -> Router {
        Router::new().route(
            "/v1/trace-upload-claim",
            post(|| async {
                Json(serde_json::json!({
                    "access_token": "stub-claim-jwt",
                    "token_type": "Bearer",
                    "expires_at": chrono::Utc::now() + chrono::Duration::seconds(300),
                    "expires_in": 300,
                }))
            }),
        )
    }

    #[tokio::test]
    async fn envelope_is_stamped_with_requested_scopes_when_issuer_omits_echo() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_omits_scope_echo()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        // cfg_for requests debugging_evaluation + model_training; the stub
        // issuer's claim response has no consent_scopes/allowed_uses fields
        // at all, so the fallback must stamp the requested set verbatim.
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(outcomes[0], SubmitOutcome::Submitted { .. }));
        let received_guard = received.lock().unwrap();
        assert_eq!(received_guard.len(), 1);
        let sent = &received_guard[0];
        assert_eq!(
            sent["consent"]["scopes"],
            serde_json::json!(["debugging_evaluation", "model_training"])
        );
    }

    #[tokio::test]
    async fn scope_refusal_from_issuer_yields_refused_outcome_with_no_deliveries() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_refuses_scopes()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        match &outcomes[0] {
            SubmitOutcome::Refused { reason_label, .. } => {
                assert_eq!(reason_label, "scopes-not-permitted");
            }
            other => panic!("expected Refused(scopes-not-permitted), got {other:?}"),
        }
        assert_eq!(received.lock().unwrap().len(), 0);
        assert!(store.load_receipts().unwrap().is_empty());
    }

    #[tokio::test]
    async fn uses_refusal_from_issuer_yields_refused_outcome_with_no_deliveries() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_refuses_uses()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        match &outcomes[0] {
            SubmitOutcome::Refused { reason_label, .. } => {
                assert_eq!(reason_label, "scopes-not-permitted");
            }
            other => panic!("expected Refused(scopes-not-permitted), got {other:?}"),
        }
        assert_eq!(received.lock().unwrap().len(), 0);
        assert!(store.load_receipts().unwrap().is_empty());
    }

    /// Mints `["debugging_evaluation", "model_training"]` on the first call
    /// and the narrower `["debugging_evaluation"]` on every call after —
    /// simulating a grant narrowed between the first and second mint.
    fn stub_issuer_narrows_on_remint(mint_calls: Arc<std::sync::atomic::AtomicUsize>) -> Router {
        Router::new().route(
            "/v1/trace-upload-claim",
            post(move || {
                let mint_calls = mint_calls.clone();
                async move {
                    let n = mint_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n == 0 {
                        Json(serde_json::json!({
                            "access_token": "stub-claim-jwt",
                            "token_type": "Bearer",
                            "expires_at": chrono::Utc::now() + chrono::Duration::seconds(300),
                            "expires_in": 300,
                            "consent_scopes": ["debugging_evaluation", "model_training"],
                            "allowed_uses": ["debugging", "evaluation", "model_training", "aggregate_analytics"],
                        }))
                    } else {
                        Json(serde_json::json!({
                            "access_token": "stub-claim-jwt",
                            "token_type": "Bearer",
                            "expires_at": chrono::Utc::now() + chrono::Duration::seconds(300),
                            "expires_in": 300,
                            "consent_scopes": ["debugging_evaluation"],
                            "allowed_uses": ["debugging", "evaluation", "aggregate_analytics"],
                        }))
                    }
                }
            }),
        )
    }

    fn stub_issuer_widens_on_remint(mint_calls: Arc<std::sync::atomic::AtomicUsize>) -> Router {
        Router::new().route(
            "/v1/trace-upload-claim",
            post(move || {
                let mint_calls = mint_calls.clone();
                async move {
                    let n = mint_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let (consent_scopes, allowed_uses) = if n == 0 {
                        (
                            serde_json::json!(["debugging_evaluation"]),
                            serde_json::json!(["debugging", "evaluation", "aggregate_analytics"]),
                        )
                    } else {
                        (
                            serde_json::json!([
                                "debugging_evaluation",
                                "benchmark_only",
                                "ranking_training",
                                "model_training",
                                "public_attribution"
                            ]),
                            serde_json::json!([
                                "debugging",
                                "evaluation",
                                "benchmark_generation",
                                "ranking_model_training",
                                "model_training",
                                "aggregate_analytics"
                            ]),
                        )
                    };
                    Json(serde_json::json!({
                        "access_token": "stub-claim-jwt",
                        "token_type": "Bearer",
                        "expires_at": chrono::Utc::now() + chrono::Duration::seconds(300),
                        "expires_in": 300,
                        "consent_scopes": consent_scopes,
                        "allowed_uses": allowed_uses,
                    }))
                }
            }),
        )
    }

    /// Refuses the first POST with 401 (forcing a claim re-mint + retry) and
    /// accepts every POST after, recording every received body so the test
    /// can inspect what the *retried* request actually carried.
    fn stub_ingest_401_then_200(
        received: Arc<Mutex<Vec<serde_json::Value>>>,
        post_calls: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Router {
        use axum::response::IntoResponse;
        Router::new().route(
            "/v1/traces",
            post(move |Json(body): Json<serde_json::Value>| {
                let received = received.clone();
                let post_calls = post_calls.clone();
                async move {
                    let n = post_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    received.lock().unwrap().push(body);
                    if n == 0 {
                        axum::http::StatusCode::UNAUTHORIZED.into_response()
                    } else {
                        Json(serde_json::json!({
                            "status": "accepted",
                            "credit_points_pending": 0.0,
                            "explanation": []
                        }))
                        .into_response()
                    }
                }
            }),
        )
    }

    #[tokio::test]
    async fn envelope_is_restamped_after_claim_remint_on_auth_failure() {
        use std::sync::atomic::AtomicUsize;

        let mint_calls = Arc::new(AtomicUsize::new(0));
        let post_calls = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));

        let issuer = spawn(stub_issuer_narrows_on_remint(mint_calls.clone())).await;
        let ingest = spawn(stub_ingest_401_then_200(
            received.clone(),
            post_calls.clone(),
        ))
        .await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(
            matches!(outcomes[0], SubmitOutcome::Submitted { .. }),
            "expected Submitted after remint+retry, got {:?}",
            outcomes[0]
        );
        assert_eq!(mint_calls.load(std::sync::atomic::Ordering::SeqCst), 2);

        let received_guard = received.lock().unwrap();
        assert_eq!(
            received_guard.len(),
            2,
            "the 401 attempt and the successful retry must both reach ingest"
        );
        // The envelope actually delivered on the second (200) POST must carry
        // the NEW token's narrower grant, not the original wider one it was
        // first stamped with.
        let restamped = &received_guard[1];
        assert_eq!(
            restamped["consent"]["scopes"],
            serde_json::json!(["debugging_evaluation"]),
            "retried envelope must be restamped with the re-minted (narrower) scopes: {restamped}"
        );
        let allowed_uses = restamped["trace_card"]["allowed_uses"].as_array().unwrap();
        assert!(
            !allowed_uses
                .iter()
                .any(|u| u == &serde_json::json!("model_training")),
            "retried envelope must not retain model_training from the stale claim: {restamped}"
        );
    }

    #[tokio::test]
    async fn post_remint_size_overflow_is_a_structured_refusal() {
        use std::sync::atomic::AtomicUsize;

        let trajectory_dir = tempfile::tempdir().unwrap();
        let trajectory_path = trajectory_dir.path().join("boundary.json");
        let base_content_len = 1_496_000usize;
        write_test_trajectory(&trajectory_path, &"x".repeat(base_content_len));

        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let mint_calls = Arc::new(AtomicUsize::new(0));
        let post_calls = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_widens_on_remint(mint_calls.clone())).await;
        let ingest = spawn(stub_ingest_401_then_200(
            received.clone(),
            post_calls.clone(),
        ))
        .await;
        let mut cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        cfg.consent_scopes = vec!["debugging_evaluation".to_string()];
        let narrow_token = ClaimToken {
            access_token: "narrow".to_string(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            consent_scopes: vec!["debugging_evaluation".to_string()],
            allowed_uses: vec![
                "debugging".to_string(),
                "evaluation".to_string(),
                "aggregate_analytics".to_string(),
            ],
        };
        let wide_token = ClaimToken {
            access_token: "wide".to_string(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            consent_scopes: crate::consent::VALID_SCOPES
                .iter()
                .map(|scope| scope.to_string())
                .collect(),
            allowed_uses: crate::consent::scopes_to_allowed_uses(
                &crate::consent::VALID_SCOPES
                    .iter()
                    .map(|scope| scope.to_string())
                    .collect::<Vec<_>>(),
            ),
        };

        let initial =
            narrow_boundary_envelope(&trajectory_path, base_content_len, &cfg, &narrow_token).await;
        let target_size = MAX_ENVELOPE_BYTES - 64;
        let initial_size = envelope_size(&initial).unwrap();
        let calibrated_len = if initial_size <= target_size {
            base_content_len + (target_size - initial_size)
        } else {
            base_content_len - (initial_size - target_size)
        };
        let narrow =
            narrow_boundary_envelope(&trajectory_path, calibrated_len, &cfg, &narrow_token).await;
        let narrow_size = envelope_size(&narrow).unwrap();
        let mut wide = narrow.clone();
        stamp_granted_scopes(&mut wide, &cfg, &wide_token);
        let wide_size = envelope_size(&wide).unwrap();
        assert_eq!(narrow_size, target_size);
        assert!(wide_size > MAX_ENVELOPE_BYTES);

        let opts = SubmitOptions {
            ..Default::default()
        };
        let outcomes = submit_sessions(
            &store,
            &cfg,
            trajectory_selection(trajectory_dir.path()),
            &opts,
        )
        .await
        .unwrap();

        match &outcomes[0] {
            SubmitOutcome::Refused {
                reason_label,
                size_bytes,
                limit_bytes,
                ..
            } => {
                assert_eq!(reason_label, "session-too-large");
                assert!(size_bytes.unwrap() > MAX_ENVELOPE_BYTES);
                assert_eq!(*limit_bytes, Some(MAX_ENVELOPE_BYTES));
            }
            other => panic!("expected structured size refusal, got {other:?}"),
        }
        assert_eq!(mint_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(post_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Records every claim-request body it receives (as raw JSON) before
    /// responding with a fixed claim, so tests can inspect what scopes/uses
    /// were actually requested.
    fn stub_issuer_recording_requests(received: Arc<Mutex<Vec<serde_json::Value>>>) -> Router {
        Router::new().route(
            "/v1/trace-upload-claim",
            post(move |body: String| {
                let received = received.clone();
                async move {
                    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                    received.lock().unwrap().push(parsed);
                    Json(serde_json::json!({
                        "access_token": "stub-claim-jwt",
                        "token_type": "Bearer",
                        "expires_at": chrono::Utc::now() + chrono::Duration::seconds(300),
                        "expires_in": 300,
                        "consent_scopes": ["debugging_evaluation", "model_training"],
                        "allowed_uses": ["debugging", "evaluation", "model_training", "aggregate_analytics"],
                    }))
                }
            }),
        )
    }

    fn stub_submission_status_ingest() -> Router {
        Router::new().route(
            "/v1/contributors/me/submission-status",
            post(|Json(req): Json<serde_json::Value>| async move {
                let ids = req["submission_ids"].as_array().unwrap();
                let updates: Vec<serde_json::Value> = ids
                    .iter()
                    .map(|id| {
                        serde_json::json!({
                            "submission_id": id,
                            "trace_id": id,
                            "status": "accepted",
                            "credit_points_pending": 0.0,
                        })
                    })
                    .collect();
                Json(updates)
            }),
        )
    }

    #[tokio::test]
    async fn status_mints_claim_with_empty_scopes_and_uses() {
        let claim_requests = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_recording_requests(claim_requests.clone())).await;
        let ingest = spawn(stub_submission_status_ingest()).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);

        // Seed a receipt so status() actually mints a claim and calls out.
        store
            .append_receipt(&crate::config::Receipt {
                submission_id: Uuid::new_v4(),
                session_hash: "sha256:test".to_string(),
                source: "claude-code".to_string(),
                submitted_at: Utc::now(),
                status: "submitted".to_string(),
            })
            .unwrap();

        let updates = status(&store, &cfg).await.unwrap();
        assert_eq!(updates.len(), 1);

        let requests = claim_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(
            req["consent_scopes"],
            serde_json::json!([]),
            "status claim request must not request the submit-path's scopes: {req}"
        );
        assert_eq!(
            req["allowed_uses"],
            serde_json::json!([]),
            "status claim request must not request the submit-path's uses: {req}"
        );
    }

    /// Records the method and body of every /v1/community/profile call.
    fn stub_community_profile_ingest(seen: Arc<Mutex<Vec<(String, String)>>>) -> Router {
        Router::new().route(
            "/v1/community/profile",
            axum::routing::put({
                let seen = seen.clone();
                move |body: String| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push(("PUT".to_string(), body));
                        Json(serde_json::json!({
                            "display_handle": "stub_handle",
                            "handle_normalized": "stub_handle",
                            "bio": null,
                            "public_since": chrono::Utc::now(),
                            "last_updated_at": chrono::Utc::now(),
                            "update_count": 0,
                        }))
                    }
                }
            })
            .delete(move |body: String| {
                let seen = seen.clone();
                async move {
                    seen.lock().unwrap().push(("DELETE".to_string(), body));
                    axum::http::StatusCode::NO_CONTENT
                }
            }),
        )
    }

    #[tokio::test]
    async fn set_profile_mints_an_empty_scope_claim() {
        // Same property `status` relies on: an empty request resolves to the
        // caller's full grant ceiling, so claiming a handle does not depend
        // on whichever scopes were narrowed for the last submission.
        let claim_requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_recording_requests(claim_requests.clone())).await;
        let ingest = spawn(stub_community_profile_ingest(seen.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);

        let profile = set_profile(&store, &cfg, "stub_handle", None)
            .await
            .unwrap();
        assert_eq!(profile.display_handle, "stub_handle");

        let requests = claim_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["consent_scopes"], serde_json::json!([]));
        assert_eq!(requests[0]["allowed_uses"], serde_json::json!([]));

        let calls = seen.lock().unwrap();
        assert_eq!(calls[0].0, "PUT");
        let body: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
        assert_eq!(body["display_handle"], "stub_handle");
        // Omitting the key is NOT a way to preserve an existing bio: the
        // server deserializes missing and null identically to None and then
        // upserts `bio = excluded.bio`, so either form clears it. An earlier
        // version of this test asserted the opposite. The protection against
        // clearing a bio by accident lives in the command layer, which
        // requires --bio or --no-bio; this only pins the wire shape.
        assert!(
            body.get("bio").is_none(),
            "bio must be omitted from the body when not set: {body}"
        );
    }

    #[tokio::test]
    async fn clear_profile_sends_a_bodyless_delete() {
        let claim_requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_recording_requests(claim_requests.clone())).await;
        let ingest = spawn(stub_community_profile_ingest(seen.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);

        clear_profile(&store, &cfg).await.unwrap();

        let calls = seen.lock().unwrap();
        assert_eq!(calls[0].0, "DELETE");
        assert!(
            calls[0].1.is_empty(),
            "withdrawal must not send a JSON body: {:?}",
            calls[0].1
        );
    }

    #[tokio::test]
    async fn upload_refuses_ingest_host_off_allowlist_before_any_request() {
        let received = Arc::new(Mutex::new(Vec::new()));
        // Issuer stays on the literal `127.0.0.1` host (allowed); ingest is
        // addressed via `localhost` (not on the allowlist), so the claim
        // mints fine but the ingest client must refuse to even build.
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn_as_localhost(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        cfg.allowed_hosts = Some("127.0.0.1".to_string());
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        match &outcomes[0] {
            SubmitOutcome::Failed { reason_label } => {
                assert_eq!(reason_label, "host-not-allowed");
            }
            other => panic!("expected Failed(host-not-allowed), got {other:?}"),
        }
        assert_eq!(received.lock().unwrap().len(), 0);
        assert!(store.load_receipts().unwrap().is_empty());
    }

    #[test]
    fn build_manifest_includes_only_delivered_ids() {
        let u1 = Uuid::new_v4();
        let u2 = Uuid::new_v4();
        let outcomes = vec![
            SubmitOutcome::Submitted {
                submission_id: u1,
                status: "submitted".to_string(),
            },
            SubmitOutcome::AlreadySubmitted {
                submission_id: u2,
                prior_status: "quarantined".to_string(),
            },
            refused("secret-leak-detected", "sha256:test"),
            SubmitOutcome::Failed {
                reason_label: "claim-mint-failed".to_string(),
            },
            SubmitOutcome::SkippedParseFailure {
                reason_label: "parse-failed".to_string(),
            },
        ];

        let manifest = build_manifest(&outcomes);

        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest[0].submission_id, u1);
        assert_eq!(manifest[0].status, "submitted");
        assert_eq!(manifest[1].submission_id, u2);
        // Previously the literal "already-submitted". A collector reading the
        // manifest could not distinguish an accepted trace from a quarantined
        // one, so a contributor's re-run looked like a batch of failures.
        assert_eq!(manifest[1].status, "quarantined");
    }

    #[tokio::test]
    async fn submit_sessions_outcomes_round_trip_through_manifest_file() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer()).await;
        let ingest = spawn(stub_ingest(received.clone())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);
        let opts = SubmitOptions {
            ..Default::default()
        };

        let outcomes = submit_sessions(&store, &cfg, fixture_selection(), &opts)
            .await
            .unwrap();
        assert!(matches!(outcomes[0], SubmitOutcome::Submitted { .. }));

        let entries = build_manifest(&outcomes);
        let manifest_path = tempfile::NamedTempFile::new().unwrap();
        let json = serde_json::to_string_pretty(&entries).unwrap();
        std::fs::write(manifest_path.path(), json).unwrap();

        let read_back = std::fs::read_to_string(manifest_path.path()).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&read_back).unwrap();
        assert_eq!(parsed.len(), 1);
        let SubmitOutcome::Submitted { submission_id, .. } = &outcomes[0] else {
            unreachable!()
        };
        assert_eq!(
            parsed[0]["submission_id"],
            serde_json::Value::String(submission_id.to_string())
        );
        assert_eq!(parsed[0]["status"], "accepted");
    }
    /// A scoped-attestation ingest stub whose `pending` count drains by one
    /// on every call, so a test can watch the bounded wait poll.
    fn stub_scoped_attestation_ingest(
        calls: Arc<Mutex<Vec<serde_json::Value>>>,
        pending_for_call: Vec<usize>,
    ) -> Router {
        Router::new().route(
            "/v1/contributors/me/score-attestation",
            post(move |Json(req): Json<serde_json::Value>| {
                let calls = calls.clone();
                let pending_for_call = pending_for_call.clone();
                async move {
                    let requested = req["submission_ids"].as_array().unwrap().len();
                    let call_index = {
                        let mut calls = calls.lock().unwrap();
                        calls.push(req.clone());
                        calls.len() - 1
                    };
                    let pending = *pending_for_call
                        .get(call_index)
                        .unwrap_or(pending_for_call.last().unwrap_or(&0));
                    let pending = pending.min(requested);
                    Json(serde_json::json!({
                        "attestation": format!("header.payload-{call_index}.signature"),
                        "scored": requested - pending,
                        "pending": pending,
                        "unknown": 0,
                    }))
                }
            }),
        )
    }

    /// The bounded wait polls until nothing is pending, then writes the
    /// attestation it was given last.
    #[tokio::test]
    async fn attest_out_waits_for_pending_to_empty_then_writes() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_recording_requests(Arc::new(Mutex::new(
            Vec::new(),
        ))))
        .await;
        let ingest = spawn(stub_scoped_attestation_ingest(calls.clone(), vec![2, 1, 0])).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);

        let ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        let out = dir.path().join("attestation.jws");
        let outcome = emit_scoped_attestation(
            &store,
            &cfg,
            &ids,
            &out,
            std::time::Duration::from_secs(10),
            std::time::Duration::from_millis(1),
        )
        .await
        .expect("attestation emitted");

        assert_eq!(outcome.requested, 2);
        assert_eq!(outcome.scored, 2);
        assert_eq!(outcome.pending, 0);
        assert_eq!(
            calls.lock().unwrap().len(),
            3,
            "polled until nothing pending"
        );
        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(written.trim(), "header.payload-2.signature");
    }

    /// On timeout the attestation is still written and the outcome reports
    /// what it does not cover. `submit` must not fail here: the traces are
    /// uploaded and the receipts written, and the artifact is truthful about
    /// the part that is still waiting.
    #[tokio::test]
    async fn attest_out_on_timeout_still_writes_and_reports_pending() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_recording_requests(Arc::new(Mutex::new(
            Vec::new(),
        ))))
        .await;
        let ingest = spawn(stub_scoped_attestation_ingest(calls.clone(), vec![1])).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);

        let ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        let out = dir.path().join("attestation.jws");
        let outcome = emit_scoped_attestation(
            &store,
            &cfg,
            &ids,
            &out,
            std::time::Duration::from_millis(30),
            std::time::Duration::from_millis(1),
        )
        .await
        .expect("a timed-out attestation is still emitted");

        assert_eq!(outcome.scored, 1);
        assert_eq!(outcome.pending, 1);
        assert!(out.exists(), "the attestation is written on timeout too");
        assert_eq!(
            outcome.progress_line(),
            "1 of 2 traces scored, 1 pending",
            "the timeout line names the shortfall without failing the submit"
        );
    }

    /// A failed attestation fetch is a warning, not a submit failure: the
    /// caller gets `None` and nothing is written.
    #[tokio::test]
    async fn attest_out_reports_a_failed_fetch_as_none_rather_than_an_error() {
        let issuer = spawn(stub_issuer_recording_requests(Arc::new(Mutex::new(
            Vec::new(),
        ))))
        .await;
        let ingest = spawn(Router::new().route(
            "/v1/contributors/me/score-attestation",
            post(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
        ))
        .await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);

        let out = dir.path().join("attestation.jws");
        let outcome = emit_scoped_attestation(
            &store,
            &cfg,
            &[Uuid::new_v4()],
            &out,
            std::time::Duration::from_millis(30),
            std::time::Duration::from_millis(1),
        )
        .await;
        assert!(outcome.is_none(), "a failed fetch does not fail the submit");
        assert!(
            !out.exists(),
            "nothing is written when there is nothing to write"
        );
    }

    /// More ids than the server's per-request cap are split across requests
    /// rather than silently truncated: every submitted trace is attested to
    /// by one of the documents in the file.
    #[tokio::test]
    async fn attest_out_splits_id_lists_past_the_server_cap() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let issuer = spawn(stub_issuer_recording_requests(Arc::new(Mutex::new(
            Vec::new(),
        ))))
        .await;
        let ingest = spawn(stub_scoped_attestation_ingest(calls.clone(), vec![0])).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer, &ingest, &device.device_key_id);

        let ids: Vec<Uuid> = (0..SCORE_ATTESTATION_REQUEST_CHUNK + 1)
            .map(|_| Uuid::new_v4())
            .collect();
        let out = dir.path().join("attestation.jws");
        let outcome = emit_scoped_attestation(
            &store,
            &cfg,
            &ids,
            &out,
            std::time::Duration::from_secs(10),
            std::time::Duration::from_millis(1),
        )
        .await
        .expect("attestation emitted");

        assert_eq!(outcome.requested, SCORE_ATTESTATION_REQUEST_CHUNK + 1);
        assert_eq!(outcome.scored, SCORE_ATTESTATION_REQUEST_CHUNK + 1);
        let sizes: Vec<usize> = calls
            .lock()
            .unwrap()
            .iter()
            .map(|req| req["submission_ids"].as_array().unwrap().len())
            .collect();
        assert_eq!(sizes, vec![SCORE_ATTESTATION_REQUEST_CHUNK, 1]);
        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(
            written.lines().count(),
            2,
            "one signed document per chunk, newline-delimited"
        );
    }

    // -----------------------------------------------------------------
    // Task 6: the witness at the envelope-build site.
    // -----------------------------------------------------------------

    const WITNESS_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    fn pinned_witness() -> WitnessSettings {
        WitnessSettings {
            admission_evidence: false,
            url: "http://witness.invalid".into(),
            signing_address: WITNESS_ADDRESS.into(),
            expected_measurements: vec![format!(
                "mrtd={},mrconfigid={}",
                "aa".repeat(48),
                "bb".repeat(48)
            )],
        }
    }

    fn unpinned_witness() -> WitnessSettings {
        WitnessSettings {
            admission_evidence: false,
            expected_measurements: Vec::new(),
            ..pinned_witness()
        }
    }

    /// Run one submission against unreachable endpoints and report the label.
    ///
    /// Both the issuer and the witness are `.invalid`, so which refusal comes
    /// back is a statement about ORDER: a refusal naming the issuer means the
    /// mint ran first, and one naming the pin means the pin was judged before
    /// the mint.
    async fn witnessed_refusal(witness: Option<WitnessSettings>) -> SubmitOutcome {
        let (_sd, store) = crate::config::tests_support::temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        cfg.witness = witness;
        let opts = SubmitOptions {
            dry_run: true,
            machine_readable: true,
            ..Default::default()
        };
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let selection = fixture_selection();
        let (source, session_ref) = &selection[0];
        ctx.submit_one(source.as_ref(), session_ref).await.unwrap()
    }

    fn refusal_label_of(outcome: &SubmitOutcome) -> String {
        match outcome {
            SubmitOutcome::Refused { reason_label, .. } => reason_label.clone(),
            SubmitOutcome::Failed { reason_label } => reason_label.clone(),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// An attestable call, built through the real reader.
    fn receipt_fixture_call() -> (crate::routing::attested::AttestedCall, tempfile::TempDir) {
        receipt_fixture_call_with_request("{\"model\":\"Qwen/Qwen3.6-27B-FP8\"}")
    }
    fn receipt_fixture_call_with_request(
        request: &str,
    ) -> (crate::routing::attested::AttestedCall, tempfile::TempDir) {
        use sha2::Digest as _;

        const RESPONSE: &str = "data: [DONE]\n\n";

        let dir = tempfile::tempdir().expect("a temporary body store");
        let reference = "00000000000000000011-000000";
        std::fs::write(dir.path().join(format!("{reference}.req")), request).expect("req");
        std::fs::write(dir.path().join(format!("{reference}.res")), RESPONSE).expect("res");

        let row = crate::routing::RoutedExchange {
            id: Some(11),
            started_at: chrono::Utc::now(),
            client_session_id: Some("session".to_string()),
            total_ms: Some(10),
            facade: "openai".to_string(),
            backend: "nearai".to_string(),
            requested_model: Some("Qwen/Qwen3.6-27B-FP8".to_string()),
            served_model: Some("Qwen/Qwen3.6-27B-FP8".to_string()),
            upstream_id: Some("chatcmpl-abc123".to_string()),
            request_sha256: Some(hex::encode(sha2::Sha256::digest(request.as_bytes()))),
            response_sha256: Some(hex::encode(sha2::Sha256::digest(RESPONSE.as_bytes()))),
            body_ref: Some(reference.to_string()),
            rung: "full".to_string(),
            attempts: 1,
            input_tokens: Some(1),
            cache_read_tokens: None,
            cache_write_tokens: None,
            output_tokens: Some(1),
            cost_usd: Some(0.0),
            status: 200,
        };
        let call = crate::routing::attested::attested_final_call(&[row], dir.path())
            .expect("the fixture must be attestable, or these tests prove nothing");
        (call, dir)
    }

    #[test]
    fn window_profile_is_selected_from_source_before_receipt_fetch() {
        use trace_commons_protocol::admission::REQUEST_METADATA_KEY;
        assert_eq!(admission_profile_for_request(true, None), Ok(false));
        for legacy in [
            r#"{"model":"old-provider"}"#,
            r#"{"metadata":null}"#,
            r#"{"metadata":{"other":"value"}}"#,
        ] {
            assert_eq!(admission_profile_for_request(true, Some(legacy)), Ok(false));
        }
        for marker in [
            serde_json::json!("tcad1:invalid"),
            serde_json::Value::Null,
            serde_json::json!(42),
        ] {
            let body = serde_json::json!({"metadata":{REQUEST_METADATA_KEY:marker}}).to_string();
            assert_eq!(
                admission_profile_for_request(true, Some(&body)),
                Ok(true),
                "a malformed marker cannot downgrade"
            );
        }
        assert!(admission_profile_for_request(true, Some("not JSON")).is_err());
        assert!(admission_profile_for_request(true, Some(r#"{"metadata":"malformed"}"#)).is_err());
        assert_eq!(
            admission_profile_for_request(false, Some("not JSON")),
            Ok(false),
            "invited configuration keeps its existing policy"
        );
    }

    #[test]
    fn the_inference_record_is_written_from_what_was_offered_not_what_was_wanted() {
        use crate::witness::inference_record::{
            InferenceAttestationRecord, REASON_NO_ATTESTED_CALL, REASON_RECEIPT_UNAVAILABLE,
        };
        let (call, _dir) = receipt_fixture_call();
        let receipt = stand_in_receipt();
        assert_eq!(
            inference_attestation_for(None, None),
            InferenceAttestationRecord::uncertified(REASON_NO_ATTESTED_CALL)
        );
        // The failure mode this exists for: an attested call whose receipt
        // could not be fetched used to ship with every surface reading
        // "attested". It is uncertified, by name.
        assert_eq!(
            inference_attestation_for(Some(&call), None),
            InferenceAttestationRecord::uncertified(REASON_RECEIPT_UNAVAILABLE)
        );
        assert_eq!(
            inference_attestation_for(Some(&call), Some(&receipt)),
            InferenceAttestationRecord::certified()
        );
        assert!(
            !inference_attestation_for(None, Some(&receipt)).is_certified(),
            "a receipt with no call to bind it is not attested inference"
        );
    }

    #[tokio::test]
    async fn admission_review_without_body_consent_refuses_before_claim_or_witness() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        cfg.witness = Some(WitnessSettings {
            admission_evidence: true,
            ..pinned_witness()
        });
        let opts = SubmitOptions {
            dry_run: false,
            pii_filter: None,
            no_reasoning: false,
            machine_readable: true,
            unenrolled_preview: false,
            remediate_quarantined: false,
            verdict: None,
        };
        let mut context = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let selection = fixture_selection();
        let (source, reference) = &selection[0];
        let transcript = source.load(reference).unwrap();
        let error = context
            .prepare_witnessed_review(&transcript, None, false)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "admission_receipt_unavailable");
    }

    /// A correction has nowhere to go on this profile, and a contributor is
    /// told so rather than shown an entry that reads approved-with-correction
    /// over a certified envelope carrying neither. Refused before the claim
    /// mint and before anything reaches a witness.
    #[tokio::test]
    async fn a_correction_the_admission_profile_cannot_carry_is_refused_by_name() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        cfg.witness = Some(WitnessSettings {
            admission_evidence: true,
            ..pinned_witness()
        });
        let selection = fixture_selection();
        let (source, reference) = &selection[0];
        let transcript = source.load(reference).unwrap();

        for (verdict, correction) in [
            (None, Some("the model dropped the last hunk")),
            (Some(crate::envelope::ContributorVerdict::Worked), None),
        ] {
            let opts = SubmitOptions {
                verdict,
                ..review_options()
            };
            let mut context = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
            let error = context
                .prepare_witnessed_review(&transcript, correction, true)
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), "admission_correction_unsupported");
        }

        // Blank is not a correction, and the invited profile is untouched:
        // both must get past this refusal to the one that comes next.
        let opts = review_options();
        let mut context = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let error = context
            .prepare_witnessed_review(&transcript, Some("   "), true)
            .await
            .unwrap_err();
        assert_ne!(error.to_string(), "admission_correction_unsupported");
        cfg.witness.as_mut().unwrap().admission_evidence = false;
        let mut context = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let error = context
            .prepare_witnessed_review(&transcript, Some("a real correction"), false)
            .await
            .unwrap_err();
        assert_ne!(error.to_string(), "admission_correction_unsupported");
    }

    #[tokio::test]
    async fn bound_receipt_fetch_failure_cannot_turn_into_a_window_review() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let witness_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let receipt_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let receipt_address = receipt_listener.local_addr().unwrap();
        drop(receipt_listener); // Deterministic loopback connection refusal, no provider call.
        let mut cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        cfg.allowed_hosts = Some("127.0.0.1".into());
        cfg.inference_receipt_endpoint = Some(format!("https://{receipt_address}/v1"));
        let settings = WitnessSettings {
            admission_evidence: true,
            url: format!("http://{}", witness_listener.local_addr().unwrap()),
            ..pinned_witness()
        };
        cfg.witness = Some(settings.clone());
        let opts = SubmitOptions {
            dry_run: false,
            pii_filter: None,
            no_reasoning: false,
            machine_readable: true,
            unenrolled_preview: false,
            remediate_quarantined: false,
            verdict: None,
        };
        let ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let selection = fixture_selection();
        let (source, reference) = &selection[0];
        let transcript = source.load(reference).unwrap();
        let raw = build_raw_contribution_with_verdict(&transcript, &cfg, Utc::now(), None);
        let request = r#"{"model":"Qwen/Qwen3.6-27B-FP8","metadata":{"trace_commons_admission":"tcad1:bound-call"}}"#;
        let (call, _bodies) = receipt_fixture_call_with_request(request);
        let token = ClaimToken {
            access_token: "fixture".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            consent_scopes: vec!["debugging_evaluation".into()],
            allowed_uses: vec!["debugging".into()],
        };
        let error = ctx
            .witness_envelope(&settings, raw, Some(&call), &token, Utc::now())
            .await
            .unwrap_err();
        assert_eq!(error, "admission_receipt_unavailable");
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                witness_listener.accept()
            )
            .await
            .is_err(),
            "failed receipt fetch cannot send raw bodies to either witness route"
        );
    }

    /// A receipt shaped like a fetched one. Not verifiable, and it does not
    /// need to be: the enclave verifies receipts, and what this test needs is
    /// for the fetch to succeed so the code under it runs.
    fn stand_in_receipt() -> trace_commons_attestation::receipt::ReceiptPayload {
        use trace_commons_attestation::receipt::{ReceiptAlgo, ReceiptSignatureKind};
        trace_commons_attestation::receipt::ReceiptPayload {
            text: "aaaa1111:bbbb2222".to_string(),
            signature: "0xcccc3333".to_string(),
            signing_address: "0xdddd444444444444444444444444444444444444".to_string(),
            signing_algo: ReceiptAlgo::Ecdsa,
            signature_kind: ReceiptSignatureKind::Unrecognised,
        }
    }

    /// The projection is wired into the production path, not merely written.
    ///
    /// `witness_envelope` cannot be driven to the wire in-process:
    /// `witness_session` verifies a real TDX quote before it offers anything
    /// and no test holds one. What it can be driven to is the size bound that
    /// sits ahead of the attestation fetch, and that bound is enough of an
    /// observable. An oversized session refuses `witness_payload_too_large`
    /// when it reaches the witness whole; the admission projection discards
    /// the event list, so the same session clears that bound and refuses on
    /// the unreachable attestation instead. Drop the projection from the call
    /// site and the admission half reports the size refusal, because the
    /// history it was supposed to have isolated is still attached.
    ///
    /// The invited half is the control: it is the same session, the same
    /// call, the same everything but the profile, and it must still refuse on
    /// size -- a projection applied unconditionally would be a different
    /// defect.
    #[tokio::test]
    async fn the_admission_call_site_projects_before_anything_is_offered() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let unreachable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let witness_address = unreachable.local_addr().unwrap();
        drop(unreachable); // Deterministic loopback refusal; nothing is served.
        let mut cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        cfg.allowed_hosts = Some("127.0.0.1".into());
        let opts = review_options();
        let selection = fixture_selection();
        let (source, reference) = &selection[0];
        let transcript = source.load(reference).unwrap();
        let mut raw = crate::envelope::build_raw_contribution_with_correction(
            &transcript,
            &cfg,
            Utc::now(),
            None,
            None,
        );
        let mut oversized = raw.events[0].clone();
        oversized.content = Some("x".repeat(crate::envelope::MAX_ENVELOPE_BYTES + 1_000_000));
        raw.events.push(oversized);
        assert!(
            crate::envelope::raw_contribution_size(&raw).unwrap()
                > crate::envelope::MAX_ENVELOPE_BYTES,
            "the session must exceed the bound, or this test observes nothing"
        );
        let request = r#"{"model":"Qwen/Qwen3.6-27B-FP8","metadata":{"trace_commons_admission":"tcad1:bound-call"}}"#;
        let (call, _bodies) = receipt_fixture_call_with_request(request);
        let token = ClaimToken {
            access_token: "fixture".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            consent_scopes: vec!["debugging_evaluation".into()],
            allowed_uses: vec!["debugging".into()],
        };

        let mut labels = Vec::new();
        for admission_evidence in [true, false] {
            let settings = WitnessSettings {
                admission_evidence,
                url: format!("http://{witness_address}"),
                ..pinned_witness()
            };
            let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
            ctx.receipt_override = Some(stand_in_receipt());
            labels.push(
                ctx.witness_envelope(&settings, raw.clone(), Some(&call), &token, Utc::now())
                    .await
                    .unwrap_err(),
            );
        }
        assert_eq!(
            labels,
            vec![
                "witness_attestation_unavailable",
                "witness_payload_too_large"
            ],
            "the admission profile must reach the witness carrying only the bound call, \
             and the invited profile must be left alone"
        );
    }

    /// Nothing is fetched when no endpoint is configured, and the answer is
    /// an absent receipt rather than an error.
    #[tokio::test]
    async fn no_configured_endpoint_yields_no_receipt() {
        let (_sd, store) = crate::config::tests_support::temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        let opts = SubmitOptions {
            dry_run: true,
            machine_readable: true,
            ..Default::default()
        };
        let ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let (call, _dir) = receipt_fixture_call();

        assert!(
            ctx.inference_receipt_for(&call).await.is_err(),
            "an unconfigured endpoint must not produce a receipt"
        );
    }

    /// And an endpoint the operator's allowlist excludes yields no receipt
    /// too -- an `Err`, never a panic. The `Err` is non-fatal: `witness_envelope`
    /// turns it into a `ReceiptShipped::Omitted` and the submission still
    /// ships unattested.
    ///
    /// This is the behaviour the whole design turns on: a receipt that cannot
    /// be obtained makes a submission unattested, and the witness decides
    /// whether unattested is acceptable. Failing the submission here would
    /// throw away a contribution over somebody else's outage.
    #[tokio::test]
    async fn an_unfetchable_receipt_is_an_absent_one_and_not_a_failure() {
        let (_sd, store) = crate::config::tests_support::temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        cfg.inference_receipt_endpoint = Some("https://receipts.invalid/v1".to_string());
        cfg.allowed_hosts = Some("issuer.invalid,ingest.invalid".to_string());
        let opts = SubmitOptions {
            dry_run: true,
            machine_readable: true,
            ..Default::default()
        };
        let ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let (call, _dir) = receipt_fixture_call();

        assert!(
            ctx.inference_receipt_for(&call).await.is_err(),
            "an unreachable or disallowed endpoint must yield no receipt, not an error"
        );
    }

    #[tokio::test]
    async fn an_unconfigured_client_takes_the_local_path_and_does_not_refuse_for_a_witness() {
        // The default path is untouched by the feature. A dry run with no
        // witness reaches the dry-run return, which means the envelope was
        // built locally -- there is no other way to get there.
        let outcome = witnessed_refusal(None).await;
        assert!(
            matches!(outcome, SubmitOutcome::Submitted { .. }),
            "the witness feature changed the default path: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_witness_url_without_a_pin_refuses_the_submission() {
        let outcome = witnessed_refusal(Some(unpinned_witness())).await;
        assert_eq!(
            refusal_label_of(&outcome),
            "witness_expected_measurement",
            "an unpinned witness must refuse, never quietly redact locally"
        );
    }

    #[tokio::test]
    async fn a_malformed_pin_is_refused_under_its_own_name() {
        // Distinct from the unpinned case: a contributor who mistyped a
        // measurement should not be told they configured none.
        let mut settings = pinned_witness();
        settings.expected_measurements = vec!["mrtd=nothex".to_string()];
        let outcome = witnessed_refusal(Some(settings)).await;
        assert_eq!(
            refusal_label_of(&outcome),
            "witness_expected_measurement_malformed"
        );
    }

    #[tokio::test]
    async fn a_witnessed_submission_mints_its_claim_before_it_sends_anything_raw() {
        // Both endpoints are unreachable. A pinned witness therefore fails at
        // whichever step runs first, and the label says which: `claim-mint-
        // failed` means the mint preceded the witness call. If the order
        // inverted, this would come back as a witness transport refusal
        // instead -- which is exactly the bug, because the grants would then
        // have to be stamped after certification.
        let outcome = witnessed_refusal(Some(pinned_witness())).await;
        assert_eq!(
            refusal_label_of(&outcome),
            "claim-mint-failed",
            "grants must be inside the certified bytes, not stamped after"
        );
    }

    #[tokio::test]
    async fn an_approved_envelope_under_a_configured_witness_refuses_rather_than_uploading_bare() {
        // The preview path refuses to build an envelope under a configured
        // witness, so an approved one here predates the configuration. Sending
        // it would be an uncertified submission from a contributor who
        // believes their submissions are certified.
        let (_sd, store) = crate::config::tests_support::temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let mut cfg = cfg_for(
            "http://issuer.invalid",
            "http://ingest.invalid",
            &device.device_key_id,
        );
        cfg.witness = Some(pinned_witness());
        let opts = SubmitOptions {
            dry_run: true,
            machine_readable: true,
            ..Default::default()
        };
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();

        // An envelope built locally, as the previous release's preview would
        // have left in the queue.
        let selection = fixture_selection();
        let (source, session_ref) = &selection[0];
        let transcript = source.load(session_ref).unwrap();
        let redactor = build_redactor_with(&cfg, transcript.cwd.as_deref(), None).unwrap();
        let raw = build_raw_contribution_with_verdict(&transcript, &cfg, Utc::now(), None);
        let approved = redact_to_envelope(&redactor, raw).await.unwrap();
        ctx.use_approved_envelope(Some(approved));

        let outcome = ctx.submit_one(source.as_ref(), session_ref).await.unwrap();
        assert_eq!(refusal_label_of(&outcome), "witness_certificate_missing");
    }

    #[test]
    fn a_config_written_before_this_release_loads_with_no_witness() {
        // `#[serde(default)]` on the field is load-bearing, not decorative:
        // this struct is read from a file the previous release wrote, and that
        // file has no `witness` key. Without the attribute every existing
        // contributor's config would fail to parse on upgrade.
        let previous_release = serde_json::json!({
            "schema_version": crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION,
            "issuer_url": "https://issuer.example",
            "ingest_url": "https://ingest.example",
            "audience": "trace-commons-upload",
            "tenant_id": "tenant-abc",
            "instance_id": "instance-1",
            "user_subject": "alice",
            "device_key_id": "device-1",
            "consent_scopes": ["debugging_evaluation"],
            "pii_filter": serde_json::Value::Null,
            "allowed_hosts": serde_json::Value::Null,
        });
        let cfg: ContributorConfig = serde_json::from_value(previous_release)
            .expect("a config written before the witness field must still load");
        assert!(cfg.witness.is_none(), "absent must mean off");
    }

    #[test]
    fn witness_settings_parse_every_pinned_set_and_refuse_a_bad_one() {
        let settings = WitnessSettings {
            admission_evidence: false,
            expected_measurements: vec![
                format!("mrtd={},mrconfigid={}", "aa".repeat(48), "bb".repeat(48)),
                format!("mrtd={},mrconfigid={}", "aa".repeat(48), "cc".repeat(48)),
            ],
            ..pinned_witness()
        };
        let trust = settings.trust().expect("both sets parse");
        assert_eq!(trust.measurements.len(), 2, "an upgrade window needs both");
        assert!(trust.is_pinned());

        // A malformed entry is an error, never a skipped line: a silently
        // dropped pin leaves a contributor believing they pinned something.
        let mut broken = settings.clone();
        broken
            .expected_measurements
            .push("mrtd=deadbeef".to_string());
        assert!(broken.trust().is_err());

        assert!(!unpinned_witness().trust().unwrap().is_pinned());
    }

    #[tokio::test]
    async fn a_witnessed_grant_is_derived_the_same_way_a_stamped_one_is() {
        // The witness receives the grants instead of the envelope being
        // stamped with them, so the two derivations must agree -- otherwise a
        // witnessed and an unwitnessed submission from the same claim would
        // consent to different things.
        let cfg = cfg_for("http://issuer.invalid", "http://ingest.invalid", "device-1");
        let token = ClaimToken {
            access_token: "token".into(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            consent_scopes: vec!["debugging_evaluation".into()],
            allowed_uses: vec!["debugging".into()],
        };

        let selection = fixture_selection();
        let (source, session_ref) = &selection[0];
        let transcript = source.load(session_ref).unwrap();
        let redactor = build_redactor_with(&cfg, transcript.cwd.as_deref(), None).unwrap();
        let raw = build_raw_contribution_with_verdict(&transcript, &cfg, Utc::now(), None);
        let mut envelope = redact_to_envelope(&redactor, raw).await.unwrap();

        let (scopes, uses) = granted_consent_for(&cfg, &token);
        stamp_granted_scopes(&mut envelope, &cfg, &token);
        assert_eq!(envelope.consent.scopes, scopes);
        assert_eq!(envelope.trace_card.allowed_uses, uses);
        // A positive control: the derived grant is the claim's, not the
        // config's wider request.
        assert_ne!(
            scopes.len(),
            cfg.consent_scopes.len(),
            "the fixture cannot tell a claim grant from a config request"
        );
    }

    // -----------------------------------------------------------------
    // Task 7: what reaches POST /v1/traces.
    // -----------------------------------------------------------------

    use axum::response::IntoResponse as _;
    use sha2::Digest as _;

    /// One captured submission: the raw body bytes and the headers.
    #[derive(Clone, Default)]
    struct CapturedUpload {
        bodies: Vec<Vec<u8>>,
        headers: Vec<axum::http::HeaderMap>,
    }

    /// An ingest stub that keeps the body as **bytes**.
    ///
    /// `stub_ingest` parses into a `serde_json::Value`, which is exactly the
    /// comparison that would pass over the bug this task exists to prevent: a
    /// re-serialised envelope still parses to the same value. Byte capture is
    /// what makes the digest assertion real.
    fn stub_ingest_raw(captured: Arc<Mutex<CapturedUpload>>, first_status: u16) -> Router {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Router::new().route(
            "/v1/traces",
            post(
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let captured = captured.clone();
                    let calls = calls.clone();
                    async move {
                        {
                            let mut captured = captured.lock().unwrap();
                            captured.bodies.push(body.to_vec());
                            captured.headers.push(headers);
                        }
                        let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if n == 0 && first_status != 200 {
                            return (
                                axum::http::StatusCode::from_u16(first_status).unwrap(),
                                Json(serde_json::json!({"error": "claim expired"})),
                            )
                                .into_response();
                        }
                        Json(serde_json::json!({
                            "status": "accepted",
                            "credit_points_pending": 0.0,
                            "explanation": []
                        }))
                        .into_response()
                    }
                },
            ),
        )
    }

    fn stub_claim(now: DateTime<Utc>) -> ClaimToken {
        ClaimToken {
            access_token: "stub-claim-jwt".into(),
            expires_at: now + chrono::Duration::hours(1),
            consent_scopes: vec!["debugging_evaluation".into()],
            allowed_uses: vec!["debugging".into()],
        }
    }

    /// A witnessed response over `bytes`, with a certificate that is not
    /// checked here -- `upload_with_retry` forwards it, it does not verify it.
    /// Verification is `witness::transport`'s job and is tested there.
    fn witnessed_over(bytes: &[u8]) -> WitnessedEnvelope {
        WitnessedEnvelope {
            admission: None,
            envelope_bytes: bytes.to_vec(),
            certificate_json: serde_json::json!({
                "redacted_sha256": hex::encode(sha2::Sha256::digest(bytes)),
                "residual_risk_verdict": "low",
                "redaction_policy_version": "deterministic-v1",
                "witness_measurement": "aa".repeat(48),
                "timestamp": 1_788_264_000i64,
            })
            .to_string(),
            signature_hex: format!("0x{}", "ab".repeat(65)),
        }
    }

    /// Envelope bytes whose compact re-serialisation is a DIFFERENT string, so
    /// a `call_json` on this path would be caught rather than passing because
    /// the fixture was already canonical.
    ///
    /// Not a real envelope: `upload_with_retry` never parses the witnessed
    /// body, which is the property under test.
    const UNCANONICAL_ENVELOPE: &[u8] = br#"{"zeta":1,"alpha": "two","gamma":1.50}"#;

    async fn upload_once(
        witnessed: Option<&WitnessedEnvelope>,
        first_status: u16,
    ) -> (
        std::result::Result<TraceSubmissionReceipt, String>,
        CapturedUpload,
    ) {
        upload_once_with_compatible_grant(witnessed, first_status, false).await
    }

    async fn upload_once_with_compatible_grant(
        witnessed: Option<&WitnessedEnvelope>,
        first_status: u16,
        compatible_grant: bool,
    ) -> (
        std::result::Result<TraceSubmissionReceipt, String>,
        CapturedUpload,
    ) {
        let captured = Arc::new(Mutex::new(CapturedUpload::default()));
        let issuer_url = spawn(stub_issuer()).await;
        let ingest_url = spawn(stub_ingest_raw(captured.clone(), first_status)).await;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = cfg_for(&issuer_url, &ingest_url, &device.device_key_id);
        let issuer = IssuerClient::new(crate::config::allowlist_for(None)).unwrap();

        let now = Utc::now();
        let mut initial = stub_claim(now);
        if compatible_grant {
            initial.consent_scopes = vec!["debugging_evaluation".into(), "model_training".into()];
            initial.allowed_uses = vec![
                "debugging".into(),
                "evaluation".into(),
                "model_training".into(),
                "aggregate_analytics".into(),
            ];
        }
        let mut claim = Some(initial);
        let mut envelope = baseline_envelope(&cfg).await;
        stamp_granted_scopes(&mut envelope, &cfg, claim.as_ref().unwrap());

        let result = upload_with_retry(
            &cfg,
            &issuer,
            &device,
            &mut claim,
            &mut envelope,
            &cfg,
            witnessed,
        )
        .await;
        let captured = captured.lock().unwrap().clone();
        (result, captured)
    }

    async fn baseline_envelope(cfg: &ContributorConfig) -> TraceContributionEnvelope {
        let selection = fixture_selection();
        let (source, session_ref) = &selection[0];
        let transcript = source.load(session_ref).unwrap();
        let redactor = build_redactor_with(cfg, transcript.cwd.as_deref(), None).unwrap();
        let raw = build_raw_contribution_with_verdict(&transcript, cfg, Utc::now(), None);
        redact_to_envelope(&redactor, raw).await.unwrap()
    }

    #[tokio::test]
    async fn a_witnessed_submission_carries_the_certificate_in_headers_and_not_in_the_body() {
        let witnessed = witnessed_over(UNCANONICAL_ENVELOPE);
        let (result, captured) = upload_once(Some(&witnessed), 200).await;
        result.expect("the stub accepted the submission");

        let headers = &captured.headers[0];
        assert!(headers.contains_key(WITNESS_CERTIFICATE_HEADER));
        assert!(headers.contains_key(WITNESS_SIGNATURE_HEADER));

        let body: serde_json::Value = serde_json::from_slice(&captured.bodies[0]).unwrap();
        assert!(
            body.get("witness_certificate").is_none(),
            "the envelope grew a field it is hashed over"
        );
    }

    #[tokio::test]
    async fn the_bytes_on_the_wire_are_the_bytes_the_certificate_covers() {
        // The test that catches a re-serialisation. Compares the captured
        // request body against the witness's bytes BYTE FOR BYTE -- not field
        // by field, and not by parsing both sides, which is the comparison
        // that would pass over exactly the bug being hunted.
        let witnessed = witnessed_over(UNCANONICAL_ENVELOPE);
        let (result, captured) = upload_once(Some(&witnessed), 200).await;
        result.expect("the stub accepted the submission");

        assert_eq!(captured.bodies[0], witnessed.envelope_bytes);
        let certificate: serde_json::Value = serde_json::from_str(
            captured.headers[0][WITNESS_CERTIFICATE_HEADER]
                .to_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            certificate["redacted_sha256"].as_str().unwrap(),
            hex::encode(sha2::Sha256::digest(&captured.bodies[0])),
        );
        // The fixture must be one a re-serialisation would move, or the
        // assertion above cannot fail.
        let round_tripped = serde_json::to_vec(
            &serde_json::from_slice::<serde_json::Value>(UNCANONICAL_ENVELOPE).unwrap(),
        )
        .unwrap();
        assert_ne!(
            round_tripped, UNCANONICAL_ENVELOPE,
            "the fixture cannot detect a re-serialisation"
        );
    }

    #[tokio::test]
    async fn admission_headers_and_bytes_survive_compatible_retry_verbatim() {
        let mut witnessed = witnessed_over(UNCANONICAL_ENVELOPE);
        witnessed.admission = Some(crate::witness::transport::AdmissionHeaders {
            evidence_json: "{ \"profile\": \"transport-test\" }".into(),
            signature_hex: format!("0x{}", "cd".repeat(65)),
        });
        let (result, captured) =
            upload_once_with_compatible_grant(Some(&witnessed), 401, true).await;
        result.unwrap();
        assert_eq!(captured.bodies.len(), 2);
        for (body, headers) in captured.bodies.iter().zip(&captured.headers) {
            assert_eq!(body, &witnessed.envelope_bytes);
            let admission = witnessed.admission.as_ref().unwrap();
            assert_eq!(
                headers[trace_commons_protocol::admission::EVIDENCE_HEADER],
                admission.evidence_json
            );
            assert_eq!(
                headers[trace_commons_protocol::admission::SIGNATURE_HEADER],
                admission.signature_hex
            );
        }
    }

    #[tokio::test]
    async fn an_unwitnessed_submission_sends_its_envelope_and_no_new_headers() {
        let (result, captured) = upload_once(None, 200).await;
        result.expect("the stub accepted the submission");

        assert!(
            !captured.headers[0]
                .keys()
                .any(|k| k.as_str().starts_with("x-trace-witness")),
            "an unwitnessed submission grew witness headers"
        );
        // And the body is the envelope, as it always was.
        let body: serde_json::Value = serde_json::from_slice(&captured.bodies[0]).unwrap();
        assert!(body.get("schema_version").is_some());
    }

    #[tokio::test]
    async fn witness_review_compatible_401_retry_preserves_bytes_and_certificate() {
        let witnessed = witnessed_over(UNCANONICAL_ENVELOPE);
        let (result, captured) =
            upload_once_with_compatible_grant(Some(&witnessed), 401, true).await;
        result.expect("a compatible fresh grant permits the exact approved artifact");
        assert_eq!(captured.bodies.len(), 2);
        assert_eq!(captured.bodies[0], witnessed.envelope_bytes);
        assert_eq!(captured.bodies[1], witnessed.envelope_bytes);
        for headers in &captured.headers {
            assert_eq!(
                headers[WITNESS_CERTIFICATE_HEADER],
                witnessed.certificate_json
            );
            assert_eq!(headers[WITNESS_SIGNATURE_HEADER], witnessed.signature_hex);
        }
    }

    #[tokio::test]
    async fn a_changed_re_mint_refuses_rather_than_restamping_certified_bytes() {
        // upload_with_retry restamps granted scopes after a 401 re-mint,
        // deliberately, so a stale grant is not resent. On a witnessed
        // submission that write breaks the digest, and silently re-witnessing
        // would send the raw session a second time on the strength of a
        // verification made for a different exchange.
        let witnessed = witnessed_over(UNCANONICAL_ENVELOPE);
        let (result, captured) = upload_once(Some(&witnessed), 401).await;
        assert_eq!(result.unwrap_err(), "witness-grant-changed");
        assert_eq!(
            captured.bodies.len(),
            1,
            "the witnessed session was offered a second time after a re-mint"
        );
    }

    #[tokio::test]
    async fn an_unwitnessed_submission_still_retries_after_a_re_mint() {
        // The positive control for the refusal above: without it, a
        // upload_with_retry that refused every 401 would satisfy that test.
        let (result, captured) = upload_once(None, 401).await;
        result.expect("an unwitnessed submission re-mints and retries");
        assert_eq!(captured.bodies.len(), 2);
    }

    #[tokio::test]
    async fn the_residual_risk_field_is_unchanged_by_witnessing() {
        // Both shapes are on the wire at once during the rollout, and the
        // fields do not overlap: ingest reads privacy.residual_pii_risk
        // exactly as it does today and the certificate is additional
        // evidence. A server that ignores the headers accepts the submission
        // unchanged.
        let (_, captured) = upload_once(None, 200).await;
        let body: serde_json::Value = serde_json::from_slice(&captured.bodies[0]).unwrap();
        assert!(
            body["privacy"]["residual_pii_risk"].is_string(),
            "the client-computed residual risk left the envelope"
        );
    }
}

/// Machine-readable form of a submit run, for callers driving this CLI
/// programmatically (an MCP server, CI, a hackathon collector).
///
/// Every outcome is represented, including the ones `build_manifest` drops:
/// a caller automating submission needs to know a session was refused and
/// why, not merely that it is absent from the manifest.
pub fn outcomes_to_json(
    outcomes: &[SubmitOutcome],
    unenrolled_preview: bool,
    notices: &[&str],
) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|o| {
            let mut entry = match o {
                SubmitOutcome::Submitted {
                    submission_id,
                    status,
                } if unenrolled_preview => serde_json::json!({
                    "outcome": "previewed",
                    "preview_id": submission_id,
                    "status": status,
                }),
                SubmitOutcome::Submitted {
                    submission_id,
                    status,
                } => serde_json::json!({
                    "outcome": "submitted",
                    "submission_id": submission_id,
                    "status": status,
                }),
                SubmitOutcome::AlreadySubmitted {
                    submission_id,
                    prior_status,
                } => serde_json::json!({
                    "outcome": "already-submitted",
                    "submission_id": submission_id,
                    "status": prior_status,
                }),
                SubmitOutcome::SkippedParseFailure { reason_label } => serde_json::json!({
                    "outcome": "skipped",
                    "reason": reason_label,
                }),
                SubmitOutcome::Refused {
                    reason_label,
                    session_ref,
                    size_bytes,
                    limit_bytes,
                } => serde_json::json!({
                    "outcome": "refused",
                    "reason": reason_label,
                    "session_ref": session_ref,
                    "size_bytes": size_bytes,
                    "limit_bytes": limit_bytes,
                }),
                SubmitOutcome::Failed { reason_label } => serde_json::json!({
                    "outcome": "failed",
                    "reason": reason_label,
                }),
            };
            entry["unenrolled_preview"] = serde_json::Value::Bool(unenrolled_preview);
            entry
        })
        .collect();
    serde_json::json!({
        "schema_version": "trace_commons.submit_result.v1",
        "unenrolled_preview": unenrolled_preview,
        "notices": notices,
        "results": entries,
    })
}

#[cfg(test)]
mod json_output_tests {
    use super::*;

    #[test]
    fn every_outcome_kind_is_represented() {
        let id = Uuid::new_v4();
        let out = outcomes_to_json(
            &[
                SubmitOutcome::Submitted {
                    submission_id: id,
                    status: "accepted".to_string(),
                },
                SubmitOutcome::AlreadySubmitted {
                    submission_id: id,
                    prior_status: "quarantined".to_string(),
                },
                refused("secret-leak-detected", "sha256:test"),
                SubmitOutcome::Failed {
                    reason_label: "claim-mint-failed".to_string(),
                },
                SubmitOutcome::SkippedParseFailure {
                    reason_label: "parse-failed".to_string(),
                },
            ],
            false,
            &[],
        );

        let results = out["results"].as_array().unwrap();
        // A caller automating submission must be able to see a refusal. The
        // manifest deliberately omits these, so JSON output cannot reuse it.
        assert_eq!(results.len(), 5, "no outcome may be silently dropped");
        assert_eq!(results[0]["outcome"], "submitted");
        assert_eq!(results[1]["outcome"], "already-submitted");
        assert_eq!(
            results[1]["status"], "quarantined",
            "the real prior status must survive into JSON"
        );
        assert_eq!(results[2]["outcome"], "refused");
        assert_eq!(results[2]["reason"], "secret-leak-detected");
        assert_eq!(results[2]["session_ref"], "sha256:test");
        assert_eq!(results[3]["outcome"], "failed");
        assert_eq!(results[4]["outcome"], "skipped");
    }

    #[test]
    fn reasons_stay_labels_and_never_carry_content() {
        // Reason labels are fixed strings by construction. Pinning it here
        // stops a future change from surfacing a response body or path to a
        // caller that logs this output.
        let out = outcomes_to_json(
            &[refused_for_size("sha256:test", 1_600_000)],
            true,
            &["preview notice"],
        );
        let reason = out["results"][0]["reason"].as_str().unwrap();
        assert!(!reason.contains('/'), "a label must not look like a path");
        assert!(reason.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
        assert_eq!(out["unenrolled_preview"], true);
        assert_eq!(out["results"][0]["unenrolled_preview"], true);
        assert_eq!(out["notices"][0], "preview notice");
        assert_eq!(out["results"][0]["session_ref"], "sha256:test");
        assert_eq!(out["results"][0]["size_bytes"], 1_600_000);
        assert_eq!(
            out["results"][0]["limit_bytes"],
            crate::envelope::MAX_ENVELOPE_BYTES
        );
    }
}

/// Validate a `--attest-post` target before anything is sent to it.
///
/// Fail-closed in a way the ingest path deliberately is not. `allowlist_for`
/// returns a permissive allowlist when nobody configured one, which is fine
/// for ingest -- that URL came from enrollment and is already trusted. This
/// URL comes from the command line, and the payload is a signed statement
/// about the contributor that whoever holds it can present. So an
/// unconfigured allowlist means no egress, not any host.
///
/// The scheme check is separate from the host check and both must pass:
/// allowlisting a collector says who may receive the attestation, not that it
/// may cross the network in the clear.
pub fn validate_attest_post_target(
    raw: &str,
    allowlist: &trace_commons_operator_client::host_allowlist::HostAllowlist,
) -> anyhow::Result<reqwest::Url> {
    let url =
        reqwest::Url::parse(raw).with_context(|| format!("--attest-post is not a URL: {raw}"))?;
    if url.scheme() != "https" {
        anyhow::bail!(
            "--attest-post must be https: an attestation is presentable by \
             whoever holds it, so it does not cross the network in the clear"
        );
    }
    if !allowlist.is_enforcing() {
        anyhow::bail!(
            "--attest-post needs an explicit host allowlist. Set --allowed-hosts \
             at login, or TRACE_COMMONS_ALLOWED_HOSTS, naming the collector you \
             mean to send the attestation to"
        );
    }
    allowlist
        .check(&url)
        .context("--attest-post host is not on the allowlist")?;
    Ok(url)
}

/// Deliver the attestation to a collector endpoint the contributor named.
///
/// Returns whether it was delivered. A failure here is reported and swallowed:
/// the traces are already uploaded and the receipts already written, so
/// exiting non-zero would tell a contributor their submission failed when it
/// did not. The attestation is on disk if `--attest-out` was also given, and
/// `attest` can always mint another.
///
/// Label-only on failure. The URL is the contributor's, but the response body
/// is the collector's and may carry anything.
pub async fn post_attestation(
    target: &reqwest::Url,
    attested: &ScopedAttestation,
    allowed_hosts: Option<&str>,
) -> bool {
    let client = match reqwest::Client::builder()
        .user_agent(concat!(
            "trace-commons-contributor/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            tracing::warn!("attestation not delivered: http-client-unavailable");
            return false;
        }
    };
    // Re-check immediately before sending. The validator ran when the flag was
    // parsed; this is the call that actually opens the connection, and a
    // redirect could otherwise carry the document to a host nobody authorized.
    let allowlist = crate::config::allowlist_for(allowed_hosts);
    if validate_attest_post_target(target.as_str(), &allowlist).is_err() {
        tracing::warn!("attestation not delivered: target-not-allowlisted");
        return false;
    }
    let body = serde_json::json!({
        "schema_version": "trace_commons.attestation_delivery.v1",
        "attestations": attested.attestations,
        "scored": attested.scored,
        "pending": attested.pending,
    });
    match client.post(target.clone()).json(&body).send().await {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            // Status only. A collector's error body is not ours to print.
            tracing::warn!(
                status = response.status().as_u16(),
                "attestation not delivered: collector-rejected"
            );
            false
        }
        Err(_) => {
            tracing::warn!("attestation not delivered: transport-failed");
            false
        }
    }
}

#[cfg(test)]
mod attest_post_tests {
    use super::validate_attest_post_target;
    use trace_commons_operator_client::host_allowlist::HostAllowlist;

    #[test]
    fn a_permissive_allowlist_refuses_rather_than_posting_anywhere() {
        // The allowlist is permissive whenever nobody configured one, which is
        // the common case. For ingest that is tolerable -- the URL came from
        // enrollment. Here the URL comes from the command line, and the payload
        // is a signed statement about the contributor, so "no allowlist" must
        // mean "no egress" rather than "any host".
        let err = validate_attest_post_target(
            "https://collector.example/hook",
            &HostAllowlist::permissive(),
        )
        .expect_err("permissive allowlist must refuse");
        assert!(
            err.to_string().contains("allowed-hosts"),
            "the refusal must say how to authorize the host: {err}"
        );
    }

    #[test]
    fn a_host_outside_the_allowlist_is_refused() {
        let allow = HostAllowlist::from_csv("collector.example");
        let err = validate_attest_post_target("https://elsewhere.example/hook", &allow)
            .expect_err("off-list host must refuse");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn plaintext_http_is_refused_even_when_allowlisted() {
        // An attestation is a bearer-shaped artifact: whoever holds it can
        // present it. Allowlisting a host says who may receive it, not that it
        // may cross the network in the clear.
        let allow = HostAllowlist::from_csv("collector.example");
        let err = validate_attest_post_target("http://collector.example/hook", &allow)
            .expect_err("http must refuse");
        assert!(err.to_string().contains("https"), "unexpected error: {err}");
    }

    /// `--attest-post` must keep deriving its allowlist from `allowlist_for`,
    /// never from the enrolled config.
    ///
    /// The hazard is a future refactor that "unifies" `allowlist_for` and
    /// `config::config_allowlist`. That would make `is_enforcing()` true here
    /// from the config's own hosts, silently retiring the deliberate "needs an
    /// explicit host allowlist" refusal -- for a URL that arrives from the
    /// command line carrying a signed statement about the contributor, and
    /// permitting any collector that happened to equal the ingest host.
    ///
    /// Driven through `post_attestation`, the real call site, rather than
    /// through the validator: passing a permissive list to the validator by
    /// hand would still pass after exactly that refactor. A counting listener
    /// separates "refused by the gate" from "dialled and failed" -- without it
    /// both arms return `false` and the test proves nothing.
    #[tokio::test]
    async fn attest_post_is_not_authorized_by_the_enrolled_config() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });

        let target = reqwest::Url::parse(&format!("https://127.0.0.1:{port}/hook")).unwrap();
        let attested = super::ScopedAttestation {
            attestations: vec!["fixture.jws".into()],
            requested: 1,
            scored: 1,
            pending: 0,
        };

        // No explicit allowlist: refused before anything is dialled. A
        // signup-written config names hosts, but none of them authorize this.
        assert!(!super::post_attestation(&target, &attested, None).await);
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "an unauthorized attest-post target must not be dialled at all"
        );

        // Named explicitly, the same target IS dialled -- TLS then fails
        // against a bare TCP socket, so this still returns false. The
        // difference between the two arms is the whole assertion.
        assert!(!super::post_attestation(&target, &attested, Some("127.0.0.1")).await);
        assert!(
            accepted.load(Ordering::SeqCst) >= 1,
            "an explicitly allowlisted target must actually be dialled"
        );
    }

    #[test]
    fn an_allowlisted_https_target_is_accepted() {
        let allow = HostAllowlist::from_csv("collector.example");
        let url = validate_attest_post_target("https://collector.example/hook", &allow)
            .expect("allowlisted https target");
        assert_eq!(url.host_str(), Some("collector.example"));
    }
}
