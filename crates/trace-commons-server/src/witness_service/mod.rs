// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The redaction witness service, as a function.
//!
//! [`witness`] is the whole service: it takes a contributor's raw transcript,
//! **performs** the redaction, computes the residual-PII verdict with the same
//! function ingest uses, and signs a [`WitnessCertificate`] over the artifact
//! it is about to return. The HTTP surface is a thin adapter over this, so the
//! service is testable without a socket.
//!
//! # It performs the redaction; it does not check one
//!
//! An earlier design had the witness verify a *client-supplied* span list.
//! That cannot work for the real pipeline: the redactor holds a model-based
//! prose classifier whose calls do not reproduce, so a witness that recomputed
//! and compared would refuse **honest** submissions. The witness therefore
//! produces the redaction, and correspondence holds by construction.
//!
//! [`check_correspondence`] is still on the path, and its job here is narrow
//! and worth stating exactly: it is the only producer of a
//! [`CorrespondenceProof`], and [`WitnessCertificate::from_proof`] is the only
//! production constructor of a certificate, so the digest a certificate claims
//! can only have come from bytes a check ran over. The witness runs it over
//! the artifact it is returning, with an empty span list, which binds the
//! certificate's digest to *those exact bytes* rather than to a string some
//! later refactor computed separately. It proves nothing about the raw text --
//! it cannot, and this module never claims it does.
//!
//! Two facts make a span-bearing check unavailable rather than merely
//! unnecessary, and they are recorded so the "improvement" is not attempted:
//! `DeterministicTraceRedactor` returns redacted text and a report, never a
//! span list; and its placeholders (`<PRIVATE_EMAIL_1>`) are not the
//! `[REDACTED]` / `[REDACTED:label]` grammar [`apply_spans`] enforces, so a
//! span list describing a real redaction by this pipeline would be refused as
//! [`CorrespondenceError::MalformedReplacement`].
//!
//! [`apply_spans`]: crate::redaction_witness::correspondence::apply_spans
//! [`CorrespondenceError::MalformedReplacement`]: crate::redaction_witness::correspondence::CorrespondenceError::MalformedReplacement
//!
//! # What the certificate does not say
//!
//! It attests **mechanics and a verdict**: that a program with a given
//! measurement produced this artifact and reached this residual-risk verdict
//! over it. It does not say the artifact is clean, and no name, comment,
//! error or field in this module may be read that way. A `Low` verdict from
//! an unpinned measurement is worth nothing at all.
//!
//! The verdict is a **pass** verdict. It is what
//! [`residual_risk_basis`] says about the redaction pass's own report, which
//! is the same thing `DeterministicTraceRedactor::redact_trace` writes into
//! `privacy.residual_pii_risk`. It is *not* the post-residual-scan verdict
//! `rescrub_trace_envelope` resolves on the server, which may raise it: a
//! detection-only sweep over the finished artifact can find a survivor this
//! pass cannot see. A server that trusts this verdict is trusting a pass
//! verdict, and the residual-scan half of its own decision is what it is
//! choosing to skip.
//!
//! # The witness holds nothing
//!
//! Raw bytes live in memory for one request. Nothing here writes, logs or
//! returns them, and no error carries content: every variant of
//! [`WitnessError`] is a bare label, and `Debug` delegates to `Display` so
//! that `tracing::warn!(?err)` cannot render what `%err` is guarded against.
//! [`WitnessRequest`] and [`WitnessResponse`] have hand-written `Debug`
//! impls that withhold every content-bearing field, for the same reason.

pub mod enclave;
pub mod http;
pub mod inference;
pub mod surface;

use async_trait::async_trait;
use std::sync::Arc;

use trace_commons_protocol::trace_contribution::{
    ConsentMetadata, ConsentScope, DETERMINISTIC_REDACTION_PIPELINE_VERSION,
    DeterministicTraceRedactor, PrivacyFilterAdapter, PrivacyFilterBackendTag,
    RawTraceContribution, RedactionReport, ResidualPiiRisk, ResidualRiskCondition, TraceAllowedUse,
    TraceContributionEnvelope, TraceRedactor, apply_granted_scopes, redaction_pipeline_version,
    residual_risk_basis,
};

use crate::near_attestation::receipt::ReceiptPayload;
use crate::redaction_witness::certificate::{CertificateDetails, WitnessCertificate};
use crate::redaction_witness::correspondence::check_correspondence;
use crate::witness_service::inference::{
    InferenceAttestationPolicy, WitnessedSession, check_inference_attestation,
    strip_inference_bodies,
};

/// What the contributor sends: the raw transcript and the consent flags that
/// declare what it carries.
///
/// The flags are part of the verdict's input -- `residual_risk_basis` floors
/// an envelope at Medium when a content flag is set -- so they must be
/// witnessed alongside the text rather than attached afterwards.
#[derive(Clone)]
pub struct WitnessRequest {
    /// The raw transcript. Never logged, never echoed, never persisted.
    pub raw_transcript: String,
    /// The contributor's declared consent flags, as they will be declared on
    /// the envelope.
    pub consent: ConsentMetadata,
    /// The receipt the contributor offers for this session's last inference
    /// call.
    ///
    /// `None` is legal only where the deployment's
    /// [`InferenceAttestationPolicy`] does not require attestation. On this
    /// route a receipt is refused outright: a transcript carries no event
    /// order, so nothing here can establish which call was last. See
    /// [`WitnessedSession::Transcript`].
    pub offered_receipt: Option<ReceiptPayload>,
}

impl std::fmt::Debug for WitnessRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written, and it withholds the transcript. A derived Debug on a
        // struct holding raw contributor text is one `?request` away from
        // putting a whole session in a log line.
        formatter
            .debug_struct("WitnessRequest")
            .field("raw_transcript", &"<withheld>")
            .field("consent", &"<withheld>")
            .field("offered_receipt", &"<withheld>")
            .finish()
    }
}

/// What the witness returns: the artifact, the certificate over it, and the
/// signature.
///
/// The artifact is the redacted text the contributor uploads through the
/// existing path. If they alter it the digest no longer matches and the
/// server refuses.
#[derive(Clone)]
pub struct WitnessResponse {
    /// The redacted artifact, byte for byte as the certificate's digest was
    /// taken over it. Any re-encoding, wrapper or added trailing newline
    /// between here and the server fails closed at
    /// `verify_witness_certificate`.
    pub redacted_artifact: String,
    /// The certificate. Its digest is over `redacted_artifact`.
    pub certificate: WitnessCertificate,
    /// EIP-191 signature over `certificate.signing_bytes()`, as 65 bytes of
    /// `0x`-prefixed hex.
    pub signature_hex: String,
}

impl WitnessResponse {
    /// The verdict the certificate binds.
    ///
    /// Read off the certificate rather than stored beside it. A second copy
    /// in this struct would be a second source of truth for the field the
    /// whole design turns on, and the two would eventually disagree.
    pub fn residual_risk_verdict(&self) -> ResidualPiiRisk {
        self.certificate.residual_risk_verdict()
    }
}

impl std::fmt::Debug for WitnessResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The artifact is redacted, not clean -- it is contributor content
        // that a pass happened to find nothing more in. It is withheld here
        // for the same reason the raw transcript is. The signature is
        // withheld because the repo's logging convention says so.
        formatter
            .debug_struct("WitnessResponse")
            .field("redacted_artifact", &"<withheld>")
            .field("certificate", &self.certificate)
            .field("signature_hex", &"<withheld>")
            .finish()
    }
}

/// Why the witness refused.
///
/// Every variant is a bare label. Nothing here carries a reason string, a
/// count, an offset or a length: these errors reach operational surfaces, and
/// on this path every quantity derived from the input describes contributor
/// content. Callers branch on the variant.
///
/// There is no variant that means "certified with reservations". A witness
/// that cannot complete a step refuses; there is no partial certificate.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
    /// The redaction did not complete. The configured prose-PII classifier
    /// was unavailable or errored, or the deterministic pass refused the
    /// input outright.
    ///
    /// This is the fail-closed arm the whole module exists around: a witness
    /// that certified what it had at the point of failure would be signing a
    /// partial redaction, which is worse than signing nothing.
    #[error("the witness could not complete the redaction")]
    RedactionFailed,
    /// The witness could not bind a digest to the artifact it produced.
    #[error("the witness could not bind a digest to the artifact it produced")]
    ArtifactBindingFailed,
    /// The enclave could not report its own measurement. Without it the
    /// certificate would name no program, and an operator's pin would have
    /// nothing to match.
    #[error("the enclave could not report its measurement")]
    MeasurementUnavailable,
    /// The signer refused or was unavailable.
    #[error("the witness could not sign the certificate")]
    SigningUnavailable,
    /// This deployment requires attested inference and the submission carried
    /// no receipt.
    ///
    /// The missing-control name for the fail-closed arm of the requirement.
    /// There is no variant meaning "certified without attestation": a witness
    /// configured to require it and unable to verify it refuses, and never
    /// downgrades to certifying an unattested trace.
    #[error("the witness requires attested inference and this submission carried none")]
    InferenceAttestationMissing,
    /// Attested inference was required or offered on a route that cannot
    /// establish which inference call was last.
    ///
    /// The text route. A transcript is opaque, so the only way to attest one
    /// would be to let the caller nominate the exchange -- which is a claim
    /// about the caller's choice, not about the session.
    #[error("this route cannot establish which inference call a receipt attests")]
    InferenceAttestationUnavailable,
    /// The contribution declares no inference call at all, so there is nothing
    /// a receipt could attest.
    ///
    /// Named separately from a missing receipt because an operator does
    /// something different about it: this contribution cannot satisfy the
    /// requirement in principle rather than having failed to.
    #[error("this contribution declares no inference call")]
    InferenceCallAbsent,
    /// The last declared inference call declares that its stream was
    /// restarted, so no receipt for it exists or ever will.
    ///
    /// IronWire's resilience guard restarts a stalled stream and records no
    /// digest for it. Named separately from a missing receipt because the
    /// contributor could not have supplied one: reporting it as missing would
    /// send an operator looking for a client bug.
    #[error("the attested inference call was restarted mid-stream and cannot be attested")]
    InferenceCallUnattestable,
    /// The last declared inference call carries no request or response body.
    ///
    /// In practice: the contribution withheld tool payloads, so the conversion
    /// wrote method and status and no bodies. A requirement cannot be
    /// satisfied without the bytes the receipt binds.
    #[error("the attested inference call carries no bodies in this session")]
    InferenceBodyNotInSession,
    /// The offered receipt did not verify against the bodies in the session.
    ///
    /// One label for every [`ReceiptError`], deliberately, and named for what
    /// was observed rather than for a conclusion about why: a capture that
    /// re-serialised a body is indistinguishable from a forged receipt, and on
    /// an honest deployment the capture bug is likelier.
    ///
    /// [`ReceiptError`]: crate::near_attestation::receipt::ReceiptError
    #[error("the offered inference receipt did not verify against these bodies")]
    InferenceReceiptUnverified,
    /// An attested body was larger than this witness will hash.
    #[error("an attested inference body is larger than this witness will hash")]
    InferenceReceiptTooLarge,
}

impl std::fmt::Debug for WitnessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

/// A seam could not do its job.
///
/// One type for all three seams, carrying nothing. Which refusal an operator
/// sees is decided in [`witness`] by the call site, not by the implementation
/// -- so a redactor cannot report itself as a signing failure, and no seam can
/// invent a variant that reads as a softer refusal than it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unavailable")]
pub struct SeamUnavailable;

/// What a redaction pass produced.
///
/// The report travels with the text because the verdict is derived from it.
/// Returning only the text and letting the caller re-derive a report would be
/// a second implementation of the thing this module refuses to duplicate.
pub struct RedactedTranscript {
    /// The redacted text.
    pub redacted: String,
    /// The pass's own report, fed verbatim to [`residual_risk_basis`].
    pub report: RedactionReport,
    /// The policy alias this pass reports. **An alias, never an authority** --
    /// see [`CertificateDetails::redaction_policy_version`]. The measurement
    /// is the real policy identity.
    pub policy_version: String,
}

/// The redaction seam.
///
/// A trait object, following the same pattern as the gate seam in this repo:
/// the witness holds behaviour, never a concrete pipeline, so a test can
/// substitute one and a deployment can change the classifier backend without
/// touching this module.
///
/// It is fallible on purpose. [`DeterministicRedaction`] below never returns
/// `Err`, because the deterministic secret path cannot fail on well-formed
/// UTF-8; the prose-PII stage can and does -- `apply_privacy_filter_to_text`
/// propagates a self-hosted or NEAR AI backend failure rather than degrading
/// to deterministic-only -- and that failure must reach [`witness`] as a
/// refusal rather than as quietly narrower coverage.
#[async_trait]
pub trait TranscriptRedactor: Send + Sync {
    /// Redact `raw`. `Err` means the pass did not complete; there is no
    /// partial success.
    async fn redact(&self, raw: &str) -> Result<RedactedTranscript, SeamUnavailable>;
}

/// The deterministic secret path, and only that.
///
/// **This is not the full pipeline ingest runs**, and a certificate from a
/// witness wired this way says so: its `redaction_policy_version` is the
/// deterministic alias, and a server that requires the prose classifier must
/// refuse it. [`FullPipelineRedaction`] is the one that runs both stages.
///
/// This one is kept, rather than deleted in favour of it, because it is the
/// only implementation with no network dependency: it is what a test uses,
/// and what a deployment with no classifier backend reachable from inside the
/// enclave can honestly run.
pub struct DeterministicRedaction {
    redactor: DeterministicTraceRedactor,
}

impl DeterministicRedaction {
    /// Build the deterministic pass with the path prefixes it should treat as
    /// known. No env is read: a witness must not have its redaction policy
    /// changed by the environment it happens to boot into.
    pub fn new(known_path_prefixes: Vec<String>) -> Self {
        Self {
            redactor: DeterministicTraceRedactor::deterministic_only(known_path_prefixes),
        }
    }
}

#[async_trait]
impl TranscriptRedactor for DeterministicRedaction {
    async fn redact(&self, raw: &str) -> Result<RedactedTranscript, SeamUnavailable> {
        let (redacted, report) = self.redactor.redact_text(raw);
        Ok(RedactedTranscript {
            redacted,
            report,
            // Exactly what `redaction_pipeline_version(PrivacyFilterBackendTag::None)`
            // returns in the protocol crate, from the same public constant, so
            // the alias a server allowlists cannot drift from the one ingest
            // writes for the same pipeline.
            policy_version: DETERMINISTIC_REDACTION_PIPELINE_VERSION.to_string(),
        })
    }
}

/// Both stages: the deterministic secret pass, then the prose-PII classifier
/// over its output.
///
/// This is what closes the gap [`DeterministicRedaction`] leaves. It calls
/// `DeterministicTraceRedactor::redact_text_through_prose_filter`, the same
/// two stages in the same order that `TraceRedactor::redact_trace` applies to
/// every event ingest receives -- they share one private helper in the
/// protocol crate, so the pipeline a certificate attests cannot drift from the
/// one the server runs.
///
/// # This talks to the classifier over the network
///
/// [`TranscriptRedactor::redact`] is `async` for exactly this reason. Under
/// the `near-ai` backend the classifier is another host; under `self-hosted`
/// it is a loopback process. An enclave that cannot reach its configured
/// backend cannot run this redactor, and must not silently fall back to
/// [`DeterministicRedaction`] -- a backend failure surfaces as
/// [`SeamUnavailable`], which [`witness`] turns into a refusal.
///
/// # What the verdict does and does not cover
///
/// The report this returns is the originating pass's. The server's PII
/// backstop (`rescrub_envelope_prose_pii_with`) runs a further deterministic
/// sweep over the classifier's *output*, because the classifier is trained on
/// prose PII and can echo a credential back verbatim. That sweep has no
/// counterpart here, so a verdict derived from this report speaks for the
/// originating redaction, not for the backstop.
pub struct FullPipelineRedaction {
    redactor: DeterministicTraceRedactor,
    policy_version: String,
}

impl FullPipelineRedaction {
    /// Build the full pipeline from an explicitly supplied classifier
    /// adapter.
    ///
    /// The adapter is a parameter rather than something read from the
    /// environment here, for the same reason [`DeterministicRedaction::new`]
    /// reads no env: a witness must not have its redaction policy decided by
    /// the environment it happens to boot into. The binary resolves the
    /// backend once, at startup, and a witness that could not resolve one
    /// does not start.
    pub fn new(
        known_path_prefixes: Vec<String>,
        adapter: Arc<dyn PrivacyFilterAdapter>,
        backend: PrivacyFilterBackendTag,
    ) -> Self {
        Self {
            redactor: DeterministicTraceRedactor::deterministic_only(known_path_prefixes)
                .with_privacy_filter(adapter, backend),
            // From the protocol crate's own function, so the alias a server
            // allowlists is the one ingest writes for this same backend.
            policy_version: redaction_pipeline_version(backend),
        }
    }
}

#[async_trait]
impl TranscriptRedactor for FullPipelineRedaction {
    async fn redact(&self, raw: &str) -> Result<RedactedTranscript, SeamUnavailable> {
        // Fail-closed: a `near-ai` or `self-hosted` backend failure comes back
        // as `Err` from the protocol crate and becomes a refusal here. It is
        // never downgraded to the deterministic result, which would be a
        // certificate claiming coverage the pass did not have.
        let result = self
            .redactor
            .redact_text_through_prose_filter(raw)
            .await
            .map_err(|_| SeamUnavailable)?;
        Ok(RedactedTranscript {
            redacted: result.redacted,
            report: result.report,
            policy_version: self.policy_version.clone(),
        })
    }
}

/// The signing seam.
///
/// Synchronous: a dstack implementation fetches the raw private scalar once at
/// construction (`GetKey`, not the agent's `Sign`, which returns a 64-byte
/// `r || s` with no recovery byte that `recover_eip191_signer` cannot use) and
/// signs in-process thereafter. Nothing on this path should reach a socket per
/// signature.
pub trait Signer: Send + Sync {
    /// Sign `message` under EIP-191, returning 65 bytes of `0x`-prefixed hex
    /// with a 27/28 recovery byte -- the form
    /// `WitnessCertificate::verify` recovers from.
    fn sign_eip191(&self, message: &[u8]) -> Result<String, SeamUnavailable>;
}

/// The enclave seam: what the witness can say about the machine it runs on.
///
/// Declared here rather than with its dstack implementation because
/// [`witness`] consumes it as a trait object and would not compile otherwise.
#[async_trait]
pub trait Enclave: Send + Sync {
    /// The address that will sign the certificate this witness issues.
    ///
    /// Here rather than only on [`Signer`] because it is half of what a
    /// nonce-bound quote binds: a contributor compares this against the
    /// address `verify_witness_certificate` recovered, and a quote that named
    /// some other address would attest to a machine that did not sign what it
    /// is holding. Infallible -- a witness that could not name its own signer
    /// failed to start.
    fn signing_address(&self) -> &str;

    /// The measurement a contributor pins before sending anything, and the
    /// server pins before trusting a verdict. Fallible: a witness that cannot
    /// name itself must refuse, not certify anonymously.
    async fn measurement(&self) -> Result<String, SeamUnavailable>;

    /// A nonce-bound attestation quote over `report_data`.
    ///
    /// Not used by [`witness`] -- it is the other half of the surface, served
    /// so a client can verify the measurement *before* sending raw bytes.
    /// dstack accepts up to 64 bytes and zero-pads on the right; an
    /// implementation rejects anything longer rather than truncating.
    async fn attestation_quote(&self, report_data: &[u8]) -> Result<Vec<u8>, SeamUnavailable>;

    /// A quote bound to `nonce` **and** to this witness's signing address.
    ///
    /// Provided rather than required, and the one a surface should call: an
    /// HTTP handler that composed report data itself could compose it wrong,
    /// and the failure -- a quote that does not carry the caller's nonce -- is
    /// a replay that looks exactly like a success.
    async fn nonce_bound_quote(&self, nonce: &[u8]) -> Result<Vec<u8>, SeamUnavailable> {
        let report_data = enclave::witness_report_data(self.signing_address(), nonce)
            .map_err(|_| SeamUnavailable)?;
        self.attestation_quote(&report_data).await
    }
}

/// The residual-risk tier one condition implies.
///
/// The mapping is a `match` rather than [`ResidualRiskCondition::forces_high`]
/// plus an `else`, so that a new condition in the protocol crate is a compile
/// error here and gets a deliberate tier instead of silently inheriting
/// Medium. `condition_tiers_agree_with_the_protocol_crate` pins it against
/// `forces_high` so the two cannot drift apart.
fn condition_tier(condition: ResidualRiskCondition) -> ResidualPiiRisk {
    match condition {
        ResidualRiskCondition::KeyFinding
        | ResidualRiskCondition::CoverageIncomplete
        | ResidualRiskCondition::ResidualSurvivor
        | ResidualRiskCondition::ResidualScanUnavailable => ResidualPiiRisk::High,
        ResidualRiskCondition::FoundAndRemoved | ResidualRiskCondition::ConsentContentFlag => {
            ResidualPiiRisk::Medium
        }
    }
}

/// The verdict a basis implies: the highest tier any condition in it carries,
/// and `Low` when nothing held.
///
/// `ResidualPiiRisk` derives `Ord` in declaration order `Low < Medium < High`,
/// so `max` is the escalating fold and not a coincidence of spelling.
fn verdict_from_basis(basis: &[ResidualRiskCondition]) -> ResidualPiiRisk {
    basis
        .iter()
        .copied()
        .map(condition_tier)
        .fold(ResidualPiiRisk::Low, std::cmp::max)
}

/// Redact, judge, and certify.
///
/// The order of operations is the design:
///
/// 1. **Redact.** The witness performs the redaction; it never checks one.
/// 2. **Judge.** The verdict comes from [`residual_risk_basis`] in the
///    permissive crate -- the same function ingest runs. Not a
///    reimplementation: the certificate is worth something precisely because
///    a known program reached the verdict the server *would have*, and two
///    implementations drift.
/// 3. **Bind.** [`check_correspondence`] over the artifact being returned is
///    the only way to obtain the [`CorrespondenceProof`] that
///    [`WitnessCertificate::from_proof`] requires, so the digest is of those
///    bytes and no others.
/// 4. **Certify.** Name the enclave, stamp the time, sign.
///
/// Every step that cannot complete refuses with a named [`WitnessError`].
/// There is no arm that certifies what it has so far.
///
/// The redactor is a parameter alongside the signer and the enclave. It has
/// to be: `RedactionFailed` is the fail-closed arm this function exists
/// around, and a redactor constructed inside here could not be made to fail,
/// so the guard would be untestable and the deployment's classifier backend
/// would be decided by whatever env the process booted into.
///
/// [`CorrespondenceProof`]: crate::redaction_witness::correspondence::CorrespondenceProof
pub async fn witness(
    request: WitnessRequest,
    policy: &InferenceAttestationPolicy,
    redactor: &dyn TranscriptRedactor,
    signer: &dyn Signer,
    enclave: &dyn Enclave,
) -> Result<WitnessResponse, WitnessError> {
    // First, and before the redaction pass: a submission that will be refused
    // must not first spend a metered classifier, and the projection is onto
    // the raw transcript rather than the redacted artifact -- a completion
    // carrying a secret comes back from the pass as a placeholder, so
    // projecting after redaction would refuse exactly the honest submissions
    // that most needed redacting.
    check_inference_attestation(
        policy,
        request.offered_receipt.as_ref(),
        &WitnessedSession::Transcript,
    )?;

    let RedactedTranscript {
        redacted,
        report,
        policy_version,
    } = redactor
        .redact(&request.raw_transcript)
        .await
        .map_err(|SeamUnavailable| WitnessError::RedactionFailed)?;

    // `None`: this witness runs no detection-only residual scan, so it has no
    // residual findings to report. That is not the same as a scan that came
    // back clean, and the module doc says what a server is choosing to skip
    // when it trusts a pass verdict.
    let basis = residual_risk_basis(&request.consent, &report, None);
    let residual_risk_verdict = verdict_from_basis(&basis);

    // Binds the digest to the bytes returned below and nothing else. The
    // empty span list is not a shortcut around a check -- the witness
    // produced this redaction, so there is no client claim to check -- and
    // the module doc records why a span-bearing check is unavailable here.
    let proof = check_correspondence(&redacted, &redacted, &[])
        .map_err(|_| WitnessError::ArtifactBindingFailed)?;

    let certificate = WitnessCertificate::from_proof(
        proof,
        CertificateDetails {
            residual_risk_verdict,
            redaction_policy_version: policy_version,
            witness_measurement: enclave
                .measurement()
                .await
                .map_err(|SeamUnavailable| WitnessError::MeasurementUnavailable)?,
            timestamp: chrono::Utc::now().timestamp(),
        },
    );

    let signature_hex = signer
        .sign_eip191(&certificate.signing_bytes())
        .map_err(|SeamUnavailable| WitnessError::SigningUnavailable)?;

    Ok(WitnessResponse {
        redacted_artifact: redacted,
        certificate,
        signature_hex,
    })
}

/// The consent grant a claim actually carried, as the witness must apply it.
///
/// This is in the *request* rather than stamped onto the returned envelope
/// afterwards, and that placement is the whole reason the type exists. The
/// certificate binds the serialised envelope bytes; `apply_granted_scopes`
/// run by the client after certification is a byte change the certificate
/// does not cover, so the digest would no longer match what is submitted.
/// The grants therefore have to be inside the bytes the witness digests.
///
/// Attribution only in the sense that the witness does not check them: they
/// come from a claim the issuer minted, and a contributor who lies here has
/// lied to their own issuer, not to the witness.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantedConsent {
    /// The scopes the claim granted.
    pub scopes: Vec<ConsentScope>,
    /// The uses the claim granted.
    pub uses: Vec<TraceAllowedUse>,
}

/// The structured request: a raw contribution and the grants to apply to it.
///
/// The second request shape, alongside [`WitnessRequest`]. The text shape is
/// kept -- the deployment README's smoke tests drive it, and it is the only
/// one that needs no envelope schema -- but it cannot serve the client this
/// design is for: the server holds a serialised
/// [`TraceContributionEnvelope`], never a redacted transcript, so a
/// certificate over a transcript names bytes nothing on the server can check.
#[derive(Clone)]
pub struct WitnessContributionRequest {
    /// The unredacted contribution. Never logged, never echoed, never
    /// persisted.
    pub raw_contribution: RawTraceContribution,
    /// What the contributor's claim granted.
    pub granted: GrantedConsent,
    /// The receipt the contributor offers for this contribution's last
    /// declared inference call.
    ///
    /// Which call that is, is decided by the witness and not by this field:
    /// the receipt is verified against the last `HttpExchange` event in the
    /// contribution's own order. `None` is legal only where the deployment's
    /// [`InferenceAttestationPolicy`] does not require attestation.
    pub offered_receipt: Option<ReceiptPayload>,
}

impl std::fmt::Debug for WitnessContributionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written and withholding, for the same reason
        // `WitnessRequest`'s is: a derived `Debug` on a struct holding an
        // unredacted session is one `?request` away from a log line carrying
        // the whole thing. The grants are withheld too -- they describe a
        // contributor's consent decisions, which is not content but is
        // theirs.
        formatter
            .debug_struct("WitnessContributionRequest")
            .field("raw_contribution", &"<withheld>")
            .field("granted", &"<withheld>")
            .field("offered_receipt", &"<withheld>")
            .finish()
    }
}

/// What the structured path returns: the envelope **as bytes**, and a
/// certificate over exactly those bytes.
///
/// `envelope_bytes` rather than a `TraceContributionEnvelope` is the point of
/// the type. A parsed envelope would have to be serialised again by whoever
/// submits it, and the certificate binds the serialisation this witness
/// performed -- so handing back a parsed value would put a serde round trip
/// between the digest and the submission, which is the failure this whole
/// path exists to remove. Nothing between here and `POST /v1/traces` may
/// deserialise, re-serialise, re-order, pretty-print or append to them.
#[derive(Clone)]
pub struct WitnessContributionResponse {
    /// The serialised envelope, byte for byte as the certificate's digest was
    /// taken over it.
    pub envelope_bytes: Vec<u8>,
    /// The certificate. Its digest is over `envelope_bytes`.
    pub certificate: WitnessCertificate,
    /// EIP-191 signature over `certificate.signing_bytes()`, as 65 bytes of
    /// `0x`-prefixed hex.
    pub signature_hex: String,
}

impl WitnessContributionResponse {
    /// The verdict the certificate binds.
    ///
    /// Read off the certificate, never stored beside it -- the same rule
    /// [`WitnessResponse::residual_risk_verdict`] follows, and for the same
    /// reason: two copies of the field this design turns on eventually
    /// disagree.
    pub fn residual_risk_verdict(&self) -> ResidualPiiRisk {
        self.certificate.residual_risk_verdict()
    }
}

impl std::fmt::Debug for WitnessContributionResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WitnessContributionResponse")
            .field("envelope_bytes", &"<withheld>")
            .field("certificate", &self.certificate)
            .field("signature_hex", &"<withheld>")
            .finish()
    }
}

/// What a structured redaction pass produced.
///
/// The envelope rather than text plus a report, because
/// `TraceRedactor::redact_trace` has already derived
/// `privacy.residual_pii_risk` from its own report using `residual_risk` --
/// the same function ingest runs. Returning the report as well and having
/// [`witness_contribution`] re-derive a verdict from it would create a second
/// source of truth for the one field the design turns on, and the two would
/// eventually disagree. The verdict is read off the envelope.
pub struct RedactedContribution {
    /// The redacted envelope, before the grants are applied.
    pub envelope: TraceContributionEnvelope,
    /// The policy alias this pass reports. **An alias, never an authority**
    /// -- see [`CertificateDetails::redaction_policy_version`].
    pub policy_version: String,
}

/// The structured redaction seam.
///
/// Separate from [`TranscriptRedactor`] rather than a second method on it:
/// the two shapes have different inputs, different outputs and different
/// failure modes, and a deployment that can serve one is not thereby able to
/// serve the other.
///
/// Fallible for the same reasons [`TranscriptRedactor`] is, plus one more the
/// text path does not have: `redact_trace` **refuses** a credential-shaped
/// `outcome.human_correction` rather than masking it (the S5 rule), and that
/// refusal must reach [`witness_contribution`] as
/// [`WitnessError::RedactionFailed`] rather than as a certificate over a
/// masked correction.
#[async_trait]
pub trait ContributionRedactor: Send + Sync {
    /// Private event provenance, available only when every text stage supplied
    /// exact byte replacements. Legacy redactors safely omit maps.
    async fn redact_with_edits(
        &self,
        raw: RawTraceContribution,
    ) -> Result<
        (
            RedactedContribution,
            std::collections::BTreeMap<
                uuid::Uuid,
                trace_commons_protocol::private_edit_map::PrivateRedactionEdits,
            >,
        ),
        SeamUnavailable,
    > {
        Ok((self.redact(raw).await?, std::collections::BTreeMap::new()))
    }
    /// Redact `raw`. `Err` means the pass did not complete; there is no
    /// partial success.
    async fn redact(
        &self,
        raw: RawTraceContribution,
    ) -> Result<RedactedContribution, SeamUnavailable>;
}

/// The structured pipeline, over a [`DeterministicTraceRedactor`].
///
/// One type for both backends rather than a `Deterministic`/`FullPipeline`
/// pair, because unlike the text seam there is nothing to choose between:
/// `redact_trace` is the same call either way and the difference is entirely
/// in how the redactor was built. The constructors mirror
/// [`DeterministicRedaction::new`] and [`FullPipelineRedaction::new`], and
/// read no environment for the same reason those do not -- a witness must not
/// have its redaction policy decided by the environment it happens to boot
/// into.
pub struct PipelineContributionRedaction {
    redactor: DeterministicTraceRedactor,
    policy_version: String,
}

impl PipelineContributionRedaction {
    /// The deterministic secret path, and only that. No network dependency,
    /// so this is what a test uses and what a deployment with no classifier
    /// reachable from inside the enclave can honestly run. Its certificate
    /// says so through `redaction_policy_version`.
    pub fn deterministic_only(known_path_prefixes: Vec<String>) -> Self {
        Self {
            redactor: DeterministicTraceRedactor::deterministic_only(known_path_prefixes),
            policy_version: DETERMINISTIC_REDACTION_PIPELINE_VERSION.to_string(),
        }
    }

    /// Both stages: the deterministic pass, then the prose-PII classifier,
    /// per event. A backend failure surfaces as [`SeamUnavailable`] and
    /// becomes a refusal; it is never downgraded to the deterministic result,
    /// which would be a certificate claiming coverage the pass did not have.
    pub fn with_privacy_filter(
        known_path_prefixes: Vec<String>,
        adapter: Arc<dyn PrivacyFilterAdapter>,
        backend: PrivacyFilterBackendTag,
    ) -> Self {
        Self {
            redactor: DeterministicTraceRedactor::deterministic_only(known_path_prefixes)
                .with_privacy_filter(adapter, backend),
            policy_version: redaction_pipeline_version(backend),
        }
    }
}

#[async_trait]
impl ContributionRedactor for PipelineContributionRedaction {
    async fn redact_with_edits(
        &self,
        raw: RawTraceContribution,
    ) -> Result<
        (
            RedactedContribution,
            std::collections::BTreeMap<
                uuid::Uuid,
                trace_commons_protocol::private_edit_map::PrivateRedactionEdits,
            >,
        ),
        SeamUnavailable,
    > {
        let (envelope, maps) = self
            .redactor
            .redact_trace_with_edits(raw)
            .await
            .map_err(|_| SeamUnavailable)?;
        Ok((
            RedactedContribution {
                envelope,
                policy_version: self.policy_version.clone(),
            },
            maps,
        ))
    }
    async fn redact(
        &self,
        raw: RawTraceContribution,
    ) -> Result<RedactedContribution, SeamUnavailable> {
        let envelope = self
            .redactor
            .redact_trace(raw)
            .await
            .map_err(|_| SeamUnavailable)?;
        Ok(RedactedContribution {
            envelope,
            policy_version: self.policy_version.clone(),
        })
    }
}

/// Redact a contribution, judge it, serialise it **once**, and certify those
/// bytes.
///
/// The structured counterpart of [`witness`], and the one a real client uses.
/// The order of operations is the design, and step 3 is the reason this
/// function exists rather than a parameter swap on the text path:
///
/// 1. **Redact.** `redact_trace` walks the events, applies the tool-payload
///    profiles by tool name, canonicalizes payloads, computes
///    `redaction_hash`, builds the trace card, and refuses a credential-shaped
///    correction rather than masking it. A text pass over a serialised
///    contribution would do none of that and would scrub the correction the
///    S5 rule preserves.
/// 2. **Grant.** `apply_granted_scopes` before serialisation, never after.
/// 3. **Serialise once.** The bytes returned to the caller and the bytes
///    digested are the *same* `Vec`. There is deliberately no second
///    `to_vec` anywhere on this path: a digest taken over a re-serialisation
///    would be a digest of bytes nobody will ever send.
/// 4. **Bind.** [`check_correspondence`] over those bytes is the only way to
///    obtain the [`CorrespondenceProof`] [`WitnessCertificate::from_proof`]
///    requires.
/// 5. **Certify.** Name the enclave, stamp the time, sign.
///
/// The verdict comes off `envelope.privacy.residual_pii_risk`, which
/// `redact_trace` derived with `residual_risk` -- the same function ingest
/// runs. Not re-derived here: the certificate and the envelope must not be
/// able to disagree about the field a server would act on.
///
/// [`CorrespondenceProof`]: crate::redaction_witness::correspondence::CorrespondenceProof
pub async fn witness_contribution(
    mut request: WitnessContributionRequest,
    policy: &InferenceAttestationPolicy,
    redactor: &dyn ContributionRedactor,
    signer: &dyn Signer,
    enclave: &dyn Enclave,
) -> Result<WitnessContributionResponse, WitnessError> {
    // Before the redaction pass, and onto the raw contribution, for the
    // reasons `witness` gives above.
    check_inference_attestation(
        policy,
        request.offered_receipt.as_ref(),
        &WitnessedSession::Contribution(&request.raw_contribution),
    )?;

    inference::strip_raw_inference_bodies(&mut request.raw_contribution);
    let RedactedContribution {
        mut envelope,
        policy_version,
    } = redactor
        .redact(request.raw_contribution)
        .await
        .map_err(|SeamUnavailable| WitnessError::RedactionFailed)?;

    // Inside the certified bytes. A client that had to stamp these after
    // certification would be making a byte change the certificate does not
    // cover, and its submission would fail verification on the server for a
    // reason that looks exactly like tampering.
    apply_granted_scopes(
        &mut envelope,
        &request.granted.scopes,
        &request.granted.uses,
    );

    let residual_risk_verdict = envelope.privacy.residual_pii_risk;

    // Redact, strip, hash, sign -- in that order, and the order is the whole
    // of it. The digest below must cover the artifact the contributor
    // receives, so the bodies have to be gone before `to_string` runs; a
    // strip after serialisation would hand back a certificate naming bytes
    // nobody holds. `strip_inference_bodies` says why they go rather than
    // being kept for a downstream verifier.
    //
    // Unconditional, not gated on whether a receipt was offered or on whether
    // this witness requires one. A refusal returns no artifact at all, and
    // every path that does return one goes through here, so there is no way
    // out of this function that carries a body.
    strip_inference_bodies(&mut envelope);
    // A classifier can echo a secret back. Scan the final contributed leaves
    // and dynamic keys, and refuse an incomplete scan rather than certifying it.
    let residual = trace_commons_protocol::trace_contribution::residual_secret_labels(
        &DeterministicTraceRedactor::deterministic_only(Vec::new()),
        &envelope,
    )
    .map_err(|_| WitnessError::RedactionFailed)?;
    if !residual.is_empty() {
        return Err(WitnessError::RedactionFailed);
    }

    // The single serialisation on this path. `serde_json::to_string` rather
    // than `to_vec` so the same allocation can be handed to
    // `check_correspondence`, which takes `&str`, and then returned as bytes
    // -- `String::into_bytes` moves the buffer and cannot re-encode it.
    let serialised =
        serde_json::to_string(&envelope).map_err(|_| WitnessError::ArtifactBindingFailed)?;

    // Binds the digest to the bytes returned below and nothing else. The
    // empty span list is not a shortcut around a check -- the witness
    // produced this redaction, so there is no client claim to check.
    let proof = check_correspondence(&serialised, &serialised, &[])
        .map_err(|_| WitnessError::ArtifactBindingFailed)?;

    let certificate = WitnessCertificate::from_proof(
        proof,
        CertificateDetails {
            residual_risk_verdict,
            redaction_policy_version: policy_version,
            witness_measurement: enclave
                .measurement()
                .await
                .map_err(|SeamUnavailable| WitnessError::MeasurementUnavailable)?,
            timestamp: chrono::Utc::now().timestamp(),
        },
    );

    let signature_hex = signer
        .sign_eip191(&certificate.signing_bytes())
        .map_err(|SeamUnavailable| WitnessError::SigningUnavailable)?;

    Ok(WitnessContributionResponse {
        envelope_bytes: serialised.into_bytes(),
        certificate,
        signature_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction_witness::verification::{
        WitnessPin, WitnessVerificationError, verify_witness_certificate,
    };
    use k256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use sha3::Keccak256;
    use trace_commons_protocol::trace_contribution::ConsentScope;

    /// A secret the deterministic pass is guaranteed to find: it matches the
    /// `aws_access_key` pattern exactly. Distinctive enough that searching a
    /// serialized response for it cannot match by accident.
    // Split so the twenty-character form never appears verbatim in the
    // source. The value is synthetic -- a keyboard walk, not a
    // credential -- but GitHub push protection matches the shape, and it
    // is right to: a scanner that trusted our word about which
    // AKIA-prefixed strings are fake would be useless. Our own detector
    // requires the prefix, so the fixture cannot avoid it; splitting the
    // literal is the honest way to keep both checks working.
    const SECRET: &str = concat!("AKIA", "QQWERTYUIOPASDFG");

    /// A token that is not secret-shaped and must therefore SURVIVE the
    /// redaction. The positive control for the leak test: without it, a
    /// redactor that returned the empty string would pass every "the secret
    /// is absent" assertion in this file.
    const SURVIVOR: &str = "zzq-control-token-zzq";

    /// A marker fed to a request that is going to be refused. Nothing may
    /// echo it -- not the error, not its `Debug`.
    const REFUSED_MARKER: &str = "zzq-refused-marker-zzq";

    /// The measurement the honest enclave reports and the pin admits.
    const MEASUREMENT: &str = "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";

    fn consent(message_text_included: bool) -> ConsentMetadata {
        ConsentMetadata {
            policy_version: "consent-v1".to_string(),
            scopes: vec![ConsentScope::DebuggingEvaluation],
            message_text_included,
            tool_payloads_included: false,
            correction_included: false,
            routing_metadata_included: false,
            revocable: true,
        }
    }

    fn request(raw: &str, message_text_included: bool) -> WitnessRequest {
        WitnessRequest {
            raw_transcript: raw.to_string(),
            consent: consent(message_text_included),
            offered_receipt: None,
        }
    }

    /// The two service functions, pinned to a witness that requires no
    /// attested inference.
    ///
    /// These shadow `super::witness` and `super::witness_contribution` inside
    /// the test module on purpose. Every test below this line was written
    /// about redaction, verdicts and certificates, and adding a policy
    /// parameter to their call sites would have said nothing about any of
    /// them. The attested-inference behaviour is exercised by tests that call
    /// the real functions with a real policy -- see `inference_requirement`
    /// below and `witness_service::inference` -- so this shadowing narrows
    /// what the old tests say rather than weakening what anything checks.
    async fn witness(
        request: WitnessRequest,
        redactor: &dyn TranscriptRedactor,
        signer: &dyn Signer,
        enclave: &dyn Enclave,
    ) -> Result<WitnessResponse, WitnessError> {
        super::witness(
            request,
            &InferenceAttestationPolicy::not_required(),
            redactor,
            signer,
            enclave,
        )
        .await
    }

    async fn witness_contribution(
        request: WitnessContributionRequest,
        redactor: &dyn ContributionRedactor,
        signer: &dyn Signer,
        enclave: &dyn Enclave,
    ) -> Result<WitnessContributionResponse, WitnessError> {
        super::witness_contribution(
            request,
            &InferenceAttestationPolicy::not_required(),
            redactor,
            signer,
            enclave,
        )
        .await
    }

    /// The production redaction seam, with no known path prefixes so that
    /// `local_path` -- present in 93% of real sessions and deliberately
    /// non-severity-bearing -- cannot be what a verdict assertion is
    /// observing.
    fn redactor() -> DeterministicRedaction {
        DeterministicRedaction::new(Vec::new())
    }

    struct TestSigner(SigningKey);

    impl TestSigner {
        fn new(seed: &str) -> Self {
            let bytes = Keccak256::digest(seed.as_bytes());
            Self(SigningKey::from_slice(&bytes).expect("seed is a valid scalar"))
        }

        fn address(&self) -> String {
            let point = self.0.verifying_key().to_encoded_point(false);
            let digest = Keccak256::digest(&point.as_bytes()[1..]);
            format!("0x{}", hex::encode(&digest[12..]))
        }
    }

    impl Signer for TestSigner {
        fn sign_eip191(&self, message: &[u8]) -> Result<String, SeamUnavailable> {
            let mut hasher = Keccak256::new();
            hasher.update(b"\x19Ethereum Signed Message:\n");
            hasher.update(message.len().to_string().as_bytes());
            hasher.update(message);
            let digest: [u8; 32] = hasher.finalize().into();
            let (signature, recovery_id) = self
                .0
                .sign_prehash_recoverable(&digest)
                .expect("the digest is 32 bytes");
            let mut raw = signature.to_bytes().to_vec();
            raw.push(recovery_id.to_byte() + 27);
            Ok(format!("0x{}", hex::encode(raw)))
        }
    }

    struct RefusingSigner;

    impl Signer for RefusingSigner {
        fn sign_eip191(&self, _message: &[u8]) -> Result<String, SeamUnavailable> {
            Err(SeamUnavailable)
        }
    }

    /// The address the enclave doubles report. Production unites the signing
    /// and enclave seams in one `DstackEnclave`; the doubles split them, so
    /// this is a constant rather than the `TestSigner`'s address.
    const ENCLAVE_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    struct TestEnclave;

    #[async_trait]
    impl Enclave for TestEnclave {
        fn signing_address(&self) -> &str {
            ENCLAVE_ADDRESS
        }

        async fn measurement(&self) -> Result<String, SeamUnavailable> {
            Ok(MEASUREMENT.to_string())
        }

        async fn attestation_quote(&self, _report_data: &[u8]) -> Result<Vec<u8>, SeamUnavailable> {
            Ok(vec![0xab; 8])
        }
    }

    struct SilentEnclave;

    #[async_trait]
    impl Enclave for SilentEnclave {
        fn signing_address(&self) -> &str {
            ENCLAVE_ADDRESS
        }

        async fn measurement(&self) -> Result<String, SeamUnavailable> {
            Err(SeamUnavailable)
        }

        async fn attestation_quote(&self, _report_data: &[u8]) -> Result<Vec<u8>, SeamUnavailable> {
            Err(SeamUnavailable)
        }
    }

    /// A stand-in prose classifier. It removes a person's name, which the
    /// deterministic regex suite does not touch, so its effect on the output
    /// is distinguishable from the deterministic stage's.
    struct NameRemovingFilter;

    #[async_trait]
    impl trace_commons_protocol::trace_contribution::PrivacyFilterAdapter for NameRemovingFilter {
        async fn redact_text(
            &self,
            text: &str,
        ) -> Result<
            Option<trace_commons_protocol::trace_contribution::SafePrivacyFilterRedaction>,
            trace_commons_protocol::trace_contribution::TraceContributionError,
        > {
            Ok(Some(
                trace_commons_protocol::trace_contribution::SafePrivacyFilterRedaction {
                    private_edits: None,
                    redacted_text: text.replace(CLASSIFIER_ONLY_PII, "<PROSE_NAME>"),
                    summary: Default::default(),
                    report: RedactionReport::default(),
                },
            ))
        }
    }

    /// A classifier backend that is down.
    struct UnavailableFilter;

    #[async_trait]
    impl trace_commons_protocol::trace_contribution::PrivacyFilterAdapter for UnavailableFilter {
        async fn redact_text(
            &self,
            _text: &str,
        ) -> Result<
            Option<trace_commons_protocol::trace_contribution::SafePrivacyFilterRedaction>,
            trace_commons_protocol::trace_contribution::TraceContributionError,
        > {
            Err(
                trace_commons_protocol::trace_contribution::TraceContributionError::RedactionFailed {
                    reason: "classifier down".to_string(),
                },
            )
        }
    }

    /// Prose PII the deterministic pass leaves alone.
    const CLASSIFIER_ONLY_PII: &str = "Alice Brannigan";

    /// The full-pipeline redactor runs BOTH stages. Asserted on the two
    /// findings separately, because a redactor that ran only one of them
    /// would still satisfy an assertion about the other.
    #[tokio::test]
    async fn the_full_pipeline_redactor_runs_the_classifier_and_the_deterministic_pass() {
        let redactor = FullPipelineRedaction::new(
            Vec::new(),
            Arc::new(NameRemovingFilter),
            PrivacyFilterBackendTag::SelfHosted,
        );
        let raw = format!("{CLASSIFIER_ONLY_PII} deployed {SECRET} and kept {SURVIVOR}");

        let result = redactor.redact(&raw).await.expect("both stages succeed");

        assert!(
            !result.redacted.contains(SECRET),
            "deterministic stage did not run: {}",
            result.redacted
        );
        assert!(
            !result.redacted.contains(CLASSIFIER_ONLY_PII),
            "classifier stage did not run: {}",
            result.redacted
        );
        assert!(
            result.redacted.contains(SURVIVOR),
            "a redactor that emptied the text would pass the two assertions \
             above; it must not: {}",
            result.redacted
        );
        assert!(
            result.report.blocked_secret_detected,
            "the report must carry what the pass found: {:?}",
            result.report
        );
    }

    /// The policy alias names the backend that actually ran, and comes from
    /// the protocol crate's own function rather than a string assembled here.
    #[tokio::test]
    async fn the_full_pipeline_policy_alias_names_the_configured_backend() {
        for backend in [
            PrivacyFilterBackendTag::SelfHosted,
            PrivacyFilterBackendTag::NearAi,
            PrivacyFilterBackendTag::Sidecar,
        ] {
            let redactor =
                FullPipelineRedaction::new(Vec::new(), Arc::new(NameRemovingFilter), backend);
            let result = redactor.redact("nothing here").await.expect("succeeds");
            assert_eq!(
                result.policy_version,
                redaction_pipeline_version(backend),
                "alias must come from the protocol crate for {backend:?}"
            );
            assert_ne!(
                result.policy_version, DETERMINISTIC_REDACTION_PIPELINE_VERSION,
                "a full-pipeline witness must not report the deterministic \
                 alias for {backend:?}"
            );
        }
    }

    /// Fail-closed: a classifier backend that is down makes the witness
    /// refuse. It must NEVER hand back the deterministic-only result, which
    /// would be a certificate claiming coverage the pass did not have.
    #[tokio::test]
    async fn a_down_classifier_refuses_rather_than_degrading() {
        for backend in [
            PrivacyFilterBackendTag::SelfHosted,
            PrivacyFilterBackendTag::NearAi,
        ] {
            let redactor =
                FullPipelineRedaction::new(Vec::new(), Arc::new(UnavailableFilter), backend);
            let outcome = redactor.redact(&format!("deployed {SECRET}")).await;
            assert!(
                outcome.is_err(),
                "{backend:?}: a down classifier must refuse, not degrade to \
                 the deterministic pass"
            );
        }
    }

    struct RefusingRedactor;

    #[async_trait]
    impl TranscriptRedactor for RefusingRedactor {
        async fn redact(&self, _raw: &str) -> Result<RedactedTranscript, SeamUnavailable> {
            Err(SeamUnavailable)
        }
    }

    /// A redactor that reports a coverage gap. The only way to reach a High
    /// verdict here: `coverage_incomplete` is set when a configured filter
    /// was unavailable or skipped content, and the deterministic pass over
    /// well-formed UTF-8 never sets it.
    struct CoverageGapRedactor;

    #[async_trait]
    impl TranscriptRedactor for CoverageGapRedactor {
        async fn redact(&self, raw: &str) -> Result<RedactedTranscript, SeamUnavailable> {
            let report = RedactionReport {
                coverage_incomplete: true,
                ..RedactionReport::default()
            };
            Ok(RedactedTranscript {
                redacted: raw.to_string(),
                report,
                policy_version: "coverage-gap-test-policy".to_string(),
            })
        }
    }

    fn pin(signer: &TestSigner) -> WitnessPin {
        WitnessPin::new(&signer.address(), [MEASUREMENT.to_string()])
            .expect("the address and measurement are well formed")
    }

    #[tokio::test]
    async fn a_witnessed_artifact_and_its_certificate_agree() {
        let signer = TestSigner::new("witness-agreement");
        let response = witness(
            request(&format!("deploying {SURVIVOR} with {SECRET}"), false),
            &redactor(),
            &signer,
            &TestEnclave,
        )
        .await
        .expect("the witness certifies");

        // Ground truth from outside: the digest is checked against the bytes
        // the response actually returns, not against anything the witness
        // computed internally. A certificate over a DIFFERENT artifact is the
        // failure mode the whole design exists to prevent, and
        // `verify_witness_certificate` is the server's own check, so this
        // exercises the real consumer rather than a restatement of it.
        let verified = verify_witness_certificate(
            response.certificate.clone(),
            &response.signature_hex,
            Some(&pin(&signer)),
            response.redacted_artifact.as_bytes(),
        )
        .expect("the certificate verifies against the artifact it was returned with");

        assert_eq!(
            verified.redacted_sha256(),
            hex::encode(Sha256::digest(response.redacted_artifact.as_bytes())),
            "the certificate's digest must be of the returned bytes"
        );
        assert_eq!(verified.witness_measurement(), MEASUREMENT);
    }

    #[tokio::test]
    async fn the_verdict_matches_what_the_shared_function_says() {
        // Three cases through the production redactor, chosen so a constant
        // verdict cannot satisfy them: an empty basis, the found-and-removed
        // floor, and the consent-flag floor. The expected basis is asserted
        // against `residual_risk_basis` run directly on the same input --
        // ground truth from the permissive crate, outside the code under
        // test -- and the expected verdict is a literal, so neither the
        // shared function nor this module's mapping can drift unnoticed.
        let cases: [(&str, bool, Vec<ResidualRiskCondition>, ResidualPiiRisk); 3] = [
            (
                "the build finished and the tests passed",
                false,
                Vec::new(),
                ResidualPiiRisk::Low,
            ),
            (
                // Split for the reason given at SECRET above.
                concat!("exported AWS_ACCESS_KEY_ID=", "AKIA", "QQWERTYUIOPASDFG"),
                false,
                vec![ResidualRiskCondition::FoundAndRemoved],
                ResidualPiiRisk::Medium,
            ),
            (
                "the build finished and the tests passed",
                true,
                vec![ResidualRiskCondition::ConsentContentFlag],
                ResidualPiiRisk::Medium,
            ),
        ];

        // Collected and compared whole, not asserted inside the loop. An
        // in-loop `assert_eq!` short-circuits, so the first divergent case
        // masks every later one -- and a mutation that gets exactly one case
        // wrong would look identical to a mutation that gets all of them
        // wrong. Comparing the full vectors reports every case.
        let mut actual_bases = Vec::new();
        let mut expected_bases = Vec::new();
        let mut actual_verdicts = Vec::new();
        let mut expected_verdicts = Vec::new();

        for (raw, message_text_included, expected_basis, expected_verdict) in cases {
            let consent = consent(message_text_included);
            let (_, report) =
                DeterministicTraceRedactor::deterministic_only(Vec::new()).redact_text(raw);
            actual_bases.push(residual_risk_basis(&consent, &report, None));
            expected_bases.push(expected_basis);

            let response = witness(
                request(raw, message_text_included),
                &redactor(),
                &TestSigner::new("witness-verdict"),
                &TestEnclave,
            )
            .await
            .expect("the witness certifies");
            actual_verdicts.push(response.residual_risk_verdict());
            expected_verdicts.push(expected_verdict);
        }

        // The High tier, unreachable through the deterministic pass because
        // it never sets a coverage gap. Without this case a mapping that
        // never returns High would satisfy every assertion above.
        let response = witness(
            request("the build finished and the tests passed", false),
            &CoverageGapRedactor,
            &TestSigner::new("witness-verdict"),
            &TestEnclave,
        )
        .await
        .expect("the witness certifies");
        actual_verdicts.push(response.residual_risk_verdict());
        expected_verdicts.push(ResidualPiiRisk::High);

        assert_eq!(
            actual_bases, expected_bases,
            "the shared function's basis changed for at least one case"
        );
        assert_eq!(
            actual_verdicts, expected_verdicts,
            "the witness verdict diverged from the shared function for at least one case"
        );
    }

    #[test]
    fn condition_tiers_agree_with_the_protocol_crate() {
        // Pins this module's `match` against `forces_high` in the permissive
        // crate. Iterating `ALL` rather than a list written here is what
        // makes a newly added condition reach this test at all.
        for condition in ResidualRiskCondition::ALL.iter().copied() {
            let expected = if condition.forces_high() {
                ResidualPiiRisk::High
            } else {
                ResidualPiiRisk::Medium
            };
            assert_eq!(
                condition_tier(condition),
                expected,
                "tier for {condition:?} disagrees with forces_high"
            );
        }
    }

    #[tokio::test]
    async fn raw_bytes_never_appear_in_a_response_or_an_error() {
        let signer = TestSigner::new("witness-leak");
        let raw = format!("session start\n{SURVIVOR}\nexport KEY={SECRET}\nsession end");

        let response = witness(request(&raw, false), &redactor(), &signer, &TestEnclave)
            .await
            .expect("the witness certifies");

        // The positive control first: if this fails, every absence assertion
        // below is satisfied by a redactor that returned nothing, and the
        // test would have been proving that.
        assert!(
            response.redacted_artifact.contains(SURVIVOR),
            "non-secret content must survive, or the absence checks below are vacuous"
        );

        // Every surface the success path hands a caller, searched for the
        // secret itself rather than asserted about which function ran.
        // Named, and every leaking surface collected before asserting: a
        // `for` loop of `assert!` stops at the first one and would report a
        // single leak where there were four.
        let surfaces = [
            ("redacted_artifact", response.redacted_artifact.clone()),
            ("Debug of the response", format!("{response:?}")),
            (
                "Debug of the certificate",
                format!("{:?}", response.certificate),
            ),
            ("signature_hex", response.signature_hex.clone()),
        ];
        let leaking: Vec<&str> = surfaces
            .iter()
            .filter(|(_, rendered)| rendered.contains(SECRET))
            .map(|(name, _)| *name)
            .collect();
        assert!(
            leaking.is_empty(),
            "witness surfaces carried the raw secret: {leaking:?}"
        );

        // And the refusal path. A refused request returns nothing at all, so
        // the marker here is ordinary text rather than a secret: if any part
        // of the input can reach an error rendering, this catches it.
        let refused = witness(
            request(&format!("plain text {REFUSED_MARKER}"), false),
            &RefusingRedactor,
            &signer,
            &TestEnclave,
        )
        .await
        .expect_err("the witness refuses");
        let error_surfaces = [
            ("Display", format!("{refused}")),
            ("Debug", format!("{refused:?}")),
        ];
        let leaking: Vec<&str> = error_surfaces
            .iter()
            .filter(|(_, rendered)| rendered.contains(REFUSED_MARKER) || rendered.contains(SECRET))
            .map(|(name, _)| *name)
            .collect();
        assert!(
            leaking.is_empty(),
            "witness error renderings carried request content: {leaking:?}"
        );
    }

    #[tokio::test]
    async fn a_redaction_failure_refuses_rather_than_certifying_what_it_has() {
        let error = witness(
            request(&format!("export KEY={SECRET}"), false),
            &RefusingRedactor,
            &TestSigner::new("witness-refusal"),
            &TestEnclave,
        )
        .await
        .expect_err("a redaction that did not complete cannot be certified");
        assert_eq!(error, WitnessError::RedactionFailed);
    }

    #[tokio::test]
    async fn an_enclave_that_cannot_name_itself_refuses() {
        // A certificate naming no program is one an operator's pin can never
        // match, and signing it would put an unpinnable certificate into
        // circulation.
        let error = witness(
            request("the build finished", false),
            &redactor(),
            &TestSigner::new("witness-refusal"),
            &SilentEnclave,
        )
        .await
        .expect_err("a witness that cannot name itself cannot certify");
        assert_eq!(error, WitnessError::MeasurementUnavailable);
    }

    #[tokio::test]
    async fn a_signer_that_refuses_yields_no_response() {
        let error = witness(
            request("the build finished", false),
            &redactor(),
            &RefusingSigner,
            &TestEnclave,
        )
        .await
        .expect_err("an unsigned certificate is not a certificate");
        assert_eq!(error, WitnessError::SigningUnavailable);
    }

    // ---------------------------------------------------------------
    // The structured path: a certificate over the envelope bytes.
    // ---------------------------------------------------------------

    /// The structured redaction seam, deterministic-only, with no known path
    /// prefixes -- so `local_path`, present in 93% of real sessions and
    /// deliberately non-severity-bearing, cannot be what a verdict assertion
    /// is actually observing.
    fn contribution_redactor() -> PipelineContributionRedaction {
        PipelineContributionRedaction::deterministic_only(Vec::new())
    }

    fn granted() -> GrantedConsent {
        GrantedConsent {
            scopes: vec![
                ConsentScope::DebuggingEvaluation,
                ConsentScope::ModelTraining,
            ],
            uses: vec![TraceAllowedUse::Debugging, TraceAllowedUse::Evaluation],
        }
    }

    /// One turn of session content carrying the secret, plus a tool event with
    /// a structured payload, so the structured path's per-event walk and its
    /// payload canonicalization are both on the path a test observes.
    fn raw_contribution(text: &str) -> RawTraceContribution {
        use trace_commons_protocol::trace_contribution::{
            RawTraceCaptureTurn, RawTraceContributionEvent, RecordedTraceContributionOptions,
            TraceContributionEventType,
        };
        let started = chrono::Utc::now();
        let mut raw = RawTraceContribution::from_capture_turns(
            &[RawTraceCaptureTurn {
                user_input: text.to_string(),
                response: None,
                tool_calls: Vec::new(),
                started_at: started,
                completed_at: Some(started + chrono::Duration::milliseconds(10)),
                state: Some("Completed".to_string()),
            }],
            RecordedTraceContributionOptions {
                include_message_text: true,
                ..RecordedTraceContributionOptions::default()
            },
        );
        // Keys deliberately out of sorted order in the source. Under
        // `serde_json/preserve_order` -- which `dcap-qvl` turns on in every
        // graph containing this crate -- an uncanonicalized payload would
        // serialise in this order, so this fixture is what
        // `redact_trace`'s `canonicalize_event_payloads` is observable
        // through.
        raw.events.push(RawTraceContributionEvent {
            event_id: uuid::Uuid::new_v4(),
            parent_event_id: None,
            event_type: TraceContributionEventType::ToolResult,
            timestamp: started,
            content: None,
            structured_payload: serde_json::json!({
                "zeta": 1,
                "alpha": {"omega": 2.5, "beta": [3, 4]},
                "middle": SURVIVOR,
            }),
            tool_name: Some("Bash".to_string()),
            tool_call_id: Some("call-1".to_string()),
            latency_ms: Some(12),
            token_counts: None,
            cost_usd: None,
            success: Some(true),
            failure_modes: Vec::new(),
        });
        raw
    }

    fn contribution_request(text: &str) -> WitnessContributionRequest {
        WitnessContributionRequest {
            raw_contribution: raw_contribution(text),
            granted: granted(),
            offered_receipt: None,
        }
    }

    fn raw_with_correction(correction: &str) -> WitnessContributionRequest {
        let mut request = contribution_request("ran the build");
        request.raw_contribution.outcome.human_correction = Some(correction.to_string());
        request
    }

    #[tokio::test]
    async fn the_certificate_covers_the_bytes_the_response_returns() {
        let response = witness_contribution(
            contribution_request(&format!("deploy key {SECRET} and {SURVIVOR}")),
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");

        // Ground truth taken from the returned bytes, not from anything the
        // witness computed internally and not from a re-serialisation of the
        // parsed envelope -- a test that re-serialises cannot catch a
        // serialisation bug.
        assert_eq!(
            response.certificate.claimed_redacted_sha256(),
            hex::encode(Sha256::digest(&response.envelope_bytes)),
        );
    }

    #[tokio::test]
    async fn the_returned_bytes_deserialise_to_a_submittable_envelope_carrying_the_grants() {
        let response = witness_contribution(
            contribution_request("ran the build"),
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");

        let envelope: TraceContributionEnvelope =
            serde_json::from_slice(&response.envelope_bytes).expect("the bytes are an envelope");
        assert_eq!(envelope.consent.scopes, granted().scopes);
        assert_eq!(envelope.trace_card.allowed_uses, granted().uses);
        // The client must not need to stamp anything afterwards: an empty set
        // here forces a post-certification write, which is a byte change the
        // certificate does not cover.
        assert!(!envelope.consent.scopes.is_empty());
        // And the grants must be the CLAIM's, not the raw contribution's --
        // otherwise this test would pass on a witness that ignored them.
        assert_ne!(
            envelope.consent.scopes,
            raw_contribution("ran the build").consent.scopes,
            "the fixture cannot tell an applied grant from an ignored one"
        );
    }

    #[tokio::test]
    async fn a_reserialisation_of_the_envelope_would_break_the_digest() {
        // The guard the whole "bytes as received" rule rests on.
        //
        // The plan asked this test to assert that a *compact* serde round
        // trip moves bytes. Measured, it does not, and the reason is
        // structural rather than a bad fixture: the only untyped JSON in a
        // `TraceContributionEnvelope` is `event.structured_payload`, and
        // `redact_trace` runs `canonicalize_event_payloads` over every one
        // of them before returning, so the map is key-sorted under either
        // backing map and the round trip is a no-op. Every other field is a
        // `#[derive(Serialize)]` struct written in declaration order.
        // `a_compact_round_trip_is_byte_stable_today` records that as a
        // measured fact.
        //
        // So the divergence is constructed rather than hoped for. Pretty
        // printing is the realistic accident -- a client that logs the
        // envelope, or reformats it, or hands it to a framework that does --
        // and it always moves bytes, so this assertion is falsifiable in
        // every build graph rather than only in one.
        let response = witness_contribution(
            contribution_request("ran the build"),
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");

        let reserialised = serde_json::to_vec_pretty(
            &serde_json::from_slice::<TraceContributionEnvelope>(&response.envelope_bytes).unwrap(),
        )
        .unwrap();
        assert_ne!(
            reserialised, response.envelope_bytes,
            "the fixture cannot detect a re-serialisation"
        );
        assert_eq!(
            response.certificate.claimed_redacted_sha256(),
            hex::encode(Sha256::digest(&response.envelope_bytes)),
        );
        assert_ne!(
            response.certificate.claimed_redacted_sha256(),
            hex::encode(Sha256::digest(&reserialised)),
        );
    }

    #[tokio::test]
    async fn a_compact_round_trip_is_byte_stable_today() {
        // Measured, not relied upon. This is the fact that makes the
        // constructed divergence above necessary, and it is pinned here so
        // that if it ever stops being true -- a new untyped-JSON field, a
        // payload the canonicalizer does not reach -- the reason the other
        // test is shaped the way it is stops being a mystery.
        //
        // It is NOT a licence for a client to re-serialise. The rule is that
        // the bytes travel verbatim; this test says only that today's
        // envelope happens not to punish breaking it in one specific way.
        let response = witness_contribution(
            contribution_request("ran the build"),
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");

        let round_tripped = serde_json::to_vec(
            &serde_json::from_slice::<TraceContributionEnvelope>(&response.envelope_bytes).unwrap(),
        )
        .unwrap();
        assert_eq!(round_tripped, response.envelope_bytes);
    }

    #[tokio::test]
    async fn a_correction_is_not_rewritten_by_the_structured_path() {
        // The S5 rule. A text pass over a serialized contribution would
        // scrub the path out of this and destroy the explanation.
        let correction = "the agent used /Users/zaki/proj/config.toml instead of the staging one";
        let response = witness_contribution(
            raw_with_correction(correction),
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect("a correction naming a path is not a refusal");

        let envelope: TraceContributionEnvelope =
            serde_json::from_slice(&response.envelope_bytes).unwrap();
        assert_eq!(
            envelope.outcome.human_correction.as_deref(),
            Some(correction)
        );
    }

    #[tokio::test]
    async fn a_credential_shaped_correction_is_refused_by_name() {
        let err = witness_contribution(
            raw_with_correction(&format!("the token is {SECRET}")),
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect_err("a credential in a correction is refused, not masked");
        assert_eq!(err, WitnessError::RedactionFailed);
    }

    #[tokio::test]
    async fn the_verdict_matches_what_the_envelope_carries() {
        let response = witness_contribution(
            contribution_request(&format!("deploy key {SECRET} and {SURVIVOR}")),
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");

        let envelope: TraceContributionEnvelope =
            serde_json::from_slice(&response.envelope_bytes).unwrap();
        assert_eq!(
            response.residual_risk_verdict(),
            envelope.privacy.residual_pii_risk,
            "two sources of truth for the field the design turns on"
        );
        // A positive control. Both sides being `Low` by default would make
        // the equality above hold on a witness that read neither.
        assert_ne!(
            envelope.privacy.residual_pii_risk,
            ResidualPiiRisk::Low,
            "the fixture must carry a finding, or the agreement is vacuous"
        );
    }

    #[tokio::test]
    async fn a_structured_certificate_verifies_against_the_bytes_it_returned() {
        let signer = TestSigner::new("witness");
        let response = witness_contribution(
            contribution_request(&format!("deploy key {SECRET}")),
            &contribution_redactor(),
            &signer,
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");

        // The end-to-end statement: the server's own verifier, over the exact
        // bytes the client will submit.
        verify_witness_certificate(
            response.certificate.clone(),
            &response.signature_hex,
            Some(&pin(&signer)),
            &response.envelope_bytes,
        )
        .expect("the certificate the witness issued verifies against the bytes it returned");

        // And it refuses one byte later, which is what says the check above
        // is over these bytes rather than over anything a witness asserted.
        let mut tampered = response.envelope_bytes.clone();
        tampered.push(b'\n');
        let err = verify_witness_certificate(
            response.certificate,
            &response.signature_hex,
            Some(&pin(&signer)),
            &tampered,
        )
        .expect_err("an appended newline is a different artifact");
        assert!(matches!(err, WitnessVerificationError::ArtifactMismatch));
    }

    #[tokio::test]
    async fn raw_bytes_never_appear_in_a_structured_response_or_an_error() {
        let signer = TestSigner::new("witness");
        let response = witness_contribution(
            contribution_request(&format!("deploy key {SECRET} and {SURVIVOR}")),
            &contribution_redactor(),
            &signer,
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");

        let rendered = String::from_utf8(response.envelope_bytes.clone()).unwrap();
        assert!(!rendered.contains(SECRET), "the secret survived redaction");
        // The positive control. Without it a redactor that emitted an empty
        // envelope would satisfy the assertion above.
        assert!(
            rendered.contains(SURVIVOR),
            "the survivor was removed too, so the assertion above proves nothing"
        );
        assert!(!format!("{response:?}").contains(SECRET));
        assert!(
            !format!("{response:?}").contains(SURVIVOR),
            "Debug rendered the envelope, which is contributor content"
        );

        // And on the refusal path.
        let refused = witness_contribution(
            raw_with_correction(&format!("the token is {SECRET} {REFUSED_MARKER}")),
            &contribution_redactor(),
            &signer,
            &TestEnclave,
        )
        .await
        .expect_err("a credential in a correction is refused");
        for rendering in [format!("{refused}"), format!("{refused:?}")] {
            assert!(!rendering.contains(SECRET));
            assert!(!rendering.contains(REFUSED_MARKER));
        }

        let request = raw_with_correction(REFUSED_MARKER);
        assert!(!format!("{request:?}").contains(REFUSED_MARKER));
    }

    /// The markers a stripping test needs: distinctive enough that finding one
    /// in a response cannot be an accident, and not secret-shaped, so the
    /// redaction pass has no reason to remove them. If the redactor removed
    /// them, an absence assertion would pass against a witness that strips
    /// nothing.
    const REQUEST_BODY_MARKER: &str = "zzq-request-body-marker-zzq";
    const RESPONSE_BODY_MARKER: &str = "zzq-response-body-marker-zzq";
    const HEADER_MARKER: &str = "zzq-bearer-marker-zzq";
    /// The positive control's marker, and it is in the URL's **host**, not
    /// its path.
    ///
    /// It used to be a path segment, and it survived only because
    /// `tool_payload_profile` recognised no profile for the name `inference`
    /// and so ran no structural rules at all. That fallback now falls closed,
    /// and the restrictive profile sanitizes a URL exactly as the browser
    /// profile always did -- host kept, path replaced. So a path segment is
    /// no longer a control for "the exchange survived"; it is a control for
    /// the hole this test was written to describe.
    ///
    /// The host is the right marker: it survives redaction under every
    /// profile, so the assertion still fails if the witness deletes the
    /// event, empties the artifact, or strips more than the bodies.
    const URL_MARKER: &str = "zzq-url-marker-zzq";

    /// A contribution whose final `HttpExchange` carries bodies, a header
    /// bearing a credential, and a URL that must survive.
    fn contribution_with_exchange() -> WitnessContributionRequest {
        use trace_commons_protocol::trace_contribution::{
            RawTraceContributionEvent, TraceContributionEventType,
        };
        let mut request = contribution_request("ran the build");
        // Two fixture choices that are load-bearing, and both were found by
        // watching this test fail rather than by reading.
        //
        // The tool name is `inference` rather than `http`, which is the case
        // the profile table used to miss entirely: it keyed on the *name*,
        // and a name containing http, browser or web dropped `body` and
        // `headers` while every other name ran no structural rules at all.
        // An exchange captured under any other name was a raw prompt and a
        // live `Authorization` header on their way to storage.
        //
        // The protocol's fallback now falls closed, so the pass no longer
        // leaves them behind. This strip is still not redundant: it *removes*
        // the fields rather than replacing them with markers a reader has to
        // reason about, it runs before the digest so the certificate covers
        // the bytes the contributor holds, and it makes the guarantee a
        // property of the witness rather than of a classifier table. Keeping
        // this fixture on an unrecognised name keeps both controls honest --
        // if the protocol fallback regresses, the protocol's own tests fail;
        // if this strip regresses, these do.
        //
        // Payload consent is granted, which is the other configuration in which
        // this strip does any work: without it the redaction pass already
        // removes an `http_exchange`'s bodies and headers as
        // `browser_content` and `browser_header`. The requirement needs the
        // bodies present in the raw input, so it needs this flag -- and that
        // is exactly the case where an unstripped artifact would carry them
        // onward.
        request.raw_contribution.consent.tool_payloads_included = true;
        request
            .raw_contribution
            .events
            .push(RawTraceContributionEvent {
                event_id: uuid::Uuid::new_v4(),
                parent_event_id: None,
                event_type: TraceContributionEventType::HttpExchange,
                timestamp: chrono::Utc::now(),
                content: Some(format!(
                    r#"{{"choices":[{{"message":{{"content":"{RESPONSE_BODY_MARKER}"}}}}]}}"#
                )),
                structured_payload: serde_json::json!({
                    "request": {
                        "method": "POST",
                        "url": format!("https://{URL_MARKER}.invalid/v1/chat/completions"),
                        "headers": {"authorization": format!("Bearer {HEADER_MARKER}")},
                        "body": format!(r#"{{"model":"m","prompt":"{REQUEST_BODY_MARKER}"}}"#),
                    },
                    "response": {"status": 200, "headers": {"x-request-id": HEADER_MARKER}},
                }),
                tool_name: Some("inference".to_string()),
                tool_call_id: None,
                latency_ms: None,
                token_counts: None,
                cost_usd: None,
                success: Some(true),
                failure_modes: Vec::new(),
            });
        request
    }

    /// The artifact a contributor receives carries no inference body and no
    /// header, and still carries the exchange itself.
    #[tokio::test]
    async fn the_returned_artifact_carries_no_inference_bodies_or_headers() {
        let response = witness_contribution(
            contribution_with_exchange(),
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");
        let artifact =
            String::from_utf8(response.envelope_bytes.clone()).expect("the envelope is UTF-8");

        // The positive control first. Without it, a witness that returned an
        // empty document would pass every absence assertion below -- and so
        // would one that deleted the whole event, which is not what this
        // strips.
        assert!(
            artifact.contains(URL_MARKER),
            "the exchange itself must survive: method, URL and status are \
             ordinary trace content"
        );

        for (label, marker) in [
            ("the request body", REQUEST_BODY_MARKER),
            ("the response body", RESPONSE_BODY_MARKER),
            ("a header", HEADER_MARKER),
        ] {
            assert!(
                !artifact.contains(marker),
                "{label} reached the artifact the contributor submits"
            );
        }
    }

    /// The ordering: redact, strip, hash, sign. A digest taken before the strip
    /// names bytes nobody holds, and every verification downstream fails as an
    /// artifact mismatch -- which looks exactly like tampering.
    #[tokio::test]
    async fn the_certificate_covers_the_stripped_bytes_and_not_the_unstripped_ones() {
        let signer = TestSigner::new("witness");
        let response = witness_contribution(
            contribution_with_exchange(),
            &contribution_redactor(),
            &signer,
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");

        verify_witness_certificate(
            response.certificate.clone(),
            &response.signature_hex,
            Some(&pin(&signer)),
            &response.envelope_bytes,
        )
        .expect(
            "the certificate must cover the stripped artifact the contributor \
             actually holds",
        );

        // And the digest is genuinely over these bytes rather than over
        // something the witness asserted about them.
        let mut tampered = response.envelope_bytes.clone();
        tampered.push(b'\n');
        assert!(matches!(
            verify_witness_certificate(
                response.certificate,
                &response.signature_hex,
                Some(&pin(&signer)),
                &tampered,
            )
            .expect_err("an appended newline is a different artifact"),
            WitnessVerificationError::ArtifactMismatch
        ));
    }

    /// Stripping is not conditional on attestation. A witness that requires
    /// nothing, handed a contribution nobody offered a receipt for, still
    /// returns an artifact with no bodies in it.
    #[tokio::test]
    async fn bodies_are_stripped_even_where_no_receipt_was_offered() {
        let mut request = contribution_with_exchange();
        request.offered_receipt = None;
        let response = witness_contribution(
            request,
            &contribution_redactor(),
            &TestSigner::new("witness"),
            &TestEnclave,
        )
        .await
        .expect("the fixture redacts");
        let artifact = String::from_utf8(response.envelope_bytes).expect("UTF-8");
        assert!(artifact.contains(URL_MARKER), "positive control");
        assert!(!artifact.contains(REQUEST_BODY_MARKER));
        assert!(!artifact.contains(RESPONSE_BODY_MARKER));
    }
    #[tokio::test]
    async fn structured_witness_removes_pii_from_contributed_metadata() {
        let mut request = contribution_request(SURVIVOR);
        request.raw_contribution.conversation_id = Some(CLASSIFIER_ONLY_PII.into());
        request
            .raw_contribution
            .ironclaw
            .feature_flags
            .insert("imported-provenance".into(), CLASSIFIER_ONLY_PII.into());
        request
            .raw_contribution
            .replay
            .replay_notes
            .push(CLASSIFIER_ONLY_PII.into());
        request
            .raw_contribution
            .value
            .explanation
            .push(CLASSIFIER_ONLY_PII.into());
        let event = request.raw_contribution.events.last_mut().unwrap();
        event.tool_call_id = None;
        event.structured_payload["tool_call_id"] = serde_json::json!(CLASSIFIER_ONLY_PII);
        let redactor = PipelineContributionRedaction::with_privacy_filter(
            Vec::new(),
            Arc::new(NameRemovingFilter),
            PrivacyFilterBackendTag::SelfHosted,
        );
        let response = witness_contribution(
            request,
            &redactor,
            &TestSigner::new("metadata-witness"),
            &TestEnclave,
        )
        .await
        .unwrap();
        let artifact = String::from_utf8(response.envelope_bytes).unwrap();
        assert!(
            !artifact.contains(CLASSIFIER_ONLY_PII),
            "certified metadata must not retain the planted name"
        );
        assert!(artifact.contains(SURVIVOR), "positive content control");
    }

    #[tokio::test]
    async fn structured_witness_refuses_secret_echoed_by_classifier() {
        struct EchoSecret;
        #[async_trait]
        impl PrivacyFilterAdapter for EchoSecret {
            async fn redact_text(
                &self,
                text: &str,
            ) -> Result<
                Option<trace_commons_protocol::trace_contribution::SafePrivacyFilterRedaction>,
                trace_commons_protocol::trace_contribution::TraceContributionError,
            > {
                Ok(Some(
                    trace_commons_protocol::trace_contribution::SafePrivacyFilterRedaction {
                        private_edits: None,
                        redacted_text: if text == SURVIVOR {
                            SECRET.into()
                        } else {
                            text.into()
                        },
                        summary: Default::default(),
                        report: Default::default(),
                    },
                ))
            }
        }
        let redactor = PipelineContributionRedaction::with_privacy_filter(
            Vec::new(),
            Arc::new(EchoSecret),
            PrivacyFilterBackendTag::SelfHosted,
        );
        assert!(
            witness_contribution(
                contribution_request(SURVIVOR),
                &redactor,
                &TestSigner::new("metadata-witness"),
                &TestEnclave
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn structured_witness_refuses_colliding_redacted_metadata_keys() {
        let mut request = contribution_request(SURVIVOR);
        request
            .raw_contribution
            .ironclaw
            .feature_flags
            .insert(CLASSIFIER_ONLY_PII.into(), "first".into());
        request
            .raw_contribution
            .ironclaw
            .feature_flags
            .insert("<PROSE_NAME>".into(), "second".into());
        let redactor = PipelineContributionRedaction::with_privacy_filter(
            Vec::new(),
            Arc::new(NameRemovingFilter),
            PrivacyFilterBackendTag::SelfHosted,
        );
        assert!(
            witness_contribution(
                request,
                &redactor,
                &TestSigner::new("metadata-witness"),
                &TestEnclave
            )
            .await
            .is_err()
        );
    }

    /// Over budget degrades to incomplete coverage, which forces High -- it
    /// is not a refusal. A hard `Err` here would refuse an ordinary long
    /// session on every submission path, not just admission.
    #[tokio::test]
    async fn structured_witness_degrades_metadata_beyond_the_classifier_budget() {
        let oversized_field = {
            let mut request = contribution_request(SURVIVOR);
            request.raw_contribution.conversation_id = Some("x".repeat(32_001));
            request
        };
        let mut cases = vec![oversized_field];
        for value in [serde_json::json!(0), serde_json::json!([])] {
            let mut request = contribution_request(SURVIVOR);
            request.raw_contribution.replay.expected_assertions = vec![value; 4_001];
            cases.push(request);
        }
        for request in cases {
            let response = witness_contribution(
                request,
                &contribution_redactor(),
                &TestSigner::new("metadata-witness"),
                &TestEnclave,
            )
            .await
            .expect("an oversized metadata scan degrades, it does not refuse");
            let envelope: TraceContributionEnvelope =
                serde_json::from_slice(&response.envelope_bytes).unwrap();
            assert_eq!(
                envelope.privacy.residual_pii_risk,
                trace_commons_protocol::trace_contribution::ResidualPiiRisk::High,
                "an incomplete scan cannot speak for what it never examined"
            );
        }
    }

    #[tokio::test]
    async fn token_bundle_derives_and_certifies_the_receipt_bound_assistant_event() {
        use crate::admission_evidence::AdmissionProviderTrust;
        use ring::signature::KeyPair as _;
        use trace_commons_protocol::admission::{AdmissionBinding, REQUEST_METADATA_KEY, hash_hex};
        use trace_commons_protocol::token_distribution::*;
        use trace_commons_protocol::trace_contribution::TraceContributionEventType;
        let provider = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        let key = hex::encode(provider.public_key().as_ref());
        let witness = Arc::new(TestSigner::new("token-bundle-fixture"));
        struct MatchingEnclave(String);
        #[async_trait]
        impl Enclave for MatchingEnclave {
            fn signing_address(&self) -> &str {
                &self.0
            }
            async fn measurement(&self) -> Result<String, SeamUnavailable> {
                Ok(MEASUREMENT.into())
            }
            async fn attestation_quote(&self, _: &[u8]) -> Result<Vec<u8>, SeamUnavailable> {
                Ok(vec![1; 8])
            }
        }
        let service = surface::WitnessService::new(
            Arc::new(FullPipelineRedaction::new(
                Vec::new(),
                Arc::new(NameRemovingFilter),
                PrivacyFilterBackendTag::SelfHosted,
            )),
            witness.clone(),
            Arc::new(MatchingEnclave(witness.address())),
            1024 * 1024,
        )
        .with_contribution_redactor(Arc::new(
            PipelineContributionRedaction::with_privacy_filter(
                Vec::new(),
                Arc::new(NameRemovingFilter),
                PrivacyFilterBackendTag::SelfHosted,
            ),
        ))
        .with_admission_provider_trust(
            AdmissionProviderTrust::new([key.clone()], Vec::new(), ["fixture-model".into()], 1)
                .unwrap(),
        );
        let binding = AdmissionBinding {
            account_anchor_sha256: "a".repeat(64),
            nonce_hex: "c".repeat(64),
            expires_at: chrono::Utc::now().timestamp() + 120,
        };
        let request_body = serde_json::json!({"model":"fixture-model","logprobs":true,"top_logprobs":1,"metadata":{REQUEST_METADATA_KEY:binding.encode().unwrap()},"messages":[{"role":"user","content":"hello"}]}).to_string();
        let response_body = serde_json::json!({"id":"token-fixture-response","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hello"},"logprobs":{"content":[{"token":"hello","bytes":[104,101,108,108,111],"logprob":-1.25,"top_logprobs":[{"token":"hi","bytes":[104,105],"logprob":-2.5}]}]}}]}).to_string();
        let receipt_text = format!(
            "fixture-model:{}:{}",
            hash_hex(request_body.as_bytes()),
            hash_hex(response_body.as_bytes())
        );
        let mut request = contribution_request("unbound history");
        let mut exchange = request.raw_contribution.events.pop().unwrap();
        exchange.event_type = TraceContributionEventType::HttpExchange;
        exchange.structured_payload =
            serde_json::json!({"request":{"body":request_body},"response":{}});
        exchange.content = Some(response_body);
        request.raw_contribution.events = vec![exchange];
        request.offered_receipt = Some(ReceiptPayload {
            signature: hex::encode(provider.sign(receipt_text.as_bytes()).as_ref()),
            signing_address: key,
            signing_algo: crate::near_attestation::receipt::ReceiptAlgo::Ed25519,
            signature_kind: crate::near_attestation::receipt::ReceiptSignatureKind::ProviderTee,
            text: receipt_text,
        });
        let options = || token_bundle::TokenBundleOptions {
            capture_store_id: "1".repeat(32),
            capture_id: "2".repeat(32),
            bundle_revision: "r1".into(),
            restricted_token_consent: true,
        };
        let trust = AdmissionProviderTrust::new(
            [request
                .offered_receipt
                .as_ref()
                .unwrap()
                .signing_address
                .clone()],
            Vec::new(),
            ["fixture-model".into()],
            1,
        )
        .unwrap();
        let verified_call = crate::admission_evidence::verify_admission_call(
            &request.raw_contribution,
            request.offered_receipt.as_ref().unwrap(),
            &trust,
            chrono::Utc::now().timestamp(),
            1024 * 1024,
        )
        .expect("provider source verifies");
        let mut restricted = request.clone();
        verified_call
            .restrict_contribution(&mut restricted.raw_contribution)
            .expect("source projection succeeds");
        trace_commons_protocol::token_distribution_chat::extract_chat_tokens(
            restricted.raw_contribution.events[0]
                .content
                .as_ref()
                .unwrap()
                .as_bytes(),
            false,
        )
        .expect("token capture parses");
        let result = service
            .witness_token_bundle(request.clone(), options())
            .await
            .unwrap();
        let envelope: TraceContributionEnvelope =
            serde_json::from_slice(&result.contribution.envelope_bytes).unwrap();
        let assistant = envelope
            .events
            .iter()
            .find(|e| e.event_type == TraceContributionEventType::AssistantMessage)
            .unwrap();
        assert_eq!(assistant.redacted_content.as_deref(), Some("hello"));
        let manifest = ContributionBundleManifest::decode(&result.manifest_bytes).unwrap();
        assert!(
            manifest
                .envelope_digest
                .matches(&result.contribution.envelope_bytes)
        );
        assert_eq!(
            manifest.attachments[0].event_id,
            assistant.event_id.to_string()
        );
        manifest
            .verify_sanitized_attachment(
                &manifest.attachments[0].artifact_id,
                &result.attachment_bytes,
                b"hello",
            )
            .unwrap();
        verify_witness_certificate(
            result.certificate.clone(),
            &result.signature_hex,
            Some(&pin(&witness)),
            &result.manifest_bytes,
        )
        .unwrap();
        verify_witness_certificate(
            result.contribution.certificate.clone(),
            &result.contribution.signature_hex,
            Some(&pin(&witness)),
            &result.contribution.envelope_bytes,
        )
        .unwrap();
        let mut tampered = result.manifest_bytes.clone();
        tampered.push(b' ');
        assert!(
            verify_witness_certificate(
                result.certificate.clone(),
                &result.signature_hex,
                Some(&pin(&witness)),
                &tampered
            )
            .is_err()
        );
        assert!(result.admission.is_some());
        let mut no_consent = options();
        no_consent.restricted_token_consent = false;
        assert!(
            service
                .witness_token_bundle(request.clone(), no_consent)
                .await
                .is_err()
        );
        request.raw_contribution.events[0]
            .content
            .as_mut()
            .unwrap()
            .push(' ');
        assert!(
            service
                .witness_token_bundle(request, options())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn admission_evidence_binds_trusted_final_call_account_and_witness_artifact() {
        use crate::admission_evidence::{AdmissionProviderTrust, verify_admission_evidence};
        use ring::signature::KeyPair as _;
        use trace_commons_protocol::admission::{AdmissionBinding, REQUEST_METADATA_KEY, hash_hex};
        use trace_commons_protocol::trace_contribution::TraceContributionEventType;
        let provider = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let provider_key = hex::encode(provider.public_key().as_ref());
        let witness = Arc::new(TestSigner::new("synthetic-admission-witness"));
        struct MatchingEnclave(String);
        #[async_trait]
        impl Enclave for MatchingEnclave {
            fn signing_address(&self) -> &str {
                &self.0
            }
            async fn measurement(&self) -> Result<String, SeamUnavailable> {
                Ok(MEASUREMENT.into())
            }
            async fn attestation_quote(&self, _: &[u8]) -> Result<Vec<u8>, SeamUnavailable> {
                Ok(vec![0xab; 8])
            }
        }
        let trust = AdmissionProviderTrust::new(
            [provider_key.clone()],
            Vec::new(),
            ["fixture-model".into()],
            1,
        )
        .unwrap();
        let service = surface::WitnessService::new(
            Arc::new(redactor()),
            witness.clone(),
            Arc::new(MatchingEnclave(witness.address())),
            1024 * 1024,
        )
        .with_contribution_redactor(Arc::new(contribution_redactor()))
        .with_admission_provider_trust(trust.clone());
        let now = chrono::Utc::now().timestamp();
        let binding = AdmissionBinding {
            account_anchor_sha256: "a".repeat(64),
            nonce_hex: "b".repeat(64),
            expires_at: now + 60,
        };
        let request_body=serde_json::json!({"model":"fixture-model","metadata":{REQUEST_METADATA_KEY:binding.encode().unwrap()},"messages":[{"role":"user","content":"hello"}]}).to_string();
        let response_body = r#"{"choices":[{"message":{"role":"assistant","content":"hello"}}]}"#;
        let receipt_text = format!(
            "fixture-model:{}:{}",
            hash_hex(request_body.as_bytes()),
            hash_hex(response_body.as_bytes())
        );
        let receipt = ReceiptPayload {
            signature: hex::encode(provider.sign(receipt_text.as_bytes()).as_ref()),
            signing_address: provider_key.clone(),
            signing_algo: crate::near_attestation::receipt::ReceiptAlgo::Ed25519,
            signature_kind: crate::near_attestation::receipt::ReceiptSignatureKind::ProviderTee,
            text: receipt_text.clone(),
        };
        let mut request = contribution_request("built a useful fixture");
        let event = request.raw_contribution.events.last_mut().unwrap();
        event.event_type = TraceContributionEventType::HttpExchange;
        event.structured_payload = serde_json::json!({"request":{"method":"POST","body":request_body},"response":{"status":200}});
        event.content = Some(response_body.into());
        // Importer claims the receipt does not cover, and that no redaction
        // pass would remove because none of them is PII. `restrict_contribution`
        // is the only thing that clears them; deleting it fails the assertions
        // on the certified artifact below.
        event.cost_usd = Some("12.34".parse().unwrap());
        request.raw_contribution.replay.replayable = true;
        request
            .raw_contribution
            .replay
            .replay_notes
            .push("importer-supplied replay claim".into());
        request.offered_receipt = Some(receipt);
        // A valid receipt for the final exchange does not cover companion
        // history supplied by an arbitrary importer.
        assert!(
            service
                .witness_admission_contribution(request.clone())
                .await
                .is_err(),
            "unbound companion history must not acquire admission authority"
        );
        let last = request.raw_contribution.events.pop().unwrap();
        request.raw_contribution.events = vec![last];
        let (response, evidence, signature) = service
            .witness_admission_contribution(request.clone())
            .await
            .unwrap();
        // The two signer sets are disjoint. This key is trusted to sign a
        // provider-TEE receipt, which binds the model; the same key offering
        // the two-part gateway form, which binds no model, is a different
        // claim and this deployment pinned nobody to make it.
        let mut gateway_request = request.clone();
        let gateway_text = format!(
            "{}:{}",
            hash_hex(request_body.as_bytes()),
            hash_hex(response_body.as_bytes())
        );
        gateway_request.offered_receipt = Some(ReceiptPayload {
            signature: hex::encode(provider.sign(gateway_text.as_bytes()).as_ref()),
            signing_address: provider_key.clone(),
            signing_algo: crate::near_attestation::receipt::ReceiptAlgo::Ed25519,
            signature_kind: crate::near_attestation::receipt::ReceiptSignatureKind::Gateway,
            text: gateway_text,
        });
        assert!(
            service
                .witness_admission_contribution(gateway_request.clone())
                .await
                .is_err(),
            "a provider-TEE key must not vouch for a gateway receipt"
        );
        // The same request against a deployment that did pin this key as a
        // gateway signer: non-vacuity for the refusal above.
        assert!(
            surface::WitnessService::new(
                Arc::new(redactor()),
                witness.clone(),
                Arc::new(MatchingEnclave(witness.address())),
                1024 * 1024,
            )
            .with_contribution_redactor(Arc::new(contribution_redactor()))
            .with_admission_provider_trust(
                AdmissionProviderTrust::new(
                    ["f".repeat(64)],
                    [provider_key.clone()],
                    ["fixture-model".into()],
                    1
                )
                .unwrap()
            )
            .witness_admission_contribution(gateway_request)
            .await
            .is_ok()
        );
        assert_eq!(evidence.model, "fixture-model");
        assert_eq!(evidence.request_bytes, request_body.len() as u64);
        // A receipt certifies one exchange, not the importer's claims about
        // it. None of these is PII, so no redaction pass would remove them.
        let certified: TraceContributionEnvelope =
            serde_json::from_slice(&response.envelope_bytes).unwrap();
        assert!(!certified.replay.replayable);
        assert!(certified.replay.replay_notes.is_empty());
        assert!(certified.events.iter().all(|e| e.cost_usd.is_none()));
        for restricted in [
            AdmissionProviderTrust::new(
                [provider_key.clone()],
                Vec::new(),
                ["other-model".into()],
                1,
            )
            .unwrap(),
            AdmissionProviderTrust::new(
                [provider_key.clone()],
                Vec::new(),
                ["fixture-model".into()],
                request_body.len() as u64 + 1,
            )
            .unwrap(),
        ] {
            assert!(
                crate::admission_evidence::verify_admission_call(
                    &request.raw_contribution,
                    request.offered_receipt.as_ref().unwrap(),
                    &restricted,
                    now,
                    1024 * 1024
                )
                .is_err()
            );
        }
        let mut missing_kind = request.clone();
        missing_kind
            .offered_receipt
            .as_mut()
            .unwrap()
            .signature_kind = crate::near_attestation::receipt::ReceiptSignatureKind::Unrecognised;
        assert!(
            service
                .witness_admission_contribution(missing_kind)
                .await
                .is_err()
        );
        let mut wrong_algo = request.offered_receipt.clone().unwrap();
        wrong_algo.signing_algo = crate::near_attestation::receipt::ReceiptAlgo::Ecdsa;
        assert!(
            crate::admission_evidence::verify_admission_call(
                &request.raw_contribution,
                &wrong_algo,
                &trust,
                now,
                1024 * 1024
            )
            .is_err()
        );
        let witness_pin = pin(&witness);
        let artifact = verify_witness_certificate(
            response.certificate,
            &response.signature_hex,
            Some(&witness_pin),
            &response.envelope_bytes,
        )
        .unwrap();
        for restricted in [
            AdmissionProviderTrust::new(
                [provider_key.clone()],
                Vec::new(),
                ["other-model".into()],
                1,
            )
            .unwrap(),
            AdmissionProviderTrust::new(
                [provider_key.clone()],
                Vec::new(),
                ["fixture-model".into()],
                request_body.len() as u64 + 1,
            )
            .unwrap(),
        ] {
            assert!(
                verify_admission_evidence(
                    &evidence,
                    &signature,
                    &artifact,
                    &witness_pin,
                    &restricted,
                    &binding.account_anchor_sha256,
                    now
                )
                .is_err(),
                "ingest enforces its own policy on authenticated evidence"
            );
        }
        let now = chrono::Utc::now().timestamp();
        assert_eq!(evidence.challenge_sha256, binding.digest().unwrap());
        verify_admission_evidence(
            &evidence,
            &signature,
            &artifact,
            &witness_pin,
            &trust,
            &binding.account_anchor_sha256,
            now,
        )
        .unwrap();
        assert!(
            verify_admission_evidence(
                &evidence,
                &signature,
                &artifact,
                &witness_pin,
                &trust,
                &"c".repeat(64),
                now
            )
            .is_err()
        );
        assert!(
            verify_admission_evidence(
                &evidence,
                &signature,
                &artifact,
                &witness_pin,
                &trust,
                &binding.account_anchor_sha256,
                now + 60
            )
            .is_err()
        );
        let mut altered = evidence.clone();
        altered.artifact_sha256 = "d".repeat(64);
        assert!(
            verify_admission_evidence(
                &altered,
                &signature,
                &artifact,
                &witness_pin,
                &trust,
                &binding.account_anchor_sha256,
                now
            )
            .is_err()
        );
        let mut mutated = request.clone();
        mutated
            .raw_contribution
            .events
            .last_mut()
            .unwrap()
            .structured_payload["request"]["body"] =
            serde_json::Value::String(format!("{request_body} "));
        assert!(
            service
                .witness_admission_contribution(mutated)
                .await
                .is_err(),
            "receipt binds exact final bytes, including whitespace"
        );
        let untrusted =
            AdmissionProviderTrust::new(["f".repeat(64)], Vec::new(), ["fixture-model".into()], 1)
                .unwrap();
        assert!(
            verify_admission_evidence(
                &evidence,
                &signature,
                &artifact,
                &witness_pin,
                &untrusted,
                &binding.account_anchor_sha256,
                now
            )
            .is_err()
        );
        let attacker = TestSigner::new("self-reported-provider");
        request.offered_receipt = Some(ReceiptPayload {
            signature: attacker.sign_eip191(receipt_text.as_bytes()).unwrap(),
            signing_address: attacker.address(),
            signing_algo: crate::near_attestation::receipt::ReceiptAlgo::Ecdsa,
            signature_kind: crate::near_attestation::receipt::ReceiptSignatureKind::Unrecognised,
            text: receipt_text,
        });
        assert!(
            service
                .witness_admission_contribution(request.clone())
                .await
                .is_err(),
            "valid self-signed receipt is not provider trust"
        );
        request.offered_receipt = None;
        assert!(
            service
                .witness_admission_contribution(request)
                .await
                .is_err(),
            "redaction v1 without provider evidence cannot become admission"
        );
    }
}

pub mod token_bundle;
