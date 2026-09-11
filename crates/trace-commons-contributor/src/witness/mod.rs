//! Verifying a redaction witness before handing it a raw session.
//!
//! # The property this module exists to hold
//!
//! The contributor sends the enclave a **raw, unredacted session**. That is
//! the largest disclosure in this system, and it is acceptable only because
//! the enclave's measurement was verified first. A design that sent and then
//! checked would not have a weakened version of this property; it would have
//! none, because the bytes are gone before the check runs.
//!
//! So the ordering is not asserted in a comment. [`verify::VerifiedWitness`]
//! has private fields and exactly one constructor, and that constructor *is*
//! the verification. The only function that transmits raw bytes takes a
//! `&VerifiedWitness`. There is no path from "we have a witness URL" to "we
//! sent raw bytes" that does not pass through the verification, and that is a
//! property of the types rather than of a review.
//!
//! # Ship disabled
//!
//! [`WitnessSettings`] reaches `ContributorConfig` as an
//! `Option<_>` with `#[serde(default)]`, absent. **Absent means this module is
//! not entered at all** and the local redaction runs byte for byte as it does
//! today -- not "runs and falls back". There is no discovery, no
//! server-pushed enablement, and no default that could move under a
//! contributor.
//!
//! # Configured but unsatisfiable refuses
//!
//! Never a silent fall back to local redaction. The contributor's bytes would
//! stay home, which sounds like the safe outcome, but the envelope would then
//! carry a self-reported risk while the contributor believed it carried a
//! certificate, and the operator would see an uncertified submission from
//! someone enrolled as certified. Silence about a downgrade is the failure
//! this design is aimed at.
//!
//! # What a pin proves, and what it does not
//!
//! A matching measurement proves the deployment has not changed under the
//! contributor, and that two contributors are talking to the same enclave. It
//! does **not** prove the running code is the code in this repository: the
//! image is not reproducibly buildable and has never been reproduced. No text
//! in this module may say "verifiable against source".

pub mod inference_record;
pub mod status;
pub mod transport;
pub mod verify;

use trace_commons_attestation::measurements::ExpectedMeasurements;

/// The missing-control name for an unpinned witness.
///
/// One constant, used by the refusal and by the config error, so an operator
/// greps once.
pub const WITNESS_EXPECTED_MEASUREMENT_CONTROL: &str = "witness_expected_measurement";

/// The 8-byte domain tag at the front of a witness quote's report data.
///
/// **Duplicated from `trace_commons_server::witness_service::enclave`**, which
/// is AGPL and which this permissive crate must not depend on. The layout is
/// therefore pinned on both sides by tests rather than by a shared constant,
/// and `the_report_data_layout_matches_the_witness_service` in `verify.rs`
/// states it explicitly so a change on either side is visible here.
pub const WITNESS_QUOTE_DOMAIN: &[u8; 8] = b"tcwitns1";
/// Offset of the signing address within the report data.
pub const WITNESS_ADDRESS_AT: usize = 8;
/// Offset of the contributor nonce within the report data.
pub const WITNESS_NONCE_AT: usize = 28;
/// The nonce length. 32 bytes, fresh per verification.
pub const WITNESS_NONCE_LEN: usize = 32;
/// TDX report data is 64 bytes.
pub const WITNESS_REPORT_DATA_LEN: usize = 64;

/// What the client pins about a witness.
///
/// # Why the measurements are a *list* of sets
///
/// dstack derives an enclave's signing key from a stable app id, so an image
/// upgrade moves the measurement and leaves the signing address where it is.
/// A pin that held one measurement would break every client on every upgrade.
/// Holding several sets means an operator can allowlist the new measurement
/// *before* the fleet rolls; if they do not, every correctly-pinned
/// contributor refuses the new deployment and it looks like an outage.
///
/// A set that only ever grows stops being a pin, which is a documentation
/// problem rather than a code one, and is named in the operator text.
///
/// # What to pin
///
/// `mrtd` and `mrconfigid`. **Not `rtmr3`** -- it carries a per-deployment
/// random instance-id, so two byte-identical replicas differ and pinning it
/// fails closed on the second one. **Not `rtmr0`** -- it hashes SMBIOS tables
/// that change when the VM is resized. `ExpectedMeasurements` will accept
/// either, so this is the only place the policy is written down in code.
///
/// `mrconfigid` commits to the compose hash directly in the signed quote
/// body, which is why none of this needs the RTMR3 event log replayed.
/// Under config-id **v1** -- `01` followed by the compose hash and fifteen
/// zero bytes -- it pins the compose hash and says nothing about app id, so
/// no text here may claim app-id binding until a deployment is confirmed to
/// emit v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessTrust {
    /// The address whose signature this client will accept on a certificate,
    /// and which the quote's report data must name.
    pub signing_address: String,
    /// Every measurement set that is admitted. Empty means nothing is
    /// pinned, which is a refusal and never a pass.
    pub measurements: Vec<ExpectedMeasurements>,
}

impl WitnessTrust {
    /// True when at least one measurement set is pinned.
    ///
    /// Read by the config gate so an unpinned witness refuses *before* any
    /// network call, rather than after fetching a quote it could not judge.
    pub fn is_pinned(&self) -> bool {
        !self.measurements.is_empty()
    }
}

/// Why the client would not trust, or would not use, a witness.
///
/// Every variant names one specific condition. `Debug` delegates to `Display`
/// for the variants that could carry caller data, and no variant carries a
/// witness URL, a signature, a raw byte, a redacted byte, or any count
/// derived from session content.
///
/// `reported` on [`Self::WitnessMeasurementUnpinned`] is the exception and is
/// deliberate: a measurement is a public image identifier, not a secret, and
/// an operator holding both halves can go straight to the image. That is the
/// whole point of naming the field.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessTrustError {
    /// The witness host is not on the contributor's allowlist. Raised before
    /// any request is made.
    #[error("the witness host is not on the allowed-hosts list")]
    WitnessHostNotAllowed,
    /// `/v1/attestation` could not be reached, or did not answer with a
    /// quote.
    #[error("the witness attestation endpoint is unavailable")]
    WitnessAttestationUnavailable,
    /// Intel collateral could not be obtained. A refusal, never a
    /// verification without it.
    #[error("attestation collateral is unavailable")]
    WitnessCollateralUnavailable,
    /// DCAP verification failed. The quote is not a genuine TDX quote, or it
    /// does not verify against this collateral as of this clock.
    #[error("the witness quote did not verify")]
    WitnessQuoteUnverified,
    /// The quote's report data does not carry the nonce this client just
    /// generated. A quote for someone else's nonce proves nothing about now,
    /// which is exactly what a replay looks like.
    #[error("the witness quote is not bound to this client's nonce")]
    WitnessQuoteReplayed,
    /// The quote's report data names an address other than the pinned one. A
    /// quote for a machine that did not sign proves nothing about the
    /// certificate.
    #[error("the witness quote names a different signer than the pinned one")]
    WitnessSignerUnexpected,
    /// No measurement set is configured, or none matched.
    ///
    /// One variant for both because they are the same instruction to a
    /// contributor -- pin the measurement this deployment reports -- and two
    /// names would only tell them which half of the configuration to blame.
    /// `reported` distinguishes them: `None` means nothing was pinned.
    #[error("the witness measurement is not pinned")]
    WitnessMeasurementUnpinned {
        control: &'static str,
        reported: Option<String>,
    },
    /// The contribution is larger than this client will send. Refused
    /// locally, before anything is offered.
    #[error("the contribution is larger than the witness path will carry")]
    WitnessPayloadTooLarge,
    /// The certificate's digest does not cover the bytes the witness
    /// returned. Only the client can catch this: it is the only party holding
    /// both the input and the returned artifact.
    #[error("the witness certificate does not cover the artifact it returned")]
    WitnessCertificateMismatched,
    /// The certificate's signature does not recover to the pinned address.
    #[error("the witness certificate did not verify")]
    WitnessCertificateUnverified,
    /// A witness response could not be read as a certificate and an envelope.
    #[error("the witness response was malformed")]
    WitnessResponseMalformed,
    /// The witness declined the receipt behind an evidence-bearing request:
    /// its signer, its model, or the size of the request it covers is outside
    /// what that deployment accepts.
    ///
    /// A decision, not a fault. It is the refusal a rollout produces most
    /// often -- a signer not yet trusted, a model not yet accepted -- and
    /// folding it into [`Self::WitnessResponseMalformed`] made it read as the
    /// witness being broken.
    #[error("the witness declined the receipt behind this request")]
    WitnessAdmissionEvidenceRefused,
    /// A claim is required for a witnessed submission and none was
    /// available.
    #[error("a claim is required before a session can be witnessed")]
    WitnessClaimUnavailable,
    /// The witness returned an artifact still carrying the raw inference
    /// bodies it was sent.
    ///
    /// The bodies are handed to a witness so it can verify a receipt against
    /// them, and on the understanding that it strips them before certifying.
    /// An artifact that still holds them would turn a prompt that never left
    /// the machine into a submitted one, and the client is the last party
    /// able to notice. Refused whatever the certificate says.
    #[error("the witness returned an artifact still carrying the raw bodies")]
    WitnessBodyNotStripped,
}

impl std::fmt::Debug for WitnessTrustError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `reported` is public image identity and is worth rendering; every
        // other variant is a bare label. Written out rather than derived so
        // that a variant which gains a content-bearing field is a visible
        // decision here rather than a silent widening of every `?err`.
        match self {
            Self::WitnessMeasurementUnpinned { control, reported } => formatter
                .debug_struct("WitnessMeasurementUnpinned")
                .field("control", control)
                .field("reported", reported)
                .finish(),
            other => std::fmt::Display::fmt(other, formatter),
        }
    }
}

impl WitnessTrustError {
    /// The refusal label a submission surface reports.
    ///
    /// A closed set of constants, matching the spelling `submit.rs` uses for
    /// its own refusals. Exhaustive rather than a catch-all, so a new variant
    /// is a compile error here and gets a deliberate label instead of
    /// inheriting one that reads as something else.
    pub fn refusal_label(&self) -> &'static str {
        match self {
            Self::WitnessHostNotAllowed => "witness_host_not_allowed",
            Self::WitnessAttestationUnavailable => "witness_attestation_unavailable",
            Self::WitnessCollateralUnavailable => "witness_collateral_unavailable",
            Self::WitnessQuoteUnverified => "witness_quote_unverified",
            Self::WitnessQuoteReplayed => "witness_quote_replayed",
            Self::WitnessSignerUnexpected => "witness_signer_unexpected",
            Self::WitnessMeasurementUnpinned { control, .. } => control,
            Self::WitnessPayloadTooLarge => "witness_payload_too_large",
            Self::WitnessCertificateMismatched => "witness_certificate_mismatched",
            Self::WitnessCertificateUnverified => "witness_certificate_unverified",
            Self::WitnessResponseMalformed => "witness_response_malformed",
            Self::WitnessClaimUnavailable => "witness_claim_unavailable",
            Self::WitnessBodyNotStripped => "witness_body_not_stripped",
            // The server's own spelling, passed through: one refusal, one
            // name, wherever a contributor meets it.
            Self::WitnessAdmissionEvidenceRefused => {
                trace_commons_protocol::admission::AdmissionRefusal::EvidenceRefused.label()
            }
        }
    }

    /// Every refusal label this type can produce.
    ///
    /// Written out rather than derived, because `refusal_label` has one arm
    /// that returns a runtime value -- the measurement control -- and a
    /// derivation would have to construct a variant to read it.
    /// `every_refusal_label_is_recognised` walks the enum and fails if this
    /// list falls behind.
    pub const ALL_REFUSAL_LABELS: [&'static str; 14] = [
        "witness_host_not_allowed",
        "witness_attestation_unavailable",
        "witness_collateral_unavailable",
        "witness_quote_unverified",
        "witness_quote_replayed",
        "witness_signer_unexpected",
        WITNESS_EXPECTED_MEASUREMENT_CONTROL,
        "witness_payload_too_large",
        "witness_certificate_mismatched",
        "witness_certificate_unverified",
        "witness_response_malformed",
        "witness_claim_unavailable",
        "witness_body_not_stripped",
        "admission_evidence_refused",
    ];

    /// Recognise a refusal label that has been through a `String`.
    ///
    /// Returns this crate's own constant, never the caller's slice, so a
    /// value that has crossed a boundary as text cannot become a word a
    /// contributor is shown unless it is one of these.
    #[must_use]
    pub fn refusal_label_from(value: &str) -> Option<&'static str> {
        Self::ALL_REFUSAL_LABELS
            .into_iter()
            .find(|label| *label == value)
    }
}

/// Verify a witness, then hand it a raw session. In that order, always.
///
/// The whole client path in one function, so there is one place where the
/// order is written down and no caller assembles it themselves.
///
/// # The order, and why each step is where it is
///
/// 1. **Refuse an unpinned client**, before anything reaches the network. A
///    client with no pin cannot judge any quote it receives, so fetching one
///    would be spending a round trip to learn nothing -- and would put the
///    witness URL on the wire for a submission that was always going to be
///    refused.
/// 2. **Refuse an oversized contribution**, also before the network. The
///    client already refuses these in `raw_contribution_size_ok`; what matters
///    here is that it happens before anything is offered, because on this path
///    finding out late means the session was already transmitted.
/// 3. **A fresh nonce**, then the quote, then the collateral.
/// 4. **Verify.** [`verify::verify_witness`] is the only producer of a
///    [`verify::VerifiedWitness`].
/// 5. **Send**, and check what comes back.
///
/// `attested`'s receipt is carried through untouched. It is fetched before
/// this function is called, deliberately: a receipt fetch is a third-party
/// call, and putting it inside the verify-then-send sequence would let a
/// provider outage delay -- or, misread, abort -- a submission whose
/// correctness does not depend on it. An absent receipt is an unattested
/// submission, never a failed one.
///
/// Steps 1 and 2 are the reason this returns before `transport` is touched in
/// the refusal cases, which `a_witness_url_without_a_pin_never_reaches_the_network`
/// asserts against a recording transport.
pub async fn witness_session(
    transport: &dyn transport::WitnessTransport,
    url: &str,
    trust: &WitnessTrust,
    now_unix: u64,
    raw: trace_commons_protocol::trace_contribution::RawTraceContribution,
    attested: Option<transport::AttestedInference<'_>>,
    granted: &transport::GrantedConsent,
) -> Result<transport::WitnessedEnvelope, WitnessTrustError> {
    if !trust.is_pinned() {
        // Never a fall back to local redaction. See the module docs: the
        // contributor's bytes would stay home, but the envelope would carry a
        // self-reported risk while the contributor believed it carried a
        // certificate.
        return Err(WitnessTrustError::WitnessMeasurementUnpinned {
            control: WITNESS_EXPECTED_MEASUREMENT_CONTROL,
            reported: None,
        });
    }
    crate::envelope::raw_contribution_size_ok(&raw)
        .map_err(|_| WitnessTrustError::WitnessPayloadTooLarge)?;

    let nonce = transport::WitnessNonce::fresh()?;
    let evidence = transport.attestation(&nonce).await?;
    let quote = hex::decode(evidence.quote_hex.trim())
        .map_err(|_| WitnessTrustError::WitnessQuoteUnverified)?;
    let collateral = transport.collateral(&quote).await?;

    let verified = verify::verify_witness(url, &evidence, &collateral, &nonce, now_unix, trust)?;

    transport::witness_contribution(transport, &verified, raw, attested, granted).await
}

/// Inputs for an explicitly approved token-bundle witness request.
pub struct TokenBundleSession<'a> {
    pub url: &'a str,
    pub trust: &'a WitnessTrust,
    pub now_unix: u64,
    pub raw: trace_commons_protocol::trace_contribution::RawTraceContribution,
    pub attested: transport::AttestedInference<'a>,
    pub granted: &'a transport::GrantedConsent,
    pub options: transport::TokenBundleRequest,
}

/// Perform the same nonce, measurement and signing-key checks as ordinary
/// witnessing before transmitting any raw capture bytes.
pub async fn witness_token_session(
    transport: &transport::HttpWitnessTransport,
    request: TokenBundleSession<'_>,
) -> Result<crate::token_bundle::CertifiedBundleUpload, WitnessTrustError> {
    use transport::WitnessTransport;
    if !request.trust.is_pinned() {
        return Err(WitnessTrustError::WitnessMeasurementUnpinned {
            control: WITNESS_EXPECTED_MEASUREMENT_CONTROL,
            reported: None,
        });
    }
    if !request.options.restricted_token_consent || request.attested.receipt.is_none() {
        return Err(WitnessTrustError::WitnessAdmissionEvidenceRefused);
    }
    crate::envelope::raw_contribution_size_ok(&request.raw)
        .map_err(|_| WitnessTrustError::WitnessPayloadTooLarge)?;
    let nonce = transport::WitnessNonce::fresh()?;
    let evidence = transport.attestation(&nonce).await?;
    let quote = hex::decode(evidence.quote_hex.trim())
        .map_err(|_| WitnessTrustError::WitnessQuoteUnverified)?;
    let collateral = transport.collateral(&quote).await?;
    let verified = verify::verify_witness(
        request.url,
        &evidence,
        &collateral,
        &nonce,
        request.now_unix,
        request.trust,
    )?;
    transport
        .witness_token_contribution(
            &verified,
            request.raw,
            request.attested,
            request.granted,
            request.options,
        )
        .await
}
