// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The narrowed capability the HTTP surface is given.
//!
//! [`super::witness`] takes three seams as trait objects; a handler that held
//! them would hold more authority than serving two routes needs. In
//! particular it would hold an [`Enclave`], and
//! [`Enclave::attestation_quote`] takes **arbitrary** report data -- so a
//! handler could compose report data itself, get it wrong, and serve a quote
//! that carries no caller nonce. That failure is a replay, and it looks
//! exactly like a success at the response boundary.
//!
//! [`Enclave::nonce_bound_quote`] exists to prevent it, but a method nobody is
//! *required* to use is a convention, and this repository keeps finding
//! conventions at the bottom of its defects.
//!
//! So this module holds the seams behind private fields and publishes exactly
//! two operations: [`WitnessService::witness`] and
//! [`WitnessService::attest`]. Neither returns the enclave, nothing derefs to
//! it, and [`super::http`] is a *different* module -- so Rust's privacy rules,
//! not a comment, are what make the unbound call unwritable there. The second
//! half of the guard is [`ContributorNonce`]: `attest` cannot be called with
//! anything but 32 bytes that were parsed from hex, so there is no path by
//! which a short, padded, truncated or hashed nonce reaches `report_data`.
//!
//! This is the shape `WitnessCertificate` uses at the other end of the
//! service, where a digest can only come from a `CorrespondenceProof`.
//!
//! [`Enclave`]: super::Enclave
//! [`Enclave::attestation_quote`]: super::Enclave::attestation_quote
//! [`Enclave::nonce_bound_quote`]: super::Enclave::nonce_bound_quote

use std::sync::Arc;

use super::enclave::WITNESS_NONCE_LEN;
use super::inference::InferenceAttestationPolicy;
use super::{
    ContributionRedactor, Enclave, SeamUnavailable, Signer, TranscriptRedactor,
    WitnessContributionRequest, WitnessContributionResponse, WitnessError, WitnessRequest,
    WitnessResponse, witness, witness_contribution,
};

/// A contributor's attestation nonce: exactly [`WITNESS_NONCE_LEN`] bytes,
/// and no way to make one that is not.
///
/// The field is private and there is no constructor but [`Self::parse_hex`].
/// That is the point of the type rather than an accident of style: the only
/// interesting way for `/v1/attestation` to fail is to serve a quote bound to
/// bytes that are not the ones the caller chose, and every route to that
/// failure -- padding a short nonce, truncating a long one, hashing a
/// malformed one into the right length -- begins with a value that is not
/// already 32 bytes. A `&[u8]` parameter would leave all of them open.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ContributorNonce([u8; WITNESS_NONCE_LEN]);

impl ContributorNonce {
    /// Parse exactly `2 * WITNESS_NONCE_LEN` hex characters.
    ///
    /// Bare hex only. dstack's `GetQuote` accepts an optional `0x` prefix and
    /// right-pads anything shorter than 64 bytes, and both of those are
    /// leniencies this surface declines: one encoding means a contributor and
    /// a witness cannot disagree about which bytes were bound, and padding is
    /// precisely how a nonce that was never sent ends up inside a quote that
    /// appears to answer for it.
    ///
    /// Case-insensitive, because `hex::decode` accepts both and the two
    /// spellings are the same 32 bytes.
    pub fn parse_hex(value: &str) -> Result<Self, NonceMalformed> {
        if value.len() != WITNESS_NONCE_LEN * 2 {
            return Err(NonceMalformed);
        }
        let decoded = hex::decode(value).map_err(|_| NonceMalformed)?;
        let bytes = decoded.try_into().map_err(|_| NonceMalformed)?;
        Ok(Self(bytes))
    }

    /// The bytes, for [`WitnessService::attest`] and nothing else.
    ///
    /// `pub(super)` on purpose. If the HTTP module could read these it could
    /// hand them to something that is not `nonce_bound_quote`, and the type
    /// would be back to being a convention.
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ContributorNonce {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The nonce is the contributor's, not content, and rendering it is
        // what makes a failing attestation test readable. Hand-written rather
        // than derived so that gaining a content-bearing field would be a
        // visible decision here.
        write!(formatter, "ContributorNonce({})", hex::encode(self.0))
    }
}

/// The nonce was not exactly 32 bytes of bare hex.
///
/// One variant, carrying nothing. "Too short", "not hex" and "`0x`-prefixed"
/// are the same instruction to the caller -- send 64 hex characters -- and
/// three labels would only tell a prober which of its guesses was closest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the nonce is not 32 bytes of hex")]
pub struct NonceMalformed;

/// The enclave could not produce a quote.
///
/// Deliberately not a [`WitnessError`] variant. `WitnessError` answers "why
/// was nothing certified"; every one of its variants means a certificate was
/// refused, and an attestation failure certifies nothing either way. Folding
/// the two would let a surface report a quote failure with a name that reads
/// as a redaction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the enclave could not produce a nonce-bound quote")]
pub struct AttestationError;

/// What `/v1/attestation` returns.
///
/// The quote and the address it names, and nothing else. Notably **not** the
/// measurement label: the measurement a contributor pins has to be read out of
/// the quote they verified, and serving a convenient copy beside it invites
/// pinning the copy -- which any witness could type, attested by nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEvidence {
    /// The raw quote bytes as lowercase hex, no `0x` prefix.
    pub quote_hex: String,
    /// The address that signs this witness's certificates, as the quote's
    /// report data binds it.
    pub signing_address: String,
}

/// This deployment serves no structured redaction seam.
///
/// A configuration statement, not a refusal of the input. See
/// [`WitnessService::witness_contribution`] for why it is not a
/// [`WitnessError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("this witness is not configured for the structured contribution path")]
pub struct ContributionPathUnavailable;

/// The witness, as the HTTP surface is allowed to see it.
pub struct WitnessService {
    redactor: Arc<dyn TranscriptRedactor>,
    /// The structured seam, or `None` on a deployment wired only for the text
    /// route.
    ///
    /// `Option` rather than a required constructor parameter so that adding
    /// the structured path did not change [`Self::new`]'s signature, and so a
    /// deployment that has not been reconfigured refuses the new route by
    /// name instead of serving it from a redactor somebody defaulted in. A
    /// default here would be a redaction policy chosen by omission, which is
    /// exactly what the two `new`-style constructors on the seams refuse to
    /// let the environment do.
    contribution_redactor: Option<Arc<dyn ContributionRedactor>>,
    signer: Arc<dyn Signer>,
    enclave: Arc<dyn Enclave>,
    max_request_bytes: usize,
    /// Whether this deployment refuses a contribution that carries no verified
    /// attested inference, and what it will admit when it does not.
    ///
    /// Held here rather than read per request, and defaulted to
    /// [`InferenceAttestationPolicy::not_required`] by [`Self::new`] with
    /// [`Self::requiring_attested_inference`] as the only way to turn it on:
    /// a security control whose default is "on" would be one an operator
    /// could not have chosen, and one assembled per request would be one the
    /// environment could change under a running witness.
    inference_policy: InferenceAttestationPolicy,
    admission_provider_trust: Option<crate::admission_evidence::AdmissionProviderTrust>,
}

impl WitnessService {
    /// Assemble the service from its three seams and the request bound.
    ///
    /// The bound is a constructor parameter rather than a constant because the
    /// witness receives **raw** transcripts: the redacted-envelope cap is
    /// 16 MiB, the measured raw-to-envelope ratio on this pilot is about
    /// 3.4:1, and 7% of real sessions already exceed the cap before that
    /// multiplier. There is no single right number, so the deployment picks
    /// one and the surface refuses over it by name.
    pub fn new(
        redactor: Arc<dyn TranscriptRedactor>,
        signer: Arc<dyn Signer>,
        enclave: Arc<dyn Enclave>,
        max_request_bytes: usize,
    ) -> Self {
        Self {
            redactor,
            contribution_redactor: None,
            signer,
            enclave,
            max_request_bytes,
            inference_policy: InferenceAttestationPolicy::not_required(),
            admission_provider_trust: None,
        }
    }

    /// Refuse anything this policy does not admit.
    ///
    /// Additive like [`Self::with_contribution_redactor`], and fail-closed in
    /// the direction that matters: a witness built without this call requires
    /// nothing and says so, rather than a witness built with a policy it
    /// silently ignores. A receipt offered to a witness with no requirement is
    /// still verified and still has to project exactly -- see
    /// [`InferenceAttestationPolicy::not_required`].
    pub fn requiring_attested_inference(mut self, policy: InferenceAttestationPolicy) -> Self {
        self.inference_policy = policy;
        self
    }

    /// The attested-inference policy this witness enforces.
    pub fn inference_policy(&self) -> &InferenceAttestationPolicy {
        &self.inference_policy
    }

    /// Attach the structured seam, enabling the `raw_contribution` request
    /// shape.
    ///
    /// Additive on purpose: a witness built without it serves the text route
    /// exactly as before and refuses the structured one, rather than the two
    /// shapes sharing a redactor that was configured for only one of them.
    pub fn with_contribution_redactor(mut self, redactor: Arc<dyn ContributionRedactor>) -> Self {
        self.contribution_redactor = Some(redactor);
        self
    }

    /// The largest request body this witness will read, in bytes.
    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    /// Redact, judge and certify. Thin over [`super::witness`].
    pub async fn witness(&self, request: WitnessRequest) -> Result<WitnessResponse, WitnessError> {
        witness(
            request,
            &self.inference_policy,
            self.redactor.as_ref(),
            self.signer.as_ref(),
            self.enclave.as_ref(),
        )
        .await
    }

    /// Redact a raw contribution, judge it, serialise it once and certify
    /// those bytes. Thin over [`super::witness_contribution`].
    ///
    /// `Err(ContributionPathUnavailable)` when no structured seam was
    /// attached. Deliberately not a [`WitnessError`] variant: every one of
    /// those means a certificate was refused *by* a witness that tried, and
    /// this one means the route is not configured on this deployment at all.
    /// Folding them would let an unconfigured witness report a
    /// configuration gap under a name that reads as a redaction failure.
    pub async fn witness_contribution(
        &self,
        request: WitnessContributionRequest,
    ) -> Result<Result<WitnessContributionResponse, WitnessError>, ContributionPathUnavailable>
    {
        let Some(redactor) = self.contribution_redactor.as_ref() else {
            return Err(ContributionPathUnavailable);
        };
        Ok(witness_contribution(
            request,
            &self.inference_policy,
            redactor.as_ref(),
            self.signer.as_ref(),
            self.enclave.as_ref(),
        )
        .await)
    }

    /// Explicit bundle route; source attestation and separate consent are required.
    pub async fn witness_token_bundle(
        &self,
        mut request: WitnessContributionRequest,
        options: super::token_bundle::TokenBundleOptions,
    ) -> Result<super::token_bundle::WitnessTokenBundle, WitnessError> {
        let trust = self
            .admission_provider_trust
            .as_ref()
            .ok_or(WitnessError::InferenceAttestationMissing)?;
        let receipt = request
            .offered_receipt
            .as_ref()
            .ok_or(WitnessError::InferenceAttestationMissing)?;
        let call = crate::admission_evidence::verify_admission_call(
            &request.raw_contribution,
            receipt,
            trust,
            chrono::Utc::now().timestamp(),
            self.inference_policy.max_body_bytes(),
        )
        .map_err(|_| WitnessError::ArtifactBindingFailed)?;
        call.restrict_contribution(&mut request.raw_contribution)
            .map_err(|_| WitnessError::ArtifactBindingFailed)?;
        let redactor = self
            .contribution_redactor
            .as_ref()
            .ok_or(WitnessError::RedactionFailed)?;
        let mut response = super::token_bundle::witness_token_bundle(
            request,
            options,
            &self.inference_policy,
            redactor.as_ref(),
            self.redactor.as_ref(),
            self.signer.as_ref(),
            self.enclave.as_ref(),
        )
        .await?;
        response.admission = Some(
            call.certify(
                &response.contribution,
                self.signer.as_ref(),
                chrono::Utc::now().timestamp(),
            )
            .map_err(|_| WitnessError::ArtifactBindingFailed)?,
        );
        Ok(response)
    }

    pub fn with_admission_provider_trust(
        mut self,
        trust: crate::admission_evidence::AdmissionProviderTrust,
    ) -> Self {
        self.admission_provider_trust = Some(trust);
        self
    }

    pub async fn witness_admission_contribution(
        &self,
        mut request: WitnessContributionRequest,
    ) -> Result<
        (
            WitnessContributionResponse,
            trace_commons_protocol::admission::AdmissionEvidence,
            String,
        ),
        crate::admission_evidence::AdmissionEvidenceError,
    > {
        use crate::admission_evidence::{AdmissionEvidenceError, verify_admission_call};
        let trust = self
            .admission_provider_trust
            .as_ref()
            .ok_or(AdmissionEvidenceError)?;
        let receipt = request
            .offered_receipt
            .as_ref()
            .ok_or(AdmissionEvidenceError)?;
        let call = verify_admission_call(
            &request.raw_contribution,
            receipt,
            trust,
            chrono::Utc::now().timestamp(),
            self.inference_policy.max_body_bytes(),
        )?;
        call.restrict_contribution(&mut request.raw_contribution)?;
        let response = self
            .witness_contribution(request)
            .await
            .map_err(|_| AdmissionEvidenceError)?
            .map_err(|_| AdmissionEvidenceError)?;
        let (evidence, signature) = call.certify(
            &response,
            self.signer.as_ref(),
            chrono::Utc::now().timestamp(),
        )?;
        Ok((response, evidence, signature))
    }

    /// A quote bound to `nonce` and to this witness's signing address.
    ///
    /// The single call site of [`Enclave::nonce_bound_quote`] in this crate,
    /// and the only way any caller outside this module obtains a quote.
    ///
    /// [`Enclave::nonce_bound_quote`]: super::Enclave::nonce_bound_quote
    pub async fn attest(
        &self,
        nonce: &ContributorNonce,
    ) -> Result<AttestationEvidence, AttestationError> {
        let quote = self
            .enclave
            .nonce_bound_quote(nonce.as_bytes())
            .await
            .map_err(|SeamUnavailable| AttestationError)?;
        Ok(AttestationEvidence {
            quote_hex: hex::encode(quote),
            signing_address: self.enclave.signing_address().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_thirty_two_bytes_of_bare_hex_and_nothing_else() {
        let good = hex::encode([0x5au8; WITNESS_NONCE_LEN]);
        assert_eq!(
            ContributorNonce::parse_hex(&good)
                .expect("64 hex characters")
                .as_bytes(),
            &[0x5au8; WITNESS_NONCE_LEN]
        );
        // Uppercase is the same 32 bytes, not a second encoding.
        assert_eq!(
            ContributorNonce::parse_hex(&good.to_uppercase()).expect("uppercase hex"),
            ContributorNonce::parse_hex(&good).expect("lowercase hex")
        );

        let rejected = [
            ("empty", String::new()),
            ("one byte short", hex::encode([0xaau8; 31])),
            ("one byte long", hex::encode([0xaau8; 33])),
            ("odd length", "a".repeat(63)),
            ("not hex", "z".repeat(64)),
            ("0x prefixed", format!("0x{}", hex::encode([0xaau8; 31]))),
            (
                "0x prefixed full length",
                format!("0x{}", hex::encode([0xaau8; WITNESS_NONCE_LEN])),
            ),
            ("trailing space", format!("{} ", &good[..63])),
        ];
        // Collected, not asserted in the loop: a short-circuiting assertion
        // would let the first accepted case hide every one after it.
        let accepted: Vec<&str> = rejected
            .iter()
            .filter(|(_, value)| ContributorNonce::parse_hex(value).is_ok())
            .map(|(label, _)| *label)
            .collect();
        assert!(
            accepted.is_empty(),
            "malformed nonces accepted: {accepted:?}"
        );
    }

    #[test]
    fn debug_renders_the_nonce_and_the_error_carries_nothing() {
        let nonce = ContributorNonce::parse_hex(&hex::encode([0x01u8; WITNESS_NONCE_LEN]))
            .expect("well formed");
        assert!(format!("{nonce:?}").contains(&hex::encode([0x01u8; WITNESS_NONCE_LEN])));
        assert_eq!(
            format!("{NonceMalformed:?}"),
            "NonceMalformed",
            "the error gained a field, and that field will reach a log"
        );
    }
}
