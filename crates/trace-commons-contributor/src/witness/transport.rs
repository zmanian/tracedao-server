//! Talking to a witness: the nonce, the evidence, the collateral, and the one
//! function that sends a raw session.
//!
//! # This module cannot construct a `VerifiedWitness`
//!
//! [`witness_contribution`] is the only function in this crate that transmits
//! an unredacted session, and it takes a
//! [`&VerifiedWitness`](super::verify::VerifiedWitness). That type's fields
//! are private to `super::verify`, so nothing here can build one -- which is
//! what makes "verify, then send" a property of the types rather than of a
//! review. Nothing in this file may change that, and a `pub(crate)`
//! constructor over there would end it silently.

use std::sync::Arc;
use std::time::Duration;

use trace_commons_attestation::quote::{Collateral, parse_collateral};
use trace_commons_attestation::receipt::ReceiptPayload;
use trace_commons_operator_client::host_allowlist::HostAllowlist;
use trace_commons_protocol::trace_contribution::{
    ConsentScope, RawTraceContribution, TraceAllowedUse, TraceContributionEnvelope,
};

use super::verify::VerifiedWitness;
use super::{WITNESS_NONCE_LEN, WitnessTrustError};
use crate::envelope::{MAX_ENVELOPE_BYTES, raw_contribution_size_ok};

/// The header the certificate travels in, on the witness response and on
/// `POST /v1/traces`. One spelling, so the client forwards what it received.
pub const WITNESS_CERTIFICATE_HEADER: &str = "x-trace-witness-certificate";
/// The header the signature travels in.
pub const WITNESS_SIGNATURE_HEADER: &str = "x-trace-witness-signature";

/// A contributor's attestation nonce: exactly 32 bytes, fresh per
/// verification.
///
/// The field is private and the production constructor is [`Self::fresh`].
/// **Never reused across submissions**: a reused nonce turns a replayed quote
/// into an accepted one for as long as the reuse lasts, and the reuse is
/// invisible at the response boundary because a replayed quote verifies
/// perfectly.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WitnessNonce([u8; WITNESS_NONCE_LEN]);

impl WitnessNonce {
    /// 32 fresh bytes from the system CSPRNG.
    ///
    /// `ring::rand::SystemRandom`, already a dependency of this crate. `Err`
    /// when the system source is unavailable, which is a refusal: a nonce
    /// this client did not choose at random is not a nonce.
    pub fn fresh() -> Result<Self, WitnessTrustError> {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0u8; WITNESS_NONCE_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| WitnessTrustError::WitnessAttestationUnavailable)?;
        Ok(Self(bytes))
    }

    /// Build from known bytes. `cfg(test)` only -- a production caller that
    /// could choose the nonce could choose a constant, which is the whole
    /// failure `fresh` exists to prevent.
    #[cfg(test)]
    pub fn from_bytes(bytes: [u8; WITNESS_NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes, for building report data and for the query parameter.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Bare lowercase hex, no `0x` prefix -- the encoding
    /// `/v1/attestation?nonce=` accepts and the only one it accepts.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for WitnessNonce {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The nonce is this client's own and is not content; rendering it is
        // what makes a failing attestation readable.
        write!(formatter, "WitnessNonce({})", hex::encode(self.0))
    }
}

/// What `GET /v1/attestation` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEvidence {
    /// The raw quote as lowercase hex, no `0x` prefix.
    pub quote_hex: String,
    /// The address the witness says signs its certificates. **Advisory
    /// only**: the address that matters is the pinned one, and the quote's
    /// report data is what binds it. This is carried so a mismatch can be
    /// reported, never so it can be trusted.
    pub signing_address: String,
}

/// The witnessed result: the envelope bytes as received, and the certificate
/// over them.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessedEnvelope {
    /// The serialised envelope, byte for byte as it came off the wire.
    /// Nothing may deserialise, re-serialise, re-order, pretty-print or
    /// append to these before they reach `POST /v1/traces`.
    #[serde(
        serialize_with = "serialize_envelope_bytes",
        deserialize_with = "deserialize_envelope_bytes"
    )]
    pub envelope_bytes: Vec<u8>,
    /// The certificate as compact JSON, exactly as the header carried it.
    pub certificate_json: String,
    /// The signature, `0x`-prefixed hex.
    pub signature_hex: String,
    /// Exact distinct admission headers, when this explicit profile was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<AdmissionHeaders>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionHeaders {
    pub evidence_json: String,
    pub signature_hex: String,
}

fn serialize_envelope_bytes<S: serde::Serializer>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use base64::Engine as _;
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn deserialize_envelope_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    use base64::Engine as _;
    let encoded = <String as serde::Deserialize>::deserialize(deserializer)?;
    if encoded.len() > MAX_ENVELOPE_BYTES.div_ceil(3) * 4 {
        return Err(serde::de::Error::custom("witness-artifact-too-large"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| serde::de::Error::custom("witness-artifact-malformed"))
}

impl std::fmt::Debug for WitnessedEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WitnessedEnvelope")
            .field("envelope_bytes", &"<withheld>")
            .field("certificate_json", &"<withheld>")
            .field("signature_hex", &"<withheld>")
            .finish()
    }
}

/// The two reads a client makes before it trusts anything.
///
/// A trait so the ordering tests can drive a recording double, and so the
/// allowlist gate is observable as "nothing was contacted" rather than
/// inferred from a check existing.
#[async_trait::async_trait]
pub trait WitnessTransport: Send + Sync {
    /// `GET /v1/attestation?nonce=<hex>`.
    async fn attestation(
        &self,
        nonce: &WitnessNonce,
    ) -> Result<AttestationEvidence, WitnessTrustError>;

    /// `POST /v1/attestation-collateral` against **ingest**, not the witness.
    async fn collateral(&self, quote: &[u8]) -> Result<Collateral, WitnessTrustError>;

    /// `POST /v1/witness` with the raw contribution.
    ///
    /// Takes `&VerifiedWitness` rather than a URL, and that is the whole
    /// point: an implementation cannot be called without one, and only
    /// `super::verify` can make one.
    async fn witness(
        &self,
        witness: &VerifiedWitness,
        body: &[u8],
    ) -> Result<WitnessedEnvelope, WitnessTrustError>;
}

/// One session's attested inference call, and the receipt offered for it.
///
/// The two travel together because a receipt without bodies attests nothing:
/// the witness verifies a receipt against the exchange it picks out of the
/// session, so a receipt with no exchange to verify against is a value that
/// can only be refused. Bundling them makes that state unrepresentable rather
/// than merely wrong.
///
/// The reverse is a real state and stays expressible: `receipt: None` is a
/// call whose bodies are carried and whose receipt could not be obtained --
/// an honestly unattested submission. See
/// [`crate::submit`]'s `inference_receipt_for` for why that is not a refusal.
#[derive(Clone, Copy)]
pub struct AttestedInference<'a> {
    /// The final call's verbatim bodies.
    pub call: &'a crate::routing::attested::AttestedCall,
    /// The provider's signature over the two body digests, when one was
    /// obtained. Forwarded verbatim; nothing in this crate reads it.
    pub receipt: Option<&'a ReceiptPayload>,
}

impl std::fmt::Debug for AttestedInference<'_> {
    /// Neither half is renderable. `AttestedCall` withholds its bodies and a
    /// receipt is caller data, so this says only whether one is present.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttestedInference")
            .field("call", &self.call)
            .field("receipt", &self.receipt.is_some())
            .finish()
    }
}

/// The consent grant a claim carried, applied by the witness *inside* the
/// certified bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantedConsent {
    pub scopes: Vec<ConsentScope>,
    pub uses: Vec<TraceAllowedUse>,
}

/// Send a raw session to a witness that has been verified, and check what
/// comes back.
///
/// # Why the client verifies a certificate it is only forwarding
///
/// It is the only party holding both the input and the returned artifact. A
/// witness that returned an artifact its own certificate does not cover is
/// **undetectable on the server**, which would check that certificate against
/// the bytes it holds, find them consistent, and never have seen what was
/// sent. So both halves are checked here: the signature recovers to the
/// **pinned** address, and the digest matches the returned envelope bytes *as
/// received on the wire* -- never a re-serialisation of a parsed envelope,
/// which would compare the certificate against bytes nobody will ever send.
///
/// # Why the attested bodies are attached HERE and nowhere else
///
/// `attested` carries the final inference call's verbatim request and
/// response bytes, and this function is the **only** place in the client that
/// puts them into a contribution. They are appended to a copy that exists for
/// the length of one request: not to the transcript's own raw contribution,
/// not to anything redacted locally, not to anything queued or submitted.
///
/// That is the whole safety argument for carrying them at all. The witness
/// runs in an enclave, verifies the receipt against these bytes, **strips
/// them**, and certifies the stripped artifact. So the bodies exist in one
/// process's memory and one TLS connection, and nothing downstream ever holds
/// them. A contributor who has configured no witness ships exactly what they
/// shipped before, because this function is not on their path.
///
/// The strip is the witness's job and this client cannot perform it, but it
/// can refuse to accept an artifact where it did not happen -- see
/// [`WitnessTrustError::WitnessBodyNotStripped`]. That check is not a
/// courtesy: a witness that returned the bodies would have turned a private
/// prompt into a submitted one, and the client is the only party that can
/// still tell.
///
/// # The receipt travels beside the bodies, and binds no model
///
/// `attested.receipt` is the provider's signature over
/// `<sha256 of the request as sent>:<sha256 of the response as received>`,
/// fetched by [`crate::routing::receipt`]. It is forwarded as
/// `inference_receipt`; the witness verifies the last exchange the trace
/// declares. When admission evidence comes back, this client additionally
/// verifies the supplied receipt and compares its exact-byte identity to that
/// evidence before returning the artifact.
///
/// `None` is a first-class case, not a degraded one. A submission with the
/// bodies and no receipt is honestly unattested; a witness configured to
/// require attestation refuses it by name rather than certifying it as
/// attested. Nothing on this path may treat an absent receipt as a reason to
/// abandon a submission.
///
/// The provider's receipt endpoint takes the model as an **unsigned query
/// parameter** and signs a two-part text with no model in it, so a verified
/// receipt establishes nothing about which model served. No caller, comment
/// or surface may say otherwise.
pub async fn witness_contribution(
    transport: &dyn WitnessTransport,
    witness: &VerifiedWitness,
    raw: RawTraceContribution,
    attested: Option<AttestedInference<'_>>,
    granted: &GrantedConsent,
) -> Result<WitnessedEnvelope, WitnessTrustError> {
    // Refused locally, before anything is offered. The client already refuses
    // raw contributions above this bound in `raw_contribution_size_ok`; what
    // is new here is naming the refusal on this path, where the cost of
    // finding out late is that the session was already transmitted.
    raw_contribution_size_ok(&raw).map_err(|_| WitnessTrustError::WitnessPayloadTooLarge)?;

    // The in-transit copy. `raw` itself is left alone so a caller that keeps
    // it -- for a retry, for a local fallback -- never finds bodies in it.
    let mut offered = raw;
    if let Some(attested) = attested {
        let call = attested.call;
        // Strictly last. A witness attests the LAST `HttpExchange` event a
        // trace declares, so an exchange that is not in the final position is
        // a claim about a call that was not the final one. Nothing may be
        // appended after this.
        offered
            .events
            .push(crate::routing::attested::attested_exchange_event(call));
        // The declaration describes what is offered, and what is offered has
        // just changed: the exchange carries the request and the response
        // bodies, which is `tool_payloads` content by the same rule the
        // envelope builder applies. Recomputed here because this is where the
        // event list stops changing -- the caller built its declaration over
        // a list this function then appended to, and on the admission profile
        // that list was empty, so every flag would otherwise read `false`
        // beside the prompt and the completion.
        //
        // Derived rather than asserted, and derived from the same function
        // the builder uses, so the two cannot drift. Nothing here can lower a
        // flag: the events are a superset of the ones the caller declared
        // over.
        let presence = crate::envelope::declared_content_presence(&offered.events);
        offered.consent.message_text_included = presence.message_text;
        offered.consent.tool_payloads_included = presence.tool_payloads;
        offered.consent.routing_metadata_included = presence.routing_metadata;
    }

    let body = witness_request_body(
        &offered,
        granted,
        attested.and_then(|attested| attested.receipt),
    )?;
    // Bounded again after the bodies were added: `raw_contribution_size_ok`
    // above judged the session without them, and the witness has its own
    // request limit. Refused here rather than discovered as a transport
    // error, so the contributor is told the session was too large rather
    // than that the witness was unreachable.
    if body.len() > MAX_WITNESS_REQUEST_BYTES {
        return Err(WitnessTrustError::WitnessPayloadTooLarge);
    }

    let response = transport.witness(witness, &body).await?;

    // The envelope must still be submittable. Checked before the certificate
    // so an oversized artifact is reported as oversized rather than as a
    // certificate problem.
    if response.envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(WitnessTrustError::WitnessPayloadTooLarge);
    }

    // Before the certificate, deliberately. An artifact still carrying the
    // raw bodies is a privacy failure whatever its signature says, and a
    // valid certificate over it is worse than an invalid one -- it would be
    // submitted.
    if let Some(attested) = attested {
        if artifact_still_carries(&response.envelope_bytes, attested.call) {
            return Err(WitnessTrustError::WitnessBodyNotStripped);
        }
    }

    verify_certificate(&response, witness.signing_address())?;
    verify_admission_context(
        &response,
        offered.contributor.tenant_scope_ref.as_deref(),
        attested,
    )?;
    Ok(response)
}

/// Bind signed admission evidence to this account and the exact offered call.
/// Signature verification alone cannot detect a valid certificate for another request.
fn verify_admission_context(
    response: &WitnessedEnvelope,
    tenant: Option<&str>,
    attested: Option<AttestedInference<'_>>,
) -> Result<(), WitnessTrustError> {
    use trace_commons_attestation::receipt::{ReceiptAlgo, verify_receipt};
    use trace_commons_protocol::admission::{
        AdmissionBinding, AdmissionEvidence, REQUEST_METADATA_KEY, is_hash, receipt_identity,
    };
    let Some(headers) = &response.admission else {
        return Ok(());
    };
    let refused = || WitnessTrustError::WitnessCertificateMismatched;
    let evidence: AdmissionEvidence =
        serde_json::from_str(&headers.evidence_json).map_err(|_| refused())?;
    // The tenant id is NOT the account anchor and has not been since V61.
    //
    // This used to read `tenant.strip_prefix("near-")` and compare that
    // suffix to both anchors below. V58 held the two equal by database
    // constraint -- `CHECK (tenant_id = 'near-' || substring(anchor_hash
    // from 8))` -- so the comparison restated a server invariant rather than
    // checking anything this client independently knew. V61 made the anchor a
    // keyed blind index and the tenant id 32 random bytes, precisely so a
    // contributor's tenant id is not computable from their NEAR account name
    // (#716, #783, #785), and from that point the comparison was false for
    // every real account: it refused every admission-bearing submission here,
    // on the upload path, before ingest ever saw one.
    //
    // What replaces it is a check with two genuinely independent inputs,
    // which the tenant comparison never had. `binding.account_anchor_sha256`
    // arrives from the proxy's challenge; `evidence.account_anchor_sha256`
    // comes back from the witness. Requiring those to agree is what the old
    // comparison was standing in for, and unlike it, it can fail honestly: a
    // witness that bound this artifact to some other account is caught here.
    //
    // The account's *authorisation* is not this client's to check and never
    // was. The server resolves the anchor from its stored row for the
    // authenticated (tenant, principal) and refuses evidence bound to any
    // other account in `verify_admission_evidence`. See `is_near_tenant_id`
    // in `daemon::account_onboarding`, which reached the same conclusion.
    // The namespace still has to be right -- admission evidence on a
    // non-wallet tenant is nonsense -- but the suffix is checked for shape
    // only, and is never read as an anchor. `is_hash` is the same predicate
    // the server applies to the `near-` suffix in `admission::anchor`.
    if !tenant
        .and_then(|value| value.strip_prefix("near-"))
        .is_some_and(is_hash)
    {
        return Err(refused());
    }
    let attested = attested.ok_or_else(refused)?;
    let receipt = attested.receipt.ok_or_else(refused)?;
    let request: serde_json::Value =
        serde_json::from_str(attested.call.request_body()).map_err(|_| refused())?;
    let model = request
        .get("model")
        .and_then(|v| v.as_str())
        .ok_or_else(refused)?;
    let encoded = request
        .get("metadata")
        .and_then(|v| v.get(REQUEST_METADATA_KEY))
        .and_then(|v| v.as_str())
        .ok_or_else(refused)?;
    let binding = AdmissionBinding::parse(encoded).map_err(|_| refused())?;
    let verified = verify_receipt(
        receipt,
        attested.call.request_body().as_bytes(),
        attested.call.response_body().as_bytes(),
        model,
    )
    .map_err(|_| refused())?;
    let identity = receipt_identity(
        &verified.signing_address,
        &verified.request_sha256,
        &verified.response_sha256,
    )
    .map_err(|_| refused())?;
    if verified.signing_algo != ReceiptAlgo::Ed25519
        || !is_hash(&binding.account_anchor_sha256)
        || evidence.account_anchor_sha256 != binding.account_anchor_sha256
        || evidence.challenge_sha256 != binding.digest().map_err(|_| refused())?
        || evidence.expires_at != binding.expires_at
        || evidence.provider_signer != verified.signing_address
        || evidence.request_sha256 != verified.request_sha256
        || evidence.response_sha256 != verified.response_sha256
        || evidence.receipt_sha256 != identity
        || evidence.model != model
        || evidence.request_bytes != attested.call.request_body().len() as u64
    {
        return Err(refused());
    }
    Ok(())
}

/// The `POST /v1/witness` request document.
///
/// Split out of [`witness_contribution`] so that the AGPL crate's
/// `witness_certificate_cross_implementation` test can drive the server's real
/// router with bytes this function produced. The witness deserialises this
/// with `deny_unknown_fields`, so the field names here are a second
/// implementation of a wire format whose first implementation is unreachable
/// from this crate -- exactly the shape that has drifted silently before.
/// Nothing else in this crate may spell that document.
///
/// `inference_receipt` is **omitted** when there is none, never sent as
/// `null` or as an object of empty strings. Absent is a shape the witness
/// names ("this submission carried no receipt"); an empty receipt is one it
/// would have to refuse as unverifiable, which reads as tampering rather than
/// as an absence.
///
/// # Errors
///
/// [`WitnessTrustError::WitnessResponseMalformed`] if the contribution does
/// not serialise.
pub fn witness_request_body(
    offered: &RawTraceContribution,
    granted: &GrantedConsent,
    receipt: Option<&ReceiptPayload>,
) -> Result<Vec<u8>, WitnessTrustError> {
    let mut document = serde_json::Map::new();
    document.insert(
        "raw_contribution".to_string(),
        serde_json::to_value(offered).map_err(|_| WitnessTrustError::WitnessResponseMalformed)?,
    );
    document.insert(
        "granted_scopes".to_string(),
        serde_json::json!(granted.scopes),
    );
    document.insert("granted_uses".to_string(), serde_json::json!(granted.uses));
    if let Some(receipt) = receipt {
        let mut body = serde_json::Map::new();
        body.insert("text".to_string(), serde_json::json!(receipt.text));
        body.insert(
            "signature".to_string(),
            serde_json::json!(receipt.signature),
        );
        body.insert(
            "signing_address".to_string(),
            serde_json::json!(receipt.signing_address),
        );
        body.insert(
            "signing_algo".to_string(),
            serde_json::json!(receipt.signing_algo.as_wire()),
        );
        // Which attested key the provider says signed it. The witness routes
        // on this: a `gateway` receipt (what the Responses API returns, and
        // therefore what every Codex session produces) is checked against the
        // gateway's attested key, a `provider_tee` one against the serving
        // model's. Omitting it would send every receipt to one source.
        //
        // **Omitted, not sent as null, when the provider named no kind we
        // recognise.** That is also what keeps this compatible with a witness
        // that predates the field: such a witness refuses unknown fields, so
        // a receipt with no kind to declare still reaches it in the shape it
        // knows. A receipt that *does* declare one needs a witness that
        // understands it -- deploy the witness before the client.
        if let Some(kind) = receipt.signature_kind.as_wire() {
            body.insert("signature_kind".to_string(), serde_json::json!(kind));
        }
        document.insert(
            "inference_receipt".to_string(),
            serde_json::Value::Object(body),
        );
    }
    serde_json::to_vec(&serde_json::Value::Object(document))
        .map_err(|_| WitnessTrustError::WitnessResponseMalformed)
}

/// How large the witnessed request may be once the bodies are in it.
///
/// 32 MiB, half the witness's own 64 MiB request limit. Half rather than all
/// of it because the limit the witness enforces is on the whole HTTP request
/// and this bound is on the JSON document alone; a client that budgeted the
/// server's exact limit would send requests the server refuses.
const MAX_WITNESS_REQUEST_BYTES: usize = 32 * 1024 * 1024;

/// Whether a returned artifact still contains either attested body.
///
/// A containment test over the bytes as received, not a structural walk. The
/// question is not "is the field still there" -- a witness could move it, put
/// it in a different event, or leave it in a diagnostic string -- but "did
/// any of these bytes come back". Substring containment answers exactly that
/// and cannot be satisfied by a rename.
///
/// Only the request body is checked in full. The response body is checked the
/// same way, and both are checked as their raw JSON-escaped forms, because
/// that is how they would appear inside a serialized envelope.
fn artifact_still_carries(
    envelope_bytes: &[u8],
    call: &crate::routing::attested::AttestedCall,
) -> bool {
    let Ok(text) = std::str::from_utf8(envelope_bytes) else {
        // Not a JSON document at all. Reported as malformed by the checks
        // that follow rather than as an un-stripped body.
        return false;
    };
    [call.request_body(), call.response_body()]
        .into_iter()
        .filter(|body| !body.is_empty())
        .any(|body| {
            // The escaped form is what a serialized envelope would hold; the
            // literal form catches an artifact that is not JSON-escaping.
            let escaped = serde_json::to_string(body).unwrap_or_default();
            let escaped = escaped.trim_matches('"');
            text.contains(body) || (!escaped.is_empty() && text.contains(escaped))
        })
}

/// Check a certificate against the bytes that came back with it.
///
/// This is the signature/artifact primitive, not request authorization.
/// `witness_contribution` additionally checks admission against the account,
/// binding and exact receipt it supplied before returning a persistable artifact.
/// Stored review validation checks the configured account again.
///
/// `pub` so the AGPL server crate's
/// `tests/witness_certificate_cross_implementation.rs` can drive the witness's
/// own router and require THIS function to accept what it produced. That test
/// is the only reason the preimage encoder below can be trusted, and it can
/// only live on the server side: the licence boundary lets the AGPL crate
/// depend on this one and never the reverse.
pub fn verify_certificate(
    response: &WitnessedEnvelope,
    pinned_address: &str,
) -> Result<(), WitnessTrustError> {
    use sha2::{Digest as _, Sha256};

    let certificate: serde_json::Value = serde_json::from_str(&response.certificate_json)
        .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?;
    let claimed = certificate
        .get("redacted_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or(WitnessTrustError::WitnessResponseMalformed)?;

    // Over the bytes as received. Not over a re-serialisation of a parsed
    // envelope, which would compare the certificate against bytes nobody will
    // ever send.
    let actual = hex::encode(Sha256::digest(&response.envelope_bytes));
    if !claimed.eq_ignore_ascii_case(&actual) {
        return Err(WitnessTrustError::WitnessCertificateMismatched);
    }

    // The signature is over the certificate's canonical signing bytes, which
    // the server derives from these same fields. The client checks recovery
    // against the PINNED address, never against an address the witness
    // reported -- a witness that could name the address its signature
    // recovers to could sign with any key at all.
    let signing_bytes = certificate_signing_bytes(&certificate)
        .ok_or(WitnessTrustError::WitnessResponseMalformed)?;
    let recovered = trace_commons_attestation::eip191::recover_eip191_signer(
        &signing_bytes,
        &response.signature_hex,
    )
    .map_err(|_| WitnessTrustError::WitnessCertificateUnverified)?;
    let expected = trace_commons_attestation::address::decode_address(pinned_address)
        .ok_or(WitnessTrustError::WitnessCertificateUnverified)?;
    if recovered != expected {
        return Err(WitnessTrustError::WitnessCertificateUnverified);
    }
    if let Some(headers) = &response.admission {
        let evidence: trace_commons_protocol::admission::AdmissionEvidence =
            serde_json::from_str(&headers.evidence_json)
                .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?;
        let signing_bytes = evidence
            .signing_bytes()
            .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?;
        if evidence.artifact_sha256 != actual
            || certificate
                .get("witness_measurement")
                .and_then(|v| v.as_str())
                != Some(evidence.witness_measurement.as_str())
            || certificate
                .get("redaction_policy_version")
                .and_then(|v| v.as_str())
                != Some(evidence.redaction_policy_version.as_str())
        {
            return Err(WitnessTrustError::WitnessCertificateMismatched);
        }
        let signer = trace_commons_attestation::eip191::recover_eip191_signer(
            &signing_bytes,
            &headers.signature_hex,
        )
        .map_err(|_| WitnessTrustError::WitnessCertificateUnverified)?;
        if signer != expected {
            return Err(WitnessTrustError::WitnessCertificateUnverified);
        }
    }
    Ok(())
}

/// Rebuild the certificate's signing preimage from its wire fields.
///
/// **Length-prefixed, never JSON.** The server's `WitnessCertificate` has
/// deliberately no `Serialize`, precisely so that no JSON form of it can drift
/// into being treated as the signing preimage: `serde_json`'s map ordering is
/// not guaranteed, and `serde_json/preserve_order` -- which `dcap-qvl` enables
/// in this crate's graph -- has already moved digests in this workspace once.
/// The length prefixes are what make the encoding injective; concatenating
/// fields directly would let content shift across a boundary without changing
/// the bytes.
///
/// **Little-endian, both prefixes.** The server's `signing_bytes` is the
/// single source of truth for this encoding and writes every fixed-width
/// field little-endian; a big-endian length prefix here recovers a different
/// address and refuses every honest certificate. Nothing about the layout is
/// observable from a client-only test, which is why the cross-implementation
/// test below is the thing that holds it.
///
/// This is a second implementation of an encoding whose first implementation
/// is AGPL and unreachable from here. That duplication is a real cost and the
/// reason `a_certificate_this_client_accepts_is_one_the_server_issued` exists:
/// it drives the server's own witness through a fixture and requires this
/// function to verify what that produced, so the two cannot drift silently.
fn certificate_signing_bytes(certificate: &serde_json::Value) -> Option<Vec<u8>> {
    const SIGNING_DOMAIN: &[u8] = b"trace_commons.redaction_witness_certificate.v1\n";

    let digest = certificate.get("redacted_sha256")?.as_str()?;
    let verdict = certificate.get("residual_risk_verdict")?.as_str()?;
    let policy = certificate.get("redaction_policy_version")?.as_str()?;
    let measurement = certificate.get("witness_measurement")?.as_str()?;
    let timestamp = certificate.get("timestamp")?.as_i64()?;

    // The verdict is a fixed-width tag, not its label. These values are
    // assigned permanently on the server side; changing one would let a
    // Medium certificate re-verify as Low.
    let verdict_tag = match verdict {
        "low" => 1u8,
        "medium" => 2,
        "high" => 3,
        _ => return None,
    };

    let mut bytes = Vec::new();
    bytes.extend_from_slice(SIGNING_DOMAIN);
    for field in [digest, policy, measurement] {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes.push(verdict_tag);
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    Some(bytes)
}

/// The HTTP implementation.
pub struct HttpWitnessTransport {
    http: reqwest::Client,
    witness_url: String,
    collateral_url: String,
    allowlist: Arc<HostAllowlist>,
    admission_evidence: bool,
}

impl HttpWitnessTransport {
    /// Build a transport. `collateral_url` is the **ingest** base URL, not
    /// the witness: collateral comes from ingest, which already has a PCCS
    /// and the rustls provider its client needs.
    pub fn new(
        witness_url: impl Into<String>,
        collateral_url: impl Into<String>,
        allowlist: Arc<HostAllowlist>,
        timeout: Duration,
    ) -> Result<Self, WitnessTrustError> {
        let http = reqwest::Client::builder()
            // Raw sessions are authorized for this attested endpoint only.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| WitnessTrustError::WitnessAttestationUnavailable)?;
        Ok(Self {
            http,
            witness_url: witness_url.into(),
            collateral_url: collateral_url.into(),
            allowlist,
            admission_evidence: false,
        })
    }

    /// Select the distinct evidence route only for an explicitly configured profile.
    pub fn with_admission_evidence(mut self, enabled: bool) -> Self {
        self.admission_evidence = enabled;
        self
    }

    /// The allowlist gate, applied **before** a request is built.
    ///
    /// The same `HostAllowlist` `issuer_url` and `ingest_url` pass. A host
    /// outside it is refused with nothing contacted, which the ordering tests
    /// assert directly rather than inferring from this check existing.
    fn allowed(&self, url: &str) -> Result<url::Url, WitnessTrustError> {
        let parsed = url::Url::parse(url).map_err(|_| WitnessTrustError::WitnessHostNotAllowed)?;
        self.allowlist
            .check(&parsed)
            .map_err(|_| WitnessTrustError::WitnessHostNotAllowed)?;
        Ok(parsed)
    }
}

#[async_trait::async_trait]
impl WitnessTransport for HttpWitnessTransport {
    async fn attestation(
        &self,
        nonce: &WitnessNonce,
    ) -> Result<AttestationEvidence, WitnessTrustError> {
        let base = self.allowed(&self.witness_url)?;
        let url = base
            .join("/v1/attestation")
            .map_err(|_| WitnessTrustError::WitnessHostNotAllowed)?;
        let response = self
            .http
            .get(url)
            .query(&[("nonce", nonce.to_hex())])
            .send()
            .await
            .map_err(|_| WitnessTrustError::WitnessAttestationUnavailable)?;
        if !response.status().is_success() {
            return Err(WitnessTrustError::WitnessAttestationUnavailable);
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|_| WitnessTrustError::WitnessAttestationUnavailable)?;
        Ok(AttestationEvidence {
            quote_hex: body
                .get("quote_hex")
                .and_then(serde_json::Value::as_str)
                .ok_or(WitnessTrustError::WitnessAttestationUnavailable)?
                .to_string(),
            signing_address: body
                .get("signing_address")
                .and_then(serde_json::Value::as_str)
                .ok_or(WitnessTrustError::WitnessAttestationUnavailable)?
                .to_string(),
        })
    }

    async fn collateral(&self, quote: &[u8]) -> Result<Collateral, WitnessTrustError> {
        let base = self.allowed(&self.collateral_url)?;
        let url = base
            .join("/v1/attestation-collateral")
            .map_err(|_| WitnessTrustError::WitnessHostNotAllowed)?;
        let response = self
            .http
            .post(url)
            .json(&serde_json::json!({ "quote_hex": hex::encode(quote) }))
            .send()
            .await
            .map_err(|_| WitnessTrustError::WitnessCollateralUnavailable)?;
        if !response.status().is_success() {
            return Err(WitnessTrustError::WitnessCollateralUnavailable);
        }
        let body = response
            .text()
            .await
            .map_err(|_| WitnessTrustError::WitnessCollateralUnavailable)?;
        parse_collateral(&body).map_err(|_| WitnessTrustError::WitnessCollateralUnavailable)
    }

    async fn witness(
        &self,
        witness: &VerifiedWitness,
        body: &[u8],
    ) -> Result<WitnessedEnvelope, WitnessTrustError> {
        /// Read a non-success witness answer as the refusal it names.
        ///
        /// The status alone cannot separate "declined your receipt" from
        /// "answered nonsense", and those are opposite instructions to a
        /// contributor. The body is attacker-influenceable, so it selects
        /// nothing: it is matched against the protocol's closed set, must
        /// agree with the status, and anything else -- an unknown label, a
        /// body that is not JSON, no body at all -- keeps the answer this
        /// client gave before.
        ///
        /// Only the head of the body is read. A refusal envelope is a few
        /// dozen bytes, and a witness that answers a refusal with megabytes
        /// is not one whose body should be buffered whole.
        async fn refusal_from(response: reqwest::Response) -> WitnessTrustError {
            const REFUSAL_BODY_BOUND: usize = 4096;
            let status = response.status().as_u16();
            let Ok(body) = response.bytes().await else {
                return WitnessTrustError::WitnessResponseMalformed;
            };
            let head = &body[..body.len().min(REFUSAL_BODY_BOUND)];
            let label = serde_json::from_slice::<serde_json::Value>(head)
                .ok()
                .and_then(|value| value.get("error")?.as_str().map(str::to_string));
            match label.as_deref().and_then(|label| {
                trace_commons_protocol::admission::AdmissionRefusal::from_response(status, label)
            }) {
                Some(trace_commons_protocol::admission::AdmissionRefusal::EvidenceRefused) => {
                    WitnessTrustError::WitnessAdmissionEvidenceRefused
                }
                // Every other refusal in that set belongs to the ingest gate,
                // which is not what answered here.
                _ => WitnessTrustError::WitnessResponseMalformed,
            }
        }

        let base = self.allowed(witness.url())?;
        let url = base
            .join(if self.admission_evidence {
                "/v1/witness/admission"
            } else {
                "/v1/witness"
            })
            .map_err(|_| WitnessTrustError::WitnessHostNotAllowed)?;
        let response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| WitnessTrustError::WitnessAttestationUnavailable)?;
        if !response.status().is_success() {
            return Err(refusal_from(response).await);
        }
        let headers = response.headers().clone();
        let read = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
                .ok_or(WitnessTrustError::WitnessResponseMalformed)
        };
        let certificate_json = read(WITNESS_CERTIFICATE_HEADER)?;
        let signature_hex = read(WITNESS_SIGNATURE_HEADER)?;
        let admission = if self.admission_evidence {
            Some(AdmissionHeaders {
                evidence_json: read(trace_commons_protocol::admission::EVIDENCE_HEADER)?,
                signature_hex: read(trace_commons_protocol::admission::SIGNATURE_HEADER)?,
            })
        } else {
            None
        };
        // `bytes()`, never `json()`: the certificate covers these exact bytes
        // and a parse-then-reserialise here would break the digest before the
        // client ever checked it.
        let envelope_bytes = response
            .bytes()
            .await
            .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?
            .to_vec();
        Ok(WitnessedEnvelope {
            envelope_bytes,
            certificate_json,
            signature_hex,
            admission,
        })
    }
}

/// Parse the bytes a witness returned, for a caller that needs the envelope
/// as a value.
///
/// Provided so that no caller is tempted to parse and then re-serialise: the
/// parsed value is for reading, and `envelope_bytes` remains the only thing
/// that is ever submitted.
pub fn parse_witnessed_envelope(
    response: &WitnessedEnvelope,
) -> Result<TraceContributionEnvelope, WitnessTrustError> {
    serde_json::from_slice(&response.envelope_bytes)
        .map_err(|_| WitnessTrustError::WitnessResponseMalformed)
}

#[cfg(test)]
pub(crate) fn signed_fixture(bytes: Vec<u8>) -> (WitnessedEnvelope, String) {
    tests::signed_fixture(bytes)
}

#[cfg(test)]
pub(crate) fn signed_admission_fixture(bytes: Vec<u8>, account: &str) -> WitnessedEnvelope {
    tests::signed_admission_fixture(bytes, account)
}

/// Explicit token-bundle request, bound to a separately acquired capture lease.
pub struct TokenBundleRequest {
    pub capture_store_id: String,
    pub capture_id: String,
    pub bundle_revision: String,
    pub restricted_token_consent: bool,
}

impl HttpWitnessTransport {
    /// The verified witness type enforces attestation before raw bytes leave.
    pub async fn witness_token_contribution(
        &self,
        witness: &VerifiedWitness,
        mut raw: RawTraceContribution,
        attested: AttestedInference<'_>,
        granted: &GrantedConsent,
        options: TokenBundleRequest,
    ) -> Result<crate::token_bundle::CertifiedBundleUpload, WitnessTrustError> {
        if !options.restricted_token_consent || attested.receipt.is_none() {
            return Err(WitnessTrustError::WitnessAdmissionEvidenceRefused);
        }
        if !raw.events.is_empty() {
            return Err(WitnessTrustError::WitnessAdmissionEvidenceRefused);
        }
        raw.events
            .push(crate::routing::attested::attested_exchange_event(
                attested.call,
            ));
        let presence = crate::envelope::declared_content_presence(&raw.events);
        raw.consent.message_text_included = presence.message_text;
        raw.consent.tool_payloads_included = presence.tool_payloads;
        raw.consent.routing_metadata_included = presence.routing_metadata;
        raw_contribution_size_ok(&raw).map_err(|_| WitnessTrustError::WitnessPayloadTooLarge)?;
        let contribution: serde_json::Value =
            serde_json::from_slice(&witness_request_body(&raw, granted, attested.receipt)?)
                .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?;
        let body = serde_json::to_vec(&serde_json::json!({"contribution":contribution,"capture_store_id":options.capture_store_id,"capture_id":options.capture_id,"bundle_revision":options.bundle_revision,"restricted_token_consent":true})).map_err(|_| WitnessTrustError::WitnessResponseMalformed)?;
        if body.len() > MAX_WITNESS_REQUEST_BYTES {
            return Err(WitnessTrustError::WitnessPayloadTooLarge);
        }
        let url = self
            .allowed(witness.url())?
            .join("/v1/witness/token-bundle")
            .map_err(|_| WitnessTrustError::WitnessHostNotAllowed)?;
        let mut response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| WitnessTrustError::WitnessAttestationUnavailable)?;
        if !response.status().is_success() {
            return Err(WitnessTrustError::WitnessAdmissionEvidenceRefused);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?
        {
            if bytes.len().saturating_add(chunk.len()) > 64 * 1024 * 1024 {
                return Err(WitnessTrustError::WitnessPayloadTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            envelope_bytes: Vec<u8>,
            envelope_certificate: serde_json::Value,
            envelope_signature_hex: String,
            manifest_bytes: Vec<u8>,
            attachment_bytes: Vec<u8>,
            certificate: serde_json::Value,
            signature_hex: String,
            admission: Option<(trace_commons_protocol::admission::AdmissionEvidence, String)>,
        }
        let response: Response = serde_json::from_slice(&bytes)
            .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?;
        let encode = |value: &serde_json::Value| {
            serde_json::to_string(value).map_err(|_| WitnessTrustError::WitnessResponseMalformed)
        };
        let admission = response
            .admission
            .map(|(evidence, signature_hex)| {
                Ok::<_, WitnessTrustError>(AdmissionHeaders {
                    evidence_json: serde_json::to_string(&evidence)
                        .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?,
                    signature_hex,
                })
            })
            .transpose()?;
        let envelope = WitnessedEnvelope {
            envelope_bytes: response.envelope_bytes,
            certificate_json: encode(&response.envelope_certificate)?,
            signature_hex: response.envelope_signature_hex,
            admission,
        };
        if envelope.envelope_bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(WitnessTrustError::WitnessPayloadTooLarge);
        }
        if artifact_still_carries(&envelope.envelope_bytes, attested.call) {
            return Err(WitnessTrustError::WitnessBodyNotStripped);
        }
        verify_certificate(&envelope, witness.signing_address())?;
        verify_admission_context(
            &envelope,
            raw.contributor.tenant_scope_ref.as_deref(),
            Some(attested),
        )?;
        let manifest = WitnessedEnvelope {
            envelope_bytes: response.manifest_bytes,
            certificate_json: encode(&response.certificate)?,
            signature_hex: response.signature_hex,
            admission: None,
        };
        verify_certificate(&manifest, witness.signing_address())?;
        let decoded =
            trace_commons_protocol::token_distribution::ContributionBundleManifest::decode(
                &manifest.envelope_bytes,
            )
            .map_err(|_| WitnessTrustError::WitnessResponseMalformed)?;
        if decoded.attachments.len() != 1
            || !decoded.envelope_digest.matches(&envelope.envelope_bytes)
        {
            return Err(WitnessTrustError::WitnessCertificateMismatched);
        }
        decoded
            .verify_attachment(
                &decoded.attachments[0].artifact_id,
                &response.attachment_bytes,
            )
            .map_err(|_| WitnessTrustError::WitnessCertificateMismatched)?;
        Ok(crate::token_bundle::CertifiedBundleUpload {
            pinned_witness_address: witness.signing_address().into(),
            envelope,
            manifest,
            attachments: std::collections::BTreeMap::from([(
                decoded.attachments[0].artifact_id.clone(),
                response.attachment_bytes,
            )]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::{Query, Request};
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use trace_commons_attestation::receipt::{ReceiptAlgo, ReceiptSignatureKind};

    /// What a local witness saw.
    ///
    /// Assertions are about what reached the wire, not about what the client
    /// believes it sent -- which is the only way to state "nothing was
    /// contacted" as a fact rather than as an inference from a check
    /// existing.
    #[derive(Default)]
    struct Seen {
        /// Route names in the order they were requested.
        routes: Vec<String>,
        /// The `nonce` query parameter, as received.
        nonces: Vec<String>,
        /// Bodies posted to `/v1/witness`, as received.
        witness_bodies: Vec<Vec<u8>>,
        /// Bodies posted to the collateral route, as received.
        collateral_bodies: Vec<Vec<u8>>,
    }

    /// What a local witness should answer with. `None` on any field makes
    /// that route 503, which is how the unreachable-route tests are driven.
    #[derive(Default, Clone)]
    struct Answers {
        attestation: Option<serde_json::Value>,
        collateral: Option<String>,
        witness: Option<(String, String, Vec<u8>)>,
        /// A status and an `{"error": ...}` label the witness answers with
        /// instead of certifying. Takes precedence over `witness`.
        witness_refusal: Option<(u16, &'static str)>,
    }

    struct LocalWitness {
        base: String,
        seen: Arc<Mutex<Seen>>,
        _shutdown: tokio::sync::oneshot::Sender<()>,
    }

    impl LocalWitness {
        fn routes(&self) -> Vec<String> {
            self.seen.lock().unwrap().routes.clone()
        }
        fn nonces(&self) -> Vec<String> {
            self.seen.lock().unwrap().nonces.clone()
        }
        fn witness_bodies(&self) -> Vec<Vec<u8>> {
            self.seen.lock().unwrap().witness_bodies.clone()
        }
        fn collateral_bodies(&self) -> Vec<Vec<u8>> {
            self.seen.lock().unwrap().collateral_bodies.clone()
        }
    }

    /// Spawn a witness on an ephemeral port.
    ///
    /// A real socket rather than a mock: the thing under test is the
    /// transport -- which URL it composes, which query parameter it sets, and
    /// whether a body reached the wire at all.
    async fn local_witness(answers: Answers) -> LocalWitness {
        let seen = Arc::new(Mutex::new(Seen::default()));

        let attestation_seen = seen.clone();
        let attestation = answers.attestation.clone();
        let collateral_seen = seen.clone();
        let collateral = answers.collateral.clone();
        let witness_seen = seen.clone();
        let witness = answers.witness.clone();
        let witness_refusal = answers.witness_refusal;

        let app = Router::new()
            .route(
                "/v1/attestation",
                get(move |Query(query): Query<HashMap<String, String>>| {
                    let seen = attestation_seen.clone();
                    let body = attestation.clone();
                    async move {
                        {
                            let mut seen = seen.lock().unwrap();
                            seen.routes.push("attestation".to_string());
                            if let Some(nonce) = query.get("nonce") {
                                seen.nonces.push(nonce.clone());
                            }
                        }
                        match body {
                            Some(body) => axum::Json(body).into_response(),
                            None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                        }
                    }
                }),
            )
            .route(
                "/v1/attestation-collateral",
                post(move |request: Request| {
                    let seen = collateral_seen.clone();
                    let body = collateral.clone();
                    async move {
                        let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                            .await
                            .unwrap_or_default();
                        {
                            let mut seen = seen.lock().unwrap();
                            seen.routes.push("collateral".to_string());
                            seen.collateral_bodies.push(bytes.to_vec());
                        }
                        match body {
                            Some(body) => body.into_response(),
                            None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                        }
                    }
                }),
            )
            .route(
                "/v1/witness",
                post(move |request: Request| {
                    let seen = witness_seen.clone();
                    let answer = witness.clone();
                    async move {
                        let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024 * 1024)
                            .await
                            .unwrap_or_default();
                        {
                            let mut seen = seen.lock().unwrap();
                            seen.routes.push("witness".to_string());
                            seen.witness_bodies.push(bytes.to_vec());
                        }
                        match witness_refusal {
                            Some((status, label)) => (
                                StatusCode::from_u16(status).expect("a legal status"),
                                axum::Json(serde_json::json!({ "error": label })),
                            )
                                .into_response(),
                            None => witness_answer(answer),
                        }
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        LocalWitness {
            base,
            seen,
            _shutdown: tx,
        }
    }

    fn witness_answer(answer: Option<(String, String, Vec<u8>)>) -> Response {
        let Some((certificate, signature, envelope)) = answer else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            WITNESS_CERTIFICATE_HEADER,
            HeaderValue::from_str(&certificate).expect("a test certificate header"),
        );
        headers.insert(
            WITNESS_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).expect("a test signature header"),
        );
        (headers, envelope).into_response()
    }

    fn transport_for(base: &str, allowlist: HostAllowlist) -> HttpWitnessTransport {
        HttpWitnessTransport::new(
            base.to_string(),
            base.to_string(),
            Arc::new(allowlist),
            Duration::from_secs(5),
        )
        .expect("the transport builds")
    }

    fn permissive() -> HostAllowlist {
        HostAllowlist::permissive()
    }

    #[tokio::test]
    async fn the_nonce_on_the_wire_is_the_one_we_will_check_against() {
        let server = local_witness(Answers {
            attestation: Some(serde_json::json!({
                "quote_hex": "00ff",
                "signing_address": "0x1111111111111111111111111111111111111111",
            })),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());

        let nonce = WitnessNonce::fresh().expect("the system CSPRNG is available");
        let evidence = transport.attestation(&nonce).await.expect("evidence");

        assert_eq!(server.nonces(), vec![nonce.to_hex()]);
        // Bare hex, no `0x`: the witness surface accepts that encoding and
        // only that one, and a prefixed nonce would be refused as malformed.
        assert!(!nonce.to_hex().starts_with("0x"));
        assert_eq!(nonce.to_hex().len(), WITNESS_NONCE_LEN * 2);
        assert_eq!(evidence.quote_hex, "00ff");
    }

    #[tokio::test]
    async fn two_verifications_never_reuse_a_nonce() {
        // A reused nonce turns a replayed quote into an accepted one for as
        // long as the reuse lasts, and the reuse is invisible at the response
        // boundary because a replayed quote verifies perfectly.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let nonce = WitnessNonce::fresh().expect("the system CSPRNG is available");
            assert!(
                seen.insert(nonce.to_hex()),
                "WitnessNonce::fresh repeated a value"
            );
        }
    }

    #[tokio::test]
    async fn a_host_outside_the_allowlist_is_refused_before_any_request() {
        let server = local_witness(Answers {
            attestation: Some(serde_json::json!({
                "quote_hex": "00ff",
                "signing_address": "0x1111111111111111111111111111111111111111",
            })),
            ..Answers::default()
        })
        .await;
        // An allowlist naming somebody else. The transport still points at the
        // live server, so if the gate were applied after the request the
        // server would record it.
        let transport = transport_for(&server.base, HostAllowlist::from_csv("allowed.example"));

        let err = transport
            .attestation(&WitnessNonce::fresh().unwrap())
            .await
            .expect_err("a host outside the allowlist is refused");
        assert_eq!(err, WitnessTrustError::WitnessHostNotAllowed);
        assert!(
            server.routes().is_empty(),
            "a refused host was still contacted: {:?}",
            server.routes()
        );
    }

    #[tokio::test]
    async fn an_unreachable_attestation_route_refuses_by_name() {
        let server = local_witness(Answers::default()).await;
        let transport = transport_for(&server.base, permissive());
        assert_eq!(
            transport
                .attestation(&WitnessNonce::fresh().unwrap())
                .await
                .unwrap_err(),
            WitnessTrustError::WitnessAttestationUnavailable
        );
    }

    #[tokio::test]
    async fn an_attestation_response_missing_a_field_refuses_rather_than_defaulting() {
        // A response that parses as JSON but names no quote. Defaulting to an
        // empty quote here would send an empty string into `verify_quote`,
        // which would fail -- but under the wrong error, telling a contributor
        // the quote did not verify when the witness never sent one.
        let server = local_witness(Answers {
            attestation: Some(serde_json::json!({ "signing_address": "0x11" })),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        assert_eq!(
            transport
                .attestation(&WitnessNonce::fresh().unwrap())
                .await
                .unwrap_err(),
            WitnessTrustError::WitnessAttestationUnavailable
        );
    }

    #[tokio::test]
    async fn missing_collateral_refuses_rather_than_verifying_without_it() {
        let server = local_witness(Answers::default()).await;
        let transport = transport_for(&server.base, permissive());
        assert_eq!(
            transport.collateral(b"quote").await.unwrap_err(),
            WitnessTrustError::WitnessCollateralUnavailable
        );
    }

    #[tokio::test]
    async fn malformed_collateral_refuses_rather_than_being_used() {
        let server = local_witness(Answers {
            collateral: Some("not collateral".to_string()),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        assert_eq!(
            transport.collateral(b"quote").await.unwrap_err(),
            WitnessTrustError::WitnessCollateralUnavailable
        );
    }

    #[tokio::test]
    async fn the_collateral_request_names_the_quote_it_is_for() {
        let server = local_witness(Answers {
            collateral: Some("{}".to_string()),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let _ = transport.collateral(b"\x01\x02\xab").await;

        assert_eq!(server.routes(), vec!["collateral".to_string()]);
        let sent: serde_json::Value =
            serde_json::from_slice(&server.collateral_bodies()[0]).expect("the body is JSON");
        // Collateral for the wrong quote verifies nothing, and the failure
        // would look like a bad quote rather than a bad request.
        assert_eq!(sent["quote_hex"], "0102ab");
    }

    #[tokio::test]
    async fn a_nonce_debug_renders_the_nonce_and_nothing_else() {
        let nonce = WitnessNonce::from_bytes([0x01u8; WITNESS_NONCE_LEN]);
        let rendered = format!("{nonce:?}");
        assert!(rendered.contains(&hex::encode([0x01u8; WITNESS_NONCE_LEN])));
        assert!(rendered.starts_with("WitnessNonce("));
    }

    // -----------------------------------------------------------------
    // Task 5: the ordering property, and what comes back.
    // -----------------------------------------------------------------

    /// A secret the assertions look for in what reached the wire. Distinctive
    /// enough that a match cannot be a coincidence.
    const SECRET: &str = "zzq-raw-session-secret-zzq";

    /// Real Intel collateral, shared with `trace-commons-attestation`'s own
    /// suite.
    ///
    /// Real so that `parse_collateral` succeeds and the refusal below lands
    /// where the test says it does -- at `verify_quote`, on a quote that is
    /// not Intel-signed. With placeholder collateral the run would refuse one
    /// step earlier, at the collateral parse, and the test would be asserting
    /// that a malformed fixture is malformed rather than that an unverifiable
    /// quote is refused.
    const COLLATERAL: &str = include_str!(
        "../../../trace-commons-attestation/tests/fixtures/near_ai_attestation_collateral.json"
    );

    pub(crate) fn signed_fixture(bytes: Vec<u8>) -> (WitnessedEnvelope, String) {
        let key = test_signer("witness-review-test-only");
        let (certificate_json, signature_hex, _) = signed_answer(&key, &bytes);
        (
            WitnessedEnvelope {
                envelope_bytes: bytes,
                admission: None,
                certificate_json,
                signature_hex,
            },
            address_of(&key),
        )
    }

    // Signature/approval fixture only: not provider or enclave qualification.
    pub(crate) fn signed_admission_fixture(bytes: Vec<u8>, account: &str) -> WitnessedEnvelope {
        use trace_commons_protocol::admission::{AdmissionEvidence, EVIDENCE_DOMAIN, hash_hex};
        let (mut response, _) = signed_fixture(bytes);
        let key = test_signer("witness-review-test-only");
        let evidence = AdmissionEvidence {
            profile: EVIDENCE_DOMAIN.into(),
            account_anchor_sha256: account.into(),
            challenge_sha256: "22".repeat(32),
            provider_signer: "33".repeat(32),
            // The kind the witness checked is part of the signed statement.
            // A fixture has to say which one; these exercise signature and
            // approval, not provider qualification, so the attested kind is
            // the one that changes nothing about what they assert.
            signature_kind: trace_commons_protocol::admission::AdmissionSignatureKind::ProviderTee,
            model: "test-model".into(),
            request_bytes: 1,
            request_sha256: "44".repeat(32),
            response_sha256: "55".repeat(32),
            receipt_sha256: "66".repeat(32),
            artifact_sha256: hash_hex(&response.envelope_bytes),
            witness_measurement: "aa".repeat(48),
            redaction_policy_version: "deterministic-v1".into(),
            // Long expired, deliberately. Nothing on the client reloads an
            // approved artifact and re-judges this window:
            // `WitnessReviewArtifact::validate_stored` checks the account
            // anchor and the certificate, and the queue digest pin catches
            // stored tampering, so the window is the operator's to enforce at
            // upload against a clock this process does not own. Epoch-2
            // timestamps are here so a client-side expiry check added later
            // shows up as these tests failing rather than as silence.
            issued_at: 1,
            expires_at: 2,
        };
        response.admission = Some(AdmissionHeaders {
            evidence_json: serde_json::to_string(&evidence).unwrap(),
            signature_hex: sign_eip191(&key, &evidence.signing_bytes().unwrap()),
        });
        response
    }

    #[test]
    fn admission_evidence_is_bound_to_artifact_policy_and_pinned_witness() {
        use trace_commons_protocol::admission::{AdmissionEvidence, EVIDENCE_DOMAIN, hash_hex};
        let (mut response, pinned) = signed_fixture(envelope_bytes());
        let key = test_signer("witness-review-test-only");
        let evidence = AdmissionEvidence {
            profile: EVIDENCE_DOMAIN.into(),
            account_anchor_sha256: "11".repeat(32),
            challenge_sha256: "22".repeat(32),
            provider_signer: "33".repeat(32),
            // The kind the witness checked is part of the signed statement.
            // A fixture has to say which one; these exercise signature and
            // approval, not provider qualification, so the attested kind is
            // the one that changes nothing about what they assert.
            signature_kind: trace_commons_protocol::admission::AdmissionSignatureKind::ProviderTee,
            model: "test-model".into(),
            request_bytes: 1,
            request_sha256: "44".repeat(32),
            response_sha256: "55".repeat(32),
            receipt_sha256: "66".repeat(32),
            artifact_sha256: hash_hex(&response.envelope_bytes),
            witness_measurement: "aa".repeat(48),
            redaction_policy_version: "deterministic-v1".into(),
            issued_at: 1,
            expires_at: 2,
        };
        let headers_for =
            |evidence: &AdmissionEvidence, signer: &k256::ecdsa::SigningKey| AdmissionHeaders {
                evidence_json: serde_json::to_string(evidence).unwrap(),
                signature_hex: sign_eip191(signer, &evidence.signing_bytes().unwrap()),
            };
        response.admission = Some(headers_for(&evidence, &key));
        verify_certificate(&response, &pinned).unwrap();
        response.admission = Some(headers_for(&evidence, &test_signer("untrusted")));
        assert!(verify_certificate(&response, &pinned).is_err());
        for field in ["artifact", "policy", "measurement"] {
            let mut altered = evidence.clone();
            match field {
                "artifact" => altered.artifact_sha256 = "77".repeat(32),
                "policy" => altered.redaction_policy_version = "other".into(),
                _ => altered.witness_measurement = "other".into(),
            }
            response.admission = Some(headers_for(&altered, &key));
            assert!(verify_certificate(&response, &pinned).is_err());
        }
    }

    #[test]
    fn signed_admission_must_match_our_account_challenge_and_exact_receipt() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        use trace_commons_protocol::admission::{
            AdmissionBinding, AdmissionEvidence, EVIDENCE_DOMAIN, hash_hex, receipt_identity,
        };
        let binding = AdmissionBinding {
            account_anchor_sha256: "11".repeat(32),
            nonce_hex: "22".repeat(32),
            expires_at: 200,
        };
        let request = serde_json::json!({"model":"Qwen/Qwen3.6-27B-FP8", "metadata":{"trace_commons_admission":binding.encode().unwrap()}}).to_string();
        let (call, _dir) = attestable_call_with_bodies(&request, "response bytes");
        let provider = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
        let text = format!(
            "{}:{}",
            hash_hex(request.as_bytes()),
            hash_hex(call.response_body().as_bytes())
        );
        let receipt = ReceiptPayload {
            signature: hex::encode(provider.sign(text.as_bytes()).as_ref()),
            text,
            signing_address: hex::encode(provider.public_key().as_ref()),
            signing_algo: ReceiptAlgo::Ed25519,
            signature_kind: trace_commons_attestation::receipt::ReceiptSignatureKind::ProviderTee,
        };
        let (mut response, pinned) = signed_fixture(envelope_bytes());
        let witness = test_signer("witness-review-test-only");
        let evidence = AdmissionEvidence {
            profile: EVIDENCE_DOMAIN.into(),
            account_anchor_sha256: binding.account_anchor_sha256.clone(),
            challenge_sha256: binding.digest().unwrap(),
            provider_signer: receipt.signing_address.clone(),
            // The kind the witness checked is part of the signed statement.
            // A fixture has to say which one; these exercise signature and
            // approval, not provider qualification, so the attested kind is
            // the one that changes nothing about what they assert.
            signature_kind: trace_commons_protocol::admission::AdmissionSignatureKind::ProviderTee,
            model: "Qwen/Qwen3.6-27B-FP8".into(),
            request_bytes: request.len() as u64,
            request_sha256: hash_hex(request.as_bytes()),
            response_sha256: hash_hex(call.response_body().as_bytes()),
            receipt_sha256: receipt_identity(
                &receipt.signing_address,
                &hash_hex(request.as_bytes()),
                &hash_hex(call.response_body().as_bytes()),
            )
            .unwrap(),
            artifact_sha256: hash_hex(&response.envelope_bytes),
            witness_measurement: "aa".repeat(48),
            redaction_policy_version: "deterministic-v1".into(),
            issued_at: 1,
            expires_at: 200,
        };
        // This fixture used to be `format!("near-{}",
        // binding.account_anchor_sha256)`, and while it read that way the
        // "valid" case below could not fail for a real V61 account. See
        // `v61_account`, which names this site.
        let (tenant, _anchor) = crate::config::tests_support::v61_account();
        assert_ne!(
            tenant.strip_prefix("near-"),
            Some(binding.account_anchor_sha256.as_str()),
            "the fixture drifted back to the pre-V61 shape"
        );
        let attested = Some(AttestedInference {
            call: &call,
            receipt: Some(&receipt),
        });
        for field in [
            "valid",
            "account",
            "challenge",
            "provider",
            "request",
            "response",
            "receipt",
            "model",
            "size",
            "expiry",
        ] {
            let mut altered = evidence.clone();
            match field {
                "account" => altered.account_anchor_sha256 = "77".repeat(32),
                "challenge" => altered.challenge_sha256 = "77".repeat(32),
                "provider" => altered.provider_signer = "77".repeat(32),
                "request" => altered.request_sha256 = "77".repeat(32),
                "response" => altered.response_sha256 = "77".repeat(32),
                "receipt" => altered.receipt_sha256 = "77".repeat(32),
                "model" => altered.model = "other".into(),
                "size" => altered.request_bytes += 1,
                "expiry" => altered.expires_at += 1,
                _ => {}
            }
            response.admission = Some(AdmissionHeaders {
                evidence_json: serde_json::to_string(&altered).unwrap(),
                signature_hex: sign_eip191(&witness, &altered.signing_bytes().unwrap()),
            });
            verify_certificate(&response, &pinned).unwrap();
            assert_eq!(
                verify_admission_context(&response, Some(&tenant), attested).is_ok(),
                field == "valid",
                "{field}"
            );
        }
        assert!(verify_admission_context(&response, Some(&tenant), None).is_err());
    }

    fn test_signer(seed: &str) -> k256::ecdsa::SigningKey {
        use sha3::Digest as _;
        k256::ecdsa::SigningKey::from_slice(&sha3::Keccak256::digest(seed.as_bytes()))
            .expect("the seed is a valid scalar")
    }

    fn address_of(key: &k256::ecdsa::SigningKey) -> String {
        use sha3::Digest as _;
        let point = key.verifying_key().to_encoded_point(false);
        let digest = sha3::Keccak256::digest(&point.as_bytes()[1..]);
        format!("0x{}", hex::encode(&digest[12..]))
    }

    fn sign_eip191(key: &k256::ecdsa::SigningKey, message: &[u8]) -> String {
        use sha3::Digest as _;
        let mut hasher = sha3::Keccak256::new();
        hasher.update(b"\x19Ethereum Signed Message:\n");
        hasher.update(message.len().to_string().as_bytes());
        hasher.update(message);
        let digest: [u8; 32] = hasher.finalize().into();
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&digest)
            .expect("the digest is 32 bytes");
        let mut raw = signature.to_bytes().to_vec();
        raw.push(recovery_id.to_byte() + 27);
        format!("0x{}", hex::encode(raw))
    }

    /// The envelope bytes a witness returns in these tests. Not a real
    /// envelope -- nothing here parses it -- but real bytes, which is what the
    /// digest is over.
    fn envelope_bytes() -> Vec<u8> {
        br#"{"schema_version":"test","zeta":1,"alpha":"two"}"#.to_vec()
    }

    fn certificate_json_for(digest_over: &[u8]) -> String {
        use sha2::Digest as _;
        serde_json::json!({
            "redacted_sha256": hex::encode(sha2::Sha256::digest(digest_over)),
            "residual_risk_verdict": "low",
            "redaction_policy_version": "deterministic-v1",
            "witness_measurement": "aa".repeat(48),
            "timestamp": 1_788_264_000i64,
        })
        .to_string()
    }

    /// A witness answer whose certificate covers `digest_over` and is signed
    /// by `signer`.
    fn signed_answer(
        signer: &k256::ecdsa::SigningKey,
        digest_over: &[u8],
    ) -> (String, String, Vec<u8>) {
        let certificate = certificate_json_for(digest_over);
        let parsed: serde_json::Value = serde_json::from_str(&certificate).unwrap();
        let signing_bytes =
            certificate_signing_bytes(&parsed).expect("the fixture certificate is well formed");
        let signature = sign_eip191(signer, &signing_bytes);
        (certificate, signature, envelope_bytes())
    }

    fn raw_with_secret() -> RawTraceContribution {
        use trace_commons_protocol::trace_contribution::{
            RawTraceCaptureTurn, RecordedTraceContributionOptions,
        };
        let started = chrono::Utc::now();
        RawTraceContribution::from_capture_turns(
            &[RawTraceCaptureTurn {
                user_input: format!("deploy with {SECRET}"),
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
        )
    }

    fn granted() -> GrantedConsent {
        GrantedConsent {
            scopes: vec![ConsentScope::DebuggingEvaluation],
            uses: vec![TraceAllowedUse::Debugging],
        }
    }

    fn unpinnable_trust(address: &str) -> crate::witness::WitnessTrust {
        use trace_commons_attestation::measurements::ExpectedMeasurements;
        crate::witness::WitnessTrust {
            signing_address: address.to_string(),
            measurements: vec![
                ExpectedMeasurements::from_env_value(Some(&format!("mrtd={}", "aa".repeat(48))))
                    .unwrap()
                    .unwrap(),
            ],
        }
    }

    #[tokio::test]
    async fn nothing_raw_is_sent_before_the_attestation_is_verified() {
        // Ordering observed at a recording transport, not inferred from a
        // check existing. The quote here is not a real Intel-signed quote, so
        // verification fails -- which is exactly the case that matters: the
        // raw session must not have been offered by the time it does.
        let signer = test_signer("witness");
        let server = local_witness(Answers {
            attestation: Some(serde_json::json!({
                "quote_hex": "00ff",
                "signing_address": address_of(&signer),
            })),
            collateral: Some(COLLATERAL.to_string()),
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            witness_refusal: None,
        })
        .await;
        let transport = transport_for(&server.base, permissive());

        let result = crate::witness::witness_session(
            &transport,
            &server.base,
            &unpinnable_trust(&address_of(&signer)),
            1_788_264_000,
            raw_with_secret(),
            None,
            &granted(),
        )
        .await;
        assert!(result.is_err(), "an unverifiable quote must not be trusted");

        let routes = server.routes();
        let attested = routes.iter().position(|route| route == "attestation");
        let sent = routes.iter().position(|route| route == "witness");
        assert!(
            attested.is_some(),
            "the attestation was never fetched: {routes:?}"
        );
        assert!(
            sent.map(|sent| attested.unwrap() < sent).unwrap_or(true),
            "raw bytes were offered before the enclave was verified: {routes:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_verification_sends_nothing_at_all() {
        // The assertion the test above cannot make on its own: not merely
        // "the send came second" but "the send never happened, and the
        // transcript is not on the wire anywhere".
        let signer = test_signer("witness");
        let server = local_witness(Answers {
            attestation: Some(serde_json::json!({
                "quote_hex": "00ff",
                "signing_address": address_of(&signer),
            })),
            collateral: Some(COLLATERAL.to_string()),
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            witness_refusal: None,
        })
        .await;
        let transport = transport_for(&server.base, permissive());

        let err = crate::witness::witness_session(
            &transport,
            &server.base,
            &unpinnable_trust(&address_of(&signer)),
            1_788_264_000,
            raw_with_secret(),
            None,
            &granted(),
        )
        .await
        .expect_err("an unverifiable quote is refused");
        assert_eq!(err, WitnessTrustError::WitnessQuoteUnverified);

        assert!(
            !server.routes().iter().any(|route| route == "witness"),
            "a refused verification still reached the witness route"
        );
        let everything: Vec<u8> = server
            .witness_bodies()
            .into_iter()
            .chain(server.collateral_bodies())
            .flatten()
            .collect();
        assert!(
            !String::from_utf8_lossy(&everything).contains(SECRET),
            "a refusal still disclosed the transcript, which is the failure this design prevents"
        );
    }

    #[tokio::test]
    async fn a_witness_url_without_a_pin_never_reaches_the_network() {
        let server = local_witness(Answers::default()).await;
        let transport = transport_for(&server.base, permissive());
        let unpinned = crate::witness::WitnessTrust {
            signing_address: address_of(&test_signer("witness")),
            measurements: Vec::new(),
        };

        let err = crate::witness::witness_session(
            &transport,
            &server.base,
            &unpinned,
            1_788_264_000,
            raw_with_secret(),
            None,
            &granted(),
        )
        .await
        .expect_err("an unpinned witness must refuse, never quietly redact locally");
        assert_eq!(err.refusal_label(), "witness_expected_measurement");
        assert!(
            server.routes().is_empty(),
            "an unpinned client still contacted the witness: {:?}",
            server.routes()
        );
    }

    /// A witness that declines a receipt is not a witness that answered
    /// nonsense.
    ///
    /// The trust configuration this refusal comes from -- which signers,
    /// which models, which minimum request size -- is exactly what changes
    /// during a rollout, so this is the common refusal on that path and it
    /// was reported as a malformed response, which every shell renders as a
    /// failed review. Indistinguishable from the witness being down.
    #[tokio::test]
    async fn a_declined_receipt_is_not_a_malformed_response() {
        use trace_commons_protocol::admission::AdmissionRefusal;
        let signer = test_signer("witness");
        let refusal = AdmissionRefusal::EvidenceRefused;
        let server = local_witness(Answers {
            witness_refusal: Some((refusal.status(), refusal.label())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        let err = witness_contribution(&transport, &witness, raw_with_secret(), None, &granted())
            .await
            .expect_err("a declined receipt is still a refusal");
        assert_ne!(
            err,
            WitnessTrustError::WitnessResponseMalformed,
            "a deliberate refusal is still reported as a broken witness"
        );
        assert_eq!(err.refusal_label(), refusal.label());
    }

    /// The fail-closed half: a non-2xx that carries no label this client
    /// knows is still what it always was.
    #[tokio::test]
    async fn an_unlabelled_failure_is_still_a_malformed_response() {
        let signer = test_signer("witness");
        for answer in [
            // No body at all.
            None,
            // A label on a status it is never sent with.
            Some((500, "admission_evidence_refused")),
            Some((403, "something_else_entirely")),
        ] {
            let server = local_witness(Answers {
                witness_refusal: answer,
                ..Answers::default()
            })
            .await;
            let transport = transport_for(&server.base, permissive());
            let witness = crate::witness::verify::verified_witness_for_test(
                &server.base,
                &address_of(&signer),
            );
            let err =
                witness_contribution(&transport, &witness, raw_with_secret(), None, &granted())
                    .await
                    .expect_err("a failed witness call is a refusal");
            assert_eq!(
                err,
                WitnessTrustError::WitnessResponseMalformed,
                "{answer:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_artifact_the_certificate_does_not_cover_is_refused() {
        // Only the client can catch this. The server would check the same
        // certificate against the bytes it holds, find them consistent, and
        // never have seen what was sent.
        let signer = test_signer("witness");
        // A certificate over OTHER bytes, returned alongside `envelope_bytes`.
        let (certificate, signature, _) = signed_answer(&signer, b"some other artifact entirely");
        let server = local_witness(Answers {
            witness: Some((certificate, signature, envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        let err = witness_contribution(&transport, &witness, raw_with_secret(), None, &granted())
            .await
            .expect_err("only the client can catch this; the server cannot");
        assert_eq!(err, WitnessTrustError::WitnessCertificateMismatched);
    }

    #[tokio::test]
    async fn a_certificate_signed_by_another_key_is_refused() {
        let witness_key = test_signer("witness");
        let impostor = test_signer("impostor");
        assert_ne!(address_of(&witness_key), address_of(&impostor));

        // A certificate that covers the returned bytes perfectly -- so the
        // digest check passes -- but is signed by somebody else.
        let server = local_witness(Answers {
            witness: Some(signed_answer(&impostor, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness = crate::witness::verify::verified_witness_for_test(
            &server.base,
            &address_of(&witness_key),
        );

        let err = witness_contribution(&transport, &witness, raw_with_secret(), None, &granted())
            .await
            .expect_err("a certificate from an unpinned key is worth nothing");
        assert_eq!(err, WitnessTrustError::WitnessCertificateUnverified);
    }

    #[tokio::test]
    async fn admission_http_failure_never_retries_the_ordinary_window_route() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let strict = Arc::new(AtomicUsize::new(0));
        let ordinary = Arc::new(AtomicUsize::new(0));
        let strict_count = strict.clone();
        let ordinary_count = ordinary.clone();
        let app = Router::new()
            .route(
                "/v1/witness/admission",
                post(move || {
                    let count = strict_count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        axum::http::StatusCode::BAD_REQUEST
                    }
                }),
            )
            .route(
                "/v1/witness",
                post(move || {
                    let count = ordinary_count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        axum::http::StatusCode::OK
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let source = r#"{"metadata":{"trace_commons_admission":"tcad1:malformed"}}"#;
        let profile = crate::submit::admission_profile_for_request(true, Some(source)).unwrap();
        let transport = transport_for(&url, permissive()).with_admission_evidence(profile);
        let key = test_signer("strict-window-test");
        let witness = crate::witness::verify::verified_witness_for_test(&url, &address_of(&key));
        assert!(
            witness_contribution(&transport, &witness, raw_with_secret(), None, &granted())
                .await
                .is_err()
        );
        assert_eq!(strict.load(Ordering::SeqCst), 1);
        assert_eq!(ordinary.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn a_correctly_signed_certificate_over_the_returned_bytes_is_accepted() {
        // The positive control. Without it, every refusal above would pass on
        // a `verify_certificate` that refused unconditionally.
        let signer = test_signer("witness");
        let server = local_witness(Answers {
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        let response =
            witness_contribution(&transport, &witness, raw_with_secret(), None, &granted())
                .await
                .expect("a certificate over these bytes from the pinned key is accepted");
        // And what comes back is the bytes as received, byte for byte.
        assert_eq!(response.envelope_bytes, envelope_bytes());
    }

    #[tokio::test]
    async fn an_oversized_contribution_is_refused_locally_and_never_offered() {
        let signer = test_signer("witness");
        let server = local_witness(Answers {
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        let mut oversized = raw_with_secret();
        oversized.events[0].content = Some("x".repeat(MAX_ENVELOPE_BYTES + 1));

        let err = witness_contribution(&transport, &witness, oversized, None, &granted())
            .await
            .expect_err("an oversized contribution is refused before it is offered");
        assert_eq!(err, WitnessTrustError::WitnessPayloadTooLarge);
        assert!(
            server.witness_bodies().is_empty(),
            "an oversized contribution was offered anyway"
        );
    }

    #[tokio::test]
    async fn a_witnessed_error_never_renders_the_transcript() {
        let signer = test_signer("witness");
        let (certificate, signature, _) = signed_answer(&signer, b"other bytes");
        let server = local_witness(Answers {
            witness: Some((certificate, signature, envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));
        let err = witness_contribution(&transport, &witness, raw_with_secret(), None, &granted())
            .await
            .unwrap_err();
        for rendering in [format!("{err}"), format!("{err:?}")] {
            assert!(!rendering.contains(SECRET));
            assert!(!rendering.contains(&server.base));
        }
    }

    /// A fully attestable call, built from a temporary body store so the
    /// digests are real and the bodies are the ones the module actually
    /// carries.
    ///
    /// The request body is one a re-serialiser would demonstrably change:
    /// non-alphabetical keys, ragged whitespace, non-ASCII inside a string,
    /// and a float with more precision than a round trip preserves.
    fn attestable_call() -> (crate::routing::attested::AttestedCall, tempfile::TempDir) {
        const AWKWARD: &str = "{\"model\":\"Qwen/Qwen3.6-27B-FP8\", \"temperature\":0.30000000000000004,\n  \"messages\":[{\"role\":\"user\",\"content\":\"café — naïve secret-in-prompt\"}]}";
        const RESPONSE: &str =
            "data: {\"choices\":[{\"delta\":{\"content\":\"café\"}}]}\n\ndata: [DONE]\n\n";

        attestable_call_with_bodies(AWKWARD, RESPONSE)
    }

    fn attestable_call_with_bodies(
        request: &str,
        response: &str,
    ) -> (crate::routing::attested::AttestedCall, tempfile::TempDir) {
        use sha2::Digest as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let reference = "00000000000000000003-000000";
        std::fs::write(dir.path().join(format!("{reference}.req")), request).expect("req");
        std::fs::write(dir.path().join(format!("{reference}.res")), response).expect("res");

        let row = crate::routing::RoutedExchange {
            id: Some(3),
            started_at: chrono::Utc::now(),
            client_session_id: Some("session".to_string()),
            total_ms: Some(10),
            facade: "openai".to_string(),
            backend: "nearai".to_string(),
            requested_model: Some("Qwen/Qwen3.6-27B-FP8".to_string()),
            served_model: Some("Qwen/Qwen3.6-27B-FP8".to_string()),
            upstream_id: Some("chatcmpl-abc123".to_string()),
            request_sha256: Some(hex::encode(sha2::Sha256::digest(request.as_bytes()))),
            response_sha256: Some(hex::encode(sha2::Sha256::digest(response.as_bytes()))),
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
            .expect("the fixture must actually be attestable, or these tests prove nothing");
        (call, dir)
    }

    /// The link: the bodies reach the witness verbatim, as the last
    /// `HttpExchange` event, so the enclave can hash them against a receipt.
    #[tokio::test]
    async fn the_attested_bodies_reach_the_witness_verbatim() {
        let signer = test_signer("witness");
        let server = local_witness(Answers {
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));
        let (call, _dir) = attestable_call();

        witness_contribution(
            &transport,
            &witness,
            raw_with_secret(),
            Some(AttestedInference {
                call: &call,
                receipt: None,
            }),
            &granted(),
        )
        .await
        .expect("a witnessed submission carrying bodies succeeds");

        let sent = server
            .witness_bodies()
            .into_iter()
            .next()
            .expect("the witness was contacted");
        let document: serde_json::Value =
            serde_json::from_slice(&sent).expect("the request is JSON");
        let events = document["raw_contribution"]["events"]
            .as_array()
            .expect("the contribution carries events");
        let last = events.last().expect("there is a last event");

        assert_eq!(
            last["event_type"], "http_exchange",
            "the attested exchange must be the LAST event; a witness attests \
             the last one and nothing else"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event_type"] == "http_exchange")
                .count(),
            1,
            "one call is attested, never one per turn"
        );
        assert_eq!(
            last["structured_payload"]["request"]["body"]
                .as_str()
                .expect("the request body is a string the enclave can hash"),
            call.request_body(),
            "the request body must reach the enclave byte for byte"
        );
        assert_eq!(
            last["content"].as_str().expect("the response body"),
            call.response_body(),
            "the response body must reach the enclave byte for byte"
        );
        assert_eq!(
            last["structured_payload"]["response"]["stream_restarted"],
            serde_json::json!(false),
            "the marker the witness reads must be written"
        );
    }

    /// A receipt for the fixture call. Not verifiable -- these tests are
    /// about the wire, and the enclave-side verification is exercised in
    /// `trace-commons-server`'s cross-implementation suite -- but shaped
    /// exactly like one, with three distinct values so a field that arrives
    /// under the wrong name is visible rather than accidentally equal.
    fn offered_receipt() -> ReceiptPayload {
        ReceiptPayload {
            text: "aaaa1111:bbbb2222".to_string(),
            signature: "0xcccc3333".to_string(),
            signing_address: "0xdddd444444444444444444444444444444444444".to_string(),
            signing_algo: ReceiptAlgo::Ecdsa,
            signature_kind: ReceiptSignatureKind::Unrecognised,
        }
    }

    /// The scheme travels with the receipt. The witness reads
    /// `signing_algo` and dispatches on it; a receipt sent without it is read
    /// as ECDSA, so an ed25519 receipt sent bare would be refused as a
    /// malformed 20-byte address.
    #[test]
    fn the_offered_receipt_carries_its_scheme_to_the_witness() {
        let receipt = ReceiptPayload {
            text: "aaaa1111:bbbb2222".to_string(),
            signature: "cccc3333".to_string(),
            signing_address: "dddd4444".to_string(),
            signing_algo: ReceiptAlgo::Ed25519,
            signature_kind: ReceiptSignatureKind::ProviderTee,
        };
        let body = witness_request_body(&raw_with_secret(), &granted(), Some(&receipt))
            .expect("the fixture contribution serialises");
        let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(document["inference_receipt"]["signing_algo"], "ed25519");
    }

    /// The signature kind travels with the receipt too. The witness routes on
    /// it -- a `gateway` receipt (what the Responses API returns, and so what
    /// every Codex session produces) against the gateway's attested key, a
    /// `provider_tee` one against the serving model's -- so a client that
    /// omitted it would send every receipt to one key source.
    #[test]
    fn the_offered_receipt_carries_its_signature_kind_to_the_witness() {
        for (kind, wire) in [
            (ReceiptSignatureKind::Gateway, "gateway"),
            (ReceiptSignatureKind::ProviderTee, "provider_tee"),
        ] {
            let mut receipt = offered_receipt();
            receipt.signature_kind = kind;
            let body = witness_request_body(&raw_with_secret(), &granted(), Some(&receipt))
                .expect("the fixture contribution serialises");
            let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(document["inference_receipt"]["signature_kind"], wire);
        }
    }

    /// A receipt whose provider named no kind we recognise sends no
    /// `signature_kind` at all -- omitted, never `null`, and never a guessed
    /// default. That is also what keeps such a receipt readable by a witness
    /// that predates the field, which refuses unknown ones.
    #[test]
    fn a_receipt_with_no_recognised_kind_sends_no_signature_kind_field() {
        let receipt = offered_receipt();
        assert_eq!(receipt.signature_kind, ReceiptSignatureKind::Unrecognised);
        let body = witness_request_body(&raw_with_secret(), &granted(), Some(&receipt))
            .expect("the fixture contribution serialises");
        let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            document["inference_receipt"]
                .get("signature_kind")
                .is_none(),
            "an unrecognised kind is omitted, not sent as null or as a default"
        );
    }

    /// The receipt reaches the witness, in the field the witness reads, with
    /// its three strings unchanged.
    ///
    /// The field name is the whole test. `WitnessRequestBody` is
    /// `deny_unknown_fields`, so a misspelling here does not degrade to an
    /// unattested submission -- it makes every witnessed submission a 400,
    /// and this side would report it as an unreachable witness.
    #[tokio::test]
    async fn the_offered_receipt_reaches_the_witness_in_the_field_it_reads() {
        let signer = test_signer("witness");
        let server = local_witness(Answers {
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));
        let (call, _dir) = attestable_call();
        let receipt = offered_receipt();

        witness_contribution(
            &transport,
            &witness,
            raw_with_secret(),
            Some(AttestedInference {
                call: &call,
                receipt: Some(&receipt),
            }),
            &granted(),
        )
        .await
        .expect("a witnessed submission carrying a receipt succeeds");

        let sent = server
            .witness_bodies()
            .into_iter()
            .next()
            .expect("the witness was contacted");
        let document: serde_json::Value =
            serde_json::from_slice(&sent).expect("the request is JSON");
        let offered = &document["inference_receipt"];
        assert_eq!(
            offered["text"].as_str(),
            Some(receipt.text.as_str()),
            "the signed text must reach the enclave verbatim; it is what the \
             two body digests are compared against"
        );
        assert_eq!(
            offered["signature"].as_str(),
            Some(receipt.signature.as_str())
        );
        assert_eq!(
            offered["signing_address"].as_str(),
            Some(receipt.signing_address.as_str())
        );
    }

    /// And a submission with no receipt omits the key rather than sending an
    /// empty one.
    ///
    /// `null` or three empty strings would be a receipt the witness has to
    /// try to verify and refuse as unverifiable -- which an operator reads as
    /// tampering. Absent is the shape that means "carried none", and it is
    /// the one a requiring witness names.
    #[tokio::test]
    async fn no_receipt_means_no_field_rather_than_an_empty_one() {
        let signer = test_signer("witness");
        let server = local_witness(Answers {
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));
        let (call, _dir) = attestable_call();

        witness_contribution(
            &transport,
            &witness,
            raw_with_secret(),
            Some(AttestedInference {
                call: &call,
                receipt: None,
            }),
            &granted(),
        )
        .await
        .expect("an unattested submission carrying bodies still succeeds");

        let sent = server
            .witness_bodies()
            .into_iter()
            .next()
            .expect("the witness was contacted");
        let document: serde_json::Value =
            serde_json::from_slice(&sent).expect("the request is JSON");
        assert!(
            document.get("inference_receipt").is_none(),
            "an absent receipt must be an absent key, never a null or an \
             empty object"
        );
    }

    /// The verbatim request body the mock proxy captured. Awkward on
    /// purpose -- a re-serialiser would change it, and then the digest the
    /// row records would not match.
    const CAPTURED_REQUEST: &str = "{\"model\":\"Qwen/Qwen3.6-27B-FP8\", \"temperature\":0.30000000000000004,\n  \"messages\":[{\"role\":\"user\",\"content\":\"café — the contributor's prompt\"}]}";
    /// The verbatim response body, as a stream comes back.
    const CAPTURED_RESPONSE: &str =
        "data: {\"choices\":[{\"delta\":{\"content\":\"café\"}}]}\n\ndata: [DONE]\n\n";

    /// A daemon standing where a contributor's machine stands: a declared
    /// session root with a session in it, a declared proxy with a captured
    /// exchange for that session, and the attested-bodies switch set to
    /// `carry_bodies`.
    ///
    /// Every step below is the production one -- `DaemonShared::load`,
    /// `rebuild_routing`, `refresh_routing`, `source_roots_with_routing`,
    /// `all_sources`, and the adapter's own `load`. Nothing calls
    /// `SourceRoots::with_attested_bodies` here, which is the point: that
    /// function existed and was exercised by tests while the production
    /// path never reached it.
    async fn transcript_from_a_declared_proxy(
        carry_bodies: bool,
    ) -> (crate::source::SessionTranscript, Vec<tempfile::TempDir>) {
        use sha2::Digest as _;

        let state = tempfile::tempdir().expect("state dir");
        let claude_root = tempfile::tempdir().expect("claude root");
        let ironwire_home = tempfile::tempdir().expect("ironwire home");

        // What the agent wrote.
        let project = claude_root.path().join("proj");
        std::fs::create_dir_all(&project).expect("project dir");
        std::fs::write(
            project.join("sess-1.jsonl"),
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hi\"},\
             \"cwd\":\"/x/proj\",\"timestamp\":\"2026-08-08T10:00:00Z\",\
             \"version\":\"2.0.1\",\"sessionId\":\"sess-1\",\"uuid\":\"a1\"}\n",
        )
        .expect("session file");

        // What the proxy wrote: its control token, and the body store beside
        // it. The directory name is not restated here -- it is the one the
        // settings module derives, so a change there fails this test.
        std::fs::write(ironwire_home.path().join("control.token"), "token\n").expect("token");
        let bodies = ironwire_home
            .path()
            .join(crate::daemon::settings::IRONWIRE_BODIES_SUBDIR);
        std::fs::create_dir_all(&bodies).expect("body store");
        let reference = "00000000000000000007-000000";
        std::fs::write(bodies.join(format!("{reference}.req")), CAPTURED_REQUEST).expect("req");
        std::fs::write(bodies.join(format!("{reference}.res")), CAPTURED_RESPONSE).expect("res");

        // And the proxy itself, answering with that one exchange.
        let row = serde_json::json!({
            "id": 7,
            "started_at": "2026-08-08T10:05:00Z",
            "client_session_id": "sess-1",
            "facade": "openai",
            "backend": "nearai",
            "rung": "full",
            "attempts": 1,
            "status": 200,
            "served_model": "Qwen/Qwen3.6-27B-FP8",
            "upstream_id": "chatcmpl-abc123",
            "body_ref": reference,
            "request_sha256": hex::encode(sha2::Sha256::digest(CAPTURED_REQUEST.as_bytes())),
            "response_sha256": hex::encode(sha2::Sha256::digest(CAPTURED_RESPONSE.as_bytes())),
        });
        let app = Router::new().route(
            "/_ironwire/log",
            get(move || {
                let row = row.clone();
                async move { axum::Json(serde_json::json!({ "exchanges": [row] })) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let store = crate::config::ConfigStore::open(state.path().to_path_buf()).expect("store");
        let shared = crate::daemon::ipc::DaemonShared::load(store).expect("daemon state");
        {
            let mut settings = shared.settings.lock().expect("settings lock");
            settings.claude_source = Some(crate::daemon::settings::SourceDeclaration::Watch {
                path: claude_root.path().to_path_buf(),
            });
            settings.ironwire = Some(crate::daemon::settings::IronWireDeclaration::Watch {
                port,
                token_dir: Some(ironwire_home.path().to_path_buf()),
            });
            settings.ironwire_attested_bodies = carry_bodies;
            shared.rebuild_effective_routing(&settings);
        }
        shared.refresh_routing().await;

        let roots = shared.source_roots_with_routing();
        let sources = crate::source::all_sources(&roots);
        let claude = sources
            .iter()
            .find(|src| src.name() == crate::source::SOURCE_CLAUDE_CODE)
            .expect("the declared claude source is built");
        let session_ref = claude
            .discover()
            .expect("discovery")
            .into_iter()
            .next()
            .expect("the written session was discovered");
        let transcript = claude.load(&session_ref).expect("the session loads");
        assert_eq!(
            transcript.routing.len(),
            1,
            "the declared proxy's row must have joined the session, or this \
             test is proving nothing about the switch"
        );
        (transcript, vec![state, claude_root, ironwire_home])
    }

    /// The wiring, end to end: a declared proxy plus the separate
    /// attested-bodies switch, through the source roots the daemon actually
    /// builds, to the bytes that reach a witness -- with the receipt beside
    /// them, which is the complete shape `submit::witness_envelope` sends.
    ///
    /// The two halves are honest about different things. The **bodies** are
    /// production-derived: nothing in this test writes an `AttestedCall`, it
    /// comes off a transcript the daemon's own source roots produced, so the
    /// wiring under test is what put it there. The **receipt** is the fixture
    /// `offered_receipt`, not a fetched one: `receipt_for_attested_call`
    /// refuses a plaintext endpoint before it refuses anything else, so a
    /// mock on loopback cannot be fetched from, and a receipt is only
    /// verifiable against a signer this test does not have. It is shaped like
    /// one and carried like one, which is what the wire assertion needs.
    #[tokio::test]
    async fn admission_wire_contains_only_the_isolated_call_and_never_retries_ordinary() {
        let (transcript, _dirs) = transcript_from_a_declared_proxy(true).await;
        let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let seen = captured.clone();
        let ordinary = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ordinary_count = ordinary.clone();
        let app = Router::new().route(
            "/v1/witness/admission",
            post(move |request: Request| {
                let seen = seen.clone();
                async move {
                    let body = axum::body::to_bytes(request.into_body(), MAX_WITNESS_REQUEST_BYTES)
                        .await
                        .unwrap();
                    seen.lock().unwrap().push(body.to_vec());
                    StatusCode::BAD_REQUEST
                }
            }),
        );
        let app = app.route(
            "/v1/witness",
            post(move || {
                let count = ordinary_count.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let transport = transport_for(&url, permissive()).with_admission_evidence(true);
        let key = test_signer("isolated-call");
        let witness = crate::witness::verify::verified_witness_for_test(&url, &address_of(&key));
        let cfg = crate::commands::unenrolled_preview_config();
        let mut raw = raw_with_secret();
        raw.outcome.human_correction = Some("UNBOUND-CORRECTION".into());
        let isolated = crate::submit::witness_input_for_profile(raw, &cfg, true);
        let receipt = offered_receipt();
        let call = transcript.attested_call.as_deref().unwrap();
        assert!(
            witness_contribution(
                &transport,
                &witness,
                isolated,
                Some(AttestedInference {
                    call,
                    receipt: Some(&receipt)
                }),
                &granted()
            )
            .await
            .is_err()
        );
        let bodies = captured.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(ordinary.load(std::sync::atomic::Ordering::SeqCst), 0);
        let body: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        let events = body["raw_contribution"]["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]["structured_payload"]["request"]["body"],
            CAPTURED_REQUEST
        );
        assert_eq!(events[0]["content"], CAPTURED_RESPONSE);
        let serialized = String::from_utf8(bodies[0].clone()).unwrap();
        assert!(!serialized.contains(SECRET));
        assert!(!serialized.contains("UNBOUND-CORRECTION"));
        assert_eq!(body["raw_contribution"]["replay"]["replayable"], false);
        assert_eq!(
            body["raw_contribution"]["consent"]["tool_payloads_included"],
            serde_json::json!(true),
            "the declaration must describe the bodies this request carries"
        );
        task.abort();
    }

    #[tokio::test]
    async fn token_wire_contains_only_the_isolated_call_and_never_retries_ordinary() {
        let (transcript, _dirs) = transcript_from_a_declared_proxy(true).await;
        let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let seen = captured.clone();
        let ordinary = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ordinary_count = ordinary.clone();
        let app = Router::new().route(
            "/v1/witness/token-bundle",
            post(move |request: Request| {
                let seen = seen.clone();
                async move {
                    let body = axum::body::to_bytes(request.into_body(), MAX_WITNESS_REQUEST_BYTES)
                        .await
                        .unwrap();
                    seen.lock().unwrap().push(body.to_vec());
                    StatusCode::BAD_REQUEST
                }
            }),
        );
        let app = app.route(
            "/v1/witness",
            post(move || {
                let count = ordinary_count.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let transport = transport_for(&url, permissive()).with_admission_evidence(true);
        let key = test_signer("isolated-call");
        let witness = crate::witness::verify::verified_witness_for_test(&url, &address_of(&key));
        let cfg = crate::commands::unenrolled_preview_config();
        let mut raw = raw_with_secret();
        raw.outcome.human_correction = Some("UNBOUND-CORRECTION".into());
        let isolated = crate::submit::witness_input_for_profile(raw, &cfg, true);
        let receipt = offered_receipt();
        let call = transcript.attested_call.as_deref().unwrap();
        assert!(
            transport
                .witness_token_contribution(
                    &witness,
                    isolated,
                    AttestedInference {
                        call,
                        receipt: Some(&receipt)
                    },
                    &granted(),
                    TokenBundleRequest {
                        capture_store_id: "1".repeat(32),
                        capture_id: "2".repeat(32),
                        bundle_revision: "r1".into(),
                        restricted_token_consent: true
                    }
                )
                .await
                .is_err()
        );
        let bodies = captured.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(ordinary.load(std::sync::atomic::Ordering::SeqCst), 0);
        let wrapped: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        let body = &wrapped["contribution"];
        let events = body["raw_contribution"]["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]["structured_payload"]["request"]["body"],
            CAPTURED_REQUEST
        );
        assert_eq!(events[0]["content"], CAPTURED_RESPONSE);
        let serialized = String::from_utf8(bodies[0].clone()).unwrap();
        assert!(!serialized.contains(SECRET));
        assert!(!serialized.contains("UNBOUND-CORRECTION"));
        assert_eq!(body["raw_contribution"]["replay"]["replayable"], false);
        assert_eq!(
            body["raw_contribution"]["consent"]["tool_payloads_included"],
            serde_json::json!(true),
            "the declaration must describe the bodies this request carries"
        );
        task.abort();
    }

    /// The declaration follows the payload, in both directions.
    ///
    /// An admission projection carries no events, so it declares no content --
    /// right up to the moment the transport appends the attested exchange,
    /// whose `content` is the completion and whose structured payload is the
    /// prompt. The second half is what a blanket `true` would fail: the same
    /// projection offered without bodies must still declare `false`.
    #[tokio::test]
    async fn the_offered_declaration_follows_the_appended_bodies() {
        let (transcript, _dirs) = transcript_from_a_declared_proxy(true).await;
        let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let seen = captured.clone();
        let app = Router::new().route(
            "/v1/witness/admission",
            post(move |request: Request| {
                let seen = seen.clone();
                async move {
                    let body = axum::body::to_bytes(request.into_body(), MAX_WITNESS_REQUEST_BYTES)
                        .await
                        .unwrap();
                    seen.lock().unwrap().push(body.to_vec());
                    StatusCode::BAD_REQUEST
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let transport = transport_for(&url, permissive()).with_admission_evidence(true);
        let key = test_signer("declaration");
        let witness = crate::witness::verify::verified_witness_for_test(&url, &address_of(&key));
        let cfg = crate::commands::unenrolled_preview_config();
        let isolated = crate::submit::witness_input_for_profile(raw_with_secret(), &cfg, true);
        assert!(
            !isolated.consent.tool_payloads_included,
            "the projection itself declares nothing; the append is what changes it"
        );
        let receipt = offered_receipt();
        let call = transcript.attested_call.as_deref().unwrap();

        assert!(
            witness_contribution(
                &transport,
                &witness,
                isolated.clone(),
                Some(AttestedInference {
                    call,
                    receipt: Some(&receipt)
                }),
                &granted()
            )
            .await
            .is_err()
        );
        assert!(
            witness_contribution(&transport, &witness, isolated, None, &granted())
                .await
                .is_err()
        );

        let bodies = captured.lock().unwrap();
        assert_eq!(bodies.len(), 2);
        let with_bodies: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        let without: serde_json::Value = serde_json::from_slice(&bodies[1]).unwrap();
        assert_eq!(
            with_bodies["raw_contribution"]["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            with_bodies["raw_contribution"]["consent"]["tool_payloads_included"],
            serde_json::json!(true),
            "an offered prompt and completion must be declared"
        );
        assert_eq!(
            with_bodies["raw_contribution"]["consent"]["message_text_included"],
            serde_json::json!(false),
            "an exchange is tool-payload content, and raising the other flags with it \
             would declare conversation this request does not carry"
        );
        assert!(
            without["raw_contribution"]["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            without["raw_contribution"]["consent"]["tool_payloads_included"],
            serde_json::json!(false),
            "declaring content that is not there is the same defect the other way round"
        );
        assert_eq!(
            without["raw_contribution"]["consent"]["message_text_included"],
            serde_json::json!(false)
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_declared_bodies_directory_reaches_the_witness_through_the_daemon_source_roots() {
        let (transcript, _dirs) = transcript_from_a_declared_proxy(true).await;

        let signer = test_signer("witness");
        let server = local_witness(Answers {
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        // The bundle, assembled exactly as `submit::witness_envelope` does:
        // the transcript's own field, mapped into an `AttestedInference` with
        // whatever receipt was obtained for it.
        let receipt = offered_receipt();
        let attested = transcript
            .attested_call
            .as_deref()
            .map(|call| AttestedInference {
                call,
                receipt: Some(&receipt),
            });
        assert!(
            attested.is_some(),
            "the declared body store must have been read on the production path"
        );

        witness_contribution(
            &transport,
            &witness,
            raw_with_secret(),
            attested,
            &granted(),
        )
        .await
        .expect("a witnessed submission carrying the declared bodies succeeds");

        let sent = server
            .witness_bodies()
            .into_iter()
            .next()
            .expect("the witness was contacted");
        let document: serde_json::Value =
            serde_json::from_slice(&sent).expect("the request is JSON");
        let last = document["raw_contribution"]["events"]
            .as_array()
            .expect("events")
            .last()
            .cloned()
            .expect("there is a last event");
        assert_eq!(
            last["structured_payload"]["request"]["body"]
                .as_str()
                .expect("the request body is a string"),
            CAPTURED_REQUEST,
            "the bytes the proxy captured must reach the witness verbatim"
        );
        assert_eq!(
            last["content"].as_str().expect("the response body"),
            CAPTURED_RESPONSE
        );
        // Both halves, in one request: the enclave hashes those bodies and
        // compares the result against the text this receipt signs.
        assert_eq!(
            document["inference_receipt"]["text"].as_str(),
            Some(receipt.text.as_str()),
            "the receipt must ride along with the bodies it is about"
        );
    }

    /// And the separation: the same declared proxy, the same captured
    /// exchange, the switch off. Routing metadata still joins the session --
    /// so the proxy is genuinely declared and genuinely read -- and no body
    /// goes anywhere.
    ///
    /// The receipt goes nowhere either, and not by a second check: the
    /// bundle is built from the call, so no call is no bundle. A receipt
    /// with no bodies to verify it against is unrepresentable.
    #[tokio::test]
    async fn routing_declared_without_the_switch_carries_no_body_to_the_witness() {
        let (transcript, _dirs) = transcript_from_a_declared_proxy(false).await;
        assert!(
            transcript.attested_call.is_none(),
            "cost attribution is not consent to send a prompt"
        );

        let signer = test_signer("witness");
        let server = local_witness(Answers {
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        let receipt = offered_receipt();
        let attested = transcript
            .attested_call
            .as_deref()
            .map(|call| AttestedInference {
                call,
                receipt: Some(&receipt),
            });

        witness_contribution(
            &transport,
            &witness,
            raw_with_secret(),
            attested,
            &granted(),
        )
        .await
        .expect("an unattested submission still succeeds");

        let sent = server
            .witness_bodies()
            .into_iter()
            .next()
            .expect("the witness was contacted");
        let on_the_wire = String::from_utf8_lossy(&sent);
        assert!(
            !on_the_wire.contains("http_exchange"),
            "no switch must mean no exchange event on the wire"
        );
        assert!(
            !on_the_wire.contains("the contributor's prompt"),
            "the captured prompt must not reach the witness"
        );
        assert!(
            !on_the_wire.contains("inference_receipt"),
            "no bodies must mean no receipt either"
        );
    }

    /// And a submission with no attested call sends exactly what it always
    /// sent. This is what a contributor with capture off gets.
    #[tokio::test]
    async fn a_submission_without_an_attested_call_sends_no_exchange() {
        let signer = test_signer("witness");
        let server = local_witness(Answers {
            witness: Some(signed_answer(&signer, &envelope_bytes())),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        witness_contribution(&transport, &witness, raw_with_secret(), None, &granted())
            .await
            .expect("an unattested submission still succeeds");

        let sent = server
            .witness_bodies()
            .into_iter()
            .next()
            .expect("the witness was contacted");
        assert!(
            !String::from_utf8_lossy(&sent).contains("http_exchange"),
            "no attested call must mean no exchange event on the wire"
        );
    }

    /// The witness is required to strip the bodies before certifying. This
    /// client cannot make it do that, but it is the last party that can tell
    /// when it did not -- and an artifact still carrying a raw prompt would
    /// otherwise be submitted, certificate and all.
    #[tokio::test]
    async fn an_artifact_that_still_carries_the_bodies_is_refused() {
        let signer = test_signer("witness");
        let (call, _dir) = attestable_call();

        // An artifact that came back with the request body still in it. The
        // certificate covers it perfectly, so every other check passes.
        let leaked = serde_json::to_vec(&serde_json::json!({
            "schema_version": "test",
            "events": [{
                "event_type": "http_exchange",
                "structured_payload": { "request": { "body": call.request_body() } },
            }],
        }))
        .expect("serializes");
        // `signed_answer` always returns the standard artifact as its body,
        // so the leaked bytes are substituted here -- otherwise the digest
        // check fires first and this test would pass for the wrong reason.
        let server = local_witness(Answers {
            witness: Some({
                let (certificate, signature, _) = signed_answer(&signer, &leaked);
                (certificate, signature, leaked)
            }),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        let err = witness_contribution(
            &transport,
            &witness,
            raw_with_secret(),
            Some(AttestedInference {
                call: &call,
                receipt: None,
            }),
            &granted(),
        )
        .await
        .expect_err("an artifact still carrying the raw bodies must be refused");
        assert_eq!(err, WitnessTrustError::WitnessBodyNotStripped);
        assert_eq!(err.refusal_label(), "witness_body_not_stripped");
    }

    /// The same check, over the response body, which comes back as event
    /// content rather than as a payload field.
    #[tokio::test]
    async fn an_artifact_that_still_carries_the_response_body_is_refused() {
        let signer = test_signer("witness");
        let (call, _dir) = attestable_call();

        let leaked = serde_json::to_vec(&serde_json::json!({
            "schema_version": "test",
            "events": [{ "redacted_content": call.response_body() }],
        }))
        .expect("serializes");
        // `signed_answer` always returns the standard artifact as its body,
        // so the leaked bytes are substituted here -- otherwise the digest
        // check fires first and this test would pass for the wrong reason.
        let server = local_witness(Answers {
            witness: Some({
                let (certificate, signature, _) = signed_answer(&signer, &leaked);
                (certificate, signature, leaked)
            }),
            ..Answers::default()
        })
        .await;
        let transport = transport_for(&server.base, permissive());
        let witness =
            crate::witness::verify::verified_witness_for_test(&server.base, &address_of(&signer));

        let err = witness_contribution(
            &transport,
            &witness,
            raw_with_secret(),
            Some(AttestedInference {
                call: &call,
                receipt: None,
            }),
            &granted(),
        )
        .await
        .expect_err("a response body that came back must be refused too");
        assert_eq!(err, WitnessTrustError::WitnessBodyNotStripped);
    }
    #[tokio::test]
    async fn redirects_never_forward_attestation_or_sensitive_witness_posts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let target_hits = Arc::new(AtomicUsize::new(0));
        let hits = target_hits.clone();
        let target_app = Router::new().fallback(move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        });
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/delegated", target.local_addr().unwrap());
        let target_task = tokio::spawn(async move {
            axum::serve(target, target_app).await.unwrap();
        });
        let origin_hits = Arc::new(AtomicUsize::new(0));
        let hits = origin_hits.clone();
        let origin_app = Router::new().fallback(move |request: Request| {
            let destination = target_url.clone();
            let hits = hits.clone();
            async move {
                let method = request.method().clone();
                let body = axum::body::to_bytes(request.into_body(), usize::MAX)
                    .await
                    .unwrap();
                if method == axum::http::Method::POST {
                    assert_eq!(body.as_ref(), b"private-test-transcript");
                }
                hits.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, destination)],
                )
            }
        });
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_url = format!("http://{}", origin.local_addr().unwrap());
        let origin_task = tokio::spawn(async move {
            axum::serve(origin, origin_app).await.unwrap();
        });
        let transport = transport_for(&origin_url, permissive());
        assert_eq!(
            transport
                .attestation(&WitnessNonce::fresh().unwrap())
                .await
                .unwrap_err(),
            WitnessTrustError::WitnessAttestationUnavailable
        );
        let verified = crate::witness::verify::verified_witness_for_test(
            &origin_url,
            "0x1111111111111111111111111111111111111111",
        );
        for admission in [false, true] {
            let transport =
                transport_for(&origin_url, permissive()).with_admission_evidence(admission);
            assert_eq!(
                transport
                    .witness(&verified, b"private-test-transcript")
                    .await
                    .err(),
                Some(WitnessTrustError::WitnessResponseMalformed)
            );
        }
        assert_eq!(origin_hits.load(Ordering::SeqCst), 3);
        assert_eq!(target_hits.load(Ordering::SeqCst), 0);
        origin_task.abort();
        target_task.abort();
    }
}
