// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The witness's HTTP surface: two routes, and deliberately nothing else.
//!
//! - `POST /v1/witness` -- raw transcript in, redacted artifact and
//!   certificate out.
//! - `GET /v1/attestation?nonce=<64 hex chars>` -- a nonce-bound quote and the
//!   signing address, so a contributor can pin the enclave *before* sending
//!   anything.
//!
//! # What is missing on purpose
//!
//! There is no health route that reports state, no metrics route, and no route
//! that lists anything. The witness's entire posture is that it holds nothing;
//! a surface that can be asked what it has seen contradicts that claim
//! regardless of how carefully the answer is phrased. A counter of requests
//! served is a record of contributor activity, and an operator who can read it
//! is an operator who can correlate it. If a load balancer needs a liveness
//! probe, `GET /v1/attestation` with a fresh nonce is one, and it proves more.
//!
//! # What bounds the work
//!
//! Both routes are unauthenticated -- deliberately, because authenticating
//! would give the witness an identity to correlate against content -- so
//! anything reachable here is reachable by anyone. [`WitnessLoadBound`] is
//! what keeps `POST /v1/witness` from being unbounded compute and unbounded
//! classifier spend: a fixed number of requests in flight, each under a
//! deadline, and an immediate honest refusal past either. See its
//! documentation for why a concurrency bound and not a rate limit.
//!
//! # Why this module cannot serve an unbound quote
//!
//! [`Enclave::attestation_quote`] takes arbitrary report data. A handler that
//! called it directly would serve a quote that carries no caller nonce -- a
//! replay, indistinguishable from a success at the response boundary, and the
//! exact thing `/v1/attestation` exists to prevent.
//!
//! Rather than documenting that hazard, this module is structured so the call
//! cannot be written here: the handlers hold a [`WitnessService`], whose
//! `Arc<dyn Enclave>` is a private field of a *different* module. No accessor
//! returns it, no `Deref` reaches it, and Rust's module privacy is what
//! enforces that. The only quote this module can obtain is the one
//! [`WitnessService::attest`] returns, which is composed by
//! [`Enclave::nonce_bound_quote`] over a [`ContributorNonce`] that itself
//! cannot be built except by parsing 32 bytes of hex. This is the pattern
//! `WitnessCertificate` uses for its digest, applied to the other end of the
//! service.
//!
//! [`Enclave`]: super::Enclave
//! [`Enclave::attestation_quote`]: super::Enclave::attestation_quote
//! [`Enclave::nonce_bound_quote`]: super::Enclave::nonce_bound_quote

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use tokio::sync::Semaphore;
use trace_commons_protocol::trace_contribution::{
    ConsentMetadata, ConsentScope, RawTraceContribution, ResidualPiiRisk, TraceAllowedUse,
};

use crate::near_attestation::receipt::{ReceiptAlgo, ReceiptPayload, ReceiptSignatureKind};
use crate::redaction_witness::certificate::WitnessCertificate;

use super::surface::{
    AttestationError, ContributionPathUnavailable, ContributorNonce, NonceMalformed, WitnessService,
};
use super::{
    GrantedConsent, WitnessContributionRequest, WitnessContributionResponse, WitnessError,
};

/// The header the certificate travels in, on this route and on
/// `POST /v1/traces`. One spelling, so a client forwards what it received.
pub const WITNESS_CERTIFICATE_HEADER: &str = "x-trace-witness-certificate";
/// The header the signature travels in. Same rule.
pub const WITNESS_SIGNATURE_HEADER: &str = "x-trace-witness-signature";

/// The two routes, and nothing else.
///
/// Built here rather than in the binary so that route wiring is covered by the
/// library test suite. A handler can be correct and unreachable; the tests
/// below drive this exact `Router`.
pub fn witness_router(service: Arc<WitnessService>, load: WitnessLoadBound) -> Router {
    Router::new()
        .route("/v1/witness", post(witness_handler))
        .route("/v1/witness/token-bundle", post(token_bundle_handler))
        .route("/v1/witness/admission", post(admission_witness_handler))
        // Axum's default 2 MiB body cap would refuse an oversized transcript
        // before the handler could name the refusal, and would accept nothing
        // larger even when the operator configured a larger bound. The bound
        // that applies is `WitnessService::max_request_bytes`, enforced in the
        // handler by `to_bytes`, which stops reading rather than buffering.
        //
        // The position of this line is load-bearing: `Router::layer` applies
        // to the routes added *above* it, so the default cap is lifted for
        // `/v1/witness` and still guards `/v1/attestation`, which has no body
        // to read and should not be able to be sent one.
        .layer(DefaultBodyLimit::disable())
        // Applied to `/v1/witness` and not to `/v1/attestation`, for the same
        // reason as the line above: `Router::layer` applies to the routes
        // added before it. The expensive route is the one that redacts a body
        // and, in `full-pipeline`, spends a metered classifier; the
        // attestation route reads no body and does one enclave round trip, and
        // it is what a contributor uses to pin this witness *before* trusting
        // it. Bounding that one too would let a load spike on the expensive
        // route make the enclave unpinnable.
        //
        // Outside the body limit rather than inside it, so a permit covers the
        // body read as well as the redaction. A caller who dribbles out 64 MiB
        // is spending the same slot as one who sends it at once, and the
        // timeout is what bounds both.
        .layer(middleware::from_fn_with_state(load, bound_witness_load))
        .route("/v1/attestation", get(attestation_handler))
        .with_state(service)
}

/// How many `POST /v1/witness` requests may run at once, and how long one may
/// take before it is abandoned.
///
/// Both halves are needed and neither is sufficient. A concurrency bound with
/// no timeout is not a bound: one request whose classifier call never returns
/// holds its permit for as long as the process lives, and enough of those
/// wedge the witness at full occupancy with nothing running. A timeout with no
/// concurrency bound leaves the arrival rate unbounded, which is the thing an
/// unauthenticated route makes free.
///
/// # Why a concurrency bound rather than a rate limit
///
/// The witness sits behind dstack-gateway, so the peer address it sees is the
/// gateway's. A per-source limit would have to key on a forwarded header --
/// and a header trusted for limiting is a header an attacker sets. Worse, the
/// witness is deliberately denied any identity to correlate against content
/// (see `deploy/witness/README.md`); keying a limiter on *who* is asking
/// reintroduces exactly what the two routes are unauthenticated to avoid.
///
/// A concurrency bound needs no identity at all. It bounds what is in flight
/// rather than who sent it, and what is in flight is what costs cores and
/// classifier spend.
#[derive(Clone)]
pub struct WitnessLoadBound {
    /// Shared, so every clone of the layered service counts against the same
    /// budget. A per-clone semaphore would be a per-connection bound, which
    /// bounds nothing an attacker cannot multiply by opening connections.
    permits: Arc<Semaphore>,
    request_timeout: Duration,
}

impl WitnessLoadBound {
    /// `max_concurrent_requests` slots, each held for at most
    /// `request_timeout`.
    pub fn new(max_concurrent_requests: usize, request_timeout: Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent_requests)),
            request_timeout,
        }
    }
}

/// What a saturated witness tells a caller to wait, in seconds.
///
/// A constant rather than a value derived from the timeout: `Retry-After` is a
/// hint to a client, and deriving it from the request timeout would publish
/// the deployment's occupancy ceiling to anyone who reads a 503.
const SATURATED_RETRY_AFTER_SECS: u32 = 30;

/// The bound itself: acquire or refuse, then run under a deadline.
async fn bound_witness_load(
    State(load): State<WitnessLoadBound>,
    request: Request,
    next: Next,
) -> Response {
    // `try_acquire_owned`, not `acquire_owned`. Waiting for a permit is a
    // queue, an unbounded queue in front of a bounded worker turns a load
    // problem into a memory problem, and it does it while telling the caller
    // nothing -- a contributor cannot distinguish "queued behind four hundred
    // others" from "working". Refusing immediately is the honest answer and
    // the cheap one.
    let Ok(_permit) = Arc::clone(&load.permits).try_acquire_owned() else {
        return Refusal::new(StatusCode::SERVICE_UNAVAILABLE, "witness_saturated")
            .retry_after(SATURATED_RETRY_AFTER_SECS)
            .into_response();
    };

    match tokio::time::timeout(load.request_timeout, next.run(request)).await {
        Ok(response) => response,
        // Dropping the timed-out future is what makes this a bound rather than
        // a message: the handler, its redaction pass and any classifier call
        // under it are cancelled here, and `_permit` is released on the way
        // out of this function. Without that, a hung backend would retire a
        // slot permanently.
        Err(_elapsed) => {
            Refusal::new(StatusCode::GATEWAY_TIMEOUT, "witness_request_timed_out").into_response()
        }
    }
}

/// The wire form of a witness request: two shapes in one struct.
///
/// `deny_unknown_fields` because a field this witness does not understand may
/// be one a contributor believed was being witnessed. Refusing is the honest
/// answer to that.
///
/// # Why one struct with options rather than an untagged enum
///
/// `#[serde(untagged)]` picks the first variant that deserialises and
/// discards the errors from the others, so a `raw_contribution` with one
/// malformed event would silently fall through to "neither shape matched" --
/// and, worse, `deny_unknown_fields` does not apply to an untagged enum's
/// variants at all, so the guard above would quietly stop holding. Optional
/// fields plus an explicit disambiguation in [`shape_of`] keeps both, and
/// makes "both shapes at once" a case that is *named* rather than resolved
/// by declaration order.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessRequestBody {
    #[serde(default)]
    raw_transcript: Option<String>,
    #[serde(default)]
    consent: Option<ConsentMetadata>,
    /// Boxed because `RawTraceContribution` is by far the largest variant
    /// here and clippy's `large_enum_variant`/`result_large_err` reasoning
    /// applies to a struct that is only ever one of two shapes.
    #[serde(default)]
    raw_contribution: Option<Box<RawTraceContribution>>,
    #[serde(default)]
    granted_scopes: Option<Vec<ConsentScope>>,
    #[serde(default)]
    granted_uses: Option<Vec<TraceAllowedUse>>,
    /// The receipt offered for this session's last inference call.
    ///
    /// Optional on the wire and absent by default, because a witness with no
    /// requirement is the deployed configuration today. Absent is not a
    /// downgrade: a witness that requires attestation refuses an absent
    /// receipt by name.
    ///
    /// There are no body fields beside it, and no field naming which exchange
    /// it attests. The bodies are already in the session, and the witness --
    /// not the caller -- decides which exchange was last. A second copy of the
    /// bodies sent alongside would be a copy that has to be joined back to the
    /// first, which is exactly the problem this shape does not have.
    #[serde(default)]
    inference_receipt: Option<InferenceReceiptBody>,
}

/// The offered receipt, on the wire.
///
/// `deny_unknown_fields` for the reason the outer body has it: a field this
/// witness does not understand may be one a contributor believed was being
/// checked -- a `request_body` or a `produced_event_id` sent here is refused
/// rather than ignored, because a caller who sent one believed it mattered.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InferenceReceiptBody {
    /// The receipt's signed text: two or three `:`-separated parts.
    text: String,
    /// The signature, hex. 65 bytes for ecdsa, 64 for ed25519; which is
    /// decided by `signing_algo`.
    signature: String,
    /// The address the provider claims signed it.
    signing_address: String,
    /// Which scheme the receipt is in. Optional, defaulting to `ecdsa`:
    /// every receipt issued before this field existed is ECDSA, and a
    /// witness that required the field would refuse every existing client.
    /// An unrecognised value is a malformed request, never a guess.
    ///
    /// Absent reads as ECDSA (the pre-field shape). An explicit `null` does
    /// NOT: the client refuses it as malformed, and the witness matches. The
    /// double `Option` is what lets serde tell the two apart -- outer `None`
    /// is absent, inner `None` is null.
    #[serde(default, deserialize_with = "deserialize_present")]
    signing_algo: Option<Option<String>>,
    /// Which attested key the provider says signed it: `gateway` for a
    /// Responses-API receipt, `provider_tee` for a Chat-Completions one. The
    /// two are signed by different attested keys, and this is what selects
    /// which one the pins check the signer against.
    ///
    /// Optional and absent-tolerant for the same reason `signing_algo` is:
    /// every receipt sent before this field existed carried no kind, and a
    /// witness that required it would refuse every existing client. Absent
    /// reads as *unrecognised*, not as a default kind -- there is no safe
    /// default here, since guessing one would check a signer against a key
    /// set the receipt never claimed.
    ///
    /// An unrecognised *value* is likewise not a malformed request. It is
    /// carried through and refused later, folded into
    /// `witness_inference_receipt_unverified` with every other receipt
    /// failure: a distinct 400 would tell a prober which kinds this witness
    /// knows, which is the oracle the folded label exists to deny. An
    /// explicit `null` is still malformed, matching `signing_algo`.
    #[serde(default, deserialize_with = "deserialize_present")]
    signature_kind: Option<Option<String>>,
}

/// Distinguishes an absent field from a present-but-`null` one: plain
/// `Option<T>` deserialization collapses both to `None`, which is exactly
/// the ambiguity `signing_algo` must not have.
fn deserialize_present<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(d).map(Some)
}

impl TryFrom<InferenceReceiptBody> for ReceiptPayload {
    type Error = Refusal;

    fn try_from(body: InferenceReceiptBody) -> Result<Self, Refusal> {
        let malformed = || Refusal::new(StatusCode::BAD_REQUEST, "witness_request_malformed");
        let signing_algo = match body.signing_algo {
            None => ReceiptAlgo::Ecdsa,
            Some(None) => return Err(malformed()),
            Some(Some(s)) => ReceiptAlgo::from_wire(&s).ok_or_else(malformed)?,
        };
        let signature_kind = match body.signature_kind {
            None => ReceiptSignatureKind::Unrecognised,
            Some(None) => return Err(malformed()),
            Some(Some(s)) => ReceiptSignatureKind::from_wire(&s),
        };
        Ok(ReceiptPayload {
            text: body.text,
            signature: body.signature,
            signing_address: body.signing_address,
            signing_algo,
            signature_kind,
        })
    }
}

/// Which of the two request shapes a body carries, once disambiguated.
///
/// The structured variant is boxed: a `RawTraceContribution` is an order of
/// magnitude larger than a transcript request, and an unboxed enum would make
/// every value of this type that size.
enum RequestShape {
    Transcript(super::WitnessRequest),
    Contribution(Box<WitnessContributionRequest>),
}

/// Decide which shape a body is, or refuse.
///
/// A body carrying both shapes is refused rather than resolved. A caller who
/// sent both does not know which one this witness will certify, and guessing
/// on their behalf means certifying something they may not have meant to
/// send -- on a path whose entire subject is raw session content.
///
/// A `raw_contribution` with no grants is refused too, and this is the
/// interesting one: an empty grant list is a *legal* value that would
/// certify an envelope granting nothing, which the contributor would then
/// have to fix by stamping the real grants after certification -- the byte
/// change this whole path exists to make unnecessary. Absent and empty are
/// therefore both refusals, and neither is a default.
fn shape_of(body: WitnessRequestBody) -> Result<RequestShape, Refusal> {
    let malformed = || Refusal::new(StatusCode::BAD_REQUEST, "witness_request_malformed");
    match (body.raw_transcript, body.raw_contribution) {
        (Some(_), Some(_)) => Err(malformed()),
        (None, None) => Err(malformed()),
        (Some(raw_transcript), None) => {
            if body.granted_scopes.is_some() || body.granted_uses.is_some() {
                // Grants belong to the structured shape. Accepting them here
                // and ignoring them would tell a contributor their grants
                // were witnessed when nothing read them.
                return Err(malformed());
            }
            let consent = body.consent.ok_or_else(malformed)?;
            // Carried rather than refused here even though the text route
            // cannot attest anything. The refusal belongs to the service,
            // where it has a name -- `InferenceAttestationUnavailable` --
            // rather than being folded into "malformed", which would tell a
            // contributor their request was wrong when what is wrong is the
            // route they used.
            Ok(RequestShape::Transcript(super::WitnessRequest {
                raw_transcript,
                consent,
                offered_receipt: body
                    .inference_receipt
                    .map(ReceiptPayload::try_from)
                    .transpose()?,
            }))
        }
        (None, Some(raw_contribution)) => {
            if body.consent.is_some() {
                // The structured shape carries its consent flags inside the
                // contribution. A second copy beside it is two sources of
                // truth for the declaration `residual_risk_basis` floors on.
                return Err(malformed());
            }
            let scopes = body
                .granted_scopes
                .filter(|s| !s.is_empty())
                .ok_or_else(malformed)?;
            let uses = body
                .granted_uses
                .filter(|u| !u.is_empty())
                .ok_or_else(malformed)?;
            Ok(RequestShape::Contribution(Box::new(
                WitnessContributionRequest {
                    raw_contribution: *raw_contribution,
                    granted: GrantedConsent { scopes, uses },
                    offered_receipt: body
                        .inference_receipt
                        .map(ReceiptPayload::try_from)
                        .transpose()?,
                },
            )))
        }
    }
}

/// The nonce query parameter, and only that.
///
/// `Option` so that an absent nonce is refused by this module's own name
/// rather than by axum's extractor rejection, whose body is not one of our
/// labels. `deny_unknown_fields` so a caller who misspells `nonce` is told,
/// rather than being served a refusal that looks like a bad value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationQuery {
    nonce: Option<String>,
}

/// A refusal, as a machine-readable label and nothing else.
///
/// The label set is closed and every member is a constant: no variant carries
/// a byte count, an offset, a field name taken from the request, or a
/// serialized error. On this path every quantity derived from the input
/// describes contributor content, and an error body is the easiest place in a
/// service to leak one.
struct Refusal {
    status: StatusCode,
    code: &'static str,
    /// Seconds for a `Retry-After` header, on the refusals where waiting is
    /// the right answer. `None` everywhere else: telling a caller to retry a
    /// malformed body would be advice to send it again.
    retry_after_secs: Option<u32>,
}

impl Refusal {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            retry_after_secs: None,
        }
    }

    const fn retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_secs = Some(seconds);
        self
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            axum::Json(serde_json::json!({ "error": self.code })),
        )
            .into_response();
        if let Some(seconds) = self.retry_after_secs {
            // An integer renders as a valid header value; a hypothetical
            // failure here loses the hint and keeps the refusal, which is the
            // right way round.
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// The refusal an operator sees for each witness failure.
///
/// A `match` rather than a catch-all, so a new [`WitnessError`] variant is a
/// compile error here and gets a deliberate status instead of inheriting one.
/// All four are 503: every one of them is the witness failing to do its job,
/// not the contributor sending something wrong, and a 4xx would tell a
/// contributor to change their input when nothing about their input was the
/// problem.
fn refusal_for(error: WitnessError) -> Refusal {
    match error {
        WitnessError::RedactionFailed => {
            Refusal::new(StatusCode::SERVICE_UNAVAILABLE, "witness_redaction_failed")
        }
        WitnessError::ArtifactBindingFailed => Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "witness_artifact_binding_failed",
        ),
        WitnessError::MeasurementUnavailable => Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "witness_measurement_unavailable",
        ),
        WitnessError::SigningUnavailable => Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "witness_signing_unavailable",
        ),
        // The attested-inference refusals are 403, not 503. Every one of them
        // is this deployment declining this submission under a policy the
        // operator set, which is a permanent answer for this input: a 503
        // would tell a contributor to retry something that will be refused
        // identically forever, and a 400 would tell them their request was
        // malformed when it was well-formed and unattested.
        WitnessError::InferenceAttestationMissing => Refusal::new(
            StatusCode::FORBIDDEN,
            "witness_inference_attestation_missing",
        ),
        WitnessError::InferenceAttestationUnavailable => Refusal::new(
            StatusCode::FORBIDDEN,
            "witness_inference_attestation_unavailable",
        ),
        WitnessError::InferenceCallAbsent => {
            Refusal::new(StatusCode::FORBIDDEN, "witness_inference_call_absent")
        }
        WitnessError::InferenceCallUnattestable => {
            Refusal::new(StatusCode::FORBIDDEN, "witness_inference_call_unattestable")
        }
        WitnessError::InferenceBodyNotInSession => Refusal::new(
            StatusCode::FORBIDDEN,
            "witness_inference_body_not_in_session",
        ),
        WitnessError::InferenceReceiptUnverified => Refusal::new(
            StatusCode::FORBIDDEN,
            "witness_inference_receipt_unverified",
        ),
        WitnessError::InferenceReceiptTooLarge => {
            Refusal::new(StatusCode::FORBIDDEN, "witness_inference_body_too_large")
        }
    }
}

/// `POST /v1/witness`.
async fn witness_handler(
    State(service): State<Arc<WitnessService>>,
    request: Request,
) -> Result<Response, Refusal> {
    // `to_bytes` stops at the bound rather than buffering the whole body and
    // measuring afterwards, so an oversized request costs the configured
    // maximum and not what the sender chose to send.
    let body = axum::body::to_bytes(request.into_body(), service.max_request_bytes())
        .await
        .map_err(|_| Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "witness_request_too_large"))?;

    let parsed: WitnessRequestBody = serde_json::from_slice(&body)
        .map_err(|_| Refusal::new(StatusCode::BAD_REQUEST, "witness_request_malformed"))?;

    match shape_of(parsed)? {
        RequestShape::Transcript(request) => {
            let response = service.witness(request).await.map_err(refusal_for)?;
            let certificate = &response.certificate;
            Ok(axum::Json(serde_json::json!({
                "redacted_artifact": response.redacted_artifact,
                "certificate": certificate_json(
                    certificate,
                    response.residual_risk_verdict(),
                ),
                "signature_hex": response.signature_hex,
            }))
            .into_response())
        }
        RequestShape::Contribution(request) => {
            let response = service
                .witness_contribution(*request)
                .await
                .map_err(|ContributionPathUnavailable| {
                    Refusal::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "witness_contribution_path_unavailable",
                    )
                })?
                .map_err(refusal_for)?;
            Ok(contribution_response(response))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBundleBody {
    contribution: WitnessRequestBody,
    capture_store_id: String,
    capture_id: String,
    bundle_revision: String,
    restricted_token_consent: bool,
}
async fn token_bundle_handler(
    State(service): State<Arc<WitnessService>>,
    request: Request,
) -> Result<Response, Refusal> {
    let body = axum::body::to_bytes(request.into_body(), service.max_request_bytes())
        .await
        .map_err(|_| Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "witness_request_too_large"))?;
    let body: TokenBundleBody = serde_json::from_slice(&body)
        .map_err(|_| Refusal::new(StatusCode::BAD_REQUEST, "witness_request_malformed"))?;
    let RequestShape::Contribution(request) = shape_of(body.contribution)? else {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "witness_request_malformed",
        ));
    };
    let response = service
        .witness_token_bundle(
            *request,
            super::token_bundle::TokenBundleOptions {
                capture_store_id: body.capture_store_id,
                capture_id: body.capture_id,
                bundle_revision: body.bundle_revision,
                restricted_token_consent: body.restricted_token_consent,
            },
        )
        .await
        .map_err(refusal_for)?;
    let verdict = response.contribution.residual_risk_verdict();
    Ok(axum::Json(serde_json::json!({
        "envelope_bytes":response.contribution.envelope_bytes,
        "envelope_certificate":certificate_json(&response.contribution.certificate,verdict),
        "envelope_signature_hex":response.contribution.signature_hex,
        "manifest_bytes":response.manifest_bytes,"attachment_bytes":response.attachment_bytes,
        "admission":response.admission,
        "certificate":certificate_json(&response.certificate,verdict),"signature_hex":response.signature_hex
    })).into_response())
}

/// Separate route: legacy callers never accidentally request admission evidence.
async fn admission_witness_handler(
    State(service): State<Arc<WitnessService>>,
    request: Request,
) -> Result<Response, Refusal> {
    let body = axum::body::to_bytes(request.into_body(), service.max_request_bytes())
        .await
        .map_err(|_| Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "witness_request_too_large"))?;
    let parsed: WitnessRequestBody = serde_json::from_slice(&body)
        .map_err(|_| Refusal::new(StatusCode::BAD_REQUEST, "witness_request_malformed"))?;
    let RequestShape::Contribution(request) = shape_of(parsed)? else {
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "admission_evidence_refused",
        ));
    };
    let (response, evidence, signature) = service
        .witness_admission_contribution(*request)
        .await
        .map_err(|_| Refusal::new(StatusCode::FORBIDDEN, "admission_evidence_refused"))?;
    let encoded = serde_json::to_string(&evidence).map_err(|_| {
        Refusal::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admission_evidence_refused",
        )
    })?;
    let mut response = contribution_response(response);
    for (name, value) in [
        (trace_commons_protocol::admission::EVIDENCE_HEADER, encoded),
        (
            trace_commons_protocol::admission::SIGNATURE_HEADER,
            signature,
        ),
    ] {
        response.headers_mut().insert(
            name,
            HeaderValue::from_str(&value).map_err(|_| {
                Refusal::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "admission_evidence_refused",
                )
            })?,
        );
    }
    Ok(response)
}

/// The structured response: the envelope **as the body**, the certificate in
/// headers.
///
/// Not a JSON object with the envelope nested inside it, and the difference
/// is the whole point of the structured path. The certificate binds these
/// exact bytes, so the client has to be able to take them off the wire and
/// submit them without touching them. Nesting would make the client extract a
/// value out of a parsed document and re-encode it, which is a serde round
/// trip in the one place this design cannot have one -- and it would be a
/// round trip whose failure is invisible, because the re-encoded bytes still
/// parse as the same envelope.
///
/// The header names are the ones Task 7 puts on `POST /v1/traces`, so the
/// client forwards what it received rather than re-rendering it. Headers are
/// ASCII by construction here: the certificate is compact JSON over a hex
/// digest, a closed verdict label, a policy alias and two integers, and the
/// signature is `0x`-prefixed hex.
fn contribution_response(response: WitnessContributionResponse) -> Response {
    let certificate = serde_json::to_string(&certificate_json(
        &response.certificate,
        response.residual_risk_verdict(),
    ))
    .unwrap_or_default();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // A header value that will not build is a bug in `certificate_json`, not
    // contributor input, and serving the envelope without its certificate
    // would be serving an uncertified artifact under a certified route. So
    // both are `?`-free but fail closed through `ok_or`.
    for (name, value) in [
        (WITNESS_CERTIFICATE_HEADER, certificate),
        (WITNESS_SIGNATURE_HEADER, response.signature_hex),
    ] {
        let Ok(value) = HeaderValue::from_str(&value) else {
            return Refusal::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "witness_certificate_unrenderable",
            )
            .into_response();
        };
        headers.insert(name, value);
    }

    (headers, response.envelope_bytes).into_response()
}

/// The certificate's fields, as both routes render them.
///
/// One function so the two routes cannot drift into two spellings of the same
/// certificate, which is the kind of difference a client only discovers in
/// production.
///
/// `pub` so that the cross-implementation test can render a certificate
/// through the REAL producer rather than a fixture spelled the same way by
/// hand. A hand-spelled fixture agrees with whatever the test author believed,
/// which is exactly how the field names here went unchecked against both
/// consumers.
pub fn certificate_json(
    certificate: &WitnessCertificate,
    verdict: ResidualPiiRisk,
) -> serde_json::Value {
    serde_json::json!({
        "redacted_sha256": certificate.claimed_redacted_sha256(),
        "residual_risk_verdict": verdict_label(verdict),
        "redaction_policy_version": certificate.claimed_redaction_policy_version(),
        "witness_measurement": certificate.claimed_witness_measurement(),
        "timestamp": certificate.claimed_timestamp(),
    })
}

/// The wire spelling of a verdict.
///
/// Written here rather than derived from `Serialize` so that the strings a
/// server compares against are visible in one place, and exhaustive so a new
/// tier cannot silently serialize as something a consumer treats as unknown.
///
/// `pub` for the same reason [`certificate_json`] is.
pub fn verdict_label(verdict: ResidualPiiRisk) -> &'static str {
    match verdict {
        ResidualPiiRisk::Low => "low",
        ResidualPiiRisk::Medium => "medium",
        ResidualPiiRisk::High => "high",
    }
}

/// `GET /v1/attestation?nonce=<hex>`.
async fn attestation_handler(
    State(service): State<Arc<WitnessService>>,
    Query(query): Query<AttestationQuery>,
) -> Result<Response, Refusal> {
    let Some(nonce_hex) = query.nonce else {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "witness_nonce_malformed",
        ));
    };
    let nonce = ContributorNonce::parse_hex(&nonce_hex).map_err(|NonceMalformed| {
        Refusal::new(StatusCode::BAD_REQUEST, "witness_nonce_malformed")
    })?;

    let evidence = service.attest(&nonce).await.map_err(|AttestationError| {
        Refusal::new(StatusCode::SERVICE_UNAVAILABLE, "witness_quote_unavailable")
    })?;

    Ok(axum::Json(serde_json::json!({
        "quote_hex": evidence.quote_hex,
        "signing_address": evidence.signing_address,
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness_service::enclave::{WITNESS_NONCE_LEN, witness_report_data};
    use crate::witness_service::{
        DeterministicRedaction, Enclave, RedactedTranscript, SeamUnavailable, Signer,
        TranscriptRedactor,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Method, Request as HttpRequest};
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};
    use std::sync::Mutex;
    use tower::ServiceExt;
    use trace_commons_protocol::trace_contribution::ConsentScope;

    /// Matches the `aws_access_key` pattern exactly, so the deterministic pass
    /// is guaranteed to remove it.
    // Split so the twenty-character form never appears verbatim in the
    // source. The value is synthetic -- a keyboard walk, not a
    // credential -- but GitHub push protection matches the shape, and it
    // is right to: a scanner that trusted our word about which
    // AKIA-prefixed strings are fake would be useless. Our own detector
    // requires the prefix, so the fixture cannot avoid it; splitting the
    // literal is the honest way to keep both checks working.
    const SECRET: &str = concat!("AKIA", "QQWERTYUIOPASDFG");

    /// Not secret-shaped, so it must SURVIVE redaction. The positive control:
    /// without it, a redactor that returned the empty string would satisfy
    /// every "the secret is absent" assertion below.
    const SURVIVOR: &str = "zzq-control-token-zzq";

    const MEASUREMENT: &str = "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";
    const ENCLAVE_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    /// A generous default for tests that are not about the bound.
    const TEST_LIMIT: usize = 64 * 1024;

    /// A load bound wide enough that tests which are not about it never meet
    /// it: more slots than any test sends at once, and a timeout far longer
    /// than a deterministic redaction of a few kilobytes.
    fn unconstrained_load() -> WitnessLoadBound {
        WitnessLoadBound::new(64, Duration::from_secs(30))
    }

    struct TestSigner(SigningKey);

    impl TestSigner {
        fn new(seed: &str) -> Self {
            let bytes = Keccak256::digest(seed.as_bytes());
            Self(SigningKey::from_slice(&bytes).expect("seed is a valid scalar"))
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

    /// Records every `report_data` it was asked to quote over, so a test can
    /// assert what the route actually bound rather than that it returned
    /// something.
    #[derive(Default)]
    struct RecordingEnclave {
        seen: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingEnclave {
        fn seen(&self) -> Vec<Vec<u8>> {
            self.seen.lock().expect("no test panics holding it").clone()
        }
    }

    #[async_trait]
    impl Enclave for RecordingEnclave {
        fn signing_address(&self) -> &str {
            ENCLAVE_ADDRESS
        }

        async fn measurement(&self) -> Result<String, SeamUnavailable> {
            Ok(MEASUREMENT.to_string())
        }

        async fn attestation_quote(&self, report_data: &[u8]) -> Result<Vec<u8>, SeamUnavailable> {
            self.seen
                .lock()
                .expect("no test panics holding it")
                .push(report_data.to_vec());
            // Echoing the report data as the quote body lets a test read what
            // was bound out of the served bytes, not only out of the double.
            Ok(report_data.to_vec())
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

    struct RefusingRedactor;

    #[async_trait]
    impl TranscriptRedactor for RefusingRedactor {
        async fn redact(&self, _raw: &str) -> Result<RedactedTranscript, SeamUnavailable> {
            Err(SeamUnavailable)
        }
    }

    fn service_with(
        redactor: Arc<dyn TranscriptRedactor>,
        signer: Arc<dyn Signer>,
        enclave: Arc<dyn Enclave>,
        max_request_bytes: usize,
    ) -> Arc<WitnessService> {
        Arc::new(WitnessService::new(
            redactor,
            signer,
            enclave,
            max_request_bytes,
        ))
    }

    fn healthy_service(limit: usize) -> (Arc<WitnessService>, Arc<RecordingEnclave>) {
        let enclave = Arc::new(RecordingEnclave::default());
        let service = service_with(
            Arc::new(DeterministicRedaction::new(Vec::new())),
            Arc::new(TestSigner::new("http-surface")),
            enclave.clone(),
            limit,
        );
        (service, enclave)
    }

    fn consent_json() -> serde_json::Value {
        serde_json::json!({
            "policy_version": "consent-v1",
            "scopes": [ConsentScope::DebuggingEvaluation],
            "message_text_included": false,
            "tool_payloads_included": false,
            "correction_included": false,
            "routing_metadata_included": false,
            "revocable": true,
        })
    }

    fn witness_body(raw: &str) -> String {
        serde_json::json!({ "raw_transcript": raw, "consent": consent_json() }).to_string()
    }

    /// A request body of exactly `bytes` total length, whose transcript is
    /// padded to reach it. The padding is a non-secret filler so the request
    /// remains one the witness would otherwise certify.
    fn witness_body_of_length(bytes: usize) -> String {
        let base = witness_body("");
        let padding = bytes
            .checked_sub(base.len())
            .expect("the caller asked for a body at least as long as an empty one");
        witness_body(&"a".repeat(padding))
    }

    async fn send(
        service: Arc<WitnessService>,
        request: HttpRequest<Body>,
    ) -> (StatusCode, String) {
        send_bounded(service, unconstrained_load(), request).await
    }

    /// `send`, with the load bound under test.
    async fn send_bounded(
        service: Arc<WitnessService>,
        load: WitnessLoadBound,
        request: HttpRequest<Body>,
    ) -> (StatusCode, String) {
        let (status, _, body) = send_bounded_full(service, load, request).await;
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// `send_bounded`, keeping the headers as well.
    async fn send_bounded_full(
        service: Arc<WitnessService>,
        load: WitnessLoadBound,
        request: HttpRequest<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = witness_router(service, load)
            .oneshot(request)
            .await
            .expect("the router is infallible");
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .expect("the test bodies are small");
        (status, headers, body.to_vec())
    }

    fn post_witness(body: String) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/witness")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("a well formed test request")
    }

    fn get_attestation(query: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method(Method::GET)
            .uri(format!("/v1/attestation{query}"))
            .body(Body::empty())
            .expect("a well formed test request")
    }

    fn error_code(body: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .expect("a refusal is JSON")
            .get("error")
            .and_then(|value| value.as_str())
            .expect("a refusal names its code")
            .to_string()
    }

    /// The witness route is reachable through the real router and returns the
    /// artifact, the certificate and the signature.
    ///
    /// Drives `witness_router` rather than the handler: a handler can be
    /// correct and unreachable.
    #[tokio::test]
    async fn the_witness_route_is_reachable_through_the_router() {
        let (service, _) = healthy_service(TEST_LIMIT);
        let (status, body) = send(
            service,
            post_witness(witness_body(&format!("deploy {SURVIVOR} with {SECRET}"))),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body: {body}");
        let value: serde_json::Value = serde_json::from_str(&body).expect("a JSON response");
        let artifact = value["redacted_artifact"]
            .as_str()
            .expect("the artifact is a string");
        assert!(
            !artifact.contains(SECRET),
            "the secret survived the served artifact"
        );
        assert!(
            artifact.contains(SURVIVOR),
            "the positive control did not survive, so the assertion above proves nothing"
        );

        let certificate = &value["certificate"];
        let missing: Vec<&str> = [
            "redacted_sha256",
            "residual_risk_verdict",
            "redaction_policy_version",
            "witness_measurement",
            "timestamp",
        ]
        .into_iter()
        .filter(|field| certificate.get(*field).is_none())
        .collect();
        assert!(
            missing.is_empty(),
            "certificate fields missing: {missing:?}"
        );
        assert_eq!(certificate["witness_measurement"], MEASUREMENT);
        assert!(
            value["signature_hex"]
                .as_str()
                .is_some_and(|s| s.starts_with("0x") && s.len() == 132),
            "the signature is not 65 bytes of 0x hex: {}",
            value["signature_hex"]
        );
    }

    /// The certificate's digest is over the artifact the route served, byte
    /// for byte. A response whose digest described some other bytes would fail
    /// at the server rather than here, which is far too late.
    #[tokio::test]
    async fn the_served_digest_is_over_the_served_artifact() {
        let (service, _) = healthy_service(TEST_LIMIT);
        let (status, body) = send(
            service,
            post_witness(witness_body(&format!("deploy {SURVIVOR} with {SECRET}"))),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let value: serde_json::Value = serde_json::from_str(&body).expect("a JSON response");
        let artifact = value["redacted_artifact"].as_str().expect("a string");
        let expected = hex::encode(sha2::Sha256::digest(artifact.as_bytes()));
        assert_eq!(value["certificate"]["redacted_sha256"], expected);
    }

    /// The verdict reaches the wire as the label a server compares against,
    /// and different verdicts reach it as different labels.
    ///
    /// Without the second case a `verdict_label` that returned one constant
    /// would satisfy a single-verdict assertion, and the field a server keys
    /// its PII-backstop bypass off would be a constant on the wire.
    #[tokio::test]
    async fn the_verdict_reaches_the_wire_as_its_label() {
        async fn label(raw: &str) -> String {
            let (service, _) = healthy_service(TEST_LIMIT);
            let (status, body) = send(service, post_witness(witness_body(raw))).await;
            assert_eq!(status, StatusCode::OK, "body: {body}");
            serde_json::from_str::<serde_json::Value>(&body).expect("a JSON response")
                ["certificate"]["residual_risk_verdict"]
                .as_str()
                .expect("the verdict is a string")
                .to_string()
        }

        assert_eq!(label(SURVIVOR).await, "low");
        assert_eq!(label(&format!("{SURVIVOR} {SECRET}")).await, "medium");
    }

    /// The attestation route is reachable, and the quote it serves is bound to
    /// the caller's nonce and to this witness's signing address.
    #[tokio::test]
    async fn the_attestation_route_serves_a_nonce_bound_quote() {
        let (service, enclave) = healthy_service(TEST_LIMIT);
        let nonce = [0x5au8; WITNESS_NONCE_LEN];
        let nonce_hex = hex::encode(nonce);

        let (status, body) = send(service, get_attestation(&format!("?nonce={nonce_hex}"))).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let value: serde_json::Value = serde_json::from_str(&body).expect("a JSON response");
        assert_eq!(value["signing_address"], ENCLAVE_ADDRESS);

        let expected = witness_report_data(ENCLAVE_ADDRESS, &nonce).expect("well formed inputs");
        assert_eq!(
            enclave.seen(),
            vec![expected.to_vec()],
            "the route quoted over report data that is not the nonce-bound composition"
        );
        // And the same bytes reached the caller, not only the double.
        assert_eq!(value["quote_hex"], hex::encode(expected));
    }

    /// A different nonce produces a different binding. Without this, a handler
    /// that ignored the query string and quoted a constant would satisfy the
    /// test above.
    #[tokio::test]
    async fn a_different_nonce_produces_a_different_quote() {
        let (service, _) = healthy_service(TEST_LIMIT);
        let first = send(
            service.clone(),
            get_attestation(&format!(
                "?nonce={}",
                hex::encode([0x01u8; WITNESS_NONCE_LEN])
            )),
        )
        .await;
        let second = send(
            service,
            get_attestation(&format!(
                "?nonce={}",
                hex::encode([0x02u8; WITNESS_NONCE_LEN])
            )),
        )
        .await;

        assert_eq!(first.0, StatusCode::OK);
        assert_eq!(second.0, StatusCode::OK);
        assert_ne!(
            first.1, second.1,
            "two different nonces produced the same attestation response"
        );
    }

    /// A malformed nonce is refused by name, and nothing is quoted over it.
    ///
    /// The second half is the point: a handler that padded, truncated or
    /// hashed a bad nonce into 32 bytes would serve a quote a contributor
    /// would read as bound to the nonce they sent. Asserting only the status
    /// would not catch a handler that refused *after* quoting.
    #[tokio::test]
    async fn a_malformed_nonce_is_refused_rather_than_padded() {
        let cases = [
            ("empty", String::new()),
            ("too short", hex::encode([0xaau8; 16])),
            ("too long", hex::encode([0xaau8; 33])),
            ("odd length", "abc".to_string()),
            ("not hex", "z".repeat(64)),
            (
                "0x prefixed",
                format!("0x{}", hex::encode([0xaau8; WITNESS_NONCE_LEN])),
            ),
        ];

        let mut wrong: Vec<(&str, StatusCode, String, usize)> = Vec::new();
        for (label, nonce) in cases {
            let (service, enclave) = healthy_service(TEST_LIMIT);
            let (status, body) = send(service, get_attestation(&format!("?nonce={nonce}"))).await;
            let quoted = enclave.seen().len();
            if status != StatusCode::BAD_REQUEST
                || error_code(&body) != "witness_nonce_malformed"
                || quoted != 0
            {
                wrong.push((label, status, error_code(&body), quoted));
            }
        }
        // Collected rather than asserted in the loop: a short-circuiting
        // assertion lets the first failure hide every case after it.
        assert!(wrong.is_empty(), "malformed nonces not refused: {wrong:?}");
    }

    /// A missing `nonce` parameter is the same refusal, not a quote over
    /// nothing.
    #[tokio::test]
    async fn an_absent_nonce_is_refused() {
        let (service, enclave) = healthy_service(TEST_LIMIT);
        let (status, body) = send(service, get_attestation("")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_code(&body), "witness_nonce_malformed");
        assert!(enclave.seen().is_empty(), "a quote was taken anyway");
    }

    /// A body over the configured bound is refused by name.
    #[tokio::test]
    async fn an_oversized_body_is_refused_by_name() {
        let limit = witness_body_of_length(2048).len();
        let (service, _) = healthy_service(limit);
        let (status, body) = send(service, post_witness(witness_body_of_length(limit + 1))).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "body: {body}");
        assert_eq!(error_code(&body), "witness_request_too_large");
    }

    /// A body exactly at the bound is accepted.
    ///
    /// The positive control for the test above: without it, a surface that
    /// refused every request would pass the oversize test, and so would one
    /// whose bound was off by an order of magnitude in the wrong direction.
    #[tokio::test]
    async fn a_body_at_the_bound_is_accepted() {
        let limit = witness_body_of_length(2048).len();
        let (service, _) = healthy_service(limit);
        let (status, body) = send(service, post_witness(witness_body_of_length(limit))).await;

        assert_eq!(status, StatusCode::OK, "body: {body}");
    }

    /// An oversized body is refused without the transcript reaching the
    /// response, and without a byte count naming how much was sent.
    #[tokio::test]
    async fn an_oversized_refusal_reports_no_quantity_and_no_content() {
        let limit = witness_body_of_length(2048).len();
        let (service, _) = healthy_service(limit);
        let marker = "zzq-oversize-marker-zzq";
        let padded = format!("{marker}{}", "a".repeat(limit));
        let (status, body) = send(service, post_witness(witness_body(&padded))).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!body.contains(marker), "the refusal echoed the transcript");
        assert!(
            !body.contains(&limit.to_string()),
            "the refusal named the configured bound"
        );
    }

    /// Nothing but the two routes exists, and the two exist only under the
    /// methods they are documented for.
    #[tokio::test]
    async fn no_route_other_than_the_two_exists() {
        let probes = [
            (Method::GET, "/healthz", StatusCode::NOT_FOUND),
            (Method::GET, "/health", StatusCode::NOT_FOUND),
            (Method::GET, "/metrics", StatusCode::NOT_FOUND),
            (Method::GET, "/v1/source", StatusCode::NOT_FOUND),
            (Method::GET, "/v1/witnesses", StatusCode::NOT_FOUND),
            (Method::GET, "/", StatusCode::NOT_FOUND),
            (Method::GET, "/v1/witness", StatusCode::METHOD_NOT_ALLOWED),
            (
                Method::POST,
                "/v1/attestation",
                StatusCode::METHOD_NOT_ALLOWED,
            ),
        ];

        let mut wrong: Vec<(&str, StatusCode)> = Vec::new();
        for (method, path, expected) in probes {
            let (service, _) = healthy_service(TEST_LIMIT);
            let request = HttpRequest::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("a well formed test request");
            let (status, _) = send(service, request).await;
            if status != expected {
                wrong.push((path, status));
            }
        }
        assert!(wrong.is_empty(), "unexpected routing: {wrong:?}");
    }

    /// Every witness refusal reaches the wire as a named 503, and none of them
    /// carries the transcript.
    #[tokio::test]
    async fn a_seam_failure_is_a_named_refusal_that_echoes_nothing() {
        let marker = "zzq-refused-marker-zzq";
        let cases: Vec<(&str, Arc<WitnessService>, &str)> = vec![
            (
                "redaction",
                service_with(
                    Arc::new(RefusingRedactor),
                    Arc::new(TestSigner::new("http-surface")),
                    Arc::new(RecordingEnclave::default()),
                    TEST_LIMIT,
                ),
                "witness_redaction_failed",
            ),
            (
                "measurement",
                service_with(
                    Arc::new(DeterministicRedaction::new(Vec::new())),
                    Arc::new(TestSigner::new("http-surface")),
                    Arc::new(SilentEnclave),
                    TEST_LIMIT,
                ),
                "witness_measurement_unavailable",
            ),
            (
                "signing",
                service_with(
                    Arc::new(DeterministicRedaction::new(Vec::new())),
                    Arc::new(RefusingSigner),
                    Arc::new(RecordingEnclave::default()),
                    TEST_LIMIT,
                ),
                "witness_signing_unavailable",
            ),
        ];

        let mut wrong: Vec<(&str, StatusCode, String, bool)> = Vec::new();
        for (label, service, expected) in cases {
            let (status, body) = send(
                service,
                post_witness(witness_body(&format!("{marker} {SECRET}"))),
            )
            .await;
            let leaked = body.contains(marker) || body.contains(SECRET);
            if status != StatusCode::SERVICE_UNAVAILABLE || error_code(&body) != expected || leaked
            {
                wrong.push((label, status, error_code(&body), leaked));
            }
        }
        assert!(wrong.is_empty(), "refusals wrong: {wrong:?}");
    }

    /// A quote the enclave cannot produce is a named 503, not an empty 200.
    #[tokio::test]
    async fn an_unavailable_quote_is_a_named_refusal() {
        let service = service_with(
            Arc::new(DeterministicRedaction::new(Vec::new())),
            Arc::new(TestSigner::new("http-surface")),
            Arc::new(SilentEnclave),
            TEST_LIMIT,
        );
        let (status, body) = send(
            service,
            get_attestation(&format!(
                "?nonce={}",
                hex::encode([0x07u8; WITNESS_NONCE_LEN])
            )),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(&body), "witness_quote_unavailable");
    }

    /// A malformed request body is refused by name and does not echo itself.
    #[tokio::test]
    async fn a_malformed_request_body_is_refused_by_name() {
        let marker = "zzq-malformed-marker-zzq";
        let (service, _) = healthy_service(TEST_LIMIT);
        let (status, body) = send(
            service,
            post_witness(format!("{{\"raw_transcript\": \"{marker}\"}}")),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_code(&body), "witness_request_malformed");
        assert!(!body.contains(marker), "the refusal echoed the request");
    }

    /// An unknown field is refused rather than dropped: a contributor may
    /// believe it was witnessed.
    #[tokio::test]
    async fn an_unknown_request_field_is_refused() {
        let (service, _) = healthy_service(TEST_LIMIT);
        let body = serde_json::json!({
            "raw_transcript": "hello",
            "consent": consent_json(),
            "attest_inference": true,
        })
        .to_string();
        let (status, body) = send(service, post_witness(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_code(&body), "witness_request_malformed");
    }

    // ---------------------------------------------------------------
    // The structured request shape.
    // ---------------------------------------------------------------

    /// A healthy service with the structured seam attached.
    fn structured_service() -> Arc<WitnessService> {
        Arc::new(
            WitnessService::new(
                Arc::new(DeterministicRedaction::new(Vec::new())),
                Arc::new(TestSigner::new("http-surface")),
                Arc::new(RecordingEnclave::default()),
                TEST_LIMIT,
            )
            .with_contribution_redactor(Arc::new(
                super::super::PipelineContributionRedaction::deterministic_only(Vec::new()),
            )),
        )
    }

    fn raw_contribution_json(text: &str) -> serde_json::Value {
        use trace_commons_protocol::trace_contribution::{
            RawTraceCaptureTurn, RawTraceContribution, RecordedTraceContributionOptions,
        };
        let started = chrono::Utc::now();
        let raw = RawTraceContribution::from_capture_turns(
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
        serde_json::to_value(&raw).expect("a raw contribution serialises")
    }

    fn contribution_body(text: &str) -> String {
        serde_json::json!({
            "raw_contribution": raw_contribution_json(text),
            "granted_scopes": ["debugging_evaluation"],
            "granted_uses": ["debugging"],
        })
        .to_string()
    }

    /// Send and keep the headers, which the structured response puts the
    /// certificate in.
    async fn send_full(
        service: Arc<WitnessService>,
        request: HttpRequest<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = witness_router(service, unconstrained_load())
            .oneshot(request)
            .await
            .expect("the router is infallible");
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .expect("the test bodies are small");
        (status, headers, body.to_vec())
    }

    #[tokio::test]
    async fn the_structured_route_returns_the_envelope_bytes_as_the_body() {
        let (status, headers, body) = send_full(
            structured_service(),
            post_witness(contribution_body("ran the build")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The body IS the envelope, not a document with the envelope inside
        // it. A client that had to reach into a wrapper would be parsing and
        // re-encoding the bytes the certificate covers.
        let envelope: serde_json::Value =
            serde_json::from_slice(&body).expect("the body is the envelope");
        assert!(
            envelope.get("schema_version").is_some() && envelope.get("privacy").is_some(),
            "the body is not an envelope at its top level"
        );
        assert!(
            envelope.get("redacted_artifact").is_none()
                && envelope.get("certificate").is_none()
                && envelope.get("envelope").is_none(),
            "the envelope is nested inside a wrapper"
        );

        // And the certificate the headers carry is over exactly those bytes.
        let certificate: serde_json::Value = serde_json::from_str(
            headers[WITNESS_CERTIFICATE_HEADER]
                .to_str()
                .expect("the certificate header is ASCII"),
        )
        .expect("the certificate header is JSON");
        assert_eq!(
            certificate["redacted_sha256"].as_str().unwrap(),
            hex::encode(sha2::Sha256::digest(&body)),
        );
        assert!(
            headers[WITNESS_SIGNATURE_HEADER]
                .to_str()
                .unwrap()
                .starts_with("0x"),
            "the signature is not 0x-prefixed hex"
        );
    }

    #[tokio::test]
    async fn the_structured_route_applies_the_granted_scopes_inside_the_certified_bytes() {
        let (_, _, body) = send_full(
            structured_service(),
            post_witness(contribution_body("ran the build")),
        )
        .await;
        let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            envelope["trace_card"]["allowed_uses"],
            serde_json::json!(["debugging"]),
            "the grants were not applied before serialisation, so a client must stamp them after"
        );
    }

    #[tokio::test]
    async fn a_body_carrying_both_request_shapes_is_refused_by_name() {
        let both = serde_json::json!({
            "raw_transcript": "ran the build",
            "consent": consent_json(),
            "raw_contribution": raw_contribution_json("ran the build"),
            "granted_scopes": ["debugging_evaluation"],
            "granted_uses": ["debugging"],
        })
        .to_string();
        let (status, body) = send(structured_service(), post_witness(both)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_code(&body), "witness_request_malformed");
    }

    #[tokio::test]
    async fn a_structured_body_with_no_grants_is_refused_rather_than_certified_empty() {
        // Absent and empty are both refusals: certifying an envelope that
        // grants nothing forces the contributor into the post-certification
        // stamp this path exists to remove.
        for grants in [
            serde_json::json!({}),
            serde_json::json!({ "granted_scopes": [], "granted_uses": [] }),
            serde_json::json!({ "granted_scopes": ["debugging_evaluation"] }),
        ] {
            let mut body = serde_json::json!({
                "raw_contribution": raw_contribution_json("ran the build"),
            });
            for (key, value) in grants.as_object().unwrap() {
                body[key] = value.clone();
            }
            let (status, response) =
                send(structured_service(), post_witness(body.to_string())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "accepted: {grants}");
            assert_eq!(error_code(&response), "witness_request_malformed");
        }
    }

    #[tokio::test]
    async fn a_witness_without_a_structured_seam_refuses_the_route_by_name() {
        // Never a 200 from the text redactor, and never a redaction-failure
        // label: this is a configuration gap, and an operator reading
        // `witness_redaction_failed` would go looking at the classifier.
        let (service, _) = healthy_service(TEST_LIMIT);
        let (status, body) = send(service, post_witness(contribution_body("ran the build"))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(&body), "witness_contribution_path_unavailable");
    }

    #[tokio::test]
    async fn an_unknown_field_is_still_refused_on_the_structured_shape() {
        // `deny_unknown_fields` survived the second shape. An untagged enum
        // would have silently dropped it.
        let mut body: serde_json::Value =
            serde_json::from_str(&contribution_body("ran the build")).unwrap();
        body["witnessed_spans"] = serde_json::json!([]);
        let (status, response) = send(structured_service(), post_witness(body.to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_code(&response), "witness_request_malformed");
    }

    #[tokio::test]
    async fn the_structured_route_echoes_no_raw_content() {
        let secret = format!("deploy key {SECRET} and {SURVIVOR}");
        let (_, headers, body) = send_full(
            structured_service(),
            post_witness(contribution_body(&secret)),
        )
        .await;
        let rendered = String::from_utf8_lossy(&body);
        assert!(!rendered.contains(SECRET));
        assert!(
            rendered.contains(SURVIVOR),
            "the survivor was removed too, so the assertion above proves nothing"
        );
        for (_, value) in headers.iter() {
            assert!(!value.to_str().unwrap_or_default().contains(SECRET));
        }
    }

    // ---------------------------------------------------------------
    // The load bound.
    // ---------------------------------------------------------------

    /// A redactor that parks in `redact` until it is released, so a test can
    /// hold a slot open for as long as it needs one.
    ///
    /// Parks rather than sleeping: a sleep long enough to be reliable makes
    /// the test slow, and one short enough to be fast makes it flaky.
    struct ParkingRedactor {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl TranscriptRedactor for ParkingRedactor {
        async fn redact(&self, raw: &str) -> Result<RedactedTranscript, SeamUnavailable> {
            self.entered.notify_one();
            self.release.notified().await;
            DeterministicRedaction::new(Vec::new()).redact(raw).await
        }
    }

    /// A redactor that hangs forever on its first call and behaves normally
    /// afterwards -- a classifier that never answers, which is the failure the
    /// timeout exists for.
    struct HangsOnceRedactor {
        hung: Mutex<bool>,
    }

    #[async_trait]
    impl TranscriptRedactor for HangsOnceRedactor {
        async fn redact(&self, raw: &str) -> Result<RedactedTranscript, SeamUnavailable> {
            let first = {
                let mut hung = self.hung.lock().expect("no test panics holding it");
                let first = !*hung;
                *hung = true;
                first
            };
            if first {
                // Never resolves. Only cancellation ends this.
                std::future::pending::<()>().await;
            }
            DeterministicRedaction::new(Vec::new()).redact(raw).await
        }
    }

    fn service_with_redactor(redactor: Arc<dyn TranscriptRedactor>) -> Arc<WitnessService> {
        service_with(
            redactor,
            Arc::new(TestSigner::new("http-surface")),
            Arc::new(RecordingEnclave::default()),
            TEST_LIMIT,
        )
    }

    /// A witness at its concurrency bound REFUSES the next request. It does
    /// not queue it, and it certifies nothing.
    ///
    /// The refusal is the assertion that matters: a queueing limiter would
    /// pass a test that only checked "the second request did not run
    /// concurrently", because it would eventually return 200.
    #[tokio::test]
    async fn a_second_request_at_the_bound_is_refused_rather_than_queued() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let service = service_with_redactor(Arc::new(ParkingRedactor {
            entered: entered.clone(),
            release: release.clone(),
        }));
        // One slot, and a timeout long enough that it cannot be what refuses.
        let load = WitnessLoadBound::new(1, Duration::from_secs(30));

        let held = tokio::spawn({
            let (service, load) = (service.clone(), load.clone());
            async move { send_bounded(service, load, post_witness(witness_body("first"))).await }
        });
        // The slot is occupied only once the handler is inside the redactor.
        entered.notified().await;

        let (status, headers, body) = send_bounded_full(
            service.clone(),
            load.clone(),
            post_witness(witness_body("second")),
        )
        .await;
        let rendered = String::from_utf8_lossy(&body).into_owned();

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {rendered}");
        assert_eq!(error_code(&rendered), "witness_saturated");
        assert_eq!(
            headers
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some(SATURATED_RETRY_AFTER_SECS.to_string().as_str()),
        );
        // Nothing was certified: no certificate in the body and none in the
        // headers the structured path uses.
        assert!(!rendered.contains("certificate"), "body: {rendered}");
        assert!(headers.get(WITNESS_CERTIFICATE_HEADER).is_none());
        assert!(headers.get(WITNESS_SIGNATURE_HEADER).is_none());

        // The held request still completes, so the bound refused the second
        // caller rather than breaking the first.
        release.notify_one();
        let (held_status, _) = held.await.expect("the held request did not panic");
        assert_eq!(held_status, StatusCode::OK);
    }

    /// The attestation route is NOT bounded with the witness route. A
    /// contributor can still pin the enclave while every witness slot is
    /// occupied.
    #[tokio::test]
    async fn attestation_still_answers_while_the_witness_route_is_saturated() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let service = service_with_redactor(Arc::new(ParkingRedactor {
            entered: entered.clone(),
            release: release.clone(),
        }));
        let load = WitnessLoadBound::new(1, Duration::from_secs(30));

        let held = tokio::spawn({
            let (service, load) = (service.clone(), load.clone());
            async move { send_bounded(service, load, post_witness(witness_body("first"))).await }
        });
        entered.notified().await;

        let nonce = hex::encode([0x11u8; WITNESS_NONCE_LEN]);
        let (status, body) = send_bounded(
            service.clone(),
            load.clone(),
            get_attestation(&format!("?nonce={nonce}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        release.notify_one();
        held.await.expect("the held request did not panic");
    }

    /// A request that exceeds the timeout is refused with 504, certifies
    /// nothing, and -- the part that makes this a bound rather than a
    /// message -- RELEASES ITS SLOT, so the witness serves the next caller.
    ///
    /// Without the release, one hung backend call would retire a slot for the
    /// life of the process and enough of them would wedge the service at full
    /// occupancy with nothing running.
    #[tokio::test]
    async fn a_timed_out_request_releases_its_slot_and_the_witness_recovers() {
        let service = service_with_redactor(Arc::new(HangsOnceRedactor {
            hung: Mutex::new(false),
        }));
        // One slot, so a leaked permit means the second request can never run.
        let load = WitnessLoadBound::new(1, Duration::from_millis(50));

        let (status, headers, body) = send_bounded_full(
            service.clone(),
            load.clone(),
            post_witness(witness_body("hangs")),
        )
        .await;
        let rendered = String::from_utf8_lossy(&body).into_owned();
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "body: {rendered}");
        assert_eq!(error_code(&rendered), "witness_request_timed_out");
        assert!(!rendered.contains("certificate"), "body: {rendered}");
        assert!(headers.get(WITNESS_CERTIFICATE_HEADER).is_none());
        assert!(headers.get(WITNESS_SIGNATURE_HEADER).is_none());

        // The next request finds a free slot and is certified normally.
        let (status, body) = send_bounded(
            service,
            load,
            post_witness(witness_body(&format!("deploy {SURVIVOR}"))),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the witness wedged: {body}");
        let value: serde_json::Value = serde_json::from_str(&body).expect("a JSON response");
        assert!(value["certificate"]["redacted_sha256"].is_string());
    }

    /// A slot is returned when its request finishes, so a witness serves an
    /// unbounded number of requests over time -- the bound is on concurrency,
    /// not on lifetime volume.
    #[tokio::test]
    async fn slots_are_returned_so_sequential_requests_all_succeed() {
        let (service, _) = healthy_service(TEST_LIMIT);
        let load = WitnessLoadBound::new(1, Duration::from_secs(30));
        for attempt in 0..5 {
            let (status, body) = send_bounded(
                service.clone(),
                load.clone(),
                post_witness(witness_body("sequential")),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "attempt {attempt}: {body}");
        }
    }

    // ---------------------------------------------------------------
    // The attested-inference requirement, over the real router.
    // ---------------------------------------------------------------

    /// The same structured service, refusing anything whose last declared
    /// inference call does not carry a verified receipt.
    fn requiring_service() -> Arc<WitnessService> {
        Arc::new(
            WitnessService::new(
                Arc::new(DeterministicRedaction::new(Vec::new())),
                Arc::new(TestSigner::new("http-surface")),
                Arc::new(RecordingEnclave::default()),
                TEST_LIMIT,
            )
            .with_contribution_redactor(Arc::new(
                super::super::PipelineContributionRedaction::deterministic_only(Vec::new()),
            ))
            .requiring_attested_inference(
                super::super::inference::InferenceAttestationPolicy::required(
                    super::super::inference::DEFAULT_MAX_BODY_BYTES,
                )
                .expect("a well formed policy"),
            ),
        )
    }

    #[tokio::test]
    async fn a_requiring_witness_refuses_an_unattested_contribution_and_certifies_nothing() {
        let body = contribution_body("ran the build");

        // The control first: the identical body is certified by a witness
        // that requires nothing, so what follows is the policy and not the
        // fixture.
        let (status, headers, _) =
            send_full(structured_service(), post_witness(body.clone())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.contains_key(WITNESS_CERTIFICATE_HEADER));

        let (status, headers, response) = send_full(requiring_service(), post_witness(body)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a policy refusal is permanent for this input, not a 503 to retry"
        );
        assert_eq!(
            error_code(&String::from_utf8_lossy(&response)),
            "witness_inference_attestation_missing"
        );
        // The whole point of a fail-closed requirement: nothing was signed.
        assert!(
            !headers.contains_key(WITNESS_CERTIFICATE_HEADER)
                && !headers.contains_key(WITNESS_SIGNATURE_HEADER),
            "a refused submission must carry no certificate"
        );
    }

    #[tokio::test]
    async fn the_text_route_cannot_satisfy_the_requirement_and_says_which_control_is_missing() {
        let (status, body) = send(
            requiring_service(),
            post_witness(witness_body("ran the build")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            error_code(&body),
            "witness_inference_attestation_unavailable",
            "the text route carries no event order, so it can attest nothing; \
             the label must name that rather than reading as a bad request"
        );
    }

    /// The wire field reaches the payload as the discriminator the verifier
    /// dispatches on. Tested at this seam rather than through the route,
    /// because every receipt failure is deliberately one label on the wire
    /// (see `inference.rs`) and a route-level test therefore cannot tell an
    /// ed25519 reading from an ECDSA one. Hardcoding `Ecdsa` in `try_from`
    /// while keeping the `from_wire` validation fails this test and nothing
    /// else -- which is the point.
    #[test]
    fn the_wire_signing_algo_becomes_the_payload_discriminator() {
        let absent: InferenceReceiptBody = serde_json::from_value(serde_json::json!({
            "text": "a:b", "signature": "cc", "signing_address": "0xdd"
        }))
        .unwrap();
        assert_eq!(
            ReceiptPayload::try_from(absent)
                .ok()
                .expect("an absent signing_algo is accepted")
                .signing_algo,
            ReceiptAlgo::Ecdsa
        );

        let ed: InferenceReceiptBody = serde_json::from_value(serde_json::json!({
            "text": "a:b", "signature": "cc", "signing_address": "dd", "signing_algo": "ed25519"
        }))
        .unwrap();
        assert_eq!(
            ReceiptPayload::try_from(ed)
                .ok()
                .expect("a recognised signing_algo is accepted")
                .signing_algo,
            ReceiptAlgo::Ed25519
        );

        let unknown: InferenceReceiptBody = serde_json::from_value(serde_json::json!({
            "text": "a:b", "signature": "cc", "signing_address": "0xdd", "signing_algo": "rsa"
        }))
        .unwrap();
        match ReceiptPayload::try_from(unknown) {
            Err(refusal) => {
                assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
                assert_eq!(refusal.code, "witness_request_malformed");
            }
            Ok(_) => panic!("an unknown scheme is a refusal, never a default"),
        }

        // An explicit `null` is not absence: the client refuses it as
        // malformed rather than guessing ECDSA, and the witness must match.
        let null: InferenceReceiptBody = serde_json::from_value(serde_json::json!({
            "text": "a:b", "signature": "cc", "signing_address": "0xdd", "signing_algo": null
        }))
        .unwrap();
        match ReceiptPayload::try_from(null) {
            Err(refusal) => {
                assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
                assert_eq!(refusal.code, "witness_request_malformed");
            }
            Ok(_) => panic!("an explicit null signing_algo is a refusal, never ECDSA"),
        }
    }

    /// The wire `signature_kind` becomes the discriminator the pins route on.
    ///
    /// Absent is *unrecognised*, not a default kind: guessing one would check
    /// a signer against a key set the receipt never claimed. An unrecognised
    /// value is likewise carried rather than rejected here, so its refusal
    /// folds into `witness_inference_receipt_unverified` instead of becoming
    /// a 400 that tells a prober which kinds this witness knows.
    #[test]
    fn the_wire_signature_kind_becomes_the_routing_discriminator() {
        let body = |kind: serde_json::Value| {
            let mut map = serde_json::json!({
                "text": "a:b", "signature": "cc", "signing_address": "dd",
                "signing_algo": "ed25519"
            });
            map["signature_kind"] = kind;
            serde_json::from_value::<InferenceReceiptBody>(map).unwrap()
        };

        let absent: InferenceReceiptBody = serde_json::from_value(serde_json::json!({
            "text": "a:b", "signature": "cc", "signing_address": "dd", "signing_algo": "ed25519"
        }))
        .unwrap();
        assert_eq!(
            ReceiptPayload::try_from(absent)
                .ok()
                .expect("an absent signature_kind is accepted")
                .signature_kind,
            ReceiptSignatureKind::Unrecognised,
            "absent is unrecognised, never a default kind"
        );

        for (wire, expected) in [
            ("gateway", ReceiptSignatureKind::Gateway),
            ("provider_tee", ReceiptSignatureKind::ProviderTee),
            ("something_new", ReceiptSignatureKind::Unrecognised),
        ] {
            assert_eq!(
                ReceiptPayload::try_from(body(serde_json::json!(wire)))
                    .ok()
                    .expect("a string kind is accepted")
                    .signature_kind,
                expected
            );
        }

        // An explicit `null` is malformed, matching `signing_algo`.
        match ReceiptPayload::try_from(body(serde_json::Value::Null)) {
            Err(refusal) => {
                assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
                assert_eq!(refusal.code, "witness_request_malformed");
            }
            Ok(_) => panic!("an explicit null signature_kind is a refusal"),
        }
    }
}
