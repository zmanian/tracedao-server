//! Client for the server-side trace-withdrawal endpoint.
//!
//! `POST /v1/account/traces/{submission_id}/withdraw`, per
//! `docs/superpowers/specs/2026-08-08-trace-withdrawal-design.md`. It is
//! authenticated by an **account session**, not the device key that
//! authenticates every other call this crate makes -- withdrawal is meant to
//! survive losing the device that submitted a trace.
//!
//! The session is acquired by `crate::account_auth`: the human completes the
//! ordinary browser login flow and the browser hands this machine a
//! short-lived bearer token on a loopback redirect. `daemon::withdraw` reads
//! that token and fails closed with `account-session-required` when there
//! isn't a live one, so this function is only ever called with a session the
//! contributor actually established.
//!
//! Never logs or returns a path, a token, or trace content: errors here are
//! fixed labels, matching every other boundary in this crate.

use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use trace_commons_operator_client::{Client, Error as OcError};

use crate::config::allowlist_for;

/// Which of the three withdrawal tiers the server applied. See the design
/// doc's table: a trace never in the commons is simply deleted; a trace
/// already in the commons is deleted and excluded from future exports; a
/// trace already inside a published export or benchmark cannot be recalled
/// from copies already distributed, and the UI must say so rather than
/// implying otherwise.
/// The wire names are the SERVER's, not this crate's. They were written on
/// both sides in parallel against the design doc and did not agree: this
/// client expected `in_commons`/`distributed` while the server sends
/// `commons_not_distributed`/`commons_distributed`, so the two
/// already-accepted tiers -- exactly the ones whose message a contributor most
/// needs to be true -- failed to deserialize. The server owns this format;
/// the explicit renames below pin it, and `wire_names_match_the_server`
/// fails if either side moves again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionReach {
    /// Never entered the commons. Nothing was distributed.
    #[serde(rename = "not_distributed")]
    NotDistributed,
    /// `accepted`, not yet used in any published export or benchmark.
    #[serde(rename = "commons_not_distributed")]
    InCommons,
    /// `accepted` and already included in a published export or benchmark.
    /// Copies already distributed cannot be recalled.
    #[serde(rename = "commons_distributed")]
    Distributed,
}

#[derive(Debug, Deserialize)]
struct WithdrawResponseBody {
    #[serde(default)]
    token_deletion_state: Option<TokenDeletionState>,
    distribution_reach: DistributionReach,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenDeletionState {
    Pending,
    Held,
    Completed,
    #[serde(other)]
    Unknown,
}
impl TokenDeletionState {
    pub fn note(self) -> &'static str {
        match self {
            Self::Pending => "Token data is blocked from use. Stored copies are awaiting deletion.",
            Self::Held => {
                "Token data is blocked from use. A retention hold prevents deletion of stored copies."
            }
            Self::Completed => {
                "Token data is blocked from use. Server-managed token copies have been deleted; backup retention and previously downloaded copies are separate."
            }
            Self::Unknown => "Token data deletion status is unavailable.",
        }
    }
}

/// The outcome the caller needs: which tier applied, so the UI can tell the
/// contributor the truth instead of a generic "done".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawOutcome {
    pub token_deletion_state: Option<TokenDeletionState>,
    pub distribution_reach: DistributionReach,
}

/// Errors this client reports. Never carries a response body, a URL, or a
/// token -- only a fixed label, matching every other boundary in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawError {
    /// The account session was rejected: expired, revoked, or never valid.
    SessionInvalid,
    /// The server has no record of this submission for this account. Per
    /// the design doc's testing section, the server deliberately answers
    /// this the same way whether the trace belongs to someone else or does
    /// not exist at all, so as not to disclose which.
    NotFound,
    /// Anything else: transport failure, malformed response, or an
    /// unrecognized server label.
    Unavailable,
}

/// Call the server's withdrawal endpoint for one submission.
///
/// `ingest_url` / `allowed_hosts` are the same values the daemon already
/// loads from `ContributorConfig` for every other ingest call.
/// `account_session_token` is the one input this function cannot obtain
/// itself -- see the module doc.
///
/// Idempotent on the server side (withdrawing twice is a success), so this
/// makes no attempt at its own retry-suppression; a caller may call it again
/// on failure without needing to check whether the first attempt actually
/// landed.
pub async fn call_withdraw(
    ingest_url: &str,
    allowed_hosts: Option<&str>,
    account_session_token: &str,
    submission_id: Uuid,
) -> Result<WithdrawOutcome, WithdrawError> {
    let client = Client::builder(ingest_url, "TRACE_COMMONS_CONTRIBUTOR_UNUSED_BEARER_ENV")
        .bearer_token(account_session_token)
        .host_allowlist(allowlist_for(allowed_hosts))
        .build()
        .map_err(|_| WithdrawError::Unavailable)?;
    let path = format!("/v1/account/traces/{submission_id}/withdraw");
    match client
        .call_json::<(), WithdrawResponseBody>(Method::POST, &path, &[], None)
        .await
    {
        Ok(body) => Ok(WithdrawOutcome {
            token_deletion_state: body.token_deletion_state,
            distribution_reach: body.distribution_reach,
        }),
        Err(e) => Err(classify(&e)),
    }
}

/// Tier-aware confirmation copy, verbatim where the design doc gives it.
///
/// `docs/superpowers/specs/2026-08-08-trace-withdrawal-design.md`'s "UI"
/// section writes out the exact wording for two of the three tiers: a
/// quarantined trace, and an accepted trace already included in a published
/// export. Both are reproduced here unchanged -- particularly the sentence
/// admitting that already-distributed copies cannot be recalled, which must
/// never be softened or paraphrased by whichever shell (this crate's own
/// CLI, or a native menu-bar/window application built from the IPC
/// contract) ends up presenting it. Every such shell should call this
/// rather than hold its own copy of the wording, so that sentence cannot
/// drift or go missing in one of them.
///
/// The design doc does not write out literal copy for the middle tier
/// (`InCommons`: accepted, but not yet in any published export) or
/// distinguish `submitted` from `quarantined` within `NotDistributed` --
/// only "for a quarantined trace" is given, which is also the dominant real
/// case this feature exists for (the 48 pilot traces stuck in quarantine).
/// `NotDistributed` always uses that wording. `InCommons` uses the middle
/// paragraph shared by both of the doc's two given examples, without either
/// tier's distinguishing sentence, rather than inventing wording the design
/// doc does not contain.
///
/// `export_published_on` is only consulted for the `Distributed` tier, and
/// should be a short human date string (the design doc's example: `"12
/// June"`); pass `None` if that date is not available and the line will
/// read "an earlier date" rather than fabricating one.
pub fn confirmation_prompt(reach: DistributionReach, export_published_on: Option<&str>) -> String {
    match reach {
        DistributionReach::NotDistributed => "Withdraw this trace?\n\n\
It is waiting for privacy review and has not entered the commons. Its \
content will be deleted. No one but a reviewer has seen it.\n\n\
Credit already recorded stays."
            .to_string(),
        DistributionReach::InCommons => "Withdraw this trace?\n\n\
Its content will be deleted and it will be excluded from future exports and \
training sets.\n\n\
Credit already recorded stays."
            .to_string(),
        DistributionReach::Distributed => {
            let published = export_published_on.unwrap_or("an earlier date");
            format!(
                "Withdraw this trace?\n\n\
Its content will be deleted and it will be excluded from future exports and \
training sets.\n\n\
It was included in an export published on {published}. Copies already \
distributed cannot be recalled. We cannot undo that and will not pretend \
otherwise.\n\n\
Credit already recorded stays."
            )
        }
    }
}

fn classify(e: &OcError) -> WithdrawError {
    match e {
        OcError::ServerLabel { status, .. } | OcError::HttpFailure { status, .. } => {
            match status.as_u16() {
                401 | 403 => WithdrawError::SessionInvalid,
                404 => WithdrawError::NotFound,
                _ => WithdrawError::Unavailable,
            }
        }
        _ => WithdrawError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    /// The server's constants, copied verbatim from
    /// `trace-commons-ingest.rs` (TRACE_WITHDRAWAL_REACH_*). If either side
    /// renames a tier, this fails rather than a contributor being told the
    /// wrong thing about whether their trace can still be recalled.
    #[test]
    fn wire_names_match_the_server() {
        use super::DistributionReach::*;
        for (variant, wire) in [
            (NotDistributed, "\"not_distributed\""),
            (InCommons, "\"commons_not_distributed\""),
            (Distributed, "\"commons_distributed\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), wire);
            assert_eq!(
                serde_json::from_str::<super::DistributionReach>(wire).unwrap(),
                variant
            );
        }
    }

    use super::*;
    use axum::{Json, Router, extract::Path, http::HeaderMap, routing::post};
    use std::sync::{Arc, Mutex};

    async fn spawn(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    fn stub_withdraw(received_auth: Arc<Mutex<Vec<String>>>, reach: &'static str) -> Router {
        Router::new().route(
            "/v1/account/traces/{submission_id}/withdraw",
            post(
                move |headers: HeaderMap, Path(_submission_id): Path<String>| {
                    let received_auth = received_auth.clone();
                    async move {
                        if let Some(auth) = headers.get("authorization") {
                            received_auth
                                .lock()
                                .unwrap()
                                .push(auth.to_str().unwrap_or("").to_string());
                        }
                        Json(serde_json::json!({ "distribution_reach": reach }))
                    }
                },
            ),
        )
    }

    fn stub_withdraw_status(status: axum::http::StatusCode, label: &'static str) -> Router {
        Router::new().route(
            "/v1/account/traces/{submission_id}/withdraw",
            post(move |Path(_submission_id): Path<String>| async move {
                (status, Json(serde_json::json!({ "error": label })))
            }),
        )
    }

    #[tokio::test]
    async fn reports_the_tier_the_server_returned() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let base = spawn(stub_withdraw(received.clone(), "not_distributed")).await;
        let outcome = call_withdraw(&base, None, "acct-session-token", Uuid::nil())
            .await
            .unwrap();
        assert_eq!(
            outcome.distribution_reach,
            DistributionReach::NotDistributed
        );
        assert_eq!(received.lock().unwrap()[0], "Bearer acct-session-token");
    }

    #[tokio::test]
    async fn reports_the_in_commons_tier() {
        let base = spawn(stub_withdraw(
            Arc::new(Mutex::new(Vec::new())),
            "commons_not_distributed",
        ))
        .await;
        let outcome = call_withdraw(&base, None, "acct-session-token", Uuid::nil())
            .await
            .unwrap();
        assert_eq!(outcome.distribution_reach, DistributionReach::InCommons);
    }

    #[tokio::test]
    async fn reports_the_distributed_tier_and_its_cannot_recall_meaning() {
        let base = spawn(stub_withdraw(
            Arc::new(Mutex::new(Vec::new())),
            "commons_distributed",
        ))
        .await;
        let outcome = call_withdraw(&base, None, "acct-session-token", Uuid::nil())
            .await
            .unwrap();
        assert_eq!(outcome.distribution_reach, DistributionReach::Distributed);
    }

    #[tokio::test]
    async fn a_401_is_reported_as_session_invalid_not_a_generic_failure() {
        let base = spawn(stub_withdraw_status(
            axum::http::StatusCode::UNAUTHORIZED,
            "SessionExpired",
        ))
        .await;
        let err = call_withdraw(&base, None, "stale-token", Uuid::nil())
            .await
            .unwrap_err();
        assert_eq!(err, WithdrawError::SessionInvalid);
    }

    #[tokio::test]
    async fn a_404_is_reported_as_not_found() {
        // The design doc requires the server to answer this the same way for
        // "not yours" and "does not exist" so existence is never disclosed;
        // this client just needs to pass that answer through distinctly from
        // a generic failure.
        let base = spawn(stub_withdraw_status(
            axum::http::StatusCode::NOT_FOUND,
            "SubmissionNotFound",
        ))
        .await;
        let err = call_withdraw(&base, None, "acct-session-token", Uuid::nil())
            .await
            .unwrap_err();
        assert_eq!(err, WithdrawError::NotFound);
    }

    #[tokio::test]
    async fn a_server_error_is_reported_as_unavailable() {
        let base = spawn(stub_withdraw_status(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Boom",
        ))
        .await;
        let err = call_withdraw(&base, None, "acct-session-token", Uuid::nil())
            .await
            .unwrap_err();
        assert_eq!(err, WithdrawError::Unavailable);
    }

    #[test]
    fn not_distributed_copy_matches_the_design_doc_verbatim() {
        let copy = confirmation_prompt(DistributionReach::NotDistributed, None);
        assert!(copy.contains("Withdraw this trace?"));
        assert!(copy.contains(
            "It is waiting for privacy review and has not entered the commons. Its \
             content will be deleted. No one but a reviewer has seen it."
        ));
        assert!(copy.contains("Credit already recorded stays."));
        // Must never claim exclusion from exports for a trace that was
        // never in the commons in the first place.
        assert!(!copy.contains("excluded from future exports"));
    }

    #[test]
    fn distributed_copy_matches_the_design_doc_verbatim_and_names_the_export_date() {
        let copy = confirmation_prompt(DistributionReach::Distributed, Some("12 June"));
        assert!(copy.contains("It was included in an export published on 12 June."));
        assert!(copy.contains(
            "Copies already distributed cannot be recalled. We cannot undo that and \
             will not pretend otherwise."
        ));
        assert!(copy.contains("Credit already recorded stays."));
    }

    #[test]
    fn distributed_copy_never_claims_a_recall_is_possible() {
        // The one sentence in this whole feature that must never be
        // softened or dropped by an over-eager rewrite.
        for date in [Some("1 January"), None] {
            let copy = confirmation_prompt(DistributionReach::Distributed, date);
            assert!(copy.contains("cannot be recalled"));
            assert!(!copy.to_lowercase().contains("we will remove all copies"));
        }
    }

    #[test]
    fn distributed_copy_without_a_date_says_so_rather_than_fabricating_one() {
        let copy = confirmation_prompt(DistributionReach::Distributed, None);
        assert!(copy.contains("an earlier date"));
    }

    #[test]
    fn in_commons_copy_does_not_claim_review_is_pending_or_a_recall_happened() {
        // The one tier the design doc gives no literal wording for -- must
        // not borrow either neighboring tier's tier-specific sentence.
        let copy = confirmation_prompt(DistributionReach::InCommons, None);
        assert!(copy.contains("excluded from future exports and training sets."));
        assert!(!copy.contains("waiting for privacy review"));
        assert!(!copy.contains("cannot be recalled"));
    }
}
