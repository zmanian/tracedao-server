//! IPC handlers for `withdraw` and `withdraw_bulk`.
//!
//! Both call `crate::withdraw::call_withdraw` -- the server's
//! `POST /v1/account/traces/{submission_id}/withdraw` -- for real, update the
//! local history cache (`daemon::history::mark_withdrawn`) with what the
//! server reported, and hand the caller the tier that applied so a UI can
//! tell the contributor the truth rather than a generic success. See
//! `docs/superpowers/specs/2026-08-08-trace-withdrawal-design.md`.
//!
//! # The account session
//!
//! That endpoint is authenticated by an **account session**, not the device
//! key this daemon holds -- withdrawal is meant to survive losing the device
//! that submitted a trace, and a stolen device key must not be worth the
//! ability to delete someone's contribution history.
//!
//! The session comes from `crate::account_auth`: the human completes the
//! ordinary browser login flow, and the browser hands this machine a
//! short-lived bearer token on a loopback redirect. [`account_session_token`]
//! reads that token, and treats an absent, unparseable, or expired one as
//! absent -- so both handlers below fail closed with
//! [`ERR_ACCOUNT_SESSION_REQUIRED`] rather than making a call that would 401.
//! That is a distinct, documented error rather than a generic failure so a
//! calling shell can route the contributor to `account login`.

use chrono::Utc;
use uuid::Uuid;

use super::history::{self, HistoryCache, STATUS_ACCEPTED, STATUS_QUARANTINED, STATUS_SUBMITTED};
use super::ipc::{DaemonShared, ERR_BAD_PARAMS, ERR_UNAVAILABLE, Request, Response};

/// Distinct from every other error this daemon returns: a caller that sees
/// this knows exactly what is missing (an account session) rather than
/// having to guess from a generic `unavailable`.
pub const ERR_ACCOUNT_SESSION_REQUIRED: &str = "account-session-required";

/// The account-session token this daemon presents to the withdrawal endpoint.
///
/// `None` whenever the token is missing, unreadable, or expired (or about to
/// be): the caller must then report [`ERR_ACCOUNT_SESSION_REQUIRED`] rather
/// than fall back to the device key, which is deliberately not accepted for
/// withdrawal.
fn account_session_token(shared: &DaemonShared) -> anyhow::Result<Option<String>> {
    super::run_blocking(|| crate::account_auth::try_load_token(&shared.store))
}

fn parse_submission_id(params: &serde_json::Value) -> Result<Uuid, &'static str> {
    params
        .get("submission_id")
        .and_then(|v| v.as_str())
        .ok_or("submission_id-required")?
        .parse()
        .map_err(|_| "submission_id-invalid")
}

/// Statuses `withdraw_bulk` accepts: the same three the server reports on
/// submission-status read-back (see `daemon::history`'s `STATUS_*`
/// constants). `withdrawn` itself and the `other` bucket are deliberately
/// not accepted -- withdrawing what is already withdrawn is a no-op with
/// nothing to bulk, and `other` covers statuses this client has no stable
/// name for.
fn valid_bulk_status(s: &str) -> bool {
    matches!(s, STATUS_SUBMITTED | STATUS_QUARANTINED | STATUS_ACCEPTED)
}

/// `distribution_reach` as a wire string, straight from
/// `crate::withdraw::DistributionReach`'s own `Serialize` impl, so this
/// module cannot hand-maintain a second copy of the tier names that drifts
/// from the client's.
fn reach_label(reach: crate::withdraw::DistributionReach) -> serde_json::Value {
    serde_json::to_value(reach).unwrap_or(serde_json::Value::Null)
}

/// Withdraw one submission. See the module doc for why this always answers
/// [`ERR_ACCOUNT_SESSION_REQUIRED`] today.
pub(super) async fn handle_withdraw(shared: &DaemonShared, req: &Request) -> Response {
    let submission_id = match parse_submission_id(&req.params) {
        Ok(id) => id,
        Err(m) => return Response::err(req.id, ERR_BAD_PARAMS, m),
    };
    let token = match account_session_token(shared) {
        Ok(Some(token)) => token,
        Ok(None) => return Response::err(req.id, ERR_UNAVAILABLE, ERR_ACCOUNT_SESSION_REQUIRED),
        Err(_) => {
            return Response::err(
                req.id,
                ERR_UNAVAILABLE,
                "commons_credential_storage_unavailable",
            );
        }
    };
    let Ok(Some(cfg)) = shared.store.load_config() else {
        return Response::err(req.id, ERR_UNAVAILABLE, "not-logged-in");
    };
    match crate::withdraw::call_withdraw(
        &cfg.ingest_url,
        cfg.allowed_hosts.as_deref(),
        &token,
        submission_id,
    )
    .await
    {
        Ok(outcome) => {
            if let Ok(mut records) = HistoryCache::load(&shared.store) {
                if history::mark_withdrawn(&mut records, submission_id, Utc::now()) {
                    let _ = HistoryCache::save(&shared.store, &records);
                }
            }
            Response::ok(
                req.id,
                serde_json::json!({
                    "withdrawn": true,
                    "distribution_reach": reach_label(outcome.distribution_reach),
                    "token_deletion_note":outcome.token_deletion_state.map(|s| s.note()),
                }),
            )
        }
        Err(_) => Response::err(req.id, ERR_UNAVAILABLE, "withdraw-failed"),
    }
}

/// Withdraw every submission currently at `status` in the local history
/// cache. See the module doc for why this always answers
/// [`ERR_ACCOUNT_SESSION_REQUIRED`] today.
///
/// A per-submission failure does not stop the batch: the response's
/// `failed` count is how a caller learns some did not go through, and the
/// contributor can retry with a plain `withdraw` on the ones that matter to
/// them (this method reports counts, not which ids failed, since submission
/// ids are not otherwise exposed over this socket beyond what `list_history`
/// already shows).
pub(super) async fn handle_withdraw_bulk(shared: &DaemonShared, req: &Request) -> Response {
    let status = match req.params.get("status").and_then(|v| v.as_str()) {
        Some(s) if valid_bulk_status(s) => s.to_string(),
        Some(_) => return Response::err(req.id, ERR_BAD_PARAMS, "status-invalid"),
        None => return Response::err(req.id, ERR_BAD_PARAMS, "status-required"),
    };
    let token = match account_session_token(shared) {
        Ok(Some(token)) => token,
        Ok(None) => return Response::err(req.id, ERR_UNAVAILABLE, ERR_ACCOUNT_SESSION_REQUIRED),
        Err(_) => {
            return Response::err(
                req.id,
                ERR_UNAVAILABLE,
                "commons_credential_storage_unavailable",
            );
        }
    };
    let Ok(Some(cfg)) = shared.store.load_config() else {
        return Response::err(req.id, ERR_UNAVAILABLE, "not-logged-in");
    };
    let mut records = match HistoryCache::load(&shared.store) {
        Ok(r) => r,
        Err(_) => return Response::err(req.id, ERR_UNAVAILABLE, "history-read-failed"),
    };
    let targets: Vec<Uuid> = records
        .iter()
        .filter(|r| r.status == status)
        .map(|r| r.submission_id)
        .collect();

    let mut withdrawn = 0u32;
    let mut failed = 0u32;
    let now = Utc::now();
    for id in targets {
        match crate::withdraw::call_withdraw(
            &cfg.ingest_url,
            cfg.allowed_hosts.as_deref(),
            &token,
            id,
        )
        .await
        {
            Ok(_) => {
                if history::mark_withdrawn(&mut records, id, now) {
                    withdrawn += 1;
                }
            }
            Err(_) => failed += 1,
        }
    }
    if withdrawn > 0 {
        let _ = HistoryCache::save(&shared.store, &records);
    }
    Response::ok(
        req.id,
        serde_json::json!({ "withdrawn": withdrawn, "failed": failed }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> DaemonShared {
        let (_d, store) = crate::config::tests_support::temp_store();
        std::mem::forget(_d);
        DaemonShared::load(store).unwrap()
    }

    fn req(method: &str, params: serde_json::Value) -> Request {
        Request {
            id: 1,
            method: method.to_string(),
            params,
        }
    }

    #[tokio::test]
    async fn withdraw_without_a_submission_id_is_a_param_error() {
        let s = shared();
        let r = handle_withdraw(&s, &req("withdraw", serde_json::json!({}))).await;
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[tokio::test]
    async fn withdraw_with_a_malformed_submission_id_is_a_param_error() {
        let s = shared();
        let r = handle_withdraw(
            &s,
            &req(
                "withdraw",
                serde_json::json!({"submission_id": "not-a-uuid"}),
            ),
        )
        .await;
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[tokio::test]
    async fn withdraw_with_a_valid_submission_id_reports_account_session_required() {
        // The daemon holds a device key, not an account session (see this
        // module's doc), so a structurally valid request still cannot be
        // authenticated today -- and must say so distinctly rather than
        // failing generically.
        let s = shared();
        let r = handle_withdraw(
            &s,
            &req(
                "withdraw",
                serde_json::json!({"submission_id": Uuid::new_v4().to_string()}),
            ),
        )
        .await;
        let err = r.error.unwrap();
        assert_eq!(err.code, ERR_UNAVAILABLE);
        assert_eq!(err.message, ERR_ACCOUNT_SESSION_REQUIRED);
    }

    #[tokio::test]
    async fn withdraw_bulk_without_a_status_is_a_param_error() {
        let s = shared();
        let r = handle_withdraw_bulk(&s, &req("withdraw_bulk", serde_json::json!({}))).await;
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[tokio::test]
    async fn withdraw_bulk_rejects_an_unrecognized_status() {
        let s = shared();
        let r = handle_withdraw_bulk(
            &s,
            &req(
                "withdraw_bulk",
                serde_json::json!({"status": "not-a-status"}),
            ),
        )
        .await;
        assert_eq!(r.error.unwrap().code, ERR_BAD_PARAMS);
    }

    #[tokio::test]
    async fn withdraw_bulk_accepts_quarantined_and_reports_account_session_required() {
        let s = shared();
        let r = handle_withdraw_bulk(
            &s,
            &req(
                "withdraw_bulk",
                serde_json::json!({"status": "quarantined"}),
            ),
        )
        .await;
        let err = r.error.unwrap();
        assert_eq!(err.code, ERR_UNAVAILABLE);
        assert_eq!(err.message, ERR_ACCOUNT_SESSION_REQUIRED);
    }

    #[test]
    fn account_session_token_is_none_until_the_contributor_signs_in() {
        // Fail closed: a store with no account session offers no token, so
        // withdrawal reports `account-session-required` rather than reaching
        // for the device key.
        let s = shared();
        assert_eq!(account_session_token(&s).unwrap(), None);
    }

    #[test]
    fn account_session_token_is_offered_once_a_live_session_is_stored() {
        // The other half of the seam: with a live token on disk, withdrawal
        // proceeds to the network call instead of the fail-closed error. If
        // this ever silently stopped working, `withdraw` would look "safe"
        // while being permanently broken.
        let s = shared();
        let session = crate::account_auth::AccountSession {
            access_token: "tcn1_dGVuYW50.secret".to_string(),
            expires_at: Utc::now() + chrono::TimeDelta::hours(6),
            account_id: "acct".to_string(),
        };
        s.store
            .write_daemon_file(
                crate::config::ACCOUNT_SESSION_FILE,
                &serde_json::to_vec(&session).unwrap(),
            )
            .unwrap();
        assert_eq!(
            account_session_token(&s).unwrap().as_deref(),
            Some("tcn1_dGVuYW50.secret")
        );
    }

    #[tokio::test]
    async fn withdraw_with_an_expired_session_still_reports_account_session_required() {
        // An expired token must not be presented and 401: the contributor is
        // told to sign in again, which is the whole point of the distinct
        // error code.
        let s = shared();
        let session = crate::account_auth::AccountSession {
            access_token: "tcn1_dGVuYW50.secret".to_string(),
            expires_at: Utc::now() - chrono::TimeDelta::hours(1),
            account_id: "acct".to_string(),
        };
        s.store
            .write_daemon_file(
                crate::config::ACCOUNT_SESSION_FILE,
                &serde_json::to_vec(&session).unwrap(),
            )
            .unwrap();
        let r = handle_withdraw(
            &s,
            &req(
                "withdraw",
                serde_json::json!({"submission_id": Uuid::new_v4().to_string()}),
            ),
        )
        .await;
        let err = r.error.unwrap();
        assert_eq!(err.code, ERR_UNAVAILABLE);
        assert_eq!(err.message, ERR_ACCOUNT_SESSION_REQUIRED);
    }
}
