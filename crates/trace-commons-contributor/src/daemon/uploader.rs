//! Turning an approved queue entry into an upload.
//!
//! The uploader adds three things to the shared submit pipeline, all of them
//! consequences of the upload being unattended:
//!
//! 1. **A re-hash guard, and an approval-terms guard.** The contributor
//!    approves a description of a session -- a project, a size, a time --
//!    and, if they previewed it, a specific redacted envelope. Digests
//!    batch every few hours, so the file can grow between the offer and the
//!    approval; if it did, the approval does not cover the current content,
//!    so nothing is uploaded and a fresh offer is made instead.
//!
//!    The re-hash guard alone was not enough, and the comment that used to
//!    live here claimed more than the code did. It verifies the *input*.
//!    Everything else that determines what actually leaves the machine --
//!    the privacy-filter selection, the NEAR AI backend and model, the
//!    consent scopes, the identity and endpoints stamped onto the envelope,
//!    and the redaction service's own output -- could move between the
//!    preview and the send with the session hash unchanged, and the guard
//!    stayed silent. So the approval also pins an input fingerprint
//!    (`preview::input_fingerprint`), re-derived here before every upload;
//!    a mismatch re-offers the entry instead of uploading it.
//!
//!    For a previewed entry the artifact is not re-derived at all: the
//!    envelope the contributor was shown was written to disk
//!    (`daemon::approved_envelope`) and `submit_loaded` sends precisely
//!    those bytes. This replaced a digest comparison that was correct and
//!    unusable -- an LLM-backed privacy filter does not reproduce its own
//!    spans, so every previewed entry was refused forever. Together these
//!    are the central consent property of the whole daemon.
//! 2. **Revocation checks.** A cached claim stays valid for minutes after a
//!    logout, so enrollment is re-checked immediately before every upload
//!    rather than once at startup.
//! 3. **Volume caps.** A background process spending the contributor's
//!    bandwidth and privacy-filter budget stops at a daily ceiling.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use super::health::{
    HealthState, LABEL_ADMISSION_LIMIT_REACHED, LABEL_ADMISSION_REFUSED, LABEL_CANARY_FAILED,
    LABEL_CLAIM_MINT_FAILED, LABEL_DAILY_CAP_REACHED, LABEL_INGEST_UNREACHABLE,
    LABEL_NEAR_AI_NOTICE_PENDING, LABEL_NOT_LOGGED_IN, LABEL_PII_FILTER_UNAVAILABLE,
};
use super::queue::QueueEntry;
use super::settings::DaemonSettings;
use super::state::DaemonState;
use crate::config::ConfigStore;
use crate::source::{SessionRef, TraceSource};
use crate::submit::{
    PRECONDITION_CANARY_FAILED, PRECONDITION_NEAR_AI_NOTICE_UNRECORDED, PRECONDITION_NOT_LOGGED_IN,
    SubmitContext, SubmitOutcome, SubmitPreconditionFailure,
};
use trace_commons_protocol::admission::AdmissionRefusal;
use trace_commons_protocol::trace_contribution::TraceContributionEnvelope;

#[derive(Debug, PartialEq, Eq)]
pub enum UploadDecision {
    Uploaded {
        submission_id: Uuid,
        /// What the receipt fetch produced for this upload, so the daemon can
        /// correct the attestation mark on a row whose receipt did not
        /// arrive. See `attestation_mark::writeback_after_upload`.
        receipt: crate::submit::ReceiptShipped,
    },
    /// Already delivered previously; nothing sent.
    AlreadySubmitted { submission_id: Uuid },
    /// The session changed after it was offered. Nothing was sent, and
    /// `new_hash` describes what is on disk now.
    Superseded { new_hash: String },
    /// The pipeline declined to send this, fail-closed.
    Refused { reason_label: String },
    /// The approval no longer covers what would be sent -- an
    /// envelope-determining input moved, or the envelope the pipeline built
    /// is not the one the contributor was shown. Nothing was sent; the
    /// entry goes back in front of the contributor under `reason_label`.
    ApprovalStale { reason_label: String },
    /// Network or auth failure.
    Failed { reason_label: String },
    /// A daily volume cap is in force.
    CapReached,
}

/// Whether one more upload of `size_bytes` fits inside today's budget.
///
/// Call `DaemonState::roll_day` first; this deliberately does not mutate.
pub fn cap_check(state: &DaemonState, size_bytes: u64, settings: &DaemonSettings) -> bool {
    if state.uploads_today >= settings.max_uploads_per_day {
        return false;
    }
    state.bytes_today.saturating_add(size_bytes) <= settings.max_bytes_per_day
}

/// What today's volume budget looks like, and what it is currently holding
/// back.
///
/// The daily cap was already enforced and already had a health label, but
/// neither was legible from outside: `LABEL_DAILY_CAP_REACHED` sits at the
/// bottom of the precedence order, so any other condition -- a full queue,
/// in the case this was diagnosed from -- occupies the single
/// `health.last_error_label` slot and the cap becomes invisible. From the
/// contributor's side an exhausted budget was indistinguishable from a
/// broken app: approvals simply stopped turning into uploads.
///
/// This is therefore reported on `status` as its own field rather than
/// through the health slot, so it is visible no matter what else is wrong.
/// Everything on it is a count or a timestamp; nothing here can carry a
/// path, a hash, or a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DailyBudget {
    pub bytes_today: u64,
    pub max_bytes_per_day: u64,
    pub bytes_remaining: u64,
    pub uploads_today: u32,
    pub max_uploads_per_day: u32,
    pub uploads_remaining: u32,
    /// The next UTC midnight, which is exactly when `DaemonState::roll_day`
    /// zeroes the counters above. Derived, not guessed: `roll_day` buckets
    /// by `%Y-%m-%d` in UTC, so this is the real reset instant and a client
    /// may state it.
    pub resets_at: DateTime<Utc>,
    /// Approved entries that this budget will not let out before the reset.
    pub blocked_entries: u32,
    /// Their combined on-disk size.
    pub blocked_bytes: u64,
}

impl DailyBudget {
    /// Whether anything is actually being held back. A spent budget with
    /// nothing approved behind it is not a condition worth telling anyone
    /// about.
    pub fn blocked(&self) -> bool {
        self.blocked_entries > 0
    }
}

/// The next UTC midnight strictly after `now` -- when `roll_day` will next
/// change the day bucket.
fn next_utc_midnight(now: DateTime<Utc>) -> DateTime<Utc> {
    (now.date_naive() + chrono::Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .expect("midnight is a valid time")
        .and_utc()
}

/// Measure today's budget against the entries waiting on it.
///
/// `approved` must be the approved entries in the order `drain_approved`
/// walks them, because that order is what decides which of them go today.
/// The walk here mirrors that loop exactly: each entry that fits is charged
/// against a running copy of the counters, and the first one that does not
/// fit stops the pass -- so it and every entry behind it are blocked, even
/// the small ones. Counting only the entries that individually overflow
/// would under-report, which is the same silence in a smaller font.
///
/// Does not mutate: the day roll is applied to a local copy, so calling
/// this from a read-only `status` cannot move the daemon's own counters.
pub fn budget_snapshot(
    approved: &[QueueEntry],
    state: &DaemonState,
    settings: &DaemonSettings,
    now: DateTime<Utc>,
) -> DailyBudget {
    let mut rolled = state.clone();
    rolled.roll_day(now);

    let mut simulated = rolled.clone();
    let mut blocked_entries: u32 = 0;
    let mut blocked_bytes: u64 = 0;
    let mut stopped = false;
    for entry in approved {
        if stopped {
            blocked_entries = blocked_entries.saturating_add(1);
            blocked_bytes = blocked_bytes.saturating_add(entry.size_bytes);
            continue;
        }
        if cap_check(&simulated, entry.size_bytes, settings) {
            simulated.uploads_today = simulated.uploads_today.saturating_add(1);
            simulated.bytes_today = simulated.bytes_today.saturating_add(entry.size_bytes);
        } else {
            stopped = true;
            blocked_entries = blocked_entries.saturating_add(1);
            blocked_bytes = blocked_bytes.saturating_add(entry.size_bytes);
        }
    }

    DailyBudget {
        bytes_today: rolled.bytes_today,
        max_bytes_per_day: settings.max_bytes_per_day,
        bytes_remaining: settings
            .max_bytes_per_day
            .saturating_sub(rolled.bytes_today),
        uploads_today: rolled.uploads_today,
        max_uploads_per_day: settings.max_uploads_per_day,
        uploads_remaining: settings
            .max_uploads_per_day
            .saturating_sub(rolled.uploads_today),
        resets_at: next_utc_midnight(now),
        blocked_entries,
        blocked_bytes,
    }
}

/// Map a pipeline outcome onto a daemon decision, so the queue records a
/// fixed label rather than pipeline internals.
fn decision_for(outcome: SubmitOutcome, receipt: crate::submit::ReceiptShipped) -> UploadDecision {
    match outcome {
        SubmitOutcome::Refused { reason_label, .. } | SubmitOutcome::Failed { reason_label }
            if matches!(
                reason_label.as_str(),
                "witness-grant-changed" | "witness-review-stale"
            ) =>
        {
            UploadDecision::ApprovalStale { reason_label }
        }
        SubmitOutcome::Submitted { submission_id, .. } => UploadDecision::Uploaded {
            submission_id,
            receipt,
        },
        SubmitOutcome::AlreadySubmitted { submission_id, .. } => {
            UploadDecision::AlreadySubmitted { submission_id }
        }
        SubmitOutcome::SkippedParseFailure { reason_label } => {
            UploadDecision::Refused { reason_label }
        }
        SubmitOutcome::Refused { reason_label, .. } => UploadDecision::Refused { reason_label },
        SubmitOutcome::Failed { reason_label } => UploadDecision::Failed { reason_label },
    }
}

/// The health label a decision implies, if any.
pub fn health_label_for(decision: &UploadDecision) -> Option<&'static str> {
    match decision {
        UploadDecision::CapReached => Some(LABEL_DAILY_CAP_REACHED),
        UploadDecision::Refused { reason_label } => match reason_label.as_str() {
            "pii-filter-unavailable" => Some(LABEL_PII_FILTER_UNAVAILABLE),
            LABEL_NEAR_AI_NOTICE_PENDING => Some(LABEL_NEAR_AI_NOTICE_PENDING),
            LABEL_NOT_LOGGED_IN => Some(LABEL_NOT_LOGGED_IN),
            _ => None,
        },
        UploadDecision::Failed { reason_label } => match reason_label.as_str() {
            "claim-mint-failed" => Some(LABEL_CLAIM_MINT_FAILED),
            // A refusal the commons sent on purpose, before the catch-all
            // that reads everything else as an outage.
            other => match AdmissionRefusal::from_label(other) {
                Some(AdmissionRefusal::LimitReached) => Some(LABEL_ADMISSION_LIMIT_REACHED),
                // A lease another attempt holds, which the next retry
                // resolves. Nothing for a contributor to be told about.
                Some(AdmissionRefusal::InProgress) => None,
                Some(_) => Some(LABEL_ADMISSION_REFUSED),
                None => Some(LABEL_INGEST_UNREACHABLE),
            },
        },
        _ => None,
    }
}

/// The health label for a fail-closed precondition that aborted a submit
/// pass.
///
/// Reads the typed `SubmitPreconditionFailure` rather than matching on
/// error text. An error that is not one of those cannot currently arise
/// from `submit_one`, but if one ever does it must still block expiry
/// rather than silently letting the clock run, so the fallback is the
/// most conservative blocking label rather than `None`.
pub fn precondition_health_label(e: &anyhow::Error) -> &'static str {
    match e.downcast_ref::<SubmitPreconditionFailure>().map(|f| f.0) {
        Some(PRECONDITION_CANARY_FAILED) => LABEL_CANARY_FAILED,
        Some(PRECONDITION_NEAR_AI_NOTICE_UNRECORDED) => LABEL_NEAR_AI_NOTICE_PENDING,
        Some(PRECONDITION_NOT_LOGGED_IN) => LABEL_NOT_LOGGED_IN,
        _ => LABEL_PII_FILTER_UNAVAILABLE,
    }
}

/// Whether this store still holds a usable enrollment.
///
/// Checked immediately before every upload, not once at startup: a cached
/// claim outlives a logout by minutes, and the receipts file it would append
/// to is gone.
pub fn enrollment_is_live(store: &ConfigStore) -> bool {
    match store.load_config() {
        Ok(Some(_)) => store.load_device_key().ok().flatten().is_some(),
        _ => false,
    }
}

pub struct Uploader<'a, 'ctx> {
    pub ctx: &'a mut SubmitContext<'ctx>,
    pub store: &'a ConfigStore,
    pub settings: &'a DaemonSettings,
    pub state: &'a mut DaemonState,
    pub health: &'a mut HealthState,
}

impl Uploader<'_, '_> {
    /// The exact redacted envelope this entry was approved as, if it was
    /// previewed at all.
    ///
    /// `Ok(None)` -- never previewed (armed auto-upload, approve-all), so
    /// the pipeline builds the envelope as it always has.
    /// `Ok(Some(_))` -- previewed; send these bytes.
    /// `Err(label)` -- previewed, but the bytes are gone, unreadable, or
    /// not the ones the entry is pinned to. Fail-closed: the approval is
    /// revoked and the entry re-offered rather than rebuilt.
    ///
    /// The digest re-check is a consistency check on this crate's own
    /// storage -- a truncated file, a file crossed over from another entry
    /// -- not a check on redaction. Redaction is not re-run here at all.
    fn approved_witness_for(
        &self,
        entry: &QueueEntry,
    ) -> Result<super::approved_envelope::WitnessReviewArtifact> {
        let artifact = super::approved_envelope::load_witnessed(self.store, entry.entry_id)?
            .ok_or_else(|| anyhow::anyhow!("witness-review-stale"))?;
        if Some(artifact.digest()?.as_str()) != entry.previewed_envelope_digest.as_deref() {
            anyhow::bail!("witness-review-stale");
        }
        let fingerprint = super::preview::input_fingerprint(
            self.ctx.effective_cfg(),
            self.ctx.near_ai(),
            self.settings.ironwire_attested_bodies,
        );
        artifact.validate(
            self.ctx.effective_cfg(),
            &entry.session_hash,
            &fingerprint,
            entry.approved_verdict.as_deref(),
            entry.approved_correction.as_deref(),
        )?;
        Ok(artifact)
    }

    fn approved_envelope_for(
        &self,
        entry: &QueueEntry,
    ) -> Result<Option<TraceContributionEnvelope>, String> {
        let Some(pinned) = entry.previewed_envelope_digest.as_deref() else {
            return Ok(None);
        };
        let stored = super::approved_envelope::load(self.store, entry.entry_id)
            .map_err(|_| super::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE.to_string())?
            .ok_or_else(|| super::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE.to_string())?;
        let actual = super::preview::envelope_digest(&stored)
            .map_err(|_| super::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE.to_string())?;
        if actual != pinned {
            return Err(super::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE.to_string());
        }
        // AFTER the digest check, never before it. The check is a
        // consistency check on this crate's own storage and has to run
        // against the bytes as stored; applying the verdict first would make
        // a truncated or crossed-over file pass.
        //
        // This is the one deliberate divergence from "the upload sends
        // precisely the stored bytes", and it is bounded to
        // `outcome.task_success`. See this module's doc note.
        //
        // An unparseable stored verdict is ignored rather than refused: the
        // IPC boundary already validates, so a bad value here means a
        // hand-edited queue file, and refusing the upload would strand the
        // entry.
        let mut stored = stored;
        if let Some(name) = entry.approved_verdict.as_deref() {
            if let Some(verdict) = crate::envelope::ContributorVerdict::parse(name) {
                crate::envelope::apply_verdict(&mut stored, verdict);
            }
        }
        Ok(Some(stored))
    }

    /// Upload one queue entry, or explain why not.
    pub async fn upload_entry(
        &mut self,
        source: &dyn TraceSource,
        session_ref: &SessionRef,
        entry: &QueueEntry,
        now: DateTime<Utc>,
    ) -> Result<UploadDecision> {
        if !enrollment_is_live(self.store) {
            self.health.fail(LABEL_NOT_LOGGED_IN, now);
            return Ok(UploadDecision::Refused {
                reason_label: LABEL_NOT_LOGGED_IN.to_string(),
            });
        }
        // Enrollment is live, so retract the not-logged-in condition if it was set.
        self.health.resolve(LABEL_NOT_LOGGED_IN);

        if self.settings.near_ai.is_some() && !self.store.near_ai_notice_shown() {
            // The one-time notice is delivered interactively. Under a service
            // manager its output goes to a log nobody reads, so a daemon that
            // consumed the marker would send the contributor's text to a third
            // party with the notice never actually delivered.
            self.health.fail(LABEL_NEAR_AI_NOTICE_PENDING, now);
            return Ok(UploadDecision::Refused {
                reason_label: LABEL_NEAR_AI_NOTICE_PENDING.to_string(),
            });
        }
        // Near-AI notice requirement is met (either not configured or already shown),
        // so retract the notice-pending condition if it was set.
        self.health.resolve(LABEL_NEAR_AI_NOTICE_PENDING);

        self.state.roll_day(now);
        if !cap_check(self.state, entry.size_bytes, self.settings) {
            self.health.fail(LABEL_DAILY_CAP_REACHED, now);
            return Ok(UploadDecision::CapReached);
        }
        // Cap check passed, so retract the daily-cap-reached condition if it was set.
        self.health.resolve(LABEL_DAILY_CAP_REACHED);

        // Re-read and re-hash. The approval was for the content described by
        // entry.session_hash; if the file has moved on, that approval does not
        // transfer to the new content.
        // `source.load` reads the whole session file and hashes it -- blocking,
        // non-yielding work with no `.await` of its own, run once per approved
        // entry from inside the supervisor's task. Off-worker for the same
        // reason `watcher::tick`'s scan is; see `super::run_blocking`'s doc.
        let transcript = match super::run_blocking(|| source.load(session_ref)) {
            Ok(t) => t,
            Err(_) => {
                return Ok(UploadDecision::Refused {
                    reason_label: "parse-failed".to_string(),
                });
            }
        };
        if transcript.session_hash != entry.session_hash {
            return Ok(UploadDecision::Superseded {
                new_hash: transcript.session_hash,
            });
        }

        // The input half of the approval-terms guard, re-derived from what
        // this pipeline will actually use rather than from what the config
        // said at some earlier moment. `None` on an approved entry means
        // the terms were never recorded (an entry from before this field
        // existed, or an approval taken with no readable config), which is
        // "unknown, so re-ask": fail-closed.
        let inputs_now = super::preview::input_fingerprint(
            self.ctx.effective_cfg(),
            self.ctx.near_ai(),
            self.settings.ironwire_attested_bodies,
        );
        if entry.approved_inputs.as_deref() != Some(inputs_now.as_str()) {
            return Ok(UploadDecision::ApprovalStale {
                reason_label: super::preview::REASON_INPUTS_CHANGED.to_string(),
            });
        }

        // The artifact half. A previewed entry carries the envelope it was
        // previewed as, on disk; the pipeline sends exactly those bytes.
        // Nothing rebuilds and compares -- see
        // `SubmitContext::use_approved_envelope` and
        // `daemon::approved_envelope` for why a comparison cannot work
        // against an LLM-backed privacy filter.
        //
        // Fail-closed on anything unexpected: an entry pinned to a preview
        // whose bytes are gone, unreadable, or not the ones that were
        // pinned goes back in front of the contributor. It is never
        // silently rebuilt, because rebuilding is precisely how a
        // contributor ends up sending something they were never shown.
        if entry.holds_witness_certificate() {
            let result = self.approved_witness_for(entry);
            match result {
                Ok(artifact) => {
                    if artifact.token_bundle.is_some()
                        != self.settings.token_distributions_contribution
                    {
                        return Ok(UploadDecision::ApprovalStale {
                            reason_label: "token-distribution-consent-changed".into(),
                        });
                    }
                    self.ctx
                        .use_approved_token_bundle(artifact.token_bundle.clone());
                    if self
                        .ctx
                        .use_approved_witness(artifact.response().clone())
                        .is_err()
                    {
                        return Ok(UploadDecision::ApprovalStale {
                            reason_label: "witness-review-stale".to_string(),
                        });
                    }
                }
                Err(_) => {
                    return Ok(UploadDecision::ApprovalStale {
                        reason_label: "witness-review-stale".to_string(),
                    });
                }
            }
        } else {
            if self.settings.token_distributions_contribution {
                return Ok(UploadDecision::ApprovalStale {
                    reason_label: "token-distribution-review-required".into(),
                });
            }
            match self.approved_envelope_for(entry) {
                Ok(approved) => self.ctx.use_approved_envelope(approved),
                Err(reason_label) => return Ok(UploadDecision::ApprovalStale { reason_label }),
            }
        }

        // `submit_one` returns `Err` only for a fail-closed precondition
        // (`SubmitPreconditionFailure`) -- a privacy-filter canary that did
        // not catch its planted secret, an unrecordable NEAR AI notice, a
        // missing device identity. Each of those stops the whole pass, and
        // each must set its health label *before* the error propagates:
        // `LABEL_CANARY_FAILED` is in `EXPIRY_BLOCKING_LABELS` but was
        // never set by any production path, so during a filter outage the
        // daemon reported healthy, `blocks_expiry()` was false, and
        // `queue.expire` discarded pending traces as
        // expired-without-decision -- exactly what expiry suspension exists
        // to prevent.
        // `submit_loaded`, not `submit_one`: the transcript just loaded and
        // hashed above is the one that gets sent. `submit_one` would load
        // the file a third, independent time, and it was *that* read --
        // never hashed, never compared -- whose bytes went out. A session
        // appended to between the two reads passed the guard and shipped
        // content the guard had never seen.
        let outcome = match self.ctx.submit_loaded(transcript).await {
            Ok(o) => o,
            Err(e) => {
                self.health.fail(precondition_health_label(&e), now);
                return Err(e);
            }
        };
        let decision = decision_for(outcome, self.ctx.last_receipt_shipped());

        match &decision {
            UploadDecision::Uploaded { .. } => {
                self.state
                    .record_upload(&entry.path, &entry.session_hash, entry.size_bytes, now);
                self.health.clear();
            }
            other => {
                if let Some(label) = health_label_for(other) {
                    self.health.fail(label, now);
                }
            }
        }
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests_support::temp_store;
    use crate::daemon::queue::{QueueEntry, QueueState, entry_id_for};
    use crate::source::claude_code::ClaudeCodeSource;
    use std::path::PathBuf;

    use crate::daemon::test_support::at;

    fn settings() -> DaemonSettings {
        DaemonSettings::default()
    }

    #[test]
    fn cap_check_rejects_past_the_daily_upload_count() {
        let mut st = DaemonState::new();
        st.uploads_today = 50;
        assert!(!cap_check(&st, 10, &settings()));
    }

    #[test]
    fn cap_check_rejects_past_the_daily_byte_budget() {
        let mut st = DaemonState::new();
        st.bytes_today = 209_715_200;
        assert!(!cap_check(&st, 1, &settings()));
    }

    #[test]
    fn cap_check_rejects_an_upload_that_would_cross_the_byte_budget() {
        let mut st = DaemonState::new();
        st.bytes_today = 209_715_100;
        assert!(!cap_check(&st, 200, &settings()));
    }

    #[test]
    fn cap_check_allows_a_normal_upload() {
        assert!(cap_check(&DaemonState::new(), 1024, &settings()));
    }

    /// An approved entry of a given size, with nothing else that matters
    /// to a budget calculation.
    fn sized(size_bytes: u64) -> QueueEntry {
        QueueEntry {
            entry_id: Uuid::new_v4(),
            session_hash: "sha256:00".into(),
            source: "claude-code".into(),
            project_key: "/Users/testuser/code/myproj".into(),
            project_label: "myproj".into(),
            path: PathBuf::from("/tmp/a.jsonl"),
            size_bytes,
            discovered_at: at("2026-08-08T12:00:00Z"),
            state: QueueState::Approved,
            ..Default::default()
        }
    }

    /// The state observed on the machine this was diagnosed from: the byte
    /// budget all but spent, 14 approved entries waiting behind it.
    fn nearly_spent() -> DaemonState {
        let mut st = DaemonState::new();
        st.day_bucket = Some("2026-08-08".to_string());
        st.uploads_today = 12;
        st.bytes_today = 204_659_969;
        st
    }

    #[test]
    fn an_entry_that_fails_the_byte_check_is_reported_as_budget_blocked() {
        // 14.9 MB against 5,055,231 bytes of remaining budget.
        let approved = vec![sized(14_900_000)];
        let b = budget_snapshot(
            &approved,
            &nearly_spent(),
            &settings(),
            at("2026-08-08T20:00:00Z"),
        );
        assert!(b.blocked());
        assert_eq!(b.blocked_entries, 1);
        assert_eq!(b.blocked_bytes, 14_900_000);
        // The numbers, not just the flag.
        assert_eq!(b.bytes_today, 204_659_969);
        assert_eq!(b.max_bytes_per_day, 209_715_200);
        assert_eq!(b.bytes_remaining, 5_055_231);
        assert_eq!(b.uploads_today, 12);
        assert_eq!(b.uploads_remaining, 38);
    }

    #[test]
    fn an_entry_that_passes_the_byte_check_is_not_reported_as_blocked() {
        let approved = vec![sized(1_000_000)];
        let b = budget_snapshot(
            &approved,
            &nearly_spent(),
            &settings(),
            at("2026-08-08T20:00:00Z"),
        );
        assert!(!b.blocked());
        assert_eq!(b.blocked_entries, 0);
        assert_eq!(b.blocked_bytes, 0);
    }

    #[test]
    fn a_small_entry_queued_behind_a_blocked_one_is_blocked_too() {
        // `drain_approved` breaks on the first cap failure rather than
        // skipping past it, so a 1 KB entry behind a 14.9 MB one does not
        // go today either. Counting only the entries that individually
        // overflow would under-report the wait.
        let approved = vec![sized(14_900_000), sized(1_024)];
        let b = budget_snapshot(
            &approved,
            &nearly_spent(),
            &settings(),
            at("2026-08-08T20:00:00Z"),
        );
        assert_eq!(b.blocked_entries, 2);
        assert_eq!(b.blocked_bytes, 14_901_024);
    }

    #[test]
    fn entries_ahead_of_the_first_blocked_one_are_charged_against_the_budget() {
        // Two 3 MB entries fit in 5,055,231 bytes only one at a time; the
        // first is charged, so the second is what stops the pass.
        let approved = vec![sized(3_000_000), sized(3_000_000), sized(1_024)];
        let b = budget_snapshot(
            &approved,
            &nearly_spent(),
            &settings(),
            at("2026-08-08T20:00:00Z"),
        );
        assert_eq!(b.blocked_entries, 2);
        assert_eq!(b.blocked_bytes, 3_001_024);
    }

    #[test]
    fn the_upload_count_cap_blocks_just_as_the_byte_cap_does() {
        let mut st = DaemonState::new();
        st.day_bucket = Some("2026-08-08".to_string());
        st.uploads_today = 50;
        let b = budget_snapshot(&[sized(1)], &st, &settings(), at("2026-08-08T20:00:00Z"));
        assert!(b.blocked());
        assert_eq!(b.uploads_remaining, 0);
        // The byte budget is untouched, and says so.
        assert_eq!(b.bytes_remaining, 209_715_200);
    }

    #[test]
    fn the_condition_clears_when_the_day_rolls() {
        // Same spent counters, but `now` is the next UTC day: `roll_day`
        // zeroes them, so nothing is blocked any more.
        let approved = vec![sized(14_900_000)];
        let b = budget_snapshot(
            &approved,
            &nearly_spent(),
            &settings(),
            at("2026-08-09T00:00:01Z"),
        );
        assert!(!b.blocked());
        assert_eq!(b.bytes_today, 0);
        assert_eq!(b.uploads_today, 0);
        assert_eq!(b.bytes_remaining, 209_715_200);
    }

    #[test]
    fn measuring_the_budget_does_not_move_the_daemons_own_counters() {
        // `status` polls this; a snapshot that rolled the real day would
        // hand a contributor a fresh budget for free.
        let state = nearly_spent();
        let before = state.clone();
        let _ = budget_snapshot(&[sized(1)], &state, &settings(), at("2026-08-09T00:00:01Z"));
        assert_eq!(state, before);
    }

    #[test]
    fn the_reset_time_is_the_next_utc_midnight() {
        let b = budget_snapshot(
            &[],
            &nearly_spent(),
            &settings(),
            at("2026-08-08T23:59:59Z"),
        );
        assert_eq!(b.resets_at, at("2026-08-09T00:00:00Z"));
        let b = budget_snapshot(
            &[],
            &nearly_spent(),
            &settings(),
            at("2026-08-08T00:00:00Z"),
        );
        assert_eq!(b.resets_at, at("2026-08-09T00:00:00Z"));
    }

    #[test]
    fn a_spent_budget_with_nothing_waiting_is_not_a_condition() {
        // Nothing to tell anyone about, so `blocked` stays false even
        // though the budget really is gone.
        let mut st = nearly_spent();
        st.bytes_today = 209_715_200;
        let b = budget_snapshot(&[], &st, &settings(), at("2026-08-08T20:00:00Z"));
        assert!(!b.blocked());
        assert_eq!(b.bytes_remaining, 0);
    }

    #[test]
    fn a_failed_upload_maps_to_an_ingest_health_label() {
        let d = UploadDecision::Failed {
            reason_label: "upload-failed".into(),
        };
        assert_eq!(health_label_for(&d), Some(LABEL_INGEST_UNREACHABLE));
    }

    #[test]
    fn a_claim_failure_is_distinguished_from_an_ingest_failure() {
        let d = UploadDecision::Failed {
            reason_label: "claim-mint-failed".into(),
        };
        assert_eq!(health_label_for(&d), Some(LABEL_CLAIM_MINT_FAILED));
    }

    /// A refusal the commons sent deliberately is not an outage.
    ///
    /// Every `Failed` label except the claim one used to become
    /// `ingest-unreachable`, so a declined contribution and a spent budget
    /// both told the contributor the service was down, in front of a queue
    /// that would never drain by retrying.
    #[test]
    fn an_admission_refusal_is_not_an_outage() {
        use trace_commons_protocol::admission::AdmissionRefusal;
        for refusal in AdmissionRefusal::ALL {
            let d = UploadDecision::Failed {
                reason_label: refusal.label().into(),
            };
            assert_ne!(
                health_label_for(&d),
                Some(LABEL_INGEST_UNREACHABLE),
                "{} is reported as an outage",
                refusal.label()
            );
        }
        assert_eq!(
            health_label_for(&UploadDecision::Failed {
                reason_label: AdmissionRefusal::Refused.label().into(),
            }),
            Some(LABEL_ADMISSION_REFUSED)
        );
        assert_eq!(
            health_label_for(&UploadDecision::Failed {
                reason_label: AdmissionRefusal::LimitReached.label().into(),
            }),
            Some(LABEL_ADMISSION_LIMIT_REACHED)
        );
        // A lease another attempt is holding is resolved by the retry that
        // follows it. Reporting a condition for it would put a banner up for
        // a race that clears itself.
        assert_eq!(
            health_label_for(&UploadDecision::Failed {
                reason_label: AdmissionRefusal::InProgress.label().into(),
            }),
            None
        );
    }

    #[test]
    fn a_successful_upload_implies_no_health_failure() {
        let d = UploadDecision::Uploaded {
            submission_id: Uuid::nil(),
            receipt: crate::submit::ReceiptShipped::NoCall,
        };
        assert_eq!(health_label_for(&d), None);
    }

    /// A claude-code session in a tempdir that can be grown on demand.
    struct GrowingSession {
        _dir: tempfile::TempDir,
        root: PathBuf,
        path: PathBuf,
    }

    impl GrowingSession {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("projects");
            let project = root.join("-Users-testuser-code-myproj");
            std::fs::create_dir_all(&project).unwrap();
            let path = project.join("33333333-3333-3333-3333-333333333333.jsonl");
            std::fs::write(
                &path,
                "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"first question\"},\
                 \"cwd\":\"/Users/testuser/code/myproj\",\"timestamp\":\"2026-08-08T10:00:00Z\",\
                 \"version\":\"2.0.1\",\"sessionId\":\"33333333-3333-3333-3333-333333333333\",\
                 \"uuid\":\"a1\"}\n",
            )
            .unwrap();
            Self {
                _dir: dir,
                root,
                path,
            }
        }

        fn source(&self) -> ClaudeCodeSource {
            ClaudeCodeSource::new(self.root.clone())
        }

        fn session_ref(&self) -> SessionRef {
            self.source().discover().unwrap().remove(0)
        }

        fn current_hash(&self) -> String {
            self.source()
                .load(&self.session_ref())
                .unwrap()
                .session_hash
        }

        fn append_more_events(&self) {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&self.path)
                .unwrap();
            f.write_all(
                b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"much later work\"},\
                  \"cwd\":\"/Users/testuser/code/myproj\",\"timestamp\":\"2026-08-08T18:00:00Z\",\
                  \"version\":\"2.0.1\",\"sessionId\":\"33333333-3333-3333-3333-333333333333\",\
                  \"uuid\":\"a2\"}\n",
            )
            .unwrap();
        }

        /// Write a delegated transcript beside the session, stamped with its
        /// `sessionId` so it verifies as a member of the group.
        fn add_subagent(&self, agent: &str) {
            let session = "33333333-3333-3333-3333-333333333333";
            let subagents = self.path.parent().unwrap().join(session).join("subagents");
            std::fs::create_dir_all(&subagents).unwrap();
            std::fs::write(
                subagents.join(format!("{agent}.jsonl")),
                format!(
                    "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"delegated work\"}},\
                     \"cwd\":\"/Users/testuser/code/myproj\",\"timestamp\":\"2026-08-08T18:00:00Z\",\
                     \"version\":\"2.0.1\",\"sessionId\":\"{session}\",\"uuid\":\"s1\"}}\n"
                ),
            )
            .unwrap();
        }

        /// An approved entry whose recorded terms match `cfg` -- i.e. the
        /// ordinary case where nothing moved between approval and upload.
        fn entry_for(&self, hash: &str, cfg: &crate::config::ContributorConfig) -> QueueEntry {
            QueueEntry {
                approved_inputs: Some(crate::daemon::preview::input_fingerprint(cfg, None, false)),
                ..self.entry(hash)
            }
        }

        fn entry(&self, hash: &str) -> QueueEntry {
            QueueEntry {
                entry_id: entry_id_for(hash),
                session_hash: hash.to_string(),
                source: "claude-code".into(),
                project_key: "/Users/testuser/code/myproj".into(),
                project_label: "myproj".into(),
                path: self.path.clone(),
                size_bytes: std::fs::metadata(&self.path).unwrap().len(),
                discovered_at: at("2026-08-08T12:00:00Z"),
                state: QueueState::Approved,
                ..Default::default()
            }
        }
    }

    fn dry_run_opts() -> crate::submit::SubmitOptions {
        crate::submit::SubmitOptions {
            dry_run: true,
            pii_filter: None,
            no_reasoning: false,
            machine_readable: true,
            unenrolled_preview: false,
            remediate_quarantined: false,
            verdict: None,
        }
    }

    #[tokio::test]
    async fn upload_refuses_when_a_delegated_transcript_appeared_after_approval() {
        // The same consent property as the test below, one level out: an
        // approval covers a conversation, and a conversation that has since
        // delegated work to a subagent is not the one that was approved. The
        // group hash is what makes the re-hash guard see it -- with a
        // parent-only hash this would ship silently.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = crate::config::ContributorConfig {
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
            // No public profile claimed. These are cache fields, excluded
            // from the input fingerprint, so they cannot affect what this
            // test measures -- the re-hash guard seeing a new subagent.
            display_handle: None,
            public_bio: None,
            public_since: None,
            witness: None,
        };
        store.save_config(&cfg).unwrap();

        let offered_hash = session.current_hash();
        let entry = session.entry_for(&offered_hash, &cfg);
        session.add_subagent("agent-a");

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };

        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        match decision {
            UploadDecision::Superseded { new_hash } => {
                assert_ne!(new_hash, entry.session_hash);
                assert_eq!(new_hash, session.current_hash());
            }
            other => panic!("expected Superseded, got {other:?}"),
        }
        assert_eq!(
            state.uploads_today, 0,
            "nothing may be uploaded once the conversation has grown a delegate"
        );
    }

    #[tokio::test]
    async fn upload_refuses_when_the_session_grew_after_it_was_offered() {
        // The central consent property: approve a 1-event session, never
        // ship one that has since gained an afternoon of work.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = crate::config::ContributorConfig {
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
        };
        store.save_config(&cfg).unwrap();

        let offered_hash = session.current_hash();
        let entry = session.entry(&offered_hash);
        session.append_more_events();

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };

        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        match decision {
            UploadDecision::Superseded { new_hash } => {
                assert_ne!(new_hash, entry.session_hash);
                assert_eq!(new_hash, session.current_hash());
            }
            other => panic!("expected Superseded, got {other:?}"),
        }
        assert_eq!(
            state.uploads_today, 0,
            "nothing may be uploaded when the hash no longer matches"
        );
    }

    #[tokio::test]
    async fn upload_proceeds_when_the_hash_still_matches() {
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = crate::config::ContributorConfig {
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
        };
        store.save_config(&cfg).unwrap();

        let entry = session.entry_for(&session.current_hash(), &cfg);
        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };

        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert!(
            matches!(decision, UploadDecision::Uploaded { .. }),
            "got {decision:?}"
        );
        assert_eq!(state.uploads_today, 1);
        assert!(health.ok());
    }

    /// The config the fixture sessions above are approved and uploaded
    /// under.
    fn fixture_cfg(store: &ConfigStore) -> crate::config::ContributorConfig {
        let device = crate::identity::DeviceIdentity::load_or_generate(store).unwrap();
        crate::config::ContributorConfig {
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

    #[tokio::test]
    async fn upload_refuses_when_an_envelope_determining_input_moved_but_the_bytes_did_not() {
        // THE finding. The raw session file is byte-for-byte what was
        // approved -- the re-hash guard is perfectly happy -- but the
        // configuration that determines the envelope has moved underneath
        // the approval. Before this guard, the uploader re-hashed only the
        // transcript, then had `submit_loaded` rebuild the envelope from
        // whatever the config said at that moment, and the upload went out
        // silently under terms the contributor never saw.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let approved_under = fixture_cfg(&store);
        store.save_config(&approved_under).unwrap();
        let entry = session.entry_for(&session.current_hash(), &approved_under);

        // Not a byte of the session changes. Only an envelope-determining
        // input does: the contributor's identity is now stamped onto the
        // envelope under a different tenant.
        let mut cfg = approved_under.clone();
        cfg.tenant_id = "tenant-somebody-else".into();
        store.save_config(&cfg).unwrap();
        assert_eq!(
            session.current_hash(),
            entry.session_hash,
            "the raw session bytes must be unchanged for this test to mean anything"
        );

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert_eq!(
            decision,
            UploadDecision::ApprovalStale {
                reason_label: crate::daemon::preview::REASON_INPUTS_CHANGED.to_string(),
            },
            "an approval must not transfer to an envelope built from different inputs"
        );
        assert_eq!(state.uploads_today, 0, "nothing may be uploaded");
    }

    #[tokio::test]
    async fn upload_refuses_when_the_approved_envelope_bytes_are_gone() {
        // An entry pinned to a preview whose stored bytes are missing. The
        // daemon must NOT quietly rebuild the envelope -- rebuilding is
        // exactly what the stored bytes exist to avoid -- so it revokes the
        // approval and re-offers instead.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();
        let entry = QueueEntry {
            previewed_envelope_digest: Some("sha256:pinned-but-never-stored".to_string()),
            ..session.entry_for(&session.current_hash(), &cfg)
        };

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert_eq!(
            decision,
            UploadDecision::ApprovalStale {
                reason_label: crate::daemon::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE
                    .to_string(),
            }
        );
        assert_eq!(state.uploads_today, 0);
    }

    #[tokio::test]
    async fn a_witnessed_preview_refuses_by_name_rather_than_building_locally() {
        // The preview path has no claim -- it runs before the contributor has
        // answered -- and a witnessed envelope must carry the granted scopes
        // inside the bytes the certificate covers, which means minting first.
        //
        // Refusing rather than building locally is the point: these exact
        // bytes are what `use_approved_envelope` uploads later, so a
        // locally-redacted preview under a configured witness would be an
        // uncertified submission from a contributor who believes their
        // submissions are certified.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let mut cfg = fixture_cfg(&store);
        cfg.witness = Some(crate::config::WitnessSettings {
            admission_evidence: false,
            url: "http://witness.invalid".into(),
            signing_address: "0x1111111111111111111111111111111111111111".into(),
            expected_measurements: vec![format!(
                "mrtd={},mrconfigid={}",
                "aa".repeat(48),
                "bb".repeat(48)
            )],
        });
        store.save_config(&cfg).unwrap();

        let err = crate::daemon::preview::build_preview(
            &store,
            Some(&cfg),
            None,
            &session.source(),
            &session.session_ref(),
        )
        .await
        .expect_err("a witnessed preview has no claim to mint the grants from");
        assert_eq!(err.to_string(), "witness_claim_unavailable");
    }

    #[tokio::test]
    async fn an_unwitnessed_preview_still_builds() {
        // The positive control. Without it the refusal above would pass on a
        // preview path that had stopped working entirely.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();

        crate::daemon::preview::build_preview(
            &store,
            Some(&cfg),
            None,
            &session.source(),
            &session.session_ref(),
        )
        .await
        .expect("an unconfigured client previews exactly as it did before");
    }

    #[tokio::test]
    async fn upload_refuses_stored_bytes_that_are_not_the_ones_pinned() {
        // A consistency check on this crate's own storage, not on redaction:
        // a truncated file, or one crossed over from another entry, must not
        // be sent as though it were what the contributor approved.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();

        let (_summary, _body, envelope) = crate::daemon::preview::build_preview(
            &store,
            Some(&cfg),
            None,
            &session.source(),
            &session.session_ref(),
        )
        .await
        .unwrap();
        let entry = QueueEntry {
            previewed_envelope_digest: Some("sha256:some-other-artifact".to_string()),
            ..session.entry_for(&session.current_hash(), &cfg)
        };
        crate::daemon::approved_envelope::save(&store, entry.entry_id, &envelope).unwrap();

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert_eq!(
            decision,
            UploadDecision::ApprovalStale {
                reason_label: crate::daemon::preview::REASON_APPROVED_ENVELOPE_UNAVAILABLE
                    .to_string(),
            }
        );
        assert_eq!(state.uploads_today, 0);
    }

    #[tokio::test]
    async fn an_entry_uploads_the_stored_envelope_even_when_a_rebuild_would_differ() {
        // The case the previous design could not do at all. The stored
        // envelope deliberately is NOT what a rebuild produces -- one
        // redacted event body has been altered, which is precisely the shape
        // of an LLM-backed filter returning different spans the second time
        // -- and the upload must still go out, carrying those bytes. The
        // digest-comparison design refused this forever.
        //
        // `daemon_nondeterministic_filter.rs` drives the same property end
        // to end against a filter service that really does move.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();

        let (_summary, _body, mut envelope) = crate::daemon::preview::build_preview(
            &store,
            Some(&cfg),
            None,
            &session.source(),
            &session.session_ref(),
        )
        .await
        .unwrap();
        envelope.events[0].redacted_content =
            Some("a redaction only this run produced".to_string());
        let pinned = crate::daemon::preview::envelope_digest(&envelope).unwrap();
        let entry = QueueEntry {
            previewed_envelope_digest: Some(pinned),
            ..session.entry_for(&session.current_hash(), &cfg)
        };
        crate::daemon::approved_envelope::save(&store, entry.entry_id, &envelope).unwrap();

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert!(
            matches!(decision, UploadDecision::Uploaded { .. }),
            "a previewed entry must upload even though a rebuild would not \
             reproduce its envelope: got {decision:?}"
        );
        assert_eq!(state.uploads_today, 1);
    }

    #[tokio::test]
    async fn an_entry_pinned_to_its_stored_envelope_uploads_normally() {
        // The ordinary case: a preview ran, its bytes were stored, the
        // contributor approved what it showed, nothing moved.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();

        let (summary, _body, envelope) = crate::daemon::preview::build_preview(
            &store,
            Some(&cfg),
            None,
            &session.source(),
            &session.session_ref(),
        )
        .await
        .unwrap();
        let entry = QueueEntry {
            previewed_envelope_digest: Some(summary.envelope_digest.clone()),
            ..session.entry_for(&session.current_hash(), &cfg)
        };
        crate::daemon::approved_envelope::save(&store, entry.entry_id, &envelope).unwrap();

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert!(
            matches!(decision, UploadDecision::Uploaded { .. }),
            "got {decision:?}"
        );
        assert_eq!(state.uploads_today, 1);
    }

    #[tokio::test]
    async fn an_approved_entry_with_no_recorded_terms_is_re_offered_not_uploaded() {
        // Entries written before the approval terms existed, and approvals
        // taken with no readable config, record nothing. Unknown terms are
        // re-asked, never assumed to still hold.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();
        let entry = session.entry(&session.current_hash());
        assert!(entry.approved_inputs.is_none());

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert_eq!(
            decision,
            UploadDecision::ApprovalStale {
                reason_label: crate::daemon::preview::REASON_INPUTS_CHANGED.to_string(),
            }
        );
        assert_eq!(state.uploads_today, 0);
    }

    #[tokio::test]
    async fn upload_refuses_once_the_enrollment_is_gone() {
        // A cached claim outlives a logout by minutes.
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = crate::config::ContributorConfig {
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
        };
        store.save_config(&cfg).unwrap();
        let entry = session.entry_for(&session.current_hash(), &cfg);
        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();

        // Log out underneath the running context.
        store.wipe().unwrap();

        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert_eq!(
            decision,
            UploadDecision::Refused {
                reason_label: LABEL_NOT_LOGGED_IN.to_string()
            }
        );
        assert_eq!(
            health.last_error_label.as_deref(),
            Some(LABEL_NOT_LOGGED_IN)
        );
        assert_eq!(state.uploads_today, 0);
    }

    #[tokio::test]
    async fn upload_stops_at_the_daily_cap() {
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let device = crate::identity::DeviceIdentity::load_or_generate(&store).unwrap();
        let cfg = crate::config::ContributorConfig {
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
        };
        store.save_config(&cfg).unwrap();

        let entry = session.entry_for(&session.current_hash(), &cfg);
        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        state.roll_day(at("2026-08-08T16:00:00Z"));
        state.uploads_today = 50;
        let mut health = HealthState::default();
        let settings = settings();
        let mut up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let decision = up
            .upload_entry(
                &session.source(),
                &session.session_ref(),
                &entry,
                at("2026-08-08T16:00:00Z"),
            )
            .await
            .unwrap();

        assert_eq!(decision, UploadDecision::CapReached);
        assert_eq!(
            health.last_error_label.as_deref(),
            Some(LABEL_DAILY_CAP_REACHED)
        );
    }

    /// The setup the stored-envelope tests above build inline: a previewed
    /// session whose redacted envelope is on disk and pinned by its entry.
    async fn seeded_stored_envelope(
        session: &GrowingSession,
        store: &ConfigStore,
        cfg: &crate::config::ContributorConfig,
    ) -> (QueueEntry, TraceContributionEnvelope) {
        let (summary, _body, envelope) = crate::daemon::preview::build_preview(
            store,
            Some(cfg),
            None,
            &session.source(),
            &session.session_ref(),
        )
        .await
        .unwrap();
        let entry = QueueEntry {
            previewed_envelope_digest: Some(summary.envelope_digest.clone()),
            ..session.entry_for(&session.current_hash(), cfg)
        };
        crate::daemon::approved_envelope::save(store, entry.entry_id, &envelope).unwrap();
        (entry, envelope)
    }

    /// The verdict must reach the envelope that is actually sent.
    ///
    /// The daemon does not rebuild at upload time -- it sends the stored
    /// bytes -- so a verdict routed through `SubmitOptions` would pass every
    /// fresh-build test and be dropped on exactly this path. That was the
    /// original design error; this test is its regression guard.
    #[tokio::test]
    async fn a_verdict_reaches_a_stored_envelope() {
        use trace_commons_protocol::trace_contribution::TaskSuccess;

        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();
        let (mut entry, _envelope) = seeded_stored_envelope(&session, &store, &cfg).await;
        entry.approved_verdict = Some("failed".to_string());

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let sent = up
            .approved_envelope_for(&entry)
            .expect("load succeeds")
            .expect("an envelope is stored");

        assert_eq!(sent.outcome.task_success, TaskSuccess::Failure);

        // The stored bytes themselves are untouched -- the verdict is
        // stamped on the loaded copy, not written back.
        let on_disk = crate::daemon::approved_envelope::load(&store, entry.entry_id)
            .unwrap()
            .expect("an envelope is stored");
        assert_eq!(on_disk.outcome.task_success, TaskSuccess::Unknown);
    }

    #[tokio::test]
    async fn no_verdict_leaves_a_stored_envelope_unknown() {
        use trace_commons_protocol::trace_contribution::TaskSuccess;

        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();
        let (entry, _envelope) = seeded_stored_envelope(&session, &store, &cfg).await;
        assert_eq!(entry.approved_verdict, None);

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let sent = up
            .approved_envelope_for(&entry)
            .expect("load succeeds")
            .expect("an envelope is stored");

        assert_eq!(sent.outcome.task_success, TaskSuccess::Unknown);
    }

    /// A verdict is a judgement about the task, not content, so it must not
    /// move either consent declaration. #421 pins this for the build path
    /// (`a_verdict_declares_no_content`); this extends it to the daemon
    /// path, where the verdict is stamped onto an already-redacted envelope
    /// and could otherwise disturb flags that were derived before it
    /// arrived.
    #[tokio::test]
    async fn a_verdict_moves_neither_consent_flag_on_a_stored_envelope() {
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();
        let (mut entry, stored) = seeded_stored_envelope(&session, &store, &cfg).await;
        let before = (
            stored.consent.message_text_included,
            stored.consent.tool_payloads_included,
        );
        entry.approved_verdict = Some("failed".to_string());

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        let sent = up
            .approved_envelope_for(&entry)
            .expect("load succeeds")
            .expect("an envelope is stored");

        assert_eq!(
            (
                sent.consent.message_text_included,
                sent.consent.tool_payloads_included
            ),
            before,
            "a verdict is not content and must not move a consent declaration"
        );
    }

    /// The digest check guards this crate's own storage and must keep
    /// running against the bytes AS STORED. A verdict applied before it
    /// would make a tampered file pass.
    #[tokio::test]
    async fn a_tampered_stored_envelope_is_still_refused_with_a_verdict_present() {
        let session = GrowingSession::new();
        let (_d, store) = temp_store();
        let cfg = fixture_cfg(&store);
        store.save_config(&cfg).unwrap();
        let (mut entry, _envelope) = seeded_stored_envelope(&session, &store, &cfg).await;
        entry.approved_verdict = Some("worked".to_string());
        entry.previewed_envelope_digest = Some("0".repeat(64));

        let opts = dry_run_opts();
        let mut ctx = SubmitContext::new(&store, &cfg, &opts, None).unwrap();
        let mut state = DaemonState::new();
        let mut health = HealthState::default();
        let settings = settings();
        let up = Uploader {
            ctx: &mut ctx,
            store: &store,
            settings: &settings,
            state: &mut state,
            health: &mut health,
        };
        assert!(up.approved_envelope_for(&entry).is_err());
    }
}
