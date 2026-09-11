// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TraceCommons server-owned database facade.

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::DatabaseConfig;
use crate::error::DatabaseError;
use crate::trace_corpus_storage::{
    TraceCorpusStore, TraceCreditSettlementBatchWrite, TraceNearCreditOutboxItemWrite,
};
use crate::trace_invite_registry::InviteTenantMode;

pub mod postgres;

mod trace_corpus_common;
mod trace_corpus_pg;

pub use postgres::InviteRedemption;

/// Insert payload for an invite grant. Mirrors `InviteEntry` minus
/// `revoked_at`, which is only ever set by `revoke_invite_grant`.
#[derive(Debug, Clone)]
pub struct InviteGrantWrite {
    pub invite_subject_hash: String,
    pub policy_label: String,
    pub tenant_mode: InviteTenantMode,
    pub fixed_tenant_id: Option<String>,
    pub tenant_template_id: Option<String>,
    pub policy_version: String,
    pub allowed_consent_scopes: Vec<String>,
    pub allowed_uses: Vec<String>,
    pub max_uses: u32,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub issuance_source: String,
    pub issued_by_label: Option<String>,
    pub credential_binding_hash: Option<String>,
    pub note_label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteGrantInsertOutcome {
    Inserted,
    /// The partial unique index refused the write: this credential already has
    /// a live invite in this pool.
    CredentialAlreadyBound,
    /// An invite with this hash already exists. Makes the file import
    /// idempotent.
    AlreadyExists,
}

/// Safe structural diagnostics for PostgreSQL TraceCommons RLS readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceCorpusRlsDiagnostics {
    pub expected_table_count: usize,
    pub rls_enabled_count: usize,
    pub force_rls_enabled_count: usize,
    pub policy_installed_count: usize,
    pub missing_policy_tables: Vec<String>,
    pub rls_disabled_tables: Vec<String>,
    pub force_rls_disabled_tables: Vec<String>,
    pub policy_expression_mismatch_tables: Vec<String>,
    pub current_role_hash: String,
    pub current_role_bypasses_rls: bool,
    pub current_role_owns_trace_tables: bool,
    pub tenant_context_transaction_local: bool,
}

impl TraceCorpusRlsDiagnostics {
    pub fn rls_ready(&self) -> bool {
        self.missing_policy_tables.is_empty()
            && self.rls_disabled_tables.is_empty()
            && self.policy_expression_mismatch_tables.is_empty()
            && self.policy_installed_count == self.expected_table_count
            && self.rls_enabled_count == self.expected_table_count
            && !self.current_role_bypasses_rls
            && !self.current_role_owns_trace_tables
            && self.tenant_context_transaction_local
    }

    pub fn force_rls_ready(&self) -> bool {
        self.force_rls_disabled_tables.is_empty()
            && self.force_rls_enabled_count == self.expected_table_count
    }

    pub fn production_ready(&self) -> bool {
        self.rls_ready() && self.force_rls_ready()
    }

    pub fn runtime_role_matches_expected_hash(&self, expected_hash: Option<&str>) -> bool {
        expected_hash.is_none_or(|expected_hash| self.current_role_hash == expected_hash)
    }

    pub fn production_ready_with_expected_runtime_role(&self, expected_hash: Option<&str>) -> bool {
        self.production_ready() && self.runtime_role_matches_expected_hash(expected_hash)
    }
}

/// Session-level Postgres advisory lock guarding the NEAR settlement SUBMIT
/// pass for a single tenant. The lock is held on a dedicated pooled connection
/// for the full duration of a submit run — across the external submitter call
/// and the `pending -> submitted/failed` status writes — so two overlapping
/// submit runs (e.g. a scheduler tick racing a manual worker POST) can never
/// both invoke the external submitter for the same outbox row (money-path
/// double-submit). The lock is independent of RLS / tenant transactions.
///
/// MUST be released by calling [`NearCreditSubmitAdvisoryLock::release`] when the
/// pass completes; the connection is then returned to the pool. `Drop` is a
/// best-effort safety net only (it cannot run async unlock), so callers are
/// responsible for the explicit release on every path.
pub struct NearCreditSubmitAdvisoryLock {
    inner: Option<crate::db::postgres::NearCreditSubmitAdvisoryLockInner>,
}

impl NearCreditSubmitAdvisoryLock {
    pub(crate) fn new(inner: crate::db::postgres::NearCreditSubmitAdvisoryLockInner) -> Self {
        Self { inner: Some(inner) }
    }

    /// Release the advisory lock and return the connection to the pool. Idempotent.
    pub async fn release(mut self) -> Result<(), DatabaseError> {
        if let Some(inner) = self.inner.take() {
            inner.release().await
        } else {
            Ok(())
        }
    }
}

impl Drop for NearCreditSubmitAdvisoryLock {
    fn drop(&mut self) {
        if self.inner.is_some() {
            // Safety net: the lock guard was dropped without an explicit
            // `release().await`. The session-level lock will linger on the
            // recycled connection until the backend session ends or the
            // connection is reset. Log hash-free so operators can spot the leak.
            tracing::warn!(
                "NEAR credit submit advisory lock dropped without explicit release; \
                 connection-scoped lock may linger until session reset"
            );
        }
    }
}

/// Session-level Postgres advisory lock guarding a live credit-settlement
/// finalize for a single tenant. Prevents two overlapping settlement runs from
/// both passing the source-event conflict check and writing divergent batches
/// (and partial outbox rows) for the same credits. Independent of the submit
/// lock classid / namespace.
///
/// MUST be released via [`CreditSettlementAdvisoryLock::release`].
pub struct CreditSettlementAdvisoryLock {
    inner: Option<crate::db::postgres::CreditSettlementAdvisoryLockInner>,
}

impl CreditSettlementAdvisoryLock {
    pub(crate) fn new(inner: crate::db::postgres::CreditSettlementAdvisoryLockInner) -> Self {
        Self { inner: Some(inner) }
    }

    /// Release the advisory lock and return the connection to the pool. Idempotent.
    pub async fn release(mut self) -> Result<(), DatabaseError> {
        if let Some(inner) = self.inner.take() {
            inner.release().await
        } else {
            Ok(())
        }
    }
}

impl Drop for CreditSettlementAdvisoryLock {
    fn drop(&mut self) {
        if self.inner.is_some() {
            tracing::warn!(
                "credit settlement advisory lock dropped without explicit release; \
                 connection-scoped lock may linger until session reset"
            );
        }
    }
}

#[async_trait]
pub trait Database: TraceCorpusStore + Send + Sync {
    async fn get_near_provisioned_anchor(
        &self,
        _tenant_id: &str,
        _principal_ref: &str,
    ) -> Result<Option<String>, DatabaseError> {
        Err(DatabaseError::Pool("near_provisioning_unconfigured".into()))
    }
    async fn admission_runtime_ready(&self) -> Result<bool, DatabaseError> {
        Err(DatabaseError::Pool("admission_database_unavailable".into()))
    }
    async fn lookup_completed_submission_admission(
        &self,
        _tenant: &str,
        _anchor: &str,
        _submission: uuid::Uuid,
        _body_hash: &str,
    ) -> Result<bool, DatabaseError> {
        Err(DatabaseError::Pool("admission_database_unavailable".into()))
    }
    async fn acquire_admission_processing_lock(
        &self,
        _tenant: &str,
        _submission: uuid::Uuid,
    ) -> Result<Option<crate::admission_ledger::AdmissionProcessingGuard>, DatabaseError> {
        Err(DatabaseError::Pool("admission_database_unavailable".into()))
    }
    async fn prune_onboarding_expiry(
        &self,
        _tenant: &str,
        _limit: i32,
        _dry_run: bool,
    ) -> Result<u64, DatabaseError> {
        Err(DatabaseError::Pool(
            "onboarding_retention_unavailable".into(),
        ))
    }
    async fn issue_admission_challenge(
        &self,
        _tenant: &str,
        _anchor: &str,
        _challenge: &str,
        _expires: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool("admission_database_unavailable".into()))
    }
    async fn reserve_submission_admission(
        &self,
        _request: &crate::admission_ledger::AdmissionReservation,
    ) -> Result<crate::admission_ledger::AdmissionDecision, DatabaseError> {
        Err(DatabaseError::Pool("admission_database_unavailable".into()))
    }
    async fn transition_submission_admission(
        &self,
        _tenant: &str,
        _submission: uuid::Uuid,
        _lease: uuid::Uuid,
        _next: &str,
    ) -> Result<bool, DatabaseError> {
        Err(DatabaseError::Pool("admission_database_unavailable".into()))
    }

    async fn run_migrations(&self) -> Result<(), DatabaseError>;

    /// Try to acquire the per-tenant NEAR settlement submit advisory lock without
    /// blocking. Returns `Ok(Some(guard))` if acquired (caller may proceed and
    /// MUST `release()` it), or `Ok(None)` if another submit run already holds it
    /// (caller must no-op). Default impl returns `Ok(None)` (no serialization
    /// available), which is fail-closed for the submit worker.
    async fn try_acquire_near_credit_submit_lock(
        &self,
        _tenant_id: &str,
    ) -> Result<Option<NearCreditSubmitAdvisoryLock>, DatabaseError> {
        Ok(None)
    }

    /// Try to acquire the per-tenant live credit-settlement advisory lock without
    /// blocking. Returns `Ok(Some(guard))` if acquired (caller MUST `release()`),
    /// or `Ok(None)` if another settlement run already holds it. Default returns
    /// `Ok(None)` so callers without Postgres serialization refuse to race.
    async fn try_acquire_credit_settlement_lock(
        &self,
        _tenant_id: &str,
    ) -> Result<Option<CreditSettlementAdvisoryLock>, DatabaseError> {
        Ok(None)
    }

    /// Atomically persist a finalized settlement batch together with every NEAR
    /// outbox row it expects. Default falls back to sequential upserts (not
    /// crash-atomic across statements); Postgres overrides this with one
    /// tenant-scoped transaction so a process death cannot leave a finalized
    /// batch without its payout work.
    async fn upsert_credit_settlement_finalize(
        &self,
        batch: TraceCreditSettlementBatchWrite,
        outbox_items: Vec<TraceNearCreditOutboxItemWrite>,
    ) -> Result<(), DatabaseError> {
        self.upsert_trace_credit_settlement_batch(batch).await?;
        for item in outbox_items {
            self.upsert_trace_near_credit_outbox_item(item).await?;
        }
        Ok(())
    }

    async fn trace_corpus_rls_diagnostics(
        &self,
    ) -> Result<Option<TraceCorpusRlsDiagnostics>, DatabaseError> {
        Ok(None)
    }

    /// Upsert a contributor's public profile (display handle + optional bio).
    /// Creates a row if none exists for `(tenant_id, principal_ref)`; otherwise
    /// updates handle/bio and bumps `update_count` + `last_updated_at`. Always
    /// clears `withdrawn_at` so a withdrawn contributor can re-opt-in.
    ///
    /// Caller is responsible for handle/bio validation. The unique
    /// `(tenant_id, handle_normalized)` constraint may surface as
    /// [`DatabaseError`] when a different principal already claimed the
    /// handle; callers should map that to a 409 conflict.
    async fn upsert_contributor_profile(
        &self,
        _tenant_id: &str,
        _principal_ref: &str,
        _display_handle: &str,
        _handle_normalized: &str,
        _bio: Option<&str>,
    ) -> Result<ContributorProfileRow, DatabaseError> {
        Err(DatabaseError::Pool(
            "upsert_contributor_profile not implemented".to_string(),
        ))
    }

    /// Soft-delete by stamping `withdrawn_at = NOW()`, enqueue a coalesced
    /// community-snapshot invalidation for `(window_label, metric)`, and
    /// record an eviction receipt — all in one transaction.
    ///
    /// Idempotent: returns `Ok(None)` when no active profile row exists for
    /// `(tenant_id, principal_ref)`. A successful withdrawal returns the
    /// eviction receipt so callers can audit that the published surface was
    /// asked to drop the contributor.
    async fn withdraw_contributor_profile(
        &self,
        _tenant_id: &str,
        _principal_ref: &str,
        _window_label: &str,
        _metric: &str,
    ) -> Result<Option<CommunityWithdrawalEvictionRow>, DatabaseError> {
        Err(DatabaseError::Pool(
            "withdraw_contributor_profile not implemented".to_string(),
        ))
    }

    /// Latest undrained community-snapshot invalidation watermark, if any.
    /// Public reads refuse snapshots whose `computed_at` is strictly before
    /// this instant.
    async fn pending_community_snapshot_invalidation(
        &self,
        _window_label: &str,
        _metric: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, DatabaseError> {
        Err(DatabaseError::Pool(
            "pending_community_snapshot_invalidation not implemented".to_string(),
        ))
    }

    /// Clear a pending invalidation after a snapshot whose `computed_at` is
    /// at or after the pending watermark has been written. Returns `true`
    /// when a pending row was drained. Concurrent withdrawals that land
    /// after `snapshot_computed_at` leave the pending flag set.
    async fn drain_community_snapshot_invalidation(
        &self,
        _window_label: &str,
        _metric: &str,
        _snapshot_id: uuid::Uuid,
        _snapshot_computed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, DatabaseError> {
        Err(DatabaseError::Pool(
            "drain_community_snapshot_invalidation not implemented".to_string(),
        ))
    }

    /// Append an audit row for any profile mutation (opt_in / update /
    /// withdraw / rejected). Caller passes the action verb and any
    /// human-readable reason that is safe to surface back to the
    /// contributor.
    async fn append_contributor_profile_audit(
        &self,
        _tenant_id: &str,
        _principal_ref: &str,
        _action: &str,
        _handle_normalized: Option<&str>,
        _reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "append_contributor_profile_audit not implemented".to_string(),
        ))
    }

    /// Compute the per-contributor leaderboard inputs for the given
    /// community tenant set and window. Implementations set the RLS tenant
    /// GUC for each tenant, so aggregation still respects per-table RLS.
    /// Applies the `min_cell_count` threshold at the SQL level —
    /// contributors with fewer than `min_cell_count` accepted submissions
    /// in-window are not returned. Noise / privacy-budget integration is
    /// deferred to a follow-up slice.
    async fn compute_leaderboard_inputs(
        &self,
        _window_days: i32,
        _min_cell_count: i64,
        _tenant_ids: &[String],
    ) -> Result<Vec<LeaderboardContributorRow>, DatabaseError> {
        Err(DatabaseError::Pool(
            "compute_leaderboard_inputs not implemented".to_string(),
        ))
    }

    /// Compute the corpus-wide aggregate summary for the given community
    /// tenant set and window. Crosses tenants the same way
    /// `compute_leaderboard_inputs` does.
    async fn compute_corpus_analytics_summary(
        &self,
        _window_days: i32,
        _tenant_ids: &[String],
    ) -> Result<CorpusAnalyticsSummary, DatabaseError> {
        Err(DatabaseError::Pool(
            "compute_corpus_analytics_summary not implemented".to_string(),
        ))
    }

    /// All-time totals for the public register-stats aggregate. Crosses
    /// tenants the same way `compute_leaderboard_inputs` and
    /// `compute_corpus_analytics_summary` do: per-tenant transactions under
    /// the RLS tenant GUC, never a raw cross-tenant query and never
    /// `BYPASSRLS`.
    ///
    /// `configured_tenant_ids` is the same escape hatch
    /// `compute_leaderboard_inputs` / `compute_corpus_analytics_summary`
    /// take: when non-empty, enumerate exactly those tenants; when empty,
    /// fall back to `SELECT tenant_id FROM trace_tenants`. That fallback
    /// query carries no tenant GUC, and `trace_tenants` is itself
    /// FORCE-RLS'd on `tenant_id = trace_current_tenant_id()` -- so under a
    /// NOBYPASSRLS runtime role with no tenant context, it silently returns
    /// zero rows rather than erroring. Implementations MUST refuse
    /// (`Err`) rather than compute totals when the resolved tenant list is
    /// empty: a zero here is indistinguishable from "the register really
    /// has nothing" and from "RLS ate the enumeration," and only the first
    /// is safe to publish. (This is why a superuser-connected pg test
    /// cannot exercise the failure mode this guards against -- the owning
    /// test principal bypasses the RLS that would otherwise produce it.)
    async fn compute_register_stats_totals(
        &self,
        _configured_tenant_ids: &[String],
    ) -> Result<RegisterStatsTotals, DatabaseError> {
        Err(DatabaseError::Pool(
            "compute_register_stats_totals not implemented".to_string(),
        ))
    }

    /// Read the `trace_register_stats` singleton row as it stands.
    async fn fetch_register_stats_row(&self) -> Result<RegisterStatsRow, DatabaseError> {
        Err(DatabaseError::Pool(
            "fetch_register_stats_row not implemented".to_string(),
        ))
    }

    /// Read the same singleton row, but under the dedicated
    /// `trace_commons_public_read` role, for the unauthenticated public
    /// endpoint.
    ///
    /// Separate from [`Database::fetch_register_stats_row`] on purpose. That
    /// one runs as the ordinary runtime role, which reaches this row through
    /// the unscoped `trace_register_stats_runtime_read` policy and could
    /// reach every other table besides. The unauthenticated path takes the
    /// least-privileged route V55 built for it: a NOBYPASSRLS role holding
    /// one column-scoped SELECT grant and nothing else, so a mistake in this
    /// handler cannot become a read of anything but six aggregate columns.
    async fn fetch_register_stats_row_as_public_read(
        &self,
    ) -> Result<RegisterStatsRow, DatabaseError> {
        Err(DatabaseError::Pool(
            "fetch_register_stats_row_as_public_read not implemented".to_string(),
        ))
    }

    /// Write freshly computed totals into the `trace_register_stats`
    /// singleton row, stamping both `as_of` and `refreshed_at` to now, and
    /// clearing `withheld`. Returns the row as written.
    async fn write_register_stats_row(
        &self,
        _totals: RegisterStatsTotals,
    ) -> Result<RegisterStatsRow, DatabaseError> {
        Err(DatabaseError::Pool(
            "write_register_stats_row not implemented".to_string(),
        ))
    }

    /// Insert a pre-rendered leaderboard snapshot. `contents_jsonb` is
    /// the wire-shape payload the read endpoints will serve verbatim.
    async fn insert_leaderboard_snapshot(
        &self,
        _snapshot: LeaderboardSnapshotWrite,
    ) -> Result<LeaderboardSnapshotRow, DatabaseError> {
        Err(DatabaseError::Pool(
            "insert_leaderboard_snapshot not implemented".to_string(),
        ))
    }

    /// Drop all but the `keep` most recent snapshots for a window/metric,
    /// returning how many rows were removed.
    ///
    /// Only the newest snapshot is ever served, but older ones are the
    /// record of what was published and under which privacy controls, so
    /// this trims rather than truncates. It exists because recompute went
    /// from an occasional manual action to a scheduled one: at a 60s
    /// interval an unpruned table gains on the order of half a million
    /// rows a year, each carrying a full JSON payload.
    async fn prune_leaderboard_snapshots(
        &self,
        _window_label: &str,
        _metric: &str,
        _keep: i64,
    ) -> Result<u64, DatabaseError> {
        Err(DatabaseError::Pool(
            "prune_leaderboard_snapshots not implemented".to_string(),
        ))
    }

    /// Fetch the most recent snapshot matching `(window_label, metric)`.
    /// Returns `Ok(None)` if no snapshot has ever been computed.
    async fn latest_leaderboard_snapshot(
        &self,
        _window_label: &str,
        _metric: &str,
    ) -> Result<Option<LeaderboardSnapshotRow>, DatabaseError> {
        Err(DatabaseError::Pool(
            "latest_leaderboard_snapshot not implemented".to_string(),
        ))
    }

    async fn insert_device_key(
        &self,
        _device_key: DeviceKeyWrite,
    ) -> Result<DeviceKeyRecord, DatabaseError> {
        Err(DatabaseError::Pool(
            "insert_device_key not implemented".to_string(),
        ))
    }

    async fn get_device_key(
        &self,
        _tenant_id: &str,
        _device_key_id: &str,
    ) -> Result<Option<DeviceKeyRecord>, DatabaseError> {
        Err(DatabaseError::Pool(
            "get_device_key not implemented".to_string(),
        ))
    }

    async fn list_device_keys(
        &self,
        _tenant_id: &str,
    ) -> Result<Vec<DeviceKeyRecord>, DatabaseError> {
        Err(DatabaseError::Pool(
            "list_device_keys not implemented".to_string(),
        ))
    }

    async fn revoke_device_key(
        &self,
        _tenant_id: &str,
        _device_key_id: &str,
    ) -> Result<Option<DeviceKeyRecord>, DatabaseError> {
        Err(DatabaseError::Pool(
            "revoke_device_key not implemented".to_string(),
        ))
    }

    async fn onboard_device_key(
        &self,
        _device_key: DeviceKeyWrite,
        _max_uses: i32,
    ) -> Result<OnboardDeviceKeyRecord, OnboardDeviceKeyError> {
        Err(OnboardDeviceKeyError::Database(DatabaseError::Pool(
            "onboard_device_key not implemented".to_string(),
        )))
    }

    /// Provision a tenant for an instance user (no-account fallback path).
    ///
    /// In a single tenant-scoped transaction, this op:
    /// 1. Ensures the `trace_tenants` row exists.
    /// 2. Stamps the contribution policy from the supplied template
    ///    (`ON CONFLICT (tenant_id) DO NOTHING` — never overwrites an existing policy).
    /// 3. Registers the device key (`ON CONFLICT (device_key_id) DO NOTHING`).
    ///
    /// The operation is fully idempotent: re-running with the same inputs is safe.
    async fn enroll_instance_user(&self, p: InstanceUserProvision) -> Result<(), DatabaseError>;

    /// Atomically deduplicate a user enrollment against `trace_instance_enrollments`
    /// and enforce a per-instance cap.
    ///
    /// The op runs in one instance-scoped transaction (setting
    /// `trace_commons.instance_subject` transaction-locally). It first checks
    /// for an existing `(instance_subject_hash, user_subject_hash)` row — if
    /// found, it returns `ExistingUser` without consuming cap. Otherwise it
    /// count-checks the cap before inserting with `ON CONFLICT DO NOTHING`.
    ///
    /// **Race note:** a concurrent burst of DISTINCT new users could each read
    /// `count < cap` and all insert, overshooting the cap by the concurrency
    /// width. For the pilot's per-instance rate limit this is acceptable. If
    /// strict capping is later required, take an advisory lock on
    /// `hashtext(instance_subject_hash)` at the top of the transaction.
    ///
    async fn reserve_instance_enrollment(
        &self,
        instance_subject_hash: &str,
        user_subject_hash: &str,
        tenant_id: &str,
        max_enrollments: i64,
    ) -> Result<InstanceEnrollmentOutcome, DatabaseError>;

    /// Verify the V35 instance-enrollment ledger has forced row-level security
    /// and its `trace_instance_isolation` policy installed. The ledger isolates
    /// on the INSTANCE predicate (`trace_current_instance_subject()`), not the
    /// tenant predicate, so it is intentionally absent from the tenant RLS
    /// diagnostics; this check lets the production-readiness gate catch RLS drift
    /// on the ledger. Returns `false` (fail-closed) if either control is missing.
    async fn instance_ledger_rls_ready(&self) -> Result<bool, DatabaseError>;

    /// Create-or-reuse the durable account for `principal_ref` within `tenant_id`.
    /// Returns the stable `account_id`. Idempotent: repeated calls for the same
    /// active principal return the same account. Tolerates a concurrent racing
    /// mint by re-selecting after an `ON CONFLICT DO NOTHING` link insert.
    async fn create_or_reuse_account(
        &self,
        _tenant_id: &str,
        _principal_ref: &str,
    ) -> Result<uuid::Uuid, DatabaseError> {
        Err(DatabaseError::Pool(
            "create_or_reuse_account not implemented".to_string(),
        ))
    }

    /// Batched principal->account resolution. Returns a map from each
    /// `principal_ref` that has an ACTIVE link (`unlinked_at IS NULL`) within
    /// `tenant_id` to its `account_id`. Principals with no active link (never
    /// linked, unlinked, or absent) are omitted from the map. An empty input
    /// slice yields an empty map. Used by the credit-view and settlement re-key
    /// paths to fold per-principal rows up to their durable account.
    async fn resolve_principals_to_accounts(
        &self,
        _tenant_id: &str,
        _principal_refs: &[String],
    ) -> Result<std::collections::HashMap<String, uuid::Uuid>, DatabaseError> {
        Err(DatabaseError::Pool(
            "resolve_principals_to_accounts not implemented".to_string(),
        ))
    }

    /// Count this principal's outstanding (unconsumed, unexpired) login links.
    /// Used by the mint endpoint to cap per-principal outstanding links.
    async fn count_outstanding_login_links(
        &self,
        _tenant_id: &str,
        _created_principal_ref: &str,
    ) -> Result<i64, DatabaseError> {
        Err(DatabaseError::Pool(
            "count_outstanding_login_links not implemented".to_string(),
        ))
    }

    /// Insert a single-use login link. Stores ONLY the `code_hash`
    /// (sha256:-shaped); the raw code never reaches the database.
    async fn insert_login_link(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _code_hash: &str,
        _created_principal_ref: &str,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "insert_login_link not implemented".to_string(),
        ))
    }

    /// Append a hash-only / label-only row to `trace_account_audit`. Actor and
    /// metadata MUST be reserved-prefix or hash-shaped; never raw codes/URLs.
    async fn append_account_audit(
        &self,
        _tenant_id: &str,
        _action: &str,
        _actor_ref: &str,
        _outcome: &str,
        _safe_metadata: serde_json::Value,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "append_account_audit not implemented".to_string(),
        ))
    }

    /// Resolve the tenant for a login `code_hash` via the NARROW restricted-role
    /// resolver pool (separate role, column-scoped SELECT, no BYPASSRLS).
    /// Returns the tenant only. Fail-closed: an unconfigured resolver pool MUST
    /// error with a safe missing-control name, never fall back to the runtime
    /// pool. The caller re-confirms tenant inside an RLS-scoped tx before any
    /// write.
    async fn resolve_login_link_tenant(
        &self,
        _code_hash: &str,
    ) -> Result<Option<String>, DatabaseError> {
        Err(DatabaseError::Pool(
            "resolve_login_link_tenant not implemented".to_string(),
        ))
    }

    /// Resolve the tenant for a WebAuthn `credential_id` via the SAME NARROW
    /// restricted-role resolver pool used by `resolve_login_link_tenant` (separate
    /// role, column-scoped SELECT, no BYPASSRLS). Returns the tenant ONLY. The
    /// discoverable-login path (Task 6) calls this with the credential id parsed
    /// from an UNAUTHENTICATED assertion, BEFORE any tenant context exists, then
    /// re-confirms tenant inside an RLS-scoped tx via
    /// `load_webauthn_credential_for_login`. Fail-closed: an unconfigured resolver
    /// pool MUST error with a safe missing-control name, never fall back to the
    /// runtime pool. NO `ensure_trace_tenant` here: this is a pure read on a
    /// globally-UNIQUE column and MUST NOT write any tenant row for a forged id.
    async fn resolve_credential_tenant(
        &self,
        _credential_id: &str,
    ) -> Result<Option<String>, DatabaseError> {
        Err(DatabaseError::Pool(
            "resolve_credential_tenant not implemented".to_string(),
        ))
    }

    /// Resolve a NEAR access public_key to its tenant via the column-scoped,
    /// restricted-role resolver pool, exactly as `resolve_credential_tenant` does
    /// for webauthn credentials. Returns the tenant ONLY. The NEAR-login path
    /// (Task 7) calls this with the public_key parsed from an UNAUTHENTICATED,
    /// wallet-signed assertion, BEFORE any tenant context exists, then re-confirms
    /// tenant inside an RLS-scoped tx. Fail-closed: an unconfigured resolver pool
    /// MUST error with a safe missing-control name, never fall back to the runtime
    /// pool. NO `ensure_trace_tenant` here: this is a pure read on a
    /// globally-UNIQUE column and MUST NOT write any tenant row for a forged key.
    async fn store_near_provisioning_ceremony(
        &self,
        _ceremony_hash: &str,
        _pending: crate::account_onboarding::NativeProvisioningPending,
        _expires_at: i64,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool("near_provisioning_unconfigured".into()))
    }

    async fn take_near_provisioning_ceremony(
        &self,
        _ceremony_hash: &str,
    ) -> Result<Option<crate::account_onboarding::NativeProvisioningPending>, DatabaseError> {
        Err(DatabaseError::Pool("near_provisioning_unconfigured".into()))
    }

    /// `identity` is not optional and has no default: a backend that cannot be
    /// handed a pepper and an account-name key must not provision, because the
    /// alternative is an anchor computed from public inputs alone -- the exact
    /// defect the salted scheme exists to remove.
    async fn provision_verified_near_account(
        &self,
        _proof: crate::account_onboarding::VerifiedNearProvisioning,
        _session: NewSession<'_>,
        _identity: &crate::near_account_identity::NearAccountIdentity,
    ) -> Result<crate::account_onboarding::ProvisionedNearAccount, DatabaseError> {
        Err(DatabaseError::Pool("near_provisioning_unconfigured".into()))
    }

    /// Store a NEAR AI login ceremony (#836). Fail-closed by default, like
    /// its wallet sibling.
    async fn store_near_ai_login_ceremony(
        &self,
        _ceremony_hash: &str,
        _pending: &crate::account_onboarding::NearAiLoginPending,
        _expires_at: i64,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "near_ai_login_provisioning_unconfigured".into(),
        ))
    }

    /// Consume a NEAR AI login ceremony. Single use: a second take of the same
    /// handle answers `None`.
    async fn take_near_ai_login_ceremony(
        &self,
        _ceremony_hash: &str,
    ) -> Result<Option<crate::account_onboarding::NearAiLoginPending>, DatabaseError> {
        Err(DatabaseError::Pool(
            "near_ai_login_provisioning_unconfigured".into(),
        ))
    }

    /// Provision from a verified NEAR AI login (#836).
    ///
    /// The default refuses, like its wallet sibling: a backend that has not
    /// implemented this has not configured login provisioning, and the
    /// fail-closed answer is the only safe one for a path that mints an
    /// admission anchor.
    async fn provision_near_ai_login(
        &self,
        _login: &crate::near_ai_login::VerifiedNearAiLogin,
        _device_public_key: &[u8; 32],
        _session: NewSession<'_>,
        _identity: &crate::near_account_identity::NearAccountIdentity,
    ) -> Result<crate::account_onboarding::ProvisionedNearAccount, DatabaseError> {
        Err(DatabaseError::Pool(
            "near_ai_login_provisioning_unconfigured".into(),
        ))
    }

    async fn resolve_near_public_key_tenant(
        &self,
        _public_key: &str,
    ) -> Result<Option<String>, DatabaseError> {
        Err(DatabaseError::Pool(
            "resolve_near_public_key_tenant not implemented".to_string(),
        ))
    }

    /// Atomically redeem a single-use login link: consume + session insert +
    /// audit insert in ONE RLS-scoped transaction, so redeem is all-or-nothing.
    ///
    /// The conditional consume UPDATE is ALWAYS executed (never a
    /// SELECT-then-branch): unknown / expired / already-consumed / wrong-tenant
    /// codes all affect zero rows → `Ok(None)`, and the transaction commits with
    /// nothing changed, leaving the link UNconsumed and retryable. On a winning
    /// consume, the session row (hash-only `session_token_hash`) and the hash-only
    /// audit row are inserted and the whole transaction commits together; any
    /// failure rolls everything back (link stays reusable, no orphaned session, no
    /// un-audited state change). The `tenant_id = trace_current_tenant_id()`
    /// predicate is belt-and-suspenders on top of RLS. The raw code and the raw
    /// session secret never reach the database. `session_id` is server-assigned.
    async fn redeem_login_link(
        &self,
        _tenant_id: &str,
        _code_hash: &str,
        _session: NewSession<'_>,
        _audit: RedeemAudit,
    ) -> Result<Option<RedeemedSession>, DatabaseError> {
        Err(DatabaseError::Pool(
            "redeem_login_link not implemented".to_string(),
        ))
    }

    /// Validate a browser session by its `token_hash` (sha256 of the secret part
    /// of the cookie, NOT the whole cookie value) under the caller-asserted
    /// `tenant_id`. Inside an RLS-scoped tx: select the account for a session
    /// that is unexpired, not revoked, and seen within the idle cap, matching
    /// either the CURRENT `token_hash` or a within-grace previous token. On a hit,
    /// bump `last_seen_at` and return the account id together with the session's
    /// `auth_credential_id`. When the matched row aged past the rotation interval
    /// AND the request matched the current token, mint a new secret in the same tx
    /// (rotate `token_hash`, set `prev_token_hash`/`prev_token_valid_until`,
    /// reset `token_issued_at`) and return it as `rotated_secret`. A within-grace
    /// previous-token match does NOT re-rotate. On a miss (including an
    /// idle-capped row, which is auto-revoked) return `None`. Any store/DB error
    /// surfaces as `Err`; callers MUST treat both `None` and `Err` as a denial.
    ///
    /// Safety of the client-supplied tenant: `token_hash` is globally UNIQUE and
    /// bound to exactly one real `(tenant, account, session)`. A forged or
    /// mismatched tenant simply scopes the RLS lookup to a tenant where this
    /// hash does not exist, so it finds no row and fails closed.
    async fn validate_session(
        &self,
        _tenant_id: &str,
        _token_hash: &str,
    ) -> Result<Option<ValidatedSession>, DatabaseError> {
        Err(DatabaseError::Pool(
            "validate_session not implemented".to_string(),
        ))
    }

    /// Revoke the CURRENT browser session identified by its `token_hash` (sha256
    /// of the secret part of the cookie). Idempotent: an already-revoked or
    /// unknown hash affects zero rows. Returns the number of rows revoked (0 or 1).
    /// The `tenant_id = trace_current_tenant_id()` predicate is belt-and-suspenders
    /// on top of forced RLS; `token_hash` is globally UNIQUE.
    async fn revoke_current_session(
        &self,
        _tenant_id: &str,
        _token_hash: &str,
    ) -> Result<u64, DatabaseError> {
        Err(DatabaseError::Pool(
            "revoke_current_session not implemented".to_string(),
        ))
    }

    /// Revoke ALL live sessions belonging to `account_id` (sign-out-everywhere).
    /// Only the caller's own account is ever affected: the caller passes an
    /// auth-derived `account_id` and the UPDATE is tenant- + account-scoped under
    /// forced RLS. Returns the number of sessions revoked.
    async fn revoke_all_account_sessions(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
    ) -> Result<u64, DatabaseError> {
        Err(DatabaseError::Pool(
            "revoke_all_account_sessions not implemented".to_string(),
        ))
    }

    /// Resolve the active account a device `principal_ref` is linked to (bearer
    /// path). Active-membership only (`unlinked_at IS NULL`, Hardening A). `None`
    /// when the principal is unlinked or links to no account.
    async fn resolve_account_for_principal(
        &self,
        _tenant_id: &str,
        _principal_ref: &str,
    ) -> Result<Option<uuid::Uuid>, DatabaseError> {
        Err(DatabaseError::Pool(
            "resolve_account_for_principal not implemented".to_string(),
        ))
    }

    /// Expand an account's ACTIVE principal memberships — the ONLY sanctioned
    /// ownership-bearing expansion (Hardening A). MUST filter `unlinked_at IS
    /// NULL`; an unlinked principal is absent from the returned set. Returns the
    /// `AccountPrincipalSet` newtype directly so the only mint site for an
    /// ownership-bearing set stays inside this crate (Hardening C); callers in
    /// the bins cannot construct one themselves.
    async fn expand_account_principals(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
    ) -> Result<crate::account_session::AccountPrincipalSet, DatabaseError> {
        Err(DatabaseError::Pool(
            "expand_account_principals not implemented".to_string(),
        ))
    }

    /// Insert a registered passkey for `account_id`. The serialized webauthn-rs
    /// `Passkey` (public key, sign counter, AAGUID, transports) is stored as
    /// JSONB; `credential_id` is the globally-UNIQUE base64url WebAuthn id and
    /// `label` is an optional user-supplied display name. Tenant- + account-
    /// scoped under forced RLS.
    async fn insert_webauthn_credential(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _credential_id: &str,
        _passkey: &serde_json::Value,
        _label: Option<&str>,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "insert_webauthn_credential not implemented".to_string(),
        ))
    }

    /// Load an ACTIVE credential for the LOGIN (assertion) path by its
    /// `credential_id`, under the already-resolved `tenant_id`. Returns the
    /// account id and serialized `Passkey` JSON, or `None` for an unknown /
    /// revoked / other-tenant credential. Runs inside an RLS-scoped tx; the
    /// `tenant_id = trace_current_tenant_id()` predicate is belt-and-suspenders
    /// on top of forced RLS, and `credential_id` is globally UNIQUE.
    async fn load_webauthn_credential_for_login(
        &self,
        _tenant_id: &str,
        _credential_id: &str,
    ) -> Result<Option<WebauthnCredentialRow>, DatabaseError> {
        Err(DatabaseError::Pool(
            "load_webauthn_credential_for_login not implemented".to_string(),
        ))
    }

    /// Persist the post-finish `Passkey` after a successful assertion so the
    /// updated sign counter (clone-detection state) is durable, and stamp
    /// `last_used_at`. Tenant-scoped under forced RLS; only an active
    /// (unrevoked) credential is updated.
    async fn update_webauthn_credential_after_login(
        &self,
        _tenant_id: &str,
        _credential_id: &str,
        _passkey: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "update_webauthn_credential_after_login not implemented".to_string(),
        ))
    }

    /// Issue a session for a native-app loopback sign-in whose one-time code and
    /// PKCE verifier have ALREADY been checked. Mirrors
    /// [`Database::issue_passkey_session`] except `client_kind = 'native'` and
    /// `auth_credential_id` is NULL: no passkey or wallet key authenticated this
    /// session, the human's browser login did.
    ///
    /// As with the passkey/NEAR paths there is NO `ensure_trace_tenant` here.
    /// The tenant came from a login link that a human already redeemed in a
    /// browser, so the account row provably exists; the insert is FK-bound to
    /// `(tenant_id, account_id)` and a bogus pair simply fails rather than
    /// writing anything. The raw session secret never reaches the database.
    async fn issue_native_session(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _session: NewSession<'_>,
        _audit: RedeemAudit,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "issue_native_session not implemented".to_string(),
        ))
    }

    /// Issue a browser session for a passkey login that has ALREADY been verified
    /// (Task 6). Inserts a `trace_sessions` row (hash-only `token_hash`,
    /// `client_kind = 'passkey'`, `auth_credential_id` = the base64url credential
    /// id STRING that authenticated the session, `token_issued_at` defaulted) plus
    /// a hash-only audit row, in ONE RLS-scoped tx under the already-resolved
    /// tenant. The caller MUST have verified the assertion (and thereby the
    /// credential's FK-backed tenant) before calling this; there is therefore NO
    /// `ensure_trace_tenant` here — the tenant provably exists via the credential
    /// row, and an UPSERT before verification would let a forged assertion spray
    /// tenant rows. The raw session secret never reaches the database; only its
    /// sha256 `token_hash` is stored.
    async fn issue_passkey_session(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _session: NewSession<'_>,
        _auth_credential_id: &str,
        _audit: RedeemAudit,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "issue_passkey_session not implemented".to_string(),
        ))
    }

    /// Issue a browser session for a NEAR wallet login that has ALREADY been
    /// verified (Slice 3a Task 7). Mirrors [`Database::issue_passkey_session`]
    /// exactly except `client_kind = 'near'` and `auth_credential_id` carries the
    /// NEAR access key (`ed25519:...` public key) that authenticated the session.
    /// Inserts a `trace_sessions` row (hash-only `token_hash`, `token_issued_at`
    /// defaulted) plus a hash-only audit row in ONE RLS-scoped tx under the
    /// already-resolved tenant. The caller MUST have verified the NEP-413 assertion
    /// AND loaded the identity under that tenant before calling this; there is
    /// therefore NO `ensure_trace_tenant` here — the tenant provably exists via the
    /// identity row, and an UPSERT before verification would let a forged assertion
    /// spray tenant rows. The raw session secret never reaches the database; only
    /// its sha256 `token_hash` is stored, and the public key is never audited.
    async fn issue_near_session(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _session: NewSession<'_>,
        _auth_credential_id: &str,
        _audit: RedeemAudit,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "issue_near_session not implemented".to_string(),
        ))
    }

    /// List the ACTIVE (unrevoked) credentials for `account_id`, oldest first.
    /// Label- and timestamp-only; no key material. Tenant- + account-scoped
    /// under forced RLS so another account's credentials are never returned.
    async fn list_account_credentials(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
    ) -> Result<Vec<AccountCredentialSummary>, DatabaseError> {
        Err(DatabaseError::Pool(
            "list_account_credentials not implemented".to_string(),
        ))
    }

    /// Rename one of `account_id`'s ACTIVE credentials. Returns whether a row was
    /// affected (`false` for an unknown / revoked / other-account credential).
    /// Tenant- + account-scoped under forced RLS so a caller can never rename a
    /// credential they do not own.
    async fn rename_account_credential(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _credential_id: &str,
        _label: Option<&str>,
    ) -> Result<bool, DatabaseError> {
        Err(DatabaseError::Pool(
            "rename_account_credential not implemented".to_string(),
        ))
    }

    /// Soft-revoke one of `account_id`'s ACTIVE credentials and report how many of
    /// the account's credentials remain active afterwards. `removed` is `false`
    /// for an unknown / already-revoked / other-account credential. Tenant- +
    /// account-scoped under forced RLS so a caller can never revoke a credential
    /// they do not own; the remaining-count lets the caller refuse to remove the
    /// last passkey.
    async fn revoke_account_credential(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _credential_id: &str,
    ) -> Result<RevokeCredentialResult, DatabaseError> {
        Err(DatabaseError::Pool(
            "revoke_account_credential not implemented".to_string(),
        ))
    }

    /// Insert a registered NEAR access key for `account_id`. `public_key` is the
    /// globally-UNIQUE NEAR access key (`ed25519:...`) used by the unauthenticated
    /// login resolver to map key -> tenant; `near_account_id` is the human-readable
    /// NEAR account label (attribution only); `label` is an optional user-supplied
    /// display name. Tenant- + account-scoped under forced RLS.
    async fn insert_near_identity(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _public_key: &str,
        _near_account_id: &str,
        _label: Option<&str>,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "insert_near_identity not implemented".to_string(),
        ))
    }

    /// Load an ACTIVE NEAR identity for the LOGIN (wallet-assertion) path by its
    /// `public_key`, under the already-resolved `tenant_id`. Returns the account id
    /// and the human-readable NEAR account id, or `None` for an unknown / revoked /
    /// other-tenant key. Runs inside an RLS-scoped tx; the `tenant_id =
    /// trace_current_tenant_id()` predicate is belt-and-suspenders on top of forced
    /// RLS, and `public_key` is globally UNIQUE. NO `ensure_trace_tenant` here: this
    /// mirrors `load_webauthn_credential_for_login` — the tenant already exists for
    /// any registered identity, and the resolver mapped public_key -> tenant first.
    async fn load_near_identity_for_login(
        &self,
        _tenant_id: &str,
        _public_key: &str,
    ) -> Result<Option<NearIdentityRow>, DatabaseError> {
        Err(DatabaseError::Pool(
            "load_near_identity_for_login not implemented".to_string(),
        ))
    }

    /// Stamp `last_used_at` on an ACTIVE NEAR identity after a successful
    /// wallet-assertion login. Tenant-scoped under forced RLS; only an active
    /// (unrevoked) identity is updated. `public_key` is globally UNIQUE.
    async fn touch_near_identity_last_used(
        &self,
        _tenant_id: &str,
        _public_key: &str,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Pool(
            "touch_near_identity_last_used not implemented".to_string(),
        ))
    }

    /// List the ACTIVE (unrevoked) NEAR identities for `account_id`, oldest first.
    /// Label- and timestamp-only plus the public attribution fields (`public_key`,
    /// `near_account_id`); no secret material. Tenant- + account-scoped under forced
    /// RLS so another account's identities are never returned.
    async fn list_account_near_identities(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
    ) -> Result<Vec<NearIdentitySummary>, DatabaseError> {
        Err(DatabaseError::Pool(
            "list_account_near_identities not implemented".to_string(),
        ))
    }

    /// Rename one of `account_id`'s ACTIVE NEAR identities. Returns whether a row was
    /// affected (`false` for an unknown / revoked / other-account key). Tenant- +
    /// account-scoped under forced RLS so a caller can never rename an identity they
    /// do not own.
    async fn rename_account_near_identity(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _public_key: &str,
        _label: Option<&str>,
    ) -> Result<bool, DatabaseError> {
        Err(DatabaseError::Pool(
            "rename_account_near_identity not implemented".to_string(),
        ))
    }

    /// Soft-revoke one of `account_id`'s ACTIVE NEAR identities and report how many
    /// strong authenticators (webauthn credentials + NEAR identities) remain active
    /// for the account afterwards, computed in the SAME tx as the revoke. `removed`
    /// is `false` for an unknown / already-revoked / other-account key. Tenant- +
    /// account-scoped under forced RLS so a caller can never revoke an identity they
    /// do not own; the remaining-strong count lets the caller refuse to remove the
    /// last strong authenticator.
    async fn revoke_account_near_identity(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _public_key: &str,
    ) -> Result<RevokeNearResult, DatabaseError> {
        Err(DatabaseError::Pool(
            "revoke_account_near_identity not implemented".to_string(),
        ))
    }

    /// Count `account_id`'s ACTIVE strong authenticators: webauthn credentials plus
    /// NEAR identities, summed in ONE RLS-scoped tx. Lets a caller enforce
    /// "keep at least one strong authenticator" before revoking the last passkey or
    /// NEAR key. Tenant- + account-scoped under forced RLS.
    async fn count_active_strong_authenticators(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
    ) -> Result<i64, DatabaseError> {
        Err(DatabaseError::Pool(
            "count_active_strong_authenticators not implemented".to_string(),
        ))
    }

    /// Designate one of `account_id`'s ACTIVE NEAR identities as its payout target.
    /// In ONE tx: clear any existing active designation for the account (so at most
    /// one holds, never violating the partial-unique index), then stamp
    /// `payout_designated_at = now()` on the named active key. Returns whether the
    /// stamp affected a row (`false` for an unknown / revoked / other-account key,
    /// which the caller surfaces as a 404). Tenant- + account-scoped under forced RLS.
    async fn designate_payout_near_identity(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _public_key: &str,
    ) -> Result<bool, DatabaseError> {
        Err(DatabaseError::Pool(
            "designate_payout_near_identity not implemented".to_string(),
        ))
    }

    /// Clear the payout designation from one of `account_id`'s ACTIVE NEAR
    /// identities. Returns whether a row changed (`false` when the key was not an
    /// active, currently-designated identity). Tenant- + account-scoped under forced
    /// RLS so a caller can never clear an identity they do not own.
    async fn clear_payout_near_identity(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
        _public_key: &str,
    ) -> Result<bool, DatabaseError> {
        Err(DatabaseError::Pool(
            "clear_payout_near_identity not implemented".to_string(),
        ))
    }

    /// Resolve the NEAR account id to pay for `account_id`, fail-closed. Reading the
    /// account's ACTIVE identities in one RLS-scoped tx: a designated one wins
    /// (`Designated`); else a single active identity is the unambiguous target
    /// (`SoleActive`); else zero active holds `NoneEnrolled` and two-or-more active
    /// with none designated holds `AmbiguousNoDesignation`. Settlement must withhold
    /// on any `Hold` rather than guess. Tenant- + account-scoped under forced RLS.
    async fn resolve_payout_near_account_id(
        &self,
        _tenant_id: &str,
        _account_id: uuid::Uuid,
    ) -> Result<PayoutResolution, DatabaseError> {
        Err(DatabaseError::Pool(
            "resolve_payout_near_account_id not implemented".to_string(),
        ))
    }

    /// Stage a device-principal account merge by consuming device B's login-link
    /// as proof-of-control, in ONE RLS-scoped transaction. The conditional consume
    /// UPDATE on `trace_login_links` is ALWAYS executed (never a SELECT-then-branch):
    /// an unknown / expired / already-consumed code affects zero rows -> `Ok(None)`,
    /// committing the no-op tx so the link stays retryable. On a winning consume,
    /// `account_id` is the absorbed account B. Fail-closed guards (each -> `Ok(None)`,
    /// no proposal written): B equals `surviving_account_id` (cannot merge into self);
    /// B already `closed_at`. Otherwise B's ACTIVE principal count is taken and a
    /// single-use, 10-minute proposal row is inserted naming `surviving_account_id`
    /// (A) as surviving and B as absorbed. Returns the staged proposal. The raw code
    /// never reaches the database; `proposal_id` is server-assigned. Tenant-scoped
    /// under forced RLS throughout.
    async fn stage_merge_proposal(
        &self,
        _tenant_id: &str,
        _surviving_account_id: uuid::Uuid,
        _merge_code_hash: &str,
    ) -> Result<Option<StagedMergeProposal>, DatabaseError> {
        Err(DatabaseError::Pool(
            "stage_merge_proposal not implemented".to_string(),
        ))
    }

    /// Execute a previously-staged merge atomically, in ONE RLS-scoped transaction:
    /// a partial merge is never observable. The proposal is loaded + consumed with a
    /// single conditional UPDATE (`consumed_at = now()` WHERE not-yet-consumed AND
    /// unexpired AND `surviving_account_id` matches the auth-derived A): an expired /
    /// not-owned / already-consumed / unknown proposal affects zero rows -> `Ok(None)`.
    /// The consume re-validates ownership (only A can execute its own proposal). B
    /// (absorbed) is re-checked still-open; if B closed mid-flight, return `Ok(None)`
    /// WITHOUT committing so the consume rolls back (the proposal stays usable). On the
    /// happy path, in the SAME tx: active principal links move from B to A (collision-
    /// free under `UNIQUE (tenant_id, principal_ref)`); active webauthn credentials and
    /// NEAR identities re-key from B to A (NEAR rows have `payout_designated_at` cleared
    /// so the per-account partial-unique payout index can never trip); ALL of B's live
    /// sessions are revoked; B is closed; and a hash-only `account_merged` audit row
    /// (counts only, no identifiers) is appended. The whole tx commits together; any
    /// failure rolls everything back. Returns the move counts. Tenant-scoped under
    /// forced RLS throughout.
    async fn execute_merge(
        &self,
        _tenant_id: &str,
        _surviving_account_id: uuid::Uuid,
        _proposal_id: uuid::Uuid,
    ) -> Result<Option<ExecutedMerge>, DatabaseError> {
        Err(DatabaseError::Pool(
            "execute_merge not implemented".to_string(),
        ))
    }

    /// Enumerate submissions that still need a perplexity-scoring gate
    /// decision, across ALL tenants. Runs on the narrow, cross-tenant
    /// `trace_gate_driver` pool (never the tenant-scoped runtime pool) — the
    /// permissive `USING (true)` SELECT policies installed by migration V36
    /// authorize cross-tenant row visibility, and V42 narrows that grant to
    /// the columns the driver's queries actually use (mirroring V38).
    /// authorize the read.
    ///
    /// A submission qualifies when: it has a `submitted_envelope` object ref
    /// that is neither invalidated nor deleted; it has no `trace_gate_decisions`
    /// row yet; its recorded attempt count in `trace_gate_evaluation_attempts`
    /// is below `max_attempts`; and (if it has been attempted before) enough
    /// time has passed since `last_attempt_at` per an exponential backoff of
    /// `backoff_base_seconds * 2^attempts`. Results are ordered oldest-received
    /// first and capped at `limit`.
    ///
    /// The default implementation returns a "not configured" error, which is
    /// the correct behavior for any [`Database`] impl that never wires a
    /// gate-driver pool (e.g. test doubles). [`postgres::PgBackend`] overrides
    /// this with the real query and its own "pool not configured" check when
    /// `TRACE_COMMONS_GATE_DRIVER_DATABASE_URL` is unset.
    /// How many submissions the enumeration above would eventually return,
    /// ignoring its `LIMIT`. The driver's backlog depth.
    ///
    /// Deliberately the SAME predicate as `list_submissions_needing_gate_decision`,
    /// so the number answers "work this driver can actually pick up" rather
    /// than "rows with no decision". Two exclusions follow from that and are
    /// worth knowing before reading a zero as "nothing outstanding":
    ///
    /// - Submissions in exponential backoff are excluded until their next
    ///   attempt is due. They come back on their own.
    /// - Submissions at or past `max_attempts` are excluded permanently. They
    ///   do not come back without an operator resetting their attempt row, so
    ///   a backlog of zero can coexist with traces that will never be scored.
    async fn count_submissions_needing_gate_decision(
        &self,
        _now: chrono::DateTime<chrono::Utc>,
        _max_attempts: i32,
        _backoff_base_seconds: i64,
    ) -> Result<i64, DatabaseError> {
        Err(DatabaseError::Pool(
            "gate-driver pool not configured".to_string(),
        ))
    }

    async fn list_submissions_needing_gate_decision(
        &self,
        _now: chrono::DateTime<chrono::Utc>,
        _max_attempts: i32,
        _backoff_base_seconds: i64,
        _limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::GateWorkItem>, DatabaseError> {
        Err(DatabaseError::Pool(
            "gate-driver pool not configured".to_string(),
        ))
    }

    /// Enumerate submissions awaiting the server-side NEAR AI PII backstop,
    /// across ALL tenants. Runs on the narrow, cross-tenant
    /// `trace_pii_backstop_driver` pool (never the tenant-scoped runtime
    /// pool) — the permissive `USING (true)` SELECT policies installed by
    /// migration V38 authorize the read.
    ///
    /// A submission qualifies when: its status is `awaiting_pii_backstop`; it
    /// has a `submitted_envelope` object ref that is neither invalidated nor
    /// deleted; its recorded attempt count in `trace_pii_backstop` is below
    /// `max_attempts`; and (if it has been attempted before) enough time has
    /// passed since `last_attempt_at` per an exponential backoff of
    /// `backoff_base_seconds * 2^attempts`. Results are ordered
    /// oldest-received first and capped at `limit`.
    ///
    /// The default implementation returns a "not configured" error, which is
    /// the correct behavior for any [`Database`] impl that never wires a
    /// pii-backstop-driver pool (e.g. test doubles). [`postgres::PgBackend`]
    /// overrides this with the real query and its own "pool not configured"
    /// check when `TRACE_COMMONS_PII_BACKSTOP_DRIVER_DATABASE_URL` is unset.
    async fn list_submissions_awaiting_pii_backstop(
        &self,
        _now: chrono::DateTime<chrono::Utc>,
        _max_attempts: i32,
        _backoff_base_seconds: i64,
        _limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::GateWorkItem>, DatabaseError> {
        Err(DatabaseError::Pool(
            "pii-backstop-driver pool not configured".to_string(),
        ))
    }

    /// Enumerate submissions that ALREADY have a `trace_gate_decisions` row,
    /// cross-tenant, ordered oldest-received first, capped at `limit`. This is
    /// the sibling of [`Self::list_submissions_needing_gate_decision`] used by
    /// the perplexity re-score maintenance task: it targets the historical
    /// decisions that need their perplexity recomputed. Like the enumeration it
    /// mirrors, it reads through the gate-driver reader pool with NO tenant GUC
    /// set — the `trace_gate_driver` role's permissive cross-tenant SELECT
    /// policies authorize the read.
    ///
    /// The default returns an empty list, which is correct for any [`Database`]
    /// impl that never wires a gate-driver pool (e.g. test doubles).
    /// [`postgres::PgBackend`] overrides this with the real query.
    async fn list_submissions_with_gate_decision(
        &self,
        _limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::GateWorkItem>, DatabaseError> {
        Ok(Vec::new())
    }

    /// Enumerate decision rows for shadow credit-quality scoring, cross-tenant,
    /// oldest-decided first, capped at `limit`. Reads through the gate-driver
    /// reader pool with NO tenant GUC (the trace_gate_driver role's permissive
    /// cross-tenant SELECT policies authorize it). Default: empty (test doubles
    /// / backends without a gate-driver pool).
    async fn list_gate_decisions_for_credit_scoring(
        &self,
        _limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::GateCreditInput>, DatabaseError> {
        Ok(Vec::new())
    }

    /// Enumerate dedup signal rows (migration V40), cross-tenant, oldest-decided
    /// first, capped at `limit`. Reads through the gate-driver reader pool with
    /// NO tenant GUC (the trace_gate_driver role's permissive cross-tenant
    /// SELECT policies authorize it). Default: empty (test doubles / backends
    /// without a gate-driver pool).
    async fn list_dedup_signals(
        &self,
        _limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::DedupSignalRow>, DatabaseError> {
        Ok(Vec::new())
    }

    /// Enumerate correction-value signal rows (migration V48), cross-tenant,
    /// oldest-decided first, capped at `limit`. Reads through the gate-driver
    /// reader pool with NO tenant GUC (the trace_gate_driver role's permissive
    /// cross-tenant SELECT policies authorize it). Corrections cluster
    /// cross-tenant for the same reason traces do: the same correction pasted
    /// into two tenants is one correction. Default: empty (test doubles /
    /// backends without a gate-driver pool).
    async fn list_correction_signals(
        &self,
        _limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::CorrectionSignalRow>, DatabaseError> {
        Ok(Vec::new())
    }

    /// Enumerate per-contributor cap signal rows (migration V41), cross-tenant,
    /// joining each decision to its submission for the contributor identity
    /// (`auth_principal_ref`), ordered `(auth_principal_ref, decided_at ASC)`
    /// so the recompute pass can group per contributor and forward-accumulate
    /// in time order. Reads through the gate-driver reader pool with NO tenant
    /// GUC (the trace_gate_driver role's permissive cross-tenant SELECT
    /// policies authorize it). Default: empty (test doubles / backends
    /// without a gate-driver pool).
    async fn list_contributor_cap_signals(
        &self,
        _limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::ContributorCapSignalRow>, DatabaseError> {
        Ok(Vec::new())
    }

    /// Look up the LATEST gate-decision score for each of `submission_ids`,
    /// cross-tenant. Reads through the gate-driver reader pool with NO tenant
    /// GUC (the trace_gate_driver role's permissive cross-tenant SELECT
    /// policies authorize it). Ids with no decision row are simply absent
    /// from the result — this is not an error. Default: empty (test doubles
    /// / backends without a gate-driver pool).
    async fn list_scores_by_submission_ids(
        &self,
        _submission_ids: &[uuid::Uuid],
    ) -> Result<Vec<crate::trace_corpus_storage::TraceScoreBySubmissionRow>, DatabaseError> {
        Ok(Vec::new())
    }

    /// Enumerate the LATEST gate-decision score for every submission owned
    /// by `(tenant_id, auth_principal_ref)` — the read behind server-signed
    /// score attestations (see `trace_score_attestation`). Unlike
    /// `list_scores_by_submission_ids`, both identity fields are supplied by
    /// the CALLER'S SERVER-SIDE code, resolved from an authenticated
    /// request context, never from a client-supplied id list; this method
    /// exists so that resolution never has to widen into a
    /// caller-suppliable filter. Reads through the gate-driver reader pool
    /// with NO tenant GUC (the trace_gate_driver role's permissive
    /// cross-tenant SELECT policies authorize it); the `tenant_id`/
    /// `auth_principal_ref` equality checks are enforced in the query text
    /// itself as defense in depth. Default: empty (test doubles / backends
    /// without a gate-driver pool).
    async fn list_own_gate_decision_scores(
        &self,
        _tenant_id: &str,
        _auth_principal_ref: &str,
        _limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::TraceScoreBySubmissionRow>, DatabaseError> {
        Ok(Vec::new())
    }

    /// The scoped counterpart of `list_own_gate_decision_scores`: for each of
    /// `submission_ids` OWNED by `(tenant_id, auth_principal_ref)`, return
    /// its latest gate-decision score, or `None` when it has not been scored
    /// yet. Ids the principal does not own are simply absent from the
    /// result, whether they belong to another principal or to nobody — the
    /// caller must not be able to tell those apart, or this becomes a probe
    /// for other contributors' submission ids.
    ///
    /// `submission_ids` is the ONLY caller-supplied input; the identity pair
    /// still comes from the authenticated request context, never from the
    /// request body. The id list narrows a set the principal already owns,
    /// so it cannot widen the read. Default: empty (test doubles / backends
    /// without a gate-driver pool).
    async fn list_own_gate_decision_scores_for_submissions(
        &self,
        _tenant_id: &str,
        _auth_principal_ref: &str,
        _submission_ids: &[uuid::Uuid],
    ) -> Result<Vec<crate::trace_corpus_storage::OwnSubmissionScoreRow>, DatabaseError> {
        Ok(Vec::new())
    }
}

/// The session row to create on a winning redeem. `token_hash` is sha256-shaped;
/// the raw secret never reaches the database. `session_id` is server-assigned by
/// the implementation, never carried here.
#[derive(Debug, Clone, Copy)]
pub struct NewSession<'a> {
    pub token_hash: &'a str,
    pub client_kind: &'a str,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// The hash-only / label-only audit row written inside the redeem transaction.
/// The actor is derived by the implementation from the consumed account id;
/// callers supply only the action label, outcome label, and safe metadata.
#[derive(Debug, Clone)]
pub struct RedeemAudit {
    pub action: String,
    pub outcome: String,
    pub metadata: serde_json::Value,
}

/// Result of a successful atomic login-link redeem. Carries only the durable
/// account id and the server-assigned session id; never the raw code or any
/// secret material.
#[derive(Debug, Clone)]
pub struct RedeemedSession {
    pub account_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
}

/// Outcome of a successful [`Database::validate_session`] lookup. Carries the
/// durable account id and the `auth_credential_id` recorded on the session row
/// (the base64url WebAuthn credential id that authenticated a passkey session, or
/// `None` for a device-link session). The credential id is a public identifier,
/// never key material.
#[derive(Debug, Clone)]
pub struct ValidatedSession {
    pub account_id: uuid::Uuid,
    pub auth_credential_id: Option<String>,
    /// The `client_kind` recorded on the session row (`'web'` for a device-link
    /// session, `'passkey'` for a passkey login, `'near'` for a NEAR login). Used
    /// by the strong-authenticator gate to classify session strength: a `'web'`
    /// session is WEAK, a `'passkey'`/`'near'` session is STRONG. A public label,
    /// never key material.
    pub client_kind: String,
    /// Set to the NEW raw session secret when rotation-on-use fired for this
    /// request (the matched row's `token_issued_at` aged past the rotation
    /// interval and the request matched the CURRENT `token_hash`), and `None`
    /// otherwise. When `Some`, the caller MUST emit a fresh `Set-Cookie` so the
    /// browser swaps to the new secret before the short prev-token grace lapses;
    /// the auth middleware is the single guaranteed attach point. A request that
    /// matched the previous token within grace (multi-tab) does NOT re-rotate and
    /// leaves this `None`.
    pub rotated_secret: Option<String>,
}

/// A registered passkey resolved for the LOGIN (assertion) path. Carries only
/// the durable account id and the serialized webauthn-rs `Passkey` JSON (public
/// key, sign counter, AAGUID, transports); never PII. The loader runs under the
/// already-resolved tenant's RLS, so the row is tenant-scoped by construction.
#[derive(Debug, Clone)]
pub struct WebauthnCredentialRow {
    pub account_id: uuid::Uuid,
    pub passkey: serde_json::Value,
}

/// A single ACTIVE credential as surfaced in the account's credential list.
/// Label-only and timestamp-only: no public-key material or counter state. The
/// `credential_id` is the base64url WebAuthn id (a label, not a secret).
#[derive(Debug, Clone)]
pub struct AccountCredentialSummary {
    pub credential_id: String,
    pub label: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Outcome of revoking one of an account's credentials. `removed` is whether the
/// soft-delete affected a row (false for an unknown / already-revoked / other
/// account's credential); `remaining` is the count of the account's credentials
/// still active after the revoke, so the caller can refuse to remove the last
/// passkey if policy requires it.
#[derive(Debug, Clone, Copy)]
pub struct RevokeCredentialResult {
    pub removed: bool,
    pub remaining: i64,
}

/// A registered NEAR identity resolved for the LOGIN (wallet-assertion) path.
/// Carries only the durable account id and the human-readable `near_account_id`
/// (attribution only); never key material or PII. The loader runs under the
/// already-resolved tenant's RLS, so the row is tenant-scoped by construction.
#[derive(Debug, Clone)]
pub struct NearIdentityRow {
    pub account_id: uuid::Uuid,
    pub near_account_id: String,
}

/// A single ACTIVE NEAR identity as surfaced in the account's identity list.
/// Label-, timestamp-, and public-attribution-only: `public_key` is the NEAR
/// access key (a public identifier, not a secret) and `near_account_id` is the
/// human-readable NEAR account label.
#[derive(Debug, Clone)]
pub struct NearIdentitySummary {
    pub public_key: String,
    pub near_account_id: String,
    pub label: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// True when this identity is the account's designated payout target
    /// (`payout_designated_at IS NOT NULL` on an ACTIVE row). At most one active
    /// identity per account carries this flag (enforced by a partial-unique index).
    pub is_payout: bool,
}

/// Why [`Database::resolve_payout_near_account_id`] withheld a payout target. A
/// fail-closed signal: settlement must hold (not guess) when no unambiguous
/// designation exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayoutHoldReason {
    /// The account has no ACTIVE NEAR identities at all.
    NoneEnrolled,
    /// The account has two or more ACTIVE NEAR identities and none is designated
    /// as the payout target, so there is no unambiguous choice.
    AmbiguousNoDesignation,
}

/// Outcome of resolving an account's payout NEAR account id. The carried `String`
/// is the human-readable `near_account_id` to pay; a [`PayoutResolution::Hold`]
/// means settlement must withhold until the account designates a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayoutResolution {
    /// The account explicitly designated this `near_account_id` as its payout target.
    Designated(String),
    /// The account has exactly one ACTIVE NEAR identity and none is explicitly
    /// designated; pay it as the sole unambiguous choice.
    SoleActive(String),
    /// No unambiguous payout target; hold with the given reason.
    Hold(PayoutHoldReason),
}

/// Outcome of revoking one of an account's NEAR identities. `removed` is whether
/// the soft-delete affected a row (false for an unknown / already-revoked / other
/// account's key); `remaining_strong` is the count of the account's strong
/// authenticators (webauthn credentials + NEAR identities) still active after the
/// revoke, so the caller can refuse to remove the last strong authenticator.
#[derive(Debug, Clone, Copy)]
pub struct RevokeNearResult {
    pub removed: bool,
    pub remaining_strong: i64,
}

/// Outcome of [`Database::stage_merge_proposal`]: device B's login-link was
/// consumed as proof-of-control and a single-use, time-bounded merge proposal
/// was staged. Carries only durable account/proposal ids and an attribution-only
/// active-principal count for `absorbed_account_id`; never any code or secret.
#[derive(Debug, Clone, Copy)]
pub struct StagedMergeProposal {
    pub proposal_id: uuid::Uuid,
    pub absorbed_account_id: uuid::Uuid,
    pub absorbed_principal_count: i64,
}

/// Outcome of a successful [`Database::execute_merge`]: how many active principal
/// links and strong authenticators (webauthn credentials + NEAR identities) were
/// re-keyed from the absorbed account onto the surviving account. Counts only;
/// never identifiers.
#[derive(Debug, Clone, Copy)]
pub struct ExecutedMerge {
    pub principals_moved: i64,
    pub authenticators_moved: i64,
}

/// Per-contributor row returned by [`Database::compute_leaderboard_inputs`].
/// The `*_in_window` columns count over the window the caller passed; the
/// `total_*` columns are all-time.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaderboardContributorRow {
    pub tenant_id: String,
    pub principal_ref: String,
    pub display_handle: String,
    pub handle_normalized: String,
    pub bio: Option<String>,
    pub public_since: chrono::DateTime<chrono::Utc>,
    pub accepted_in_window: i64,
    pub credit_in_window: f64,
    pub total_accepted: i64,
    pub total_credit: f64,
}

/// Corpus-wide aggregates for [`Database::compute_corpus_analytics_summary`].
/// All counts are pre-noise; the snapshot worker is the right place to
/// apply Laplace noise / privacy-budget accounting in a follow-up slice.
#[derive(Debug, Clone, PartialEq)]
pub struct CorpusAnalyticsSummary {
    pub total_submissions: i64,
    pub total_accepted: i64,
    pub total_rejected: i64,
    /// Decimal in [0, 1]. Zero when there are no submissions.
    pub accept_rate: f64,
    /// `(bucket_micros, count)` sorted ascending by bucket. Bucket
    /// width is 100_000 micros (10 buckets across [0, 1_000_000]).
    pub novelty_histogram: Vec<(i64, i64)>,
    /// `(outcome_label, count)` sorted descending by count.
    /// Labels: `both_passed`, `novelty_failed`, `perplexity_failed`,
    /// `both_failed`.
    pub gate_outcomes: Vec<(String, i64)>,
}

/// All-time, all-tenant totals for [`Database::compute_register_stats_totals`].
/// Feeds the `trace_register_stats` singleton row that the public register
/// endpoint reads; computed from the same tables the tenant-scoped admin
/// summaries already read, crossed the same way `compute_corpus_analytics_summary`
/// crosses tenants -- per-tenant transactions under the RLS tenant GUC,
/// never `BYPASSRLS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterStatsTotals {
    pub traces_accepted: i64,
    /// Distinct `credit_account_ref` values across every tenant's credit
    /// ledger.
    pub contributors: i64,
    /// Sum of positive `points_delta` across every tenant's credit ledger.
    pub points_issued: i64,
}

/// The `trace_register_stats` singleton row, as read or as just written by
/// [`Database::fetch_register_stats_row`] / [`Database::write_register_stats_row`].
/// `refreshed_at` is `None` until a refresh has actually run; the public
/// endpoint (a later slice) must refuse to publish while it is `None`,
/// because a zero would be a claim about the register nobody made.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegisterStatsRow {
    pub traces_accepted: i64,
    pub contributors: i64,
    pub points_issued: i64,
    /// The computed/never-computed marker: TRUE until a refresh has run, and
    /// cleared by every refresh. Not an operator control -- see `suppressed`.
    pub withheld: bool,
    /// The operator's lever. No refresh ever writes it, so suppression set
    /// during an incident survives the next scheduled run.
    pub suppressed: bool,
    pub as_of: chrono::DateTime<chrono::Utc>,
    pub refreshed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Write-shape for [`Database::insert_leaderboard_snapshot`]. The caller
/// computes `contents_sha256` and `noise_seed_hash`; the DB owns
/// `computed_at`.
#[derive(Debug, Clone)]
pub struct LeaderboardSnapshotWrite {
    pub snapshot_id: uuid::Uuid,
    pub window_label: String,
    pub metric: String,
    pub contents: serde_json::Value,
    pub contents_sha256: String,
    pub min_cell_count: i32,
    pub noise_seed_hash: String,
}

/// Read-shape returned by [`Database::insert_leaderboard_snapshot`] and
/// [`Database::latest_leaderboard_snapshot`].
#[derive(Debug, Clone)]
pub struct LeaderboardSnapshotRow {
    pub snapshot_id: uuid::Uuid,
    pub computed_at: chrono::DateTime<chrono::Utc>,
    pub window_label: String,
    pub metric: String,
    pub contents: serde_json::Value,
    pub contents_sha256: String,
    pub min_cell_count: i32,
    pub noise_seed_hash: String,
}

/// Row returned by [`Database::upsert_contributor_profile`]. Mirrors the
/// columns of `trace_contributor_profiles` that the API surfaces back
/// to the contributor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributorProfileRow {
    pub tenant_id: String,
    pub principal_ref: String,
    pub display_handle: String,
    pub handle_normalized: String,
    pub bio: Option<String>,
    pub public_since: chrono::DateTime<chrono::Utc>,
    pub last_updated_at: chrono::DateTime<chrono::Utc>,
    pub update_count: i32,
}

/// Eviction receipt written atomically with a community-profile
/// withdrawal. Proves the published snapshot surface was asked to drop
/// the contributor rather than relying on an assumed cache TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityWithdrawalEvictionRow {
    pub eviction_id: uuid::Uuid,
    pub tenant_id: String,
    pub principal_ref: String,
    pub display_handle: Option<String>,
    pub handle_normalized: Option<String>,
    pub withdrawn_at: chrono::DateTime<chrono::Utc>,
    pub invalidation_requested_at: chrono::DateTime<chrono::Utc>,
    pub window_label: String,
    pub metric: String,
}

#[derive(Debug, Clone)]
pub struct DeviceKeyWrite {
    pub device_key_id: String,
    pub tenant_id: String,
    pub public_key: String,
    pub invite_subject_hash: String,
    pub client_info: serde_json::Value,
    /// Grant-scope override from the invite, when redemption goes through
    /// the DB-authoritative registry. `None` (every pre-existing call site)
    /// preserves today's behavior byte-for-byte: the hardcoded
    /// `DEFAULT_ONBOARDING_CONSENT_SCOPES`. An empty `Some(vec![])` -- as
    /// carried by invites imported from the file allowlist, which never had
    /// a scopes column -- is treated the same as `None`, not as "grant
    /// nothing": provisioning an imported invite with zero consent scopes
    /// would silently strip permissions the pilot already granted it.
    pub allowed_consent_scopes: Option<Vec<String>>,
    /// Same override/empty-fallback behavior as `allowed_consent_scopes`,
    /// against `DEFAULT_ONBOARDING_ALLOWED_USES`.
    pub allowed_uses: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceKeyRecord {
    pub device_key_id: String,
    pub tenant_id: String,
    pub public_key: String,
    pub invite_subject_hash: Option<String>,
    pub client_info: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardDeviceKeyStatus {
    Registered,
    Idempotent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OnboardDeviceKeyRecord {
    pub device_key: DeviceKeyRecord,
    pub status: OnboardDeviceKeyStatus,
}

#[derive(Debug, thiserror::Error)]
pub enum OnboardDeviceKeyError {
    #[error("invite not valid")]
    InviteNotValid,
    #[error("invite already consumed")]
    InviteAlreadyConsumed,
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
}

/// Input to [`Database::enroll_instance_user`].
#[derive(Debug, Clone)]
pub struct InstanceUserProvision {
    pub device_key_id: String,
    pub tenant_id: String,
    pub public_key: String,
    /// The `sha256:…` hash identifying the instance subject; used as
    /// `invite_subject_hash` on the device key row and embedded in the
    /// `updated_by_principal_ref` audit column of the policy row.
    pub instance_subject_hash: String,
    pub client_info: serde_json::Value,
    pub policy_version: String,
    pub allowed_consent_scopes: serde_json::Value,
    pub allowed_uses: serde_json::Value,
}

pub async fn connect_from_config(
    config: &DatabaseConfig,
) -> Result<Arc<dyn Database>, DatabaseError> {
    let backend = postgres::PgBackend::new(config).await?;
    backend.run_migrations().await?;
    Ok(Arc::new(backend) as Arc<dyn Database>)
}

/// Outcome of [`Database::reserve_instance_enrollment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceEnrollmentOutcome {
    /// The user was not previously enrolled and has been added to the ledger.
    NewlyEnrolled,
    /// The user was already enrolled; no cap was consumed.
    ExistingUser,
    /// The per-instance cap is reached; the user was NOT enrolled.
    CapExceeded,
}

mod token_bundles;
