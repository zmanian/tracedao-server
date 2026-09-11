// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL backend for TraceCommons server storage.

use std::collections::HashSet;

#[path = "postgres_account_onboarding.rs"]
mod account_onboarding;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::config::DatabaseConfig;
use crate::db::{Database, TraceCorpusRlsDiagnostics};
use crate::error::DatabaseError;

/// Rotation-on-use cadence for browser sessions. A cookie session whose CURRENT
/// token was issued more than this many seconds ago is rotated on its next live
/// request: a fresh secret is minted and the old hash is parked in
/// `prev_token_hash` for a short grace window. Default ~12h. Overridable via
/// `TRACE_COMMONS_SESSION_ROTATION_INTERVAL_SECS` so tests can force rotation
/// without waiting (the env var is read per call; production never sets it).
const SESSION_ROTATION_INTERVAL_SECS_DEFAULT: i64 = 12 * 60 * 60;
/// Grace window during which the PREVIOUS token still validates after a rotation,
/// so an in-flight / multi-tab request holding the old cookie is not logged out
/// before it observes the new `Set-Cookie`. Default ~2 min. Overridable via
/// `TRACE_COMMONS_SESSION_ROTATION_GRACE_SECS` for tests.
const SESSION_ROTATION_GRACE_SECS_DEFAULT: i64 = 2 * 60;

/// Read the rotation interval (seconds), honoring the test-only env override.
/// A malformed or non-positive override falls back to the default so a bad value
/// can never disable rotation cadence entirely.
fn session_rotation_interval_secs() -> i64 {
    std::env::var("TRACE_COMMONS_SESSION_ROTATION_INTERVAL_SECS")
        .ok()
        .and_then(|raw| raw.parse::<i64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(SESSION_ROTATION_INTERVAL_SECS_DEFAULT)
}

/// Read the prev-token grace (seconds), honoring the test-only env override.
fn session_rotation_grace_secs() -> i64 {
    std::env::var("TRACE_COMMONS_SESSION_ROTATION_GRACE_SECS")
        .ok()
        .and_then(|raw| raw.parse::<i64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(SESSION_ROTATION_GRACE_SECS_DEFAULT)
}

/// Fixed advisory-lock namespace (classid) for the NEAR settlement submit serializer.
/// Paired with a per-tenant objid (`hashtext('near-credit-submit:'||tenant)`), the
/// two-int `pg_try_advisory_lock(classid, objid)` form keeps this lock space
/// disjoint from the one-arg `pg_advisory_xact_lock(hashtext(tenant))` used by the
/// audit-chain append, so the two can never alias.
const NEAR_CREDIT_SUBMIT_ADVISORY_LOCK_CLASSID: i32 = 0x7472_6163u32 as i32; // "trac"

/// Fixed advisory-lock namespace for live credit-settlement finalize. Distinct from
/// the submit classid so a submit pass and a settlement pass never contend on the
/// same key — they serialize different money-path races.
const CREDIT_SETTLEMENT_ADVISORY_LOCK_CLASSID: i32 = 0x7365_7474u32 as i32; // "sett"

/// Owns the pooled connection that holds a session-level advisory lock for the
/// duration of a NEAR settlement submit pass. Released explicitly via
/// [`NearCreditSubmitAdvisoryLockInner::release`]; see the public
/// `NearCreditSubmitAdvisoryLock` wrapper in `db::mod` for lifecycle docs.
pub struct NearCreditSubmitAdvisoryLockInner {
    client: deadpool_postgres::Object,
    objid: i32,
}

impl NearCreditSubmitAdvisoryLockInner {
    pub(crate) async fn release(self) -> Result<(), DatabaseError> {
        // Best-effort unlock on the SAME connection that took the lock; session
        // advisory locks are connection-scoped, so this must run here before the
        // connection returns to the pool.
        self.client
            .execute(
                "SELECT pg_advisory_unlock($1, $2)",
                &[&NEAR_CREDIT_SUBMIT_ADVISORY_LOCK_CLASSID, &self.objid],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(())
    }
}

/// Owns the pooled connection holding the live credit-settlement advisory lock.
pub struct CreditSettlementAdvisoryLockInner {
    client: deadpool_postgres::Object,
    objid: i32,
}

impl CreditSettlementAdvisoryLockInner {
    pub(crate) async fn release(self) -> Result<(), DatabaseError> {
        self.client
            .execute(
                "SELECT pg_advisory_unlock($1, $2)",
                &[&CREDIT_SETTLEMENT_ADVISORY_LOCK_CLASSID, &self.objid],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(())
    }
}

pub struct PgBackend {
    pool: Pool,
    /// Narrow, SEPARATE pool for the unauthenticated login-link redeem path.
    /// Built only when `login_resolver_url` is configured; its DB user is the
    /// operator-provisioned `trace_login_resolver` role (no BYPASSRLS,
    /// column-scoped SELECT on `trace_login_links` only). `None` keeps the
    /// account-redeem path fail-closed. NEVER aliased to `pool`.
    login_resolver_pool: Option<Pool>,
    /// Narrow, SEPARATE pool for the cross-tenant gate-driver enumeration
    /// query. Built only when `gate_driver_url` is configured; its DB user is
    /// the operator-provisioned `trace_gate_driver` role (NOLOGIN base,
    /// NOBYPASSRLS, V36 USING(true) cross-tenant policies, V42 column-scoped
    /// SELECT grants mirroring `trace_pii_backstop_driver`). `None` keeps the
    /// gate driver's enumeration path fail-closed. NEVER aliased to `pool`.
    gate_driver_pool: Option<Pool>,
    /// Narrow, SEPARATE pool for the cross-tenant PII-backstop driver
    /// enumeration query (server-side NEAR AI PII backstop). Built only when
    /// `pii_backstop_driver_url` is configured; its DB user is the
    /// operator-provisioned `trace_pii_backstop_driver` role (NOLOGIN base,
    /// NOBYPASSRLS, permissive cross-tenant SELECT policies from migration
    /// V38). `None` keeps the backstop driver's enumeration path fail-closed.
    /// NEVER aliased to `pool`. Mirrors `gate_driver_pool`. Read by
    /// `list_submissions_awaiting_pii_backstop`.
    pii_backstop_driver_pool: Option<Pool>,
    /// Narrow, SEPARATE pool for the invite registry cache refresh and the
    /// admin invite API. Built only when `invite_registry_url` is configured;
    /// its DB user is the operator-provisioned `trace_invite_registry` role
    /// (NOLOGIN base, NOBYPASSRLS, permissive policy from V42). `None` keeps
    /// invite redemption fail-closed. NEVER aliased to `pool`.
    invite_registry_pool: Option<Pool>,
}

/// Tables whose tenant isolation `trace_corpus_rls_diagnostics` attests to.
///
/// Public so RLS tests assert against this list rather than a hand-maintained
/// copy; the copy had drifted twelve tables out of date while the diagnostic
/// that would have caught it was failing to parse.
///
/// Deliberate exclusions, so an absence is never mistaken for an oversight
/// again: `trace_instance_enrollments` and `onboarding_invite_grants` are
/// isolated by subject hash rather than by tenant;
/// `trace_near_provisioning_ceremonies` uses an unpredictable ceremony hash, and
/// `trace_community_snapshot_invalidations` and `trace_leaderboard_snapshots`
/// are deployment-wide aggregate bookkeeping with no tenant column to
/// predicate on -- inexpressible rather than merely unnecessary. The
/// leaderboard snapshot's `contents_jsonb` DOES carry contributor handles;
/// see the exclusion notes at the bottom of
/// `migrations/V56__community_withdrawal_eviction_rls.sql` for why that is
/// opt-in published data and does not change the answer.
pub const TRACE_COMMONS_RLS_TABLES: &[&str] = &[
    "trace_tenants",
    "trace_tenant_policies",
    "trace_tenant_access_grants",
    "trace_submissions",
    "trace_object_refs",
    "trace_derived_records",
    "trace_audit_events",
    "trace_credit_ledger",
    "trace_tombstones",
    "trace_withdrawals",
    "trace_token_bundles",
    "trace_token_attachments",
    "trace_vector_entries",
    "trace_export_manifests",
    "trace_export_manifest_items",
    "trace_retention_jobs",
    "trace_retention_job_items",
    "trace_export_access_grants",
    "trace_export_jobs",
    "trace_revocation_propagation_items",
    "trace_utility_attestations",
    "trace_credit_settlement_batches",
    "trace_credit_holds",
    "trace_near_credit_outbox",
    "trace_near_credit_account_outbox",
    "trace_benchmark_registry_outbox",
    "trace_ranking_model_versions",
    "trace_ranking_calibration_datasets",
    "trace_ranking_features",
    "trace_ranking_predictions",
    "trace_ranking_labels",
    "trace_ranking_preference_labels",
    "trace_ranking_calibration_runs",
    "trace_ranking_worker_runs",
    "trace_contributor_profiles",
    "trace_contributor_profile_audit",
    "device_keys",
    "onboarding_invites",
    "trace_accounts",
    "trace_account_principals",
    "trace_login_links",
    "trace_sessions",
    "trace_account_audit",
    "trace_webauthn_credentials",
    "trace_near_identities",
    "trace_near_account_anchors",
    "trace_near_provisioned_devices",
    "trace_account_merge_proposals",
    "trace_community_withdrawal_evictions",
];

const TRACE_COMMONS_RLS_POLICY_EXPRESSION_VARIANTS: &[&str] = &[
    "(tenant_id = trace_current_tenant_id())",
    "(tenant_id = public.trace_current_tenant_id())",
];

const ONBOARDING_DEVICE_GRANT_REASON: &str = "onboarding device-key default pilot access";

const LEADERBOARD_INPUTS_SQL: &str = "SELECT
                        cp.tenant_id,
                        cp.principal_ref,
                        cp.display_handle,
                        cp.handle_normalized,
                        cp.bio,
                        cp.public_since,
                        COUNT(*) FILTER (
                            WHERE cl.event_type = 'accepted'
                              AND COALESCE(ts.received_at, cl.occurred_at)
                                  >= NOW() - ($1 || ' days')::interval
                        ) AS accepted_in_window,
                        COALESCE(SUM(cl.points_delta::float8) FILTER (
                            WHERE cl.event_type = 'accepted'
                              AND COALESCE(ts.received_at, cl.occurred_at)
                                  >= NOW() - ($1 || ' days')::interval
                        ), 0.0) AS credit_in_window,
                        COUNT(*) FILTER (WHERE cl.event_type = 'accepted') AS total_accepted,
                        COALESCE(SUM(cl.points_delta::float8) FILTER (
                            WHERE cl.event_type = 'accepted'
                        ), 0.0) AS total_credit
                     FROM trace_contributor_profiles cp
                     LEFT JOIN trace_credit_ledger cl
                            ON cl.tenant_id = cp.tenant_id
                           AND (
                                cl.credit_account_ref = cp.principal_ref
                                OR EXISTS (
                                    SELECT 1
                                    FROM trace_submissions ts_match
                                    WHERE ts_match.tenant_id = cl.tenant_id
                                      AND ts_match.submission_id = cl.submission_id
                                      AND (
                                           ts_match.auth_principal_ref = cp.principal_ref
                                           OR COALESCE(
                                                ts_match.contributor_pseudonym,
                                                ts_match.auth_principal_ref
                                           ) = cp.principal_ref
                                      )
                                )
                           )
                     LEFT JOIN trace_submissions ts
                            ON ts.tenant_id = cl.tenant_id
                           AND ts.submission_id = cl.submission_id
                     WHERE cp.withdrawn_at IS NULL
                     GROUP BY cp.tenant_id, cp.principal_ref, cp.display_handle,
                              cp.handle_normalized, cp.bio, cp.public_since
                     HAVING COUNT(*) FILTER (
                        WHERE cl.event_type = 'accepted'
                          AND COALESCE(ts.received_at, cl.occurred_at)
                              >= NOW() - ($1 || ' days')::interval
                     ) >= $2";

impl PgBackend {
    pub async fn new(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let pg_config = config
            .url()
            .parse::<tokio_postgres::Config>()
            .map_err(|e| DatabaseError::Pool(format!("invalid PostgreSQL URL: {e}")))?;
        let manager = deadpool_postgres::Manager::new(pg_config, tokio_postgres::NoTls);
        let pool = Pool::builder(manager).max_size(config.pool_size).build()?;

        // Build a SEPARATE, small resolver pool only when a distinct resolver
        // connection string is configured. This pool runs as the narrow
        // `trace_login_resolver` role and is never aliased to the runtime pool.
        let login_resolver_pool = match config.login_resolver_url() {
            Some(resolver_url) => {
                let resolver_config =
                    resolver_url
                        .parse::<tokio_postgres::Config>()
                        .map_err(|e| {
                            DatabaseError::Pool(format!(
                                "invalid login-resolver PostgreSQL URL: {e}"
                            ))
                        })?;
                let resolver_manager =
                    deadpool_postgres::Manager::new(resolver_config, tokio_postgres::NoTls);
                let resolver_pool = Pool::builder(resolver_manager).max_size(2).build()?;
                Some(resolver_pool)
            }
            None => None,
        };

        // Build a SEPARATE, small gate-driver pool only when a distinct
        // gate-driver connection string is configured. This pool runs as the
        // narrow `trace_gate_driver` role and is never aliased to the runtime
        // pool. Mirrors the login-resolver pool above exactly.
        let gate_driver_pool = match config.gate_driver_url() {
            Some(gate_driver_url) => {
                let gate_driver_config = gate_driver_url
                    .parse::<tokio_postgres::Config>()
                    .map_err(|e| {
                        DatabaseError::Pool(format!("invalid gate-driver PostgreSQL URL: {e}"))
                    })?;
                let gate_driver_manager =
                    deadpool_postgres::Manager::new(gate_driver_config, tokio_postgres::NoTls);
                let gate_driver_pool = Pool::builder(gate_driver_manager).max_size(2).build()?;
                Some(gate_driver_pool)
            }
            None => None,
        };

        // Build a SEPARATE, small PII-backstop driver pool only when a
        // distinct PII-backstop driver connection string is configured. This
        // pool runs as the narrow `trace_pii_backstop_driver` role and is
        // never aliased to the runtime pool. Mirrors the gate-driver pool
        // above exactly.
        let pii_backstop_driver_pool = match config.pii_backstop_driver_url() {
            Some(pii_backstop_driver_url) => {
                let pii_backstop_driver_config = pii_backstop_driver_url
                    .parse::<tokio_postgres::Config>()
                    .map_err(|e| {
                        DatabaseError::Pool(format!(
                            "invalid pii-backstop-driver PostgreSQL URL: {e}"
                        ))
                    })?;
                let pii_backstop_driver_manager = deadpool_postgres::Manager::new(
                    pii_backstop_driver_config,
                    tokio_postgres::NoTls,
                );
                let pii_backstop_driver_pool = Pool::builder(pii_backstop_driver_manager)
                    .max_size(2)
                    .build()?;
                Some(pii_backstop_driver_pool)
            }
            None => None,
        };

        // Build a SEPARATE, small invite-registry pool only when a distinct
        // invite-registry connection string is configured. This pool runs as
        // the narrow `trace_invite_registry` role and is never aliased to the
        // runtime pool. Mirrors the gate-driver pool above exactly.
        let invite_registry_pool = match config.invite_registry_url() {
            Some(invite_registry_url) => {
                let invite_registry_config = invite_registry_url
                    .parse::<tokio_postgres::Config>()
                    .map_err(|e| {
                        DatabaseError::Pool(format!("invalid invite-registry PostgreSQL URL: {e}"))
                    })?;
                let invite_registry_manager =
                    deadpool_postgres::Manager::new(invite_registry_config, tokio_postgres::NoTls);
                let invite_registry_pool =
                    Pool::builder(invite_registry_manager).max_size(2).build()?;
                Some(invite_registry_pool)
            }
            None => None,
        };

        Ok(Self {
            pool,
            login_resolver_pool,
            gate_driver_pool,
            pii_backstop_driver_pool,
            invite_registry_pool,
        })
    }

    pub(crate) fn trace_pool(&self) -> Pool {
        self.pool.clone()
    }

    #[doc(hidden)]
    pub fn trace_pool_for_test(&self) -> Pool {
        self.pool.clone()
    }

    #[doc(hidden)]
    pub fn raw_pool_for_tests_and_diagnostics(&self) -> Pool {
        self.pool.clone()
    }

    /// Resolve the tenant for a login code via the NARROW resolver pool (separate
    /// role, column-scoped SELECT, no BYPASSRLS). Returns the tenant only; the
    /// caller MUST re-confirm tenant inside an RLS-scoped transaction before any
    /// write. Fail-closed: if the resolver pool is not configured, this errors
    /// with a safe missing-control name rather than falling back to the runtime
    /// pool.
    pub async fn resolve_login_link_tenant(
        &self,
        code_hash: &str,
    ) -> anyhow::Result<Option<String>> {
        let pool = self
            .login_resolver_pool
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing-control: login-resolver-pool-unconfigured"))?;
        let client = pool.get().await?;
        // Safe without a tenant predicate: code_hash is globally UNIQUE (CHECK-shaped sha256) so
        // this returns at most one row across all tenants; the redeem handler re-confirms tenant
        // inside an RLS-scoped tx before any write. Do NOT add a non-unique lookup column to this
        // role's grant.
        let row = client
            .query_opt(
                "SELECT tenant_id FROM trace_login_links WHERE code_hash = $1",
                &[&code_hash],
            )
            .await?;
        Ok(row.map(|r| r.get::<_, String>(0)))
    }

    /// Resolve the tenant for a WebAuthn credential via the NARROW resolver pool
    /// (separate role, column-scoped SELECT, no BYPASSRLS). Returns the tenant
    /// only; the caller MUST re-confirm tenant inside an RLS-scoped transaction
    /// before any write. Fail-closed: if the resolver pool is not configured, this
    /// errors with a safe missing-control name rather than falling back to the
    /// runtime pool.
    ///
    /// Wired into the login handler in Task 6; until then its only non-test caller
    /// is pending. It is `pub` (part of the crate API, like
    /// `resolve_login_link_tenant`), so it does not trip dead-code under
    /// `-D warnings` despite having no internal caller yet.
    pub async fn resolve_credential_tenant(
        &self,
        credential_id: &str,
    ) -> anyhow::Result<Option<String>> {
        let pool = self
            .login_resolver_pool
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing-control: login-resolver-pool-unconfigured"))?;
        let client = pool.get().await?;
        // Safe without a tenant predicate: credential_id is globally UNIQUE so this returns at most
        // one row across all tenants; the login handler re-confirms tenant inside an RLS-scoped tx
        // before any write. Do NOT add a non-unique lookup column to this role's grant.
        let row = client
            .query_opt(
                "SELECT tenant_id FROM trace_webauthn_credentials WHERE credential_id = $1",
                &[&credential_id],
            )
            .await?;
        Ok(row.map(|r| r.get::<_, String>(0)))
    }

    /// Resolve a NEAR access public_key to its tenant via the narrow,
    /// restricted-role resolver pool (separate role, column-scoped SELECT, no
    /// BYPASSRLS), exactly like `resolve_credential_tenant`. Returns the tenant
    /// ONLY. The NEAR login path (Task 7) calls this with the public_key parsed
    /// from an UNAUTHENTICATED, wallet-signed assertion, BEFORE any tenant context
    /// exists, then re-confirms tenant inside an RLS-scoped tx before any write.
    /// Fail-closed: if the resolver pool is not configured, this errors with a
    /// safe missing-control name rather than falling back to the runtime pool.
    ///
    /// Wired into the login handler in Task 7; until then its only non-test caller
    /// is pending. It is `pub` (part of the crate API, like
    /// `resolve_credential_tenant`), so it does not trip dead-code under
    /// `-D warnings` despite having no internal caller yet.
    pub async fn resolve_near_public_key_tenant(
        &self,
        public_key: &str,
    ) -> anyhow::Result<Option<String>> {
        let pool = self
            .login_resolver_pool
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing-control: login-resolver-pool-unconfigured"))?;
        let client = pool.get().await?;
        // Safe without a tenant predicate: public_key is globally UNIQUE so this returns at most
        // one row across all tenants; the login handler re-confirms tenant inside an RLS-scoped tx
        // before any write. Do NOT add a non-unique lookup column to this role's grant.
        let row = client
            .query_opt(
                "SELECT tenant_id FROM trace_near_identities WHERE public_key = $1",
                &[&public_key],
            )
            .await?;
        Ok(row.map(|r| r.get::<_, String>(0)))
    }

    fn invite_registry_pool(&self) -> Result<Pool, DatabaseError> {
        self.invite_registry_pool
            .clone()
            .ok_or_else(|| DatabaseError::Pool("invite registry pool not configured".to_string()))
    }

    fn invite_entry_from_row(
        row: tokio_postgres::Row,
    ) -> Result<crate::trace_invite_registry::InviteEntry, DatabaseError> {
        let mode: String = row.get("tenant_mode");
        let tenant_mode = match mode.as_str() {
            "fixed" => crate::trace_invite_registry::InviteTenantMode::Fixed,
            "derived" => crate::trace_invite_registry::InviteTenantMode::Derived,
            other => {
                return Err(DatabaseError::Serialization(format!(
                    "unknown invite tenant_mode {other:?}"
                )));
            }
        };
        let max_uses: i32 = row.get("max_uses");
        Ok(crate::trace_invite_registry::InviteEntry {
            invite_subject_hash: row.get("invite_subject_hash"),
            policy_label: row.get("policy_label"),
            tenant_mode,
            fixed_tenant_id: row.get("fixed_tenant_id"),
            tenant_template_id: row.get("tenant_template_id"),
            policy_version: row.get("policy_version"),
            allowed_consent_scopes: row.get("allowed_consent_scopes"),
            allowed_uses: row.get("allowed_uses"),
            max_uses: max_uses as u32,
            expires_at: row.get("expires_at"),
            issuance_source: row.get("issuance_source"),
            issued_by_label: row.get("issued_by_label"),
            credential_binding_hash: row.get("credential_binding_hash"),
            note_label: row.get("note_label"),
            revoked_at: row.get("revoked_at"),
        })
    }

    /// Cache-refresh and admin listing. Runs on the registry pool, whose
    /// permissive V42 policy is what authorizes cross-invite reads. Excludes
    /// revoked and expired rows: the cache only ever holds live invites.
    pub async fn list_invite_grants(
        &self,
    ) -> Result<Vec<crate::trace_invite_registry::InviteEntry>, DatabaseError> {
        let pool = self.invite_registry_pool()?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        let rows = client
            .query(
                &format!(
                    "SELECT {INVITE_GRANT_COLUMNS}
                       FROM onboarding_invite_grants
                      WHERE revoked_at IS NULL
                        AND (expires_at IS NULL OR expires_at > NOW())"
                ),
                &[],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        rows.into_iter().map(Self::invite_entry_from_row).collect()
    }

    /// Count live grants in one pool. Backs the self-serve claim cap and the
    /// public remaining-count surface.
    ///
    /// "Live" matches `list_invite_grants`: not revoked, not expired. An
    /// expired Legion grant therefore frees a slot, which is the intended
    /// behaviour — an unredeemed allotment should not hold the cap down
    /// forever.
    ///
    /// Runs on the registry pool, whose permissive V42 policy authorizes the
    /// cross-invite read. The runtime pool cannot do this: its RLS predicate
    /// confines it to the single invite hash the caller presented.
    pub async fn count_live_invite_grants(&self, policy_label: &str) -> Result<u32, DatabaseError> {
        let pool = self.invite_registry_pool()?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        let row = client
            .query_one(
                "SELECT COUNT(*)::BIGINT AS live
                   FROM onboarding_invite_grants
                  WHERE policy_label = $1
                    AND revoked_at IS NULL
                    AND (expires_at IS NULL OR expires_at > NOW())",
                &[&policy_label],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let live: i64 = row.get("live");
        u32::try_from(live).map_err(|_| {
            DatabaseError::Serialization("invite grant count out of range".to_string())
        })
    }

    /// Count grants that occupy the V42 one-claim-per-account index, ignoring
    /// expiry.
    ///
    /// [`count_live_invite_grants`] excludes expired rows, but the V42 index is
    /// `WHERE credential_binding_hash IS NOT NULL AND revoked_at IS NULL` —
    /// expiry is not in the predicate, and cannot be: Postgres requires index
    /// predicates to be IMMUTABLE, so `NOW()` is not permitted there. An
    /// expired grant therefore still blocks its account from claiming again
    /// while no longer counting toward the cap. Counting the two differently
    /// turns a fixed cap into a rolling window — after one TTL a fresh cohort
    /// could claim the whole cap again, on top of everyone already holding a
    /// binding.
    ///
    /// This counts what the index enforces, so a cap bounds total issuance.
    pub async fn count_bound_invite_grants(
        &self,
        policy_label: &str,
    ) -> Result<u32, DatabaseError> {
        let pool = self.invite_registry_pool()?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        let row = client
            .query_one(
                "SELECT COUNT(*)::BIGINT AS bound
                   FROM onboarding_invite_grants
                  WHERE policy_label = $1
                    AND revoked_at IS NULL
                    AND credential_binding_hash IS NOT NULL",
                &[&policy_label],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let bound: i64 = row.get("bound");
        u32::try_from(bound).map_err(|_| {
            DatabaseError::Serialization("invite grant count out of range".to_string())
        })
    }

    /// True iff this credential already holds an unrevoked grant in any of
    /// `policy_labels`.
    ///
    /// The V42 index is scoped `(policy_label, credential_binding_hash)`, so it
    /// cannot see across pools. Where one cohort is split into several pools —
    /// as the Legion ranks are — an account whose rank changes resolves to a
    /// different label and the index does not fire. This is the cross-pool
    /// check the index structurally cannot perform.
    pub async fn credential_bound_in_any(
        &self,
        policy_labels: &[String],
        credential_binding_hash: &str,
    ) -> Result<bool, DatabaseError> {
        let pool = self.invite_registry_pool()?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        let row = client
            .query_one(
                "SELECT EXISTS (
                     SELECT 1
                       FROM onboarding_invite_grants
                      WHERE policy_label = ANY($1)
                        AND credential_binding_hash = $2
                        AND revoked_at IS NULL
                 ) AS bound",
                &[&policy_labels, &credential_binding_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(row.get("bound"))
    }

    pub async fn insert_invite_grant(
        &self,
        write: crate::db::InviteGrantWrite,
    ) -> Result<crate::db::InviteGrantInsertOutcome, DatabaseError> {
        let pool = self.invite_registry_pool()?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        let tenant_mode = match write.tenant_mode {
            crate::trace_invite_registry::InviteTenantMode::Fixed => "fixed",
            crate::trace_invite_registry::InviteTenantMode::Derived => "derived",
        };
        let max_uses = i32::try_from(write.max_uses).map_err(|_| {
            DatabaseError::Serialization("invite max_uses out of range".to_string())
        })?;
        let inserted = client
            .query_opt(
                "INSERT INTO onboarding_invite_grants (
                    invite_subject_hash, policy_label, tenant_mode, fixed_tenant_id,
                    tenant_template_id, policy_version, allowed_consent_scopes,
                    allowed_uses, max_uses, expires_at, issuance_source,
                    issued_by_label, credential_binding_hash, note_label
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                 ON CONFLICT (invite_subject_hash) DO NOTHING
                 RETURNING invite_subject_hash",
                &[
                    &write.invite_subject_hash,
                    &write.policy_label,
                    &tenant_mode,
                    &write.fixed_tenant_id,
                    &write.tenant_template_id,
                    &write.policy_version,
                    &write.allowed_consent_scopes,
                    &write.allowed_uses,
                    &max_uses,
                    &write.expires_at,
                    &write.issuance_source,
                    &write.issued_by_label,
                    &write.credential_binding_hash,
                    &write.note_label,
                ],
            )
            .await;

        match inserted {
            Ok(Some(_)) => Ok(crate::db::InviteGrantInsertOutcome::Inserted),
            Ok(None) => Ok(crate::db::InviteGrantInsertOutcome::AlreadyExists),
            Err(e) => {
                // 23505 unique_violation from the partial credential index.
                // Report it as a typed outcome, not an opaque 500, and never
                // echo the credential hash into the error.
                let is_unique_violation = e
                    .code()
                    .map(|c| c == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
                    .unwrap_or(false);
                if is_unique_violation {
                    Ok(crate::db::InviteGrantInsertOutcome::CredentialAlreadyBound)
                } else {
                    Err(DatabaseError::Postgres(e))
                }
            }
        }
    }

    /// Soft revoke. Returns true only when this call is what revoked it, so a
    /// second revoke is a reported no-op rather than an error.
    pub async fn revoke_invite_grant(
        &self,
        invite_subject_hash: &str,
    ) -> Result<bool, DatabaseError> {
        let pool = self.invite_registry_pool()?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        let updated = client
            .execute(
                "UPDATE onboarding_invite_grants
                    SET revoked_at = NOW(), updated_at = NOW()
                  WHERE invite_subject_hash = $1 AND revoked_at IS NULL",
                &[&invite_subject_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(updated == 1)
    }

    /// Authoritative in-transaction re-check on the RUNTIME pool. Sets the
    /// GUC the V42 invite_lookup policy reads, so this can only ever return
    /// the invite whose code the caller presented.
    pub async fn lookup_invite_grant_in_tx(
        tx: &deadpool_postgres::Transaction<'_>,
        invite_subject_hash: &str,
    ) -> Result<Option<crate::trace_invite_registry::InviteEntry>, DatabaseError> {
        tx.execute(
            "SELECT set_config('trace_commons.invite_subject', $1, true)",
            &[&invite_subject_hash],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        let row = tx
            .query_opt(
                &format!(
                    "SELECT {INVITE_GRANT_COLUMNS}
                       FROM onboarding_invite_grants
                      WHERE invite_subject_hash = $1
                        AND revoked_at IS NULL
                        AND (expires_at IS NULL OR expires_at > NOW())
                      FOR SHARE"
                ),
                &[&invite_subject_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        row.map(Self::invite_entry_from_row).transpose()
    }

    /// Authoritative redemption resolve. Runs on the RUNTIME pool under the
    /// V42 GUC policy, re-checks revocation and expiry inside the transaction,
    /// and holds FOR SHARE so a concurrent revoke serializes behind it.
    ///
    /// This does NOT increment the V29 counter; the caller does that in the
    /// same transaction via the existing onboard_device_key path.
    /// `Ok(None)` means the invite is not redeemable -- absent, revoked, or
    /// expired, deliberately indistinguishable to the caller. `Err` is
    /// reserved for genuine database failures, so a backend outage is never
    /// reported to a contributor as an invalid invite.
    pub async fn redeem_invite_grant(
        &self,
        invite_subject_hash: &str,
        user_subject: &str,
    ) -> Result<Option<InviteRedemption>, DatabaseError> {
        let pool = self.trace_pool();
        let mut client = pool.get().await.map_err(DatabaseError::from)?;
        let tx = client
            .transaction()
            .await
            .map_err(DatabaseError::Postgres)?;
        let Some(entry) = Self::lookup_invite_grant_in_tx(&tx, invite_subject_hash).await? else {
            return Ok(None);
        };

        let tenant_id = match entry.tenant_mode {
            crate::trace_invite_registry::InviteTenantMode::Fixed => {
                entry.fixed_tenant_id.clone().ok_or_else(|| {
                    DatabaseError::Serialization("invite fixed_tenant_id missing".to_string())
                })?
            }
            crate::trace_invite_registry::InviteTenantMode::Derived => {
                let template = entry.tenant_template_id.as_deref().ok_or_else(|| {
                    DatabaseError::Serialization("invite tenant_template_id missing".to_string())
                })?;
                trace_commons_protocol::onboarding::derive_user_tenant_id(template, user_subject)
            }
        };

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(Some(InviteRedemption {
            tenant_id,
            policy_version: entry.policy_version,
            allowed_consent_scopes: entry.allowed_consent_scopes,
            allowed_uses: entry.allowed_uses,
            max_uses: entry.max_uses,
        }))
    }
}

/// Resolved grant for a redeemed invite.
#[derive(Debug, Clone)]
pub struct InviteRedemption {
    pub tenant_id: String,
    pub policy_version: String,
    pub allowed_consent_scopes: Vec<String>,
    pub allowed_uses: Vec<String>,
    pub max_uses: u32,
}

const INVITE_GRANT_COLUMNS: &str = "invite_subject_hash, policy_label, tenant_mode,
    fixed_tenant_id, tenant_template_id, policy_version, allowed_consent_scopes,
    allowed_uses, max_uses, expires_at, issuance_source, issued_by_label,
    credential_binding_hash, note_label, revoked_at";

/// Serialises `run_migrations` across processes sharing one database.
///
/// The value is arbitrary but must never change: it is the identity of the lock
/// itself, and two builds disagreeing about it do not exclude each other. The
/// advisory-lock space is per database and shared with anything else that takes
/// one, so this is deliberately not a small number.
const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x7472_6163_655f_6d67;

/// Applies one migration and records it in `_trace_commons_migrations` as a
/// single transaction.
///
/// The apply and the record used to be two statements on one connection with
/// nothing wrapping them. A crash, a connection reset, or a failing insert
/// between the two left the migration applied but unrecorded, and the next boot
/// re-ran it and died on `already exists` -- an unbootable server that only a
/// hand-written INSERT could clear. Committing both together makes that state
/// unreachable: either the version is recorded and its DDL is durable, or
/// neither is.
///
/// This is sound only because every migration in `migrations/` is executable
/// inside a transaction block. PostgreSQL refuses a handful of statements there
/// -- `CREATE INDEX CONCURRENTLY`, `DROP INDEX CONCURRENTLY`,
/// `REINDEX CONCURRENTLY`, `ALTER TABLE ... DETACH PARTITION CONCURRENTLY`,
/// `VACUUM`, `CREATE`/`DROP DATABASE`, `CREATE`/`DROP TABLESPACE`,
/// `ALTER SYSTEM`, `CREATE`/`DROP SUBSCRIPTION`, `DISCARD`, and, before
/// PostgreSQL 12, `ALTER TYPE ... ADD VALUE`. `migrations/` holds none of them
/// as of V60, and
/// `no_migration_uses_a_statement_postgres_refuses_inside_a_transaction` fails
/// the build if one appears. A migration that genuinely needs a concurrent
/// index has to opt out of this wrapper explicitly -- carrying the reason in
/// code, and recording itself on the same connection immediately afterwards.
/// Do not quietly unwrap every migration to accommodate one.
///
/// `batch_execute` sends the file as one simple-query message, which PostgreSQL
/// already runs as an implicit transaction; the explicit one folds the record
/// into that unit, it does not change how the file's own statements relate.
///
/// Exposed (hidden) so `tests/migration_atomicity_pg.rs` can drive it against a
/// recording forced to fail, which is the only way to observe the rollback.
#[doc(hidden)]
pub async fn apply_and_record_migration(
    client: &mut tokio_postgres::Client,
    version: i32,
    name: &str,
    sql: &str,
) -> Result<(), DatabaseError> {
    let tx = client.transaction().await?;
    tx.batch_execute(sql).await?;
    tx.execute(
        "INSERT INTO _trace_commons_migrations (version, name) VALUES ($1, $2)",
        &[&version, &name],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Every migration in `migrations/`, in the order `run_migrations` applies
/// them: `(version, recorded name, SQL text)`. The recorded name is the file
/// stem and the SQL is the file itself, embedded at compile time.
///
/// This table is the wiring: a migration file that is not listed here silently
/// never runs. `every_migration_is_wired_into_run_migrations` checks the table
/// against the directory, including that each row's `include_str!` names the
/// row's own version and stem.
///
/// Applying a row is `apply_and_record_migration`, which commits the DDL and
/// the `_trace_commons_migrations` insert together.
const MIGRATIONS: &[(i32, &str, &str)] = &[
    (
        1,
        "trace_commons_schema",
        include_str!("../../../../migrations/V1__trace_commons_schema.sql"),
    ),
    (
        2,
        "trace_credit_settlement",
        include_str!("../../../../migrations/V2__trace_credit_settlement.sql"),
    ),
    (
        3,
        "trace_ranking_evidence",
        include_str!("../../../../migrations/V3__trace_ranking_evidence.sql"),
    ),
    (
        4,
        "trace_ranking_calibration_runs",
        include_str!("../../../../migrations/V4__trace_ranking_calibration_runs.sql"),
    ),
    (
        5,
        "trace_credit_settlement_ranking_gate",
        include_str!("../../../../migrations/V5__trace_credit_settlement_ranking_gate.sql"),
    ),
    (
        6,
        "trace_force_rls",
        include_str!("../../../../migrations/V6__trace_force_rls.sql"),
    ),
    (
        7,
        "trace_ranking_calibration_label_source_gate",
        include_str!("../../../../migrations/V7__trace_ranking_calibration_label_source_gate.sql"),
    ),
    (
        8,
        "trace_ranking_calibration_source_error_gate",
        include_str!("../../../../migrations/V8__trace_ranking_calibration_source_error_gate.sql"),
    ),
    (
        9,
        "trace_ranking_calibration_joined_evidence_hash",
        include_str!(
            "../../../../migrations/V9__trace_ranking_calibration_joined_evidence_hash.sql"
        ),
    ),
    (
        10,
        "trace_credit_settlement_joined_evidence_hash",
        include_str!(
            "../../../../migrations/V10__trace_credit_settlement_joined_evidence_hash.sql"
        ),
    ),
    (
        11,
        "trace_ranking_worker_runs",
        include_str!("../../../../migrations/V11__trace_ranking_worker_runs.sql"),
    ),
    (
        12,
        "trace_ranking_worker_run_lifecycle",
        include_str!("../../../../migrations/V12__trace_ranking_worker_run_lifecycle.sql"),
    ),
    (
        13,
        "trace_credit_settlement_exclusion_reasons",
        include_str!("../../../../migrations/V13__trace_credit_settlement_exclusion_reasons.sql"),
    ),
    (
        14,
        "trace_ranking_preference_labels",
        include_str!("../../../../migrations/V14__trace_ranking_preference_labels.sql"),
    ),
    (
        15,
        "trace_benchmark_registry_outbox",
        include_str!("../../../../migrations/V15__trace_benchmark_registry_outbox.sql"),
    ),
    (
        16,
        "trace_ranking_calibration_datasets",
        include_str!("../../../../migrations/V16__trace_ranking_calibration_datasets.sql"),
    ),
    (
        17,
        "trace_ranking_calibration_dataset_manifest_immutability",
        include_str!(
            "../../../../migrations/V17__trace_ranking_calibration_dataset_manifest_immutability.sql"
        ),
    ),
    (
        18,
        "trace_central_rls_tenant_predicate",
        include_str!("../../../../migrations/V18__trace_central_rls_tenant_predicate.sql"),
    ),
    (
        19,
        "trace_ranking_calibration_label_actor_count",
        include_str!("../../../../migrations/V19__trace_ranking_calibration_label_actor_count.sql"),
    ),
    (
        20,
        "trace_credit_settlement_issuer_approval_hash",
        include_str!(
            "../../../../migrations/V20__trace_credit_settlement_issuer_approval_hash.sql"
        ),
    ),
    (
        21,
        "trace_near_credit_account_outbox",
        include_str!("../../../../migrations/V21__trace_near_credit_account_outbox.sql"),
    ),
    (
        22,
        "trace_revocation_worker_queue_invalidation",
        include_str!("../../../../migrations/V22__trace_revocation_worker_queue_invalidation.sql"),
    ),
    (
        23,
        "novelty_utility_credit_and_gate_decisions",
        include_str!("../../../../migrations/V23__novelty_utility_credit_and_gate_decisions.sql"),
    ),
    (
        24,
        "gate_decision_vector_entry_id",
        include_str!("../../../../migrations/V24__gate_decision_vector_entry_id.sql"),
    ),
    (
        25,
        "gate_decision_credit_withheld_reason",
        include_str!("../../../../migrations/V25__gate_decision_credit_withheld_reason.sql"),
    ),
    (
        26,
        "trace_contributor_profiles",
        include_str!("../../../../migrations/V26__trace_contributor_profiles.sql"),
    ),
    (
        27,
        "trace_leaderboard_snapshots",
        include_str!("../../../../migrations/V27__trace_leaderboard_snapshots.sql"),
    ),
    (
        28,
        "device_keys",
        include_str!("../../../../migrations/V28__device_keys.sql"),
    ),
    (
        29,
        "onboarding_invites",
        include_str!("../../../../migrations/V29__onboarding_invites.sql"),
    ),
    (
        30,
        "trace_accounts",
        include_str!("../../../../migrations/V30__trace_accounts.sql"),
    ),
    (
        31,
        "account_traces_index",
        include_str!("../../../../migrations/V31__account_traces_index.sql"),
    ),
    (
        32,
        "webauthn_credentials",
        include_str!("../../../../migrations/V32__webauthn_credentials.sql"),
    ),
    (
        33,
        "near_identities",
        include_str!("../../../../migrations/V33__near_identities.sql"),
    ),
    (
        34,
        "account_consolidation",
        include_str!("../../../../migrations/V34__account_consolidation.sql"),
    ),
    (
        35,
        "trace_instance_enrollments",
        include_str!("../../../../migrations/V35__trace_instance_enrollments.sql"),
    ),
    (
        36,
        "trace_gate_driver",
        include_str!("../../../../migrations/V36__trace_gate_driver.sql"),
    ),
    (
        37,
        "large_trace_chunked_scoring",
        include_str!("../../../../migrations/V37__large_trace_chunked_scoring.sql"),
    ),
    // V38 ships with the server-side PII backstop. It is applied here
    // out of numeric order relative to what a long-lived pilot may
    // already hold (V39-V41 landed on main while this sat unmerged);
    // that is safe because each block gates on its own version number,
    // not on sequence position.
    (
        38,
        "trace_pii_backstop",
        include_str!("../../../../migrations/V38__trace_pii_backstop.sql"),
    ),
    (
        39,
        "trace_credit_quality",
        include_str!("../../../../migrations/V39__trace_credit_quality.sql"),
    ),
    (
        40,
        "trace_dedup",
        include_str!("../../../../migrations/V40__trace_dedup.sql"),
    ),
    (
        41,
        "trace_contributor_cap",
        include_str!("../../../../migrations/V41__trace_contributor_cap.sql"),
    ),
    // V42 makes the database authoritative for contributor invites.
    (
        42,
        "onboarding_invite_grants",
        include_str!("../../../../migrations/V42__onboarding_invite_grants.sql"),
    ),
    // V43 (not V42: that number is held by the unmerged
    // db-authoritative-invites branch) adds the contributor-withdrawal
    // tombstone and the trace_submissions.withdrawn_at column.
    (
        43,
        "trace_withdrawal",
        include_str!("../../../../migrations/V43__trace_withdrawal.sql"),
    ),
    // V44 widens the trace_sessions.client_kind CHECK to admit 'native',
    // the client_kind of a loopback native-app session token.
    (
        44,
        "native_session_client_kind",
        include_str!("../../../../migrations/V44__native_session_client_kind.sql"),
    ),
    // V45 retrofits V36's table-wide SELECT grants to the V38
    // column-scoped convention. Safe to apply after V36+; the USING(true)
    // policies stay.
    (
        45,
        "trace_gate_driver_column_grants",
        include_str!("../../../../migrations/V45__trace_gate_driver_column_grants.sql"),
    ),
    // V46 evicts withdrawn contributors from published community
    // snapshots.
    //
    // Renumbered from V42 on merge: V42 is held by the unmerged
    // db-authoritative-invites branch, V43/V44 landed on main while this
    // branch was open, and V45 is taken by the gate-driver column-grants
    // branch.
    (
        46,
        "community_snapshot_withdrawal_eviction",
        include_str!("../../../../migrations/V46__community_snapshot_withdrawal_eviction.sql"),
    ),
    // V47 persists the pre-cap chunk total on gate decisions and repairs
    // the gate-driver column-grant drift left by V37 (chunk_count and
    // chunks_capped were added without extending the column-level
    // grants).
    (
        47,
        "trace_gate_decision_total_chunk_count",
        include_str!("../../../../migrations/V47__trace_gate_decision_total_chunk_count.sql"),
    ),
    // V48 adds the shadow-mode correction-value columns (S5) and grants
    // the two the cross-tenant correction-cluster scan reads to the
    // gate-driver role. `run_migrations` is hand-rolled: a migration file
    // that is not wired in here silently never runs.
    (
        48,
        "trace_correction_value",
        include_str!("../../../../migrations/V48__trace_correction_value.sql"),
    ),
    (
        49,
        "trace_submission_last_status_reason",
        include_str!("../../../../migrations/V49__trace_submission_last_status_reason.sql"),
    ),
    (
        50,
        "onboarding_invite_grant_consumption",
        include_str!("../../../../migrations/V50__onboarding_invite_grant_consumption.sql"),
    ),
    (
        51,
        "privacy_classify_window_cache",
        include_str!("../../../../migrations/V51__privacy_classify_window_cache.sql"),
    ),
    (
        52,
        "trace_submission_residual_risk_basis",
        include_str!("../../../../migrations/V52__trace_submission_residual_risk_basis.sql"),
    ),
    // V53 adds the prospective gate-utility instrumentation columns
    // (#199). Additive and backfill-free: rows written before it keep NULL
    // forever, because a novelty score recomputed against a fuller index
    // is not the number production used.
    (
        53,
        "trace_gate_decision_composite_score",
        include_str!("../../../../migrations/V53__trace_gate_decision_composite_score.sql"),
    ),
    (
        54,
        "trace_gate_decision_qualifying_mass",
        include_str!("../../../../migrations/V54__trace_gate_decision_qualifying_mass.sql"),
    ),
    (
        55,
        "register_stats_public_read",
        include_str!("../../../../migrations/V55__register_stats_public_read.sql"),
    ),
    (
        56,
        "community_withdrawal_eviction_rls",
        include_str!("../../../../migrations/V56__community_withdrawal_eviction_rls.sql"),
    ),
    // V57 names the derivation behind dedup_simhash (#211, #325).
    // Additive, nullable and backfill-free: a row written before it keeps
    // NULL, which code reads as the legacy v1 stamp rather than as
    // unknown. Also grants the new column to the gate-driver role, which
    // holds column-scoped grants and now selects it in
    // `list_dedup_signals`.
    (
        57,
        "trace_gate_decision_dedup_signal_version",
        include_str!("../../../../migrations/V57__trace_gate_decision_dedup_signal_version.sql"),
    ),
    (
        58,
        "near_account_provisioning",
        include_str!("../../../../migrations/V58__near_account_provisioning.sql"),
    ),
    (
        59,
        "trace_admission_ledger",
        include_str!("../../../../migrations/V59__trace_admission_ledger.sql"),
    ),
    (
        60,
        "onboarding_retention",
        include_str!("../../../../migrations/V60__onboarding_retention.sql"),
    ),
    // V61 salts the NEAR account anchor (#716): the anchor becomes a peppered
    // blind index, the tenant id becomes random, and the account name is stored
    // sealed so the pepper can be rotated. It refuses outright if pre-salting
    // anchor rows exist, because their account names were never stored and the
    // new index cannot be computed for them.
    (
        61,
        "near_account_anchor_salting",
        include_str!("../../../../migrations/V61__near_account_anchor_salting.sql"),
    ),
    // V62 finishes what V61 only appeared to do. V61 looked for V58's
    // tenant/anchor CHECK by its rendered definition, matching `substring`
    // where Postgres prints `SUBSTRING`, so it dropped nothing and still
    // reported success -- leaving the tenant id derived from the anchor, which
    // is the whole defect V61 exists to remove. V62 finds the constraint by the
    // columns it constrains rather than by how the server prints it, and then
    // re-reads the catalogue and refuses if it is still there.
    (
        62,
        "near_account_anchor_tenant_binding_drop",
        include_str!("../../../../migrations/V62__near_account_anchor_tenant_binding_drop.sql"),
    ),
    // A NEAR AI login as a second source of the admission anchor (#836).
    // Widens two `device_keys` CHECKs to admit a `near_ai` origin, and records
    // on the anchor row which identity system minted it. The widening is
    // add-then-drop so the table is never less constrained than before.
    (
        63,
        "near_ai_login_provisioning",
        include_str!("../../../../migrations/V63__near_ai_login_provisioning.sql"),
    ),
    (
        64,
        "token_distribution_bundles",
        include_str!("../../../../migrations/V64__token_distribution_bundles.sql"),
    ),
    (
        65,
        "token_bundle_processing",
        include_str!("../../../../migrations/V65__token_bundle_processing.sql"),
    ),
    (
        66,
        "token_processing_retry",
        include_str!("../../../../migrations/V66__token_processing_retry.sql"),
    ),
    (
        67,
        "token_rescrub_revocation",
        include_str!("../../../../migrations/V67__token_rescrub_revocation.sql"),
    ),
];

#[async_trait]
impl Database for PgBackend {
    async fn admission_runtime_ready(&self) -> Result<bool, DatabaseError> {
        self.check_admission_runtime().await
    }
    async fn lookup_completed_submission_admission(
        &self,
        tenant: &str,
        anchor: &str,
        submission: uuid::Uuid,
        body_hash: &str,
    ) -> Result<bool, DatabaseError> {
        self.completed_admission(tenant, anchor, submission, body_hash)
            .await
    }
    async fn acquire_admission_processing_lock(
        &self,
        tenant: &str,
        submission: uuid::Uuid,
    ) -> Result<Option<crate::admission_ledger::AdmissionProcessingGuard>, DatabaseError> {
        self.lock_admission(tenant, submission).await
    }
    async fn prune_onboarding_expiry(
        &self,
        tenant: &str,
        limit: i32,
        dry_run: bool,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id',$1,true)",
            &[&tenant],
        )
        .await?;
        let count: i64 = tx
            .query_one(
                "SELECT trace_prune_onboarding_expiry($1,$2,$3)",
                &[&tenant, &limit, &dry_run],
            )
            .await?
            .get(0);
        tx.commit().await?;
        u64::try_from(count)
            .map_err(|_| DatabaseError::Pool("onboarding_retention_unavailable".into()))
    }
    async fn issue_admission_challenge(
        &self,
        tenant: &str,
        anchor: &str,
        challenge: &str,
        expires: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DatabaseError> {
        self.insert_admission_challenge(tenant, anchor, challenge, expires)
            .await
    }
    async fn reserve_submission_admission(
        &self,
        request: &crate::admission_ledger::AdmissionReservation,
    ) -> Result<crate::admission_ledger::AdmissionDecision, DatabaseError> {
        self.reserve_admission(request).await
    }
    async fn transition_submission_admission(
        &self,
        tenant: &str,
        submission: uuid::Uuid,
        lease: uuid::Uuid,
        next: &str,
    ) -> Result<bool, DatabaseError> {
        self.transition_admission(tenant, submission, lease, next)
            .await
    }

    async fn try_acquire_near_credit_submit_lock(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::db::NearCreditSubmitAdvisoryLock>, DatabaseError> {
        let client = self
            .trace_pool()
            .get()
            .await
            .map_err(|e| DatabaseError::Pool(e.to_string()))?;
        // Derive the per-tenant objid in SQL so it matches the unlock key exactly.
        let objid: i32 = client
            .query_one(
                "SELECT hashtext('near-credit-submit:' || $1)",
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .get(0);
        let acquired: bool = client
            .query_one(
                "SELECT pg_try_advisory_lock($1, $2)",
                &[&NEAR_CREDIT_SUBMIT_ADVISORY_LOCK_CLASSID, &objid],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .get(0);
        if !acquired {
            // Another submit run already holds the lock; drop the connection back
            // to the pool without taking ownership.
            return Ok(None);
        }
        Ok(Some(crate::db::NearCreditSubmitAdvisoryLock::new(
            NearCreditSubmitAdvisoryLockInner { client, objid },
        )))
    }

    async fn try_acquire_credit_settlement_lock(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::db::CreditSettlementAdvisoryLock>, DatabaseError> {
        let client = self
            .trace_pool()
            .get()
            .await
            .map_err(|e| DatabaseError::Pool(e.to_string()))?;
        let objid: i32 = client
            .query_one("SELECT hashtext('credit-settlement:' || $1)", &[&tenant_id])
            .await
            .map_err(DatabaseError::Postgres)?
            .get(0);
        let acquired: bool = client
            .query_one(
                "SELECT pg_try_advisory_lock($1, $2)",
                &[&CREDIT_SETTLEMENT_ADVISORY_LOCK_CLASSID, &objid],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .get(0);
        if !acquired {
            return Ok(None);
        }
        Ok(Some(crate::db::CreditSettlementAdvisoryLock::new(
            CreditSettlementAdvisoryLockInner { client, objid },
        )))
    }

    async fn upsert_credit_settlement_finalize(
        &self,
        batch: crate::trace_corpus_storage::TraceCreditSettlementBatchWrite,
        outbox_items: Vec<crate::trace_corpus_storage::TraceNearCreditOutboxItemWrite>,
    ) -> Result<(), DatabaseError> {
        self.upsert_credit_settlement_finalize_tx(batch, &outbox_items)
            .await
    }

    async fn run_migrations(&self) -> Result<(), DatabaseError> {
        let mut client = self
            .trace_pool()
            .get()
            .await
            .map_err(|e| DatabaseError::Pool(e.to_string()))?;
        // One migration run at a time per database. Nothing below is atomic
        // against a second caller: `CREATE TABLE IF NOT EXISTS` is not atomic
        // against a concurrent `CREATE TABLE` in PostgreSQL, and neither is the
        // applied/not-applied check -- two callers both read a migration as
        // unapplied, both run its DDL, and the loser dies on a system-catalog
        // unique index with `duplicate key value violates unique constraint
        // "pg_type_typname_nsp_index"`, which names nothing a reader can act on.
        // A rolling restart reaches that, and so does an operator running an
        // issuer subcommand (they migrate at boot) beside a starting service.
        //
        // The lock is session-scoped, not transaction-scoped, because each
        // migration commits in its own transaction; it therefore has to be
        // released by hand before the connection goes back to the pool, on the
        // failure path as much as the success one.
        client
            .execute(
                "SELECT pg_advisory_lock($1)",
                &[&MIGRATION_ADVISORY_LOCK_KEY],
            )
            .await?;
        let applied = async {
            client
                .batch_execute(
                    "CREATE TABLE IF NOT EXISTS _trace_commons_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );",
                )
                .await?;
            for (version, name, sql) in MIGRATIONS {
                let already_applied = client
                    .query_opt(
                        "SELECT 1 FROM _trace_commons_migrations WHERE version = $1",
                        &[version],
                    )
                    .await?
                    .is_some();
                if !already_applied {
                    apply_and_record_migration(&mut client, *version, name, sql).await?;
                }
            }
            Ok::<(), DatabaseError>(())
        }
        .await;
        let released = client
            .execute(
                "SELECT pg_advisory_unlock($1)",
                &[&MIGRATION_ADVISORY_LOCK_KEY],
            )
            .await;
        // The migration failure is the one worth reporting; a failure to
        // release only matters when the run itself was clean.
        applied?;
        released?;
        Ok(())
    }

    async fn trace_corpus_rls_diagnostics(
        &self,
    ) -> Result<Option<TraceCorpusRlsDiagnostics>, DatabaseError> {
        let mut client = self
            .trace_pool()
            .get()
            .await
            .map_err(|e| DatabaseError::Pool(e.to_string()))?;
        let expected_tables = TRACE_COMMONS_RLS_TABLES
            .iter()
            .map(|table| (*table).to_string())
            .collect::<Vec<_>>();
        let expected_policy_expressions = TRACE_COMMONS_RLS_POLICY_EXPRESSION_VARIANTS
            .iter()
            .map(|expression| (*expression).to_string())
            .collect::<Vec<_>>();
        let rows = client
            .query(
                "SELECT
                    c.relname,
                    c.relrowsecurity,
                    c.relforcerowsecurity,
                    COALESCE(p.has_policy, false) AS has_policy,
                    COALESCE(p.expression_matches, false) AS expression_matches
                 FROM pg_class c
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                 LEFT JOIN LATERAL (
                    SELECT
                        true AS has_policy,
                        pol.polcmd = '*'
                            AND pg_get_expr(pol.polqual, pol.polrelid) = ANY($2)
                            AND pg_get_expr(pol.polwithcheck, pol.polrelid) = ANY($2)
                            AS expression_matches
                        FROM pg_policies p
                        JOIN pg_policy pol
                          ON pol.polname = p.policyname
                         AND pol.polrelid = c.oid
                        WHERE p.schemaname = n.nspname
                          AND p.tablename = c.relname
                          AND p.policyname = 'trace_corpus_tenant_isolation'
                        LIMIT 1
                 ) p ON true
                 WHERE n.nspname = current_schema()
                   AND c.relkind = 'r'
                   AND c.relname = ANY($1)",
                &[&expected_tables, &expected_policy_expressions],
            )
            .await?;
        let current_role = client
            .query_one(
                "SELECT
                    current_user AS current_role_name,
                    EXISTS (
                        SELECT 1
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        JOIN pg_roles r ON r.oid = c.relowner
                        WHERE n.nspname = current_schema()
                          AND c.relkind = 'r'
                          AND c.relname = ANY($1)
                          AND r.rolname = current_user
                    ) AS owns_trace_tables,
                    EXISTS (
                        SELECT 1
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        JOIN pg_roles r ON r.oid = c.relowner
                        WHERE n.nspname = current_schema()
                          AND c.relkind = 'r'
                          AND c.relname = ANY($1)
                          AND r.rolname = current_user
                          AND NOT c.relforcerowsecurity
                    ) AS owns_unforced_trace_tables,
                    COALESCE((
                        SELECT rolsuper OR rolbypassrls
                        FROM pg_roles
                        WHERE rolname = current_user
                    ), false) AS bypass_role",
                &[&expected_tables],
            )
            .await?;

        let mut seen_tables = HashSet::new();
        let mut rls_enabled_count = 0usize;
        let mut force_rls_enabled_count = 0usize;
        let mut policy_installed_count = 0usize;
        let mut rls_disabled_tables = Vec::new();
        let mut force_rls_disabled_tables = Vec::new();
        let mut missing_policy_tables = Vec::new();
        let mut policy_expression_mismatch_tables = Vec::new();
        for row in rows {
            let table: String = row.get("relname");
            let rls_enabled: bool = row.get("relrowsecurity");
            let force_rls_enabled: bool = row.get("relforcerowsecurity");
            let has_policy: bool = row.get("has_policy");
            let expression_matches: bool = row.get("expression_matches");
            seen_tables.insert(table.clone());
            if rls_enabled {
                rls_enabled_count += 1;
            } else {
                rls_disabled_tables.push(table.clone());
            }
            if force_rls_enabled {
                force_rls_enabled_count += 1;
            } else {
                force_rls_disabled_tables.push(table.clone());
            }
            if has_policy {
                policy_installed_count += 1;
                if !expression_matches {
                    policy_expression_mismatch_tables.push(table.clone());
                }
            } else {
                missing_policy_tables.push(table.clone());
            }
        }
        for table in &expected_tables {
            if !seen_tables.contains(table) {
                missing_policy_tables.push(table.clone());
                rls_disabled_tables.push(table.clone());
                force_rls_disabled_tables.push(table.clone());
            }
        }
        missing_policy_tables.sort();
        missing_policy_tables.dedup();
        rls_disabled_tables.sort();
        rls_disabled_tables.dedup();
        force_rls_disabled_tables.sort();
        force_rls_disabled_tables.dedup();
        policy_expression_mismatch_tables.sort();
        policy_expression_mismatch_tables.dedup();

        let current_role_name: String = current_role.get("current_role_name");
        let owns_unforced_trace_tables: bool = current_role.get("owns_unforced_trace_tables");
        let owns_trace_tables: bool = current_role.get("owns_trace_tables");
        let bypass_role: bool = current_role.get("bypass_role");
        let tenant_context_transaction_local =
            trace_tenant_context_is_transaction_local(&mut client).await?;
        Ok(Some(TraceCorpusRlsDiagnostics {
            expected_table_count: expected_tables.len(),
            rls_enabled_count,
            force_rls_enabled_count,
            policy_installed_count,
            missing_policy_tables,
            rls_disabled_tables,
            force_rls_disabled_tables,
            policy_expression_mismatch_tables,
            current_role_hash: sha256_prefixed(&current_role_name),
            current_role_bypasses_rls: owns_unforced_trace_tables || bypass_role,
            current_role_owns_trace_tables: owns_trace_tables,
            tenant_context_transaction_local,
        }))
    }

    async fn upsert_contributor_profile(
        &self,
        tenant_id: &str,
        principal_ref: &str,
        display_handle: &str,
        handle_normalized: &str,
        bio: Option<&str>,
    ) -> Result<crate::db::ContributorProfileRow, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let bio_opt: Option<&str> = bio;
        let row = tx
            .query_one(
                "INSERT INTO trace_contributor_profiles (
                    tenant_id, principal_ref, display_handle, handle_normalized, bio
                 ) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tenant_id, principal_ref) DO UPDATE SET
                    display_handle = excluded.display_handle,
                    handle_normalized = excluded.handle_normalized,
                    bio = excluded.bio,
                    last_updated_at = NOW(),
                    update_count = trace_contributor_profiles.update_count + 1,
                    withdrawn_at = NULL
                 RETURNING tenant_id, principal_ref, display_handle, handle_normalized,
                           bio, public_since, last_updated_at, update_count",
                &[
                    &tenant_id,
                    &principal_ref,
                    &display_handle,
                    &handle_normalized,
                    &bio_opt,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(crate::db::ContributorProfileRow {
            tenant_id: row.get("tenant_id"),
            principal_ref: row.get("principal_ref"),
            display_handle: row.get("display_handle"),
            handle_normalized: row.get("handle_normalized"),
            bio: row.get("bio"),
            public_since: row.get("public_since"),
            last_updated_at: row.get("last_updated_at"),
            update_count: row.get("update_count"),
        })
    }

    async fn withdraw_contributor_profile(
        &self,
        tenant_id: &str,
        principal_ref: &str,
        window_label: &str,
        metric: &str,
    ) -> Result<Option<crate::db::CommunityWithdrawalEvictionRow>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let profile = tx
            .query_opt(
                "SELECT display_handle, handle_normalized
                   FROM trace_contributor_profiles
                  WHERE tenant_id = $1 AND principal_ref = $2 AND withdrawn_at IS NULL
                  FOR UPDATE",
                &[&tenant_id, &principal_ref],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let Some(profile) = profile else {
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(None);
        };
        let display_handle: String = profile.get("display_handle");
        let handle_normalized: String = profile.get("handle_normalized");
        let withdrawn = tx
            .query_one(
                "UPDATE trace_contributor_profiles
                    SET withdrawn_at = NOW(), last_updated_at = NOW()
                  WHERE tenant_id = $1 AND principal_ref = $2 AND withdrawn_at IS NULL
              RETURNING withdrawn_at",
                &[&tenant_id, &principal_ref],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let withdrawn_at: chrono::DateTime<chrono::Utc> = withdrawn.get("withdrawn_at");
        // Coalesce by (window, metric): N withdrawals in a window share one
        // rebuild. Keep the latest pending_requested_at so a snapshot that
        // finished before the newest withdrawal stays refused.
        let invalidation = tx
            .query_one(
                "INSERT INTO trace_community_snapshot_invalidations (
                    window_label, metric, pending_requested_at, pending_withdrawal_count
                 ) VALUES ($1, $2, $3, 1)
                 ON CONFLICT (window_label, metric) DO UPDATE SET
                    pending_requested_at = EXCLUDED.pending_requested_at,
                    pending_withdrawal_count = CASE
                        WHEN trace_community_snapshot_invalidations.pending_requested_at IS NULL
                            THEN 1
                        ELSE trace_community_snapshot_invalidations.pending_withdrawal_count + 1
                    END
                 RETURNING pending_requested_at",
                &[&window_label, &metric, &withdrawn_at],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let invalidation_requested_at: chrono::DateTime<chrono::Utc> =
            invalidation.get("pending_requested_at");
        let eviction_id = uuid::Uuid::new_v4();
        tx.execute(
            "INSERT INTO trace_community_withdrawal_evictions (
                eviction_id, tenant_id, principal_ref, display_handle, handle_normalized,
                withdrawn_at, invalidation_requested_at, window_label, metric
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &eviction_id,
                &tenant_id,
                &principal_ref,
                &display_handle,
                &handle_normalized,
                &withdrawn_at,
                &invalidation_requested_at,
                &window_label,
                &metric,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(Some(crate::db::CommunityWithdrawalEvictionRow {
            eviction_id,
            tenant_id: tenant_id.to_string(),
            principal_ref: principal_ref.to_string(),
            display_handle: Some(display_handle),
            handle_normalized: Some(handle_normalized),
            withdrawn_at,
            invalidation_requested_at,
            window_label: window_label.to_string(),
            metric: metric.to_string(),
        }))
    }

    async fn pending_community_snapshot_invalidation(
        &self,
        window_label: &str,
        metric: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, DatabaseError> {
        let client = self.trace_pool().get().await?;
        let row = client
            .query_opt(
                "SELECT pending_requested_at
                   FROM trace_community_snapshot_invalidations
                  WHERE window_label = $1 AND metric = $2
                    AND pending_requested_at IS NOT NULL",
                &[&window_label, &metric],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(row.map(|row| row.get("pending_requested_at")))
    }

    async fn drain_community_snapshot_invalidation(
        &self,
        window_label: &str,
        metric: &str,
        snapshot_id: uuid::Uuid,
        snapshot_computed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, DatabaseError> {
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = client
            .transaction()
            .await
            .map_err(DatabaseError::Postgres)?;
        // The eviction UPDATE below is deliberately cross-tenant: one drain
        // covers every pending withdrawal for this (window, metric). V56 gates
        // that on this transaction-local GUC rather than on a tenant
        // predicate. Without it the statement does not fail -- it silently
        // marks zero rows, because the tenant policy hides every row from a
        // connection with no tenant context.
        tx.execute(
            "SELECT set_config('trace_commons.community_drain', 'on', true)",
            &[],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        let drained = tx
            .execute(
                "UPDATE trace_community_snapshot_invalidations
                    SET pending_requested_at = NULL,
                        pending_withdrawal_count = 0,
                        last_drained_at = $3,
                        last_drained_snapshot_id = $4
                  WHERE window_label = $1
                    AND metric = $2
                    AND pending_requested_at IS NOT NULL
                    AND pending_requested_at <= $3",
                &[&window_label, &metric, &snapshot_computed_at, &snapshot_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        if drained > 0 {
            tx.execute(
                "UPDATE trace_community_withdrawal_evictions
                    SET drained_at = $3,
                        drained_snapshot_id = $4
                  WHERE window_label = $1
                    AND metric = $2
                    AND drained_at IS NULL
                    AND invalidation_requested_at <= $3",
                &[&window_label, &metric, &snapshot_computed_at, &snapshot_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        }
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(drained > 0)
    }

    async fn append_contributor_profile_audit(
        &self,
        tenant_id: &str,
        principal_ref: &str,
        action: &str,
        handle_normalized: Option<&str>,
        reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_contributor_profile_audit (
                tenant_id, principal_ref, action, handle_normalized, reason
             ) VALUES ($1, $2, $3, $4, $5)",
            &[
                &tenant_id,
                &principal_ref,
                &action,
                &handle_normalized,
                &reason,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn compute_leaderboard_inputs(
        &self,
        window_days: i32,
        min_cell_count: i64,
        configured_tenant_ids: &[String],
    ) -> Result<Vec<crate::db::LeaderboardContributorRow>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tenant_ids: Vec<String> = if configured_tenant_ids.is_empty() {
            client
                .query("SELECT tenant_id FROM trace_tenants", &[])
                .await
                .map_err(DatabaseError::Postgres)?
                .into_iter()
                .map(|row| row.get::<_, String>("tenant_id"))
                .collect()
        } else {
            configured_tenant_ids.to_vec()
        };
        let mut rows = Vec::new();
        for tenant_id in &tenant_ids {
            let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
            // We bind `window_days` via interval arithmetic in SQL so the
            // window is consistent across rows even if the transaction
            // straddles a clock tick.
            let pg_rows = tx
                .query(
                    LEADERBOARD_INPUTS_SQL,
                    &[&window_days.to_string(), &min_cell_count],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            for pg_row in pg_rows {
                rows.push(crate::db::LeaderboardContributorRow {
                    tenant_id: pg_row.get("tenant_id"),
                    principal_ref: pg_row.get("principal_ref"),
                    display_handle: pg_row.get("display_handle"),
                    handle_normalized: pg_row.get("handle_normalized"),
                    bio: pg_row.get("bio"),
                    public_since: pg_row.get("public_since"),
                    accepted_in_window: pg_row.get("accepted_in_window"),
                    credit_in_window: pg_row.get("credit_in_window"),
                    total_accepted: pg_row.get("total_accepted"),
                    total_credit: pg_row.get("total_credit"),
                });
            }
        }
        Ok(rows)
    }

    async fn compute_corpus_analytics_summary(
        &self,
        window_days: i32,
        configured_tenant_ids: &[String],
    ) -> Result<crate::db::CorpusAnalyticsSummary, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tenant_ids: Vec<String> = if configured_tenant_ids.is_empty() {
            client
                .query("SELECT tenant_id FROM trace_tenants", &[])
                .await
                .map_err(DatabaseError::Postgres)?
                .into_iter()
                .map(|row| row.get::<_, String>("tenant_id"))
                .collect()
        } else {
            configured_tenant_ids.to_vec()
        };

        let mut total_submissions = 0_i64;
        let mut total_accepted = 0_i64;
        let mut total_rejected = 0_i64;
        // Histogram buckets: 0, 100k, ..., 900k (the 10th absorbs >=1M).
        let mut histogram: [(i64, i64); 11] = [
            (0, 0),
            (100_000, 0),
            (200_000, 0),
            (300_000, 0),
            (400_000, 0),
            (500_000, 0),
            (600_000, 0),
            (700_000, 0),
            (800_000, 0),
            (900_000, 0),
            (1_000_000, 0),
        ];
        let mut both_passed = 0_i64;
        let mut novelty_failed = 0_i64;
        let mut perplexity_failed = 0_i64;
        let mut both_failed = 0_i64;

        for tenant_id in &tenant_ids {
            let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
            // Submission counts.
            let counts = tx
                .query_one(
                    "SELECT
                        COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE status = 'accepted') AS accepted,
                        COUNT(*) FILTER (WHERE status IN ('rejected', 'quarantined', 'revoked')) AS rejected
                     FROM trace_submissions
                     WHERE received_at >= NOW() - ($1 || ' days')::interval",
                    &[&window_days.to_string()],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            total_submissions += counts.get::<_, i64>("total");
            total_accepted += counts.get::<_, i64>("accepted");
            total_rejected += counts.get::<_, i64>("rejected");
            // Novelty score histogram + gate outcomes.
            let buckets = tx
                .query(
                    "SELECT
                        LEAST(novelty_score_micros / 100000, 10) AS bucket_idx,
                        COUNT(*) AS bucket_count
                     FROM trace_gate_decisions
                     WHERE decided_at >= NOW() - ($1 || ' days')::interval
                     GROUP BY 1",
                    &[&window_days.to_string()],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            for row in buckets {
                let idx: i64 = row.get("bucket_idx");
                let count: i64 = row.get("bucket_count");
                let idx = idx.clamp(0, 10) as usize;
                histogram[idx].1 += count;
            }
            let outcomes = tx
                .query(
                    "SELECT
                        COUNT(*) FILTER (WHERE perplexity_passed AND novelty_passed) AS both_passed,
                        COUNT(*) FILTER (WHERE perplexity_passed AND NOT novelty_passed) AS novelty_failed,
                        COUNT(*) FILTER (WHERE NOT perplexity_passed AND novelty_passed) AS perplexity_failed,
                        COUNT(*) FILTER (WHERE NOT perplexity_passed AND NOT novelty_passed) AS both_failed
                     FROM trace_gate_decisions
                     WHERE decided_at >= NOW() - ($1 || ' days')::interval",
                    &[&window_days.to_string()],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            let outcome = outcomes
                .first()
                .ok_or_else(|| DatabaseError::Pool("expected 1 row".to_string()))?;
            both_passed += outcome.get::<_, i64>("both_passed");
            novelty_failed += outcome.get::<_, i64>("novelty_failed");
            perplexity_failed += outcome.get::<_, i64>("perplexity_failed");
            both_failed += outcome.get::<_, i64>("both_failed");
            tx.commit().await.map_err(DatabaseError::Postgres)?;
        }

        let accept_rate = if total_submissions > 0 {
            total_accepted as f64 / total_submissions as f64
        } else {
            0.0
        };
        let novelty_histogram = histogram.into_iter().collect();
        let mut gate_outcomes = vec![
            ("both_passed".to_string(), both_passed),
            ("novelty_failed".to_string(), novelty_failed),
            ("perplexity_failed".to_string(), perplexity_failed),
            ("both_failed".to_string(), both_failed),
        ];
        gate_outcomes.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        Ok(crate::db::CorpusAnalyticsSummary {
            total_submissions,
            total_accepted,
            total_rejected,
            accept_rate,
            novelty_histogram,
            gate_outcomes,
        })
    }

    async fn compute_register_stats_totals(
        &self,
        configured_tenant_ids: &[String],
    ) -> Result<crate::db::RegisterStatsTotals, DatabaseError> {
        let mut client = self.trace_pool().get().await?;

        // Can this role see through RLS at all? An empty enumeration means
        // something different depending on the answer -- see
        // refuse_if_enumeration_is_ambiguous.
        let visibility = client
            .query_one(
                "SELECT current_setting('is_superuser') = 'on' AS is_superuser,
                        COALESCE(
                            (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user),
                            false
                        ) AS bypasses_rls",
                &[],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let role_sees_through_rls =
            visibility.get::<_, bool>("is_superuser") || visibility.get::<_, bool>("bypasses_rls");

        let tenant_ids: Vec<String> = if configured_tenant_ids.is_empty() {
            client
                .query("SELECT tenant_id FROM trace_tenants", &[])
                .await
                .map_err(DatabaseError::Postgres)?
                .into_iter()
                .map(|row| row.get::<_, String>("tenant_id"))
                .collect()
        } else {
            configured_tenant_ids.to_vec()
        };
        refuse_if_enumeration_is_ambiguous(&tenant_ids, role_sees_through_rls)?;

        let mut traces_accepted = 0_i64;
        // Accumulated as f64 and rounded once at the end (the same
        // `(x).round() as i64` idiom `credit_delta_micros` uses elsewhere in
        // this codebase to cross from a float points figure to an integer),
        // rather than casting each tenant's SUM to bigint before adding it
        // to the running total -- which would round per tenant and let the
        // published total drift from the true global sum.
        let mut points_issued: f64 = 0.0;
        let mut contributors: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();

        for tenant_id in &tenant_ids {
            let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
            let accepted = tx
                .query_one(
                    "SELECT COUNT(*) AS accepted FROM trace_submissions WHERE status = 'accepted'",
                    &[],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            traces_accepted += accepted.get::<_, i64>("accepted");

            let issued = tx
                .query_one(
                    "SELECT COALESCE(SUM(points_delta::numeric), 0)::double precision AS issued
                     FROM trace_credit_ledger
                     WHERE points_delta::numeric > 0",
                    &[],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            points_issued += issued.get::<_, f64>("issued");

            let accounts = tx
                .query(
                    "SELECT DISTINCT credit_account_ref FROM trace_credit_ledger",
                    &[],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            for row in accounts {
                contributors.insert(row.get::<_, String>("credit_account_ref"));
            }
            tx.commit().await.map_err(DatabaseError::Postgres)?;
        }

        Ok(crate::db::RegisterStatsTotals {
            traces_accepted,
            contributors: contributors.len() as i64,
            // Rounded once here, at the global sum -- not per tenant.
            points_issued: points_issued.round() as i64,
        })
    }

    async fn fetch_register_stats_row(&self) -> Result<crate::db::RegisterStatsRow, DatabaseError> {
        let client = self.trace_pool().get().await?;
        let row = client
            .query_one(REGISTER_STATS_SELECT_SQL, &[])
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(register_stats_row_from(&row))
    }

    async fn fetch_register_stats_row_as_public_read(
        &self,
    ) -> Result<crate::db::RegisterStatsRow, DatabaseError> {
        let pool = self.trace_pool();
        let mut client = pool.get().await?;
        let tx = client
            .transaction()
            .await
            .map_err(DatabaseError::Postgres)?;
        // SET LOCAL, never a bare SET: the role reverts when this transaction
        // ends, including on the error path, so a pooled connection can never
        // be handed back to another request still wearing it.
        //
        // This fails loudly ("permission denied to set role") when the serving
        // role is not a member of trace_commons_public_read, which is the
        // fail-closed direction: a deployment that applied migrations as a
        // different role gets an error on this endpoint rather than a quietly
        // over-privileged read. See docs/operator/register-stats-role.md.
        tx.batch_execute("SET LOCAL ROLE trace_commons_public_read")
            .await
            .map_err(DatabaseError::Postgres)?;
        let row = tx
            .query_one(REGISTER_STATS_SELECT_SQL, &[])
            .await
            .map_err(DatabaseError::Postgres)?;
        let parsed = register_stats_row_from(&row);
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(parsed)
    }

    async fn write_register_stats_row(
        &self,
        totals: crate::db::RegisterStatsTotals,
    ) -> Result<crate::db::RegisterStatsRow, DatabaseError> {
        let client = self.trace_pool().get().await?;
        let row = client
            .query_one(
                REGISTER_STATS_REFRESH_SQL,
                &[
                    &totals.traces_accepted,
                    &totals.contributors,
                    &totals.points_issued,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(register_stats_row_from(&row))
    }

    async fn insert_leaderboard_snapshot(
        &self,
        write: crate::db::LeaderboardSnapshotWrite,
    ) -> Result<crate::db::LeaderboardSnapshotRow, DatabaseError> {
        let client = self.trace_pool().get().await?;
        let row = client
            .query_one(
                "INSERT INTO trace_leaderboard_snapshots (
                    snapshot_id, window_label, metric, contents_jsonb,
                    contents_sha256, min_cell_count, noise_seed_hash
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                 RETURNING snapshot_id, computed_at, window_label, metric,
                           contents_jsonb, contents_sha256, min_cell_count,
                           noise_seed_hash",
                &[
                    &write.snapshot_id,
                    &write.window_label,
                    &write.metric,
                    &write.contents,
                    &write.contents_sha256,
                    &write.min_cell_count,
                    &write.noise_seed_hash,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(crate::db::LeaderboardSnapshotRow {
            snapshot_id: row.get("snapshot_id"),
            computed_at: row.get("computed_at"),
            window_label: row.get("window_label"),
            metric: row.get("metric"),
            contents: row.get("contents_jsonb"),
            contents_sha256: row.get("contents_sha256"),
            min_cell_count: row.get("min_cell_count"),
            noise_seed_hash: row.get("noise_seed_hash"),
        })
    }

    async fn prune_leaderboard_snapshots(
        &self,
        window_label: &str,
        metric: &str,
        keep: i64,
    ) -> Result<u64, DatabaseError> {
        // Ordered by computed_at with snapshot_id as the tiebreak so the
        // set kept is deterministic when two snapshots share a timestamp.
        let client = self.trace_pool().get().await?;
        let removed = client
            .execute(
                "DELETE FROM trace_leaderboard_snapshots
                  WHERE window_label = $1
                    AND metric = $2
                    AND snapshot_id NOT IN (
                        SELECT snapshot_id
                          FROM trace_leaderboard_snapshots
                         WHERE window_label = $1
                           AND metric = $2
                         ORDER BY computed_at DESC, snapshot_id DESC
                         LIMIT $3
                    )",
                &[&window_label, &metric, &keep],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(removed)
    }

    async fn latest_leaderboard_snapshot(
        &self,
        window_label: &str,
        metric: &str,
    ) -> Result<Option<crate::db::LeaderboardSnapshotRow>, DatabaseError> {
        let client = self.trace_pool().get().await?;
        let row = client
            .query_opt(
                "SELECT snapshot_id, computed_at, window_label, metric,
                        contents_jsonb, contents_sha256, min_cell_count,
                        noise_seed_hash
                 FROM trace_leaderboard_snapshots
                 WHERE window_label = $1 AND metric = $2
                 ORDER BY computed_at DESC
                 LIMIT 1",
                &[&window_label, &metric],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(row.map(|row| crate::db::LeaderboardSnapshotRow {
            snapshot_id: row.get("snapshot_id"),
            computed_at: row.get("computed_at"),
            window_label: row.get("window_label"),
            metric: row.get("metric"),
            contents: row.get("contents_jsonb"),
            contents_sha256: row.get("contents_sha256"),
            min_cell_count: row.get("min_cell_count"),
            noise_seed_hash: row.get("noise_seed_hash"),
        }))
    }

    async fn insert_device_key(
        &self,
        device_key: crate::db::DeviceKeyWrite,
    ) -> Result<crate::db::DeviceKeyRecord, DatabaseError> {
        self.ensure_trace_tenant(&device_key.tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &device_key.tenant_id).await?;
        let row = tx
            .query_one(
                "INSERT INTO device_keys (
                    device_key_id, tenant_id, public_key, invite_subject_hash, client_info
                 ) VALUES ($1, $2, $3, $4, $5)
                 RETURNING device_key_id, tenant_id, public_key, invite_subject_hash,
                           client_info, created_at, revoked_at",
                &[
                    &device_key.device_key_id,
                    &device_key.tenant_id,
                    &device_key.public_key,
                    &device_key.invite_subject_hash,
                    &device_key.client_info,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(device_key_record_from_row(row))
    }

    async fn get_device_key(
        &self,
        tenant_id: &str,
        device_key_id: &str,
    ) -> Result<Option<crate::db::DeviceKeyRecord>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT device_key_id, tenant_id, public_key, invite_subject_hash,
                        client_info, created_at, revoked_at
                   FROM device_keys
                  WHERE tenant_id = $1 AND device_key_id = $2",
                &[&tenant_id, &device_key_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.map(device_key_record_from_row))
    }

    async fn list_device_keys(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<crate::db::DeviceKeyRecord>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT device_key_id, tenant_id, public_key, invite_subject_hash,
                        client_info, created_at, revoked_at
                   FROM device_keys
                  WHERE tenant_id = $1
                  ORDER BY created_at ASC, device_key_id ASC",
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(rows.into_iter().map(device_key_record_from_row).collect())
    }

    async fn revoke_device_key(
        &self,
        tenant_id: &str,
        device_key_id: &str,
    ) -> Result<Option<crate::db::DeviceKeyRecord>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "UPDATE device_keys
                    SET revoked_at = COALESCE(revoked_at, NOW())
                  WHERE tenant_id = $1 AND device_key_id = $2
                  RETURNING device_key_id, tenant_id, public_key, invite_subject_hash,
                            client_info, created_at, revoked_at",
                &[&tenant_id, &device_key_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.map(device_key_record_from_row))
    }

    async fn onboard_device_key(
        &self,
        device_key: crate::db::DeviceKeyWrite,
        max_uses: i32,
    ) -> Result<crate::db::OnboardDeviceKeyRecord, crate::db::OnboardDeviceKeyError> {
        if max_uses <= 0 {
            return Err(crate::db::OnboardDeviceKeyError::InviteNotValid);
        }
        let default_allowed_consent_scopes: Vec<String> = DEFAULT_ONBOARDING_CONSENT_SCOPES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let default_allowed_uses: Vec<String> = DEFAULT_ONBOARDING_ALLOWED_USES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let resolved_allowed_consent_scopes = resolve_onboarding_scope_override(
            &device_key.allowed_consent_scopes,
            &default_allowed_consent_scopes,
        );
        let resolved_allowed_uses =
            resolve_onboarding_scope_override(&device_key.allowed_uses, &default_allowed_uses);
        self.ensure_trace_tenant(&device_key.tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &device_key.tenant_id).await?;

        if let Some(existing) = tx
            .query_opt(
                "SELECT device_key_id, tenant_id, public_key, invite_subject_hash,
                        client_info, created_at, revoked_at
                   FROM device_keys
                  WHERE tenant_id = $1 AND device_key_id = $2",
                &[&device_key.tenant_id, &device_key.device_key_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?
        {
            let record = device_key_record_from_row(existing);
            if record.public_key == device_key.public_key
                && record.invite_subject_hash.as_deref()
                    == Some(device_key.invite_subject_hash.as_str())
                && record.revoked_at.is_none()
            {
                upsert_onboarding_device_tenant_access_grant(
                    &tx,
                    &device_key.tenant_id,
                    &device_key.device_key_id,
                    &resolved_allowed_consent_scopes,
                    &resolved_allowed_uses,
                )
                .await?;
                tx.commit().await.map_err(DatabaseError::Postgres)?;
                return Ok(crate::db::OnboardDeviceKeyRecord {
                    device_key: record,
                    status: crate::db::OnboardDeviceKeyStatus::Idempotent,
                });
            }
            return Err(crate::db::OnboardDeviceKeyError::InviteNotValid);
        }

        let invite_upsert = tx
            .query_opt(
                "INSERT INTO onboarding_invites (
                    tenant_id, invite_subject_hash, max_uses
                 ) VALUES ($1, $2, $3)
                 ON CONFLICT (tenant_id, invite_subject_hash) DO UPDATE SET
                    max_uses = GREATEST(onboarding_invites.consumed_uses, excluded.max_uses),
                    updated_at = NOW()
                 WHERE onboarding_invites.revoked_at IS NULL
                 RETURNING invite_subject_hash",
                &[
                    &device_key.tenant_id,
                    &device_key.invite_subject_hash,
                    &max_uses,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        if invite_upsert.is_none() {
            return Err(crate::db::OnboardDeviceKeyError::InviteNotValid);
        }

        let inserted = tx
            .query_opt(
                "INSERT INTO device_keys (
                    device_key_id, tenant_id, public_key, invite_subject_hash, client_info
                 ) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (device_key_id) DO NOTHING
                 RETURNING device_key_id, tenant_id, public_key, invite_subject_hash,
                           client_info, created_at, revoked_at",
                &[
                    &device_key.device_key_id,
                    &device_key.tenant_id,
                    &device_key.public_key,
                    &device_key.invite_subject_hash,
                    &device_key.client_info,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;

        let Some(inserted) = inserted else {
            let existing = tx
                .query_opt(
                    "SELECT device_key_id, tenant_id, public_key, invite_subject_hash,
                            client_info, created_at, revoked_at
                       FROM device_keys
                      WHERE tenant_id = $1 AND device_key_id = $2",
                    &[&device_key.tenant_id, &device_key.device_key_id],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            if let Some(existing) = existing {
                let record = device_key_record_from_row(existing);
                if record.public_key == device_key.public_key
                    && record.invite_subject_hash.as_deref()
                        == Some(device_key.invite_subject_hash.as_str())
                    && record.revoked_at.is_none()
                {
                    upsert_onboarding_device_tenant_access_grant(
                        &tx,
                        &device_key.tenant_id,
                        &device_key.device_key_id,
                        &resolved_allowed_consent_scopes,
                        &resolved_allowed_uses,
                    )
                    .await?;
                    tx.commit().await.map_err(DatabaseError::Postgres)?;
                    return Ok(crate::db::OnboardDeviceKeyRecord {
                        device_key: record,
                        status: crate::db::OnboardDeviceKeyStatus::Idempotent,
                    });
                }
            }
            return Err(crate::db::OnboardDeviceKeyError::InviteNotValid);
        };

        // Consume the invite's OWN allowance before the per-tenant one.
        //
        // V29's counter is keyed (tenant_id, invite_subject_hash), and under
        // InviteTenantMode::Derived the tenant is computed from the redeemer's
        // device key -- so each redeemer gets a fresh row at zero and the limit
        // never binds. This counter is on the tenant-less grant row, so it
        // binds whatever tenant the redeemer lands in.
        //
        // The GUC is set transaction-locally so the grant row for the code
        // actually presented is visible and updatable, and no other; the
        // policies in V42 and V50 are both predicated on it.
        tx.execute(
            "SELECT set_config('trace_commons.invite_subject', $1, true)",
            &[&device_key.invite_subject_hash],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        let has_grant = tx
            .query_opt(
                "SELECT 1 FROM onboarding_invite_grants WHERE invite_subject_hash = $1",
                &[&device_key.invite_subject_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .is_some();
        if has_grant {
            // Absent when the invite came from the file allowlist rather than
            // the DB registry. That path has no grant row and no second
            // counter, so "no row" must mean "not governed here" rather than
            // "exhausted" -- conflating them would refuse every legacy invite.
            let globally_consumed = tx
                .query_opt(
                    "UPDATE onboarding_invite_grants
                        SET consumed_uses = consumed_uses + 1,
                            updated_at = NOW()
                      WHERE invite_subject_hash = $1
                        AND revoked_at IS NULL
                        AND consumed_uses < max_uses
                      RETURNING consumed_uses",
                    &[&device_key.invite_subject_hash],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            if globally_consumed.is_none() {
                return Err(crate::db::OnboardDeviceKeyError::InviteAlreadyConsumed);
            }
        }

        let consumed = tx
            .query_opt(
                "UPDATE onboarding_invites
                    SET consumed_uses = consumed_uses + 1,
                        updated_at = NOW()
                  WHERE tenant_id = $1
                    AND invite_subject_hash = $2
                    AND revoked_at IS NULL
                    AND consumed_uses < max_uses
                  RETURNING consumed_uses",
                &[&device_key.tenant_id, &device_key.invite_subject_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        if consumed.is_none() {
            return Err(crate::db::OnboardDeviceKeyError::InviteAlreadyConsumed);
        }

        upsert_onboarding_device_tenant_access_grant(
            &tx,
            &device_key.tenant_id,
            &device_key.device_key_id,
            &resolved_allowed_consent_scopes,
            &resolved_allowed_uses,
        )
        .await?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(crate::db::OnboardDeviceKeyRecord {
            device_key: device_key_record_from_row(inserted),
            status: crate::db::OnboardDeviceKeyStatus::Registered,
        })
    }

    async fn enroll_instance_user(
        &self,
        p: crate::db::InstanceUserProvision,
    ) -> Result<(), DatabaseError> {
        // ensure_trace_tenant runs in its own transaction and is idempotent.
        self.ensure_trace_tenant(&p.tenant_id).await?;

        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &p.tenant_id).await?;

        // Stamp the contribution policy once; never overwrite an existing row.
        tx.execute(
            "INSERT INTO trace_tenant_policies
                 (tenant_id, policy_version, allowed_consent_scopes, allowed_uses,
                  updated_by_principal_ref)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id) DO NOTHING",
            &[
                &p.tenant_id,
                &p.policy_version,
                &p.allowed_consent_scopes,
                &p.allowed_uses,
                &format!("instance-enroll:{}", p.instance_subject_hash),
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        // Register the device key (the principal). `device_key_id` is a GLOBAL
        // primary key, so an `ON CONFLICT DO NOTHING` no-op can mean the key
        // already exists under a DIFFERENT tenant or is revoked here — in which
        // case the device's bearer would not authenticate to the derived tenant.
        // Mirror `onboard_device_key`: insert-or-reselect and accept only an
        // identical, non-revoked row under THIS tenant; otherwise fail closed so
        // enrollment never reports success for an unusable device key.
        let inserted = tx
            .query_opt(
                "INSERT INTO device_keys
                     (device_key_id, tenant_id, public_key, invite_subject_hash, client_info)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (device_key_id) DO NOTHING
                 RETURNING device_key_id",
                &[
                    &p.device_key_id,
                    &p.tenant_id,
                    &p.public_key,
                    &p.instance_subject_hash,
                    &p.client_info,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;

        if inserted.is_none() {
            let existing = tx
                .query_opt(
                    "SELECT public_key, revoked_at
                       FROM device_keys
                      WHERE tenant_id = $1 AND device_key_id = $2",
                    &[&p.tenant_id, &p.device_key_id],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            let usable = match existing {
                Some(row) => {
                    let public_key: String = row.get("public_key");
                    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row.get("revoked_at");
                    public_key == p.public_key && revoked_at.is_none()
                }
                None => false,
            };
            if !usable {
                return Err(DatabaseError::Pool(
                    "instance enroll device key conflict: not usable under derived tenant"
                        .to_string(),
                ));
            }
        }

        // Grant the default contributor tenant-access grant so the device can mint
        // upload claims under the `require_tenant_access_grants` gate, exactly like
        // an invite-onboarded device. Same helper, same principal_ref derivation.
        // Scopes come from the instance's policy template, falling back to the
        // pilot defaults when the template is missing, empty, or malformed.
        let allowed_consent_scopes = normalize_provision_scope_values(
            &p.allowed_consent_scopes,
            &DEFAULT_ONBOARDING_CONSENT_SCOPES,
        );
        let allowed_uses =
            normalize_provision_scope_values(&p.allowed_uses, &DEFAULT_ONBOARDING_ALLOWED_USES);
        upsert_onboarding_device_tenant_access_grant(
            &tx,
            &p.tenant_id,
            &p.device_key_id,
            &allowed_consent_scopes,
            &allowed_uses,
        )
        .await?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;

        // Create-or-reuse the contributor account and bind the device principal so
        // instance-enrolled users get account-scoped trace read-back immediately,
        // without waiting for a first login-link mint. The principal_ref is the one
        // the device authenticates as (and the login-link mint path passes), so
        // this converges idempotently with that path. `create_or_reuse_account`
        // runs its own self-contained tenant transaction.
        let principal_ref = onboarding_device_principal_ref(&p.tenant_id, &p.device_key_id);
        self.create_or_reuse_account(&p.tenant_id, &principal_ref)
            .await?;

        Ok(())
    }

    async fn reserve_instance_enrollment(
        &self,
        instance_subject_hash: &str,
        user_subject_hash: &str,
        tenant_id: &str,
        max_enrollments: i64,
    ) -> Result<crate::db::InstanceEnrollmentOutcome, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = client
            .transaction()
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.execute(
            "SELECT set_config('trace_commons.instance_subject', $1, true)",
            &[&instance_subject_hash],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        // Already enrolled? Idempotent — no cap consumption.
        let existing = tx
            .query_opt(
                "SELECT 1 FROM trace_instance_enrollments
                  WHERE instance_subject_hash = $1 AND user_subject_hash = $2",
                &[&instance_subject_hash, &user_subject_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        if existing.is_some() {
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(crate::db::InstanceEnrollmentOutcome::ExistingUser);
        }

        // Lock-free cap check: count, then insert ON CONFLICT DO NOTHING.
        // A concurrent burst of DISTINCT new users could each read count < cap
        // and all insert, overshooting the cap by the concurrency width. For
        // the pilot's per-instance rate limit this is acceptable; if strict
        // capping is later required, take an advisory lock on
        // hashtext(instance_subject_hash) at the top of the tx.
        let count: i64 = tx
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM trace_instance_enrollments
                  WHERE instance_subject_hash = $1",
                &[&instance_subject_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .get(0);
        if count >= max_enrollments {
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(crate::db::InstanceEnrollmentOutcome::CapExceeded);
        }

        let inserted = tx
            .execute(
                "INSERT INTO trace_instance_enrollments
                     (instance_subject_hash, user_subject_hash, tenant_id)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (instance_subject_hash, user_subject_hash) DO NOTHING",
                &[&instance_subject_hash, &user_subject_hash, &tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;

        // A racing insert of the SAME user resolves to ExistingUser.
        Ok(if inserted == 1 {
            crate::db::InstanceEnrollmentOutcome::NewlyEnrolled
        } else {
            crate::db::InstanceEnrollmentOutcome::ExistingUser
        })
    }

    async fn instance_ledger_rls_ready(&self) -> Result<bool, DatabaseError> {
        let client = self.trace_pool().get().await?;
        let row = client
            .query_one(
                "SELECT
                    EXISTS (
                        SELECT 1
                          FROM pg_class c
                          JOIN pg_namespace n ON n.oid = c.relnamespace
                         WHERE n.nspname = current_schema()
                           AND c.relname = 'trace_instance_enrollments'
                           AND c.relrowsecurity
                           AND c.relforcerowsecurity
                    ) AS rls_forced,
                    EXISTS (
                        SELECT 1
                          FROM pg_policies
                         WHERE schemaname = current_schema()
                           AND tablename = 'trace_instance_enrollments'
                           AND policyname = 'trace_instance_isolation'
                    ) AS policy_present",
                &[],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let rls_forced: bool = row.get("rls_forced");
        let policy_present: bool = row.get("policy_present");
        Ok(rls_forced && policy_present)
    }

    async fn create_or_reuse_account(
        &self,
        tenant_id: &str,
        principal_ref: &str,
    ) -> Result<Uuid, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;

        // Fast path: an active link for this principal already maps to an account.
        if let Some(row) = tx
            .query_opt(
                "SELECT account_id FROM trace_account_principals
                  WHERE tenant_id = trace_current_tenant_id()
                    AND principal_ref = $1
                    AND unlinked_at IS NULL",
                &[&principal_ref],
            )
            .await
            .map_err(DatabaseError::Postgres)?
        {
            let account_id: Uuid = row.get("account_id");
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(account_id);
        }

        // No active link: mint a fresh account and link the principal. The link
        // insert is ON CONFLICT DO NOTHING against the UNIQUE (tenant_id,
        // principal_ref) constraint so a concurrent mint that won the race does
        // not error us out; we re-select the authoritative account below.
        let new_account_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO trace_accounts (tenant_id, account_id)
             VALUES (trace_current_tenant_id(), $1)",
            &[&new_account_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.execute(
            "INSERT INTO trace_account_principals (tenant_id, account_id, principal_ref)
             VALUES (trace_current_tenant_id(), $1, $2)
             ON CONFLICT (tenant_id, principal_ref) DO NOTHING",
            &[&new_account_id, &principal_ref],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        // Re-select the authoritative account for this principal. If a
        // concurrent mint inserted the link first, this returns ITS account_id
        // and our freshly-inserted (now orphaned) trace_accounts row is harmless
        // (no principal links to it). If we won, it returns new_account_id.
        let row = tx
            .query_one(
                "SELECT account_id FROM trace_account_principals
                  WHERE tenant_id = trace_current_tenant_id()
                    AND principal_ref = $1
                    AND unlinked_at IS NULL",
                &[&principal_ref],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let account_id: Uuid = row.get("account_id");
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(account_id)
    }

    /// Batched principal->account resolution. One query under the tenant tx maps
    /// every active-linked principal in `principal_refs` to its account; principals
    /// with no active link are simply absent from the result. Mirrors the
    /// tenant-tx shape of `create_or_reuse_account`.
    async fn resolve_principals_to_accounts(
        &self,
        tenant_id: &str,
        principal_refs: &[String],
    ) -> Result<std::collections::HashMap<String, Uuid>, DatabaseError> {
        // Empty input short-circuits without a query.
        if principal_refs.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT principal_ref, account_id FROM trace_account_principals
                  WHERE tenant_id = trace_current_tenant_id()
                    AND unlinked_at IS NULL
                    AND principal_ref = ANY($1)",
                &[&principal_refs],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        let mut map = std::collections::HashMap::with_capacity(rows.len());
        for row in rows {
            let principal_ref: String = row.get("principal_ref");
            let account_id: Uuid = row.get("account_id");
            map.insert(principal_ref, account_id);
        }
        Ok(map)
    }

    async fn count_outstanding_login_links(
        &self,
        tenant_id: &str,
        created_principal_ref: &str,
    ) -> Result<i64, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_one(
                "SELECT count(*) AS outstanding
                   FROM trace_login_links
                  WHERE tenant_id = trace_current_tenant_id()
                    AND created_principal_ref = $1
                    AND consumed_at IS NULL
                    AND expires_at > now()",
                &[&created_principal_ref],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let outstanding: i64 = row.get("outstanding");
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(outstanding)
    }

    async fn insert_login_link(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        code_hash: &str,
        created_principal_ref: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let link_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO trace_login_links (
                tenant_id, link_id, account_id, code_hash,
                created_principal_ref, created_at, expires_at
             ) VALUES (
                trace_current_tenant_id(), $1, $2, $3, $4, now(), $5
             )",
            &[
                &link_id,
                &account_id,
                &code_hash,
                &created_principal_ref,
                &expires_at,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn append_account_audit(
        &self,
        tenant_id: &str,
        action: &str,
        actor_ref: &str,
        outcome: &str,
        safe_metadata: serde_json::Value,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_account_audit (
                tenant_id, action, actor_ref, outcome, safe_metadata
             ) VALUES (trace_current_tenant_id(), $1, $2, $3, $4)",
            &[&action, &actor_ref, &outcome, &safe_metadata],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn resolve_login_link_tenant(
        &self,
        code_hash: &str,
    ) -> Result<Option<String>, DatabaseError> {
        // Delegate to the inherent implementation (narrow resolver pool); map its
        // anyhow error onto the trait's DatabaseError. The fail-closed
        // unconfigured-resolver path surfaces here as a Pool error.
        PgBackend::resolve_login_link_tenant(self, code_hash)
            .await
            .map_err(|error| DatabaseError::Pool(error.to_string()))
    }

    async fn resolve_credential_tenant(
        &self,
        credential_id: &str,
    ) -> Result<Option<String>, DatabaseError> {
        // Delegate to the inherent implementation (narrow resolver pool); map its
        // anyhow error onto the trait's DatabaseError. The fail-closed
        // unconfigured-resolver path surfaces here as a Pool error, which the
        // login handler collapses to the uniform deny.
        PgBackend::resolve_credential_tenant(self, credential_id)
            .await
            .map_err(|error| DatabaseError::Pool(error.to_string()))
    }

    async fn store_near_provisioning_ceremony(
        &self,
        hash: &str,
        pending: crate::account_onboarding::NativeProvisioningPending,
        expires_at: i64,
    ) -> Result<(), DatabaseError> {
        self.near_store_ceremony(hash, pending, expires_at).await
    }
    async fn take_near_provisioning_ceremony(
        &self,
        hash: &str,
    ) -> Result<Option<crate::account_onboarding::NativeProvisioningPending>, DatabaseError> {
        self.near_take_ceremony(hash).await
    }
    async fn provision_verified_near_account(
        &self,
        proof: crate::account_onboarding::VerifiedNearProvisioning,
        session: crate::db::NewSession<'_>,
        identity: &crate::near_account_identity::NearAccountIdentity,
    ) -> Result<crate::account_onboarding::ProvisionedNearAccount, DatabaseError> {
        self.near_provision(proof, session, identity).await
    }
    async fn store_near_ai_login_ceremony(
        &self,
        ceremony_hash: &str,
        pending: &crate::account_onboarding::NearAiLoginPending,
        expires_at: i64,
    ) -> Result<(), DatabaseError> {
        self.near_ai_login_store_ceremony(ceremony_hash, pending, expires_at)
            .await
    }

    async fn take_near_ai_login_ceremony(
        &self,
        ceremony_hash: &str,
    ) -> Result<Option<crate::account_onboarding::NearAiLoginPending>, DatabaseError> {
        self.near_ai_login_take_ceremony(ceremony_hash).await
    }

    async fn provision_near_ai_login(
        &self,
        login: &crate::near_ai_login::VerifiedNearAiLogin,
        device_public_key: &[u8; 32],
        session: crate::db::NewSession<'_>,
        identity: &crate::near_account_identity::NearAccountIdentity,
    ) -> Result<crate::account_onboarding::ProvisionedNearAccount, DatabaseError> {
        self.near_ai_login_provision(login, device_public_key, session, identity)
            .await
    }

    async fn get_near_provisioned_anchor(
        &self,
        tenant: &str,
        principal: &str,
    ) -> Result<Option<String>, DatabaseError> {
        self.near_anchor_for_principal(tenant, principal).await
    }

    async fn resolve_near_public_key_tenant(
        &self,
        public_key: &str,
    ) -> Result<Option<String>, DatabaseError> {
        // Delegate to the inherent implementation (narrow resolver pool); map its
        // anyhow error onto the trait's DatabaseError. The fail-closed
        // unconfigured-resolver path surfaces here as a Pool error, which the
        // login handler collapses to the uniform deny.
        PgBackend::resolve_near_public_key_tenant(self, public_key)
            .await
            .map_err(|error| DatabaseError::Pool(error.to_string()))
    }

    async fn redeem_login_link(
        &self,
        tenant_id: &str,
        code_hash: &str,
        session: crate::db::NewSession<'_>,
        audit: crate::db::RedeemAudit,
    ) -> Result<Option<crate::db::RedeemedSession>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;

        // Single atomic conditional consume (Hardening D/G): ALWAYS executed, never
        // SELECT-then-branch. Unknown / expired / already-consumed / wrong-tenant
        // codes all affect zero rows. The explicit tenant predicate is
        // belt-and-suspenders on top of RLS; `code_hash` is globally UNIQUE.
        let consumed = tx
            .query_opt(
                "UPDATE trace_login_links SET consumed_at = now()
                  WHERE code_hash = $1
                    AND tenant_id = trace_current_tenant_id()
                    AND consumed_at IS NULL
                    AND expires_at > now()
                  RETURNING account_id",
                &[&code_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let Some(consumed) = consumed else {
            // No row consumed: commit the no-op tx so the link stays UNconsumed and
            // retryable, and return None for the uniform deny upstream.
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(None);
        };
        let account_id: Uuid = consumed.get("account_id");

        // Same RLS-scoped tx: insert the session (hash-only token) ...
        let session_id = Uuid::new_v4(); // server-assigned; never client-supplied.
        tx.execute(
            "INSERT INTO trace_sessions (
                tenant_id, session_id, account_id, token_hash,
                client_kind, created_at, last_seen_at, expires_at
             ) VALUES (
                trace_current_tenant_id(), $1, $2, $3, $4, now(), now(), $5
             )",
            &[
                &session_id,
                &account_id,
                &session.token_hash,
                &session.client_kind,
                &session.expires_at,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        // ... and the hash-only / label-only audit row. Actor is derived from the
        // consumed account_id (reserved-prefix, never sha-shaped). If any of these
        // fail the whole redeem rolls back: link stays reusable, no orphaned
        // session, no un-audited state change.
        let actor_ref = crate::account_session::account_actor_ref(
            &crate::account_session::AccountId::from_uuid(account_id),
        );
        tx.execute(
            "INSERT INTO trace_account_audit (
                tenant_id, action, actor_ref, outcome, safe_metadata
             ) VALUES (trace_current_tenant_id(), $1, $2, $3, $4)",
            &[&audit.action, &actor_ref, &audit.outcome, &audit.metadata],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(Some(crate::db::RedeemedSession {
            account_id,
            session_id,
        }))
    }

    async fn validate_session(
        &self,
        tenant_id: &str,
        token_hash: &str,
    ) -> Result<Option<crate::db::ValidatedSession>, DatabaseError> {
        // SECURITY: do NOT ensure_trace_tenant here. `tenant_id` is the
        // client-supplied, pre-auth value decoded from the session cookie; an
        // UPSERT into trace_tenants would let an unauthenticated forged cookie
        // spray arbitrary tenant rows before the token is validated. The tenant
        // already exists for any legitimate session (created at mint), and
        // begin_trace_tenant_transaction only sets the RLS config var (no row
        // dependency), so a forged/nonexistent tenant scopes the lookup to a
        // tenant where this hash cannot exist -> zero rows -> deny, no write.
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;

        // Every-request liveness gate (Hardening I): unexpired AND not revoked AND
        // seen within the idle cap. The idle cap (3d) is intentionally shorter than
        // the 7d absolute `expires_at` so an abandoned session dies sooner than its
        // hard expiry. The `tenant_id = trace_current_tenant_id()` predicate is
        // belt-and-suspenders on top of forced RLS; `token_hash` is globally
        // UNIQUE so a client-supplied (forged/mismatched) tenant simply scopes the
        // lookup to a tenant where this hash does not exist -> no row -> deny.
        //
        // Rotation-on-use: the SELECT also accepts a within-grace PREVIOUS token
        // (`prev_token_hash = $1 AND prev_token_valid_until > now()`) so a request
        // still carrying the old cookie during the brief rotation grace continues
        // to validate (multi-tab / in-flight). `matched_current` records whether
        // the request matched the CURRENT token: only a current match is eligible
        // to (re-)rotate, so a prev-token request never re-rotates. `needs_rotate`
        // pre-computes the age check in SQL against the (possibly env-overridden)
        // interval. We always read back the row's CURRENT `token_hash` so the
        // last_seen / rotate UPDATE keys on the canonical hash, not the presented
        // one (which may be the prev token).
        let interval_secs = session_rotation_interval_secs();
        let grace_secs = session_rotation_grace_secs();
        let row = tx
            .query_opt(
                "SELECT s.account_id, s.auth_credential_id, s.token_hash, s.client_kind,
                        (s.token_hash = $1) AS matched_current,
                        (s.token_issued_at < now() - make_interval(secs => $2)) AS needs_rotate
                   FROM trace_sessions s
                   JOIN trace_accounts a
                     ON a.tenant_id = s.tenant_id
                    AND a.account_id = s.account_id
                  WHERE s.tenant_id = trace_current_tenant_id()
                    AND a.closed_at IS NULL
                    AND (s.token_hash = $1
                         OR (s.prev_token_hash = $1 AND s.prev_token_valid_until > now()))
                    AND s.expires_at > now()
                    AND s.revoked_at IS NULL
                    AND s.last_seen_at > now() - INTERVAL '3 days'",
                &[&token_hash, &(interval_secs as f64)],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let Some(row) = row else {
            // Miss OR idle-capped. Auto-revoke any matching row that is still live
            // (unexpired, unrevoked) but fell past the idle cap, so a leaked secret
            // cannot be reused after the idle window even before hard expiry. The
            // predicate is the inverse idle-cap on an otherwise-valid row; a true
            // unknown hash affects zero rows. It keys ONLY on the CURRENT
            // `token_hash`, so a within-grace prev-token presentation (whose own
            // row, if any, is still live and was simply not matched here) is never
            // revoked by this branch.
            tx.execute(
                "UPDATE trace_sessions SET revoked_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND token_hash = $1
                    AND revoked_at IS NULL
                    AND expires_at > now()
                    AND last_seen_at <= now() - INTERVAL '3 days'",
                &[&token_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(None);
        };
        let account_id: Uuid = row.get("account_id");
        let auth_credential_id: Option<String> = row.get("auth_credential_id");
        let client_kind: String = row.get("client_kind");
        let current_token_hash: String = row.get("token_hash");
        let matched_current: bool = row.get("matched_current");
        let needs_rotate: bool = row.get("needs_rotate");

        // Rotate only on a CURRENT-token match that has aged past the interval. A
        // prev-token (within-grace) request slides the idle window forward but must
        // NOT re-rotate (that would churn the secret every multi-tab request and
        // could orphan the cookie the other tab still holds).
        let rotated_secret = if matched_current && needs_rotate {
            let new_secret = crate::account_session::generate_session_secret();
            let new_hash = crate::account_session::hash_secret(&new_secret);
            // Same-tx rotation: park the old hash as the prev token for `grace`,
            // swap in the new hash, reset the issue clock, slide last_seen. Keyed on
            // the canonical current hash.
            tx.execute(
                "UPDATE trace_sessions
                    SET prev_token_hash = token_hash,
                        prev_token_valid_until = now() + make_interval(secs => $2),
                        token_hash = $3,
                        token_issued_at = now(),
                        last_seen_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND token_hash = $1",
                &[&current_token_hash, &(grace_secs as f64), &new_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;

            // Hash-only audit. Records only the action and actor (reserved-prefix
            // account actor); never a token, secret, or hash.
            let actor_ref = crate::account_session::account_actor_ref(
                &crate::account_session::AccountId::from_uuid(account_id),
            );
            tx.execute(
                "INSERT INTO trace_account_audit (
                    tenant_id, action, actor_ref, outcome, safe_metadata
                 ) VALUES (trace_current_tenant_id(), $1, $2, $3, $4)",
                &[
                    &"account_session_rotated",
                    &actor_ref,
                    &"success",
                    &serde_json::json!({}),
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
            Some(new_secret)
        } else {
            // Live hit (no rotation): bump last_seen_at to slide the idle window
            // forward. Keyed on the canonical current hash so a prev-token match
            // still refreshes the right row.
            tx.execute(
                "UPDATE trace_sessions SET last_seen_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND token_hash = $1",
                &[&current_token_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
            None
        };
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(Some(crate::db::ValidatedSession {
            account_id,
            auth_credential_id,
            client_kind,
            rotated_secret,
        }))
    }

    async fn revoke_current_session(
        &self,
        tenant_id: &str,
        token_hash: &str,
    ) -> Result<u64, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Idempotent single-session revoke. Match the presented hash as EITHER the
        // current `token_hash` OR the just-rotated-away `prev_token_hash`: if the
        // same request rotated the session (rotation runs in the auth middleware
        // BEFORE the logout handler re-derives the hash from the presented OLD
        // cookie), the row's current hash is now the freshly minted one and the
        // presented hash lives in `prev_token_hash`. Keying on the current hash
        // alone would miss that row and leave the rotated session live. Revoking on
        // either match kills the WHOLE row (one row per session: both hashes belong
        // to the same row), so the rotated cookie the middleware appends lands on an
        // already-revoked row and the next request 401s. `token_hash` is globally
        // UNIQUE and `prev_token_hash` is its short-lived predecessor, so at most one
        // row matches; an already-revoked or unknown hash affects zero rows.
        let revoked = tx
            .execute(
                "UPDATE trace_sessions SET revoked_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND (token_hash = $1 OR prev_token_hash = $1)
                    AND revoked_at IS NULL",
                &[&token_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(revoked)
    }

    async fn revoke_all_account_sessions(
        &self,
        tenant_id: &str,
        account_id: Uuid,
    ) -> Result<u64, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Sign-out-everywhere: revoke every live session for the auth-derived
        // account. Tenant- + account-scoped under forced RLS, so only the caller's
        // own sessions can ever be touched.
        let revoked = tx
            .execute(
                "UPDATE trace_sessions SET revoked_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND revoked_at IS NULL",
                &[&account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(revoked)
    }

    async fn resolve_account_for_principal(
        &self,
        tenant_id: &str,
        principal_ref: &str,
    ) -> Result<Option<Uuid>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Active-membership only (Hardening A): an unlinked principal must not
        // resolve to its former account.
        let row = tx
            .query_opt(
                "SELECT account_id FROM trace_account_principals
                  WHERE tenant_id = trace_current_tenant_id()
                    AND principal_ref = $1
                    AND unlinked_at IS NULL",
                &[&principal_ref],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let account_id = row.map(|row| row.get::<_, Uuid>("account_id"));
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(account_id)
    }

    async fn expand_account_principals(
        &self,
        tenant_id: &str,
        account_id: Uuid,
    ) -> Result<crate::account_session::AccountPrincipalSet, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // The ONLY sanctioned ownership-bearing expansion (Hardening A): active
        // memberships only. An `unlinked_at`-set principal is absent from the set.
        let rows = tx
            .query(
                "SELECT principal_ref FROM trace_account_principals
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND unlinked_at IS NULL",
                &[&account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let principals = crate::account_session::AccountPrincipalSet::from_iter(
            rows.into_iter()
                .map(|row| row.get::<_, String>("principal_ref")),
        );
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(principals)
    }

    async fn insert_webauthn_credential(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        credential_id: &str,
        passkey: &serde_json::Value,
        label: Option<&str>,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_webauthn_credentials (
                tenant_id, credential_id, account_id, passkey, label, created_at
             ) VALUES (
                trace_current_tenant_id(), $1, $2, $3, $4, now()
             )",
            &[&credential_id, &account_id, &passkey, &label],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn load_webauthn_credential_for_login(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> Result<Option<crate::db::WebauthnCredentialRow>, DatabaseError> {
        // The resolver has already mapped credential_id -> tenant_id; this load
        // runs under that resolved tenant's RLS. We do NOT ensure_trace_tenant
        // here: the tenant already exists for any registered credential, and
        // begin_trace_tenant_transaction only sets the RLS config var (no row
        // dependency). The `tenant_id = trace_current_tenant_id()` predicate is
        // belt-and-suspenders on top of forced RLS; `credential_id` is globally
        // UNIQUE.
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT account_id, passkey FROM trace_webauthn_credentials
                  WHERE tenant_id = trace_current_tenant_id()
                    AND credential_id = $1
                    AND revoked_at IS NULL",
                &[&credential_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.map(|row| crate::db::WebauthnCredentialRow {
            account_id: row.get("account_id"),
            passkey: row.get("passkey"),
        }))
    }

    async fn update_webauthn_credential_after_login(
        &self,
        tenant_id: &str,
        credential_id: &str,
        passkey: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "UPDATE trace_webauthn_credentials
                SET passkey = $1, last_used_at = now()
              WHERE tenant_id = trace_current_tenant_id()
                AND credential_id = $2
                AND revoked_at IS NULL",
            &[&passkey, &credential_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn issue_native_session(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        session: crate::db::NewSession<'_>,
        audit: crate::db::RedeemAudit,
    ) -> Result<(), DatabaseError> {
        // SECURITY: no ensure_trace_tenant, for the same reason as
        // issue_passkey_session. The tenant here came from a login link a human
        // just redeemed in a browser; the session insert is FK-bound to
        // (tenant_id, account_id), so a bogus pair fails the insert rather than
        // writing a tenant row.
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;

        // auth_credential_id is left NULL: a native session is authenticated by
        // the browser login that approved it, not by a passkey or wallet key.
        let session_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO trace_sessions (
                tenant_id, session_id, account_id, token_hash,
                client_kind, created_at, last_seen_at, expires_at
             ) VALUES (
                trace_current_tenant_id(), $1, $2, $3, $4, now(), now(), $5
             )",
            &[
                &session_id,
                &account_id,
                &session.token_hash,
                &session.client_kind,
                &session.expires_at,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        let actor_ref = crate::account_session::account_actor_ref(
            &crate::account_session::AccountId::from_uuid(account_id),
        );
        tx.execute(
            "INSERT INTO trace_account_audit (
                tenant_id, action, actor_ref, outcome, safe_metadata
             ) VALUES (trace_current_tenant_id(), $1, $2, $3, $4)",
            &[&audit.action, &actor_ref, &audit.outcome, &audit.metadata],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn issue_passkey_session(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        session: crate::db::NewSession<'_>,
        auth_credential_id: &str,
        audit: crate::db::RedeemAudit,
    ) -> Result<(), DatabaseError> {
        // SECURITY: do NOT ensure_trace_tenant here. The credential (and thus its
        // tenant) was verified by the login handler before this call: the tenant
        // provably exists via the credential row's FK, and an UPSERT here would
        // let a forged assertion spray tenant rows. begin_trace_tenant_transaction
        // only sets the RLS config var (no row dependency), and the session insert
        // is FK-bound to (tenant_id, account_id) in trace_accounts, so a bogus
        // tenant/account simply fails the insert rather than writing anything.
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;

        // Session row: hash-only token, client_kind='passkey', the base64url
        // credential id STRING in auth_credential_id (V32 TEXT column), and
        // token_issued_at left to its DEFAULT now(). session_id is server-assigned.
        let session_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO trace_sessions (
                tenant_id, session_id, account_id, token_hash,
                client_kind, auth_credential_id, created_at, last_seen_at, expires_at
             ) VALUES (
                trace_current_tenant_id(), $1, $2, $3, $4, $5, now(), now(), $6
             )",
            &[
                &session_id,
                &account_id,
                &session.token_hash,
                &session.client_kind,
                &auth_credential_id,
                &session.expires_at,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        // Hash-only / label-only audit row in the SAME tx so an audit failure rolls
        // back the session (no un-audited session, no orphaned audit).
        let actor_ref = crate::account_session::account_actor_ref(
            &crate::account_session::AccountId::from_uuid(account_id),
        );
        tx.execute(
            "INSERT INTO trace_account_audit (
                tenant_id, action, actor_ref, outcome, safe_metadata
             ) VALUES (trace_current_tenant_id(), $1, $2, $3, $4)",
            &[&audit.action, &actor_ref, &audit.outcome, &audit.metadata],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn issue_near_session(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        session: crate::db::NewSession<'_>,
        auth_credential_id: &str,
        audit: crate::db::RedeemAudit,
    ) -> Result<(), DatabaseError> {
        // SECURITY: do NOT ensure_trace_tenant here. The NEAR identity (and thus
        // its tenant) was verified by the login handler before this call: the
        // tenant provably exists via the identity row's FK, and an UPSERT here
        // would let a forged assertion spray tenant rows. begin_trace_tenant_
        // transaction only sets the RLS config var (no row dependency), and the
        // session insert is FK-bound to (tenant_id, account_id) in trace_accounts,
        // so a bogus tenant/account simply fails the insert rather than writing
        // anything. Mirrors issue_passkey_session except client_kind='near' and
        // auth_credential_id carries the NEAR access key (a public identifier).
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;

        let session_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO trace_sessions (
                tenant_id, session_id, account_id, token_hash,
                client_kind, auth_credential_id, created_at, last_seen_at, expires_at
             ) VALUES (
                trace_current_tenant_id(), $1, $2, $3, $4, $5, now(), now(), $6
             )",
            &[
                &session_id,
                &account_id,
                &session.token_hash,
                &session.client_kind,
                &auth_credential_id,
                &session.expires_at,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        // Hash-only / label-only audit row in the SAME tx so an audit failure rolls
        // back the session (no un-audited session, no orphaned audit). Never the
        // NEAR public key, account id, or any signature material.
        let actor_ref = crate::account_session::account_actor_ref(
            &crate::account_session::AccountId::from_uuid(account_id),
        );
        tx.execute(
            "INSERT INTO trace_account_audit (
                tenant_id, action, actor_ref, outcome, safe_metadata
             ) VALUES (trace_current_tenant_id(), $1, $2, $3, $4)",
            &[&audit.action, &actor_ref, &audit.outcome, &audit.metadata],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn list_account_credentials(
        &self,
        tenant_id: &str,
        account_id: Uuid,
    ) -> Result<Vec<crate::db::AccountCredentialSummary>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT credential_id, label, created_at, last_used_at
                   FROM trace_webauthn_credentials
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND revoked_at IS NULL
                  ORDER BY created_at",
                &[&account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| crate::db::AccountCredentialSummary {
                credential_id: row.get("credential_id"),
                label: row.get("label"),
                created_at: row.get("created_at"),
                last_used_at: row.get("last_used_at"),
            })
            .collect())
    }

    async fn rename_account_credential(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        credential_id: &str,
        label: Option<&str>,
    ) -> Result<bool, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // account-scoped so a caller can never rename a credential they do not own.
        let affected = tx
            .execute(
                "UPDATE trace_webauthn_credentials
                    SET label = $1
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $2
                    AND credential_id = $3
                    AND revoked_at IS NULL",
                &[&label, &account_id, &credential_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(affected > 0)
    }

    async fn revoke_account_credential(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        credential_id: &str,
    ) -> Result<crate::db::RevokeCredentialResult, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // account-scoped soft-delete: an unknown / already-revoked / other-account
        // credential affects zero rows.
        let removed = tx
            .execute(
                "UPDATE trace_webauthn_credentials
                    SET revoked_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND credential_id = $2
                    AND revoked_at IS NULL",
                &[&account_id, &credential_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let remaining_row = tx
            .query_one(
                "SELECT count(*) AS remaining
                   FROM trace_webauthn_credentials
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND revoked_at IS NULL",
                &[&account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let remaining: i64 = remaining_row.get("remaining");
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(crate::db::RevokeCredentialResult {
            removed: removed > 0,
            remaining,
        })
    }

    async fn insert_near_identity(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        public_key: &str,
        near_account_id: &str,
        label: Option<&str>,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_near_identities (
                tenant_id, public_key, near_account_id, account_id, label, created_at
             ) VALUES (
                trace_current_tenant_id(), $1, $2, $3, $4, now()
             )",
            &[&public_key, &near_account_id, &account_id, &label],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn load_near_identity_for_login(
        &self,
        tenant_id: &str,
        public_key: &str,
    ) -> Result<Option<crate::db::NearIdentityRow>, DatabaseError> {
        // The resolver has already mapped public_key -> tenant_id; this load runs
        // under that resolved tenant's RLS. We do NOT ensure_trace_tenant here: the
        // tenant already exists for any registered identity, and
        // begin_trace_tenant_transaction only sets the RLS config var (no row
        // dependency). The `tenant_id = trace_current_tenant_id()` predicate is
        // belt-and-suspenders on top of forced RLS; `public_key` is globally UNIQUE.
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT account_id, near_account_id FROM trace_near_identities
                  WHERE tenant_id = trace_current_tenant_id()
                    AND public_key = $1
                    AND revoked_at IS NULL",
                &[&public_key],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.map(|row| crate::db::NearIdentityRow {
            account_id: row.get("account_id"),
            near_account_id: row.get("near_account_id"),
        }))
    }

    async fn touch_near_identity_last_used(
        &self,
        tenant_id: &str,
        public_key: &str,
    ) -> Result<(), DatabaseError> {
        // SECURITY: do NOT ensure_trace_tenant here — login path. The identity row
        // (loaded above) already guarantees the tenant via its FK;
        // begin_trace_tenant_transaction only sets the RLS var (no write).
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "UPDATE trace_near_identities
                SET last_used_at = now()
              WHERE tenant_id = trace_current_tenant_id()
                AND public_key = $1
                AND revoked_at IS NULL",
            &[&public_key],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn list_account_near_identities(
        &self,
        tenant_id: &str,
        account_id: Uuid,
    ) -> Result<Vec<crate::db::NearIdentitySummary>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT public_key, near_account_id, label, created_at, last_used_at,
                        payout_designated_at
                   FROM trace_near_identities
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND revoked_at IS NULL
                  ORDER BY created_at",
                &[&account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let payout_designated_at: Option<chrono::DateTime<chrono::Utc>> =
                    row.get("payout_designated_at");
                crate::db::NearIdentitySummary {
                    public_key: row.get("public_key"),
                    near_account_id: row.get("near_account_id"),
                    label: row.get("label"),
                    created_at: row.get("created_at"),
                    last_used_at: row.get("last_used_at"),
                    is_payout: payout_designated_at.is_some(),
                }
            })
            .collect())
    }

    async fn rename_account_near_identity(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        public_key: &str,
        label: Option<&str>,
    ) -> Result<bool, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // account-scoped so a caller can never rename an identity they do not own.
        let affected = tx
            .execute(
                "UPDATE trace_near_identities
                    SET label = $1
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $2
                    AND public_key = $3
                    AND revoked_at IS NULL",
                &[&label, &account_id, &public_key],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(affected > 0)
    }

    async fn revoke_account_near_identity(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        public_key: &str,
    ) -> Result<crate::db::RevokeNearResult, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // account-scoped soft-delete: an unknown / already-revoked / other-account
        // key affects zero rows.
        let removed = tx
            .execute(
                "UPDATE trace_near_identities
                    SET revoked_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND public_key = $2
                    AND revoked_at IS NULL",
                &[&account_id, &public_key],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        // remaining strong authenticators = webauthn credentials + NEAR identities,
        // computed in the SAME tx after the revoke.
        let remaining_row = tx
            .query_one(
                "SELECT (
                    SELECT count(*) FROM trace_webauthn_credentials
                      WHERE tenant_id = trace_current_tenant_id()
                        AND account_id = $1
                        AND revoked_at IS NULL
                  ) + (
                    SELECT count(*) FROM trace_near_identities
                      WHERE tenant_id = trace_current_tenant_id()
                        AND account_id = $1
                        AND revoked_at IS NULL
                  ) AS remaining_strong",
                &[&account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let remaining_strong: i64 = remaining_row.get("remaining_strong");
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(crate::db::RevokeNearResult {
            removed: removed > 0,
            remaining_strong,
        })
    }

    async fn count_active_strong_authenticators(
        &self,
        tenant_id: &str,
        account_id: Uuid,
    ) -> Result<i64, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_one(
                "SELECT (
                    SELECT count(*) FROM trace_webauthn_credentials
                      WHERE tenant_id = trace_current_tenant_id()
                        AND account_id = $1
                        AND revoked_at IS NULL
                  ) + (
                    SELECT count(*) FROM trace_near_identities
                      WHERE tenant_id = trace_current_tenant_id()
                        AND account_id = $1
                        AND revoked_at IS NULL
                  ) AS strong_count",
                &[&account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.get("strong_count"))
    }

    async fn designate_payout_near_identity(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        public_key: &str,
    ) -> Result<bool, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Clear any existing active designation first so at most one active row ever
        // carries payout_designated_at -> the partial-unique index can never trip.
        tx.execute(
            "UPDATE trace_near_identities
                SET payout_designated_at = NULL
              WHERE tenant_id = trace_current_tenant_id()
                AND account_id = $1
                AND payout_designated_at IS NOT NULL",
            &[&account_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        // Stamp the named active key. account-scoped + revoked_at IS NULL so an
        // unknown / revoked / other-account key affects zero rows.
        let affected = tx
            .execute(
                "UPDATE trace_near_identities
                    SET payout_designated_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND public_key = $2
                    AND revoked_at IS NULL",
                &[&account_id, &public_key],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(affected > 0)
    }

    async fn clear_payout_near_identity(
        &self,
        tenant_id: &str,
        account_id: Uuid,
        public_key: &str,
    ) -> Result<bool, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let affected = tx
            .execute(
                "UPDATE trace_near_identities
                    SET payout_designated_at = NULL
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND public_key = $2
                    AND revoked_at IS NULL
                    AND payout_designated_at IS NOT NULL",
                &[&account_id, &public_key],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(affected > 0)
    }

    async fn resolve_payout_near_account_id(
        &self,
        tenant_id: &str,
        account_id: Uuid,
    ) -> Result<crate::db::PayoutResolution, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT near_account_id, payout_designated_at
                   FROM trace_near_identities
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND revoked_at IS NULL",
                &[&account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;

        // A designated active identity wins outright.
        if let Some(row) = rows.iter().find(|row| {
            row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("payout_designated_at")
                .is_some()
        }) {
            return Ok(crate::db::PayoutResolution::Designated(
                row.get("near_account_id"),
            ));
        }
        // No designation: a single active identity is unambiguous; otherwise hold.
        match rows.len() {
            0 => Ok(crate::db::PayoutResolution::Hold(
                crate::db::PayoutHoldReason::NoneEnrolled,
            )),
            1 => Ok(crate::db::PayoutResolution::SoleActive(
                rows[0].get("near_account_id"),
            )),
            _ => Ok(crate::db::PayoutResolution::Hold(
                crate::db::PayoutHoldReason::AmbiguousNoDesignation,
            )),
        }
    }

    async fn stage_merge_proposal(
        &self,
        tenant_id: &str,
        surviving_account_id: Uuid,
        merge_code_hash: &str,
    ) -> Result<Option<crate::db::StagedMergeProposal>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;

        // Proof-of-control: consume device B's login-link with the SAME atomic
        // conditional consume as redeem_login_link (ALWAYS executed, never a
        // SELECT-then-branch). Unknown / expired / already-consumed / wrong-tenant
        // codes all affect zero rows -> commit the no-op tx and deny. The
        // `tenant_id = trace_current_tenant_id()` predicate is belt-and-suspenders
        // on top of forced RLS; `code_hash` is globally UNIQUE.
        let consumed = tx
            .query_opt(
                "UPDATE trace_login_links SET consumed_at = now()
                  WHERE code_hash = $1
                    AND tenant_id = trace_current_tenant_id()
                    AND consumed_at IS NULL
                    AND expires_at > now()
                  RETURNING account_id",
                &[&merge_code_hash],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let Some(consumed) = consumed else {
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(None);
        };
        let absorbed_account_id: Uuid = consumed.get("account_id");

        // Guard: cannot merge an account into itself. The consume already fired,
        // so commit it (the link is single-use spent) and deny.
        if absorbed_account_id == surviving_account_id {
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(None);
        }

        // Guard: the absorbed account B must still be open. A closed account has
        // nothing live to fold in.
        let closed_at: Option<chrono::DateTime<chrono::Utc>> = tx
            .query_one(
                "SELECT closed_at FROM trace_accounts
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1",
                &[&absorbed_account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .get("closed_at");
        if closed_at.is_some() {
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(None);
        }

        // Attribution-only count of B's ACTIVE principals for operator review.
        let absorbed_principal_count: i64 = tx
            .query_one(
                "SELECT count(*) FROM trace_account_principals
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1
                    AND unlinked_at IS NULL",
                &[&absorbed_account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .get(0);

        // Stage the single-use, time-bounded proposal. proposal_id is
        // server-assigned; expires in 10 minutes.
        let proposal_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO trace_account_merge_proposals (
                tenant_id, proposal_id, surviving_account_id, absorbed_account_id,
                absorbed_principal_count, created_at, expires_at
             ) VALUES (
                trace_current_tenant_id(), $1, $2, $3, $4, now(),
                now() + interval '10 minutes'
             )",
            &[
                &proposal_id,
                &surviving_account_id,
                &absorbed_account_id,
                &absorbed_principal_count,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(Some(crate::db::StagedMergeProposal {
            proposal_id,
            absorbed_account_id,
            absorbed_principal_count,
        }))
    }

    async fn execute_merge(
        &self,
        tenant_id: &str,
        surviving_account_id: Uuid,
        proposal_id: Uuid,
    ) -> Result<Option<crate::db::ExecutedMerge>, DatabaseError> {
        self.ensure_trace_tenant(tenant_id).await?;
        let mut client = self.trace_pool().get().await.map_err(DatabaseError::from)?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;

        // Load + consume the proposal atomically. The conditional UPDATE
        // re-validates OWNERSHIP (surviving_account_id = A, the auth-derived
        // caller), single-use (consumed_at IS NULL), and freshness (expires_at >
        // now()) AND that the surviving account A is still OPEN in one shot: an
        // expired / not-owned / already-consumed / unknown proposal, or a
        // soft-closed A, affects zero rows -> deny. The A-open EXISTS guard is
        // load-bearing: the proposal FK only guarantees A exists, not that it is
        // open, and a soft-close (closed_at) does not trigger ON DELETE CASCADE,
        // so without it B's principals + authenticators could be folded onto a
        // tombstoned account (irreversible identity corruption). Returning Ok(None)
        // before any mutation drops the tx (no commit), so the consume itself rolls
        // back and the proposal stays usable on the benign-not-found paths.
        let consumed = tx
            .query_opt(
                "UPDATE trace_account_merge_proposals SET consumed_at = now()
                  WHERE tenant_id = trace_current_tenant_id()
                    AND proposal_id = $1
                    AND surviving_account_id = $2
                    AND consumed_at IS NULL
                    AND expires_at > now()
                    AND EXISTS (
                        SELECT 1 FROM trace_accounts a
                         WHERE a.tenant_id = trace_current_tenant_id()
                           AND a.account_id = $2
                           AND a.closed_at IS NULL
                    )
                  RETURNING absorbed_account_id",
                &[&proposal_id, &surviving_account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let Some(consumed) = consumed else {
            return Ok(None);
        };
        let absorbed_account_id: Uuid = consumed.get("absorbed_account_id");

        // Re-check B is still open. If B closed between stage and execute, abandon
        // the whole merge: return Ok(None) WITHOUT committing so the consume above
        // (and any reads) roll back and the proposal remains usable.
        let closed_at: Option<chrono::DateTime<chrono::Utc>> = tx
            .query_one(
                "SELECT closed_at FROM trace_accounts
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $1",
                &[&absorbed_account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .get("closed_at");
        if closed_at.is_some() {
            return Ok(None);
        }

        // Move B's ACTIVE principal links onto A. PK-column UPDATE; collision-free
        // because (tenant_id, principal_ref) is UNIQUE and a principal has at most
        // one active link.
        let principals_moved = tx
            .execute(
                "UPDATE trace_account_principals
                    SET account_id = $1
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $2
                    AND unlinked_at IS NULL",
                &[&surviving_account_id, &absorbed_account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)? as i64;

        // Re-key B's ACTIVE webauthn credentials onto A (account_id is a non-key
        // column, so a plain UPDATE is safe).
        let webauthn_moved = tx
            .execute(
                "UPDATE trace_webauthn_credentials
                    SET account_id = $1
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $2
                    AND revoked_at IS NULL",
                &[&surviving_account_id, &absorbed_account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)? as i64;

        // Re-key B's ACTIVE NEAR identities onto A, CLEARING payout_designated_at:
        // A may already have its own designated payout, and the partial-unique
        // index forbids two active designations per account. The contributor can
        // re-designate afterward.
        let near_moved = tx
            .execute(
                "UPDATE trace_near_identities
                    SET account_id = $1, payout_designated_at = NULL
                  WHERE tenant_id = trace_current_tenant_id()
                    AND account_id = $2
                    AND revoked_at IS NULL",
                &[&surviving_account_id, &absorbed_account_id],
            )
            .await
            .map_err(DatabaseError::Postgres)? as i64;
        let authenticators_moved = webauthn_moved + near_moved;

        // Revoke ALL of B's live sessions (mirror revoke_all_account_sessions):
        // B's credentials now belong to A, so its old sessions must die.
        tx.execute(
            "UPDATE trace_sessions SET revoked_at = now()
              WHERE tenant_id = trace_current_tenant_id()
                AND account_id = $1
                AND revoked_at IS NULL",
            &[&absorbed_account_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        // Close B.
        tx.execute(
            "UPDATE trace_accounts SET closed_at = now()
              WHERE tenant_id = trace_current_tenant_id()
                AND account_id = $1
                AND closed_at IS NULL",
            &[&absorbed_account_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        // Hash-only / label-only audit. Actor is the surviving account A
        // (reserved-prefix). Metadata is COUNTS ONLY: no principal_refs, public
        // keys, or account uuids.
        let actor_ref = crate::account_session::account_actor_ref(
            &crate::account_session::AccountId::from_uuid(surviving_account_id),
        );
        let safe_metadata = serde_json::json!({
            "principals_moved": principals_moved,
            "authenticators_moved": authenticators_moved,
        });
        tx.execute(
            "INSERT INTO trace_account_audit (
                tenant_id, action, actor_ref, outcome, safe_metadata
             ) VALUES (trace_current_tenant_id(), $1, $2, $3, $4)",
            &[&"account_merged", &actor_ref, &"success", &safe_metadata],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(Some(crate::db::ExecutedMerge {
            principals_moved,
            authenticators_moved,
        }))
    }

    async fn count_submissions_needing_gate_decision(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        max_attempts: i32,
        backoff_base_seconds: i64,
    ) -> Result<i64, DatabaseError> {
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // Character-for-character the predicate in
        // `list_submissions_needing_gate_decision`, minus its ORDER BY and
        // LIMIT. If the two ever drift, the logged backlog stops describing
        // the queue the driver is actually draining, which is worse than not
        // logging one -- an operator would tune against a number that means
        // something else. The pg test asserts they agree on real rows.
        let row = client
            .query_one(
                "SELECT count(*) FROM (
                   SELECT DISTINCT s.tenant_id, s.submission_id, s.received_at
                     FROM trace_submissions s
                     JOIN trace_object_refs o
                       ON o.tenant_id = s.tenant_id
                      AND o.submission_id = s.submission_id
                      AND o.artifact_kind = 'submitted_envelope'
                      AND o.invalidated_at IS NULL
                      AND o.deleted_at IS NULL
                     LEFT JOIN trace_gate_decisions d
                       ON d.tenant_id = s.tenant_id AND d.submission_id = s.submission_id
                     LEFT JOIN trace_gate_evaluation_attempts a
                       ON a.tenant_id = s.tenant_id AND a.submission_id = s.submission_id
                    WHERE d.decision_id IS NULL
                      AND COALESCE(a.attempts, 0) < $1
                      AND (a.last_attempt_at IS NULL
                           OR a.last_attempt_at + make_interval(secs => ($2::bigint)::double precision * POWER(2, COALESCE(a.attempts,0))) <= $3)
                 ) pending",
                &[&max_attempts, &backoff_base_seconds, &now],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(row.get::<_, i64>(0))
    }

    async fn list_submissions_needing_gate_decision(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        max_attempts: i32,
        backoff_base_seconds: i64,
        limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::GateWorkItem>, DatabaseError> {
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant context is set on this connection: the trace_gate_driver
        // role's permissive cross-tenant SELECT policies (migration V36) plus
        // column-scoped grants (migration V42) authorize this read across
        // every tenant's submissions.
        let rows = client
            .query(
                // DISTINCT: a submission can carry more than one active
                // submitted_envelope object ref, so the INNER JOIN can fan out
                // to multiple rows per submission. Deduplicate to one work item
                // per (tenant, submission) — otherwise a multi-ref submission
                // wastes LIMIT slots and gets scored/attempted concurrently
                // more than once. `received_at` is included in the projection
                // only so it is a legal DISTINCT + ORDER BY target; it is a
                // per-submission constant, so it does not change dedup
                // cardinality, and it is dropped when mapping to GateWorkItem.
                "SELECT DISTINCT s.tenant_id, s.submission_id, s.received_at
                 FROM trace_submissions s
                 JOIN trace_object_refs o
                   ON o.tenant_id = s.tenant_id
                  AND o.submission_id = s.submission_id
                  AND o.artifact_kind = 'submitted_envelope'
                  AND o.invalidated_at IS NULL
                  AND o.deleted_at IS NULL
                 LEFT JOIN trace_gate_decisions d
                   ON d.tenant_id = s.tenant_id AND d.submission_id = s.submission_id
                 LEFT JOIN trace_gate_evaluation_attempts a
                   ON a.tenant_id = s.tenant_id AND a.submission_id = s.submission_id
                 WHERE d.decision_id IS NULL
                   AND COALESCE(a.attempts, 0) < $1
                   AND (a.last_attempt_at IS NULL
                        OR a.last_attempt_at + make_interval(secs => ($2::bigint)::double precision * POWER(2, COALESCE(a.attempts,0))) <= $3)
                 ORDER BY s.received_at ASC
                 LIMIT $4",
                &[&max_attempts, &backoff_base_seconds, &now, &limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;

        Ok(rows
            .into_iter()
            .map(|row| crate::trace_corpus_storage::GateWorkItem {
                tenant_id: row.get("tenant_id"),
                submission_id: row.get("submission_id"),
            })
            .collect())
    }

    async fn list_submissions_awaiting_pii_backstop(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        max_attempts: i32,
        backoff_base_seconds: i64,
        limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::GateWorkItem>, DatabaseError> {
        let pool = self.pii_backstop_driver_pool.as_ref().ok_or_else(|| {
            DatabaseError::Pool("pii-backstop-driver pool not configured".to_string())
        })?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant context is set on this connection: the
        // trace_pii_backstop_driver role's permissive cross-tenant SELECT
        // policies (migration V38) are what authorize this read across every
        // tenant's submissions.
        let rows = client
            .query(
                // DISTINCT: a submission can carry more than one active
                // submitted_envelope object ref, so the INNER JOIN can fan out
                // to multiple rows per submission. Deduplicate to one work item
                // per (tenant, submission) — otherwise a multi-ref submission
                // wastes LIMIT slots and gets attempted concurrently more than
                // once. `received_at` and `a.last_attempt_at` are included in
                // the projection only so they are legal DISTINCT + ORDER BY
                // targets; both are per-submission constants, so they do not
                // change dedup cardinality, and both are dropped when mapping
                // to GateWorkItem.
                // `rescrubbed_envelope` is accepted alongside `submitted_envelope`
                // so a submission that has ALREADY been through the backstop can
                // be re-enumerated. Requeueing a quarantined submission
                // invalidates nothing and resurrects nothing: its
                // `submitted_envelope` ref stays invalidated -- an active
                // pre-scrub ref is the concurrent-read hazard documented in
                // `process_one_pii_backstop` -- and the driver reads through the
                // record's own pointers, which already address the rescrubbed
                // artifact. Without this, flipping a quarantined submission back
                // to `awaiting_pii_backstop` would silently never be picked up.
                "SELECT DISTINCT s.tenant_id, s.submission_id, s.received_at, a.last_attempt_at
                 FROM trace_submissions s
                 JOIN trace_object_refs o
                   ON o.tenant_id = s.tenant_id
                  AND o.submission_id = s.submission_id
                  AND o.artifact_kind IN ('submitted_envelope', 'rescrubbed_envelope')
                  AND o.invalidated_at IS NULL
                  AND o.deleted_at IS NULL
                 LEFT JOIN trace_pii_backstop a
                   ON a.tenant_id = s.tenant_id AND a.submission_id = s.submission_id
                 WHERE s.status = 'awaiting_pii_backstop'
                   AND COALESCE(a.attempts, 0) < $1
                   AND (a.last_attempt_at IS NULL
                        OR a.last_attempt_at + make_interval(secs => ($2::bigint)::double precision * POWER(2, COALESCE(a.attempts,0))) <= $3)
                 -- Least-recently-attempted first, never-attempted before
                 -- everything else. Ordering by received_at alone let a
                 -- submission that keeps failing transiently sit at the head
                 -- of every batch forever: a transient failure charges no
                 -- attempt, so it stayed permanently eligible, and the
                 -- consecutive-failure breaker aborted each tick before
                 -- reaching anything behind it. On 2026-08-27 that starved
                 -- 233 never-attempted traces behind the same three.
                 ORDER BY a.last_attempt_at ASC NULLS FIRST, s.received_at ASC
                 LIMIT $4",
                &[&max_attempts, &backoff_base_seconds, &now, &limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;

        Ok(rows
            .into_iter()
            .map(|row| crate::trace_corpus_storage::GateWorkItem {
                tenant_id: row.get("tenant_id"),
                submission_id: row.get("submission_id"),
            })
            .collect())
    }

    async fn list_submissions_with_gate_decision(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::GateWorkItem>, DatabaseError> {
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant context is set on this connection: the trace_gate_driver
        // role's permissive cross-tenant SELECT policies (migration V36) plus
        // column-scoped grants (migration V42) authorize this read across
        // every tenant's decisions.
        //
        // DISTINCT + `received_at` in the projection mirrors the sibling
        // `list_submissions_needing_gate_decision` query: `received_at` is a
        // legal DISTINCT + ORDER BY target and a per-submission constant, so it
        // does not change dedup cardinality and is dropped when mapping to
        // GateWorkItem. A submission with a decision necessarily has a decision
        // row, so the INNER JOIN never fans out beyond the one decision.
        let rows = client
            .query(
                "SELECT DISTINCT s.tenant_id, s.submission_id, s.received_at
                 FROM trace_submissions s
                 JOIN trace_gate_decisions d
                   ON d.tenant_id = s.tenant_id AND d.submission_id = s.submission_id
                 ORDER BY s.received_at ASC
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;

        Ok(rows
            .into_iter()
            .map(|row| crate::trace_corpus_storage::GateWorkItem {
                tenant_id: row.get("tenant_id"),
                submission_id: row.get("submission_id"),
            })
            .collect())
    }

    async fn list_gate_decisions_for_credit_scoring(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::GateCreditInput>, DatabaseError> {
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant GUC: the trace_gate_driver role's permissive cross-tenant
        // SELECT policies authorize this read across every tenant's decisions.
        let rows = client
            .query(
                "SELECT tenant_id, decision_id,
                        COALESCE(perplexity_micros, 0)      AS perplexity_micros,
                        COALESCE(peak_perplexity_micros, 0) AS peak_perplexity_micros,
                        COALESCE(novelty_score_micros, 0)   AS novelty_score_micros
                 FROM trace_gate_decisions
                 ORDER BY decided_at ASC
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| crate::trace_corpus_storage::GateCreditInput {
                tenant_id: row.get("tenant_id"),
                decision_id: row.get("decision_id"),
                perplexity_micros: row.get("perplexity_micros"),
                peak_perplexity_micros: row.get("peak_perplexity_micros"),
                novelty_score_micros: row.get("novelty_score_micros"),
            })
            .collect())
    }

    async fn list_dedup_signals(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::DedupSignalRow>, DatabaseError> {
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant GUC: the trace_gate_driver role's permissive cross-tenant
        // SELECT policies authorize this read across every tenant's decisions.
        let rows = client
            .query(
                // `dedup_signal_version` (V57) is selected here, so V57 also
                // grants it to trace_gate_driver: the role holds
                // COLUMN-scoped grants, and column privileges cover every
                // column a query references.
                "SELECT tenant_id, decision_id, dedup_cluster_id, dedup_simhash,
                        dedup_signal_version
                 FROM trace_gate_decisions
                 ORDER BY decided_at ASC
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| crate::trace_corpus_storage::DedupSignalRow {
                tenant_id: row.get("tenant_id"),
                decision_id: row.get("decision_id"),
                dedup_cluster_id: row.get("dedup_cluster_id"),
                dedup_simhash: row.get("dedup_simhash"),
                dedup_signal_version: row.get("dedup_signal_version"),
            })
            .collect())
    }

    async fn list_correction_signals(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::CorrectionSignalRow>, DatabaseError> {
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant GUC: the trace_gate_driver role's permissive cross-tenant
        // SELECT policies authorize this read across every tenant's decisions.
        // Corrections cluster cross-tenant deliberately — the same correction
        // pasted into two tenants is one correction.
        let rows = client
            .query(
                "SELECT tenant_id, decision_id, correction_cluster_id, correction_simhash
                 FROM trace_gate_decisions
                 WHERE correction_simhash IS NOT NULL
                 ORDER BY decided_at ASC
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| crate::trace_corpus_storage::CorrectionSignalRow {
                tenant_id: row.get("tenant_id"),
                decision_id: row.get("decision_id"),
                correction_cluster_id: row.get("correction_cluster_id"),
                correction_simhash: row.get("correction_simhash"),
            })
            .collect())
    }

    async fn list_contributor_cap_signals(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::ContributorCapSignalRow>, DatabaseError> {
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant GUC: the trace_gate_driver role's permissive cross-tenant
        // SELECT policies authorize this read across every tenant's decisions and
        // submissions. Ordered by (auth_principal_ref, decided_at) so the recompute
        // pass groups per contributor and forward-accumulates in time order.
        let rows = client
            .query(
                "SELECT d.tenant_id, d.decision_id, s.auth_principal_ref,
                        d.decided_at, d.credit_quality_micros, d.dedup_cluster_size
                 FROM trace_gate_decisions d
                 JOIN trace_submissions s
                   ON s.tenant_id = d.tenant_id AND s.submission_id = d.submission_id
                 -- decision_id is the final, unique tiebreaker so decisions
                 -- with an identical decided_at within a contributor sort
                 -- deterministically; the forward pass then assigns each row a
                 -- stable factor/cumulative across idempotent re-runs.
                 ORDER BY s.auth_principal_ref ASC, d.decided_at ASC, d.decision_id ASC
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| crate::trace_corpus_storage::ContributorCapSignalRow {
                tenant_id: row.get("tenant_id"),
                decision_id: row.get("decision_id"),
                auth_principal_ref: row.get("auth_principal_ref"),
                decided_at: row.get("decided_at"),
                credit_quality_micros: row.get("credit_quality_micros"),
                dedup_cluster_size: row.get("dedup_cluster_size"),
            })
            .collect())
    }

    async fn list_scores_by_submission_ids(
        &self,
        submission_ids: &[uuid::Uuid],
    ) -> Result<Vec<crate::trace_corpus_storage::TraceScoreBySubmissionRow>, DatabaseError> {
        if submission_ids.is_empty() {
            return Ok(Vec::new());
        }
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant GUC: the trace_gate_driver role's permissive cross-tenant
        // SELECT policies authorize this read across every tenant's decisions.
        let rows = client
            .query(
                "SELECT DISTINCT ON (submission_id)
                    submission_id,
                    credit_quality_micros,
                    perplexity_micros,
                    novelty_score_micros,
                    perplexity_passed,
                    novelty_passed,
                    chunk_count,
                    total_chunk_count,
                    chunks_capped
                 FROM trace_gate_decisions
                 WHERE submission_id = ANY($1)
                 -- decision_id is the final, unique tiebreaker (mirrors
                 -- list_contributor_cap_signals) so decisions that share a
                 -- decided_at sort deterministically instead of Postgres
                 -- picking an arbitrary row among ties on repeated reads.
                 ORDER BY submission_id, decided_at DESC, decision_id DESC",
                &[&submission_ids],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let perplexity_passed: bool = row.get("perplexity_passed");
                let novelty_passed: bool = row.get("novelty_passed");
                crate::trace_corpus_storage::TraceScoreBySubmissionRow {
                    submission_id: row.get("submission_id"),
                    credit_quality_micros: row.get("credit_quality_micros"),
                    perplexity_micros: row.get("perplexity_micros"),
                    novelty_score_micros: row.get("novelty_score_micros"),
                    gate_passed: perplexity_passed && novelty_passed,
                    chunk_count: row.get("chunk_count"),
                    total_chunk_count: row.get("total_chunk_count"),
                    chunks_capped: row.get("chunks_capped"),
                }
            })
            .collect())
    }

    async fn list_own_gate_decision_scores(
        &self,
        tenant_id: &str,
        auth_principal_ref: &str,
        limit: i64,
    ) -> Result<Vec<crate::trace_corpus_storage::TraceScoreBySubmissionRow>, DatabaseError> {
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // No tenant GUC: the trace_gate_driver role's permissive cross-tenant
        // SELECT policies authorize this read. The `s.tenant_id = $1 AND
        // s.auth_principal_ref = $2` predicates are what actually scope the
        // read to the caller's own rows — both values come from the
        // authenticated request context, never from a client-supplied
        // parameter (see `trace_score_attestation` and the ingest binary's
        // `score_attestation_handler`).
        let rows = client
            .query(
                // The inner SELECT picks the LATEST decision per submission;
                // the outer one orders those by recency and truncates. The
                // two cannot be one statement: DISTINCT ON requires its
                // leading ORDER BY term to be the distinct key, so a single
                // query can only truncate in submission_id order — which is
                // a random v4 per trace, making truncation an arbitrary slice
                // of the UUID space rather than a comprehensible "your oldest
                // scores fell off".
                "SELECT * FROM (
                    SELECT DISTINCT ON (d.submission_id)
                        d.submission_id,
                        d.credit_quality_micros,
                        d.perplexity_micros,
                        d.novelty_score_micros,
                        d.perplexity_passed,
                        d.novelty_passed,
                        d.chunk_count,
                        d.total_chunk_count,
                        d.chunks_capped,
                        d.decided_at
                     FROM trace_gate_decisions d
                     JOIN trace_submissions s
                       ON s.tenant_id = d.tenant_id AND s.submission_id = d.submission_id
                     WHERE s.tenant_id = $1 AND s.auth_principal_ref = $2
                     -- decision_id is the final, unique tiebreaker (mirrors
                     -- list_scores_by_submission_ids) so decisions that share a
                     -- decided_at sort deterministically instead of Postgres
                     -- picking an arbitrary row among ties on repeated reads.
                     ORDER BY d.submission_id, d.decided_at DESC, d.decision_id DESC
                 ) latest
                 -- submission_id breaks decided_at ties so the truncated set
                 -- is stable across repeated reads.
                 ORDER BY latest.decided_at DESC, latest.submission_id DESC
                 LIMIT $3",
                &[&tenant_id, &auth_principal_ref, &limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let perplexity_passed: bool = row.get("perplexity_passed");
                let novelty_passed: bool = row.get("novelty_passed");
                crate::trace_corpus_storage::TraceScoreBySubmissionRow {
                    submission_id: row.get("submission_id"),
                    credit_quality_micros: row.get("credit_quality_micros"),
                    perplexity_micros: row.get("perplexity_micros"),
                    novelty_score_micros: row.get("novelty_score_micros"),
                    gate_passed: perplexity_passed && novelty_passed,
                    chunk_count: row.get("chunk_count"),
                    total_chunk_count: row.get("total_chunk_count"),
                    chunks_capped: row.get("chunks_capped"),
                }
            })
            .collect())
    }

    async fn list_own_gate_decision_scores_for_submissions(
        &self,
        tenant_id: &str,
        auth_principal_ref: &str,
        submission_ids: &[uuid::Uuid],
    ) -> Result<Vec<crate::trace_corpus_storage::OwnSubmissionScoreRow>, DatabaseError> {
        if submission_ids.is_empty() {
            return Ok(Vec::new());
        }
        let pool = self
            .gate_driver_pool
            .as_ref()
            .ok_or_else(|| DatabaseError::Pool("gate-driver pool not configured".to_string()))?;
        let client = pool.get().await.map_err(DatabaseError::from)?;
        // Same authorization story as `list_own_gate_decision_scores`: no
        // tenant GUC, the trace_gate_driver role's permissive cross-tenant
        // SELECT policies authorize the read, and the `s.tenant_id = $1 AND
        // s.auth_principal_ref = $2` predicates are what scope it to the
        // caller's own rows. $3 only NARROWS that set.
        //
        // The join is LEFT, and driven from trace_submissions rather than
        // from trace_gate_decisions, precisely so an owned-but-unscored
        // submission comes back with NULL score columns instead of
        // vanishing. That absence is the defect this method exists to fix.
        let rows = client
            .query(
                "SELECT DISTINCT ON (s.submission_id)
                    s.submission_id,
                    d.decision_id,
                    d.credit_quality_micros,
                    d.perplexity_micros,
                    d.novelty_score_micros,
                    d.perplexity_passed,
                    d.novelty_passed,
                    d.chunk_count,
                    d.total_chunk_count,
                    d.chunks_capped
                 FROM trace_submissions s
                 LEFT JOIN trace_gate_decisions d
                   ON d.tenant_id = s.tenant_id AND d.submission_id = s.submission_id
                 WHERE s.tenant_id = $1
                   AND s.auth_principal_ref = $2
                   AND s.submission_id = ANY($3)
                 ORDER BY s.submission_id, d.decided_at DESC NULLS LAST, d.decision_id DESC",
                &[&tenant_id, &auth_principal_ref, &submission_ids],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let decision_id: Option<Uuid> = row.get("decision_id");
                let submission_id: Uuid = row.get("submission_id");
                // Every score column is NULLable only because of the LEFT
                // join; a present decision_id means the whole row is present.
                let score = decision_id.map(|_| {
                    let perplexity_passed: bool = row.get("perplexity_passed");
                    let novelty_passed: bool = row.get("novelty_passed");
                    crate::trace_corpus_storage::TraceScoreBySubmissionRow {
                        submission_id,
                        credit_quality_micros: row.get("credit_quality_micros"),
                        perplexity_micros: row.get("perplexity_micros"),
                        novelty_score_micros: row.get("novelty_score_micros"),
                        gate_passed: perplexity_passed && novelty_passed,
                        chunk_count: row.get("chunk_count"),
                        total_chunk_count: row.get("total_chunk_count"),
                        chunks_capped: row.get("chunks_capped"),
                    }
                });
                crate::trace_corpus_storage::OwnSubmissionScoreRow {
                    submission_id,
                    score,
                }
            })
            .collect())
    }
}

fn device_key_record_from_row(row: Row) -> crate::db::DeviceKeyRecord {
    crate::db::DeviceKeyRecord {
        device_key_id: row.get("device_key_id"),
        tenant_id: row.get("tenant_id"),
        public_key: row.get("public_key"),
        invite_subject_hash: row.get("invite_subject_hash"),
        client_info: row.get("client_info"),
        created_at: row.get("created_at"),
        revoked_at: row.get("revoked_at"),
    }
}

/// Pilot-default consent scopes for onboarding device-key grants, used when a
/// device is onboarded via invite (no per-tenant policy template) and as the
/// fail-closed fallback for instance-enrolled devices.
const DEFAULT_ONBOARDING_CONSENT_SCOPES: [&str; 2] = ["debugging_evaluation", "public_attribution"];
/// Pilot-default allowed uses, mirroring `DEFAULT_ONBOARDING_CONSENT_SCOPES`.
const DEFAULT_ONBOARDING_ALLOWED_USES: [&str; 3] =
    ["debugging", "evaluation", "aggregate_analytics"];

/// Normalize a policy-template scope array (serde_json::Value from
/// InstanceUserProvision) into storage strings. Non-array, empty, or
/// non-string-element values fall back to `defaults` (fail closed).
fn normalize_provision_scope_values(value: &serde_json::Value, defaults: &[&str]) -> Vec<String> {
    let fallback = || defaults.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let Some(items) = value.as_array() else {
        return fallback();
    };
    if items.is_empty() {
        return fallback();
    }
    let mut normalized = Vec::with_capacity(items.len());
    for item in items {
        match item.as_str() {
            Some(s) => normalized.push(s.to_string()),
            None => return fallback(),
        }
    }
    normalized
}

/// Resolve the scopes to grant on `/v1/onboard`: an invite-supplied override
/// when present and non-empty, otherwise the process-wide default. Empty is
/// deliberately treated the same as absent -- invites imported from the file
/// allowlist carry empty scope vectors (the file format never had a scopes
/// column), and provisioning them with zero consent scopes would silently
/// strip permissions the pilot already grants those invites.
fn resolve_onboarding_scope_override(
    override_scopes: &Option<Vec<String>>,
    default: &[String],
) -> Vec<String> {
    match override_scopes {
        Some(scopes) if !scopes.is_empty() => scopes.clone(),
        _ => default.to_vec(),
    }
}

async fn upsert_onboarding_device_tenant_access_grant(
    tx: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    device_key_id: &str,
    allowed_consent_scopes: &[String],
    allowed_uses: &[String],
) -> Result<(), DatabaseError> {
    let grant_id = onboarding_device_tenant_access_grant_id(tenant_id, device_key_id);
    let principal_ref = onboarding_device_principal_ref(tenant_id, device_key_id);
    let allowed_consent_scopes = serde_json::json!(allowed_consent_scopes);
    let allowed_uses = serde_json::json!(allowed_uses);
    let metadata_json =
        serde_json::json!({"source": "onboarding_device_key", "capability": "pilot_default"});

    tx.execute(
        "INSERT INTO trace_tenant_access_grants (
            tenant_id, grant_id, principal_ref, role, status,
            allowed_consent_scopes, allowed_uses, issuer, audience, subject,
            issued_at, expires_at, revoked_at, created_by_principal_ref,
            revoked_by_principal_ref, reason, metadata_json
         ) VALUES ($1, $2, $3, 'contributor', 'active',
            $4, $5, NULL, NULL, NULL, NOW(), NULL, NULL,
            'system:onboard_device_key', NULL, $6, $7)
         ON CONFLICT (tenant_id, grant_id) DO UPDATE SET
            principal_ref = excluded.principal_ref,
            role = excluded.role,
            status = excluded.status,
            allowed_consent_scopes = excluded.allowed_consent_scopes,
            allowed_uses = excluded.allowed_uses,
            issuer = excluded.issuer,
            audience = excluded.audience,
            subject = excluded.subject,
            expires_at = excluded.expires_at,
            revoked_at = excluded.revoked_at,
            created_by_principal_ref = excluded.created_by_principal_ref,
            reason = excluded.reason,
            metadata_json = excluded.metadata_json,
            updated_at = NOW()
          WHERE trace_tenant_access_grants.status <> 'revoked'",
        &[
            &tenant_id,
            &grant_id,
            &principal_ref,
            &allowed_consent_scopes,
            &allowed_uses,
            &ONBOARDING_DEVICE_GRANT_REASON,
            &metadata_json,
        ],
    )
    .await
    .map_err(DatabaseError::Postgres)?;
    Ok(())
}

fn onboarding_device_tenant_access_grant_id(tenant_id: &str, device_key_id: &str) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "tracecommons:onboarding-device-access-grant:{}:{}",
            tenant_id.trim(),
            device_key_id.trim()
        )
        .as_bytes(),
    )
}

fn onboarding_device_principal_ref(tenant_id: &str, device_key_id: &str) -> String {
    let digest = Sha256::digest(format!(
        "device:{}:{}",
        tenant_id.trim(),
        device_key_id.trim()
    ));
    format!("principal_sha256:{}", hex::encode(digest))
}

fn sha256_prefixed(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

/// The seven columns `trace_commons_public_read` is granted, and no others --
/// `singleton` among them, because the filter below references it.
///
/// One constant rather than two copies: the runtime read and the public read
/// must return the same shape, and the public role's GRANT is column-scoped,
/// so a seventh column added to one copy would fail at request time under
/// that role only.
///
/// `WHERE singleton = TRUE` is a correctness guard, not decoration, and stays.
/// `query_one` errors on anything but exactly one row, so a bare
/// `SELECT ... FROM trace_register_stats` is correct only for as long as
/// `singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton)` holds. That
/// constraint is one migration away from being relaxed, and the failure mode
/// then is a 500 or a silently wrong row, not a compile error.
///
/// `singleton` must therefore appear in V55's column grant, and does.
/// PostgreSQL column privileges cover every column a query REFERENCES, not
/// just the ones it projects, so filtering on an ungranted column denies the
/// whole table under `trace_commons_public_read` ("permission denied for
/// table trace_register_stats") even when every projected column is granted.
/// That shipped once as a 500 on every request.
///
/// Public so `tests/register_stats_rls.rs` proves the role against the
/// statement the server actually issues. That test previously ran a
/// hand-copied, shortened projection with no `WHERE`, and so passed while the
/// shipped query was denied on every request.
pub const REGISTER_STATS_SELECT_SQL: &str = "SELECT traces_accepted, contributors, points_issued, \
     withheld, suppressed, as_of, refreshed_at FROM trace_register_stats WHERE singleton = TRUE";

/// The refresh write. Note what is NOT in the `SET` list: `suppressed`.
///
/// That column is the operator's lever, and a refresh that cleared it would
/// make it useless -- an operator suppressing publication during an incident
/// would have it silently undone by the next scheduled run, with no error and
/// no log. `withheld` is the computed/never-computed marker and is cleared
/// here, which is exactly why it cannot double as the lever.
///
/// One constant so `the_refresh_never_clears_the_operator_suppression` can
/// assert that property without a database.
const REGISTER_STATS_REFRESH_SQL: &str = "UPDATE trace_register_stats
                 SET traces_accepted = $1,
                     contributors = $2,
                     points_issued = $3,
                     withheld = FALSE,
                     as_of = NOW(),
                     refreshed_at = NOW()
                 WHERE singleton = TRUE
                 RETURNING traces_accepted, contributors, points_issued, withheld, \
                           suppressed, as_of, refreshed_at";

fn register_stats_row_from(row: &tokio_postgres::Row) -> crate::db::RegisterStatsRow {
    crate::db::RegisterStatsRow {
        traces_accepted: row.get("traces_accepted"),
        contributors: row.get("contributors"),
        points_issued: row.get("points_issued"),
        withheld: row.get("withheld"),
        suppressed: row.get("suppressed"),
        as_of: row.get("as_of"),
        refreshed_at: row.get("refreshed_at"),
    }
}

/// Guard for `PgBackend::compute_register_stats_totals`.
///
/// An empty resolved tenant enumeration is genuinely ambiguous: it is the
/// correct, honest answer on a fresh deployment before any tenant exists,
/// but it is *also* exactly what `SELECT tenant_id FROM trace_tenants`
/// silently returns under a NOBYPASSRLS role with no tenant GUC set, since
/// `trace_tenants` is itself FORCE RLS on `tenant_id = trace_current_tenant_id()`.
/// The query cannot tell those two cases apart from inside itself, so this
/// asks a different question instead: can the connecting role see through
/// RLS at all (`is_superuser`, or `rolbypassrls`)? If it can, an empty
/// result is a true statement about the register and is safe to publish. If
/// it cannot, forced RLS with no GUC set MUST hide every row, so an empty
/// result is uninformative and the refresh must refuse rather than stamp a
/// zero it cannot vouch for.
///
/// This does not wedge anything: on refusal `refreshed_at` stays whatever it
/// already was (unstamped on a fresh table), the endpoint keeps publishing
/// nothing, and the very next run after the first tenant exists succeeds --
/// which is the right posture for a register with no contributors anyway.
///
/// Extracted as a pure function so this exact branch is unit-testable
/// without a database: the live masking scenario it protects against cannot
/// be reproduced against a superuser-connected local test database (the
/// connecting role bypasses RLS entirely, which is itself the `true` branch
/// here), so the only thing CI can verify is that the guard's logic is
/// correct for both roles.
fn refuse_if_enumeration_is_ambiguous(
    tenant_ids: &[String],
    role_sees_through_rls: bool,
) -> Result<(), DatabaseError> {
    if tenant_ids.is_empty() && !role_sees_through_rls {
        Err(DatabaseError::Pool(
            "compute_register_stats_totals enumerated no tenants under a role that \
             cannot see through RLS; refusing to publish a zero it cannot distinguish \
             from RLS hiding every row"
                .to_string(),
        ))
    } else {
        Ok(())
    }
}

async fn trace_tenant_context_is_transaction_local(
    client: &mut deadpool_postgres::Client,
) -> Result<bool, DatabaseError> {
    let tx = client.transaction().await?;
    let probe_tenant = "__trace_rls_probe_tenant__";
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&probe_tenant],
    )
    .await?;
    let inside = tx
        .query_one(
            "SELECT current_setting('trace_commons.trace_tenant_id', true) AS tenant_context",
            &[],
        )
        .await?
        .get::<_, Option<String>>("tenant_context");
    tx.commit().await?;
    let after = client
        .query_one(
            "SELECT current_setting('trace_commons.trace_tenant_id', true) AS tenant_context",
            &[],
        )
        .await?
        .get::<_, Option<String>>("tenant_context");
    Ok(inside.as_deref() == Some(probe_tenant) && after.as_deref().is_none_or(str::is_empty))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onboarding_device_principal_ref_matches_issuer_hash_input() {
        assert_eq!(
            onboarding_device_principal_ref("tenant-1", "sha256:device-key"),
            "principal_sha256:2bf5c8fb2e00d4b044f1e3d24aaf864d21197baaaca9de3da5de631a951caf9d"
        );
    }

    #[test]
    fn onboarding_device_grant_id_is_stable_and_device_scoped() {
        let first = onboarding_device_tenant_access_grant_id("tenant-1", "sha256:device-key");
        let second = onboarding_device_tenant_access_grant_id("tenant-1", "sha256:device-key");
        let other_device = onboarding_device_tenant_access_grant_id("tenant-1", "sha256:other");
        let other_tenant =
            onboarding_device_tenant_access_grant_id("tenant-2", "sha256:device-key");

        assert_eq!(first, second);
        assert_ne!(first, other_device);
        assert_ne!(first, other_tenant);
    }

    #[test]
    fn provision_scopes_normalize_or_fall_back() {
        use serde_json::json;
        let d = ["debugging_evaluation", "public_attribution"];
        assert_eq!(
            normalize_provision_scope_values(
                &json!(["model_training", "debugging_evaluation"]),
                &d
            ),
            vec![
                "model_training".to_string(),
                "debugging_evaluation".to_string()
            ]
        );
        // Empty array, non-array, and mixed-type arrays all fall back.
        assert_eq!(
            normalize_provision_scope_values(&json!([]), &d),
            d.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        assert_eq!(
            normalize_provision_scope_values(&json!("nope"), &d),
            d.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        assert_eq!(
            normalize_provision_scope_values(&json!([1, "x"]), &d),
            d.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn onboarding_scope_override_wins_when_non_empty() {
        let default = vec![
            "debugging_evaluation".to_string(),
            "public_attribution".to_string(),
        ];
        let overridden =
            resolve_onboarding_scope_override(&Some(vec!["model_training".to_string()]), &default);
        assert_eq!(overridden, vec!["model_training".to_string()]);
    }

    #[test]
    fn onboarding_scope_override_falls_back_on_empty_or_absent() {
        let default = vec![
            "debugging_evaluation".to_string(),
            "public_attribution".to_string(),
        ];
        // Imported file invites carry `Some(vec![])`, not `None` -- both
        // must resolve to the default, not to "grant nothing".
        assert_eq!(
            resolve_onboarding_scope_override(&Some(vec![]), &default),
            default
        );
        assert_eq!(resolve_onboarding_scope_override(&None, &default), default);
    }

    #[test]
    fn leaderboard_inputs_credit_device_key_profiles_by_submission_principal() {
        assert!(
            LEADERBOARD_INPUTS_SQL.contains("FROM trace_submissions ts_match"),
            "leaderboard rows must bridge accepted credit events through the source submission"
        );
        assert!(
            LEADERBOARD_INPUTS_SQL.contains("ts_match.auth_principal_ref = cp.principal_ref"),
            "device-key public profiles are keyed by auth principal, not trace pseudonym"
        );
        assert!(
            LEADERBOARD_INPUTS_SQL.contains("ts_match.contributor_pseudonym"),
            "leaderboard rows must also support profiles keyed by trace credit pseudonym"
        );
        assert!(
            LEADERBOARD_INPUTS_SQL.contains("COALESCE(ts.received_at, cl.occurred_at)"),
            "leaderboard recency should prefer trace receive time over ledger backfill time"
        );
        assert!(
            LEADERBOARD_INPUTS_SQL.contains("cl.credit_account_ref = cp.principal_ref"),
            "legacy credit-account joins must remain supported"
        );
    }

    /// V47 persists the pre-cap chunk total and repairs the gate-driver
    /// column-grant drift. A grant-less column is exactly the bug V37 shipped:
    /// `chunk_count`/`chunks_capped` were added without extending the
    /// column-level grants, and the gate-driver role could not read them
    /// (column privileges live in `pg_attribute.attacl`, so the table looks
    /// granted while the column is not).
    #[test]
    fn v47_grants_every_chunk_coverage_column_to_the_gate_driver() {
        const V47: &str =
            include_str!("../../../../migrations/V47__trace_gate_decision_total_chunk_count.sql");
        assert!(
            V47.contains("ADD COLUMN IF NOT EXISTS total_chunk_count INT"),
            "V47 must add the pre-cap chunk total column"
        );
        for column in ["total_chunk_count", "chunk_count", "chunks_capped"] {
            assert!(
                V47.contains(&format!(
                    "GRANT SELECT ({column}) ON trace_gate_decisions TO trace_gate_driver;"
                )),
                "V47 must grant column-level SELECT on {column} to trace_gate_driver"
            );
        }
        assert!(
            !V47.to_uppercase().contains("DISABLE ROW LEVEL SECURITY"),
            "V47 must not weaken forced RLS"
        );
    }

    /// V48 adds the shadow correction-value columns and must grant the two the
    /// cross-tenant correction-cluster scan reads. The gate-driver role holds
    /// COLUMN-level grants (V45), so an ungranted new column is unreadable —
    /// the same drift V47 had to repair for the V37 chunk columns.
    #[test]
    fn v48_adds_correction_columns_and_grants_the_scanned_ones() {
        const V48: &str = include_str!("../../../../migrations/V48__trace_correction_value.sql");
        for column in [
            "correction_simhash",
            "correction_cluster_id",
            "correction_cluster_size",
            "correction_novelty_micros",
            "correction_value_micros",
            "correction_value_version",
        ] {
            assert!(
                V48.contains(&format!("ADD COLUMN IF NOT EXISTS {column} ")),
                "V48 must add {column}"
            );
        }
        for column in ["correction_simhash", "correction_cluster_id"] {
            assert!(
                V48.contains(&format!(
                    "GRANT SELECT ({column}) ON trace_gate_decisions TO trace_gate_driver;"
                )),
                "V48 must grant column-level SELECT on {column} to trace_gate_driver"
            );
        }
        assert!(
            !V48.to_uppercase().contains("DISABLE ROW LEVEL SECURITY"),
            "V48 must not weaken forced RLS"
        );
    }

    /// V49 adds the label-only status-reason column. It must stay
    /// label-only: the point of the column is that a reviewer can tell a
    /// privacy finding from a processing failure, and the point of the
    /// allowlist behind it is that caller-supplied revocation text never
    /// lands in a plainly-readable column. No new reader-role grant either --
    /// widening a column-scoped reader for a column it never reads is exactly
    /// the drift V45 exists to prevent.
    #[test]
    fn v49_adds_a_nullable_label_only_status_reason_column() {
        const V49: &str =
            include_str!("../../../../migrations/V49__trace_submission_last_status_reason.sql");
        assert!(
            V49.contains("ADD COLUMN IF NOT EXISTS last_status_reason TEXT"),
            "V49 must add the status-reason column"
        );
        assert!(
            !V49.to_uppercase().contains("NOT NULL"),
            "V49 must leave pre-existing rows NULL rather than assert a reason for them"
        );
        assert!(
            !V49.to_uppercase().contains("UPDATE TRACE_SUBMISSIONS"),
            "V49 must not backfill a guessed reason onto historical rows"
        );
        assert!(
            !V49.contains("GRANT SELECT (last_status_reason)"),
            "V49 must not widen a column-scoped reader role for a column it does not read"
        );
        assert!(
            !V49.to_uppercase().contains("DISABLE ROW LEVEL SECURITY"),
            "V49 must not weaken forced RLS"
        );
    }

    /// V51 stores classifier output for reuse. The properties that keep it
    /// from becoming a content store, or a cross-tenant one, are pinned here
    /// because they are the whole basis on which the cache was accepted.
    #[test]
    fn v51_cache_is_tenant_scoped_and_stores_no_text() {
        const V51: &str =
            include_str!("../../../../migrations/V51__privacy_classify_window_cache.sql");
        assert!(
            V51.contains("FORCE ROW LEVEL SECURITY"),
            "V51 must force RLS like every other Trace Commons table"
        );
        assert!(
            V51.contains("tenant_id = trace_current_tenant_id()"),
            "V51 must isolate by tenant; a cross-tenant cache needs a promotion rule"
        );
        assert!(
            V51.contains("PRIMARY KEY (tenant_id, filter_version, window_hash)"),
            "filter_version must be in the key, or a model change reads stale spans"
        );
        // The value column holds offsets and labels. A column that could hold
        // trace text -- redacted or otherwise -- would make this a content
        // store rather than a span cache. Check the SCHEMA, not the prose:
        // the comments discuss text precisely because storing it is what the
        // design rules out.
        let schema: String = V51
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        for banned in ["redacted_text", "content", "plaintext", "window_text"] {
            assert!(
                !schema.contains(banned),
                "V51 must not store trace text; found a {banned:?} column"
            );
        }
        assert!(
            schema.contains("spans") && schema.contains("window_hash"),
            "V51 must key on a hash and store spans"
        );
    }

    /// V52 records WHICH residual-risk conditions held when a submission's
    /// privacy risk was decided (#474 proposal 4). Same shape as V49 and for
    /// the same reason: at review time a coverage gap forced High is
    /// indistinguishable from a filter that looked and found a secret, and
    /// those two demand opposite responses.
    ///
    /// Label-only by construction, nullable, backfill-free. Inferring a basis
    /// from `status` would fabricate exactly the data this column exists to
    /// obtain.
    #[test]
    fn v52_adds_a_nullable_label_only_residual_risk_basis_column() {
        const V52: &str =
            include_str!("../../../../migrations/V52__trace_submission_residual_risk_basis.sql");
        assert!(
            V52.contains("ADD COLUMN IF NOT EXISTS residual_risk_basis JSONB"),
            "V52 must add the residual-risk basis column"
        );
        assert!(
            !V52.to_uppercase().contains("NOT NULL"),
            "V52 must leave pre-existing rows NULL rather than assert a basis for them"
        );
        assert!(
            !V52.to_uppercase().contains("UPDATE TRACE_SUBMISSIONS"),
            "V52 must not backfill a guessed basis onto historical rows"
        );
        assert!(
            !V52.contains("GRANT SELECT (residual_risk_basis)"),
            "V52 must not widen a column-scoped reader role for a column it does not read"
        );
        assert!(
            !V52.to_uppercase().contains("DISABLE ROW LEVEL SECURITY"),
            "V52 must not weaken forced RLS"
        );
    }

    /// V53 records the composite score credit keys on, plus the vector-index
    /// state novelty was scored against (#199). Prospective by construction:
    /// recomputing novelty later scores against a fuller index and produces a
    /// number production never used, so historical rows must keep NULL.
    #[test]
    fn v53_adds_nullable_prospective_gate_instrumentation_columns() {
        const V53: &str =
            include_str!("../../../../migrations/V53__trace_gate_decision_composite_score.sql");
        assert!(
            V53.contains("ADD COLUMN IF NOT EXISTS composite_score_micros BIGINT"),
            "V53 must add the composite-score column"
        );
        assert!(
            V53.contains("ADD COLUMN IF NOT EXISTS vector_index_snapshot_id UUID"),
            "V53 must add the vector-index snapshot column"
        );
        assert!(
            V53.contains("ADD COLUMN IF NOT EXISTS index_cardinality_at_scoring BIGINT"),
            "V53 must add the index-cardinality covariate column"
        );
        assert!(
            !V53.to_uppercase().contains("NOT NULL"),
            "V53 must leave pre-existing rows NULL rather than assert a score for them"
        );
        assert!(
            !V53.to_uppercase().contains("UPDATE TRACE_GATE_DECISIONS"),
            "V53 must not backfill: a recomputed novelty is not the number production used"
        );
        assert!(
            !V53.contains("GRANT SELECT (composite_score_micros)"),
            "V53 must not widen a column-scoped reader role for a column it does not read"
        );
        assert!(
            !V53.to_uppercase().contains("DISABLE ROW LEVEL SECURITY"),
            "V53 must not weaken forced RLS"
        );
    }

    /// V54 records the composition statistic for large traces (#478). Shadow
    /// mode, and prospective for a harder reason than V53: per-chunk logprobs
    /// are never persisted, so it cannot be recomputed for a decision already
    /// taken at any price. NULL must stay distinct from 0 -- a trace where no
    /// chunk clears the floor genuinely scores 0, while a pre-V54 row and any
    /// deterministic-service decision have no value at all.
    #[test]
    fn v54_adds_a_nullable_qualifying_mass_column() {
        const V54: &str =
            include_str!("../../../../migrations/V54__trace_gate_decision_qualifying_mass.sql");
        assert!(
            V54.contains("ADD COLUMN IF NOT EXISTS qualifying_token_fraction_micros BIGINT"),
            "V54 must add the qualifying-mass column"
        );
        assert!(
            !V54.contains("NOT NULL") && !V54.contains("DEFAULT"),
            "V54 must stay nullable and backfill-free: a zero default would \
             enrol every historical row into the calibration sample as a real \
             observation of the worst possible score"
        );
    }

    /// V55 gives the public register-stats endpoint (Task 4) a way to read
    /// one aggregate row without a tenant. This test runs WITHOUT
    /// PostgreSQL, so it is the only thing CI can ever check about the
    /// role/policy shape below -- it has to carry real weight rather than
    /// just check the file exists.
    #[test]
    fn v55_creates_a_nobypassrls_role_scoped_to_one_column_grant_and_policy() {
        const V55: &str =
            include_str!("../../../../migrations/V55__register_stats_public_read.sql");
        assert!(
            V55.contains("CREATE ROLE trace_commons_public_read NOLOGIN NOBYPASSRLS"),
            "V55 must create the public-read role as NOLOGIN NOBYPASSRLS -- \
             never a role that can bypass RLS"
        );
        assert!(
            V55.contains(
                "GRANT SELECT (singleton, traces_accepted, contributors, points_issued, withheld, suppressed, as_of, refreshed_at)\n    ON trace_register_stats TO trace_commons_public_read"
            ),
            "V55 must grant the public-read role SELECT on exactly the named \
             columns and nothing else -- `singleton` included, because the \
             public read filters on it and column privileges cover every \
             column a query references"
        );
        assert!(
            V55.contains("CREATE POLICY trace_register_stats_public_read")
                && V55.contains("TO trace_commons_public_read")
                && V55.contains("FOR SELECT"),
            "V55 must scope the read policy to the public-read role, not PUBLIC"
        );
        // SQL comment lines stripped first, so this checks actual statements
        // rather than tripping on the prose ("... NOT `BYPASSRLS` ...") that
        // explains why. Every remaining NOBYPASSRLS occurrence is then
        // stripped too, so what's left can only be a stray BYPASSRLS grant.
        let sql_only_v55 = V55
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !sql_only_v55
                .to_uppercase()
                .replace("NOBYPASSRLS", "")
                .contains("BYPASSRLS"),
            "V55 must never grant BYPASSRLS to any role"
        );
        assert!(
            V55.contains("FORCE ROW LEVEL SECURITY"),
            "V55 must force RLS on trace_register_stats"
        );
        assert!(
            !V55.to_uppercase().contains("DISABLE ROW LEVEL SECURITY"),
            "V55 must not weaken forced RLS"
        );
        // FORCE ROW LEVEL SECURITY binds the table owner too, so the refresh
        // worker (running as the ordinary runtime role, not
        // trace_commons_public_read) needs its own read/write policies or it
        // could never touch the row -- not even once. Both are scoped by
        // predicate (no `TO` clause) rather than by role, so they add no
        // privilege to trace_commons_public_read: that role's reach stays
        // bounded by the column-scoped GRANT above, not by these policies.
        assert!(
            V55.contains("CREATE POLICY trace_register_stats_runtime_write")
                && V55.contains("FOR UPDATE"),
            "V55 must let the runtime role write the row it refreshes"
        );
        assert!(
            V55.contains("CREATE POLICY trace_register_stats_runtime_read"),
            "V55 must let the runtime role read the row it just wrote"
        );
        // Whitespace-normalized rather than matching the file's exact
        // indentation/newlines: an exact-whitespace match here would go
        // silently vacuous (always pass) the moment someone reflows this
        // SQL without changing its meaning, which defeats the point of a
        // negative assertion.
        let normalized_v55 = V55.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            !normalized_v55.contains(
                "trace_register_stats_runtime_write ON trace_register_stats FOR UPDATE TO "
            ) && !normalized_v55.contains(
                "trace_register_stats_runtime_read ON trace_register_stats FOR SELECT TO "
            ),
            "V55's runtime policies must stay unscoped by role (no `TO`), \
             not widened to name trace_commons_public_read"
        );
        assert!(
            !V55.contains("FOR INSERT"),
            "V55 must not let the runtime role INSERT: the singleton row is \
             seeded once by the migration itself; a refresh that finds the \
             row missing must fail loudly, not conjure a fresh one in a \
             state nobody computed"
        );
        // Roles are cluster-wide: a bare CREATE ROLE aborts the whole
        // batch_execute on a cluster where the role already exists (a
        // second database, a recreated one), and since run_migrations
        // records the version only after the batch succeeds, V55 would
        // never record itself and would retry -- and fail -- on every boot.
        assert!(
            V55.contains(
                "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trace_commons_public_read')"
            ) && V55.contains("DO $$"),
            "V55 must guard CREATE ROLE with an existence check, like V30 \
             and V42 do for their roles"
        );
        // Without this, nothing grants membership in the role, and Task 4's
        // SET ROLE trace_commons_public_read fails in production with
        // "permission denied to set role".
        assert!(
            V55.contains("GRANT trace_commons_public_read TO CURRENT_USER"),
            "V55 must grant whoever applies the migration membership in the \
             role, or nothing can ever assume it"
        );
    }

    /// V57 names the derivation behind `dedup_simhash` (#211, #325). The
    /// column has to be nullable and backfill-free for the reason V53 and V54
    /// are, and for one of its own: a DEFAULT would assert in the schema the
    /// reading that code makes explicitly (NULL means the legacy v1 stamp),
    /// and a later re-derivation pass could no longer tell a defaulted row
    /// from a stamped one.
    #[test]
    fn v57_adds_a_nullable_dedup_signal_version_column() {
        const V57: &str = include_str!(
            "../../../../migrations/V57__trace_gate_decision_dedup_signal_version.sql"
        );
        // Comment lines stripped first (the idiom V55's test uses), because
        // this file's header explains at length why there is NO DEFAULT and
        // no backfill -- prose that would trip every negative assertion
        // below and make them vacuous to "fix".
        let sql_only = V57
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            sql_only.contains("ADD COLUMN IF NOT EXISTS dedup_signal_version TEXT"),
            "V57 must add the dedup-signal-version column as TEXT: it carries \
             a composed \"<render>+<simhash>\" name plus a third value that is \
             neither, which an integer version cannot express"
        );
        assert!(
            !sql_only.to_uppercase().contains("NOT NULL")
                && !sql_only.to_uppercase().contains("DEFAULT"),
            "V57 must stay nullable and default-free: NULL is what says \
             \"recorded before the stamp existed\", and code maps it to the \
             legacy v1 stamp"
        );
        assert!(
            !sql_only
                .to_uppercase()
                .contains("UPDATE TRACE_GATE_DECISIONS"),
            "V57 must not backfill: the re-derivation pass rewrites these \
             rows from retained inputs, and a migration cannot render text"
        );
        // Unlike V53/V54, this column IS read on the gate-driver pool.
        assert!(
            sql_only.contains(
                "GRANT SELECT (dedup_signal_version) ON trace_gate_decisions TO trace_gate_driver"
            ),
            "V57 must grant the new column to trace_gate_driver: \
             `list_dedup_signals` runs on that pool and now selects it, and \
             column privileges cover every column a query references"
        );
        assert!(
            !sql_only
                .to_uppercase()
                .contains("DISABLE ROW LEVEL SECURITY"),
            "V57 must not weaken forced RLS"
        );
    }

    /// Same `MIGRATIONS`-table trap as V47, V53 and V54: wiring, pinned.
    /// Counted rather than merely present, because a literal in the
    /// assertion's own source would satisfy the assertion by itself and pass
    /// with the migration wired into nothing.
    #[test]
    fn v57_is_wired_into_run_migrations() {
        const THIS_FILE: &str = include_str!("postgres.rs");
        let file_marker = format!(
            "migrations/V{}__trace_gate_decision_dedup_signal_version.sql",
            57
        );
        assert_eq!(
            THIS_FILE.matches(&file_marker).count(),
            2,
            "V57 must be named exactly twice: once by the MIGRATIONS table's include_str! \
             and once by the migration-content test above"
        );
        assert!(
            super::MIGRATIONS
                .iter()
                .any(|(version, name, _)| *version == 57
                    && *name == "trace_gate_decision_dedup_signal_version"),
            "V57 must record itself in _trace_commons_migrations under its own file stem"
        );
    }

    #[test]
    fn every_column_the_public_read_references_is_granted() {
        // PostgreSQL column privileges cover every column a query REFERENCES,
        // not just the ones it projects -- a WHERE, an ORDER BY, a function
        // argument all count. A column in the statement but not in V55's
        // GRANT denies the WHOLE TABLE under trace_commons_public_read, with
        // an error that names no column. That shipped once as a 500 on every
        // request, from a `WHERE singleton = TRUE` against a grant that
        // omitted `singleton`.
        //
        // This compares the statement against the grant PARSED OUT of V55
        // rather than a restated list, so the two cannot drift: add a column
        // to the query without granting it and this fails, on a machine with
        // no PostgreSQL.
        const V55: &str =
            include_str!("../../../../migrations/V55__register_stats_public_read.sql");
        let granted = V55
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .split("GRANT SELECT (")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .expect("V55 carries a column-scoped GRANT SELECT")
            .split(',')
            .map(|column| column.trim().to_string())
            .collect::<Vec<_>>();

        // The table's columns, PARSED OUT of V55's CREATE TABLE rather than
        // restated. A hardcoded list here would be a third hand-maintained
        // copy of the schema: add an eighth column to the table, the query
        // and the grant but not to the list, and this test would silently
        // have no opinion about it while claiming to cover every column.
        let table_columns = V55
            .split("CREATE TABLE trace_register_stats (")
            .nth(1)
            .and_then(|rest| rest.split("\n);").next())
            .expect("V55 creates trace_register_stats")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("--"))
            .filter_map(|line| line.split_whitespace().next())
            .map(|name| name.trim_end_matches(',').to_string())
            .collect::<Vec<_>>();

        // Anti-vacuity: a parser that silently returned nothing would make
        // every loop below run zero times and pass. Tie it to the grant,
        // which is parsed independently -- every granted column must be a
        // real column of the table, which also catches a typo in the grant.
        assert!(
            !table_columns.is_empty(),
            "failed to parse any column out of V55's CREATE TABLE"
        );
        assert!(
            !granted.is_empty(),
            "failed to parse V55's GRANT SELECT list"
        );
        for column in &granted {
            assert!(
                table_columns.contains(column),
                "V55 grants {column}, which is not a column of \
                 trace_register_stats -- check the grant for a typo"
            );
        }

        for column in &table_columns {
            if REGISTER_STATS_SELECT_SQL.contains(column.as_str()) {
                assert!(
                    granted.contains(column),
                    "the public read references {column}, so V55 must grant \
                     it -- an ungranted reference denies the whole table"
                );
            }
        }

        // And the filter specifically, since dropping it is the tempting
        // wrong fix: `query_one` demands exactly one row, which a bare
        // SELECT delivers only while the CHECK constraint holds.
        assert!(
            REGISTER_STATS_SELECT_SQL.contains("WHERE singleton = TRUE"),
            "the public read must keep its singleton filter: it is what \
             keeps the read correct if the CHECK is ever relaxed"
        );
    }

    #[test]
    fn the_refresh_never_clears_the_operator_suppression() {
        // `suppressed` is the operator's lever and the refresh must not touch
        // it: a cron-driven refresh that cleared it would silently undo an
        // incident-time suppression, with no error and no log. Split at
        // RETURNING first, because `suppressed` legitimately appears there.
        let set_clause = REGISTER_STATS_REFRESH_SQL
            .split("RETURNING")
            .next()
            .expect("the refresh has a SET clause before RETURNING");
        assert!(
            !set_clause.contains("suppressed"),
            "the refresh must never write `suppressed` -- it is the \
             operator's lever, not a computed field"
        );
        // And it must still clear the computed marker, which is what makes
        // the two columns different things rather than duplicates.
        assert!(
            set_clause.contains("withheld = FALSE"),
            "the refresh must clear `withheld`, the computed marker"
        );
        // The read must actually carry the lever, or the endpoint cannot
        // honour it however faithfully the refresh leaves it alone.
        assert!(
            REGISTER_STATS_SELECT_SQL.contains("suppressed"),
            "the public read must select `suppressed`"
        );
    }

    #[test]
    fn the_operator_verification_recipe_runs_the_real_statement() {
        // The recipe in that runbook is what an operator actually types to
        // prove the role works. It carried a shortened projection while the
        // shipped query was denied on every request, so it would have said
        // "verified" about a statement the server never issues.
        const RUNBOOK: &str = include_str!("../../../../docs/operator/register-stats-role.md");
        let normalized = RUNBOOK.split_whitespace().collect::<Vec<_>>().join(" ");
        let statement = REGISTER_STATS_SELECT_SQL
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        // Terminated with `;`, so a runbook carrying a LONGER statement does
        // not satisfy this by containing the shorter one as a prefix. That
        // asymmetry is how a recipe that quietly drops a trailing clause --
        // exactly the defect this guards -- would otherwise still pass.
        assert!(
            normalized.contains(&format!("{statement};")),
            "docs/operator/register-stats-role.md must contain the exact \
             statement the public read issues, terminated, not a shortened \
             or extended one"
        );
    }

    #[test]
    fn refuses_an_empty_enumeration_under_a_role_that_cannot_see_through_rls() {
        // The masking case: forced RLS with no GUC set MUST hide every row,
        // so an empty result under a role that cannot see through RLS is
        // uninformative -- indistinguishable from "RLS ate it".
        assert!(refuse_if_enumeration_is_ambiguous(&[], false).is_err());
    }

    #[test]
    fn accepts_an_empty_enumeration_under_a_role_that_sees_through_rls() {
        // The fresh-deployment case: a role that can see through RLS
        // (superuser or BYPASSRLS) genuinely saw every trace_tenants row,
        // so an empty result means the register really has no tenants yet
        // -- a true, publishable zero.
        assert!(refuse_if_enumeration_is_ambiguous(&[], true).is_ok());
    }

    #[test]
    fn a_nonempty_enumeration_never_refuses_regardless_of_role() {
        let tenants = ["some-tenant".to_string()];
        assert!(refuse_if_enumeration_is_ambiguous(&tenants, false).is_ok());
        assert!(refuse_if_enumeration_is_ambiguous(&tenants, true).is_ok());
    }

    /// The minimum number of times a migration's path may appear in THIS
    /// file: once for `run_migrations`' own `include_str!`, plus one for each
    /// test that READS the migration rather than restating it.
    ///
    /// Only migrations with a reader beyond `run_migrations` need a row; the
    /// wiring check itself enumerates `migrations/` and needs no table.
    /// Asserted as a lower bound, so a new legitimate reader does not fail an
    /// unrelated row -- but deleting a content test still does.
    const MIGRATION_READER_MINIMUMS: &[(u32, usize)] = &[
        (47, 2),
        (48, 2),
        (49, 2),
        (51, 2),
        (52, 2),
        (53, 2),
        (54, 2),
        (55, 3),
        (56, 4),
    ];

    /// Every `.sql` file in `migrations/`, as `(version, file_stem)`, read at
    /// test time rather than listed.
    ///
    /// `migrations/` is the source of truth for what migrations exist, so
    /// enumerating it is what lets the wiring check below fail for a migration
    /// nobody remembered to mention -- the failure mode a hand-maintained
    /// table reproduces rather than closes. `CARGO_MANIFEST_DIR` is
    /// `crates/trace-commons-server`; the migrations live at the repo root.
    fn migrations_on_disk() -> Vec<(u32, String)> {
        const MIGRATIONS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");

        let entries = std::fs::read_dir(MIGRATIONS_DIR)
            .unwrap_or_else(|err| panic!("cannot read {MIGRATIONS_DIR}: {err}"));

        let mut migrations: Vec<(u32, String)> = Vec::new();
        for entry in entries {
            let name = entry.expect("directory entry").file_name();
            let name = name.to_str().expect("migration filenames are UTF-8");
            let Some(rest) = name.strip_prefix('V') else {
                panic!("{name}: migrations must be named V<version>__<stem>.sql");
            };
            let Some((version, stem)) = rest.split_once("__") else {
                panic!("{name}: migrations must be named V<version>__<stem>.sql");
            };
            let Some(stem) = stem.strip_suffix(".sql") else {
                panic!("{name}: migrations must be named V<version>__<stem>.sql");
            };
            let version: u32 = version
                .parse()
                .unwrap_or_else(|_| panic!("{name}: version is not a number"));
            migrations.push((version, stem.to_string()));
        }

        // An empty or wrong directory would make every check below pass
        // vacuously, so refuse a read that plainly did not find the tree.
        assert!(
            migrations.len() >= 56,
            "found only {} migrations in {MIGRATIONS_DIR}: the enumeration read the wrong \
                 directory, and an empty one passes every check below",
            migrations.len()
        );

        migrations.sort();
        migrations
    }

    /// `run_migrations` is driven by the `MIGRATIONS` table: a migration that
    /// is not listed there never runs, and a row that pairs one version with
    /// another migration's SQL runs the wrong file or records the wrong name.
    /// Driven from `migrations/` the way
    /// `trace_commons_rls_registry_matches_migration_policy_coverage` below is
    /// driven from its policy set, so a failing row names the migration.
    ///
    /// Three properties, in the order they catch things:
    ///
    /// 1. The table's `(version, name)` pairs equal `migrations/` exactly, in
    ///    order. The set under test is read from the directory, not listed
    ///    here, so a migration added and never wired in fails without anyone
    ///    having to remember this test exists -- which is how V50 came to have
    ///    no coverage while nine hand-written per-version tests were green. A
    ///    phantom row, or a row recording a name that is not its own file
    ///    stem, fails the same assertion.
    /// 2. Versions strictly increase, so no version is listed twice and the
    ///    apply order matches the numbering. Contiguity is deliberately not
    ///    asserted: the per-version wiring this table replaced never required
    ///    it, and each row gates on its own version rather than on sequence
    ///    position.
    /// 3. Each row's `include_str!` path names that row's own version and
    ///    stem. This one is checked against this file's source text, because
    ///    nothing at runtime can see which file a row embedded: a row carrying
    ///    V57's version and V56's SQL is invisible to the two checks above.
    ///
    /// The recorded name is checked against the filename rather than restated:
    /// all 57 wired migrations record their own file stem, and a second copy
    /// of it here would only be a new way for this test to lie.
    ///
    /// What it still does not prove: that the SQL inside a migration file does
    /// what its name says.
    /// `apply_and_record_migration` runs each migration file inside an explicit
    /// transaction so the `_trace_commons_migrations` row commits with the DDL.
    /// That is only legal for SQL PostgreSQL will accept inside a transaction
    /// block, and the statements it refuses there are exactly the ones below.
    /// None of them appears in `migrations/` today; this test is what keeps it
    /// that way, because the alternative discovery route is a migration that
    /// fails on a production boot with `cannot run inside a transaction block`.
    ///
    /// A migration that genuinely needs one -- a `CREATE INDEX CONCURRENTLY` on
    /// a table too large to lock, most likely -- is not forbidden. It has to
    /// opt out of the wrapper explicitly, with its reason in code, and record
    /// itself on the same connection right after. Downgrading every migration
    /// to the old unwrapped path to accommodate one is what this test exists to
    /// make someone argue for rather than do quietly.
    ///
    /// Every `--` in `migrations/` today starts a line comment, so dropping
    /// comment lines is exact; the assertion below pins that. A trailing
    /// comment introduced later would survive the strip and could only produce
    /// a false positive here, never a false negative.
    #[test]
    fn no_migration_uses_a_statement_postgres_refuses_inside_a_transaction() {
        // Multi-word where a single word would collide with prose: `alter type`
        // and `vacuum` are plausible in a comment, and a comment that mentions
        // them is not a bug.
        const REFUSED_INSIDE_A_TRANSACTION: &[&str] = &[
            "index concurrently",
            "partition concurrently",
            "reindex",
            "vacuum",
            "alter type",
            "alter system",
            "create database",
            "drop database",
            "create tablespace",
            "drop tablespace",
            "create subscription",
            "drop subscription",
            "alter subscription",
            "discard",
        ];

        assert!(
            super::MIGRATIONS.len() >= 60,
            "the MIGRATIONS table came back with {} rows: an empty or truncated \
             table passes every check below vacuously",
            super::MIGRATIONS.len()
        );

        let mut offenders: Vec<String> = Vec::new();
        for (version, name, sql) in super::MIGRATIONS {
            for line in sql.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("--") {
                    continue;
                }
                assert!(
                    !trimmed.contains("--"),
                    "V{version} ({name}): a `--` appears outside a leading comment, so the \
                     comment strip this test relies on is no longer exact -- widen the strip \
                     deliberately rather than letting it drift"
                );
                let normalized = trimmed.to_ascii_lowercase();
                let normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
                for refused in REFUSED_INSIDE_A_TRANSACTION {
                    if normalized.contains(refused) {
                        offenders.push(format!("V{version} ({name}): {refused}"));
                    }
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "these migrations use statements PostgreSQL refuses inside a transaction \
             block, which apply_and_record_migration opens around every migration:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The apply and the record must commit together. Read against the source
    /// rather than a live database because the loop's non-atomic form was
    /// invisible to every test in the suite: both statements succeed, and only
    /// a crash between them shows the difference. `migration_atomicity_pg`
    /// proves the rollback against real PostgreSQL where one is configured;
    /// this pins the shape everywhere else, including CI, which runs no
    /// PostgreSQL at all.
    #[test]
    fn applying_a_migration_and_recording_it_share_one_transaction() {
        const THIS_FILE: &str = include_str!("postgres.rs");

        let start = THIS_FILE
            .find("pub async fn apply_and_record_migration(")
            .expect("apply_and_record_migration must exist in this file");
        let body = &THIS_FILE[start..];
        let end = body
            .find("\n}\n")
            .expect("apply_and_record_migration must be closed by a `}` at column zero");
        let body = &body[..end];

        assert!(
            body.contains("client.transaction().await?"),
            "apply_and_record_migration must open a transaction: without one the \
             INSERT into _trace_commons_migrations is a separate statement, and a \
             crash between it and the DDL leaves a migration applied but unrecorded"
        );
        assert!(
            body.contains("tx.batch_execute(sql)"),
            "the migration SQL must run on the transaction, not on the connection \
             beside it"
        );
        assert!(
            body.contains("INSERT INTO _trace_commons_migrations") && body.contains("tx.execute("),
            "the _trace_commons_migrations insert must run on the same transaction \
             as the migration SQL"
        );
        assert!(
            body.contains("tx.commit().await?"),
            "the transaction must be committed, and its failure must propagate: an \
             uncommitted transaction rolls back the migration it just applied"
        );

        let start = THIS_FILE
            .find("    async fn run_migrations(&self)")
            .expect("run_migrations must exist in this file");
        let body = &THIS_FILE[start..];
        let end = body
            .find("\n    }\n")
            .expect("run_migrations must be closed by a `}` at its own indent");
        let body = &body[..end];
        assert!(
            body.contains("apply_and_record_migration(&mut client, *version, name, sql)"),
            "run_migrations must apply each migration through \
             apply_and_record_migration, not inline the apply and the record as two \
             statements again"
        );
        assert!(
            body.contains("SELECT pg_advisory_lock($1)")
                && body.contains("SELECT pg_advisory_unlock($1)"),
            "run_migrations must hold an advisory lock across the whole run and \
             release it again: without one, two callers both read a migration as \
             unapplied and both run its DDL, and the loser dies on a system-catalog \
             unique index. Requires a real database to observe, so this is the only \
             check that runs everywhere"
        );
    }

    #[test]
    fn every_migration_is_wired_into_run_migrations() {
        const THIS_FILE: &str = include_str!("postgres.rs");

        let on_disk = migrations_on_disk();

        let wired: Vec<(u32, String)> = super::MIGRATIONS
            .iter()
            .map(|(version, name, _)| {
                (
                    u32::try_from(*version).expect("migration versions are positive"),
                    (*name).to_string(),
                )
            })
            .collect();

        assert_eq!(
            wired, on_disk,
            "the MIGRATIONS table and migrations/ disagree: every migration on disk must be \
                 wired in exactly once, under its own version and file stem, in version order"
        );

        for pair in wired.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "MIGRATIONS versions must strictly increase, so that no version is applied \
                     twice and the apply order matches the numbering: V{} is followed by V{}",
                pair[0].0,
                pair[1].0
            );
        }

        // Which file a row embedded is not observable at runtime, so the
        // include_str! paths are read from this file's own source text.
        let table_start = THIS_FILE
            .find("const MIGRATIONS: &[(i32, &str, &str)] = &[")
            .expect("the MIGRATIONS table must exist in this file");
        let table_end = table_start
            + THIS_FILE[table_start..]
                .find("\n];")
                .expect("the MIGRATIONS table must be closed by a `];` at column zero");
        let table = &THIS_FILE[table_start..table_end];

        // The strip below cuts each line at its first `//` and cannot see a
        // block comment, so a row wrapped in one would read as wired.
        assert!(
            !table.contains("/*"),
            "the MIGRATIONS table gained a block comment; the line-comment strip no longer \
                 covers it"
        );

        // Comments dropped, then whitespace, then the trailing comma rustfmt
        // adds inside a wrapped tuple, so a row matches whether or not rustfmt
        // kept it on one line.
        let squashed: String = table
            .lines()
            .map(|line| match line.find("//") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .replace(",)", ")");

        let mut failures: Vec<String> = Vec::new();

        for (version, file_stem) in &on_disk {
            let file_marker = format!("migrations/V{version}__{file_stem}.sql");

            let row =
                format!("({version},\"{file_stem}\",include_str!(\"../../../../{file_marker}\")),");
            let hits = squashed.matches(&row).count();
            if hits != 1 {
                failures.push(format!(
                    "V{version}: appears {hits} times in the MIGRATIONS table carrying its own \
                         version, file stem and file, expected exactly once -- a row that pairs \
                         one version with another migration's SQL runs the wrong file"
                ));
            }

            let readers = MIGRATION_READER_MINIMUMS
                .iter()
                .find(|(wanted, _)| wanted == version)
                .map(|(_, readers)| *readers)
                .unwrap_or(1);
            let references = THIS_FILE.matches(&file_marker).count();
            if references < readers {
                failures.push(format!(
                    "V{version}: named {references} times in this file, expected at least \
                         {readers} -- the MIGRATIONS table's include_str! plus each test that \
                         reads the migration. A missing one means such a test was deleted or now \
                         restates the migration instead of reading it"
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "{} migration(s) are not correctly wired into run_migrations:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }

    #[test]
    fn trace_commons_rls_registry_matches_migration_policy_coverage() {
        let central_policy_migrations = [
            include_str!("../../../../migrations/V18__trace_central_rls_tenant_predicate.sql"),
            include_str!("../../../../migrations/V21__trace_near_credit_account_outbox.sql"),
            include_str!("../../../../migrations/V26__trace_contributor_profiles.sql"),
            include_str!("../../../../migrations/V28__device_keys.sql"),
            include_str!("../../../../migrations/V29__onboarding_invites.sql"),
            include_str!("../../../../migrations/V30__trace_accounts.sql"),
            include_str!("../../../../migrations/V32__webauthn_credentials.sql"),
            include_str!("../../../../migrations/V33__near_identities.sql"),
            include_str!("../../../../migrations/V34__account_consolidation.sql"),
            include_str!("../../../../migrations/V43__trace_withdrawal.sql"),
            include_str!("../../../../migrations/V56__community_withdrawal_eviction_rls.sql"),
            include_str!("../../../../migrations/V58__near_account_provisioning.sql"),
            include_str!("../../../../migrations/V64__token_distribution_bundles.sql"),
        ];
        let force_rls_migrations = [
            include_str!("../../../../migrations/V6__trace_force_rls.sql"),
            include_str!("../../../../migrations/V11__trace_ranking_worker_runs.sql"),
            include_str!("../../../../migrations/V14__trace_ranking_preference_labels.sql"),
            include_str!("../../../../migrations/V15__trace_benchmark_registry_outbox.sql"),
            include_str!("../../../../migrations/V16__trace_ranking_calibration_datasets.sql"),
            include_str!("../../../../migrations/V21__trace_near_credit_account_outbox.sql"),
            include_str!("../../../../migrations/V26__trace_contributor_profiles.sql"),
            include_str!("../../../../migrations/V28__device_keys.sql"),
            include_str!("../../../../migrations/V29__onboarding_invites.sql"),
            include_str!("../../../../migrations/V30__trace_accounts.sql"),
            include_str!("../../../../migrations/V32__webauthn_credentials.sql"),
            include_str!("../../../../migrations/V33__near_identities.sql"),
            include_str!("../../../../migrations/V34__account_consolidation.sql"),
            include_str!("../../../../migrations/V43__trace_withdrawal.sql"),
            include_str!("../../../../migrations/V56__community_withdrawal_eviction_rls.sql"),
            include_str!("../../../../migrations/V58__near_account_provisioning.sql"),
            include_str!("../../../../migrations/V64__token_distribution_bundles.sql"),
        ];

        for table in TRACE_COMMONS_RLS_TABLES {
            assert!(
                central_policy_migrations.iter().any(|migration| {
                    migration.contains(&format!(
                        "DROP POLICY IF EXISTS trace_corpus_tenant_isolation ON {table};"
                    ))
                }),
                "{table} is missing from the central RLS policy migration cleanup"
            );
            assert!(
                central_policy_migrations.iter().any(|migration| {
                    migration.contains(&format!(
                        "CREATE POLICY trace_corpus_tenant_isolation ON {table}"
                    ))
                }),
                "{table} is missing from the central RLS policy migration install"
            );
            assert!(
                force_rls_migrations.iter().any(|migration| {
                    migration.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"))
                }),
                "{table} is missing FORCE ROW LEVEL SECURITY migration coverage"
            );
        }

        let central_policy_count = TRACE_COMMONS_RLS_TABLES
            .iter()
            .filter(|table| {
                central_policy_migrations.iter().any(|migration| {
                    migration.contains(&format!(
                        "CREATE POLICY trace_corpus_tenant_isolation ON {table}"
                    ))
                })
            })
            .count();
        assert_eq!(
            central_policy_count,
            TRACE_COMMONS_RLS_TABLES.len(),
            "central RLS policy migration and diagnostics registry drifted"
        );
    }

    /// The eviction drain is the one write path on
    /// `trace_community_withdrawal_evictions` that carries no tenant id. V55
    /// gates it on a transaction-local GUC; without that `set_config` the
    /// statement does not fail, it silently marks zero rows. Guard the line
    /// here, since a database is not available in CI to catch its removal.
    #[test]
    fn community_snapshot_drain_enters_drain_scope() {
        let source = include_str!("postgres.rs");
        let drain = source
            .split("async fn drain_community_snapshot_invalidation")
            .nth(1)
            .expect("drain_community_snapshot_invalidation must exist");
        let body = drain
            .split("async fn ")
            .next()
            .expect("drain body must be delimited by the next fn");
        let guc_marker = concat!(
            "set_config('trace_commons.",
            "community_drain', 'on', true)"
        );
        let update_marker = "UPDATE trace_community_withdrawal_evictions";
        let guc_at = body
            .find(guc_marker)
            .expect("the drain must enter transaction-local drain scope");
        let update_at = body
            .find(update_marker)
            .expect("the drain must mark eviction receipts");
        assert!(
            guc_at < update_at,
            "drain scope must be entered before the cross-tenant eviction UPDATE"
        );
    }

    #[test]
    fn trace_corpus_pg_client_access_enters_tenant_context_transactions() {
        let source = include_str!("trace_corpus_pg.rs");
        let client_marker = concat!("self.", "trace_pool().get().await?");
        let tenant_context_marker = "Self::begin_trace_tenant_transaction";
        let mut checked_client_accesses = 0;

        for (line_number, line) in source.lines().enumerate() {
            if !line.contains(client_marker) {
                continue;
            }
            checked_client_accesses += 1;

            let tenant_context_window = source
                .lines()
                .skip(line_number + 1)
                .take(8)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                tenant_context_window.contains(tenant_context_marker),
                "trace_corpus_pg.rs:{} gets a PostgreSQL client without immediately entering \
                 transaction-local trace tenant context",
                line_number + 1
            );
        }

        assert!(
            checked_client_accesses >= TRACE_COMMONS_RLS_TABLES.len(),
            "trace corpus tenant-context guard did not inspect the expected store surface"
        );
    }

    #[test]
    fn pg_backend_does_not_expose_raw_pool_as_application_api() {
        let source = include_str!("postgres.rs");
        let public_raw_pool_marker = concat!("pub fn ", "pool(&self) -> Pool");
        assert!(
            !source.contains(public_raw_pool_marker),
            "PgBackend must not expose its raw pool as a normal public API; use the \
             tenant-context helpers for application paths and an explicit test hook for \
             raw RLS probes"
        );
    }
}
