// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;

use chrono::{DateTime, SubsecRound, Utc};
use secrecy::{ExposeSecret, SecretString};
use tokio::time::{Duration, sleep};
use tokio_postgres::NoTls;
use trace_commons_server::config::{DatabaseConfig, SslMode};
use trace_commons_server::db::{
    Database, TraceCorpusRlsDiagnostics,
    postgres::{PgBackend, TRACE_COMMONS_RLS_TABLES},
};
use trace_commons_server::trace_corpus_storage::{
    GateWorkItem, TenantScopedTraceObjectRef, TraceAuditAction, TraceAuditEventWrite,
    TraceAuditSafeMetadata, TraceBenchmarkRegistryOutboxItemWrite,
    TraceBenchmarkRegistryOutboxOperation, TraceBenchmarkRegistryOutboxStatus, TraceCorpusStatus,
    TraceCorpusStore, TraceCreditAccountSettlementLineItem, TraceCreditEventType,
    TraceCreditEventWrite, TraceCreditHoldReason, TraceCreditHoldWrite,
    TraceCreditSettlementBatchStatus, TraceCreditSettlementBatchWrite,
    TraceCreditSettlementNearStatus, TraceCreditSettlementState, TraceDerivedRecordWrite,
    TraceDerivedStatus, TraceExportAccessGrantStatus, TraceExportAccessGrantWrite,
    TraceExportJobStatus, TraceExportJobStatusUpdate, TraceExportJobWrite,
    TraceExportManifestItemInvalidationReason, TraceExportManifestItemWrite,
    TraceExportManifestWrite, TraceGateDecisionRow, TraceNearCreditOutboxItemWrite,
    TraceObjectArtifactKind, TraceObjectRefWrite, TraceRankingCalibrationDatasetStatus,
    TraceRankingCalibrationDatasetWrite, TraceRankingCalibrationRunWrite, TraceRankingFeatureWrite,
    TraceRankingLabelOutcome, TraceRankingLabelSource, TraceRankingLabelWrite,
    TraceRankingModelStatus, TraceRankingModelVersionWrite, TraceRankingPredictionWrite,
    TraceRankingPreferenceLabelWrite, TraceRankingUtilityCategory, TraceRankingWorkerRunKind,
    TraceRankingWorkerRunStatus, TraceRankingWorkerRunWrite, TraceRetentionJobItemAction,
    TraceRetentionJobItemStatus, TraceRetentionJobItemWrite, TraceRetentionJobStatus,
    TraceRetentionJobWrite, TraceReviewLeaseAuditAction, TraceRevocationPropagationAction,
    TraceRevocationPropagationItemStatus, TraceRevocationPropagationItemStatusUpdate,
    TraceRevocationPropagationItemWrite, TraceRevocationPropagationTarget, TraceSubmissionWrite,
    TraceTenantAccessGrantRole, TraceTenantAccessGrantStatus, TraceTenantAccessGrantWrite,
    TraceTenantPolicyWrite, TraceTombstoneWrite, TraceUtilityAttestationWrite,
    TraceVectorEntrySourceProjection, TraceVectorEntryStatus, TraceVectorEntryWrite,
    TraceWorkerKind,
};
use uuid::Uuid;

fn postgres_test_config() -> Option<DatabaseConfig> {
    let url = std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;

    Some(DatabaseConfig {
        url: SecretString::from(url),
        pool_size: 4,
        ssl_mode: SslMode::Prefer,
        login_resolver_url:
            trace_commons_server::config::DatabaseConfig::login_resolver_url_from_env(),
        gate_driver_url: trace_commons_server::config::DatabaseConfig::gate_driver_url_from_env(),
        pii_backstop_driver_url:
            trace_commons_server::config::DatabaseConfig::pii_backstop_driver_url_from_env(),
        invite_registry_url: None,
    })
}

/// Like `postgres_test_config`, but with `gate_driver_url` pointed at the SAME
/// test database URL (rather than the separate
/// `TRACE_COMMONS_GATE_DRIVER_DATABASE_URL`, which CI does not provision).
/// This exercises the real second-pool wiring and the enumeration SQL
/// end-to-end; the test DB role's actual RLS treatment for `trace_gate_driver`
/// is covered separately by
/// `gate_driver_role_reads_across_tenants_while_default_role_stays_isolated`
/// via an explicit `SET ROLE`.
fn gate_driver_test_config() -> Option<DatabaseConfig> {
    let url = std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;

    Some(DatabaseConfig {
        url: SecretString::from(url.clone()),
        pool_size: 4,
        ssl_mode: SslMode::Prefer,
        login_resolver_url: None,
        gate_driver_url: Some(SecretString::from(url)),
        pii_backstop_driver_url: None,
        invite_registry_url: None,
    })
}

async fn gate_driver_backend() -> Option<PgBackend> {
    let Some(config) = gate_driver_test_config() else {
        eprintln!("skipping: TRACE_COMMONS_PG_TEST_DATABASE_URL or DATABASE_URL not configured");
        return None;
    };

    match PgBackend::new(&config).await {
        Ok(backend) => Some(backend),
        Err(e) => {
            eprintln!("skipping: database unavailable ({e})");
            None
        }
    }
}

async fn postgres_backend() -> Option<PgBackend> {
    let Some(config) = postgres_test_config() else {
        eprintln!("skipping: TRACE_COMMONS_PG_TEST_DATABASE_URL or DATABASE_URL not configured");
        return None;
    };

    match PgBackend::new(&config).await {
        Ok(backend) => Some(backend),
        Err(e) => {
            eprintln!("skipping: database unavailable ({e})");
            None
        }
    }
}

async fn single_connection_postgres_backend() -> Option<PgBackend> {
    let Some(mut config) = postgres_test_config() else {
        eprintln!("skipping: TRACE_COMMONS_PG_TEST_DATABASE_URL or DATABASE_URL not configured");
        return None;
    };
    config.pool_size = 1;

    match PgBackend::new(&config).await {
        Ok(backend) => Some(backend),
        Err(e) => {
            eprintln!("skipping: database unavailable ({e})");
            None
        }
    }
}

fn sample_submission(tenant_id: &str, submission_id: Uuid) -> TraceSubmissionWrite {
    let mut redaction_counts = BTreeMap::new();
    redaction_counts.insert("secret".to_string(), 1);

    TraceSubmissionWrite {
        tenant_id: tenant_id.to_string(),
        submission_id,
        trace_id: Uuid::new_v4(),
        auth_principal_ref: format!("principal:{tenant_id}"),
        contributor_pseudonym: Some(format!("contributor:{tenant_id}")),
        submitted_tenant_scope_ref: Some(tenant_id.to_string()),
        schema_version: "ironclaw.trace_contribution.v1".to_string(),
        consent_policy_version: "2026-04-24".to_string(),
        consent_scopes: vec!["debugging_evaluation".to_string()],
        allowed_uses: vec!["debugging".to_string()],
        retention_policy_id: "private_corpus_revocable".to_string(),
        status: TraceCorpusStatus::Accepted,
        privacy_risk: "low".to_string(),
        redaction_pipeline_version: "deterministic-v1".to_string(),
        redaction_counts,
        redaction_hash: format!("sha256:redaction:{tenant_id}"),
        canonical_summary_hash: Some(format!("sha256:summary:{tenant_id}")),
        submission_score: Some(0.5),
        credit_points_pending: Some(1.0),
        credit_points_final: None,
        expires_at: None,
        residual_risk_basis: None,
    }
}

fn ready_rls_diagnostics() -> TraceCorpusRlsDiagnostics {
    TraceCorpusRlsDiagnostics {
        expected_table_count: 2,
        rls_enabled_count: 2,
        force_rls_enabled_count: 2,
        policy_installed_count: 2,
        missing_policy_tables: Vec::new(),
        rls_disabled_tables: Vec::new(),
        force_rls_disabled_tables: Vec::new(),
        policy_expression_mismatch_tables: Vec::new(),
        current_role_hash:
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        current_role_bypasses_rls: false,
        current_role_owns_trace_tables: false,
        tenant_context_transaction_local: true,
    }
}

fn expected_trace_rls_tables() -> Vec<&'static str> {
    TRACE_COMMONS_RLS_TABLES.to_vec()
}

fn sample_audit_event(
    tenant_id: &str,
    submission_id: Uuid,
    previous_event_hash: &str,
    event_hash: &str,
) -> TraceAuditEventWrite {
    TraceAuditEventWrite {
        tenant_id: tenant_id.to_string(),
        audit_event_id: Uuid::new_v4(),
        submission_id: Some(submission_id),
        actor_principal_ref: format!("principal:{tenant_id}"),
        actor_role: "contributor".to_string(),
        action: TraceAuditAction::Submit,
        reason: None,
        request_id: Some(format!("request:{event_hash}")),
        object_ref_id: None,
        export_manifest_id: None,
        decision_inputs_hash: None,
        previous_event_hash: Some(previous_event_hash.to_string()),
        event_hash: Some(event_hash.to_string()),
        canonical_event_json: Some(format!("{{\"event_hash\":\"{event_hash}\"}}")),
        metadata: TraceAuditSafeMetadata::Submission {
            status: TraceCorpusStatus::Accepted,
            privacy_risk: "low".to_string(),
        },
    }
}

fn sample_unhashed_audit_event(tenant_id: &str, submission_id: Uuid) -> TraceAuditEventWrite {
    TraceAuditEventWrite {
        tenant_id: tenant_id.to_string(),
        audit_event_id: Uuid::new_v4(),
        submission_id: Some(submission_id),
        actor_principal_ref: format!("principal:{tenant_id}"),
        actor_role: "system".to_string(),
        action: TraceAuditAction::Review,
        reason: Some("db_native_review_projection".to_string()),
        request_id: None,
        object_ref_id: None,
        export_manifest_id: None,
        decision_inputs_hash: None,
        previous_event_hash: None,
        event_hash: None,
        canonical_event_json: None,
        metadata: TraceAuditSafeMetadata::ReviewDecision {
            decision: "accepted".to_string(),
            resulting_status: TraceCorpusStatus::Accepted,
            reason_code: Some("db_native_review_projection".to_string()),
        },
    }
}

fn sample_raw_rls_audit_event(
    tenant_id: &str,
    submission_id: Uuid,
    audit_event_id: Uuid,
    label: &str,
) -> TraceAuditEventWrite {
    TraceAuditEventWrite {
        tenant_id: tenant_id.to_string(),
        audit_event_id,
        submission_id: Some(submission_id),
        actor_principal_ref: format!("principal:{tenant_id}:raw-rls"),
        actor_role: "rls_tester".to_string(),
        action: TraceAuditAction::Read,
        reason: Some(format!("raw RLS audit probe {label}")),
        request_id: Some(format!("request:{label}:audit")),
        object_ref_id: None,
        export_manifest_id: None,
        decision_inputs_hash: None,
        previous_event_hash: None,
        event_hash: None,
        canonical_event_json: None,
        metadata: TraceAuditSafeMetadata::Read {
            surface: "raw_rls_probe".to_string(),
            item_count: 1,
        },
    }
}

fn sample_credit_event(
    tenant_id: &str,
    submission_id: Uuid,
    trace_id: Uuid,
    credit_event_id: Uuid,
) -> TraceCreditEventWrite {
    TraceCreditEventWrite {
        tenant_id: tenant_id.to_string(),
        credit_event_id,
        submission_id,
        trace_id,
        credit_account_ref: format!("credit-account:{tenant_id}"),
        event_type: TraceCreditEventType::Accepted,
        points_delta: "1.0".to_string(),
        reason: format!("accepted submission for {tenant_id}"),
        external_ref: Some(format!("external:{tenant_id}:{credit_event_id}")),
        actor_principal_ref: format!("principal:{tenant_id}"),
        actor_role: "system".to_string(),
        settlement_state: TraceCreditSettlementState::Pending,
    }
}

#[derive(Clone, Copy)]
struct RawCreditControlPlaneIds {
    utility_attestation_id: Uuid,
    settlement_batch_id: Uuid,
    credit_hold_id: Uuid,
    near_outbox_id: Uuid,
    near_account_outbox_id: Uuid,
}

const RAW_RLS_RANKING_MODEL_VERSION: &str = "trace-ranker-raw-rls-v1";
const RAW_RLS_RANKING_FEATURE_SCHEMA_VERSION: &str = "ranking-features-raw-rls-v1";
const RAW_RLS_RANKING_POLICY_VERSION: &str = "trace-credit-policy-raw-rls-v1";
const RAW_RLS_RANKING_TARGET_USE: &str = "ranking_model_training";
const RAW_RLS_RANKING_CALIBRATION_DATASET_HASH: &str = "sha256:raw-rls-calibration-dataset";

/// `trace_ranking_model_versions` and `trace_ranking_calibration_datasets` are
/// keyed by a version string and a hash, not by a UUID, so the fixture wrote
/// the SAME value under both tenants and `raw_trace_rls_counts` counted it with
/// a literal rather than a per-tenant parameter. Every other count in that
/// query is scoped to one tenant's row by id.
///
/// The effect was that "how many of tenant B's rows can tenant A see" returned
/// tenant A's OWN row and read as a cross-tenant leak. Nobody saw it: the
/// assertion has never run, because the connecting role always bypassed RLS
/// (#752). The policies on both tables are correct; the fixture was not.
fn raw_rls_ranking_model_version(tenant_id: &str) -> String {
    format!("{RAW_RLS_RANKING_MODEL_VERSION}:{tenant_id}")
}

fn raw_rls_ranking_calibration_dataset_hash(tenant_id: &str) -> String {
    format!("{RAW_RLS_RANKING_CALIBRATION_DATASET_HASH}:{tenant_id}")
}

#[derive(Clone, Copy)]
struct RawRankingControlPlaneIds {
    secondary_submission_id: Uuid,
    secondary_trace_id: Uuid,
    ranking_feature_id: Uuid,
    ranking_prediction_id: Uuid,
    ranking_label_id: Uuid,
    preference_label_id: Uuid,
    calibration_run_id: Uuid,
    ranking_worker_run_id: Uuid,
    benchmark_outbox_id: Uuid,
    benchmark_conversion_id: Uuid,
}

#[derive(Clone, Copy)]
struct RawTraceRlsIds {
    submission_id: Uuid,
    object_ref_id: Uuid,
    derived_id: Uuid,
    vector_entry_id: Uuid,
    export_manifest_id: Uuid,
    export_access_grant_id: Uuid,
    export_job_id: Uuid,
    audit_event_id: Uuid,
    credit_event_id: Uuid,
    utility_attestation_id: Uuid,
    settlement_batch_id: Uuid,
    credit_hold_id: Uuid,
    near_outbox_id: Uuid,
    near_account_outbox_id: Uuid,
    ranking_feature_id: Uuid,
    ranking_prediction_id: Uuid,
    ranking_label_id: Uuid,
    preference_label_id: Uuid,
    calibration_run_id: Uuid,
    ranking_worker_run_id: Uuid,
    benchmark_outbox_id: Uuid,
    tombstone_id: Uuid,
    retention_job_id: Uuid,
    propagation_item_id: Uuid,
}

#[derive(Debug, PartialEq, Eq)]
struct RawTraceRlsCounts {
    submissions: i64,
    object_refs: i64,
    derived_records: i64,
    vector_entries: i64,
    export_manifests: i64,
    export_manifest_items: i64,
    export_access_grants: i64,
    export_jobs: i64,
    audit_events: i64,
    credit_events: i64,
    utility_attestations: i64,
    credit_settlement_batches: i64,
    credit_holds: i64,
    near_credit_outbox: i64,
    near_credit_account_outbox: i64,
    ranking_model_versions: i64,
    ranking_calibration_datasets: i64,
    ranking_features: i64,
    ranking_predictions: i64,
    ranking_labels: i64,
    ranking_preference_labels: i64,
    ranking_calibration_runs: i64,
    ranking_worker_runs: i64,
    benchmark_registry_outbox: i64,
    tombstones: i64,
    retention_jobs: i64,
    retention_job_items: i64,
    revocation_propagation_items: i64,
}

impl RawTraceRlsCounts {
    fn all(count: i64) -> Self {
        Self {
            submissions: count,
            object_refs: count,
            derived_records: count,
            vector_entries: count,
            export_manifests: count,
            export_manifest_items: count,
            export_access_grants: count,
            export_jobs: count,
            audit_events: count,
            credit_events: count,
            utility_attestations: count,
            credit_settlement_batches: count,
            credit_holds: count,
            near_credit_outbox: count,
            near_credit_account_outbox: count,
            ranking_model_versions: count,
            ranking_calibration_datasets: count,
            ranking_features: count,
            ranking_predictions: count,
            ranking_labels: count,
            ranking_preference_labels: count,
            ranking_calibration_runs: count,
            ranking_worker_runs: count,
            benchmark_registry_outbox: count,
            tombstones: count,
            retention_jobs: count,
            retention_job_items: count,
            revocation_propagation_items: count,
        }
    }
}

fn sample_revocation_propagation_item(
    tenant_id: &str,
    submission_id: Uuid,
    propagation_item_id: Uuid,
    target: TraceRevocationPropagationTarget,
    idempotency_suffix: &str,
) -> TraceRevocationPropagationItemWrite {
    TraceRevocationPropagationItemWrite {
        tenant_id: tenant_id.to_string(),
        propagation_item_id,
        source_submission_id: submission_id,
        target,
        action: TraceRevocationPropagationAction::InvalidateMetadata,
        status: TraceRevocationPropagationItemStatus::Pending,
        idempotency_key: format!("{submission_id}:{idempotency_suffix}"),
        reason: "tenant_revoked_trace".to_string(),
        attempt_count: 0,
        last_error: None,
        next_attempt_at: None,
        completed_at: None,
        evidence_hash: None,
        metadata: BTreeMap::new(),
    }
}

async fn write_sample_credit_control_plane_rows(
    backend: &PgBackend,
    tenant_id: &str,
    submission_id: Uuid,
    credit_event_id: Uuid,
    ids: RawCreditControlPlaneIds,
    label: &str,
) {
    let credit_account_ref = format!("credit-account:{tenant_id}");
    let credit_account_hash = format!("sha256:{tenant_id}:credit-account");
    let source_list_hash = format!("sha256:{tenant_id}:settlement-sources");
    backend
        .upsert_trace_utility_attestation(TraceUtilityAttestationWrite {
            tenant_id: tenant_id.to_string(),
            attestation_id: ids.utility_attestation_id,
            event_type: TraceCreditEventType::TrainingUtility,
            use_category: "model_training".to_string(),
            policy_version: "trace-credit-policy-rls".to_string(),
            evidence_hash: format!("sha256:{tenant_id}:utility-evidence"),
            external_ref_hash: format!("sha256:{tenant_id}:utility-ref"),
            source_submission_ids: vec![submission_id],
            actor_principal_ref: format!("principal:{tenant_id}:utility-worker"),
        })
        .await
        .expect("write tenant utility attestation");
    backend
        .upsert_trace_credit_hold(TraceCreditHoldWrite {
            tenant_id: tenant_id.to_string(),
            hold_id: ids.credit_hold_id,
            credit_account_ref: credit_account_ref.clone(),
            credit_account_hash: credit_account_hash.clone(),
            reason: TraceCreditHoldReason::AttestationDispute,
            reason_hash: format!("sha256:{tenant_id}:hold-reason"),
            actor_principal_ref: format!("principal:{tenant_id}:admin"),
            released_at: None,
        })
        .await
        .expect("write tenant credit hold");
    backend
        .upsert_trace_credit_settlement_batch(TraceCreditSettlementBatchWrite {
            tenant_id: tenant_id.to_string(),
            settlement_batch_id: ids.settlement_batch_id,
            policy_version: "trace-credit-policy-rls".to_string(),
            status: TraceCreditSettlementBatchStatus::Finalized,
            reason_hash: format!("sha256:{tenant_id}:settlement-reason"),
            issuer_approval_evidence_hash: Some(format!("sha256:{tenant_id}:issuer-approval")),
            source_credit_event_ids: vec![credit_event_id],
            source_submission_ids: vec![submission_id],
            source_list_hash: source_list_hash.clone(),
            settled_credit_points: "1.000000".to_string(),
            settled_credit_micros: 1_000_000,
            line_items: vec![TraceCreditAccountSettlementLineItem {
                credit_account_ref: credit_account_ref.clone(),
                credit_account_hash: credit_account_hash.clone(),
                settled_credit_delta_micros: 1_000_000,
                source_credit_event_ids: vec![credit_event_id],
                source_submission_ids: vec![submission_id],
                source_list_hash: source_list_hash.clone(),
                near_status: TraceCreditSettlementNearStatus::Pending,
                near_outbox_id: Some(ids.near_outbox_id),
                near_payout_hold_reason: None,
            }],
            near_contract_id: Some("trace-credits.testnet".to_string()),
            ranking_model_version: None,
            ranking_target_use: None,
            ranking_calibration_run_id: None,
            ranking_calibration_report_hash: None,
            ranking_calibration_joined_evidence_hash: None,
            ranking_credit_events_excluded_count: 0,
            ranking_credit_events_excluded_reason_counts: BTreeMap::new(),
            actor_principal_ref: format!("principal:{tenant_id}:admin"),
        })
        .await
        .expect("write tenant settlement batch");
    backend
        .upsert_trace_near_credit_outbox_item(TraceNearCreditOutboxItemWrite {
            tenant_id: tenant_id.to_string(),
            near_outbox_id: ids.near_outbox_id,
            settlement_batch_id: ids.settlement_batch_id,
            credit_account_hash: credit_account_hash.clone(),
            near_call_json: serde_json::json!({
                "contract_id": "trace-credits.testnet",
                "method_name": "settle_credit_receipt",
                "args": {
                    "settlement_batch_id": ids.settlement_batch_id,
                    "credit_account_hash": credit_account_hash
                },
                "idempotency_key": format!("sha256:{label}:settle")
            }),
            status: TraceCreditSettlementNearStatus::Pending,
            payout_near_account_id: None,
        })
        .await
        .expect("write tenant NEAR receipt outbox");
    backend
        .upsert_trace_near_credit_outbox_item(TraceNearCreditOutboxItemWrite {
            tenant_id: tenant_id.to_string(),
            near_outbox_id: ids.near_account_outbox_id,
            settlement_batch_id: ids.credit_hold_id,
            credit_account_hash: format!("sha256:{tenant_id}:credit-account"),
            near_call_json: serde_json::json!({
                "contract_id": "trace-credits.testnet",
                "method_name": "freeze_credit_account",
                "args": {
                    "credit_account_hash": format!("sha256:{tenant_id}:credit-account"),
                    "reason_hash": format!("sha256:{tenant_id}:hold-reason")
                },
                "idempotency_key": format!("sha256:{label}:freeze")
            }),
            status: TraceCreditSettlementNearStatus::Pending,
            payout_near_account_id: None,
        })
        .await
        .expect("write tenant NEAR account outbox");
}

async fn write_sample_ranking_and_benchmark_control_plane_rows(
    backend: &PgBackend,
    tenant_id: &str,
    submission_id: Uuid,
    trace_id: Uuid,
    ids: RawRankingControlPlaneIds,
    label: &str,
) {
    let mut secondary_submission = sample_submission(tenant_id, ids.secondary_submission_id);
    secondary_submission.trace_id = ids.secondary_trace_id;
    secondary_submission.allowed_uses = vec![RAW_RLS_RANKING_TARGET_USE.to_string()];
    backend
        .upsert_trace_submission(secondary_submission)
        .await
        .expect("write tenant secondary ranking source submission");
    backend
        .upsert_trace_ranking_model_version(TraceRankingModelVersionWrite {
            tenant_id: tenant_id.to_string(),
            model_version: raw_rls_ranking_model_version(tenant_id),
            feature_schema_version: RAW_RLS_RANKING_FEATURE_SCHEMA_VERSION.to_string(),
            policy_version: RAW_RLS_RANKING_POLICY_VERSION.to_string(),
            status: TraceRankingModelStatus::Candidate,
            training_dataset_hash: format!("sha256:{tenant_id}:raw-rls-training"),
            calibration_dataset_hash: raw_rls_ranking_calibration_dataset_hash(tenant_id),
            model_artifact_hash: format!("sha256:{tenant_id}:raw-rls-model"),
            actor_principal_ref: format!("principal:{tenant_id}:ranker-admin"),
        })
        .await
        .expect("write tenant ranking model version");
    backend
        .upsert_trace_ranking_calibration_dataset(TraceRankingCalibrationDatasetWrite {
            tenant_id: tenant_id.to_string(),
            calibration_dataset_hash: raw_rls_ranking_calibration_dataset_hash(tenant_id),
            target_use: RAW_RLS_RANKING_TARGET_USE.to_string(),
            policy_version: RAW_RLS_RANKING_POLICY_VERSION.to_string(),
            source_manifest_hash: format!("sha256:{tenant_id}:raw-rls-calibration-manifest"),
            source_count: 32,
            label_source_count: 2,
            label_actor_count: 2,
            status: TraceRankingCalibrationDatasetStatus::Candidate,
            actor_principal_ref: format!("principal:{tenant_id}:ranker-admin"),
        })
        .await
        .expect("write tenant ranking calibration dataset");
    backend
        .upsert_trace_ranking_feature(TraceRankingFeatureWrite {
            tenant_id: tenant_id.to_string(),
            ranking_feature_id: ids.ranking_feature_id,
            submission_id,
            trace_id,
            target_use: RAW_RLS_RANKING_TARGET_USE.to_string(),
            feature_schema_version: RAW_RLS_RANKING_FEATURE_SCHEMA_VERSION.to_string(),
            feature_vector_hash: format!("sha256:{tenant_id}:raw-rls-feature-vector"),
            feature_names_hash: format!("sha256:{tenant_id}:raw-rls-feature-names"),
            source_feature_hash: format!("sha256:{tenant_id}:raw-rls-source-feature"),
            duplicate_score: Some(0.01),
            novelty_score: Some(0.9),
            privacy_risk_score: Some(0.02),
            quality_score: Some(0.95),
            coverage_tags: vec![format!("tenant:{label}")],
            actor_principal_ref: format!("principal:{tenant_id}:ranker-worker"),
        })
        .await
        .expect("write tenant ranking feature");
    backend
        .upsert_trace_ranking_prediction(TraceRankingPredictionWrite {
            tenant_id: tenant_id.to_string(),
            ranking_prediction_id: ids.ranking_prediction_id,
            submission_id,
            trace_id,
            target_use: RAW_RLS_RANKING_TARGET_USE.to_string(),
            model_version: raw_rls_ranking_model_version(tenant_id),
            feature_schema_version: RAW_RLS_RANKING_FEATURE_SCHEMA_VERSION.to_string(),
            prediction_policy_version: RAW_RLS_RANKING_POLICY_VERSION.to_string(),
            feature_vector_hash: format!("sha256:{tenant_id}:raw-rls-feature-vector"),
            predicted_utility_micros: 1_250_000,
            uncertainty_micros: 125_000,
            confidence: 0.87,
            risk_penalty_micros: 10_000,
            novelty_bonus_micros: 50_000,
            settlement_score_micros: 1_290_000,
            explanation_codes: vec![format!("raw_rls_prediction_{label}")],
            actor_principal_ref: format!("principal:{tenant_id}:ranker-worker"),
        })
        .await
        .expect("write tenant ranking prediction");
    backend
        .upsert_trace_ranking_label(TraceRankingLabelWrite {
            tenant_id: tenant_id.to_string(),
            ranking_label_id: ids.ranking_label_id,
            submission_id,
            trace_id,
            target_use: RAW_RLS_RANKING_TARGET_USE.to_string(),
            label_source: TraceRankingLabelSource::FrontierLab,
            utility_category: TraceRankingUtilityCategory::RankingTraining,
            label_outcome: TraceRankingLabelOutcome::Useful,
            utility_delta_micros: 1_400_000,
            evidence_hash: format!("sha256:{tenant_id}:raw-rls-label-evidence"),
            external_ref_hash: format!("sha256:{tenant_id}:raw-rls-label-ref"),
            actor_principal_ref: format!("principal:{tenant_id}:frontier-lab"),
        })
        .await
        .expect("write tenant ranking label");
    backend
        .upsert_trace_ranking_preference_label(TraceRankingPreferenceLabelWrite {
            tenant_id: tenant_id.to_string(),
            preference_label_id: ids.preference_label_id,
            preferred_submission_id: submission_id,
            preferred_trace_id: trace_id,
            rejected_submission_id: ids.secondary_submission_id,
            rejected_trace_id: ids.secondary_trace_id,
            target_use: RAW_RLS_RANKING_TARGET_USE.to_string(),
            label_source: TraceRankingLabelSource::Reviewer,
            utility_category: TraceRankingUtilityCategory::RankingTraining,
            preference_strength_micros: 700_000,
            evidence_hash: format!("sha256:{tenant_id}:raw-rls-preference-evidence"),
            external_ref_hash: format!("sha256:{tenant_id}:raw-rls-preference-ref"),
            actor_principal_ref: format!("principal:{tenant_id}:reviewer"),
        })
        .await
        .expect("write tenant ranking preference label");
    backend
        .upsert_trace_ranking_calibration_run(TraceRankingCalibrationRunWrite {
            tenant_id: tenant_id.to_string(),
            calibration_run_id: ids.calibration_run_id,
            model_version: raw_rls_ranking_model_version(tenant_id),
            target_use: RAW_RLS_RANKING_TARGET_USE.to_string(),
            policy_version: RAW_RLS_RANKING_POLICY_VERSION.to_string(),
            evaluation_dataset_hash: raw_rls_ranking_calibration_dataset_hash(tenant_id),
            prediction_count: 1,
            label_count: 1,
            joined_label_prediction_count: 1,
            joined_label_source_count: 1,
            joined_label_actor_count: 1,
            joined_evidence_hash: format!("sha256:{tenant_id}:raw-rls-joined-evidence"),
            average_predicted_utility_micros: Some(1_250_000),
            average_label_utility_delta_micros: Some(1_400_000),
            average_absolute_error_micros: Some(150_000),
            max_label_source_average_absolute_error_micros: Some(150_000),
            max_error_label_source: Some("frontier_lab".to_string()),
            mean_signed_error_micros: Some(-150_000),
            low_confidence_prediction_count: 0,
            confidence_threshold: 0.5,
            min_label_count: 1,
            min_label_source_count: 1,
            max_average_absolute_error_micros: 500_000,
            promotable: true,
            reason_codes: Vec::new(),
            report_hash: format!("sha256:{tenant_id}:raw-rls-calibration-report"),
            actor_principal_ref: format!("principal:{tenant_id}:ranker-worker"),
        })
        .await
        .expect("write tenant ranking calibration run");
    backend
        .upsert_trace_ranking_worker_run(TraceRankingWorkerRunWrite {
            tenant_id: tenant_id.to_string(),
            ranking_worker_run_id: ids.ranking_worker_run_id,
            run_kind: TraceRankingWorkerRunKind::Calibration,
            status: TraceRankingWorkerRunStatus::Completed,
            dry_run: false,
            reason_hash: format!("sha256:{tenant_id}:raw-rls-worker-reason"),
            model_version: Some(raw_rls_ranking_model_version(tenant_id)),
            target_use: Some(RAW_RLS_RANKING_TARGET_USE.to_string()),
            policy_version: Some(RAW_RLS_RANKING_POLICY_VERSION.to_string()),
            limit: 10,
            checked_count: 1,
            succeeded_count: 1,
            skipped_existing_count: 0,
            skipped_model_risk_count: 0,
            skipped_ineligible_count: 0,
            pending_after_count: 0,
            result_refs: vec![format!(
                "ranking_calibration_run:{}",
                ids.calibration_run_id
            )],
            reason_counts: BTreeMap::new(),
            actor_principal_ref: format!("principal:{tenant_id}:ranker-worker"),
            created_at: Utc::now(),
            completed_at: Some(Utc::now()),
            last_error_hash: None,
        })
        .await
        .expect("write tenant ranking worker run");
    backend
        .upsert_trace_benchmark_registry_outbox_item(TraceBenchmarkRegistryOutboxItemWrite {
            tenant_id: tenant_id.to_string(),
            benchmark_outbox_id: ids.benchmark_outbox_id,
            conversion_id: ids.benchmark_conversion_id,
            operation: TraceBenchmarkRegistryOutboxOperation::Publish,
            registry_ref: format!("benchmark-registry:{tenant_id}:raw-rls"),
            artifact_payload_hash: format!("sha256:{tenant_id}:raw-rls-benchmark-artifact"),
            source_submission_ids_hash: format!("sha256:{tenant_id}:raw-rls-benchmark-sources"),
            evaluator_ref: Some(format!("benchmark-evaluator:{label}")),
            evaluation_score: Some(0.99),
            status: TraceBenchmarkRegistryOutboxStatus::Pending,
        })
        .await
        .expect("write tenant benchmark registry outbox item");
}

async fn current_role_bypasses_trace_rls(
    client: &mut tokio_postgres::Client,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT
                EXISTS (
                    SELECT 1
                    FROM pg_class c
                    JOIN pg_roles r ON r.oid = c.relowner
                    WHERE c.relname = 'trace_submissions'
                      AND r.rolname = current_user
                      AND NOT c.relforcerowsecurity
                ) AS owns_unforced_trace_table,
                COALESCE((
                    SELECT rolsuper OR rolbypassrls
                    FROM pg_roles
                    WHERE rolname = current_user
                ), false) AS bypass_role",
            &[],
        )
        .await?;
    Ok(row.get::<_, bool>("owns_unforced_trace_table") || row.get::<_, bool>("bypass_role"))
}

/// Login role the raw-SQL assertions in this suite connect as.
///
/// Those assertions read a trace table directly and judge RLS by what comes
/// back, so they mean nothing under a role that bypasses RLS: a superuser, a
/// BYPASSRLS role, or the owner of a table whose policies are not FORCEd sees
/// every row whatever the policy says. Each of them used to detect that and
/// return early. The `postgres-suites` job connects as the container
/// superuser, so on every CI run they all did -- and the suite still reported
/// `32 passed; 0 failed`. That is #752, and the count was seven, not one:
/// locally, as a superuser, seven assertions announced a skip and the suite
/// went green.
///
/// So there is no longer anything to detect. This role is provisioned after
/// the migrations have run and therefore owns nothing; it is NOSUPERUSER
/// NOBYPASSRLS and holds exactly the DML these assertions perform and no DDL.
/// Failing to reach it is a failure, not a skip.
///
/// NOINHERIT is load-bearing, not tidiness. `V36` grants `trace_gate_driver`
/// permissive `USING (true)` SELECT policies on `trace_submissions` and three
/// other tables, and PostgreSQL applies a policy to any role holding the
/// privileges of the role the policy names. This role is granted membership of
/// `trace_gate_driver` so that
/// `gate_driver_role_reads_across_tenants_while_default_role_stays_isolated`
/// can `SET ROLE` to it; an inheriting membership would hand every other
/// assertion in this file that cross-tenant read without asking for it.
const RAW_RLS_ASSERTION_ROLE: &str = "trace_rls_assertion_runtime";

/// Advisory-lock key serialising every test-role GRANT in this suite.
///
/// `GRANT ... ON ALL TABLES IN SCHEMA public` rewrites the `relacl` of every
/// table in the schema, and libtest runs these tests in parallel against one
/// database. Two of those in flight -- or one of them against the single-table
/// grant in `community_withdrawal_eviction_client` -- update the same
/// `pg_class` tuples, and PostgreSQL raises `XX000 tuple concurrently
/// updated`. It surfaces as an RLS test failing on whatever PR happened to be
/// running: observed on run 34381118381 against #825, a copy-only change.
///
/// The contended tuple belongs to the TABLE, not to the role. Giving each test
/// its own role does not help -- reproduced outside this suite, two concurrent
/// `GRANT ... ON ALL TABLES` to two DIFFERENT roles raise it just as two to
/// the same role do. Serialising the DDL is what removes it, following the
/// migration runner's advisory-lock precedent.
///
/// Two-int form with its own classid, so it cannot alias the one-arg
/// `pg_advisory_xact_lock(hashtext(tenant))` the audit-chain append takes.
/// Taken with `_xact_`, inside the implicit transaction that wraps a
/// multi-statement `batch_execute`, so it is released when that batch commits
/// and no path can leak it. The `SET ROLE` that shares one of those batches is
/// session-scoped, not transaction-scoped, so it deliberately outlives that
/// commit -- the assertions run under that role after the batch returns. Two
/// different scopes in one statement list is intentional; do not "fix" it by
/// making them agree.
const RLS_TEST_ROLE_DDL_LOCK_CLASSID: i32 = 0x726f_6c65u32 as i32; // "role"
const RLS_TEST_ROLE_DDL_LOCK_OBJID: i32 = 0x7273_6c73u32 as i32; // "rsls"

/// Connect for a raw-SQL RLS assertion as a role that cannot bypass RLS.
///
/// Panics rather than skipping, at every step. `purpose` names the assertion
/// so a failure says which one could not be made.
async fn connect_for_raw_rls_assertion(
    database_url: &str,
    purpose: &str,
) -> tokio_postgres::Client {
    let (admin_client, admin_connection) = tokio_postgres::connect(database_url, NoTls)
        .await
        .unwrap_or_else(|e| {
            panic!("{purpose}: connect to provision {RAW_RLS_ASSERTION_ROLE} ({e})")
        });
    tokio::spawn(async move {
        let _ = admin_connection.await;
    });

    admin_client
        .batch_execute(&format!(
            "SELECT pg_advisory_xact_lock({RLS_TEST_ROLE_DDL_LOCK_CLASSID}, \
                {RLS_TEST_ROLE_DDL_LOCK_OBJID});
             DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RAW_RLS_ASSERTION_ROLE}')
                THEN CREATE ROLE {RAW_RLS_ASSERTION_ROLE}
                     LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trace_gate_driver')
                THEN GRANT trace_gate_driver TO {RAW_RLS_ASSERTION_ROLE};
                END IF;
             END $$;
             GRANT USAGE ON SCHEMA public TO {RAW_RLS_ASSERTION_ROLE};
             GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
                TO {RAW_RLS_ASSERTION_ROLE};
             GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
                TO {RAW_RLS_ASSERTION_ROLE};"
        ))
        .await
        .unwrap_or_else(|e| panic!("{purpose}: provision {RAW_RLS_ASSERTION_ROLE} ({e})"));

    let mut assertion_url = reqwest::Url::parse(database_url)
        .unwrap_or_else(|e| panic!("{purpose}: parse the test database URL ({e})"));
    assertion_url
        .set_username(RAW_RLS_ASSERTION_ROLE)
        .unwrap_or_else(|()| panic!("{purpose}: rewrite the username in the test database URL"));

    let (mut client, connection) = tokio_postgres::connect(assertion_url.as_str(), NoTls)
        .await
        .unwrap_or_else(|e| panic!("{purpose}: connect as {RAW_RLS_ASSERTION_ROLE} ({e})"));
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let bypasses = current_role_bypasses_trace_rls(&mut client)
        .await
        .unwrap_or_else(|e| panic!("{purpose}: inspect the connecting role ({e})"));
    assert!(
        !bypasses,
        "{purpose}: connected as a role that bypasses RLS, which sees every row whatever \
         the policy says. This assertion reads raw SQL and would pass against no policy \
         at all, so it fails here rather than returning early. See #752."
    );

    client
}

async fn assert_raw_sql_rls_filters_by_tenant_context(
    database_url: &str,
    tenant_a: &str,
    tenant_b: &str,
    submission_id: Uuid,
) {
    let mut client = connect_for_raw_rls_assertion(database_url, "raw RLS assertion").await;

    let tx = client
        .transaction()
        .await
        .expect("start raw RLS assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_a],
    )
    .await
    .expect("set tenant context");
    let tenant_a_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_submissions WHERE submission_id = $1",
            &[&submission_id],
        )
        .await
        .expect("count tenant A visible submissions")
        .get(0);
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_b],
    )
    .await
    .expect("switch tenant context");
    let tenant_b_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_submissions WHERE submission_id = $1",
            &[&submission_id],
        )
        .await
        .expect("count tenant B visible submissions")
        .get(0);
    tx.commit().await.expect("commit raw RLS assertion");

    assert_eq!(tenant_a_count, 1);
    assert_eq!(tenant_b_count, 1);
}

async fn assert_raw_sql_tenants_visible_only_with_matching_tenant_context(
    database_url: &str,
    tenant_a: &str,
    tenant_b: &str,
) {
    let mut client = connect_for_raw_rls_assertion(database_url, "raw tenant RLS assertion").await;

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant no-context assertion transaction");
    let no_context_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenants WHERE tenant_id = $1 OR tenant_id = $2",
            &[&tenant_a, &tenant_b],
        )
        .await
        .expect("count tenants without context")
        .get(0);
    assert_eq!(
        no_context_count, 0,
        "tenant rows must be invisible without tenant context"
    );
    tx.commit()
        .await
        .expect("commit raw tenant no-context assertion");

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant A assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_a],
    )
    .await
    .expect("set tenant A context");
    let tenant_a_visible_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenants WHERE tenant_id = $1 OR tenant_id = $2",
            &[&tenant_a, &tenant_b],
        )
        .await
        .expect("count tenants for tenant A")
        .get(0);
    let tenant_b_from_a_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenants WHERE tenant_id = $1",
            &[&tenant_b],
        )
        .await
        .expect("count tenant B from tenant A context")
        .get(0);
    assert_eq!(tenant_a_visible_count, 1);
    assert_eq!(tenant_b_from_a_count, 0);
    tx.commit().await.expect("commit raw tenant A assertion");

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant B assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_b],
    )
    .await
    .expect("set tenant B context");
    let tenant_b_visible_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenants WHERE tenant_id = $1 OR tenant_id = $2",
            &[&tenant_a, &tenant_b],
        )
        .await
        .expect("count tenants for tenant B")
        .get(0);
    let tenant_a_from_b_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenants WHERE tenant_id = $1",
            &[&tenant_a],
        )
        .await
        .expect("count tenant A from tenant B context")
        .get(0);
    assert_eq!(tenant_b_visible_count, 1);
    assert_eq!(tenant_a_from_b_count, 0);
    tx.commit().await.expect("commit raw tenant B assertion");
}

async fn raw_trace_rls_counts(
    tx: &tokio_postgres::Transaction<'_>,
    ids: RawTraceRlsIds,
    tenant_id: &str,
) -> RawTraceRlsCounts {
    let model_version = raw_rls_ranking_model_version(tenant_id);
    let calibration_dataset_hash = raw_rls_ranking_calibration_dataset_hash(tenant_id);
    let row = tx
        .query_one(
            "SELECT
                (SELECT COUNT(*) FROM trace_submissions WHERE submission_id = $1) AS submissions,
                (SELECT COUNT(*) FROM trace_object_refs WHERE object_ref_id = $2) AS object_refs,
                (SELECT COUNT(*) FROM trace_derived_records WHERE derived_id = $3) AS derived_records,
                (SELECT COUNT(*) FROM trace_vector_entries WHERE vector_entry_id = $4) AS vector_entries,
                (SELECT COUNT(*) FROM trace_export_manifests WHERE export_manifest_id = $5) AS export_manifests,
                (SELECT COUNT(*) FROM trace_export_manifest_items WHERE export_manifest_id = $5) AS export_manifest_items,
                (SELECT COUNT(*) FROM trace_export_access_grants WHERE grant_id = $6) AS export_access_grants,
                (SELECT COUNT(*) FROM trace_export_jobs WHERE export_job_id = $7) AS export_jobs,
                (SELECT COUNT(*) FROM trace_audit_events WHERE audit_event_id = $8) AS audit_events,
                (SELECT COUNT(*) FROM trace_credit_ledger WHERE credit_event_id = $9) AS credit_events,
                (SELECT COUNT(*) FROM trace_utility_attestations WHERE attestation_id = $10) AS utility_attestations,
                (SELECT COUNT(*) FROM trace_credit_settlement_batches WHERE settlement_batch_id = $11) AS credit_settlement_batches,
                (SELECT COUNT(*) FROM trace_credit_holds WHERE hold_id = $12) AS credit_holds,
                (SELECT COUNT(*) FROM trace_near_credit_outbox WHERE near_outbox_id = $13) AS near_credit_outbox,
                (SELECT COUNT(*) FROM trace_near_credit_account_outbox WHERE near_outbox_id = $14) AS near_credit_account_outbox,
                (SELECT COUNT(*) FROM trace_ranking_model_versions WHERE model_version = $25) AS ranking_model_versions,
                (SELECT COUNT(*) FROM trace_ranking_calibration_datasets WHERE calibration_dataset_hash = $26) AS ranking_calibration_datasets,
                (SELECT COUNT(*) FROM trace_ranking_features WHERE ranking_feature_id = $15) AS ranking_features,
                (SELECT COUNT(*) FROM trace_ranking_predictions WHERE ranking_prediction_id = $16) AS ranking_predictions,
                (SELECT COUNT(*) FROM trace_ranking_labels WHERE ranking_label_id = $17) AS ranking_labels,
                (SELECT COUNT(*) FROM trace_ranking_preference_labels WHERE preference_label_id = $18) AS ranking_preference_labels,
                (SELECT COUNT(*) FROM trace_ranking_calibration_runs WHERE calibration_run_id = $19) AS ranking_calibration_runs,
                (SELECT COUNT(*) FROM trace_ranking_worker_runs WHERE ranking_worker_run_id = $20) AS ranking_worker_runs,
                (SELECT COUNT(*) FROM trace_benchmark_registry_outbox WHERE benchmark_outbox_id = $21) AS benchmark_registry_outbox,
                (SELECT COUNT(*) FROM trace_tombstones WHERE tombstone_id = $22) AS tombstones,
                (SELECT COUNT(*) FROM trace_retention_jobs WHERE retention_job_id = $23) AS retention_jobs,
                (SELECT COUNT(*) FROM trace_retention_job_items WHERE retention_job_id = $23) AS retention_job_items,
                (SELECT COUNT(*) FROM trace_revocation_propagation_items WHERE propagation_item_id = $24) AS revocation_propagation_items",
            &[
                &ids.submission_id,
                &ids.object_ref_id,
                &ids.derived_id,
                &ids.vector_entry_id,
                &ids.export_manifest_id,
                &ids.export_access_grant_id,
                &ids.export_job_id,
                &ids.audit_event_id,
                &ids.credit_event_id,
                &ids.utility_attestation_id,
                &ids.settlement_batch_id,
                &ids.credit_hold_id,
                &ids.near_outbox_id,
                &ids.near_account_outbox_id,
                &ids.ranking_feature_id,
                &ids.ranking_prediction_id,
                &ids.ranking_label_id,
                &ids.preference_label_id,
                &ids.calibration_run_id,
                &ids.ranking_worker_run_id,
                &ids.benchmark_outbox_id,
                &ids.tombstone_id,
                &ids.retention_job_id,
                &ids.propagation_item_id,
                &model_version,
                &calibration_dataset_hash,
            ],
        )
        .await
        .expect("count raw Trace Commons rows under RLS");

    RawTraceRlsCounts {
        submissions: row.get("submissions"),
        object_refs: row.get("object_refs"),
        derived_records: row.get("derived_records"),
        vector_entries: row.get("vector_entries"),
        export_manifests: row.get("export_manifests"),
        export_manifest_items: row.get("export_manifest_items"),
        export_access_grants: row.get("export_access_grants"),
        export_jobs: row.get("export_jobs"),
        audit_events: row.get("audit_events"),
        credit_events: row.get("credit_events"),
        utility_attestations: row.get("utility_attestations"),
        credit_settlement_batches: row.get("credit_settlement_batches"),
        credit_holds: row.get("credit_holds"),
        near_credit_outbox: row.get("near_credit_outbox"),
        near_credit_account_outbox: row.get("near_credit_account_outbox"),
        ranking_model_versions: row.get("ranking_model_versions"),
        ranking_calibration_datasets: row.get("ranking_calibration_datasets"),
        ranking_features: row.get("ranking_features"),
        ranking_predictions: row.get("ranking_predictions"),
        ranking_labels: row.get("ranking_labels"),
        ranking_preference_labels: row.get("ranking_preference_labels"),
        ranking_calibration_runs: row.get("ranking_calibration_runs"),
        ranking_worker_runs: row.get("ranking_worker_runs"),
        benchmark_registry_outbox: row.get("benchmark_registry_outbox"),
        tombstones: row.get("tombstones"),
        retention_jobs: row.get("retention_jobs"),
        retention_job_items: row.get("retention_job_items"),
        revocation_propagation_items: row.get("revocation_propagation_items"),
    }
}

async fn assert_raw_sql_trace_rows_visible_only_with_matching_tenant_context(
    database_url: &str,
    tenant_a: &str,
    tenant_b: &str,
    tenant_a_ids: RawTraceRlsIds,
    tenant_b_ids: RawTraceRlsIds,
) {
    let mut client = connect_for_raw_rls_assertion(database_url, "raw RLS assertion").await;

    let tx = client
        .transaction()
        .await
        .expect("start raw no-context RLS assertion transaction");
    assert_eq!(
        raw_trace_rls_counts(&tx, tenant_a_ids, tenant_a).await,
        RawTraceRlsCounts::all(0),
        "tenant A rows must be invisible without transaction-local tenant context"
    );
    assert_eq!(
        raw_trace_rls_counts(&tx, tenant_b_ids, tenant_b).await,
        RawTraceRlsCounts::all(0),
        "tenant B rows must be invisible without transaction-local tenant context"
    );
    tx.commit()
        .await
        .expect("commit raw no-context RLS assertion");

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant A RLS assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_a],
    )
    .await
    .expect("set tenant A context");
    assert_eq!(
        raw_trace_rls_counts(&tx, tenant_a_ids, tenant_a).await,
        RawTraceRlsCounts::all(1),
        "tenant A rows must be visible with matching tenant context"
    );
    assert_eq!(
        raw_trace_rls_counts(&tx, tenant_b_ids, tenant_b).await,
        RawTraceRlsCounts::all(0),
        "tenant B rows must be invisible from tenant A context"
    );
    tx.commit()
        .await
        .expect("commit raw tenant A RLS assertion");

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant B RLS assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_b],
    )
    .await
    .expect("set tenant B context");
    assert_eq!(
        raw_trace_rls_counts(&tx, tenant_b_ids, tenant_b).await,
        RawTraceRlsCounts::all(1),
        "tenant B rows must be visible with matching tenant context"
    );
    assert_eq!(
        raw_trace_rls_counts(&tx, tenant_a_ids, tenant_a).await,
        RawTraceRlsCounts::all(0),
        "tenant A rows must be invisible from tenant B context"
    );
    tx.commit()
        .await
        .expect("commit raw tenant B RLS assertion");
}

async fn assert_raw_sql_tenant_policies_visible_only_with_matching_tenant_context(
    database_url: &str,
    tenant_a: &str,
    tenant_b: &str,
) {
    let mut client =
        connect_for_raw_rls_assertion(database_url, "raw tenant policy RLS assertion").await;

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant policy no-context assertion transaction");
    let no_context_count: i64 = tx
        .query_one("SELECT COUNT(*) FROM trace_tenant_policies", &[])
        .await
        .expect("count tenant policies without context")
        .get(0);
    assert_eq!(
        no_context_count, 0,
        "tenant policy rows must be invisible without tenant context"
    );
    tx.commit()
        .await
        .expect("commit raw tenant policy no-context assertion");

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant policy tenant A assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_a],
    )
    .await
    .expect("set tenant A context");
    let tenant_a_visible_count: i64 = tx
        .query_one("SELECT COUNT(*) FROM trace_tenant_policies", &[])
        .await
        .expect("count tenant policies for tenant A")
        .get(0);
    let tenant_b_from_a_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenant_policies WHERE tenant_id = $1",
            &[&tenant_b],
        )
        .await
        .expect("count tenant B policy from tenant A context")
        .get(0);
    assert_eq!(tenant_a_visible_count, 1);
    assert_eq!(tenant_b_from_a_count, 0);
    tx.commit()
        .await
        .expect("commit raw tenant policy tenant A assertion");

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant policy tenant B assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_b],
    )
    .await
    .expect("set tenant B context");
    let tenant_b_visible_count: i64 = tx
        .query_one("SELECT COUNT(*) FROM trace_tenant_policies", &[])
        .await
        .expect("count tenant policies for tenant B")
        .get(0);
    let tenant_a_from_b_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenant_policies WHERE tenant_id = $1",
            &[&tenant_a],
        )
        .await
        .expect("count tenant A policy from tenant B context")
        .get(0);
    assert_eq!(tenant_b_visible_count, 1);
    assert_eq!(tenant_a_from_b_count, 0);
    tx.commit()
        .await
        .expect("commit raw tenant policy tenant B assertion");
}

/// The two expected counts are the caller's, because only the caller knows how
/// many grants its fixture wrote. This assertion used to hardcode one apiece
/// while the calling test seeds TWO grants for tenant A and asserts so itself,
/// which nobody noticed because the assertion never ran under a role that
/// could not bypass RLS (#752). The unqualified `COUNT(*)` is the point of the
/// assertion -- it proves RLS hides every other tenant's grant, not merely
/// that a `WHERE tenant_id` predicate works -- so it stays unqualified and the
/// expected number comes in from outside.
async fn assert_raw_sql_tenant_access_grants_visible_only_with_matching_tenant_context(
    database_url: &str,
    tenant_a: &str,
    tenant_b: &str,
    expected_tenant_a_grants: i64,
    expected_tenant_b_grants: i64,
) {
    let mut client =
        connect_for_raw_rls_assertion(database_url, "raw tenant access grant RLS assertion").await;

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant access grant no-context assertion transaction");
    let no_context_count: i64 = tx
        .query_one("SELECT COUNT(*) FROM trace_tenant_access_grants", &[])
        .await
        .expect("count tenant access grants without context")
        .get(0);
    assert_eq!(
        no_context_count, 0,
        "tenant access grant rows must be invisible without tenant context"
    );
    tx.commit()
        .await
        .expect("commit raw tenant access grant no-context assertion");

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant access grant tenant A assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_a],
    )
    .await
    .expect("set tenant A context");
    let tenant_a_visible_count: i64 = tx
        .query_one("SELECT COUNT(*) FROM trace_tenant_access_grants", &[])
        .await
        .expect("count tenant access grants for tenant A")
        .get(0);
    let tenant_b_from_a_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenant_access_grants WHERE tenant_id = $1",
            &[&tenant_b],
        )
        .await
        .expect("count tenant B access grant from tenant A context")
        .get(0);
    assert_eq!(
        tenant_a_visible_count, expected_tenant_a_grants,
        "tenant A must see exactly the grants its own fixture wrote"
    );
    assert_eq!(tenant_b_from_a_count, 0);
    tx.commit()
        .await
        .expect("commit raw tenant access grant tenant A assertion");

    let tx = client
        .transaction()
        .await
        .expect("start raw tenant access grant tenant B assertion transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_b],
    )
    .await
    .expect("set tenant B context");
    let tenant_b_visible_count: i64 = tx
        .query_one("SELECT COUNT(*) FROM trace_tenant_access_grants", &[])
        .await
        .expect("count tenant access grants for tenant B")
        .get(0);
    let tenant_a_from_b_count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM trace_tenant_access_grants WHERE tenant_id = $1",
            &[&tenant_a],
        )
        .await
        .expect("count tenant A access grant from tenant B context")
        .get(0);
    assert_eq!(
        tenant_b_visible_count, expected_tenant_b_grants,
        "tenant B must see exactly the grants its own fixture wrote"
    );
    assert_eq!(tenant_a_from_b_count, 0);
    tx.commit()
        .await
        .expect("commit raw tenant access grant tenant B assertion");
}

async fn cleanup_trace_tenants(backend: &PgBackend, tenant_ids: &[&str]) {
    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in tenant_ids {
        let tenant_id = *tenant_id;
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

async fn assert_trace_rls_policies_installed(backend: &PgBackend) {
    let expected_tables: Vec<String> = expected_trace_rls_tables()
        .into_iter()
        .map(str::to_string)
        .collect();
    let client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get policy connection");
    let rows = client
        .query(
            "SELECT tablename
             FROM pg_policies
             WHERE schemaname = current_schema()
               AND policyname = 'trace_corpus_tenant_isolation'
               AND tablename = ANY($1)",
            &[&expected_tables],
        )
        .await
        .expect("read trace RLS policies");
    let mut actual_tables: Vec<String> = rows.iter().map(|row| row.get("tablename")).collect();
    actual_tables.sort();

    let mut expected_tables = expected_tables;
    expected_tables.sort();
    assert_eq!(actual_tables, expected_tables);
}

#[test]
fn force_rls_migration_covers_every_trace_rls_table() {
    let migrations_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut sql = std::fs::read_to_string(migrations_root.join("V6__trace_force_rls.sql"))
        .expect("read FORCE RLS production hardening migration");
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V11__trace_ranking_worker_runs.sql"))
            .expect("read ranking worker run production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V14__trace_ranking_preference_labels.sql"))
            .expect("read ranking preference label production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V15__trace_benchmark_registry_outbox.sql"))
            .expect("read benchmark registry outbox production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(
            migrations_root.join("V16__trace_ranking_calibration_datasets.sql"),
        )
        .expect("read ranking calibration dataset production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V21__trace_near_credit_account_outbox.sql"))
            .expect("read NEAR account outbox production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V38__trace_pii_backstop.sql"))
            .expect("read PII backstop production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V26__trace_contributor_profiles.sql"))
            .expect("read contributor profile production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V28__device_keys.sql"))
            .expect("read device key production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V29__onboarding_invites.sql"))
            .expect("read onboarding invite production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V30__trace_accounts.sql"))
            .expect("read trace account production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V32__webauthn_credentials.sql"))
            .expect("read WebAuthn credential production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V33__near_identities.sql"))
            .expect("read NEAR identity production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V34__account_consolidation.sql"))
            .expect("read account consolidation production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V43__trace_withdrawal.sql"))
            .expect("read trace withdrawal production hardening migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(
            migrations_root.join("V56__community_withdrawal_eviction_rls.sql"),
        )
        .expect("read community withdrawal eviction production hardening migration"),
    );
    // Tables introduced after the original hardening migration install their
    // policies in their creation migration; earlier migrations cannot alter them.
    sql.push_str(include_str!(
        "../../../migrations/V58__near_account_provisioning.sql"
    ));
    sql.push_str(include_str!(
        "../../../migrations/V64__token_distribution_bundles.sql"
    ));
    // `trace_pii_backstop` carries the same tenant-isolation policy but is not
    // in `TRACE_COMMONS_RLS_TABLES`, so assert it here rather than lose the
    // coverage the hand-maintained table list used to provide.
    for table in expected_trace_rls_tables()
        .into_iter()
        .chain(["trace_pii_backstop"])
    {
        let statement = format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY;");
        assert!(
            sql.contains(&statement),
            "FORCE RLS migration must include {statement}"
        );
    }
}

#[test]
fn central_rls_tenant_predicate_migration_covers_every_trace_rls_table() {
    let migrations_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut sql = std::fs::read_to_string(
        migrations_root.join("V18__trace_central_rls_tenant_predicate.sql"),
    )
    .expect("read central RLS tenant predicate migration");
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V21__trace_near_credit_account_outbox.sql"))
            .expect("read NEAR account outbox central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V38__trace_pii_backstop.sql"))
            .expect("read PII backstop central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V26__trace_contributor_profiles.sql"))
            .expect("read contributor profile central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V28__device_keys.sql"))
            .expect("read device key central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V29__onboarding_invites.sql"))
            .expect("read onboarding invite central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V30__trace_accounts.sql"))
            .expect("read trace account central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V32__webauthn_credentials.sql"))
            .expect("read WebAuthn credential central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V33__near_identities.sql"))
            .expect("read NEAR identity central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V34__account_consolidation.sql"))
            .expect("read account consolidation central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(migrations_root.join("V43__trace_withdrawal.sql"))
            .expect("read trace withdrawal central RLS policy migration"),
    );
    sql.push_str(
        &std::fs::read_to_string(
            migrations_root.join("V56__community_withdrawal_eviction_rls.sql"),
        )
        .expect("read community withdrawal eviction central RLS policy migration"),
    );

    // Tables introduced after the original hardening migration install their
    // policies in their creation migration; earlier migrations cannot alter them.
    sql.push_str(include_str!(
        "../../../migrations/V58__near_account_provisioning.sql"
    ));
    sql.push_str(include_str!(
        "../../../migrations/V64__token_distribution_bundles.sql"
    ));
    assert!(sql.contains("CREATE OR REPLACE FUNCTION trace_current_tenant_id()"));
    assert!(sql.contains("RETURNS TEXT"));
    assert!(sql.contains("current_setting('trace_commons.trace_tenant_id', true)"));
    for table in expected_trace_rls_tables()
        .into_iter()
        .chain(["trace_pii_backstop"])
    {
        assert!(
            sql.contains(&format!(
                "DROP POLICY IF EXISTS trace_corpus_tenant_isolation ON {table};"
            )),
            "central tenant predicate migration must drop stale policy on {table}"
        );
        assert!(
            sql.contains(&format!(
                "CREATE POLICY trace_corpus_tenant_isolation ON {table}"
            )),
            "central tenant predicate migration must recreate policy on {table}"
        );
    }
}

#[test]
fn onboarding_creation_migrations_enforce_their_rls_boundaries() {
    let provisioning = include_str!("../../../migrations/V58__near_account_provisioning.sql");
    let admission = include_str!("../../../migrations/V59__trace_admission_ledger.sql");
    // V59 uses dedicated policy names checked by admission_runtime_ready;
    // validate those separately from the corpus policy-name registry.
    for (sql, table, policy) in [
        (
            provisioning,
            "trace_near_account_anchors",
            "trace_corpus_tenant_isolation",
        ),
        (
            provisioning,
            "trace_near_provisioned_devices",
            "trace_corpus_tenant_isolation",
        ),
        (
            admission,
            "trace_admission_challenges",
            "admission_challenge_tenant",
        ),
        (
            admission,
            "trace_admission_accounts",
            "admission_account_tenant",
        ),
        (
            admission,
            "trace_admission_submissions",
            "admission_submission_tenant",
        ),
    ] {
        assert!(sql.contains(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")));
        assert!(sql.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")));
        let normalized: String = sql.split_whitespace().collect();
        assert!(normalized.contains(&format!(
            "CREATEPOLICY{policy}ON{table}USING(tenant_id=trace_current_tenant_id())WITHCHECK(tenant_id=trace_current_tenant_id());"
        )), "{table} must constrain both reads and writes with the canonical tenant predicate");
    }
    // The pre-account ceremony and global ledger state have distinct scopes;
    // neither may lose FORCE RLS or acquire a public unrestricted policy.
    for (sql, table, policy, expression) in [
        (
            provisioning,
            "trace_near_provisioning_ceremonies",
            "trace_near_ceremony_isolation",
            "USING(ceremony_hash=current_setting('trace_commons.near_ceremony_hash',true))WITHCHECK(ceremony_hash=current_setting('trace_commons.near_ceremony_hash',true));",
        ),
        (
            admission,
            "trace_admission_receipts",
            "admission_receipt_guard",
            "TOtrace_admission_guardUSING(TRUE)WITHCHECK(TRUE);",
        ),
        (
            admission,
            "trace_admission_global_budget",
            "admission_global_guard",
            "TOtrace_admission_guardUSING(TRUE)WITHCHECK(TRUE);",
        ),
    ] {
        assert!(sql.contains(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")));
        assert!(sql.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")));
        let normalized: String = sql.split_whitespace().collect();
        assert!(
            normalized.contains(&format!("CREATEPOLICY{policy}ON{table}{expression}")),
            "{table} must retain its scoped policy"
        );
    }
}

#[test]
fn onboarding_retention_keeps_scoped_policies_and_never_prunes_durable_ledger() {
    let sql = include_str!("../../../migrations/V60__onboarding_retention.sql");
    let normalized: String = sql.split_whitespace().collect();
    assert!(normalized.contains("CREATEPOLICYtrace_near_ceremony_expiryONtrace_near_provisioning_ceremoniesTOtrace_onboarding_retention_guardUSING(expires_at<=statement_timestamp());"));
    assert!(sql.contains("NOLOGIN NOBYPASSRLS"));
    assert!(sql.contains("REVOKE trace_onboarding_retention_guard FROM CURRENT_USER"));
    assert!(sql.contains("p_limit > 1000"));
    assert!(sql.contains("tenant_id=p_tenant AND expires_at <= statement_timestamp()"));
    for table in [
        "trace_admission_accounts",
        "trace_admission_submissions",
        "trace_admission_receipts",
        "trace_admission_global_budget",
    ] {
        assert!(!sql.contains(&format!("DELETE FROM public.{table}")));
        assert!(!sql.contains(&format!("UPDATE public.{table}")));
    }
}

#[test]
fn trace_corpus_rls_diagnostics_ready_requires_complete_safe_policy_state() {
    assert!(ready_rls_diagnostics().rls_ready());

    let mut missing_policy = ready_rls_diagnostics();
    missing_policy.policy_installed_count = 1;
    missing_policy
        .missing_policy_tables
        .push("trace_submissions".to_string());
    assert!(!missing_policy.rls_ready());

    let mut disabled_rls = ready_rls_diagnostics();
    disabled_rls.rls_enabled_count = 1;
    disabled_rls
        .rls_disabled_tables
        .push("trace_object_refs".to_string());
    assert!(!disabled_rls.rls_ready());

    let mut expression_mismatch = ready_rls_diagnostics();
    expression_mismatch
        .policy_expression_mismatch_tables
        .push("trace_credit_ledger".to_string());
    assert!(!expression_mismatch.rls_ready());

    let mut bypass_role = ready_rls_diagnostics();
    bypass_role.current_role_bypasses_rls = true;
    assert!(!bypass_role.rls_ready());

    let mut table_owner_role = ready_rls_diagnostics();
    table_owner_role.current_role_owns_trace_tables = true;
    assert!(!table_owner_role.rls_ready());
    assert!(!table_owner_role.production_ready());

    let mut force_rls_disabled = ready_rls_diagnostics();
    force_rls_disabled.force_rls_enabled_count = 1;
    force_rls_disabled
        .force_rls_disabled_tables
        .push("trace_object_refs".to_string());
    assert!(force_rls_disabled.rls_ready());
    assert!(!force_rls_disabled.force_rls_ready());
    assert!(!force_rls_disabled.production_ready());
}

#[tokio::test]
async fn pg_store_rejects_stale_audit_previous_hash_per_tenant() {
    let Some(backend) = single_connection_postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_id = format!("pg-audit-chain-{}", Uuid::new_v4());
    let other_tenant_id = format!("pg-audit-chain-other-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();
    let other_submission_id = Uuid::new_v4();

    backend
        .upsert_trace_submission(sample_submission(&tenant_id, submission_id))
        .await
        .expect("insert submission");
    backend
        .upsert_trace_submission(sample_submission(&other_tenant_id, other_submission_id))
        .await
        .expect("insert other tenant submission");

    backend
        .append_trace_audit_event(sample_unhashed_audit_event(&tenant_id, submission_id))
        .await
        .expect("append DB-native unhashed audit event");
    backend
        .append_trace_audit_event(sample_audit_event(
            &tenant_id,
            submission_id,
            "sha256:file-only-predecessor",
            "sha256:first",
        ))
        .await
        .expect("append first mirrored hash-chain segment");
    backend
        .append_trace_audit_event(sample_audit_event(
            &tenant_id,
            submission_id,
            "sha256:first",
            "sha256:second",
        ))
        .await
        .expect("append second audit event");

    let stale_append = backend
        .append_trace_audit_event(sample_audit_event(
            &tenant_id,
            submission_id,
            "sha256:file-only-predecessor",
            "sha256:stale",
        ))
        .await;
    assert!(
        stale_append.is_err(),
        "stale audit hash-chain predecessor must be rejected"
    );

    let audit_events = backend
        .list_trace_audit_events(&tenant_id)
        .await
        .expect("list audit events");
    assert_eq!(audit_events.len(), 3);
    assert_eq!(
        audit_events
            .iter()
            .map(|event| event.event_hash.as_deref())
            .collect::<Vec<_>>(),
        vec![None, Some("sha256:first"), Some("sha256:second")]
    );
    assert_eq!(
        audit_events
            .iter()
            .map(|event| event.audit_sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );

    backend
        .append_trace_audit_event(sample_audit_event(
            &other_tenant_id,
            other_submission_id,
            "sha256:genesis",
            "sha256:first-other-tenant",
        ))
        .await
        .expect("other tenant starts an independent audit chain");

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in [&tenant_id, &other_tenant_id] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn store_facade_sets_transaction_local_tenant_context() {
    let Some(backend) = single_connection_postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_a = format!("rls-context-a-{}", Uuid::new_v4());
    let tenant_b = format!("rls-context-b-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();

    {
        let client = backend
            .raw_pool_for_tests_and_diagnostics()
            .get()
            .await
            .expect("get pooled connection");
        client
            .execute(
                "SELECT set_config('trace_commons.trace_tenant_id', $1, false)",
                &[&tenant_b],
            )
            .await
            .expect("poison pooled tenant context");
    }

    let inserted_a = backend
        .upsert_trace_submission(sample_submission(&tenant_a, submission_id))
        .await
        .expect("insert tenant A submission despite stale session context");
    assert_eq!(inserted_a.tenant_id, tenant_a);

    let fetched_a = backend
        .get_trace_submission(&tenant_a, submission_id)
        .await
        .expect("get tenant A submission despite stale session context")
        .expect("tenant A submission exists");
    assert_eq!(fetched_a.tenant_id, tenant_a);

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get pooled connection");
    let tenant_context: String = client
        .query_one(
            "SELECT current_setting('trace_commons.trace_tenant_id', true)",
            &[],
        )
        .await
        .expect("read pooled tenant context")
        .get(0);
    assert_eq!(tenant_context, tenant_b);

    let role_bypasses_rls = current_role_bypasses_trace_rls(&mut client)
        .await
        .unwrap_or_else(|e| {
            eprintln!("skipping RLS role assertion: could not inspect role ({e})");
            true
        });
    if role_bypasses_rls {
        eprintln!(
            "RLS role bypasses table policies; this test verifies transaction-local context cleanup, not policy enforcement"
        );
    }

    let tx = client
        .transaction()
        .await
        .expect("start cleanup transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_a],
    )
    .await
    .expect("set cleanup tenant context");
    let _ = tx
        .execute(
            "DELETE FROM trace_tenants WHERE tenant_id = $1",
            &[&tenant_a],
        )
        .await;
    tx.commit().await.expect("commit cleanup transaction");
}

#[tokio::test]
async fn store_facade_keeps_same_submission_id_isolated_by_tenant() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_a = format!("rls-tenant-a-{}", Uuid::new_v4());
    let tenant_b = format!("rls-tenant-b-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();

    let inserted_a = backend
        .upsert_trace_submission(sample_submission(&tenant_a, submission_id))
        .await
        .expect("insert tenant A submission");
    let inserted_b = backend
        .upsert_trace_submission(sample_submission(&tenant_b, submission_id))
        .await
        .expect("insert tenant B submission with same submission id");

    assert_eq!(inserted_a.submission_id, submission_id);
    assert_eq!(inserted_b.submission_id, submission_id);
    assert_eq!(inserted_a.tenant_id, tenant_a);
    assert_eq!(inserted_b.tenant_id, tenant_b);
    assert_ne!(inserted_a.trace_id, inserted_b.trace_id);

    let tenant_a_submission = backend
        .get_trace_submission(&tenant_a, submission_id)
        .await
        .expect("get tenant A submission")
        .expect("tenant A submission exists");
    let tenant_b_submission = backend
        .get_trace_submission(&tenant_b, submission_id)
        .await
        .expect("get tenant B submission")
        .expect("tenant B submission exists");

    assert_eq!(tenant_a_submission.tenant_id, tenant_a);
    assert_eq!(tenant_b_submission.tenant_id, tenant_b);
    assert_eq!(
        tenant_a_submission.contributor_pseudonym.as_deref(),
        Some(format!("contributor:{tenant_a}").as_str())
    );
    assert_eq!(
        tenant_b_submission.contributor_pseudonym.as_deref(),
        Some(format!("contributor:{tenant_b}").as_str())
    );

    let listed_a = backend
        .list_trace_submissions(&tenant_a)
        .await
        .expect("list tenant A submissions");
    let listed_b = backend
        .list_trace_submissions(&tenant_b)
        .await
        .expect("list tenant B submissions");

    assert_eq!(listed_a.len(), 1);
    assert_eq!(listed_b.len(), 1);
    assert_eq!(listed_a[0].tenant_id, tenant_a);
    assert_eq!(listed_b[0].tenant_id, tenant_b);
    assert_ne!(listed_a[0].trace_id, listed_b[0].trace_id);

    if let Some(config) = postgres_test_config() {
        assert_raw_sql_rls_filters_by_tenant_context(
            config.url.expose_secret(),
            &tenant_a,
            &tenant_b,
            submission_id,
        )
        .await;
    }

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in [tenant_a, tenant_b] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn store_facade_keeps_same_ranking_prediction_and_worker_ids_isolated_by_tenant() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_a = format!("rls-ranking-a-{}", Uuid::new_v4());
    let tenant_b = format!("rls-ranking-b-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();
    let trace_id = Uuid::new_v4();
    let ranking_feature_id = Uuid::new_v4();
    let ranking_prediction_id = Uuid::new_v4();
    let ranking_worker_run_id = Uuid::new_v4();

    for (tenant_id, utility_micros, reason) in [
        (&tenant_a, 2_400_000_i64, "tenant_a_high_signal"),
        (&tenant_b, 800_000_i64, "tenant_b_holdout"),
    ] {
        let mut submission = sample_submission(tenant_id, submission_id);
        submission.trace_id = trace_id;
        submission.allowed_uses = vec!["ranking_model_training".to_string()];
        backend
            .upsert_trace_submission(submission)
            .await
            .expect("insert ranking source submission");

        backend
            .upsert_trace_ranking_model_version(TraceRankingModelVersionWrite {
                tenant_id: tenant_id.clone(),
                model_version: "trace-ranker-credit-v1".to_string(),
                feature_schema_version: "ranking-features-v1".to_string(),
                policy_version: "trace-credit-policy-v1".to_string(),
                status: TraceRankingModelStatus::Candidate,
                training_dataset_hash: format!("sha256:{tenant_id}:training"),
                calibration_dataset_hash: format!("sha256:{tenant_id}:calibration"),
                model_artifact_hash: format!("sha256:{tenant_id}:model"),
                actor_principal_ref: format!("principal:{tenant_id}:ranker-admin"),
            })
            .await
            .expect("upsert tenant-scoped ranking model");

        backend
            .upsert_trace_ranking_feature(TraceRankingFeatureWrite {
                tenant_id: tenant_id.clone(),
                ranking_feature_id,
                submission_id,
                trace_id,
                target_use: "ranking_model_training".to_string(),
                feature_schema_version: "ranking-features-v1".to_string(),
                feature_vector_hash: format!("sha256:{tenant_id}:feature-vector"),
                feature_names_hash: format!("sha256:{tenant_id}:feature-names"),
                source_feature_hash: format!("sha256:{tenant_id}:source"),
                duplicate_score: Some(0.01),
                novelty_score: Some(0.8),
                privacy_risk_score: Some(0.02),
                quality_score: Some(0.9),
                coverage_tags: vec![format!("tenant:{tenant_id}")],
                actor_principal_ref: format!("principal:{tenant_id}:ranker-worker"),
            })
            .await
            .expect("upsert tenant-scoped ranking feature");

        backend
            .upsert_trace_ranking_prediction(TraceRankingPredictionWrite {
                tenant_id: tenant_id.clone(),
                ranking_prediction_id,
                submission_id,
                trace_id,
                target_use: "ranking_model_training".to_string(),
                model_version: "trace-ranker-credit-v1".to_string(),
                feature_schema_version: "ranking-features-v1".to_string(),
                prediction_policy_version: "trace-credit-policy-v1".to_string(),
                feature_vector_hash: format!("sha256:{tenant_id}:feature-vector"),
                predicted_utility_micros: utility_micros,
                uncertainty_micros: 125_000,
                confidence: 0.91,
                risk_penalty_micros: 25_000,
                novelty_bonus_micros: 50_000,
                settlement_score_micros: utility_micros + 25_000,
                explanation_codes: vec![reason.to_string()],
                actor_principal_ref: format!("principal:{tenant_id}:ranker-worker"),
            })
            .await
            .expect("upsert tenant-scoped ranking prediction");

        let mut reason_counts = BTreeMap::new();
        reason_counts.insert(reason.to_string(), 1);
        backend
            .upsert_trace_ranking_worker_run(TraceRankingWorkerRunWrite {
                tenant_id: tenant_id.clone(),
                ranking_worker_run_id,
                run_kind: TraceRankingWorkerRunKind::PredictionCredit,
                status: TraceRankingWorkerRunStatus::Completed,
                dry_run: false,
                reason_hash: format!("sha256:{tenant_id}:worker-reason"),
                model_version: Some("trace-ranker-credit-v1".to_string()),
                target_use: Some("ranking_model_training".to_string()),
                policy_version: Some("trace-credit-policy-v1".to_string()),
                limit: 10,
                checked_count: 1,
                succeeded_count: 1,
                skipped_existing_count: 0,
                skipped_model_risk_count: 0,
                skipped_ineligible_count: 0,
                pending_after_count: 0,
                result_refs: vec![format!("ranking_prediction:{ranking_prediction_id}")],
                reason_counts,
                actor_principal_ref: format!("principal:{tenant_id}:ranker-worker"),
                created_at: Utc::now(),
                completed_at: Some(Utc::now()),
                last_error_hash: None,
            })
            .await
            .expect("upsert tenant-scoped ranking worker run");
    }

    let tenant_a_models = backend
        .list_trace_ranking_model_versions(&tenant_a)
        .await
        .expect("list tenant A ranking models");
    let tenant_b_models = backend
        .list_trace_ranking_model_versions(&tenant_b)
        .await
        .expect("list tenant B ranking models");
    assert_eq!(tenant_a_models.len(), 1);
    assert_eq!(tenant_b_models.len(), 1);
    assert_eq!(tenant_a_models[0].tenant_id, tenant_a);
    assert_eq!(tenant_b_models[0].tenant_id, tenant_b);
    assert_ne!(
        tenant_a_models[0].model_artifact_hash,
        tenant_b_models[0].model_artifact_hash
    );

    let tenant_a_predictions = backend
        .list_trace_ranking_predictions(&tenant_a)
        .await
        .expect("list tenant A ranking predictions");
    let tenant_b_predictions = backend
        .list_trace_ranking_predictions(&tenant_b)
        .await
        .expect("list tenant B ranking predictions");
    assert_eq!(tenant_a_predictions.len(), 1);
    assert_eq!(tenant_b_predictions.len(), 1);
    assert_eq!(
        tenant_a_predictions[0].ranking_prediction_id,
        ranking_prediction_id
    );
    assert_eq!(
        tenant_b_predictions[0].ranking_prediction_id,
        ranking_prediction_id
    );
    assert_eq!(tenant_a_predictions[0].tenant_id, tenant_a);
    assert_eq!(tenant_b_predictions[0].tenant_id, tenant_b);
    assert_eq!(tenant_a_predictions[0].predicted_utility_micros, 2_400_000);
    assert_eq!(tenant_b_predictions[0].predicted_utility_micros, 800_000);
    assert_eq!(
        tenant_a_predictions[0].explanation_codes,
        vec!["tenant_a_high_signal"]
    );
    assert_eq!(
        tenant_b_predictions[0].explanation_codes,
        vec!["tenant_b_holdout"]
    );

    let tenant_a_worker_runs = backend
        .list_trace_ranking_worker_runs(&tenant_a)
        .await
        .expect("list tenant A ranking worker runs");
    let tenant_b_worker_runs = backend
        .list_trace_ranking_worker_runs(&tenant_b)
        .await
        .expect("list tenant B ranking worker runs");
    assert_eq!(tenant_a_worker_runs.len(), 1);
    assert_eq!(tenant_b_worker_runs.len(), 1);
    assert_eq!(
        tenant_a_worker_runs[0].ranking_worker_run_id,
        ranking_worker_run_id
    );
    assert_eq!(
        tenant_b_worker_runs[0].ranking_worker_run_id,
        ranking_worker_run_id
    );
    assert_eq!(tenant_a_worker_runs[0].tenant_id, tenant_a);
    assert_eq!(tenant_b_worker_runs[0].tenant_id, tenant_b);
    assert_eq!(
        tenant_a_worker_runs[0]
            .reason_counts
            .get("tenant_a_high_signal"),
        Some(&1)
    );
    assert_eq!(
        tenant_b_worker_runs[0]
            .reason_counts
            .get("tenant_b_holdout"),
        Some(&1)
    );

    cleanup_trace_tenants(&backend, &[&tenant_a, &tenant_b]).await;
}

#[tokio::test]
async fn store_facade_preserves_tenant_policy_scope_and_updates() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_alpha = format!("rls-policy-alpha-{}", Uuid::new_v4());
    let tenant_beta = format!("rls-policy-beta-{}", Uuid::new_v4());

    let alpha_policy = backend
        .upsert_trace_tenant_policy(TraceTenantPolicyWrite {
            tenant_id: tenant_alpha.clone(),
            policy_version: "tenant-policy-v1".to_string(),
            allowed_consent_scopes: vec!["debugging_evaluation".to_string()],
            allowed_uses: vec!["debugging".to_string(), "evaluation".to_string()],
            updated_by_principal_ref: "admin:alpha".to_string(),
        })
        .await
        .expect("insert alpha tenant policy");
    assert_eq!(alpha_policy.tenant_id, tenant_alpha);
    assert_eq!(alpha_policy.policy_version, "tenant-policy-v1");
    assert_eq!(
        alpha_policy.allowed_consent_scopes,
        vec!["debugging_evaluation"]
    );
    assert_eq!(alpha_policy.allowed_uses, vec!["debugging", "evaluation"]);
    assert_eq!(alpha_policy.updated_by_principal_ref, "admin:alpha");

    let read_alpha_policy = backend
        .get_trace_tenant_policy(&tenant_alpha)
        .await
        .expect("read alpha tenant policy")
        .expect("alpha tenant policy exists");
    assert_eq!(read_alpha_policy, alpha_policy);
    assert!(
        backend
            .get_trace_tenant_policy(&tenant_beta)
            .await
            .expect("probe beta tenant policy")
            .is_none()
    );

    let beta_policy = backend
        .upsert_trace_tenant_policy(TraceTenantPolicyWrite {
            tenant_id: tenant_beta.clone(),
            policy_version: "tenant-policy-beta-v1".to_string(),
            allowed_consent_scopes: vec!["benchmark_only".to_string()],
            allowed_uses: vec!["benchmark".to_string()],
            updated_by_principal_ref: "admin:beta".to_string(),
        })
        .await
        .expect("insert beta tenant policy");

    let updated_alpha_policy = backend
        .upsert_trace_tenant_policy(TraceTenantPolicyWrite {
            tenant_id: tenant_alpha.clone(),
            policy_version: "tenant-policy-v2".to_string(),
            allowed_consent_scopes: vec![
                "debugging_evaluation".to_string(),
                "benchmark_only".to_string(),
            ],
            allowed_uses: vec!["debugging".to_string()],
            updated_by_principal_ref: "admin:alpha-second".to_string(),
        })
        .await
        .expect("update alpha tenant policy");
    assert_eq!(updated_alpha_policy.tenant_id, tenant_alpha);
    assert_eq!(updated_alpha_policy.policy_version, "tenant-policy-v2");
    assert_eq!(
        updated_alpha_policy.allowed_consent_scopes,
        vec!["debugging_evaluation", "benchmark_only"]
    );
    assert_eq!(updated_alpha_policy.allowed_uses, vec!["debugging"]);
    assert_eq!(
        updated_alpha_policy.updated_by_principal_ref,
        "admin:alpha-second"
    );

    let read_beta_policy = backend
        .get_trace_tenant_policy(&tenant_beta)
        .await
        .expect("read beta tenant policy")
        .expect("beta tenant policy exists");
    assert_eq!(read_beta_policy, beta_policy);
    assert_ne!(
        updated_alpha_policy.updated_by_principal_ref,
        read_beta_policy.updated_by_principal_ref
    );

    if let Some(config) = postgres_test_config() {
        assert_raw_sql_tenant_policies_visible_only_with_matching_tenant_context(
            config.url.expose_secret(),
            &tenant_alpha,
            &tenant_beta,
        )
        .await;
    }

    cleanup_trace_tenants(&backend, &[&tenant_alpha, &tenant_beta]).await;
}

#[tokio::test]
async fn store_facade_preserves_tenant_access_grant_scope_and_active_filter() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_alpha = format!("rls-access-alpha-{}", Uuid::new_v4());
    let tenant_beta = format!("rls-access-beta-{}", Uuid::new_v4());
    let now = DateTime::parse_from_rfc3339("2026-04-27T12:00:00Z")
        .expect("parse now")
        .with_timezone(&Utc);
    let grant_id = Uuid::new_v4();
    let expired_grant_id = Uuid::new_v4();
    let mut metadata = BTreeMap::new();
    metadata.insert("issuer_key_mode".to_string(), "managed_eddsa".to_string());
    metadata.insert("hosted_surface".to_string(), "near.com".to_string());

    let alpha_grant = backend
        .upsert_trace_tenant_access_grant(TraceTenantAccessGrantWrite {
            tenant_id: tenant_alpha.clone(),
            grant_id,
            principal_ref: "principal:hosted-agent".to_string(),
            role: TraceTenantAccessGrantRole::Contributor,
            status: TraceTenantAccessGrantStatus::Active,
            allowed_consent_scopes: vec![
                "debugging_evaluation".to_string(),
                "ranking_training".to_string(),
            ],
            allowed_uses: vec![
                "debugging_evaluation".to_string(),
                "ranking_model_training".to_string(),
            ],
            issuer: Some("https://issuer.near.com".to_string()),
            audience: Some("trace-commons".to_string()),
            subject: Some("tenant-alpha-agent".to_string()),
            issued_at: now - chrono::Duration::minutes(5),
            expires_at: Some(now + chrono::Duration::minutes(30)),
            revoked_at: None,
            created_by_principal_ref: Some("issuer:near.com".to_string()),
            revoked_by_principal_ref: None,
            reason: Some("hosted tenant verified".to_string()),
            metadata: metadata.clone(),
        })
        .await
        .expect("insert alpha tenant access grant");
    assert_eq!(alpha_grant.tenant_id, tenant_alpha);
    assert_eq!(alpha_grant.grant_id, grant_id);
    assert_eq!(alpha_grant.role, TraceTenantAccessGrantRole::Contributor);
    assert_eq!(alpha_grant.status, TraceTenantAccessGrantStatus::Active);
    assert_eq!(alpha_grant.metadata, metadata);

    backend
        .upsert_trace_tenant_access_grant(TraceTenantAccessGrantWrite {
            tenant_id: tenant_alpha.clone(),
            grant_id: expired_grant_id,
            principal_ref: "principal:hosted-agent".to_string(),
            role: TraceTenantAccessGrantRole::Contributor,
            status: TraceTenantAccessGrantStatus::Active,
            allowed_consent_scopes: vec!["debugging_evaluation".to_string()],
            allowed_uses: vec!["debugging_evaluation".to_string()],
            issuer: Some("https://issuer.near.com".to_string()),
            audience: Some("trace-commons".to_string()),
            subject: Some("tenant-alpha-agent".to_string()),
            issued_at: now - chrono::Duration::hours(1),
            expires_at: Some(now - chrono::Duration::minutes(1)),
            revoked_at: None,
            created_by_principal_ref: Some("issuer:near.com".to_string()),
            revoked_by_principal_ref: None,
            reason: Some("expired grant".to_string()),
            metadata: BTreeMap::new(),
        })
        .await
        .expect("insert alpha expired tenant access grant");

    let beta_grant = backend
        .upsert_trace_tenant_access_grant(TraceTenantAccessGrantWrite {
            tenant_id: tenant_beta.clone(),
            grant_id,
            principal_ref: "principal:hosted-agent".to_string(),
            role: TraceTenantAccessGrantRole::Admin,
            status: TraceTenantAccessGrantStatus::Active,
            allowed_consent_scopes: vec!["debugging_evaluation".to_string()],
            allowed_uses: vec!["debugging_evaluation".to_string()],
            issuer: Some("https://issuer.near.com".to_string()),
            audience: Some("trace-commons".to_string()),
            subject: Some("tenant-beta-agent".to_string()),
            issued_at: now - chrono::Duration::minutes(5),
            expires_at: Some(now + chrono::Duration::minutes(30)),
            revoked_at: None,
            created_by_principal_ref: Some("issuer:near.com".to_string()),
            revoked_by_principal_ref: None,
            reason: Some("beta grant with same id".to_string()),
            metadata: BTreeMap::new(),
        })
        .await
        .expect("insert beta tenant access grant");
    assert_eq!(beta_grant.tenant_id, tenant_beta);
    assert_eq!(beta_grant.grant_id, grant_id);
    assert_eq!(beta_grant.role, TraceTenantAccessGrantRole::Admin);

    let alpha_grants = backend
        .list_trace_tenant_access_grants(&tenant_alpha)
        .await
        .expect("list alpha tenant access grants");
    assert_eq!(alpha_grants.len(), 2);
    assert!(
        alpha_grants
            .iter()
            .all(|grant| grant.tenant_id == tenant_alpha)
    );

    let alpha_active = backend
        .list_active_trace_tenant_access_grants_for_principal(
            &tenant_alpha,
            "principal:hosted-agent",
            now,
        )
        .await
        .expect("list active alpha tenant access grants");
    assert_eq!(alpha_active.len(), 1);
    assert_eq!(alpha_active[0].grant_id, grant_id);
    assert_eq!(
        alpha_active[0].allowed_uses,
        vec!["debugging_evaluation", "ranking_model_training"]
    );

    let beta_grants = backend
        .list_trace_tenant_access_grants(&tenant_beta)
        .await
        .expect("list beta tenant access grants");
    assert_eq!(beta_grants.len(), 1);
    assert_eq!(beta_grants[0].grant_id, grant_id);
    assert_eq!(beta_grants[0].role, TraceTenantAccessGrantRole::Admin);

    if let Some(config) = postgres_test_config() {
        assert_raw_sql_tenant_access_grants_visible_only_with_matching_tenant_context(
            config.url.expose_secret(),
            &tenant_alpha,
            &tenant_beta,
            alpha_grants.len() as i64,
            beta_grants.len() as i64,
        )
        .await;
    }

    cleanup_trace_tenants(&backend, &[&tenant_alpha, &tenant_beta]).await;
}

#[tokio::test]
async fn store_facade_preserves_review_lease_audit_metadata() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_alpha = format!("rls-lease-audit-alpha-{}", Uuid::new_v4());
    let tenant_beta = format!("rls-lease-audit-beta-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();

    backend
        .upsert_trace_submission(sample_submission(&tenant_alpha, submission_id))
        .await
        .expect("insert alpha submission");

    backend
        .append_trace_audit_event(TraceAuditEventWrite {
            tenant_id: tenant_alpha.clone(),
            audit_event_id: Uuid::new_v4(),
            submission_id: Some(submission_id),
            actor_principal_ref: "principal:contributor".to_string(),
            actor_role: "contributor".to_string(),
            action: TraceAuditAction::Submit,
            reason: None,
            request_id: Some("request:submit".to_string()),
            object_ref_id: None,
            export_manifest_id: None,
            decision_inputs_hash: None,
            previous_event_hash: Some("sha256:genesis".to_string()),
            event_hash: Some("sha256:lease-audit-submit".to_string()),
            canonical_event_json: Some("{\"kind\":\"submitted\"}".to_string()),
            metadata: TraceAuditSafeMetadata::Submission {
                status: TraceCorpusStatus::Accepted,
                privacy_risk: "low".to_string(),
            },
        })
        .await
        .expect("append submit audit event");

    let lease_expires_at = DateTime::parse_from_rfc3339("2026-04-25T12:15:00Z")
        .expect("parse lease expiry")
        .with_timezone(&Utc);
    let review_due_at = DateTime::parse_from_rfc3339("2026-04-25T13:00:00Z")
        .expect("parse review due")
        .with_timezone(&Utc);
    backend
        .append_trace_audit_event(TraceAuditEventWrite {
            tenant_id: tenant_alpha.clone(),
            audit_event_id: Uuid::new_v4(),
            submission_id: Some(submission_id),
            actor_principal_ref: "principal:reviewer".to_string(),
            actor_role: "reviewer".to_string(),
            action: TraceAuditAction::Review,
            reason: Some("action=claim".to_string()),
            request_id: None,
            object_ref_id: None,
            export_manifest_id: None,
            decision_inputs_hash: None,
            previous_event_hash: Some("sha256:lease-audit-submit".to_string()),
            event_hash: Some("sha256:lease-audit-claim".to_string()),
            canonical_event_json: Some("{\"kind\":\"review_lease\"}".to_string()),
            metadata: TraceAuditSafeMetadata::ReviewLease {
                action: TraceReviewLeaseAuditAction::Claim,
                lease_expires_at: Some(lease_expires_at),
                review_due_at: Some(review_due_at),
            },
        })
        .await
        .expect("append review lease audit event");

    let audit_events = backend
        .list_trace_audit_events(&tenant_alpha)
        .await
        .expect("list alpha audit events");
    assert_eq!(audit_events.len(), 2);
    assert_eq!(audit_events[1].submission_id, Some(submission_id));
    assert_eq!(audit_events[1].action, TraceAuditAction::Review);
    assert_eq!(
        audit_events[1].metadata,
        TraceAuditSafeMetadata::ReviewLease {
            action: TraceReviewLeaseAuditAction::Claim,
            lease_expires_at: Some(lease_expires_at),
            review_due_at: Some(review_due_at),
        }
    );

    let beta_audit_events = backend
        .list_trace_audit_events(&tenant_beta)
        .await
        .expect("list beta audit events");
    assert!(beta_audit_events.is_empty());

    cleanup_trace_tenants(&backend, &[&tenant_alpha, &tenant_beta]).await;
}

#[tokio::test]
async fn store_facade_claims_releases_review_leases_by_tenant_and_reviewer() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_alpha = format!("rls-lease-alpha-{}", Uuid::new_v4());
    let tenant_beta = format!("rls-lease-beta-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();

    let mut alpha_submission = sample_submission(&tenant_alpha, submission_id);
    alpha_submission.status = TraceCorpusStatus::Quarantined;
    backend
        .upsert_trace_submission(alpha_submission)
        .await
        .expect("insert alpha quarantined submission");
    let mut beta_submission = sample_submission(&tenant_beta, submission_id);
    beta_submission.status = TraceCorpusStatus::Quarantined;
    backend
        .upsert_trace_submission(beta_submission)
        .await
        .expect("insert beta quarantined submission with same submission id");

    let now = DateTime::parse_from_rfc3339("2026-04-25T12:00:00Z")
        .expect("parse lease now")
        .with_timezone(&Utc);
    let lease_expires_at = now + chrono::Duration::minutes(15);
    let review_due_at = now + chrono::Duration::hours(1);
    let alpha_claim = backend
        .claim_trace_review_lease(
            &tenant_alpha,
            submission_id,
            "principal:reviewer-alpha",
            lease_expires_at,
            Some(review_due_at),
            now,
        )
        .await
        .expect("claim alpha review lease")
        .expect("alpha review lease is claimable");
    assert_eq!(alpha_claim.tenant_id, tenant_alpha);
    assert_eq!(alpha_claim.status, TraceCorpusStatus::Quarantined);
    assert_eq!(
        alpha_claim.review_assigned_to_principal_ref.as_deref(),
        Some("principal:reviewer-alpha")
    );
    assert_eq!(alpha_claim.review_lease_expires_at, Some(lease_expires_at));
    assert_eq!(alpha_claim.review_due_at, Some(review_due_at));

    let blocked_claim = backend
        .claim_trace_review_lease(
            &tenant_alpha,
            submission_id,
            "principal:reviewer-other",
            lease_expires_at + chrono::Duration::minutes(5),
            Some(review_due_at + chrono::Duration::minutes(5)),
            now + chrono::Duration::minutes(1),
        )
        .await
        .expect("attempt conflicting alpha review lease claim");
    assert!(blocked_claim.is_none());

    let alpha_reclaim = backend
        .claim_trace_review_lease(
            &tenant_alpha,
            submission_id,
            "principal:reviewer-alpha",
            lease_expires_at + chrono::Duration::minutes(10),
            Some(review_due_at + chrono::Duration::minutes(10)),
            now + chrono::Duration::minutes(2),
        )
        .await
        .expect("same reviewer renews alpha review lease")
        .expect("same reviewer can renew lease");
    assert_eq!(
        alpha_reclaim.review_assigned_to_principal_ref.as_deref(),
        Some("principal:reviewer-alpha")
    );
    assert_eq!(
        alpha_reclaim.review_lease_expires_at,
        Some(lease_expires_at + chrono::Duration::minutes(10))
    );

    let wrong_release = backend
        .release_trace_review_lease(&tenant_alpha, submission_id, "principal:reviewer-other")
        .await
        .expect("attempt conflicting alpha review lease release");
    assert!(wrong_release.is_none());

    let beta_claim = backend
        .claim_trace_review_lease(
            &tenant_beta,
            submission_id,
            "principal:reviewer-beta",
            lease_expires_at,
            Some(review_due_at),
            now,
        )
        .await
        .expect("claim beta review lease with same submission id")
        .expect("beta review lease is independently claimable");
    assert_eq!(beta_claim.tenant_id, tenant_beta);
    assert_eq!(
        beta_claim.review_assigned_to_principal_ref.as_deref(),
        Some("principal:reviewer-beta")
    );

    let alpha_release = backend
        .release_trace_review_lease(&tenant_alpha, submission_id, "principal:reviewer-alpha")
        .await
        .expect("release alpha review lease")
        .expect("alpha review lease is releasable by owner");
    assert!(alpha_release.review_assigned_to_principal_ref.is_none());
    assert!(alpha_release.review_assigned_at.is_none());
    assert!(alpha_release.review_lease_expires_at.is_none());
    assert!(alpha_release.review_due_at.is_none());

    let stored_beta = backend
        .get_trace_submission(&tenant_beta, submission_id)
        .await
        .expect("read beta submission")
        .expect("beta submission still exists");
    assert_eq!(
        stored_beta.review_assigned_to_principal_ref.as_deref(),
        Some("principal:reviewer-beta")
    );

    let expired_alpha_claim = backend
        .claim_trace_review_lease(
            &tenant_alpha,
            submission_id,
            "principal:reviewer-alpha",
            lease_expires_at,
            Some(review_due_at),
            now,
        )
        .await
        .expect("reclaim alpha lease after release")
        .expect("alpha lease is claimable after release");
    assert_eq!(
        expired_alpha_claim
            .review_assigned_to_principal_ref
            .as_deref(),
        Some("principal:reviewer-alpha")
    );
    let alpha_handoff = backend
        .claim_trace_review_lease(
            &tenant_alpha,
            submission_id,
            "principal:reviewer-other",
            lease_expires_at + chrono::Duration::minutes(30),
            Some(review_due_at + chrono::Duration::minutes(30)),
            lease_expires_at + chrono::Duration::seconds(1),
        )
        .await
        .expect("claim expired alpha lease")
        .expect("expired alpha lease can be claimed by another reviewer");
    assert_eq!(
        alpha_handoff.review_assigned_to_principal_ref.as_deref(),
        Some("principal:reviewer-other")
    );

    cleanup_trace_tenants(&backend, &[&tenant_alpha, &tenant_beta]).await;
}

#[tokio::test]
async fn store_facade_preserves_retention_job_scope_and_items() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_alpha = format!("rls-retention-alpha-{}", Uuid::new_v4());
    let tenant_beta = format!("rls-retention-beta-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();

    backend
        .upsert_trace_submission(sample_submission(&tenant_alpha, submission_id))
        .await
        .expect("insert alpha submission");
    backend
        .upsert_trace_submission(sample_submission(&tenant_beta, submission_id))
        .await
        .expect("insert beta submission with same submission id");

    let retention_job_id = Uuid::new_v4();
    let mut action_counts = BTreeMap::new();
    action_counts.insert("records_marked_expired".to_string(), 1);
    action_counts.insert("records_marked_purged".to_string(), 1);
    let job = backend
        .upsert_trace_retention_job(TraceRetentionJobWrite {
            tenant_id: tenant_alpha.clone(),
            retention_job_id,
            purpose: "test_pg_retention_purge".to_string(),
            dry_run: false,
            status: TraceRetentionJobStatus::Running,
            requested_by_principal_ref: "principal:retention-worker".to_string(),
            requested_by_role: "retention_worker".to_string(),
            purge_expired_before: Some(Utc::now()),
            prune_export_cache: true,
            max_export_age_hours: Some(24),
            audit_event_id: Some(Uuid::new_v4()),
            action_counts: action_counts.clone(),
            selected_revoked_count: 0,
            selected_expired_count: 1,
            started_at: Some(Utc::now()),
            completed_at: None,
        })
        .await
        .expect("insert alpha retention job");
    assert_eq!(job.tenant_id, tenant_alpha);
    assert_eq!(job.retention_job_id, retention_job_id);
    assert_eq!(job.status, TraceRetentionJobStatus::Running);
    assert_eq!(job.action_counts, action_counts);

    action_counts.insert("records_marked_purged".to_string(), 2);
    let updated_job = backend
        .upsert_trace_retention_job(TraceRetentionJobWrite {
            tenant_id: tenant_alpha.clone(),
            retention_job_id,
            purpose: "test_pg_retention_purge".to_string(),
            dry_run: false,
            status: TraceRetentionJobStatus::Complete,
            requested_by_principal_ref: "principal:retention-worker".to_string(),
            requested_by_role: "retention_worker".to_string(),
            purge_expired_before: Some(Utc::now()),
            prune_export_cache: true,
            max_export_age_hours: Some(24),
            audit_event_id: job.audit_event_id,
            action_counts: action_counts.clone(),
            selected_revoked_count: 0,
            selected_expired_count: 2,
            started_at: job.started_at,
            completed_at: Some(Utc::now()),
        })
        .await
        .expect("idempotently update alpha retention job");
    assert_eq!(updated_job.retention_job_id, retention_job_id);
    assert_eq!(updated_job.status, TraceRetentionJobStatus::Complete);
    assert_eq!(updated_job.action_counts, action_counts);
    assert_eq!(updated_job.selected_expired_count, 2);

    let mut item_counts = BTreeMap::new();
    item_counts.insert("object_refs_invalidated".to_string(), 1);
    item_counts.insert("derived_records_invalidated".to_string(), 1);
    let item = backend
        .upsert_trace_retention_job_item(TraceRetentionJobItemWrite {
            tenant_id: tenant_alpha.clone(),
            retention_job_id,
            submission_id,
            action: TraceRetentionJobItemAction::Purge,
            status: TraceRetentionJobItemStatus::Pending,
            reason: "retention_pending".to_string(),
            action_counts: item_counts.clone(),
            verified_at: None,
        })
        .await
        .expect("insert alpha retention job item");
    assert_eq!(item.tenant_id, tenant_alpha);
    assert_eq!(item.submission_id, submission_id);
    assert_eq!(item.action, TraceRetentionJobItemAction::Purge);
    assert_eq!(item.status, TraceRetentionJobItemStatus::Pending);

    item_counts.insert("records_marked_purged".to_string(), 1);
    let updated_item = backend
        .upsert_trace_retention_job_item(TraceRetentionJobItemWrite {
            tenant_id: tenant_alpha.clone(),
            retention_job_id,
            submission_id,
            action: TraceRetentionJobItemAction::Purge,
            status: TraceRetentionJobItemStatus::Done,
            reason: "retention_purged".to_string(),
            action_counts: item_counts.clone(),
            verified_at: Some(Utc::now()),
        })
        .await
        .expect("idempotently update alpha retention job item");
    assert_eq!(updated_item.status, TraceRetentionJobItemStatus::Done);
    assert_eq!(updated_item.reason, "retention_purged");
    assert_eq!(updated_item.action_counts, item_counts);

    let alpha_jobs = backend
        .list_trace_retention_jobs(&tenant_alpha)
        .await
        .expect("list alpha retention jobs");
    assert_eq!(alpha_jobs.len(), 1);
    assert_eq!(alpha_jobs[0].retention_job_id, retention_job_id);
    assert_eq!(alpha_jobs[0].status, TraceRetentionJobStatus::Complete);
    let beta_jobs = backend
        .list_trace_retention_jobs(&tenant_beta)
        .await
        .expect("list beta retention jobs");
    assert!(beta_jobs.is_empty());

    let alpha_items = backend
        .list_trace_retention_job_items(&tenant_alpha, retention_job_id)
        .await
        .expect("list alpha retention job items");
    assert_eq!(alpha_items.len(), 1);
    assert_eq!(alpha_items[0].submission_id, submission_id);
    assert_eq!(alpha_items[0].status, TraceRetentionJobItemStatus::Done);
    let beta_items = backend
        .list_trace_retention_job_items(&tenant_beta, retention_job_id)
        .await
        .expect("list beta retention job items");
    assert!(beta_items.is_empty());

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in [&tenant_alpha, &tenant_beta] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn store_facade_preserves_revocation_propagation_scope_and_updates() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_alpha = format!("rls-propagation-alpha-{}", Uuid::new_v4());
    let tenant_beta = format!("rls-propagation-beta-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();

    let alpha_submission = sample_submission(&tenant_alpha, submission_id);
    let alpha_trace_id = alpha_submission.trace_id;
    backend
        .upsert_trace_submission(alpha_submission)
        .await
        .expect("insert alpha submission");
    let beta_submission = sample_submission(&tenant_beta, submission_id);
    let beta_trace_id = beta_submission.trace_id;
    backend
        .upsert_trace_submission(beta_submission)
        .await
        .expect("insert beta submission with same submission id");

    let alpha_propagation_item_id = Uuid::new_v4();
    let alpha_object_ref_id = Uuid::new_v4();
    let alpha_item = backend
        .upsert_trace_revocation_propagation_item(sample_revocation_propagation_item(
            &tenant_alpha,
            submission_id,
            alpha_propagation_item_id,
            TraceRevocationPropagationTarget::ObjectRef {
                object_ref_id: alpha_object_ref_id,
            },
            "alpha:object-ref",
        ))
        .await
        .expect("insert alpha revocation propagation item");
    assert_eq!(alpha_item.tenant_id, tenant_alpha);
    assert_eq!(alpha_item.trace_id, alpha_trace_id);
    assert_eq!(
        alpha_item.status,
        TraceRevocationPropagationItemStatus::Pending
    );

    let beta_propagation_item_id = Uuid::new_v4();
    let beta_export_manifest_id = Uuid::new_v4();
    let beta_item = backend
        .upsert_trace_revocation_propagation_item(sample_revocation_propagation_item(
            &tenant_beta,
            submission_id,
            beta_propagation_item_id,
            TraceRevocationPropagationTarget::ExportManifestItem {
                export_manifest_id: beta_export_manifest_id,
                source_submission_id: submission_id,
            },
            "beta:export-item",
        ))
        .await
        .expect("insert beta revocation propagation item");
    assert_eq!(beta_item.tenant_id, tenant_beta);
    assert_eq!(beta_item.trace_id, beta_trace_id);

    let alpha_items = backend
        .list_trace_revocation_propagation_items(&tenant_alpha, submission_id)
        .await
        .expect("list alpha revocation propagation items");
    assert_eq!(alpha_items.len(), 1);
    assert_eq!(
        alpha_items[0].propagation_item_id,
        alpha_propagation_item_id
    );
    assert_eq!(
        alpha_items[0].target,
        TraceRevocationPropagationTarget::ObjectRef {
            object_ref_id: alpha_object_ref_id
        }
    );

    let beta_items_from_alpha_submission_id = backend
        .list_trace_revocation_propagation_items(&tenant_beta, submission_id)
        .await
        .expect("list beta revocation propagation items");
    assert_eq!(beta_items_from_alpha_submission_id.len(), 1);
    assert_eq!(
        beta_items_from_alpha_submission_id[0].propagation_item_id,
        beta_propagation_item_id
    );

    let alpha_due = backend
        .list_due_trace_revocation_propagation_items(&tenant_alpha, Utc::now(), 10)
        .await
        .expect("list due alpha revocation propagation items");
    assert_eq!(alpha_due.len(), 1);
    assert_eq!(alpha_due[0].propagation_item_id, alpha_propagation_item_id);
    assert_ne!(alpha_due[0].propagation_item_id, beta_propagation_item_id);

    let cross_tenant_update = backend
        .update_trace_revocation_propagation_item_status(
            &tenant_alpha,
            beta_propagation_item_id,
            TraceRevocationPropagationItemStatusUpdate {
                status: TraceRevocationPropagationItemStatus::Done,
                attempt_count: 1,
                last_error: None,
                next_attempt_at: None,
                completed_at: Some(Utc::now()),
                evidence_hash: Some("sha256:cross-tenant-update".to_string()),
            },
        )
        .await
        .expect("cross-tenant update is scoped by tenant");
    assert!(cross_tenant_update.is_none());

    let updated_alpha = backend
        .update_trace_revocation_propagation_item_status(
            &tenant_alpha,
            alpha_propagation_item_id,
            TraceRevocationPropagationItemStatusUpdate {
                status: TraceRevocationPropagationItemStatus::Done,
                attempt_count: 1,
                last_error: None,
                next_attempt_at: None,
                completed_at: Some(Utc::now()),
                evidence_hash: Some("sha256:alpha-object-ref-invalidated".to_string()),
            },
        )
        .await
        .expect("update alpha revocation propagation item")
        .expect("alpha revocation propagation item exists");
    assert_eq!(
        updated_alpha.status,
        TraceRevocationPropagationItemStatus::Done
    );
    assert_eq!(
        updated_alpha.evidence_hash.as_deref(),
        Some("sha256:alpha-object-ref-invalidated")
    );

    let beta_items_after_alpha_update = backend
        .list_trace_revocation_propagation_items(&tenant_beta, submission_id)
        .await
        .expect("list beta revocation propagation items after alpha update");
    assert_eq!(beta_items_after_alpha_update.len(), 1);
    assert_eq!(
        beta_items_after_alpha_update[0].status,
        TraceRevocationPropagationItemStatus::Pending
    );
    assert!(beta_items_after_alpha_update[0].evidence_hash.is_none());

    cleanup_trace_tenants(&backend, &[&tenant_alpha, &tenant_beta]).await;
}

#[tokio::test]
async fn store_facade_preserves_export_grant_job_scope_and_updates() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_alpha = format!("rls-export-job-alpha-{}", Uuid::new_v4());
    let tenant_beta = format!("rls-export-job-beta-{}", Uuid::new_v4());
    let export_job_id = Uuid::new_v4();
    let alpha_grant_id = Uuid::new_v4();
    let beta_grant_id = Uuid::new_v4();
    let result_manifest_id = Uuid::new_v4();
    // PostgreSQL `timestamptz` holds microseconds, so anything finer is
    // truncated on write and a read-back value can never equal an in-memory
    // one that carried nanoseconds. Pin the fixture to what the store can
    // actually hold. macOS clocks are microsecond-granular, so `Utc::now()`
    // there has zero sub-microsecond nanos and this passed on every Mac; Linux
    // clocks are nanosecond-granular, so it could never pass in CI.
    let requested_at = Utc::now().trunc_subsecs(6);
    let expires_at = requested_at + chrono::Duration::minutes(15);
    let mut metadata = BTreeMap::new();
    metadata.insert("request_id".to_string(), "pg-rls-alpha".to_string());

    let alpha_grant = backend
        .upsert_trace_export_access_grant(TraceExportAccessGrantWrite {
            tenant_id: tenant_alpha.clone(),
            export_job_id,
            grant_id: alpha_grant_id,
            caller_principal_ref: "principal:alpha-exporter".to_string(),
            requested_dataset_kind: "replay".to_string(),
            purpose: "alpha-eval".to_string(),
            max_item_cap: Some(64),
            status: TraceExportAccessGrantStatus::Active,
            requested_at,
            expires_at,
            metadata: metadata.clone(),
        })
        .await
        .expect("insert alpha export access grant");
    assert_eq!(alpha_grant.tenant_id, tenant_alpha);
    assert_eq!(alpha_grant.grant_id, alpha_grant_id);
    assert_eq!(alpha_grant.status, TraceExportAccessGrantStatus::Active);

    let alpha_job = backend
        .upsert_trace_export_job(TraceExportJobWrite {
            tenant_id: tenant_alpha.clone(),
            export_job_id,
            grant_id: alpha_grant_id,
            caller_principal_ref: "principal:alpha-exporter".to_string(),
            requested_dataset_kind: "replay".to_string(),
            purpose: "alpha-eval".to_string(),
            max_item_cap: Some(64),
            status: TraceExportJobStatus::Queued,
            requested_at,
            started_at: None,
            finished_at: None,
            expires_at,
            result_manifest_id: None,
            item_count: None,
            last_error: None,
            metadata: metadata.clone(),
        })
        .await
        .expect("insert alpha export job");
    assert_eq!(alpha_job.tenant_id, tenant_alpha);
    assert_eq!(alpha_job.status, TraceExportJobStatus::Queued);

    backend
        .upsert_trace_export_access_grant(TraceExportAccessGrantWrite {
            tenant_id: tenant_beta.clone(),
            export_job_id,
            grant_id: beta_grant_id,
            caller_principal_ref: "principal:beta-exporter".to_string(),
            requested_dataset_kind: "benchmark".to_string(),
            purpose: "beta-eval".to_string(),
            max_item_cap: Some(7),
            status: TraceExportAccessGrantStatus::Active,
            requested_at,
            expires_at,
            metadata: BTreeMap::new(),
        })
        .await
        .expect("insert beta export access grant");
    backend
        .upsert_trace_export_job(TraceExportJobWrite {
            tenant_id: tenant_beta.clone(),
            export_job_id,
            grant_id: beta_grant_id,
            caller_principal_ref: "principal:beta-exporter".to_string(),
            requested_dataset_kind: "benchmark".to_string(),
            purpose: "beta-eval".to_string(),
            max_item_cap: Some(7),
            status: TraceExportJobStatus::Running,
            requested_at,
            started_at: Some(requested_at),
            finished_at: None,
            expires_at,
            result_manifest_id: None,
            item_count: Some(3),
            last_error: None,
            metadata: BTreeMap::new(),
        })
        .await
        .expect("insert beta export job with same job id");

    let alpha_grants = backend
        .list_trace_export_access_grants(&tenant_alpha)
        .await
        .expect("list alpha export grants");
    assert_eq!(alpha_grants.len(), 1);
    assert_eq!(alpha_grants[0].grant_id, alpha_grant_id);
    assert_eq!(alpha_grants[0].metadata, metadata);

    let alpha_jobs = backend
        .list_trace_export_jobs(&tenant_alpha)
        .await
        .expect("list alpha export jobs");
    assert_eq!(alpha_jobs.len(), 1);
    assert_eq!(alpha_jobs[0].status, TraceExportJobStatus::Queued);

    let claim_at = requested_at + chrono::Duration::seconds(3);
    let claimed_alpha = backend
        .claim_next_trace_export_job(
            &tenant_alpha,
            Some("replay"),
            claim_at,
            "principal:alpha-export-worker",
        )
        .await
        .expect("claim alpha queued export job")
        .expect("alpha queued export job is claimable");
    assert_eq!(claimed_alpha.export_job_id, export_job_id);
    assert_eq!(claimed_alpha.status, TraceExportJobStatus::Running);
    assert_eq!(claimed_alpha.started_at, Some(claim_at));
    assert_eq!(
        claimed_alpha.metadata.get("request_id").map(String::as_str),
        Some("pg-rls-alpha")
    );
    assert_eq!(
        claimed_alpha.metadata.get("state").map(String::as_str),
        Some("running")
    );
    assert_eq!(
        claimed_alpha
            .metadata
            .get("claimed_by_principal_ref")
            .map(String::as_str),
        Some("principal:alpha-export-worker")
    );
    let beta_claim_miss = backend
        .claim_next_trace_export_job(
            &tenant_beta,
            Some("replay"),
            claim_at,
            "principal:beta-export-worker",
        )
        .await
        .expect("dataset-kind claim is tenant scoped");
    assert!(beta_claim_miss.is_none());

    let finished_at = requested_at + chrono::Duration::seconds(12);
    let updated_alpha = backend
        .update_trace_export_job_status(
            &tenant_alpha,
            export_job_id,
            TraceExportJobStatusUpdate {
                status: TraceExportJobStatus::Complete,
                started_at: Some(requested_at),
                finished_at: Some(finished_at),
                result_manifest_id: Some(result_manifest_id),
                item_count: Some(42),
                last_error: None,
                metadata: metadata.clone(),
            },
        )
        .await
        .expect("update alpha export job")
        .expect("alpha export job exists");
    assert_eq!(updated_alpha.status, TraceExportJobStatus::Complete);
    assert_eq!(updated_alpha.item_count, Some(42));
    assert_eq!(updated_alpha.result_manifest_id, Some(result_manifest_id));

    let beta_jobs = backend
        .list_trace_export_jobs(&tenant_beta)
        .await
        .expect("list beta export jobs");
    assert_eq!(beta_jobs.len(), 1);
    assert_eq!(beta_jobs[0].status, TraceExportJobStatus::Running);
    assert_eq!(beta_jobs[0].item_count, Some(3));
    assert_eq!(beta_jobs[0].result_manifest_id, None);

    let stale_job_id = Uuid::new_v4();
    let stale_expires_at = requested_at - chrono::Duration::minutes(1);
    let stale_grant_id = Uuid::new_v4();
    // The stale job still belongs to a real grant; expiry does not remove the
    // tenant/grant foreign key required by the production storage schema.
    backend
        .upsert_trace_export_access_grant(TraceExportAccessGrantWrite {
            tenant_id: tenant_alpha.clone(),
            export_job_id: stale_job_id,
            grant_id: stale_grant_id,
            caller_principal_ref: "principal:alpha-exporter".to_string(),
            requested_dataset_kind: "replay".to_string(),
            purpose: "alpha-stale-eval".to_string(),
            max_item_cap: Some(8),
            status: TraceExportAccessGrantStatus::Active,
            requested_at: requested_at - chrono::Duration::minutes(10),
            expires_at: stale_expires_at,
            metadata: BTreeMap::new(),
        })
        .await
        .expect("insert stale alpha export access grant");
    backend
        .upsert_trace_export_job(TraceExportJobWrite {
            tenant_id: tenant_alpha.clone(),
            export_job_id: stale_job_id,
            grant_id: stale_grant_id,
            caller_principal_ref: "principal:alpha-exporter".to_string(),
            requested_dataset_kind: "replay".to_string(),
            purpose: "alpha-stale-eval".to_string(),
            max_item_cap: Some(8),
            status: TraceExportJobStatus::Running,
            requested_at: requested_at - chrono::Duration::minutes(10),
            started_at: Some(requested_at - chrono::Duration::minutes(10)),
            finished_at: None,
            expires_at: stale_expires_at,
            result_manifest_id: None,
            item_count: None,
            last_error: None,
            metadata: BTreeMap::from([("state".to_string(), "started".to_string())]),
        })
        .await
        .expect("insert stale alpha export job");
    let recovered_stale = backend
        .recover_stale_trace_export_job(
            &tenant_alpha,
            stale_job_id,
            requested_at,
            TraceExportJobStatusUpdate {
                status: TraceExportJobStatus::Expired,
                started_at: Some(requested_at - chrono::Duration::minutes(10)),
                finished_at: Some(requested_at),
                result_manifest_id: None,
                item_count: None,
                last_error: Some("stale_export_job_expired;reason_hash=sha256:test".to_string()),
                metadata: BTreeMap::from([
                    ("state".to_string(), "expired".to_string()),
                    (
                        "recovery".to_string(),
                        "stale_running_export_job".to_string(),
                    ),
                ]),
            },
        )
        .await
        .expect("recover stale alpha export job")
        .expect("stale alpha export job matches recovery predicate");
    assert_eq!(recovered_stale.status, TraceExportJobStatus::Expired);
    assert_eq!(recovered_stale.finished_at, Some(requested_at));
    assert_eq!(
        recovered_stale.metadata.get("recovery").map(String::as_str),
        Some("stale_running_export_job")
    );

    let fresh_recovery = backend
        .recover_stale_trace_export_job(
            &tenant_beta,
            export_job_id,
            requested_at,
            TraceExportJobStatusUpdate {
                status: TraceExportJobStatus::Expired,
                started_at: Some(requested_at),
                finished_at: Some(requested_at),
                result_manifest_id: None,
                item_count: Some(3),
                last_error: Some("should not update fresh rows".to_string()),
                metadata: BTreeMap::new(),
            },
        )
        .await
        .expect("fresh beta export job recovery predicate is tenant scoped");
    assert!(fresh_recovery.is_none());

    let missing_tenant_update = backend
        .update_trace_export_job_status(
            "tenant-gamma",
            export_job_id,
            TraceExportJobStatusUpdate {
                status: TraceExportJobStatus::Failed,
                started_at: None,
                finished_at: Some(finished_at),
                result_manifest_id: None,
                item_count: None,
                last_error: Some("not found".to_string()),
                metadata: BTreeMap::new(),
            },
        )
        .await
        .expect("tenant-scoped missing update");
    assert!(missing_tenant_update.is_none());

    cleanup_trace_tenants(&backend, &[&tenant_alpha, &tenant_beta]).await;
}

#[tokio::test]
async fn raw_trace_corpus_rls_requires_matching_transaction_local_tenant_context() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_a = format!("rls-raw-a-{}", Uuid::new_v4());
    let tenant_b = format!("rls-raw-b-{}", Uuid::new_v4());
    let tenant_a_submission_id = Uuid::new_v4();
    let tenant_b_submission_id = Uuid::new_v4();
    let tenant_a_trace_id = Uuid::new_v4();
    let tenant_b_trace_id = Uuid::new_v4();

    let mut tenant_a_submission = sample_submission(&tenant_a, tenant_a_submission_id);
    tenant_a_submission.trace_id = tenant_a_trace_id;
    backend
        .upsert_trace_submission(tenant_a_submission)
        .await
        .expect("insert tenant A submission");
    let mut tenant_b_submission = sample_submission(&tenant_b, tenant_b_submission_id);
    tenant_b_submission.trace_id = tenant_b_trace_id;
    backend
        .upsert_trace_submission(tenant_b_submission)
        .await
        .expect("insert tenant B submission");

    let tenant_a_object_ref_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_a.clone(),
            object_ref_id: tenant_a_object_ref_id,
            submission_id: tenant_a_submission_id,
            artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_a}/submission.json"),
            content_sha256: format!("sha256:{tenant_a}:object"),
            encryption_key_ref: format!("kms:{tenant_a}"),
            size_bytes: 4096,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("append tenant A object ref");
    let tenant_b_object_ref_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_b.clone(),
            object_ref_id: tenant_b_object_ref_id,
            submission_id: tenant_b_submission_id,
            artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_b}/submission.json"),
            content_sha256: format!("sha256:{tenant_b}:object"),
            encryption_key_ref: format!("kms:{tenant_b}"),
            size_bytes: 2048,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("append tenant B object ref");

    let tenant_a_derived_id = Uuid::new_v4();
    backend
        .append_trace_derived_record(TraceDerivedRecordWrite {
            tenant_id: tenant_a.clone(),
            derived_id: tenant_a_derived_id,
            submission_id: tenant_a_submission_id,
            trace_id: tenant_a_trace_id,
            status: TraceDerivedStatus::Current,
            worker_kind: TraceWorkerKind::DuplicatePrecheck,
            worker_version: "raw-rls-derived-v1".to_string(),
            input_object_ref: None,
            input_hash: format!("sha256:{tenant_a}:derived-input"),
            output_object_ref: None,
            canonical_summary: Some("tenant A raw RLS summary".to_string()),
            canonical_summary_hash: Some(format!("sha256:{tenant_a}:summary")),
            summary_model: "raw-rls-summary-model".to_string(),
            task_success: Some("success".to_string()),
            privacy_risk: Some("low".to_string()),
            event_count: Some(1),
            tool_sequence: vec!["terminal".to_string()],
            tool_categories: vec!["shell".to_string()],
            coverage_tags: vec!["raw-rls".to_string()],
            duplicate_score: Some(0.01),
            novelty_score: Some(0.9),
            cluster_id: Some(format!("cluster:{tenant_a}")),
        })
        .await
        .expect("append tenant A derived record");
    let tenant_a_vector_entry_id = Uuid::new_v4();
    backend
        .upsert_trace_vector_entry(TraceVectorEntryWrite {
            tenant_id: tenant_a.clone(),
            submission_id: tenant_a_submission_id,
            derived_id: tenant_a_derived_id,
            vector_entry_id: tenant_a_vector_entry_id,
            vector_store: "raw-rls-vector-store".to_string(),
            embedding_model: "raw-rls-embedder".to_string(),
            embedding_dimension: 8,
            embedding_version: "v1".to_string(),
            source_projection: TraceVectorEntrySourceProjection::CanonicalSummary,
            source_hash: format!("sha256:{tenant_a}:summary"),
            status: TraceVectorEntryStatus::Active,
            nearest_trace_ids: vec![tenant_a_trace_id.to_string()],
            cluster_id: Some(format!("cluster:{tenant_a}")),
            duplicate_score: Some(0.01),
            novelty_score: Some(0.9),
            indexed_at: Some(Utc::now()),
            invalidated_at: None,
            deleted_at: None,
        })
        .await
        .expect("append tenant A vector entry");
    let tenant_b_derived_id = Uuid::new_v4();
    backend
        .append_trace_derived_record(TraceDerivedRecordWrite {
            tenant_id: tenant_b.clone(),
            derived_id: tenant_b_derived_id,
            submission_id: tenant_b_submission_id,
            trace_id: tenant_b_trace_id,
            status: TraceDerivedStatus::Current,
            worker_kind: TraceWorkerKind::DuplicatePrecheck,
            worker_version: "raw-rls-derived-v1".to_string(),
            input_object_ref: None,
            input_hash: format!("sha256:{tenant_b}:derived-input"),
            output_object_ref: None,
            canonical_summary: Some("tenant B raw RLS summary".to_string()),
            canonical_summary_hash: Some(format!("sha256:{tenant_b}:summary")),
            summary_model: "raw-rls-summary-model".to_string(),
            task_success: Some("success".to_string()),
            privacy_risk: Some("low".to_string()),
            event_count: Some(1),
            tool_sequence: vec!["terminal".to_string()],
            tool_categories: vec!["shell".to_string()],
            coverage_tags: vec!["raw-rls".to_string()],
            duplicate_score: Some(0.02),
            novelty_score: Some(0.8),
            cluster_id: Some(format!("cluster:{tenant_b}")),
        })
        .await
        .expect("append tenant B derived record");
    let tenant_b_vector_entry_id = Uuid::new_v4();
    backend
        .upsert_trace_vector_entry(TraceVectorEntryWrite {
            tenant_id: tenant_b.clone(),
            submission_id: tenant_b_submission_id,
            derived_id: tenant_b_derived_id,
            vector_entry_id: tenant_b_vector_entry_id,
            vector_store: "raw-rls-vector-store".to_string(),
            embedding_model: "raw-rls-embedder".to_string(),
            embedding_dimension: 8,
            embedding_version: "v1".to_string(),
            source_projection: TraceVectorEntrySourceProjection::CanonicalSummary,
            source_hash: format!("sha256:{tenant_b}:summary"),
            status: TraceVectorEntryStatus::Active,
            nearest_trace_ids: vec![tenant_b_trace_id.to_string()],
            cluster_id: Some(format!("cluster:{tenant_b}")),
            duplicate_score: Some(0.02),
            novelty_score: Some(0.8),
            indexed_at: Some(Utc::now()),
            invalidated_at: None,
            deleted_at: None,
        })
        .await
        .expect("append tenant B vector entry");

    let tenant_a_export_manifest_id = Uuid::new_v4();
    backend
        .upsert_trace_export_manifest(TraceExportManifestWrite {
            tenant_id: tenant_a.clone(),
            export_manifest_id: tenant_a_export_manifest_id,
            artifact_kind: TraceObjectArtifactKind::ExportArtifact,
            purpose_code: Some("rls_replay_dataset".to_string()),
            audit_event_id: Some(Uuid::new_v4()),
            source_submission_ids: vec![tenant_a_submission_id],
            source_submission_ids_hash: format!("sha256:{tenant_a}:sources"),
            item_count: 1,
            generated_at: Utc::now(),
        })
        .await
        .expect("append tenant A export manifest");
    backend
        .upsert_trace_export_manifest_item(TraceExportManifestItemWrite {
            tenant_id: tenant_a.clone(),
            export_manifest_id: tenant_a_export_manifest_id,
            submission_id: tenant_a_submission_id,
            trace_id: tenant_a_trace_id,
            derived_id: None,
            object_ref_id: Some(tenant_a_object_ref_id),
            vector_entry_id: None,
            source_status_at_export: TraceCorpusStatus::Accepted,
            source_hash_at_export: format!("sha256:{tenant_a}:source"),
        })
        .await
        .expect("append tenant A export manifest item");
    let tenant_b_export_manifest_id = Uuid::new_v4();
    backend
        .upsert_trace_export_manifest(TraceExportManifestWrite {
            tenant_id: tenant_b.clone(),
            export_manifest_id: tenant_b_export_manifest_id,
            artifact_kind: TraceObjectArtifactKind::ExportArtifact,
            purpose_code: Some("rls_replay_dataset".to_string()),
            audit_event_id: Some(Uuid::new_v4()),
            source_submission_ids: vec![tenant_b_submission_id],
            source_submission_ids_hash: format!("sha256:{tenant_b}:sources"),
            item_count: 1,
            generated_at: Utc::now(),
        })
        .await
        .expect("append tenant B export manifest");
    backend
        .upsert_trace_export_manifest_item(TraceExportManifestItemWrite {
            tenant_id: tenant_b.clone(),
            export_manifest_id: tenant_b_export_manifest_id,
            submission_id: tenant_b_submission_id,
            trace_id: tenant_b_trace_id,
            derived_id: None,
            object_ref_id: Some(tenant_b_object_ref_id),
            vector_entry_id: None,
            source_status_at_export: TraceCorpusStatus::Accepted,
            source_hash_at_export: format!("sha256:{tenant_b}:source"),
        })
        .await
        .expect("append tenant B export manifest item");

    let export_requested_at = Utc::now();
    let export_expires_at = export_requested_at + chrono::Duration::minutes(30);
    let tenant_a_export_grant_id = Uuid::new_v4();
    let tenant_a_export_job_id = Uuid::new_v4();
    backend
        .upsert_trace_export_access_grant(TraceExportAccessGrantWrite {
            tenant_id: tenant_a.clone(),
            export_job_id: tenant_a_export_job_id,
            grant_id: tenant_a_export_grant_id,
            caller_principal_ref: format!("principal:{tenant_a}:exporter"),
            requested_dataset_kind: "replay".to_string(),
            purpose: "raw-rls-export".to_string(),
            max_item_cap: Some(10),
            status: TraceExportAccessGrantStatus::Active,
            requested_at: export_requested_at,
            expires_at: export_expires_at,
            metadata: BTreeMap::new(),
        })
        .await
        .expect("append tenant A export access grant");
    backend
        .upsert_trace_export_job(TraceExportJobWrite {
            tenant_id: tenant_a.clone(),
            export_job_id: tenant_a_export_job_id,
            grant_id: tenant_a_export_grant_id,
            caller_principal_ref: format!("principal:{tenant_a}:exporter"),
            requested_dataset_kind: "replay".to_string(),
            purpose: "raw-rls-export".to_string(),
            max_item_cap: Some(10),
            status: TraceExportJobStatus::Queued,
            requested_at: export_requested_at,
            started_at: None,
            finished_at: None,
            expires_at: export_expires_at,
            result_manifest_id: Some(tenant_a_export_manifest_id),
            item_count: Some(1),
            last_error: None,
            metadata: BTreeMap::new(),
        })
        .await
        .expect("append tenant A export job");
    let tenant_b_export_grant_id = Uuid::new_v4();
    let tenant_b_export_job_id = Uuid::new_v4();
    backend
        .upsert_trace_export_access_grant(TraceExportAccessGrantWrite {
            tenant_id: tenant_b.clone(),
            export_job_id: tenant_b_export_job_id,
            grant_id: tenant_b_export_grant_id,
            caller_principal_ref: format!("principal:{tenant_b}:exporter"),
            requested_dataset_kind: "benchmark".to_string(),
            purpose: "raw-rls-export".to_string(),
            max_item_cap: Some(10),
            status: TraceExportAccessGrantStatus::Active,
            requested_at: export_requested_at,
            expires_at: export_expires_at,
            metadata: BTreeMap::new(),
        })
        .await
        .expect("append tenant B export access grant");
    backend
        .upsert_trace_export_job(TraceExportJobWrite {
            tenant_id: tenant_b.clone(),
            export_job_id: tenant_b_export_job_id,
            grant_id: tenant_b_export_grant_id,
            caller_principal_ref: format!("principal:{tenant_b}:exporter"),
            requested_dataset_kind: "benchmark".to_string(),
            purpose: "raw-rls-export".to_string(),
            max_item_cap: Some(10),
            status: TraceExportJobStatus::Queued,
            requested_at: export_requested_at,
            started_at: None,
            finished_at: None,
            expires_at: export_expires_at,
            result_manifest_id: Some(tenant_b_export_manifest_id),
            item_count: Some(1),
            last_error: None,
            metadata: BTreeMap::new(),
        })
        .await
        .expect("append tenant B export job");

    let tenant_a_audit_event_id = Uuid::new_v4();
    backend
        .append_trace_audit_event(sample_raw_rls_audit_event(
            &tenant_a,
            tenant_a_submission_id,
            tenant_a_audit_event_id,
            "raw-a",
        ))
        .await
        .expect("append tenant A audit event");
    let tenant_b_audit_event_id = Uuid::new_v4();
    backend
        .append_trace_audit_event(sample_raw_rls_audit_event(
            &tenant_b,
            tenant_b_submission_id,
            tenant_b_audit_event_id,
            "raw-b",
        ))
        .await
        .expect("append tenant B audit event");

    let tenant_a_credit_event_id = Uuid::new_v4();
    backend
        .append_trace_credit_event(sample_credit_event(
            &tenant_a,
            tenant_a_submission_id,
            tenant_a_trace_id,
            tenant_a_credit_event_id,
        ))
        .await
        .expect("append tenant A credit event");
    let tenant_b_credit_event_id = Uuid::new_v4();
    backend
        .append_trace_credit_event(sample_credit_event(
            &tenant_b,
            tenant_b_submission_id,
            tenant_b_trace_id,
            tenant_b_credit_event_id,
        ))
        .await
        .expect("append tenant B credit event");

    let tenant_a_credit_control_ids = RawCreditControlPlaneIds {
        utility_attestation_id: Uuid::new_v4(),
        settlement_batch_id: Uuid::new_v4(),
        credit_hold_id: Uuid::new_v4(),
        near_outbox_id: Uuid::new_v4(),
        near_account_outbox_id: Uuid::new_v4(),
    };
    write_sample_credit_control_plane_rows(
        &backend,
        &tenant_a,
        tenant_a_submission_id,
        tenant_a_credit_event_id,
        tenant_a_credit_control_ids,
        "raw-a",
    )
    .await;
    let tenant_b_credit_control_ids = RawCreditControlPlaneIds {
        utility_attestation_id: Uuid::new_v4(),
        settlement_batch_id: Uuid::new_v4(),
        credit_hold_id: Uuid::new_v4(),
        near_outbox_id: Uuid::new_v4(),
        near_account_outbox_id: Uuid::new_v4(),
    };
    write_sample_credit_control_plane_rows(
        &backend,
        &tenant_b,
        tenant_b_submission_id,
        tenant_b_credit_event_id,
        tenant_b_credit_control_ids,
        "raw-b",
    )
    .await;

    let tenant_a_ranking_control_ids = RawRankingControlPlaneIds {
        secondary_submission_id: Uuid::new_v4(),
        secondary_trace_id: Uuid::new_v4(),
        ranking_feature_id: Uuid::new_v4(),
        ranking_prediction_id: Uuid::new_v4(),
        ranking_label_id: Uuid::new_v4(),
        preference_label_id: Uuid::new_v4(),
        calibration_run_id: Uuid::new_v4(),
        ranking_worker_run_id: Uuid::new_v4(),
        benchmark_outbox_id: Uuid::new_v4(),
        benchmark_conversion_id: Uuid::new_v4(),
    };
    write_sample_ranking_and_benchmark_control_plane_rows(
        &backend,
        &tenant_a,
        tenant_a_submission_id,
        tenant_a_trace_id,
        tenant_a_ranking_control_ids,
        "raw-a",
    )
    .await;
    let tenant_b_ranking_control_ids = RawRankingControlPlaneIds {
        secondary_submission_id: Uuid::new_v4(),
        secondary_trace_id: Uuid::new_v4(),
        ranking_feature_id: Uuid::new_v4(),
        ranking_prediction_id: Uuid::new_v4(),
        ranking_label_id: Uuid::new_v4(),
        preference_label_id: Uuid::new_v4(),
        calibration_run_id: Uuid::new_v4(),
        ranking_worker_run_id: Uuid::new_v4(),
        benchmark_outbox_id: Uuid::new_v4(),
        benchmark_conversion_id: Uuid::new_v4(),
    };
    write_sample_ranking_and_benchmark_control_plane_rows(
        &backend,
        &tenant_b,
        tenant_b_submission_id,
        tenant_b_trace_id,
        tenant_b_ranking_control_ids,
        "raw-b",
    )
    .await;

    let effective_at = DateTime::parse_from_rfc3339("2026-04-25T12:00:00Z")
        .expect("parse effective timestamp")
        .with_timezone(&Utc);
    let tenant_a_tombstone_id = Uuid::new_v4();
    backend
        .write_trace_tombstone(TraceTombstoneWrite {
            tombstone_id: tenant_a_tombstone_id,
            tenant_id: tenant_a.clone(),
            submission_id: tenant_a_submission_id,
            trace_id: Some(tenant_a_trace_id),
            redaction_hash: Some(format!("sha256:{tenant_a}:redaction")),
            canonical_summary_hash: Some(format!("sha256:{tenant_a}:summary")),
            reason: "tenant A revocation".to_string(),
            effective_at,
            retain_until: None,
            created_by_principal_ref: format!("principal:{tenant_a}"),
        })
        .await
        .expect("write tenant A tombstone");
    let tenant_b_tombstone_id = Uuid::new_v4();
    backend
        .write_trace_tombstone(TraceTombstoneWrite {
            tombstone_id: tenant_b_tombstone_id,
            tenant_id: tenant_b.clone(),
            submission_id: tenant_b_submission_id,
            trace_id: Some(tenant_b_trace_id),
            redaction_hash: Some(format!("sha256:{tenant_b}:redaction")),
            canonical_summary_hash: Some(format!("sha256:{tenant_b}:summary")),
            reason: "tenant B revocation".to_string(),
            effective_at,
            retain_until: None,
            created_by_principal_ref: format!("principal:{tenant_b}"),
        })
        .await
        .expect("write tenant B tombstone");

    let mut tenant_a_retention_action_counts = BTreeMap::new();
    tenant_a_retention_action_counts.insert("records_marked_expired".to_string(), 1);
    let tenant_a_retention_job_id = Uuid::new_v4();
    backend
        .upsert_trace_retention_job(TraceRetentionJobWrite {
            tenant_id: tenant_a.clone(),
            retention_job_id: tenant_a_retention_job_id,
            purpose: "rls_retention_a".to_string(),
            dry_run: false,
            status: TraceRetentionJobStatus::Complete,
            requested_by_principal_ref: format!("principal:{tenant_a}"),
            requested_by_role: "retention_worker".to_string(),
            purge_expired_before: Some(effective_at),
            prune_export_cache: true,
            max_export_age_hours: Some(24),
            audit_event_id: Some(Uuid::new_v4()),
            action_counts: tenant_a_retention_action_counts,
            selected_revoked_count: 0,
            selected_expired_count: 1,
            started_at: Some(effective_at),
            completed_at: Some(effective_at),
        })
        .await
        .expect("write tenant A retention job");
    let mut tenant_a_retention_item_counts = BTreeMap::new();
    tenant_a_retention_item_counts.insert("records_marked_expired".to_string(), 1);
    backend
        .upsert_trace_retention_job_item(TraceRetentionJobItemWrite {
            tenant_id: tenant_a.clone(),
            retention_job_id: tenant_a_retention_job_id,
            submission_id: tenant_a_submission_id,
            action: TraceRetentionJobItemAction::Expire,
            status: TraceRetentionJobItemStatus::Done,
            reason: "retention_expired".to_string(),
            action_counts: tenant_a_retention_item_counts,
            verified_at: Some(effective_at),
        })
        .await
        .expect("write tenant A retention job item");

    let mut tenant_b_retention_action_counts = BTreeMap::new();
    tenant_b_retention_action_counts.insert("records_marked_purged".to_string(), 1);
    let tenant_b_retention_job_id = Uuid::new_v4();
    backend
        .upsert_trace_retention_job(TraceRetentionJobWrite {
            tenant_id: tenant_b.clone(),
            retention_job_id: tenant_b_retention_job_id,
            purpose: "rls_retention_b".to_string(),
            dry_run: false,
            status: TraceRetentionJobStatus::Complete,
            requested_by_principal_ref: format!("principal:{tenant_b}"),
            requested_by_role: "retention_worker".to_string(),
            purge_expired_before: Some(effective_at),
            prune_export_cache: true,
            max_export_age_hours: Some(24),
            audit_event_id: Some(Uuid::new_v4()),
            action_counts: tenant_b_retention_action_counts,
            selected_revoked_count: 0,
            selected_expired_count: 1,
            started_at: Some(effective_at),
            completed_at: Some(effective_at),
        })
        .await
        .expect("write tenant B retention job");
    let mut tenant_b_retention_item_counts = BTreeMap::new();
    tenant_b_retention_item_counts.insert("records_marked_purged".to_string(), 1);
    backend
        .upsert_trace_retention_job_item(TraceRetentionJobItemWrite {
            tenant_id: tenant_b.clone(),
            retention_job_id: tenant_b_retention_job_id,
            submission_id: tenant_b_submission_id,
            action: TraceRetentionJobItemAction::Purge,
            status: TraceRetentionJobItemStatus::Done,
            reason: "retention_purged".to_string(),
            action_counts: tenant_b_retention_item_counts,
            verified_at: Some(effective_at),
        })
        .await
        .expect("write tenant B retention job item");

    let tenant_a_propagation_item_id = Uuid::new_v4();
    backend
        .upsert_trace_revocation_propagation_item(sample_revocation_propagation_item(
            &tenant_a,
            tenant_a_submission_id,
            tenant_a_propagation_item_id,
            TraceRevocationPropagationTarget::ObjectRef {
                object_ref_id: tenant_a_object_ref_id,
            },
            "raw-a:object-ref",
        ))
        .await
        .expect("write tenant A revocation propagation item");
    let tenant_b_propagation_item_id = Uuid::new_v4();
    backend
        .upsert_trace_revocation_propagation_item(sample_revocation_propagation_item(
            &tenant_b,
            tenant_b_submission_id,
            tenant_b_propagation_item_id,
            TraceRevocationPropagationTarget::ExportManifestItem {
                export_manifest_id: tenant_b_export_manifest_id,
                source_submission_id: tenant_b_submission_id,
            },
            "raw-b:export-item",
        ))
        .await
        .expect("write tenant B revocation propagation item");

    assert!(
        backend
            .get_trace_submission(&tenant_b, tenant_a_submission_id)
            .await
            .expect("tenant B probes tenant A submission")
            .is_none()
    );
    assert!(
        backend
            .list_trace_object_refs(&tenant_b, tenant_a_submission_id)
            .await
            .expect("tenant B probes tenant A object refs")
            .is_empty()
    );

    let tenant_b_credit_events = backend
        .list_trace_credit_events(&tenant_b)
        .await
        .expect("list tenant B credit events");
    assert_eq!(tenant_b_credit_events.len(), 1);
    assert_eq!(
        tenant_b_credit_events[0].credit_event_id,
        tenant_b_credit_event_id
    );
    assert_ne!(
        tenant_b_credit_events[0].credit_event_id,
        tenant_a_credit_event_id
    );

    let tenant_b_tombstones = backend
        .list_trace_tombstones(&tenant_b)
        .await
        .expect("list tenant B tombstones");
    assert_eq!(tenant_b_tombstones.len(), 1);
    assert_eq!(tenant_b_tombstones[0].tombstone_id, tenant_b_tombstone_id);
    assert_ne!(tenant_b_tombstones[0].tombstone_id, tenant_a_tombstone_id);

    if let Some(config) = postgres_test_config() {
        assert_raw_sql_tenants_visible_only_with_matching_tenant_context(
            config.url.expose_secret(),
            &tenant_a,
            &tenant_b,
        )
        .await;
        assert_raw_sql_trace_rows_visible_only_with_matching_tenant_context(
            config.url.expose_secret(),
            &tenant_a,
            &tenant_b,
            RawTraceRlsIds {
                submission_id: tenant_a_submission_id,
                object_ref_id: tenant_a_object_ref_id,
                derived_id: tenant_a_derived_id,
                vector_entry_id: tenant_a_vector_entry_id,
                export_manifest_id: tenant_a_export_manifest_id,
                export_access_grant_id: tenant_a_export_grant_id,
                export_job_id: tenant_a_export_job_id,
                audit_event_id: tenant_a_audit_event_id,
                credit_event_id: tenant_a_credit_event_id,
                utility_attestation_id: tenant_a_credit_control_ids.utility_attestation_id,
                settlement_batch_id: tenant_a_credit_control_ids.settlement_batch_id,
                credit_hold_id: tenant_a_credit_control_ids.credit_hold_id,
                near_outbox_id: tenant_a_credit_control_ids.near_outbox_id,
                near_account_outbox_id: tenant_a_credit_control_ids.near_account_outbox_id,
                ranking_feature_id: tenant_a_ranking_control_ids.ranking_feature_id,
                ranking_prediction_id: tenant_a_ranking_control_ids.ranking_prediction_id,
                ranking_label_id: tenant_a_ranking_control_ids.ranking_label_id,
                preference_label_id: tenant_a_ranking_control_ids.preference_label_id,
                calibration_run_id: tenant_a_ranking_control_ids.calibration_run_id,
                ranking_worker_run_id: tenant_a_ranking_control_ids.ranking_worker_run_id,
                benchmark_outbox_id: tenant_a_ranking_control_ids.benchmark_outbox_id,
                tombstone_id: tenant_a_tombstone_id,
                retention_job_id: tenant_a_retention_job_id,
                propagation_item_id: tenant_a_propagation_item_id,
            },
            RawTraceRlsIds {
                submission_id: tenant_b_submission_id,
                object_ref_id: tenant_b_object_ref_id,
                derived_id: tenant_b_derived_id,
                vector_entry_id: tenant_b_vector_entry_id,
                export_manifest_id: tenant_b_export_manifest_id,
                export_access_grant_id: tenant_b_export_grant_id,
                export_job_id: tenant_b_export_job_id,
                audit_event_id: tenant_b_audit_event_id,
                credit_event_id: tenant_b_credit_event_id,
                utility_attestation_id: tenant_b_credit_control_ids.utility_attestation_id,
                settlement_batch_id: tenant_b_credit_control_ids.settlement_batch_id,
                credit_hold_id: tenant_b_credit_control_ids.credit_hold_id,
                near_outbox_id: tenant_b_credit_control_ids.near_outbox_id,
                near_account_outbox_id: tenant_b_credit_control_ids.near_account_outbox_id,
                ranking_feature_id: tenant_b_ranking_control_ids.ranking_feature_id,
                ranking_prediction_id: tenant_b_ranking_control_ids.ranking_prediction_id,
                ranking_label_id: tenant_b_ranking_control_ids.ranking_label_id,
                preference_label_id: tenant_b_ranking_control_ids.preference_label_id,
                calibration_run_id: tenant_b_ranking_control_ids.calibration_run_id,
                ranking_worker_run_id: tenant_b_ranking_control_ids.ranking_worker_run_id,
                benchmark_outbox_id: tenant_b_ranking_control_ids.benchmark_outbox_id,
                tombstone_id: tenant_b_tombstone_id,
                retention_job_id: tenant_b_retention_job_id,
                propagation_item_id: tenant_b_propagation_item_id,
            },
        )
        .await;
    }

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in [&tenant_a, &tenant_b] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn pg_trace_corpus_rls_diagnostics_report_policy_coverage() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let diagnostics = backend
        .trace_corpus_rls_diagnostics()
        .await
        .expect("read RLS diagnostics")
        .expect("PostgreSQL reports RLS diagnostics");
    assert_eq!(
        diagnostics.expected_table_count,
        expected_trace_rls_tables().len()
    );
    assert_eq!(
        diagnostics.policy_installed_count,
        diagnostics.expected_table_count
    );
    assert_eq!(
        diagnostics.rls_enabled_count,
        diagnostics.expected_table_count
    );
    assert!(diagnostics.missing_policy_tables.is_empty());
    assert!(diagnostics.rls_disabled_tables.is_empty());
    assert!(diagnostics.policy_expression_mismatch_tables.is_empty());
    assert_eq!(
        diagnostics.force_rls_enabled_count,
        diagnostics.expected_table_count
    );
    assert!(diagnostics.force_rls_disabled_tables.is_empty());
    assert!(diagnostics.force_rls_ready());
    assert_eq!(
        diagnostics.production_ready(),
        diagnostics.rls_ready() && diagnostics.force_rls_ready()
    );
    assert_eq!(
        diagnostics.rls_ready(),
        !diagnostics.current_role_bypasses_rls && !diagnostics.current_role_owns_trace_tables,
        "RLS readiness should be blocked only by runtime-role safety once catalog coverage is complete"
    );
}

#[tokio::test]
async fn store_facade_invalidates_object_refs_and_tombstones_by_tenant_scope() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_a = format!("rls-objects-a-{}", Uuid::new_v4());
    let tenant_b = format!("rls-objects-b-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();

    let inserted_a = backend
        .upsert_trace_submission(sample_submission(&tenant_a, submission_id))
        .await
        .expect("insert tenant A submission");
    let inserted_b = backend
        .upsert_trace_submission(sample_submission(&tenant_b, submission_id))
        .await
        .expect("insert tenant B submission");

    let tenant_a_first_object_ref_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_a.clone(),
            object_ref_id: tenant_a_first_object_ref_id,
            submission_id,
            artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_a}/submission.json"),
            content_sha256: format!("sha256:{tenant_a}:object-1"),
            encryption_key_ref: format!("kms:{tenant_a}"),
            size_bytes: 4096,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("append tenant A first object ref");

    sleep(Duration::from_millis(5)).await;

    let tenant_a_latest_object_ref_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_a.clone(),
            object_ref_id: tenant_a_latest_object_ref_id,
            submission_id,
            artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_a}/submission-v2.json"),
            content_sha256: format!("sha256:{tenant_a}:object-2"),
            encryption_key_ref: format!("kms:{tenant_a}"),
            size_bytes: 8192,
            compression: Some("zstd".to_string()),
            created_by_job_id: Some(Uuid::new_v4()),
        })
        .await
        .expect("append tenant A latest object ref");

    let tenant_b_object_ref_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_b.clone(),
            object_ref_id: tenant_b_object_ref_id,
            submission_id,
            artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_b}/submission.json"),
            content_sha256: format!("sha256:{tenant_b}:object"),
            encryption_key_ref: format!("kms:{tenant_b}"),
            size_bytes: 2048,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("append tenant B object ref");

    let tenant_a_latest = backend
        .get_latest_active_trace_object_ref(
            &tenant_a,
            submission_id,
            TraceObjectArtifactKind::SubmittedEnvelope,
        )
        .await
        .expect("get tenant A latest active object ref")
        .expect("tenant A latest active object ref exists");
    assert_eq!(tenant_a_latest.object_ref_id, tenant_a_latest_object_ref_id);
    assert_eq!(
        tenant_a_latest.object_key,
        format!("{tenant_a}/submission-v2.json")
    );

    let tenant_b_latest = backend
        .get_latest_active_trace_object_ref(
            &tenant_b,
            submission_id,
            TraceObjectArtifactKind::SubmittedEnvelope,
        )
        .await
        .expect("get tenant B latest active object ref")
        .expect("tenant B latest active object ref exists");
    assert_eq!(tenant_b_latest.object_ref_id, tenant_b_object_ref_id);
    assert_eq!(
        tenant_b_latest.object_key,
        format!("{tenant_b}/submission.json")
    );

    let tenant_a_derived_id = Uuid::new_v4();
    backend
        .append_trace_derived_record(TraceDerivedRecordWrite {
            tenant_id: tenant_a.clone(),
            derived_id: tenant_a_derived_id,
            submission_id,
            trace_id: inserted_a.trace_id,
            status: TraceDerivedStatus::Current,
            worker_kind: TraceWorkerKind::DuplicatePrecheck,
            worker_version: "duplicate-worker-v1".to_string(),
            input_object_ref: Some(TenantScopedTraceObjectRef {
                tenant_id: tenant_a.clone(),
                submission_id,
                object_ref_id: tenant_a_first_object_ref_id,
            }),
            input_hash: format!("sha256:{tenant_a}:object-1"),
            output_object_ref: None,
            canonical_summary: Some("Tenant A canonical summary.".to_string()),
            canonical_summary_hash: Some(format!("sha256:{tenant_a}:summary")),
            summary_model: "summary-model-v1".to_string(),
            task_success: Some("success".to_string()),
            privacy_risk: Some("low".to_string()),
            event_count: Some(3),
            tool_sequence: vec!["calendar_create".to_string()],
            tool_categories: vec!["calendar".to_string()],
            coverage_tags: vec!["tool:calendar_create".to_string()],
            duplicate_score: Some(0.1),
            novelty_score: Some(0.7),
            cluster_id: Some(format!("cluster:{tenant_a}")),
        })
        .await
        .expect("append tenant A derived record");

    let tenant_b_derived_id = Uuid::new_v4();
    backend
        .append_trace_derived_record(TraceDerivedRecordWrite {
            tenant_id: tenant_b.clone(),
            derived_id: tenant_b_derived_id,
            submission_id,
            trace_id: inserted_b.trace_id,
            status: TraceDerivedStatus::Current,
            worker_kind: TraceWorkerKind::DuplicatePrecheck,
            worker_version: "duplicate-worker-v1".to_string(),
            input_object_ref: Some(TenantScopedTraceObjectRef {
                tenant_id: tenant_b.clone(),
                submission_id,
                object_ref_id: tenant_b_object_ref_id,
            }),
            input_hash: format!("sha256:{tenant_b}:object"),
            output_object_ref: None,
            canonical_summary: Some("Tenant B canonical summary.".to_string()),
            canonical_summary_hash: Some(format!("sha256:{tenant_b}:summary")),
            summary_model: "summary-model-v1".to_string(),
            task_success: Some("success".to_string()),
            privacy_risk: Some("low".to_string()),
            event_count: Some(2),
            tool_sequence: vec!["memory_search".to_string()],
            tool_categories: vec!["memory".to_string()],
            coverage_tags: vec!["tool:memory_search".to_string()],
            duplicate_score: Some(0.2),
            novelty_score: Some(0.5),
            cluster_id: Some(format!("cluster:{tenant_b}")),
        })
        .await
        .expect("append tenant B derived record");

    let invalidated = backend
        .invalidate_trace_submission_artifacts(
            &tenant_a,
            submission_id,
            TraceDerivedStatus::Revoked,
        )
        .await
        .expect("invalidate tenant A artifacts");
    assert_eq!(invalidated.object_refs_invalidated, 2);
    assert_eq!(invalidated.derived_records_invalidated, 1);

    let idempotent = backend
        .invalidate_trace_submission_artifacts(
            &tenant_a,
            submission_id,
            TraceDerivedStatus::Revoked,
        )
        .await
        .expect("repeat tenant A artifact invalidation");
    assert_eq!(idempotent.object_refs_invalidated, 0);
    assert_eq!(idempotent.derived_records_invalidated, 0);

    assert!(
        backend
            .get_latest_active_trace_object_ref(
                &tenant_a,
                submission_id,
                TraceObjectArtifactKind::SubmittedEnvelope,
            )
            .await
            .expect("get tenant A active object ref after invalidation")
            .is_none()
    );

    let tenant_a_object_refs = backend
        .list_trace_object_refs(&tenant_a, submission_id)
        .await
        .expect("list tenant A object refs after invalidation");
    assert_eq!(tenant_a_object_refs.len(), 2);
    assert!(
        tenant_a_object_refs
            .iter()
            .all(|object_ref| object_ref.invalidated_at.is_some())
    );
    assert!(
        tenant_a_object_refs
            .iter()
            .all(|object_ref| object_ref.deleted_at.is_none())
    );
    let deleted_count = backend
        .mark_trace_object_ref_deleted(
            &tenant_a,
            submission_id,
            "s3://private-corpus",
            &format!("{tenant_a}/submission.json"),
        )
        .await
        .expect("mark tenant A exact object ref deleted");
    assert_eq!(deleted_count, 1);
    let tenant_a_object_refs_after_delete = backend
        .list_trace_object_refs(&tenant_a, submission_id)
        .await
        .expect("list tenant A object refs after exact delete");
    let deleted_ref = tenant_a_object_refs_after_delete
        .iter()
        .find(|object_ref| object_ref.object_ref_id == tenant_a_first_object_ref_id)
        .expect("tenant A deleted object ref remains listed");
    assert!(deleted_ref.deleted_at.is_some());
    let untouched_ref = tenant_a_object_refs_after_delete
        .iter()
        .find(|object_ref| object_ref.object_ref_id == tenant_a_latest_object_ref_id)
        .expect("tenant A untouched object ref remains listed");
    assert!(untouched_ref.deleted_at.is_none());
    let idempotent_delete = backend
        .mark_trace_object_ref_deleted(
            &tenant_a,
            submission_id,
            "s3://private-corpus",
            &format!("{tenant_a}/submission.json"),
        )
        .await
        .expect("repeat tenant A exact object ref delete");
    assert_eq!(idempotent_delete, 0);

    let tenant_b_still_active = backend
        .get_latest_active_trace_object_ref(
            &tenant_b,
            submission_id,
            TraceObjectArtifactKind::SubmittedEnvelope,
        )
        .await
        .expect("get tenant B active object ref after tenant A invalidation")
        .expect("tenant B object ref remains active");
    assert_eq!(tenant_b_still_active.object_ref_id, tenant_b_object_ref_id);

    let tenant_a_records = backend
        .list_trace_derived_records(&tenant_a)
        .await
        .expect("list tenant A derived records");
    assert_eq!(tenant_a_records.len(), 1);
    assert_eq!(tenant_a_records[0].status, TraceDerivedStatus::Revoked);

    let tenant_b_records = backend
        .list_trace_derived_records(&tenant_b)
        .await
        .expect("list tenant B derived records");
    assert_eq!(tenant_b_records.len(), 1);
    assert_eq!(tenant_b_records[0].status, TraceDerivedStatus::Current);

    let effective_at = DateTime::parse_from_rfc3339("2026-04-25T12:00:00Z")
        .expect("parse effective timestamp")
        .with_timezone(&Utc);
    let retain_until = DateTime::parse_from_rfc3339("2026-05-25T12:00:00Z")
        .expect("parse retain-until timestamp")
        .with_timezone(&Utc);
    let tombstone_id = Uuid::new_v4();
    backend
        .write_trace_tombstone(TraceTombstoneWrite {
            tombstone_id,
            tenant_id: tenant_a.clone(),
            submission_id,
            trace_id: Some(inserted_a.trace_id),
            redaction_hash: Some(format!("sha256:{tenant_a}:redaction")),
            canonical_summary_hash: Some(format!("sha256:{tenant_a}:summary")),
            reason: "user requested revocation".to_string(),
            effective_at,
            retain_until: Some(retain_until),
            created_by_principal_ref: format!("principal:{tenant_a}"),
        })
        .await
        .expect("write tenant A tombstone");

    backend
        .write_trace_tombstone(TraceTombstoneWrite {
            tombstone_id: Uuid::new_v4(),
            tenant_id: tenant_a.clone(),
            submission_id,
            trace_id: Some(inserted_a.trace_id),
            redaction_hash: Some(format!("sha256:{tenant_a}:later-redaction")),
            canonical_summary_hash: Some(format!("sha256:{tenant_a}:later-summary")),
            reason: "later duplicate revocation".to_string(),
            effective_at: Utc::now(),
            retain_until: None,
            created_by_principal_ref: format!("principal:{tenant_a}:later"),
        })
        .await
        .expect("repeat tenant A tombstone write is idempotent");

    backend
        .write_trace_tombstone(TraceTombstoneWrite {
            tombstone_id: Uuid::new_v4(),
            tenant_id: tenant_b.clone(),
            submission_id,
            trace_id: Some(inserted_b.trace_id),
            redaction_hash: Some(format!("sha256:{tenant_b}:redaction")),
            canonical_summary_hash: Some(format!("sha256:{tenant_b}:summary")),
            reason: "other tenant revocation".to_string(),
            effective_at,
            retain_until: None,
            created_by_principal_ref: format!("principal:{tenant_b}"),
        })
        .await
        .expect("write tenant B tombstone");

    let tenant_a_tombstones = backend
        .list_trace_tombstones(&tenant_a)
        .await
        .expect("list tenant A tombstones");
    assert_eq!(tenant_a_tombstones.len(), 1);
    assert_eq!(tenant_a_tombstones[0].tombstone_id, tombstone_id);
    assert_eq!(tenant_a_tombstones[0].tenant_id, tenant_a);
    assert_eq!(tenant_a_tombstones[0].trace_id, Some(inserted_a.trace_id));
    assert_eq!(tenant_a_tombstones[0].reason, "user requested revocation");
    assert_eq!(tenant_a_tombstones[0].retain_until, Some(retain_until));

    let tenant_b_tombstones = backend
        .list_trace_tombstones(&tenant_b)
        .await
        .expect("list tenant B tombstones");
    assert_eq!(tenant_b_tombstones.len(), 1);
    assert_eq!(tenant_b_tombstones[0].tenant_id, tenant_b);
    assert_eq!(tenant_b_tombstones[0].trace_id, Some(inserted_b.trace_id));
    assert_eq!(tenant_b_tombstones[0].reason, "other tenant revocation");

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in [&tenant_a, &tenant_b] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn store_facade_invalidates_export_manifests_by_submission_with_tenant_scope() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let submission_id = Uuid::new_v4();
    backend
        .upsert_trace_submission(sample_submission("tenant-alpha", submission_id))
        .await
        .expect("insert alpha submission");
    backend
        .upsert_trace_submission(sample_submission("tenant-beta", submission_id))
        .await
        .expect("insert beta submission");

    let alpha_export_id = Uuid::new_v4();
    let beta_export_id = Uuid::new_v4();
    backend
        .upsert_trace_export_manifest(TraceExportManifestWrite {
            tenant_id: "tenant-alpha".to_string(),
            export_manifest_id: alpha_export_id,
            artifact_kind: TraceObjectArtifactKind::ExportArtifact,
            purpose_code: Some("ranking_dataset".to_string()),
            audit_event_id: Some(Uuid::new_v4()),
            source_submission_ids: vec![submission_id],
            source_submission_ids_hash: "sha256:alpha-sources".to_string(),
            item_count: 1,
            generated_at: Utc::now(),
        })
        .await
        .expect("insert alpha export manifest");
    backend
        .upsert_trace_export_manifest(TraceExportManifestWrite {
            tenant_id: "tenant-beta".to_string(),
            export_manifest_id: beta_export_id,
            artifact_kind: TraceObjectArtifactKind::ExportArtifact,
            purpose_code: Some("ranking_dataset".to_string()),
            audit_event_id: Some(Uuid::new_v4()),
            source_submission_ids: vec![submission_id],
            source_submission_ids_hash: "sha256:beta-sources".to_string(),
            item_count: 1,
            generated_at: Utc::now(),
        })
        .await
        .expect("insert beta export manifest");

    let invalidated = backend
        .invalidate_trace_export_manifests_for_submission("tenant-alpha", submission_id)
        .await
        .expect("invalidate alpha export manifest");
    assert_eq!(invalidated, 1);

    let idempotent = backend
        .invalidate_trace_export_manifests_for_submission("tenant-alpha", submission_id)
        .await
        .expect("repeat export manifest invalidation");
    assert_eq!(idempotent, 0);

    let alpha_manifests = backend
        .list_trace_export_manifests("tenant-alpha")
        .await
        .expect("list alpha export manifests");
    let alpha_manifest = alpha_manifests
        .iter()
        .find(|manifest| manifest.export_manifest_id == alpha_export_id)
        .expect("alpha export manifest exists");
    assert!(alpha_manifest.invalidated_at.is_some());
    assert!(alpha_manifest.deleted_at.is_none());

    let beta_manifests = backend
        .list_trace_export_manifests("tenant-beta")
        .await
        .expect("list beta export manifests");
    let beta_manifest = beta_manifests
        .iter()
        .find(|manifest| manifest.export_manifest_id == beta_export_id)
        .expect("beta export manifest exists");
    assert!(beta_manifest.invalidated_at.is_none());
    assert!(beta_manifest.deleted_at.is_none());

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for (tenant_id, export_manifest_id) in [
        ("tenant-alpha", alpha_export_id),
        ("tenant-beta", beta_export_id),
    ] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_export_manifests
                 WHERE tenant_id = $1 AND export_manifest_id = $2",
                &[&tenant_id, &export_manifest_id],
            )
            .await;
        let _ = tx
            .execute(
                "DELETE FROM trace_submissions
                 WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn store_facade_invalidates_export_manifest_items_by_submission_with_tenant_scope() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_a = format!("rls-export-items-a-{}", Uuid::new_v4());
    let tenant_b = format!("rls-export-items-b-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();
    let trace_id = Uuid::new_v4();

    let mut tenant_a_submission = sample_submission(&tenant_a, submission_id);
    tenant_a_submission.trace_id = trace_id;
    backend
        .upsert_trace_submission(tenant_a_submission)
        .await
        .expect("insert tenant A submission");
    let mut tenant_b_submission = sample_submission(&tenant_b, submission_id);
    tenant_b_submission.trace_id = trace_id;
    backend
        .upsert_trace_submission(tenant_b_submission)
        .await
        .expect("insert tenant B submission");

    let tenant_a_export_id = Uuid::new_v4();
    let tenant_b_export_id = Uuid::new_v4();
    backend
        .upsert_trace_export_manifest(TraceExportManifestWrite {
            tenant_id: tenant_a.clone(),
            export_manifest_id: tenant_a_export_id,
            artifact_kind: TraceObjectArtifactKind::ExportArtifact,
            purpose_code: Some("replay_dataset".to_string()),
            audit_event_id: Some(Uuid::new_v4()),
            source_submission_ids: vec![submission_id],
            source_submission_ids_hash: format!("sha256:{tenant_a}:sources"),
            item_count: 1,
            generated_at: Utc::now(),
        })
        .await
        .expect("insert tenant A manifest");
    backend
        .upsert_trace_export_manifest(TraceExportManifestWrite {
            tenant_id: tenant_b.clone(),
            export_manifest_id: tenant_b_export_id,
            artifact_kind: TraceObjectArtifactKind::ExportArtifact,
            purpose_code: Some("replay_dataset".to_string()),
            audit_event_id: Some(Uuid::new_v4()),
            source_submission_ids: vec![submission_id],
            source_submission_ids_hash: format!("sha256:{tenant_b}:sources"),
            item_count: 1,
            generated_at: Utc::now(),
        })
        .await
        .expect("insert tenant B manifest");

    let tenant_a_object_ref_id = Uuid::new_v4();
    let tenant_a_derived_id = Uuid::new_v4();
    let tenant_a_vector_entry_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_a.clone(),
            object_ref_id: tenant_a_object_ref_id,
            submission_id,
            artifact_kind: TraceObjectArtifactKind::WorkerIntermediate,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_a}/worker/summary.json"),
            content_sha256: format!("sha256:{tenant_a}:object"),
            encryption_key_ref: format!("kms:{tenant_a}"),
            size_bytes: 128,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("insert tenant A object ref");
    backend
        .append_trace_derived_record(TraceDerivedRecordWrite {
            tenant_id: tenant_a.clone(),
            derived_id: tenant_a_derived_id,
            submission_id,
            trace_id,
            status: TraceDerivedStatus::Current,
            worker_kind: TraceWorkerKind::Summary,
            worker_version: "summary-worker-v1".to_string(),
            input_object_ref: Some(TenantScopedTraceObjectRef {
                tenant_id: tenant_a.clone(),
                submission_id,
                object_ref_id: tenant_a_object_ref_id,
            }),
            input_hash: format!("sha256:{tenant_a}:object"),
            output_object_ref: None,
            canonical_summary: Some("Tenant A summary.".to_string()),
            canonical_summary_hash: Some(format!("sha256:{tenant_a}:summary")),
            summary_model: "summary-model-v1".to_string(),
            task_success: Some("success".to_string()),
            privacy_risk: Some("low".to_string()),
            event_count: Some(2),
            tool_sequence: vec!["memory_search".to_string()],
            tool_categories: vec!["memory".to_string()],
            coverage_tags: vec!["tool:memory_search".to_string()],
            duplicate_score: Some(0.1),
            novelty_score: Some(0.4),
            cluster_id: Some(format!("cluster:{tenant_a}")),
        })
        .await
        .expect("insert tenant A derived record");
    backend
        .upsert_trace_vector_entry(TraceVectorEntryWrite {
            tenant_id: tenant_a.clone(),
            submission_id,
            derived_id: tenant_a_derived_id,
            vector_entry_id: tenant_a_vector_entry_id,
            vector_store: "trace-commons-main".to_string(),
            embedding_model: "text-embedding-3-small".to_string(),
            embedding_dimension: 1536,
            embedding_version: "embedding-v1".to_string(),
            source_projection: TraceVectorEntrySourceProjection::CanonicalSummary,
            source_hash: format!("sha256:{tenant_a}:summary"),
            status: TraceVectorEntryStatus::Active,
            nearest_trace_ids: Vec::new(),
            cluster_id: Some(format!("cluster:{tenant_a}")),
            duplicate_score: Some(0.1),
            novelty_score: Some(0.4),
            indexed_at: Some(Utc::now()),
            invalidated_at: None,
            deleted_at: None,
        })
        .await
        .expect("insert tenant A vector entry");

    backend
        .upsert_trace_export_manifest_item(TraceExportManifestItemWrite {
            tenant_id: tenant_a.clone(),
            export_manifest_id: tenant_a_export_id,
            submission_id,
            trace_id,
            derived_id: Some(tenant_a_derived_id),
            object_ref_id: Some(tenant_a_object_ref_id),
            vector_entry_id: Some(tenant_a_vector_entry_id),
            source_status_at_export: TraceCorpusStatus::Accepted,
            source_hash_at_export: format!("sha256:{tenant_a}:source"),
        })
        .await
        .expect("insert tenant A manifest item");
    backend
        .upsert_trace_export_manifest_item(TraceExportManifestItemWrite {
            tenant_id: tenant_b.clone(),
            export_manifest_id: tenant_b_export_id,
            submission_id,
            trace_id,
            derived_id: None,
            object_ref_id: None,
            vector_entry_id: None,
            source_status_at_export: TraceCorpusStatus::Accepted,
            source_hash_at_export: format!("sha256:{tenant_b}:source"),
        })
        .await
        .expect("insert tenant B manifest item");

    let tenant_a_items = backend
        .list_trace_export_manifest_items(&tenant_a, tenant_a_export_id)
        .await
        .expect("list tenant A manifest items");
    assert_eq!(tenant_a_items.len(), 1);
    assert_eq!(tenant_a_items[0].tenant_id, tenant_a);
    assert_eq!(tenant_a_items[0].export_manifest_id, tenant_a_export_id);
    assert_eq!(tenant_a_items[0].submission_id, submission_id);
    assert_eq!(tenant_a_items[0].trace_id, trace_id);
    assert_eq!(
        tenant_a_items[0].source_status_at_export,
        TraceCorpusStatus::Accepted
    );
    assert_eq!(
        tenant_a_items[0].source_hash_at_export,
        format!("sha256:{tenant_a}:source")
    );
    assert!(tenant_a_items[0].derived_id.is_some());
    assert!(tenant_a_items[0].object_ref_id.is_some());
    assert!(tenant_a_items[0].vector_entry_id.is_some());
    assert!(tenant_a_items[0].source_invalidated_at.is_none());
    assert!(tenant_a_items[0].source_invalidation_reason.is_none());

    let invalidated = backend
        .invalidate_trace_export_manifest_items_for_submission(
            &tenant_a,
            submission_id,
            TraceExportManifestItemInvalidationReason::Revoked,
        )
        .await
        .expect("invalidate tenant A manifest item");
    assert_eq!(invalidated, 1);
    let idempotent = backend
        .invalidate_trace_export_manifest_items_for_submission(
            &tenant_a,
            submission_id,
            TraceExportManifestItemInvalidationReason::Revoked,
        )
        .await
        .expect("repeat tenant A manifest item invalidation");
    assert_eq!(idempotent, 0);

    let tenant_a_items = backend
        .list_trace_export_manifest_items(&tenant_a, tenant_a_export_id)
        .await
        .expect("list invalidated tenant A manifest items");
    assert!(tenant_a_items[0].source_invalidated_at.is_some());
    assert_eq!(
        tenant_a_items[0].source_invalidation_reason,
        Some(TraceExportManifestItemInvalidationReason::Revoked)
    );

    let tenant_b_items = backend
        .list_trace_export_manifest_items(&tenant_b, tenant_b_export_id)
        .await
        .expect("list tenant B manifest items");
    assert_eq!(tenant_b_items.len(), 1);
    assert_eq!(tenant_b_items[0].tenant_id, tenant_b);
    assert_eq!(tenant_b_items[0].submission_id, submission_id);
    assert!(tenant_b_items[0].source_invalidated_at.is_none());
    assert!(tenant_b_items[0].source_invalidation_reason.is_none());

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in [&tenant_a, &tenant_b] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn store_facade_rejects_export_manifest_item_cross_tenant_refs() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_a = format!("rls-export-ref-a-{}", Uuid::new_v4());
    let tenant_b = format!("rls-export-ref-b-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();
    let trace_id = Uuid::new_v4();

    let mut tenant_a_submission = sample_submission(&tenant_a, submission_id);
    tenant_a_submission.trace_id = trace_id;
    backend
        .upsert_trace_submission(tenant_a_submission)
        .await
        .expect("insert tenant A submission");
    let mut tenant_b_submission = sample_submission(&tenant_b, submission_id);
    tenant_b_submission.trace_id = trace_id;
    backend
        .upsert_trace_submission(tenant_b_submission)
        .await
        .expect("insert tenant B submission");

    let tenant_b_object_ref_id = Uuid::new_v4();
    let tenant_b_derived_id = Uuid::new_v4();
    let tenant_b_vector_entry_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_b.clone(),
            object_ref_id: tenant_b_object_ref_id,
            submission_id,
            artifact_kind: TraceObjectArtifactKind::WorkerIntermediate,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_b}/worker/summary.json"),
            content_sha256: format!("sha256:{tenant_b}:object"),
            encryption_key_ref: format!("kms:{tenant_b}"),
            size_bytes: 128,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("insert tenant B object ref");
    backend
        .append_trace_derived_record(TraceDerivedRecordWrite {
            tenant_id: tenant_b.clone(),
            derived_id: tenant_b_derived_id,
            submission_id,
            trace_id,
            status: TraceDerivedStatus::Current,
            worker_kind: TraceWorkerKind::Summary,
            worker_version: "summary-worker-v1".to_string(),
            input_object_ref: Some(TenantScopedTraceObjectRef {
                tenant_id: tenant_b.clone(),
                submission_id,
                object_ref_id: tenant_b_object_ref_id,
            }),
            input_hash: format!("sha256:{tenant_b}:object"),
            output_object_ref: None,
            canonical_summary: Some("Tenant B summary.".to_string()),
            canonical_summary_hash: Some(format!("sha256:{tenant_b}:summary")),
            summary_model: "summary-model-v1".to_string(),
            task_success: Some("success".to_string()),
            privacy_risk: Some("low".to_string()),
            event_count: Some(2),
            tool_sequence: vec!["memory_search".to_string()],
            tool_categories: vec!["memory".to_string()],
            coverage_tags: vec!["tool:memory_search".to_string()],
            duplicate_score: Some(0.1),
            novelty_score: Some(0.4),
            cluster_id: Some(format!("cluster:{tenant_b}")),
        })
        .await
        .expect("insert tenant B derived record");
    backend
        .upsert_trace_vector_entry(TraceVectorEntryWrite {
            tenant_id: tenant_b.clone(),
            submission_id,
            derived_id: tenant_b_derived_id,
            vector_entry_id: tenant_b_vector_entry_id,
            vector_store: "trace-commons-main".to_string(),
            embedding_model: "text-embedding-3-small".to_string(),
            embedding_dimension: 1536,
            embedding_version: "embedding-v1".to_string(),
            source_projection: TraceVectorEntrySourceProjection::CanonicalSummary,
            source_hash: format!("sha256:{tenant_b}:summary"),
            status: TraceVectorEntryStatus::Active,
            nearest_trace_ids: Vec::new(),
            cluster_id: Some(format!("cluster:{tenant_b}")),
            duplicate_score: Some(0.1),
            novelty_score: Some(0.4),
            indexed_at: Some(Utc::now()),
            invalidated_at: None,
            deleted_at: None,
        })
        .await
        .expect("insert tenant B vector entry");

    let tenant_a_export_id = Uuid::new_v4();
    backend
        .upsert_trace_export_manifest(TraceExportManifestWrite {
            tenant_id: tenant_a.clone(),
            export_manifest_id: tenant_a_export_id,
            artifact_kind: TraceObjectArtifactKind::ExportArtifact,
            purpose_code: Some("replay_dataset".to_string()),
            audit_event_id: Some(Uuid::new_v4()),
            source_submission_ids: vec![submission_id],
            source_submission_ids_hash: format!("sha256:{tenant_a}:sources"),
            item_count: 1,
            generated_at: Utc::now(),
        })
        .await
        .expect("insert tenant A manifest");

    let err = backend
        .upsert_trace_export_manifest_item(TraceExportManifestItemWrite {
            tenant_id: tenant_a.clone(),
            export_manifest_id: tenant_a_export_id,
            submission_id,
            trace_id,
            derived_id: Some(tenant_b_derived_id),
            object_ref_id: Some(tenant_b_object_ref_id),
            vector_entry_id: Some(tenant_b_vector_entry_id),
            source_status_at_export: TraceCorpusStatus::Accepted,
            source_hash_at_export: format!("sha256:{tenant_a}:source"),
        })
        .await
        .expect_err("cross-tenant export refs must be rejected");

    assert!(
        err.to_string().contains("does not belong to tenant"),
        "unexpected error: {err}"
    );

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in [&tenant_a, &tenant_b] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn store_facade_rejects_derived_record_mismatched_tenant_object_ref() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_a = format!("rls-derived-ref-a-{}", Uuid::new_v4());
    let tenant_b = format!("rls-derived-ref-b-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();
    let trace_id = Uuid::new_v4();

    let mut tenant_a_submission = sample_submission(&tenant_a, submission_id);
    tenant_a_submission.trace_id = trace_id;
    backend
        .upsert_trace_submission(tenant_a_submission)
        .await
        .expect("insert tenant A submission");
    let mut tenant_b_submission = sample_submission(&tenant_b, submission_id);
    tenant_b_submission.trace_id = trace_id;
    backend
        .upsert_trace_submission(tenant_b_submission)
        .await
        .expect("insert tenant B submission");

    let tenant_b_object_ref_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_b.clone(),
            object_ref_id: tenant_b_object_ref_id,
            submission_id,
            artifact_kind: TraceObjectArtifactKind::WorkerIntermediate,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_b}/worker/summary.json"),
            content_sha256: format!("sha256:{tenant_b}:object"),
            encryption_key_ref: format!("kms:{tenant_b}"),
            size_bytes: 128,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("insert tenant B object ref");

    let err = backend
        .append_trace_derived_record(TraceDerivedRecordWrite {
            tenant_id: tenant_a.clone(),
            derived_id: Uuid::new_v4(),
            submission_id,
            trace_id,
            status: TraceDerivedStatus::Current,
            worker_kind: TraceWorkerKind::Summary,
            worker_version: "summary-worker-v1".to_string(),
            input_object_ref: Some(TenantScopedTraceObjectRef {
                tenant_id: tenant_b.clone(),
                submission_id,
                object_ref_id: tenant_b_object_ref_id,
            }),
            input_hash: format!("sha256:{tenant_b}:object"),
            output_object_ref: None,
            canonical_summary: Some("Tenant A summary.".to_string()),
            canonical_summary_hash: Some(format!("sha256:{tenant_a}:summary")),
            summary_model: "summary-model-v1".to_string(),
            task_success: Some("success".to_string()),
            privacy_risk: Some("low".to_string()),
            event_count: Some(2),
            tool_sequence: vec!["memory_search".to_string()],
            tool_categories: vec!["memory".to_string()],
            coverage_tags: vec!["tool:memory_search".to_string()],
            duplicate_score: Some(0.1),
            novelty_score: Some(0.4),
            cluster_id: Some(format!("cluster:{tenant_a}")),
        })
        .await
        .expect_err("derived records must reject cross-tenant object refs");

    assert!(
        err.to_string().contains("does not belong to tenant"),
        "unexpected error: {err}"
    );

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    for tenant_id in [&tenant_a, &tenant_b] {
        let tx = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[tenant_id],
        )
        .await
        .expect("set cleanup tenant context");
        let _ = tx
            .execute(
                "DELETE FROM trace_tenants WHERE tenant_id = $1",
                &[tenant_id],
            )
            .await;
        tx.commit().await.expect("commit cleanup transaction");
    }
}

#[tokio::test]
async fn store_facade_rejects_vector_entry_mismatched_submission_derived_id() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");
    assert_trace_rls_policies_installed(&backend).await;

    let tenant_id = format!("rls-vector-derived-{}", Uuid::new_v4());
    let submission_a_id = Uuid::new_v4();
    let trace_a_id = Uuid::new_v4();
    let mut submission_a = sample_submission(&tenant_id, submission_a_id);
    submission_a.trace_id = trace_a_id;
    backend
        .upsert_trace_submission(submission_a)
        .await
        .expect("insert submission A");

    let submission_b_id = Uuid::new_v4();
    let trace_b_id = Uuid::new_v4();
    let mut submission_b = sample_submission(&tenant_id, submission_b_id);
    submission_b.trace_id = trace_b_id;
    backend
        .upsert_trace_submission(submission_b)
        .await
        .expect("insert submission B");

    let object_ref_b_id = Uuid::new_v4();
    let derived_b_id = Uuid::new_v4();
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_id.clone(),
            object_ref_id: object_ref_b_id,
            submission_id: submission_b_id,
            artifact_kind: TraceObjectArtifactKind::WorkerIntermediate,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_id}/submission-b/summary.json"),
            content_sha256: format!("sha256:{tenant_id}:submission-b-object"),
            encryption_key_ref: format!("kms:{tenant_id}"),
            size_bytes: 128,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("insert submission B object ref");
    backend
        .append_trace_derived_record(TraceDerivedRecordWrite {
            tenant_id: tenant_id.clone(),
            derived_id: derived_b_id,
            submission_id: submission_b_id,
            trace_id: trace_b_id,
            status: TraceDerivedStatus::Current,
            worker_kind: TraceWorkerKind::Summary,
            worker_version: "summary-worker-v1".to_string(),
            input_object_ref: Some(TenantScopedTraceObjectRef {
                tenant_id: tenant_id.clone(),
                submission_id: submission_b_id,
                object_ref_id: object_ref_b_id,
            }),
            input_hash: format!("sha256:{tenant_id}:submission-b-object"),
            output_object_ref: None,
            canonical_summary: Some("Submission B summary.".to_string()),
            canonical_summary_hash: Some(format!("sha256:{tenant_id}:submission-b-summary")),
            summary_model: "summary-model-v1".to_string(),
            task_success: Some("success".to_string()),
            privacy_risk: Some("low".to_string()),
            event_count: Some(2),
            tool_sequence: vec!["memory_search".to_string()],
            tool_categories: vec!["memory".to_string()],
            coverage_tags: vec!["tool:memory_search".to_string()],
            duplicate_score: Some(0.1),
            novelty_score: Some(0.4),
            cluster_id: Some(format!("cluster:{tenant_id}")),
        })
        .await
        .expect("insert submission B derived record");

    let err = backend
        .upsert_trace_vector_entry(TraceVectorEntryWrite {
            tenant_id: tenant_id.clone(),
            submission_id: submission_a_id,
            derived_id: derived_b_id,
            vector_entry_id: Uuid::new_v4(),
            vector_store: "trace-commons-main".to_string(),
            embedding_model: "text-embedding-3-small".to_string(),
            embedding_dimension: 1536,
            embedding_version: "embedding-v1".to_string(),
            source_projection: TraceVectorEntrySourceProjection::CanonicalSummary,
            source_hash: format!("sha256:{tenant_id}:submission-a-summary"),
            status: TraceVectorEntryStatus::Active,
            nearest_trace_ids: Vec::new(),
            cluster_id: Some(format!("cluster:{tenant_id}")),
            duplicate_score: Some(0.1),
            novelty_score: Some(0.4),
            indexed_at: Some(Utc::now()),
            invalidated_at: None,
            deleted_at: None,
        })
        .await
        .expect_err("vector entries must reject derived ids from another submission");

    assert!(
        err.to_string().contains("does not belong to tenant"),
        "unexpected error: {err}"
    );

    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get cleanup connection");
    let tx = client
        .transaction()
        .await
        .expect("start cleanup transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .expect("set cleanup tenant context");
    let _ = tx
        .execute(
            "DELETE FROM trace_tenants WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await;
    tx.commit().await.expect("commit cleanup transaction");
}

#[tokio::test]
async fn instance_enrollment_ledger_is_instance_scoped() {
    let database_url = match std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
    {
        Ok(url) => url,
        Err(_) => {
            eprintln!(
                "skipping: TRACE_COMMONS_PG_TEST_DATABASE_URL or DATABASE_URL not configured"
            );
            return;
        }
    };

    // Apply migrations (including V35) before the raw connection test.
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend
        .run_migrations()
        .await
        .expect("run migrations for instance enrollment test");

    let mut client =
        connect_for_raw_rls_assertion(&database_url, "instance enrollment RLS test").await;

    let instance_a = format!("sha256:{}", "a".repeat(64));
    let instance_b = format!("sha256:{}", "c".repeat(64));
    let user_hash = format!("sha256:{}", "b".repeat(64));
    let tenant_id = "tenant-deadbeef";

    // Insert a row under instance A's context.
    let tx = client
        .transaction()
        .await
        .expect("start instance A insert transaction");
    tx.execute(
        "SELECT set_config('trace_commons.instance_subject', $1, true)",
        &[&instance_a],
    )
    .await
    .expect("set instance A context");
    tx.execute(
        "INSERT INTO trace_instance_enrollments \
         (instance_subject_hash, user_subject_hash, tenant_id) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
        &[&instance_a, &user_hash, &tenant_id],
    )
    .await
    .expect("insert instance A enrollment row");
    tx.commit()
        .await
        .expect("commit instance A insert transaction");

    // Under instance B's context the row must be invisible.
    let tx = client
        .transaction()
        .await
        .expect("start instance B read transaction");
    tx.execute(
        "SELECT set_config('trace_commons.instance_subject', $1, true)",
        &[&instance_b],
    )
    .await
    .expect("set instance B context");
    let rows = tx
        .query("SELECT 1 FROM trace_instance_enrollments", &[])
        .await
        .expect("query enrollments under instance B context");
    assert!(
        rows.is_empty(),
        "instance B must not see instance A rows; got {} row(s)",
        rows.len()
    );
    tx.commit()
        .await
        .expect("commit instance B read transaction");

    // Cleanup: re-set instance A context to delete inserted row.
    let tx = client
        .transaction()
        .await
        .expect("start cleanup transaction");
    tx.execute(
        "SELECT set_config('trace_commons.instance_subject', $1, true)",
        &[&instance_a],
    )
    .await
    .expect("set instance A context for cleanup");
    let _ = tx
        .execute(
            "DELETE FROM trace_instance_enrollments WHERE instance_subject_hash = $1",
            &[&instance_a],
        )
        .await;
    tx.commit().await.expect("commit cleanup transaction");
}

#[tokio::test]
async fn gate_driver_role_reads_across_tenants_while_default_role_stays_isolated() {
    let database_url = match std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
    {
        Ok(url) => url,
        Err(_) => {
            eprintln!(
                "skipping: TRACE_COMMONS_PG_TEST_DATABASE_URL or DATABASE_URL not configured"
            );
            return;
        }
    };

    // Apply migrations (including V36) before the raw connection test.
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend
        .run_migrations()
        .await
        .expect("run migrations for gate driver test");

    let mut client = connect_for_raw_rls_assertion(&database_url, "gate driver RLS test").await;

    let tenant_id = format!("gate-driver-tenant-{}", Uuid::new_v4());
    let submission_id = Uuid::new_v4();

    // Insert tenant + attempts row under the tenant's own RLS context.
    let tx = client
        .transaction()
        .await
        .expect("start gate driver setup transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .expect("set tenant context");
    tx.execute(
        "INSERT INTO trace_tenants (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING",
        &[&tenant_id],
    )
    .await
    .expect("insert tenant row");
    tx.execute(
        "INSERT INTO trace_gate_evaluation_attempts (tenant_id, submission_id, attempts) \
         VALUES ($1, $2, 1)",
        &[&tenant_id, &submission_id],
    )
    .await
    .expect("insert gate evaluation attempts row");
    tx.commit()
        .await
        .expect("commit gate driver setup transaction");

    // Default role, no tenant context: forced RLS must hide the row entirely.
    let rows = client
        .query(
            "SELECT 1 FROM trace_gate_evaluation_attempts WHERE submission_id = $1",
            &[&submission_id],
        )
        .await
        .expect("query attempts row with no tenant context");
    assert!(
        rows.is_empty(),
        "default role without tenant context must not see the gate evaluation attempts row"
    );

    // trace_gate_driver role: the permissive cross-tenant SELECT policy must allow the
    // read even with no tenant context set.
    match client.batch_execute("SET ROLE trace_gate_driver").await {
        Ok(()) => {
            let rows = client
                .query(
                    "SELECT attempts FROM trace_gate_evaluation_attempts WHERE submission_id = $1",
                    &[&submission_id],
                )
                .await
                .expect("query attempts row as trace_gate_driver");
            assert_eq!(
                rows.len(),
                1,
                "trace_gate_driver must read the attempts row across tenants via the permissive policy"
            );
            let attempts: i32 = rows[0].get(0);
            assert_eq!(attempts, 1);

            client
                .batch_execute("RESET ROLE")
                .await
                .expect("reset role after gate driver assertion");
        }
        Err(e) => {
            eprintln!(
                "skipping trace_gate_driver permissive-read assertion: cannot SET ROLE ({e})"
            );
        }
    }

    // Cleanup.
    let tx = client
        .transaction()
        .await
        .expect("start gate driver cleanup transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .expect("set tenant context for cleanup");
    let _ = tx
        .execute(
            "DELETE FROM trace_tenants WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await;
    tx.commit()
        .await
        .expect("commit gate driver cleanup transaction");
}

/// V42 narrows `trace_gate_driver` from table-wide SELECT (V36) to the same
/// column-scoped convention V38 established for `trace_pii_backstop_driver`.
/// Cross-tenant USING(true) policies stay; this asserts grant *width*: the
/// driver's enumeration columns remain readable, while object keys and other
/// out-of-surface columns are not.
#[tokio::test]
async fn gate_driver_column_grants_exclude_object_keys_and_wide_columns() {
    let database_url = match std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
    {
        Ok(url) => url,
        Err(_) => {
            eprintln!(
                "skipping: TRACE_COMMONS_PG_TEST_DATABASE_URL or DATABASE_URL not configured"
            );
            return;
        }
    };

    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend
        .run_migrations()
        .await
        .expect("run migrations for gate driver column-grant test");

    let (mut client, connection) = match tokio_postgres::connect(&database_url, NoTls).await {
        Ok(parts) => parts,
        Err(e) => {
            eprintln!("skipping gate driver column-grant test: database unavailable ({e})");
            return;
        }
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // has_column_privilege confirms the grant boundary directly, independent of
    // SET ROLE / RLS. Granted surface first.
    let granted: bool = client
        .query_one(
            "SELECT has_column_privilege('trace_gate_driver', 'trace_object_refs', 'artifact_kind', 'SELECT')
             AND has_column_privilege('trace_gate_driver', 'trace_object_refs', 'invalidated_at', 'SELECT')
             AND has_column_privilege('trace_gate_driver', 'trace_object_refs', 'deleted_at', 'SELECT')
             AND has_column_privilege('trace_gate_driver', 'trace_submissions', 'auth_principal_ref', 'SELECT')
             AND has_column_privilege('trace_gate_driver', 'trace_submissions', 'received_at', 'SELECT')
             AND has_column_privilege('trace_gate_driver', 'trace_gate_decisions', 'credit_quality_micros', 'SELECT')
             -- V57. `list_dedup_signals` runs on this pool and selects this
             -- column, and PostgreSQL column privileges cover every column a
             -- query REFERENCES, so a missing grant fails the recluster pass
             -- on its first query rather than at deploy.
             AND has_column_privilege('trace_gate_driver', 'trace_gate_decisions', 'dedup_signal_version', 'SELECT')
             AND has_column_privilege('trace_gate_driver', 'trace_gate_evaluation_attempts', 'attempts', 'SELECT')",
            &[],
        )
        .await
        .expect("granted column privilege check runs")
        .get(0);
    assert!(
        granted,
        "trace_gate_driver must retain SELECT on the columns its queries use"
    );

    // Out-of-grant columns that a compromised credential must not enumerate.
    let object_key_priv: bool = client
        .query_one(
            "SELECT has_column_privilege('trace_gate_driver', 'trace_object_refs', 'object_key', 'SELECT')",
            &[],
        )
        .await
        .expect("object_key privilege check runs")
        .get(0);
    assert!(
        !object_key_priv,
        "trace_gate_driver must NOT have SELECT on object_key (V42 / #192)"
    );

    let encryption_key_ref_priv: bool = client
        .query_one(
            "SELECT has_column_privilege('trace_gate_driver', 'trace_object_refs', 'encryption_key_ref', 'SELECT')",
            &[],
        )
        .await
        .expect("encryption_key_ref privilege check runs")
        .get(0);
    assert!(
        !encryption_key_ref_priv,
        "trace_gate_driver must NOT have SELECT on encryption_key_ref"
    );

    let redaction_hash_priv: bool = client
        .query_one(
            "SELECT has_column_privilege('trace_gate_driver', 'trace_submissions', 'redaction_hash', 'SELECT')",
            &[],
        )
        .await
        .expect("redaction_hash privilege check runs")
        .get(0);
    assert!(
        !redaction_hash_priv,
        "trace_gate_driver must NOT have SELECT on redaction_hash"
    );

    let attestation_priv: bool = client
        .query_one(
            "SELECT has_column_privilege('trace_gate_driver', 'trace_gate_decisions', 'attestation_chain_hash', 'SELECT')",
            &[],
        )
        .await
        .expect("attestation_chain_hash privilege check runs")
        .get(0);
    assert!(
        !attestation_priv,
        "trace_gate_driver must NOT have SELECT on attestation_chain_hash"
    );

    let last_error_priv: bool = client
        .query_one(
            "SELECT has_column_privilege('trace_gate_driver', 'trace_gate_evaluation_attempts', 'last_error_label', 'SELECT')",
            &[],
        )
        .await
        .expect("last_error_label privilege check runs")
        .get(0);
    assert!(
        !last_error_priv,
        "trace_gate_driver must NOT have SELECT on last_error_label"
    );

    // Live SELECT under SET ROLE: granted columns succeed; object_key fails.
    // Superuser test connections drop bypass on SET ROLE to a NOBYPASSRLS role.
    match client.batch_execute("SET ROLE trace_gate_driver").await {
        Ok(()) => {
            client
                .batch_execute("RESET ROLE")
                .await
                .expect("reset before seed");

            let tenant_id = format!("gate-driver-cols-{}", Uuid::new_v4());
            let submission_id = Uuid::new_v4();
            backend
                .upsert_trace_submission(sample_submission(&tenant_id, submission_id))
                .await
                .expect("seed submission via corpus store");
            backend
                .append_trace_object_ref(TraceObjectRefWrite {
                    tenant_id: tenant_id.clone(),
                    object_ref_id: Uuid::new_v4(),
                    submission_id,
                    artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
                    object_store: "s3://private-corpus".to_string(),
                    object_key: "secret/object/key".to_string(),
                    content_sha256: "sha256:gate-cols".to_string(),
                    encryption_key_ref: "kms:gate-cols".to_string(),
                    size_bytes: 1024,
                    compression: None,
                    created_by_job_id: None,
                })
                .await
                .expect("seed object ref via corpus store");

            client
                .batch_execute("SET ROLE trace_gate_driver")
                .await
                .expect("re-assume gate driver role");

            let granted_read = client
                .query_opt(
                    "SELECT artifact_kind FROM trace_object_refs WHERE submission_id = $1",
                    &[&submission_id],
                )
                .await
                .expect("granted column SELECT must succeed under SET ROLE");
            assert!(
                granted_read.is_some(),
                "trace_gate_driver must read granted object_refs columns cross-tenant"
            );

            let object_key_read = client
                .query_opt(
                    "SELECT object_key FROM trace_object_refs WHERE submission_id = $1",
                    &[&submission_id],
                )
                .await;
            assert!(
                object_key_read.is_err(),
                "trace_gate_driver must be rejected when selecting object_key"
            );

            let _ = client.batch_execute("RESET ROLE").await;

            let tx = client
                .transaction()
                .await
                .expect("start column-grant cleanup transaction");
            tx.execute(
                "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
                &[&tenant_id],
            )
            .await
            .expect("set tenant context for cleanup");
            let _ = tx
                .execute(
                    "DELETE FROM trace_tenants WHERE tenant_id = $1",
                    &[&tenant_id],
                )
                .await;
            tx.commit()
                .await
                .expect("commit column-grant cleanup transaction");
        }
        Err(e) => {
            eprintln!("skipping live SET ROLE column-grant assertion: cannot SET ROLE ({e})");
        }
    }
}

/// The perplexity scoring driver's enumeration query
/// (`Database::list_submissions_needing_gate_decision`) must return only
/// submissions that (a) have a submitted-envelope object ref, (b) have no
/// `trace_gate_decisions` row yet, and (c) have not exhausted their attempt
/// budget in `trace_gate_evaluation_attempts`. Seeds two tenants: tenant A
/// gets a gate decision (must be excluded), tenant B has none (must be the
/// sole result). A third submission (tenant C) is given an attempts row at
/// the `max_attempts` cap and must also be excluded.
#[tokio::test]
async fn list_submissions_needing_gate_decision_excludes_decided_and_capped_submissions() {
    let Some(backend) = gate_driver_backend().await else {
        return;
    };
    backend.run_migrations().await.expect("run migrations");

    let tenant_a = format!("gate-work-decided-{}", Uuid::new_v4());
    let tenant_b = format!("gate-work-ungated-{}", Uuid::new_v4());
    let tenant_c = format!("gate-work-capped-{}", Uuid::new_v4());
    let submission_a = Uuid::new_v4();
    let submission_b = Uuid::new_v4();
    let submission_c = Uuid::new_v4();

    for (tenant_id, submission_id) in [
        (&tenant_a, submission_a),
        (&tenant_b, submission_b),
        (&tenant_c, submission_c),
    ] {
        backend
            .upsert_trace_submission(sample_submission(tenant_id, submission_id))
            .await
            .expect("insert submission");
        backend
            .append_trace_object_ref(TraceObjectRefWrite {
                tenant_id: tenant_id.clone(),
                object_ref_id: Uuid::new_v4(),
                submission_id,
                artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
                object_store: "s3://private-corpus".to_string(),
                object_key: format!("{tenant_id}/submission.json"),
                content_sha256: format!("sha256:{tenant_id}:object"),
                encryption_key_ref: format!("kms:{tenant_id}"),
                size_bytes: 1024,
                compression: None,
                created_by_job_id: None,
            })
            .await
            .expect("append submitted-envelope object ref");
    }

    // Tenant B carries a SECOND active submitted-envelope object ref (real:
    // multi-ref submissions exist, hence get_latest_active_trace_object_ref).
    // The INNER JOIN would fan out to two rows without DISTINCT; the
    // enumeration must still return tenant B exactly once.
    backend
        .append_trace_object_ref(TraceObjectRefWrite {
            tenant_id: tenant_b.clone(),
            object_ref_id: Uuid::new_v4(),
            submission_id: submission_b,
            artifact_kind: TraceObjectArtifactKind::SubmittedEnvelope,
            object_store: "s3://private-corpus".to_string(),
            object_key: format!("{tenant_b}/submission-second.json"),
            content_sha256: format!("sha256:{tenant_b}:object-second"),
            encryption_key_ref: format!("kms:{tenant_b}"),
            size_bytes: 2048,
            compression: None,
            created_by_job_id: None,
        })
        .await
        .expect("append tenant B second submitted-envelope object ref");

    // Tenant A already has a gate decision: must be excluded.
    backend
        .insert_trace_gate_decision(
            &tenant_a,
            TraceGateDecisionRow {
                decision_id: Uuid::new_v4(),
                submission_id: submission_a,
                gate_policy_version: "enclave_mock_v1".to_string(),
                gate_version_hash: "sha256:enclave_mock_v1".to_string(),
                perplexity_micros: 1_500_000,
                tail_fraction_micros: 750_000,
                perplexity_passed: true,
                novelty_score_micros: 900_000,
                nearest_neighbor_hash: "sha256:fixture-neighbor".to_string(),
                novelty_passed: true,
                embedding_evidence_hash: "sha256:fixture-evidence".to_string(),
                attestation_chain_hash: "sha256:fixture-attestation".to_string(),
                decided_at: Utc::now(),
                vector_entry_id: Some(Uuid::new_v4()),
                credit_withheld_reason: None,
                peak_perplexity_micros: None,
                peak_novelty_micros: None,
                chunk_count: None,
                total_chunk_count: None,
                qualifying_token_fraction_micros: None,
                chunks_capped: None,
                composite_score_micros: None,
                vector_index_snapshot_id: None,
                index_cardinality_at_scoring: None,
            },
        )
        .await
        .expect("insert tenant A gate decision");

    // Tenant C has exhausted its attempt budget: must be excluded even though
    // it has no gate decision yet.
    let max_attempts: i32 = 5;
    let mut cap_client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get connection for attempts seed");
    let tx = cap_client
        .transaction()
        .await
        .expect("start attempts seed transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_c],
    )
    .await
    .expect("set tenant C context");
    tx.execute(
        "INSERT INTO trace_gate_evaluation_attempts (tenant_id, submission_id, attempts, last_attempt_at) \
         VALUES ($1, $2, $3, now())",
        &[&tenant_c, &submission_c, &max_attempts],
    )
    .await
    .expect("insert capped attempts row");
    tx.commit().await.expect("commit attempts seed transaction");

    let now = Utc::now();
    let work_items = backend
        // The enumeration is deliberately cross-tenant, so a small limit turns
        // this into a race against every other ungated submission left in the
        // database by earlier tests. The claim under test is which rows are
        // eligible, not which ten come back first.
        .list_submissions_needing_gate_decision(now, max_attempts, 30, 10_000)
        .await
        .expect("enumerate submissions needing a gate decision");

    let tenant_b_item = GateWorkItem {
        tenant_id: tenant_b.clone(),
        submission_id: submission_b,
    };
    let tenant_b_count = work_items
        .iter()
        .filter(|item| **item == tenant_b_item)
        .count();
    assert_eq!(
        tenant_b_count, 1,
        "ungated tenant B submission must be returned exactly once despite two active envelope refs"
    );
    assert!(
        !work_items
            .iter()
            .any(|item| item.tenant_id == tenant_a && item.submission_id == submission_a),
        "tenant A submission already has a gate decision and must be excluded"
    );
    assert!(
        !work_items
            .iter()
            .any(|item| item.tenant_id == tenant_c && item.submission_id == submission_c),
        "tenant C submission is at the attempts cap and must be excluded"
    );

    cleanup_trace_tenants(&backend, &[&tenant_a, &tenant_b, &tenant_c]).await;
}

/// When no gate-driver pool is configured, the enumeration must fail closed
/// with a clear error rather than panicking.
#[tokio::test]
async fn list_submissions_needing_gate_decision_fails_closed_without_gate_driver_pool() {
    // Build the config here rather than going through `postgres_backend()`:
    // that helper reads `TRACE_COMMONS_GATE_DRIVER_DATABASE_URL` from the
    // ambient environment, so on a machine where the operator HAS provisioned
    // the gate-driver pool this test would assert the opposite of its name and
    // fail. The absent pool is the fixture, so state it explicitly.
    let Some(mut config) = postgres_test_config() else {
        eprintln!("skipping: TRACE_COMMONS_PG_TEST_DATABASE_URL or DATABASE_URL not configured");
        return;
    };
    config.gate_driver_url = None;
    let backend = PgBackend::new(&config)
        .await
        .expect("construct configured backend");

    let result = backend
        .list_submissions_needing_gate_decision(Utc::now(), 5, 30, 10)
        .await;
    let error = result.expect_err("enumeration without a gate-driver pool must fail closed");
    match error {
        trace_commons_server::error::DatabaseError::Pool(message) => {
            assert_eq!(message, "gate-driver pool not configured");
        }
        other => panic!("expected missing gate-driver pool, got {other:?}"),
    }
}

/// Name of the NOBYPASSRLS role these tests run their assertions under.
///
/// A superuser connection bypasses RLS entirely, so asserting isolation as one
/// proves nothing: a count over a protected table with no tenant context still
/// returns every row. Every assertion below therefore runs after `SET ROLE` to
/// this role, and the test refuses to assert -- rather than quietly passing --
/// if it cannot get there.
const RLS_TEST_ACTOR_ROLE: &str = "trace_rls_test_actor";

/// Connect, apply migrations, and put the session on a role that cannot bypass
/// RLS. Returns `None` (with a printed reason) when there is no database, and
/// panics when there is a database but the session cannot be de-privileged --
/// silently skipping that case is how an unexercised policy ships.
async fn rls_actor_client() -> Option<tokio_postgres::Client> {
    let database_url = match std::env::var("TRACE_COMMONS_PG_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
    {
        Ok(url) => url,
        Err(_) => {
            eprintln!(
                "skipping: TRACE_COMMONS_PG_TEST_DATABASE_URL or DATABASE_URL not configured"
            );
            return None;
        }
    };

    let backend = postgres_backend().await?;
    backend
        .run_migrations()
        .await
        .expect("run migrations for community withdrawal eviction RLS test");

    let (mut client, connection) = match tokio_postgres::connect(&database_url, NoTls).await {
        Ok(parts) => parts,
        Err(e) => {
            eprintln!(
                "skipping community withdrawal eviction RLS test: database unavailable ({e})"
            );
            return None;
        }
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });

    if current_role_bypasses_trace_rls(&mut client)
        .await
        .expect("inspect current role")
    {
        // BYPASSRLS does not imply CREATEROLE. Only missing privilege while
        // creating this fixture may skip; schema/grant/SET ROLE failures remain errors.
        if let Err(error) = client
            .batch_execute(&format!(
                "SELECT pg_advisory_xact_lock({RLS_TEST_ROLE_DDL_LOCK_CLASSID}, \
                    {RLS_TEST_ROLE_DDL_LOCK_OBJID});
                 DO $$ BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RLS_TEST_ACTOR_ROLE}')
                    THEN CREATE ROLE {RLS_TEST_ACTOR_ROLE} NOLOGIN NOBYPASSRLS;
                    END IF;
                 END $$;"
            ))
            .await
        {
            if error.code() == Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE) {
                eprintln!("skipping: CREATEROLE privilege unavailable for RLS fixture");
                return None;
            }
            panic!("create NOBYPASSRLS test role: {error}");
        }
        client
            .batch_execute(&format!(
                "SELECT pg_advisory_xact_lock({RLS_TEST_ROLE_DDL_LOCK_CLASSID}, \
                    {RLS_TEST_ROLE_DDL_LOCK_OBJID});
                 GRANT SELECT, INSERT, UPDATE, DELETE
                    ON trace_community_withdrawal_evictions TO {RLS_TEST_ACTOR_ROLE};
                 SET ROLE {RLS_TEST_ACTOR_ROLE};"
            ))
            .await
            .expect("grant and assume the NOBYPASSRLS test role");
    }

    assert!(
        !current_role_bypasses_trace_rls(&mut client)
            .await
            .expect("re-inspect current role"),
        "community withdrawal eviction RLS assertions must not run under a role that \
         bypasses RLS; a superuser sees every row regardless of policy"
    );
    Some(client)
}

async fn insert_eviction_under_tenant(
    client: &mut tokio_postgres::Client,
    tenant_id: &str,
    eviction_id: Uuid,
) {
    let tx = client
        .transaction()
        .await
        .expect("start eviction insert transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .expect("set tenant context for eviction insert");
    tx.execute(
        "INSERT INTO trace_community_withdrawal_evictions (
            eviction_id, tenant_id, principal_ref, display_handle, handle_normalized,
            withdrawn_at, invalidation_requested_at, window_label, metric
         ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), 'rolling_7d', 'credit')",
        &[
            &eviction_id,
            &tenant_id,
            &format!("principal:{tenant_id}"),
            &format!("handle-{tenant_id}"),
            &format!("handle-{tenant_id}"),
        ],
    )
    .await
    .expect("insert eviction receipt under tenant context");
    tx.commit().await.expect("commit eviction insert");
}

async fn delete_eviction_under_tenant(
    client: &mut tokio_postgres::Client,
    tenant_id: &str,
    eviction_id: Uuid,
) {
    let tx = client
        .transaction()
        .await
        .expect("start eviction cleanup transaction");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_id],
    )
    .await
    .expect("set tenant context for eviction cleanup");
    let _ = tx
        .execute(
            "DELETE FROM trace_community_withdrawal_evictions WHERE eviction_id = $1",
            &[&eviction_id],
        )
        .await;
    tx.commit().await.expect("commit eviction cleanup");
}

/// V46 shipped this table with no RLS at all while it carries `tenant_id`,
/// `principal_ref` and the withdrawn contributor's handle. V56 gives it the
/// central tenant predicate; this asserts the predicate actually isolates.
#[tokio::test]
async fn community_withdrawal_evictions_are_tenant_isolated() {
    let Some(mut client) = rls_actor_client().await else {
        return;
    };

    let tenant_a = format!("tenant-evict-a-{}", Uuid::new_v4().simple());
    let tenant_b = format!("tenant-evict-b-{}", Uuid::new_v4().simple());
    let eviction_a = Uuid::new_v4();
    let eviction_b = Uuid::new_v4();

    insert_eviction_under_tenant(&mut client, &tenant_a, eviction_a).await;
    insert_eviction_under_tenant(&mut client, &tenant_b, eviction_b).await;

    // Tenant A sees its own row.
    let tx = client.transaction().await.expect("start tenant A read");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_a],
    )
    .await
    .expect("set tenant A context");
    let own: Vec<Uuid> = tx
        .query(
            "SELECT eviction_id FROM trace_community_withdrawal_evictions
              WHERE eviction_id = ANY($1)",
            &[&vec![eviction_a, eviction_b]],
        )
        .await
        .expect("read evictions under tenant A context")
        .iter()
        .map(|row| row.get("eviction_id"))
        .collect();
    assert_eq!(
        own,
        vec![eviction_a],
        "tenant A must see exactly its own eviction receipt"
    );
    tx.commit().await.expect("commit tenant A read");

    // With no tenant context at all, nothing is visible.
    let tx = client.transaction().await.expect("start no-context read");
    let rows = tx
        .query(
            "SELECT eviction_id FROM trace_community_withdrawal_evictions
              WHERE eviction_id = ANY($1)",
            &[&vec![eviction_a, eviction_b]],
        )
        .await
        .expect("read evictions without tenant context");
    assert!(
        rows.is_empty(),
        "a connection with no tenant context must see no eviction receipts; got {}",
        rows.len()
    );
    tx.commit().await.expect("commit no-context read");

    // Tenant B cannot write into tenant A's scope either.
    let tx = client.transaction().await.expect("start tenant B write");
    tx.execute(
        "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
        &[&tenant_b],
    )
    .await
    .expect("set tenant B context");
    let cross_tenant_insert = tx
        .execute(
            "INSERT INTO trace_community_withdrawal_evictions (
                eviction_id, tenant_id, principal_ref, withdrawn_at,
                invalidation_requested_at, window_label, metric
             ) VALUES ($1, $2, 'principal:forged', NOW(), NOW(), 'rolling_7d', 'credit')",
            &[&Uuid::new_v4(), &tenant_a],
        )
        .await;
    assert!(
        cross_tenant_insert.is_err(),
        "tenant B must not be able to insert a receipt attributed to tenant A"
    );
    tx.rollback().await.expect("roll back tenant B write");

    delete_eviction_under_tenant(&mut client, &tenant_a, eviction_a).await;
    delete_eviction_under_tenant(&mut client, &tenant_b, eviction_b).await;
}

/// The drain is deliberately cross-tenant: one statement marks every pending
/// eviction for a (window, metric). V56 gates it on a transaction-local GUC
/// instead of a tenant predicate. This asserts the drain still drains across
/// tenants, and that the allowance is no wider than that.
#[tokio::test]
async fn community_withdrawal_eviction_drain_crosses_tenants_within_drain_scope() {
    let Some(mut client) = rls_actor_client().await else {
        return;
    };

    let tenant_a = format!("tenant-drain-a-{}", Uuid::new_v4().simple());
    let tenant_b = format!("tenant-drain-b-{}", Uuid::new_v4().simple());
    let eviction_a = Uuid::new_v4();
    let eviction_b = Uuid::new_v4();
    let ids = vec![eviction_a, eviction_b];

    insert_eviction_under_tenant(&mut client, &tenant_a, eviction_a).await;
    insert_eviction_under_tenant(&mut client, &tenant_b, eviction_b).await;

    // Without the drain GUC the same statement silently marks nothing -- it
    // does not error, which is precisely why this needs asserting.
    let tx = client.transaction().await.expect("start undrained attempt");
    let undrained = tx
        .execute(
            "UPDATE trace_community_withdrawal_evictions
                SET drained_at = NOW(), drained_snapshot_id = $2
              WHERE window_label = 'rolling_7d' AND metric = 'credit'
                AND drained_at IS NULL AND eviction_id = ANY($1)",
            &[&ids, &Uuid::new_v4()],
        )
        .await
        .expect("run drain statement without drain scope");
    assert_eq!(
        undrained, 0,
        "outside drain scope the drain statement must mark no rows"
    );
    tx.commit().await.expect("commit undrained attempt");

    // Inside drain scope it marks both tenants' rows in one statement.
    let snapshot_id = Uuid::new_v4();
    let tx = client.transaction().await.expect("start drain");
    tx.execute(
        "SELECT set_config('trace_commons.community_drain', 'on', true)",
        &[],
    )
    .await
    .expect("enter drain scope");
    let drained = tx
        .execute(
            "UPDATE trace_community_withdrawal_evictions
                SET drained_at = NOW(), drained_snapshot_id = $2
              WHERE window_label = 'rolling_7d' AND metric = 'credit'
                AND drained_at IS NULL AND eviction_id = ANY($1)",
            &[&ids, &snapshot_id],
        )
        .await
        .expect("run drain statement in drain scope");
    assert_eq!(
        drained, 2,
        "the drain must mark both tenants' receipts in one statement"
    );

    // The allowance is UPDATE-only and one-way: drain scope cannot delete a
    // receipt, and cannot un-drain one.
    let deleted = tx
        .execute(
            "DELETE FROM trace_community_withdrawal_evictions WHERE eviction_id = ANY($1)",
            &[&ids],
        )
        .await
        .expect("attempt delete in drain scope");
    assert_eq!(
        deleted, 0,
        "drain scope must not be able to delete eviction receipts"
    );
    let undone = tx
        .execute(
            "UPDATE trace_community_withdrawal_evictions
                SET drained_at = NULL WHERE eviction_id = ANY($1)",
            &[&ids],
        )
        .await
        .expect("attempt un-drain in drain scope");
    assert_eq!(
        undone, 0,
        "drain scope must not be able to clear drained_at"
    );
    tx.commit().await.expect("commit drain");

    // Each tenant sees its own receipt drained, and still only its own.
    for (tenant_id, eviction_id) in [(&tenant_a, eviction_a), (&tenant_b, eviction_b)] {
        let tx = client.transaction().await.expect("start post-drain read");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .expect("set tenant context for post-drain read");
        let rows = tx
            .query(
                "SELECT eviction_id, drained_snapshot_id
                   FROM trace_community_withdrawal_evictions
                  WHERE drained_at IS NOT NULL AND eviction_id = ANY($1)",
                &[&ids],
            )
            .await
            .expect("read drained receipts under tenant context");
        assert_eq!(
            rows.len(),
            1,
            "{tenant_id} must see exactly its own receipt"
        );
        assert_eq!(rows[0].get::<_, Uuid>("eviction_id"), eviction_id);
        assert_eq!(
            rows[0].get::<_, Option<Uuid>>("drained_snapshot_id"),
            Some(snapshot_id),
            "the drain must have stamped the snapshot id"
        );
        tx.commit().await.expect("commit post-drain read");
    }

    delete_eviction_under_tenant(&mut client, &tenant_a, eviction_a).await;
    delete_eviction_under_tenant(&mut client, &tenant_b, eviction_b).await;
}

/// The raw-SQL tests above pin the policy. This one pins the caller: the real
/// `drain_community_snapshot_invalidation` must still drain across tenants
/// once the table is protected. It is the statement that would have gone
/// silently no-op had V56 shipped the tenant predicate alone.
#[tokio::test]
async fn store_facade_drains_withdrawal_evictions_across_tenants() {
    let Some(backend) = postgres_backend().await else {
        return;
    };
    backend
        .run_migrations()
        .await
        .expect("run migrations for withdrawal eviction drain test");

    let tenant_a = format!("tenant-drainfacade-a-{}", Uuid::new_v4().simple());
    let tenant_b = format!("tenant-drainfacade-b-{}", Uuid::new_v4().simple());
    let window_label = "rolling_7d";
    let metric = "credit";

    for tenant_id in [&tenant_a, &tenant_b] {
        backend
            .upsert_contributor_profile(
                tenant_id,
                &format!("principal:{tenant_id}"),
                &format!("Handle {tenant_id}"),
                &format!("handle-{tenant_id}"),
                None,
            )
            .await
            .expect("opt the contributor in");
    }

    let mut receipts = Vec::new();
    for tenant_id in [&tenant_a, &tenant_b] {
        let receipt = backend
            .withdraw_contributor_profile(
                tenant_id,
                &format!("principal:{tenant_id}"),
                window_label,
                metric,
            )
            .await
            .expect("withdraw the contributor")
            .expect("an active profile must yield an eviction receipt");
        assert_eq!(&receipt.tenant_id, tenant_id);
        receipts.push(receipt);
    }

    let pending = backend
        .pending_community_snapshot_invalidation(window_label, metric)
        .await
        .expect("read pending invalidation")
        .expect("two withdrawals must leave a pending watermark");

    let snapshot_id = Uuid::new_v4();
    let drained = backend
        .drain_community_snapshot_invalidation(
            window_label,
            metric,
            snapshot_id,
            pending + chrono::Duration::seconds(1),
        )
        .await
        .expect("drain the coalesced invalidation");
    assert!(drained, "the pending invalidation must drain");

    // Read the receipts back under each tenant's own context. Every one of
    // this deployment's tenants withdrew into the same (window, metric), and
    // one drain statement had to reach all of them.
    let eviction_ids: Vec<Uuid> = receipts.iter().map(|r| r.eviction_id).collect();
    let mut client = backend
        .raw_pool_for_tests_and_diagnostics()
        .get()
        .await
        .expect("get verification connection");
    for receipt in &receipts {
        let tx = client
            .transaction()
            .await
            .expect("start drain verification transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&receipt.tenant_id],
        )
        .await
        .expect("set tenant context for drain verification");
        let rows = tx
            .query(
                "SELECT eviction_id, drained_snapshot_id
                   FROM trace_community_withdrawal_evictions
                  WHERE drained_at IS NOT NULL AND eviction_id = ANY($1)",
                &[&eviction_ids],
            )
            .await
            .expect("read drained receipts");
        assert!(
            rows.iter().any(
                |row| row.get::<_, Uuid>("eviction_id") == receipt.eviction_id
                    && row.get::<_, Option<Uuid>>("drained_snapshot_id") == Some(snapshot_id)
            ),
            "{}'s receipt must be marked drained by the cross-tenant drain",
            receipt.tenant_id
        );
        tx.commit().await.expect("commit drain verification");
    }
    // The eviction table has no FK to trace_tenants, so tenant cleanup does not
    // cascade to receipts; drop them explicitly.
    for receipt in &receipts {
        let tx = client
            .transaction()
            .await
            .expect("start receipt cleanup transaction");
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&receipt.tenant_id],
        )
        .await
        .expect("set tenant context for receipt cleanup");
        let _ = tx
            .execute(
                "DELETE FROM trace_community_withdrawal_evictions WHERE eviction_id = $1",
                &[&receipt.eviction_id],
            )
            .await;
        tx.commit().await.expect("commit receipt cleanup");
    }
    drop(client);

    cleanup_trace_tenants(&backend, &[&tenant_a, &tenant_b]).await;
}
