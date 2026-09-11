// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::db::postgres::PgBackend;
use crate::db::trace_corpus_common::{
    audit_action_for_status, enum_from_storage, enum_to_storage,
    validate_tenant_scoped_trace_object_ref, validate_trace_audit_append_chain,
};
use crate::error::DatabaseError;
use crate::trace_corpus_storage::{
    TenantScopedTraceObjectRef, TraceArtifactInvalidationCounts, TraceAuditEventRecord,
    TraceAuditEventWrite, TraceAuditSafeMetadata, TraceBenchmarkRegistryOutboxItemRecord,
    TraceBenchmarkRegistryOutboxItemWrite, TraceBenchmarkRegistryOutboxStatus, TraceCorpusStatus,
    TraceCorpusStore, TraceCreditEventRecord, TraceCreditEventType, TraceCreditEventWrite,
    TraceCreditHoldReason, TraceCreditHoldRecord, TraceCreditHoldWrite,
    TraceCreditSettlementBatchRecord, TraceCreditSettlementBatchStatus,
    TraceCreditSettlementBatchWrite, TraceCreditSettlementNearStatus, TraceCreditSettlementState,
    TraceDerivedRecord, TraceDerivedRecordWrite, TraceDerivedStatus, TraceExportAccessGrantRecord,
    TraceExportAccessGrantStatus, TraceExportAccessGrantWrite, TraceExportJobRecord,
    TraceExportJobStatus, TraceExportJobStatusUpdate, TraceExportJobWrite,
    TraceExportManifestItemInvalidationReason, TraceExportManifestItemRecord,
    TraceExportManifestItemWrite, TraceExportManifestMirrorWrite, TraceExportManifestRecord,
    TraceExportManifestWrite, TraceGateChunkVectorEntryRow, TraceGateDecisionRow,
    TraceNearCreditOutboxItemRecord, TraceNearCreditOutboxItemWrite, TraceObjectArtifactKind,
    TraceObjectRefRecord, TraceObjectRefWrite, TraceRankingCalibrationDatasetRecord,
    TraceRankingCalibrationDatasetStatus, TraceRankingCalibrationDatasetStatusUpdate,
    TraceRankingCalibrationDatasetWrite, TraceRankingCalibrationRunRecord,
    TraceRankingCalibrationRunWrite, TraceRankingFeatureRecord, TraceRankingFeatureWrite,
    TraceRankingLabelOutcome, TraceRankingLabelRecord, TraceRankingLabelSource,
    TraceRankingLabelWrite, TraceRankingModelStatus, TraceRankingModelVersionRecord,
    TraceRankingModelVersionWrite, TraceRankingPredictionRecord, TraceRankingPredictionWrite,
    TraceRankingPreferenceLabelRecord, TraceRankingPreferenceLabelWrite,
    TraceRankingUtilityCategory, TraceRankingWorkerRunKind, TraceRankingWorkerRunRecord,
    TraceRankingWorkerRunStatus, TraceRankingWorkerRunWrite, TraceRetentionJobItemAction,
    TraceRetentionJobItemRecord, TraceRetentionJobItemStatus, TraceRetentionJobItemWrite,
    TraceRetentionJobRecord, TraceRetentionJobStatus, TraceRetentionJobWrite,
    TraceRevocationPropagationAction, TraceRevocationPropagationItemRecord,
    TraceRevocationPropagationItemStatus, TraceRevocationPropagationItemStatusUpdate,
    TraceRevocationPropagationItemWrite, TraceRevocationPropagationTarget,
    TraceRevocationPropagationTargetKind, TraceSubmissionKeysetCursor, TraceSubmissionRecord,
    TraceSubmissionWrite, TraceTenantAccessGrantRecord, TraceTenantAccessGrantRole,
    TraceTenantAccessGrantStatus, TraceTenantAccessGrantWrite, TraceTenantPolicyRecord,
    TraceTenantPolicyWrite, TraceTombstoneRecord, TraceTombstoneWrite,
    TraceUtilityAttestationRecord, TraceUtilityAttestationWrite, TraceVectorEntryRecord,
    TraceVectorEntrySourceProjection, TraceVectorEntryStatus, TraceVectorEntryWrite,
    TraceWithdrawalRecord, TraceWorkerKind,
};

const TRACE_OBJECT_REF_COLUMNS: &str = "\
    tenant_id, submission_id, object_ref_id, artifact_kind, object_store, object_key, \
    content_sha256, encryption_key_ref, size_bytes, compression, created_by_job_id, \
    invalidated_at, deleted_at, updated_at, created_at";

const TRACE_EXPORT_MANIFEST_COLUMNS: &str = "\
    tenant_id, export_manifest_id, artifact_kind, purpose_code, audit_event_id, \
    source_submission_ids, source_submission_ids_hash, item_count, generated_at, \
    invalidated_at, deleted_at, created_at, updated_at";

const TRACE_EXPORT_MANIFEST_ITEM_COLUMNS: &str = "\
    tenant_id, export_manifest_id, submission_id, trace_id, derived_id, object_ref_id, \
    vector_entry_id, source_status_at_export, source_hash_at_export, source_invalidated_at, \
    source_invalidation_reason, created_at, updated_at";

const TRACE_TOMBSTONE_COLUMNS: &str = "\
    tenant_id, tombstone_id, submission_id, trace_id, redaction_hash, canonical_summary_hash, \
    reason, effective_at, retain_until, created_by_principal_ref, created_at";

const TRACE_RETENTION_JOB_COLUMNS: &str = "\
    tenant_id, retention_job_id, purpose, dry_run, status, requested_by_principal_ref, \
    requested_by_role, purge_expired_before, prune_export_cache, max_export_age_hours, \
    audit_event_id, action_counts, selected_revoked_count, selected_expired_count, \
    started_at, completed_at, created_at, updated_at";

const TRACE_RETENTION_JOB_ITEM_COLUMNS: &str = "\
    tenant_id, retention_job_id, submission_id, action, status, reason, action_counts, \
    verified_at, created_at, updated_at";

const TRACE_REVOCATION_PROPAGATION_ITEM_COLUMNS: &str = "\
    tenant_id, propagation_item_id, source_submission_id, trace_id, target_kind, target_json, \
    action, status, idempotency_key, reason, attempt_count, last_error, next_attempt_at, \
    completed_at, evidence_hash, metadata_json, created_at, updated_at";

const TRACE_EXPORT_ACCESS_GRANT_COLUMNS: &str = "\
    tenant_id, export_job_id, grant_id, caller_principal_ref, requested_dataset_kind, \
    purpose, max_item_cap, status, requested_at, expires_at, metadata_json, created_at, updated_at";

const TRACE_EXPORT_JOB_COLUMNS: &str = "\
    tenant_id, export_job_id, grant_id, caller_principal_ref, requested_dataset_kind, \
    purpose, max_item_cap, status, requested_at, started_at, finished_at, expires_at, \
    result_manifest_id, item_count, last_error, metadata_json, created_at, updated_at";

const TRACE_UTILITY_ATTESTATION_COLUMNS: &str = "\
    tenant_id, attestation_id, event_type, use_category, policy_version, evidence_hash, \
    external_ref_hash, source_submission_ids, actor_principal_ref, created_at";

const TRACE_CREDIT_SETTLEMENT_BATCH_COLUMNS: &str = "\
    tenant_id, settlement_batch_id, policy_version, status, reason_hash, \
    issuer_approval_evidence_hash, source_credit_event_ids, source_submission_ids, \
    source_list_hash, settled_credit_points, settled_credit_micros, line_items_json, \
    near_contract_id, ranking_model_version, \
    ranking_target_use, ranking_calibration_run_id, ranking_calibration_report_hash, \
    ranking_calibration_joined_evidence_hash, ranking_credit_events_excluded_count, \
    ranking_credit_events_excluded_reason_counts_json, actor_principal_ref, created_at";

/// The shadow correction-value UPDATE (migration V48). Held as a named const
/// so a test can pin what it is allowed to touch: only the six correction_*
/// columns, on exactly one tenant-scoped decision row.
const UPDATE_CORRECTION_VALUE_SQL: &str = "UPDATE trace_gate_decisions
                SET correction_simhash = $3,
                    correction_cluster_id = $4,
                    correction_cluster_size = $5,
                    correction_novelty_micros = $6,
                    correction_value_micros = $7,
                    correction_value_version = $8
             WHERE tenant_id = $1 AND decision_id = $2";

const TRACE_CREDIT_HOLD_COLUMNS: &str = "\
    tenant_id, hold_id, credit_account_ref, credit_account_hash, reason, reason_hash, \
    actor_principal_ref, created_at, released_at";

const TRACE_NEAR_CREDIT_OUTBOX_COLUMNS: &str = "\
    tenant_id, near_outbox_id, settlement_batch_id, credit_account_hash, near_call_json, \
    status, payout_near_account_id, created_at, submitted_at, near_transaction_hash, \
    last_error_hash, confirmed_at";

// The account-hold outbox table has no payout designation; project a typed NULL
// so the shared `row_to_near_credit_outbox_item` mapper can read the column.
const TRACE_NEAR_CREDIT_ACCOUNT_OUTBOX_COLUMNS: &str = "\
    tenant_id, near_outbox_id, credit_hold_id AS settlement_batch_id, credit_account_hash, \
    near_call_json, status, NULL::text AS payout_near_account_id, created_at, submitted_at, \
    near_transaction_hash, last_error_hash, confirmed_at";

const TRACE_BENCHMARK_REGISTRY_OUTBOX_COLUMNS: &str = "\
    tenant_id, benchmark_outbox_id, conversion_id, operation, registry_ref, \
    artifact_payload_hash, source_submission_ids_hash, evaluator_ref, evaluation_score, \
    status, created_at, submitted_at, external_receipt_ref, last_error_hash, confirmed_at";

const TRACE_TENANT_ACCESS_GRANT_COLUMNS: &str = "\
    tenant_id, grant_id, principal_ref, role, status, allowed_consent_scopes, allowed_uses, \
    issuer, audience, subject, issued_at, expires_at, revoked_at, created_by_principal_ref, \
    revoked_by_principal_ref, reason, metadata_json, created_at, updated_at";

const TRACE_RANKING_MODEL_VERSION_COLUMNS: &str = "\
    tenant_id, model_version, feature_schema_version, policy_version, status, \
    training_dataset_hash, calibration_dataset_hash, model_artifact_hash, \
    actor_principal_ref, created_at";

const TRACE_RANKING_CALIBRATION_DATASET_COLUMNS: &str = "\
    tenant_id, calibration_dataset_hash, target_use, policy_version, source_manifest_hash, \
    source_count, label_source_count, label_actor_count, status, actor_principal_ref, created_at";

const TRACE_RANKING_FEATURE_COLUMNS: &str = "\
    tenant_id, ranking_feature_id, submission_id, trace_id, target_use, \
    feature_schema_version, feature_vector_hash, feature_names_hash, source_feature_hash, \
    duplicate_score, novelty_score, privacy_risk_score, quality_score, coverage_tags, \
    actor_principal_ref, created_at";

const TRACE_RANKING_PREDICTION_COLUMNS: &str = "\
    tenant_id, ranking_prediction_id, submission_id, trace_id, target_use, model_version, \
    feature_schema_version, prediction_policy_version, feature_vector_hash, \
    predicted_utility_micros, uncertainty_micros, confidence, risk_penalty_micros, \
    novelty_bonus_micros, settlement_score_micros, explanation_codes, actor_principal_ref, \
    created_at";

const TRACE_RANKING_LABEL_COLUMNS: &str = "\
    tenant_id, ranking_label_id, submission_id, trace_id, target_use, label_source, \
    utility_category, label_outcome, utility_delta_micros, evidence_hash, external_ref_hash, \
    actor_principal_ref, created_at";

const TRACE_RANKING_PREFERENCE_LABEL_COLUMNS: &str = "\
    tenant_id, preference_label_id, preferred_submission_id, preferred_trace_id, \
    rejected_submission_id, rejected_trace_id, target_use, label_source, utility_category, \
    preference_strength_micros, evidence_hash, external_ref_hash, actor_principal_ref, \
    created_at";

const TRACE_RANKING_CALIBRATION_RUN_COLUMNS: &str = "\
    tenant_id, calibration_run_id, model_version, target_use, policy_version, \
    evaluation_dataset_hash, prediction_count, label_count, joined_label_prediction_count, \
    joined_label_source_count, joined_label_actor_count, joined_evidence_hash, \
    average_predicted_utility_micros, average_label_utility_delta_micros, \
    average_absolute_error_micros, max_label_source_average_absolute_error_micros, \
    max_error_label_source, mean_signed_error_micros, low_confidence_prediction_count, \
    confidence_threshold, min_label_count, min_label_source_count, \
    max_average_absolute_error_micros, promotable, reason_codes, report_hash, actor_principal_ref, \
    created_at";

const TRACE_RANKING_WORKER_RUN_COLUMNS: &str = "\
    tenant_id, ranking_worker_run_id, run_kind, status, dry_run, reason_hash, model_version, target_use, \
    policy_version, limit_count, checked_count, succeeded_count, skipped_existing_count, \
    skipped_model_risk_count, skipped_ineligible_count, pending_after_count, result_refs, \
    reason_counts, actor_principal_ref, created_at, completed_at, last_error_hash";

async fn ensure_pg_object_ref_belongs_to_submission(
    tx: &Transaction<'_>,
    tenant_id: &str,
    submission_id: Uuid,
    object_ref_id: Uuid,
    field: &str,
) -> Result<(), DatabaseError> {
    let exists = tx
        .query_opt(
            "SELECT 1
             FROM trace_object_refs
             WHERE tenant_id = $1
               AND submission_id = $2
               AND object_ref_id = $3
             LIMIT 1",
            &[&tenant_id, &submission_id, &object_ref_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?
        .is_some();
    if exists {
        return Ok(());
    }

    Err(DatabaseError::Constraint(format!(
        "trace {field} object_ref_id {object_ref_id} does not belong to tenant {tenant_id} submission {submission_id}"
    )))
}

async fn ensure_pg_derived_record_belongs_to_submission(
    tx: &Transaction<'_>,
    tenant_id: &str,
    submission_id: Uuid,
    derived_id: Uuid,
) -> Result<(), DatabaseError> {
    let exists = tx
        .query_opt(
            "SELECT 1
             FROM trace_derived_records
             WHERE tenant_id = $1
               AND submission_id = $2
               AND derived_id = $3
             LIMIT 1",
            &[&tenant_id, &submission_id, &derived_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?
        .is_some();
    if exists {
        return Ok(());
    }

    Err(DatabaseError::Constraint(format!(
        "trace export manifest derived_id {derived_id} does not belong to tenant {tenant_id} submission {submission_id}"
    )))
}

async fn ensure_pg_vector_entry_belongs_to_submission(
    tx: &Transaction<'_>,
    tenant_id: &str,
    submission_id: Uuid,
    vector_entry_id: Uuid,
) -> Result<(), DatabaseError> {
    let exists = tx
        .query_opt(
            "SELECT 1
             FROM trace_vector_entries
             WHERE tenant_id = $1
               AND submission_id = $2
               AND vector_entry_id = $3
             LIMIT 1",
            &[&tenant_id, &submission_id, &vector_entry_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?
        .is_some();
    if exists {
        return Ok(());
    }

    Err(DatabaseError::Constraint(format!(
        "trace export manifest vector_entry_id {vector_entry_id} does not belong to tenant {tenant_id} submission {submission_id}"
    )))
}

fn json_array_strings(
    value: serde_json::Value,
    column: &str,
) -> Result<Vec<String>, DatabaseError> {
    let values = value.as_array().ok_or_else(|| {
        DatabaseError::Serialization(format!("trace {column} column is not a JSON array"))
    })?;
    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                DatabaseError::Serialization(format!(
                    "trace {column} column contains a non-string value"
                ))
            })
        })
        .collect()
}

fn json_u32_map(
    value: serde_json::Value,
    column: &str,
) -> Result<BTreeMap<String, u32>, DatabaseError> {
    serde_json::from_value(value).map_err(|e| {
        DatabaseError::Serialization(format!("trace {column} column JSON decode failed: {e}"))
    })
}

fn row_to_submission(row: &Row) -> Result<TraceSubmissionRecord, DatabaseError> {
    let status: String = row.get("status");
    let consent_scopes: serde_json::Value = row.get("consent_scopes");
    let allowed_uses: serde_json::Value = row.get("allowed_uses");
    let redaction_counts: serde_json::Value = row.get("redaction_counts");
    Ok(TraceSubmissionRecord {
        tenant_id: row.get("tenant_id"),
        submission_id: row.get("submission_id"),
        trace_id: row.get("trace_id"),
        status: enum_from_storage::<TraceCorpusStatus>(&status, "TraceCorpusStatus")?,
        auth_principal_ref: row.get("auth_principal_ref"),
        contributor_pseudonym: row.get("contributor_pseudonym"),
        submitted_tenant_scope_ref: row.get("submitted_tenant_scope_ref"),
        schema_version: row.get("schema_version"),
        consent_policy_version: row.get("consent_policy_version"),
        consent_scopes: json_array_strings(consent_scopes, "consent_scopes")?,
        allowed_uses: json_array_strings(allowed_uses, "allowed_uses")?,
        retention_policy_id: row.get("retention_policy_id"),
        privacy_risk: row.get("privacy_risk"),
        redaction_pipeline_version: row.get("redaction_pipeline_version"),
        redaction_counts: json_u32_map(redaction_counts, "redaction_counts")?,
        redaction_hash: row.get("redaction_hash"),
        canonical_summary_hash: row.get("canonical_summary_hash"),
        submission_score: row.get("submission_score"),
        credit_points_pending: row.get("credit_points_pending"),
        credit_points_final: row.get("credit_points_final"),
        received_at: row.get("received_at"),
        updated_at: row.get("updated_at"),
        reviewed_at: row.get("reviewed_at"),
        review_assigned_to_principal_ref: row.get("review_assigned_to_principal_ref"),
        review_assigned_at: row.get("review_assigned_at"),
        review_lease_expires_at: row.get("review_lease_expires_at"),
        review_due_at: row.get("review_due_at"),
        revoked_at: row.get("revoked_at"),
        expires_at: row.get("expires_at"),
        purged_at: row.get("purged_at"),
        last_status_reason: row.get("last_status_reason"),
        // NULL reads as "not recorded" (every row before V51), never as an
        // empty basis. `Some(vec![])` is the distinct recorded-and-empty case.
        residual_risk_basis: row
            .get::<_, Option<serde_json::Value>>("residual_risk_basis")
            .map(|value| json_array_strings(value, "residual_risk_basis"))
            .transpose()?,
    })
}

fn row_to_tenant_policy(row: &Row) -> Result<TraceTenantPolicyRecord, DatabaseError> {
    let allowed_consent_scopes: serde_json::Value = row.get("allowed_consent_scopes");
    let allowed_uses: serde_json::Value = row.get("allowed_uses");
    Ok(TraceTenantPolicyRecord {
        tenant_id: row.get("tenant_id"),
        policy_version: row.get("policy_version"),
        allowed_consent_scopes: json_array_strings(
            allowed_consent_scopes,
            "allowed_consent_scopes",
        )?,
        allowed_uses: json_array_strings(allowed_uses, "allowed_uses")?,
        updated_by_principal_ref: row.get("updated_by_principal_ref"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_tenant_access_grant(row: &Row) -> Result<TraceTenantAccessGrantRecord, DatabaseError> {
    let role: String = row.get("role");
    let status: String = row.get("status");
    let allowed_consent_scopes: serde_json::Value = row.get("allowed_consent_scopes");
    let allowed_uses: serde_json::Value = row.get("allowed_uses");
    let metadata_json: serde_json::Value = row.get("metadata_json");
    Ok(TraceTenantAccessGrantRecord {
        tenant_id: row.get("tenant_id"),
        grant_id: row.get("grant_id"),
        principal_ref: row.get("principal_ref"),
        role: enum_from_storage::<TraceTenantAccessGrantRole>(&role, "TraceTenantAccessGrantRole")?,
        status: enum_from_storage::<TraceTenantAccessGrantStatus>(
            &status,
            "TraceTenantAccessGrantStatus",
        )?,
        allowed_consent_scopes: json_array_strings(
            allowed_consent_scopes,
            "tenant_access_grants.allowed_consent_scopes",
        )?,
        allowed_uses: json_array_strings(allowed_uses, "tenant_access_grants.allowed_uses")?,
        issuer: row.get("issuer"),
        audience: row.get("audience"),
        subject: row.get("subject"),
        issued_at: row.get("issued_at"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
        created_by_principal_ref: row.get("created_by_principal_ref"),
        revoked_by_principal_ref: row.get("revoked_by_principal_ref"),
        reason: row.get("reason"),
        metadata: serde_json::from_value(metadata_json).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace tenant access grant metadata decode failed: {e}"
            ))
        })?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_object_ref(row: &Row) -> Result<TraceObjectRefRecord, DatabaseError> {
    let artifact_kind: String = row.get("artifact_kind");
    Ok(TraceObjectRefRecord {
        tenant_id: row.get("tenant_id"),
        submission_id: row.get("submission_id"),
        object_ref_id: row.get("object_ref_id"),
        artifact_kind: enum_from_storage::<TraceObjectArtifactKind>(
            &artifact_kind,
            "TraceObjectArtifactKind",
        )?,
        object_store: row.get("object_store"),
        object_key: row.get("object_key"),
        content_sha256: row.get("content_sha256"),
        encryption_key_ref: row.get("encryption_key_ref"),
        size_bytes: row.get("size_bytes"),
        compression: row.get("compression"),
        created_by_job_id: row.get("created_by_job_id"),
        invalidated_at: row.get("invalidated_at"),
        deleted_at: row.get("deleted_at"),
        updated_at: row.get("updated_at"),
        created_at: row.get("created_at"),
    })
}

fn row_to_credit_event(row: &Row) -> Result<TraceCreditEventRecord, DatabaseError> {
    let event_type: String = row.get("event_type");
    let settlement_state: String = row.get("settlement_state");
    Ok(TraceCreditEventRecord {
        tenant_id: row.get("tenant_id"),
        credit_event_id: row.get("credit_event_id"),
        submission_id: row.get("submission_id"),
        trace_id: row.get("trace_id"),
        credit_account_ref: row.get("credit_account_ref"),
        event_type: enum_from_storage(&event_type, "TraceCreditEventType")?,
        points_delta: row.get("points_delta"),
        reason: row.get("reason"),
        external_ref: row.get("external_ref"),
        actor_principal_ref: row.get("actor_principal_ref"),
        actor_role: row.get("actor_role"),
        settlement_state: enum_from_storage::<TraceCreditSettlementState>(
            &settlement_state,
            "TraceCreditSettlementState",
        )?,
        occurred_at: row.get("occurred_at"),
    })
}

fn row_to_utility_attestation(row: &Row) -> Result<TraceUtilityAttestationRecord, DatabaseError> {
    let event_type: String = row.get("event_type");
    Ok(TraceUtilityAttestationRecord {
        tenant_id: row.get("tenant_id"),
        attestation_id: row.get("attestation_id"),
        event_type: enum_from_storage::<TraceCreditEventType>(&event_type, "TraceCreditEventType")?,
        use_category: row.get("use_category"),
        policy_version: row.get("policy_version"),
        evidence_hash: row.get("evidence_hash"),
        external_ref_hash: row.get("external_ref_hash"),
        source_submission_ids: row.get("source_submission_ids"),
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_credit_settlement_batch(
    row: &Row,
) -> Result<TraceCreditSettlementBatchRecord, DatabaseError> {
    let status: String = row.get("status");
    let line_items_json: serde_json::Value = row.get("line_items_json");
    let ranking_credit_events_excluded_reason_counts_json: serde_json::Value =
        row.get("ranking_credit_events_excluded_reason_counts_json");
    Ok(TraceCreditSettlementBatchRecord {
        tenant_id: row.get("tenant_id"),
        settlement_batch_id: row.get("settlement_batch_id"),
        policy_version: row.get("policy_version"),
        status: enum_from_storage::<TraceCreditSettlementBatchStatus>(
            &status,
            "TraceCreditSettlementBatchStatus",
        )?,
        reason_hash: row.get("reason_hash"),
        issuer_approval_evidence_hash: row.get("issuer_approval_evidence_hash"),
        source_credit_event_ids: row.get("source_credit_event_ids"),
        source_submission_ids: row.get("source_submission_ids"),
        source_list_hash: row.get("source_list_hash"),
        settled_credit_points: row.get("settled_credit_points"),
        settled_credit_micros: row.get("settled_credit_micros"),
        line_items: serde_json::from_value(line_items_json).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace credit settlement line_items_json decode failed: {e}"
            ))
        })?,
        near_contract_id: row.get("near_contract_id"),
        ranking_model_version: row.get("ranking_model_version"),
        ranking_target_use: row.get("ranking_target_use"),
        ranking_calibration_run_id: row.get("ranking_calibration_run_id"),
        ranking_calibration_report_hash: row.get("ranking_calibration_report_hash"),
        ranking_calibration_joined_evidence_hash: row
            .get("ranking_calibration_joined_evidence_hash"),
        ranking_credit_events_excluded_count: row_i32_to_u32(
            row,
            "ranking_credit_events_excluded_count",
        )?,
        ranking_credit_events_excluded_reason_counts: serde_json::from_value(
            ranking_credit_events_excluded_reason_counts_json,
        )
        .map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace credit settlement ranking exclusion reason counts decode failed: {e}"
            ))
        })?,
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_credit_hold(row: &Row) -> Result<TraceCreditHoldRecord, DatabaseError> {
    let reason: String = row.get("reason");
    Ok(TraceCreditHoldRecord {
        tenant_id: row.get("tenant_id"),
        hold_id: row.get("hold_id"),
        credit_account_ref: row.get("credit_account_ref"),
        credit_account_hash: row.get("credit_account_hash"),
        reason: enum_from_storage::<TraceCreditHoldReason>(&reason, "TraceCreditHoldReason")?,
        reason_hash: row.get("reason_hash"),
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
        released_at: row.get("released_at"),
    })
}

fn row_to_near_credit_outbox_item(
    row: &Row,
) -> Result<TraceNearCreditOutboxItemRecord, DatabaseError> {
    let status: String = row.get("status");
    Ok(TraceNearCreditOutboxItemRecord {
        tenant_id: row.get("tenant_id"),
        near_outbox_id: row.get("near_outbox_id"),
        settlement_batch_id: row.get("settlement_batch_id"),
        credit_account_hash: row.get("credit_account_hash"),
        near_call_json: row.get("near_call_json"),
        status: enum_from_storage::<TraceCreditSettlementNearStatus>(
            &status,
            "TraceCreditSettlementNearStatus",
        )?,
        payout_near_account_id: row.get("payout_near_account_id"),
        created_at: row.get("created_at"),
        submitted_at: row.get("submitted_at"),
        near_transaction_hash: row.get("near_transaction_hash"),
        last_error_hash: row.get("last_error_hash"),
        confirmed_at: row.get("confirmed_at"),
    })
}

fn near_credit_call_method_name(call: &serde_json::Value) -> Option<&str> {
    call.get("method_name").and_then(serde_json::Value::as_str)
}

fn near_credit_call_is_account_operation(call: &serde_json::Value) -> bool {
    near_credit_call_method_name(call).is_some_and(|method_name| {
        matches!(
            method_name,
            "freeze_credit_account" | "unfreeze_credit_account"
        )
    })
}

fn row_to_benchmark_registry_outbox_item(
    row: &Row,
) -> Result<TraceBenchmarkRegistryOutboxItemRecord, DatabaseError> {
    let operation: String = row.get("operation");
    let status: String = row.get("status");
    Ok(TraceBenchmarkRegistryOutboxItemRecord {
        tenant_id: row.get("tenant_id"),
        benchmark_outbox_id: row.get("benchmark_outbox_id"),
        conversion_id: row.get("conversion_id"),
        operation: enum_from_storage(&operation, "TraceBenchmarkRegistryOutboxOperation")?,
        registry_ref: row.get("registry_ref"),
        artifact_payload_hash: row.get("artifact_payload_hash"),
        source_submission_ids_hash: row.get("source_submission_ids_hash"),
        evaluator_ref: row.get("evaluator_ref"),
        evaluation_score: row.get("evaluation_score"),
        status: enum_from_storage::<TraceBenchmarkRegistryOutboxStatus>(
            &status,
            "TraceBenchmarkRegistryOutboxStatus",
        )?,
        created_at: row.get("created_at"),
        submitted_at: row.get("submitted_at"),
        external_receipt_ref: row.get("external_receipt_ref"),
        last_error_hash: row.get("last_error_hash"),
        confirmed_at: row.get("confirmed_at"),
    })
}

fn row_to_derived_record(row: &Row) -> Result<TraceDerivedRecord, DatabaseError> {
    let status: String = row.get("status");
    let worker_kind: String = row.get("worker_kind");
    let tenant_id: String = row.get("tenant_id");
    let submission_id: Uuid = row.get("submission_id");
    let input_object_ref_id: Option<Uuid> = row.get("input_object_ref_id");
    let output_object_ref_id: Option<Uuid> = row.get("output_object_ref_id");
    let tool_sequence: serde_json::Value = row.get("tool_sequence");
    let tool_categories: serde_json::Value = row.get("tool_categories");
    let coverage_tags: serde_json::Value = row.get("coverage_tags");
    Ok(TraceDerivedRecord {
        derived_id: row.get("derived_id"),
        tenant_id: tenant_id.clone(),
        submission_id,
        trace_id: row.get("trace_id"),
        status: enum_from_storage::<TraceDerivedStatus>(&status, "TraceDerivedStatus")?,
        worker_kind: enum_from_storage::<TraceWorkerKind>(&worker_kind, "TraceWorkerKind")?,
        worker_version: row.get("worker_version"),
        input_object_ref: input_object_ref_id.map(|object_ref_id| TenantScopedTraceObjectRef {
            tenant_id: tenant_id.clone(),
            submission_id,
            object_ref_id,
        }),
        input_hash: row.get("input_hash"),
        output_object_ref: output_object_ref_id.map(|object_ref_id| TenantScopedTraceObjectRef {
            tenant_id: tenant_id.clone(),
            submission_id,
            object_ref_id,
        }),
        canonical_summary: row.get("canonical_summary"),
        canonical_summary_hash: row.get("canonical_summary_hash"),
        summary_model: row.get("summary_model"),
        task_success: row.get("task_success"),
        privacy_risk: row.get("privacy_risk"),
        event_count: row.get("event_count"),
        tool_sequence: json_array_strings(tool_sequence, "tool_sequence")?,
        tool_categories: json_array_strings(tool_categories, "tool_categories")?,
        coverage_tags: json_array_strings(coverage_tags, "coverage_tags")?,
        duplicate_score: row.get("duplicate_score"),
        novelty_score: row.get("novelty_score"),
        cluster_id: row.get("cluster_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_vector_entry(row: &Row) -> Result<TraceVectorEntryRecord, DatabaseError> {
    let source_projection: String = row.get("source_projection");
    let status: String = row.get("status");
    Ok(TraceVectorEntryRecord {
        tenant_id: row.get("tenant_id"),
        submission_id: row.get("submission_id"),
        derived_id: row.get("derived_id"),
        vector_entry_id: row.get("vector_entry_id"),
        vector_store: row.get("vector_store"),
        embedding_model: row.get("embedding_model"),
        embedding_dimension: row.get("embedding_dimension"),
        embedding_version: row.get("embedding_version"),
        source_projection: enum_from_storage::<TraceVectorEntrySourceProjection>(
            &source_projection,
            "TraceVectorEntrySourceProjection",
        )?,
        source_hash: row.get("source_hash"),
        status: enum_from_storage::<TraceVectorEntryStatus>(&status, "TraceVectorEntryStatus")?,
        nearest_trace_ids: row.get("nearest_trace_ids"),
        cluster_id: row.get("cluster_id"),
        duplicate_score: row.get("duplicate_score"),
        novelty_score: row.get("novelty_score"),
        indexed_at: row.get("indexed_at"),
        invalidated_at: row.get("invalidated_at"),
        deleted_at: row.get("deleted_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_ranking_model_version(
    row: &Row,
) -> Result<TraceRankingModelVersionRecord, DatabaseError> {
    let status: String = row.get("status");
    Ok(TraceRankingModelVersionRecord {
        tenant_id: row.get("tenant_id"),
        model_version: row.get("model_version"),
        feature_schema_version: row.get("feature_schema_version"),
        policy_version: row.get("policy_version"),
        status: enum_from_storage::<TraceRankingModelStatus>(&status, "TraceRankingModelStatus")?,
        training_dataset_hash: row.get("training_dataset_hash"),
        calibration_dataset_hash: row.get("calibration_dataset_hash"),
        model_artifact_hash: row.get("model_artifact_hash"),
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_ranking_calibration_dataset(
    row: &Row,
) -> Result<TraceRankingCalibrationDatasetRecord, DatabaseError> {
    let status: String = row.get("status");
    Ok(TraceRankingCalibrationDatasetRecord {
        tenant_id: row.get("tenant_id"),
        calibration_dataset_hash: row.get("calibration_dataset_hash"),
        target_use: row.get("target_use"),
        policy_version: row.get("policy_version"),
        source_manifest_hash: row.get("source_manifest_hash"),
        source_count: row_i32_to_u32(row, "source_count")?,
        label_source_count: row_i32_to_u32(row, "label_source_count")?,
        label_actor_count: row_i32_to_u32(row, "label_actor_count")?,
        status: enum_from_storage::<TraceRankingCalibrationDatasetStatus>(
            &status,
            "TraceRankingCalibrationDatasetStatus",
        )?,
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_ranking_feature(row: &Row) -> Result<TraceRankingFeatureRecord, DatabaseError> {
    let coverage_tags: serde_json::Value = row.get("coverage_tags");
    Ok(TraceRankingFeatureRecord {
        tenant_id: row.get("tenant_id"),
        ranking_feature_id: row.get("ranking_feature_id"),
        submission_id: row.get("submission_id"),
        trace_id: row.get("trace_id"),
        target_use: row.get("target_use"),
        feature_schema_version: row.get("feature_schema_version"),
        feature_vector_hash: row.get("feature_vector_hash"),
        feature_names_hash: row.get("feature_names_hash"),
        source_feature_hash: row.get("source_feature_hash"),
        duplicate_score: row.get("duplicate_score"),
        novelty_score: row.get("novelty_score"),
        privacy_risk_score: row.get("privacy_risk_score"),
        quality_score: row.get("quality_score"),
        coverage_tags: json_array_strings(coverage_tags, "ranking_features.coverage_tags")?,
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_ranking_prediction(row: &Row) -> Result<TraceRankingPredictionRecord, DatabaseError> {
    let explanation_codes: serde_json::Value = row.get("explanation_codes");
    Ok(TraceRankingPredictionRecord {
        tenant_id: row.get("tenant_id"),
        ranking_prediction_id: row.get("ranking_prediction_id"),
        submission_id: row.get("submission_id"),
        trace_id: row.get("trace_id"),
        target_use: row.get("target_use"),
        model_version: row.get("model_version"),
        feature_schema_version: row.get("feature_schema_version"),
        prediction_policy_version: row.get("prediction_policy_version"),
        feature_vector_hash: row.get("feature_vector_hash"),
        predicted_utility_micros: row.get("predicted_utility_micros"),
        uncertainty_micros: row.get("uncertainty_micros"),
        confidence: row.get("confidence"),
        risk_penalty_micros: row.get("risk_penalty_micros"),
        novelty_bonus_micros: row.get("novelty_bonus_micros"),
        settlement_score_micros: row.get("settlement_score_micros"),
        explanation_codes: json_array_strings(
            explanation_codes,
            "ranking_predictions.explanation_codes",
        )?,
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_ranking_label(row: &Row) -> Result<TraceRankingLabelRecord, DatabaseError> {
    let label_source: String = row.get("label_source");
    let utility_category: String = row.get("utility_category");
    let label_outcome: String = row.get("label_outcome");
    Ok(TraceRankingLabelRecord {
        tenant_id: row.get("tenant_id"),
        ranking_label_id: row.get("ranking_label_id"),
        submission_id: row.get("submission_id"),
        trace_id: row.get("trace_id"),
        target_use: row.get("target_use"),
        label_source: enum_from_storage::<TraceRankingLabelSource>(
            &label_source,
            "TraceRankingLabelSource",
        )?,
        utility_category: enum_from_storage::<TraceRankingUtilityCategory>(
            &utility_category,
            "TraceRankingUtilityCategory",
        )?,
        label_outcome: enum_from_storage::<TraceRankingLabelOutcome>(
            &label_outcome,
            "TraceRankingLabelOutcome",
        )?,
        utility_delta_micros: row.get("utility_delta_micros"),
        evidence_hash: row.get("evidence_hash"),
        external_ref_hash: row.get("external_ref_hash"),
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_ranking_preference_label(
    row: &Row,
) -> Result<TraceRankingPreferenceLabelRecord, DatabaseError> {
    let label_source: String = row.get("label_source");
    let utility_category: String = row.get("utility_category");
    Ok(TraceRankingPreferenceLabelRecord {
        tenant_id: row.get("tenant_id"),
        preference_label_id: row.get("preference_label_id"),
        preferred_submission_id: row.get("preferred_submission_id"),
        preferred_trace_id: row.get("preferred_trace_id"),
        rejected_submission_id: row.get("rejected_submission_id"),
        rejected_trace_id: row.get("rejected_trace_id"),
        target_use: row.get("target_use"),
        label_source: enum_from_storage::<TraceRankingLabelSource>(
            &label_source,
            "TraceRankingLabelSource",
        )?,
        utility_category: enum_from_storage::<TraceRankingUtilityCategory>(
            &utility_category,
            "TraceRankingUtilityCategory",
        )?,
        preference_strength_micros: row.get("preference_strength_micros"),
        evidence_hash: row.get("evidence_hash"),
        external_ref_hash: row.get("external_ref_hash"),
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_i32_to_u32(row: &Row, column: &str) -> Result<u32, DatabaseError> {
    row.get::<_, i32>(column).try_into().map_err(|e| {
        DatabaseError::Serialization(format!("invalid unsigned {column} column value: {e}"))
    })
}

fn u32_to_pg_i32(value: u32, column: &str) -> Result<i32, DatabaseError> {
    i32::try_from(value).map_err(|e| {
        DatabaseError::Serialization(format!(
            "trace {column} exceeds PostgreSQL integer range: {e}"
        ))
    })
}

fn row_to_ranking_calibration_run(
    row: &Row,
) -> Result<TraceRankingCalibrationRunRecord, DatabaseError> {
    let reason_codes: serde_json::Value = row.get("reason_codes");
    Ok(TraceRankingCalibrationRunRecord {
        tenant_id: row.get("tenant_id"),
        calibration_run_id: row.get("calibration_run_id"),
        model_version: row.get("model_version"),
        target_use: row.get("target_use"),
        policy_version: row.get("policy_version"),
        evaluation_dataset_hash: row.get("evaluation_dataset_hash"),
        prediction_count: row_i32_to_u32(row, "prediction_count")?,
        label_count: row_i32_to_u32(row, "label_count")?,
        joined_label_prediction_count: row_i32_to_u32(row, "joined_label_prediction_count")?,
        joined_label_source_count: row_i32_to_u32(row, "joined_label_source_count")?,
        joined_label_actor_count: row_i32_to_u32(row, "joined_label_actor_count")?,
        joined_evidence_hash: row.get("joined_evidence_hash"),
        average_predicted_utility_micros: row.get("average_predicted_utility_micros"),
        average_label_utility_delta_micros: row.get("average_label_utility_delta_micros"),
        average_absolute_error_micros: row.get("average_absolute_error_micros"),
        max_label_source_average_absolute_error_micros: row
            .get("max_label_source_average_absolute_error_micros"),
        max_error_label_source: row.get("max_error_label_source"),
        mean_signed_error_micros: row.get("mean_signed_error_micros"),
        low_confidence_prediction_count: row_i32_to_u32(row, "low_confidence_prediction_count")?,
        confidence_threshold: row.get("confidence_threshold"),
        min_label_count: row_i32_to_u32(row, "min_label_count")?,
        min_label_source_count: row_i32_to_u32(row, "min_label_source_count")?,
        max_average_absolute_error_micros: row.get("max_average_absolute_error_micros"),
        promotable: row.get("promotable"),
        reason_codes: json_array_strings(reason_codes, "ranking_calibration_runs.reason_codes")?,
        report_hash: row.get("report_hash"),
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_ranking_worker_run(row: &Row) -> Result<TraceRankingWorkerRunRecord, DatabaseError> {
    let run_kind: String = row.get("run_kind");
    let status: String = row.get("status");
    let result_refs: serde_json::Value = row.get("result_refs");
    let reason_counts: serde_json::Value = row.get("reason_counts");
    Ok(TraceRankingWorkerRunRecord {
        tenant_id: row.get("tenant_id"),
        ranking_worker_run_id: row.get("ranking_worker_run_id"),
        run_kind: enum_from_storage::<TraceRankingWorkerRunKind>(
            &run_kind,
            "TraceRankingWorkerRunKind",
        )?,
        status: enum_from_storage::<TraceRankingWorkerRunStatus>(
            &status,
            "TraceRankingWorkerRunStatus",
        )?,
        dry_run: row.get("dry_run"),
        reason_hash: row.get("reason_hash"),
        model_version: row.get("model_version"),
        target_use: row.get("target_use"),
        policy_version: row.get("policy_version"),
        limit: row_i32_to_u32(row, "limit_count")?,
        checked_count: row_i32_to_u32(row, "checked_count")?,
        succeeded_count: row_i32_to_u32(row, "succeeded_count")?,
        skipped_existing_count: row_i32_to_u32(row, "skipped_existing_count")?,
        skipped_model_risk_count: row_i32_to_u32(row, "skipped_model_risk_count")?,
        skipped_ineligible_count: row_i32_to_u32(row, "skipped_ineligible_count")?,
        pending_after_count: row_i32_to_u32(row, "pending_after_count")?,
        result_refs: json_array_strings(result_refs, "ranking_worker_runs.result_refs")?,
        reason_counts: json_u32_map(reason_counts, "ranking_worker_runs.reason_counts")?,
        actor_principal_ref: row.get("actor_principal_ref"),
        created_at: row.get("created_at"),
        completed_at: row.get("completed_at"),
        last_error_hash: row.get("last_error_hash"),
    })
}

fn row_to_export_manifest(row: &Row) -> Result<TraceExportManifestRecord, DatabaseError> {
    let artifact_kind: String = row.get("artifact_kind");
    Ok(TraceExportManifestRecord {
        tenant_id: row.get("tenant_id"),
        export_manifest_id: row.get("export_manifest_id"),
        artifact_kind: enum_from_storage::<TraceObjectArtifactKind>(
            &artifact_kind,
            "TraceObjectArtifactKind",
        )?,
        purpose_code: row.get("purpose_code"),
        audit_event_id: row.get("audit_event_id"),
        source_submission_ids: row.get("source_submission_ids"),
        source_submission_ids_hash: row.get("source_submission_ids_hash"),
        item_count: row.get::<_, i32>("item_count").try_into().map_err(|e| {
            DatabaseError::Serialization(format!(
                "invalid trace_export_manifests.item_count column value: {e}"
            ))
        })?,
        generated_at: row.get("generated_at"),
        invalidated_at: row.get("invalidated_at"),
        deleted_at: row.get("deleted_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_export_manifest_item(row: &Row) -> Result<TraceExportManifestItemRecord, DatabaseError> {
    let source_status_at_export: String = row.get("source_status_at_export");
    let source_invalidation_reason: Option<String> = row.get("source_invalidation_reason");
    Ok(TraceExportManifestItemRecord {
        tenant_id: row.get("tenant_id"),
        export_manifest_id: row.get("export_manifest_id"),
        submission_id: row.get("submission_id"),
        trace_id: row.get("trace_id"),
        derived_id: row.get("derived_id"),
        object_ref_id: row.get("object_ref_id"),
        vector_entry_id: row.get("vector_entry_id"),
        source_status_at_export: enum_from_storage::<TraceCorpusStatus>(
            &source_status_at_export,
            "TraceCorpusStatus",
        )?,
        source_hash_at_export: row.get("source_hash_at_export"),
        source_invalidated_at: row.get("source_invalidated_at"),
        source_invalidation_reason: source_invalidation_reason
            .as_deref()
            .map(|reason| {
                enum_from_storage::<TraceExportManifestItemInvalidationReason>(
                    reason,
                    "TraceExportManifestItemInvalidationReason",
                )
            })
            .transpose()?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_audit_event(row: &Row) -> Result<TraceAuditEventRecord, DatabaseError> {
    let action: String = row.get("action");
    let metadata: serde_json::Value = row.get("metadata_json");
    Ok(TraceAuditEventRecord {
        tenant_id: row.get("tenant_id"),
        audit_sequence: row.get("audit_sequence"),
        audit_event_id: row.get("audit_event_id"),
        actor_principal_ref: row.get("actor_principal_ref"),
        actor_role: row.get("actor_role"),
        action: enum_from_storage(&action, "TraceAuditAction")?,
        reason: row.get("reason"),
        request_id: row.get("request_id"),
        submission_id: row.get("submission_id"),
        object_ref_id: row.get("object_ref_id"),
        export_manifest_id: row.get("export_manifest_id"),
        decision_inputs_hash: row.get("decision_inputs_hash"),
        previous_event_hash: row.get("previous_event_hash"),
        event_hash: row.get("event_hash"),
        canonical_event_json: row.get("canonical_event_json"),
        metadata: serde_json::from_value(metadata).map_err(|e| {
            DatabaseError::Serialization(format!("trace audit metadata JSON decode failed: {e}"))
        })?,
        occurred_at: row.get("occurred_at"),
    })
}

fn row_to_tombstone(row: &Row) -> Result<TraceTombstoneRecord, DatabaseError> {
    Ok(TraceTombstoneRecord {
        tenant_id: row.get("tenant_id"),
        tombstone_id: row.get("tombstone_id"),
        submission_id: row.get("submission_id"),
        trace_id: row.get("trace_id"),
        redaction_hash: row.get("redaction_hash"),
        canonical_summary_hash: row.get("canonical_summary_hash"),
        reason: row.get("reason"),
        effective_at: row.get("effective_at"),
        retain_until: row.get("retain_until"),
        created_by_principal_ref: row.get("created_by_principal_ref"),
        created_at: row.get("created_at"),
    })
}

fn row_to_retention_job(row: &Row) -> Result<TraceRetentionJobRecord, DatabaseError> {
    let status: String = row.get("status");
    let action_counts: serde_json::Value = row.get("action_counts");
    Ok(TraceRetentionJobRecord {
        tenant_id: row.get("tenant_id"),
        retention_job_id: row.get("retention_job_id"),
        purpose: row.get("purpose"),
        dry_run: row.get("dry_run"),
        status: enum_from_storage::<TraceRetentionJobStatus>(&status, "TraceRetentionJobStatus")?,
        requested_by_principal_ref: row.get("requested_by_principal_ref"),
        requested_by_role: row.get("requested_by_role"),
        purge_expired_before: row.get("purge_expired_before"),
        prune_export_cache: row.get("prune_export_cache"),
        max_export_age_hours: row.get("max_export_age_hours"),
        audit_event_id: row.get("audit_event_id"),
        action_counts: json_u32_map(action_counts, "retention_job.action_counts")?,
        selected_revoked_count: row
            .get::<_, i32>("selected_revoked_count")
            .try_into()
            .map_err(|e| {
                DatabaseError::Serialization(format!(
                    "invalid trace_retention_jobs.selected_revoked_count column value: {e}"
                ))
            })?,
        selected_expired_count: row
            .get::<_, i32>("selected_expired_count")
            .try_into()
            .map_err(|e| {
                DatabaseError::Serialization(format!(
                    "invalid trace_retention_jobs.selected_expired_count column value: {e}"
                ))
            })?,
        started_at: row.get("started_at"),
        completed_at: row.get("completed_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_retention_job_item(row: &Row) -> Result<TraceRetentionJobItemRecord, DatabaseError> {
    let action: String = row.get("action");
    let status: String = row.get("status");
    let action_counts: serde_json::Value = row.get("action_counts");
    Ok(TraceRetentionJobItemRecord {
        tenant_id: row.get("tenant_id"),
        retention_job_id: row.get("retention_job_id"),
        submission_id: row.get("submission_id"),
        action: enum_from_storage::<TraceRetentionJobItemAction>(
            &action,
            "TraceRetentionJobItemAction",
        )?,
        status: enum_from_storage::<TraceRetentionJobItemStatus>(
            &status,
            "TraceRetentionJobItemStatus",
        )?,
        reason: row.get("reason"),
        action_counts: json_u32_map(action_counts, "retention_job_item.action_counts")?,
        verified_at: row.get("verified_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_export_access_grant(row: &Row) -> Result<TraceExportAccessGrantRecord, DatabaseError> {
    let status: String = row.get("status");
    let metadata_json: serde_json::Value = row.get("metadata_json");
    Ok(TraceExportAccessGrantRecord {
        tenant_id: row.get("tenant_id"),
        export_job_id: row.get("export_job_id"),
        grant_id: row.get("grant_id"),
        caller_principal_ref: row.get("caller_principal_ref"),
        requested_dataset_kind: row.get("requested_dataset_kind"),
        purpose: row.get("purpose"),
        max_item_cap: row
            .get::<_, Option<i32>>("max_item_cap")
            .map(|value| {
                u32::try_from(value).map_err(|e| {
                    DatabaseError::Serialization(format!(
                        "invalid trace_export_access_grants.max_item_cap column value: {e}"
                    ))
                })
            })
            .transpose()?,
        status: enum_from_storage::<TraceExportAccessGrantStatus>(
            &status,
            "TraceExportAccessGrantStatus",
        )?,
        requested_at: row.get("requested_at"),
        expires_at: row.get("expires_at"),
        metadata: serde_json::from_value(metadata_json).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace export access grant metadata decode failed: {e}"
            ))
        })?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_export_job(row: &Row) -> Result<TraceExportJobRecord, DatabaseError> {
    let status: String = row.get("status");
    let metadata_json: serde_json::Value = row.get("metadata_json");
    Ok(TraceExportJobRecord {
        tenant_id: row.get("tenant_id"),
        export_job_id: row.get("export_job_id"),
        grant_id: row.get("grant_id"),
        caller_principal_ref: row.get("caller_principal_ref"),
        requested_dataset_kind: row.get("requested_dataset_kind"),
        purpose: row.get("purpose"),
        max_item_cap: row
            .get::<_, Option<i32>>("max_item_cap")
            .map(|value| {
                u32::try_from(value).map_err(|e| {
                    DatabaseError::Serialization(format!(
                        "invalid trace_export_jobs.max_item_cap column value: {e}"
                    ))
                })
            })
            .transpose()?,
        status: enum_from_storage::<TraceExportJobStatus>(&status, "TraceExportJobStatus")?,
        requested_at: row.get("requested_at"),
        started_at: row.get("started_at"),
        finished_at: row.get("finished_at"),
        expires_at: row.get("expires_at"),
        result_manifest_id: row.get("result_manifest_id"),
        item_count: row
            .get::<_, Option<i32>>("item_count")
            .map(|value| {
                u32::try_from(value).map_err(|e| {
                    DatabaseError::Serialization(format!(
                        "invalid trace_export_jobs.item_count column value: {e}"
                    ))
                })
            })
            .transpose()?,
        last_error: row.get("last_error"),
        metadata: serde_json::from_value(metadata_json).map_err(|e| {
            DatabaseError::Serialization(format!("trace export job metadata decode failed: {e}"))
        })?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn row_to_revocation_propagation_item(
    row: &Row,
) -> Result<TraceRevocationPropagationItemRecord, DatabaseError> {
    let target_kind: String = row.get("target_kind");
    let target_json: serde_json::Value = row.get("target_json");
    let action: String = row.get("action");
    let status: String = row.get("status");
    let metadata_json: serde_json::Value = row.get("metadata_json");
    let attempt_count = row.get::<_, i32>("attempt_count").try_into().map_err(|e| {
        DatabaseError::Serialization(format!(
            "invalid trace_revocation_propagation_items.attempt_count column value: {e}"
        ))
    })?;

    Ok(TraceRevocationPropagationItemRecord {
        tenant_id: row.get("tenant_id"),
        propagation_item_id: row.get("propagation_item_id"),
        source_submission_id: row.get("source_submission_id"),
        trace_id: row.get("trace_id"),
        target_kind: enum_from_storage::<TraceRevocationPropagationTargetKind>(
            &target_kind,
            "TraceRevocationPropagationTargetKind",
        )?,
        target: serde_json::from_value::<TraceRevocationPropagationTarget>(target_json).map_err(
            |e| {
                DatabaseError::Serialization(format!(
                    "trace revocation propagation target decode failed: {e}"
                ))
            },
        )?,
        action: enum_from_storage::<TraceRevocationPropagationAction>(
            &action,
            "TraceRevocationPropagationAction",
        )?,
        status: enum_from_storage::<TraceRevocationPropagationItemStatus>(
            &status,
            "TraceRevocationPropagationItemStatus",
        )?,
        idempotency_key: row.get("idempotency_key"),
        reason: row.get("reason"),
        attempt_count,
        last_error: row.get("last_error"),
        next_attempt_at: row.get("next_attempt_at"),
        completed_at: row.get("completed_at"),
        evidence_hash: row.get("evidence_hash"),
        metadata: serde_json::from_value(metadata_json).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace revocation propagation metadata decode failed: {e}"
            ))
        })?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

impl PgBackend {
    pub(super) async fn ensure_trace_tenant(&self, tenant_id: &str) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_tenants (tenant_id) VALUES ($1)
             ON CONFLICT (tenant_id) DO UPDATE SET updated_at = NOW()",
            &[&tenant_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    pub(crate) async fn begin_trace_tenant_transaction<'a>(
        client: &'a mut deadpool_postgres::Client,
        tenant_id: &str,
    ) -> Result<deadpool_postgres::Transaction<'a>, DatabaseError> {
        let tx = client
            .transaction()
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        Ok(tx)
    }

    /// Write a finalized settlement batch and every expected NEAR outbox row in
    /// one tenant-scoped transaction. A crash mid-loop can no longer leave the
    /// ledger finalized while payout work is only partially present.
    pub(crate) async fn upsert_credit_settlement_finalize_tx(
        &self,
        batch: TraceCreditSettlementBatchWrite,
        outbox_items: &[TraceNearCreditOutboxItemWrite],
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(&batch.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &batch.tenant_id).await?;
        insert_credit_settlement_batch_on_tx(&tx, &batch).await?;
        for item in outbox_items {
            if item.tenant_id != batch.tenant_id {
                return Err(DatabaseError::Serialization(
                    "NEAR outbox tenant_id does not match settlement batch".to_string(),
                ));
            }
            if item.settlement_batch_id != batch.settlement_batch_id {
                return Err(DatabaseError::Serialization(
                    "NEAR outbox settlement_batch_id does not match settlement batch".to_string(),
                ));
            }
            insert_near_credit_outbox_item_on_tx(&tx, item).await?;
        }
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }
}

async fn insert_credit_settlement_batch_on_tx(
    tx: &Transaction<'_>,
    batch: &TraceCreditSettlementBatchWrite,
) -> Result<(), DatabaseError> {
    let status = enum_to_storage(batch.status)?;
    let line_items_json = serde_json::to_value(&batch.line_items).map_err(|e| {
        DatabaseError::Serialization(format!(
            "trace credit settlement line_items_json encode failed: {e}"
        ))
    })?;
    let ranking_credit_events_excluded_count = i32::try_from(
        batch.ranking_credit_events_excluded_count,
    )
    .map_err(|e| {
        DatabaseError::Serialization(format!(
            "trace credit settlement excluded ranking count exceeds PostgreSQL integer range: {e}"
        ))
    })?;
    let ranking_credit_events_excluded_reason_counts_json =
        serde_json::to_value(&batch.ranking_credit_events_excluded_reason_counts).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace credit settlement ranking exclusion reason counts encode failed: {e}"
            ))
        })?;
    tx.execute(
        "INSERT INTO trace_credit_settlement_batches (
            tenant_id, settlement_batch_id, policy_version, status, reason_hash,
            issuer_approval_evidence_hash, source_credit_event_ids,
            source_submission_ids, source_list_hash, settled_credit_points,
            settled_credit_micros, line_items_json, near_contract_id,
            ranking_model_version, ranking_target_use,
            ranking_calibration_run_id, ranking_calibration_report_hash,
            ranking_calibration_joined_evidence_hash,
            ranking_credit_events_excluded_count,
            ranking_credit_events_excluded_reason_counts_json,
            actor_principal_ref
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21
         )
         ON CONFLICT (tenant_id, settlement_batch_id) DO UPDATE SET
            policy_version = excluded.policy_version,
            status = excluded.status,
            reason_hash = excluded.reason_hash,
            issuer_approval_evidence_hash = excluded.issuer_approval_evidence_hash,
            source_credit_event_ids = excluded.source_credit_event_ids,
            source_submission_ids = excluded.source_submission_ids,
            source_list_hash = excluded.source_list_hash,
            settled_credit_points = excluded.settled_credit_points,
            settled_credit_micros = excluded.settled_credit_micros,
            line_items_json = excluded.line_items_json,
            near_contract_id = excluded.near_contract_id,
            ranking_model_version = excluded.ranking_model_version,
            ranking_target_use = excluded.ranking_target_use,
            ranking_calibration_run_id = excluded.ranking_calibration_run_id,
            ranking_calibration_report_hash = excluded.ranking_calibration_report_hash,
            ranking_calibration_joined_evidence_hash = excluded.ranking_calibration_joined_evidence_hash,
            ranking_credit_events_excluded_count = excluded.ranking_credit_events_excluded_count,
            ranking_credit_events_excluded_reason_counts_json = excluded.ranking_credit_events_excluded_reason_counts_json,
            actor_principal_ref = excluded.actor_principal_ref",
        &[
            &batch.tenant_id,
            &batch.settlement_batch_id,
            &batch.policy_version,
            &status,
            &batch.reason_hash,
            &batch.issuer_approval_evidence_hash,
            &batch.source_credit_event_ids,
            &batch.source_submission_ids,
            &batch.source_list_hash,
            &batch.settled_credit_points,
            &batch.settled_credit_micros,
            &line_items_json,
            &batch.near_contract_id,
            &batch.ranking_model_version,
            &batch.ranking_target_use,
            &batch.ranking_calibration_run_id,
            &batch.ranking_calibration_report_hash,
            &batch.ranking_calibration_joined_evidence_hash,
            &ranking_credit_events_excluded_count,
            &ranking_credit_events_excluded_reason_counts_json,
            &batch.actor_principal_ref,
        ],
    )
    .await
    .map_err(DatabaseError::Postgres)?;
    Ok(())
}

async fn insert_near_credit_outbox_item_on_tx(
    tx: &Transaction<'_>,
    item: &TraceNearCreditOutboxItemWrite,
) -> Result<(), DatabaseError> {
    let status = enum_to_storage(item.status)?;
    let account_operation = near_credit_call_method_name(&item.near_call_json)
        .filter(|_| near_credit_call_is_account_operation(&item.near_call_json))
        .map(str::to_string);
    if let Some(account_operation) = account_operation {
        tx.execute(
            "INSERT INTO trace_near_credit_account_outbox (
                tenant_id, near_outbox_id, credit_hold_id, operation,
                credit_account_hash, near_call_json, status
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, near_outbox_id) DO UPDATE SET
                credit_hold_id = excluded.credit_hold_id,
                operation = excluded.operation,
                credit_account_hash = excluded.credit_account_hash,
                near_call_json = excluded.near_call_json,
                status = excluded.status",
            &[
                &item.tenant_id,
                &item.near_outbox_id,
                &item.settlement_batch_id,
                &account_operation,
                &item.credit_account_hash,
                &item.near_call_json,
                &status,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO trace_near_credit_outbox (
            tenant_id, near_outbox_id, settlement_batch_id, credit_account_hash,
            near_call_json, status, payout_near_account_id
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (tenant_id, near_outbox_id) DO UPDATE SET
            settlement_batch_id = excluded.settlement_batch_id,
            credit_account_hash = excluded.credit_account_hash,
            near_call_json = excluded.near_call_json,
            status = excluded.status,
            payout_near_account_id = excluded.payout_near_account_id",
        &[
            &item.tenant_id,
            &item.near_outbox_id,
            &item.settlement_batch_id,
            &item.credit_account_hash,
            &item.near_call_json,
            &status,
            &item.payout_near_account_id,
        ],
    )
    .await
    .map_err(DatabaseError::Postgres)?;
    Ok(())
}

#[async_trait]
impl TraceCorpusStore for PgBackend {
    fn supports_token_bundles(&self) -> bool {
        true
    }
    async fn publish_token_object(
        &self,
        tenant: &str,
        submission: Uuid,
        revision: &str,
        owner: &str,
        artifact: &str,
        store: &dyn crate::trace_artifact_store::TraceArtifactStore,
    ) -> Result<(), DatabaseError> {
        super::token_bundles::publish_token_object(
            self, tenant, submission, revision, owner, artifact, store,
        )
        .await
    }
    async fn get_token_bundle_for_export(
        &self,
        tenant: &str,
        submission: Uuid,
        revision: &str,
    ) -> Result<Option<crate::token_bundle_store::StoredTokenBundle>, DatabaseError> {
        super::token_bundles::get_token_bundle_for_export(self, tenant, submission, revision).await
    }
    async fn process_token_bundles(
        &self,
        tenant: &str,
        store: &dyn crate::trace_artifact_store::TraceArtifactStore,
    ) -> Result<usize, DatabaseError> {
        super::token_bundles::process_token_bundles(self, tenant, store).await
    }
    async fn query_token_bundles(
        &self,
        tenant: &str,
        owner: Option<&str>,
        query: &crate::token_bundle_store::TokenBundleQuery,
    ) -> Result<Vec<crate::token_bundle_store::TokenBundleIndexEntry>, DatabaseError> {
        super::token_bundles::query_token_bundles(self, tenant, owner, query).await
    }
    async fn delete_token_objects(
        &self,
        tenant: &str,
        submission: Uuid,
        revision: &str,
        held_policies: &[String],
        store: &dyn crate::trace_artifact_store::TraceArtifactStore,
    ) -> Result<(), DatabaseError> {
        super::token_bundles::delete_token_objects(
            self,
            tenant,
            submission,
            revision,
            held_policies,
            store,
        )
        .await
    }
    async fn begin_token_bundle(
        &self,
        bundle: crate::token_bundle_store::StoredTokenBundle,
    ) -> Result<crate::token_bundle_store::StoredTokenBundle, DatabaseError> {
        super::token_bundles::begin_token_bundle(self, bundle).await
    }
    async fn get_token_bundle(
        &self,
        tenant: &str,
        submission: Uuid,
        revision: &str,
        owner: &str,
    ) -> Result<Option<crate::token_bundle_store::StoredTokenBundle>, DatabaseError> {
        super::token_bundles::get_token_bundle(self, tenant, submission, revision, owner).await
    }
    async fn stage_token_object(
        &self,
        tenant: &str,
        submission: Uuid,
        revision: &str,
        owner: &str,
        object: crate::token_bundle_store::StoredTokenObject,
    ) -> Result<(), DatabaseError> {
        super::token_bundles::stage_token_object(self, tenant, submission, revision, owner, object)
            .await
    }
    async fn commit_token_bundle(
        &self,
        tenant: &str,
        submission: Uuid,
        revision: &str,
        owner: &str,
        receipt: trace_commons_protocol::token_distribution::DurableBundleReceipt,
    ) -> Result<trace_commons_protocol::token_distribution::DurableBundleReceipt, DatabaseError>
    {
        super::token_bundles::commit_token_bundle(
            self, tenant, submission, revision, owner, receipt,
        )
        .await
    }
    async fn pending_token_bundle_deletions(
        &self,
        tenant: &str,
        submission: Option<Uuid>,
    ) -> Result<Vec<crate::token_bundle_store::StoredTokenBundle>, DatabaseError> {
        super::token_bundles::pending_token_bundle_deletions(self, tenant, submission).await
    }
    async fn mark_token_object_deleted(
        &self,
        tenant: &str,
        submission: Uuid,
        revision: &str,
        artifact: &str,
    ) -> Result<(), DatabaseError> {
        super::token_bundles::mark_token_object_deleted(
            self, tenant, submission, revision, artifact,
        )
        .await
    }
    async fn upsert_trace_submission(
        &self,
        submission: TraceSubmissionWrite,
    ) -> Result<TraceSubmissionRecord, DatabaseError> {
        self.ensure_trace_tenant(&submission.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &submission.tenant_id).await?;
        let status = enum_to_storage(submission.status)?;
        let consent_scopes = serde_json::to_value(&submission.consent_scopes).map_err(|e| {
            DatabaseError::Serialization(format!("trace consent scopes encode failed: {e}"))
        })?;
        let allowed_uses = serde_json::to_value(&submission.allowed_uses).map_err(|e| {
            DatabaseError::Serialization(format!("trace allowed uses encode failed: {e}"))
        })?;
        let redaction_counts = serde_json::to_value(&submission.redaction_counts).map_err(|e| {
            DatabaseError::Serialization(format!("trace redaction counts encode failed: {e}"))
        })?;
        // NULL when the caller recorded no basis, which reads as "not
        // recorded" -- never as a claim that no condition held.
        //
        // The DO UPDATE below is deliberately COALESCE-free. It overwrites
        // `privacy_risk` unconditionally, so preserving an older basis
        // underneath a fresh risk would leave the two describing different
        // passes, and a basis that disagrees with the risk on its own row is
        // worse than an absent one, because it will be believed. The pair is
        // written together or cleared together.
        let residual_risk_basis = submission
            .residual_risk_basis
            .as_ref()
            .map(|labels| {
                serde_json::to_value(labels).map_err(|e| {
                    DatabaseError::Serialization(format!(
                        "trace residual risk basis encode failed: {e}"
                    ))
                })
            })
            .transpose()?;

        let row = tx
            .query_one(
                "INSERT INTO trace_submissions (
                    tenant_id, submission_id, trace_id, auth_principal_ref, contributor_pseudonym,
                    submitted_tenant_scope_ref, schema_version, consent_policy_version,
                    consent_scopes, allowed_uses, retention_policy_id, status, privacy_risk,
                    redaction_pipeline_version, redaction_hash, redaction_counts, canonical_summary_hash,
                    submission_score, credit_points_pending, credit_points_final, expires_at,
                    residual_risk_basis
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
                 )
                 ON CONFLICT (tenant_id, submission_id) DO UPDATE SET
                    trace_id = excluded.trace_id,
                    auth_principal_ref = excluded.auth_principal_ref,
                    contributor_pseudonym = excluded.contributor_pseudonym,
                    submitted_tenant_scope_ref = excluded.submitted_tenant_scope_ref,
                    schema_version = excluded.schema_version,
                    consent_policy_version = excluded.consent_policy_version,
                    consent_scopes = excluded.consent_scopes,
                    allowed_uses = excluded.allowed_uses,
                    retention_policy_id = excluded.retention_policy_id,
                    status = excluded.status,
                    privacy_risk = excluded.privacy_risk,
                    redaction_pipeline_version = excluded.redaction_pipeline_version,
                    redaction_hash = excluded.redaction_hash,
                    redaction_counts = excluded.redaction_counts,
                    canonical_summary_hash = excluded.canonical_summary_hash,
                    submission_score = excluded.submission_score,
                    credit_points_pending = excluded.credit_points_pending,
                    credit_points_final = excluded.credit_points_final,
                    expires_at = excluded.expires_at,
                    residual_risk_basis = excluded.residual_risk_basis,
                    updated_at = NOW()
                 RETURNING
                    tenant_id, submission_id, trace_id, status, auth_principal_ref,
                    contributor_pseudonym, submitted_tenant_scope_ref, schema_version,
                    consent_policy_version, consent_scopes, allowed_uses, retention_policy_id,
                    privacy_risk, redaction_pipeline_version, redaction_hash,
                    redaction_counts, canonical_summary_hash, submission_score, credit_points_pending,
                    credit_points_final, received_at, updated_at, reviewed_at,
                    review_assigned_to_principal_ref, review_assigned_at,
                    review_lease_expires_at, review_due_at, revoked_at, expires_at, purged_at, last_status_reason, residual_risk_basis",
                &[
                    &submission.tenant_id,
                    &submission.submission_id,
                    &submission.trace_id,
                    &submission.auth_principal_ref,
                    &submission.contributor_pseudonym,
                    &submission.submitted_tenant_scope_ref,
                    &submission.schema_version,
                    &submission.consent_policy_version,
                    &consent_scopes,
                    &allowed_uses,
                    &submission.retention_policy_id,
                    &status,
                    &submission.privacy_risk,
                    &submission.redaction_pipeline_version,
                    &submission.redaction_hash,
                    &redaction_counts,
                    &submission.canonical_summary_hash,
                    &submission.submission_score,
                    &submission.credit_points_pending,
                    &submission.credit_points_final,
                    &submission.expires_at,
                    &residual_risk_basis,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_submission(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn get_trace_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<Option<TraceSubmissionRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT
                    tenant_id, submission_id, trace_id, status, auth_principal_ref,
                    contributor_pseudonym, submitted_tenant_scope_ref, schema_version,
                    consent_policy_version, consent_scopes, allowed_uses, retention_policy_id,
                    privacy_risk, redaction_pipeline_version, redaction_hash,
                    redaction_counts, canonical_summary_hash, submission_score, credit_points_pending,
                    credit_points_final, received_at, updated_at, reviewed_at,
                    review_assigned_to_principal_ref, review_assigned_at,
                    review_lease_expires_at, review_due_at, revoked_at, expires_at, purged_at, last_status_reason, residual_risk_basis
                 FROM trace_submissions
                 WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_submission).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_submissions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceSubmissionRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT
                    tenant_id, submission_id, trace_id, status, auth_principal_ref,
                    contributor_pseudonym, submitted_tenant_scope_ref, schema_version,
                    consent_policy_version, consent_scopes, allowed_uses, retention_policy_id,
                    privacy_risk, redaction_pipeline_version, redaction_hash,
                    redaction_counts, canonical_summary_hash, submission_score, credit_points_pending,
                    credit_points_final, received_at, updated_at, reviewed_at,
                    review_assigned_to_principal_ref, review_assigned_at,
                    review_lease_expires_at, review_due_at, revoked_at, expires_at, purged_at, last_status_reason, residual_risk_basis
                 FROM trace_submissions
                 WHERE tenant_id = $1
                 ORDER BY received_at ASC",
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_submission).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn list_account_trace_submissions_keyset(
        &self,
        tenant_id: &str,
        principal_refs: &[String],
        cursor: Option<TraceSubmissionKeysetCursor>,
        limit: i64,
    ) -> Result<Vec<TraceSubmissionRecord>, DatabaseError> {
        // An empty active principal set can own no submissions; return an empty
        // page without querying the table (Hardening A/B: ownership is carried
        // only by the set).
        if principal_refs.is_empty() {
            return Ok(Vec::new());
        }
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Tenant-leading keyset over `(received_at DESC, submission_id DESC)`
        // backed by idx_trace_submissions_account_keyset (V31). The
        // `= ANY($2)` filter is an index-condition over the active principal
        // set; the cursor totally-orders across any number of principals
        // (Hardening H). No offset.
        const SELECT_COLUMNS: &str = "tenant_id, submission_id, trace_id, status, auth_principal_ref,
                    contributor_pseudonym, submitted_tenant_scope_ref, schema_version,
                    consent_policy_version, consent_scopes, allowed_uses, retention_policy_id,
                    privacy_risk, redaction_pipeline_version, redaction_hash,
                    redaction_counts, canonical_summary_hash, submission_score, credit_points_pending,
                    credit_points_final, received_at, updated_at, reviewed_at,
                    review_assigned_to_principal_ref, review_assigned_at,
                    review_lease_expires_at, review_due_at, revoked_at, expires_at, purged_at, last_status_reason, residual_risk_basis";
        let rows = match cursor {
            Some(cursor) => {
                let sql = format!(
                    "SELECT {SELECT_COLUMNS}
                     FROM trace_submissions
                     WHERE tenant_id = $1
                       AND auth_principal_ref = ANY($2)
                       AND (received_at, submission_id) < ($3, $4)
                     ORDER BY received_at DESC, submission_id DESC
                     LIMIT $5"
                );
                tx.query(
                    &sql,
                    &[
                        &tenant_id,
                        &principal_refs,
                        &cursor.received_at,
                        &cursor.submission_id,
                        &limit,
                    ],
                )
                .await
                .map_err(DatabaseError::Postgres)?
            }
            None => {
                let sql = format!(
                    "SELECT {SELECT_COLUMNS}
                     FROM trace_submissions
                     WHERE tenant_id = $1
                       AND auth_principal_ref = ANY($2)
                     ORDER BY received_at DESC, submission_id DESC
                     LIMIT $3"
                );
                tx.query(&sql, &[&tenant_id, &principal_refs, &limit])
                    .await
                    .map_err(DatabaseError::Postgres)?
            }
        };
        let records = rows.iter().map(row_to_submission).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_tenant_policy(
        &self,
        policy: TraceTenantPolicyWrite,
    ) -> Result<TraceTenantPolicyRecord, DatabaseError> {
        self.ensure_trace_tenant(&policy.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &policy.tenant_id).await?;
        let allowed_consent_scopes =
            serde_json::to_value(&policy.allowed_consent_scopes).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "trace tenant policy consent scopes encode failed: {e}"
                ))
            })?;
        let allowed_uses = serde_json::to_value(&policy.allowed_uses).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace tenant policy allowed uses encode failed: {e}"
            ))
        })?;
        let row = tx
            .query_one(
                "INSERT INTO trace_tenant_policies (
                    tenant_id, policy_version, allowed_consent_scopes, allowed_uses,
                    updated_by_principal_ref
                 ) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tenant_id) DO UPDATE SET
                    policy_version = excluded.policy_version,
                    allowed_consent_scopes = excluded.allowed_consent_scopes,
                    allowed_uses = excluded.allowed_uses,
                    updated_by_principal_ref = excluded.updated_by_principal_ref,
                    updated_at = NOW()
                 RETURNING
                    tenant_id, policy_version, allowed_consent_scopes, allowed_uses,
                    updated_by_principal_ref, created_at, updated_at",
                &[
                    &policy.tenant_id,
                    &policy.policy_version,
                    &allowed_consent_scopes,
                    &allowed_uses,
                    &policy.updated_by_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_tenant_policy(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn get_trace_tenant_policy(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TraceTenantPolicyRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT
                    tenant_id, policy_version, allowed_consent_scopes, allowed_uses,
                    updated_by_principal_ref, created_at, updated_at
                 FROM trace_tenant_policies
                 WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_tenant_policy).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn upsert_trace_tenant_access_grant(
        &self,
        grant: TraceTenantAccessGrantWrite,
    ) -> Result<TraceTenantAccessGrantRecord, DatabaseError> {
        self.ensure_trace_tenant(&grant.tenant_id).await?;
        let role = enum_to_storage(grant.role)?;
        let status = enum_to_storage(grant.status)?;
        let allowed_consent_scopes =
            serde_json::to_value(&grant.allowed_consent_scopes).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "trace tenant access grant consent scopes encode failed: {e}"
                ))
            })?;
        let allowed_uses = serde_json::to_value(&grant.allowed_uses).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace tenant access grant allowed uses encode failed: {e}"
            ))
        })?;
        let metadata_json = serde_json::to_value(&grant.metadata).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace tenant access grant metadata encode failed: {e}"
            ))
        })?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &grant.tenant_id).await?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_tenant_access_grants (
                        tenant_id, grant_id, principal_ref, role, status,
                        allowed_consent_scopes, allowed_uses, issuer, audience, subject,
                        issued_at, expires_at, revoked_at, created_by_principal_ref,
                        revoked_by_principal_ref, reason, metadata_json
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                     ON CONFLICT (tenant_id, grant_id) DO UPDATE SET
                        principal_ref = excluded.principal_ref,
                        role = excluded.role,
                        status = excluded.status,
                        allowed_consent_scopes = excluded.allowed_consent_scopes,
                        allowed_uses = excluded.allowed_uses,
                        issuer = excluded.issuer,
                        audience = excluded.audience,
                        subject = excluded.subject,
                        issued_at = excluded.issued_at,
                        expires_at = excluded.expires_at,
                        revoked_at = excluded.revoked_at,
                        created_by_principal_ref = excluded.created_by_principal_ref,
                        revoked_by_principal_ref = excluded.revoked_by_principal_ref,
                        reason = excluded.reason,
                        metadata_json = excluded.metadata_json,
                        updated_at = NOW()
                     RETURNING {TRACE_TENANT_ACCESS_GRANT_COLUMNS}"
                ),
                &[
                    &grant.tenant_id,
                    &grant.grant_id,
                    &grant.principal_ref,
                    &role,
                    &status,
                    &allowed_consent_scopes,
                    &allowed_uses,
                    &grant.issuer,
                    &grant.audience,
                    &grant.subject,
                    &grant.issued_at,
                    &grant.expires_at,
                    &grant.revoked_at,
                    &grant.created_by_principal_ref,
                    &grant.revoked_by_principal_ref,
                    &grant.reason,
                    &metadata_json,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_tenant_access_grant(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_tenant_access_grants(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceTenantAccessGrantRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_TENANT_ACCESS_GRANT_COLUMNS}
                     FROM trace_tenant_access_grants
                     WHERE tenant_id = $1
                     ORDER BY issued_at ASC, created_at ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_tenant_access_grant).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn list_active_trace_tenant_access_grants_for_principal(
        &self,
        tenant_id: &str,
        principal_ref: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<TraceTenantAccessGrantRecord>, DatabaseError> {
        let active = enum_to_storage(TraceTenantAccessGrantStatus::Active)?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_TENANT_ACCESS_GRANT_COLUMNS}
                     FROM trace_tenant_access_grants
                     WHERE tenant_id = $1
                       AND principal_ref = $2
                       AND status = $3
                       AND issued_at <= $4
                       AND (expires_at IS NULL OR expires_at > $4)
                       AND revoked_at IS NULL
                     ORDER BY issued_at ASC, created_at ASC"
                ),
                &[&tenant_id, &principal_ref, &active, &now],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_tenant_access_grant).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn list_trace_credit_events(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceCreditEventRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT
                    tenant_id, credit_event_id, submission_id, trace_id, credit_account_ref,
                    event_type, points_delta, reason, external_ref, actor_principal_ref,
                    actor_role, settlement_state, occurred_at
                 FROM trace_credit_ledger
                 WHERE tenant_id = $1
                 ORDER BY occurred_at ASC",
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_credit_event).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn list_quarantined_with_only_residual_survivor(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<(String, Uuid)>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // `residual_risk_basis` is JSONB (V52), so membership is a containment
        // test. The two NOT clauses are what keep this narrow: both name causes
        // that re-derive identically on the next pass, so resetting a prior for
        // them would widen a privileged operation to no effect.
        let rows = tx
            .query(
                "SELECT s.tenant_id, s.submission_id
                 FROM trace_submissions s
                 WHERE s.status = 'quarantined'
                   AND s.residual_risk_basis @> '[\"residual_survivor\"]'::jsonb
                   AND NOT (s.residual_risk_basis @> '[\"key_finding\"]'::jsonb)
                   AND NOT (s.residual_risk_basis @> '[\"coverage_incomplete\"]'::jsonb)
                   AND EXISTS (
                       SELECT 1 FROM trace_object_refs o
                       WHERE o.tenant_id = s.tenant_id
                         AND o.submission_id = s.submission_id
                         AND o.artifact_kind = 'rescrubbed_envelope'
                         AND o.invalidated_at IS NULL
                         AND o.deleted_at IS NULL
                   )
                 ORDER BY s.received_at ASC
                 LIMIT $1",
                &[&limit],
            )
            .await?;
        tx.commit().await?;
        Ok(rows
            .iter()
            .map(|row| (row.get("tenant_id"), row.get("submission_id")))
            .collect())
    }

    async fn requeue_quarantined_for_pii_backstop(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // The subquery restricts to submissions with an ACTIVE
        // `rescrubbed_envelope`: that is both what the driver will read and
        // what makes the row enumerable again. The `submitted_envelope` ref is
        // deliberately left invalidated.
        let updated = tx
            .execute(
                "UPDATE trace_submissions
                 SET status = 'awaiting_pii_backstop',
                     updated_at = NOW(),
                     reviewed_at = NULL
                 WHERE submission_id IN (
                     SELECT s.submission_id
                     FROM trace_submissions s
                     JOIN trace_object_refs o
                       ON o.tenant_id = s.tenant_id
                      AND o.submission_id = s.submission_id
                      AND o.artifact_kind = 'rescrubbed_envelope'
                      AND o.invalidated_at IS NULL
                      AND o.deleted_at IS NULL
                     WHERE s.status = 'quarantined'
                     ORDER BY s.received_at ASC
                     LIMIT $1
                 )",
                &[&limit],
            )
            .await?;
        tx.commit().await?;
        Ok(updated)
    }

    async fn update_trace_submission_status(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        status: TraceCorpusStatus,
        actor_principal_ref: &str,
        reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let status_value = enum_to_storage(status)?;
        // Allowlisted label only -- never the caller's text. See
        // `safe_status_reason_label`.
        let reason_label = reason.map(crate::trace_corpus_storage::safe_status_reason_label);
        let updated = tx
            .execute(
                "UPDATE trace_submissions
                 SET status = $3,
                     updated_at = NOW(),
                     reviewed_at = CASE
                         WHEN $3 IN ('accepted', 'quarantined', 'rejected') THEN NOW()
                         ELSE reviewed_at
                     END,
                     review_assigned_to_principal_ref = CASE
                         WHEN $3 IN ('accepted', 'rejected', 'revoked', 'expired', 'purged')
                         THEN NULL
                         ELSE review_assigned_to_principal_ref
                     END,
                     review_assigned_at = CASE
                         WHEN $3 IN ('accepted', 'rejected', 'revoked', 'expired', 'purged')
                         THEN NULL
                         ELSE review_assigned_at
                     END,
                     review_lease_expires_at = CASE
                         WHEN $3 IN ('accepted', 'rejected', 'revoked', 'expired', 'purged')
                         THEN NULL
                         ELSE review_lease_expires_at
                     END,
                     review_due_at = CASE
                         WHEN $3 IN ('accepted', 'rejected', 'revoked', 'expired', 'purged')
                         THEN NULL
                         ELSE review_due_at
                     END,
                     revoked_at = CASE WHEN $3 = 'revoked' THEN NOW() ELSE revoked_at END,
                     purged_at = CASE WHEN $3 = 'purged' THEN NOW() ELSE purged_at END,
                     credit_points_pending = CASE
                         WHEN $3 IN ('revoked', 'expired', 'purged') THEN 0
                         ELSE credit_points_pending
                     END,
                     credit_points_final = CASE
                         WHEN $3 IN ('revoked', 'expired', 'purged') THEN 0
                         ELSE credit_points_final
                     END,
                     last_status_reason = $4
                 WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id, &status_value, &reason_label],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        if updated == 0 {
            return Err(DatabaseError::NotFound {
                entity: "trace_submission".to_string(),
                id: submission_id.to_string(),
            });
        }
        tx.commit().await.map_err(DatabaseError::Postgres)?;

        self.append_trace_audit_event(TraceAuditEventWrite {
            audit_event_id: Uuid::new_v4(),
            tenant_id: tenant_id.to_string(),
            actor_principal_ref: actor_principal_ref.to_string(),
            actor_role: "system".to_string(),
            action: audit_action_for_status(status),
            reason: reason.map(str::to_string),
            request_id: None,
            submission_id: Some(submission_id),
            object_ref_id: None,
            export_manifest_id: None,
            decision_inputs_hash: None,
            previous_event_hash: None,
            event_hash: None,
            canonical_event_json: None,
            metadata: TraceAuditSafeMetadata::ReviewDecision {
                decision: status_value,
                resulting_status: status,
                reason_code: reason.map(str::to_string),
            },
        })
        .await
    }

    async fn release_pii_backstop_hold(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        status: TraceCorpusStatus,
        actor_principal_ref: &str,
        reason: Option<&str>,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let status_value = enum_to_storage(status)?;
        // Allowlisted label only -- never the caller's text. See
        // `safe_status_reason_label`.
        let reason_label = reason.map(crate::trace_corpus_storage::safe_status_reason_label);
        let updated = tx
            .execute(
                "UPDATE trace_submissions
                 SET status = $3,
                     updated_at = NOW(),
                     reviewed_at = CASE
                         WHEN $3 IN ('accepted', 'quarantined', 'rejected') THEN NOW()
                         ELSE reviewed_at
                     END,
                     review_assigned_to_principal_ref = CASE
                         WHEN $3 IN ('accepted', 'rejected', 'revoked', 'expired', 'purged')
                         THEN NULL
                         ELSE review_assigned_to_principal_ref
                     END,
                     review_assigned_at = CASE
                         WHEN $3 IN ('accepted', 'rejected', 'revoked', 'expired', 'purged')
                         THEN NULL
                         ELSE review_assigned_at
                     END,
                     review_lease_expires_at = CASE
                         WHEN $3 IN ('accepted', 'rejected', 'revoked', 'expired', 'purged')
                         THEN NULL
                         ELSE review_lease_expires_at
                     END,
                     review_due_at = CASE
                         WHEN $3 IN ('accepted', 'rejected', 'revoked', 'expired', 'purged')
                         THEN NULL
                         ELSE review_due_at
                     END,
                     revoked_at = CASE WHEN $3 = 'revoked' THEN NOW() ELSE revoked_at END,
                     purged_at = CASE WHEN $3 = 'purged' THEN NOW() ELSE purged_at END,
                     credit_points_pending = CASE
                         WHEN $3 IN ('revoked', 'expired', 'purged') THEN 0
                         ELSE credit_points_pending
                     END,
                     credit_points_final = CASE
                         WHEN $3 IN ('revoked', 'expired', 'purged') THEN 0
                         ELSE credit_points_final
                     END,
                     last_status_reason = $4
                 WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id, &status_value, &reason_label],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        if updated == 0 {
            return Err(DatabaseError::NotFound {
                entity: "trace_submission".to_string(),
                id: submission_id.to_string(),
            });
        }

        // Invalidate the pre-backstop `submitted_envelope` ref(s) in the SAME
        // transaction as the status flip above. Both must commit together:
        // see the trait doc comment on `release_pii_backstop_hold` for why a
        // partial commit either leaks pre-backstop bytes via export-by-ref or
        // strands the submission on `awaiting_pii_backstop` forever.
        let submitted_envelope_kind = enum_to_storage(TraceObjectArtifactKind::SubmittedEnvelope)?;
        let invalidated = tx
            .execute(
                "UPDATE trace_object_refs
                 SET invalidated_at = COALESCE(invalidated_at, NOW()),
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND artifact_kind = $3
                   AND invalidated_at IS NULL
                   AND deleted_at IS NULL",
                &[&tenant_id, &submission_id, &submitted_envelope_kind],
            )
            .await
            .map_err(DatabaseError::Postgres)?;

        tx.commit().await.map_err(DatabaseError::Postgres)?;

        self.append_trace_audit_event(TraceAuditEventWrite {
            audit_event_id: Uuid::new_v4(),
            tenant_id: tenant_id.to_string(),
            actor_principal_ref: actor_principal_ref.to_string(),
            actor_role: "system".to_string(),
            action: audit_action_for_status(status),
            reason: reason.map(str::to_string),
            request_id: None,
            submission_id: Some(submission_id),
            object_ref_id: None,
            export_manifest_id: None,
            decision_inputs_hash: None,
            previous_event_hash: None,
            event_hash: None,
            canonical_event_json: None,
            metadata: TraceAuditSafeMetadata::ReviewDecision {
                decision: status_value,
                resulting_status: status,
                reason_code: reason.map(str::to_string),
            },
        })
        .await?;

        Ok(invalidated)
    }

    async fn claim_trace_review_lease(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        actor_principal_ref: &str,
        lease_expires_at: DateTime<Utc>,
        review_due_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Option<TraceSubmissionRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "UPDATE trace_submissions
                 SET review_assigned_to_principal_ref = $3,
                     review_assigned_at = $6,
                     review_lease_expires_at = $4,
                     review_due_at = $5,
                     updated_at = $6
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND status = 'quarantined'
                   AND (
                        review_lease_expires_at IS NULL
                        OR review_lease_expires_at <= $6
                        OR review_assigned_to_principal_ref = $3
                   )
                 RETURNING
                    tenant_id, submission_id, trace_id, status, auth_principal_ref,
                    contributor_pseudonym, submitted_tenant_scope_ref, schema_version,
                    consent_policy_version, consent_scopes, allowed_uses, retention_policy_id,
                    privacy_risk, redaction_pipeline_version, redaction_hash,
                    redaction_counts, canonical_summary_hash, submission_score, credit_points_pending,
                    credit_points_final, received_at, updated_at, reviewed_at,
                    review_assigned_to_principal_ref, review_assigned_at,
                    review_lease_expires_at, review_due_at, revoked_at, expires_at, purged_at, last_status_reason, residual_risk_basis",
                &[
                    &tenant_id,
                    &submission_id,
                    &actor_principal_ref,
                    &lease_expires_at,
                    &review_due_at,
                    &now,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_submission).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn release_trace_review_lease(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        actor_principal_ref: &str,
    ) -> Result<Option<TraceSubmissionRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "UPDATE trace_submissions
                 SET review_assigned_to_principal_ref = NULL,
                     review_assigned_at = NULL,
                     review_lease_expires_at = NULL,
                     review_due_at = NULL,
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND status = 'quarantined'
                   AND review_assigned_to_principal_ref = $3
                 RETURNING
                    tenant_id, submission_id, trace_id, status, auth_principal_ref,
                    contributor_pseudonym, submitted_tenant_scope_ref, schema_version,
                    consent_policy_version, consent_scopes, allowed_uses, retention_policy_id,
                    privacy_risk, redaction_pipeline_version, redaction_hash,
                    redaction_counts, canonical_summary_hash, submission_score, credit_points_pending,
                    credit_points_final, received_at, updated_at, reviewed_at,
                    review_assigned_to_principal_ref, review_assigned_at,
                    review_lease_expires_at, review_due_at, revoked_at, expires_at, purged_at, last_status_reason, residual_risk_basis",
                &[&tenant_id, &submission_id, &actor_principal_ref],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_submission).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn append_trace_object_ref(
        &self,
        object_ref: TraceObjectRefWrite,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(&object_ref.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &object_ref.tenant_id).await?;
        let artifact_kind = enum_to_storage(object_ref.artifact_kind)?;
        tx.execute(
            "INSERT INTO trace_object_refs (
                    tenant_id, submission_id, object_ref_id, artifact_kind, object_store,
                    object_key, content_sha256, encryption_key_ref, size_bytes, compression,
                    created_by_job_id
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (tenant_id, submission_id, object_ref_id) DO UPDATE SET
                    artifact_kind = excluded.artifact_kind,
                    object_store = excluded.object_store,
                    object_key = excluded.object_key,
                    content_sha256 = excluded.content_sha256,
                    encryption_key_ref = excluded.encryption_key_ref,
                    size_bytes = excluded.size_bytes,
                    compression = excluded.compression,
                    created_by_job_id = excluded.created_by_job_id,
                    updated_at = NOW()",
            &[
                &object_ref.tenant_id,
                &object_ref.submission_id,
                &object_ref.object_ref_id,
                &artifact_kind,
                &object_ref.object_store,
                &object_ref.object_key,
                &object_ref.content_sha256,
                &object_ref.encryption_key_ref,
                &object_ref.size_bytes,
                &object_ref.compression,
                &object_ref.created_by_job_id,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn list_trace_object_refs(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<Vec<TraceObjectRefRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_OBJECT_REF_COLUMNS}
                     FROM trace_object_refs
                     WHERE tenant_id = $1 AND submission_id = $2
                     ORDER BY created_at ASC"
                ),
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_object_ref).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn get_latest_active_trace_object_ref(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        artifact_kind: TraceObjectArtifactKind,
    ) -> Result<Option<TraceObjectRefRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let artifact_kind = enum_to_storage(artifact_kind)?;
        let row = tx
            .query_opt(
                &format!(
                    "SELECT {TRACE_OBJECT_REF_COLUMNS}
                     FROM trace_object_refs
                     WHERE tenant_id = $1
                       AND submission_id = $2
                       AND artifact_kind = $3
                       AND invalidated_at IS NULL
                       AND deleted_at IS NULL
                     ORDER BY created_at DESC
                     LIMIT 1"
                ),
                &[&tenant_id, &submission_id, &artifact_kind],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_object_ref).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn append_trace_derived_record(
        &self,
        derived_record: TraceDerivedRecordWrite,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(&derived_record.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx =
            Self::begin_trace_tenant_transaction(&mut client, &derived_record.tenant_id).await?;
        if let Some(object_ref) = derived_record.input_object_ref.as_ref() {
            validate_tenant_scoped_trace_object_ref(
                "derived input",
                object_ref,
                &derived_record.tenant_id,
                derived_record.submission_id,
            )?;
            ensure_pg_object_ref_belongs_to_submission(
                &tx,
                &derived_record.tenant_id,
                derived_record.submission_id,
                object_ref.object_ref_id,
                "derived input",
            )
            .await?;
        }
        if let Some(object_ref) = derived_record.output_object_ref.as_ref() {
            validate_tenant_scoped_trace_object_ref(
                "derived output",
                object_ref,
                &derived_record.tenant_id,
                derived_record.submission_id,
            )?;
            ensure_pg_object_ref_belongs_to_submission(
                &tx,
                &derived_record.tenant_id,
                derived_record.submission_id,
                object_ref.object_ref_id,
                "derived output",
            )
            .await?;
        }
        let status = enum_to_storage(derived_record.status)?;
        let worker_kind = enum_to_storage(derived_record.worker_kind)?;
        let input_object_ref_id = derived_record
            .input_object_ref
            .as_ref()
            .map(|object_ref| object_ref.object_ref_id);
        let output_object_ref_id = derived_record
            .output_object_ref
            .as_ref()
            .map(|object_ref| object_ref.object_ref_id);
        let tool_sequence = serde_json::to_value(&derived_record.tool_sequence).map_err(|e| {
            DatabaseError::Serialization(format!("trace tool sequence encode failed: {e}"))
        })?;
        let tool_categories =
            serde_json::to_value(&derived_record.tool_categories).map_err(|e| {
                DatabaseError::Serialization(format!("trace tool categories encode failed: {e}"))
            })?;
        let coverage_tags = serde_json::to_value(&derived_record.coverage_tags).map_err(|e| {
            DatabaseError::Serialization(format!("trace coverage tags encode failed: {e}"))
        })?;

        tx.execute(
            "INSERT INTO trace_derived_records (
                    tenant_id, derived_id, submission_id, trace_id, status, worker_kind,
                    worker_version, input_object_ref_id, input_hash, output_object_ref_id,
                    canonical_summary, canonical_summary_hash, summary_model, task_success,
                    privacy_risk, event_count, tool_sequence, tool_categories, coverage_tags,
                    duplicate_score, novelty_score, cluster_id
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
                 )
                 ON CONFLICT (tenant_id, derived_id) DO UPDATE SET
                    status = excluded.status,
                    worker_kind = excluded.worker_kind,
                    worker_version = excluded.worker_version,
                    input_object_ref_id = excluded.input_object_ref_id,
                    input_hash = excluded.input_hash,
                    output_object_ref_id = excluded.output_object_ref_id,
                    canonical_summary = excluded.canonical_summary,
                    canonical_summary_hash = excluded.canonical_summary_hash,
                    summary_model = excluded.summary_model,
                    task_success = excluded.task_success,
                    privacy_risk = excluded.privacy_risk,
                    event_count = excluded.event_count,
                    tool_sequence = excluded.tool_sequence,
                    tool_categories = excluded.tool_categories,
                    coverage_tags = excluded.coverage_tags,
                    duplicate_score = excluded.duplicate_score,
                    novelty_score = excluded.novelty_score,
                    cluster_id = excluded.cluster_id,
                    updated_at = NOW()",
            &[
                &derived_record.tenant_id,
                &derived_record.derived_id,
                &derived_record.submission_id,
                &derived_record.trace_id,
                &status,
                &worker_kind,
                &derived_record.worker_version,
                &input_object_ref_id,
                &derived_record.input_hash,
                &output_object_ref_id,
                &derived_record.canonical_summary,
                &derived_record.canonical_summary_hash,
                &derived_record.summary_model,
                &derived_record.task_success,
                &derived_record.privacy_risk,
                &derived_record.event_count,
                &tool_sequence,
                &tool_categories,
                &coverage_tags,
                &derived_record.duplicate_score,
                &derived_record.novelty_score,
                &derived_record.cluster_id,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn list_trace_derived_records(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceDerivedRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT
                    tenant_id, derived_id, submission_id, trace_id, status, worker_kind,
                    worker_version, input_object_ref_id, input_hash, output_object_ref_id,
                    canonical_summary, canonical_summary_hash, summary_model, task_success,
                    privacy_risk, event_count, tool_sequence, tool_categories, coverage_tags,
                    duplicate_score, novelty_score, cluster_id, created_at, updated_at
                 FROM trace_derived_records
                 WHERE tenant_id = $1
                 ORDER BY created_at ASC",
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_derived_record).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_vector_entry(
        &self,
        vector_entry: TraceVectorEntryWrite,
    ) -> Result<TraceVectorEntryRecord, DatabaseError> {
        self.ensure_trace_tenant(&vector_entry.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &vector_entry.tenant_id).await?;
        ensure_pg_derived_record_belongs_to_submission(
            &tx,
            &vector_entry.tenant_id,
            vector_entry.submission_id,
            vector_entry.derived_id,
        )
        .await?;
        let source_projection = enum_to_storage(vector_entry.source_projection)?;
        let status = enum_to_storage(vector_entry.status)?;
        let row = tx
            .query_one(
                "INSERT INTO trace_vector_entries (
                    tenant_id, submission_id, derived_id, vector_entry_id, vector_store,
                    embedding_model, embedding_dimension, embedding_version, source_projection,
                    source_hash, status, nearest_trace_ids, cluster_id, duplicate_score,
                    novelty_score, indexed_at, invalidated_at, deleted_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                    $14, $15, $16, $17, $18
                 )
                 ON CONFLICT (tenant_id, submission_id, vector_entry_id) DO UPDATE SET
                    derived_id = excluded.derived_id,
                    vector_store = excluded.vector_store,
                    embedding_model = excluded.embedding_model,
                    embedding_dimension = excluded.embedding_dimension,
                    embedding_version = excluded.embedding_version,
                    source_projection = excluded.source_projection,
                    source_hash = excluded.source_hash,
                    status = excluded.status,
                    nearest_trace_ids = excluded.nearest_trace_ids,
                    cluster_id = excluded.cluster_id,
                    duplicate_score = excluded.duplicate_score,
                    novelty_score = excluded.novelty_score,
                    indexed_at = excluded.indexed_at,
                    invalidated_at = excluded.invalidated_at,
                    deleted_at = excluded.deleted_at,
                    updated_at = NOW()
                 RETURNING
                    tenant_id, submission_id, derived_id, vector_entry_id, vector_store,
                    embedding_model, embedding_dimension, embedding_version, source_projection,
                    source_hash, status, nearest_trace_ids, cluster_id, duplicate_score,
                    novelty_score, indexed_at, invalidated_at, deleted_at, created_at, updated_at",
                &[
                    &vector_entry.tenant_id,
                    &vector_entry.submission_id,
                    &vector_entry.derived_id,
                    &vector_entry.vector_entry_id,
                    &vector_entry.vector_store,
                    &vector_entry.embedding_model,
                    &vector_entry.embedding_dimension,
                    &vector_entry.embedding_version,
                    &source_projection,
                    &vector_entry.source_hash,
                    &status,
                    &vector_entry.nearest_trace_ids,
                    &vector_entry.cluster_id,
                    &vector_entry.duplicate_score,
                    &vector_entry.novelty_score,
                    &vector_entry.indexed_at,
                    &vector_entry.invalidated_at,
                    &vector_entry.deleted_at,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_vector_entry(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_vector_entries(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceVectorEntryRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT
                    tenant_id, submission_id, derived_id, vector_entry_id, vector_store,
                    embedding_model, embedding_dimension, embedding_version, source_projection,
                    source_hash, status, nearest_trace_ids, cluster_id, duplicate_score,
                    novelty_score, indexed_at, invalidated_at, deleted_at, created_at, updated_at
                 FROM trace_vector_entries
                 WHERE tenant_id = $1
                 ORDER BY created_at ASC",
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_vector_entry).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_ranking_model_version(
        &self,
        model_version: TraceRankingModelVersionWrite,
    ) -> Result<TraceRankingModelVersionRecord, DatabaseError> {
        self.ensure_trace_tenant(&model_version.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx =
            Self::begin_trace_tenant_transaction(&mut client, &model_version.tenant_id).await?;
        let status = enum_to_storage(model_version.status)?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_ranking_model_versions (
                        tenant_id, model_version, feature_schema_version, policy_version,
                        status, training_dataset_hash, calibration_dataset_hash,
                        model_artifact_hash, actor_principal_ref
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                     ON CONFLICT (tenant_id, model_version) DO UPDATE SET
                        feature_schema_version = excluded.feature_schema_version,
                        policy_version = excluded.policy_version,
                        status = excluded.status,
                        training_dataset_hash = excluded.training_dataset_hash,
                        calibration_dataset_hash = excluded.calibration_dataset_hash,
                        model_artifact_hash = excluded.model_artifact_hash,
                        actor_principal_ref = excluded.actor_principal_ref
                     RETURNING {TRACE_RANKING_MODEL_VERSION_COLUMNS}"
                ),
                &[
                    &model_version.tenant_id,
                    &model_version.model_version,
                    &model_version.feature_schema_version,
                    &model_version.policy_version,
                    &status,
                    &model_version.training_dataset_hash,
                    &model_version.calibration_dataset_hash,
                    &model_version.model_artifact_hash,
                    &model_version.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_ranking_model_version(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_ranking_model_versions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingModelVersionRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RANKING_MODEL_VERSION_COLUMNS}
                     FROM trace_ranking_model_versions
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, model_version ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_ranking_model_version).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_ranking_calibration_dataset(
        &self,
        dataset: TraceRankingCalibrationDatasetWrite,
    ) -> Result<TraceRankingCalibrationDatasetRecord, DatabaseError> {
        self.ensure_trace_tenant(&dataset.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &dataset.tenant_id).await?;
        let source_count = u32_to_pg_i32(
            dataset.source_count,
            "ranking_calibration_datasets.source_count",
        )?;
        let label_source_count = u32_to_pg_i32(
            dataset.label_source_count,
            "ranking_calibration_datasets.label_source_count",
        )?;
        let label_actor_count = u32_to_pg_i32(
            dataset.label_actor_count,
            "ranking_calibration_datasets.label_actor_count",
        )?;
        let status = enum_to_storage(dataset.status)?;
        let row = tx
            .query_opt(
                &format!(
                    "INSERT INTO trace_ranking_calibration_datasets (
                        tenant_id, calibration_dataset_hash, target_use, policy_version,
                        source_manifest_hash, source_count, label_source_count,
                        label_actor_count, status, actor_principal_ref
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                     ON CONFLICT (tenant_id, calibration_dataset_hash, target_use, policy_version)
                     DO UPDATE SET
                        status = excluded.status,
                        actor_principal_ref = excluded.actor_principal_ref,
                        created_at = NOW()
                     WHERE trace_ranking_calibration_datasets.source_manifest_hash = excluded.source_manifest_hash
                        AND trace_ranking_calibration_datasets.source_count = excluded.source_count
                        AND trace_ranking_calibration_datasets.label_source_count = excluded.label_source_count
                        AND trace_ranking_calibration_datasets.label_actor_count = excluded.label_actor_count
                     RETURNING {TRACE_RANKING_CALIBRATION_DATASET_COLUMNS}"
                ),
                &[
                    &dataset.tenant_id,
                    &dataset.calibration_dataset_hash,
                    &dataset.target_use,
                    &dataset.policy_version,
                    &dataset.source_manifest_hash,
                    &source_count,
                    &label_source_count,
                    &label_actor_count,
                    &status,
                    &dataset.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let row = row.ok_or_else(|| {
            DatabaseError::Constraint(
                "ranking calibration dataset manifest is immutable for this target use and policy"
                    .to_string(),
            )
        })?;
        let record = row_to_ranking_calibration_dataset(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn update_trace_ranking_calibration_dataset_status(
        &self,
        update: TraceRankingCalibrationDatasetStatusUpdate,
    ) -> Result<TraceRankingCalibrationDatasetRecord, DatabaseError> {
        self.ensure_trace_tenant(&update.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &update.tenant_id).await?;
        let status = enum_to_storage(update.status)?;
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE trace_ranking_calibration_datasets
                     SET status = $5,
                         actor_principal_ref = $6,
                         created_at = NOW()
                     WHERE tenant_id = $1
                        AND calibration_dataset_hash = $2
                        AND target_use = $3
                        AND policy_version = $4
                     RETURNING {TRACE_RANKING_CALIBRATION_DATASET_COLUMNS}"
                ),
                &[
                    &update.tenant_id,
                    &update.calibration_dataset_hash,
                    &update.target_use,
                    &update.policy_version,
                    &status,
                    &update.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let row = row.ok_or_else(|| DatabaseError::NotFound {
            entity: "trace_ranking_calibration_dataset".to_string(),
            id: format!(
                "{}:{}:{}:{}",
                update.tenant_id,
                update.calibration_dataset_hash,
                update.target_use,
                update.policy_version
            ),
        })?;
        let record = row_to_ranking_calibration_dataset(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_ranking_calibration_datasets(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingCalibrationDatasetRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RANKING_CALIBRATION_DATASET_COLUMNS}
                     FROM trace_ranking_calibration_datasets
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, calibration_dataset_hash ASC, target_use ASC, policy_version ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows
            .iter()
            .map(row_to_ranking_calibration_dataset)
            .collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_ranking_feature(
        &self,
        feature: TraceRankingFeatureWrite,
    ) -> Result<TraceRankingFeatureRecord, DatabaseError> {
        self.ensure_trace_tenant(&feature.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &feature.tenant_id).await?;
        let coverage_tags = serde_json::to_value(&feature.coverage_tags).map_err(|e| {
            DatabaseError::Serialization(format!("trace ranking coverage_tags encode failed: {e}"))
        })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_ranking_features (
                        tenant_id, ranking_feature_id, submission_id, trace_id, target_use,
                        feature_schema_version, feature_vector_hash, feature_names_hash,
                        source_feature_hash, duplicate_score, novelty_score, privacy_risk_score,
                        quality_score, coverage_tags, actor_principal_ref
                     ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
                     )
                     ON CONFLICT (tenant_id, ranking_feature_id) DO UPDATE SET
                        submission_id = excluded.submission_id,
                        trace_id = excluded.trace_id,
                        target_use = excluded.target_use,
                        feature_schema_version = excluded.feature_schema_version,
                        feature_vector_hash = excluded.feature_vector_hash,
                        feature_names_hash = excluded.feature_names_hash,
                        source_feature_hash = excluded.source_feature_hash,
                        duplicate_score = excluded.duplicate_score,
                        novelty_score = excluded.novelty_score,
                        privacy_risk_score = excluded.privacy_risk_score,
                        quality_score = excluded.quality_score,
                        coverage_tags = excluded.coverage_tags,
                        actor_principal_ref = excluded.actor_principal_ref
                     RETURNING {TRACE_RANKING_FEATURE_COLUMNS}"
                ),
                &[
                    &feature.tenant_id,
                    &feature.ranking_feature_id,
                    &feature.submission_id,
                    &feature.trace_id,
                    &feature.target_use,
                    &feature.feature_schema_version,
                    &feature.feature_vector_hash,
                    &feature.feature_names_hash,
                    &feature.source_feature_hash,
                    &feature.duplicate_score,
                    &feature.novelty_score,
                    &feature.privacy_risk_score,
                    &feature.quality_score,
                    &coverage_tags,
                    &feature.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_ranking_feature(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_ranking_features(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingFeatureRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RANKING_FEATURE_COLUMNS}
                     FROM trace_ranking_features
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, ranking_feature_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_ranking_feature).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_ranking_prediction(
        &self,
        prediction: TraceRankingPredictionWrite,
    ) -> Result<TraceRankingPredictionRecord, DatabaseError> {
        self.ensure_trace_tenant(&prediction.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &prediction.tenant_id).await?;
        let explanation_codes =
            serde_json::to_value(&prediction.explanation_codes).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "trace ranking explanation_codes encode failed: {e}"
                ))
            })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_ranking_predictions (
                        tenant_id, ranking_prediction_id, submission_id, trace_id, target_use,
                        model_version, feature_schema_version, prediction_policy_version,
                        feature_vector_hash, predicted_utility_micros, uncertainty_micros,
                        confidence, risk_penalty_micros, novelty_bonus_micros,
                        settlement_score_micros, explanation_codes, actor_principal_ref
                     ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
                     )
                     ON CONFLICT (tenant_id, ranking_prediction_id) DO UPDATE SET
                        submission_id = excluded.submission_id,
                        trace_id = excluded.trace_id,
                        target_use = excluded.target_use,
                        model_version = excluded.model_version,
                        feature_schema_version = excluded.feature_schema_version,
                        prediction_policy_version = excluded.prediction_policy_version,
                        feature_vector_hash = excluded.feature_vector_hash,
                        predicted_utility_micros = excluded.predicted_utility_micros,
                        uncertainty_micros = excluded.uncertainty_micros,
                        confidence = excluded.confidence,
                        risk_penalty_micros = excluded.risk_penalty_micros,
                        novelty_bonus_micros = excluded.novelty_bonus_micros,
                        settlement_score_micros = excluded.settlement_score_micros,
                        explanation_codes = excluded.explanation_codes,
                        actor_principal_ref = excluded.actor_principal_ref
                     RETURNING {TRACE_RANKING_PREDICTION_COLUMNS}"
                ),
                &[
                    &prediction.tenant_id,
                    &prediction.ranking_prediction_id,
                    &prediction.submission_id,
                    &prediction.trace_id,
                    &prediction.target_use,
                    &prediction.model_version,
                    &prediction.feature_schema_version,
                    &prediction.prediction_policy_version,
                    &prediction.feature_vector_hash,
                    &prediction.predicted_utility_micros,
                    &prediction.uncertainty_micros,
                    &prediction.confidence,
                    &prediction.risk_penalty_micros,
                    &prediction.novelty_bonus_micros,
                    &prediction.settlement_score_micros,
                    &explanation_codes,
                    &prediction.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_ranking_prediction(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_ranking_predictions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingPredictionRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RANKING_PREDICTION_COLUMNS}
                     FROM trace_ranking_predictions
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, ranking_prediction_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_ranking_prediction).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_ranking_label(
        &self,
        label: TraceRankingLabelWrite,
    ) -> Result<TraceRankingLabelRecord, DatabaseError> {
        self.ensure_trace_tenant(&label.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &label.tenant_id).await?;
        let label_source = enum_to_storage(label.label_source)?;
        let utility_category = enum_to_storage(label.utility_category)?;
        let label_outcome = enum_to_storage(label.label_outcome)?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_ranking_labels (
                        tenant_id, ranking_label_id, submission_id, trace_id, target_use,
                        label_source, utility_category, label_outcome, utility_delta_micros,
                        evidence_hash, external_ref_hash, actor_principal_ref
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                     ON CONFLICT (tenant_id, submission_id, target_use, label_source, external_ref_hash)
                     DO UPDATE SET
                        trace_id = excluded.trace_id,
                        utility_category = excluded.utility_category,
                        label_outcome = excluded.label_outcome,
                        utility_delta_micros = excluded.utility_delta_micros,
                        evidence_hash = excluded.evidence_hash,
                        actor_principal_ref = excluded.actor_principal_ref
                     RETURNING {TRACE_RANKING_LABEL_COLUMNS}"
                ),
                &[
                    &label.tenant_id,
                    &label.ranking_label_id,
                    &label.submission_id,
                    &label.trace_id,
                    &label.target_use,
                    &label_source,
                    &utility_category,
                    &label_outcome,
                    &label.utility_delta_micros,
                    &label.evidence_hash,
                    &label.external_ref_hash,
                    &label.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_ranking_label(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_ranking_labels(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingLabelRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RANKING_LABEL_COLUMNS}
                     FROM trace_ranking_labels
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, ranking_label_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_ranking_label).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_ranking_preference_label(
        &self,
        preference: TraceRankingPreferenceLabelWrite,
    ) -> Result<TraceRankingPreferenceLabelRecord, DatabaseError> {
        self.ensure_trace_tenant(&preference.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &preference.tenant_id).await?;
        let label_source = enum_to_storage(preference.label_source)?;
        let utility_category = enum_to_storage(preference.utility_category)?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_ranking_preference_labels (
                        tenant_id, preference_label_id, preferred_submission_id, preferred_trace_id,
                        rejected_submission_id, rejected_trace_id, target_use, label_source,
                        utility_category, preference_strength_micros, evidence_hash,
                        external_ref_hash, actor_principal_ref
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                     ON CONFLICT (
                        tenant_id, preferred_submission_id, rejected_submission_id, target_use,
                        label_source, external_ref_hash
                     )
                     DO UPDATE SET
                        preferred_trace_id = excluded.preferred_trace_id,
                        rejected_trace_id = excluded.rejected_trace_id,
                        utility_category = excluded.utility_category,
                        preference_strength_micros = excluded.preference_strength_micros,
                        evidence_hash = excluded.evidence_hash,
                        actor_principal_ref = excluded.actor_principal_ref
                     RETURNING {TRACE_RANKING_PREFERENCE_LABEL_COLUMNS}"
                ),
                &[
                    &preference.tenant_id,
                    &preference.preference_label_id,
                    &preference.preferred_submission_id,
                    &preference.preferred_trace_id,
                    &preference.rejected_submission_id,
                    &preference.rejected_trace_id,
                    &preference.target_use,
                    &label_source,
                    &utility_category,
                    &preference.preference_strength_micros,
                    &preference.evidence_hash,
                    &preference.external_ref_hash,
                    &preference.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_ranking_preference_label(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_ranking_preference_labels(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingPreferenceLabelRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RANKING_PREFERENCE_LABEL_COLUMNS}
                     FROM trace_ranking_preference_labels
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, preference_label_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_ranking_preference_label).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_ranking_calibration_run(
        &self,
        run: TraceRankingCalibrationRunWrite,
    ) -> Result<TraceRankingCalibrationRunRecord, DatabaseError> {
        self.ensure_trace_tenant(&run.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &run.tenant_id).await?;
        let prediction_count = i32::try_from(run.prediction_count).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace ranking calibration prediction_count exceeds PostgreSQL integer range: {e}"
            ))
        })?;
        let label_count = i32::try_from(run.label_count).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace ranking calibration label_count exceeds PostgreSQL integer range: {e}"
            ))
        })?;
        let joined_label_prediction_count =
            i32::try_from(run.joined_label_prediction_count).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "trace ranking calibration joined_label_prediction_count exceeds PostgreSQL integer range: {e}"
                ))
            })?;
        let joined_label_source_count =
            i32::try_from(run.joined_label_source_count).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "trace ranking calibration joined_label_source_count exceeds PostgreSQL integer range: {e}"
                ))
            })?;
        let joined_label_actor_count =
            i32::try_from(run.joined_label_actor_count).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "trace ranking calibration joined_label_actor_count exceeds PostgreSQL integer range: {e}"
                ))
            })?;
        let low_confidence_prediction_count =
            i32::try_from(run.low_confidence_prediction_count).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "trace ranking calibration low_confidence_prediction_count exceeds PostgreSQL integer range: {e}"
                ))
            })?;
        let min_label_count = i32::try_from(run.min_label_count).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace ranking calibration min_label_count exceeds PostgreSQL integer range: {e}"
            ))
        })?;
        let min_label_source_count = i32::try_from(run.min_label_source_count).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace ranking calibration min_label_source_count exceeds PostgreSQL integer range: {e}"
            ))
        })?;
        let reason_codes = serde_json::to_value(&run.reason_codes).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace ranking calibration reason_codes encode failed: {e}"
            ))
        })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_ranking_calibration_runs (
                        tenant_id, calibration_run_id, model_version, target_use, policy_version,
                        evaluation_dataset_hash, prediction_count, label_count,
                        joined_label_prediction_count, joined_label_source_count, joined_label_actor_count,
                        joined_evidence_hash, average_predicted_utility_micros,
                        average_label_utility_delta_micros, average_absolute_error_micros,
                        max_label_source_average_absolute_error_micros,
                        max_error_label_source, mean_signed_error_micros,
                        low_confidence_prediction_count, confidence_threshold, min_label_count,
                        min_label_source_count, max_average_absolute_error_micros, promotable,
                        reason_codes, report_hash, actor_principal_ref
                     ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                        $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
                     )
                     ON CONFLICT (tenant_id, calibration_run_id) DO UPDATE SET
                        model_version = excluded.model_version,
                        target_use = excluded.target_use,
                        policy_version = excluded.policy_version,
                        evaluation_dataset_hash = excluded.evaluation_dataset_hash,
                        prediction_count = excluded.prediction_count,
                        label_count = excluded.label_count,
                        joined_label_prediction_count = excluded.joined_label_prediction_count,
                        joined_label_source_count = excluded.joined_label_source_count,
                        joined_label_actor_count = excluded.joined_label_actor_count,
                        joined_evidence_hash = excluded.joined_evidence_hash,
                        average_predicted_utility_micros = excluded.average_predicted_utility_micros,
                        average_label_utility_delta_micros = excluded.average_label_utility_delta_micros,
                        average_absolute_error_micros = excluded.average_absolute_error_micros,
                        max_label_source_average_absolute_error_micros = excluded.max_label_source_average_absolute_error_micros,
                        max_error_label_source = excluded.max_error_label_source,
                        mean_signed_error_micros = excluded.mean_signed_error_micros,
                        low_confidence_prediction_count = excluded.low_confidence_prediction_count,
                        confidence_threshold = excluded.confidence_threshold,
                        min_label_count = excluded.min_label_count,
                        min_label_source_count = excluded.min_label_source_count,
                        max_average_absolute_error_micros = excluded.max_average_absolute_error_micros,
                        promotable = excluded.promotable,
                        reason_codes = excluded.reason_codes,
                        report_hash = excluded.report_hash,
                        actor_principal_ref = excluded.actor_principal_ref
                     RETURNING {TRACE_RANKING_CALIBRATION_RUN_COLUMNS}"
                ),
                &[
                    &run.tenant_id,
                    &run.calibration_run_id,
                    &run.model_version,
                    &run.target_use,
                    &run.policy_version,
                    &run.evaluation_dataset_hash,
                    &prediction_count,
                    &label_count,
                    &joined_label_prediction_count,
                    &joined_label_source_count,
                    &joined_label_actor_count,
                    &run.joined_evidence_hash,
                    &run.average_predicted_utility_micros,
                    &run.average_label_utility_delta_micros,
                    &run.average_absolute_error_micros,
                    &run.max_label_source_average_absolute_error_micros,
                    &run.max_error_label_source,
                    &run.mean_signed_error_micros,
                    &low_confidence_prediction_count,
                    &run.confidence_threshold,
                    &min_label_count,
                    &min_label_source_count,
                    &run.max_average_absolute_error_micros,
                    &run.promotable,
                    &reason_codes,
                    &run.report_hash,
                    &run.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_ranking_calibration_run(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_ranking_calibration_runs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingCalibrationRunRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RANKING_CALIBRATION_RUN_COLUMNS}
                     FROM trace_ranking_calibration_runs
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, calibration_run_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_ranking_calibration_run).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_ranking_worker_run(
        &self,
        run: TraceRankingWorkerRunWrite,
    ) -> Result<TraceRankingWorkerRunRecord, DatabaseError> {
        self.ensure_trace_tenant(&run.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &run.tenant_id).await?;
        let run_kind = enum_to_storage(run.run_kind)?;
        let status = enum_to_storage(run.status)?;
        let limit = u32_to_pg_i32(run.limit, "ranking_worker_runs.limit")?;
        let checked_count = u32_to_pg_i32(run.checked_count, "ranking_worker_runs.checked_count")?;
        let succeeded_count =
            u32_to_pg_i32(run.succeeded_count, "ranking_worker_runs.succeeded_count")?;
        let skipped_existing_count = u32_to_pg_i32(
            run.skipped_existing_count,
            "ranking_worker_runs.skipped_existing_count",
        )?;
        let skipped_model_risk_count = u32_to_pg_i32(
            run.skipped_model_risk_count,
            "ranking_worker_runs.skipped_model_risk_count",
        )?;
        let skipped_ineligible_count = u32_to_pg_i32(
            run.skipped_ineligible_count,
            "ranking_worker_runs.skipped_ineligible_count",
        )?;
        let pending_after_count = u32_to_pg_i32(
            run.pending_after_count,
            "ranking_worker_runs.pending_after_count",
        )?;
        let result_refs = serde_json::to_value(&run.result_refs).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace ranking worker run result_refs encode failed: {e}"
            ))
        })?;
        let reason_counts = serde_json::to_value(&run.reason_counts).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace ranking worker run reason_counts encode failed: {e}"
            ))
        })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_ranking_worker_runs (
                        tenant_id, ranking_worker_run_id, run_kind, status, dry_run, reason_hash,
                        model_version, target_use, policy_version, limit_count, checked_count,
                        succeeded_count, skipped_existing_count, skipped_model_risk_count,
                        skipped_ineligible_count, pending_after_count, result_refs, reason_counts,
                        actor_principal_ref, created_at, completed_at, last_error_hash
                     ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                        $17, $18, $19, $20, $21, $22
                     )
                     ON CONFLICT (tenant_id, ranking_worker_run_id) DO UPDATE SET
                        run_kind = excluded.run_kind,
                        status = excluded.status,
                        dry_run = excluded.dry_run,
                        reason_hash = excluded.reason_hash,
                        model_version = excluded.model_version,
                        target_use = excluded.target_use,
                        policy_version = excluded.policy_version,
                        limit_count = excluded.limit_count,
                        checked_count = excluded.checked_count,
                        succeeded_count = excluded.succeeded_count,
                        skipped_existing_count = excluded.skipped_existing_count,
                        skipped_model_risk_count = excluded.skipped_model_risk_count,
                        skipped_ineligible_count = excluded.skipped_ineligible_count,
                        pending_after_count = excluded.pending_after_count,
                        result_refs = excluded.result_refs,
                        reason_counts = excluded.reason_counts,
                        actor_principal_ref = excluded.actor_principal_ref,
                        created_at = excluded.created_at,
                        completed_at = excluded.completed_at,
                        last_error_hash = excluded.last_error_hash
                     RETURNING {TRACE_RANKING_WORKER_RUN_COLUMNS}"
                ),
                &[
                    &run.tenant_id,
                    &run.ranking_worker_run_id,
                    &run_kind,
                    &status,
                    &run.dry_run,
                    &run.reason_hash,
                    &run.model_version,
                    &run.target_use,
                    &run.policy_version,
                    &limit,
                    &checked_count,
                    &succeeded_count,
                    &skipped_existing_count,
                    &skipped_model_risk_count,
                    &skipped_ineligible_count,
                    &pending_after_count,
                    &result_refs,
                    &reason_counts,
                    &run.actor_principal_ref,
                    &run.created_at,
                    &run.completed_at,
                    &run.last_error_hash,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_ranking_worker_run(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_ranking_worker_runs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingWorkerRunRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RANKING_WORKER_RUN_COLUMNS}
                     FROM trace_ranking_worker_runs
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, ranking_worker_run_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_ranking_worker_run).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_export_manifest(
        &self,
        manifest: TraceExportManifestWrite,
    ) -> Result<TraceExportManifestRecord, DatabaseError> {
        self.ensure_trace_tenant(&manifest.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &manifest.tenant_id).await?;
        let artifact_kind = enum_to_storage(manifest.artifact_kind)?;
        let item_count = i32::try_from(manifest.item_count).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace export manifest item_count exceeds PostgreSQL integer range: {e}"
            ))
        })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_export_manifests (
                        tenant_id, export_manifest_id, artifact_kind, purpose_code,
                        audit_event_id, source_submission_ids, source_submission_ids_hash,
                        item_count, generated_at
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                     ON CONFLICT (tenant_id, export_manifest_id) DO UPDATE SET
                        artifact_kind = excluded.artifact_kind,
                        purpose_code = excluded.purpose_code,
                        audit_event_id = excluded.audit_event_id,
                        source_submission_ids = excluded.source_submission_ids,
                        source_submission_ids_hash = excluded.source_submission_ids_hash,
                        item_count = excluded.item_count,
                        generated_at = excluded.generated_at,
                        invalidated_at = NULL,
                        deleted_at = NULL,
                        updated_at = NOW()
                     RETURNING {TRACE_EXPORT_MANIFEST_COLUMNS}"
                ),
                &[
                    &manifest.tenant_id,
                    &manifest.export_manifest_id,
                    &artifact_kind,
                    &manifest.purpose_code,
                    &manifest.audit_event_id,
                    &manifest.source_submission_ids,
                    &manifest.source_submission_ids_hash,
                    &item_count,
                    &manifest.generated_at,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_export_manifest(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn upsert_trace_export_manifest_mirror(
        &self,
        mirror: TraceExportManifestMirrorWrite,
    ) -> Result<TraceExportManifestRecord, DatabaseError> {
        let tenant_id = mirror.manifest.tenant_id.clone();
        for object_ref in &mirror.object_refs {
            if object_ref.tenant_id != tenant_id {
                return Err(DatabaseError::Serialization(format!(
                    "trace export mirror object ref tenant {} does not match manifest tenant {}",
                    object_ref.tenant_id, tenant_id
                )));
            }
        }
        for item in &mirror.items {
            if item.tenant_id != tenant_id {
                return Err(DatabaseError::Serialization(format!(
                    "trace export mirror item tenant {} does not match manifest tenant {}",
                    item.tenant_id, tenant_id
                )));
            }
            if item.export_manifest_id != mirror.manifest.export_manifest_id {
                return Err(DatabaseError::Serialization(format!(
                    "trace export mirror item manifest {} does not match manifest {}",
                    item.export_manifest_id, mirror.manifest.export_manifest_id
                )));
            }
        }

        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_tenants (tenant_id) VALUES ($1)
             ON CONFLICT (tenant_id) DO UPDATE SET updated_at = NOW()",
            &[&tenant_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;

        for object_ref in &mirror.object_refs {
            let artifact_kind = enum_to_storage(object_ref.artifact_kind)?;
            tx.execute(
                "INSERT INTO trace_object_refs (
                    tenant_id, submission_id, object_ref_id, artifact_kind, object_store,
                    object_key, content_sha256, encryption_key_ref, size_bytes, compression,
                    created_by_job_id
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (tenant_id, submission_id, object_ref_id) DO UPDATE SET
                    artifact_kind = excluded.artifact_kind,
                    object_store = excluded.object_store,
                    object_key = excluded.object_key,
                    content_sha256 = excluded.content_sha256,
                    encryption_key_ref = excluded.encryption_key_ref,
                    size_bytes = excluded.size_bytes,
                    compression = excluded.compression,
                    created_by_job_id = excluded.created_by_job_id,
                    updated_at = NOW()",
                &[
                    &object_ref.tenant_id,
                    &object_ref.submission_id,
                    &object_ref.object_ref_id,
                    &artifact_kind,
                    &object_ref.object_store,
                    &object_ref.object_key,
                    &object_ref.content_sha256,
                    &object_ref.encryption_key_ref,
                    &object_ref.size_bytes,
                    &object_ref.compression,
                    &object_ref.created_by_job_id,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        }

        let artifact_kind = enum_to_storage(mirror.manifest.artifact_kind)?;
        let item_count = i32::try_from(mirror.manifest.item_count).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace export manifest item_count exceeds PostgreSQL integer range: {e}"
            ))
        })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_export_manifests (
                        tenant_id, export_manifest_id, artifact_kind, purpose_code,
                        audit_event_id, source_submission_ids, source_submission_ids_hash,
                        item_count, generated_at
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                     ON CONFLICT (tenant_id, export_manifest_id) DO UPDATE SET
                        artifact_kind = excluded.artifact_kind,
                        purpose_code = excluded.purpose_code,
                        audit_event_id = excluded.audit_event_id,
                        source_submission_ids = excluded.source_submission_ids,
                        source_submission_ids_hash = excluded.source_submission_ids_hash,
                        item_count = excluded.item_count,
                        generated_at = excluded.generated_at,
                        invalidated_at = NULL,
                        deleted_at = NULL,
                        updated_at = NOW()
                     RETURNING {TRACE_EXPORT_MANIFEST_COLUMNS}"
                ),
                &[
                    &mirror.manifest.tenant_id,
                    &mirror.manifest.export_manifest_id,
                    &artifact_kind,
                    &mirror.manifest.purpose_code,
                    &mirror.manifest.audit_event_id,
                    &mirror.manifest.source_submission_ids,
                    &mirror.manifest.source_submission_ids_hash,
                    &item_count,
                    &mirror.manifest.generated_at,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_export_manifest(&row)?;

        for item in &mirror.items {
            if let Some(derived_id) = item.derived_id {
                ensure_pg_derived_record_belongs_to_submission(
                    &tx,
                    &item.tenant_id,
                    item.submission_id,
                    derived_id,
                )
                .await?;
            }
            if let Some(object_ref_id) = item.object_ref_id {
                ensure_pg_object_ref_belongs_to_submission(
                    &tx,
                    &item.tenant_id,
                    item.submission_id,
                    object_ref_id,
                    "export manifest mirror item",
                )
                .await?;
            }
            if let Some(vector_entry_id) = item.vector_entry_id {
                ensure_pg_vector_entry_belongs_to_submission(
                    &tx,
                    &item.tenant_id,
                    item.submission_id,
                    vector_entry_id,
                )
                .await?;
            }
            let source_status_at_export = enum_to_storage(item.source_status_at_export)?;
            tx.execute(
                "INSERT INTO trace_export_manifest_items (
                    tenant_id, export_manifest_id, submission_id, trace_id, derived_id,
                    object_ref_id, vector_entry_id, source_status_at_export,
                    source_hash_at_export
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (tenant_id, export_manifest_id, submission_id) DO UPDATE SET
                    trace_id = excluded.trace_id,
                    derived_id = excluded.derived_id,
                    object_ref_id = excluded.object_ref_id,
                    vector_entry_id = excluded.vector_entry_id,
                    source_status_at_export = excluded.source_status_at_export,
                    source_hash_at_export = excluded.source_hash_at_export,
                    source_invalidated_at = NULL,
                    source_invalidation_reason = NULL,
                    updated_at = NOW()",
                &[
                    &item.tenant_id,
                    &item.export_manifest_id,
                    &item.submission_id,
                    &item.trace_id,
                    &item.derived_id,
                    &item.object_ref_id,
                    &item.vector_entry_id,
                    &source_status_at_export,
                    &item.source_hash_at_export,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        }

        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn delete_trace_export_manifest_mirror(
        &self,
        tenant_id: &str,
        export_manifest_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "DELETE FROM trace_export_manifest_items
             WHERE tenant_id = $1 AND export_manifest_id = $2",
            &[&tenant_id, &export_manifest_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.execute(
            "DELETE FROM trace_object_refs
             WHERE tenant_id = $1 AND created_by_job_id = $2",
            &[&tenant_id, &export_manifest_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.execute(
            "DELETE FROM trace_export_manifests
             WHERE tenant_id = $1 AND export_manifest_id = $2",
            &[&tenant_id, &export_manifest_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn list_trace_export_manifests(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceExportManifestRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_EXPORT_MANIFEST_COLUMNS}
                     FROM trace_export_manifests
                     WHERE tenant_id = $1
                     ORDER BY generated_at ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_export_manifest).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_export_manifest_item(
        &self,
        item: TraceExportManifestItemWrite,
    ) -> Result<TraceExportManifestItemRecord, DatabaseError> {
        self.ensure_trace_tenant(&item.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &item.tenant_id).await?;
        if let Some(derived_id) = item.derived_id {
            ensure_pg_derived_record_belongs_to_submission(
                &tx,
                &item.tenant_id,
                item.submission_id,
                derived_id,
            )
            .await?;
        }
        if let Some(object_ref_id) = item.object_ref_id {
            ensure_pg_object_ref_belongs_to_submission(
                &tx,
                &item.tenant_id,
                item.submission_id,
                object_ref_id,
                "export manifest item",
            )
            .await?;
        }
        if let Some(vector_entry_id) = item.vector_entry_id {
            ensure_pg_vector_entry_belongs_to_submission(
                &tx,
                &item.tenant_id,
                item.submission_id,
                vector_entry_id,
            )
            .await?;
        }
        let source_status_at_export = enum_to_storage(item.source_status_at_export)?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_export_manifest_items (
                        tenant_id, export_manifest_id, submission_id, trace_id, derived_id,
                        object_ref_id, vector_entry_id, source_status_at_export,
                        source_hash_at_export
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                     ON CONFLICT (tenant_id, export_manifest_id, submission_id) DO UPDATE SET
                        trace_id = excluded.trace_id,
                        derived_id = excluded.derived_id,
                        object_ref_id = excluded.object_ref_id,
                        vector_entry_id = excluded.vector_entry_id,
                        source_status_at_export = excluded.source_status_at_export,
                        source_hash_at_export = excluded.source_hash_at_export,
                        source_invalidated_at = NULL,
                        source_invalidation_reason = NULL,
                        updated_at = NOW()
                     RETURNING {TRACE_EXPORT_MANIFEST_ITEM_COLUMNS}"
                ),
                &[
                    &item.tenant_id,
                    &item.export_manifest_id,
                    &item.submission_id,
                    &item.trace_id,
                    &item.derived_id,
                    &item.object_ref_id,
                    &item.vector_entry_id,
                    &source_status_at_export,
                    &item.source_hash_at_export,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_export_manifest_item(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_export_manifest_items(
        &self,
        tenant_id: &str,
        export_manifest_id: Uuid,
    ) -> Result<Vec<TraceExportManifestItemRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_EXPORT_MANIFEST_ITEM_COLUMNS}
                     FROM trace_export_manifest_items
                     WHERE tenant_id = $1 AND export_manifest_id = $2
                     ORDER BY created_at ASC"
                ),
                &[&tenant_id, &export_manifest_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_export_manifest_item).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn invalidate_trace_export_manifests_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let updated = tx
            .execute(
                "UPDATE trace_export_manifests
                 SET invalidated_at = COALESCE(invalidated_at, NOW()),
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND $2 = ANY(source_submission_ids)
                   AND invalidated_at IS NULL
                   AND deleted_at IS NULL",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(updated)
    }

    async fn invalidate_trace_export_manifest_items_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        reason: TraceExportManifestItemInvalidationReason,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let reason = enum_to_storage(reason)?;
        let updated = tx
            .execute(
                "UPDATE trace_export_manifest_items
                 SET source_invalidated_at = COALESCE(source_invalidated_at, NOW()),
                     source_invalidation_reason = $3,
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND source_invalidated_at IS NULL",
                &[&tenant_id, &submission_id, &reason],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(updated)
    }

    async fn record_trace_withdrawal(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        withdrawn_at: DateTime<Utc>,
        prior_status: &str,
        distribution_reach: &str,
    ) -> Result<TraceWithdrawalRecord, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // First writer wins. `DO NOTHING` + a RETURNING-less follow-up SELECT
        // keeps a second withdrawal reporting the ORIGINAL tier and timestamp
        // rather than silently restamping them.
        tx.execute(
            "INSERT INTO trace_withdrawals
                 (tenant_id, submission_id, withdrawn_at, prior_status, distribution_reach)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, submission_id) DO NOTHING",
            &[
                &tenant_id,
                &submission_id,
                &withdrawn_at,
                &prior_status,
                &distribution_reach,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        // The content is deleted by the caller, so the submission row goes to
        // `revoked` (which every consumer/export predicate already excludes)
        // and carries both `withdrawn_at` and `purged_at`. Credit columns are
        // deliberately untouched: withdrawal is not a clawback.
        tx.execute(
            "UPDATE trace_submissions
                SET status = 'revoked',
                    withdrawn_at = COALESCE(withdrawn_at, $3),
                    revoked_at = COALESCE(revoked_at, $3),
                    purged_at = COALESCE(purged_at, $3),
                    updated_at = NOW()
              WHERE tenant_id = $1 AND submission_id = $2",
            &[&tenant_id, &submission_id, &withdrawn_at],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        let row = tx
            .query_one(
                "SELECT tenant_id, submission_id, withdrawn_at, prior_status, distribution_reach
                 FROM trace_withdrawals
                 WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(TraceWithdrawalRecord {
            tenant_id: row.get("tenant_id"),
            submission_id: row.get("submission_id"),
            withdrawn_at: row.get("withdrawn_at"),
            prior_status: row.get("prior_status"),
            distribution_reach: row.get("distribution_reach"),
        })
    }

    async fn get_trace_withdrawal(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<Option<TraceWithdrawalRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT tenant_id, submission_id, withdrawn_at, prior_status, distribution_reach
                 FROM trace_withdrawals
                 WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.map(|row| TraceWithdrawalRecord {
            tenant_id: row.get("tenant_id"),
            submission_id: row.get("submission_id"),
            withdrawn_at: row.get("withdrawn_at"),
            prior_status: row.get("prior_status"),
            distribution_reach: row.get("distribution_reach"),
        }))
    }

    async fn count_trace_export_memberships(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<i64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Deliberately counts invalidated memberships too: an export that was
        // published and later invalidated still put copies in other hands.
        let row = tx
            .query_one(
                "SELECT COUNT(*)::BIGINT AS membership_count
                 FROM trace_export_manifest_items
                 WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.get("membership_count"))
    }

    async fn list_trace_vector_entry_ids_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT vector_entry_id FROM trace_vector_entries
                   WHERE tenant_id = $1 AND submission_id = $2
                 UNION
                 SELECT vector_entry_id FROM trace_gate_decisions
                   WHERE tenant_id = $1 AND submission_id = $2
                     AND vector_entry_id IS NOT NULL
                 UNION
                 SELECT vector_entry_id FROM trace_gate_chunk_vector_entries
                   WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    async fn clear_trace_dedup_cluster_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let updated = tx
            .execute(
                // The version stamp goes with the value it names (V57): a
                // row holding a stamp but no simhash would claim a
                // derivation it no longer carries the output of.
                "UPDATE trace_gate_decisions
                    SET dedup_simhash = NULL,
                        dedup_cluster_id = NULL,
                        dedup_cluster_size = NULL,
                        dedup_signal_version = NULL
                  WHERE tenant_id = $1 AND submission_id = $2",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(updated)
    }

    async fn invalidate_trace_vector_entries_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let invalidated = enum_to_storage(TraceVectorEntryStatus::Invalidated)?;
        let updated = tx
            .execute(
                "UPDATE trace_vector_entries
                 SET status = $3,
                     invalidated_at = COALESCE(invalidated_at, NOW()),
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND status <> $3
                   AND deleted_at IS NULL",
                &[&tenant_id, &submission_id, &invalidated],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(updated)
    }

    async fn invalidate_trace_vector_entry_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        vector_entry_id: Uuid,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let invalidated = enum_to_storage(TraceVectorEntryStatus::Invalidated)?;
        let updated = tx
            .execute(
                "UPDATE trace_vector_entries
                 SET status = $4,
                     invalidated_at = COALESCE(invalidated_at, NOW()),
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND vector_entry_id = $3
                   AND status <> $4
                   AND deleted_at IS NULL",
                &[&tenant_id, &submission_id, &vector_entry_id, &invalidated],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(updated)
    }

    async fn append_trace_audit_event(
        &self,
        audit_event: TraceAuditEventWrite,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(&audit_event.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &audit_event.tenant_id).await?;
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
            &[&audit_event.tenant_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        let latest_event_hash: Option<String> = tx
            .query_opt(
                "SELECT event_hash
                 FROM trace_audit_events
                 WHERE tenant_id = $1
                   AND event_hash IS NOT NULL
                 ORDER BY audit_sequence DESC
                 LIMIT 1",
                &[&audit_event.tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .map(|row| row.get("event_hash"));
        validate_trace_audit_append_chain(
            &audit_event.tenant_id,
            audit_event.audit_event_id,
            latest_event_hash.as_deref(),
            audit_event.previous_event_hash.as_deref(),
            audit_event.event_hash.is_some(),
        )?;
        let next_audit_sequence: i64 = tx
            .query_one(
                "SELECT COALESCE(MAX(audit_sequence), 0) + 1
                 FROM trace_audit_events
                 WHERE tenant_id = $1",
                &[&audit_event.tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?
            .get(0);
        let action = enum_to_storage(audit_event.action)?;
        let metadata_json = serde_json::to_value(&audit_event.metadata).map_err(|e| {
            DatabaseError::Serialization(format!("trace audit metadata encode failed: {e}"))
        })?;
        tx.execute(
            "INSERT INTO trace_audit_events (
                    tenant_id, audit_sequence, audit_event_id, actor_principal_ref, actor_role,
                    action, reason, request_id, submission_id, object_ref_id, export_manifest_id,
                    decision_inputs_hash, previous_event_hash, event_hash, canonical_event_json,
                    metadata_json
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
            &[
                &audit_event.tenant_id,
                &next_audit_sequence,
                &audit_event.audit_event_id,
                &audit_event.actor_principal_ref,
                &audit_event.actor_role,
                &action,
                &audit_event.reason,
                &audit_event.request_id,
                &audit_event.submission_id,
                &audit_event.object_ref_id,
                &audit_event.export_manifest_id,
                &audit_event.decision_inputs_hash,
                &audit_event.previous_event_hash,
                &audit_event.event_hash,
                &audit_event.canonical_event_json,
                &metadata_json,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn list_trace_audit_events(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceAuditEventRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT
                    tenant_id, audit_sequence, audit_event_id, actor_principal_ref, actor_role,
                    action, reason, request_id, submission_id, object_ref_id, export_manifest_id,
                    decision_inputs_hash, previous_event_hash, event_hash, canonical_event_json,
                    metadata_json,
                    occurred_at
                 FROM trace_audit_events
                 WHERE tenant_id = $1
                 ORDER BY audit_sequence ASC",
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_audit_event).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn list_recent_trace_audit_events(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<TraceAuditEventRecord>, DatabaseError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = tx
            .query(
                "SELECT
                    tenant_id, audit_sequence, audit_event_id, actor_principal_ref, actor_role,
                    action, reason, request_id, submission_id, object_ref_id, export_manifest_id,
                    decision_inputs_hash, previous_event_hash, event_hash, canonical_event_json,
                    metadata_json,
                    occurred_at
                 FROM trace_audit_events
                 WHERE tenant_id = $1
                 ORDER BY audit_sequence DESC
                 LIMIT $2",
                &[&tenant_id, &limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_audit_event).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn get_trace_audit_event_by_id(
        &self,
        tenant_id: &str,
        audit_event_id: Uuid,
    ) -> Result<Option<TraceAuditEventRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT
                    tenant_id, audit_sequence, audit_event_id, actor_principal_ref, actor_role,
                    action, reason, request_id, submission_id, object_ref_id, export_manifest_id,
                    decision_inputs_hash, previous_event_hash, event_hash, canonical_event_json,
                    metadata_json,
                    occurred_at
                 FROM trace_audit_events
                 WHERE tenant_id = $1 AND audit_event_id = $2
                 LIMIT 1",
                &[&tenant_id, &audit_event_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_audit_event).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn append_trace_credit_event(
        &self,
        credit_event: TraceCreditEventWrite,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(&credit_event.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &credit_event.tenant_id).await?;
        let event_type = enum_to_storage(credit_event.event_type)?;
        let settlement_state = enum_to_storage(credit_event.settlement_state)?;
        tx.execute(
            "INSERT INTO trace_credit_ledger (
                    tenant_id, credit_event_id, submission_id, trace_id, credit_account_ref,
                    event_type, points_delta, reason, external_ref, actor_principal_ref,
                    actor_role, settlement_state
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &credit_event.tenant_id,
                &credit_event.credit_event_id,
                &credit_event.submission_id,
                &credit_event.trace_id,
                &credit_event.credit_account_ref,
                &event_type,
                &credit_event.points_delta,
                &credit_event.reason,
                &credit_event.external_ref,
                &credit_event.actor_principal_ref,
                &credit_event.actor_role,
                &settlement_state,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn upsert_trace_utility_attestation(
        &self,
        attestation: TraceUtilityAttestationWrite,
    ) -> Result<TraceUtilityAttestationRecord, DatabaseError> {
        self.ensure_trace_tenant(&attestation.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &attestation.tenant_id).await?;
        let event_type = enum_to_storage(attestation.event_type)?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_utility_attestations (
                        tenant_id, attestation_id, event_type, use_category, policy_version,
                        evidence_hash, external_ref_hash, source_submission_ids, actor_principal_ref
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                     ON CONFLICT (tenant_id, event_type, external_ref_hash) DO UPDATE SET
                        use_category = excluded.use_category,
                        policy_version = excluded.policy_version,
                        evidence_hash = excluded.evidence_hash,
                        source_submission_ids = excluded.source_submission_ids,
                        actor_principal_ref = excluded.actor_principal_ref
                     RETURNING {TRACE_UTILITY_ATTESTATION_COLUMNS}"
                ),
                &[
                    &attestation.tenant_id,
                    &attestation.attestation_id,
                    &event_type,
                    &attestation.use_category,
                    &attestation.policy_version,
                    &attestation.evidence_hash,
                    &attestation.external_ref_hash,
                    &attestation.source_submission_ids,
                    &attestation.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_utility_attestation(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_utility_attestations(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceUtilityAttestationRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_UTILITY_ATTESTATION_COLUMNS}
                     FROM trace_utility_attestations
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, attestation_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_utility_attestation).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_credit_settlement_batch(
        &self,
        batch: TraceCreditSettlementBatchWrite,
    ) -> Result<TraceCreditSettlementBatchRecord, DatabaseError> {
        self.ensure_trace_tenant(&batch.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &batch.tenant_id).await?;
        let status = enum_to_storage(batch.status)?;
        let line_items_json = serde_json::to_value(&batch.line_items).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace credit settlement line_items_json encode failed: {e}"
            ))
        })?;
        let ranking_credit_events_excluded_count =
            i32::try_from(batch.ranking_credit_events_excluded_count).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "trace credit settlement excluded ranking count exceeds PostgreSQL integer range: {e}"
                ))
            })?;
        let ranking_credit_events_excluded_reason_counts_json = serde_json::to_value(
            &batch.ranking_credit_events_excluded_reason_counts,
        )
        .map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace credit settlement ranking exclusion reason counts encode failed: {e}"
            ))
        })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_credit_settlement_batches (
                        tenant_id, settlement_batch_id, policy_version, status, reason_hash,
                        issuer_approval_evidence_hash, source_credit_event_ids,
                        source_submission_ids, source_list_hash, settled_credit_points,
                        settled_credit_micros, line_items_json, near_contract_id,
                        ranking_model_version, ranking_target_use,
                        ranking_calibration_run_id, ranking_calibration_report_hash,
                        ranking_calibration_joined_evidence_hash,
                        ranking_credit_events_excluded_count,
                        ranking_credit_events_excluded_reason_counts_json,
                        actor_principal_ref
                     ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                        $16, $17, $18, $19, $20, $21
                     )
                     ON CONFLICT (tenant_id, settlement_batch_id) DO UPDATE SET
                        policy_version = excluded.policy_version,
                        status = excluded.status,
                        reason_hash = excluded.reason_hash,
                        issuer_approval_evidence_hash = excluded.issuer_approval_evidence_hash,
                        source_credit_event_ids = excluded.source_credit_event_ids,
                        source_submission_ids = excluded.source_submission_ids,
                        source_list_hash = excluded.source_list_hash,
                        settled_credit_points = excluded.settled_credit_points,
                        settled_credit_micros = excluded.settled_credit_micros,
                        line_items_json = excluded.line_items_json,
                        near_contract_id = excluded.near_contract_id,
                        ranking_model_version = excluded.ranking_model_version,
                        ranking_target_use = excluded.ranking_target_use,
                        ranking_calibration_run_id = excluded.ranking_calibration_run_id,
                        ranking_calibration_report_hash = excluded.ranking_calibration_report_hash,
                        ranking_calibration_joined_evidence_hash = excluded.ranking_calibration_joined_evidence_hash,
                        ranking_credit_events_excluded_count = excluded.ranking_credit_events_excluded_count,
                        ranking_credit_events_excluded_reason_counts_json = excluded.ranking_credit_events_excluded_reason_counts_json,
                        actor_principal_ref = excluded.actor_principal_ref
                     RETURNING {TRACE_CREDIT_SETTLEMENT_BATCH_COLUMNS}"
                ),
                &[
                    &batch.tenant_id,
                    &batch.settlement_batch_id,
                    &batch.policy_version,
                    &status,
                    &batch.reason_hash,
                    &batch.issuer_approval_evidence_hash,
                    &batch.source_credit_event_ids,
                    &batch.source_submission_ids,
                    &batch.source_list_hash,
                    &batch.settled_credit_points,
                    &batch.settled_credit_micros,
                    &line_items_json,
                    &batch.near_contract_id,
                    &batch.ranking_model_version,
                    &batch.ranking_target_use,
                    &batch.ranking_calibration_run_id,
                    &batch.ranking_calibration_report_hash,
                    &batch.ranking_calibration_joined_evidence_hash,
                    &ranking_credit_events_excluded_count,
                    &ranking_credit_events_excluded_reason_counts_json,
                    &batch.actor_principal_ref,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_credit_settlement_batch(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_credit_settlement_batches(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceCreditSettlementBatchRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_CREDIT_SETTLEMENT_BATCH_COLUMNS}
                     FROM trace_credit_settlement_batches
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, settlement_batch_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_credit_settlement_batch).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_credit_hold(
        &self,
        hold: TraceCreditHoldWrite,
    ) -> Result<TraceCreditHoldRecord, DatabaseError> {
        self.ensure_trace_tenant(&hold.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &hold.tenant_id).await?;
        let reason = enum_to_storage(hold.reason)?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_credit_holds (
                        tenant_id, hold_id, credit_account_ref, credit_account_hash, reason,
                        reason_hash, actor_principal_ref, released_at
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                     ON CONFLICT (tenant_id, hold_id) DO UPDATE SET
                        credit_account_ref = excluded.credit_account_ref,
                        credit_account_hash = excluded.credit_account_hash,
                        reason = excluded.reason,
                        reason_hash = excluded.reason_hash,
                        actor_principal_ref = excluded.actor_principal_ref,
                        released_at = excluded.released_at
                     RETURNING {TRACE_CREDIT_HOLD_COLUMNS}"
                ),
                &[
                    &hold.tenant_id,
                    &hold.hold_id,
                    &hold.credit_account_ref,
                    &hold.credit_account_hash,
                    &reason,
                    &hold.reason_hash,
                    &hold.actor_principal_ref,
                    &hold.released_at,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_credit_hold(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_credit_holds(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceCreditHoldRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_CREDIT_HOLD_COLUMNS}
                     FROM trace_credit_holds
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, hold_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_credit_hold).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_near_credit_outbox_item(
        &self,
        item: TraceNearCreditOutboxItemWrite,
    ) -> Result<TraceNearCreditOutboxItemRecord, DatabaseError> {
        self.ensure_trace_tenant(&item.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &item.tenant_id).await?;
        let status = enum_to_storage(item.status)?;
        let account_operation = near_credit_call_method_name(&item.near_call_json)
            .filter(|_| near_credit_call_is_account_operation(&item.near_call_json))
            .map(str::to_string);
        let Some(account_operation) = account_operation else {
            let row = tx
                .query_one(
                    &format!(
                        "INSERT INTO trace_near_credit_outbox (
                            tenant_id, near_outbox_id, settlement_batch_id, credit_account_hash,
                            near_call_json, status, payout_near_account_id
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                         ON CONFLICT (tenant_id, near_outbox_id) DO UPDATE SET
                            settlement_batch_id = excluded.settlement_batch_id,
                            credit_account_hash = excluded.credit_account_hash,
                            near_call_json = excluded.near_call_json,
                            status = excluded.status,
                            payout_near_account_id = excluded.payout_near_account_id
                         RETURNING {TRACE_NEAR_CREDIT_OUTBOX_COLUMNS}"
                    ),
                    &[
                        &item.tenant_id,
                        &item.near_outbox_id,
                        &item.settlement_batch_id,
                        &item.credit_account_hash,
                        &item.near_call_json,
                        &status,
                        &item.payout_near_account_id,
                    ],
                )
                .await
                .map_err(DatabaseError::Postgres)?;
            let record = row_to_near_credit_outbox_item(&row)?;
            tx.commit().await.map_err(DatabaseError::Postgres)?;
            return Ok(record);
        };
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_near_credit_account_outbox (
                        tenant_id, near_outbox_id, credit_hold_id, operation,
                        credit_account_hash, near_call_json, status
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                     ON CONFLICT (tenant_id, near_outbox_id) DO UPDATE SET
                        credit_hold_id = excluded.credit_hold_id,
                        operation = excluded.operation,
                        credit_account_hash = excluded.credit_account_hash,
                        near_call_json = excluded.near_call_json,
                        status = excluded.status
                     RETURNING {TRACE_NEAR_CREDIT_ACCOUNT_OUTBOX_COLUMNS}"
                ),
                &[
                    &item.tenant_id,
                    &item.near_outbox_id,
                    &item.settlement_batch_id,
                    &account_operation,
                    &item.credit_account_hash,
                    &item.near_call_json,
                    &status,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_near_credit_outbox_item(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_near_credit_outbox_items(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceNearCreditOutboxItemRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_NEAR_CREDIT_OUTBOX_COLUMNS}
                     FROM trace_near_credit_outbox
                     WHERE tenant_id = $1
                     UNION ALL
                     SELECT {TRACE_NEAR_CREDIT_ACCOUNT_OUTBOX_COLUMNS}
                     FROM trace_near_credit_account_outbox
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, near_outbox_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_near_credit_outbox_item).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn update_trace_near_credit_outbox_status(
        &self,
        tenant_id: &str,
        near_outbox_id: Uuid,
        status: TraceCreditSettlementNearStatus,
        near_transaction_hash: Option<String>,
        last_error_hash: Option<String>,
        expected_prior_statuses: Option<Vec<TraceCreditSettlementNearStatus>>,
    ) -> Result<Option<TraceNearCreditOutboxItemRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let status_storage = enum_to_storage(status)?;
        // Optimistic prior-status allow-list (text[] or NULL). When NULL the write
        // is unconditional; when present the UPDATE only matches a row whose current
        // status is in the list, so the submit path can never re-advance an already
        // `submitted`/`confirmed` row.
        let expected_prior_storage: Option<Vec<String>> = match expected_prior_statuses {
            Some(statuses) => Some(
                statuses
                    .into_iter()
                    .map(enum_to_storage)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None => None,
        };
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE trace_near_credit_outbox
                     SET status = $3,
                         near_transaction_hash = COALESCE($4, near_transaction_hash),
                         submitted_at = CASE
                            WHEN submitted_at IS NULL AND $3 IN ('submitted', 'confirmed')
                            THEN NOW()
                            ELSE submitted_at
                         END,
                         confirmed_at = CASE
                            WHEN $3 = 'confirmed' THEN NOW()
                            WHEN $3 IN ('submitted', 'failed') THEN NULL
                            ELSE confirmed_at
                         END,
                         last_error_hash = CASE
                            WHEN $3 = 'failed' THEN $5
                            WHEN $3 = 'submitted' THEN $5
                            WHEN $3 = 'confirmed' THEN NULL
                            ELSE last_error_hash
                         END
                     WHERE tenant_id = $1 AND near_outbox_id = $2
                       AND ($6::text[] IS NULL OR status = ANY($6))
                     RETURNING {TRACE_NEAR_CREDIT_OUTBOX_COLUMNS}"
                ),
                &[
                    &tenant_id,
                    &near_outbox_id,
                    &status_storage,
                    &near_transaction_hash,
                    &last_error_hash,
                    &expected_prior_storage,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let row = if row.is_some() {
            row
        } else {
            tx.query_opt(
                &format!(
                    "UPDATE trace_near_credit_account_outbox
                     SET status = $3,
                         near_transaction_hash = COALESCE($4, near_transaction_hash),
                         submitted_at = CASE
                            WHEN submitted_at IS NULL AND $3 IN ('submitted', 'confirmed')
                            THEN NOW()
                            ELSE submitted_at
                         END,
                         confirmed_at = CASE
                            WHEN $3 = 'confirmed' THEN NOW()
                            WHEN $3 IN ('submitted', 'failed') THEN NULL
                            ELSE confirmed_at
                         END,
                         last_error_hash = CASE
                            WHEN $3 = 'failed' THEN $5
                            WHEN $3 = 'submitted' THEN $5
                            WHEN $3 = 'confirmed' THEN NULL
                            ELSE last_error_hash
                         END
                     WHERE tenant_id = $1 AND near_outbox_id = $2
                       AND ($6::text[] IS NULL OR status = ANY($6))
                     RETURNING {TRACE_NEAR_CREDIT_ACCOUNT_OUTBOX_COLUMNS}"
                ),
                &[
                    &tenant_id,
                    &near_outbox_id,
                    &status_storage,
                    &near_transaction_hash,
                    &last_error_hash,
                    &expected_prior_storage,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?
        };
        let record = row
            .as_ref()
            .map(row_to_near_credit_outbox_item)
            .transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn upsert_trace_benchmark_registry_outbox_item(
        &self,
        item: TraceBenchmarkRegistryOutboxItemWrite,
    ) -> Result<TraceBenchmarkRegistryOutboxItemRecord, DatabaseError> {
        self.ensure_trace_tenant(&item.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &item.tenant_id).await?;
        let operation = enum_to_storage(item.operation)?;
        let status = enum_to_storage(item.status)?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_benchmark_registry_outbox (
                        tenant_id, benchmark_outbox_id, conversion_id, operation, registry_ref,
                        artifact_payload_hash, source_submission_ids_hash, evaluator_ref,
                        evaluation_score, status
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                     ON CONFLICT (tenant_id, benchmark_outbox_id) DO UPDATE SET
                        conversion_id = excluded.conversion_id,
                        operation = excluded.operation,
                        registry_ref = excluded.registry_ref,
                        artifact_payload_hash = excluded.artifact_payload_hash,
                        source_submission_ids_hash = excluded.source_submission_ids_hash,
                        evaluator_ref = excluded.evaluator_ref,
                        evaluation_score = excluded.evaluation_score
                     RETURNING {TRACE_BENCHMARK_REGISTRY_OUTBOX_COLUMNS}"
                ),
                &[
                    &item.tenant_id,
                    &item.benchmark_outbox_id,
                    &item.conversion_id,
                    &operation,
                    &item.registry_ref,
                    &item.artifact_payload_hash,
                    &item.source_submission_ids_hash,
                    &item.evaluator_ref,
                    &item.evaluation_score,
                    &status,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_benchmark_registry_outbox_item(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_benchmark_registry_outbox_items(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceBenchmarkRegistryOutboxItemRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_BENCHMARK_REGISTRY_OUTBOX_COLUMNS}
                     FROM trace_benchmark_registry_outbox
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC, benchmark_outbox_id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows
            .iter()
            .map(row_to_benchmark_registry_outbox_item)
            .collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn update_trace_benchmark_registry_outbox_status(
        &self,
        tenant_id: &str,
        benchmark_outbox_id: Uuid,
        status: TraceBenchmarkRegistryOutboxStatus,
        external_receipt_ref: Option<String>,
        last_error_hash: Option<String>,
    ) -> Result<Option<TraceBenchmarkRegistryOutboxItemRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let status_storage = enum_to_storage(status)?;
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE trace_benchmark_registry_outbox
                     SET status = $3,
                         external_receipt_ref = COALESCE($4, external_receipt_ref),
                         submitted_at = CASE
                            WHEN submitted_at IS NULL AND $3 IN ('submitted', 'confirmed')
                            THEN NOW()
                            ELSE submitted_at
                         END,
                         confirmed_at = CASE
                            WHEN $3 = 'confirmed' THEN NOW()
                            WHEN $3 IN ('submitted', 'failed') THEN NULL
                            ELSE confirmed_at
                         END,
                         last_error_hash = CASE
                            WHEN $3 = 'failed' THEN $5
                            WHEN $3 IN ('submitted', 'confirmed') THEN NULL
                            ELSE last_error_hash
                         END
                     WHERE tenant_id = $1 AND benchmark_outbox_id = $2
                     RETURNING {TRACE_BENCHMARK_REGISTRY_OUTBOX_COLUMNS}"
                ),
                &[
                    &tenant_id,
                    &benchmark_outbox_id,
                    &status_storage,
                    &external_receipt_ref,
                    &last_error_hash,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row
            .as_ref()
            .map(row_to_benchmark_registry_outbox_item)
            .transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn write_trace_tombstone(
        &self,
        tombstone: TraceTombstoneWrite,
    ) -> Result<(), DatabaseError> {
        self.ensure_trace_tenant(&tombstone.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &tombstone.tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_tombstones (
                    tenant_id, tombstone_id, submission_id, trace_id, redaction_hash,
                    canonical_summary_hash, reason, effective_at, retain_until,
                    created_by_principal_ref
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (tenant_id, submission_id) DO NOTHING",
            &[
                &tombstone.tenant_id,
                &tombstone.tombstone_id,
                &tombstone.submission_id,
                &tombstone.trace_id,
                &tombstone.redaction_hash,
                &tombstone.canonical_summary_hash,
                &tombstone.reason,
                &tombstone.effective_at,
                &tombstone.retain_until,
                &tombstone.created_by_principal_ref,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn list_trace_tombstones(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceTombstoneRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_TOMBSTONE_COLUMNS}
                     FROM trace_tombstones
                     WHERE tenant_id = $1
                     ORDER BY effective_at ASC, created_at ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_tombstone).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_retention_job(
        &self,
        job: TraceRetentionJobWrite,
    ) -> Result<TraceRetentionJobRecord, DatabaseError> {
        self.ensure_trace_tenant(&job.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &job.tenant_id).await?;
        let status = enum_to_storage(job.status)?;
        let action_counts = serde_json::to_value(&job.action_counts).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace retention job action_counts encode failed: {e}"
            ))
        })?;
        let selected_revoked_count = i32::try_from(job.selected_revoked_count).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace retention job selected_revoked_count exceeds PostgreSQL integer range: {e}"
            ))
        })?;
        let selected_expired_count = i32::try_from(job.selected_expired_count).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace retention job selected_expired_count exceeds PostgreSQL integer range: {e}"
            ))
        })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_retention_jobs (
                        tenant_id, retention_job_id, purpose, dry_run, status,
                        requested_by_principal_ref, requested_by_role, purge_expired_before,
                        prune_export_cache, max_export_age_hours, audit_event_id, action_counts,
                        selected_revoked_count, selected_expired_count, started_at, completed_at
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                     ON CONFLICT (tenant_id, retention_job_id) DO UPDATE SET
                        purpose = excluded.purpose,
                        dry_run = excluded.dry_run,
                        status = excluded.status,
                        requested_by_principal_ref = excluded.requested_by_principal_ref,
                        requested_by_role = excluded.requested_by_role,
                        purge_expired_before = excluded.purge_expired_before,
                        prune_export_cache = excluded.prune_export_cache,
                        max_export_age_hours = excluded.max_export_age_hours,
                        audit_event_id = excluded.audit_event_id,
                        action_counts = excluded.action_counts,
                        selected_revoked_count = excluded.selected_revoked_count,
                        selected_expired_count = excluded.selected_expired_count,
                        started_at = excluded.started_at,
                        completed_at = excluded.completed_at,
                        updated_at = NOW()
                     RETURNING {TRACE_RETENTION_JOB_COLUMNS}"
                ),
                &[
                    &job.tenant_id,
                    &job.retention_job_id,
                    &job.purpose,
                    &job.dry_run,
                    &status,
                    &job.requested_by_principal_ref,
                    &job.requested_by_role,
                    &job.purge_expired_before,
                    &job.prune_export_cache,
                    &job.max_export_age_hours,
                    &job.audit_event_id,
                    &action_counts,
                    &selected_revoked_count,
                    &selected_expired_count,
                    &job.started_at,
                    &job.completed_at,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_retention_job(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn upsert_trace_retention_job_item(
        &self,
        item: TraceRetentionJobItemWrite,
    ) -> Result<TraceRetentionJobItemRecord, DatabaseError> {
        self.ensure_trace_tenant(&item.tenant_id).await?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &item.tenant_id).await?;
        let action = enum_to_storage(item.action)?;
        let status = enum_to_storage(item.status)?;
        let action_counts = serde_json::to_value(&item.action_counts).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace retention job item action_counts encode failed: {e}"
            ))
        })?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_retention_job_items (
                        tenant_id, retention_job_id, submission_id, action, status, reason,
                        action_counts, verified_at
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                     ON CONFLICT (tenant_id, retention_job_id, submission_id, action) DO UPDATE SET
                        status = excluded.status,
                        reason = excluded.reason,
                        action_counts = excluded.action_counts,
                        verified_at = excluded.verified_at,
                        updated_at = NOW()
                     RETURNING {TRACE_RETENTION_JOB_ITEM_COLUMNS}"
                ),
                &[
                    &item.tenant_id,
                    &item.retention_job_id,
                    &item.submission_id,
                    &action,
                    &status,
                    &item.reason,
                    &action_counts,
                    &item.verified_at,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_retention_job_item(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_retention_jobs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRetentionJobRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RETENTION_JOB_COLUMNS}
                     FROM trace_retention_jobs
                     WHERE tenant_id = $1
                     ORDER BY created_at ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_retention_job).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn list_trace_retention_job_items(
        &self,
        tenant_id: &str,
        retention_job_id: Uuid,
    ) -> Result<Vec<TraceRetentionJobItemRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_RETENTION_JOB_ITEM_COLUMNS}
                     FROM trace_retention_job_items
                     WHERE tenant_id = $1 AND retention_job_id = $2
                     ORDER BY created_at ASC, submission_id ASC, action ASC"
                ),
                &[&tenant_id, &retention_job_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_retention_job_item).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_export_access_grant(
        &self,
        grant: TraceExportAccessGrantWrite,
    ) -> Result<TraceExportAccessGrantRecord, DatabaseError> {
        self.ensure_trace_tenant(&grant.tenant_id).await?;
        let max_item_cap = grant
            .max_item_cap
            .map(|value| {
                i32::try_from(value).map_err(|e| {
                    DatabaseError::Constraint(format!(
                        "trace export access grant max_item_cap is too large: {e}"
                    ))
                })
            })
            .transpose()?;
        let status = enum_to_storage(grant.status)?;
        let metadata_json = serde_json::to_value(&grant.metadata).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace export access grant metadata encode failed: {e}"
            ))
        })?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &grant.tenant_id).await?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_export_access_grants (
                        tenant_id, export_job_id, grant_id, caller_principal_ref,
                        requested_dataset_kind, purpose, max_item_cap, status,
                        requested_at, expires_at, metadata_json
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                     ON CONFLICT (tenant_id, grant_id) DO UPDATE SET
                        export_job_id = excluded.export_job_id,
                        caller_principal_ref = excluded.caller_principal_ref,
                        requested_dataset_kind = excluded.requested_dataset_kind,
                        purpose = excluded.purpose,
                        max_item_cap = excluded.max_item_cap,
                        status = excluded.status,
                        requested_at = excluded.requested_at,
                        expires_at = excluded.expires_at,
                        metadata_json = excluded.metadata_json,
                        updated_at = NOW()
                     RETURNING {TRACE_EXPORT_ACCESS_GRANT_COLUMNS}"
                ),
                &[
                    &grant.tenant_id,
                    &grant.export_job_id,
                    &grant.grant_id,
                    &grant.caller_principal_ref,
                    &grant.requested_dataset_kind,
                    &grant.purpose,
                    &max_item_cap,
                    &status,
                    &grant.requested_at,
                    &grant.expires_at,
                    &metadata_json,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_export_access_grant(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_export_access_grants(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceExportAccessGrantRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_EXPORT_ACCESS_GRANT_COLUMNS}
                     FROM trace_export_access_grants
                     WHERE tenant_id = $1
                     ORDER BY requested_at ASC, created_at ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_export_access_grant).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn upsert_trace_export_job(
        &self,
        job: TraceExportJobWrite,
    ) -> Result<TraceExportJobRecord, DatabaseError> {
        self.ensure_trace_tenant(&job.tenant_id).await?;
        let max_item_cap = job
            .max_item_cap
            .map(|value| {
                i32::try_from(value).map_err(|e| {
                    DatabaseError::Constraint(format!(
                        "trace export job max_item_cap is too large: {e}"
                    ))
                })
            })
            .transpose()?;
        let item_count = job
            .item_count
            .map(|value| {
                i32::try_from(value).map_err(|e| {
                    DatabaseError::Constraint(format!(
                        "trace export job item_count is too large: {e}"
                    ))
                })
            })
            .transpose()?;
        let status = enum_to_storage(job.status)?;
        let metadata_json = serde_json::to_value(&job.metadata).map_err(|e| {
            DatabaseError::Serialization(format!("trace export job metadata encode failed: {e}"))
        })?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &job.tenant_id).await?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO trace_export_jobs (
                        tenant_id, export_job_id, grant_id, caller_principal_ref,
                        requested_dataset_kind, purpose, max_item_cap, status, requested_at,
                        started_at, finished_at, expires_at, result_manifest_id, item_count,
                        last_error, metadata_json
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                     ON CONFLICT (tenant_id, export_job_id) DO UPDATE SET
                        grant_id = excluded.grant_id,
                        caller_principal_ref = excluded.caller_principal_ref,
                        requested_dataset_kind = excluded.requested_dataset_kind,
                        purpose = excluded.purpose,
                        max_item_cap = excluded.max_item_cap,
                        status = excluded.status,
                        requested_at = excluded.requested_at,
                        started_at = excluded.started_at,
                        finished_at = excluded.finished_at,
                        expires_at = excluded.expires_at,
                        result_manifest_id = excluded.result_manifest_id,
                        item_count = excluded.item_count,
                        last_error = excluded.last_error,
                        metadata_json = excluded.metadata_json,
                        updated_at = NOW()
                     RETURNING {TRACE_EXPORT_JOB_COLUMNS}"
                ),
                &[
                    &job.tenant_id,
                    &job.export_job_id,
                    &job.grant_id,
                    &job.caller_principal_ref,
                    &job.requested_dataset_kind,
                    &job.purpose,
                    &max_item_cap,
                    &status,
                    &job.requested_at,
                    &job.started_at,
                    &job.finished_at,
                    &job.expires_at,
                    &job.result_manifest_id,
                    &item_count,
                    &job.last_error,
                    &metadata_json,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row_to_export_job(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_export_jobs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceExportJobRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_EXPORT_JOB_COLUMNS}
                     FROM trace_export_jobs
                     WHERE tenant_id = $1
                     ORDER BY requested_at ASC, created_at ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows.iter().map(row_to_export_job).collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn update_trace_export_job_status(
        &self,
        tenant_id: &str,
        export_job_id: Uuid,
        update: TraceExportJobStatusUpdate,
    ) -> Result<Option<TraceExportJobRecord>, DatabaseError> {
        let item_count = update
            .item_count
            .map(|value| {
                i32::try_from(value).map_err(|e| {
                    DatabaseError::Constraint(format!(
                        "trace export job item_count is too large: {e}"
                    ))
                })
            })
            .transpose()?;
        let status = enum_to_storage(update.status)?;
        let metadata_json = serde_json::to_value(&update.metadata).map_err(|e| {
            DatabaseError::Serialization(format!("trace export job metadata encode failed: {e}"))
        })?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE trace_export_jobs
                     SET status = $3,
                         started_at = $4,
                         finished_at = $5,
                         result_manifest_id = $6,
                         item_count = $7,
                         last_error = $8,
                         metadata_json = $9,
                         updated_at = NOW()
                     WHERE tenant_id = $1 AND export_job_id = $2
                     RETURNING {TRACE_EXPORT_JOB_COLUMNS}"
                ),
                &[
                    &tenant_id,
                    &export_job_id,
                    &status,
                    &update.started_at,
                    &update.finished_at,
                    &update.result_manifest_id,
                    &item_count,
                    &update.last_error,
                    &metadata_json,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_export_job).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn claim_next_trace_export_job(
        &self,
        tenant_id: &str,
        requested_dataset_kind: Option<&str>,
        claim_at: DateTime<Utc>,
        worker_principal_ref: &str,
    ) -> Result<Option<TraceExportJobRecord>, DatabaseError> {
        let dataset_kind = requested_dataset_kind.map(str::to_string);
        let queued_status = enum_to_storage(TraceExportJobStatus::Queued)?;
        let running_status = enum_to_storage(TraceExportJobStatus::Running)?;
        let metadata_patch = serde_json::to_value(BTreeMap::from([
            ("state".to_string(), "running".to_string()),
            (
                "claimed_by_principal_ref".to_string(),
                worker_principal_ref.to_string(),
            ),
        ]))
        .map_err(|e| {
            DatabaseError::Serialization(format!("trace export job metadata encode failed: {e}"))
        })?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                &format!(
                    // `next_job` renames the claimed id so that the unqualified
                    // `RETURNING {TRACE_EXPORT_JOB_COLUMNS}` list below stays
                    // unambiguous across the `FROM next_job` join.
                    "WITH next_job AS (
                        SELECT export_job_id AS claimed_export_job_id
                          FROM trace_export_jobs
                         WHERE tenant_id = $1
                           AND status = $2
                           AND expires_at > $3
                           AND ($4::TEXT IS NULL OR requested_dataset_kind = $4)
                         ORDER BY requested_at ASC, created_at ASC
                         LIMIT 1
                         FOR UPDATE SKIP LOCKED
                     )
                     UPDATE trace_export_jobs AS job
                        SET status = $5,
                            started_at = $3,
                            finished_at = NULL,
                            last_error = NULL,
                            metadata_json = job.metadata_json || $6::JSONB,
                            updated_at = NOW()
                       FROM next_job
                      WHERE job.tenant_id = $1
                        AND job.export_job_id = next_job.claimed_export_job_id
                      RETURNING {TRACE_EXPORT_JOB_COLUMNS}"
                ),
                &[
                    &tenant_id,
                    &queued_status,
                    &claim_at,
                    &dataset_kind,
                    &running_status,
                    &metadata_patch,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_export_job).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn recover_stale_trace_export_job(
        &self,
        tenant_id: &str,
        export_job_id: Uuid,
        stale_at: DateTime<Utc>,
        update: TraceExportJobStatusUpdate,
    ) -> Result<Option<TraceExportJobRecord>, DatabaseError> {
        let item_count = update
            .item_count
            .map(|value| {
                i32::try_from(value).map_err(|e| {
                    DatabaseError::Constraint(format!(
                        "trace export job item_count is too large: {e}"
                    ))
                })
            })
            .transpose()?;
        let status = enum_to_storage(update.status)?;
        let running_status = enum_to_storage(TraceExportJobStatus::Running)?;
        let metadata_json = serde_json::to_value(&update.metadata).map_err(|e| {
            DatabaseError::Serialization(format!("trace export job metadata encode failed: {e}"))
        })?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE trace_export_jobs
                     SET status = $3,
                         started_at = $4,
                         finished_at = $5,
                         result_manifest_id = $6,
                         item_count = $7,
                         last_error = $8,
                         metadata_json = $9,
                         updated_at = NOW()
                     WHERE tenant_id = $1
                       AND export_job_id = $2
                       AND status = $10
                       AND expires_at <= $11
                     RETURNING {TRACE_EXPORT_JOB_COLUMNS}"
                ),
                &[
                    &tenant_id,
                    &export_job_id,
                    &status,
                    &update.started_at,
                    &update.finished_at,
                    &update.result_manifest_id,
                    &item_count,
                    &update.last_error,
                    &metadata_json,
                    &running_status,
                    &stale_at,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_export_job).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn retry_failed_trace_export_job(
        &self,
        tenant_id: &str,
        export_job_id: Uuid,
        retry_at: DateTime<Utc>,
        update: TraceExportJobStatusUpdate,
    ) -> Result<Option<TraceExportJobRecord>, DatabaseError> {
        let item_count = update
            .item_count
            .map(|value| {
                i32::try_from(value).map_err(|e| {
                    DatabaseError::Constraint(format!(
                        "trace export job item_count is too large: {e}"
                    ))
                })
            })
            .transpose()?;
        let status = enum_to_storage(update.status)?;
        let failed_status = enum_to_storage(TraceExportJobStatus::Failed)?;
        let metadata_json = serde_json::to_value(&update.metadata).map_err(|e| {
            DatabaseError::Serialization(format!("trace export job metadata encode failed: {e}"))
        })?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE trace_export_jobs
                     SET status = $3,
                         started_at = $4,
                         finished_at = $5,
                         result_manifest_id = $6,
                         item_count = $7,
                         last_error = $8,
                         metadata_json = $9,
                         updated_at = NOW()
                     WHERE tenant_id = $1
                       AND export_job_id = $2
                       AND status = $10
                       AND expires_at > $11
                     RETURNING {TRACE_EXPORT_JOB_COLUMNS}"
                ),
                &[
                    &tenant_id,
                    &export_job_id,
                    &status,
                    &update.started_at,
                    &update.finished_at,
                    &update.result_manifest_id,
                    &item_count,
                    &update.last_error,
                    &metadata_json,
                    &failed_status,
                    &retry_at,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row.as_ref().map(row_to_export_job).transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn upsert_trace_revocation_propagation_item(
        &self,
        item: TraceRevocationPropagationItemWrite,
    ) -> Result<TraceRevocationPropagationItemRecord, DatabaseError> {
        self.ensure_trace_tenant(&item.tenant_id).await?;
        let attempt_count = i32::try_from(item.attempt_count).map_err(|e| {
            DatabaseError::Constraint(format!("trace revocation attempt_count is too large: {e}"))
        })?;
        let target_kind = enum_to_storage(item.target.kind())?;
        let target_json = serde_json::to_value(&item.target).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace revocation propagation target encode failed: {e}"
            ))
        })?;
        let action = enum_to_storage(item.action)?;
        let status = enum_to_storage(item.status)?;
        let metadata_json = serde_json::to_value(&item.metadata).map_err(|e| {
            DatabaseError::Serialization(format!(
                "trace revocation propagation metadata encode failed: {e}"
            ))
        })?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, &item.tenant_id).await?;
        let row = tx
            .query_opt(
                &format!(
                    "INSERT INTO trace_revocation_propagation_items (
                        tenant_id, propagation_item_id, source_submission_id, trace_id,
                        target_kind, target_json, action, status, idempotency_key, reason,
                        attempt_count, last_error, next_attempt_at, completed_at, evidence_hash,
                        metadata_json
                     )
                     SELECT $1, $2, $3, submission.trace_id, $4, $5, $6, $7, $8, $9,
                            $10, $11, $12, $13, $14, $15
                     FROM trace_submissions submission
                     WHERE submission.tenant_id = $1
                       AND submission.submission_id = $3
                     ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
                     SET target_kind = EXCLUDED.target_kind,
                         target_json = EXCLUDED.target_json,
                         action = EXCLUDED.action,
                         status = EXCLUDED.status,
                         reason = EXCLUDED.reason,
                         attempt_count = EXCLUDED.attempt_count,
                         last_error = EXCLUDED.last_error,
                         next_attempt_at = EXCLUDED.next_attempt_at,
                         completed_at = EXCLUDED.completed_at,
                         evidence_hash = EXCLUDED.evidence_hash,
                         metadata_json = EXCLUDED.metadata_json,
                         updated_at = NOW()
                     RETURNING {TRACE_REVOCATION_PROPAGATION_ITEM_COLUMNS}"
                ),
                &[
                    &item.tenant_id,
                    &item.propagation_item_id,
                    &item.source_submission_id,
                    &target_kind,
                    &target_json,
                    &action,
                    &status,
                    &item.idempotency_key,
                    &item.reason,
                    &attempt_count,
                    &item.last_error,
                    &item.next_attempt_at,
                    &item.completed_at,
                    &item.evidence_hash,
                    &metadata_json,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let Some(row) = row else {
            return Err(DatabaseError::Constraint(format!(
                "trace revocation propagation source submission {} does not belong to tenant {}",
                item.source_submission_id, item.tenant_id
            )));
        };
        let record = row_to_revocation_propagation_item(&row)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn list_trace_revocation_propagation_items(
        &self,
        tenant_id: &str,
        source_submission_id: Uuid,
    ) -> Result<Vec<TraceRevocationPropagationItemRecord>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_REVOCATION_PROPAGATION_ITEM_COLUMNS}
                     FROM trace_revocation_propagation_items
                     WHERE tenant_id = $1
                       AND source_submission_id = $2
                     ORDER BY created_at ASC, propagation_item_id ASC"
                ),
                &[&tenant_id, &source_submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows
            .iter()
            .map(row_to_revocation_propagation_item)
            .collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn list_due_trace_revocation_propagation_items(
        &self,
        tenant_id: &str,
        now: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<TraceRevocationPropagationItemRecord>, DatabaseError> {
        let limit = i64::from(limit);
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let pending = enum_to_storage(TraceRevocationPropagationItemStatus::Pending)?;
        let failed = enum_to_storage(TraceRevocationPropagationItemStatus::Failed)?;
        let rows = tx
            .query(
                &format!(
                    "SELECT {TRACE_REVOCATION_PROPAGATION_ITEM_COLUMNS}
                     FROM trace_revocation_propagation_items
                     WHERE tenant_id = $1
                       AND status IN ($2, $3)
                       AND (next_attempt_at IS NULL OR next_attempt_at <= $4)
                     ORDER BY created_at ASC, propagation_item_id ASC
                     LIMIT $5"
                ),
                &[&tenant_id, &pending, &failed, &now, &limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let records = rows
            .iter()
            .map(row_to_revocation_propagation_item)
            .collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        records
    }

    async fn update_trace_revocation_propagation_item_status(
        &self,
        tenant_id: &str,
        propagation_item_id: Uuid,
        update: TraceRevocationPropagationItemStatusUpdate,
    ) -> Result<Option<TraceRevocationPropagationItemRecord>, DatabaseError> {
        let attempt_count = i32::try_from(update.attempt_count).map_err(|e| {
            DatabaseError::Constraint(format!("trace revocation attempt_count is too large: {e}"))
        })?;
        let status = enum_to_storage(update.status)?;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE trace_revocation_propagation_items
                     SET status = $3,
                         attempt_count = $4,
                         last_error = $5,
                         next_attempt_at = $6,
                         completed_at = $7,
                         evidence_hash = $8,
                         updated_at = NOW()
                     WHERE tenant_id = $1
                       AND propagation_item_id = $2
                     RETURNING {TRACE_REVOCATION_PROPAGATION_ITEM_COLUMNS}"
                ),
                &[
                    &tenant_id,
                    &propagation_item_id,
                    &status,
                    &attempt_count,
                    &update.last_error,
                    &update.next_attempt_at,
                    &update.completed_at,
                    &update.evidence_hash,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let record = row
            .as_ref()
            .map(row_to_revocation_propagation_item)
            .transpose()?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(record)
    }

    async fn invalidate_trace_submission_artifacts(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        derived_status: TraceDerivedStatus,
    ) -> Result<TraceArtifactInvalidationCounts, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let derived_status = enum_to_storage(derived_status)?;
        let object_refs_invalidated = tx
            .execute(
                "UPDATE trace_object_refs
                 SET invalidated_at = COALESCE(invalidated_at, NOW()),
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND invalidated_at IS NULL
                   AND deleted_at IS NULL",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        let derived_records_invalidated = tx
            .execute(
                "UPDATE trace_derived_records
                 SET status = $3,
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND status <> $3",
                &[&tenant_id, &submission_id, &derived_status],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(TraceArtifactInvalidationCounts {
            object_refs_invalidated,
            derived_records_invalidated,
        })
    }

    async fn mark_trace_object_ref_deleted(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        object_store: &str,
        object_key: &str,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let deleted = tx
            .execute(
                "UPDATE trace_object_refs
                 SET invalidated_at = COALESCE(invalidated_at, NOW()),
                     deleted_at = COALESCE(deleted_at, NOW()),
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND object_store = $3
                   AND object_key = $4
                   AND deleted_at IS NULL",
                &[&tenant_id, &submission_id, &object_store, &object_key],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(deleted)
    }

    async fn invalidate_trace_object_refs_by_kind(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        artifact_kind: TraceObjectArtifactKind,
    ) -> Result<u64, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let artifact_kind = enum_to_storage(artifact_kind)?;
        let invalidated = tx
            .execute(
                "UPDATE trace_object_refs
                 SET invalidated_at = COALESCE(invalidated_at, NOW()),
                     updated_at = NOW()
                 WHERE tenant_id = $1
                   AND submission_id = $2
                   AND artifact_kind = $3
                   AND invalidated_at IS NULL
                   AND deleted_at IS NULL",
                &[&tenant_id, &submission_id, &artifact_kind],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(invalidated)
    }

    async fn stream_trace_gate_decisions_for_replay(
        &self,
        tenant_id: &str,
        page_size: u32,
        after_cursor: Option<(DateTime<Utc>, Uuid)>,
    ) -> Result<Vec<TraceGateDecisionRow>, DatabaseError> {
        if page_size == 0 {
            return Ok(Vec::new());
        }
        let limit = page_size as i64;
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = if let Some((after_decided_at, after_decision_id)) = after_cursor {
            tx.query(
                "SELECT decision_id, submission_id, gate_policy_version, gate_version_hash, \
                        perplexity_micros, tail_fraction_micros, perplexity_passed, \
                        novelty_score_micros, nearest_neighbor_hash, novelty_passed, \
                        embedding_evidence_hash, attestation_chain_hash, decided_at, \
                        vector_entry_id, credit_withheld_reason, \
                        peak_perplexity_micros, peak_novelty_micros, chunk_count, chunks_capped, \
                        total_chunk_count, qualifying_token_fraction_micros, composite_score_micros, \
                        vector_index_snapshot_id, index_cardinality_at_scoring \
                 FROM trace_gate_decisions \
                 WHERE tenant_id = $1 \
                   AND vector_entry_id IS NOT NULL \
                   AND (decided_at, decision_id) > ($2, $3) \
                 ORDER BY decided_at ASC, decision_id ASC \
                 LIMIT $4",
                &[&tenant_id, &after_decided_at, &after_decision_id, &limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?
        } else {
            tx.query(
                "SELECT decision_id, submission_id, gate_policy_version, gate_version_hash, \
                        perplexity_micros, tail_fraction_micros, perplexity_passed, \
                        novelty_score_micros, nearest_neighbor_hash, novelty_passed, \
                        embedding_evidence_hash, attestation_chain_hash, decided_at, \
                        vector_entry_id, credit_withheld_reason, \
                        peak_perplexity_micros, peak_novelty_micros, chunk_count, chunks_capped, \
                        total_chunk_count, qualifying_token_fraction_micros, composite_score_micros, \
                        vector_index_snapshot_id, index_cardinality_at_scoring \
                 FROM trace_gate_decisions \
                 WHERE tenant_id = $1 \
                   AND vector_entry_id IS NOT NULL \
                 ORDER BY decided_at ASC, decision_id ASC \
                 LIMIT $2",
                &[&tenant_id, &limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?
        };
        let out = rows
            .iter()
            .map(|row| TraceGateDecisionRow {
                decision_id: row.get("decision_id"),
                submission_id: row.get("submission_id"),
                gate_policy_version: row.get("gate_policy_version"),
                gate_version_hash: row.get("gate_version_hash"),
                perplexity_micros: row.get("perplexity_micros"),
                tail_fraction_micros: row.get("tail_fraction_micros"),
                perplexity_passed: row.get("perplexity_passed"),
                novelty_score_micros: row.get("novelty_score_micros"),
                nearest_neighbor_hash: row.get("nearest_neighbor_hash"),
                novelty_passed: row.get("novelty_passed"),
                embedding_evidence_hash: row.get("embedding_evidence_hash"),
                attestation_chain_hash: row.get("attestation_chain_hash"),
                decided_at: row.get("decided_at"),
                vector_entry_id: row.get("vector_entry_id"),
                credit_withheld_reason: row.get("credit_withheld_reason"),
                peak_perplexity_micros: row.get("peak_perplexity_micros"),
                peak_novelty_micros: row.get("peak_novelty_micros"),
                chunk_count: row.get("chunk_count"),
                total_chunk_count: row.get("total_chunk_count"),
                chunks_capped: row.get("chunks_capped"),
                qualifying_token_fraction_micros: row.get("qualifying_token_fraction_micros"),
                composite_score_micros: row.get("composite_score_micros"),
                vector_index_snapshot_id: row.get("vector_index_snapshot_id"),
                index_cardinality_at_scoring: row.get("index_cardinality_at_scoring"),
            })
            .collect();
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(out)
    }

    async fn is_vector_entry_revoked(
        &self,
        tenant_id: &str,
        vector_entry_id: Uuid,
    ) -> Result<bool, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // target_json is the serde representation of TraceRevocationPropagationTarget,
        // which serializes as `{"kind":"vector_entry","vector_entry_id":"<uuid>"}`
        // (snake_case adjacent-tagged enum). We match on both the explicit
        // `target_kind` column (storage label) AND the embedded uuid to be
        // robust to any future addition of other VectorEntry-shaped targets.
        let row = tx
            .query_opt(
                "SELECT 1 \
                 FROM trace_revocation_propagation_items \
                 WHERE tenant_id = $1 \
                   AND target_kind = 'vector_entry' \
                   AND action = 'invalidate_vector' \
                   AND status = 'done' \
                   AND (target_json ->> 'vector_entry_id') = $2 \
                 LIMIT 1",
                &[&tenant_id, &vector_entry_id.to_string()],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.is_some())
    }

    async fn insert_trace_gate_decision(
        &self,
        tenant_id: &str,
        decision: TraceGateDecisionRow,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_gate_decisions (
                 tenant_id, decision_id, submission_id, gate_policy_version,
                 gate_version_hash, perplexity_micros, tail_fraction_micros,
                 perplexity_passed, novelty_score_micros, nearest_neighbor_hash,
                 novelty_passed, embedding_evidence_hash, attestation_chain_hash,
                 decided_at, vector_entry_id, credit_withheld_reason,
                 peak_perplexity_micros, peak_novelty_micros, chunk_count, chunks_capped,
                 total_chunk_count, qualifying_token_fraction_micros,
                 composite_score_micros,
                 vector_index_snapshot_id, index_cardinality_at_scoring
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)",
            &[
                &tenant_id,
                &decision.decision_id,
                &decision.submission_id,
                &decision.gate_policy_version,
                &decision.gate_version_hash,
                &decision.perplexity_micros,
                &decision.tail_fraction_micros,
                &decision.perplexity_passed,
                &decision.novelty_score_micros,
                &decision.nearest_neighbor_hash,
                &decision.novelty_passed,
                &decision.embedding_evidence_hash,
                &decision.attestation_chain_hash,
                &decision.decided_at,
                &decision.vector_entry_id,
                &decision.credit_withheld_reason,
                &decision.peak_perplexity_micros,
                &decision.peak_novelty_micros,
                &decision.chunk_count,
                &decision.chunks_capped,
                &decision.total_chunk_count,
                &decision.qualifying_token_fraction_micros,
                &decision.composite_score_micros,
                &decision.vector_index_snapshot_id,
                &decision.index_cardinality_at_scoring,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn insert_trace_gate_decision_with_chunk_entries(
        &self,
        tenant_id: &str,
        decision: TraceGateDecisionRow,
        chunk_entries: Vec<TraceGateChunkVectorEntryRow>,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "INSERT INTO trace_gate_decisions (
                 tenant_id, decision_id, submission_id, gate_policy_version,
                 gate_version_hash, perplexity_micros, tail_fraction_micros,
                 perplexity_passed, novelty_score_micros, nearest_neighbor_hash,
                 novelty_passed, embedding_evidence_hash, attestation_chain_hash,
                 decided_at, vector_entry_id, credit_withheld_reason,
                 peak_perplexity_micros, peak_novelty_micros, chunk_count, chunks_capped,
                 total_chunk_count, qualifying_token_fraction_micros,
                 composite_score_micros,
                 vector_index_snapshot_id, index_cardinality_at_scoring
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)",
            &[
                &tenant_id,
                &decision.decision_id,
                &decision.submission_id,
                &decision.gate_policy_version,
                &decision.gate_version_hash,
                &decision.perplexity_micros,
                &decision.tail_fraction_micros,
                &decision.perplexity_passed,
                &decision.novelty_score_micros,
                &decision.nearest_neighbor_hash,
                &decision.novelty_passed,
                &decision.embedding_evidence_hash,
                &decision.attestation_chain_hash,
                &decision.decided_at,
                &decision.vector_entry_id,
                &decision.credit_withheld_reason,
                &decision.peak_perplexity_micros,
                &decision.peak_novelty_micros,
                &decision.chunk_count,
                &decision.chunks_capped,
                &decision.total_chunk_count,
                &decision.qualifying_token_fraction_micros,
                &decision.composite_score_micros,
                &decision.vector_index_snapshot_id,
                &decision.index_cardinality_at_scoring,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        for entry in &chunk_entries {
            tx.execute(
                "INSERT INTO trace_gate_chunk_vector_entries (
                     tenant_id, decision_id, submission_id, chunk_index, vector_entry_id
                 ) VALUES ($1,$2,$3,$4,$5)",
                &[
                    &tenant_id,
                    &entry.decision_id,
                    &entry.submission_id,
                    &entry.chunk_index,
                    &entry.vector_entry_id,
                ],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        }
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn list_trace_gate_chunk_vector_entries(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<Vec<TraceGateChunkVectorEntryRow>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT decision_id, submission_id, chunk_index, vector_entry_id
                 FROM trace_gate_chunk_vector_entries
                 WHERE tenant_id = $1 AND submission_id = $2
                 ORDER BY decision_id, chunk_index",
                &[&tenant_id, &submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| TraceGateChunkVectorEntryRow {
                decision_id: row.get("decision_id"),
                submission_id: row.get("submission_id"),
                chunk_index: row.get("chunk_index"),
                vector_entry_id: row.get("vector_entry_id"),
            })
            .collect())
    }

    async fn update_trace_gate_decision_credit_withheld_reason(
        &self,
        tenant_id: &str,
        decision_id: Uuid,
        credit_withheld_reason: Option<String>,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "UPDATE trace_gate_decisions SET credit_withheld_reason = $3
             WHERE tenant_id = $1 AND decision_id = $2",
            &[&tenant_id, &decision_id, &credit_withheld_reason],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn update_trace_gate_decision_perplexity(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        perplexity_micros: i64,
        peak_perplexity_micros: Option<i64>,
        perplexity_passed: bool,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Update ONLY the three perplexity columns, and ONLY on the latest
        // decision row for this submission. A single submission can own
        // multiple `trace_gate_decisions` rows (the `Cached` gate outcome
        // inserts a fresh row on every cache hit), so this mirrors the
        // `ORDER BY decided_at DESC LIMIT 1` selection used by
        // `find_gate_decision_by_canonical_hash` — otherwise this UPDATE
        // would blast the new perplexity value across every historical row
        // for the submission, corrupting rows stamped with an older
        // `gate_policy_version` / `gate_version_hash`. Novelty, tail-fraction,
        // vector-entry, gate status, credit, and all other columns are left
        // exactly as-is — the re-score maintenance path must never touch them.
        tx.execute(
            "UPDATE trace_gate_decisions
                SET perplexity_micros = $3,
                    peak_perplexity_micros = $4,
                    perplexity_passed = $5
             WHERE tenant_id = $1 AND decision_id = (
                 SELECT decision_id FROM trace_gate_decisions
                  WHERE tenant_id = $1 AND submission_id = $2
                  ORDER BY decided_at DESC LIMIT 1)",
            &[
                &tenant_id,
                &submission_id,
                &perplexity_micros,
                &peak_perplexity_micros,
                &perplexity_passed,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn update_trace_gate_decision_credit_quality(
        &self,
        tenant_id: &str,
        decision_id: Uuid,
        q_micros: i64,
        anomaly_ratio_micros: i64,
        calibration_version: i32,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Update ONLY the three credit_quality columns on exactly this decision
        // row. Perplexity, novelty, tail-fraction, vector-entry, gate status, and
        // credit are left exactly as-is.
        tx.execute(
            "UPDATE trace_gate_decisions
                SET credit_quality_micros = $3,
                    credit_quality_anomaly_ratio_micros = $4,
                    credit_quality_calibration_version = $5
             WHERE tenant_id = $1 AND decision_id = $2",
            &[
                &tenant_id,
                &decision_id,
                &q_micros,
                &anomaly_ratio_micros,
                &calibration_version,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn update_trace_gate_decision_dedup(
        &self,
        tenant_id: &str,
        decision_id: Uuid,
        write: crate::trace_corpus_storage::DedupAssignmentWrite,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Update ONLY the four dedup columns on exactly this decision row.
        // Perplexity, novelty, tail-fraction, vector-entry, gate status, and
        // credit are left exactly as-is.
        //
        // The version stamp is set in the SAME statement as the simhash it
        // describes (migration V57): a row that carries one without the other,
        // even briefly, reads as the legacy version to the recluster sweep.
        tx.execute(
            "UPDATE trace_gate_decisions
                SET dedup_simhash = $3,
                    dedup_cluster_id = $4,
                    dedup_cluster_size = $5,
                    dedup_signal_version = $6
             WHERE tenant_id = $1 AND decision_id = $2",
            &[
                &tenant_id,
                &decision_id,
                &write.dedup_simhash,
                &write.dedup_cluster_id,
                &write.dedup_cluster_size,
                &write.dedup_signal_version,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn update_trace_gate_decision_dedup_cluster(
        &self,
        tenant_id: &str,
        decision_id: Uuid,
        dedup_cluster_id: Uuid,
        dedup_cluster_size: i32,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Update ONLY the two cluster columns. `dedup_simhash` and
        // `dedup_signal_version` are deliberately absent from the SET list:
        // the recluster sweep re-clusters values it read and derived neither
        // of them, so re-writing the stamp would turn a NULL -- "recorded
        // before the stamp existed" -- into a positive claim the pass has no
        // evidence for.
        tx.execute(
            "UPDATE trace_gate_decisions
                SET dedup_cluster_id = $3,
                    dedup_cluster_size = $4
             WHERE tenant_id = $1 AND decision_id = $2",
            &[
                &tenant_id,
                &decision_id,
                &dedup_cluster_id,
                &dedup_cluster_size,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn update_trace_gate_decision_correction_value(
        &self,
        tenant_id: &str,
        decision_id: Uuid,
        write: crate::trace_corpus_storage::CorrectionValueWrite,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Update ONLY the six correction-value columns on exactly this decision
        // row. Perplexity, novelty, dedup, contributor-cap, gate status, and
        // credit are left exactly as-is: the shadow correction value must not
        // be able to move what a contributor is credited.
        // `update_correction_value_sql_touches_only_correction_columns` pins
        // that.
        tx.execute(
            UPDATE_CORRECTION_VALUE_SQL,
            &[
                &tenant_id,
                &decision_id,
                &write.correction_simhash,
                &write.correction_cluster_id,
                &write.correction_cluster_size,
                &write.correction_novelty_micros,
                &write.correction_value_micros,
                &write.correction_value_version,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn update_trace_gate_decision_contributor_cap(
        &self,
        tenant_id: &str,
        decision_id: Uuid,
        factor_micros: i32,
        cumulative_raw_micros: i64,
        epoch: i64,
        version: i32,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // Update ONLY the four contributor-cap columns on exactly this decision
        // row. Perplexity, novelty, dedup, gate status, and credit are untouched.
        tx.execute(
            "UPDATE trace_gate_decisions
                SET contributor_factor_micros = $3,
                    contributor_cumulative_raw_micros = $4,
                    contributor_cap_epoch = $5,
                    contributor_cap_version = $6
             WHERE tenant_id = $1 AND decision_id = $2",
            &[
                &tenant_id,
                &decision_id,
                &factor_micros,
                &cumulative_raw_micros,
                &epoch,
                &version,
            ],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn bump_gate_evaluation_attempt(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        now: DateTime<Utc>,
        error_label: &str,
    ) -> Result<i32, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_one(
                "INSERT INTO trace_gate_evaluation_attempts
                     (tenant_id, submission_id, attempts, last_attempt_at, last_error_label)
                 VALUES ($1, $2, 1, $3, $4)
                 ON CONFLICT (tenant_id, submission_id) DO UPDATE
                     SET attempts = trace_gate_evaluation_attempts.attempts + 1,
                         last_attempt_at = $3,
                         last_error_label = $4
                 RETURNING attempts",
                &[&tenant_id, &submission_id, &now, &error_label],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.get(0))
    }

    async fn bump_pii_backstop_attempt(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        now: DateTime<Utc>,
        error_label: &str,
    ) -> Result<i32, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let row = tx
            .query_one(
                "INSERT INTO trace_pii_backstop
                     (tenant_id, submission_id, attempts, last_attempt_at, last_error_label)
                 VALUES ($1, $2, 1, $3, $4)
                 ON CONFLICT (tenant_id, submission_id) DO UPDATE
                     SET attempts = trace_pii_backstop.attempts + 1,
                         last_attempt_at = $3,
                         last_error_label = $4
                 RETURNING attempts",
                &[&tenant_id, &submission_id, &now, &error_label],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(row.get(0))
    }

    async fn list_quarantined_pii_backstop_exhausted(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT DISTINCT s.submission_id, s.received_at
                 FROM trace_submissions s
                 JOIN trace_audit_events a
                   ON a.tenant_id = s.tenant_id
                  AND a.submission_id = s.submission_id
                  AND a.action = 'review'
                  AND a.metadata_json->>'reason_code' = 'pii_backstop_attempts_exhausted'
                 JOIN trace_object_refs o
                   ON o.tenant_id = s.tenant_id
                  AND o.submission_id = s.submission_id
                  AND o.artifact_kind = 'submitted_envelope'
                  AND o.invalidated_at IS NULL
                  AND o.deleted_at IS NULL
                 WHERE s.tenant_id = $1
                   AND s.status = 'quarantined'
                 ORDER BY s.received_at DESC
                 LIMIT $2",
                &[&tenant_id, &limit],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    async fn clear_pii_backstop_attempts(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        tx.execute(
            "DELETE FROM trace_pii_backstop WHERE tenant_id = $1 AND submission_id = $2",
            &[&tenant_id, &submission_id],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn touch_pii_backstop_attempt(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        now: DateTime<Utc>,
        error_label: &str,
    ) -> Result<(), DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        // attempts is seeded at 0 and left alone on conflict: this records
        // that an attempt was MADE without charging it against the trace's
        // budget, so the driver's least-recently-attempted ordering advances
        // while `COALESCE(a.attempts, 0) < max_attempts` stays satisfied.
        tx.execute(
            "INSERT INTO trace_pii_backstop
                 (tenant_id, submission_id, attempts, last_attempt_at, last_error_label)
             VALUES ($1, $2, 0, $3, $4)
             ON CONFLICT (tenant_id, submission_id) DO UPDATE
                 SET last_attempt_at = $3,
                     last_error_label = $4",
            &[&tenant_id, &submission_id, &now, &error_label],
        )
        .await
        .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(())
    }

    async fn find_gate_decision_by_canonical_hash(
        &self,
        tenant_id: &str,
        canonical_summary_hash: &str,
        exclude_submission_id: Uuid,
    ) -> Result<Option<TraceGateDecisionRow>, DatabaseError> {
        let mut client = self.trace_pool().get().await?;
        let tx = Self::begin_trace_tenant_transaction(&mut client, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT d.decision_id, d.submission_id, d.gate_policy_version, d.gate_version_hash,
                        d.perplexity_micros, d.tail_fraction_micros, d.perplexity_passed,
                        d.novelty_score_micros, d.nearest_neighbor_hash, d.novelty_passed,
                        d.embedding_evidence_hash, d.attestation_chain_hash, d.decided_at,
                        d.vector_entry_id, d.credit_withheld_reason,
                        d.peak_perplexity_micros, d.peak_novelty_micros, d.chunk_count, d.chunks_capped,
                        d.total_chunk_count, d.composite_score_micros,
                        d.vector_index_snapshot_id, d.index_cardinality_at_scoring,
                        d.qualifying_token_fraction_micros
                 FROM trace_gate_decisions d
                 JOIN trace_submissions s
                   ON s.tenant_id = d.tenant_id AND s.submission_id = d.submission_id
                 WHERE d.tenant_id = $1
                   AND s.canonical_summary_hash = $2
                   AND d.submission_id <> $3
                 ORDER BY d.decided_at DESC
                 LIMIT 1",
                &[&tenant_id, &canonical_summary_hash, &exclude_submission_id],
            )
            .await
            .map_err(DatabaseError::Postgres)?;
        tx.commit().await.map_err(DatabaseError::Postgres)?;
        Ok(rows.into_iter().next().map(|row| TraceGateDecisionRow {
            decision_id: row.get(0),
            submission_id: row.get(1),
            gate_policy_version: row.get(2),
            gate_version_hash: row.get(3),
            perplexity_micros: row.get(4),
            tail_fraction_micros: row.get(5),
            perplexity_passed: row.get(6),
            novelty_score_micros: row.get(7),
            nearest_neighbor_hash: row.get(8),
            novelty_passed: row.get(9),
            embedding_evidence_hash: row.get(10),
            attestation_chain_hash: row.get(11),
            decided_at: row.get(12),
            vector_entry_id: row.get(13),
            credit_withheld_reason: row.get(14),
            peak_perplexity_micros: row.get(15),
            peak_novelty_micros: row.get(16),
            chunk_count: row.get(17),
            chunks_capped: row.get(18),
            total_chunk_count: row.get(19),
            composite_score_micros: row.get(20),
            vector_index_snapshot_id: row.get(21),
            index_cardinality_at_scoring: row.get(22),
            // Appended last in the SELECT rather than kept in column order:
            // every read here is positional, so inserting mid-list would
            // silently re-point the indices above it.
            qualifying_token_fraction_micros: row.get(23),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shadow-mode guarantee, at the only place it can actually be
    /// violated: the write. A correction's value must not be able to move
    /// what a contributor is credited, so the statement that stores it may
    /// set correction_* columns and nothing else — not credit_quality, not
    /// dedup, not the contributor cap, not the gate status.
    #[test]
    fn update_correction_value_sql_touches_only_correction_columns() {
        let sql = UPDATE_CORRECTION_VALUE_SQL;
        let set_clause = sql
            .split_once("SET ")
            .expect("statement has a SET clause")
            .1
            .split_once("WHERE")
            .expect("statement has a WHERE clause")
            .0;
        for assignment in set_clause.split(',') {
            let column = assignment
                .split('=')
                .next()
                .expect("assignment has a left-hand side")
                .trim();
            assert!(
                column.starts_with("correction_"),
                "the correction-value write set a non-correction column: {column}"
            );
        }
        // And it is scoped to exactly one decision row of one tenant (forced
        // RLS still applies, but an unscoped UPDATE would be a bug regardless).
        assert!(sql.contains("WHERE tenant_id = $1 AND decision_id = $2"));

        // Named so a reader can see what is deliberately absent.
        for credited in [
            "credit_quality_micros",
            "dedup_cluster_size",
            "contributor_factor_micros",
            "credit_withheld_reason",
            "perplexity_passed",
            "novelty_passed",
        ] {
            assert!(
                !sql.contains(credited),
                "the correction-value write must not touch {credited}"
            );
        }
    }
}
