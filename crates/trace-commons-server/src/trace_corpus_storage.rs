// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backend-agnostic storage contracts for Trace Commons corpus metadata.
//!
//! These types describe the DB-backed production storage surface without
//! changing the current file-backed ingest path.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use trace_commons_protocol::trace_contribution::ResidualRiskCondition;
use uuid::Uuid;

use crate::error::DatabaseError;

fn default_trace_ranking_min_label_source_count() -> u32 {
    1
}

fn default_trace_ranking_joined_evidence_hash() -> String {
    "sha256:legacy".to_string()
}

fn default_trace_ranking_worker_run_status() -> TraceRankingWorkerRunStatus {
    TraceRankingWorkerRunStatus::Completed
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceCorpusStatus {
    Received,
    Accepted,
    Quarantined,
    /// Held state pending the NEAR AI PII backstop verdict. Never
    /// consumer/export/credit eligible and never reviewer-eligible; distinct
    /// from `Quarantined`. Wire form: `awaiting_pii_backstop`.
    AwaitingPiiBackstop,
    Rejected,
    Revoked,
    Expired,
    Purged,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceObjectArtifactKind {
    SubmittedEnvelope,
    RescrubbedEnvelope,
    ReviewSnapshot,
    BenchmarkArtifact,
    ExportArtifact,
    WorkerIntermediate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceDerivedStatus {
    Current,
    Invalidated,
    Superseded,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceVectorEntryStatus {
    Active,
    Invalidated,
    Deleted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceVectorEntrySourceProjection {
    CanonicalSummary,
    RedactedMessages,
    RedactedToolSequence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceWorkerKind {
    ServerRescrub,
    Summary,
    DuplicatePrecheck,
    Embedding,
    Ranking,
    BenchmarkConversion,
    ProcessEvaluation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceAuditAction {
    Submit,
    Read,
    Review,
    CreditMutate,
    Revoke,
    Export,
    Retain,
    Purge,
    VectorIndex,
    BenchmarkConvert,
    ProcessEvaluate,
    PolicyUpdate,
    ExportJobRecovery,
    RankingWorkerRunRecovery,
    RankingCalibrationDatasetQuarantine,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceReviewLeaseAuditAction {
    Claim,
    Release,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceCreditEventType {
    Accepted,
    PrivacyRejection,
    DuplicateRejection,
    BenchmarkConversion,
    RegressionCatch,
    TrainingUtility,
    RankingUtility,
    ReviewerBonus,
    AbusePenalty,
    NoveltyUtility,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceCreditSettlementState {
    Pending,
    Final,
    Reversed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceCreditSettlementBatchStatus {
    DryRun,
    Finalized,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceCreditSettlementNearStatus {
    Disabled,
    Pending,
    Submitted,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceBenchmarkRegistryOutboxOperation {
    Publish,
    Revoke,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceBenchmarkRegistryOutboxStatus {
    Pending,
    Submitted,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceCreditHoldReason {
    DuplicateClusterUnderReview,
    PrivacyRiskUnderReview,
    SuspectedAbuse,
    RevocationPropagation,
    AttestationDispute,
    PolicyMigration,
    LegalCompliance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceCreditHoldAuditAction {
    Placed,
    Released,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRankingModelStatus {
    Candidate,
    Active,
    Deprecated,
    Archived,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TraceRankingLabelSource {
    FrontierLab,
    Reviewer,
    Benchmark,
    System,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRankingUtilityCategory {
    ModelTraining,
    RankingTraining,
    Evaluation,
    Regression,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRankingLabelOutcome {
    Useful,
    Neutral,
    Rejected,
    RegressionCaught,
    Disputed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRankingCalibrationDatasetStatus {
    Candidate,
    Active,
    Deprecated,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingModelVersionWrite {
    pub tenant_id: String,
    pub model_version: String,
    pub feature_schema_version: String,
    pub policy_version: String,
    pub status: TraceRankingModelStatus,
    pub training_dataset_hash: String,
    pub calibration_dataset_hash: String,
    pub model_artifact_hash: String,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingModelVersionRecord {
    pub tenant_id: String,
    pub model_version: String,
    pub feature_schema_version: String,
    pub policy_version: String,
    pub status: TraceRankingModelStatus,
    pub training_dataset_hash: String,
    pub calibration_dataset_hash: String,
    pub model_artifact_hash: String,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingCalibrationDatasetWrite {
    pub tenant_id: String,
    pub calibration_dataset_hash: String,
    pub target_use: String,
    pub policy_version: String,
    pub source_manifest_hash: String,
    pub source_count: u32,
    pub label_source_count: u32,
    pub label_actor_count: u32,
    pub status: TraceRankingCalibrationDatasetStatus,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingCalibrationDatasetStatusUpdate {
    pub tenant_id: String,
    pub calibration_dataset_hash: String,
    pub target_use: String,
    pub policy_version: String,
    pub status: TraceRankingCalibrationDatasetStatus,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingCalibrationDatasetRecord {
    pub tenant_id: String,
    pub calibration_dataset_hash: String,
    pub target_use: String,
    pub policy_version: String,
    pub source_manifest_hash: String,
    pub source_count: u32,
    pub label_source_count: u32,
    pub label_actor_count: u32,
    pub status: TraceRankingCalibrationDatasetStatus,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceRankingFeatureWrite {
    pub tenant_id: String,
    pub ranking_feature_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub target_use: String,
    pub feature_schema_version: String,
    pub feature_vector_hash: String,
    pub feature_names_hash: String,
    pub source_feature_hash: String,
    pub duplicate_score: Option<f32>,
    pub novelty_score: Option<f32>,
    pub privacy_risk_score: Option<f32>,
    pub quality_score: Option<f32>,
    pub coverage_tags: Vec<String>,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceRankingFeatureRecord {
    pub tenant_id: String,
    pub ranking_feature_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub target_use: String,
    pub feature_schema_version: String,
    pub feature_vector_hash: String,
    pub feature_names_hash: String,
    pub source_feature_hash: String,
    pub duplicate_score: Option<f32>,
    pub novelty_score: Option<f32>,
    pub privacy_risk_score: Option<f32>,
    pub quality_score: Option<f32>,
    pub coverage_tags: Vec<String>,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceRankingPredictionWrite {
    pub tenant_id: String,
    pub ranking_prediction_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub target_use: String,
    pub model_version: String,
    pub feature_schema_version: String,
    pub prediction_policy_version: String,
    pub feature_vector_hash: String,
    pub predicted_utility_micros: i64,
    pub uncertainty_micros: i64,
    pub confidence: f32,
    pub risk_penalty_micros: i64,
    pub novelty_bonus_micros: i64,
    pub settlement_score_micros: i64,
    pub explanation_codes: Vec<String>,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceRankingPredictionRecord {
    pub tenant_id: String,
    pub ranking_prediction_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub target_use: String,
    pub model_version: String,
    pub feature_schema_version: String,
    pub prediction_policy_version: String,
    pub feature_vector_hash: String,
    pub predicted_utility_micros: i64,
    pub uncertainty_micros: i64,
    pub confidence: f32,
    pub risk_penalty_micros: i64,
    pub novelty_bonus_micros: i64,
    pub settlement_score_micros: i64,
    pub explanation_codes: Vec<String>,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingLabelWrite {
    pub tenant_id: String,
    pub ranking_label_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub target_use: String,
    pub label_source: TraceRankingLabelSource,
    pub utility_category: TraceRankingUtilityCategory,
    pub label_outcome: TraceRankingLabelOutcome,
    pub utility_delta_micros: i64,
    pub evidence_hash: String,
    pub external_ref_hash: String,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingLabelRecord {
    pub tenant_id: String,
    pub ranking_label_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub target_use: String,
    pub label_source: TraceRankingLabelSource,
    pub utility_category: TraceRankingUtilityCategory,
    pub label_outcome: TraceRankingLabelOutcome,
    pub utility_delta_micros: i64,
    pub evidence_hash: String,
    pub external_ref_hash: String,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingPreferenceLabelWrite {
    pub tenant_id: String,
    pub preference_label_id: Uuid,
    pub preferred_submission_id: Uuid,
    pub preferred_trace_id: Uuid,
    pub rejected_submission_id: Uuid,
    pub rejected_trace_id: Uuid,
    pub target_use: String,
    pub label_source: TraceRankingLabelSource,
    pub utility_category: TraceRankingUtilityCategory,
    pub preference_strength_micros: i64,
    pub evidence_hash: String,
    pub external_ref_hash: String,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingPreferenceLabelRecord {
    pub tenant_id: String,
    pub preference_label_id: Uuid,
    pub preferred_submission_id: Uuid,
    pub preferred_trace_id: Uuid,
    pub rejected_submission_id: Uuid,
    pub rejected_trace_id: Uuid,
    pub target_use: String,
    pub label_source: TraceRankingLabelSource,
    pub utility_category: TraceRankingUtilityCategory,
    pub preference_strength_micros: i64,
    pub evidence_hash: String,
    pub external_ref_hash: String,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceRankingCalibrationRunWrite {
    pub tenant_id: String,
    pub calibration_run_id: Uuid,
    pub model_version: String,
    pub target_use: String,
    pub policy_version: String,
    pub evaluation_dataset_hash: String,
    pub prediction_count: u32,
    pub label_count: u32,
    pub joined_label_prediction_count: u32,
    pub joined_label_source_count: u32,
    pub joined_label_actor_count: u32,
    pub joined_evidence_hash: String,
    pub average_predicted_utility_micros: Option<i64>,
    pub average_label_utility_delta_micros: Option<i64>,
    pub average_absolute_error_micros: Option<i64>,
    pub max_label_source_average_absolute_error_micros: Option<i64>,
    pub max_error_label_source: Option<String>,
    pub mean_signed_error_micros: Option<i64>,
    pub low_confidence_prediction_count: u32,
    pub confidence_threshold: f32,
    pub min_label_count: u32,
    pub min_label_source_count: u32,
    pub max_average_absolute_error_micros: i64,
    pub promotable: bool,
    pub reason_codes: Vec<String>,
    pub report_hash: String,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceRankingCalibrationRunRecord {
    pub tenant_id: String,
    pub calibration_run_id: Uuid,
    pub model_version: String,
    pub target_use: String,
    pub policy_version: String,
    pub evaluation_dataset_hash: String,
    pub prediction_count: u32,
    pub label_count: u32,
    pub joined_label_prediction_count: u32,
    #[serde(default)]
    pub joined_label_source_count: u32,
    #[serde(default)]
    pub joined_label_actor_count: u32,
    #[serde(default = "default_trace_ranking_joined_evidence_hash")]
    pub joined_evidence_hash: String,
    pub average_predicted_utility_micros: Option<i64>,
    pub average_label_utility_delta_micros: Option<i64>,
    pub average_absolute_error_micros: Option<i64>,
    #[serde(default)]
    pub max_label_source_average_absolute_error_micros: Option<i64>,
    #[serde(default)]
    pub max_error_label_source: Option<String>,
    pub mean_signed_error_micros: Option<i64>,
    pub low_confidence_prediction_count: u32,
    pub confidence_threshold: f32,
    pub min_label_count: u32,
    #[serde(default = "default_trace_ranking_min_label_source_count")]
    pub min_label_source_count: u32,
    pub max_average_absolute_error_micros: i64,
    pub promotable: bool,
    pub reason_codes: Vec<String>,
    pub report_hash: String,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRankingWorkerRunKind {
    Calibration,
    PredictionCredit,
    ModelPromotion,
    CreditCycle,
    ProcessEvaluation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRankingWorkerRunStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingWorkerRunWrite {
    pub tenant_id: String,
    pub ranking_worker_run_id: Uuid,
    pub run_kind: TraceRankingWorkerRunKind,
    pub status: TraceRankingWorkerRunStatus,
    pub dry_run: bool,
    pub reason_hash: String,
    pub model_version: Option<String>,
    pub target_use: Option<String>,
    pub policy_version: Option<String>,
    pub limit: u32,
    pub checked_count: u32,
    pub succeeded_count: u32,
    pub skipped_existing_count: u32,
    pub skipped_model_risk_count: u32,
    pub skipped_ineligible_count: u32,
    pub pending_after_count: u32,
    pub result_refs: Vec<String>,
    pub reason_counts: BTreeMap<String, u32>,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub last_error_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRankingWorkerRunRecord {
    pub tenant_id: String,
    pub ranking_worker_run_id: Uuid,
    pub run_kind: TraceRankingWorkerRunKind,
    #[serde(default = "default_trace_ranking_worker_run_status")]
    pub status: TraceRankingWorkerRunStatus,
    pub dry_run: bool,
    pub reason_hash: String,
    pub model_version: Option<String>,
    pub target_use: Option<String>,
    pub policy_version: Option<String>,
    pub limit: u32,
    pub checked_count: u32,
    pub succeeded_count: u32,
    pub skipped_existing_count: u32,
    pub skipped_model_risk_count: u32,
    pub skipped_ineligible_count: u32,
    pub pending_after_count: u32,
    pub result_refs: Vec<String>,
    pub reason_counts: BTreeMap<String, u32>,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_error_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceCreditAccountSettlementLineItem {
    pub credit_account_ref: String,
    pub credit_account_hash: String,
    pub settled_credit_delta_micros: i64,
    pub source_credit_event_ids: Vec<Uuid>,
    pub source_submission_ids: Vec<Uuid>,
    pub source_list_hash: String,
    pub near_status: TraceCreditSettlementNearStatus,
    pub near_outbox_id: Option<Uuid>,
    /// Coarse label set when this account group's on-chain payout was withheld
    /// (`"none_enrolled"` / `"ambiguous_no_designation"`). When present, NO NEAR
    /// outbox row was enqueued for the group even though the credit is finalized
    /// internally. `None` for groups that resolved a payout target and for
    /// unlinked-principal groups. A label only; carries no account identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near_payout_hold_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceUtilityAttestationWrite {
    pub tenant_id: String,
    pub attestation_id: Uuid,
    pub event_type: TraceCreditEventType,
    pub use_category: String,
    pub policy_version: String,
    pub evidence_hash: String,
    pub external_ref_hash: String,
    pub source_submission_ids: Vec<Uuid>,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceUtilityAttestationRecord {
    pub tenant_id: String,
    pub attestation_id: Uuid,
    pub event_type: TraceCreditEventType,
    pub use_category: String,
    pub policy_version: String,
    pub evidence_hash: String,
    pub external_ref_hash: String,
    pub source_submission_ids: Vec<Uuid>,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceCreditSettlementBatchWrite {
    pub tenant_id: String,
    pub settlement_batch_id: Uuid,
    pub policy_version: String,
    pub status: TraceCreditSettlementBatchStatus,
    pub reason_hash: String,
    pub issuer_approval_evidence_hash: Option<String>,
    pub source_credit_event_ids: Vec<Uuid>,
    pub source_submission_ids: Vec<Uuid>,
    pub source_list_hash: String,
    pub settled_credit_points: String,
    pub settled_credit_micros: i64,
    pub line_items: Vec<TraceCreditAccountSettlementLineItem>,
    pub near_contract_id: Option<String>,
    pub ranking_model_version: Option<String>,
    pub ranking_target_use: Option<String>,
    pub ranking_calibration_run_id: Option<Uuid>,
    pub ranking_calibration_report_hash: Option<String>,
    pub ranking_calibration_joined_evidence_hash: Option<String>,
    pub ranking_credit_events_excluded_count: u32,
    pub ranking_credit_events_excluded_reason_counts: BTreeMap<String, u32>,
    pub actor_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceCreditSettlementBatchRecord {
    pub tenant_id: String,
    pub settlement_batch_id: Uuid,
    pub policy_version: String,
    pub status: TraceCreditSettlementBatchStatus,
    pub reason_hash: String,
    pub issuer_approval_evidence_hash: Option<String>,
    pub source_credit_event_ids: Vec<Uuid>,
    pub source_submission_ids: Vec<Uuid>,
    pub source_list_hash: String,
    pub settled_credit_points: String,
    pub settled_credit_micros: i64,
    pub line_items: Vec<TraceCreditAccountSettlementLineItem>,
    pub near_contract_id: Option<String>,
    pub ranking_model_version: Option<String>,
    pub ranking_target_use: Option<String>,
    pub ranking_calibration_run_id: Option<Uuid>,
    pub ranking_calibration_report_hash: Option<String>,
    pub ranking_calibration_joined_evidence_hash: Option<String>,
    pub ranking_credit_events_excluded_count: u32,
    pub ranking_credit_events_excluded_reason_counts: BTreeMap<String, u32>,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceCreditHoldWrite {
    pub tenant_id: String,
    pub hold_id: Uuid,
    pub credit_account_ref: String,
    pub credit_account_hash: String,
    pub reason: TraceCreditHoldReason,
    pub reason_hash: String,
    pub actor_principal_ref: String,
    pub released_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceCreditHoldRecord {
    pub tenant_id: String,
    pub hold_id: Uuid,
    pub credit_account_ref: String,
    pub credit_account_hash: String,
    pub reason: TraceCreditHoldReason,
    pub reason_hash: String,
    pub actor_principal_ref: String,
    pub created_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceNearCreditOutboxItemWrite {
    pub tenant_id: String,
    pub near_outbox_id: Uuid,
    pub settlement_batch_id: Uuid,
    pub credit_account_hash: String,
    pub near_call_json: serde_json::Value,
    pub status: TraceCreditSettlementNearStatus,
    /// Designated NEAR account id to pay for this settlement group, when the
    /// group resolved to a single durable account with an unambiguous payout
    /// target. A public on-chain identifier (operational routing state), never
    /// key material. `None` for unlinked-principal groups and the account-hold /
    /// reversal flows that do not resolve a payout target.
    #[serde(default)]
    pub payout_near_account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceNearCreditOutboxItemRecord {
    pub tenant_id: String,
    pub near_outbox_id: Uuid,
    pub settlement_batch_id: Uuid,
    pub credit_account_hash: String,
    pub near_call_json: serde_json::Value,
    pub status: TraceCreditSettlementNearStatus,
    /// See [`TraceNearCreditOutboxItemWrite::payout_near_account_id`]. A public
    /// on-chain identifier persisted as operational routing state.
    #[serde(default)]
    pub payout_near_account_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub near_transaction_hash: Option<String>,
    pub last_error_hash: Option<String>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceBenchmarkRegistryOutboxItemWrite {
    pub tenant_id: String,
    pub benchmark_outbox_id: Uuid,
    pub conversion_id: Uuid,
    pub operation: TraceBenchmarkRegistryOutboxOperation,
    pub registry_ref: String,
    pub artifact_payload_hash: String,
    pub source_submission_ids_hash: String,
    pub evaluator_ref: Option<String>,
    pub evaluation_score: Option<f32>,
    pub status: TraceBenchmarkRegistryOutboxStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceBenchmarkRegistryOutboxItemRecord {
    pub tenant_id: String,
    pub benchmark_outbox_id: Uuid,
    pub conversion_id: Uuid,
    pub operation: TraceBenchmarkRegistryOutboxOperation,
    pub registry_ref: String,
    pub artifact_payload_hash: String,
    pub source_submission_ids_hash: String,
    pub evaluator_ref: Option<String>,
    pub evaluation_score: Option<f32>,
    pub status: TraceBenchmarkRegistryOutboxStatus,
    pub created_at: DateTime<Utc>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub external_receipt_ref: Option<String>,
    pub last_error_hash: Option<String>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceSubmissionWrite {
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub auth_principal_ref: String,
    pub contributor_pseudonym: Option<String>,
    pub submitted_tenant_scope_ref: Option<String>,
    pub schema_version: String,
    pub consent_policy_version: String,
    pub consent_scopes: Vec<String>,
    pub allowed_uses: Vec<String>,
    pub retention_policy_id: String,
    pub status: TraceCorpusStatus,
    pub privacy_risk: String,
    pub redaction_pipeline_version: String,
    pub redaction_counts: BTreeMap<String, u32>,
    pub redaction_hash: String,
    pub canonical_summary_hash: Option<String>,
    pub submission_score: Option<f32>,
    pub credit_points_pending: Option<f32>,
    pub credit_points_final: Option<f32>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Which conditions held when `privacy_risk` was decided, as allowlisted
    /// labels. `None` leaves the column untouched -- the two fields are
    /// written together or not at all, because a stale basis beside a fresh
    /// risk is worse than an absent one.
    pub residual_risk_basis: Option<Vec<String>>,
}

/// Opaque keyset cursor for the account trace read-back list. It carries the
/// `(received_at, submission_id)` of the last row on the previous page; the
/// next page continues strictly after it in `(received_at DESC, submission_id
/// DESC)` order. The wire encoding (base64) lives in the binary; this is the
/// decoded form the store consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceSubmissionKeysetCursor {
    pub received_at: DateTime<Utc>,
    pub submission_id: Uuid,
}

/// Fallback label for a status reason that is not on the allowlist below.
pub const STATUS_REASON_OTHER: &str = "other";

/// Reason labels that may be stored verbatim in
/// `trace_submissions.last_status_reason`.
///
/// Every entry is a fixed compile-time constant produced by the server
/// itself, never anything a caller supplies.
const ALLOWLISTED_STATUS_REASONS: &[&str] = &[
    // The driver gave up on a trace after exhausting its retry budget. The
    // whole reason this column exists: it means NOTHING was learned about the
    // trace, as opposed to a filter having found something.
    "pii_backstop_attempts_exhausted",
    // An operator returned an exhausted trace to the backlog for reassessment.
    "pii_backstop_requeued",
    // The backstop completed and released the hold on a real determination.
    "near-ai-pii-backstop-v1",
    // A human review decision.
    "review_decision",
    // Retention lifecycle.
    "retention_purged",
    "retention_expired",
    // A verified redaction-witness certificate kept this submission out of
    // the PII-backstop hold. It records WHICH pass admitted the trace, which
    // is a different basis from the server's own queued re-check and is what
    // the contributor's receipt reports. It is NOT a claim that the trace is
    // clean, and nothing may read it as one.
    WITNESS_ADMITTED_STATUS_REASON,
];

/// Status reason recorded when an attested redaction witness admitted a
/// submission in place of the server's queued PII-backstop re-check.
///
/// A separate label rather than an entry in `residual_risk_basis`: that
/// column is the set of `ResidualRiskCondition`s that held when the risk was
/// decided, every reader parses it back through
/// `ResidualRiskCondition::from_label`, and an empty basis there means Low and
/// only Low. A witness admission is neither a risk condition nor a change to
/// the risk, so putting it in that column would make the basis contradict the
/// risk stored beside it -- and a basis that contradicts its own row is worse
/// than an absent one, because it will be believed.
pub const WITNESS_ADMITTED_STATUS_REASON: &str = "witness_admitted";

/// Reduce a status-transition reason to a label safe to store in a
/// plainly-readable column.
///
/// Fail-closed: anything not on `ALLOWLISTED_STATUS_REASONS` becomes
/// [`STATUS_REASON_OTHER`]. This is not defensive tidiness -- trace revocation
/// takes a free-text reason straight from the API caller
/// (`trace_revocation_reason_for_request`), and the audit trail stores only
/// `sha256(reason)` for exactly that input. Storing it verbatim here would put
/// arbitrary caller text, potentially PII or operator-secret material, into a
/// column that the review surface reads back. An allowlist is the only form of
/// this that cannot be defeated by a new call site forgetting the rule.
pub fn safe_status_reason_label(reason: &str) -> &'static str {
    ALLOWLISTED_STATUS_REASONS
        .iter()
        .find(|allowed| **allowed == reason)
        .copied()
        .unwrap_or(STATUS_REASON_OTHER)
}

/// Reduce a residual-risk basis to the labels safe to store in
/// `trace_submissions.residual_risk_basis`.
///
/// The choke point for the label-only rule on that column, and the analogue
/// of [`safe_status_reason_label`]. It takes typed
/// [`ResidualRiskCondition`]s rather than strings on purpose: there is no
/// caller-supplied text to sanitise, because there is no way to express one.
/// Every stored value is a fixed `&'static str` produced by the server's own
/// redaction pass.
///
/// Duplicates collapse, order is preserved. A basis is a set of conditions;
/// a repeated label would distort any count derived from the column.
pub fn safe_residual_risk_basis_labels(basis: &[ResidualRiskCondition]) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for condition in basis {
        let label = condition.as_label();
        if !labels.iter().any(|seen| seen == label) {
            labels.push(label.to_string());
        }
    }
    labels
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceSubmissionRecord {
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub status: TraceCorpusStatus,
    pub auth_principal_ref: String,
    pub contributor_pseudonym: Option<String>,
    pub submitted_tenant_scope_ref: Option<String>,
    pub schema_version: String,
    pub consent_policy_version: String,
    pub consent_scopes: Vec<String>,
    pub allowed_uses: Vec<String>,
    pub retention_policy_id: String,
    pub privacy_risk: String,
    pub redaction_pipeline_version: String,
    pub redaction_counts: BTreeMap<String, u32>,
    pub redaction_hash: String,
    pub canonical_summary_hash: Option<String>,
    pub submission_score: Option<f32>,
    pub credit_points_pending: Option<f32>,
    pub credit_points_final: Option<f32>,
    pub received_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_assigned_to_principal_ref: Option<String>,
    pub review_assigned_at: Option<DateTime<Utc>>,
    pub review_lease_expires_at: Option<DateTime<Utc>>,
    pub review_due_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub purged_at: Option<DateTime<Utc>>,
    /// Allowlisted label for why the submission is in its current status, or
    /// `None` for rows written before V49. See [`safe_status_reason_label`].
    #[serde(default)]
    pub last_status_reason: Option<String>,
    /// Which conditions held when this submission's `privacy_risk` was
    /// decided, as allowlisted labels (#474). `None` means NOT RECORDED --
    /// every row written before V51, and never a claim that no condition
    /// held. `Some(vec![])` is the distinct "recorded, nothing held" case.
    /// See [`safe_residual_risk_basis_labels`].
    #[serde(default)]
    pub residual_risk_basis: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceTenantPolicyWrite {
    pub tenant_id: String,
    pub policy_version: String,
    pub allowed_consent_scopes: Vec<String>,
    pub allowed_uses: Vec<String>,
    pub updated_by_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceTenantPolicyRecord {
    pub tenant_id: String,
    pub policy_version: String,
    pub allowed_consent_scopes: Vec<String>,
    pub allowed_uses: Vec<String>,
    pub updated_by_principal_ref: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceTenantAccessGrantRole {
    Contributor,
    Reviewer,
    Admin,
    ExportWorker,
    RetentionWorker,
    VectorWorker,
    BenchmarkWorker,
    UtilityWorker,
    ProcessEvalWorker,
    RevocationWorker,
    CompetitionReadWorker,
    RegisterStatsWorker,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceTenantAccessGrantStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceTenantAccessGrantWrite {
    pub tenant_id: String,
    pub grant_id: Uuid,
    pub principal_ref: String,
    pub role: TraceTenantAccessGrantRole,
    pub status: TraceTenantAccessGrantStatus,
    pub allowed_consent_scopes: Vec<String>,
    pub allowed_uses: Vec<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub subject: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by_principal_ref: Option<String>,
    pub revoked_by_principal_ref: Option<String>,
    pub reason: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceTenantAccessGrantRecord {
    pub tenant_id: String,
    pub grant_id: Uuid,
    pub principal_ref: String,
    pub role: TraceTenantAccessGrantRole,
    pub status: TraceTenantAccessGrantStatus,
    pub allowed_consent_scopes: Vec<String>,
    pub allowed_uses: Vec<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub subject: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by_principal_ref: Option<String>,
    pub revoked_by_principal_ref: Option<String>,
    pub reason: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceObjectRefWrite {
    pub object_ref_id: Uuid,
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub artifact_kind: TraceObjectArtifactKind,
    pub object_store: String,
    pub object_key: String,
    pub content_sha256: String,
    pub encryption_key_ref: String,
    pub size_bytes: i64,
    pub compression: Option<String>,
    pub created_by_job_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceObjectRefRecord {
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub object_ref_id: Uuid,
    pub artifact_kind: TraceObjectArtifactKind,
    pub object_store: String,
    pub object_key: String,
    pub content_sha256: String,
    pub encryption_key_ref: String,
    pub size_bytes: i64,
    pub compression: Option<String>,
    pub created_by_job_id: Option<Uuid>,
    pub invalidated_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportManifestWrite {
    pub tenant_id: String,
    pub export_manifest_id: Uuid,
    pub artifact_kind: TraceObjectArtifactKind,
    pub purpose_code: Option<String>,
    pub audit_event_id: Option<Uuid>,
    pub source_submission_ids: Vec<Uuid>,
    pub source_submission_ids_hash: String,
    pub item_count: u32,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportManifestMirrorWrite {
    pub manifest: TraceExportManifestWrite,
    pub object_refs: Vec<TraceObjectRefWrite>,
    pub items: Vec<TraceExportManifestItemWrite>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportManifestRecord {
    pub tenant_id: String,
    pub export_manifest_id: Uuid,
    pub artifact_kind: TraceObjectArtifactKind,
    pub purpose_code: Option<String>,
    pub audit_event_id: Option<Uuid>,
    pub source_submission_ids: Vec<Uuid>,
    pub source_submission_ids_hash: String,
    pub item_count: u32,
    pub generated_at: DateTime<Utc>,
    pub invalidated_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceExportManifestItemInvalidationReason {
    Revoked,
    Expired,
    Purged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportManifestItemWrite {
    pub tenant_id: String,
    pub export_manifest_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub derived_id: Option<Uuid>,
    pub object_ref_id: Option<Uuid>,
    pub vector_entry_id: Option<Uuid>,
    pub source_status_at_export: TraceCorpusStatus,
    pub source_hash_at_export: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportManifestItemRecord {
    pub tenant_id: String,
    pub export_manifest_id: Uuid,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub derived_id: Option<Uuid>,
    pub object_ref_id: Option<Uuid>,
    pub vector_entry_id: Option<Uuid>,
    pub source_status_at_export: TraceCorpusStatus,
    pub source_hash_at_export: String,
    pub source_invalidated_at: Option<DateTime<Utc>>,
    pub source_invalidation_reason: Option<TraceExportManifestItemInvalidationReason>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantScopedTraceObjectRef {
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub object_ref_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceDerivedRecordWrite {
    pub derived_id: Uuid,
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub status: TraceDerivedStatus,
    pub worker_kind: TraceWorkerKind,
    pub worker_version: String,
    pub input_object_ref: Option<TenantScopedTraceObjectRef>,
    pub input_hash: String,
    pub output_object_ref: Option<TenantScopedTraceObjectRef>,
    pub canonical_summary: Option<String>,
    pub canonical_summary_hash: Option<String>,
    pub summary_model: String,
    pub task_success: Option<String>,
    pub privacy_risk: Option<String>,
    pub event_count: Option<i32>,
    pub tool_sequence: Vec<String>,
    pub tool_categories: Vec<String>,
    pub coverage_tags: Vec<String>,
    pub duplicate_score: Option<f32>,
    pub novelty_score: Option<f32>,
    pub cluster_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceDerivedRecord {
    pub derived_id: Uuid,
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub status: TraceDerivedStatus,
    pub worker_kind: TraceWorkerKind,
    pub worker_version: String,
    pub input_object_ref: Option<TenantScopedTraceObjectRef>,
    pub input_hash: String,
    pub output_object_ref: Option<TenantScopedTraceObjectRef>,
    pub canonical_summary: Option<String>,
    pub canonical_summary_hash: Option<String>,
    pub summary_model: String,
    pub task_success: Option<String>,
    pub privacy_risk: Option<String>,
    pub event_count: Option<i32>,
    pub tool_sequence: Vec<String>,
    pub tool_categories: Vec<String>,
    pub coverage_tags: Vec<String>,
    pub duplicate_score: Option<f32>,
    pub novelty_score: Option<f32>,
    pub cluster_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceVectorEntryWrite {
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub derived_id: Uuid,
    pub vector_entry_id: Uuid,
    pub vector_store: String,
    pub embedding_model: String,
    pub embedding_dimension: i32,
    pub embedding_version: String,
    pub source_projection: TraceVectorEntrySourceProjection,
    pub source_hash: String,
    pub status: TraceVectorEntryStatus,
    pub nearest_trace_ids: Vec<String>,
    pub cluster_id: Option<String>,
    pub duplicate_score: Option<f32>,
    pub novelty_score: Option<f32>,
    pub indexed_at: Option<DateTime<Utc>>,
    pub invalidated_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceVectorEntryRecord {
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub derived_id: Uuid,
    pub vector_entry_id: Uuid,
    pub vector_store: String,
    pub embedding_model: String,
    pub embedding_dimension: i32,
    pub embedding_version: String,
    pub source_projection: TraceVectorEntrySourceProjection,
    pub source_hash: String,
    pub status: TraceVectorEntryStatus,
    pub nearest_trace_ids: Vec<String>,
    pub cluster_id: Option<String>,
    pub duplicate_score: Option<f32>,
    pub novelty_score: Option<f32>,
    pub indexed_at: Option<DateTime<Utc>>,
    pub invalidated_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceAuditEventWrite {
    pub audit_event_id: Uuid,
    pub tenant_id: String,
    pub actor_principal_ref: String,
    pub actor_role: String,
    pub action: TraceAuditAction,
    pub reason: Option<String>,
    pub request_id: Option<String>,
    pub submission_id: Option<Uuid>,
    pub object_ref_id: Option<Uuid>,
    pub export_manifest_id: Option<Uuid>,
    pub decision_inputs_hash: Option<String>,
    pub previous_event_hash: Option<String>,
    pub event_hash: Option<String>,
    pub canonical_event_json: Option<String>,
    pub metadata: TraceAuditSafeMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceAuditEventRecord {
    pub audit_event_id: Uuid,
    pub tenant_id: String,
    pub audit_sequence: i64,
    pub actor_principal_ref: String,
    pub actor_role: String,
    pub action: TraceAuditAction,
    pub reason: Option<String>,
    pub request_id: Option<String>,
    pub submission_id: Option<Uuid>,
    pub object_ref_id: Option<Uuid>,
    pub export_manifest_id: Option<Uuid>,
    pub decision_inputs_hash: Option<String>,
    pub previous_event_hash: Option<String>,
    pub event_hash: Option<String>,
    pub canonical_event_json: Option<String>,
    pub metadata: TraceAuditSafeMetadata,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceAuditSafeMetadata {
    #[default]
    Empty,
    Submission {
        status: TraceCorpusStatus,
        privacy_risk: String,
    },
    ReviewDecision {
        decision: String,
        resulting_status: TraceCorpusStatus,
        reason_code: Option<String>,
    },
    ReviewLease {
        action: TraceReviewLeaseAuditAction,
        lease_expires_at: Option<DateTime<Utc>>,
        review_due_at: Option<DateTime<Utc>>,
    },
    TraceContentRead {
        surface: String,
        purpose_hash: Option<String>,
    },
    Read {
        surface: String,
        item_count: u32,
    },
    Revocation {
        reason_hash: String,
    },
    Export {
        artifact_kind: TraceObjectArtifactKind,
        purpose_code: Option<String>,
        item_count: u32,
    },
    Maintenance {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        surface: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose_hash: Option<String>,
        dry_run: bool,
        action_counts: BTreeMap<String, u32>,
    },
    CreditMutation {
        event_type: TraceCreditEventType,
        credit_points_delta_micros: i64,
        reason_hash: String,
        external_ref_hash: Option<String>,
    },
    CreditSettlementIssuerApproval {
        policy_version: String,
        source_list_hash: String,
        evidence_hash: String,
        reason_hash: String,
        evidence_ref_hash: Option<String>,
    },
    CreditHold {
        action: TraceCreditHoldAuditAction,
        hold_id: Uuid,
        credit_account_hash: String,
        hold_reason: TraceCreditHoldReason,
        reason_hash: String,
    },
    NearCreditOutboxStatus {
        near_outbox_id: Uuid,
        settlement_batch_id: Uuid,
        credit_account_hash: String,
        status: TraceCreditSettlementNearStatus,
        near_transaction_hash_hash: Option<String>,
        last_error_hash: Option<String>,
    },
    BenchmarkRegistryOutboxStatus {
        benchmark_outbox_id: Uuid,
        conversion_id: Uuid,
        operation: TraceBenchmarkRegistryOutboxOperation,
        registry_ref_hash: String,
        artifact_payload_hash: String,
        source_submission_ids_hash: String,
        evaluator_ref_hash: Option<String>,
        status: TraceBenchmarkRegistryOutboxStatus,
        external_receipt_ref_hash: Option<String>,
        last_error_hash: Option<String>,
    },
    ProcessEvaluation {
        evaluator_version_hash: String,
        label_count: u32,
        rating_counts: BTreeMap<String, u32>,
        score_band: Option<String>,
        utility_credit_delta_micros: Option<i64>,
        utility_external_ref_hash: Option<String>,
    },
    TenantPolicy {
        policy_version: String,
        allowed_consent_scope_count: u32,
        allowed_use_count: u32,
        policy_projection_hash: String,
    },
    TenantAccessGrant {
        action: String,
        role: TraceTenantAccessGrantRole,
        status: TraceTenantAccessGrantStatus,
        allowed_consent_scope_count: u32,
        allowed_use_count: u32,
        grant_projection_hash: String,
    },
    ExportJobRecovery {
        export_job_id: Uuid,
        recovered_status: TraceExportJobStatus,
        reason_hash: String,
    },
    RankingWorkerRunRecovery {
        ranking_worker_run_id: Uuid,
        run_kind: TraceRankingWorkerRunKind,
        recovered_status: TraceRankingWorkerRunStatus,
        reason_hash: String,
    },
    RankingCalibrationDatasetQuarantine {
        calibration_dataset_hash: String,
        target_use: String,
        policy_version: String,
        archived_source_manifest_hash: String,
        conflict_key_hash: String,
        reason_hash: String,
    },
    /// Phase A6: a revocation-propagation worker attempt failed. Hash-only:
    /// the `propagation_item_id` and `source_submission_id` are server-issued
    /// UUIDs (no tenant policy state), `error_class` is a stable label
    /// (e.g. `"VectorInvalidationFailed"`), `error_hash` is the SHA-256 hex of
    /// the raw error text, and `attempt_count` is the attempt that just
    /// failed. `is_terminal` is true when `attempt_count` has reached the
    /// configured retry cap (`TRACE_COMMONS_REVOCATION_PROPAGATION_MAX_ATTEMPTS`)
    /// and the item will not be re-claimed without operator intervention.
    /// Phase A6 emits this only on the `VectorEntry` path; the other
    /// propagation target kinds will adopt the same shape in a separate
    /// mechanical follow-up.
    RevocationPropagationFailure {
        propagation_item_id: Uuid,
        source_submission_id: Uuid,
        target_kind: TraceRevocationPropagationTargetKind,
        action: TraceRevocationPropagationAction,
        error_class: String,
        error_hash: String,
        attempt_count: u32,
        is_terminal: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceCreditEventWrite {
    pub credit_event_id: Uuid,
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub credit_account_ref: String,
    pub event_type: TraceCreditEventType,
    pub points_delta: String,
    pub reason: String,
    pub external_ref: Option<String>,
    pub actor_principal_ref: String,
    pub actor_role: String,
    pub settlement_state: TraceCreditSettlementState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceCreditEventRecord {
    pub credit_event_id: Uuid,
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub trace_id: Uuid,
    pub credit_account_ref: String,
    pub event_type: TraceCreditEventType,
    pub points_delta: String,
    pub reason: String,
    pub external_ref: Option<String>,
    pub actor_principal_ref: String,
    pub actor_role: String,
    pub settlement_state: TraceCreditSettlementState,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceTombstoneWrite {
    pub tombstone_id: Uuid,
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub trace_id: Option<Uuid>,
    pub redaction_hash: Option<String>,
    pub canonical_summary_hash: Option<String>,
    pub reason: String,
    pub effective_at: DateTime<Utc>,
    pub retain_until: Option<DateTime<Utc>>,
    pub created_by_principal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceTombstoneRecord {
    pub tombstone_id: Uuid,
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub trace_id: Option<Uuid>,
    pub redaction_hash: Option<String>,
    pub canonical_summary_hash: Option<String>,
    pub reason: String,
    pub effective_at: DateTime<Utc>,
    pub retain_until: Option<DateTime<Utc>>,
    pub created_by_principal_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRetentionJobStatus {
    Planned,
    Running,
    DryRun,
    Complete,
    Failed,
    Paused,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRetentionJobWrite {
    pub tenant_id: String,
    pub retention_job_id: Uuid,
    pub purpose: String,
    pub dry_run: bool,
    pub status: TraceRetentionJobStatus,
    pub requested_by_principal_ref: String,
    pub requested_by_role: String,
    pub purge_expired_before: Option<DateTime<Utc>>,
    pub prune_export_cache: bool,
    pub max_export_age_hours: Option<i64>,
    pub audit_event_id: Option<Uuid>,
    pub action_counts: BTreeMap<String, u32>,
    pub selected_revoked_count: u32,
    pub selected_expired_count: u32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRetentionJobRecord {
    pub tenant_id: String,
    pub retention_job_id: Uuid,
    pub purpose: String,
    pub dry_run: bool,
    pub status: TraceRetentionJobStatus,
    pub requested_by_principal_ref: String,
    pub requested_by_role: String,
    pub purge_expired_before: Option<DateTime<Utc>>,
    pub prune_export_cache: bool,
    pub max_export_age_hours: Option<i64>,
    pub audit_event_id: Option<Uuid>,
    pub action_counts: BTreeMap<String, u32>,
    pub selected_revoked_count: u32,
    pub selected_expired_count: u32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRetentionJobItemAction {
    Revoke,
    Expire,
    Purge,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRetentionJobItemStatus {
    Pending,
    Done,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRetentionJobItemWrite {
    pub tenant_id: String,
    pub retention_job_id: Uuid,
    pub submission_id: Uuid,
    pub action: TraceRetentionJobItemAction,
    pub status: TraceRetentionJobItemStatus,
    pub reason: String,
    pub action_counts: BTreeMap<String, u32>,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRetentionJobItemRecord {
    pub tenant_id: String,
    pub retention_job_id: Uuid,
    pub submission_id: Uuid,
    pub action: TraceRetentionJobItemAction,
    pub status: TraceRetentionJobItemStatus,
    pub reason: String,
    pub action_counts: BTreeMap<String, u32>,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceExportAccessGrantStatus {
    Active,
    Consumed,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportAccessGrantWrite {
    pub tenant_id: String,
    pub export_job_id: Uuid,
    pub grant_id: Uuid,
    pub caller_principal_ref: String,
    pub requested_dataset_kind: String,
    pub purpose: String,
    pub max_item_cap: Option<u32>,
    pub status: TraceExportAccessGrantStatus,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportAccessGrantRecord {
    pub tenant_id: String,
    pub export_job_id: Uuid,
    pub grant_id: Uuid,
    pub caller_principal_ref: String,
    pub requested_dataset_kind: String,
    pub purpose: String,
    pub max_item_cap: Option<u32>,
    pub status: TraceExportAccessGrantStatus,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceExportJobStatus {
    Queued,
    Running,
    Complete,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportJobWrite {
    pub tenant_id: String,
    pub export_job_id: Uuid,
    pub grant_id: Uuid,
    pub caller_principal_ref: String,
    pub requested_dataset_kind: String,
    pub purpose: String,
    pub max_item_cap: Option<u32>,
    pub status: TraceExportJobStatus,
    pub requested_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub result_manifest_id: Option<Uuid>,
    pub item_count: Option<u32>,
    pub last_error: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportJobStatusUpdate {
    pub status: TraceExportJobStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub result_manifest_id: Option<Uuid>,
    pub item_count: Option<u32>,
    pub last_error: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceExportJobRecord {
    pub tenant_id: String,
    pub export_job_id: Uuid,
    pub grant_id: Uuid,
    pub caller_principal_ref: String,
    pub requested_dataset_kind: String,
    pub purpose: String,
    pub max_item_cap: Option<u32>,
    pub status: TraceExportJobStatus,
    pub requested_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub result_manifest_id: Option<Uuid>,
    pub item_count: Option<u32>,
    pub last_error: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRevocationPropagationTargetKind {
    ObjectRef,
    ExportManifest,
    ExportManifestItem,
    VectorEntry,
    DerivedRecord,
    BenchmarkArtifact,
    RankerArtifact,
    CreditSettlement,
    WorkerQueue,
    PhysicalDeleteReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceRevocationPropagationTarget {
    ObjectRef {
        object_ref_id: Uuid,
    },
    ExportManifest {
        export_manifest_id: Uuid,
    },
    ExportManifestItem {
        export_manifest_id: Uuid,
        source_submission_id: Uuid,
    },
    VectorEntry {
        vector_entry_id: Uuid,
    },
    DerivedRecord {
        derived_id: Uuid,
    },
    BenchmarkArtifact {
        derived_id: Option<Uuid>,
        object_ref_id: Option<Uuid>,
        export_manifest_id: Option<Uuid>,
        artifact_ref: Option<String>,
    },
    RankerArtifact {
        export_manifest_id: Option<Uuid>,
        object_ref_id: Option<Uuid>,
        artifact_ref: Option<String>,
    },
    CreditSettlement {
        credit_event_id: Uuid,
        credit_account_ref: String,
        settlement_state_at_selection: TraceCreditSettlementState,
    },
    WorkerQueue {
        queue_surface: String,
        queue_key_hash: String,
    },
    PhysicalDeleteReceipt {
        object_ref_id: Option<Uuid>,
        object_store: String,
        object_key: String,
        receipt_sha256: String,
    },
}

impl TraceRevocationPropagationTarget {
    pub fn kind(&self) -> TraceRevocationPropagationTargetKind {
        match self {
            Self::ObjectRef { .. } => TraceRevocationPropagationTargetKind::ObjectRef,
            Self::ExportManifest { .. } => TraceRevocationPropagationTargetKind::ExportManifest,
            Self::ExportManifestItem { .. } => {
                TraceRevocationPropagationTargetKind::ExportManifestItem
            }
            Self::VectorEntry { .. } => TraceRevocationPropagationTargetKind::VectorEntry,
            Self::DerivedRecord { .. } => TraceRevocationPropagationTargetKind::DerivedRecord,
            Self::BenchmarkArtifact { .. } => {
                TraceRevocationPropagationTargetKind::BenchmarkArtifact
            }
            Self::RankerArtifact { .. } => TraceRevocationPropagationTargetKind::RankerArtifact,
            Self::CreditSettlement { .. } => TraceRevocationPropagationTargetKind::CreditSettlement,
            Self::WorkerQueue { .. } => TraceRevocationPropagationTargetKind::WorkerQueue,
            Self::PhysicalDeleteReceipt { .. } => {
                TraceRevocationPropagationTargetKind::PhysicalDeleteReceipt
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRevocationPropagationAction {
    InvalidateMetadata,
    InvalidateExportMembership,
    InvalidateVector,
    InvalidateBenchmarkArtifact,
    InvalidateRankerArtifact,
    ReverseCreditSettlement,
    InvalidateWorkerQueue,
    DeleteObjectPayload,
    RecordPhysicalDeleteReceipt,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceRevocationPropagationItemStatus {
    Pending,
    InProgress,
    Done,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRevocationPropagationItemWrite {
    pub tenant_id: String,
    pub propagation_item_id: Uuid,
    pub source_submission_id: Uuid,
    pub target: TraceRevocationPropagationTarget,
    pub action: TraceRevocationPropagationAction,
    pub status: TraceRevocationPropagationItemStatus,
    pub idempotency_key: String,
    pub reason: String,
    pub attempt_count: u32,
    pub last_error: Option<String>,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub evidence_hash: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRevocationPropagationItemStatusUpdate {
    pub status: TraceRevocationPropagationItemStatus,
    pub attempt_count: u32,
    pub last_error: Option<String>,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub evidence_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRevocationPropagationItemRecord {
    pub tenant_id: String,
    pub propagation_item_id: Uuid,
    pub source_submission_id: Uuid,
    pub trace_id: Uuid,
    pub target_kind: TraceRevocationPropagationTargetKind,
    pub target: TraceRevocationPropagationTarget,
    pub action: TraceRevocationPropagationAction,
    pub status: TraceRevocationPropagationItemStatus,
    pub idempotency_key: String,
    pub reason: String,
    pub attempt_count: u32,
    pub last_error: Option<String>,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub evidence_hash: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Audit row written by `TraceGateService` for every evaluated trace.
/// Maps 1:1 to the `trace_gate_decisions` columns introduced in V23.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceGateDecisionRow {
    pub decision_id: Uuid,
    pub submission_id: Uuid,
    pub gate_policy_version: String,
    pub gate_version_hash: String,
    pub perplexity_micros: i64,
    pub tail_fraction_micros: i64,
    pub perplexity_passed: bool,
    pub novelty_score_micros: i64,
    pub nearest_neighbor_hash: String,
    pub novelty_passed: bool,
    pub embedding_evidence_hash: String,
    pub attestation_chain_hash: String,
    pub decided_at: DateTime<Utc>,
    /// The UUID the orchestrator assigned to the inserted vector index entry.
    /// `Some` only when both gates passed and an entry was inserted (migration
    /// V24 adds the nullable column). `None` for pass-fail decisions and for
    /// deterministic/legacy service rows that never touch a real index.
    pub vector_entry_id: Option<Uuid>,
    /// Stable label-only reason populated when the gate passed but
    /// `novelty_utility` credit emission was withheld (migration V25 adds the
    /// nullable column). `None` on legacy rows, when the gate failed, or when
    /// credit was actually emitted. Allowed values written by the server are
    /// `"policy_mismatch"`, `"central_issuer_denied"`,
    /// `"non_production_gate"`, and `"submission_not_accepted"`.
    pub credit_withheld_reason: Option<String>,
    /// Peak (most-surprising min-content-guarded chunk) perplexity in
    /// micros (migration V37). `None` on pre-chunking rows — readers treat
    /// `None` as "peak == representative" (single-chunk semantics).
    pub peak_perplexity_micros: Option<i64>,
    /// Peak per-chunk novelty in micros (migration V37). Same `None`
    /// semantics as `peak_perplexity_micros`.
    pub peak_novelty_micros: Option<i64>,
    /// Number of chunks scored (migration V37). `None` reads as 1.
    pub chunk_count: Option<i32>,
    /// Total chunks the trace produced before the per-trace cap dropped any
    /// (migration V47). `None` means the denominator was never recorded —
    /// every decision written before V47 — and readers MUST report it as
    /// unknown rather than estimating one. When `chunks_capped` is false this
    /// equals `chunk_count`.
    pub total_chunk_count: Option<i32>,
    /// True when the per-trace chunk cap dropped trailing chunks
    /// (migration V37). `None` reads as false.
    pub chunks_capped: Option<bool>,
    /// Token-weighted share of the scored trace sitting in chunks that clear
    /// the per-chunk perplexity floor, * 1e6 (migration V54, #478). Shadow
    /// mode: recorded, gates nothing.
    ///
    /// `None` means no value exists, and unlike most of this struct that is
    /// permanent: per-chunk logprobs are never persisted, so a decision
    /// written before V54 can never be given one. `None` also covers a
    /// deterministic service, which scores the whole trace as one chunk and
    /// holds no per-chunk floor. It is not `Some(0)` — a trace where no chunk
    /// clears the floor earns a genuine 0 — and readers MUST NOT default it,
    /// or calibration will read every unmeasured row as the worst possible
    /// observation.
    pub qualifying_token_fraction_micros: Option<i64>,
    /// The composite credit-quality score `q` * 1e6 as computed at scoring
    /// time under the calibration active then (migration V53, #199).
    ///
    /// Deliberately distinct from `credit_quality_micros`, which the batch
    /// re-score route overwrites in place: that column holds the newest
    /// re-score, this one holds the number production actually used, and only
    /// the second can be joined to an outcome. WRITE-ONCE — no code path may
    /// update it, because a later value would silently answer a different
    /// question than the one asked.
    ///
    /// `None` means NOT INSTRUMENTED: every decision written before V53, and
    /// any path that records a decision without scoring it. It is not `Some(0)`
    /// — a below-floor trace earns a genuine composite of 0, and conflating
    /// the two would enrol unmeasured rows into the sample as real
    /// observations. Readers MUST NOT default it.
    pub composite_score_micros: Option<i64>,
    /// Which vector-index shard the novelty score was computed against
    /// (migration V53, #199), captured before this trace's own entries were
    /// inserted. Same shard id means the same corpus lineage;
    /// `index_cardinality_at_scoring` distinguishes states within it.
    /// `None` means not instrumented, or an index that cannot describe itself.
    pub vector_index_snapshot_id: Option<Uuid>,
    /// How many entries that shard held at scoring time (migration V53,
    /// #199). Novelty drifts downward as the index fills, so this is the
    /// covariate a chronological estimate has to condition on. `None` is not
    /// instrumented; `Some(0)` is the real observation for a tenant's first
    /// trace, scored against an empty shard.
    pub index_cardinality_at_scoring: Option<i64>,
}

/// One per-chunk vector-index entry row (`trace_gate_chunk_vector_entries`,
/// migration V37). Keyed `(tenant_id, decision_id, chunk_index)`; the
/// complete authoritative entry set for a decision. The decision row's
/// legacy `vector_entry_id` column keeps holding the FIRST entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceGateChunkVectorEntryRow {
    pub decision_id: Uuid,
    pub submission_id: Uuid,
    pub chunk_index: i32,
    pub vector_entry_id: Uuid,
}

/// A single submission awaiting a gate decision, as enumerated by
/// [`crate::db::Database::list_submissions_needing_gate_decision`]. Cross-tenant
/// by construction (the enumeration runs on the narrow `trace_gate_driver`
/// pool), so the tenant is carried explicitly alongside the submission id
/// rather than implied by a tenant-scoped call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateWorkItem {
    pub tenant_id: String,
    pub submission_id: Uuid,
}

/// Numeric inputs for shadow credit-quality scoring of one decision row, read
/// cross-tenant through the narrow `trace_gate_driver` pool (no tenant GUC).
/// The peak/novelty are stored micros; NULLs map to 0 (below-floor -> q 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateCreditInput {
    pub tenant_id: String,
    pub decision_id: Uuid,
    pub perplexity_micros: i64,
    pub peak_perplexity_micros: i64,
    pub novelty_score_micros: i64,
}

/// Cross-trace dedup cluster signal for one decision row (migration V40),
/// read cross-tenant through the narrow `trace_gate_driver` pool (no tenant
/// GUC). `dedup_simhash` / `dedup_cluster_id` are `None` until a dedup pass
/// has assigned this decision to a cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupSignalRow {
    pub tenant_id: String,
    pub decision_id: Uuid,
    pub dedup_cluster_id: Option<Uuid>,
    pub dedup_simhash: Option<i64>,
    /// Which renderer and simhash algorithm produced `dedup_simhash`
    /// (migration V57). `None` means the row was recorded before the stamp
    /// existed and is read as
    /// [`crate::dedup_assign::LEGACY_DEDUP_SIGNAL_VERSION`] -- never as
    /// "unknown". Two rows whose effective versions differ are not
    /// comparable, however close their simhashes are.
    pub dedup_signal_version: Option<String>,
}

impl DedupSignalRow {
    /// The version this row's `dedup_simhash` was derived under. `NULL` (and
    /// an empty string, which is a `NULL` that survived a round trip through
    /// a text column) reads as
    /// [`crate::dedup_assign::LEGACY_DEDUP_SIGNAL_VERSION`], never as
    /// "unknown": an unknown would have to cluster either with everything or
    /// with nothing, and both are wrong.
    ///
    /// This is the ONE place a stored `NULL` is decoded, and it sits on the
    /// row because that is where the `Option` originates. A caller that
    /// decoded it for itself would be a second answer to the question, free
    /// to drift from this one.
    pub fn effective_signal_version(&self) -> &str {
        match self.dedup_signal_version.as_deref() {
            Some(v) if !v.is_empty() => v,
            _ => crate::dedup_assign::LEGACY_DEDUP_SIGNAL_VERSION,
        }
    }
}

/// Correction-value signal for one decision row (migration V48), read
/// cross-tenant through the narrow `trace_gate_driver` pool (no tenant GUC).
/// `correction_simhash` / `correction_cluster_id` are `None` for every
/// decision whose envelope carried no contributor correction — which is every
/// decision until the collection UI ships. SHADOW-ONLY: nothing derived from
/// these rows gates, settles, or pays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrectionSignalRow {
    pub tenant_id: String,
    pub decision_id: Uuid,
    pub correction_cluster_id: Option<Uuid>,
    pub correction_simhash: Option<i64>,
}

/// The four cross-trace dedup fields written for one decision row
/// (migrations V40 and V57). Bundled for the reason V48 bundled its own six:
/// three of the four are positional integers and UUIDs that transpose
/// silently, and the stamp has to travel with the simhash it names rather
/// than trailing it as a sixth argument nobody reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupAssignmentWrite {
    pub dedup_simhash: i64,
    pub dedup_cluster_id: Uuid,
    pub dedup_cluster_size: i32,
    pub dedup_signal_version: String,
}

/// The six shadow correction-value fields written for one decision row
/// (migration V48). Bundled so the write is one argument rather than six
/// positional integers that are easy to transpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrectionValueWrite {
    pub correction_simhash: i64,
    pub correction_cluster_id: Uuid,
    pub correction_cluster_size: i32,
    pub correction_novelty_micros: i64,
    pub correction_value_micros: i64,
    pub correction_value_version: i32,
}

/// One row for the per-contributor cap recompute pass. Cross-tenant by
/// construction (enumerated on the gate-driver pool), joining each decision to
/// its submission for the contributor identity (`auth_principal_ref`). The pass
/// derives `r = q * dup_pen` and the epoch bucket from these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributorCapSignalRow {
    pub tenant_id: String,
    pub decision_id: Uuid,
    pub auth_principal_ref: String,
    pub decided_at: DateTime<Utc>,
    pub credit_quality_micros: Option<i64>,
    pub dedup_cluster_size: Option<i32>,
}

/// One row of the latest gate-decision score for a single submission, read
/// cross-tenant through the narrow `trace_gate_driver` pool (no tenant GUC).
/// Used by the devfolio score read-back surface, which looks up scores by
/// `submission_id` across every contributor's per-user tenant. When a
/// submission has more than one decision row, the row with the latest
/// `decided_at` wins. `credit_quality_micros` is `None` until the shadow-mode
/// credit-quality pass has scored the decision (migration V39).
///
/// Note that `submission_id` is derived from session content, so the same
/// session uploaded by two contributors in different tenants shares one id
/// and collapses to a single row here — deliberately, since the score is a
/// function of that content, but callers must not read a row as belonging
/// to any particular contributor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceScoreBySubmissionRow {
    pub submission_id: Uuid,
    pub credit_quality_micros: Option<i64>,
    pub perplexity_micros: i64,
    pub novelty_score_micros: i64,
    pub gate_passed: bool,
    /// Chunk-coverage columns, carried so a caller can state how much of the
    /// trace these scores were computed over. Same NULL semantics as
    /// `TraceGateDecisionRow`: `chunk_count` NULL reads as 1, `chunks_capped`
    /// NULL reads as false, and `total_chunk_count` NULL is an UNKNOWN
    /// denominator (pre-V47 decision) that must never be estimated.
    pub chunk_count: Option<i32>,
    pub total_chunk_count: Option<i32>,
    pub chunks_capped: Option<bool>,
}

/// One asked-about submission that the requesting principal actually owns,
/// with its latest gate-decision score when there is one.
///
/// The scoped score-attestation read returns one of these per owned id.
/// `score: None` is the "submitted, not scored yet" state that had no
/// representation anywhere before: the unscoped enumeration inner-joins the
/// decision table, so a submission awaiting the gate driver is simply absent
/// and indistinguishable from one that was never uploaded. Ids the principal
/// does not own are not returned at all, and the caller reports them as
/// `unknown` without saying whether they exist elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnSubmissionScoreRow {
    pub submission_id: Uuid,
    pub score: Option<TraceScoreBySubmissionRow>,
}

/// Safe, label-only missing-control name returned when a storage backend has
/// no real withdrawal implementation. Withdrawal deletes content and reports a
/// distribution tier; a backend that cannot do either must refuse rather than
/// degrade.
pub const TRACE_WITHDRAWAL_BACKEND_MISSING: &str = "TraceWithdrawalBackendMissing";

/// The retained withdrawal tombstone (migration V43). Hash-only/label-only by
/// construction: there is no content, no object path, and no contributor
/// identity here, and there are no columns in the table to carry them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceWithdrawalRecord {
    pub tenant_id: String,
    pub submission_id: Uuid,
    pub withdrawn_at: DateTime<Utc>,
    /// Label of the corpus status the submission held immediately before
    /// withdrawal, e.g. `quarantined` / `accepted`.
    pub prior_status: String,
    /// Which of the three withdrawal tiers applied. One of
    /// `not_distributed`, `commons_not_distributed`, `commons_distributed`.
    pub distribution_reach: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TraceArtifactInvalidationCounts {
    pub object_refs_invalidated: u64,
    pub derived_records_invalidated: u64,
}

#[async_trait]
pub trait TraceCorpusStore: Send + Sync {
    fn supports_token_bundles(&self) -> bool {
        false
    }
    async fn publish_token_object(
        &self,
        _tenant: &str,
        _submission: Uuid,
        _revision: &str,
        _owner: &str,
        _artifact: &str,
        _store: &dyn crate::trace_artifact_store::TraceArtifactStore,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn get_token_bundle_for_export(
        &self,
        _tenant: &str,
        _submission: Uuid,
        _revision: &str,
    ) -> Result<Option<crate::token_bundle_store::StoredTokenBundle>, DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn process_token_bundles(
        &self,
        _tenant: &str,
        _store: &dyn crate::trace_artifact_store::TraceArtifactStore,
    ) -> Result<usize, DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn query_token_bundles(
        &self,
        _tenant: &str,
        _owner: Option<&str>,
        _query: &crate::token_bundle_store::TokenBundleQuery,
    ) -> Result<Vec<crate::token_bundle_store::TokenBundleIndexEntry>, DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn delete_token_objects(
        &self,
        _tenant: &str,
        _submission: Uuid,
        _revision: &str,
        _held_policies: &[String],
        _store: &dyn crate::trace_artifact_store::TraceArtifactStore,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn begin_token_bundle(
        &self,
        _bundle: crate::token_bundle_store::StoredTokenBundle,
    ) -> Result<crate::token_bundle_store::StoredTokenBundle, DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn get_token_bundle(
        &self,
        _tenant: &str,
        _submission: Uuid,
        _revision: &str,
        _owner: &str,
    ) -> Result<Option<crate::token_bundle_store::StoredTokenBundle>, DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn stage_token_object(
        &self,
        _tenant: &str,
        _submission: Uuid,
        _revision: &str,
        _owner: &str,
        _object: crate::token_bundle_store::StoredTokenObject,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn commit_token_bundle(
        &self,
        _tenant: &str,
        _submission: Uuid,
        _revision: &str,
        _owner: &str,
        _receipt: trace_commons_protocol::token_distribution::DurableBundleReceipt,
    ) -> Result<trace_commons_protocol::token_distribution::DurableBundleReceipt, DatabaseError>
    {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn pending_token_bundle_deletions(
        &self,
        _tenant: &str,
        _submission: Option<Uuid>,
    ) -> Result<Vec<crate::token_bundle_store::StoredTokenBundle>, DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn mark_token_object_deleted(
        &self,
        _tenant: &str,
        _submission: Uuid,
        _revision: &str,
        _artifact: &str,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Query("TokenBundleStorageUnavailable".into()))
    }
    async fn upsert_trace_submission(
        &self,
        submission: TraceSubmissionWrite,
    ) -> Result<TraceSubmissionRecord, DatabaseError>;

    async fn get_trace_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<Option<TraceSubmissionRecord>, DatabaseError>;

    async fn list_trace_submissions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceSubmissionRecord>, DatabaseError>;

    /// Keyset-paginated submission read scoped to an account's active principal
    /// set, for the dual-auth account read-back surface
    /// (`GET /v1/account/traces`). Rows are filtered by
    /// `auth_principal_ref = ANY(principal_refs)` under the caller's tenant RLS
    /// and ordered `(received_at DESC, submission_id DESC)` so the keyset cursor
    /// totally-orders across any number of principals (Hardening H). `cursor`,
    /// when present, continues strictly after the last `(received_at,
    /// submission_id)` of the previous page. `limit` is applied at the DB; the
    /// caller is responsible for capping it. An empty `principal_refs` returns
    /// an empty page without touching the table.
    async fn list_account_trace_submissions_keyset(
        &self,
        tenant_id: &str,
        principal_refs: &[String],
        cursor: Option<TraceSubmissionKeysetCursor>,
        limit: i64,
    ) -> Result<Vec<TraceSubmissionRecord>, DatabaseError>;

    async fn upsert_trace_tenant_policy(
        &self,
        policy: TraceTenantPolicyWrite,
    ) -> Result<TraceTenantPolicyRecord, DatabaseError>;

    async fn get_trace_tenant_policy(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TraceTenantPolicyRecord>, DatabaseError>;

    async fn upsert_trace_tenant_access_grant(
        &self,
        grant: TraceTenantAccessGrantWrite,
    ) -> Result<TraceTenantAccessGrantRecord, DatabaseError>;

    async fn list_trace_tenant_access_grants(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceTenantAccessGrantRecord>, DatabaseError>;

    async fn list_active_trace_tenant_access_grants_for_principal(
        &self,
        tenant_id: &str,
        principal_ref: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<TraceTenantAccessGrantRecord>, DatabaseError>;

    async fn list_trace_credit_events(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceCreditEventRecord>, DatabaseError>;

    /// Move quarantined submissions back to `AwaitingPiiBackstop` so the
    /// backstop driver re-assesses them, oldest-received first, capped at
    /// `limit`. Returns how many rows moved.
    ///
    /// Only submissions holding an ACTIVE `rescrubbed_envelope` ref are
    /// eligible, for two reasons. It is what the driver will actually read --
    /// `process_one_pii_backstop` goes through the record's own object
    /// pointers, which address the rescrubbed artifact once a backstop pass has
    /// run -- and it is what makes them enumerable again, since their
    /// `submitted_envelope` ref was invalidated on release and must STAY
    /// invalidated: an active pre-scrub ref is the concurrent-read hazard
    /// documented on `process_one_pii_backstop`.
    ///
    /// Re-scrubbing already-scrubbed content is safe in the only direction that
    /// matters: a second pass can remove more, never restore what was removed.
    ///
    /// Deliberately does NOT clear the attempt counter. A submission
    /// quarantined by a risk verdict rather than by exhaustion already has
    /// `attempts = 0`, and silently resetting a counter that DID exhaust would
    /// hide a trace that repeatedly fails to process.
    /// Quarantined submissions whose ONLY High-forcing cause was a residual
    /// survivor, oldest-received first, capped at `limit`.
    ///
    /// This is the population PR #506 fixed: a credential the classifier could
    /// not span, left in place because the backstop never ran the deterministic
    /// sweep. They cannot clear themselves. `can_downgrade` requires the
    /// classifier to have FOUND something, and on a re-run of a trace whose
    /// credential is already gone it finds nothing, so `max_residual_risk`
    /// preserves the stale verdict forever.
    ///
    /// Eligibility is deliberately narrow:
    ///
    /// - `residual_survivor` present -- scopes this to what #506 fixed.
    /// - `key_finding` absent -- keys are never rewritten, so it re-derives
    ///   identically and resetting achieves nothing.
    /// - `coverage_incomplete` absent -- forces High before `can_downgrade` is
    ///   consulted, so likewise.
    /// - an ACTIVE `rescrubbed_envelope` -- what the driver reads, and what
    ///   makes the row enumerable at all.
    ///
    /// Returns `(tenant_id, submission_id)` so the caller can rewrite each
    /// envelope. Prior risk lives in the envelope artifact
    /// (`envelope.privacy.residual_pii_risk`), not in a column, so clearing it
    /// is an artifact rewrite rather than an UPDATE.
    async fn list_quarantined_with_only_residual_survivor(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<(String, Uuid)>, DatabaseError>;

    async fn requeue_quarantined_for_pii_backstop(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<u64, DatabaseError>;

    async fn update_trace_submission_status(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        status: TraceCorpusStatus,
        actor_principal_ref: &str,
        reason: Option<&str>,
    ) -> Result<(), DatabaseError>;

    async fn claim_trace_review_lease(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        actor_principal_ref: &str,
        lease_expires_at: DateTime<Utc>,
        review_due_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Option<TraceSubmissionRecord>, DatabaseError>;

    async fn release_trace_review_lease(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        actor_principal_ref: &str,
    ) -> Result<Option<TraceSubmissionRecord>, DatabaseError>;

    async fn append_trace_object_ref(
        &self,
        object_ref: TraceObjectRefWrite,
    ) -> Result<(), DatabaseError>;

    async fn list_trace_object_refs(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<Vec<TraceObjectRefRecord>, DatabaseError>;

    async fn get_latest_active_trace_object_ref(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        artifact_kind: TraceObjectArtifactKind,
    ) -> Result<Option<TraceObjectRefRecord>, DatabaseError>;

    /// Invalidate every currently-active object ref of `artifact_kind` for a
    /// submission by stamping `invalidated_at`. Used defensively by the PII
    /// backstop driver to retire the pre-backstop `submitted_envelope` bytes
    /// once the rescrubbed envelope ref is written, so no export-by-ref path
    /// can resolve pre-backstop bytes. Returns the number of refs invalidated.
    /// The default is a no-op (0); the Postgres store overrides it with a
    /// scoped, tenant-context UPDATE.
    async fn invalidate_trace_object_refs_by_kind(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
        _artifact_kind: TraceObjectArtifactKind,
    ) -> Result<u64, DatabaseError> {
        Ok(0)
    }

    /// Atomically release a PII-backstop hold: flip `trace_submissions.status`
    /// to the target Accepted/Quarantined status AND invalidate every active
    /// `submitted_envelope` object ref for the submission, as a single
    /// tenant-scoped operation. Both must succeed or neither may take effect:
    ///
    /// - If the status flip committed but the invalidation did not, the
    ///   pre-backstop `submitted_envelope` ref stays active while the
    ///   submission reads as released. By-ref consumers (e.g. export
    ///   revalidation) select `SubmittedEnvelope` explicitly, so this would
    ///   publish un-scrubbed, PII-bearing bytes with no re-enumeration path to
    ///   heal it (enumeration only selects `awaiting_pii_backstop`).
    /// - If the invalidation committed but the status flip did not, the
    ///   submission becomes invisible to the driver's re-enumeration (which
    ///   INNER JOINs an active `submitted_envelope` ref) while still reading
    ///   `awaiting_pii_backstop` — it would stay held forever.
    ///
    /// Returns the number of object refs invalidated. The default
    /// implementation composes the two existing calls non-atomically (used by
    /// in-memory test doubles); the Postgres store overrides it with a single
    /// transaction so the two effects are all-or-nothing.
    async fn release_pii_backstop_hold(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        status: TraceCorpusStatus,
        actor_principal_ref: &str,
        reason: Option<&str>,
    ) -> Result<u64, DatabaseError> {
        self.update_trace_submission_status(
            tenant_id,
            submission_id,
            status,
            actor_principal_ref,
            reason,
        )
        .await?;
        self.invalidate_trace_object_refs_by_kind(
            tenant_id,
            submission_id,
            TraceObjectArtifactKind::SubmittedEnvelope,
        )
        .await
    }

    async fn append_trace_derived_record(
        &self,
        derived_record: TraceDerivedRecordWrite,
    ) -> Result<(), DatabaseError>;

    async fn list_trace_derived_records(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceDerivedRecord>, DatabaseError>;

    async fn upsert_trace_vector_entry(
        &self,
        vector_entry: TraceVectorEntryWrite,
    ) -> Result<TraceVectorEntryRecord, DatabaseError>;

    async fn list_trace_vector_entries(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceVectorEntryRecord>, DatabaseError>;

    async fn upsert_trace_ranking_model_version(
        &self,
        model_version: TraceRankingModelVersionWrite,
    ) -> Result<TraceRankingModelVersionRecord, DatabaseError>;

    async fn list_trace_ranking_model_versions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingModelVersionRecord>, DatabaseError>;

    async fn upsert_trace_ranking_calibration_dataset(
        &self,
        dataset: TraceRankingCalibrationDatasetWrite,
    ) -> Result<TraceRankingCalibrationDatasetRecord, DatabaseError>;

    async fn update_trace_ranking_calibration_dataset_status(
        &self,
        update: TraceRankingCalibrationDatasetStatusUpdate,
    ) -> Result<TraceRankingCalibrationDatasetRecord, DatabaseError>;

    async fn list_trace_ranking_calibration_datasets(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingCalibrationDatasetRecord>, DatabaseError>;

    async fn upsert_trace_ranking_feature(
        &self,
        feature: TraceRankingFeatureWrite,
    ) -> Result<TraceRankingFeatureRecord, DatabaseError>;

    async fn list_trace_ranking_features(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingFeatureRecord>, DatabaseError>;

    async fn upsert_trace_ranking_prediction(
        &self,
        prediction: TraceRankingPredictionWrite,
    ) -> Result<TraceRankingPredictionRecord, DatabaseError>;

    async fn list_trace_ranking_predictions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingPredictionRecord>, DatabaseError>;

    async fn upsert_trace_ranking_label(
        &self,
        label: TraceRankingLabelWrite,
    ) -> Result<TraceRankingLabelRecord, DatabaseError>;

    async fn list_trace_ranking_labels(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingLabelRecord>, DatabaseError>;

    async fn upsert_trace_ranking_preference_label(
        &self,
        preference: TraceRankingPreferenceLabelWrite,
    ) -> Result<TraceRankingPreferenceLabelRecord, DatabaseError>;

    async fn list_trace_ranking_preference_labels(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingPreferenceLabelRecord>, DatabaseError>;

    async fn upsert_trace_ranking_calibration_run(
        &self,
        run: TraceRankingCalibrationRunWrite,
    ) -> Result<TraceRankingCalibrationRunRecord, DatabaseError>;

    async fn list_trace_ranking_calibration_runs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingCalibrationRunRecord>, DatabaseError>;

    async fn upsert_trace_ranking_worker_run(
        &self,
        run: TraceRankingWorkerRunWrite,
    ) -> Result<TraceRankingWorkerRunRecord, DatabaseError>;

    async fn list_trace_ranking_worker_runs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRankingWorkerRunRecord>, DatabaseError>;

    async fn upsert_trace_export_manifest(
        &self,
        manifest: TraceExportManifestWrite,
    ) -> Result<TraceExportManifestRecord, DatabaseError>;

    async fn upsert_trace_export_manifest_mirror(
        &self,
        mirror: TraceExportManifestMirrorWrite,
    ) -> Result<TraceExportManifestRecord, DatabaseError>;

    async fn delete_trace_export_manifest_mirror(
        &self,
        tenant_id: &str,
        export_manifest_id: Uuid,
    ) -> Result<(), DatabaseError>;

    async fn list_trace_export_manifests(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceExportManifestRecord>, DatabaseError>;

    async fn upsert_trace_export_manifest_item(
        &self,
        item: TraceExportManifestItemWrite,
    ) -> Result<TraceExportManifestItemRecord, DatabaseError>;

    async fn list_trace_export_manifest_items(
        &self,
        tenant_id: &str,
        export_manifest_id: Uuid,
    ) -> Result<Vec<TraceExportManifestItemRecord>, DatabaseError>;

    async fn invalidate_trace_export_manifests_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<u64, DatabaseError>;

    async fn invalidate_trace_export_manifest_items_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        reason: TraceExportManifestItemInvalidationReason,
    ) -> Result<u64, DatabaseError>;

    async fn invalidate_trace_vector_entries_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
    ) -> Result<u64, DatabaseError>;

    async fn invalidate_trace_vector_entry_for_submission(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        vector_entry_id: Uuid,
    ) -> Result<u64, DatabaseError>;

    // -- Contributor-initiated withdrawal (migration V43) --------------------
    //
    // Every method below defaults to a fail-closed error rather than a
    // permissive no-op: a backend without a real implementation must refuse
    // the withdrawal path with a safe missing-control name instead of
    // reporting a success that deleted nothing or a distribution tier it
    // could not actually determine.

    /// Record a contributor withdrawal for `(tenant_id, submission_id)`.
    ///
    /// Idempotent by construction: the first call wins and later calls return
    /// the ORIGINAL row unchanged, so `withdrawn_at`, `prior_status`, and
    /// `distribution_reach` never drift across retries. Implementations MUST
    /// also move the submission row out of consumer reach (status `revoked`,
    /// `withdrawn_at` set, `purged_at` set because the content is gone) in the
    /// same transaction as the tombstone insert.
    async fn record_trace_withdrawal(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
        _withdrawn_at: DateTime<Utc>,
        _prior_status: &str,
        _distribution_reach: &str,
    ) -> Result<TraceWithdrawalRecord, DatabaseError> {
        Err(DatabaseError::Query(
            TRACE_WITHDRAWAL_BACKEND_MISSING.to_string(),
        ))
    }

    /// Read the withdrawal tombstone for `(tenant_id, submission_id)`, or
    /// `None` when the submission has never been withdrawn.
    async fn get_trace_withdrawal(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
    ) -> Result<Option<TraceWithdrawalRecord>, DatabaseError> {
        Err(DatabaseError::Query(
            TRACE_WITHDRAWAL_BACKEND_MISSING.to_string(),
        ))
    }

    /// Count the export-manifest rows this submission was published in,
    /// including manifests whose membership has already been invalidated —
    /// an invalidated membership still means copies went out. Drives the
    /// `commons_distributed` tier, so it must never under-report.
    async fn count_trace_export_memberships(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
    ) -> Result<i64, DatabaseError> {
        Err(DatabaseError::Query(
            TRACE_WITHDRAWAL_BACKEND_MISSING.to_string(),
        ))
    }

    /// Every vector-index entry id this submission participates in: the
    /// `trace_vector_entries` rows, the legacy per-decision `vector_entry_id`,
    /// and the per-chunk entries. Used to evict the trace from the gate
    /// service's in-memory index, where the content survives in derived form
    /// even after the DB rows are invalidated.
    async fn list_trace_vector_entry_ids_for_submission(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        Err(DatabaseError::Query(
            TRACE_WITHDRAWAL_BACKEND_MISSING.to_string(),
        ))
    }

    /// Drop this submission's gate decisions out of any dedup cluster
    /// (migration V40 columns, and V57's version stamp, back to NULL). Peer
    /// rows keep their own cluster assignment; their `dedup_cluster_size`
    /// snapshot is refreshed by the existing recluster pass.
    async fn clear_trace_dedup_cluster_for_submission(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
    ) -> Result<u64, DatabaseError> {
        Err(DatabaseError::Query(
            TRACE_WITHDRAWAL_BACKEND_MISSING.to_string(),
        ))
    }

    async fn append_trace_audit_event(
        &self,
        audit_event: TraceAuditEventWrite,
    ) -> Result<(), DatabaseError>;

    async fn list_trace_audit_events(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceAuditEventRecord>, DatabaseError>;

    async fn list_recent_trace_audit_events(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<TraceAuditEventRecord>, DatabaseError>;

    async fn get_trace_audit_event_by_id(
        &self,
        tenant_id: &str,
        audit_event_id: Uuid,
    ) -> Result<Option<TraceAuditEventRecord>, DatabaseError>;

    async fn append_trace_credit_event(
        &self,
        credit_event: TraceCreditEventWrite,
    ) -> Result<(), DatabaseError>;

    async fn upsert_trace_utility_attestation(
        &self,
        attestation: TraceUtilityAttestationWrite,
    ) -> Result<TraceUtilityAttestationRecord, DatabaseError>;

    async fn list_trace_utility_attestations(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceUtilityAttestationRecord>, DatabaseError>;

    async fn upsert_trace_credit_settlement_batch(
        &self,
        batch: TraceCreditSettlementBatchWrite,
    ) -> Result<TraceCreditSettlementBatchRecord, DatabaseError>;

    async fn list_trace_credit_settlement_batches(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceCreditSettlementBatchRecord>, DatabaseError>;

    async fn upsert_trace_credit_hold(
        &self,
        hold: TraceCreditHoldWrite,
    ) -> Result<TraceCreditHoldRecord, DatabaseError>;

    async fn list_trace_credit_holds(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceCreditHoldRecord>, DatabaseError>;

    async fn upsert_trace_near_credit_outbox_item(
        &self,
        item: TraceNearCreditOutboxItemWrite,
    ) -> Result<TraceNearCreditOutboxItemRecord, DatabaseError>;

    async fn list_trace_near_credit_outbox_items(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceNearCreditOutboxItemRecord>, DatabaseError>;

    /// Update an outbox row's status. When `expected_prior_statuses` is `Some`,
    /// the write only applies if the row's CURRENT status is in that allow-list
    /// (optimistic guard the submit path uses to never advance an already
    /// `submitted`/`confirmed` row); `None` writes unconditionally.
    async fn update_trace_near_credit_outbox_status(
        &self,
        tenant_id: &str,
        near_outbox_id: Uuid,
        status: TraceCreditSettlementNearStatus,
        near_transaction_hash: Option<String>,
        last_error_hash: Option<String>,
        expected_prior_statuses: Option<Vec<TraceCreditSettlementNearStatus>>,
    ) -> Result<Option<TraceNearCreditOutboxItemRecord>, DatabaseError>;

    async fn upsert_trace_benchmark_registry_outbox_item(
        &self,
        item: TraceBenchmarkRegistryOutboxItemWrite,
    ) -> Result<TraceBenchmarkRegistryOutboxItemRecord, DatabaseError>;

    async fn list_trace_benchmark_registry_outbox_items(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceBenchmarkRegistryOutboxItemRecord>, DatabaseError>;

    async fn update_trace_benchmark_registry_outbox_status(
        &self,
        tenant_id: &str,
        benchmark_outbox_id: Uuid,
        status: TraceBenchmarkRegistryOutboxStatus,
        external_receipt_ref: Option<String>,
        last_error_hash: Option<String>,
    ) -> Result<Option<TraceBenchmarkRegistryOutboxItemRecord>, DatabaseError>;

    async fn write_trace_tombstone(
        &self,
        tombstone: TraceTombstoneWrite,
    ) -> Result<(), DatabaseError>;

    async fn list_trace_tombstones(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceTombstoneRecord>, DatabaseError>;

    async fn upsert_trace_retention_job(
        &self,
        job: TraceRetentionJobWrite,
    ) -> Result<TraceRetentionJobRecord, DatabaseError>;

    async fn upsert_trace_retention_job_item(
        &self,
        item: TraceRetentionJobItemWrite,
    ) -> Result<TraceRetentionJobItemRecord, DatabaseError>;

    async fn list_trace_retention_jobs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceRetentionJobRecord>, DatabaseError>;

    async fn list_trace_retention_job_items(
        &self,
        tenant_id: &str,
        retention_job_id: Uuid,
    ) -> Result<Vec<TraceRetentionJobItemRecord>, DatabaseError>;

    async fn upsert_trace_export_access_grant(
        &self,
        grant: TraceExportAccessGrantWrite,
    ) -> Result<TraceExportAccessGrantRecord, DatabaseError>;

    async fn list_trace_export_access_grants(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceExportAccessGrantRecord>, DatabaseError>;

    async fn upsert_trace_export_job(
        &self,
        job: TraceExportJobWrite,
    ) -> Result<TraceExportJobRecord, DatabaseError>;

    async fn list_trace_export_jobs(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<TraceExportJobRecord>, DatabaseError>;

    async fn update_trace_export_job_status(
        &self,
        tenant_id: &str,
        export_job_id: Uuid,
        update: TraceExportJobStatusUpdate,
    ) -> Result<Option<TraceExportJobRecord>, DatabaseError>;

    async fn claim_next_trace_export_job(
        &self,
        tenant_id: &str,
        requested_dataset_kind: Option<&str>,
        claim_at: DateTime<Utc>,
        worker_principal_ref: &str,
    ) -> Result<Option<TraceExportJobRecord>, DatabaseError>;

    async fn recover_stale_trace_export_job(
        &self,
        tenant_id: &str,
        export_job_id: Uuid,
        stale_at: DateTime<Utc>,
        update: TraceExportJobStatusUpdate,
    ) -> Result<Option<TraceExportJobRecord>, DatabaseError>;

    async fn retry_failed_trace_export_job(
        &self,
        tenant_id: &str,
        export_job_id: Uuid,
        retry_at: DateTime<Utc>,
        update: TraceExportJobStatusUpdate,
    ) -> Result<Option<TraceExportJobRecord>, DatabaseError>;

    async fn upsert_trace_revocation_propagation_item(
        &self,
        item: TraceRevocationPropagationItemWrite,
    ) -> Result<TraceRevocationPropagationItemRecord, DatabaseError>;

    async fn list_trace_revocation_propagation_items(
        &self,
        tenant_id: &str,
        source_submission_id: Uuid,
    ) -> Result<Vec<TraceRevocationPropagationItemRecord>, DatabaseError>;

    async fn list_due_trace_revocation_propagation_items(
        &self,
        tenant_id: &str,
        now: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<TraceRevocationPropagationItemRecord>, DatabaseError>;

    async fn update_trace_revocation_propagation_item_status(
        &self,
        tenant_id: &str,
        propagation_item_id: Uuid,
        update: TraceRevocationPropagationItemStatusUpdate,
    ) -> Result<Option<TraceRevocationPropagationItemRecord>, DatabaseError>;

    async fn invalidate_trace_submission_artifacts(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        derived_status: TraceDerivedStatus,
    ) -> Result<TraceArtifactInvalidationCounts, DatabaseError>;

    async fn mark_trace_object_ref_deleted(
        &self,
        tenant_id: &str,
        submission_id: Uuid,
        object_store: &str,
        object_key: &str,
    ) -> Result<u64, DatabaseError>;

    /// Append a hash-only `trace_gate_decisions` audit row for a single
    /// `TraceGateService::evaluate_trace` call. Implementations MUST scope
    /// the insert by `tenant_id` (the V23 table has forced RLS bound to
    /// `trace_current_tenant_id()`).
    async fn insert_trace_gate_decision(
        &self,
        tenant_id: &str,
        decision: TraceGateDecisionRow,
    ) -> Result<(), DatabaseError>;

    /// Insert a gate-decision row together with its per-chunk vector-entry
    /// rows, atomically (one transaction). The default delegates to
    /// `insert_trace_gate_decision` and DROPS the chunk entries — acceptable
    /// only for non-PG test doubles; the PG impl overrides this.
    async fn insert_trace_gate_decision_with_chunk_entries(
        &self,
        tenant_id: &str,
        decision: TraceGateDecisionRow,
        _chunk_entries: Vec<TraceGateChunkVectorEntryRow>,
    ) -> Result<(), DatabaseError> {
        self.insert_trace_gate_decision(tenant_id, decision).await
    }

    /// List all per-chunk vector entries recorded for a submission (all of
    /// its decisions). Default returns empty for non-PG test doubles.
    async fn list_trace_gate_chunk_vector_entries(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
    ) -> Result<Vec<TraceGateChunkVectorEntryRow>, DatabaseError> {
        Ok(Vec::new())
    }

    /// Update the label-only `credit_withheld_reason` on an already-inserted
    /// `trace_gate_decisions` row. Used by the gate-worker HTTP handler after
    /// `evaluate_and_record_gate` writes the initial row: credit-emission
    /// eligibility is only known once `attempt_emit_novelty_utility_credit`
    /// runs, which needs `TenantAuth` and so cannot live in the non-auth
    /// scoring core. Defaults to a log-once warning + no-op; only the
    /// production Postgres backend has a real implementation today. The
    /// default deliberately does not panic (so a backend that never withholds
    /// credit stays usable) but does warn (label-only, no tenant/decision
    /// identifiers) so a future non-Postgres backend that actually exercises
    /// the withheld path cannot silently drop the update.
    async fn update_trace_gate_decision_credit_withheld_reason(
        &self,
        _tenant_id: &str,
        _decision_id: Uuid,
        _credit_withheld_reason: Option<String>,
    ) -> Result<(), DatabaseError> {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "update_trace_gate_decision_credit_withheld_reason called on a backend without a real impl"
            );
        });
        Ok(())
    }

    /// Re-score maintenance: update ONLY the perplexity columns
    /// (`perplexity_micros`, `peak_perplexity_micros`, `perplexity_passed`) on
    /// the `trace_gate_decisions` row for `(tenant_id, submission_id)`. Novelty,
    /// tail-fraction, vector-entry, gate status, credit, and every other column
    /// are left untouched. Implementations MUST scope the update by `tenant_id`
    /// (the V23 table has forced RLS bound to `trace_current_tenant_id()`).
    ///
    /// Defaults to a log-once warning + no-op; only the production Postgres
    /// backend has a real implementation. The default deliberately does not
    /// panic but does warn (label-only, no tenant/submission identifiers) so a
    /// future non-Postgres backend that exercises the re-score path cannot
    /// silently drop the update.
    async fn update_trace_gate_decision_perplexity(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
        _perplexity_micros: i64,
        _peak_perplexity_micros: Option<i64>,
        _perplexity_passed: bool,
    ) -> Result<(), DatabaseError> {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "update_trace_gate_decision_perplexity called on a backend without a real impl"
            );
        });
        Ok(())
    }

    /// Update ONLY the credit-quality columns for the decision row identified by
    /// `(tenant_id, decision_id)`. Perplexity, novelty, tail-fraction, vector,
    /// gate status, and credit are left untouched. Implementations MUST scope by
    /// `tenant_id` (forced RLS). Defaults to a log-once warning + no-op so a
    /// backend without a real impl cannot silently drop the write.
    async fn update_trace_gate_decision_credit_quality(
        &self,
        _tenant_id: &str,
        _decision_id: Uuid,
        _q_micros: i64,
        _anomaly_ratio_micros: i64,
        _calibration_version: i32,
    ) -> Result<(), DatabaseError> {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "update_trace_gate_decision_credit_quality called on a backend without a real impl"
            );
        });
        Ok(())
    }

    /// Update ONLY the dedup columns (migrations V40 and V57) for the
    /// decision row identified by `(tenant_id, decision_id)`. Perplexity,
    /// novelty, tail-fraction, vector, gate status, and credit are left
    /// untouched. Implementations MUST scope by `tenant_id` (forced RLS).
    /// Defaults to a log-once warning + no-op so a backend without a real
    /// impl cannot silently drop the write.
    ///
    /// `dedup_signal_version` names the derivation behind `dedup_simhash` and
    /// is written in the same statement, never separately: a simhash whose
    /// stamp lands in a later write is a row that reads as the legacy version
    /// in between, and the recluster sweep runs continuously.
    async fn update_trace_gate_decision_dedup(
        &self,
        _tenant_id: &str,
        _decision_id: Uuid,
        _write: DedupAssignmentWrite,
    ) -> Result<(), DatabaseError> {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "update_trace_gate_decision_dedup called on a backend without a real impl"
            );
        });
        Ok(())
    }

    /// Update ONLY the two cluster columns (`dedup_cluster_id`,
    /// `dedup_cluster_size`) for the decision row identified by `(tenant_id,
    /// decision_id)`. The simhash and its version stamp are left exactly as
    /// they are. Implementations MUST scope by `tenant_id` (forced RLS).
    /// Defaults to a log-once warning + no-op so a backend without a real
    /// impl cannot silently drop the write.
    ///
    /// This is what the recluster sweep uses, and the narrowness is the
    /// point. The sweep re-clusters simhashes that are already stored; it
    /// derives neither the simhash nor the stamp, so it has no standing to
    /// write either. Writing the stamp back would materialise the legacy
    /// literal into every pre-V57 row -- exactly the assertion-in-the-schema
    /// that V57's header refuses a DEFAULT for, made by a background pass
    /// instead of by the migration.
    async fn update_trace_gate_decision_dedup_cluster(
        &self,
        _tenant_id: &str,
        _decision_id: Uuid,
        _dedup_cluster_id: Uuid,
        _dedup_cluster_size: i32,
    ) -> Result<(), DatabaseError> {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "update_trace_gate_decision_dedup_cluster called on a backend without a real impl"
            );
        });
        Ok(())
    }

    /// Update ONLY the five correction-value columns (migration V48) for the
    /// decision row identified by `(tenant_id, decision_id)`. Perplexity,
    /// novelty, dedup, contributor-cap, gate status, and credit are left
    /// untouched — the shadow correction value must not be able to move what a
    /// contributor is credited. Implementations MUST scope by `tenant_id`
    /// (forced RLS). Defaults to a log-once warning + no-op so a backend
    /// without a real impl cannot silently drop the write.
    async fn update_trace_gate_decision_correction_value(
        &self,
        _tenant_id: &str,
        _decision_id: Uuid,
        _write: CorrectionValueWrite,
    ) -> Result<(), DatabaseError> {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "update_trace_gate_decision_correction_value called on a backend without a real impl"
            );
        });
        Ok(())
    }

    /// Update ONLY the four contributor-cap columns (migration V41) for the
    /// decision row identified by `(tenant_id, decision_id)`. Perplexity,
    /// novelty, dedup, gate status, and credit are left untouched.
    /// Implementations MUST scope by `tenant_id` (forced RLS). Defaults to a
    /// log-once warning + no-op so a backend without a real impl cannot
    /// silently drop the write.
    async fn update_trace_gate_decision_contributor_cap(
        &self,
        _tenant_id: &str,
        _decision_id: Uuid,
        _factor_micros: i32,
        _cumulative_raw_micros: i64,
        _epoch: i64,
        _version: i32,
    ) -> Result<(), DatabaseError> {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "update_trace_gate_decision_contributor_cap called on a backend without a real impl"
            );
        });
        Ok(())
    }

    /// Upsert per-`(tenant_id, submission_id)` gate-evaluation attempt
    /// bookkeeping used by the perplexity-scoring driver's cost-control
    /// wrapper (`score_one_submission`, Task 4). Increments the `attempts`
    /// counter and stamps `last_attempt_at`/`last_error_label`, returning the
    /// new attempt count. Implementations MUST scope the upsert by
    /// `tenant_id` (migration V36 forces RLS on
    /// `trace_gate_evaluation_attempts` bound to `trace_current_tenant_id()`).
    ///
    /// The default returns a "not implemented" error — only the production
    /// Postgres backend has a real implementation today.
    async fn bump_gate_evaluation_attempt(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
        _now: DateTime<Utc>,
        _error_label: &str,
    ) -> Result<i32, DatabaseError> {
        Err(DatabaseError::Query(
            "bump_gate_evaluation_attempt not implemented for this backend".to_string(),
        ))
    }

    /// Upsert per-`(tenant_id, submission_id)` PII-backstop attempt
    /// bookkeeping used by the server-side NEAR AI PII backstop driver's
    /// cost-control wrapper (Task 6). Increments the `attempts` counter and
    /// stamps `last_attempt_at`/`last_error_label`, returning the new attempt
    /// count. Implementations MUST scope the upsert by `tenant_id`
    /// (migration V38 forces RLS on `trace_pii_backstop` bound to
    /// `trace_current_tenant_id()`).
    ///
    /// The default returns a "not implemented" error — only the production
    /// Postgres backend has a real implementation today.
    async fn bump_pii_backstop_attempt(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
        _now: DateTime<Utc>,
        _error_label: &str,
    ) -> Result<i32, DatabaseError> {
        Err(DatabaseError::Query(
            "bump_pii_backstop_attempt not implemented for this backend".to_string(),
        ))
    }

    /// List quarantined submissions in `tenant_id` whose quarantine was a
    /// PII-backstop retry exhaustion rather than a privacy finding, most
    /// recently received first, bounded by `limit`.
    ///
    /// Identified by an audit row with `action = 'review'` and
    /// `metadata_json->>'reason_code' = 'pii_backstop_attempts_exhausted'`,
    /// which is the only thing that records WHY a submission was quarantined
    /// -- `trace_submissions` carries no reason column today.
    ///
    /// Only submissions that still have an active `submitted_envelope` object
    /// ref are returned. Exhaustion never invalidates that ref (nothing was
    /// re-scrubbed, so there is no replacement), but a retention or revocation
    /// pass since then may have, and re-queueing a submission whose envelope
    /// is gone would strand it on `AwaitingPiiBackstop` forever.
    ///
    /// The default returns an empty list — a backend without a real
    /// implementation simply has nothing to re-queue.
    async fn list_quarantined_pii_backstop_exhausted(
        &self,
        _tenant_id: &str,
        _limit: i64,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        Ok(Vec::new())
    }

    /// Clear the PII-backstop attempt budget for one submission, so a
    /// re-queued trace is enumerated again rather than immediately
    /// re-exhausting. Deletes the bookkeeping row outright; the driver treats
    /// an absent row as `COALESCE(attempts, 0) = 0`.
    ///
    /// The default returns a "not implemented" error — only the production
    /// Postgres backend has a real implementation today.
    async fn clear_pii_backstop_attempts(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Query(
            "clear_pii_backstop_attempts not implemented for this backend".to_string(),
        ))
    }

    /// Stamp `last_attempt_at`/`last_error_label` on the per-`(tenant_id,
    /// submission_id)` PII-backstop bookkeeping row WITHOUT incrementing
    /// `attempts`, creating the row with `attempts = 0` if absent.
    ///
    /// This is the transient-failure counterpart to
    /// `bump_pii_backstop_attempt`. A transient upstream failure must not
    /// spend the trace's attempt budget — that is the 2026-08-26 incident
    /// fix — but it must still move the trace to the back of the driver's
    /// least-recently-attempted ordering. Without the timestamp a
    /// transiently-failing submission stays permanently first in every batch
    /// and starves the whole backlog behind it (2026-08-27).
    ///
    /// Implementations MUST scope the upsert by `tenant_id` (migration V38
    /// forces RLS on `trace_pii_backstop` bound to
    /// `trace_current_tenant_id()`).
    ///
    /// The default returns a "not implemented" error — only the production
    /// Postgres backend has a real implementation today. The caller treats a
    /// failure here as non-fatal: the trace stays held either way.
    async fn touch_pii_backstop_attempt(
        &self,
        _tenant_id: &str,
        _submission_id: Uuid,
        _now: DateTime<Utc>,
        _error_label: &str,
    ) -> Result<(), DatabaseError> {
        Err(DatabaseError::Query(
            "touch_pii_backstop_attempt not implemented for this backend".to_string(),
        ))
    }

    /// Look up an existing `trace_gate_decisions` row belonging to a
    /// DIFFERENT submission in the same tenant that shares the given
    /// `canonical_summary_hash`, used by the perplexity-scoring driver's
    /// cache cost-control (Task 4). Returns the most recently decided
    /// matching row (by `decided_at`), or `None` on a cache miss.
    ///
    /// The default always returns `Ok(None)` (cache miss): a backend without
    /// a real implementation simply never benefits from the cache and falls
    /// through to full scoring, which is a cost/perf tradeoff, not a
    /// correctness or security one.
    async fn find_gate_decision_by_canonical_hash(
        &self,
        _tenant_id: &str,
        _canonical_summary_hash: &str,
        _exclude_submission_id: Uuid,
    ) -> Result<Option<TraceGateDecisionRow>, DatabaseError> {
        Ok(None)
    }

    /// Paginated scan over `trace_gate_decisions` for the replay binary.
    /// Filters to rows with `vector_entry_id IS NOT NULL` (i.e. rows that
    /// actually produced a vector-index insert) and orders by `decided_at
    /// ASC, decision_id ASC` so paging via the `(decided_at, decision_id)`
    /// cursor is stable. Implementations MUST scope the read by
    /// `tenant_id` through the same forced-RLS facade used by every other
    /// audit-table read.
    ///
    /// Pass `after_cursor = None` for the first page. Subsequent calls
    /// pass the `(decided_at, decision_id)` tuple of the last row from
    /// the previous page.
    async fn stream_trace_gate_decisions_for_replay(
        &self,
        tenant_id: &str,
        page_size: u32,
        after_cursor: Option<(DateTime<Utc>, Uuid)>,
    ) -> Result<Vec<TraceGateDecisionRow>, DatabaseError>;

    /// Return true if a `trace_revocation_propagation_items` row exists
    /// matching `target_kind = VectorEntry`, `action = InvalidateVector`,
    /// `status = Done`, and the embedded `vector_entry_id` equals the
    /// supplied id. Used by the vector-replay binary to skip entries whose
    /// revocation has already propagated.
    async fn is_vector_entry_revoked(
        &self,
        tenant_id: &str,
        vector_entry_id: Uuid,
    ) -> Result<bool, DatabaseError>;
}

#[cfg(test)]
mod status_reason_tests {
    use super::{STATUS_REASON_OTHER, safe_status_reason_label};

    /// The labels the review surface actually reasons about must survive
    /// verbatim, or the queue cannot tell a processing failure from a privacy
    /// finding -- the entire point of the column.
    #[test]
    fn allowlisted_labels_pass_through_unchanged() {
        for label in [
            "pii_backstop_attempts_exhausted",
            "pii_backstop_requeued",
            "near-ai-pii-backstop-v1",
            "review_decision",
            "retention_purged",
            "retention_expired",
        ] {
            assert_eq!(
                safe_status_reason_label(label),
                label,
                "{label} must be storable verbatim"
            );
        }
    }

    /// The reason this is an allowlist and not a sanitiser. Trace revocation
    /// takes a free-text reason straight from the API caller, and the audit
    /// trail stores only sha256 of it. Anything of that shape must collapse to
    /// a fixed label rather than reach a plainly-readable column.
    #[test]
    fn caller_supplied_text_never_reaches_the_column() {
        for hostile in [
            "contact alice@example.com about this",
            "sk-live-0000000000000000000000000000000000000000",
            "https://internal.example.com/admin?token=abcd1234",
            "arn:aws:iam::123456789012:role/trace-commons",
            "",
            "PII_BACKSTOP_ATTEMPTS_EXHAUSTED",
            "pii_backstop_attempts_exhausted ",
            "review_decision; DROP TABLE trace_submissions",
        ] {
            assert_eq!(
                safe_status_reason_label(hostile),
                STATUS_REASON_OTHER,
                "{hostile:?} must not be stored verbatim"
            );
        }
    }

    /// The label is `&'static str`, so a stored value can only ever be one of
    /// a fixed set. Pin that the fallback is not itself caller-influenced.
    #[test]
    fn the_fallback_is_a_fixed_label() {
        assert_eq!(STATUS_REASON_OTHER, "other");
        assert_eq!(safe_status_reason_label("anything at all"), "other");
    }
}

#[cfg(test)]
mod residual_risk_basis_tests {
    use super::safe_residual_risk_basis_labels;
    use trace_commons_protocol::trace_contribution::ResidualRiskCondition;

    /// Every condition the protocol can produce must survive verbatim, or the
    /// column cannot answer the question it exists for (#474): whether a
    /// quarantined trace carries a privacy finding or an outage signature.
    #[test]
    fn every_protocol_condition_is_storable() {
        let conditions: Vec<ResidualRiskCondition> = ResidualRiskCondition::ALL.to_vec();
        let stored = safe_residual_risk_basis_labels(&conditions);
        assert_eq!(stored.len(), conditions.len());
        for condition in &conditions {
            assert!(
                stored.iter().any(|label| *label == condition.as_label()),
                "{condition:?} must be storable"
            );
        }
    }

    /// The choke point exists so that nothing but a fixed compile-time label
    /// can reach a plainly-readable column. The signature already forbids
    /// caller text; this pins that the stored strings are exactly the
    /// allowlist and carry no caller-influenced content.
    #[test]
    fn no_unallowlisted_label_can_be_stored() {
        let stored = safe_residual_risk_basis_labels(ResidualRiskCondition::ALL);
        for label in &stored {
            assert!(
                ResidualRiskCondition::from_label(label).is_some(),
                "{label} is not on the allowlist"
            );
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{label} is not a fixed lowercase label"
            );
        }
        // Recorded-and-empty is representable, and is not the same as NULL.
        assert!(safe_residual_risk_basis_labels(&[]).is_empty());
    }

    /// A basis is a set of conditions, not a multiset. Duplicates would
    /// distort any count derived from the column.
    #[test]
    fn duplicate_conditions_collapse() {
        let stored = safe_residual_risk_basis_labels(&[
            ResidualRiskCondition::CoverageIncomplete,
            ResidualRiskCondition::CoverageIncomplete,
            ResidualRiskCondition::KeyFinding,
        ]);
        assert_eq!(stored, vec!["coverage_incomplete", "key_finding"]);
    }
}

#[cfg(test)]
mod dedup_signal_version_tests {
    use super::DedupSignalRow;
    use crate::dedup_assign::LEGACY_DEDUP_SIGNAL_VERSION;
    use crate::trace_gate_service::DETERMINISTIC_DEDUP_SIGNAL_VERSION;
    use uuid::Uuid;

    fn row(stored: Option<&str>) -> DedupSignalRow {
        DedupSignalRow {
            tenant_id: "tenant-a".to_string(),
            decision_id: Uuid::from_u128(1),
            dedup_cluster_id: None,
            dedup_simhash: Some(42),
            dedup_signal_version: stored.map(str::to_string),
        }
    }

    #[test]
    fn a_null_stamp_reads_as_the_legacy_v1_stamp() {
        assert_eq!(
            row(None).effective_signal_version(),
            LEGACY_DEDUP_SIGNAL_VERSION
        );
        // An empty string is a NULL that survived a round trip through a text
        // column, not a version anyone named.
        assert_eq!(
            row(Some("")).effective_signal_version(),
            LEGACY_DEDUP_SIGNAL_VERSION
        );
    }

    #[test]
    fn a_named_stamp_is_returned_verbatim() {
        assert_eq!(
            row(Some("events.v2+fnv1a-2shingle.v1")).effective_signal_version(),
            "events.v2+fnv1a-2shingle.v1"
        );
        // A deterministic service's stamp is its own version, not the legacy
        // one: its value is a window of the decision digest, not a simhash of
        // any rendered text, so it must never be read as the enclave's v1.
        assert_eq!(
            row(Some(DETERMINISTIC_DEDUP_SIGNAL_VERSION)).effective_signal_version(),
            DETERMINISTIC_DEDUP_SIGNAL_VERSION
        );
        assert_ne!(
            row(Some(DETERMINISTIC_DEDUP_SIGNAL_VERSION)).effective_signal_version(),
            row(None).effective_signal_version()
        );
    }
}
